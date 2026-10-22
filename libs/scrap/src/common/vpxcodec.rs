// https://github.com/astraw/vpx-encode
// https://github.com/astraw/env-libvpx-sys
// https://github.com/rust-av/vpx-rs/blob/master/src/decoder.rs
// https://github.com/chromium/chromium/blob/e7b24573bc2e06fed4749dd6b6abfce67f29052f/media/video/vpx_video_encoder.cc#L522

use hbb_common::anyhow::{anyhow, Context};
use hbb_common::log;
use hbb_common::message_proto::{Chroma, EncodedVideoFrame, EncodedVideoFrames, VideoFrame};
use hbb_common::ResultType;

use crate::codec::{base_bitrate, codec_thread_num, EncoderApi};
use crate::{EncodeInput, EncodeYuvFormat, GoogleImage, Pixfmt, STRIDE_ALIGN};

use super::vpx::{vp8e_enc_control_id::*, vpx_codec_err_t::*, *};
use crate::{generate_call_macro, generate_call_ptr_macro, Error, Result};
use hbb_common::bytes::Bytes;
use std::os::raw::{c_int, c_uint};
use std::{ptr, slice};

generate_call_macro!(call_vpx, false);
generate_call_ptr_macro!(call_vpx_ptr);

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum VpxVideoCodecId {
    VP8,
    VP9,
}

impl Default for VpxVideoCodecId {
    fn default() -> VpxVideoCodecId {
        VpxVideoCodecId::VP9
    }
}

pub struct VpxEncoder {
    ctx: vpx_codec_ctx_t,
    width: usize,
    height: usize,
    #[cfg(target_os = "android")]
    android_scale: u16,
    id: VpxVideoCodecId,
    i444: bool,
    yuvfmt: EncodeYuvFormat,
}

pub struct VpxDecoder {
    ctx: vpx_codec_ctx_t,
}

struct VpxImageLayout {
    w: usize,
    h: usize,
    stride: [usize; 4],
    u: usize,
    v: usize,
    len: usize,
}

impl EncoderApi for VpxEncoder {
    fn new(cfg: crate::codec::EncoderCfg, i444: bool) -> ResultType<Self>
    where
        Self: Sized,
    {
        match cfg {
            crate::codec::EncoderCfg::VPX(config) => {
                #[cfg(target_os = "android")]
                if !matches!(config.android_scale, 1 | 2) {
                    return Err(anyhow!("invalid Android screen scale"));
                }
                let layout = Self::yuv_layout(
                    config.width as _,
                    config.height as _,
                    i444,
                    STRIDE_ALIGN,
                )?;
                let i = match config.codec {
                    VpxVideoCodecId::VP8 => call_vpx_ptr!(vpx_codec_vp8_cx()),
                    VpxVideoCodecId::VP9 => call_vpx_ptr!(vpx_codec_vp9_cx()),
                };
                let mut c = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
                call_vpx!(vpx_codec_enc_config_default(i, &mut c, 0));

                // https://www.webmproject.org/docs/encoder-parameters/
                // default: c.rc_min_quantizer = 0, c.rc_max_quantizer = 63
                // try rc_resize_allowed later

                c.g_w = config.width;
                c.g_h = config.height;
                c.g_timebase.num = 1;
                c.g_timebase.den = 1000; // Output timestamp precision
                c.rc_undershoot_pct = 95;
                // When the data buffer falls below this percentage of fullness, a dropped frame is indicated. Set the threshold to zero (0) to disable this feature.
                // In dynamic scenes, low bitrate gets low fps while high bitrate gets high fps.
                c.rc_dropframe_thresh = 25;
                c.g_threads = codec_thread_num(64) as _;
                c.g_error_resilient = VPX_ERROR_RESILIENT_DEFAULT;
                // https://developers.google.com/media/vp9/bitrate-modes/
                // Constant Bitrate mode (CBR) is recommended for live streaming with VP9.
                c.rc_end_usage = vpx_rc_mode::VPX_CBR;
                if let Some(keyframe_interval) = config.keyframe_interval {
                    c.kf_min_dist = 0;
                    c.kf_max_dist = keyframe_interval as _;
                } else {
                    c.kf_mode = vpx_kf_mode::VPX_KF_DISABLED; // reduce bandwidth a lot
                }

                let (q_min, q_max) = Self::calc_q_values(config.quality);
                c.rc_min_quantizer = q_min;
                c.rc_max_quantizer = q_max;
                c.rc_target_bitrate = Self::bitrate(
                    config.width as _,
                    config.height as _,
                    config.quality,
                    #[cfg(target_os = "android")]
                    config.android_scale,
                );
                // https://chromium.googlesource.com/webm/libvpx/+/refs/heads/main/vp9/common/vp9_enums.h#29
                // https://chromium.googlesource.com/webm/libvpx/+/refs/heads/main/vp8/vp8_cx_iface.c#282
                c.g_profile = if i444 && config.codec == VpxVideoCodecId::VP9 {
                    1
                } else {
                    0
                };

                /*
                The VPX encoder supports two-pass encoding for rate control purposes.
                In two-pass encoding, the entire encoding process is performed twice.
                The first pass generates new control parameters for the second pass.

                This approach enables the best PSNR at the same bit rate.
                */

                let mut ctx = Default::default();
                call_vpx!(vpx_codec_enc_init_ver(
                    &mut ctx,
                    i,
                    &c,
                    0,
                    VPX_ENCODER_ABI_VERSION as _
                ));

                if config.codec == VpxVideoCodecId::VP9 {
                    // set encoder internal speed settings
                    // in ffmpeg, it is --speed option
                    /*
                    set to 0 or a positive value 1-16, the codec will try to adapt its
                    complexity depending on the time it spends encoding. Increasing this
                    number will make the speed go up and the quality go down.
                    Negative values mean strict enforcement of this
                    while positive values are adaptive
                    */
                    /* https://developers.google.com/media/vp9/live-encoding
                    Speed 5 to 8 should be used for live / real-time encoding.
                    Lower numbers (5 or 6) are higher quality but require more CPU power.
                    Higher numbers (7 or 8) will be lower quality but more manageable for lower latency
                    use cases and also for lower CPU power devices such as mobile.
                    */
                    call_vpx!(vpx_codec_control_(&mut ctx, VP8E_SET_CPUUSED as _, 7,));
                    // set row level multi-threading
                    /*
                    as some people in comments and below have already commented,
                    more recent versions of libvpx support -row-mt 1 to enable tile row
                    multi-threading. This can increase the number of tiles by up to 4x in VP9
                    (since the max number of tile rows is 4, regardless of video height).
                    To enable this, use -tile-rows N where N is the number of tile rows in
                    log2 units (so -tile-rows 1 means 2 tile rows and -tile-rows 2 means 4 tile
                    rows). The total number of active threads will then be equal to
                    $tile_rows * $tile_columns
                    */
                    call_vpx!(vpx_codec_control_(
                        &mut ctx,
                        VP9E_SET_ROW_MT as _,
                        1 as c_int
                    ));

                    call_vpx!(vpx_codec_control_(
                        &mut ctx,
                        VP9E_SET_TILE_COLUMNS as _,
                        4 as c_int
                    ));
                } else if config.codec == VpxVideoCodecId::VP8 {
                    // https://github.com/webmproject/libvpx/blob/972149cafeb71d6f08df89e91a0130d6a38c4b15/vpx/vp8cx.h#L172
                    // https://groups.google.com/a/webmproject.org/g/webm-discuss/c/DJhSrmfQ61M
                    call_vpx!(vpx_codec_control_(&mut ctx, VP8E_SET_CPUUSED as _, 12,));
                }

                Ok(Self {
                    ctx,
                    width: config.width as _,
                    height: config.height as _,
                    #[cfg(target_os = "android")]
                    android_scale: config.android_scale,
                    id: config.codec,
                    i444,
                    yuvfmt: EncodeYuvFormat {
                        pixfmt: if i444 { Pixfmt::I444 } else { Pixfmt::I420 },
                        w: layout.w,
                        h: layout.h,
                        stride: layout.stride.to_vec(),
                        u: layout.u,
                        v: layout.v,
                    },
                })
            }
            _ => Err(anyhow!("encoder type mismatch")),
        }
    }

    fn encode_to_message(&mut self, input: EncodeInput, ms: i64) -> ResultType<VideoFrame> {
        let mut frames = Vec::new();
        for ref frame in self
            .encode(ms, input.yuv()?, STRIDE_ALIGN)
            .with_context(|| "Failed to encode")?
        {
            frames.push(VpxEncoder::create_frame(frame));
        }
        for ref frame in self.flush().with_context(|| "Failed to flush")? {
            frames.push(VpxEncoder::create_frame(frame));
        }

        // to-do: flush periodically, e.g. 1 second
        if frames.len() > 0 {
            Ok(VpxEncoder::create_video_frame(self.id, frames))
        } else {
            Err(anyhow!("no valid frame"))
        }
    }

    fn yuvfmt(&self) -> crate::EncodeYuvFormat {
        self.yuvfmt.clone()
    }

    #[cfg(feature = "vram")]
    fn input_texture(&self) -> bool {
        false
    }

    fn set_quality(&mut self, ratio: f32) -> ResultType<()> {
        let mut c = unsafe { *self.ctx.config.enc.to_owned() };
        let (q_min, q_max) = Self::calc_q_values(ratio);
        c.rc_min_quantizer = q_min;
        c.rc_max_quantizer = q_max;
        c.rc_target_bitrate = Self::bitrate(
            self.width as _,
            self.height as _,
            ratio,
            #[cfg(target_os = "android")]
            self.android_scale,
        );
        call_vpx!(vpx_codec_enc_config_set(&mut self.ctx, &c));
        Ok(())
    }

    fn bitrate(&self) -> u32 {
        let c = unsafe { *self.ctx.config.enc.to_owned() };
        c.rc_target_bitrate
    }

    fn support_changing_quality(&self) -> bool {
        true
    }

    fn latency_free(&self) -> bool {
        true
    }

    fn is_hardware(&self) -> bool {
        false
    }

    fn disable(&self) {}
}

impl VpxEncoder {
    pub fn encode<'a>(&'a mut self, pts: i64, data: &[u8], stride_align: usize) -> Result<EncodeFrames<'a>> {
        let layout = Self::yuv_layout(self.width, self.height, self.i444, stride_align)?;
        if data.len() < layout.len {
            return Err(Error::FailedCall(format!(
                "VPX input buffer too short: {} < {}",
                data.len(),
                layout.len,
            )));
        }
        let fmt = if self.i444 {
            vpx_img_fmt::VPX_IMG_FMT_I444
        } else {
            vpx_img_fmt::VPX_IMG_FMT_I420
        };

        let mut image = Default::default();
        call_vpx_ptr!(vpx_img_wrap(
            &mut image,
            fmt,
            layout.w as _,
            layout.h as _,
            stride_align as _,
            data.as_ptr() as _,
        ));
        call_vpx!(vpx_img_set_rect(
            &mut image,
            0,
            0,
            self.width as _,
            self.height as _,
        ));

        call_vpx!(vpx_codec_encode(
            &mut self.ctx,
            &image,
            pts as _,
            1, // Duration
            0, // Flags
            VPX_DL_REALTIME as _,
        ));

        Ok(EncodeFrames {
            ctx: &mut self.ctx,
            iter: ptr::null(),
        })
    }

    /// Notify the encoder to return any pending packets
    pub fn flush<'a>(&'a mut self) -> Result<EncodeFrames<'a>> {
        call_vpx!(vpx_codec_encode(
            &mut self.ctx,
            ptr::null(),
            -1, // PTS
            1,  // Duration
            0,  // Flags
            VPX_DL_REALTIME as _,
        ));

        Ok(EncodeFrames {
            ctx: &mut self.ctx,
            iter: ptr::null(),
        })
    }

    #[inline]
    pub fn create_video_frame(
        codec_id: VpxVideoCodecId,
        frames: Vec<EncodedVideoFrame>,
    ) -> VideoFrame {
        let mut vf = VideoFrame::new();
        let vpxs = EncodedVideoFrames {
            frames: frames.into(),
            ..Default::default()
        };
        match codec_id {
            VpxVideoCodecId::VP8 => vf.set_vp8s(vpxs),
            VpxVideoCodecId::VP9 => vf.set_vp9s(vpxs),
        }
        vf
    }

    #[inline]
    fn create_frame(frame: &EncodeFrame) -> EncodedVideoFrame {
        EncodedVideoFrame {
            data: Bytes::from(frame.data.to_vec()),
            key: frame.key,
            pts: frame.pts,
            ..Default::default()
        }
    }

    fn bitrate(
        width: u32,
        height: u32,
        ratio: f32,
        #[cfg(target_os = "android")] android_scale: u16,
    ) -> u32 {
        let bitrate = base_bitrate(width, height);
        #[cfg(target_os = "android")]
        let bitrate = bitrate.saturating_mul(u32::from(android_scale).pow(2));
        let bitrate = bitrate as f32;
        (bitrate * ratio) as u32
    }

    #[inline]
    fn calc_q_values(ratio: f32) -> (u32, u32) {
        let b = (ratio * 100.0) as u32;
        let b = std::cmp::min(b, 200);
        let q_min1 = 36;
        let q_min2 = 0;
        let q_max1 = 56;
        let q_max2 = 37;

        let t = b as f32 / 200.0;

        let mut q_min: u32 = ((1.0 - t) * q_min1 as f32 + t * q_min2 as f32).round() as u32;
        let mut q_max = ((1.0 - t) * q_max1 as f32 + t * q_max2 as f32).round() as u32;

        q_min = q_min.clamp(q_min2, q_min1);
        q_max = q_max.clamp(q_max2, q_max1);

        (q_min, q_max)
    }

    fn yuv_layout(
        width: usize,
        height: usize,
        i444: bool,
        stride_align: usize,
    ) -> Result<VpxImageLayout> {
        let invalid = || Error::FailedCall("invalid VPX input layout".to_string());
        // Match libvpx's image limits before narrowing any argument for the FFI.
        let align = stride_align.max(1);
        if width == 0
            || height == 0
            || width > 0x08000000
            || height > 0x08000000
            || align > 65536
            || !align.is_power_of_two()
        {
            return Err(invalid());
        }
        let shift = usize::from(!i444);
        // I420 needs complete chroma samples even for an odd display rectangle.
        let w = width.checked_add(shift).ok_or_else(invalid)? & !shift;
        let h = height.checked_add(shift).ok_or_else(invalid)? & !shift;
        let stride = w.checked_add(align - 1).ok_or_else(invalid)? & !(align - 1);
        let chroma_stride = stride >> shift;
        let u = stride.checked_mul(h).ok_or_else(invalid)?;
        let chroma_bytes = chroma_stride.checked_mul(h >> shift).ok_or_else(invalid)?;
        let v = u.checked_add(chroma_bytes).ok_or_else(invalid)?;
        let required = v
            .checked_add(chroma_bytes)
            .filter(|size| *size <= isize::MAX as usize)
            .ok_or_else(invalid)?;
        Ok(VpxImageLayout {
            w,
            h,
            stride: [stride, chroma_stride, chroma_stride, stride],
            u,
            v,
            len: required,
        })
    }
}

impl Drop for VpxEncoder {
    fn drop(&mut self) {
        unsafe {
            let result = vpx_codec_destroy(&mut self.ctx);
            if result != VPX_CODEC_OK {
                panic!("failed to destroy vpx codec");
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EncodeFrame<'a> {
    /// Compressed data.
    pub data: &'a [u8],
    /// Whether the frame is a keyframe.
    pub key: bool,
    /// Presentation timestamp (in timebase units).
    pub pts: i64,
}

#[derive(Clone, Copy, Debug)]
pub struct VpxEncoderConfig {
    /// The width (in pixels).
    pub width: c_uint,
    /// The height (in pixels).
    pub height: c_uint,
    /// The exact captured Android display scale used to derive the encoded dimensions.
    #[cfg(target_os = "android")]
    pub android_scale: u16,
    /// The bitrate ratio
    pub quality: f32,
    /// The codec
    pub codec: VpxVideoCodecId,
    /// keyframe interval
    pub keyframe_interval: Option<usize>,
}

#[derive(Clone, Copy, Debug)]
pub struct VpxDecoderConfig {
    pub codec: VpxVideoCodecId,
}

pub struct EncodeFrames<'a> {
    ctx: &'a mut vpx_codec_ctx_t,
    iter: vpx_codec_iter_t,
}

impl<'a> Iterator for EncodeFrames<'a> {
    type Item = EncodeFrame<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            unsafe {
                let pkt = vpx_codec_get_cx_data(self.ctx, &mut self.iter);
                if pkt.is_null() {
                    return None;
                } else if (*pkt).kind == vpx_codec_cx_pkt_kind::VPX_CODEC_CX_FRAME_PKT {
                    let f = &(*pkt).data.frame;
                    return Some(Self::Item {
                        data: slice::from_raw_parts(f.buf as _, f.sz as _),
                        key: (f.flags & VPX_FRAME_IS_KEY) != 0,
                        pts: f.pts,
                    });
                } else {
                    // Ignore the packet.
                }
            }
        }
    }
}

impl VpxDecoder {
    /// Create a new decoder
    ///
    /// # Errors
    ///
    /// The function may fail if the underlying libvpx does not provide
    /// the VP9 decoder.
    pub fn new(config: VpxDecoderConfig) -> Result<Self> {
        // This is sound because `vpx_codec_ctx` is a repr(C) struct without any field that can
        // cause UB if uninitialized.
        let i = match config.codec {
            VpxVideoCodecId::VP8 => call_vpx_ptr!(vpx_codec_vp8_dx()),
            VpxVideoCodecId::VP9 => call_vpx_ptr!(vpx_codec_vp9_dx()),
        };
        let mut ctx = Default::default();
        let cfg = vpx_codec_dec_cfg_t {
            threads: codec_thread_num(64) as _,
            w: 0,
            h: 0,
        };
        /*
        unsafe {
            println!("{}", vpx_codec_get_caps(i));
        }
        */
        call_vpx!(vpx_codec_dec_init_ver(
            &mut ctx,
            i,
            &cfg,
            0,
            VPX_DECODER_ABI_VERSION as _,
        ));
        Ok(Self { ctx })
    }

    /// Feed compressed data to the decoder and borrow its last displayed image.
    ///
    /// The `data` slice is sent to the decoder
    ///
    /// It matches a call to `vpx_codec_decode`.
    pub fn decode(&mut self, data: &[u8]) -> Result<Option<Image<'_>>> {
        call_vpx!(vpx_codec_decode(
            &mut self.ctx,
            data.as_ptr(),
            data.len() as _,
            ptr::null_mut(),
            0,
        ));

        self.last_image()
    }

    /// Notify the decoder to return any pending frame
    pub fn flush(&mut self) -> Result<Option<Image<'_>>> {
        call_vpx!(vpx_codec_decode(
            &mut self.ctx,
            ptr::null(),
            0,
            ptr::null_mut(),
            0
        ));
        self.last_image()
    }

    fn last_image(&mut self) -> Result<Option<Image<'_>>> {
        let mut iter = ptr::null();
        let mut last = ptr::null_mut();
        loop {
            let image = unsafe { vpx_codec_get_frame(&mut self.ctx, &mut iter) };
            if image.is_null() {
                break;
            }
            last = image;
        }
        // libvpx owns the image until the next decode call. Borrowing the decoder
        // keeps that call, and decoder destruction, after the image's final use.
        unsafe { last.as_ref() }.map(Image::new).transpose()
    }
}

impl Drop for VpxDecoder {
    fn drop(&mut self) {
        unsafe {
            let result = vpx_codec_destroy(&mut self.ctx);
            if result != VPX_CODEC_OK {
                panic!("failed to destroy vpx codec");
            }
        }
    }
}

pub struct Image<'a> {
    inner: &'a vpx_image_t,
    chroma: Chroma,
}

impl<'a> Image<'a> {
    fn new(inner: &'a vpx_image_t) -> Result<Self> {
        let chroma = match (inner.fmt, inner.bit_depth) {
            (vpx_img_fmt::VPX_IMG_FMT_I420, 8) => Chroma::I420,
            (vpx_img_fmt::VPX_IMG_FMT_I444, 8) => Chroma::I444,
            _ => return Err(Error::UnsupportedImage {
                format: inner.fmt as u32,
                bit_depth: inner.bit_depth,
            }),
        };
        Ok(Self { inner, chroma })
    }

    #[inline]
    pub fn format(&self) -> vpx_img_fmt_t {
        self.inner().fmt
    }

    #[inline]
    pub fn inner(&self) -> &vpx_image_t {
        self.inner
    }
}

impl GoogleImage for Image<'_> {
    #[inline]
    fn width(&self) -> usize {
        self.inner().d_w as _
    }

    #[inline]
    fn height(&self) -> usize {
        self.inner().d_h as _
    }

    #[inline]
    fn stride(&self) -> [i32; 4] {
        self.inner().stride
    }

    #[inline]
    fn planes(&self) -> [*mut u8; 4] {
        self.inner().planes
    }

    fn chroma(&self) -> Chroma {
        self.chroma
    }
}

unsafe impl Send for vpx_codec_ctx_t {}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoder(codec: VpxVideoCodecId, i444: bool, width: u32, height: u32) -> VpxEncoder {
        VpxEncoder::new(
            crate::codec::EncoderCfg::VPX(VpxEncoderConfig {
                width,
                height,
                #[cfg(target_os = "android")]
                android_scale: 1,
                quality: 1.0,
                codec,
                keyframe_interval: Some(1),
            }),
            i444,
        )
        .unwrap()
    }

    fn roundtrip(encoder: &mut VpxEncoder, data: &[u8], alignment: usize) {
        let mut packets: Vec<Vec<u8>> = encoder
            .encode(1, data, alignment)
            .unwrap()
            .map(|frame| frame.data.to_vec())
            .collect();
        packets.extend(encoder.flush().unwrap().map(|frame| frame.data.to_vec()));
        assert!(!packets.is_empty());
        let mut decoder = VpxDecoder::new(VpxDecoderConfig { codec: encoder.id }).unwrap();
        let mut decoded = 0;
        for packet in packets {
            if let Some(image) = decoder.decode(&packet).unwrap() {
                assert_eq!((image.width(), image.height()), (encoder.width, encoder.height));
                assert_eq!(image.chroma(), if encoder.i444 { Chroma::I444 } else { Chroma::I420 });
                decoded += 1;
            }
        }
        assert!(decoded > 0);
    }

    #[test]
    fn padded_i420_short_inputs_are_refused_and_valid_frames_roundtrip() {
        let mut refused = Vec::new();
        for codec in [VpxVideoCodecId::VP8, VpxVideoCodecId::VP9] {
            let mut encoder = encoder(codec, false, 34, 32);
            // Keep the entire allocation initialized so the unchanged encoder can
            // demonstrate false acceptance without reading inaccessible memory.
            let data = vec![128; 64 * 32 * 3 / 2];
            for length in [34 * 32 * 3 / 2, data.len() - 1] {
                let rejected = encoder.encode(0, &data[..length], 64).is_err();
                println!("VIDEO_VPX_CASE=short codec={codec:?} chroma=420 bytes={length} required={} refused={rejected}", data.len());
                refused.push(rejected);
            }
            roundtrip(&mut encoder, &data, 64);
        }
        assert!(refused.into_iter().all(|value| value));
    }

    #[test]
    fn padded_i444_short_inputs_are_refused_and_valid_frames_roundtrip() {
        let mut encoder = encoder(VpxVideoCodecId::VP9, true, 34, 32);
        let data = vec![128; 64 * 32 * 3];
        let mut refused = Vec::new();
        for length in [34 * 32 * 3, data.len() - 1] {
            let rejected = encoder.encode(0, &data[..length], 64).is_err();
            println!("VIDEO_VPX_CASE=short codec=VP9 chroma=444 bytes={length} required={} refused={rejected}", data.len());
            refused.push(rejected);
        }
        roundtrip(&mut encoder, &data, 64);
        assert!(refused.into_iter().all(|value| value));
    }

    #[test]
    fn odd_i420_storage_is_disjoint_and_roundtrips_at_supported_alignments() {
        let mut layouts = Vec::new();
        for codec in [VpxVideoCodecId::VP8, VpxVideoCodecId::VP9] {
            for (width, height) in [(33, 31), (34, 31), (33, 32)] {
                let mut encoder = encoder(codec, false, width, height);
                let format = encoder.yuvfmt();
                let storage_width = (width as usize + 1) & !1;
                let storage_height = (height as usize + 1) & !1;
                let correct = format.w == storage_width && format.h == storage_height
                    && format.stride[0] == 64 && format.stride[1] == 32
                    && format.u == 64 * storage_height
                    && format.v == format.u + 32 * storage_height / 2;
                println!("VIDEO_VPX_CASE=odd codec={codec:?} width={width} height={height} disjoint={correct}");
                layouts.push(correct);
                for alignment in [0, 1, 2, 64] {
                    let align = alignment.max(1);
                    let stride = (storage_width + align - 1) & !(align - 1);
                    let data = vec![128; stride * storage_height * 3 / 2];
                    roundtrip(&mut encoder, &data, alignment);
                }
            }
        }
        assert!(layouts.into_iter().all(|value| value));
    }

    #[test]
    fn invalid_alignment_is_refused_before_a_valid_retry() {
        let mut encoder = encoder(VpxVideoCodecId::VP9, false, 32, 32);
        let data = vec![128; 64 * 32 * 3 / 2];
        let mut alignments = vec![3, 65537, usize::MAX];
        if let Some(truncated) = (u32::MAX as usize).checked_add(2) {
            alignments.push(truncated);
        }
        let mut refused = Vec::new();
        for alignment in alignments {
            let rejected = encoder.encode(0, &data, alignment).is_err();
            println!("VIDEO_VPX_CASE=alignment value={alignment} refused={rejected}");
            refused.push(rejected);
        }
        roundtrip(&mut encoder, &data, 64);
        assert!(refused.into_iter().all(|value| value));
    }

    #[test]
    fn realtime_encoders_deliver_current_pixels_without_end_of_stream_flush() {
        let levels = [32u8, 64, 96, 128, 160, 192, 224, 80];
        let mut immediate_cases = Vec::new();
        let mut sequence_cases = Vec::new();
        for (codec, i444) in [(VpxVideoCodecId::VP8, false),
                              (VpxVideoCodecId::VP9, false),
                              (VpxVideoCodecId::VP9, true)] {
            for message_path in [false, true] {
                let mut encoder = VpxEncoder::new(
                    crate::codec::EncoderCfg::VPX(VpxEncoderConfig {
                        width: 32,
                        height: 32,
                        quality: 1.0,
                        codec,
                        keyframe_interval: None,
                    }), i444,
                ).unwrap();
                assert!(encoder.latency_free());
                let initial_lag = unsafe { (*encoder.ctx.config.enc).g_lag_in_frames };
                let format = encoder.yuvfmt();
                let chroma_rows = if i444 { format.h } else { format.h / 2 };
                let mut data = vec![128; format.v + format.stride[2] * chroma_rows];
                let mut decoder = VpxDecoder::new(VpxDecoderConfig { codec }).unwrap();
                let mut delivered = 0;
                let mut current = 0;
                let mut pixels_and_order = true;
                let mut inspect = |packet: &[u8], pts: i64| {
                    pixels_and_order &= pts == delivered as i64 * 33;
                    let image = decoder.decode(packet).unwrap().unwrap();
                    assert_eq!((image.width(), image.height()), (32, 32));
                    assert_eq!(image.chroma(), if i444 { Chroma::I444 } else { Chroma::I420 });
                    let mut rgb = crate::ImageRgb::new(crate::ImageFormat::ARGB, 0);
                    image.to(&mut rgb).unwrap();
                    let level = levels.get(delivered).copied().unwrap_or(0);
                    let expected = (298 * (i32::from(level) - 16) + 128) >> 8;
                    assert_eq!(rgb.raw.len(), 32 * 32 * 4);
                    for pixel in rgb.raw.chunks_exact(4) {
                        pixels_and_order &= pixel[3] == 255;
                        for channel in &pixel[..3] {
                            pixels_and_order &= (i32::from(*channel) - expected).abs() <= 2;
                        }
                    }
                    delivered += 1;
                };
                for (ordinal, level) in levels.iter().enumerate() {
                    if ordinal == 4 { encoder.set_quality(0.5).unwrap(); }
                    if ordinal == 6 { encoder.set_quality(1.5).unwrap(); }
                    data[..format.u].fill(*level);
                    let packets: Vec<_> = if message_path {
                        let message = encoder.encode_to_message(EncodeInput::YUV(&data), ordinal as i64 * 33).unwrap();
                        let frames = match message.union.unwrap() {
                            hbb_common::message_proto::video_frame::Union::Vp8s(frames) => frames,
                            hbb_common::message_proto::video_frame::Union::Vp9s(frames) => frames,
                            _ => panic!("VPX encoder returned another codec"),
                        };
                        frames.frames.into_iter().map(|frame| (frame.pts, frame.data.to_vec())).collect()
                    } else {
                        encoder.encode(ordinal as i64 * 33, &data, 64).unwrap()
                            .map(|frame| (frame.pts, frame.data.to_vec())).collect()
                    };
                    println!("VIDEO_VPX_REALTIME_INPUT=observed codec={codec:?} i444={i444} message_path={message_path} ordinal={ordinal} bitrate={} packets={} pts={:?}", encoder.bitrate(), packets.len(), packets.iter().map(|packet| packet.0).collect::<Vec<_>>());
                    let is_current = packets.len() == 1 && packets[0].0 == ordinal as i64 * 33;
                    current += usize::from(is_current);
                    immediate_cases.push(is_current);
                    for (pts, packet) in packets { inspect(&packet, pts); }
                }
                let tail: Vec<_> = encoder.flush().unwrap()
                    .map(|frame| (frame.pts, frame.data.to_vec())).collect();
                for (pts, packet) in &tail { inspect(packet, *pts); }
                sequence_cases.push(delivered == levels.len() && pixels_and_order);
                println!("VIDEO_VPX_REALTIME_CASE=observed codec={codec:?} i444={i444} message_path={message_path} configured_lag={initial_lag} inputs=8 current={current} tail={} decoded={delivered} pixels_and_order={pixels_and_order} quality_changes=2", tail.len());
            }
        }
        assert_eq!(immediate_cases.len(), 48);
        assert!(immediate_cases.into_iter().all(|current| current));
        assert!(sequence_cases.into_iter().all(|exact| exact));
        println!("VIDEO_VPX_REALTIME_NATIVE=pass combinations=6 inputs=48 current=48 tail=0 pixels=checked quality_changes=12");
    }

    fn native_format_packet(format: vpx_img_fmt_t) -> Vec<u8> {
        let mut encoder = encoder(VpxVideoCodecId::VP9, true, 32, 32);
        let mut source = vec![128; 64 * 32 * 3 * 2];
        let mut image = vpx_image_t::default();
        assert!(!unsafe {
            vpx_img_wrap(&mut image, format, 32, 32, 64, source.as_mut_ptr())
        }.is_null());
        assert_eq!(image.fmt, format);
        assert_eq!(image.bit_depth, 8);
        assert_eq!(unsafe {
            vpx_codec_encode(&mut encoder.ctx, &image, 0, 1, 0, VPX_DL_REALTIME as _)
        }, VPX_CODEC_OK);
        let mut packets: Vec<Vec<u8>> = EncodeFrames {
            ctx: &mut encoder.ctx,
            iter: ptr::null(),
        }.map(|frame| frame.data.to_vec()).collect();
        packets.extend(encoder.flush().unwrap().map(|frame| frame.data.to_vec()));
        assert_eq!(packets.len(), 1);
        packets.remove(0)
    }

    #[test]
    fn unsupported_vp9_chroma_is_refused_before_supported_retry() {
        let mut refused = Vec::new();
        let mut retries = 0;
        for (name, format) in [
            ("I422", vpx_img_fmt::VPX_IMG_FMT_I422),
            ("I440", vpx_img_fmt::VPX_IMG_FMT_I440),
        ] {
            let packet = native_format_packet(format);
            assert!(packet.len() < 4096);
            let mut packet_hex = String::with_capacity(packet.len() * 2);
            for byte in &packet {
                use std::fmt::Write;
                write!(&mut packet_hex, "{byte:02x}").unwrap();
            }
            println!("VIDEO_VPX_FORMAT_PACKET=hex format={name} bytes={} data={packet_hex}", packet.len());
            let mut decoder = VpxDecoder::new(VpxDecoderConfig { codec: VpxVideoCodecId::VP9 }).unwrap();
            let rejected = match decoder.decode(&packet) {
                Err(Error::UnsupportedImage { format: found, bit_depth }) => {
                    assert_eq!((found, bit_depth), (format as u32, 8));
                    true
                }
                Ok(Some(image)) => {
                    assert_eq!((image.format(), image.inner().bit_depth), (format, 8));
                    false
                }
                _ => panic!("native VP9 packet did not reach decoded-image admission"),
            };
            println!("VIDEO_VPX_FORMAT_CASE=bitstream format={name} bits=8 refused={rejected} packet_bytes={}", packet.len());
            refused.push(rejected);
            for i444 in [false, true] {
                let mut producer = encoder(VpxVideoCodecId::VP9, i444, 32, 32);
                let layout = producer.yuvfmt();
                let rows = if i444 { layout.h } else { layout.h / 2 };
                let source = vec![128; layout.v + layout.stride[2] * rows];
                let mut packets: Vec<Vec<u8>> = producer.encode(0, &source, 64).unwrap()
                    .map(|frame| frame.data.to_vec()).collect();
                packets.extend(producer.flush().unwrap().map(|frame| frame.data.to_vec()));
                assert_eq!(packets.len(), 1);
                let image = decoder.decode(&packets[0]).unwrap().unwrap();
                assert_eq!(image.chroma(), if i444 { Chroma::I444 } else { Chroma::I420 });
                let mut rgb = crate::ImageRgb::new(crate::ImageFormat::ARGB, 64);
                image.to(&mut rgb).unwrap();
                assert_eq!((rgb.w, rgb.h, rgb.raw.len()), (32, 32, 32 * 32 * 4));
                assert!(rgb.raw.chunks_exact(4).all(|pixel| pixel == [130, 130, 130, 255]));
                retries += 1;
                println!("VIDEO_VPX_FORMAT_CASE=retry after={name} i444={i444} pixels=exact");
            }
            if let Some(image) = decoder.flush().unwrap() {
                assert_eq!(image.chroma(), Chroma::I444);
            }
        }
        assert_eq!(retries, 4);
        assert!(refused.into_iter().all(|value| value));
        println!("VIDEO_VPX_FORMAT_NATIVE=pass bitstreams=2 refused=2 retries=4 pixels=exact");
    }

    #[test]
    fn native_image_descriptor_admission_is_exact() {
        let mut source = vec![128; 64 * 32 * 3 * 2];
        let mut correct = Vec::new();
        let mut allowed = 0;
        for (name, format, supported) in [
            ("I420", vpx_img_fmt::VPX_IMG_FMT_I420, true),
            ("I444", vpx_img_fmt::VPX_IMG_FMT_I444, true),
            ("I422", vpx_img_fmt::VPX_IMG_FMT_I422, false),
            ("I440", vpx_img_fmt::VPX_IMG_FMT_I440, false),
            ("I42016", vpx_img_fmt::VPX_IMG_FMT_I42016, false),
            ("I44416", vpx_img_fmt::VPX_IMG_FMT_I44416, false),
            ("I42216", vpx_img_fmt::VPX_IMG_FMT_I42216, false),
            ("I44016", vpx_img_fmt::VPX_IMG_FMT_I44016, false),
        ] {
            let mut image = vpx_image_t::default();
            assert!(!unsafe {
                vpx_img_wrap(&mut image, format, 32, 32, 64, source.as_mut_ptr())
            }.is_null());
            let admitted = Image::new(&image).is_ok();
            allowed += usize::from(admitted);
            correct.push(admitted == supported);
            println!("VIDEO_VPX_FORMAT_CASE=descriptor format={name} bits={} allowed={admitted} correct={}", image.bit_depth, admitted == supported);
        }
        for depth in [0, 10, 12, 16] {
            let mut image = vpx_image_t::default();
            assert!(!unsafe {
                vpx_img_wrap(&mut image, vpx_img_fmt::VPX_IMG_FMT_I420, 32, 32, 64, source.as_mut_ptr())
            }.is_null());
            // Fault the sample-depth metadata on an actual native descriptor.
            // This is supplementary to the real compressed VP9 packet cases.
            image.bit_depth = depth;
            let admitted = Image::new(&image).is_ok();
            allowed += usize::from(admitted);
            correct.push(!admitted);
            println!("VIDEO_VPX_FORMAT_CASE=descriptor format=I420 bits={depth} allowed={admitted} correct={}", !admitted);
        }
        assert_eq!(correct.len(), 12);
        assert!(correct.into_iter().all(|value| value));
        assert_eq!(allowed, 2);
        println!("VIDEO_VPX_FORMAT_NATIVE=pass descriptors=12 allowed=2 refused=10");
    }
}
