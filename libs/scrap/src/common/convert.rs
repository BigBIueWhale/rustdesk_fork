#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(improper_ctypes)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/yuv_ffi.rs"));

#[cfg(not(target_os = "ios"))]
use crate::PixelBuffer;
use crate::{generate_call_macro, EncodeYuvFormat, TraitPixelBuffer};
use hbb_common::{anyhow::anyhow, bail, log, ResultType};

generate_call_macro!(call_yuv, false);

#[cfg(not(target_os = "ios"))]
struct YuvConversionLayout {
    output_len: usize,
    intermediate_len: Option<usize>,
    intermediate_stride: usize,
}

#[cfg(not(target_os = "ios"))]
impl YuvConversionLayout {
    fn new(captured: &PixelBuffer, format: EncodeYuvFormat) -> ResultType<Self> {
        use crate::Pixfmt::*;

        let source_format = captured.pixfmt();
        if !matches!(source_format, BGRA | RGBA | RGB565LE)
            || !matches!(format.pixfmt, I420 | NV12 | I444)
        {
            bail!("unsupported pixfmt conversion: {source_format:?} -> {:?}", format.pixfmt);
        }
        let width = captured.width();
        let height = captured.height();
        let native_max = std::os::raw::c_int::MAX as usize;
        if [width, height, format.w, format.h]
            .iter()
            .any(|&dimension| dimension == 0 || dimension > native_max)
            || width != format.w
            || height != format.h
        {
            bail!("invalid YUV conversion dimensions");
        }
        let source_stride = captured.stride();
        let source_row = width
            .checked_mul(source_format.bytes_per_pixel())
            .ok_or_else(|| anyhow!("YUV source row size overflow"))?;
        let source_len = source_stride
            .checked_mul(height)
            .ok_or_else(|| anyhow!("YUV source size overflow"))?;
        if source_stride < source_row
            || source_stride > native_max
            || captured.data().len() < source_len
        {
            bail!("invalid YUV source layout");
        }
        if format.buffer_len == 0 || format.buffer_len > isize::MAX as usize {
            bail!("invalid YUV output buffer length");
        }
        let chroma_width = (format.w + 1) / 2;
        let chroma_height = (format.h + 1) / 2;
        let mut planes = [
            (0, format.stride[0], format.w, format.h),
            (format.u, format.stride[1], chroma_width, chroma_height),
            (format.v, format.stride[2], chroma_width, chroma_height),
        ];
        let plane_count = match format.pixfmt {
            NV12 => {
                planes[1].2 = chroma_width * 2;
                2
            }
            I444 => {
                planes[1].2 = format.w;
                planes[1].3 = format.h;
                planes[2].2 = format.w;
                planes[2].3 = format.h;
                3
            }
            _ => 3,
        };
        let mut ranges = [(0, 0); 3];
        for (index, &(offset, stride, row_bytes, rows)) in planes[..plane_count].iter().enumerate() {
            if stride < row_bytes || stride > native_max {
                bail!("invalid YUV plane stride");
            }
            let end = stride
                .checked_mul(rows)
                .and_then(|bytes| offset.checked_add(bytes))
                .filter(|&end| end <= format.buffer_len)
                .ok_or_else(|| anyhow!("YUV plane exceeds output buffer"))?;
            for &(start, previous_end) in &ranges[..index] {
                if offset < previous_end && start < end {
                    bail!("overlapping YUV planes");
                }
            }
            ranges[index] = (offset, end);
        }
        let (intermediate_len, intermediate_stride) = match (source_format, format.pixfmt) {
            (RGB565LE, NV12 | I444) => {
                let stride = width
                    .checked_mul(4)
                    .filter(|&stride| stride <= native_max)
                    .ok_or_else(|| anyhow!("YUV intermediate stride overflow"))?;
                let len = stride
                    .checked_mul(height)
                    .ok_or_else(|| anyhow!("YUV intermediate size overflow"))?;
                (Some(len), stride)
            }
            (RGBA, I444) => (Some(captured.data().len()), source_stride),
            _ => (None, 0),
        };
        Ok(Self {
            output_len: format.buffer_len,
            intermediate_len,
            intermediate_stride,
        })
    }

    fn prepare(&self, output: &mut Vec<u8>, intermediate: &mut Vec<u8>) -> ResultType<()> {
        output.try_reserve_exact(self.output_len.saturating_sub(output.len()))?;
        if let Some(len) = self.intermediate_len {
            intermediate.try_reserve_exact(len.saturating_sub(intermediate.len()))?;
        }
        output.resize(self.output_len, 0);
        if let Some(len) = self.intermediate_len {
            intermediate.resize(len, 0);
        }
        Ok(())
    }
}

#[cfg(not(target_os = "ios"))]
pub fn convert_to_yuv(
    captured: &PixelBuffer,
    dst_fmt: EncodeYuvFormat,
    dst: &mut Vec<u8>,
    mid_data: &mut Vec<u8>,
) -> ResultType<()> {
    let layout = YuvConversionLayout::new(captured, dst_fmt)?;
    layout.prepare(dst, mid_data)?;
    let src = captured.data();
    let src_stride = captured.stride();
    let src_pixfmt = captured.pixfmt();
    let src_width = captured.width();
    let src_height = captured.height();
    let unsupported = || format!(
        "unsupported pixfmt conversion: {src_pixfmt:?} -> {:?}",
        dst_fmt.pixfmt
    );

    match (src_pixfmt, dst_fmt.pixfmt) {
        (crate::Pixfmt::BGRA, crate::Pixfmt::I420)
        | (crate::Pixfmt::RGBA, crate::Pixfmt::I420)
        | (crate::Pixfmt::RGB565LE, crate::Pixfmt::I420) => {
            let dst_stride_y = dst_fmt.stride[0];
            let dst_stride_u = dst_fmt.stride[1];
            let dst_stride_v = dst_fmt.stride[2];
            let dst_y = dst.as_mut_ptr();
            let dst_u = dst[dst_fmt.u..].as_mut_ptr();
            let dst_v = dst[dst_fmt.v..].as_mut_ptr();
            let f = match src_pixfmt {
                crate::Pixfmt::BGRA => ARGBToI420,
                crate::Pixfmt::RGBA => ABGRToI420,
                crate::Pixfmt::RGB565LE => RGB565ToI420,
                _ => bail!(unsupported()),
            };
            call_yuv!(f(
                src.as_ptr(),
                src_stride as _,
                dst_y,
                dst_stride_y as _,
                dst_u,
                dst_stride_u as _,
                dst_v,
                dst_stride_v as _,
                src_width as _,
                src_height as _,
            ));
        }
        (crate::Pixfmt::BGRA, crate::Pixfmt::NV12)
        | (crate::Pixfmt::RGBA, crate::Pixfmt::NV12)
        | (crate::Pixfmt::RGB565LE, crate::Pixfmt::NV12) => {
            let dst_stride_y = dst_fmt.stride[0];
            let dst_stride_uv = dst_fmt.stride[1];
            let dst_y = dst.as_mut_ptr();
            let dst_uv = dst[dst_fmt.u..].as_mut_ptr();
            let (input, input_stride) = match src_pixfmt {
                crate::Pixfmt::BGRA => (src.as_ptr(), src_stride),
                crate::Pixfmt::RGBA => (src.as_ptr(), src_stride),
                crate::Pixfmt::RGB565LE => {
                    let mid_stride = layout.intermediate_stride;
                    call_yuv!(RGB565ToARGB(
                        src.as_ptr(),
                        src_stride as _,
                        mid_data.as_mut_ptr(),
                        mid_stride as _,
                        src_width as _,
                        src_height as _,
                    ));
                    (mid_data.as_ptr(), mid_stride)
                }
                _ => bail!(unsupported()),
            };
            let f = match src_pixfmt {
                crate::Pixfmt::BGRA => ARGBToNV12,
                crate::Pixfmt::RGBA => ABGRToNV12,
                crate::Pixfmt::RGB565LE => ARGBToNV12,
                _ => bail!(unsupported()),
            };
            call_yuv!(f(
                input,
                input_stride as _,
                dst_y,
                dst_stride_y as _,
                dst_uv,
                dst_stride_uv as _,
                src_width as _,
                src_height as _,
            ));
        }
        (crate::Pixfmt::BGRA, crate::Pixfmt::I444)
        | (crate::Pixfmt::RGBA, crate::Pixfmt::I444)
        | (crate::Pixfmt::RGB565LE, crate::Pixfmt::I444) => {
            let dst_stride_y = dst_fmt.stride[0];
            let dst_stride_u = dst_fmt.stride[1];
            let dst_stride_v = dst_fmt.stride[2];
            let dst_y = dst.as_mut_ptr();
            let dst_u = dst[dst_fmt.u..].as_mut_ptr();
            let dst_v = dst[dst_fmt.v..].as_mut_ptr();
            let (input, input_stride) = match src_pixfmt {
                crate::Pixfmt::BGRA => (src.as_ptr(), src_stride),
                crate::Pixfmt::RGBA => {
                    call_yuv!(ABGRToARGB(
                        src.as_ptr(),
                        src_stride as _,
                        mid_data.as_mut_ptr(),
                        src_stride as _,
                        src_width as _,
                        src_height as _,
                    ));
                    (mid_data.as_ptr(), src_stride)
                }
                crate::Pixfmt::RGB565LE => {
                    let mid_stride = layout.intermediate_stride;
                    call_yuv!(RGB565ToARGB(
                        src.as_ptr(),
                        src_stride as _,
                        mid_data.as_mut_ptr(),
                        mid_stride as _,
                        src_width as _,
                        src_height as _,
                    ));
                    (mid_data.as_ptr(), mid_stride)
                }
                _ => bail!(unsupported()),
            };

            call_yuv!(ARGBToI444(
                input,
                input_stride as _,
                dst_y,
                dst_stride_y as _,
                dst_u,
                dst_stride_u as _,
                dst_v,
                dst_stride_v as _,
                src_width as _,
                src_height as _,
            ));
        }
        _ => {
            bail!(unsupported());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "ios"))]
/// Convert a captured screen or camera frame to tightly packed, opaque RGBA.
pub fn convert_to_rgba(pixbuf: &PixelBuffer<'_>) -> ResultType<Vec<u8>> {
    let format = pixbuf.pixfmt();
    let bytes_per_pixel = match format {
        crate::Pixfmt::RGBA | crate::Pixfmt::BGRA => 4,
        crate::Pixfmt::RGB565LE => 2,
        _ => bail!("unsupported screenshot pixel format: {format:?}"),
    };
    let width = pixbuf.width();
    let height = pixbuf.height();
    if width == 0 || height == 0 {
        bail!("empty screenshot pixel buffer");
    }
    let stride = pixbuf.stride();
    let row_bytes = width
        .checked_mul(bytes_per_pixel)
        .ok_or_else(|| anyhow!("screenshot source row size overflow"))?;
    let required = stride
        .checked_mul(height - 1)
        .and_then(|size| size.checked_add(row_bytes))
        .ok_or_else(|| anyhow!("screenshot source size overflow"))?;
    let source = pixbuf.data();
    if stride < row_bytes || source.len() < required {
        bail!("invalid screenshot pixel buffer layout");
    }
    let output_len = width
        .checked_mul(height)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or_else(|| anyhow!("screenshot output size overflow"))?;
    let mut rgba = Vec::new();
    rgba.try_reserve_exact(output_len)?;
    for y in 0..height {
        let row = &source[y * stride..][..row_bytes];
        match format {
            crate::Pixfmt::RGBA => rgba.extend_from_slice(row),
            crate::Pixfmt::BGRA => {
                for pixel in row.chunks_exact(4) {
                    rgba.extend_from_slice(&[pixel[2], pixel[1], pixel[0], pixel[3]]);
                }
            }
            crate::Pixfmt::RGB565LE => {
                for pixel in row.chunks_exact(2) {
                    let value = u16::from_le_bytes([pixel[0], pixel[1]]);
                    let r = (value >> 11) as u8;
                    let g = ((value >> 5) & 0x3f) as u8;
                    let b = (value & 0x1f) as u8;
                    rgba.extend_from_slice(&[
                        (r << 3) | (r >> 2),
                        (g << 2) | (g >> 4),
                        (b << 3) | (b >> 2),
                        255,
                    ]);
                }
            }
            _ => bail!("unsupported screenshot pixel format: {format:?}"),
        }
    }
    // Four-byte screen-capture formats can carry unused alpha bytes.
    for pixel in rgba.chunks_exact_mut(4) {
        pixel[3] = 255;
    }
    Ok(rgba)
}

#[cfg(all(test, x11))]
mod tests {
    use super::*;
    use crate::Pixfmt;

    const COLORS: [[u8; 4]; 4] = [
        [13, 29, 211, 7],
        [241, 83, 5, 128],
        [0, 255, 67, 255],
        [193, 0, 109, 42],
    ];

    fn packed_case(format: Pixfmt, width: usize, height: usize, padding: usize) -> bool {
        let stride = width * 4 + padding;
        let mut source = vec![0xd3; stride * height];
        let mut expected = Vec::new();
        for y in 0..height {
            for x in 0..width {
                let color = COLORS[(y * width + x) % COLORS.len()];
                expected.extend_from_slice(&[color[0], color[1], color[2], 255]);
                let pixel = if format == Pixfmt::BGRA {
                    [color[2], color[1], color[0], color[3]]
                } else {
                    color
                };
                source[y * stride + x * 4..][..4].copy_from_slice(&pixel);
            }
        }
        let pixels = PixelBuffer::new(&source, format, width, height, stride).unwrap();
        let output = convert_to_rgba(&pixels).unwrap();
        let exact = output == expected;
        println!("SCREENSHOT_PIXELS_CASE=packed format={format:?} width={width} height={height} padding={padding} bytes={} exact={exact}", output.len());
        exact
    }

    #[test]
    fn padded_rgba_screenshots_keep_exact_pixels() {
        let mut outcomes = Vec::new();
        for width in [1, 2, 3, 17] {
            for height in [1, 3] {
                for padding in [4, 12] {
                    outcomes.push(packed_case(Pixfmt::RGBA, width, height, padding));
                }
            }
        }
        assert!(outcomes.into_iter().all(|exact| exact));
    }

    #[test]
    fn packed_and_padded_bgra_screenshots_preserve_pixels() {
        let mut outcomes = Vec::new();
        for width in [1, 2, 17] {
            for height in [1, 3] {
                outcomes.push(packed_case(Pixfmt::RGBA, width, height, 0));
                for padding in [0, 4, 12] {
                    outcomes.push(packed_case(Pixfmt::BGRA, width, height, padding));
                }
            }
        }
        assert!(outcomes.into_iter().all(|exact| exact));
    }

    #[test]
    fn rgb565_screenshots_expand_all_visible_pixels() {
        let colors = [
            (0xf800u16, [255, 0, 0, 255]),
            (0x07e0, [0, 255, 0, 255]),
            (0x001f, [0, 0, 255, 255]),
            (0xffff, [255, 255, 255, 255]),
            (0x0000, [0, 0, 0, 255]),
            (0xf81f, [255, 0, 255, 255]),
            (0xffe0, [255, 255, 0, 255]),
            (0x07ff, [0, 255, 255, 255]),
        ];
        let mut outcomes = Vec::new();
        for width in [1, 3, 5, 17] {
            for height in [1, 2] {
                for padding in [0, 2] {
                    let stride = width * 2 + padding;
                    let mut source = vec![0xd3; stride * height];
                    let mut expected = Vec::new();
                    for y in 0..height {
                        for x in 0..width {
                            let (pixel, rgba) = colors[(y * width + x) % colors.len()];
                            source[y * stride + x * 2..][..2].copy_from_slice(&pixel.to_le_bytes());
                            expected.extend_from_slice(&rgba);
                        }
                    }
                    let pixels = PixelBuffer::new(&source, Pixfmt::RGB565LE, width, height, stride).unwrap();
                    let result = std::panic::catch_unwind(|| convert_to_rgba(&pixels));
                    let exact = matches!(&result, Ok(Ok(output)) if *output == expected);
                    println!("SCREENSHOT_PIXELS_CASE=rgb565 width={width} height={height} padding={padding} panicked={} exact={exact}", result.is_err());
                    outcomes.push(exact);
                }
            }
        }
        assert!(outcomes.into_iter().all(|exact| exact));
    }

    #[test]
    fn planar_screenshot_inputs_are_refused() {
        let source = [0xd3; 32];
        let mut outcomes = Vec::new();
        for format in [Pixfmt::I420, Pixfmt::I444, Pixfmt::NV12] {
            let pixels = PixelBuffer::new(&source, format, 3, 2, 16).unwrap();
            let refused = convert_to_rgba(&pixels).is_err();
            println!("SCREENSHOT_PIXELS_CASE=planar format={format:?} refused={refused}");
            outcomes.push(refused);
        }
        assert!(outcomes.into_iter().all(|refused| refused));
    }

    fn capture_png(depth: u8, expected_format: Pixfmt) {
        use crate::TraitCapturer;
        use crate::test_allocator::{arm, refusals, take_armed};
        use std::io::ErrorKind;
        let display = crate::Display::primary().unwrap();
        let mut capturer = crate::Capturer::new(display).unwrap();
        let before = refusals();
        println!("SCREENSHOT_X11_ALLOC_START=observed depth={depth} phase=first-capture");
        arm();
        match capturer.frame(std::time::Duration::from_millis(100)) {
            Err(error) => assert_eq!(error.kind(), ErrorKind::OutOfMemory),
            Ok(_) => panic!("capture cache allocation refusal was not reported"),
        }
        assert!(!take_armed());
        assert_eq!(refusals(), before + 1);
        let frame = capturer.frame(std::time::Duration::from_millis(100)).unwrap();
        let crate::Frame::PixelBuffer(pixels) = frame else {
            panic!("X11 screenshot capture returned a texture");
        };
        assert_eq!((pixels.width(), pixels.height()), (129, 33));
        assert_eq!(pixels.pixfmt(), expected_format);
        let rgba = convert_to_rgba(&pixels).unwrap();
        assert_eq!(rgba.len(), 129 * 33 * 4);
        let source_alpha_zero = if depth == 24 {
            pixels.data().chunks_exact(4).filter(|pixel| pixel[3] == 0).count()
        } else {
            0
        };
        let stride = pixels.stride();
        drop(pixels);
        arm();
        match capturer.frame(std::time::Duration::from_millis(100)) {
            Err(error) => assert_eq!(error.kind(), ErrorKind::WouldBlock),
            Ok(_) => panic!("unchanged native capture was not suppressed"),
        }
        assert!(take_armed());
        assert_eq!(refusals(), before + 1);

        let mut cache = vec![0x52, 0x44, 0xff];
        let original_pointer = cache.as_ptr();
        let original_capacity = cache.capacity();
        arm();
        assert_eq!(crate::would_block_if_equal(&mut cache, &rgba).unwrap_err().kind(),
                   ErrorKind::OutOfMemory);
        assert!(!take_armed());
        assert_eq!(refusals(), before + 2);
        assert_eq!(cache, [0x52, 0x44, 0xff]);
        assert_eq!(cache.as_ptr(), original_pointer);
        assert_eq!(cache.capacity(), original_capacity);
        crate::would_block_if_equal(&mut cache, &rgba).unwrap();
        assert_eq!(cache, rgba);
        for (data, equal) in [(&rgba[..], true), (&rgba[..3], false),
                              (&rgba[..], false), (&[][..], false), (&[][..], true)] {
            arm();
            let result = crate::would_block_if_equal(&mut cache, data);
            assert!(take_armed());
            if equal {
                assert_eq!(result.unwrap_err().kind(), ErrorKind::WouldBlock);
            } else {
                result.unwrap();
            }
            assert_eq!(cache, data);
        }
        assert_eq!(refusals(), before + 2);
        println!("SCREENSHOT_X11_ALLOC_NATIVE=pass depth={depth} refusals=2 first=OutOfMemory growth=OutOfMemory preserved=true retry=pass unchanged=WouldBlock warmed=allocation-free");
        let path = std::env::var("SCREENSHOT_X11_PNG_PATH").unwrap();
        assert_eq!(path, format!("/tmp/video-vpx/screenshot-{depth}.png"));
        let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
        let mut encoder = repng::Options::smallest(129, 33).build(file).unwrap();
        encoder.write(&rgba).unwrap();
        encoder.finish().unwrap();
        drop(encoder);
        println!("SCREENSHOT_X11_PNG=created depth={depth} width=129 height=33 stride={stride} format={expected_format:?} bytes={} source_alpha_zero={source_alpha_zero}", std::fs::metadata(path).unwrap().len());
    }

    #[test]
    fn native_x11_capture_24_png() {
        capture_png(24, Pixfmt::BGRA);
    }

    #[test]
    fn native_x11_capture_16_png() {
        capture_png(16, Pixfmt::RGB565LE);
    }
}
