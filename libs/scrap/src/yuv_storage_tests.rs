use crate::{convert_to_yuv, test_allocator, EncodeYuvFormat, PixelBuffer, Pixfmt};
use std::collections::TryReserveError;

fn format(destination: Pixfmt) -> EncodeYuvFormat {
    EncodeYuvFormat {
        pixfmt: destination, w: 3, h: 2,
        stride: match destination {
            Pixfmt::I420 => [8, 4, 4],
            Pixfmt::NV12 => [8, 8, 0],
            Pixfmt::I444 => [8, 8, 8],
            _ => unreachable!(),
        },
        u: 16,
        v: if destination == Pixfmt::I420 { 20 } else { 32 },
        buffer_len: if destination == Pixfmt::I444 { 48 } else { 24 },
    }
}

fn assert_black(data: &[u8], layout: EncodeYuvFormat) {
    let plane = |offset: usize, stride: usize, width: usize, height: usize, value| {
        for row in 0..height {
            assert!(data[offset + row * stride..][..width].iter().all(|&v| v == value));
        }
    };
    plane(0, 8, 3, 2, 16);
    match layout.pixfmt {
        Pixfmt::I420 => { plane(16, 4, 2, 1, 128); plane(20, 4, 2, 1, 128); }
        Pixfmt::NV12 => plane(16, 8, 4, 1, 128),
        Pixfmt::I444 => { plane(16, 8, 3, 2, 128); plane(32, 8, 3, 2, 128); }
        _ => unreachable!(),
    }
    assert_eq!(data.len(), if layout.pixfmt == Pixfmt::I444 { 48 } else { 24 });
}

fn allocation_failure(output_failure: bool) {
    let pairs: &[(Pixfmt, Pixfmt)] = if output_failure {
        &[(Pixfmt::BGRA, Pixfmt::I420), (Pixfmt::BGRA, Pixfmt::NV12), (Pixfmt::BGRA, Pixfmt::I444),
          (Pixfmt::RGBA, Pixfmt::I420), (Pixfmt::RGBA, Pixfmt::NV12), (Pixfmt::RGBA, Pixfmt::I444),
          (Pixfmt::RGB565LE, Pixfmt::I420), (Pixfmt::RGB565LE, Pixfmt::NV12), (Pixfmt::RGB565LE, Pixfmt::I444)]
    } else {
        &[(Pixfmt::RGB565LE, Pixfmt::NV12), (Pixfmt::RGBA, Pixfmt::I444), (Pixfmt::RGB565LE, Pixfmt::I444)]
    };
    let stage = if output_failure { "output" } else { "intermediate" };
    let data = [0u8; 32];
    let initial = test_allocator::refusals();
    for &(source, destination) in pairs {
        let stride = if source == Pixfmt::RGB565LE { 8 } else { 16 };
        let pixels = PixelBuffer::new(&data[..stride * 2], source, 3, 2, stride).unwrap();
        let layout = format(destination);
        let mut output = if output_failure { Vec::new() } else { Vec::with_capacity(12288) };
        output.extend_from_slice(b"old frame");
        let mut intermediate = b"old mid".to_vec();
        let output_identity = (output.as_ptr(), output.capacity());
        let intermediate_identity = (intermediate.as_ptr(), intermediate.capacity());
        let before = test_allocator::refusals();
        test_allocator::arm();
        let result = convert_to_yuv(&pixels, layout, &mut output, &mut intermediate);
        let unused = test_allocator::take_armed();
        assert!(!unused);
        assert_eq!(test_allocator::refusals(), before + 1);
        assert!(result.unwrap_err().downcast_ref::<TryReserveError>().is_some());
        assert_eq!(output, b"old frame");
        assert_eq!(intermediate, b"old mid");
        assert_eq!((output.as_ptr(), output.capacity()), output_identity);
        assert_eq!((intermediate.as_ptr(), intermediate.capacity()), intermediate_identity);
        convert_to_yuv(&pixels, layout, &mut output, &mut intermediate).unwrap();
        assert_black(&output, layout);
        output.fill(0xa5);
        intermediate.fill(0xa5);
        test_allocator::arm();
        let result = convert_to_yuv(&pixels, layout, &mut output, &mut intermediate);
        let unused = test_allocator::take_armed();
        assert!(unused);
        result.unwrap();
        assert_black(&output, layout);
        println!("CAPTURE_STORAGE_CASE=pass stage={stage} source={source:?} destination={destination:?} state=preserved retry=pass warmed=allocation-free");
    }
    assert_eq!(test_allocator::refusals(), initial + pairs.len());
    println!("CAPTURE_METADATA_NATIVE=pass operation={stage} combinations={} refusals={} pixels=exact state=preserved retries={} warmed=allocation-free", pairs.len(), pairs.len(), pairs.len());
}

#[test]
fn output_allocation_failures_preserve_buffers_and_retry() { allocation_failure(true); }

#[test]
fn intermediate_allocation_failures_preserve_buffers_and_retry() { allocation_failure(false); }

#[test]
fn plane_layout_is_checked_and_v_stride_is_independent() {
    let data = [0u8; 64];
    let pixels = PixelBuffer::new(&data, Pixfmt::BGRA, 3, 4, 16).unwrap();
    let layout = EncodeYuvFormat { pixfmt: Pixfmt::I420, w: 3, h: 4, stride: [8, 4, 8], u: 32, v: 40, buffer_len: 56 };
    let mut output = vec![0xa5; 64];
    convert_to_yuv(&pixels, layout, &mut output, &mut Vec::new()).unwrap();
    println!("CAPTURE_LAYOUT_OBSERVED=v_plane stride_u=4 stride_v=8 first={} second={}", output[40], output[48]);
    assert_eq!(output[48], 128, "V row must use the V stride");
    for (offset, stride, width, height, value) in [(0, 8, 3, 4, 16), (32, 4, 2, 2, 128), (40, 8, 2, 2, 128)] {
        for row in 0..height {
            assert!(output[offset + row * stride..][..width].iter().all(|&v| v == value));
        }
    }
    assert_eq!(output.len(), 56);
    for case in 0..19 {
        let mut invalid = layout;
        let name = match case {
            0 => { invalid.w = 0; "zero-width" }
            1 => { invalid.h = 0; "zero-height" }
            2 => { invalid.w = 2; "narrow-destination" }
            3 => { invalid.h = 3; "short-destination" }
            4 => { invalid.stride[0] = 2; "short-y-stride" }
            5 => { invalid.stride[1] = 1; "short-u-stride" }
            6 => { invalid.stride[2] = 1; "short-v-stride" }
            7 => { invalid.u = 8; "overlapping-y-u" }
            8 => { invalid.v = 36; "overlapping-u-v" }
            9 => { invalid.u = usize::MAX; "u-offset-overflow" }
            10 => { invalid.v = usize::MAX; "v-offset-overflow" }
            11 => { invalid.w = usize::MAX; "width-outside-native-int" }
            12 => { invalid.h = usize::MAX; "height-outside-native-int" }
            13 => { invalid.stride[0] = usize::MAX; "stride-outside-native-int" }
            14 => { invalid.pixfmt = Pixfmt::NV12; invalid.stride[1] = 3; "short-nv12-stride" }
            15 => { invalid.pixfmt = Pixfmt::I444; invalid.stride = [8, 4, 2]; invalid.v = 48; "short-i444-stride" }
            16 => { invalid.buffer_len = 0; "zero-buffer-length" }
            17 => { invalid.buffer_len = 55; "short-buffer-length" }
            18 => { invalid.buffer_len = usize::MAX; "buffer-length-outside-address-space" }
            _ => unreachable!(),
        };
        let mut output = b"old frame".to_vec();
        let mut intermediate = b"old mid".to_vec();
        let identities = (output.as_ptr(), output.capacity(), intermediate.as_ptr(), intermediate.capacity());
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            convert_to_yuv(&pixels, invalid, &mut output, &mut intermediate)
        }));
        assert!(matches!(attempt, Ok(Err(_))), "{name}");
        assert_eq!(output, b"old frame");
        assert_eq!(intermediate, b"old mid");
        assert_eq!((output.as_ptr(), output.capacity(), intermediate.as_ptr(), intermediate.capacity()), identities);
        println!("CAPTURE_LAYOUT_REFUSAL=pass case={name} buffers=preserved outcome=error");
    }
    println!("CAPTURE_METADATA_NATIVE=pass operation=layout independent_v_stride=true invalid=19 storage_bytes=56 pixels=exact state=preserved");
}

#[test]
fn captured_frame_must_match_encoder_viewport_before_conversion() {
    use crate::codec::{EncoderApi, EncoderCfg};
    use crate::{Frame, GoogleImage, ImageFormat, ImageRgb, VpxDecoder, VpxDecoderConfig,
                VpxEncoder, VpxEncoderConfig, VpxVideoCodecId};

    fn decoded(encoder: &mut VpxEncoder, decoder: &mut VpxDecoder, pts: i64, yuv: &[u8]) -> Vec<u8> {
        let packets: Vec<Vec<u8>> = encoder.encode(pts, yuv, 64).unwrap()
            .map(|frame| frame.data.to_vec()).collect();
        assert_eq!(packets.len(), 1);
        let image = decoder.decode(&packets[0]).unwrap().unwrap();
        assert_eq!((image.width(), image.height()), (33, 31));
        let mut rgb = ImageRgb::new(ImageFormat::ARGB, 0);
        image.to(&mut rgb).unwrap();
        assert_eq!(rgb.raw.len(), 33 * 31 * 4);
        rgb.raw
    }

    fn white_error(rgb: &[u8]) -> u8 {
        let mut error = 0;
        for pixel in rgb.chunks_exact(4) {
            assert_eq!(pixel[3], 255);
            error = error.max(255 - *pixel[..3].iter().min().unwrap());
        }
        error
    }

    let mut accepted_partial = 0;
    let mut stale_pixels = 0;
    let mut snapshots_wrong = 0;
    let mut refused = 0;
    for (codec, i444) in [(VpxVideoCodecId::VP8, false),
                           (VpxVideoCodecId::VP9, false),
                           (VpxVideoCodecId::VP9, true)] {
        for source in [Pixfmt::BGRA, Pixfmt::RGBA, Pixfmt::RGB565LE] {
            let make_encoder = || VpxEncoder::new(EncoderCfg::VPX(VpxEncoderConfig {
                width: 33, height: 31, quality: 1.0, codec, keyframe_interval: Some(1),
            }), i444).unwrap();
            let mut encoder = make_encoder();
            let mut control_encoder = make_encoder();
            let mut decoder = VpxDecoder::new(VpxDecoderConfig { codec }).unwrap();
            let mut control_decoder = VpxDecoder::new(VpxDecoderConfig { codec }).unwrap();
            let format = encoder.yuvfmt();
            snapshots_wrong += usize::from((format.w, format.h) != (33, 31));
            let bpp = if source == Pixfmt::RGB565LE { 2 } else { 4 };
            let full_data = vec![255u8; 33 * 31 * bpp];
            let full = Frame::PixelBuffer(PixelBuffer::new(&full_data, source, 33, 31, 33 * bpp).unwrap());
            let mut output = Vec::new();
            let mut intermediate = Vec::new();
            let input = full.to(format, &mut output, &mut intermediate).unwrap();
            let control_yuv = input.yuv().unwrap().to_vec();
            let rgb = decoded(&mut encoder, &mut decoder, 0, input.yuv().unwrap());
            let control_rgb = decoded(&mut control_encoder, &mut control_decoder, 0, &control_yuv);
            assert_eq!(rgb, control_rgb);
            let max_error = white_error(&rgb);
            assert!(max_error <= 3, "initial white round trip error {}", max_error);
            println!("CAPTURE_VIEWPORT_CASE=pass operation=healthy codec={codec:?} i444={i444} source={source:?} dimensions=33x31 pixels=1023 max_error={max_error}");
            for (index, (width, height)) in [(16, 31), (33, 16), (16, 16)].iter().copied().enumerate() {
                full.to(format, &mut output, &mut intermediate).unwrap();
                let old_output = output.clone();
                let old_intermediate = intermediate.clone();
                let identities = (output.as_ptr(), output.capacity(), intermediate.as_ptr(), intermediate.capacity());
                let partial_data = vec![0u8; width * height * bpp];
                let partial = Frame::PixelBuffer(PixelBuffer::new(&partial_data, source, width, height, width * bpp).unwrap());
                let pts = index as i64 + 1;
                let control_rgb = decoded(&mut control_encoder, &mut control_decoder, pts, &control_yuv);
                let rejected = match partial.to(format, &mut output, &mut intermediate) {
                    Err(_) => true,
                    Ok(input) => {
                        let rgb = decoded(&mut encoder, &mut decoder, pts, input.yuv().unwrap());
                        let new_pixel = &rgb[..4];
                        let retained_pixel = &rgb[(33 * 31 - 1) * 4..];
                        assert_eq!((new_pixel[3], retained_pixel[3]), (255, 255));
                        let new_rgb = *new_pixel[..3].iter().max().unwrap();
                        let retained_rgb = *retained_pixel[..3].iter().min().unwrap();
                        assert!(new_rgb <= 8 && retained_rgb >= 240);
                        accepted_partial += 1;
                        stale_pixels += 1;
                        println!("CAPTURE_VIEWPORT_OBSERVED=partial codec={codec:?} i444={i444} source={source:?} width={width} height={height} new_rgb={new_rgb} retained_rgb={retained_rgb}");
                        false
                    }
                };
                if rejected {
                    assert_eq!(output, old_output);
                    assert_eq!(intermediate, old_intermediate);
                    assert_eq!((output.as_ptr(), output.capacity(), intermediate.as_ptr(), intermediate.capacity()), identities);
                    let input = full.to(format, &mut output, &mut intermediate).unwrap();
                    assert_eq!(input.yuv().unwrap(), control_yuv);
                    let rgb = decoded(&mut encoder, &mut decoder, pts, input.yuv().unwrap());
                    assert_eq!(rgb, control_rgb);
                    let control_error = white_error(&control_rgb);
                    refused += 1;
                    println!("CAPTURE_VIEWPORT_CASE=pass operation=refuse codec={codec:?} i444={i444} source={source:?} width={width} height={height} buffers=preserved retry=pass control_error={control_error}");
                }
            }
        }
    }
    if accepted_partial != 0 {
        println!("CAPTURE_VIEWPORT_NATIVE=observed combinations=9 accepted_partial={accepted_partial} stale_pixels={stale_pixels} snapshots_wrong={snapshots_wrong} healthy_pixels=9207");
    }
    assert_eq!(accepted_partial, 0, "partial capture must not retain previous visible pixels");
    assert_eq!(snapshots_wrong, 0, "descriptor must name the visible frame dimensions");
    assert_eq!(refused, 27);
    println!("CAPTURE_METADATA_NATIVE=pass operation=viewport combinations=9 mismatches=27 retries=27 pixels=36828 viewport=exact buffers=preserved");
}
