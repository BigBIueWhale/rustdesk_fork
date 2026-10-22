use crate::{test_allocator, PixelBuffer, Pixfmt, TraitPixelBuffer};
use std::hint::black_box;

#[test]
fn construction_needs_no_allocation() {
    let data = [0x5a; 32];
    let refusals = test_allocator::refusals();
    test_allocator::arm();
    let result = black_box(PixelBuffer::new(black_box(&data), Pixfmt::BGRA, 3, 2, 16));
    let unused = test_allocator::take_armed();
    assert!(unused);
    assert_eq!(test_allocator::refusals(), refusals);
    let pixels = result.unwrap();
    assert_eq!(pixels.data(), data);
    assert_eq!((pixels.width(), pixels.height()), (3, 2));
    assert_eq!(pixels.pixfmt(), Pixfmt::BGRA);
    println!("CAPTURE_METADATA_NATIVE=pass operation=construct stride={:?} allocations=0 pixels=exact", pixels.stride());
}

#[test]
fn stride_read_needs_no_allocation() {
    let data = [0x5a; 32];
    let pixels = PixelBuffer::new(&data, Pixfmt::BGRA, 3, 2, 16).unwrap();
    let refusals = test_allocator::refusals();
    test_allocator::arm();
    let stride = black_box(black_box(&pixels).stride());
    let unused = test_allocator::take_armed();
    assert!(unused);
    assert_eq!(test_allocator::refusals(), refusals);
    assert_eq!(pixels.data(), data);
    println!("CAPTURE_METADATA_NATIVE=pass operation=read stride={stride:?} allocations=0 pixels=exact");
}

#[test]
fn warmed_yuv_conversion_needs_no_allocation() {
    use crate::{convert_to_yuv, EncodeYuvFormat};

    let data = [0u8; 32];
    for source in [Pixfmt::BGRA, Pixfmt::RGBA, Pixfmt::RGB565LE] {
        let source_stride = if source == Pixfmt::RGB565LE { 8 } else { 16 };
        let pixels = PixelBuffer::new(&data[..source_stride * 2], source, 3, 2, source_stride).unwrap();
        for destination in [Pixfmt::I420, Pixfmt::NV12, Pixfmt::I444] {
            let format = EncodeYuvFormat {
                pixfmt: destination,
                w: 3,
                h: 2,
                stride: match destination {
                    Pixfmt::I420 => [8, 4, 4],
                    Pixfmt::NV12 => [8, 8, 0],
                    Pixfmt::I444 => [8, 8, 8],
                    _ => unreachable!(),
                },
                u: 16,
                v: if destination == Pixfmt::I420 { 20 } else { 32 },
            };
            let mut output = Vec::new();
            let mut intermediate = Vec::new();
            convert_to_yuv(&pixels, format, &mut output, &mut intermediate).unwrap();
            output.fill(0xa5);
            intermediate.fill(0xa5);
            let warmed_format = format;
            let before = test_allocator::refusals();
            test_allocator::arm();
            let result = black_box(convert_to_yuv(
                black_box(&pixels), warmed_format, &mut output, &mut intermediate,
            ));
            let unused = test_allocator::take_armed();
            assert!(unused, "{source:?} -> {destination:?} allocated");
            assert_eq!(test_allocator::refusals(), before);
            result.unwrap();
            let plane = |offset: usize, stride: usize, width: usize, height: usize, value: u8| {
                for row in 0..height {
                    assert!(output[offset + row * stride..][..width].iter().all(|&v| v == value));
                }
            };
            // Limited-range black: every visible Y=16, U=V=128.
            plane(0, 8, 3, 2, 16);
            match destination {
                Pixfmt::I420 => {
                    plane(16, 4, 2, 1, 128);
                    plane(20, 4, 2, 1, 128);
                }
                Pixfmt::NV12 => plane(16, 8, 4, 1, 128),
                Pixfmt::I444 => {
                    plane(16, 8, 3, 2, 128);
                    plane(32, 8, 3, 2, 128);
                }
                _ => unreachable!(),
            }
            println!("CAPTURE_YUV_CASE=pass source={source:?} destination={destination:?} pixels=exact allocation=unused");
        }
        let unsupported = EncodeYuvFormat {
            pixfmt: Pixfmt::BGRA, w: 3, h: 2, stride: [0; 3], u: 0, v: 0,
        };
        let error = convert_to_yuv(&pixels, unsupported, &mut Vec::new(), &mut Vec::new()).unwrap_err();
        assert_eq!(error.to_string(), format!("unsupported pixfmt conversion: {source:?} -> BGRA"));
    }
    println!("CAPTURE_METADATA_NATIVE=pass operation=convert combinations=9 allocations=0 pixels=exact unsupported=3");
}

#[test]
fn encoder_format_snapshot_and_frame_conversion_need_no_allocation() {
    use crate::codec::{EncoderApi, EncoderCfg};
    use crate::{Frame, GoogleImage, ImageFormat, ImageRgb, VpxDecoder, VpxDecoderConfig,
                VpxEncoder, VpxEncoderConfig, VpxVideoCodecId};

    let data = vec![0u8; 34 * 32 * 4];
    let mut samples = 0;
    for (codec, i444) in [(VpxVideoCodecId::VP8, false),
                           (VpxVideoCodecId::VP9, false),
                           (VpxVideoCodecId::VP9, true)] {
        let mut encoder = VpxEncoder::new(EncoderCfg::VPX(VpxEncoderConfig {
            width: 34,
            height: 32,
            quality: 1.0,
            codec,
            keyframe_interval: Some(1),
        }), i444).unwrap();
        let frame = Frame::PixelBuffer(PixelBuffer::new(&data, Pixfmt::BGRA, 34, 32, 136).unwrap());
        let reference = encoder.yuvfmt();
        assert_eq!((reference.w, reference.h), (34, 32));
        let mut output = Vec::new();
        let mut intermediate = Vec::new();
        frame.to(reference.clone(), &mut output, &mut intermediate).unwrap();
        output.fill(0xa5);
        let before = test_allocator::refusals();
        test_allocator::arm();
        let snapshot = black_box(encoder.yuvfmt());
        // Deliberately exercise the descriptor's public Clone operation as well.
        let copied = black_box(Clone::clone(black_box(&snapshot)));
        let result = black_box(frame.to(copied, &mut output, &mut intermediate));
        let unused = test_allocator::take_armed();
        assert!(unused, "{codec:?} i444={i444} allocated");
        assert_eq!(test_allocator::refusals(), before);
        assert_eq!((snapshot.pixfmt, snapshot.w, snapshot.h, snapshot.u, snapshot.v),
                   (reference.pixfmt, reference.w, reference.h, reference.u, reference.v));
        assert_eq!(snapshot.stride[..3], reference.stride[..3]);
        let input = result.unwrap();
        let converted = input.yuv().unwrap();
        let plane = |offset: usize, stride: usize, width: usize, height: usize, value: u8| {
            for row in 0..height {
                assert!(converted[offset + row * stride..][..width].iter().all(|&v| v == value));
            }
        };
        plane(0, reference.stride[0], 34, 32, 16);
        let (width, height) = if i444 { (34, 32) } else { (17, 16) };
        plane(reference.u, reference.stride[1], width, height, 128);
        plane(reference.v, reference.stride[2], width, height, 128);
        let packets: Vec<Vec<u8>> = encoder.encode(0, converted, 64).unwrap()
            .map(|frame| frame.data.to_vec()).collect();
        assert_eq!(packets.len(), 1);
        let mut decoder = VpxDecoder::new(VpxDecoderConfig { codec }).unwrap();
        let image = decoder.decode(&packets[0]).unwrap().unwrap();
        assert_eq!((image.width(), image.height()), (34, 32));
        let mut rgb = ImageRgb::new(ImageFormat::ARGB, 0);
        image.to(&mut rgb).unwrap();
        assert_eq!(rgb.raw.len(), 34 * 32 * 4);
        let mut max_error = 0;
        for pixel in rgb.raw.chunks_exact(4) {
            assert_eq!(pixel[3], 255);
            max_error = max_error.max(*pixel[..3].iter().max().unwrap());
        }
        assert!(max_error <= 3);
        println!("CAPTURE_ENCODER_ENCODE=pass codec={codec:?} i444={i444} dimensions=34x32 pixels=1088 alpha=255 max_error={max_error}");
        let checked = 34 * 32 + 2 * width * height;
        samples += checked;
        println!("CAPTURE_ENCODER_CASE=pass codec={codec:?} i444={i444} snapshot=preserved allocations=0 pixels=exact samples={checked}");
    }
    assert_eq!(samples, 6528);
    println!("CAPTURE_METADATA_NATIVE=pass operation=format combinations=3 allocations=0 pixels=exact samples=6528 snapshot=preserved");
}
