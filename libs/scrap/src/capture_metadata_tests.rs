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
                    Pixfmt::I420 => vec![8, 4, 4],
                    Pixfmt::NV12 => vec![8, 8],
                    Pixfmt::I444 => vec![8, 8, 8],
                    _ => unreachable!(),
                },
                u: 16,
                v: if destination == Pixfmt::I420 { 20 } else { 32 },
            };
            let mut output = Vec::new();
            let mut intermediate = Vec::new();
            convert_to_yuv(&pixels, format.clone(), &mut output, &mut intermediate).unwrap();
            output.fill(0xa5);
            intermediate.fill(0xa5);
            let warmed_format = format.clone();
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
            pixfmt: Pixfmt::BGRA, w: 3, h: 2, stride: Vec::new(), u: 0, v: 0,
        };
        let error = convert_to_yuv(&pixels, unsupported, &mut Vec::new(), &mut Vec::new()).unwrap_err();
        assert_eq!(error.to_string(), format!("unsupported pixfmt conversion: {source:?} -> BGRA"));
    }
    println!("CAPTURE_METADATA_NATIVE=pass operation=convert combinations=9 allocations=0 pixels=exact unsupported=3");
}
