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
pub fn convert_to_yuv(
    captured: &PixelBuffer,
    dst_fmt: EncodeYuvFormat,
    dst: &mut Vec<u8>,
    mid_data: &mut Vec<u8>,
) -> ResultType<()> {
    let src = captured.data();
    let src_stride = captured.stride();
    let src_pixfmt = captured.pixfmt();
    let src_width = captured.width();
    let src_height = captured.height();
    if src_width > dst_fmt.w || src_height > dst_fmt.h {
        bail!(
            "src rect > dst rect: ({src_width}, {src_height}) > ({},{})",
            dst_fmt.w,
            dst_fmt.h
        );
    }
    if src_pixfmt == crate::Pixfmt::BGRA
        || src_pixfmt == crate::Pixfmt::RGBA
        || src_pixfmt == crate::Pixfmt::RGB565LE
    {
        // stride is calculated, not real, so we need to check it
        if src_stride[0] < src_width * src_pixfmt.bytes_per_pixel() {
            bail!(
                "src_stride too small: {} < {}",
                src_stride[0],
                src_width * src_pixfmt.bytes_per_pixel()
            );
        }
        if src.len() < src_stride[0] * src_height {
            bail!(
                "wrong src len, {} < {} * {}",
                src.len(),
                src_stride[0],
                src_height
            );
        }
    }
    let align = |x: usize| (x + 63) / 64 * 64;
    let unsupported = format!(
        "unsupported pixfmt conversion: {src_pixfmt:?} -> {:?}",
        dst_fmt.pixfmt
    );

    match (src_pixfmt, dst_fmt.pixfmt) {
        (crate::Pixfmt::BGRA, crate::Pixfmt::I420)
        | (crate::Pixfmt::RGBA, crate::Pixfmt::I420)
        | (crate::Pixfmt::RGB565LE, crate::Pixfmt::I420) => {
            let dst_stride_y = dst_fmt.stride[0];
            let dst_stride_uv = dst_fmt.stride[1];
            dst.resize(dst_fmt.h * dst_stride_y * 2, 0); // waste some memory to ensure memory safety
            let dst_y = dst.as_mut_ptr();
            let dst_u = dst[dst_fmt.u..].as_mut_ptr();
            let dst_v = dst[dst_fmt.v..].as_mut_ptr();
            let f = match src_pixfmt {
                crate::Pixfmt::BGRA => ARGBToI420,
                crate::Pixfmt::RGBA => ABGRToI420,
                crate::Pixfmt::RGB565LE => RGB565ToI420,
                _ => bail!(unsupported),
            };
            call_yuv!(f(
                src.as_ptr(),
                src_stride[0] as _,
                dst_y,
                dst_stride_y as _,
                dst_u,
                dst_stride_uv as _,
                dst_v,
                dst_stride_uv as _,
                src_width as _,
                src_height as _,
            ));
        }
        (crate::Pixfmt::BGRA, crate::Pixfmt::NV12)
        | (crate::Pixfmt::RGBA, crate::Pixfmt::NV12)
        | (crate::Pixfmt::RGB565LE, crate::Pixfmt::NV12) => {
            let dst_stride_y = dst_fmt.stride[0];
            let dst_stride_uv = dst_fmt.stride[1];
            dst.resize(
                align(dst_fmt.h) * (align(dst_stride_y) + align(dst_stride_uv / 2)),
                0,
            );
            let dst_y = dst.as_mut_ptr();
            let dst_uv = dst[dst_fmt.u..].as_mut_ptr();
            let (input, input_stride) = match src_pixfmt {
                crate::Pixfmt::BGRA => (src.as_ptr(), src_stride[0]),
                crate::Pixfmt::RGBA => (src.as_ptr(), src_stride[0]),
                crate::Pixfmt::RGB565LE => {
                    let mid_stride = src_width * 4;
                    mid_data.resize(mid_stride * src_height, 0);
                    call_yuv!(RGB565ToARGB(
                        src.as_ptr(),
                        src_stride[0] as _,
                        mid_data.as_mut_ptr(),
                        mid_stride as _,
                        src_width as _,
                        src_height as _,
                    ));
                    (mid_data.as_ptr(), mid_stride)
                }
                _ => bail!(unsupported),
            };
            let f = match src_pixfmt {
                crate::Pixfmt::BGRA => ARGBToNV12,
                crate::Pixfmt::RGBA => ABGRToNV12,
                crate::Pixfmt::RGB565LE => ARGBToNV12,
                _ => bail!(unsupported),
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
            dst.resize(
                align(dst_fmt.h)
                    * (align(dst_stride_y) + align(dst_stride_u) + align(dst_stride_v)),
                0,
            );
            let dst_y = dst.as_mut_ptr();
            let dst_u = dst[dst_fmt.u..].as_mut_ptr();
            let dst_v = dst[dst_fmt.v..].as_mut_ptr();
            let (input, input_stride) = match src_pixfmt {
                crate::Pixfmt::BGRA => (src.as_ptr(), src_stride[0]),
                crate::Pixfmt::RGBA => {
                    mid_data.resize(src.len(), 0);
                    call_yuv!(ABGRToARGB(
                        src.as_ptr(),
                        src_stride[0] as _,
                        mid_data.as_mut_ptr(),
                        src_stride[0] as _,
                        src_width as _,
                        src_height as _,
                    ));
                    (mid_data.as_ptr(), src_stride[0])
                }
                crate::Pixfmt::RGB565LE => {
                    let mid_stride = src_width * 4;
                    mid_data.resize(mid_stride * src_height, 0);
                    call_yuv!(RGB565ToARGB(
                        src.as_ptr(),
                        src_stride[0] as _,
                        mid_data.as_mut_ptr(),
                        mid_stride as _,
                        src_width as _,
                        src_height as _,
                    ));
                    (mid_data.as_ptr(), mid_stride)
                }
                _ => bail!(unsupported),
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
            bail!(unsupported);
        }
    }
    Ok(())
}

#[cfg(not(target_os = "ios"))]
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
    let stride = pixbuf
        .stride()
        .first()
        .copied()
        .ok_or_else(|| anyhow!("missing screenshot pixel stride"))?;
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
        let display = crate::Display::primary().unwrap();
        let mut capturer = crate::Capturer::new(display).unwrap();
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
        let path = std::env::var("SCREENSHOT_X11_PNG_PATH").unwrap();
        assert_eq!(path, format!("/tmp/video-vpx/screenshot-{depth}.png"));
        let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
        let mut encoder = repng::Options::smallest(129, 33).build(file).unwrap();
        encoder.write(&rgba).unwrap();
        encoder.finish().unwrap();
        drop(encoder);
        println!("SCREENSHOT_X11_PNG=created depth={depth} width=129 height=33 stride={} format={expected_format:?} bytes={} source_alpha_zero={source_alpha_zero}", pixels.stride()[0], std::fs::metadata(path).unwrap().len());
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
