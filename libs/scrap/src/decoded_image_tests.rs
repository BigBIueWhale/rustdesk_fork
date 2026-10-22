use crate::codec::{EncoderApi, EncoderCfg};
use crate::test_allocator::{arm, refusals, take_armed};
use crate::{GoogleImage, ImageFormat, ImageRgb, VpxDecoder, VpxDecoderConfig,
            VpxEncoder, VpxEncoderConfig, VpxVideoCodecId};

fn convert_native_images(warmed: bool) {
    let mut combinations = 0;
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
        let format = encoder.yuvfmt();
        let chroma_rows = if i444 { format.h } else { format.h / 2 };
        let yuv = vec![128; format.v + format.stride[2] * chroma_rows];
        let packets: Vec<Vec<u8>> = encoder.encode(0, &yuv, 64).unwrap()
            .map(|frame| frame.data.to_vec()).collect();
        assert_eq!(packets.len(), 1);
        let mut decoder = VpxDecoder::new(VpxDecoderConfig { codec }).unwrap();
        let image = decoder.decode(&packets[0]).unwrap().unwrap();
        assert_eq!((image.width(), image.height()), (34, 32));
        for pixel_format in [ImageFormat::ARGB, ImageFormat::ABGR] {
            for alignment in [0, 64] {
                let mut reference = ImageRgb::new(pixel_format, alignment);
                image.to(&mut reference).unwrap();
                let stride = if alignment == 0 { 136 } else { 192 };
                assert_eq!(reference.raw.len(), stride * 32);
                for row in reference.raw.chunks_exact(stride) {
                    for pixel in row[..136].chunks_exact(4) {
                        assert_eq!(pixel, [130, 130, 130, 255]);
                    }
                }

                let mut destination = ImageRgb::new(pixel_format, alignment);
                destination.w = 3;
                destination.h = 1;
                destination.raw.extend_from_slice(b"old frame");
                if warmed {
                    image.to(&mut destination).unwrap();
                }
                let before = refusals();
                arm();
                let result = image.to(&mut destination);
                let unused_refusal = take_armed();
                if warmed {
                    assert!(unused_refusal);
                    result.unwrap();
                    assert_eq!(refusals(), before);
                } else {
                    assert!(!unused_refusal);
                    let error = result.unwrap_err();
                    assert!(error.downcast_ref::<std::collections::TryReserveError>().is_some());
                    assert_eq!(refusals(), before + 1);
                    assert_eq!((destination.w, destination.h), (3, 1));
                    assert_eq!(destination.raw, b"old frame");
                    image.to(&mut destination).unwrap();
                }
                assert_eq!((destination.w, destination.h), (34, 32));
                assert_eq!(destination.raw, reference.raw);
                let mut invalid = ImageRgb::new(pixel_format, 3);
                invalid.w = 3;
                invalid.h = 1;
                invalid.raw.extend_from_slice(b"old frame");
                assert!(image.to(&mut invalid).is_err());
                assert_eq!((invalid.w, invalid.h), (3, 1));
                assert_eq!(invalid.raw, b"old frame");
                combinations += 1;
                println!("VIDEO_RGB_ALLOC_CASE=pass codec={codec:?} i444={i444} format={pixel_format:?} alignment={alignment} warmed={warmed} pixels=exact state=preserved");
            }
        }
    }
    assert_eq!(combinations, 12);
    assert_eq!(refusals(), if warmed { 0 } else { 12 });
    println!("VIDEO_RGB_ALLOC_NATIVE=pass warmed={warmed} combinations=12 refusals={} pixels=exact state=preserved", refusals());
}

#[test]
fn decoded_image_allocation_failure_preserves_output_and_retries() {
    convert_native_images(false);
}

#[test]
fn warmed_decoded_image_conversion_needs_no_allocation() {
    convert_native_images(true);
}
