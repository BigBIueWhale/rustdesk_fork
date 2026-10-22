use super::*;
use crate::codec::EncoderCfg;
use crate::test_allocator::{arm, refusals, take_armed};
use crate::{ImageFormat, ImageRgb};

fn one_frame(message: VideoFrame, codec: VpxVideoCodecId, pts: i64) -> EncodedVideoFrame {
    use hbb_common::message_proto::video_frame::Union;
    let mut frames = match (codec, message.union.unwrap()) {
        (VpxVideoCodecId::VP8, Union::Vp8s(frames))
        | (VpxVideoCodecId::VP9, Union::Vp9s(frames)) => frames.frames,
        _ => panic!("unexpected encoded message codec"),
    };
    assert_eq!(frames.len(), 1);
    let frame = frames.remove(0);
    assert_eq!(frame.pts, pts);
    assert!(!frame.data.is_empty());
    frame
}

fn check_pixels(decoder: &mut VpxDecoder, packet: &EncodedVideoFrame, i444: bool, white: bool) {
    let image = decoder.decode(&packet.data).unwrap().unwrap();
    assert_eq!((image.width(), image.height()), (32, 32));
    assert_eq!(image.chroma(), if i444 { Chroma::I444 } else { Chroma::I420 });
    let mut rgb = ImageRgb::new(ImageFormat::ARGB, 0);
    image.to(&mut rgb).unwrap();
    assert_eq!(rgb.raw.len(), 32 * 32 * 4);
    let expected = if white { 255i32 } else { 0 };
    for pixel in rgb.raw.chunks_exact(4) {
        assert_eq!(pixel[3], 255);
        for channel in &pixel[..3] {
            // Black and white are separated by 255 levels. Match the existing
            // realtime codec test's eight-level lossy tolerance.
            assert!((i32::from(*channel) - expected).abs() <= 8);
        }
    }
}

#[test]
fn message_allocation_failure_recovers_current_pixels_with_keyframe() {
    let mut decoded = 0;
    let mut recovered = 0;
    for (codec, i444) in [(VpxVideoCodecId::VP8, false),
                           (VpxVideoCodecId::VP9, false),
                           (VpxVideoCodecId::VP9, true)] {
        let mut encoder = VpxEncoder::new(EncoderCfg::VPX(VpxEncoderConfig {
            width: 32,
            height: 32,
            quality: 1.0,
            codec,
            keyframe_interval: None,
        }), i444).unwrap();
        let format = encoder.yuvfmt();
        let mut data = vec![128; format.buffer_len];
        data[..format.u].fill(16);
        let initial = one_frame(encoder.encode_to_message(EncodeInput::YUV(&data), 0).unwrap(), codec, 0);
        assert!(initial.key);
        let mut decoder = VpxDecoder::new(VpxDecoderConfig { codec }).unwrap();
        check_pixels(&mut decoder, &initial, i444, false);
        decoded += 1;
        for cycle in 0..3 {
            let pts = cycle * 3000 + 1000;
            data[..format.u].fill(96);
            println!("VIDEO_MESSAGE_ALLOC_ATTEMPT=observed codec={codec:?} i444={i444} cycle={cycle} pts={pts}");
            let before = refusals();
            arm();
            let result = encoder.encode_to_message(EncodeInput::YUV(&data), pts);
            let unused_refusal = take_armed();
            assert!(!unused_refusal);
            let error = result.unwrap_err();
            assert!(error.downcast_ref::<std::collections::TryReserveError>().is_some());
            assert_eq!(refusals(), before + 1);

            data[..format.u].fill(235);
            let recovery = one_frame(
                encoder.encode_to_message(EncodeInput::YUV(&data), pts + 1000).unwrap(),
                codec, pts + 1000,
            );
            assert!(recovery.key);
            check_pixels(&mut decoder, &recovery, i444, true);
            let mut fresh = VpxDecoder::new(VpxDecoderConfig { codec }).unwrap();
            check_pixels(&mut fresh, &recovery, i444, true);
            decoded += 2;

            data[..format.u].fill(16);
            let following = one_frame(
                encoder.encode_to_message(EncodeInput::YUV(&data), pts + 2000).unwrap(),
                codec, pts + 2000,
            );
            assert!(!following.key);
            check_pixels(&mut decoder, &following, i444, false);
            decoded += 1;
            recovered += 1;
            println!("VIDEO_MESSAGE_ALLOC_CASE=pass codec={codec:?} i444={i444} cycle={cycle} refused=TryReserveError recovery_key=true fresh_decoder=true next_key=false pixels=checked");
        }
        assert_eq!(encoder.flush().unwrap().count(), 0);
    }
    assert_eq!((refusals(), recovered, decoded), (9, 9, 30));
    println!("VIDEO_MESSAGE_ALLOC_NATIVE=pass combinations=3 refusals=9 recoveries=9 next_nonkeys=9 decoded=30 pixels=30720 tail=0");
}
