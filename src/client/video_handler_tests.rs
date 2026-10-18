use super::{VideoHandler, MAX_DECODE_FAIL_COUNTER};
use hbb_common::{bytes::Bytes, message_proto::EncodedVideoFrame, message_proto::VideoFrame};
use scrap::{
    codec::{EncoderApi, EncoderCfg},
    vpxcodec::{VpxEncoder, VpxEncoderConfig, VpxVideoCodecId},
    CodecFormat,
};

fn packet(data: Vec<u8>) -> VideoFrame {
    VpxEncoder::create_video_frame(
        VpxVideoCodecId::VP8,
        vec![EncodedVideoFrame {
            data: Bytes::from(data),
            key: true,
            ..Default::default()
        }],
    )
}

fn visible_and_hidden_frames() -> (VideoFrame, VideoFrame) {
    let mut encoder = VpxEncoder::new(
        EncoderCfg::VPX(VpxEncoderConfig {
            width: 16,
            height: 16,
            #[cfg(target_os = "android")]
            android_scale: 1,
            quality: 1.0,
            codec: VpxVideoCodecId::VP8,
            keyframe_interval: None,
        }),
        false,
    )
    .expect("native VP8 encoder");
    let mut frames: Vec<_> = encoder
        .encode(0, &[128; 16 * 16 * 3 / 2], 1)
        .expect("encode")
        .map(|frame| (frame.key, frame.data.to_vec()))
        .collect();
    frames.extend(
        encoder
            .flush()
            .expect("flush")
            .map(|frame| (frame.key, frame.data.to_vec())),
    );
    assert_eq!(frames.len(), 1, "one native keyframe after flush");
    let (key, mut data) = frames.pop().expect("encoded keyframe");
    assert!(key);
    assert!(data.len() >= 10);
    assert_eq!(data[0] & 1, 0, "native VP8 keyframe tag");
    assert_ne!(data[0] & 0x10, 0, "native visible frame tag");
    let visible = packet(data.clone());
    // RFC 6386 section 9.1: show_frame=0 is a valid non-display frame.
    data[0] &= !0x10;
    (visible, packet(data))
}

fn decode(handler: &mut VideoHandler, frame: VideoFrame) -> hbb_common::ResultType<bool> {
    handler.handle_frame(frame, &mut true, &mut None)
}

fn assert_visible(handler: &mut VideoHandler, frame: VideoFrame) {
    assert!(decode(handler, frame).expect("native visible decode"));
    assert_eq!((handler.rgb.w, handler.rgb.h), (16, 16));
    assert!(handler.rgb.raw.len() >= 16 * 16 * 4);
    assert!(handler.decoder.valid());
    assert_eq!(handler.fail_counter, 0);
}

#[test]
fn hidden_first_packet_preserves_healthy_decoder() {
    let (visible, hidden) = visible_and_hidden_frames();
    let mut handler = VideoHandler::new(CodecFormat::VP8, 0);
    assert!(!decode(&mut handler, hidden).expect("native hidden decode"));
    assert!(handler.decoder.valid());
    assert!(handler.rgb.raw.is_empty());
    assert_eq!(handler.fail_counter, 0);
    assert_visible(&mut handler, visible);
}

#[test]
fn repeated_hidden_packets_do_not_accumulate_failures() {
    let (visible, hidden) = visible_and_hidden_frames();
    let mut handler = VideoHandler::new(CodecFormat::VP8, 0);
    assert_visible(&mut handler, visible.clone());
    for _ in 0..MAX_DECODE_FAIL_COUNTER + 2 {
        assert!(!decode(&mut handler, hidden.clone()).expect("native hidden decode"));
    }
    assert!(handler.decoder.valid());
    assert_eq!(handler.fail_counter, 0);
    assert_visible(&mut handler, visible);
}

#[test]
fn hidden_packet_clears_prior_decode_failure() {
    let (visible, hidden) = visible_and_hidden_frames();
    let mut handler = VideoHandler::new(CodecFormat::VP8, 0);
    assert_visible(&mut handler, visible.clone());
    assert!(decode(&mut handler, packet(vec![0; 3])).is_err());
    assert_eq!(handler.fail_counter, 1);
    assert!(!decode(&mut handler, hidden).expect("native hidden decode"));
    assert_eq!(handler.fail_counter, 0);
    assert_visible(&mut handler, visible);
}

#[test]
fn visible_output_and_corrupt_packet_remain_distinct() {
    let (visible, _) = visible_and_hidden_frames();
    let mut handler = VideoHandler::new(CodecFormat::VP8, 0);
    assert_visible(&mut handler, visible);
    assert!(decode(&mut handler, packet(vec![0; 3])).is_err());
    assert_eq!(handler.fail_counter, 1);
    assert!(handler.decoder.valid());
}
