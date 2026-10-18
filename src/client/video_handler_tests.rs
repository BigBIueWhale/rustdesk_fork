use super::VideoHandler;
use hbb_common::{bytes::Bytes, message_proto::EncodedVideoFrame, message_proto::VideoFrame};
use scrap::{
    codec::{EncoderApi, EncoderCfg},
    vpxcodec::{VpxEncoder, VpxEncoderConfig, VpxVideoCodecId},
    CodecFormat,
};

const WIDTH: usize = 640;
const HEIGHT: usize = 480;

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
    visible_and_hidden_frames_at(WIDTH, HEIGHT, 128)
}

fn visible_and_hidden_frames_at(width: usize, height: usize, luma: u8) -> (VideoFrame, VideoFrame) {
    let mut encoder = VpxEncoder::new(
        EncoderCfg::VPX(VpxEncoderConfig {
            width: width as _,
            height: height as _,
            #[cfg(target_os = "android")]
            android_scale: 1,
            quality: 1.0,
            codec: VpxVideoCodecId::VP8,
            keyframe_interval: None,
        }),
        false,
    )
    .expect("native VP8 encoder");
    assert!(encoder.bitrate() > 0, "positive native encoder bitrate");
    let mut yuv = vec![128; width * height * 3 / 2];
    yuv[..width * height].fill(luma);
    let mut frames: Vec<_> = encoder
        .encode(0, &yuv, 1)
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
    assert_eq!((handler.rgb.w, handler.rgb.h), (WIDTH, HEIGHT));
    assert!(handler.rgb.raw.len() >= WIDTH * HEIGHT * 4);
    assert!(handler.decoder.valid());
}

#[test]
fn hidden_first_packet_preserves_healthy_decoder() {
    let (visible, hidden) = visible_and_hidden_frames();
    let mut handler = VideoHandler::new(CodecFormat::VP8, 0);
    assert!(!decode(&mut handler, hidden).expect("native hidden decode"));
    assert!(handler.decoder.valid());
    assert!(handler.rgb.raw.is_empty());
    assert_visible(&mut handler, visible);
}

#[test]
fn repeated_hidden_packets_preserve_visible_recovery() {
    let (visible, hidden) = visible_and_hidden_frames();
    let mut handler = VideoHandler::new(CodecFormat::VP8, 0);
    assert_visible(&mut handler, visible.clone());
    for _ in 0..5 {
        assert!(!decode(&mut handler, hidden.clone()).expect("native hidden decode"));
    }
    assert!(handler.decoder.valid());
    assert_visible(&mut handler, visible);
}

#[test]
fn hidden_packet_after_corruption_preserves_native_recovery() {
    let (visible, hidden) = visible_and_hidden_frames();
    let mut handler = VideoHandler::new(CodecFormat::VP8, 0);
    assert_visible(&mut handler, visible.clone());
    assert!(decode(&mut handler, packet(vec![0; 3])).is_err());
    assert!(!decode(&mut handler, hidden).expect("native hidden decode"));
    assert_visible(&mut handler, visible);
}

#[test]
fn visible_output_and_corrupt_packet_remain_distinct() {
    let (visible, _) = visible_and_hidden_frames();
    let mut handler = VideoHandler::new(CodecFormat::VP8, 0);
    assert_visible(&mut handler, visible);
    assert!(decode(&mut handler, packet(vec![0; 3])).is_err());
    assert!(handler.decoder.valid());
}

#[test]
fn visible_frame_survives_hidden_resolution_change_in_same_batch() {
    use hbb_common::message_proto::video_frame::Union;

    let (visible, _) = visible_and_hidden_frames_at(WIDTH, HEIGHT, 32);
    let (resized, hidden) = visible_and_hidden_frames_at(1280, 720, 224);
    let mut expected = VideoHandler::new(CodecFormat::VP8, 0);
    assert_visible(&mut expected, visible.clone());
    let expected_rgb = expected.rgb.raw;

    let mut batch = visible;
    let Some(Union::Vp8s(frames)) = &mut batch.union else {
        panic!("visible VP8 batch");
    };
    let Some(Union::Vp8s(hidden)) = hidden.union else {
        panic!("hidden VP8 batch");
    };
    frames.frames.extend(hidden.frames);
    let mut handler = VideoHandler::new(CodecFormat::VP8, 0);
    assert_visible(&mut handler, batch);
    assert!(handler.rgb.raw == expected_rgb, "last visible pixels survived hidden resize");

    assert!(decode(&mut handler, resized).expect("visible resized decode"));
    assert_eq!((handler.rgb.w, handler.rgb.h), (1280, 720));
    assert!(handler.rgb.raw.len() >= 1280 * 720 * 4);
    assert!(handler.decoder.valid());
}

#[cfg(target_os = "linux")]
mod worker_tests {
    use super::*;
    use crate::{
        client::{
            io_loop::viewer_video_refresh_channel, start_video_thread, video_mailbox,
            VideoControl, VideoControlAdmission, VideoFrameAdmission,
        },
        ui_session_interface::Session,
        viewer_pipeline_smoke_tests::ViewerPipelineUi,
    };
    use hbb_common::message_proto::{DisplayInfo, PeerInfo};
    use std::{
        panic::{catch_unwind, resume_unwind, AssertUnwindSafe},
        sync::{mpsc, Arc, RwLock},
        thread,
        time::{Duration, Instant},
    };

    fn wait_until(mut complete: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !complete() {
            assert!(Instant::now() < deadline, "worker schedule deadline");
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn decode_failure_schedule(replace: bool) -> (bool, bool) {
        let (mut visible, _) = visible_and_hidden_frames();
        visible.generation = 1;
        let session = Session::<ViewerPipelineUi>::default();
        session.lc.write().unwrap().peer_info = Some(PeerInfo {
            displays: vec![DisplayInfo {
                width: WIDTH as _,
                height: HEIGHT as _,
                ..Default::default()
            }],
            ..Default::default()
        });
        let (refresh_sender, _refresh_receiver) = viewer_video_refresh_channel();
        *session.video_refresh_sender.write().unwrap() = Some(refresh_sender);
        let (sender, receiver) = video_mailbox();
        let (published, publication) = mpsc::sync_channel(2);
        let (release, released) = mpsc::sync_channel(1);
        let mut first = true;
        let worker = start_video_thread(
            session.clone(),
            0,
            receiver,
            Arc::new(RwLock::new(None)),
            Arc::new(RwLock::new(None)),
            move |display, rgb, _, _| {
                assert_eq!(display, 0);
                published.send((rgb.w, rgb.h, rgb.raw.len())).expect("RGB callback");
                if first {
                    first = false;
                    released.recv_timeout(Duration::from_secs(5)).expect("release callback");
                }
            },
        );

        let result = catch_unwind(AssertUnwindSafe(|| {
            assert_eq!(
                sender.admit_received_frame(visible.clone(), true, Instant::now()),
                VideoFrameAdmission::Queued
            );
            let (w, h, bytes) = publication.recv_timeout(Duration::from_secs(2)).expect("warm RGB");
            assert_eq!((w, h), (WIDTH, HEIGHT));
            assert!(bytes >= WIDTH * HEIGHT * 4);
            assert_eq!(sender.admit_control(VideoControl::Reset), VideoControlAdmission::RefreshRequired);
            let mut corrupt = packet(vec![0; 3]);
            corrupt.generation = 2;
            assert_eq!(
                sender.admit_received_frame(corrupt, true, Instant::now()),
                VideoFrameAdmission::Queued
            );

            // The callback gates dequeue. This write guard then gates the worker's
            // ordinary capability read after it dequeues the corrupt keyframe.
            let login = session.lc.write().unwrap();
            release.send(()).expect("release warm callback");
            wait_until(|| worker.is_finished() || sender.pending_frames() == Some(0));
            assert!(!worker.is_finished(), "worker exited before corrupt decode");
            assert_eq!(sender.pending_frames(), Some(0));
            assert!(!sender.shared.state.lock().unwrap().awaiting_keyframe,
                "corrupt keyframe expired before the gated decode");
            if replace {
                visible.generation = 3;
                assert_eq!(
                    sender.admit_received_frame(visible.clone(), true, Instant::now()),
                    VideoFrameAdmission::Queued
                );
            }
            drop(login);

            let receive_rgb = || {
                match publication.recv_timeout(Duration::from_secs(2)) {
                    Ok((w, h, bytes)) => {
                        assert_eq!((w, h), (WIDTH, HEIGHT));
                        assert!(bytes >= WIDTH * HEIGHT * 4);
                        true
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => false,
                    Err(error) => panic!("replacement RGB callback disconnected: {error}"),
                }
            };
            let refresh = |mut frame: VideoFrame, generation| {
                wait_until(|| sender.shared.state.lock().unwrap().awaiting_keyframe);
                assert!(sender.begin_refresh(), "native refresh admission");
                frame.generation = generation;
                assert_eq!(
                    sender.admit_received_frame(frame, true, Instant::now()),
                    VideoFrameAdmission::Queued
                );
            };
            if !replace {
                refresh(visible.clone(), 3);
            }
            let mut recovered = receive_rgb();
            if !replace && recovered {
                for cycle in 0..3 {
                    let mut corrupt = packet(vec![0; 3]);
                    corrupt.generation = 4 + cycle * 2;
                    assert_eq!(
                        sender.admit_received_frame(corrupt, true, Instant::now()),
                        VideoFrameAdmission::Queued
                    );
                    refresh(visible.clone(), 5 + cycle * 2);
                    recovered = receive_rgb();
                    if !recovered {
                        break;
                    }
                }
            }
            let unsupported = session.lc.read().unwrap().mark_unsupported.contains(&CodecFormat::VP8);
            (unsupported, recovered)
        }));

        let _ = release.try_send(());
        sender.close();
        worker.join().expect("exact native decoder worker joined");
        result.unwrap_or_else(|panic| resume_unwind(panic))
    }

    #[test]
    fn retired_decode_failure_keeps_replacement_codec_available() {
        let (unsupported, recovered) = decode_failure_schedule(true);
        assert!(!unsupported, "retired decode error disabled the replacement codec");
        assert!(recovered, "replacement keyframe did not reach the RGB callback");
    }

    #[test]
    fn current_decode_failure_recovers_same_codec_after_refresh() {
        let (unsupported, recovered) = decode_failure_schedule(false);
        assert!(!unsupported, "corrupt input permanently disabled the initialized codec");
        assert!(recovered, "current-error refresh did not restore RGB output");
    }
}
