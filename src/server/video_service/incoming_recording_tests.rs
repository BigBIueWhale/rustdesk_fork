use super::*;
use crate::server::connection::{video_egress_channel, VideoEgressItem};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

struct RecordingDirectory(PathBuf);

impl RecordingDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "incoming-recording-{}", hbb_common::uuid::Uuid::new_v4()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn recorder(&self) -> Recorder {
        Recorder::new(RecorderContext {
            server: true, id: "native-incoming".into(),
            dir: self.0.to_str().unwrap().into(), display_idx: 0, camera: false,
        }).unwrap()
    }

    fn writable(&self, writable: bool) {
        fs::set_permissions(&self.0,
            fs::Permissions::from_mode(if writable { 0o700 } else { 0o500 })).unwrap();
    }
}

impl Drop for RecordingDirectory {
    fn drop(&mut self) {
        self.writable(true);
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn encoder() -> Encoder {
    Encoder::new(EncoderCfg::VPX(VpxEncoderConfig {
        width: 64, height: 48, quality: 1.0,
        codec: VpxVideoCodecId::VP8, keyframe_interval: Some(1),
    }), false).unwrap()
}

#[test]
fn failed_incoming_recording_retires_while_video_continues() {
    let dir = RecordingDirectory::new();
    let recorder = Arc::new(Mutex::new(Some(dir.recorder())));
    dir.writable(false);
    let error = fs::write(dir.0.join("canary"), b"x").unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EACCES), "actual write denial");

    let service = GenericService::new("incoming-recording-test".into(), false);
    let (sender, mut receiver) = video_egress_channel();
    service.on_subscribe(ConnInner::new(71, None, Some(sender)));
    let controller = VideoFrameController::new(VideoSource::Monitor, 0).unwrap();
    let mut encoder = encoder();
    let mut decoder = Decoder::new(CodecFormat::VP8, None);
    let mut rgb = ImageRgb::new(ImageFormat::ABGR, crate::get_dst_align_rgba());
    let mut texture = ImageTexture::default();
    let mut first_frame = true;
    let mut failures = 0;
    let mut retired_after_failure = false;
    let mut output_payloads = Vec::new();
    let mut samples = Vec::new();

    for index in 0..4 {
        if index == 1 {
            retired_after_failure = recorder.lock().unwrap().is_none();
            dir.writable(true);
        }
        if index == 2 {
            assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 0,
                "a failed attempt must not restart when storage recovers");
            *recorder.lock().unwrap() = Some(dir.recorder());
        }
        let format = encoder.yuvfmt();
        let mut yuv = vec![128; format.buffer_len];
        for row in 0..48 {
            yuv[row * format.stride[0]..row * format.stride[0] + 64]
                .fill(40 + index as u8 * 40);
        }
        controller.reset();
        assert!(handle_one_frame(
            0, &service, &controller, EncodeInput::YUV(&yuv), index * 2000,
            &mut encoder, recorder.clone(), &mut failures, &mut first_frame,
            64, 48, &mut None,
        ).expect("recording failure must not fail video publication"));
        assert_eq!(failures, 0);
        let Some(VideoEgressItem::Frame(frame)) = receiver.try_recv() else {
            panic!("encoded frame must reach the existing subscriber");
        };
        assert_eq!(frame.test_wire_generation(), Some(index as u64 + 1));
        let Some(message::Union::VideoFrame(video)) = &frame.test_message().union else {
            panic!("native video message");
        };
        assert!(decoder.handle_video_frame(
            video.union.as_ref().unwrap(), &mut rgb, &mut texture, &mut true, &mut None,
        ).unwrap(), "subscriber receives decodable current pixels");
        assert_eq!((rgb.w, rgb.h), (64, 48));
        samples.push(rgb.raw.clone());
        if index >= 2 {
            let Some(video_frame::Union::Vp8s(batch)) = &video.union else {
                panic!("native VP8 output");
            };
            assert!(!batch.frames.is_empty());
            assert!(batch.frames[0].key);
            output_payloads.extend(batch.frames.iter().map(|frame| frame.data.clone()));
        }
    }
    assert!(samples.windows(2).all(|pair| pair[0] != pair[1]),
        "each delivered image must reflect changed source pixels");
    recorder.lock().unwrap().take().unwrap().finish().unwrap();
    let files: Vec<_> = fs::read_dir(&dir.0).unwrap()
        .map(|entry| entry.unwrap().path()).collect();
    assert_eq!(files.len(), 1, "one fresh recording after explicit new ownership");
    let bytes = fs::read(&files[0]).unwrap();
    assert!(bytes.starts_with(&[0x1a, 0x45, 0xdf, 0xa3]));
    assert_eq!(fs::metadata(&files[0]).unwrap().permissions().mode() & 0o777, 0o600);
    for payload in output_payloads {
        assert!(bytes.windows(payload.len()).any(|part| part == payload.as_ref()),
            "the new recording must retain each native transmitted payload");
    }
    assert!(receiver.try_recv().is_none());
    service.on_unsubscribe(71);
    drop(controller);
    drop(recorder);
    assert_eq!(fs::read(&files[0]).unwrap(), bytes);
    assert!(retired_after_failure, "the capture owner must retire its failed recorder");
}
