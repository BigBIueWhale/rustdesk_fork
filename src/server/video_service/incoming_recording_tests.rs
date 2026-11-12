use super::*;
use crate::server::connection::{video_egress_channel, VideoEgressItem};
use crate::{incoming_recording_status::{FailureStage, RecordingFailure}, server::incoming_recording::snapshot};
use hbb_common::libc;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

#[cfg(target_arch = "x86_64")]
#[path = "incoming_recording_blocked.rs"]
mod blocked;

struct RecordingDirectory(PathBuf);

impl RecordingDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "incoming-recording-{}", hbb_common::uuid::Uuid::new_v4()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn recorder(&self) -> IncomingRecording {
        IncomingRecording::new(RecorderContext {
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
    let mut recorder = Some(dir.recorder());
    assert_eq!((snapshot().starting, snapshot().active, snapshot().finishing), (1, 0, 0));
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
            retired_after_failure = recorder.is_none();
            assert_eq!(snapshot().writers(), 0);
            assert_eq!(snapshot().last_failure, Some(RecordingFailure {
                display: 0, camera: false, stage: FailureStage::Write,
            }));
            dir.writable(true);
        }
        if index == 2 {
            assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 0,
                "a failed attempt must not restart when storage recovers");
            recorder = Some(dir.recorder());
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
            &mut encoder, &mut recorder, &mut failures, &mut first_frame,
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
    assert_eq!((snapshot().starting, snapshot().active, snapshot().finishing), (0, 1, 0));
    let failure = snapshot().last_failure;
    assert!(failure.is_some(), "new ownership must not erase historical failure");
    drop(recorder.take().unwrap());
    assert_eq!(snapshot().writers(), 0);
    assert_eq!(snapshot().last_failure, failure, "healthy completion preserves failure history");
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

struct FileLimit {
    original: libc::rlimit,
    signal: libc::sighandler_t,
}

impl FileLimit {
    fn zero() -> Self {
        let mut original = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut original) }, 0);
        let signal = unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) };
        assert_ne!(signal, libc::SIG_ERR);
        let guard = Self { original, signal };
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: original.rlim_max };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &zero) }, 0);
        guard
    }
}

impl Drop for FileLimit {
    fn drop(&mut self) {
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &self.original) }, 0);
        assert_ne!(unsafe { libc::signal(libc::SIGXFSZ, self.signal) }, libc::SIG_ERR);
    }
}

#[test]
fn incoming_finalization_failure_survives_owner_retirement() {
    use std::{collections::BTreeMap, io::Write, process::{Command, Stdio}};
    const CHILD: &str = "RUSTDESK_INCOMING_FINALIZATION_CHILD";
    const TEST: &str = "server::video_service::incoming_recording_tests::incoming_finalization_failure_survives_owner_retirement";
    if std::env::var_os(CHILD).is_none() {
        // Limits and signal disposition belong to a fresh, exactly joined child.
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(CHILD, "1").stdin(Stdio::null()).output().unwrap();
        assert!(output.stdout.len() + output.stderr.len() <= 64 * 1024);
        assert!(output.status.success(), "incoming finalization child: {}\n{}\n{}",
            output.status, String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        assert!(String::from_utf8_lossy(&output.stdout)
            .contains("INCOMING_FINALIZATION=pass failure=retained retry=healthy owners=retired"));
        return;
    }

    let dir = RecordingDirectory::new();
    assert_eq!(snapshot(), Default::default());
    let files = || fs::read_dir(&dir.0).unwrap()
        .map(|entry| { let path = entry.unwrap().path(); let bytes = fs::read(&path).unwrap(); (path, bytes) })
        .collect::<BTreeMap<_, _>>();
    let mut encoder = encoder();
    let yuv = vec![128; encoder.yuvfmt().buffer_len];
    let frame = encoder.encode_to_message(EncodeInput::YUV(&yuv), 0).unwrap().unwrap();
    let frame = frame.union.as_ref().unwrap();
    let mut first = dir.recorder();
    let pending = dir.recorder();
    assert_eq!((snapshot().starting, snapshot().active), (2, 0));
    first.write_frame(frame, 64, 48).unwrap();
    assert_eq!((snapshot().starting, snapshot().active), (1, 1));
    let written = files();
    assert_eq!(written.len(), 1);
    assert!(written.values().all(|bytes| bytes.starts_with(&[0x1a, 0x45, 0xdf, 0xa3])));
    let canary_path = dir.0.join("limit-canary");
    let mut canary = fs::File::create(&canary_path).unwrap();
    let limit = FileLimit::zero();
    assert_eq!(canary.write_all(b"refused").unwrap_err().raw_os_error(), Some(libc::EFBIG));
    drop(first);
    drop(limit);
    drop(canary);
    fs::remove_file(canary_path).unwrap();
    let failure = Some(RecordingFailure { display: 0, camera: false, stage: FailureStage::Finish });
    assert_eq!(snapshot().last_failure, failure);
    assert_eq!((snapshot().starting, snapshot().active, snapshot().finishing), (1, 0, 0));
    assert_eq!(files(), written, "failed finalization must not rewrite existing bytes");
    drop(pending);
    assert_eq!(snapshot().writers(), 0);
    assert_eq!(snapshot().last_failure, failure, "unwritten completion must not clear the failure");
    let mut retry = dir.recorder();
    retry.write_frame(frame, 64, 48).unwrap();
    assert_eq!(snapshot().active, 1);
    assert_eq!(snapshot().last_failure, failure, "live counts and historical failure coexist");
    drop(retry);
    assert_eq!(snapshot().writers(), 0);
    assert_eq!(snapshot().last_failure, failure, "status reads must not consume failure");
    let finished = files();
    assert_eq!(finished.len(), 2);
    for (path, bytes) in written { assert_eq!(finished[&path], bytes); }
    assert_eq!(files(), finished, "retired writers cannot alter either file");
    println!("INCOMING_FINALIZATION=pass failure=retained retry=healthy owners=retired");
}
