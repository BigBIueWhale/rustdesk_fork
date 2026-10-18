use super::*;
use crate::{
    codec::{EncoderApi, EncoderCfg},
    vpxcodec::{VpxEncoder, VpxEncoderConfig, VpxVideoCodecId},
};
use hbb_common::{bytes::Bytes, uuid::Uuid};
use std::{
    fs,
    os::unix::fs::{symlink, DirBuilderExt, MetadataExt},
    path::Path,
};

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("rustdesk-recording-{}", Uuid::new_v4()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn context(&self, filename: &Path, format: CodecFormat) -> RecorderContext2 {
        RecorderContext2 {
            filename: filename.to_str().unwrap().into(),
            width: 64,
            height: 48,
            format,
        }
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn collision_preserves_target(kind: &str) {
    let dir = TestDir::new();
    let target = dir.0.join("target");
    let output = dir.0.join("recording.webm");
    let original = b"existing file must survive recording admission";
    if kind != "dangling-symlink" {
        fs::write(&target, original).unwrap();
    }
    match kind {
        "regular" => fs::rename(&target, &output).unwrap(),
        "hardlink" => fs::hard_link(&target, &output).unwrap(),
        "symlink" | "dangling-symlink" => symlink(&target, &output).unwrap(),
        _ => panic!("unknown collision fixture"),
    }
    let before = fs::symlink_metadata(&output).unwrap();
    let ctx = dir.context(&output, CodecFormat::VP8);
    let result = WebmRecorder::new(&ctx);
    let refused = result.is_err();
    drop(result);

    let after = fs::symlink_metadata(&output).expect("occupied recording entry preserved");
    assert_eq!((after.dev(), after.ino(), after.mode()),
        (before.dev(), before.ino(), before.mode()), "occupied recording entry changed");
    if kind == "dangling-symlink" {
        assert!(!target.exists(), "recording created the dangling symlink target");
    } else {
        assert_eq!(fs::read(&output).unwrap(), original, "existing bytes changed");
        if kind != "regular" {
            assert_eq!(fs::read(&target).unwrap(), original, "linked target bytes changed");
        }
    }
    if kind == "symlink" || kind == "dangling-symlink" {
        assert_eq!(fs::read_link(&output).unwrap(), target);
    }
    assert!(refused, "occupied output must refuse recording creation");
}

#[test]
fn existing_regular_file_is_preserved() { collision_preserves_target("regular"); }

#[test]
fn existing_hardlink_target_is_preserved() { collision_preserves_target("hardlink"); }

#[test]
fn existing_symlink_target_is_preserved() { collision_preserves_target("symlink"); }

#[test]
fn dangling_symlink_target_stays_absent() { collision_preserves_target("dangling-symlink"); }

fn native_frames(codec: VpxVideoCodecId) -> Vec<EncodedVideoFrame> {
    let mut encoder = VpxEncoder::new(EncoderCfg::VPX(VpxEncoderConfig {
        width: 64, height: 48, quality: 1.0, codec, keyframe_interval: None,
    }), false).expect("native recording encoder");
    let yuv = vec![128; 64 * 48 * 3 / 2];
    let mut frames: Vec<_> = encoder.encode(0, &yuv, 1).unwrap()
        .map(|f| EncodedVideoFrame { data: Bytes::copy_from_slice(f.data), key: f.key, ..Default::default() })
        .collect();
    frames.extend(encoder.flush().unwrap()
        .map(|f| EncodedVideoFrame { data: Bytes::copy_from_slice(f.data), key: f.key, ..Default::default() }));
    assert_eq!(frames.len(), 1);
    assert!(frames[0].key);
    let mut second = frames[0].clone();
    second.pts = 2000;
    frames.push(second);
    frames
}

fn write_native_video(recorder: &mut WebmRecorder, codec: VpxVideoCodecId) {
    for frame in native_frames(codec) {
        assert!(recorder.write_video(&frame));
    }
}

fn assert_webm(path: &Path, codec_id: &[u8]) {
    let webm = fs::read(path).expect("completed recording retained");
    assert!(webm.starts_with(&[0x1a, 0x45, 0xdf, 0xa3]), "native EBML header");
    assert!(webm.windows(codec_id.len()).any(|part| part == codec_id), "native video track codec");
}

fn fresh_recording(codec: VpxVideoCodecId, format: CodecFormat, codec_id: &[u8]) {
    let dir = TestDir::new();
    let output = dir.0.join("fresh.webm");
    let ctx = dir.context(&output, format);
    let mut recorder = WebmRecorder::new(&ctx).expect("fresh recording admitted");
    write_native_video(&mut recorder, codec);
    drop(recorder);
    assert_webm(&output, codec_id);
}

#[test]
fn fresh_vp8_recording_finalizes() {
    fresh_recording(VpxVideoCodecId::VP8, CodecFormat::VP8, b"V_VP8");
}

#[test]
fn fresh_vp9_recording_finalizes() {
    fresh_recording(VpxVideoCodecId::VP9, CodecFormat::VP9, b"V_VP9");
}

fn replaced_output_survives(kind: &str) {
    let dir = TestDir::new();
    let parent = dir.0.join("active");
    fs::create_dir(&parent).unwrap();
    let output = parent.join("recording.webm");
    let ctx = dir.context(&output, CodecFormat::VP8);
    let mut recorder = WebmRecorder::new(&ctx).unwrap();
    let before = fs::metadata(&output).unwrap();
    if kind == "written" {
        write_native_video(&mut recorder, VpxVideoCodecId::VP8);
    }
    let saved = if kind == "parent" {
        let displaced = dir.0.join("displaced");
        fs::rename(&parent, &displaced).unwrap();
        let substitute = dir.0.join("substitute");
        fs::create_dir(&substitute).unwrap();
        symlink(&substitute, &parent).unwrap();
        displaced.join("recording.webm")
    } else {
        let saved = dir.0.join("owned.webm");
        fs::rename(&output, &saved).unwrap();
        saved
    };
    let victim = dir.0.join("victim");
    let original = b"replacement entry must survive unrelated recorder cleanup";
    if kind == "symlink" {
        fs::write(&victim, original).unwrap();
        symlink(&victim, &output).unwrap();
    } else {
        fs::write(&output, original).unwrap();
    }
    let replacement = fs::symlink_metadata(&output).unwrap();
    drop(recorder);
    let after = fs::symlink_metadata(&output).expect("replacement entry preserved");
    assert_eq!((after.dev(), after.ino(), after.mode()),
        (replacement.dev(), replacement.ino(), replacement.mode()));
    assert_eq!(fs::read(&output).unwrap(), original);
    if kind == "symlink" {
        assert_eq!(fs::read_link(&output).unwrap(), victim);
        assert_eq!(fs::read(&victim).unwrap(), original);
    }
    let owned = fs::metadata(&saved).unwrap();
    assert_eq!((owned.dev(), owned.ino()), (before.dev(), before.ino()));
    if kind == "written" {
        assert_webm(&saved, b"V_VP8");
    }
}

#[test]
fn replacement_regular_entry_survives_recorder_drop() {
    replaced_output_survives("regular");
}

#[test]
fn replacement_symlink_entry_survives_recorder_drop() {
    replaced_output_survives("symlink");
}

#[test]
fn replacement_parent_symlink_survives_recorder_drop() {
    replaced_output_survives("parent");
}

#[test]
fn renamed_recording_finalizes_without_removing_replacement() {
    replaced_output_survives("written");
}

fn vp8_batch(frame: EncodedVideoFrame) -> video_frame::Union {
    video_frame::Union::Vp8s(hbb_common::message_proto::EncodedVideoFrames {
        frames: vec![frame],
        ..Default::default()
    })
}

struct FileLimit {
    limit: crate::libc::rlimit,
    signal: crate::libc::sighandler_t,
}

impl FileLimit {
    fn zero() -> Self {
        use crate::libc;
        let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit) }, 0);
        let signal = unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) };
        assert_ne!(signal, libc::SIG_ERR);
        let guard = Self { limit, signal };
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: limit.rlim_max };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &zero) }, 0);
        let mut actual = limit;
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut actual) }, 0);
        assert_eq!((actual.rlim_cur, actual.rlim_max), (0, limit.rlim_max));
        guard
    }
}

impl Drop for FileLimit {
    fn drop(&mut self) {
        use crate::libc;
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &self.limit) }, 0);
        assert_ne!(unsafe { libc::signal(libc::SIGXFSZ, self.signal) }, libc::SIG_ERR);
    }
}

fn rejected_recording_is_terminal(file_limit: bool) {
    use std::io::Write;
    let dir = TestDir::new();
    let mut recorder = Recorder::new(RecorderContext {
        server: false, id: "native-rejection".into(), dir: dir.0.to_str().unwrap().into(),
        display_idx: 0, camera: false,
    }).unwrap();
    let mut frames = native_frames(VpxVideoCodecId::VP8);
    recorder.write_frame(&vp8_batch(frames.remove(0)), 64, 48).unwrap();
    let output = PathBuf::from(&recorder.ctx2.as_ref().unwrap().filename);
    let mut rejected = frames.remove(0);
    let limit = if file_limit {
        let mut canary = OpenOptions::new().write(true).create_new(true)
            .open(dir.0.join("limit-canary")).unwrap();
        let guard = FileLimit::zero();
        assert_eq!(canary.write_all(b"x").unwrap_err().raw_os_error(), Some(crate::libc::EFBIG));
        Some(guard)
    } else {
        rejected.data = Bytes::new();
        None
    };
    let result = recorder.write_frame(&vp8_batch(rejected), 64, 48);
    drop(limit);
    assert!(result.is_err(), "native mux rejection was reported as success");
    assert!(recorder.inner.is_none(), "failed native output is still admitted");
    let bytes = fs::read(&output).unwrap();
    let entries = fs::read_dir(&dir.0).unwrap().count();
    let next = vp8_batch(native_frames(VpxVideoCodecId::VP8).remove(0));
    assert!(recorder.write_frame(&next, 64, 48).is_err(), "failed output resumed");
    assert!(recorder.write_frame(&next, 128, 96).is_err(), "resize reopened failed output");
    assert!(recorder.inner.is_none());
    assert_eq!(fs::read_dir(&dir.0).unwrap().count(), entries);
    drop(recorder);
    assert_eq!(fs::read(&output).unwrap(), bytes, "failed output changed after retirement");
}

#[test]
fn native_empty_frame_rejection_is_terminal() {
    rejected_recording_is_terminal(false);
}

#[test]
fn native_file_limit_failure_is_terminal() {
    const CHILD: &str = "RUSTDESK_RECORDING_FSIZE_CHILD";
    if std::env::var_os(CHILD).is_some() {
        rejected_recording_is_terminal(true);
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "common::record::tests::native_file_limit_failure_is_terminal",
            "--test-threads=1", "--color", "never"])
        .env(CHILD, "1").output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "isolated file-limit case: {stdout}\n{stderr}");
    assert_eq!(stdout.matches("test result: ok. 1 passed; 0 failed;").count(), 1);
    assert!(stdout.contains("test common::record::tests::native_file_limit_failure_is_terminal ... ok"));
}
