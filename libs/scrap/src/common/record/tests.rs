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

struct FaultFile {
    file: File,
    mode: &'static str,
    observed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    seek_fail: std::sync::Arc<std::sync::atomic::AtomicBool>,
    dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl std::io::Write for FaultFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use std::{io::{Error, ErrorKind}, sync::atomic::Ordering};
        if self.mode == "interrupted" && !self.observed.swap(true, Ordering::SeqCst) {
            return Err(Error::from(ErrorKind::Interrupted));
        }
        if self.mode == "zero" {
            self.observed.store(true, Ordering::SeqCst);
            return Ok(0);
        }
        let len = if self.mode == "partial" {
            self.observed.store(true, Ordering::SeqCst);
            buf.len().min(3)
        } else { buf.len() };
        std::io::Write::write(&mut self.file, &buf[..len])
    }

    fn flush(&mut self) -> std::io::Result<()> { std::io::Write::flush(&mut self.file) }
}

impl std::io::Seek for FaultFile {
    fn seek(&mut self, from: std::io::SeekFrom) -> std::io::Result<u64> {
        use std::{io::{Error, ErrorKind, SeekFrom}, sync::atomic::Ordering};
        if matches!(from, SeekFrom::Start(_)) && self.seek_fail.load(Ordering::SeqCst) {
            self.observed.store(true, Ordering::SeqCst);
            return Err(Error::from(ErrorKind::Other));
        }
        std::io::Seek::seek(&mut self.file, from)
    }
}

impl Drop for FaultFile {
    fn drop(&mut self) { self.dropped.store(true, std::sync::atomic::Ordering::SeqCst); }
}

fn native_writer_fault(mode: &'static str) {
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    let dir = TestDir::new();
    let output = dir.0.join("fault.webm");
    let ctx = dir.context(&output, CodecFormat::VP8);
    let observed = Arc::new(AtomicBool::new(false));
    let seek_fail = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let file = FaultFile {
        file: OpenOptions::new().write(true).create_new(true).open(&output).unwrap(), mode,
        observed: observed.clone(), seek_fail: seek_fail.clone(), dropped: dropped.clone(),
    };
    let mut mux = WebmMux::new(file, &ctx).unwrap();
    let mut accepted = true;
    for frame in native_frames(VpxVideoCodecId::VP8) {
        accepted &= mux.add_frame(&frame.data, frame.pts as u64 * 1_000_000, frame.key);
        if !accepted { break; }
    }
    if mode == "seek" { seek_fail.store(true, Ordering::SeqCst); }
    let finalized = mux.finalize();
    assert!(dropped.load(Ordering::SeqCst), "native destination not retired");
    assert!(observed.load(Ordering::SeqCst), "requested I/O fault was not exercised");
    if mode == "zero" {
        assert!(!accepted && !finalized, "zero-byte write accepted");
        assert!(fs::read(&output).unwrap().is_empty());
    } else if mode == "seek" {
        assert!(accepted && !finalized, "absolute seek failure not reported at finalization");
    } else {
        assert!(accepted && finalized, "resumable writer I/O rejected: {mode}");
        assert_webm(&output, b"V_VP8");
    }
}

#[test]
fn native_partial_writes_are_completed() {
    isolated_mux_case("native_partial_writes_are_completed", || native_writer_fault("partial"));
}

#[test]
fn native_interrupted_write_is_retried() {
    isolated_mux_case("native_interrupted_write_is_retried", || native_writer_fault("interrupted"));
}

#[test]
fn native_zero_write_is_refused() {
    isolated_mux_case("native_zero_write_is_refused", || native_writer_fault("zero"));
}

#[test]
fn native_absolute_seek_failure_is_reported() {
    isolated_mux_case("native_absolute_seek_failure_is_reported", || native_writer_fault("seek"));
}

fn isolated_mux_case(name: &str, run: impl FnOnce()) {
    const CHILD: &str = "RUSTDESK_RECORDING_MUX_CHILD";
    let test = format!("common::record::tests::{name}");
    if std::env::var(CHILD).as_deref() == Ok(test.as_str()) {
        let no_core = crate::libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        assert_eq!(unsafe { crate::libc::setrlimit(crate::libc::RLIMIT_CORE, &no_core) }, 0);
        run();
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &test, "--test-threads=1", "--color", "never"])
        .env(CHILD, &test).env("RUST_BACKTRACE", "0").output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "isolated mux case {test}: {stdout}\n{stderr}");
    assert_eq!(stdout.matches("test result: ok. 1 passed; 0 failed;").count(), 1);
    assert!(stdout.contains(&format!("test {test} ... ok")));
}

#[test]
fn native_nonseekable_file_is_refused() {
    const CHILD: &str = "RUSTDESK_RECORDING_NONSEEKABLE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "common::record::tests::native_nonseekable_file_is_refused",
                "--test-threads=1", "--color", "never"])
            .env(CHILD, "1").env("RUST_BACKTRACE", "0").output().unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(output.status.success(), "isolated nonseekable case: {stdout}\n{stderr}");
        assert_eq!(stdout.matches("test result: ok. 1 passed; 0 failed;").count(), 1);
        return;
    }
    use std::{io::{Seek, SeekFrom}, os::fd::OwnedFd, os::unix::net::UnixStream};
    let no_core = crate::libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    assert_eq!(unsafe { crate::libc::setrlimit(crate::libc::RLIMIT_CORE, &no_core) }, 0);
    let (stream, peer) = UnixStream::pair().unwrap();
    let fd: OwnedFd = stream.into();
    let mut file = File::from(fd);
    assert_eq!(file.seek(SeekFrom::Current(0)).unwrap_err().raw_os_error(), Some(crate::libc::ESPIPE));
    let dir = TestDir::new();
    let ctx = dir.context(&dir.0.join("unused.webm"), CodecFormat::VP8);
    let refused = match WebmMux::new(file, &ctx) {
        Ok(mut mux) => {
            let frame = native_frames(VpxVideoCodecId::VP8).remove(0);
            let accepted = mux.add_frame(&frame.data, 0, true);
            !mux.finalize() && !accepted
        }
        Err(_) => true,
    };
    drop(peer);
    assert!(refused, "nonseekable destination accepted");
}

#[test]
fn native_invalid_mux_configuration_is_refused() {
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    let dir = TestDir::new();
    for (index, width, height, format) in [
        (0, 0, 48, CodecFormat::VP8), (1, usize::MAX, 48, CodecFormat::VP8),
        (2, 64, 0, CodecFormat::VP9), (3, 64, 48, CodecFormat::Unknown),
    ] {
        let output = dir.0.join(format!("invalid-{index}.webm"));
        let mut ctx = dir.context(&output, format);
        ctx.width = width; ctx.height = height;
        let dropped = Arc::new(AtomicBool::new(false));
        let file = FaultFile {
            file: OpenOptions::new().write(true).create_new(true).open(&output).unwrap(), mode: "none",
            observed: Arc::new(AtomicBool::new(false)), seek_fail: Arc::new(AtomicBool::new(false)),
            dropped: dropped.clone(),
        };
        let result = WebmMux::new(file, &ctx);
        let refused = result.is_err();
        drop(result);
        assert!(dropped.load(Ordering::SeqCst), "failed constructor retained its destination");
        assert!(refused, "invalid mux configuration accepted");
        assert!(fs::read(&output).unwrap().is_empty());
    }
}
