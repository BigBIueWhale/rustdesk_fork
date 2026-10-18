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
    time::Duration,
};

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("rustdesk-recording-{}", Uuid::new_v4()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn context(&self, filename: &Path, format: CodecFormat) -> (RecorderContext, RecorderContext2) {
        (
            RecorderContext {
                server: false,
                id: "recording-test".into(),
                dir: self.0.to_str().unwrap().into(),
                display_idx: 0,
                camera: false,
                tx: None,
            },
            RecorderContext2 {
                filename: filename.to_str().unwrap().into(),
                width: 64,
                height: 48,
                format,
            },
        )
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
    let (ctx, ctx2) = dir.context(&output, CodecFormat::VP8);
    let result = WebmRecorder::new(ctx, ctx2);
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

fn fresh_recording(codec: VpxVideoCodecId, format: CodecFormat, codec_id: &[u8]) {
    let dir = TestDir::new();
    let output = dir.0.join("fresh.webm");
    let (ctx, ctx2) = dir.context(&output, format);
    let mut recorder = WebmRecorder::new(ctx, ctx2).expect("fresh recording admitted");
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
    assert!(recorder.write_video(&frames[0]));
    frames[0].pts = 2000;
    assert!(recorder.write_video(&frames[0]));
    recorder.start = Instant::now().checked_sub(Duration::from_secs(MIN_SECS + 1)).unwrap();
    drop(recorder);
    let webm = fs::read(&output).expect("completed recording retained");
    assert!(webm.starts_with(&[0x1a, 0x45, 0xdf, 0xa3]), "native EBML header");
    assert!(webm.windows(codec_id.len()).any(|part| part == codec_id), "native video track codec");
}

#[test]
fn fresh_vp8_recording_finalizes() {
    fresh_recording(VpxVideoCodecId::VP8, CodecFormat::VP8, b"V_VP8");
}

#[test]
fn fresh_vp9_recording_finalizes() {
    fresh_recording(VpxVideoCodecId::VP9, CodecFormat::VP9, b"V_VP9");
}
