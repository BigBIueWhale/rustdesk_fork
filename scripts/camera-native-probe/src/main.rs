use nokhwa::{
    pixel_format::RgbAFormat,
    query,
    utils::{ApiBackend, CameraIndex, RequestedFormat, RequestedFormatType},
    Camera,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    error::Error,
    fs,
    io::{self, Write},
    os::unix::fs::{FileTypeExt, MetadataExt},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn emit(value: Value) -> Result<()> {
    println!("{value}");
    io::stdout().flush()?;
    Ok(())
}

fn camera(index: u32) -> Result<Camera> {
    Ok(Camera::new(
        CameraIndex::Index(index),
        RequestedFormat::new::<RgbAFormat>(RequestedFormatType::None),
    )?)
}

fn query_indices() -> Result<Vec<u32>> {
    let mut indices = query(ApiBackend::Auto)?
        .iter()
        .map(|info| info.index().as_index())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    indices.sort_unstable();
    Ok(indices)
}

fn video_handles() -> Result<Vec<u64>> {
    let mut devices = Vec::new();
    for entry in fs::read_dir("/proc/self/fd")? {
        let path = entry?.path();
        let info = match fs::metadata(path) {
            Ok(info) => info,
            // The directory iterator itself may retire its descriptor at end-of-directory.
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if info.file_type().is_char_device() && libc::major(info.rdev()) == 81 {
            devices.push(info.rdev());
        }
    }
    devices.sort_unstable();
    Ok(devices)
}

fn frames(camera: &mut Camera) -> Result<Value> {
    camera.open_stream()?;
    let sample = sample_frames(camera)?;
    camera.stop_stream()?;
    Ok(sample)
}

fn sample_frames(camera: &mut Camera) -> Result<Value> {
    let resolution = camera.resolution();
    let (width, height) = (resolution.width(), resolution.height());
    require(width > 0 && width <= 1920 && height > 0 && height <= 1080,
            "native resolution exceeds fixture bounds")?;
    let expected = (width as usize)
        .checked_mul(height as usize)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or("native frame length overflow")?;
    let mut hashes = Vec::new();
    for _ in 0..4 {
        let frame = camera.frame()?;
        let decoded = frame.decode_image::<RgbAFormat>()?;
        require(decoded.width() == width && decoded.height() == height
                && decoded.as_raw().len() == expected, "native metadata/frame shape differs")?;
        hashes.push(format!("{:x}", Sha256::digest(decoded.as_raw())));
    }
    require(hashes.iter().collect::<BTreeSet<_>>().len() >= 2,
            "native decoded frame content did not advance")?;
    Ok(json!({"width": width, "height": height, "frame_bytes": expected,
              "frame_sha256": hashes, "decoded_format": "RGBA"}))
}

fn main_result() -> Result<()> {
    require(unsafe { libc::getuid() == 4000 && libc::getgid() == 4000
            && libc::geteuid() == 4000 && libc::getegid() == 4000
            && libc::getgroups(0, std::ptr::null_mut()) == 0 },
            "capture requires the exact unprivileged fixture principal")?;
    let cmdline = fs::read_to_string("/proc/cmdline")?;
    require(cmdline.split_whitespace().filter(|word| *word == "rustdesk.media_vm=1").count() == 1,
            "native capture requires its isolated media VM")?;
    let interfaces = fs::read_dir("/sys/class/net")?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    require(interfaces.len() == 1 && interfaces[0] == "lo", "guest interface inventory differs")?;
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    require(args.len() == 1, "one closed native scenario is required")?;
    match args[0].as_str() {
        "--capture" => {
            let indices = query_indices()?;
            require(indices == [2], "nokhwa did not discover only native index two")?;
            require(camera(0).is_err(), "native zero unexpectedly opened")?;
            let mut selected = camera(indices[0])?;
            let sample = frames(&mut selected)?;
            let name = selected.info().human_name();
            let handles = video_handles()?;
            require(handles == [fs::metadata("/dev/video2")?.rdev()], "capture handle differs from native node")?;
            drop(selected);
            require(video_handles()?.is_empty(), "native capture retained a device handle after drop")?;
            emit(json!({"scenario": "capture", "indices": indices, "name": name,
                        "sample": sample, "device_handles_retired": true}))
        }
        "--two-retained" => {
            require(query_indices()? == [2, 3], "two-device native discovery differs")?;
            let mut first = camera(2)?;
            let sample = frames(&mut first)?;
            let mut second = camera(3)?;
            let second_sample = frames(&mut second)?;
            let retained = video_handles()?;
            let mut expected = vec![fs::metadata("/dev/video2")?.rdev(), fs::metadata("/dev/video3")?.rdev()];
            expected.sort_unstable();
            require(retained == expected, "retained cameras do not own distinct native handles")?;
            drop(second);
            require(video_handles()? == [fs::metadata("/dev/video2")?.rdev()], "second drop changed the first owner")?;
            let resumed_sample = frames(&mut first)?;
            drop(first);
            require(video_handles()?.is_empty(), "retained cameras left a device handle")?;
            emit(json!({"scenario": "two-retained", "first_sample": sample,
                        "second_sample": second_sample, "resumed_sample": resumed_sample,
                        "retained_rdevs": retained, "device_handles_retired": true}))
        }
        "--stream-ownership" => {
            require(query_indices()? == [2, 3], "stream ownership discovery differs")?;
            let native = fs::metadata("/dev/video2")?.rdev();
            let mut first = camera(2)?;
            first.open_stream()?;
            let initial = sample_frames(&mut first)?;
            let mut competing = camera(2)?;
            require(video_handles()? == [native, native], "separate opens share a device handle")?;
            let error = competing.open_stream().err().ok_or("competing stream unexpectedly acquired the device")?;
            require(!competing.is_stream_open(), "failed competing open retained a stream")?;
            drop(competing);
            require(video_handles()? == [native], "competing drop changed the incumbent handle")?;
            let preserved = sample_frames(&mut first)?;
            first.stop_stream()?;
            drop(first);
            require(video_handles()?.is_empty(), "stream owner did not retire its handle")?;
            let mut fresh = camera(2)?;
            let retry = frames(&mut fresh)?;
            drop(fresh);
            require(video_handles()?.is_empty(), "fresh stream left a device handle")?;
            emit(json!({"scenario": "stream-ownership", "initial": initial, "preserved": preserved,
                        "retry": retry, "competing_error": error.to_string(), "device_handles_retired": true}))
        }
        "--reuse" => {
            require(query_indices()? == [2, 3], "reuse native discovery differs")?;
            let original = fs::metadata("/dev/video2")?.rdev();
            let replacement = fs::metadata("/dev/video3")?.rdev();
            require(original != replacement, "fixture devices do not have distinct native identities")?;
            let mut first = camera(2)?;
            let sample = frames(&mut first)?;
            emit(json!({"scenario": "reuse-ready", "original_rdev": original,
                        "replacement_rdev": replacement, "first_sample": sample}))?;
            let mut request = String::new();
            io::stdin().read_line(&mut request)?;
            require(request == "reuse\n", "native reuse handoff differs")?;
            require(fs::metadata("/dev/video2")?.rdev() == replacement,
                    "current node did not acquire the replacement identity")?;
            let mut second = camera(2)?;
            let retained = video_handles()?;
            let mut expected = vec![original, replacement];
            expected.sort_unstable();
            require(retained == expected, "fresh open did not retain the replacement node")?;
            let replacement_sample = frames(&mut second)?;
            drop(second);
            require(video_handles()? == [original], "replacement drop changed the original owner")?;
            let original_sample = frames(&mut first)?;
            drop(first);
            require(video_handles()?.is_empty(), "reuse left a native device handle after drop")?;
            emit(json!({"scenario": "reuse", "current_node_rdev": replacement,
                        "retained_rdevs": retained, "replacement_sample": replacement_sample,
                        "original_sample": original_sample, "device_handles_retired": true}))
        }
        _ => Err("unknown native camera scenario".into()),
    }
}

fn main() {
    if let Err(error) = main_result() {
        eprintln!("CAMERA_NATIVE_FAILURE={error}");
        std::process::exit(1);
    }
}
