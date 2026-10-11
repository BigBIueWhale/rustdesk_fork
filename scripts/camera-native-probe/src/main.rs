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
    let mut devices = BTreeSet::new();
    for entry in fs::read_dir("/proc/self/fd")? {
        let path = entry?.path();
        let info = match fs::metadata(path) {
            Ok(info) => info,
            // The directory iterator itself may retire its descriptor at end-of-directory.
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if info.file_type().is_char_device() && libc::major(info.rdev()) == 81 {
            devices.insert(info.rdev());
        }
    }
    Ok(devices.into_iter().collect())
}

fn frames(camera: &mut Camera) -> Result<Value> {
    let resolution = camera.resolution();
    let (width, height) = (resolution.width(), resolution.height());
    require(width > 0 && width <= 1920 && height > 0 && height <= 1080,
            "native resolution exceeds fixture bounds")?;
    let expected = (width as usize)
        .checked_mul(height as usize)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or("native frame length overflow")?;
    camera.open_stream()?;
    let mut hashes = Vec::new();
    for _ in 0..4 {
        let frame = camera.frame()?;
        let decoded = frame.decode_image::<RgbAFormat>()?;
        require(decoded.width() == width && decoded.height() == height
                && decoded.as_raw().len() == expected, "native metadata/frame shape differs")?;
        hashes.push(format!("{:x}", Sha256::digest(decoded.as_raw())));
    }
    camera.stop_stream()?;
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
        "--two-retained-baseline" => {
            require(query_indices()? == [2, 3], "two-device native discovery differs")?;
            let mut first = camera(2)?;
            let sample = frames(&mut first)?;
            emit(json!({"scenario": "two-retained-baseline", "first_sample": sample,
                        "first_handles": video_handles()?, "next_operation": "open-native-three"}))?;
            let _second = camera(3)?;
            Err("the pinned second-device assertion unexpectedly returned".into())
        }
        "--reuse-baseline" => {
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
            let second = camera(2)?;
            let retained = video_handles()?;
            require(retained == [original], "pinned cached handle behavior differs")?;
            drop(second);
            drop(first);
            require(video_handles()?.is_empty(), "reuse left a native device handle after drop")?;
            emit(json!({"scenario": "reuse-baseline", "current_node_rdev": replacement,
                        "retained_rdevs": retained, "device_handles_retired": true}))
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
