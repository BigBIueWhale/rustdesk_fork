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
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

extern crate self as hbb_common;
pub use protobuf_it::message_proto;
mod common {
    pub use anyhow::bail;
    pub type ResultType<T> = anyhow::Result<T>;
}
#[allow(dead_code)]
mod camera_types {
    include!(concat!(env!("OUT_DIR"), "/camera_types.rs"));
}
pub use camera_types::{Frame, PixelBuffer, Pixfmt, TraitCapturer, TraitPixelBuffer};
#[path = "../../../libs/scrap/src/common/frame_compare.rs"]
mod frame_compare;
pub use frame_compare::would_block_if_equal;
#[path = "../../../libs/scrap/src/common/camera.rs"]
#[allow(dead_code)]
mod product_camera;

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

fn drop_frames(control: &fs::File, percentage: i32) -> Result<()> {
    #[repr(C)]
    struct Control { id: u32, value: i32 }
    // Linux 6.1 vivid's Percentage of Dropped Buffers control. This is only
    // called after the fixture has established its exact no-NIC guest/principal.
    let mut value = Control { id: 0x00f0f040, value: percentage };
    for request in [v4l::v4l2::vidioc::VIDIOC_S_CTRL, v4l::v4l2::vidioc::VIDIOC_G_CTRL] {
        unsafe { v4l::v4l2::ioctl(control.as_raw_fd(), request, &mut value as *mut _ as *mut _)?; }
        require(value.value == percentage, "vivid did not apply the exact frame-drop control")?;
    }
    Ok(())
}

fn product_sample(selected: &mut dyn TraitCapturer) -> Result<Value> {
    let mut hashes = Vec::new();
    for _ in 0..20 {
        match selected.frame(Duration::from_millis(100)) {
            Ok(Frame::PixelBuffer(frame)) => {
                require(frame.width() == 640 && frame.height() == 360
                        && frame.pixfmt() == Pixfmt::RGBA && frame.stride() == 2560
                        && frame.data().len() == 921600, "recovered product pixel layout differs")?;
                hashes.push(format!("{:x}", Sha256::digest(frame.data())));
                if hashes.len() == 4 { break; }
            }
            Ok(Frame::Texture(_)) => return Err("camera returned a texture".into()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error.into()),
        }
    }
    require(hashes.len() == 4 && hashes.iter().collect::<BTreeSet<_>>().len() >= 2,
            "recovered product pixels did not advance")?;
    Ok(json!({"width": 640, "height": 360, "frame_bytes": 921600,
              "decoded_format": "RGBA", "frame_sha256": hashes}))
}

fn stalled_reads(selected: &mut dyn TraitCapturer, allow_queued: bool) -> Result<Vec<u128>> {
    let mut waits = Vec::new();
    for attempt in 0..10 {
        let started = Instant::now();
        let result = selected.frame(Duration::from_millis(100));
        let elapsed = started.elapsed().as_millis();
        require(elapsed < 800, "stalled camera exceeded its bounded frame wait")?;
        match result {
            Ok(_) => require(allow_queued && attempt < 5, "camera produced frames while stalled")?,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                // Duplicate buffered pixels may also return WouldBlock immediately.
                if elapsed >= 70 { waits.push(elapsed); }
                else { require(allow_queued && attempt < 5, "stalled camera spun without waiting")?; }
            }
            Err(error) => return Err(error.into()),
        }
        if waits.len() == 3 { break; }
    }
    require(waits.len() == 3, "three retryable frame deadlines were not observed")?;
    Ok(waits)
}

fn product_timeout() -> Result<()> {
    fn assert_send<T: Send>() {}
    assert_send::<nokhwa::backends::capture::V4LCaptureDevice>();
    require(query_indices()? == [0], "timeout fixture requires only native zero")?;
    let control = fs::OpenOptions::new().read(true).write(true).open("/dev/video0")?;
    drop_frames(&control, 100)?;
    // The inherited v4l stream's bounded path fails on its second read: the
    // timeout did not dequeue a buffer, but next() tries to queue index zero.
    let inherited_retry_errno;
    {
        use v4l::io::traits::CaptureStream;
        let device = v4l::Device::new(0)?;
        let mut stream = v4l::io::mmap::Stream::new(&device, v4l::buffer::Type::VideoCapture)?;
        stream.set_timeout(Duration::from_millis(100));
        let first = stream.next().err().ok_or("inherited stream did not stall")?;
        require(first.kind() == io::ErrorKind::TimedOut, "inherited timeout differs")?;
        inherited_retry_errno = stream.next().err().ok_or("inherited retry unexpectedly succeeded")?.raw_os_error();
        require(inherited_retry_errno == Some(libc::EINVAL), "inherited buffer retry failure differs")?;
    }
    product_camera::Cameras::all_info()?;
    let mut selected = product_camera::Cameras::get_capturer(0)?;
    let first_waits = stalled_reads(&mut *selected, false)?;
    let handles = video_handles()?;
    require(handles == [fs::metadata("/dev/video0")?.rdev(); 2], "timeout stream lost device ownership")?;
    drop_frames(&control, 0)?;
    let first_recovery = product_sample(&mut *selected)?;
    drop_frames(&control, 100)?;
    let second_waits = stalled_reads(&mut *selected, true)?;
    drop_frames(&control, 0)?;
    let second_recovery = product_sample(&mut *selected)?;
    require(video_handles()? == handles, "recovery changed retained camera handles")?;
    drop_frames(&control, 100)?;
    let final_waits = stalled_reads(&mut *selected, true)?;
    let started = Instant::now();
    drop(selected);
    let close_ms = started.elapsed().as_millis();
    require(close_ms < 800 && video_handles()?.len() == 1, "stalled product stream did not retire")?;
    // A fresh owner must be able to acquire buffers after the stopped owner.
    let mut fresh = product_camera::Cameras::get_capturer(0)?;
    let fresh_waits = stalled_reads(&mut *fresh, false)?;
    drop_frames(&control, 0)?;
    let fresh_recovery = product_sample(&mut *fresh)?;
    drop(fresh);
    drop(control);
    require(video_handles()?.is_empty(), "timeout fixture retained a device handle")?;
    emit(json!({"scenario": "product-timeout", "inherited_retry_errno": inherited_retry_errno,
                "waits_ms": [first_waits, second_waits, final_waits, fresh_waits],
                "recoveries": [first_recovery, second_recovery, fresh_recovery],
                "same_owner_recovery": true, "close_ms": close_ms, "device_handles_retired": true}))
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
        "--product-timeout" => product_timeout(),
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
        "--product-zero-control" => {
            require(query_indices()? == [0], "product control requires only native index zero")?;
            let advertised = product_camera::Cameras::all_info()?;
            require(advertised.len() == 1 && advertised[0].online, "product zero discovery differs")?;
            let resolution = product_camera::Cameras::get_camera_resolution(0)?;
            require(resolution.width == advertised[0].width && resolution.height == advertised[0].height,
                    "product resolution differs from its advertised metadata")?;
            let mut selected = product_camera::Cameras::get_capturer(0)?;
            let mut hashes = Vec::new();
            for _ in 0..12 {
                match selected.frame(std::time::Duration::from_millis(100)) {
                    Ok(Frame::PixelBuffer(frame)) => {
                        require(frame.width() == 640 && frame.height() == 360
                                && frame.pixfmt() == Pixfmt::RGBA && frame.stride() == 2560
                                && frame.data().len() == 921600, "product pixel layout differs")?;
                        hashes.push(format!("{:x}", Sha256::digest(frame.data())));
                        if hashes.len() == 4 { break; }
                    }
                    Ok(Frame::Texture(_)) => return Err("product camera unexpectedly returned a texture".into()),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            require(hashes.len() == 4 && hashes.iter().collect::<BTreeSet<_>>().len() >= 2,
                    "product camera pixels did not advance")?;
            drop(selected);
            require(video_handles()?.is_empty(), "product zero control retained its handle")?;
            emit(json!({"scenario": "product-zero-control", "native_index": 0,
                        "sample": {"width": 640, "height": 360, "frame_bytes": 921600,
                                   "decoded_format": "RGBA", "frame_sha256": hashes},
                        "device_handles_retired": true}))
        }
        "--product-nonzero-baseline" => {
            require(query_indices()? == [2], "product fixture requires only native index two")?;
            let advertised = product_camera::Cameras::all_info()?;
            require(advertised.len() == 1 && advertised[0].online
                    && advertised[0].width == 640 && advertised[0].height == 360,
                    "product did not advertise the actual native camera at ordinal zero")?;
            require(product_camera::primary_camera_exists(), "product primary presence check failed")?;
            require(video_handles()?.is_empty(), "product discovery retained a native device")?;
            let resolution_error = product_camera::Cameras::get_camera_resolution(0)
                .err().ok_or("product unexpectedly resolved the nonzero native camera")?.to_string();
            let capture_error = product_camera::Cameras::get_capturer(0)
                .err().ok_or("product unexpectedly opened the nonzero native camera")?.to_string();
            require(resolution_error.contains("No such file or directory")
                    && capture_error.contains("No such file or directory"),
                    "product failure was not absent-node acquisition")?;
            require(video_handles()?.is_empty(), "failed product acquisition left a device handle")?;
            let mut native = camera(2)?;
            let control = frames(&mut native)?;
            drop(native);
            require(video_handles()?.is_empty(), "positive native control retained its handle")?;
            emit(json!({"scenario": "product-nonzero-baseline", "advertised_count": advertised.len(),
                        "advertised_name": advertised[0].name, "width": advertised[0].width,
                        "height": advertised[0].height, "advertised_ordinal": 0, "native_index": 2,
                        "resolution_error": resolution_error, "capture_error": capture_error,
                        "native_control": control, "device_handles_retired": true,
                        "scope": "production-camera-module; full-application-unexecuted"}))
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
