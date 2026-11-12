pub mod compress;
pub mod connection_time;
pub mod platform;
pub mod protos;
pub use bytes;
pub use futures;
pub use protobuf;
pub use protos::message as message_proto;
pub use protos::rendezvous as rendezvous_proto;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{self, SystemTime, UNIX_EPOCH},
};
pub use tokio;
pub use tokio_util;
/// Exact controlled-video receipt contract: keyed parse of a nonzero display/generation frame,
/// acknowledged before decode or presentation.
pub const VIDEO_FRAME_RECEIPT_VERSION: u32 = 1;
pub mod cpace;
pub mod socket_client;
pub mod socket_surface;
pub mod tcp;
#[cfg(test)]
#[path = "../../../scripts/fixtures/tcp-constructor-before-resolution-boundary.rs"]
mod tcp_constructor_before_resolution_boundary;
pub use env_logger;
pub use log;
pub mod bytes_codec;
pub use anyhow::{self, bail};
pub use futures_util;
pub mod config;
pub mod fs;
pub use lazy_static;
pub use rand;
pub use regex;
pub use sodiumoxide;
pub mod password_security;
pub use chrono;
pub use directories_next;
pub use libc;
pub mod keyboard;
pub use base64;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub use dlopen;
pub use flexi_logger;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub use machine_uid;
pub use serde_derive;
pub use serde_json;
pub use sha2;
pub use sysinfo;
pub use thiserror;
pub use toml;
pub use uuid;
pub mod stream;
#[cfg(any(target_os = "android", target_os = "ios"))]
pub use rustls_platform_verifier;
pub use stream::Stream;
pub use whoami;
pub use libloading;
#[cfg(target_os = "linux")]
pub use users;
#[cfg(target_os = "linux")]
pub use x11;

pub type SessionID = uuid::Uuid;

#[inline]
pub async fn sleep(sec: f32) {
    tokio::time::sleep(time::Duration::from_secs_f32(sec)).await;
}

#[cfg(test)]
mod exact_video_receipt_wire_tests {
    use crate::{
        message_proto::{message, LoginRequest, Message, PeerInfo, VideoFrame, VideoFrameReceipt},
        protobuf::Message as _,
        VIDEO_FRAME_RECEIPT_VERSION,
    };

    #[test]
    fn r_s11fk_wire_tags_and_identity_are_exact() {
        let mut video_message = Message::new();
        video_message.set_video_frame(VideoFrame {
            display: 3,
            generation: 91,
            ..Default::default()
        });
        let encoded = video_message.write_to_bytes().unwrap();
        assert_eq!(
            encoded.as_slice(),
            &[0x32, 0x04, 0x70, 0x03, 0x78, 0x5b],
            "Message.video_frame=6, VideoFrame.display=14, and VideoFrame.generation=15 are wire compatibility"
        );
        let parsed = Message::parse_from_bytes(&encoded).unwrap();
        let Some(message::Union::VideoFrame(frame)) = parsed.union else {
            panic!("video frame must retain its top-level wire type");
        };
        assert_eq!((frame.display, frame.generation), (3, 91));

        let mut receipt_message = Message::new();
        receipt_message.set_video_frame_receipt(VideoFrameReceipt {
            display: 3,
            generation: 91,
            ..Default::default()
        });
        let encoded = receipt_message.write_to_bytes().unwrap();
        assert_eq!(
            encoded.as_slice(),
            &[0x8a, 0x02, 0x04, 0x08, 0x03, 0x10, 0x5b],
            "Message.video_frame_receipt=33 and its display=1/generation=2 identity are wire compatibility"
        );
        let parsed = Message::parse_from_bytes(&encoded).unwrap();
        let Some(message::Union::VideoFrameReceipt(receipt)) = parsed.union else {
            panic!("video receipt must retain its top-level wire type");
        };
        assert_eq!((receipt.display, receipt.generation), (3, 91));

        let login = LoginRequest {
            video_frame_receipt_version: VIDEO_FRAME_RECEIPT_VERSION,
            ..Default::default()
        };
        let encoded = login.write_to_bytes().unwrap();
        assert_eq!(
            encoded.as_slice(),
            &[0x90, 0x01, 0x01],
            "LoginRequest.video_frame_receipt_version=18 is wire compatibility"
        );
        let parsed = LoginRequest::parse_from_bytes(&encoded).unwrap();
        assert_eq!(
            parsed.video_frame_receipt_version,
            VIDEO_FRAME_RECEIPT_VERSION
        );

        let peer_info = PeerInfo {
            video_frame_receipt_version: VIDEO_FRAME_RECEIPT_VERSION,
            ..Default::default()
        };
        let encoded = peer_info.write_to_bytes().unwrap();
        assert_eq!(
            encoded.as_slice(),
            &[0x70, 0x01],
            "PeerInfo.video_frame_receipt_version=14 is wire compatibility"
        );
        let parsed = PeerInfo::parse_from_bytes(&encoded).unwrap();
        assert_eq!(
            parsed.video_frame_receipt_version,
            VIDEO_FRAME_RECEIPT_VERSION
        );
    }
}

#[macro_export]
macro_rules! allow_err {
    ($e:expr) => {
        if let Err(err) = $e {
            log::debug!(
                "{:?}, {}:{}:{}:{}",
                err,
                module_path!(),
                file!(),
                line!(),
                column!()
            );
        } else {
        }
    };

    ($e:expr, $($arg:tt)*) => {
        if let Err(err) = $e {
            log::debug!(
                "{:?}, {}, {}:{}:{}:{}",
                err,
                format_args!($($arg)*),
                module_path!(),
                file!(),
                line!(),
                column!()
            );
        } else {
        }
    };
}

#[inline]
pub fn timeout<T: std::future::Future>(ms: u64, future: T) -> tokio::time::Timeout<T> {
    tokio::time::timeout(std::time::Duration::from_millis(ms), future)
}

pub type ResultType<F, E = anyhow::Error> = anyhow::Result<F, E>;

#[inline]
pub fn try_into_v4(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) if !addr.ip().is_loopback() => {
            if let Some(v4) = v6.ip().to_ipv4() {
                SocketAddr::new(IpAddr::V4(v4), addr.port())
            } else {
                addr
            }
        }
        _ => addr,
    }
}

// Support 1.1.10-1, the number after - is a patch version.
// An unrepresentable version is unknown (0), independent of overflow-check settings.
pub fn get_version_number(v: &str) -> i64 {
    let mut versions = v.split('-');

    let mut n = 0i64;

    // The first part is the version number.
    // 1.1.10 -> 1001100, 1.2.3 -> 1002030, multiply the last number by 10
    // to leave space for patch version.
    if let Some(v) = versions.next() {
        let mut last = 0;
        for x in v.split('.') {
            last = x.parse::<i64>().unwrap_or(0);
            let Some(next) = n.checked_mul(1000).and_then(|n| n.checked_add(last)) else {
                return 0;
            };
            n = next;
        }
        let Some(base) = n.checked_sub(last) else {
            return 0;
        };
        let Some(next) = last.checked_mul(10).and_then(|last| base.checked_add(last)) else {
            return 0;
        };
        n = next;
    }

    if let Some(v) = versions.next() {
        let Some(next) = n.checked_add(v.parse::<i64>().unwrap_or(0)) else {
            return 0;
        };
        n = next;
    }

    // Ignore the rest

    n
}

pub fn get_modified_time(path: &std::path::Path) -> SystemTime {
    std::fs::metadata(path)
        .map(|m| m.modified().unwrap_or(UNIX_EPOCH))
        .unwrap_or(UNIX_EPOCH)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn machine_uuid() -> ResultType<Vec<u8>> {
    static CACHED_MACHINE_UID: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();

    #[cfg(target_os = "macos")]
    {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let username = whoami::username().trim_end_matches('\0').to_owned();
            let max_retries = if username == "root" { 16 } else { 8 };
            for i in 0..max_retries {
                match machine_uid::get() {
                    Ok(id) => {
                        let _ = CACHED_MACHINE_UID.set(id.into());
                        return;
                    }
                    Err(e) => {
                        log::error!("Failed to get machine uid in macOS retry #{i}: {e}");
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        });
    }

    if let Some(uid) = CACHED_MACHINE_UID.get() {
        return Ok(uid.clone());
    }

    match machine_uid::get() {
        Ok(id) => {
            let uid: Vec<u8> = id.into();
            if uid.is_empty() {
                bail!("machine uid is empty");
            }
            let _ = CACHED_MACHINE_UID.set(uid.clone());
            Ok(uid)
        }
        Err(e) => Err(anyhow::anyhow!("failed to get machine uid: {e}")),
    }
}

#[cfg(any(target_os = "android", target_os = "ios"))]
lazy_static::lazy_static! {
    static ref MOBILE_AT_REST_STORAGE_KEY: std::sync::RwLock<Option<Vec<u8>>> =
        std::sync::RwLock::new(None);
}

#[cfg(any(target_os = "android", target_os = "ios"))]
pub const MOBILE_AT_REST_STORAGE_KEY_LEN: usize = sodiumoxide::crypto::secretbox::KEYBYTES;

#[cfg(any(target_os = "android", target_os = "ios"))]
pub fn set_mobile_at_rest_storage_key(key: &[u8]) -> ResultType<()> {
    if key.len() != MOBILE_AT_REST_STORAGE_KEY_LEN {
        bail!(
            "mobile at-rest storage key has invalid length: {}",
            key.len()
        );
    }

    let nonce = sodiumoxide::crypto::secretbox::gen_nonce();
    let mut key_bytes = [0u8; sodiumoxide::crypto::secretbox::KEYBYTES];
    key_bytes.copy_from_slice(key);
    let secretbox_key = sodiumoxide::crypto::secretbox::Key(key_bytes);
    let plaintext = b"rustdesk-mobile-at-rest-key-self-test";
    let ciphertext = sodiumoxide::crypto::secretbox::seal(plaintext, &nonce, &secretbox_key);
    let opened = sodiumoxide::crypto::secretbox::open(&ciphertext, &nonce, &secretbox_key)
        .map_err(|_| anyhow::anyhow!("mobile at-rest storage key self-test failed"))?;
    if opened != plaintext {
        bail!("mobile at-rest storage key self-test mismatch");
    }

    *MOBILE_AT_REST_STORAGE_KEY.write().unwrap() = Some(key.to_vec());
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn mobile_at_rest_storage_key() -> ResultType<Vec<u8>> {
    MOBILE_AT_REST_STORAGE_KEY
        .read()
        .unwrap()
        .clone()
        .ok_or_else(|| anyhow::anyhow!("mobile OS at-rest storage key is not initialized"))
}

pub fn at_rest_storage_key() -> ResultType<Vec<u8>> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        return machine_uuid();
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        mobile_at_rest_storage_key()
    }
}

#[inline]
pub fn get_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0) as _
}

#[inline]
pub fn is_ipv4_str(id: &str) -> bool {
    let host = match id.split_once(':') {
        Some((host, port)) if is_direct_port(port) => host,
        Some(_) => return false,
        None => id,
    };
    host.parse::<Ipv4Addr>().is_ok()
}

#[inline]
pub fn is_ipv6_str(id: &str) -> bool {
    id.parse::<std::net::Ipv6Addr>().is_ok() || id.parse::<std::net::SocketAddrV6>().is_ok()
}

/// The direct peer grammar; socket-formatting support does not widen admission.
#[inline]
pub fn is_direct_address(address: &str) -> bool {
    address.len() <= 260 && (is_ipv4_str(address) || is_domain_port_str(address))
}

fn is_direct_port(port: &str) -> bool {
    !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|port| port != 0)
}

#[inline]
pub fn is_domain_port_str(id: &str) -> bool {
    let Some((host, port)) = id.split_once(':') else {
        return false;
    };
    let name = host.strip_suffix('.').unwrap_or(host);
    if !is_direct_port(port) || name.len() > 253 || !name.contains('.') {
        return false;
    }
    name.rsplit('.').next().is_some_and(|label| {
        label.bytes().any(|byte| byte.is_ascii_alphabetic())
    }) && name.split('.').all(|label| {
        let bytes = label.as_bytes();
        bytes.len() <= 63
            && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    })
}

#[cfg(any(test, not(debug_assertions)))]
fn file_logger(
    is_async: bool,
    path: std::path::PathBuf,
) -> Result<flexi_logger::Logger, flexi_logger::FlexiLoggerError> {
    use flexi_logger::*;
    Ok(Logger::try_with_env_or_str("debug,rustls=warn")?
        .log_to_file(FileSpec::default().directory(path))
        .write_mode(if is_async {
            WriteMode::Async
        } else {
            WriteMode::Direct
        })
        .format(opt_format)
        .rotate(
            Criterion::AgeOrSize(Age::Day, 4 * 1024 * 1024),
            Naming::Timestamps,
            Cleanup::KeepLogFiles(31),
        ))
}

pub fn init_log(_is_async: bool, _name: &str) -> Option<flexi_logger::LoggerHandle> {
    static INIT: std::sync::Once = std::sync::Once::new();
    #[allow(unused_mut)]
    let mut logger_holder: Option<flexi_logger::LoggerHandle> = None;
    INIT.call_once(|| {
        #[cfg(debug_assertions)]
        {
            use env_logger::*;
            init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info,rustls=warn"));
        }
        #[cfg(not(debug_assertions))]
        {
            // https://docs.rs/flexi_logger/latest/flexi_logger/error_info/index.html#write
            // though async logger more efficient, but it also causes more problems, disable it for now
            let mut path = config::Config::log_path();
            #[cfg(target_os = "android")]
            if !config::Config::get_home().exists() {
                return;
            }
            if !_name.is_empty() {
                path.push(_name);
            }
            if let Ok(logger) = file_logger(_is_async, path) {
                logger_holder = logger.start().ok();
            }
        }
    });
    logger_holder
}

#[cfg(test)]
mod test {
    use super::*;

    struct LogDirectory(std::path::PathBuf);

    impl LogDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "rustdesk-log-rotation-{}",
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn logs(&self) -> Vec<std::path::PathBuf> {
            std::fs::read_dir(&self.0)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.extension().is_some_and(|extension| extension == "log"))
                .collect()
        }
    }

    impl Drop for LogDirectory {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn write_log_records(logger: &dyn log::Log, count: usize) {
        let payload = "x".repeat(16 * 1024);
        for _ in 0..count {
            logger.log(
                &log::Record::builder()
                    .level(log::Level::Info)
                    .target("rotation_regression")
                    .args(format_args!("{payload}"))
                    .build(),
            );
        }
        logger.log(
            &log::Record::builder()
                .level(log::Level::Info)
                .target("rotation_regression")
                .args(format_args!("rotation final record"))
                .build(),
        );
    }

    #[test]
    fn file_logging_rotates_during_a_busy_day() {
        let directory = LogDirectory::new();
        let (logger, handle) = file_logger(false, directory.0.clone())
            .unwrap()
            .build()
            .unwrap();
        write_log_records(logger.as_ref(), 320);
        handle.shutdown();
        let logs = directory.logs();
        let largest = logs.iter()
            .map(|path| std::fs::metadata(path).unwrap().len())
            .max()
            .unwrap();
        println!("FILE_LOG_ROTATION files={} largest={largest}", logs.len());
        assert!(logs.len() >= 2, "busy logging must rotate before the day ends");
        assert!(largest <= 4 * 1024 * 1024 + 17 * 1024);
        let current = logs.iter()
            .find(|path| path.to_string_lossy().ends_with("_rCURRENT.log"))
            .unwrap();
        assert!(std::fs::read_to_string(current).unwrap()
            .ends_with("rotation final record\n"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_logging_recovers_when_file_and_stderr_writes_fail() {
        use std::io::Write;
        use std::process::{Command, Stdio};

        const DIRECTORY_ENV: &str = "RUSTDESK_LOG_WRITE_FAILURE_DIRECTORY";
        const TEST_NAME: &str = "test::file_logging_recovers_when_file_and_stderr_writes_fail";
        if let Some(path) = std::env::var_os(DIRECTORY_ENV) {
            // stdout is a pipe owned by the parent, outside the file-size fault.
            // Preserve the failing call stack even when stderr cannot report it.
            std::panic::set_hook(Box::new(|info| {
                writeln!(std::io::stdout(), "FILE_LOG_WRITE_PANIC {info}\n{}",
                    std::backtrace::Backtrace::force_capture()).unwrap();
            }));
            let (logger, handle) = file_logger(false, path.into()).unwrap().build().unwrap();
            let write_record = |message| logger.log(
                &log::Record::builder().level(log::Level::Error)
                    .target("write_failure_regression")
                    .args(format_args!("{message}")).build());
            write_record("before-write-failure");
            let mut original = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut original) }, 0);
            assert!(original.rlim_cur >= 1024 * 1024);
            let previous = unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) };
            assert_ne!(previous, libc::SIG_ERR);
            let limit = libc::rlimit { rlim_cur: 0, rlim_max: original.rlim_max };
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &limit) }, 0);
            let refused = writeln!(std::io::stderr(), "stderr-must-refuse");
            assert_eq!(refused.unwrap_err().raw_os_error(), Some(libc::EFBIG));
            write_record("during-write-failure");
            let restored = unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &original) };
            let disposition = unsafe { libc::signal(libc::SIGXFSZ, previous) };
            assert_eq!(restored, 0);
            assert_ne!(disposition, libc::SIG_ERR);
            write_record("after-write-failure");
            handle.shutdown();
            println!("FILE_LOG_WRITE_RECOVERED stderr=EFBIG limit=restored");
            return;
        }

        let directory = LogDirectory::new();
        let diagnostics = directory.0.join("stderr.capture");
        let stderr = std::fs::OpenOptions::new().create_new(true).write(true)
            .open(&diagnostics).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST_NAME, "--test-threads=1", "--nocapture"])
            .env(DIRECTORY_ENV, &directory.0).env("RUST_LOG", "error")
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::from(stderr))
            .output().unwrap();
        assert!(output.stdout.len() <= 64 * 1024);
        assert!(output.status.success(), "write-failure child: {}\n{}",
            output.status, String::from_utf8_lossy(&output.stdout));
        assert!(String::from_utf8_lossy(&output.stdout)
            .contains("FILE_LOG_WRITE_RECOVERED stderr=EFBIG limit=restored\n"));
        assert_eq!(std::fs::metadata(diagnostics).unwrap().len(), 0);
        let logs = directory.logs();
        assert_eq!(logs.len(), 1);
        let content = std::fs::read_to_string(&logs[0]).unwrap();
        assert!(content.contains("before-write-failure\n"));
        assert!(!content.contains("during-write-failure\n"));
        assert!(content.ends_with("after-write-failure\n"));
        println!("FILE_LOG_WRITE_FAILURE file=EFBIG stderr=EFBIG recovered=true child=joined");
    }

    #[test]
    fn file_logging_retains_only_the_configured_archives() {
        let directory = LogDirectory::new();
        let unrelated = directory.0.join("unrelated.keep");
        std::fs::write(&unrelated, b"preserve this file").unwrap();
        let (logger, handle) = file_logger(false, directory.0.clone())
            .unwrap()
            .build()
            .unwrap();
        write_log_records(logger.as_ref(), 34 * 256);
        handle.shutdown();
        let logs = directory.logs();
        let total: u64 = logs.iter()
            .map(|path| std::fs::metadata(path).unwrap().len())
            .sum();
        println!("FILE_LOG_RETENTION files={} bytes={total}", logs.len());
        assert_eq!(logs.len(), 32, "retain 31 archives and the current file");
        assert!(logs.iter().all(|path|
            std::fs::metadata(path).unwrap().len() <= 4 * 1024 * 1024 + 17 * 1024));
        assert_eq!(std::fs::read(unrelated).unwrap(), b"preserve this file");
        let current = logs.iter()
            .find(|path| path.to_string_lossy().ends_with("_rCURRENT.log"))
            .unwrap();
        assert!(std::fs::read_to_string(current).unwrap()
            .ends_with("rotation final record\n"));
    }

    #[test]
    fn file_logging_restarts_preserve_recent_records() {
        check_log_restarts(false);
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn file_logging_startup_preserves_recent_records() {
        check_log_restarts(true);
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn file_logging_overlapping_process_preserves_new_records() {
        use std::io::{BufRead, Write};
        use std::process::{Command, Stdio};

        const DIRECTORY_ENV: &str = "RUSTDESK_LOG_OVERLAP_TEST_DIRECTORY";
        const ROLE_ENV: &str = "RUSTDESK_LOG_OVERLAP_TEST_ROLE";
        const TEST_NAME: &str = "test::file_logging_overlapping_process_preserves_new_records";
        if let Some(path) = std::env::var_os(DIRECTORY_ENV) {
            let path = std::path::PathBuf::from(path);
            let role = std::env::var(ROLE_ENV).unwrap();
            let handle = init_log(false, path.file_name().unwrap().to_str().unwrap());
            assert!(handle.is_some());
            drop(handle);
            log::info!("overlap-record-{role}");
            if role == "resident" {
                writeln!(std::io::stdout(), "FILE_LOG_RESIDENT_READY").unwrap();
                std::io::stdout().flush().unwrap();
                let mut command = String::new();
                std::io::stdin().read_line(&mut command).unwrap();
                assert_eq!(command, "finish\n");
                log::info!("overlap-resident-final");
            }
            return;
        }

        let path = config::Config::log_path()
            .join(format!("overlap-regression-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        let directory = LogDirectory(path);
        let unrelated = directory.0.join("unrelated_r2000-01-01_00-00-00.log");
        std::fs::write(&unrelated, b"preserve this log family").unwrap();
        let executable = std::env::current_exe().unwrap();
        let child_command = |role: &str| {
            let mut command = Command::new(&executable);
            command.args(["--exact", TEST_NAME, "--test-threads=1"])
                .env(DIRECTORY_ENV, &directory.0)
                .env(ROLE_ENV, role)
                .env("RUST_LOG", "info");
            command
        };
        let mut resident = child_command("resident")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().unwrap();
        let exercise = (|| -> ResultType<()> {
            let mut reader = std::io::BufReader::new(resident.stdout.as_mut().unwrap());
            let mut line = String::new();
            let mut ready = false;
            for _ in 0..8 {
                line.clear();
                if reader.read_line(&mut line)? == 0 { break; }
                if line.ends_with("FILE_LOG_RESIDENT_READY\n") {
                    ready = true;
                    break;
                }
            }
            anyhow::ensure!(ready, "resident did not announce its initial write");
            let initial = directory.logs().into_iter()
                .map(std::fs::read_to_string).collect::<std::io::Result<Vec<_>>>()?;
            anyhow::ensure!(initial.iter().any(|s| s.contains("overlap-record-resident\n")));
            for index in 1..=40 {
                let output = child_command(&index.to_string()).output()?;
                anyhow::ensure!(output.status.success(), "logger process {index}: {output:?}");
            }
            Ok(())
        })();
        // Release and join the resident even if a launch or observation failed.
        let release = resident.stdin.take().unwrap().write_all(b"finish\n");
        let output = resident.wait_with_output().unwrap();
        assert!(release.is_ok(), "resident release failed: {release:?}");
        assert!(output.status.success(), "resident process: {output:?}");
        assert!(exercise.is_ok(), "overlap exercise failed: {exercise:?}");
        let logs: Vec<_> = directory.logs().into_iter()
            .filter(|path| path != &unrelated).collect();
        let contents = logs.iter().map(std::fs::read_to_string)
            .collect::<std::io::Result<Vec<_>>>().unwrap().join("");
        let resident_final = contents.contains("overlap-resident-final\n");
        let newest = contents.contains("overlap-record-40\n");
        println!("FILE_LOG_OVERLAP launches=40 resident_initial=true resident_final={resident_final} newest={newest} files={} children=joined", logs.len());
        assert!(newest, "the newest short-lived process record must survive");
        assert!(resident_final, "a live logger must retain its newly written record");
        assert!(logs.len() <= 33, "retention must remain bounded across process owners");
        assert_eq!(std::fs::read(unrelated).unwrap(), b"preserve this log family");
    }

    fn check_log_restarts(global: bool) {
        const DIRECTORY_ENV: &str = "RUSTDESK_LOG_RESTART_TEST_DIRECTORY";
        const RECORD_ENV: &str = "RUSTDESK_LOG_RESTART_TEST_RECORD";
        const MARKER: &str = "restart-record-";
        if let Some(path) = std::env::var_os(DIRECTORY_ENV) {
            let record: usize = std::env::var(RECORD_ENV).unwrap().parse().unwrap();
            if global {
                let path = std::path::PathBuf::from(path);
                let name = path.file_name().unwrap().to_str().unwrap();
                let handle = init_log(false, name);
                assert!(handle.is_some(), "the release file logger must start");
                drop(handle);
                let other_name = format!("{name}-second-init");
                assert!(init_log(false, &other_name).is_none());
                assert!(!config::Config::log_path().join(other_name).exists());
                log::info!("{MARKER}{record}");
                return;
            }
            let (logger, handle) = file_logger(false, path.into()).unwrap().build().unwrap();
            logger.log(
                &log::Record::builder()
                    .level(log::Level::Info)
                    .target("restart_regression")
                    .args(format_args!("{MARKER}{record}"))
                    .build(),
            );
            handle.shutdown();
            return;
        }

        let directory = if global {
            let path = config::Config::log_path()
                .join(format!("startup-regression-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            LogDirectory(path)
        } else {
            LogDirectory::new()
        };
        let test_name = if global {
            "test::file_logging_startup_preserves_recent_records"
        } else {
            "test::file_logging_restarts_preserve_recent_records"
        };
        let unrelated = directory.0.join("unrelated_r2000-01-01_00-00-00.log");
        std::fs::write(&unrelated, b"preserve this log family").unwrap();
        let executable = std::env::current_exe().unwrap();
        let mut total = 0;
        for record in 0_usize..40 {
            let output = std::process::Command::new(&executable)
                .args([
                    "--exact",
                    test_name,
                    "--test-threads=1",
                ])
                .env(DIRECTORY_ENV, &directory.0)
                .env(RECORD_ENV, record.to_string())
                .env("RUST_LOG", "info")
                .output()
                .unwrap();
            assert!(output.status.success(), "logger process {record}: {output:?}");
            let logs: Vec<_> = directory.logs().into_iter()
                .filter(|path| path != &unrelated)
                .collect();
            assert_eq!(logs.len(), (record + 1).min(32));
            let mut retained = Vec::new();
            total = 0;
            for path in &logs {
                let contents = std::fs::read_to_string(path).unwrap();
                total += contents.len();
                assert!(contents.len() < 1024);
                let lines: Vec<_> = contents.lines().collect();
                assert_eq!(lines.len(), 1, "each process wrote exactly one record");
                let (_, value) = lines[0].rsplit_once(MARKER).unwrap();
                retained.push(value.parse::<usize>().unwrap());
            }
            retained.sort_unstable();
            assert_eq!(retained, ((record + 1).saturating_sub(32)..=record).collect::<Vec<_>>());
            let current = logs.iter()
                .find(|path| path.to_string_lossy().ends_with("_rCURRENT.log"))
                .unwrap();
            assert!(std::fs::read_to_string(current).unwrap()
                .ends_with(&format!("{MARKER}{record}\n")));
            assert_eq!(std::fs::read(&unrelated).unwrap(), b"preserve this log family");
        }
        let source = if global { "STARTUP" } else { "RESTART" };
        println!("FILE_LOG_{source} processes=40 restarts=39 files=32 oldest=8 newest=39 bytes={total} unrelated=preserved children=joined");
    }

    #[test]
    fn test_allow_err() {
        allow_err!(Err("test err") as Result<(), &str>);
        allow_err!(
            Err("test err with msg") as Result<(), &str>,
            "prompt {}",
            "failed"
        );
    }

    #[test]
    fn direct_address_ipv6_formatting() {
        assert!(!is_ipv6_str("1:2:3"));
        assert!(!is_ipv6_str("[ab:2:3]:12"));
        assert!(!is_ipv6_str("[ABEF:2a:3]:12"));
        assert!(!is_ipv6_str("[ABEG:2a:3]:12"));
        assert!(!is_ipv6_str("1[ab:2:3]:12"));
        assert!(!is_ipv6_str("1.1.1.1"));
        assert!(is_ipv6_str("::1"));
        assert!(is_ipv6_str("[::1]:0"));
        assert!(is_ipv6_str("2001:db8::1"));
        assert!(!is_ipv6_str("[::1]:65536"));
        assert!(!is_ipv6_str("1:2:"));
        assert!(is_ipv6_str("1:2::0"));
        assert!(is_ipv6_str("[1:2::0]:1"));
        assert!(!is_ipv6_str("[1:2::0]:"));
        assert!(!is_ipv6_str("1:2::0]:1"));
    }

    #[test]
    fn direct_address_ipv4() {
        assert!(is_ipv4_str("1.2.3.4"));
        assert!(is_ipv4_str("1.2.3.4:90"));
        assert!(is_ipv4_str("192.168.0.1"));
        assert!(is_ipv4_str("0.0.0.0"));
        assert!(is_ipv4_str("255.255.255.255"));
        assert!(!is_ipv4_str("256.0.0.0"));
        assert!(!is_ipv4_str("256.256.256.256"));
        assert!(!is_ipv4_str("1:2:"));
        assert!(!is_ipv4_str("192.168.0.256"));
        assert!(!is_ipv4_str("192.168.0.1/24"));
        assert!(!is_ipv4_str("192.168.0."));
        assert!(!is_ipv4_str("192.168..1"));
        assert!(!is_ipv4_str("010.0.0.1"));
        assert!(!is_ipv4_str("127.1"));
        assert!(is_ipv4_str("127.0.0.1:1"));
        assert!(is_ipv4_str("127.0.0.1:65535"));
        assert!(!is_ipv4_str("127.0.0.1:0"));
        assert!(!is_ipv4_str("127.0.0.1:65536"));
    }

    #[test]
    fn direct_address_hostname_port() {
        assert!(!is_domain_port_str("a:12"));
        assert!(is_domain_port_str("a.b.c:12"));
        assert!(is_domain_port_str("test.com:12"));
        assert!(is_domain_port_str("test-UPPER.com:12"));
        assert!(is_domain_port_str("some-other.domain.com:12"));
        assert!(!is_domain_port_str("under_score:12"));
        assert!(!is_domain_port_str("a@bc:12"));
        assert!(!is_domain_port_str("1.1.1.1:12"));
        assert!(!is_domain_port_str("1.2.3:12"));
        assert!(!is_domain_port_str("1.2.3.45:12"));
        assert!(!is_domain_port_str("a.b.c:123456"));
        assert!(!is_domain_port_str("---:12"));
        assert!(!is_domain_port_str(".:12"));
        assert!(!is_domain_port_str("test.com:0"));
        assert!(!is_domain_port_str("test.com:98989"));
        assert!(is_domain_port_str("test.com:65535"));
        assert!(is_domain_port_str("3host.xn--p1ai.:1"));
        assert!(!is_domain_port_str("test.123:12"));
    }

    #[test]
    fn direct_address_hostname_bounds() {
        let label = "a".repeat(63);
        let name = format!("{label}.{label}.{label}.{}", "a".repeat(61));
        assert_eq!(name.len(), 253);
        assert!(is_direct_address(&format!("{name}:65535")));
        assert!(is_direct_address(&format!("{name}.:65535")));
        assert!(!is_direct_address(&format!("{name}a:65535")));
        assert!(!is_direct_address(&format!("{}.example:1", "a".repeat(64))));
    }

    #[test]
    fn direct_address_shared_vectors() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../flutter/test/fixtures/direct_address.json"
        ))
        .unwrap();
        for (group, accepted) in [("accepted", true), ("rejected", false)] {
            for value in vectors[group].as_array().unwrap() {
                let address = value.as_str().unwrap();
                assert_eq!(is_direct_address(address), accepted, "{address:?}");
            }
        }
    }

    #[test]
    fn test_try_into_v4() {
        for (input, expected) in [
            ("[::ffff:127.0.0.1]:8080", "127.0.0.1:8080"),
            ("[::127.0.0.1]:8080", "127.0.0.1:8080"),
            ("127.0.0.1:8080", "127.0.0.1:8080"),
            ("[ef::fe]:8080", "[ef::fe]:8080"),
            ("[::1]:8080", "[::1]:8080"),
        ] {
            let input: SocketAddr = input.parse().unwrap();
            let expected: SocketAddr = expected.parse().unwrap();
            assert_eq!(try_into_v4(input), expected);
        }
        println!("DIRECT_ADDRESS_NORMALIZATION=observed cases=5 correct=true");
    }

    #[test]
    fn test_get_version_number() {
        assert_eq!(get_version_number("1.1.10"), 1001100);
        assert_eq!(get_version_number("1.1.10-1"), 1001101);
        assert_eq!(get_version_number("1.1.11-1"), 1001111);
        assert_eq!(get_version_number("1.2.3"), 1002030);

        for (input, expected) in [
            ("", 0),
            ("0", 0),
            ("0.0.0", 0),
            ("not-a-version", 0),
            ("18446744073709551615", 0),
            ("922337203685477580", 9_223_372_036_854_775_800),
            ("9223372036854775.80", 9_223_372_036_854_775_800),
            ("0-9223372036854775807", i64::MAX),
            ("1.2.3-9223372036853773777", i64::MAX),
            ("1.2.3-1-extra", 1_002_031),
        ] {
            assert_eq!(get_version_number(input), expected, "{input}");
        }

        let mut mismatches = 0;
        for (case, input) in [
            ("last_scale", "922337203685477581"),
            ("prefix_multiply", "9223372036854775807.0"),
            ("prefix_add", "9223372036854775.808"),
            ("last_add", "9223372036854775.800"),
            ("patch_add", "1.2.3-9223372036854775807"),
            ("patch_boundary", "1.2.3-9223372036853773778"),
            ("many_components", "1.2.3.4.5.6.7.8.9.10.11"),
        ] {
            let actual = std::panic::catch_unwind(|| get_version_number(input)).ok();
            mismatches += usize::from(actual != Some(0));
            println!("VERSION_NUMBER_OVERFLOW=observed case={case} actual={actual:?} expected=0");
        }
        println!("VERSION_NUMBER_RANGE=observed cases=7 mismatches={mismatches} controls=14");
        assert_eq!(mismatches, 0, "unrepresentable versions must return unknown");
    }
}
