pub mod compress;
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
pub mod mem;
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

pub fn get_created_time(path: &std::path::Path) -> SystemTime {
    std::fs::metadata(path)
        .map(|m| m.created().unwrap_or(UNIX_EPOCH))
        .unwrap_or(UNIX_EPOCH)
}

pub fn get_exe_time() -> SystemTime {
    std::env::current_exe().map_or(UNIX_EPOCH, |path| {
        let m = get_modified_time(&path);
        let c = get_created_time(&path);
        if m > c {
            m
        } else {
            c
        }
    })
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
            use flexi_logger::*;
            if let Ok(x) = Logger::try_with_env_or_str("debug,rustls=warn") {
                logger_holder = x
                    .log_to_file(FileSpec::default().directory(path))
                    .write_mode(if _is_async {
                        WriteMode::Async
                    } else {
                        WriteMode::Direct
                    })
                    .format(opt_format)
                    .rotate(
                        Criterion::Age(Age::Day),
                        Naming::Timestamps,
                        Cleanup::KeepLogFiles(31),
                    )
                    .start()
                    .ok();
            }
        }
    });
    logger_holder
}

// R-SV3 / R-SV1 (§18 sovereignty): the version-check phone-home is DELETED, not neutered.
// Upstream's `version_check_request` built a device-fingerprinted POST (os/arch/device_id)
// to a HARDWIRED upstream version endpoint — a global-reaching egress the R-D6 api-server
// pin never covered, fired ~1s after launch by the Dart `checkUpdate`. That caller + the
// egress worker are already gone (R-X1) and `check_software_update` is neutered
// (src/common.rs); removing the request builder, its hardwired URL, and the
// VersionCheck{Request,Response} types makes the endpoint structurally absent from the binary
// (R-SV1: "the binary cannot connect because the code is gone"), not merely uncalled.

pub fn time_based_rand() -> u32 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let mut x = nanos as u64;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;

    (x % 32768) as u32
}

#[cfg(test)]
mod test {
    use super::*;

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
