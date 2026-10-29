// Native component adapters. Connection framing, transport, startup and peer
// checks are production code. CM/PA launch proofs remain outside this fixture.
extern crate self as hbb_common;
pub use anyhow;
pub use libc;
pub use log;
use anyhow::bail;
use std::{fs, path::{Path, PathBuf}, os::fd::{AsRawFd, RawFd}, os::unix::fs::PermissionsExt};
use parity_tokio_ipc::{Connection as Conn, ConnectionClient as ConnClient, Endpoint, Incoming, SecurityAttributes};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;
use futures_util::{StreamExt, SinkExt};
use serde::{Serialize, Deserialize};
mod bytes_codec;
use bytes_codec::BytesCodec;
type ResultType<T> = anyhow::Result<T>;
const POSTFIX_SERVICE: &str = "_service";
const CM_IPC_MAX_FRAME_BYTES: usize = 1024;
thread_local! { static USE_USER_MAIN_IPC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
include!("identity.rs");
include!("transport.rs");
include!("connection.rs");
type Connection = ConnectionTmpl<Conn>;
type ServiceIpcRequesterAuthorization = ();
use ipc::ipc_fs::*;

mod config {
    static APP_NAME: std::sync::RwLock<&str> = std::sync::RwLock::new("RustDesk");
    include!("config.rs");
    pub struct Config;
    impl Config {
        pub fn ipc_path(postfix: &str) -> String {
            Self::ipc_path_for_uid(unsafe { libc::geteuid() }, postfix)
        }
        pub fn ipc_path_for_uid(uid: u32, postfix: &str) -> String {
            format!("{}/ipc{}", ipc_parent_dir_for_uid(uid, postfix), postfix)
        }
    }
}
use config::Config;
mod password {
    pub const USER_PASSWORD_IPC_POSTFIX: &str = "_password";
    pub const SERVICE_PASSWORD_IPC_POSTFIX: &str = "_service_password";
    pub const SERVICE_CREDENTIAL_IPC_POSTFIX: &str = "_service_credential";
}
mod common {
    pub const CM_LAUNCH_TOKEN_ENV: &str = "UNUSED_CM_TOKEN";
    pub const CM_LAUNCH_PARENT_ENV: &str = "UNUSED_CM_PARENT";
}
fn whiteboard_ipc_postfix_is_valid(_: &str) -> bool { false }
fn linux_whiteboard_endpoint_address(_: &str) -> ResultType<String> { panic!("outside fixture") }
fn user_main_ipc_server_uid() -> ResultType<u32> { panic!("outside fixture") }
fn timeout<T: std::future::Future>(ms: u64, future: T) -> tokio::time::Timeout<T> {
    tokio::time::timeout(std::time::Duration::from_millis(ms), future)
}
impl<T> ConnectionTmpl<T> {
    fn new_pulse_audio(_: T) -> Self { panic!("outside fixture") }
    fn new_desktop_url(_: T) -> Self { panic!("outside fixture") }
    fn new_whiteboard(_: T) -> Self { panic!("outside fixture") }
}
fn ensure_linux_root_service_connection<T: AsyncRead + AsyncWrite + Unpin + AsRawFd>(s: &ConnectionTmpl<T>, postfix: &str) -> ResultType<u32> {
    validate_linux_root_service_peer(s.peer_uid(), s.peer_pid(), postfix)
}
async fn authenticate_cm_endpoint_launch_proof(_: &mut ConnectionTmpl<ConnClient>, _: &str, _: &str) -> ResultType<()> {
    panic!("CM proof is outside this component")
}
fn authenticate_cm_endpoint(_: &ConnectionTmpl<ConnClient>, _: u32, _: u32) -> ResultType<()> { panic!("outside fixture") }
fn current_linux_process_identity() -> ResultType<()> { panic!("outside fixture") }
fn ensure_linux_process_identity_matches(_: &ConnectionTmpl<ConnClient>, _: &(), _: &str) -> ResultType<()> { panic!("outside fixture") }
mod ipc {
    pub(super) use super::*;
    pub(super) mod ipc_fs {
        use super::*;
        use std::{ffi::CString, io::{Error, ErrorKind}, os::unix::ffi::OsStrExt};
        include!("filesystem.rs");
    }
}

fn ready(message: &str) {
    use std::io::Write;
    println!("{message}");
    std::io::stdout().flush().unwrap();
}

fn fd_count() -> usize {
    fs::read_dir("/proc/self/fd").unwrap().map(|entry| entry.unwrap()).count()
}

async fn service_fixture(scenario: &str) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    assert_eq!(SERVICE_IPC_MAX_FRAME_BYTES, 32768);
    let mut incoming = new_listener(POSTFIX_SERVICE).await.unwrap();
    let descriptors = fd_count();
    ready("READY");
    for _ in 0..2 {
        let stream = timeout(4000, incoming.next()).await.unwrap().unwrap().unwrap();
        let mut stream = Connection::new_protected_service(stream);
        assert_eq!(stream.next_service_request_timeout(2000).await.unwrap(),
                   Some(ServiceIpcRequest::LivenessProbe {}));
        ready("PROBE");
        match scenario {
            "valid" => handle_service_request(ServiceIpcRequest::LivenessProbe {}, &mut stream, ()).await,
            "unknown-field" => stream.inner.send(bytes::Bytes::from_static(b"{\"t\":\"Liveness\",\"extra\":true}")).await.unwrap(),
            "unknown-type" => stream.inner.send(bytes::Bytes::from_static(b"{\"t\":\"Other\"}")).await.unwrap(),
            "malformed" => stream.inner.send(bytes::Bytes::from_static(b"{")).await.unwrap(),
            "oversized" => {
                stream.inner.get_mut().write_all(&((32769u32 << 2) | 2).to_le_bytes()[..3]).await.unwrap();
                let mut byte = [0];
                assert_eq!(timeout(2500, stream.inner.get_mut().read(&mut byte)).await.unwrap().unwrap(), 0);
            }
            "truncated" => stream.inner.get_mut().write_all(&[16, b'x']).await.unwrap(),
            "silent" => {
                let mut byte = [0];
                assert_eq!(timeout(2500, stream.inner.get_mut().read(&mut byte)).await.unwrap().unwrap(), 0);
            }
            "disconnect" => {},
            _ => panic!("unknown service scenario"),
        }
        drop(stream);
        assert_eq!(fd_count(), descriptors);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 3);
    assert!(Path::new("/run/rustdesk-verifier-vm").is_dir());
    let postfix = &args[2];
    assert!(["", "_password", "_service_password", "_service_credential", "_service"].contains(&postfix.as_str()));
    let path = Config::ipc_path(postfix);
    if let Some(scenario) = args[1].strip_prefix("service-") {
        assert_eq!(postfix, POSTFIX_SERVICE);
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(service_fixture(scenario));
        return;
    }
    if args[1] == "listen" || args[1] == "listen-unprovable" {
        use std::io::{BufRead, Write};
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        if args[1] == "listen-unprovable" {
            assert_eq!(unsafe { libc::geteuid() }, 4001);
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong,
                                          0 as libc::c_ulong, 0 as libc::c_ulong,
                                          0 as libc::c_ulong) }, 0);
        }
        println!("READY");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line).unwrap();
        assert_eq!(line, "stop\n");
        return;
    }
    assert!(["start", "try-start", "try-start-nondumpable", "probe"].contains(&args[1].as_str()));
    if args[1] == "try-start-nondumpable" {
        assert_eq!(unsafe { libc::geteuid() }, 4001);
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong,
                                      0 as libc::c_ulong, 0 as libc::c_ulong,
                                      0 as libc::c_ulong) }, 0);
    }
    let try_start = args[1].starts_with("try-start");
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    if args[1] == "probe" {
        let descriptors = fd_count();
        let result = runtime.block_on(probe_existing_listener(postfix));
        assert_eq!(fd_count(), descriptors);
        match result {
            Ok(true) => println!("OK alive"),
            Ok(false) => std::process::exit(4),
            Err(error) => { eprintln!("ERR {error}"); std::process::exit(3); }
        }
        return;
    }
    let mask = || fs::read_to_string("/proc/self/status").unwrap().lines()
        .find(|line| line.starts_with("Umask:")).unwrap().to_owned();
    let original_mask = mask();
    let descriptors = fd_count();
    let result = runtime.block_on(new_listener(postfix));
    assert_eq!(mask(), original_mask);
    match result {
        Ok(listener) => {
            if try_start {
                println!("OK started");
            } else {
                use std::io::{BufRead, Write};
                println!("READY");
                std::io::stdout().flush().unwrap();
                let mut line = String::new();
                std::io::stdin().lock().read_line(&mut line).unwrap();
                assert_eq!(line, "stop\n");
            }
            drop(listener);
            if try_start {
                assert_eq!(fd_count(), descriptors);
            }
        }
        Err(error) => {
            if try_start {
                assert_eq!(fd_count(), descriptors);
            }
            eprintln!("ERR {error}"); std::process::exit(3);
        }
    }
}
