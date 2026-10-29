// Native component adapters. Transport and peer/executable checks are production code.
// CM launch proofs and service framing are deliberately unavailable in this fixture.
extern crate self as hbb_common;
pub use anyhow;
pub use libc;
pub use log;
use anyhow::bail;
use std::{fs, path::{Path, PathBuf}, os::fd::{AsRawFd, RawFd}};
use parity_tokio_ipc::{ConnectionClient as ConnClient, Endpoint};
type ResultType<T> = anyhow::Result<T>;
const POSTFIX_SERVICE: &str = "_service";
const CM_IPC_MAX_FRAME_BYTES: usize = 1024;
thread_local! { static USE_USER_MAIN_IPC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
include!("identity.rs");
include!("transport.rs");

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
struct ConnectionTmpl<T>(T);
impl<T: AsRawFd> ConnectionTmpl<T> {
    fn new(c: T) -> Self { Self(c) }
    fn new_main(c: T) -> Self { Self(c) }
    fn new_protected_service(c: T) -> Self { Self(c) }
    fn new_pulse_audio(_: T) -> Self { panic!("outside fixture") }
    fn new_desktop_url(_: T) -> Self { panic!("outside fixture") }
    fn new_whiteboard(_: T) -> Self { panic!("outside fixture") }
    fn set_max_packet_length(&mut self, _: usize) { panic!("outside fixture") }
    fn peer_uid(&self) -> Option<u32> { peer_uid_from_fd(self.0.as_raw_fd()) }
    fn peer_pid(&self) -> Option<u32> { peer_pid_from_fd(self.0.as_raw_fd()) }
    async fn send_service_request_timeout(&mut self, _: &ServiceIpcRequest, _: u64) -> ResultType<()> {
        panic!("service framing is outside this component")
    }
    async fn next_service_response_timeout(&mut self, _: u64) -> ResultType<Option<ServiceIpcResponse>> {
        panic!("service framing is outside this component")
    }
}
fn ensure_linux_root_service_connection<T: AsRawFd>(s: &ConnectionTmpl<T>, postfix: &str) -> ResultType<u32> {
    validate_linux_root_service_peer(s.peer_uid(), s.peer_pid(), postfix)
}
enum ServiceIpcRequest { LivenessProbe {} }
#[derive(Debug)]
enum ServiceIpcResponse { Liveness {} }
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 3);
    assert!(Path::new("/run/rustdesk-verifier-vm").is_dir());
    let postfix = &args[2];
    assert!(["", "_password", "_service_password", "_service_credential"].contains(&postfix.as_str()));
    let path = Config::ipc_path(postfix);
    if args[1] == "listen" {
        use std::io::{BufRead, Write};
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        println!("READY");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line).unwrap();
        assert_eq!(line, "stop\n");
        return;
    }
    assert_eq!(args[1], "check");
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    match runtime.block_on(ipc::ipc_fs::check_existing_listener(postfix)) {
        Ok(alive) => println!("OK {alive}"),
        Err(error) => { eprintln!("ERR {error}"); std::process::exit(3); }
    }
}
