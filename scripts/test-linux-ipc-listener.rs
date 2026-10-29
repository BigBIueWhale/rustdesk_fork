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

async fn admission_fixture(scenario: &str, main: bool) {
    use std::future::{poll_fn, Future};
    use std::io::Write;
    use std::task::Poll;
    use tokio::io::AsyncReadExt;

    async fn accept(listeners: &mut [IpcListener], next: &mut usize, password_first: &mut bool) -> (usize, Conn) {
        match listeners {
            [password, main] => match next_main_ipc_event(
                main.next(), next_sensitive_main_listener_event(password), password_first,
            ).await {
                MainIpcListenerEvent::Password(SensitiveMainListenerEvent::Accepted(stream)) => (0, stream),
                MainIpcListenerEvent::Main(stream) => (1, stream.unwrap().unwrap()),
                _ => panic!("unexpected password listener failure"),
            },
            [credential, password, service] => {
                let (kind, stream) = match next_service_ipc_connection(credential, password, service, next).await {
                    ServiceIpcAccept::Credential(stream) => (0, stream),
                    ServiceIpcAccept::Password(stream) => (1, stream),
                    ServiceIpcAccept::Service(stream) => (2, stream),
                };
                (kind, stream.unwrap().unwrap())
            }
            _ => panic!("unexpected listener count"),
        }
    }

    async fn label((kind, mut stream): (usize, Conn)) -> usize {
        assert_eq!(peer_uid_from_fd(stream.as_raw_fd()), Some(unsafe { libc::geteuid() }));
        assert_eq!(peer_pid_from_fd(stream.as_raw_fd()), Some(std::process::id()));
        let mut byte = [0];
        timeout(1000, stream.read_exact(&mut byte)).await.unwrap().unwrap();
        assert_eq!(byte[0] as usize, kind, "accepted connection was routed to the wrong endpoint");
        kind
    }

    let uid = unsafe { libc::geteuid() };
    let postfixes: &[&str] = if main { &["_password", ""] }
        else if uid == 0 { &["_service_credential", "_service_password", "_service"] }
        else { &["_password", "", "_url"] };
    let count = postfixes.len();
    let before = fd_count();
    {
        let mut listeners = Vec::new();
        for postfix in postfixes {
            listeners.push(new_listener(postfix).await.unwrap());
        }
        let mut next = 0;
        let mut password_first = true;
        let connect = |kind: usize| {
            let mut client = std::os::unix::net::UnixStream::connect(Config::ipc_path(postfixes[kind])).unwrap();
            client.write_all(&[kind as u8]).unwrap();
            client
        };
        match scenario {
            "backlog" => {
                // Every queue stays populated throughout all admission rounds.
                let clients: Vec<_> = (0..count).flat_map(|kind| (0..9).map(move |_| kind)).map(connect).collect();
                for _ in 0..3 {
                    let mut served = 0;
                    for _ in 0..count {
                        let accepted = timeout(1000, accept(
                            &mut listeners, &mut next, &mut password_first,
                        )).await.unwrap();
                        served |= 1 << label(accepted).await;
                    }
                    assert_eq!(served, (1 << count) - 1, "a ready IPC endpoint was starved by another backlog");
                }
                drop(clients);
            }
            "sparse" | "cancel" => {
                for kind in [2, 1, 0, 2, 0, 1] {
                    let kind = kind % count;
                    if scenario == "cancel" {
                        let cursor = (next, password_first);
                        let descriptors = fd_count();
                        {
                            let pending = accept(
                                &mut listeners, &mut next, &mut password_first,
                            );
                            tokio::pin!(pending);
                            poll_fn(|cx| {
                                assert!(pending.as_mut().poll(cx).is_pending());
                                Poll::Ready(())
                            }).await;
                        }
                        assert_eq!((next, password_first), cursor, "cancelled pending accept changed priority");
                        assert_eq!(fd_count(), descriptors);
                    }
                    let client = connect(kind);
                    let accepted = timeout(1000, accept(
                        &mut listeners, &mut next, &mut password_first,
                    )).await.unwrap();
                    assert_eq!(label(accepted).await, kind);
                    drop(client);
                }
            }
            _ => panic!("unknown admission scenario"),
        }
    }
    assert_eq!(fd_count(), before);
    let prefix = if main { "main-" } else { "" };
    println!("OK {prefix}admission-{scenario} uid={uid} cleanup=joined");
}

async fn accept_failure_fixture(scenario: &str) {
    use std::future::{poll_fn, Future};
    use std::io::Write;
    use std::task::Poll;
    use std::time::{Duration, Instant};
    use tokio::io::AsyncReadExt;

    async fn exhausted(listener: &mut IpcListener) {
        match timeout(1000, listener.next()).await.unwrap() {
            Some(Err(error)) => assert_eq!(error.raw_os_error(), Some(libc::EMFILE)),
            _ => panic!("accept did not report real descriptor exhaustion"),
        }
    }

    async fn pending_once(listener: &mut IpcListener) {
        let next = listener.next();
        tokio::pin!(next);
        poll_fn(|cx| {
            assert!(next.as_mut().poll(cx).is_pending(), "failed listener retried without waiting");
            Poll::Ready(())
        }).await;
    }

    async fn check_stream(mut stream: Conn, expected: u8) {
        assert_eq!(peer_uid_from_fd(stream.as_raw_fd()), Some(unsafe { libc::geteuid() }));
        assert_eq!(peer_pid_from_fd(stream.as_raw_fd()), Some(std::process::id()));
        let mut byte = [0];
        timeout(500, stream.read_exact(&mut byte)).await.unwrap().unwrap();
        assert_eq!(byte[0], expected);
    }

    let before = fd_count();
    {
        let mut failed = new_listener("_password").await.unwrap();
        let mut other = new_listener("").await.unwrap();
        let clients: Vec<_> = ["_password", ""].iter().enumerate().map(|(index, postfix)| {
            let mut client = std::os::unix::net::UnixStream::connect(Config::ipc_path(postfix)).unwrap();
            client.write_all(&[index as u8]).unwrap();
            client
        }).collect();
        let mut original = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut original) }, 0);
        assert!(original.rlim_cur >= 64);
        let limited = libc::rlimit { rlim_cur: 64, rlim_max: original.rlim_max };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limited) }, 0);
        let mut fillers = Vec::new();
        loop {
            assert!(fillers.len() < 64);
            match fs::File::open("/dev/null") {
                Ok(file) => fillers.push(file),
                Err(error) => {
                    assert_eq!(error.raw_os_error(), Some(libc::EMFILE));
                    break;
                }
            }
        }
        exhausted(&mut failed).await;
        match scenario {
            "retry" => {
                for _ in 0..3 {
                    let started = Instant::now();
                    exhausted(&mut failed).await;
                    assert!(started.elapsed() >= Duration::from_millis(90), "accept errors can spin");
                }
                drop(fillers.pop().unwrap());
                check_stream(timeout(1000, failed.next()).await.unwrap().unwrap().unwrap(), 0).await;
            }
            "cancel" => {
                pending_once(&mut failed).await;
                tokio::time::sleep(Duration::from_millis(60)).await;
                pending_once(&mut failed).await;
                drop(fillers.pop().unwrap());
                tokio::time::sleep(Duration::from_millis(60)).await;
                let accepted = {
                    let next = failed.next();
                    tokio::pin!(next);
                    poll_fn(|cx| match next.as_mut().poll(cx) {
                        Poll::Ready(result) => Poll::Ready(result),
                        Poll::Pending => panic!("cancellation extended the original retry deadline"),
                    }).await
                };
                check_stream(accepted.unwrap().unwrap(), 0).await;
            }
            "independent" => {
                drop(fillers.pop().unwrap());
                check_stream(timeout(50, other.next()).await.unwrap().unwrap().unwrap(), 1).await;
                check_stream(timeout(1000, failed.next()).await.unwrap().unwrap().unwrap(), 0).await;
            }
            _ => panic!("unknown accept failure scenario"),
        }
        drop(fillers);
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &original) }, 0);
        drop(clients);
    }
    assert_eq!(fd_count(), before);
    println!("OK accept-{scenario} uid={} cleanup=joined", unsafe { libc::geteuid() });
}

async fn json_serialization_fixture(scenario: &str) {
    use serde::ser::{Error, SerializeSeq};
    use std::cell::Cell;

    struct Sequence<'a> { visited: &'a Cell<usize>, fail: bool }
    impl Serialize for Sequence<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut sequence = serializer.serialize_seq(None)?;
            for i in 0..100_000 {
                self.visited.set(i + 1);
                sequence.serialize_element(&0u8)?;
                if self.fail { return Err(S::Error::custom("fixture serialization failure")); }
            }
            sequence.end()
        }
    }

    fn no_wire_bytes(stream: &tokio::net::UnixStream) {
        let mut byte = 0u8;
        assert_eq!(unsafe { libc::recv(stream.as_raw_fd(), (&mut byte as *mut u8).cast(), 1,
                                     libc::MSG_DONTWAIT | libc::MSG_PEEK) }, -1);
        assert_eq!(std::io::Error::last_os_error().kind(), std::io::ErrorKind::WouldBlock);
    }

    async fn round_trip(sender: &mut ConnectionTmpl<tokio::net::UnixStream>,
                        receiver: &mut ConnectionTmpl<tokio::net::UnixStream>, value: &str) {
        let expected = serde_json::to_vec(value).unwrap();
        let (sent, received) = tokio::join!(
            sender.send_json_timeout(&value, 1000), timeout(1000, receiver.inner.next()),
        );
        sent.unwrap();
        assert_eq!(received.unwrap().unwrap().unwrap().as_ref(), expected.as_slice());
        no_wire_bytes(receiver.inner.get_ref());
    }

    let before = fd_count();
    let observed;
    let mut bounded = true;
    {
        let (sender, receiver) = tokio::net::UnixStream::pair().unwrap();
        for fd in [sender.as_raw_fd(), receiver.as_raw_fd()] {
            assert_eq!(peer_uid_from_fd(fd), Some(unsafe { libc::geteuid() }));
            assert_eq!(peer_pid_from_fd(fd), Some(std::process::id()));
        }
        let mut sender = ConnectionTmpl::new_protected_service(sender);
        let mut receiver = ConnectionTmpl::new(receiver);
        match scenario {
            "bounds" => {
                let mut checks = 0;
                for value in ["".to_owned(), "plain".to_owned(), "\0\n\"\\é雪🦀".to_owned(),
                              "x".repeat(SERVICE_IPC_MAX_FRAME_BYTES - 2),
                              "x".repeat(MAIN_IPC_MAX_FRAME_BYTES - 2)] {
                    let length = serde_json::to_vec(&value).unwrap().len();
                    for limit in [0, length - 1, length, length + 1] {
                        sender.set_max_packet_length(limit);
                        if limit < length {
                            assert!(sender.send_json_timeout(&value, 1000).await.is_err());
                            no_wire_bytes(receiver.inner.get_ref());
                            sender.set_max_packet_length(length);
                        }
                        round_trip(&mut sender, &mut receiver, &value).await;
                        checks += 1;
                    }
                }
                observed = checks;
            }
            "streaming" | "failure" => {
                let visited = Cell::new(0);
                let value = Sequence { visited: &visited, fail: scenario == "failure" };
                assert!(sender.send_json_timeout(&value, 1000).await.is_err());
                no_wire_bytes(receiver.inner.get_ref());
                round_trip(&mut sender, &mut receiver, "after rejection").await;
                observed = visited.get();
                bounded = if value.fail { observed == 1 }
                    else { observed <= SERVICE_IPC_MAX_FRAME_BYTES / 2 + 1 };
            }
            _ => panic!("unknown JSON serialization scenario"),
        }
    }
    assert_eq!(fd_count(), before);
    assert!(bounded, "serialization exceeded the frame budget: visited={observed}");
    println!("OK json-{scenario} uid={} observed={observed} cleanup=joined", unsafe { libc::geteuid() });
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 3);
    assert!(Path::new("/run/rustdesk-verifier-vm").is_dir());
    let postfix = &args[2];
    assert!(["", "_password", "_service_password", "_service_credential", "_service"].contains(&postfix.as_str()));
    let path = Config::ipc_path(postfix);
    if let Some(scenario) = args[1].strip_prefix("json-") {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(json_serialization_fixture(scenario));
        return;
    }
    if let Some(scenario) = args[1].strip_prefix("accept-") {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(accept_failure_fixture(scenario));
        return;
    }
    if let Some((scenario, main)) = args[1].strip_prefix("admission-").map(|s| (s, false))
        .or_else(|| args[1].strip_prefix("main-admission-").map(|s| (s, true))) {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(admission_fixture(scenario, main));
        return;
    }
    if let Some(scenario) = args[1].strip_prefix("service-") {
        assert_eq!(postfix, POSTFIX_SERVICE);
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(service_fixture(scenario));
        return;
    }
    if args[1] == "listen" || args[1] == "listen-unprovable" || args[1] == "listen-wrong-uid" {
        use std::io::{BufRead, Write};
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        if args[1] == "listen-unprovable" {
            assert_eq!(unsafe { libc::geteuid() }, 4001);
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong,
                                          0 as libc::c_ulong, 0 as libc::c_ulong,
                                          0 as libc::c_ulong) }, 0);
        }
        println!("READY");
        std::io::stdout().flush().unwrap();
        if args[1] == "listen-wrong-uid" {
            use std::io::Read;
            assert_eq!(unsafe { libc::geteuid() }, 4001);
            let descriptors = fd_count();
            for _ in 0..3 {
                let mut ready = libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 };
                assert_eq!(unsafe { libc::poll(&mut ready, 1, 5000) }, 1);
                let (mut peer, _) = listener.accept().unwrap();
                assert_eq!(peer_uid_from_fd(peer.as_raw_fd()), Some(0));
                peer.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
                let mut byte = [0];
                assert_eq!(peer.read(&mut byte).unwrap(), 0);
                drop(peer);
                assert_eq!(fd_count(), descriptors);
            }
            ready("NO_PAYLOAD");
        }
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
