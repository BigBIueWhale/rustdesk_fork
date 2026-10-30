// Native component adapters. Connection framing, transport, startup and peer
// checks are production code. CM/PA launch proofs remain outside this fixture.
extern crate self as hbb_common;
pub use anyhow;
pub use libc;
pub use log;
pub use tokio;
pub use tokio_util;
use anyhow::bail;
use std::{fs, path::{Path, PathBuf}, os::fd::{AsRawFd, RawFd}, os::unix::fs::PermissionsExt};
use parity_tokio_ipc::{Connection as Conn, ConnectionClient as ConnClient, Endpoint, Incoming, SecurityAttributes};
use tokio::io::{AsyncRead, AsyncWrite};
mod framed;
use framed::IpcFrameReader;
use futures_util::StreamExt;
use serde::{Serialize, Deserialize};
use bytes::Bytes;
mod bytes_codec;
mod cli_option_read;
pub(crate) use cli_option_read::{get_options, platform, set_option};
use bytes_codec::BytesCodec;
type ResultType<T> = anyhow::Result<T>;
const POSTFIX_SERVICE: &str = "_service";
const CM_IPC_MAX_FRAME_BYTES: usize = 1024;
thread_local! { static USE_USER_MAIN_IPC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
thread_local! { static MAIN_ROUTE_UID: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) }; }
include!("identity.rs");
include!("transport.rs");
include!("connection.rs");
include!("main_responses.rs");
mod argv_auth {
    use super::*;
    include!("argv_auth.rs");
}
mod main_transaction {
    use super::*;
    thread_local! { pub(super) static CONNECT_DELAY_MS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
    // Inject only connection latency; the actual endpoint, peer and frame I/O remain real.
    async fn connect(ms: u64, postfix: &str) -> ResultType<ConnectionTmpl<ConnClient>> {
        let delay = CONNECT_DELAY_MS.with(|value| value.get());
        timeout(ms, async {
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            super::connect(ms, postfix).await
        }).await?
    }
    include!("main_transaction.rs");
}
mod url_server {
    use super::*;
    include!("url_server.rs");
}
// Only Activate/CloseAll are exercised. URL parsing and target-OS sender
// authorization/Flutter delivery are outside this Linux accept-lifetime fixture.
fn validate_desktop_url_ipc_open_url(_: &str) -> ResultType<()> { panic!("URL parsing is outside fixture") }
fn authorize_url_ipc_sender(stream: &Connection) -> bool {
    stream.peer_uid() == Some(unsafe { libc::geteuid() })
        && stream.peer_pid() == Some(std::process::id())
}
type Connection = ConnectionTmpl<Conn>;
type ServiceIpcRequesterAuthorization = ();
use ipc::ipc_fs::*;

mod config {
    use std::path::PathBuf;
    use hbb_common::libc;
    static APP_NAME: std::sync::RwLock<&str> = std::sync::RwLock::new("RustDesk");
    include!("config.rs");
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
fn user_main_ipc_server_uid() -> ResultType<u32> {
    MAIN_ROUTE_UID.with(|uid| uid.get().ok_or_else(|| anyhow::anyhow!("main route is outside fixture")))
}
fn timeout<T: std::future::Future>(ms: u64, future: T) -> tokio::time::Timeout<T> {
    tokio::time::timeout(std::time::Duration::from_millis(ms), future)
}
impl<T> ConnectionTmpl<T> {
    fn new_pulse_audio(_: T) -> Self { panic!("outside fixture") }
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
            "unknown-field" => stream.send_raw(bytes::Bytes::from_static(b"{\"t\":\"Liveness\",\"extra\":true}")).await.unwrap(),
            "unknown-type" => stream.send_raw(bytes::Bytes::from_static(b"{\"t\":\"Other\"}")).await.unwrap(),
            "malformed" => stream.send_raw(bytes::Bytes::from_static(b"{")).await.unwrap(),
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

async fn windows_main_admission_fixture(scenario: &str) {
    use std::future::{pending, poll_fn, Future};
    use std::io::Write;
    use std::task::Poll;
    use tokio::io::AsyncReadExt;

    async fn accept(listeners: &mut [IpcListener; 2], first: &mut bool) -> WindowsServiceMainIpcEvent {
        let [control, credential] = listeners;
        next_windows_service_main_ipc_event(
            pending(), pending(), control.next(), credential.next(), first,
        ).await
    }

    async fn label(event: WindowsServiceMainIpcEvent) -> usize {
        let (kind, mut stream) = match event {
            WindowsServiceMainIpcEvent::Control(stream) => (0, stream.unwrap().unwrap()),
            WindowsServiceMainIpcEvent::Credential(stream) => (1, stream.unwrap().unwrap()),
            _ => panic!("unexpected lifecycle event"),
        };
        assert_eq!(peer_uid_from_fd(stream.as_raw_fd()), Some(unsafe { libc::geteuid() }));
        assert_eq!(peer_pid_from_fd(stream.as_raw_fd()), Some(std::process::id()));
        let mut byte = [0];
        timeout(1000, stream.read_exact(&mut byte)).await.unwrap().unwrap();
        assert_eq!(byte[0] as usize, kind);
        kind
    }

    let before = fd_count();
    {
        let postfixes = ["", "_password"];
        let mut listeners = [new_listener(postfixes[0]).await.unwrap(), new_listener(postfixes[1]).await.unwrap()];
        let mut first = true;
        let connect = |kind: usize| {
            let mut client = std::os::unix::net::UnixStream::connect(Config::ipc_path(postfixes[kind])).unwrap();
            client.write_all(&[kind as u8]).unwrap();
            client
        };
        match scenario {
            "backlog" => {
                let clients: Vec<_> = (0..2).flat_map(|kind| (0..9).map(move |_| kind)).map(connect).collect();
                for _ in 0..3 {
                    let mut served = 0;
                    for _ in 0..2 {
                        let event = timeout(1000, accept(&mut listeners, &mut first)).await.unwrap();
                        served |= 1 << label(event).await;
                    }
                    assert_eq!(served, 3, "a ready service-main endpoint was starved");
                }
                drop(clients);
            }
            "sparse" | "cancel" => {
                for kind in [1, 0, 0, 1, 0, 1] {
                    if scenario == "cancel" {
                        let prior = first;
                        let descriptors = fd_count();
                        {
                            let event = accept(&mut listeners, &mut first);
                            tokio::pin!(event);
                            poll_fn(|cx| {
                                assert!(event.as_mut().poll(cx).is_pending());
                                Poll::Ready(())
                            }).await;
                        }
                        assert_eq!(first, prior);
                        assert_eq!(fd_count(), descriptors);
                    }
                    let client = connect(kind);
                    let event = timeout(1000, accept(&mut listeners, &mut first)).await.unwrap();
                    assert_eq!(label(event).await, kind);
                    drop(client);
                }
            }
            "completion" | "shutdown" => {
                let clients = [connect(0), connect(1)];
                let mut transactions = tokio::task::JoinSet::new();
                let task = transactions.spawn(async {});
                tokio::task::yield_now().await;
                assert!(task.is_finished(), "transaction must finish before selection");
                let prior = first;
                let [control, credential] = &mut listeners;
                let event = timeout(1000, next_windows_service_main_ipc_event(
                    async { if scenario != "shutdown" { pending::<()>().await; } },
                    transactions.join_next(), control.next(), credential.next(), &mut first,
                )).await.unwrap();
                if scenario == "shutdown" {
                    assert!(matches!(event, WindowsServiceMainIpcEvent::Shutdown));
                    assert_eq!(transactions.len(), 1);
                    transactions.join_next().await.unwrap().unwrap();
                } else {
                    assert!(matches!(event, WindowsServiceMainIpcEvent::Completed(Some(Ok(())))),
                            "completed work was not joined before accepting another connection");
                    assert!(transactions.is_empty());
                }
                assert_eq!(first, prior);
                let mut served = 0;
                for _ in 0..2 {
                    let event = timeout(1000, accept(&mut listeners, &mut first)).await.unwrap();
                    served |= 1 << label(event).await;
                }
                assert_eq!(served, 3, "lifecycle selection consumed a queued connection");
                drop(clients);
            }
            _ => panic!("unknown Windows service-main scenario"),
        }
    }
    assert_eq!(fd_count(), before);
    println!("OK windows-main-admission-{scenario} uid={} cleanup=joined", unsafe { libc::geteuid() });
}

async fn url_accept_fixture(scenario: &str) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    struct Observer { errors: AtomicUsize, requests: AtomicUsize }
    impl log::Log for Observer {
        fn enabled(&self, _: &log::Metadata) -> bool { true }
        fn flush(&self) {}
        fn log(&self, record: &log::Record) {
            let message = record.args().to_string();
            if message.starts_with("Failed to accept desktop URL IPC connection:")
                && message.contains("(os error 24)") {
                self.errors.fetch_add(1, Ordering::SeqCst);
            }
            if message == "Desktop URL IPC request arrived without Flutter support" {
                self.requests.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    static OBSERVER: Observer = Observer { errors: AtomicUsize::new(0), requests: AtomicUsize::new(0) };
    log::set_logger(&OBSERVER).unwrap();
    log::set_max_level(log::LevelFilter::Warn);
    let before = fd_count();
    let path = Config::ipc_path("_url");
    let server = tokio::spawn(url_server::start_ipc_url_server());
    timeout(1000, async {
        while !Path::new(&path).exists() {
            assert!(!server.is_finished(), "URL listener failed before admission");
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    // Queue the peer without yielding, then exhaust descriptors before the
    // production loop can accept it on this single-threaded runtime.
    let socket = std::os::unix::net::UnixStream::connect(&path).unwrap();
    socket.set_nonblocking(true).unwrap();
    let mut client = ConnectionTmpl::new_desktop_url(tokio::net::UnixStream::from_std(socket).unwrap());
    assert_eq!(client.peer_uid(), Some(unsafe { libc::geteuid() }));
    assert_eq!(client.peer_pid(), Some(std::process::id()));
    let mut original = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut original) }, 0);
    let mut fillers = Vec::new();
    if scenario == "recovery" {
        assert!(original.rlim_cur >= 64);
        let limited = libc::rlimit { rlim_cur: 64, rlim_max: original.rlim_max };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limited) }, 0);
        loop {
            assert!(fillers.len() < 64);
            match fs::File::open("/dev/null") {
                Ok(file) => fillers.push(file),
                Err(err) => { assert_eq!(err.raw_os_error(), Some(libc::EMFILE)); break; }
            }
        }
        timeout(500, async {
            while !server.is_finished() && OBSERVER.errors.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }).await.unwrap();
    } else { assert_eq!(scenario, "success"); }
    drop(fillers);
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &original) }, 0);
    let survived = !server.is_finished();
    let accept_errors = OBSERVER.errors.load(Ordering::SeqCst);
    let delivered = if survived {
        async {
            client.send_desktop_url_request_timeout(&DesktopUrlIpcRequest::Activate {}, 1000).await?;
            let mut byte = [0];
            anyhow::ensure!(timeout(1000, client.inner.get_mut().read(&mut byte)).await?? == 0);
            drop(client);
            let mut next = ConnectionTmpl::new_desktop_url(Endpoint::connect(&path).await?);
            next.send_desktop_url_request_timeout(&DesktopUrlIpcRequest::CloseAll {}, 1000).await?;
            anyhow::ensure!(timeout(1000, next.inner.get_mut().read(&mut byte)).await?? == 0);
            Ok::<_, anyhow::Error>(())
        }.await
    } else { drop(client); Err(anyhow::anyhow!("URL listener stopped after accept failure")) };
    let still_live = !server.is_finished();
    server.abort();
    let joined = server.await;
    fs::remove_file(path).unwrap();
    assert_eq!(fd_count(), before);
    assert!(survived, "URL listener stopped after recoverable descriptor exhaustion");
    assert_eq!(accept_errors > 0, scenario == "recovery");
    delivered.unwrap();
    assert_eq!(OBSERVER.requests.load(Ordering::SeqCst), 2);
    assert!(still_live && joined.unwrap_err().is_cancelled());
    println!("OK url-accept-{scenario} uid={} cleanup=joined", unsafe { libc::geteuid() });
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

async fn main_transaction_fixture(scenario: &str) {
    use std::time::{Duration, Instant};
    use tokio::io::AsyncReadExt;
    let before = fd_count();
    let (result, elapsed, peer) = {
        let mut incoming = new_listener("").await.unwrap();
        let delay = match scenario {
            "success" => 100,
            "deadline" => 350,
            "connect-stall" => 1000,
            "peer-stall" => 0,
            _ => panic!("unknown main transaction scenario"),
        };
        main_transaction::CONNECT_DELAY_MS.with(|value| value.set(delay));
        let client = async {
            let start = Instant::now();
            let result = main_transaction::main_ipc_request(
                MainIpcRequest::Config(MainConfigKey::VoiceCallInput {}), 500,
            ).await;
            (result, start.elapsed())
        };
        if scenario == "connect-stall" {
            let (result, elapsed) = client.await;
            assert!(timeout(50, incoming.next()).await.is_err(), "cancelled connect reached listener");
            (result, elapsed, None)
        } else {
            let server = async {
                let stream = timeout(1500, incoming.next()).await.unwrap().unwrap().unwrap();
                assert_eq!(peer_uid_from_fd(stream.as_raw_fd()), Some(unsafe { libc::geteuid() }));
                assert_eq!(peer_pid_from_fd(stream.as_raw_fd()), Some(std::process::id()));
                let mut stream = Connection::new_main(stream);
                assert!(matches!(stream.next_main_timeout(1000).await.unwrap(),
                                 Some(MainIpcRequest::Config(MainConfigKey::VoiceCallInput {}))));
                let sent = if scenario == "peer-stall" { None } else {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    Some(stream.send_json_timeout(&MainIpcResponse::Config {
                        key: MainConfigKey::VoiceCallInput {}, value: Some("receiver-device".to_owned()),
                    }, 1000).await.is_ok())
                };
                let mut byte = [0];
                assert_eq!(timeout(1000, stream.inner.get_mut().read(&mut byte)).await.unwrap().unwrap(),
                           0, "transaction retained its client socket");
                sent
            };
            let ((result, elapsed), peer) = tokio::join!(client, server);
            (result, elapsed, peer)
        }
    };
    assert_eq!(fd_count(), before);
    match scenario {
        "success" => {
            assert!(matches!(result.unwrap(), MainIpcResponse::Config {
                key: MainConfigKey::VoiceCallInput {}, value: Some(value),
            } if value == "receiver-device"));
            assert_eq!(peer, Some(true));
            assert!(elapsed < Duration::from_millis(500));
        }
        _ => {
            assert!(result.is_err(), "main transaction renewed its deadline: {result:?}, elapsed={elapsed:?}");
            assert!(elapsed >= Duration::from_millis(450) && elapsed < Duration::from_millis(650),
                    "transaction did not retire near its 500 ms budget: {elapsed:?}");
            if scenario == "deadline" { assert_eq!(peer, Some(false)); }
        }
    }
    println!("OK main-transaction-{scenario} uid={} cleanup=joined", unsafe { libc::geteuid() });
}

async fn main_validation_fixture(scenario: &str) {
    let before = fd_count();
    let (received, expected, error) = {
        let (sender, receiver) = tokio::net::UnixStream::pair().unwrap();
        for fd in [sender.as_raw_fd(), receiver.as_raw_fd()] {
            assert_eq!(peer_uid_from_fd(fd), Some(unsafe { libc::geteuid() }));
            assert_eq!(peer_pid_from_fd(fd), Some(std::process::id()));
        }
        let mut sender = ConnectionTmpl::new_main(sender);
        let mut receiver = ConnectionTmpl::new_main(receiver);
        if scenario == "config-none" {
            for (response, wire) in [
                (false, serde_json::json!({"t":"Config", "c":{
                    "t":"VoiceCallInput", "future":true
                }})),
                (true, serde_json::json!({"t":"Config", "c":{
                    "key":{"t":"VoiceCallInput", "future":true}, "value":null
                }})),
            ] {
                let read = async {
                    if response { receiver.next_main_response_timeout(1000).await.unwrap().is_none() }
                    else { receiver.next_main_timeout(1000).await.unwrap().is_none() }
                };
                let (sent, refused) = tokio::join!(sender.send_json_timeout(&wire, 1000), read);
                sent.unwrap();
                assert!(refused, "accepted surplus config-key field, response={response}");
            }
        }
        let option = |length| MainStatusOption {
            key: MainStatusOptionKey::AudioInput, value: "x".repeat(length),
        };
        let (response, error) = match scenario {
            "config-oversized" => (MainIpcResponse::Config {
                key: MainConfigKey::VoiceCallInput {},
                value: Some("x".repeat(MAIN_IPC_MAX_CONFIG_VALUE_BYTES + 1)),
            }, Some("main IPC config value is oversized")),
            "config-none" => (MainIpcResponse::Config {
                key: MainConfigKey::VoiceCallInput {}, value: None,
            }, None),
            "status-oversized" | "status-duplicate" | "status-count" => {
                let (entries, error) = match scenario {
                    "status-oversized" => (vec![option(MAIN_IPC_MAX_OPTION_VALUE_BYTES + 1)],
                                           "main IPC option value is oversized"),
                    "status-duplicate" => (vec![option(1), option(2)], "duplicate main IPC option"),
                    _ => (vec![option(1); MAIN_IPC_MAX_OPTION_COUNT + 1], "too many main IPC options"),
                };
                (MainIpcResponse::StatusSnapshot(MainStatusSnapshot {
                    options: MainStatusOptions(entries), file_transfer_enabled: None,
                }), Some(error))
            }
            "option-oversized" | "option-limit" => (MainIpcResponse::OptionSet {
                result: IpcMutationResult::Applied,
                effective: Some(option(MAIN_IPC_MAX_OPTION_VALUE_BYTES
                    + usize::from(scenario == "option-oversized"))),
            }, (scenario == "option-oversized").then_some("main IPC option value is oversized")),
            "option-none" => (MainIpcResponse::OptionSet {
                result: IpcMutationResult::Rejected, effective: None,
            }, None),
            _ => panic!("unknown main validation scenario"),
        };
        let expected = serde_json::to_vec(&response).unwrap();
        let (sent, received) = tokio::join!(
            sender.send_json_timeout(&response, 1000), receiver.next_main_response_timeout(1000),
        );
        sent.unwrap();
        (received, expected, error)
    };
    assert_eq!(fd_count(), before);
    match (error, received) {
        (Some(expected), Err(error)) => assert_eq!(error.to_string(), expected),
        (Some(_), Ok(_)) => panic!("accepted invalid {scenario} response"),
        (None, Ok(Some(response))) => assert_eq!(serde_json::to_vec(&response).unwrap(), expected),
        (None, result) => panic!("valid {scenario} response was not returned: {result:?}"),
    }
    println!("OK main-validation-{scenario} uid={} cleanup=joined", unsafe { libc::geteuid() });
}

async fn main_response_shape_fixture() {
    let before = fd_count();
    let mut failures = Vec::new();
    let (mut rejected, mut controls) = (0, 0);
    let mut retired = 0;
    let (mut request_rejected, mut request_controls) = (0, 0);
    {
        let (sender, receiver) = tokio::net::UnixStream::pair().unwrap();
        for fd in [sender.as_raw_fd(), receiver.as_raw_fd()] {
            assert_eq!(peer_uid_from_fd(fd), Some(unsafe { libc::geteuid() }));
            assert_eq!(peer_pid_from_fd(fd), Some(std::process::id()));
        }
        let mut sender = ConnectionTmpl::new_main(sender);
        let mut receiver = ConnectionTmpl::new_main(receiver);
        for (wire, response) in [
            (br#"{"t":"TerminalSessionCount"}"#.as_slice(), false),
            (br#"{"t":"TerminalSessionCount","c":0}"#.as_slice(), true),
        ] {
            let (sent, refused) = tokio::join!(
                sender.send_raw(Bytes::from_static(wire)),
                async {
                    if response {
                        receiver.next_main_response_timeout(1000).await.map(|value| value.is_none())
                    } else {
                        receiver.next_main_timeout(1000).await.map(|value| value.is_none())
                    }
                },
            );
            sent.unwrap();
            if matches!(refused, Ok(true)) { retired += 1; }
            else { failures.push(format!("retired terminal-count response={response}: {refused:?}")); }
        }
        for (index, wire) in [
            r#"{"t":"StatusSnapshot","extra":true}"#,
            r#"{"t":"StatusSnapshot","c":{"extra":true}}"#,
            r#"{"c":{"extra":true},"t":"StatusSnapshot"}"#,
            r#"{"t":"StatusSnapshot","c":[]}"#,
            r#"{"extra":true,"t":"ReadinessSnapshot"}"#,
            r#"{"t":"ReadinessSnapshot","t":"StatusSnapshot"}"#,
            r#"{"c":null,"t":"ReadinessSnapshot","c":null}"#,
            r#"{"t":"Config","c":{"t":"PermanentPassword"}}"#,
            r#"{"t":"SetVoiceCallInput","c":false}"#,
            r#"{"t":"SetVoiceCallInput"}"#,
            r#"{"t":"PasswordMutationStatus","c":{"operation_id":"fixture","extra":true}}"#,
            r#"{"c":{"operation_id":"a","operation_id":"b"},"t":"PasswordMutationStatus"}"#,
            r#"{"t":"PasswordMutationStatus","c":{}}"#,
            r#"{"t":"SetOption","c":{"key":"PermanentPassword","value":"unused"}}"#,
            r#"{"t":"SetOption","c":{"key":"AudioInput","key":"VoiceCallInput","value":"device"}}"#,
            r#"{"c":{"key":"AudioInput","value":"a","value":"b"},"t":"SetOption"}"#,
            r#"{"t":"SetOption","c":{"key":"AudioInput","value":"device","extra":true}}"#,
            r#"{"t":"ValidateCmConnection","c":{"id":1,"conn_type":{"t":"Remote"},"cm_auth_token":"fixture","extra":true}}"#,
            r#"{"t":"ValidateCmConnection","c":{"id":1,"conn_type":{"t":"Unknown"},"cm_auth_token":"fixture"}}"#,
            r#"{"c":{"id":1,"id":2,"conn_type":{"t":"Remote"},"cm_auth_token":"fixture"},"t":"ValidateCmConnection"}"#,
            r#"{"t":"ValidateCmConnection","c":{"id":1,"conn_type":{"t":"Remote"}}}"#,
            r#"{"t":"ValidatePulseAudioStart","c":{"token":"fixture","extra":true}}"#,
            r#"{"c":{"token":"a","token":"b"},"t":"ValidatePulseAudioStart"}"#,
            r#"{"t":"SetPermanentPassword","c":"unused"}"#,
        ].into_iter().enumerate() {
            let (sent, received) = tokio::join!(
                sender.send_raw(Bytes::from_static(wire.as_bytes())),
                receiver.next_main_timeout(1000),
            );
            sent.unwrap();
            if matches!(received, Ok(None)) { request_rejected += 1; }
            else { failures.push(format!("malformed request[{index}]: {received:?}")); }
        }
        for (tag, payload) in [
            ("StatusSnapshot", "null"),
            ("ReadinessSnapshot", "null"),
            ("Config", r#"{"t":"VoiceCallInput"}"#),
            ("SetVoiceCallInput", r#""device""#),
            ("PasswordMutationStatus", r#"{"operation_id":"fixture"}"#),
            ("SetOption", r#"{"key":"AudioInput","value":"device"}"#),
            ("ValidateCmConnection", r#"{"id":1,"conn_type":{"t":"Remote"},"cm_auth_token":"fixture"}"#),
            ("ValidatePulseAudioStart", r#"{"token":"fixture"}"#),
        ] {
            let tag = serde_json::to_string(tag).unwrap();
            let canonical = if payload == "null" { format!(r#"{{"t":{tag}}}"#) }
                else { format!(r#"{{"t":{tag},"c":{payload}}}"#) };
            let expected: serde_json::Value = serde_json::from_str(&canonical).unwrap();
            let mut wires = vec![format!(r#"{{"t":{tag},"c":{payload}}}"#),
                                 format!(r#"{{"c":{payload},"t":{tag}}}"#)];
            if payload == "null" { wires.push(canonical); }
            for wire in wires {
                let (sent, received) = tokio::join!(
                    sender.send_raw(Bytes::from(wire)), receiver.next_main_timeout(1000),
                );
                sent.unwrap();
                match received {
                    Ok(Some(request)) if serde_json::to_value(&request).unwrap() == expected => request_controls += 1,
                    result => failures.push(format!("valid request {tag}: {result:?}")),
                }
            }
        }
        for (tag, payload) in [
            ("StatusSnapshot", r#"{"options":[{"key":"AudioInput","value":"device"}],"file_transfer_enabled":false}"#),
            ("ReadinessSnapshot", r#"{"permanent_password_set":true,"user_owned_permanent_password_writable":false,"direct_listener_bound":true}"#),
            ("Config", r#"{"key":{"t":"VoiceCallInput"},"value":"device"}"#),
            ("OptionSet", r#"{"result":"Applied","effective":{"key":"AudioInput","value":"device"}}"#),
            ("RequestFailed", r#""InternalFailure""#),
        ] {
            let tag = serde_json::to_string(tag).unwrap();
            let expected = serde_json::from_str::<serde_json::Value>(
                &format!(r#"{{"t":{tag},"c":{payload}}}"#),
            ).unwrap();
            let mut invalid = vec![
                format!(r#"{{"future":true,"t":{tag},"c":{payload}}}"#),
                format!(r#"{{"t":{tag},"future":true,"c":{payload}}}"#),
                format!(r#"{{"t":{tag},"c":{payload},"future":true}}"#),
                format!(r#"{{"future":true,"c":{payload},"t":{tag}}}"#),
                format!(r#"{{"c":{payload},"future":true,"t":{tag}}}"#),
                format!(r#"{{"c":{payload},"t":{tag},"future":true}}"#),
            ];
            if let Some(fields) = payload.strip_prefix('{') {
                let extra = format!(r#"{{"future":{{"nested":[1,2]}},{fields}"#);
                invalid.push(format!(r#"{{"t":{tag},"c":{extra}}}"#));
                invalid.push(format!(r#"{{"c":{extra},"t":{tag}}}"#));
            }
            for (index, wire) in invalid.into_iter().enumerate() {
                let (sent, received) = tokio::join!(
                    sender.send_raw(Bytes::from(wire)),
                    receiver.next_main_response_timeout(1000),
                );
                sent.unwrap();
                if matches!(received, Ok(None)) { rejected += 1; }
                else { failures.push(format!("{tag} malformed[{index}]: {}",
                    if received.is_ok() { "accepted" } else { "transport error" })); }
            }
            // Both JSON field orders remain valid after malformed frames on the same socket.
            for wire in [format!(r#"{{"t":{tag},"c":{payload}}}"#),
                         format!(r#"{{"c":{payload},"t":{tag}}}"#)] {
                let (sent, received) = tokio::join!(
                    sender.send_raw(Bytes::from(wire)),
                    receiver.next_main_response_timeout(1000),
                );
                sent.unwrap();
                match received {
                    Ok(Some(response)) if serde_json::to_value(&response).unwrap() == expected => controls += 1,
                    result => failures.push(format!("valid {tag}: {result:?}")),
                }
            }
        }
    }
    assert_eq!(fd_count(), before);
    assert!(failures.is_empty(), "response shape failures: {failures:?}");
    assert_eq!((rejected, controls), (38, 10));
    assert_eq!(retired, 2);
    assert_eq!((request_rejected, request_controls), (24, 18));
    println!("OK main-response-shape uid={} rejected=38 controls=10 retired=2 request_rejected=24 request_controls=18 cleanup=joined", unsafe { libc::geteuid() });
}

async fn main_response_fixture(scenario: &str) {
    if scenario == "shape" {
        main_response_shape_fixture().await;
        return;
    }
    let before = fd_count();
    {
        let (sender, receiver) = tokio::net::UnixStream::pair().unwrap();
        for fd in [sender.as_raw_fd(), receiver.as_raw_fd()] {
            assert_eq!(peer_uid_from_fd(fd), Some(unsafe { libc::geteuid() }));
            assert_eq!(peer_pid_from_fd(fd), Some(std::process::id()));
        }
        let mut sender = ConnectionTmpl::new_main(sender);
        let mut receiver = ConnectionTmpl::new_main(receiver);
        let response = match scenario {
            "status" => {
                use MainStatusOptionKey::*;
                // These unpinned keys may coexist in the effective status map.
                let keys = [AllowAutoDisconnect, AutoDisconnectTimeout, AllowAutoRecordIncoming,
                            EnableAbr, AllowRemoveWallpaper, AllowAlwaysSoftwareRender, EnableHwcodec,
                            EnableDirectxCapture, EnableAndroidSoftwareEncodingHalfScale,
                            KeepAwakeDuringIncomingSessions, AudioInput, VoiceCallInput];
                let entries = keys.into_iter().map(|key| MainStatusOption {
                    key, value: "\0".repeat(MAIN_IPC_MAX_OPTION_VALUE_BYTES),
                }.validate().unwrap()).collect();
                MainIpcResponse::StatusSnapshot(MainStatusSnapshot {
                    options: MainStatusOptions(entries).validate().unwrap(),
                    file_transfer_enabled: Some(true),
                })
            }
            "config" => MainIpcResponse::Config {
                key: MainConfigKey::VoiceCallInput {},
                value: Some("\0".repeat(MAIN_IPC_MAX_CONFIG_VALUE_BYTES)),
            },
            _ => panic!("unknown main response scenario"),
        };
        let expected = serde_json::to_vec(&response).unwrap();
        assert!(expected.len() > 256 * 1024, "fixture must cross the former frame cap");
        let (sent, received) = tokio::join!(
            sender.send_json_timeout(&response, 1000), receiver.next_main_response_timeout(1000),
        );
        assert!(sent.is_ok(), "valid {scenario} response ({} bytes) cannot be sent: {sent:?}", expected.len());
        let received = received.unwrap().unwrap();
        assert_eq!(serde_json::to_vec(&received).unwrap(), expected);

        let too_large = Bytes::from(vec![0; MAIN_IPC_MAX_FRAME_BYTES + 1]);
        assert!(sender.send_raw(too_large).await.is_err());
        let mut byte = 0u8;
        assert_eq!(unsafe { libc::recv(receiver.inner.get_ref().as_raw_fd(),
                                     (&mut byte as *mut u8).cast(), 1,
                                     libc::MSG_DONTWAIT | libc::MSG_PEEK) }, -1);
        assert_eq!(std::io::Error::last_os_error().kind(), std::io::ErrorKind::WouldBlock);
        let response = MainIpcResponse::RequestFailed(IpcMutationResult::Rejected);
        let (sent, received) = tokio::join!(
            sender.send_json_timeout(&response, 1000), receiver.next_main_response_timeout(1000),
        );
        sent.unwrap();
        assert!(matches!(received.unwrap().unwrap(),
                         MainIpcResponse::RequestFailed(IpcMutationResult::Rejected)));
        use tokio::io::AsyncWriteExt;
        let (header, width) = BytesCodec::encode_header(MAIN_IPC_MAX_FRAME_BYTES + 1).unwrap();
        sender.inner.get_mut().write_all(&header[..width]).await.unwrap();
        let error = timeout(1000, receiver.next_raw()).await.unwrap().unwrap_err();
        assert_eq!(error.downcast_ref::<std::io::Error>().unwrap().kind(),
                   std::io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "Too big packet");
    }
    assert_eq!(fd_count(), before);
    println!("OK main-response-{scenario} uid={} cleanup=joined", unsafe { libc::geteuid() });
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
            "allocation" => {
                struct AddressLimit(libc::rlimit);
                impl Drop for AddressLimit {
                    fn drop(&mut self) {
                        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &self.0) }, 0);
                    }
                }

                round_trip(&mut sender, &mut receiver, "warm").await;
                let frame_bytes = 16 * 1024 * 1024;
                let value = "x".repeat(frame_bytes - 2);
                sender.set_max_packet_length(frame_bytes);
                let pages: u64 = fs::read_to_string("/proc/self/statm").unwrap()
                    .split_whitespace().next().unwrap().parse().unwrap();
                let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
                assert!(page_size > 0);
                let ceiling = pages.checked_mul(page_size as u64).unwrap()
                    .checked_add(1024 * 1024).unwrap();
                let mut original = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut original) }, 0);
                assert!(ceiling < original.rlim_cur);
                let limited = libc::rlimit { rlim_cur: ceiling, rlim_max: original.rlim_max };
                assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &limited) }, 0);
                let restore = AddressLimit(original);
                let result = sender.send_json_timeout(&value, 1000).await;
                drop(restore);
                let mut restored = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut restored) }, 0);
                assert_eq!((restored.rlim_cur, restored.rlim_max), (original.rlim_cur, original.rlim_max));
                assert_eq!(result.unwrap_err().to_string(), "IPC frame allocation failed");
                no_wire_bytes(receiver.inner.get_ref());
                round_trip(&mut sender, &mut receiver, &value).await;
                observed = frame_bytes;
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

async fn wire_fixture(scenario: &str) {
    use std::os::unix::fs::MetadataExt;
    use tokio::io::AsyncReadExt;

    struct AddressLimit(libc::rlimit);
    impl Drop for AddressLimit {
        fn drop(&mut self) {
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &self.0) }, 0);
        }
    }

    async fn receive<S: AsyncRead + Unpin>(stream: &mut S, length: usize, header: &[u8]) {
        let mut actual = [0; 4];
        stream.read_exact(&mut actual[..header.len()]).await.unwrap();
        assert_eq!(&actual[..header.len()], header);
        let mut chunk = [0; 8192];
        let mut remaining = length;
        while remaining > 0 {
            let count = remaining.min(chunk.len());
            stream.read_exact(&mut chunk[..count]).await.unwrap();
            assert!(chunk[..count].iter().all(|byte| *byte == 0x5a));
            remaining -= count;
        }
    }

    async fn transfer<S: AsyncRead + AsyncWrite + Unpin + AsRawFd>(
        scenario: &str, sender: S, mut receiver: S,
    ) -> Result<(), String> {
        for fd in [sender.as_raw_fd(), receiver.as_raw_fd()] {
            assert_eq!(peer_uid_from_fd(fd), Some(unsafe { libc::geteuid() }));
            assert_eq!(peer_pid_from_fd(fd), Some(std::process::id()));
        }
        let mut sender = ConnectionTmpl::new(sender);
        sender.send_raw(Bytes::new()).await.unwrap();
        receive(&mut receiver, 0, &[0]).await;
        if scenario == "cancel" {
            let capacity: libc::c_int = 4096;
            assert_eq!(unsafe { libc::setsockopt(sender.inner.get_ref().as_raw_fd(),
                libc::SOL_SOCKET, libc::SO_SNDBUF, (&capacity as *const libc::c_int).cast(),
                std::mem::size_of_val(&capacity) as libc::socklen_t) }, 0);
            let length = 1024 * 1024;
            assert!(timeout(25, sender.send_raw(Bytes::from(vec![0x5a; length])))
                .await.is_err(), "the real socket must block before the frame completes");
            let mut prefix = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                let count = unsafe { libc::recv(receiver.as_raw_fd(), chunk.as_mut_ptr().cast(),
                    chunk.len(), libc::MSG_DONTWAIT) };
                if count < 0 {
                    assert_eq!(std::io::Error::last_os_error().kind(), std::io::ErrorKind::WouldBlock);
                    break;
                }
                assert!(count > 0);
                prefix.extend_from_slice(&chunk[..count as usize]);
                assert!(prefix.len() < length + 3);
            }
            assert!(prefix.len() > 3, "cancellation must follow a partial payload write");
            assert_eq!(&prefix[..3], &[2, 0, 64]);
            assert!(prefix[3..].iter().all(|byte| *byte == 0x5a));
            let raw = timeout(1000, sender.send_raw(Bytes::from_static(b"next")))
                .await.expect("subsequent raw send must finish");
            let json = sender.send_json_timeout(&"next", 1000).await;
            let count = unsafe { libc::recv(receiver.as_raw_fd(), chunk.as_mut_ptr().cast(),
                chunk.len(), libc::MSG_DONTWAIT) };
            let unchanged = count == -1
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock;
            if raw.is_ok() || json.is_ok() || !unchanged {
                return Err(format!("partial_bytes={} raw={raw:?} json={json:?} appended={count}",
                    prefix.len()));
            }
            return Ok(());
        }
        let cases: &[(usize, &[u8])] = match scenario {
            "bounds" => &[(0, &[0]), (1, &[4]), (63, &[252]), (64, &[1, 1]),
                (16_383, &[253, 255]), (16_384, &[2, 0, 1]),
                (4_194_303, &[254, 255, 255]), (4_194_304, &[3, 0, 0, 1])],
            "allocation" => &[(16 * 1024 * 1024, &[3, 0, 0, 4])],
            _ => panic!("unknown wire scenario"),
        };
        for &(length, header) in cases {
            let payload = Bytes::from(vec![0x5a; length]);
            if scenario == "bounds" {
                let mut wire = bytes::BytesMut::new();
                let mut codec = BytesCodec::new();
                tokio_util::codec::Encoder::encode(&mut codec, payload.clone(), &mut wire).unwrap();
                assert_eq!(&wire[..header.len()], header);
                assert_eq!(&wire[header.len()..], payload.as_ref());
                assert_eq!(tokio_util::codec::Decoder::decode(&mut codec, &mut wire)
                    .unwrap().unwrap().as_ref(), payload.as_ref());
                assert!(wire.is_empty());
                if length > 0 {
                    sender.set_max_packet_length(length - 1);
                    assert!(sender.send_raw(payload.clone()).await.is_err());
                    let mut byte = 0u8;
                    assert_eq!(unsafe { libc::recv(receiver.as_raw_fd(), (&mut byte as *mut u8).cast(),
                        1, libc::MSG_DONTWAIT | libc::MSG_PEEK) }, -1);
                    assert_eq!(std::io::Error::last_os_error().kind(), std::io::ErrorKind::WouldBlock);
                }
            }
            sender.set_max_packet_length(length);
            let restore = if scenario == "allocation" {
                let pages: u64 = fs::read_to_string("/proc/self/statm").unwrap()
                    .split_whitespace().next().unwrap().parse().unwrap();
                let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
                assert!(page_size > 0);
                let ceiling = pages.checked_mul(page_size as u64).unwrap()
                    .checked_add(1024 * 1024).unwrap();
                let mut original = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut original) }, 0);
                assert!(ceiling < original.rlim_cur);
                let limited = libc::rlimit { rlim_cur: ceiling, rlim_max: original.rlim_max };
                assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &limited) }, 0);
                Some(AddressLimit(original))
            } else { None };
            let (sent, received) = tokio::join!(
                timeout(1000, sender.send_raw(payload)),
                timeout(1000, receive(&mut receiver, length, header)),
            );
            let original = restore.as_ref().map(|limit| (limit.0.rlim_cur, limit.0.rlim_max));
            drop(restore);
            if let Some(original) = original {
                let mut restored = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut restored) }, 0);
                assert_eq!((restored.rlim_cur, restored.rlim_max), original);
            }
            sent.unwrap().unwrap();
            received.unwrap();
        }
        assert_eq!(BytesCodec::encode_header(0x3fff_ffff).unwrap(), ([255; 4], 4));
        for length in [0x4000_0000, usize::MAX] {
            assert_eq!(BytesCodec::encode_header(length).unwrap_err().kind(),
                       std::io::ErrorKind::InvalidInput);
        }
        sender.send_raw(Bytes::new()).await.unwrap();
        receive(&mut receiver, 0, &[0]).await;
        let mut byte = 0u8;
        assert_eq!(unsafe { libc::recv(receiver.as_raw_fd(), (&mut byte as *mut u8).cast(), 1,
                                     libc::MSG_DONTWAIT | libc::MSG_PEEK) }, -1);
        assert_eq!(std::io::Error::last_os_error().kind(), std::io::ErrorKind::WouldBlock);
        Ok(())
    }
    let before = fd_count();
    let result = if let Some(scenario) = scenario.strip_prefix("ipc-") {
        let mut incoming = new_listener("").await.unwrap();
        let path = Config::ipc_path("");
        let identity = fs::symlink_metadata(&path).unwrap();
        let sender = timeout(1000, Endpoint::connect(&path)).await.unwrap().unwrap();
        let receiver = timeout(1000, incoming.next()).await.unwrap().unwrap().unwrap();
        assert!(!sender.is_write_vectored(), "pinned IPC transport must exercise scalar writes");
        let result = transfer(scenario, sender, receiver).await;
        drop(incoming);
        let retained = fs::symlink_metadata(&path).unwrap();
        assert_eq!((retained.dev(), retained.ino()), (identity.dev(), identity.ino()));
        fs::remove_file(path).unwrap();
        result
    } else {
        let (sender, receiver) = tokio::net::UnixStream::pair().unwrap();
        assert!(sender.is_write_vectored(), "socket pair must exercise vectored writes");
        transfer(scenario, sender, receiver).await
    };
    assert_eq!(fd_count(), before);
    result.expect("an interrupted frame must prevent subsequent writes");
    println!("OK wire-{scenario} uid={} cleanup=joined", unsafe { libc::geteuid() });
}

async fn read_fixture(scenario: &str) {
    use std::os::unix::fs::MetadataExt;
    use tokio::io::AsyncWriteExt;

    async fn payload<S: AsyncWrite + Unpin>(sender: &mut S, mut remaining: usize) -> std::io::Result<()> {
        let chunk = [0x5a; 8192];
        while remaining > 0 {
            let count = remaining.min(chunk.len());
            sender.write_all(&chunk[..count]).await?;
            remaining -= count;
        }
        Ok(())
    }

    let before = fd_count();
    let mut incoming = new_listener("").await.unwrap();
    let path = Config::ipc_path("");
    let identity = fs::symlink_metadata(&path).unwrap();
    let mut sender = timeout(1000, Endpoint::connect(&path)).await.unwrap().unwrap();
    let receiver = timeout(1000, incoming.next()).await.unwrap().unwrap().unwrap();
    for fd in [sender.as_raw_fd(), receiver.as_raw_fd()] {
        assert_eq!(peer_uid_from_fd(fd), Some(unsafe { libc::geteuid() }));
        assert_eq!(peer_pid_from_fd(fd), Some(std::process::id()));
    }
    let mut receiver = ConnectionTmpl::new(receiver);
    sender.write_all(&[0]).await.unwrap();
    assert!(receiver.next_raw().await.unwrap().is_empty());
    match scenario {
        "allocation" => {
            struct AddressLimit(libc::rlimit);
            impl Drop for AddressLimit {
                fn drop(&mut self) {
                    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &self.0) }, 0);
                }
            }
            let length = 16 * 1024 * 1024;
            receiver.set_max_packet_length(length);
            let pages: u64 = fs::read_to_string("/proc/self/statm").unwrap()
                .split_whitespace().next().unwrap().parse().unwrap();
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            assert!(page_size > 0);
            let ceiling = pages.checked_mul(page_size as u64).unwrap()
                .checked_add(1024 * 1024).unwrap();
            let mut original = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut original) }, 0);
            assert!(ceiling < original.rlim_cur);
            let limited = libc::rlimit { rlim_cur: ceiling, rlim_max: original.rlim_max };
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &limited) }, 0);
            let restore = AddressLimit(original);
            sender.write_all(&[3, 0, 0, 4]).await.unwrap();
            let read = async move {
                let result = timeout(1000, receiver.next_raw()).await.unwrap();
                assert_eq!(timeout(1000, receiver.next_raw()).await.unwrap().unwrap_err().to_string(),
                           "reset by the peer");
                drop(receiver);
                result
            };
            let (received, sent) = tokio::join!(read, timeout(1000, payload(&mut sender, length)));
            drop(restore);
            let mut restored = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut restored) }, 0);
            assert_eq!((restored.rlim_cur, restored.rlim_max), (original.rlim_cur, original.rlim_max));
            assert_eq!(received.unwrap_err().to_string(), "inbound IPC frame allocation failed");
            assert!(matches!(sent.unwrap().unwrap_err().kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset));
        }
        "fragments" => {
            for (length, header) in [(0, &[0][..]), (1, &[4][..]), (63, &[252][..]),
                (64, &[1, 1][..]), (16_383, &[253, 255][..]), (16_384, &[2, 0, 1][..]),
                (4_194_303, &[254, 255, 255][..]), (4_194_304, &[3, 0, 0, 1][..])] {
                receiver.set_max_packet_length(length);
                for (index, byte) in header.iter().enumerate() {
                    sender.write_all(std::slice::from_ref(byte)).await.unwrap();
                    if index + 1 < header.len() || length > 0 {
                        assert!(timeout(5, receiver.next_raw()).await.is_err());
                    }
                }
                let mut remaining = length;
                if length > 1 {
                    sender.write_all(&[0x5a]).await.unwrap();
                    remaining -= 1;
                    assert!(timeout(5, receiver.next_raw()).await.is_err());
                }
                let (sent, received) = tokio::join!(
                    timeout(1000, payload(&mut sender, remaining)),
                    timeout(1000, receiver.next_raw()),
                );
                sent.unwrap().unwrap();
                let frame = received.unwrap().unwrap();
                assert_eq!(frame.len(), length);
                assert!(frame.iter().all(|byte| *byte == 0x5a));
            }
            sender.write_all(&[0, 4, 0x5a, 0]).await.unwrap();
            sender.shutdown().await.unwrap();
            for expected in [&[][..], &[0x5a][..], &[][..]] {
                assert_eq!(receiver.next_raw().await.unwrap().as_ref(), expected);
            }
            assert_eq!(receiver.next_raw().await.unwrap_err().to_string(), "reset by the peer");
            drop(receiver);
        }
        "refusal" => {
            receiver.set_max_packet_length(8);
            sender.write_all(&[36]).await.unwrap();
            let error = timeout(1000, receiver.next_raw()).await.unwrap().unwrap_err();
            assert_eq!(error.downcast_ref::<std::io::Error>().unwrap().kind(), std::io::ErrorKind::InvalidData);
            drop(receiver);
            for prefix in [&[1][..], &[2][..], &[2, 0][..], &[3][..], &[3, 0][..],
                &[3, 0, 0][..], &[4][..], &[1, 1][..], &[1, 1, 0x5a][..],
                &[2, 0, 1][..], &[3, 0, 0, 1][..]] {
                let (mut writer, reader) = tokio::net::UnixStream::pair().unwrap();
                let mut reader = ConnectionTmpl::new(reader);
                writer.write_all(prefix).await.unwrap();
                writer.shutdown().await.unwrap();
                let error = timeout(1000, reader.next_raw()).await.unwrap().unwrap_err();
                assert_eq!(error.downcast_ref::<std::io::Error>().unwrap().kind(), std::io::ErrorKind::UnexpectedEof);
            }
        }
        _ => panic!("unknown read scenario"),
    }
    drop(sender);
    drop(incoming);
    let retained = fs::symlink_metadata(&path).unwrap();
    assert_eq!((retained.dev(), retained.ino()), (identity.dev(), identity.ino()));
    fs::remove_file(path).unwrap();
    assert_eq!(fd_count(), before);
    println!("OK read-{scenario} uid={} cleanup=joined", unsafe { libc::geteuid() });
}

async fn main_peer_server(route_uid: u32, client_uid: u32, dumpable: u32) {
    use tokio::io::AsyncReadExt;
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, dumpable as libc::c_ulong,
                                  0 as libc::c_ulong, 0 as libc::c_ulong, 0 as libc::c_ulong) }, 0);
    assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE) }, dumpable as i32);
    let before = fd_count();
    let mut payloads = 0;
    let payload = serde_json::to_vec(&MainIpcRequest::StatusSnapshot).unwrap();
    let (header, width) = BytesCodec::encode_header(payload.len()).unwrap();
    let expected: Vec<u8> = header[..width].iter().chain(payload.iter()).copied().collect();
    {
        let path = Config::ipc_path_for_uid(route_uid, "");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        ready("READY");
        for _ in 0..2 {
            let (mut stream, _) = timeout(4000, listener.accept()).await.unwrap().unwrap();
            assert_eq!(peer_uid_from_fd(stream.as_raw_fd()), Some(client_uid));
            assert!(peer_pid_from_fd(stream.as_raw_fd()).is_some_and(|pid| pid > 0));
            let mut first = [0];
            if timeout(2000, stream.read(&mut first)).await.unwrap().unwrap() != 0 {
                let mut received = vec![first[0]; expected.len()];
                timeout(2000, stream.read_exact(&mut received[1..])).await.unwrap().unwrap();
                assert_eq!(received, expected);
                payloads += 1;
                let mut stream = ConnectionTmpl::new_main(stream);
                stream.send_json_timeout(&MainIpcResponse::StatusSnapshot(MainStatusSnapshot {
                    options: MainStatusOptions(Vec::new()), file_transfer_enabled: None,
                }), 1000).await.unwrap();
            }
        }
    }
    assert_eq!(fd_count(), before);
    println!("OK main-peer-server uid={} payloads={payloads} cleanup=joined", unsafe { libc::geteuid() });
}

async fn main_peer_client(route_uid: u32, allowed: bool) {
    let before = fd_count();
    MAIN_ROUTE_UID.with(|uid| uid.set(Some(route_uid)));
    USE_USER_MAIN_IPC.with(|enabled| enabled.set(unsafe { libc::geteuid() } == 0));
    let ordinary = main_transaction::main_ipc_request(MainIpcRequest::StatusSnapshot, 1000).await;
    let explicit = async {
        let stream = connect_for_uid(1000, route_uid, "").await?;
        main_transaction::main_ipc_request_on_stream(stream, MainIpcRequest::StatusSnapshot, 1000).await
    }.await;
    assert_eq!(fd_count(), before);
    for (route, result) in [("ordinary", ordinary), ("explicit", explicit)] {
        if allowed {
            assert!(matches!(result, Ok(MainIpcResponse::StatusSnapshot(ref snapshot))
                if snapshot.options.0.is_empty() && snapshot.file_transfer_enabled.is_none()),
                "valid {route} response was not returned: {result:?}");
        } else {
            assert!(result.as_ref().err().is_some_and(|error|
                error.to_string().contains("Linux main IPC server principal does not match")),
                "foreign {route} peer was not refused: {result:?}");
        }
    }
    println!("OK main-peer-client route_uid={route_uid} allowed={allowed} cleanup=joined");
}

async fn argv_auth_fixture(allowed: bool) {
    let descriptors = fd_count();
    let mut failures = 0;
    for main in [true, false] {
        let stream = tokio::net::UnixStream::connect(Config::ipc_path("")).await.unwrap();
        let pid = peer_pid_from_fd(stream.as_raw_fd()).unwrap();
        let result = if main {
            let stream = ConnectionTmpl::new_main(stream);
            argv_auth::ensure_user_owned_main_server_is_trusted(&stream)
        } else {
            argv_auth::ensure_user_owned_password_server_is_trusted(&stream, unsafe { libc::geteuid() })
        };
        if allowed {
            assert!(result.is_ok(), "valid server role refused: {result:?}");
        } else {
            let error = result.unwrap_err().to_string();
            assert!(error.contains("argv mismatch") && error.contains(&format!("pid={pid}")));
            let marker = "synthetic-private-argument";
            let disclosed = error.contains(marker) || error.contains(&format!("{:?}", marker.as_bytes()));
            failures += usize::from(disclosed);
        }
    }
    assert_eq!(fd_count(), descriptors);
    assert_eq!(failures, 0, "peer arguments entered rejection diagnostics");
    println!("OK argv-auth-{allowed} uid={} checks=2 cleanup=joined", unsafe { libc::geteuid() });
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!(Path::new("/run/rustdesk-verifier-vm").is_dir());
    if std::env::var_os("RUSTDESK_ARGV_PEER").is_some() {
        use std::io::Read;
        let _listener = std::os::unix::net::UnixListener::bind(Config::ipc_path("")).unwrap();
        ready("READY");
        assert_eq!(std::io::stdin().read(&mut [0u8]).unwrap(), 0);
        return;
    }
    assert_eq!(args.len(), 3);
    if let Some(allowed) = args[1].strip_prefix("argv-auth-") {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(argv_auth_fixture(allowed.parse().unwrap()));
        return;
    }
    if args[1].starts_with("cli-option-") {
        cli_option_read::run();
        return;
    }
    let postfix = &args[2];
    assert!(["", "_password", "_service_password", "_service_credential", "_service"].contains(&postfix.as_str()));
    let path = Config::ipc_path(postfix);
    if let Some(parameters) = args[1].strip_prefix("main-peer-server-") {
        let values: Vec<u32> = parameters.split('-').map(|value| value.parse().unwrap()).collect();
        assert_eq!(values.len(), 3);
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(main_peer_server(values[0], values[1], values[2]));
        return;
    }
    if let Some(parameters) = args[1].strip_prefix("main-peer-client-") {
        let (uid, allowed) = parameters.split_once('-').unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(main_peer_client(uid.parse().unwrap(), allowed.parse().unwrap()));
        return;
    }
    if let Some(scenario) = args[1].strip_prefix("url-accept-") {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(url_accept_fixture(scenario));
        return;
    }
    if let Some(scenario) = args[1].strip_prefix("main-validation-") {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(main_validation_fixture(scenario));
        return;
    }
    if let Some(scenario) = args[1].strip_prefix("main-transaction-") {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(main_transaction_fixture(scenario));
        return;
    }
    if let Some(scenario) = args[1].strip_prefix("main-response-") {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(main_response_fixture(scenario));
        return;
    }
    if let Some(scenario) = args[1].strip_prefix("read-") {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(read_fixture(scenario));
        return;
    }
    if let Some(scenario) = args[1].strip_prefix("wire-") {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(wire_fixture(scenario));
        return;
    }
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
    if let Some(scenario) = args[1].strip_prefix("windows-main-admission-") {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(windows_main_admission_fixture(scenario));
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
