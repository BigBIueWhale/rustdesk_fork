use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock, Weak,
    },
    time::Duration,
};

use bytes::Bytes;

pub use connection::*;
use hbb_common::{
    allow_err,
    anyhow::Context,
    bail,
    config::{Config, PermanentPasswordCredentialSnapshot, PermanentPasswordPrsRead},
    log,
    message_proto::*,
    protobuf::{Enum, Message as _},
    rendezvous_proto::*,
    tokio, ResultType, Stream,
};
use scrap::camera;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use service::ServiceTmpl;
use service::{EmptyExtraFieldService, GenericService, Service, Subscriber};
use video_service::VideoSource;

use crate::ipc::Data;

pub mod audio_service;
#[cfg(target_os = "windows")]
pub mod terminal_helper;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub mod terminal_service;
cfg_if::cfg_if! {
if #[cfg(not(target_os = "ios"))] {
mod clipboard_service;
#[cfg(target_os = "android")]
pub use clipboard_service::is_clipboard_service_ok;
#[cfg(target_os = "linux")]
pub(crate) mod wayland;
// R-X13 (§8): the uinput + rdp_input injection modules are EXCISED — Wayland uinput (the cross-uid
// _uinput_* IPC + /dev/uinput kernel injection) and the dbus-portal RDP injection. XTEST/enigo is the
// pinned sole injector (wayland_use_uinput()/wayland_use_rdp_input() were already false by
// construction), so these were dead compiled-in surface (§8 "removed not disabled"). The separate
// scrap::wayland CAPTURE path is compiled out and source-gated under R-X12.
// R-X6: the D-Bus deep-link module (org.rustdesk.rustdesk NewConnection) is excised.
#[cfg(not(target_os = "android"))]
pub mod input_service;
} else {
mod clipboard_service {
pub const NAME: &'static str = "";
}
}
}

#[cfg(any(target_os = "android", target_os = "ios"))]
pub mod input_service {
    pub const NAME_CURSOR: &'static str = "";
    pub const NAME_POS: &'static str = "";
    pub const NAME_WINDOW_FOCUS: &'static str = "";
}

mod connection;
pub mod display_service;
// R-X9 (slices 2-4): `pub mod portable_service;` is excised — the portable SYSTEM run-mode
// is removed; the installed LocalSystem service is the sole controlled entry.
mod service;
mod video_qos;
pub mod video_service;

#[cfg(any(target_os = "windows", test))]
#[derive(Clone)]
struct WindowsCredentialTransition {
    id: String,
    previous_storage: String,
    previous_salt: String,
    previous_tag: [u8; 32],
}

#[cfg(any(target_os = "windows", test))]
#[derive(Default)]
struct WindowsCredentialReplica {
    initialized: bool,
    storage: String,
    salt: String,
    tag: [u8; 32],
    transition: Option<WindowsCredentialTransition>,
}

#[cfg(any(target_os = "windows", test))]
impl WindowsCredentialReplica {
    fn resume_with<F, C>(
        &mut self,
        transition_id: &str,
        quiesced: bool,
        restore: F,
        clear_quiesce: C,
    ) -> ResultType<crate::ipc::WindowsCredentialReplicaState>
    where
        F: FnOnce(&str, &str) -> ResultType<()>,
        C: FnOnce(),
    {
        let Some(transition) = self.transition.as_ref() else {
            if !quiesced {
                return Ok(crate::ipc::WindowsCredentialReplicaState {
                    transition_id: None,
                    replica_tag: self.tag,
                    quiesced: false,
                });
            }
            bail!("Windows credential replica quiesce state is incomplete");
        };
        if transition.id != transition_id {
            bail!("Windows credential replica transition identity mismatch");
        }
        let transition = transition.clone();
        restore(&transition.previous_storage, &transition.previous_salt)?;
        self.storage = transition.previous_storage;
        self.salt = transition.previous_salt;
        self.tag = transition.previous_tag;
        self.transition = None;
        clear_quiesce();
        Ok(crate::ipc::WindowsCredentialReplicaState {
            transition_id: None,
            replica_tag: self.tag,
            quiesced: false,
        })
    }
}

#[cfg(target_os = "windows")]
static WINDOWS_CREDENTIAL_REPLICA: std::sync::OnceLock<std::sync::Mutex<WindowsCredentialReplica>> =
    std::sync::OnceLock::new();
#[cfg(any(target_os = "windows", test))]
static WINDOWS_CREDENTIAL_QUIESCED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "windows")]
fn windows_credential_replica() -> &'static std::sync::Mutex<WindowsCredentialReplica> {
    WINDOWS_CREDENTIAL_REPLICA
        .get_or_init(|| std::sync::Mutex::new(WindowsCredentialReplica::default()))
}

#[cfg(target_os = "windows")]
fn initialize_windows_credential_replica(replica: &mut WindowsCredentialReplica) {
    if replica.initialized {
        return;
    }
    let (storage, salt) = Config::get_local_permanent_password_storage_and_salt();
    replica.tag = crate::ipc::windows_credential_replica_tag(&storage, &salt);
    replica.storage = storage;
    replica.salt = salt;
    replica.initialized = true;
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_credential_authentication_is_quiesced() -> bool {
    WINDOWS_CREDENTIAL_QUIESCED.load(Ordering::Acquire)
}

#[cfg(any(target_os = "windows", test))]
fn quiesce_windows_credential_authentication() -> ResultType<()> {
    WINDOWS_CREDENTIAL_QUIESCED.store(true, Ordering::Release);
    if let Err(err) = Config::set_permanent_password_storage_for_runtime("", "") {
        WINDOWS_CREDENTIAL_QUIESCED.store(false, Ordering::Release);
        return Err(err);
    }
    Ok(())
}

#[cfg(any(target_os = "windows", test))]
fn resume_windows_credential_authentication() {
    WINDOWS_CREDENTIAL_QUIESCED.store(false, Ordering::Release);
}

#[cfg(target_os = "windows")]
pub(crate) fn quiesce_windows_credential_replica(
    transition_id: &str,
) -> ResultType<crate::ipc::WindowsCredentialReplicaState> {
    let mut replica = windows_credential_replica().lock().unwrap();
    initialize_windows_credential_replica(&mut replica);
    if let Some(transition) = replica.transition.as_ref() {
        if transition.id != transition_id {
            bail!("another Windows credential transition is already active");
        }
        return Ok(crate::ipc::WindowsCredentialReplicaState {
            transition_id: Some(transition.id.clone()),
            replica_tag: transition.previous_tag,
            quiesced: windows_credential_authentication_is_quiesced(),
        });
    }

    quiesce_windows_credential_authentication()?;
    replica.transition = Some(WindowsCredentialTransition {
        id: transition_id.to_owned(),
        previous_storage: replica.storage.clone(),
        previous_salt: replica.salt.clone(),
        previous_tag: replica.tag,
    });
    Ok(crate::ipc::WindowsCredentialReplicaState {
        transition_id: Some(transition_id.to_owned()),
        replica_tag: replica.tag,
        quiesced: true,
    })
}

#[cfg(target_os = "windows")]
pub(crate) fn apply_windows_credential_replica(
    transition_id: &str,
    storage: &str,
    salt: &str,
    replica_tag: [u8; 32],
) -> ResultType<crate::ipc::WindowsCredentialReplicaState> {
    if crate::ipc::windows_credential_replica_tag(storage, salt) != replica_tag {
        bail!("Windows credential replica tag does not match the supplied snapshot");
    }
    let mut replica = windows_credential_replica().lock().unwrap();
    initialize_windows_credential_replica(&mut replica);
    let Some(transition) = replica.transition.as_ref() else {
        if replica.tag == replica_tag {
            return Ok(crate::ipc::WindowsCredentialReplicaState {
                transition_id: None,
                replica_tag,
                quiesced: windows_credential_authentication_is_quiesced(),
            });
        }
        bail!("Windows credential replica has no matching active transition");
    };
    if transition.id != transition_id {
        bail!("Windows credential replica transition identity mismatch");
    }
    Config::set_permanent_password_storage_for_runtime(storage, salt)?;
    replica.storage = storage.to_owned();
    replica.salt = salt.to_owned();
    replica.tag = replica_tag;
    replica.transition = None;
    resume_windows_credential_authentication();
    Ok(crate::ipc::WindowsCredentialReplicaState {
        transition_id: None,
        replica_tag,
        quiesced: false,
    })
}

#[cfg(target_os = "windows")]
pub(crate) fn resume_windows_credential_replica(
    transition_id: &str,
) -> ResultType<crate::ipc::WindowsCredentialReplicaState> {
    let mut replica = windows_credential_replica().lock().unwrap();
    initialize_windows_credential_replica(&mut replica);
    replica.resume_with(
        transition_id,
        windows_credential_authentication_is_quiesced(),
        |storage, salt| {
            Config::set_permanent_password_storage_for_runtime(storage, salt).map(|_| ())
        },
        resume_windows_credential_authentication,
    )
}

#[cfg(target_os = "windows")]
pub(crate) fn query_windows_credential_replica() -> crate::ipc::WindowsCredentialReplicaState {
    let mut replica = windows_credential_replica().lock().unwrap();
    initialize_windows_credential_replica(&mut replica);
    crate::ipc::WindowsCredentialReplicaState {
        transition_id: replica
            .transition
            .as_ref()
            .map(|transition| transition.id.clone()),
        replica_tag: replica.tag,
        quiesced: windows_credential_authentication_is_quiesced(),
    }
}

pub async fn effective_permanent_password_prs_status() -> PermanentPasswordPrsRead {
    effective_permanent_password_credential_snapshot()
        .await
        .into_parts()
        .0
}

pub async fn effective_permanent_password_credential_snapshot(
) -> PermanentPasswordCredentialSnapshot {
    #[cfg(target_os = "macos")]
    if crate::common::is_service_owned_server_process() {
        match crate::ipc::refresh_macos_service_owned_permanent_password_snapshot(1_000).await {
            Ok(_) => return Config::read_permanent_password_credential_snapshot(),
            Err(err) => {
                log::debug!("Failed to refresh macOS service-owned password snapshot: {err}");
                if let Err(clear_err) = Config::set_permanent_password_storage_for_runtime("", "") {
                    log::warn!(
                        "Failed to clear stale macOS service-owned password snapshot: {clear_err}"
                    );
                }
                return Config::read_permanent_password_credential_snapshot();
            }
        }
    }
    Config::read_permanent_password_credential_snapshot()
}

pub async fn effective_permanent_password_prs() -> String {
    effective_permanent_password_prs_status().await.into_prs()
}

pub type Childs = Arc<Mutex<Vec<std::process::Child>>>;
type ConnMap = HashMap<i32, ConnInner>;

lazy_static::lazy_static! {
    pub static ref CHILD_PROCESS: Childs = Default::default();
    // A client server used to provide local services(audio, video, clipboard, etc.)
    // for all initiative connections.
    //
    // [Note]
    // ugly
    // Now we use this [`CLIENT_SERVER`] to do following operations:
    // - record local audio, and send to remote
    pub static ref CLIENT_SERVER: ServerPtr = new();
}

// ── R-T1 / R-T0 / R-T12: DMZ connection-flood bound + flood-safe observability ────────────
/// R-T1(b): a global bound on concurrent PRE-KEY CPace handshakes. An unauthenticated
/// connection flood would otherwise spawn unbounded handshake tasks (each holding an fd and
/// up to ~36s of half-open state) and exhaust the host (R-D3 "defensible without a
/// firewall"). The slot is acquired with a non-blocking try-acquire in the accept loop
/// BEFORE the task is spawned and before any per-connection server lock is taken (R-T0
/// rule 2: a shed connection costs accept+close, not spawn+lock); it is a global CAPACITY
/// shed, NEVER a per-source ban (R-S10 cardinal rule: a CGNAT-shared attacker must not lock
/// the owner out). The budget is generous — a single-user box never has hundreds of
/// concurrent NEW handshakes, so a legitimate connection always finds a slot — while a
/// flood is capped at this many concurrent half-opens, each self-expiring via the R-P14b
/// per-step timeout. The permit is held only across the handshake and released before the
/// unbounded Connection::start session.
const PREKEY_HANDSHAKE_BUDGET: usize = 256;
/// R-T0 rule 1 / R-T12: a per-event log on the shed / rate-limit / key-confirmation hot
/// paths is itself a log-amplification DoS under the very flood it reports, so events are
/// counted lock-free and a single summary line is emitted at most once per this interval.
const SECURITY_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

lazy_static::lazy_static! {
    pub static ref PREKEY_HANDSHAKE_SLOTS: std::sync::Arc<tokio::sync::Semaphore> =
        std::sync::Arc::new(tokio::sync::Semaphore::new(PREKEY_HANDSHAKE_BUDGET));
    static ref SEC_SHED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    static ref SEC_RATE_LIMITED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    static ref SEC_KEY_CONFIRM: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    static ref SEC_LOG_STATE: std::sync::Mutex<(Option<std::time::Instant>, Option<std::net::IpAddr>)> =
        std::sync::Mutex::new((None, None));
    static ref ACCEPT_ERR_COUNT: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);
    static ref ACCEPT_ERR_LOG_STATE: std::sync::Mutex<(Option<std::time::Instant>, Option<&'static str>)> =
        std::sync::Mutex::new((None, None));
    static ref ACCEPT_NODELAY_ERR: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);
    static ref ACCEPT_KEEPALIVE_ERR: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);
    static ref ACCEPT_SETUP_LOG_STATE: std::sync::Mutex<(Option<std::time::Instant>, Option<std::net::IpAddr>)> =
        std::sync::Mutex::new((None, None));
    /// R-T9 (§20): the process-wide graceful-shutdown signal. Cancelled by the SIGTERM/SIGINT
    /// handler (`direct_service::start_direct_only`); the accept loop observes it and stops
    /// accepting, and every live connection's run-loop wakes on its `cancelled()` select-arm to
    /// send a CloseReason, flush the writer, and notify the CM before the process exits.
    static ref SHUTDOWN_TOKEN: hbb_common::tokio_util::sync::CancellationToken =
        hbb_common::tokio_util::sync::CancellationToken::new();
}

/// R-T12 security-event categories whose hot-path observability is rate-limited (R-T0 rule 1).
#[derive(Clone, Copy)]
pub enum SecurityEvent {
    /// R-T1(b): an inbound connection shed because the pre-key handshake budget is saturated.
    Shed,
    /// R-S10: a source shed because it exceeded the online-guess rate.
    RateLimited,
    /// R-P3 / R-P14c: a key-confirmation tag mismatch (an online password guess).
    KeyConfirmFail,
}

#[derive(Clone, Copy)]
pub enum AcceptSetupEvent {
    NodelayFailed,
    KeepaliveFailed,
}

/// R-T12 / R-S10: record a security event and emit at most one aggregated summary line per
/// `SECURITY_LOG_INTERVAL` (with the most-recent source). Lock-light by construction: the
/// counters are lock-free atomics, and the periodic flush is gated on a non-blocking
/// `try_lock`, so a flood never serializes on it. This is the "only audit signal on a
/// serverless box" (R-S10) made flood-safe (R-T0 rule 1) — never one log line per event.
pub fn note_security_event(kind: SecurityEvent, ip: std::net::IpAddr) {
    use std::sync::atomic::Ordering::Relaxed;
    match kind {
        SecurityEvent::Shed => {
            SEC_SHED.fetch_add(1, Relaxed);
        }
        SecurityEvent::RateLimited => {
            SEC_RATE_LIMITED.fetch_add(1, Relaxed);
        }
        SecurityEvent::KeyConfirmFail => {
            SEC_KEY_CONFIRM.fetch_add(1, Relaxed);
        }
    }
    if let Ok(mut state) = SEC_LOG_STATE.try_lock() {
        state.1 = Some(ip);
        let due = match state.0 {
            None => true,
            Some(t) => t.elapsed() >= SECURITY_LOG_INTERVAL,
        };
        if due {
            let shed = SEC_SHED.swap(0, Relaxed);
            let rate_limited = SEC_RATE_LIMITED.swap(0, Relaxed);
            let key_confirmation_failures = SEC_KEY_CONFIRM.swap(0, Relaxed);
            if shed + rate_limited + key_confirmation_failures > 0 {
                state.0 = Some(std::time::Instant::now());
                log::warn!(
                    "R-S10/R-T12 security summary (last {:?}): shed={} rate_limited={} key_confirmation_failures={} recent_src={:?}",
                    SECURITY_LOG_INTERVAL,
                    shed,
                    rate_limited,
                    key_confirmation_failures,
                    state.1
                );
            }
        }
    }
}

/// R-T12: a real `accept()` error (e.g. EMFILE/ENFILE under fd-exhaustion) — observed as an
/// aggregated periodic summary so a sustained accept-error storm cannot itself log-flood while the
/// operator still sees how many accept failures were suppressed and what errno class was most recent.
pub fn note_accept_error(port: u16, err: &std::io::Error) {
    use std::sync::atomic::Ordering::Relaxed;
    ACCEPT_ERR_COUNT.fetch_add(1, Relaxed);
    let class = accept_error_class(err);
    if let Ok(mut state) = ACCEPT_ERR_LOG_STATE.try_lock() {
        state.1 = Some(class);
        let due = match state.0 {
            None => true,
            Some(t) => t.elapsed() >= SECURITY_LOG_INTERVAL,
        };
        if due {
            let count = ACCEPT_ERR_COUNT.swap(0, Relaxed);
            if count > 0 {
                state.0 = Some(std::time::Instant::now());
                log::warn!(
                    "R-T12 accept-error summary (last {:?}) on :{}: count={} last_error={} errno={:?} last_class={}",
                    SECURITY_LOG_INTERVAL,
                    port,
                    count,
                    err,
                    err.raw_os_error(),
                    state.1.unwrap_or(class)
                );
            }
        }
    }
}

/// R-T0/R-T10: accepted-socket setup failures are on the attacker-reachable accept hot path.
/// Report them, but aggregate them so a platform-level keepalive/nodelay failure cannot become
/// a log-amplification DoS under a connection flood.
pub fn note_accept_setup_error(kind: AcceptSetupEvent, ip: std::net::IpAddr, err: &std::io::Error) {
    use std::sync::atomic::Ordering::Relaxed;
    match kind {
        AcceptSetupEvent::NodelayFailed => {
            ACCEPT_NODELAY_ERR.fetch_add(1, Relaxed);
        }
        AcceptSetupEvent::KeepaliveFailed => {
            ACCEPT_KEEPALIVE_ERR.fetch_add(1, Relaxed);
        }
    }
    if let Ok(mut state) = ACCEPT_SETUP_LOG_STATE.try_lock() {
        state.1 = Some(ip);
        let due = match state.0 {
            None => true,
            Some(t) => t.elapsed() >= SECURITY_LOG_INTERVAL,
        };
        if due {
            let nodelay_failed = ACCEPT_NODELAY_ERR.swap(0, Relaxed);
            let keepalive_failed = ACCEPT_KEEPALIVE_ERR.swap(0, Relaxed);
            if nodelay_failed + keepalive_failed > 0 {
                state.0 = Some(std::time::Instant::now());
                log::warn!(
                    "R-T0/R-T10 accepted-socket setup summary (last {:?}): nodelay_failed={} keepalive_failed={} recent_src={:?} last_error={}",
                    SECURITY_LOG_INTERVAL,
                    nodelay_failed,
                    keepalive_failed,
                    state.1,
                    err
                );
            }
        }
    }
}

/// R-T12: map the fd/resource-exhaustion accept() errnos via raw_os_error() so the operator sees the
/// CAUSE, not a bare number — under the R-T1 connection flood the box hits its fd/socket ceiling and
/// accept() returns exactly these while the kernel keeps the socket readable (the busy-spin the
/// escalating back-off damps). EMFILE/ENFILE/ENOBUFS on unix; WSAEMFILE/WSAENOBUFS on Windows.
fn accept_error_class(err: &std::io::Error) -> &'static str {
    match err.raw_os_error() {
        #[cfg(not(windows))]
        Some(n) if n == hbb_common::libc::EMFILE || n == hbb_common::libc::ENFILE => {
            " = process/system fd table exhausted (EMFILE/ENFILE)"
        }
        #[cfg(not(windows))]
        Some(n) if n == hbb_common::libc::ENOBUFS || n == hbb_common::libc::ENOMEM => {
            " = kernel socket buffers/memory exhausted (ENOBUFS/ENOMEM)"
        }
        #[cfg(windows)]
        Some(10024) => " = process socket table exhausted (WSAEMFILE)",
        #[cfg(windows)]
        Some(10055) => " = no buffer space (WSAENOBUFS)",
        _ => " — transient accept error",
    }
}

/// R-T9 (§20): a clone of the process-wide shutdown token. A connection's run-loop holds one and
/// selects on `.cancelled()`, so a graceful shutdown drains it (send CloseReason → flush → CM
/// Close) instead of a mid-write SIGKILL truncating an in-flight transfer on the peer.
pub fn shutdown_token() -> hbb_common::tokio_util::sync::CancellationToken {
    SHUTDOWN_TOKEN.clone()
}

/// R-T9: the cheap synchronous check the accept loop polls — once true it stops accepting and
/// drops its `TcpListener` so new SYNs get an RST.
pub fn is_shutting_down() -> bool {
    SHUTDOWN_TOKEN.is_cancelled()
}

static SHUTDOWN_FINALIZER_STARTED: AtomicBool = AtomicBool::new(false);

pub fn request_graceful_shutdown() {
    if !SHUTDOWN_TOKEN.is_cancelled() {
        log::info!("R-T9: graceful shutdown initiated — stop accepting, drain live sessions");
        SHUTDOWN_TOKEN.cancel();
    }
}

/// R-T9 (§20): perform a graceful shutdown on SIGTERM/SIGINT. (1) stop accepting — the accept
/// loop observes the cancelled token and drops the listener (new SYNs RST); (2) signal every live
/// connection to close gracefully (each run-loop's `cancelled()` arm sends its CloseReason, flushes,
/// and delivers the CM `Close`); (3) wait up to a BOUNDED deadline — deliberately shorter than the
/// unit's `TimeoutStopSec` (30 s) so systemd's SIGKILL stays only a backstop — for the
/// authenticated sessions to finish their cleanup tail (an `AuthedConnID`'s `Drop`, which prunes
/// `AUTHED_CONNS`, runs only AFTER that tail, so the count draining to zero means cleanup actually
/// completed); (4) force-exit 0, terminating any still-live connection past the deadline. Idempotent.
pub async fn begin_graceful_shutdown() {
    request_graceful_shutdown();
    finish_graceful_shutdown().await;
}

pub async fn finish_graceful_shutdown() {
    if SHUTDOWN_FINALIZER_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let deadline = std::time::Duration::from_secs(8);
    let start = std::time::Instant::now();
    loop {
        let live = AUTHED_CONNS.lock().unwrap().len();
        if live == 0 {
            break;
        }
        if start.elapsed() >= deadline {
            log::warn!(
                "R-T9: drain deadline reached with {} session(s) still live — forcing exit",
                live
            );
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    crate::ipc::wait_for_local_ipc_shutdown().await;
    crate::server::input_service::fix_key_down_timeout_at_exit();
    log::info!("R-T9: graceful shutdown complete — exiting 0");
    std::process::exit(0);
}

pub struct Server {
    connections: ConnMap,
    services: HashMap<String, Box<dyn Service>>,
    id_count: i32,
}

pub type ServerPtr = Arc<RwLock<Server>>;
pub type ServerPtrWeak = Weak<RwLock<Server>>;

pub fn new() -> ServerPtr {
    let mut server = Server {
        connections: HashMap::new(),
        services: HashMap::new(),
        id_count: hbb_common::rand::random::<i32>() % 1000 + 1000, // ensure positive
    };
    server.add_service(Box::new(audio_service::new()));
    #[cfg(not(target_os = "ios"))]
    {
        server.add_service(Box::new(display_service::new()));
        server.add_service(Box::new(clipboard_service::new(
            clipboard_service::NAME.to_owned(),
        )));
        #[cfg(feature = "unix-file-copy-paste")]
        server.add_service(Box::new(clipboard_service::new(
            clipboard_service::FILE_NAME.to_owned(),
        )));
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        if !display_service::capture_cursor_embedded() {
            server.add_service(Box::new(input_service::new_cursor()));
            server.add_service(Box::new(input_service::new_pos()));
            #[cfg(target_os = "linux")]
            if scrap::is_x11() {
                // wayland does not support multiple displays currently
                server.add_service(Box::new(input_service::new_window_focus()));
            }
            #[cfg(not(target_os = "linux"))]
            server.add_service(Box::new(input_service::new_window_focus()));
        }
    }
    // Terminal service is created per connection, not globally
    Arc::new(RwLock::new(server))
}

pub async fn create_tcp_connection(
    server: ServerPtr,
    stream: Stream,
    addr: SocketAddr,
    control_permissions: Option<ControlPermissions>,
    // R-T1(b): the pre-key handshake slot, acquired in the accept loop before this task was
    // spawned. Held only across the handshake below; explicitly dropped on the keyed path
    // before Connection::start (and auto-dropped on any earlier fail-closed bail), so the
    // bound caps the attacker-reachable half-open population, not authenticated sessions.
    prekey_permit: tokio::sync::OwnedSemaphorePermit,
) -> ResultType<()> {
    let mut stream = stream;
    // R-P5 / R-P14 / §8: keying is the single mandatory CPace handshake, run
    // UNCONDITIONALLY. The inherited secure-gated SignedId <-> PublicKey
    // device-identity bootstrap — its box_/sign keypair, the IdPk signature, the
    // symmetric-key unwrap (tcp::Encrypt::decode) — is removed: there are no
    // identity keys (R-P5), no alternate keying path to select, and no downgrade
    // (R-P11). With the rendezvous/relay paths neutralized (6920db9) the box only
    // serves direct connections, which always key via CPace below.
    let credential_generation = authenticate_tcp_stream(&mut stream, addr).await?;
    // R-T1(b): keying succeeded — release the pre-key handshake slot now, before the
    // unbounded Connection::start session, so the bound governs only the half-open
    // (attacker-reachable) population. (A fail-closed bail above auto-drops it on return.)
    drop(prekey_permit);
    // Allocate a session id only after CPace succeeds. Failed pre-key attempts are attacker input
    // and must not mutate authenticated-session accounting or drive an unbounded id counter.
    let id = server.write().unwrap().get_new_id();

    #[cfg(target_os = "macos")]
    crate::platform::declare_remote_user_activity();
    // R-A1: no application message is processed on an unkeyed stream, on every build
    // (R-R2b — unconditional, not behind a flag). By here the single mandatory CPace
    // handshake above has run UNCONDITIONALLY (keyed, or bailed fail-closed) — CPace is
    // the only keying — so any residual unkeyed path (the inherited pk-update /
    // invalid-message fall-throughs) MUST terminate rather than reach the message loop.
    // Makes the unkeyed-direct-path bug unreachable by construction.
    if !stream.is_secured() {
        bail!("R-A1: refusing to start a connection on an unkeyed stream");
    }
    Connection::start(
        addr,
        stream,
        id,
        Arc::downgrade(&server),
        control_permissions,
        credential_generation,
    )
    .await;
    Ok(())
}

async fn authenticate_tcp_stream(stream: &mut Stream, addr: SocketAddr) -> ResultType<u64> {
    {
        // R-P14 / R-S1: the single mandatory CPace handshake at the choke point.
        // The direct path gains mandatory keying here — every transport is mutually
        // password-authenticated and keyed before any application message. The PRS is
        // the live permanent password read fresh per connection (R-P1/R-S16); an
        // empty PRS fails closed (R-S9). Note: the matching viewer must run the
        // CPace initiator (client.rs) — fork peers only, no downgrade (R-P11).
        #[cfg(target_os = "windows")]
        if windows_credential_authentication_is_quiesced() {
            bail!("Permanent password transition is in progress");
        }
        let credential = effective_permanent_password_credential_snapshot().await;
        let (prs_status, credential_generation) = credential.into_parts();
        let prs = prs_status.into_prs();
        if prs.is_empty() {
            bail!("Refusing connection: no permanent password set (R-S9)");
        }
        // R-S10 / R-P14c: shed a source that has exceeded the online-guess rate
        // BEFORE the expensive scalar-mult — checked here, before run_responder.
        if !hbb_common::cpace::guess_limiter_allows(addr.ip()) {
            note_security_event(SecurityEvent::RateLimited, addr.ip());
            bail!("R-S10: source rate-limited after too many failed password attempts");
        }
        let handshake = {
            let Some(fs) = stream.as_framed_tcp_mut() else {
                bail!("CPace handshake requires a TCP stream at the choke point");
            };
            hbb_common::cpace::run_responder(fs, &prs).await
        };
        let keys = match handshake {
            Ok(keys) => keys,
            Err(e) => {
                if e.is_password_guess() {
                    // R-P14c: ONLY a key-confirmation tag mismatch is an online
                    // password guess and feeds the per-source limiter (R-S10);
                    // decode / order / AD / identity / timeout aborts MUST NOT, or a
                    // malformed-frame flood would trip the owner's own block.
                    hbb_common::cpace::record_guess_failure(addr.ip());
                    note_security_event(SecurityEvent::KeyConfirmFail, addr.ip());
                }
                bail!("CPace handshake failed: fail-closed");
            }
        };
        #[cfg(target_os = "windows")]
        if windows_credential_authentication_is_quiesced() {
            bail!("Permanent password transition interrupted the handshake");
        }
        // On macOS this refreshes the LaunchAgent's runtime snapshot again. On every platform
        // the generation comparison is made after CPace key confirmation and before the keys
        // become usable by an application stream.
        let confirmed_generation = effective_permanent_password_credential_snapshot()
            .await
            .generation();
        if confirmed_generation != credential_generation {
            bail!("CPace credential changed during handshake");
        }
        let keys_installed =
            Config::with_current_permanent_password_generation(credential_generation, || {
                #[cfg(target_os = "windows")]
                if windows_credential_authentication_is_quiesced() {
                    return false;
                }
                stream.set_session_keys(keys);
                true
            });
        if keys_installed != Some(true) {
            bail!("CPace credential changed before key installation");
        }
        Ok(credential_generation)
    }
}

impl Server {
    fn is_video_service_name(name: &str) -> bool {
        name.starts_with(VideoSource::Monitor.service_name_prefix())
            || name.starts_with(VideoSource::Camera.service_name_prefix())
    }

    pub fn try_add_primary_camera_service(&mut self) {
        if !camera::primary_camera_exists() {
            return;
        }
        let primary_camera_name =
            video_service::get_service_name(VideoSource::Camera, camera::PRIMARY_CAMERA_IDX);
        if !self.contains(&primary_camera_name) {
            self.add_service(Box::new(video_service::new(
                VideoSource::Camera,
                camera::PRIMARY_CAMERA_IDX,
            )));
        }
    }

    pub fn try_add_primay_video_service(&mut self) {
        let primary_video_service_name = video_service::get_service_name(
            VideoSource::Monitor,
            *display_service::PRIMARY_DISPLAY_IDX,
        );
        if !self.contains(&primary_video_service_name) {
            self.add_service(Box::new(video_service::new(
                VideoSource::Monitor,
                *display_service::PRIMARY_DISPLAY_IDX,
            )));
        }
    }

    pub fn add_camera_connection(&mut self, conn: ConnInner) {
        if camera::primary_camera_exists() {
            let primary_camera_name =
                video_service::get_service_name(VideoSource::Camera, camera::PRIMARY_CAMERA_IDX);
            if let Some(s) = self.services.get(&primary_camera_name) {
                s.on_subscribe(conn.clone());
            }
        }
        self.connections.insert(conn.id(), conn);
    }

    pub fn add_connection(&mut self, conn: ConnInner, noperms: &Vec<&'static str>) {
        let primary_video_service_name = video_service::get_service_name(
            VideoSource::Monitor,
            *display_service::PRIMARY_DISPLAY_IDX,
        );
        for s in self.services.values() {
            let name = s.name();
            if Self::is_video_service_name(&name) && name != primary_video_service_name {
                continue;
            }
            if !noperms.contains(&(&name as _)) {
                s.on_subscribe(conn.clone());
            }
        }
        #[cfg(target_os = "macos")]
        self.update_enable_retina();
        self.connections.insert(conn.id(), conn);
    }

    pub fn remove_connection(&mut self, conn: &ConnInner) {
        for s in self.services.values() {
            s.on_unsubscribe(conn.id());
        }
        self.connections.remove(&conn.id());
        #[cfg(target_os = "macos")]
        self.update_enable_retina();
    }

    pub fn close_connections(&mut self) {
        let conn_inners: Vec<_> = self.connections.values_mut().collect();
        for c in conn_inners {
            let mut misc = Misc::new();
            misc.set_stop_service(true);
            let mut msg = Message::new();
            msg.set_misc(misc);
            c.send(Arc::new(msg));
        }
    }

    fn add_service(&mut self, service: Box<dyn Service>) {
        let name = service.name();
        self.services.insert(name, service);
    }

    pub fn contains(&self, name: &str) -> bool {
        self.services.contains_key(name)
    }

    pub fn subscribe(&mut self, name: &str, conn: ConnInner, sub: bool) {
        if let Some(s) = self.services.get(name) {
            if s.is_subed(conn.id()) == sub {
                return;
            }
            if sub {
                s.on_subscribe(conn.clone());
            } else {
                s.on_unsubscribe(conn.id());
            }
            #[cfg(target_os = "macos")]
            self.update_enable_retina();
        }
    }

    // get a new unique id
    pub fn get_new_id(&mut self) -> i32 {
        // Authenticated-session ids must not rely on unchecked i32 overflow. A long-running
        // process can wrap the counter eventually; scan for an unused positive id instead of
        // colliding with a live connection or tripping debug-overflow behavior.
        for _ in 0..i32::MAX {
            self.id_count = if self.id_count == i32::MAX {
                1
            } else {
                self.id_count + 1
            };
            if !self.connections.contains_key(&self.id_count) {
                return self.id_count;
            }
        }
        log::error!(
            "R-T12: all positive connection ids are in use; returning 0 as a fail-visible sentinel"
        );
        0
    }

    pub fn set_video_service_opt(
        &self,
        display: Option<(VideoSource, usize)>,
        opt: &str,
        value: &str,
    ) {
        for (k, v) in self.services.iter() {
            if let Some((source, display)) = display {
                if k != &video_service::get_service_name(source, display) {
                    continue;
                }
            }

            if Self::is_video_service_name(k) {
                v.set_option(opt, value);
            }
        }
    }

    fn get_subbed_displays_count(&self, conn_id: i32) -> usize {
        self.services
            .keys()
            .filter(|k| {
                Self::is_video_service_name(k)
                    && self
                        .services
                        .get(*k)
                        .map(|s| s.is_subed(conn_id))
                        .unwrap_or(false)
            })
            .count()
    }

    fn capture_displays(
        &mut self,
        conn: ConnInner,
        source: VideoSource,
        displays: &[usize],
        include: bool,
        exclude: bool,
    ) {
        let displays = displays
            .iter()
            .map(|d| video_service::get_service_name(source, *d))
            .collect::<Vec<_>>();
        let keys = self.services.keys().cloned().collect::<Vec<_>>();
        for name in keys.iter() {
            if Self::is_video_service_name(&name) {
                if displays.contains(&name) {
                    if include {
                        self.subscribe(&name, conn.clone(), true);
                    }
                } else {
                    if exclude {
                        self.subscribe(&name, conn.clone(), false);
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn update_enable_retina(&self) {
        let mut video_service_count = 0;
        for (name, service) in self.services.iter() {
            if Self::is_video_service_name(&name) && service.ok() {
                video_service_count += 1;
            }
        }
        *scrap::quartz::ENABLE_RETINA.lock().unwrap() = video_service_count < 2;
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        for s in self.services.values() {
            s.join();
        }
        #[cfg(target_os = "linux")]
        wayland::clear();
    }
}

pub fn check_zombie() {
    std::thread::spawn(|| loop {
        let mut lock = CHILD_PROCESS.lock().unwrap();
        let mut i = 0;
        while i != lock.len() {
            let c = &mut (*lock)[i];
            if let Ok(Some(_)) = c.try_wait() {
                lock.remove(i);
            } else {
                i += 1;
            }
        }
        drop(lock);
        std::thread::sleep(Duration::from_millis(100));
    });
}

/// Start the host server that allows the remote peer to control the current machine.
///
/// # Arguments
///
/// * `is_server` - Whether the current client is definitely the server.
/// If true, the server will be started.
/// Otherwise, client will check if there's already a server and start one if not.
#[cfg(any(target_os = "android", target_os = "ios"))]
#[tokio::main]
pub async fn start_server(_is_server: bool, generation: u64) {
    // R-D4 / R-D7: direct-only on every target (the Android JNI service entry too) — no
    // rendezvous mediator. The inherited start_all is bypassed for start_direct_only.
    // R-D7a (N1/F1): `generation` is the service-owned-listener generation the JNI `startServer`
    // established (android_begin_generation's return) and captured before spawning this thread;
    // pass it through so the accept loop runs under exactly it, never a late re-load (the
    // orphaned-listener race). iOS never starts a controlled listener, so this is Android's path.
    crate::direct_service::start_direct_only(Some(generation)).await;
}

/// Start the host server that allows the remote peer to control the current machine.
///
/// # Arguments
///
/// * `is_server` - Whether the current client is definitely the server.
/// If true, the server will be started.
/// Otherwise, client will check if there's already a server and start one if not.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[tokio::main]
pub async fn start_server(is_server: bool) {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        #[cfg(target_os = "linux")]
        {
            log::info!("DISPLAY={:?}", std::env::var("DISPLAY"));
            log::info!("XAUTHORITY={:?}", std::env::var("XAUTHORITY"));
        }
        #[cfg(windows)]
        hbb_common::platform::windows::start_cpu_performance_monitor();
    });

    if is_server {
        crate::common::set_server_running(true);
        #[cfg(target_os = "windows")]
        if crate::common::is_service_owned_server_process() {
            std::thread::spawn(|| {
                if let Err(err) = crate::ipc::start_windows_service_main_ipc() {
                    log::error!("Failed to start Windows service-main IPC: {err}");
                    std::process::exit(1);
                }
            });
        }
        std::thread::spawn(move || {
            if let Err(err) = crate::ipc::start("") {
                log::error!("Failed to start ipc: {}", err);
                if crate::is_server() {
                    log::error!("ipc is occupied by another process");
                }
                std::process::exit(-1);
            }
        });
        #[cfg(target_os = "windows")]
        crate::platform::try_kill_broker();
        // R-D4 / §17: direct-only service entry — no rendezvous mediator (the inherited
        // start_all and its register/STUN/KCP/LAN protocol are bypassed, removal pending).
        // R-D7a (N1/F1): desktop/`--service` has no Android service generation — its listener
        // lifetime is the process/systemd-unit lifetime (R-X9), so pass `None`.
        crate::direct_service::start_direct_only(None).await;
    } else {
        match crate::ipc::get_main_status_snapshot(1000).await {
            Ok(_) => {}
            Err(err) => {
                // R-X10: the GUI/client (`is_server == false`) path NEVER auto-starts a controlled
                // server — the controlled side starts ONLY via the installed `--service` (one mode,
                // the installed-service privilege model). The inherited `else { start_server(true) }`
                // was a SECOND, non-installed-service way to run the controlled side (the portable /
                // quick-support / run-from-terminal twin R-X10 excises). The GUI path now just retries
                // the same-user main IPC connection in case a controlled `--server` comes up later; the
                // `--no-server` flag + its vestigial `no_server` param are removed too (R-X10). The
                // standalone `--service`/`--server` entries (R-D8) are unaffected — `is_server == true`
                // above.
                log::info!(
                    "no controlled --server main IPC to connect to yet (GUI viewer-only, R-X10): {err:?}"
                );
                hbb_common::sleep(1.0).await;
                std::thread::spawn(|| start_server(false));
            }
        }
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
#[tokio::main(flavor = "current_thread")]
pub async fn start_ipc_url_server() {
    log::debug!("Start an ipc server for listening to url schemes");
    match crate::ipc::new_listener("_url").await {
        Ok(mut incoming) => {
            while let Some(Ok(conn)) = incoming.next().await {
                let mut conn = crate::ipc::Connection::new(conn);
                // R-X6/R-S11c-9: this URL listener bypasses the main IPC handler, so sender auth
                // happens before any rustdesk:// URL is delivered to Flutter.
                if !crate::ipc::authorize_url_ipc_sender(&conn) {
                    log::warn!("Rejected an unauthorized sender on the _url IPC channel (R-X6)");
                    continue;
                }
                match conn.next_timeout(1000).await {
                    Ok(Some(data)) => match data {
                        #[cfg(feature = "flutter")]
                        Data::UrlLink(url) => {
                            let mut m = HashMap::new();
                            m.insert("name", "on_url_scheme_received");
                            m.insert("url", url.as_str());
                            let event = serde_json::to_string(&m).unwrap_or("".to_owned());
                            match crate::flutter::push_global_event(
                                crate::flutter::APP_TYPE_MAIN,
                                event,
                            ) {
                                None => log::warn!("No main window app found!"),
                                Some(..) => {}
                            }
                        }
                        _ => {
                            log::warn!("An unexpected data was sent to the ipc url server.")
                        }
                    },
                    Err(err) => {
                        log::error!("{}", err);
                    }
                    _ => {}
                }
            }
        }
        Err(err) => {
            log::error!("{}", err);
        }
    }
}

#[cfg(test)]
mod credential_generation_tests {
    use super::*;
    use hbb_common::{
        cpace::run_initiator,
        sodiumoxide::base64,
        tcp::FramedStream,
        tokio::net::{TcpListener, TcpStream},
    };

    async fn loopback_pair() -> (FramedStream, FramedStream, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let client = client.unwrap();
        let (server, peer) = accepted.unwrap();
        (
            FramedStream::from(client, addr),
            FramedStream::from(server, peer),
            peer,
        )
    }

    fn runtime_storage(raw: [u8; 32]) -> String {
        let hashed = "00".to_owned() + &base64::encode(raw, base64::Variant::Original);
        let encrypted =
            hbb_common::password_security::symmetric_crypt(hashed.as_bytes(), true).unwrap();
        "01".to_owned() + &base64::encode(encrypted, base64::Variant::Original)
    }

    fn assert_quiesce_ack_drains_final_authorization_callback() {
        use std::sync::mpsc;

        Config::set_permanent_password_storage_for_runtime(
            &runtime_storage([0x33u8; 32]),
            "test-salt",
        )
        .unwrap();
        let generation = Config::read_permanent_password_credential_snapshot().generation();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (authorize_tx, authorize_rx) = mpsc::channel();
        let authorized = Arc::new(AtomicBool::new(false));
        let authorized_in_callback = Arc::clone(&authorized);
        let authorization = std::thread::spawn(move || {
            Config::with_current_permanent_password_generation(generation, || {
                entered_tx.send(()).unwrap();
                authorize_rx.recv().unwrap();
                authorized_in_callback.store(true, Ordering::Release);
            })
        });

        entered_rx.recv().unwrap();
        let (quiesced_tx, quiesced_rx) = mpsc::channel();
        let quiesce = std::thread::spawn(move || {
            quiesce_windows_credential_authentication().unwrap();
            quiesced_tx.send(()).unwrap();
        });
        let quiesce_started = std::time::Instant::now();
        while !windows_credential_authentication_is_quiesced() {
            assert!(
                quiesce_started.elapsed() < Duration::from_secs(1),
                "quiesce did not reach its authorization gate"
            );
            std::thread::yield_now();
        }
        assert!(quiesced_rx.recv_timeout(Duration::from_millis(50)).is_err());
        authorize_tx.send(()).unwrap();
        assert!(authorization.join().unwrap().is_some());
        quiesced_rx.recv().unwrap();
        quiesce.join().unwrap();

        assert!(authorized.load(Ordering::Acquire));
        assert!(windows_credential_authentication_is_quiesced());
        assert!(Config::with_current_permanent_password_generation(generation, || ()).is_none());
        resume_windows_credential_authentication();
        Config::set_permanent_password_storage_for_runtime("", "").unwrap();
    }

    #[test]
    fn windows_replica_resume_retains_quiesce_until_restoration_succeeds() {
        use std::cell::Cell;

        let mut replica = WindowsCredentialReplica {
            initialized: true,
            storage: String::new(),
            salt: String::new(),
            tag: [0; 32],
            transition: Some(WindowsCredentialTransition {
                id: "transition".to_owned(),
                previous_storage: "old-storage".to_owned(),
                previous_salt: "old-salt".to_owned(),
                previous_tag: [7; 32],
            }),
        };
        let clears = Cell::new(0);
        let failed = replica.resume_with(
            "transition",
            true,
            |_, _| Err(hbb_common::anyhow::anyhow!("injected restoration failure")),
            || clears.set(clears.get() + 1),
        );
        assert!(failed.is_err());
        assert!(replica.transition.is_some());
        assert_eq!(clears.get(), 0);

        let state = replica
            .resume_with(
                "transition",
                true,
                |storage, salt| {
                    assert_eq!(storage, "old-storage");
                    assert_eq!(salt, "old-salt");
                    Ok(())
                },
                || clears.set(clears.get() + 1),
            )
            .unwrap();
        assert_eq!(state.transition_id, None);
        assert!(!state.quiesced);
        assert_eq!(state.replica_tag, [7; 32]);
        assert!(replica.transition.is_none());
        assert_eq!(clears.get(), 1);

        let replay = replica
            .resume_with(
                "transition",
                false,
                |_, _| panic!("lost-reply replay must not restore twice"),
                || panic!("lost-reply replay must not clear quiesce twice"),
            )
            .unwrap();
        assert_eq!(replay.transition_id, None);
        assert!(!replay.quiesced);
        assert_eq!(replay.replica_tag, [7; 32]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rotation_and_quiesce_races_cannot_cross_final_authorization() {
        let old_prs = base64::encode([0x11u8; 32], base64::Variant::Original);
        Config::set_permanent_password_storage_for_runtime(
            &runtime_storage([0x11u8; 32]),
            "test-salt",
        )
        .unwrap();
        let old_generation = Config::read_permanent_password_credential_snapshot().generation();

        let (mut initiator, mut proxy_from_initiator, _) = loopback_pair().await;
        let (mut proxy_to_responder, responder, responder_addr) = loopback_pair().await;
        let mut responder = Stream::Tcp(responder);

        let initiator_future = run_initiator(&mut initiator, &old_prs);
        let responder_future = authenticate_tcp_stream(&mut responder, responder_addr);
        let proxy_future = async {
            let step1 = proxy_from_initiator.next().await.unwrap().unwrap();
            proxy_to_responder.send_raw(step1.to_vec()).await.unwrap();

            let step2 = proxy_to_responder.next().await.unwrap().unwrap();
            proxy_from_initiator.send_raw(step2.to_vec()).await.unwrap();

            Config::set_permanent_password_storage_for_runtime(
                &runtime_storage([0x22u8; 32]),
                "test-salt",
            )
            .unwrap();

            let step3 = proxy_from_initiator.next().await.unwrap().unwrap();
            proxy_to_responder.send_raw(step3.to_vec()).await.unwrap();
            let step4 = proxy_to_responder.next().await.unwrap().unwrap();
            proxy_from_initiator.send_raw(step4.to_vec()).await.unwrap();
        };

        let (initiator_result, responder_result, ()) =
            tokio::join!(initiator_future, responder_future, proxy_future);
        assert!(
            initiator_result.is_ok(),
            "the old CPace transcript itself completed"
        );
        assert!(
            responder_result.is_err(),
            "the responder must reject the stale generation"
        );
        assert!(
            !responder.is_secured(),
            "stale CPace keys must never be installed"
        );
        assert!(
            Config::with_current_permanent_password_generation(old_generation, || ()).is_none(),
            "the stale generation cannot pass the final authorization linearization"
        );

        Config::set_permanent_password_storage_for_runtime("", "").unwrap();
        assert_quiesce_ack_drains_final_authorization_callback();
    }
}
