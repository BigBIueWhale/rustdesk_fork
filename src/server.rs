use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, RwLock, Weak},
    time::Duration,
};

use bytes::Bytes;

pub use connection::*;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use hbb_common::config::Config2;
use hbb_common::{
    allow_err,
    anyhow::Context,
    bail,
    config::Config,
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

#[cfg(all(target_os = "windows", feature = "flutter"))]
pub mod printer_service;

pub type Childs = Arc<Mutex<Vec<std::process::Child>>>;
type ConnMap = HashMap<i32, ConnInner>;

#[cfg(any(target_os = "macos", target_os = "linux"))]
const CONFIG_SYNC_INTERVAL_SECS: f32 = 0.3;
#[cfg(any(target_os = "macos", target_os = "linux"))]
// 3s is enough for at least one initial sync attempt:
// 0.3s backoff + up to 1s connect timeout + up to 1s response timeout.
const CONFIG_SYNC_INITIAL_WAIT_SECS: u64 = 3;

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

/// R-T9 (§20): perform a graceful shutdown on SIGTERM/SIGINT. (1) stop accepting — the accept
/// loop observes the cancelled token and drops the listener (new SYNs RST); (2) signal every live
/// connection to close gracefully (each run-loop's `cancelled()` arm sends its CloseReason, flushes,
/// and delivers the CM `Close`); (3) wait up to a BOUNDED deadline — deliberately shorter than the
/// unit's `TimeoutStopSec` (30 s) so systemd's SIGKILL stays only a backstop — for the
/// authenticated sessions to finish their cleanup tail (an `AuthedConnID`'s `Drop`, which prunes
/// `AUTHED_CONNS`, runs only AFTER that tail, so the count draining to zero means cleanup actually
/// completed); (4) force-exit 0, terminating any still-live connection past the deadline. Idempotent.
pub async fn begin_graceful_shutdown() {
    if SHUTDOWN_TOKEN.is_cancelled() {
        return;
    }
    log::info!("R-T9: graceful shutdown initiated — stop accepting, drain live sessions");
    SHUTDOWN_TOKEN.cancel();
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
    #[cfg(all(target_os = "windows", feature = "flutter"))]
    {
        match printer_service::init(&crate::get_app_name()) {
            Ok(()) => {
                log::info!("printer service initialized");
                server.add_service(Box::new(printer_service::new(
                    printer_service::NAME.to_owned(),
                )));
            }
            Err(e) => {
                log::error!("printer service init failed: {}", e);
            }
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
    {
        // R-P14 / R-S1: the single mandatory CPace handshake at the choke point.
        // The direct path gains mandatory keying here — every transport is mutually
        // password-authenticated and keyed before any application message. The PRS is
        // the live permanent password read fresh per connection (R-P1/R-S16); an
        // empty PRS fails closed (R-S9). Note: the matching viewer must run the
        // CPace initiator (client.rs) — fork peers only, no downgrade (R-P11).
        let prs = Config::get_permanent_password_prs();
        if prs.is_empty() {
            bail!("Refusing connection: no permanent password set (R-S9)");
        }
        // R-S10 / R-P14c: shed a source that has exceeded the online-guess rate
        // BEFORE the expensive scalar-mult — checked here, before run_responder.
        if !hbb_common::cpace::guess_limiter_allows(addr.ip()) {
            note_security_event(SecurityEvent::RateLimited, addr.ip());
            bail!("R-S10: source rate-limited after too many failed password attempts");
        }
        let Some(fs) = stream.as_framed_tcp_mut() else {
            bail!("CPace handshake requires a TCP stream at the choke point");
        };
        match hbb_common::cpace::run_responder_with_transcript(fs, &prs).await {
            Ok((keys, transcript)) => {
                fs.set_session_keys(keys);
                // R-S17: the controlled box is always the responder, so the
                // HostIdentity host-proof obligation lands on this headless
                // artifact (R-R2b). Emit it as the FIRST frame after keying
                // (encrypted by the session key), before any Message is read or
                // acted on. The viewer verifies the Ed25519 signature over this
                // session's transcript against its pinned key (SSH known_hosts);
                // a substitute that knows the password but not the box's private
                // key cannot forge it. The pk/sk are the box's stable
                // self-generated keypair (.1 public / .0 secret), the same key
                // --get-fingerprint prints.
                let kp = Config::get_key_pair();
                let hi = match hbb_common::cpace::build_host_identity(&transcript, &kp.1, &kp.0) {
                    Ok(hi) => hi,
                    Err(_) => bail!("R-S17: failed to build the HostIdentity host-proof"),
                };
                fs.send_raw(hi).await?;
            }
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
        }
    }
    // R-T1(b): keying succeeded — release the pre-key handshake slot now, before the
    // unbounded Connection::start session, so the bound governs only the half-open
    // (attacker-reachable) population. (A fail-closed bail above auto-drops it on return.)
    drop(prekey_permit);
    // Allocate a session id only after CPace succeeds. Failed pre-key attempts are attacker input
    // and must not mutate authenticated-session accounting or drive an unbounded id counter.
    let id = server.write().unwrap().get_new_id();

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        if let Ok(task) = Command::new("/usr/bin/caffeinate")
            .arg("-u")
            .arg("-t 5")
            .spawn()
        {
            super::CHILD_PROCESS.lock().unwrap().push(task);
        }
        log::info!("wake up macos");
    }
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
    )
    .await;
    Ok(())
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
pub async fn start_server(_is_server: bool) {
    // R-D4 / R-D7: direct-only on every target (the Android JNI service entry too) — no
    // rendezvous mediator. The inherited start_all is bypassed for start_direct_only.
    crate::direct_service::start_direct_only().await;
}

/// Start the host server that allows the remote peer to control the current machine.
///
/// # Arguments
///
/// * `is_server` - Whether the current client is definitely the server.
/// If true, the server will be started.
/// Otherwise, client will check if there's already a server and start one if not.
/// * `no_server` - If `is_server` is false, whether to start a server if not found.
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
        std::thread::spawn(move || {
            if let Err(err) = crate::ipc::start("") {
                log::error!("Failed to start ipc: {}", err);
                if crate::is_server() {
                    log::error!("ipc is occupied by another process, try kill it");
                    std::thread::spawn(stop_main_window_process).join().ok();
                }
                std::process::exit(-1);
            }
        });
        input_service::fix_key_down_timeout_loop();
        // R-X13 (§8): the dead `if wayland_use_uinput() { setup_uinput(..) }` backend-install is
        // removed with the uinput module — XTEST/enigo is the pinned sole injector.
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        wait_initial_config_sync().await;
        #[cfg(target_os = "windows")]
        crate::platform::try_kill_broker();
        #[cfg(feature = "hwcodec")]
        scrap::hwcodec::start_check_process();
        // R-D4 / §17: direct-only service entry — no rendezvous mediator (the inherited
        // start_all and its register/STUN/KCP/LAN protocol are bypassed, removal pending).
        crate::direct_service::start_direct_only().await;
    } else {
        match crate::ipc::connect(1000, "").await {
            Ok(mut conn) => {
                if conn.send(&Data::SyncConfig(None)).await.is_ok() {
                    if let Ok(Some(data)) = conn.next_timeout(1000).await {
                        match data {
                            Data::SyncConfig(Some(configs)) => {
                                let (config, config2) = *configs;
                                if Config::set(config) {
                                    log::info!("config synced");
                                }
                                if Config2::set(config2) {
                                    log::info!("config2 synced");
                                }
                            }
                            _ => {}
                        }
                    }
                }
                #[cfg(feature = "hwcodec")]
                #[cfg(any(target_os = "windows", target_os = "linux"))]
                crate::ipc::client_get_hwcodec_config_thread(0);
            }
            Err(err) => {
                // R-X10: the GUI/client (`is_server == false`) path NEVER auto-starts a controlled
                // server — the controlled side starts ONLY via the installed `--service` (one mode,
                // the installed-service privilege model). The inherited `else { start_server(true) }`
                // was a SECOND, non-installed-service way to run the controlled side (the portable /
                // quick-support / run-from-terminal twin R-X10 excises). The GUI path now just retries
                // the config-sync connect in case a `--service` comes up later; the `--no-server` flag
                // + its vestigial `no_server` param are removed too (R-X10). The standalone
                // `--service`/`--server` entries (R-D8) are unaffected — `is_server == true` above.
                log::info!("no controlled --service to sync config from yet (GUI viewer-only, R-X10): {err:?}");
                hbb_common::sleep(1.0).await;
                std::thread::spawn(|| start_server(false));
            }
        }
    }
}

#[cfg(target_os = "macos")]
#[tokio::main(flavor = "current_thread")]
pub async fn start_ipc_url_server() {
    log::debug!("Start an ipc server for listening to url schemes");
    match crate::ipc::new_listener("_url").await {
        Ok(mut incoming) => {
            while let Some(Ok(conn)) = incoming.next().await {
                let mut conn = crate::ipc::Connection::new(conn);
                // R-X6: authenticate the sender (peer-uid + peer-exe) before honoring any deep-link
                // URL. This `_url` listener bypasses the main handle() service-accept gate, so without
                // this any same-uid process could inject a rustdesk:// connect/relay/key; the only
                // legitimate sender is the rustdesk binary itself (ipc::send_url_scheme).
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

#[cfg(any(target_os = "macos", target_os = "linux"))]
async fn wait_initial_config_sync() {
    if crate::platform::is_root() {
        return;
    }

    // Non-server process should not block startup, but still keeps background sync/watch alive.
    if !crate::is_server() {
        tokio::spawn(async move {
            sync_and_watch_config_dir(None).await;
        });
        return;
    }

    let (sync_done_tx, mut sync_done_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        sync_and_watch_config_dir(Some(sync_done_tx)).await;
    });

    // Server process waits up to N seconds for initial root->local sync to reduce stale-start window.
    tokio::select! {
        _ = &mut sync_done_rx => {
        }
        _ = tokio::time::sleep(Duration::from_secs(CONFIG_SYNC_INITIAL_WAIT_SECS)) => {
            log::warn!(
                "timed out waiting {}s for initial config sync, continue startup and keep syncing in background",
                CONFIG_SYNC_INITIAL_WAIT_SECS
            );
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
async fn sync_and_watch_config_dir(sync_done_tx: Option<tokio::sync::oneshot::Sender<()>>) {
    let mut cfg0 = (Config::get(), Config2::get());
    let mut synced = false;
    let mut is_root_config_empty = false;
    let mut sync_done_tx = sync_done_tx;
    let tries = if crate::is_server() { 30 } else { 3 };
    log::debug!("#tries of ipc service connection: {}", tries);
    use hbb_common::sleep;
    for i in 1..=tries {
        sleep(i as f32 * CONFIG_SYNC_INTERVAL_SECS).await;
        match crate::ipc::connect_service(1000).await {
            Ok(mut conn) => {
                if !synced {
                    if conn.send(&Data::SyncConfig(None)).await.is_ok() {
                        if let Ok(Some(data)) = conn.next_timeout(1000).await {
                            match data {
                                Data::SyncConfig(Some(configs)) => {
                                    let (config, config2) = *configs;
                                    let _chk = crate::ipc::CheckIfRestart::new();
                                    if !config.is_empty() {
                                        if cfg0.0 != config {
                                            cfg0.0 = config.clone();
                                            Config::set(config);
                                            log::info!("sync config from root");
                                        }
                                        if cfg0.1 != config2 {
                                            cfg0.1 = config2.clone();
                                            Config2::set(config2);
                                            log::info!("sync config2 from root");
                                        }
                                    } else {
                                        // only on macos, because this issue was only reproduced on macos
                                        #[cfg(target_os = "macos")]
                                        {
                                            // root config is empty, mark for sync in watch loop
                                            // to prevent root from generating a new config on login screen
                                            is_root_config_empty = true;
                                        }
                                    }
                                    synced = true;
                                    // Notify startup waiter once initial sync phase finishes successfully.
                                    if let Some(tx) = sync_done_tx.take() {
                                        let _ = tx.send(());
                                    }
                                }
                                _ => {}
                            };
                        };
                    }
                    if !synced {
                        log::warn!(
                            "initial config sync from root failed, reconnecting to ipc_service"
                        );
                        continue;
                    }
                }

                loop {
                    sleep(CONFIG_SYNC_INTERVAL_SECS).await;
                    let cfg = (Config::get(), Config2::get());
                    let should_sync = cfg != cfg0 || (is_root_config_empty && !cfg.0.is_empty());
                    if should_sync {
                        if is_root_config_empty {
                            log::info!("root config is empty, sync our config to root");
                        } else {
                            log::info!("config updated, sync to root");
                        }
                        match conn.send(&Data::SyncConfig(Some(cfg.clone().into()))).await {
                            Err(e) => {
                                log::error!("sync config to root failed: {}", e);
                                match crate::ipc::connect_service(1000).await {
                                    Ok(mut _conn) => {
                                        conn = _conn;
                                        log::info!("reconnected to ipc_service");
                                    }
                                    _ => {}
                                }
                            }
                            _ => {
                                cfg0 = cfg;
                                conn.next_timeout(1000).await.ok();
                                is_root_config_empty = false;
                            }
                        }
                    }
                }
            }
            Err(_) => {
                log::info!("#{} try: failed to connect to ipc_service", i);
            }
        }
    }
    // Notify startup waiter even when initial sync is skipped/failed, to avoid unnecessary waiting.
    if let Some(tx) = sync_done_tx.take() {
        let _ = tx.send(());
    }
    log::warn!("skipped config sync");
}

#[tokio::main(flavor = "current_thread")]
pub async fn stop_main_window_process() {
    // this may also kill another --server process,
    // but --server usually can be auto restarted by --service, so it is ok
    if let Ok(mut conn) = crate::ipc::connect(1000, "").await {
        conn.send(&crate::ipc::Data::Close).await.ok();
    }
    #[cfg(windows)]
    {
        // in case above failure, e.g. zombie process
        if let Err(e) = crate::platform::try_kill_rustdesk_main_window_process() {
            log::error!("kill failed: {}", e);
        }
    }
}
