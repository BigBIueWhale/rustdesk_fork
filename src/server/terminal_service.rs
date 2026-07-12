use super::*;
use hbb_common::{
    anyhow::{anyhow, Context, Result},
    compress,
};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize};
use std::{
    collections::{HashMap, VecDeque},
    io::{Read, Write},
    ops::{Deref, DerefMut},
    sync::{
        atomic::{AtomicBool, AtomicI32, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
        Arc, Condvar, Mutex, Weak,
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(not(target_os = "windows"))]
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

// Windows-specific imports from terminal_helper module
#[cfg(target_os = "windows")]
use super::terminal_helper::{
    configure_utf8_shell_command, create_named_pipe_server, encode_helper_message,
    encode_resize_message, launch_terminal_helper_with_token, wait_for_pipe_connection,
    HelperProcessTerminator, HelperProcessTree, OwnedHandle, OwnedPrimaryToken, MSG_TYPE_DATA,
    PIPE_CONNECTION_TIMEOUT_MS,
};

const MAX_OUTPUT_BUFFER_SIZE: usize = 1024 * 1024; // 1MB per terminal
const MAX_BUFFER_LINES: usize = 10000;
const MAX_SERVICES: usize = 100; // Maximum number of persistent terminal services
const MAX_SESSIONS_PER_SERVICE: usize = 64;
const SERVICE_IDLE_TIMEOUT: Duration = Duration::from_secs(3600); // 1 hour idle timeout
const CHANNEL_BUFFER_SIZE: usize = 500; // Channel buffer size. Max per-message size ~4KB (reader buffer), so worst case ~500*4KB ≈ 2MB/terminal. Increased from 100 to reduce data loss during disconnects.
const COMPRESS_THRESHOLD: usize = 512; // Compress terminal data larger than this
                                       // Default max bytes for reconnection buffer replay.
const DEFAULT_RECONNECT_BUFFER_BYTES: usize = 8 * 1024;
const MAX_SIGWINCH_PHASE_ATTEMPTS: u8 = 3; // Max attempts per SIGWINCH phase before giving up
const TERMINAL_ACTION_QUEUE_CAPACITY: usize = 64;
const MAX_OUTPUT_CHUNKS_PER_POLL: usize = 64;
const MAX_OUTPUT_BYTES_PER_POLL: usize = 256 * 1024;
const HELPER_EXIT_STATUS_GRACE: Duration = Duration::from_secs(3);
const DIRECT_EXIT_STATUS_GRACE: Duration = Duration::from_secs(1);
const TERMINAL_TEARDOWN_WORKER_COUNT: usize = 4;
const TERMINAL_TEARDOWN_CAPACITY: usize = MAX_SERVICES * (MAX_SESSIONS_PER_SERVICE + 1);

#[cfg(target_os = "android")]
const UNIX_TERMINAL_SHELLS: [&str; 1] = ["/system/bin/sh"];
#[cfg(target_os = "macos")]
const UNIX_TERMINAL_SHELLS: [&str; 3] = ["/bin/zsh", "/bin/bash", "/bin/sh"];
#[cfg(all(
    not(target_os = "android"),
    not(target_os = "macos"),
    not(target_os = "windows")
))]
const UNIX_TERMINAL_SHELLS: [&str; 6] = [
    "/bin/bash",
    "/usr/bin/bash",
    "/bin/zsh",
    "/usr/bin/zsh",
    "/bin/sh",
    "/usr/bin/sh",
];

/// Two-phase SIGWINCH trigger for TUI app redraw on reconnection.
///
/// Why two phases? A single resize-then-restore done back-to-back is too fast:
/// by the time the TUI app handles the asynchronous SIGWINCH signal and calls
/// `ioctl(TIOCGWINSZ)`, the PTY size has already been restored to the original.
/// ncurses sees no size change and skips the full redraw.
///
/// Splitting across two `read_outputs()` calls (~30ms apart) ensures the app
/// sees a real size change on each SIGWINCH, forcing a complete redraw.
#[derive(Debug, Clone)]
enum SigwinchPhase {
    /// No SIGWINCH needed.
    Idle,
    /// Phase 1: Resize PTY to temp dimensions (rows±1). The app handles SIGWINCH
    /// and redraws at the temporary size.
    TempResize { retries: u8 },
    /// Phase 2: Restore PTY to correct dimensions. The app handles SIGWINCH,
    /// detects the size change, and performs a full redraw at the correct size.
    Restore { retries: u8 },
}

/// Which resize to perform in the two-phase SIGWINCH sequence.
enum SigwinchAction {
    /// Phase 1: resize to temp dimensions (rows±1) to trigger SIGWINCH with a visible size change.
    TempResize,
    /// Phase 2: restore to correct dimensions to trigger SIGWINCH and force full redraw.
    Restore,
}

/// Session state machine for terminal streaming.
#[derive(Debug)]
enum SessionState {
    /// Session is closed, not streaming data to client.
    Closed,
    /// Session is active, streaming data to client.
    /// pending_buffer: historical buffer to send before real-time data (set on reconnection).
    /// sigwinch: two-phase SIGWINCH trigger state for TUI app redraw.
    Active {
        attachment_generation: u64,
        pending_buffer: Option<Vec<u8>>,
        sigwinch: SigwinchPhase,
    },
}

impl SessionState {
    fn active_pending_buffer(&self) -> Option<&Vec<u8>> {
        match self {
            Self::Active { pending_buffer, .. } => pending_buffer.as_ref(),
            Self::Closed => None,
        }
    }
}

lazy_static::lazy_static! {
    // Global registry of persistent terminal services indexed by service_id
    static ref TERMINAL_SERVICES: Arc<Mutex<HashMap<String, Arc<Mutex<PersistentTerminalService>>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Cleanup task handle
    static ref CLEANUP_TASK: Arc<Mutex<Option<std::thread::JoinHandle<()>>>> = Arc::new(Mutex::new(None));

    // List of terminal child processes to check for zombies
    static ref TERMINAL_TASKS: Arc<Mutex<Vec<Box<dyn Child + Send + Sync>>>> = Arc::new(Mutex::new(Vec::new()));

    static ref TERMINAL_TEARDOWN_EXECUTOR: Arc<TerminalTeardownExecutor> =
        Arc::new(TerminalTeardownExecutor::new());

    static ref TERMINAL_TEARDOWN_WORKERS: Mutex<Vec<std::thread::JoinHandle<()>>> =
        Mutex::new(Vec::new());

    static ref TERMINAL_TEARDOWN_PERMIT_POOL: Arc<TerminalTeardownPermitPool> =
        Arc::new(TerminalTeardownPermitPool::new(TERMINAL_TEARDOWN_CAPACITY));
}

#[cfg(target_os = "windows")]
lazy_static::lazy_static! {
    static ref AUTHORITY_EVENT_TASK: Arc<Mutex<Option<std::thread::JoinHandle<()>>>> =
        Arc::new(Mutex::new(None));
}

#[cfg(target_os = "windows")]
#[link(name = "Wtsapi32")]
extern "system" {
    fn WTSWaitSystemEvent(
        server: *mut std::ffi::c_void,
        event_mask: u32,
        event_flags: *mut u32,
    ) -> i32;
}

#[cfg(target_os = "windows")]
const WTS_EVENT_LOGOFF: u32 = 0x0000_0040;

/// Service metadata that is sent to clients
#[derive(Clone, Debug)]
pub struct ServiceMetadata {
    pub service_id: String,
    pub created_at: Instant,
    pub terminal_count: usize,
    pub is_persistent: bool,
}

/// Generate a new persistent service ID
pub fn generate_service_id() -> String {
    format!("ts_{}", uuid::Uuid::new_v4())
}

#[cfg(not(target_os = "windows"))]
fn unix_path_is_clean_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

#[cfg(not(target_os = "windows"))]
fn trusted_unix_shell_file(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
        && metadata.uid() == 0
        && metadata.mode() & 0o022 == 0
        && metadata.mode() & 0o111 != 0
}

#[cfg(not(target_os = "windows"))]
fn trusted_unix_shell_parent(metadata: &fs::Metadata) -> bool {
    metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0
}

#[cfg(not(target_os = "windows"))]
fn trusted_unix_terminal_shell_path(path: &Path) -> Option<PathBuf> {
    if !unix_path_is_clean_absolute(path) {
        return None;
    }
    let candidate_parent = path.parent()?;
    if !trusted_unix_shell_parent(&fs::metadata(candidate_parent).ok()?) {
        return None;
    }
    let canonical = fs::canonicalize(path).ok()?;
    if !unix_path_is_clean_absolute(&canonical) {
        return None;
    }
    let canonical_parent = canonical.parent()?;
    if !trusted_unix_shell_parent(&fs::metadata(canonical_parent).ok()?) {
        return None;
    }
    if !trusted_unix_shell_file(&fs::metadata(&canonical).ok()?) {
        return None;
    }
    Some(canonical)
}

#[cfg(not(target_os = "windows"))]
fn unix_shell_path_string(path: PathBuf) -> Result<String> {
    let display = path.display().to_string();
    path.into_os_string()
        .into_string()
        .map_err(|_| anyhow!("trusted Unix terminal shell path is not valid UTF-8: {display}"))
}

fn get_default_shell() -> Result<String> {
    #[cfg(target_os = "windows")]
    {
        // Use shared implementation from terminal_helper
        super::terminal_helper::get_default_shell()
    }
    #[cfg(not(target_os = "windows"))]
    {
        for candidate in UNIX_TERMINAL_SHELLS {
            let path = Path::new(candidate);
            if let Some(shell) = trusted_unix_terminal_shell_path(path) {
                log::debug!("Found trusted Unix terminal shell: {}", shell.display());
                return unix_shell_path_string(shell);
            }
        }
        Err(anyhow!("no trusted Unix terminal shell found"))
    }
}

#[cfg(target_os = "macos")]
fn locale_value_is_utf8(value: &str) -> bool {
    let value = value.to_ascii_uppercase();
    value.contains("UTF-8") || value.contains("UTF8")
}

#[cfg(target_os = "macos")]
fn should_force_process_utf8_ctype() -> bool {
    if let Ok(value) = std::env::var("LC_ALL") {
        return !locale_value_is_utf8(&value);
    }
    if let Ok(value) = std::env::var("LC_CTYPE") {
        return !locale_value_is_utf8(&value);
    }
    if let Ok(value) = std::env::var("LANG") {
        return !locale_value_is_utf8(&value);
    }
    true
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TerminalPrincipal {
    ProcessOwner,
    WindowsSession {
        session_id: u32,
        user_sid: Vec<u8>,
        authentication_id_low: u32,
        authentication_id_high: i32,
    },
}

#[derive(Clone)]
pub(crate) struct TerminalLaunchAuthority {
    principal: TerminalPrincipal,
    kind: TerminalLaunchAuthorityKind,
}

#[derive(Clone)]
enum TerminalLaunchAuthorityKind {
    ProcessOwner,
    #[cfg(target_os = "windows")]
    WindowsSession {
        token: Arc<OwnedPrimaryToken>,
    },
    #[cfg(test)]
    TestPrincipal {
        valid: Arc<AtomicBool>,
    },
}

#[derive(Debug)]
struct TerminalAuthorityError(&'static str);

impl std::fmt::Display for TerminalAuthorityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for TerminalAuthorityError {}

fn authority_error(message: &'static str) -> hbb_common::anyhow::Error {
    TerminalAuthorityError(message).into()
}

pub(crate) fn is_fatal_authority_error(error: &hbb_common::anyhow::Error) -> bool {
    error.downcast_ref::<TerminalAuthorityError>().is_some()
}

struct TerminalWorkerState {
    fatal_authority: AtomicBool,
    subscriber_id: AtomicI32,
}

impl TerminalWorkerState {
    fn new() -> Self {
        Self {
            fatal_authority: AtomicBool::new(false),
            subscriber_id: AtomicI32::new(-1),
        }
    }

    fn mark_fatal_authority(&self) {
        self.fatal_authority.store(true, Ordering::Release);
    }

    fn ensure_authoritative(&self) -> Result<()> {
        if self.fatal_authority.load(Ordering::Acquire) {
            Err(authority_error(
                "Terminal action worker observed revoked authority",
            ))
        } else {
            Ok(())
        }
    }

    fn subscriber_id(&self) -> Option<i32> {
        let id = self.subscriber_id.load(Ordering::Acquire);
        (id >= 0).then_some(id)
    }
}

fn try_enqueue_terminal_action(
    sender: &SyncSender<TerminalAction>,
    worker_state: &TerminalWorkerState,
    action: TerminalAction,
) -> Result<()> {
    worker_state.ensure_authoritative()?;
    match sender.try_send(action) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_)) => Err(anyhow!("Terminal action queue is full")),
        Err(TrySendError::Disconnected(_)) => {
            worker_state.mark_fatal_authority();
            Err(authority_error("Terminal action worker stopped"))
        }
    }
}

impl TerminalLaunchAuthority {
    fn principal(&self) -> TerminalPrincipal {
        self.principal.clone()
    }
}

pub(crate) fn process_owner_launch_authority() -> TerminalLaunchAuthority {
    TerminalLaunchAuthority {
        principal: TerminalPrincipal::ProcessOwner,
        kind: TerminalLaunchAuthorityKind::ProcessOwner,
    }
}

fn canonical_service_id(service_id: &str) -> bool {
    let Some(value) = service_id.strip_prefix("ts_") else {
        return false;
    };
    uuid::Uuid::parse_str(value)
        .map(|uuid| uuid.to_string() == value)
        .unwrap_or(false)
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_session_launch_authority(
    expected_session_id: u32,
    raw_token: usize,
) -> Result<TerminalLaunchAuthority> {
    let token = Arc::new(OwnedPrimaryToken::from_raw(raw_token)?);
    let identity = token.identity();
    if identity.session_id != expected_session_id {
        return Err(anyhow!("Windows terminal token session mismatch"));
    }
    Ok(TerminalLaunchAuthority {
        principal: TerminalPrincipal::WindowsSession {
            session_id: identity.session_id,
            user_sid: identity.user_sid.clone(),
            authentication_id_low: identity.authentication_id_low,
            authentication_id_high: identity.authentication_id_high,
        },
        kind: TerminalLaunchAuthorityKind::WindowsSession { token },
    })
}

fn reserve_service_attachment(
    service_id: String,
    launch_authority: TerminalLaunchAuthority,
) -> Result<ServiceReservation> {
    if !canonical_service_id(&service_id) {
        return Err(anyhow!("Invalid terminal service ID"));
    }
    ensure_cleanup_task()?;
    let mut services = TERMINAL_SERVICES.lock().unwrap();
    let principal = launch_authority.principal();

    let reservation = if let Some(service) = services.get(&service_id) {
        let service = service.clone();
        let (generation, authority_epoch) = {
            let mut service_state = service.lock().unwrap();
            if service_state.principal != principal {
                return Err(anyhow!("Terminal service principal mismatch"));
            }
            if service_state.launch_authority.is_none() {
                return Err(authority_error(
                    "Terminal service launch authority was revoked",
                ));
            }
            if service_state.attached {
                return Err(anyhow!("Terminal service is already attached"));
            }
            service_state.attachment_generation = service_state
                .attachment_generation
                .checked_add(1)
                .ok_or_else(|| anyhow!("Terminal attachment generation exhausted"))?;
            service_state.attached = true;
            service_state.attachment_worker_state = None;
            (
                service_state.attachment_generation,
                service_state.authority_epoch,
            )
        };
        ServiceReservation {
            service,
            attachment_generation: generation,
            authority_epoch,
            created_entry: false,
        }
    } else {
        if services.len() >= MAX_SERVICES {
            return Err(anyhow!(
                "Maximum number of terminal services ({}) reached",
                MAX_SERVICES
            ));
        }
        let service = Arc::new(Mutex::new(PersistentTerminalService::new(
            service_id.clone(),
            principal,
            launch_authority,
        )));
        services.insert(service_id.clone(), service.clone());
        log::info!("Creating new terminal service reservation: {}", service_id);
        ServiceReservation {
            service,
            attachment_generation: 1,
            authority_epoch: 1,
            created_entry: true,
        }
    };
    Ok(reservation)
}

struct ServiceReservation {
    service: Arc<Mutex<PersistentTerminalService>>,
    attachment_generation: u64,
    authority_epoch: u64,
    created_entry: bool,
}

#[cfg(test)]
fn test_principal(session_id: u32, sid: &[u8], authentication_id_low: u32) -> TerminalPrincipal {
    TerminalPrincipal::WindowsSession {
        session_id,
        user_sid: sid.to_vec(),
        authentication_id_low,
        authentication_id_high: 0,
    }
}

#[cfg(test)]
fn test_launch_authority(principal: TerminalPrincipal) -> TerminalLaunchAuthority {
    TerminalLaunchAuthority {
        principal,
        kind: TerminalLaunchAuthorityKind::TestPrincipal {
            valid: Arc::new(AtomicBool::new(true)),
        },
    }
}

#[cfg(test)]
fn controlled_test_launch_authority(
    principal: TerminalPrincipal,
) -> (TerminalLaunchAuthority, Arc<AtomicBool>) {
    let valid = Arc::new(AtomicBool::new(true));
    (
        TerminalLaunchAuthority {
            principal,
            kind: TerminalLaunchAuthorityKind::TestPrincipal {
                valid: valid.clone(),
            },
        },
        valid,
    )
}

fn validate_launch_authority_value(authority: &TerminalLaunchAuthority) -> Result<()> {
    match &authority.kind {
        TerminalLaunchAuthorityKind::ProcessOwner => {
            #[cfg(target_os = "windows")]
            if crate::common::is_service_owned_server_process() || crate::platform::is_root() {
                return Err(authority_error(
                    "Refusing a direct terminal in a service-owned or LocalSystem process",
                ));
            }
            Ok(())
        }
        #[cfg(target_os = "windows")]
        TerminalLaunchAuthorityKind::WindowsSession { token } => {
            token.validate_unchanged().map_err(|err| {
                log::warn!("Windows terminal token changed: {}", err);
                authority_error("Windows terminal token changed")
            })?;
            let session_id = match &authority.principal {
                TerminalPrincipal::WindowsSession { session_id, .. } => *session_id,
                TerminalPrincipal::ProcessOwner => {
                    return Err(authority_error(
                        "Windows terminal launch authority has an invalid principal",
                    ));
                }
            };
            let current_token = crate::platform::get_user_token(session_id, true);
            if current_token.is_null() {
                return Err(authority_error(
                    "Windows terminal logon session is no longer active",
                ));
            }
            let current = windows_session_launch_authority(session_id, current_token as usize)
                .map_err(|err| {
                    log::warn!("Windows terminal logon validation failed: {}", err);
                    authority_error("Windows terminal logon validation failed")
                })?;
            if current.principal() != authority.principal {
                return Err(authority_error("Windows terminal logon principal changed"));
            }
            Ok(())
        }
        #[cfg(test)]
        TerminalLaunchAuthorityKind::TestPrincipal { valid } => {
            if valid.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(authority_error(
                    "Test terminal launch authority was revoked",
                ))
            }
        }
    }
}

struct TerminalTeardownPermitPool {
    available: Mutex<usize>,
    capacity: usize,
}

impl TerminalTeardownPermitPool {
    fn new(capacity: usize) -> Self {
        Self {
            available: Mutex::new(capacity),
            capacity,
        }
    }

    fn acquire(self: &Arc<Self>) -> Result<Arc<TerminalTeardownPermit>> {
        let mut available = self.available.lock().unwrap();
        if *available == 0 {
            return Err(anyhow!("Terminal teardown capacity is exhausted"));
        }
        *available -= 1;
        Ok(Arc::new(TerminalTeardownPermit { pool: self.clone() }))
    }
}

struct TerminalTeardownPermit {
    pool: Arc<TerminalTeardownPermitPool>,
}

impl Drop for TerminalTeardownPermit {
    fn drop(&mut self) {
        let mut available = self.pool.available.lock().unwrap();
        let Some(released) = (*available).checked_add(1) else {
            log::error!("Terminal teardown permit count overflow");
            std::process::abort();
        };
        if released > self.pool.capacity {
            log::error!("Terminal teardown permit capacity invariant failed");
            std::process::abort();
        }
        *available = released;
    }
}

fn acquire_teardown_permit() -> Result<Arc<TerminalTeardownPermit>> {
    TERMINAL_TEARDOWN_PERMIT_POOL.acquire()
}

enum TerminalTeardownTask {
    Session(SharedTerminalSession),
    Lease {
        service: GenericService,
        action_worker: thread::JoinHandle<()>,
        _permit: Arc<TerminalTeardownPermit>,
    },
}

impl TerminalTeardownTask {
    fn signal_shutdown(&self) {
        if let Self::Session(session) = self {
            session.signal_shutdown();
        }
    }

    fn run(self) {
        match self {
            Self::Session(session) => session.stop_for_teardown(),
            Self::Lease {
                service,
                action_worker,
                _permit,
            } => {
                if action_worker.join().is_err() {
                    log::error!("Terminal action worker panicked during teardown");
                }
                service.join();
            }
        }
    }
}

struct TerminalTeardownExecutor {
    pending: Mutex<VecDeque<TerminalTeardownTask>>,
    ready: Condvar,
}

impl TerminalTeardownExecutor {
    fn new() -> Self {
        Self {
            pending: Mutex::new(VecDeque::new()),
            ready: Condvar::new(),
        }
    }

    fn enqueue(&self, task: TerminalTeardownTask) {
        task.signal_shutdown();
        let mut pending = self.pending.lock().unwrap();
        if pending.len() >= TERMINAL_TEARDOWN_CAPACITY {
            log::error!("Terminal teardown queue capacity invariant failed");
            std::process::abort();
        }
        pending.push_back(task);
        self.ready.notify_one();
    }

    fn run(self: Arc<Self>) {
        loop {
            let task = {
                let mut pending = self.pending.lock().unwrap();
                while pending.is_empty() {
                    pending = self.ready.wait(pending).unwrap();
                }
                let Some(task) = pending.pop_front() else {
                    log::error!("Terminal teardown queue readiness invariant failed");
                    std::process::abort();
                };
                task
            };
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| task.run())).is_err() {
                log::error!("Terminal teardown task panicked");
            }
        }
    }
}

fn ensure_teardown_workers() -> Result<()> {
    let mut workers = TERMINAL_TEARDOWN_WORKERS.lock().unwrap();
    if workers.iter().any(|worker| worker.is_finished()) {
        return Err(anyhow!("Terminal teardown worker stopped unexpectedly"));
    }
    while workers.len() < TERMINAL_TEARDOWN_WORKER_COUNT {
        let executor = TERMINAL_TEARDOWN_EXECUTOR.clone();
        let worker_index = workers.len();
        let worker = thread::Builder::new()
            .name(format!("terminal-teardown-{worker_index}"))
            .spawn(move || executor.run())
            .map_err(|err| anyhow!("Failed to start terminal teardown worker: {err}"))?;
        workers.push(worker);
    }
    Ok(())
}

fn enqueue_teardown_task(task: TerminalTeardownTask) {
    TERMINAL_TEARDOWN_EXECUTOR.enqueue(task);
}

fn enqueue_session_teardown(session: SharedTerminalSession) {
    enqueue_teardown_task(TerminalTeardownTask::Session(session));
}

fn enqueue_sessions_for_teardown(sessions: Vec<SharedTerminalSession>) {
    for session in sessions {
        enqueue_session_teardown(session);
    }
}

fn take_registry_entry_exact(
    service_id: &str,
    service: &Arc<Mutex<PersistentTerminalService>>,
) -> Option<Arc<Mutex<PersistentTerminalService>>> {
    let mut services = TERMINAL_SERVICES.lock().unwrap();
    let current = services.get(service_id)?;
    if Arc::ptr_eq(current, service) {
        services.remove(service_id)
    } else {
        None
    }
}

fn revoke_service_authority(
    service: &Arc<Mutex<PersistentTerminalService>>,
    expected_epoch: u64,
) -> bool {
    let (service_id, authority, sessions) = {
        let mut state = service.lock().unwrap();
        if state.authority_epoch != expected_epoch || state.launch_authority.is_none() {
            return false;
        }
        state.authority_epoch = state.authority_epoch.checked_add(1).unwrap_or(u64::MAX);
        let authority = state.launch_authority.take();
        if let Some(worker_state) = state
            .attachment_worker_state
            .take()
            .and_then(|state| state.upgrade())
        {
            worker_state.mark_fatal_authority();
        }
        for opening in state.opening_sessions.values() {
            opening.cancel();
        }
        state.opening_sessions.clear();
        let sessions = state.sessions.drain().map(|(_, session)| session).collect();
        (state.service_id.clone(), authority, sessions)
    };
    take_registry_entry_exact(&service_id, service);
    drop(authority);
    enqueue_sessions_for_teardown(sessions);
    true
}

fn monitor_service_authority_once(service: &Arc<Mutex<PersistentTerminalService>>) -> bool {
    let (authority, epoch) = {
        let state = service.lock().unwrap();
        let Some(authority) = state.launch_authority.clone() else {
            return false;
        };
        (authority, state.authority_epoch)
    };
    if validate_launch_authority_value(&authority).is_ok() {
        false
    } else {
        revoke_service_authority(service, epoch)
    }
}

#[cfg(target_os = "windows")]
fn monitor_all_service_authorities() {
    let services = TERMINAL_SERVICES
        .lock()
        .unwrap()
        .values()
        .cloned()
        .collect::<Vec<_>>();
    for service in services {
        monitor_service_authority_once(&service);
    }
}

fn stop_service(service_id: &str, service: Arc<Mutex<PersistentTerminalService>>) {
    log::info!("Removed terminal service: {}", service_id);
    let (authority, sessions) = {
        let mut state = service.lock().unwrap();
        for opening in state.opening_sessions.values() {
            opening.cancel();
        }
        state.opening_sessions.clear();
        let authority = state.launch_authority.take();
        if let Some(worker_state) = state
            .attachment_worker_state
            .take()
            .and_then(|state| state.upgrade())
        {
            worker_state.mark_fatal_authority();
        }
        let sessions = state.sessions.drain().map(|(_, session)| session).collect();
        (authority, sessions)
    };
    drop(authority);
    enqueue_sessions_for_teardown(sessions);
}

fn release_service_attachment(
    service_id: &str,
    service: &Arc<Mutex<PersistentTerminalService>>,
    attachment_generation: u64,
    created_entry: bool,
    activated: bool,
) -> Result<()> {
    let should_remove = {
        let mut state = service.lock().unwrap();
        if !state.attached || state.attachment_generation != attachment_generation {
            return Err(anyhow!("Terminal service attachment generation mismatch"));
        }
        for opening in state.opening_sessions.values() {
            if opening.attachment_generation == attachment_generation {
                opening.cancel();
            }
        }
        state
            .opening_sessions
            .retain(|_, opening| opening.attachment_generation != attachment_generation);
        state.attached = false;
        if let Some(worker_state) = state
            .attachment_worker_state
            .take()
            .and_then(|state| state.upgrade())
        {
            worker_state.mark_fatal_authority();
        }
        state.update_activity();
        if state.launch_authority.is_none() {
            true
        } else if activated {
            !state.is_persistent
        } else {
            created_entry
        }
    };
    if should_remove {
        if let Some(removed) = take_registry_entry_exact(service_id, service) {
            stop_service(service_id, removed);
        }
    }
    Ok(())
}

/// List all active terminal services
pub fn list_services() -> Vec<ServiceMetadata> {
    let services = TERMINAL_SERVICES.lock().unwrap();
    services
        .iter()
        .filter_map(|(id, service)| {
            service.lock().ok().map(|svc| ServiceMetadata {
                service_id: id.clone(),
                created_at: svc.created_at,
                terminal_count: svc.sessions.len(),
                is_persistent: svc.is_persistent,
            })
        })
        .collect()
}

/// Clean up inactive services
pub fn cleanup_inactive_services() {
    let services = TERMINAL_SERVICES.lock().unwrap();
    let now = Instant::now();
    let mut to_remove = Vec::new();

    for (service_id, service) in services.iter() {
        if let Ok(svc) = service.lock() {
            if !svc.attached
                && ((!svc.is_persistent
                    && now.duration_since(svc.last_activity) > SERVICE_IDLE_TIMEOUT)
                    || (svc.is_persistent
                        && svc.sessions.is_empty()
                        && now.duration_since(svc.last_activity) > SERVICE_IDLE_TIMEOUT * 2))
            {
                to_remove.push((service_id.clone(), service.clone()));
            }
        }
    }

    drop(services);
    for (service_id, expected) in to_remove {
        let removed = {
            let mut services = TERMINAL_SERVICES.lock().unwrap();
            let Some(current) = services.get(&service_id) else {
                continue;
            };
            if !Arc::ptr_eq(current, &expected) {
                continue;
            }
            let removable = {
                let state = current.lock().unwrap();
                !state.attached
                    && ((!state.is_persistent
                        && now.duration_since(state.last_activity) > SERVICE_IDLE_TIMEOUT)
                        || (state.is_persistent
                            && state.sessions.is_empty()
                            && now.duration_since(state.last_activity) > SERVICE_IDLE_TIMEOUT * 2))
            };
            if removable {
                services.remove(&service_id)
            } else {
                None
            }
        };
        if let Some(removed) = removed {
            stop_service(&service_id, removed);
        }
    }
}

/// Add a child process to the zombie reaper
fn add_to_reaper(child: Box<dyn Child + Send + Sync>) {
    if let Ok(mut tasks) = TERMINAL_TASKS.lock() {
        tasks.push(child);
    }
}

/// Check and reap zombie terminal processes
fn check_zombie_terminals() {
    let mut tasks = match TERMINAL_TASKS.lock() {
        Ok(t) => t,
        Err(_) => return,
    };

    let mut i = 0;
    while i < tasks.len() {
        match tasks[i].try_wait() {
            Ok(Some(_)) => {
                // Process has exited, remove it
                log::info!("Process exited: {:?}", tasks[i].process_id());
                tasks.remove(i);
            }
            Ok(None) => {
                // Still running
                i += 1;
            }
            Err(err) => {
                // Error checking status, remove it
                log::info!(
                    "Process exited with error: {:?}, err: {err}",
                    tasks[i].process_id()
                );
                tasks.remove(i);
            }
        }
    }
}

fn remove_session_if_current(
    service: &Arc<Mutex<PersistentTerminalService>>,
    terminal_id: i32,
    expected: &SharedTerminalSession,
) -> Option<SharedTerminalSession> {
    let mut state = service.lock().unwrap();
    let current = state.sessions.get(&terminal_id)?;
    if Arc::ptr_eq(current, expected) {
        state.sessions.remove(&terminal_id)
    } else {
        None
    }
}

fn monitor_detached_sessions_once() {
    let services = TERMINAL_SERVICES
        .lock()
        .unwrap()
        .values()
        .cloned()
        .collect::<Vec<_>>();
    for service in services {
        let sessions = {
            let state = service.lock().unwrap();
            if state.attached {
                continue;
            }
            state
                .sessions
                .iter()
                .map(|(id, session)| (*id, session.clone()))
                .collect::<Vec<_>>()
        };
        for (terminal_id, session) in sessions {
            let removed = {
                let Ok(mut session_state) = session.try_lock() else {
                    continue;
                };
                if !session_state.has_exited() {
                    continue;
                }
                let removed = remove_session_if_current(&service, terminal_id, &session);
                drop(session_state);
                removed
            };
            if let Some(removed) = removed {
                enqueue_session_teardown(removed);
            }
        }
    }
}

/// Ensure the cleanup task is running
fn ensure_cleanup_task() -> Result<()> {
    ensure_teardown_workers()?;
    let mut task_handle = CLEANUP_TASK.lock().unwrap();
    if task_handle
        .as_ref()
        .map(|handle| handle.is_finished())
        .unwrap_or(false)
    {
        if let Some(handle) = task_handle.take() {
            handle
                .join()
                .map_err(|_| anyhow!("Terminal cleanup task panicked"))?;
        }
    }
    if task_handle.is_none() {
        let handle = thread::Builder::new()
            .name("terminal-cleanup".to_owned())
            .spawn(|| {
                log::info!("Started cleanup task");
                let mut last_service_cleanup = Instant::now();
                #[cfg(target_os = "windows")]
                let mut last_authority_check = Instant::now() - Duration::from_secs(2);
                loop {
                    check_zombie_terminals();
                    monitor_detached_sessions_once();

                    if last_service_cleanup.elapsed() > Duration::from_secs(300) {
                        cleanup_inactive_services();
                        last_service_cleanup = Instant::now();
                    }

                    #[cfg(target_os = "windows")]
                    if last_authority_check.elapsed() >= Duration::from_secs(1) {
                        monitor_all_service_authorities();
                        last_authority_check = Instant::now();
                    }

                    thread::sleep(Duration::from_millis(100));
                }
            })
            .map_err(|err| anyhow!("Failed to start terminal cleanup task: {err}"))?;
        *task_handle = Some(handle);
    }
    drop(task_handle);

    #[cfg(target_os = "windows")]
    {
        let mut event_task = AUTHORITY_EVENT_TASK.lock().unwrap();
        if event_task
            .as_ref()
            .map(|handle| handle.is_finished())
            .unwrap_or(false)
        {
            if let Some(handle) = event_task.take() {
                handle
                    .join()
                    .map_err(|_| anyhow!("Terminal authority event task panicked"))?;
            }
        }
        if event_task.is_none() {
            *event_task = Some(
                thread::Builder::new()
                    .name("terminal-authority-events".to_owned())
                    .spawn(|| loop {
                        let mut event_flags = 0u32;
                        let succeeded = unsafe {
                            WTSWaitSystemEvent(
                                std::ptr::null_mut(),
                                WTS_EVENT_LOGOFF,
                                &mut event_flags,
                            )
                        } != 0;
                        if succeeded && event_flags & WTS_EVENT_LOGOFF != 0 {
                            monitor_all_service_authorities();
                        } else if !succeeded {
                            thread::sleep(Duration::from_secs(1));
                        }
                    })
                    .map_err(|err| {
                        anyhow!("Failed to start terminal authority event task: {err}")
                    })?,
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn get_terminal_session_count(include_zombie_tasks: bool) -> usize {
    let mut c = TERMINAL_SERVICES.lock().unwrap().len();
    if include_zombie_tasks {
        c += TERMINAL_TASKS.lock().unwrap().len();
    }
    c
}

#[derive(Clone)]
pub struct TerminalService {
    sp: GenericService,
    service: Arc<Mutex<PersistentTerminalService>>,
    attachment_generation: u64,
    authority_epoch: u64,
    worker_state: Arc<TerminalWorkerState>,
}

impl Deref for TerminalService {
    type Target = ServiceTmpl<ConnInner>;

    fn deref(&self) -> &Self::Target {
        &self.sp
    }
}

impl DerefMut for TerminalService {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.sp
    }
}

pub fn get_service_name(source: VideoSource, idx: usize) -> String {
    format!("{}{}", source.service_name_prefix(), idx)
}

pub(crate) struct TerminalServiceLease {
    service_id: String,
    service: Arc<Mutex<PersistentTerminalService>>,
    attachment_generation: u64,
    authority_epoch: u64,
    created_entry: bool,
    requested_persistent: AtomicBool,
    activation_checkpoint: Mutex<Option<TerminalActivationCheckpoint>>,
    sp: GenericService,
    worker_state: Arc<TerminalWorkerState>,
    action_tx: Option<SyncSender<TerminalAction>>,
    action_worker: Option<thread::JoinHandle<()>>,
    teardown_permit: Option<Arc<TerminalTeardownPermit>>,
    activated: bool,
}

struct TerminalActivationCheckpoint {
    attachment_generation: u64,
    authority_epoch: u64,
}

impl TerminalServiceLease {
    pub(crate) fn service_id(&self) -> &str {
        &self.service_id
    }

    pub(crate) fn validate_for_activation(&self) -> Result<()> {
        self.validate_current_authority()?;
        *self.activation_checkpoint.lock().unwrap() = Some(TerminalActivationCheckpoint {
            attachment_generation: self.attachment_generation,
            authority_epoch: self.authority_epoch,
        });
        Ok(())
    }

    pub(crate) fn ensure_attached_authority(&self) -> Result<()> {
        self.worker_state.ensure_authoritative()?;
        self.validate_attachment().map(|_| ())
    }

    pub(crate) fn activate(&mut self, subscriber: ConnInner) -> Result<()> {
        if self.activated {
            return Err(anyhow!("Terminal service lease is already active"));
        }
        let checkpoint = self
            .activation_checkpoint
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| authority_error("Terminal activation was not validated"))?;
        if checkpoint.attachment_generation != self.attachment_generation
            || checkpoint.authority_epoch != self.authority_epoch
        {
            return Err(authority_error("Terminal activation checkpoint is stale"));
        }
        let mut state = self.service.lock().unwrap();
        state.validate_attachment(checkpoint.attachment_generation, checkpoint.authority_epoch)?;
        self.worker_state.ensure_authoritative()?;
        state.commit_attachment(self.requested_persistent.load(Ordering::SeqCst));
        self.worker_state
            .subscriber_id
            .store(subscriber.id(), Ordering::Release);
        self.sp.on_subscribe(subscriber);
        drop(state);
        self.activated = true;
        Ok(())
    }

    pub(crate) fn set_persistent(&self, is_persistent: bool) -> Result<()> {
        self.worker_state.ensure_authoritative()?;
        self.validate_attachment()?;
        self.requested_persistent
            .store(is_persistent, Ordering::SeqCst);
        if self.activated {
            let mut state = self.service.lock().unwrap();
            state.validate_attachment(self.attachment_generation, self.authority_epoch)?;
            state.is_persistent = is_persistent;
        }
        Ok(())
    }

    pub(crate) fn enqueue_action(&self, action: TerminalAction) -> Result<()> {
        if !self.activated {
            return Err(authority_error("Terminal service lease is not active"));
        }
        self.worker_state.ensure_authoritative()?;
        let sender = self
            .action_tx
            .as_ref()
            .ok_or_else(|| authority_error("Terminal action worker is unavailable"))?;
        try_enqueue_terminal_action(sender, &self.worker_state, action)
    }

    fn validate_attachment(&self) -> Result<Arc<Mutex<PersistentTerminalService>>> {
        let service = self.service.clone();
        {
            let state = service.lock().unwrap();
            state.validate_attachment(self.attachment_generation, self.authority_epoch)?;
        }
        Ok(service)
    }

    fn validate_current_authority(&self) -> Result<()> {
        let service = self.validate_attachment()?;
        let authority = service
            .lock()
            .unwrap()
            .launch_authority
            .clone()
            .ok_or_else(|| authority_error("Terminal service launch authority was revoked"))?;
        validate_launch_authority_value(&authority)?;
        let result = service
            .lock()
            .unwrap()
            .validate_attachment(self.attachment_generation, self.authority_epoch);
        result
    }
}

impl Drop for TerminalServiceLease {
    fn drop(&mut self) {
        if let Err(err) = release_service_attachment(
            &self.service_id,
            &self.service,
            self.attachment_generation,
            self.created_entry,
            self.activated,
        ) {
            log::error!("Failed to release terminal service attachment: {}", err);
        }
        {
            let _state = self.service.lock().unwrap();
            if let Some(subscriber_id) = self.worker_state.subscriber_id() {
                self.worker_state.subscriber_id.store(-1, Ordering::Release);
                self.sp.on_unsubscribe(subscriber_id);
            }
        }
        drop(self.action_tx.take());
        match (self.action_worker.take(), self.teardown_permit.take()) {
            (Some(action_worker), Some(permit)) => {
                enqueue_teardown_task(TerminalTeardownTask::Lease {
                    service: self.sp.clone(),
                    action_worker,
                    _permit: permit,
                });
            }
            _ => {
                log::error!("Terminal lease lost teardown ownership");
                std::process::abort();
            }
        }
    }
}

pub(crate) fn prepare(
    service_id: String,
    is_persistent: bool,
    launch_authority: TerminalLaunchAuthority,
) -> Result<TerminalServiceLease> {
    let reservation = reserve_service_attachment(service_id.clone(), launch_authority)?;
    let teardown_permit = match acquire_teardown_permit() {
        Ok(permit) => permit,
        Err(err) => {
            release_service_attachment(
                &service_id,
                &reservation.service,
                reservation.attachment_generation,
                reservation.created_entry,
                false,
            )?;
            return Err(err);
        }
    };
    let worker_state = Arc::new(TerminalWorkerState::new());
    {
        let mut state = reservation.service.lock().unwrap();
        state.validate_attachment(
            reservation.attachment_generation,
            reservation.authority_epoch,
        )?;
        state.attachment_worker_state = Some(Arc::downgrade(&worker_state));
    }
    let svc = TerminalService {
        sp: GenericService::new(service_id.clone(), false),
        service: reservation.service.clone(),
        attachment_generation: reservation.attachment_generation,
        authority_epoch: reservation.authority_epoch,
        worker_state: worker_state.clone(),
    };
    let proxy = TerminalServiceProxy {
        service: reservation.service.clone(),
        attachment_generation: reservation.attachment_generation,
        authority_epoch: reservation.authority_epoch,
    };
    let (action_tx, action_rx) = mpsc::sync_channel(TERMINAL_ACTION_QUEUE_CAPACITY);
    let action_service = svc.sp.clone();
    let action_worker_state = worker_state.clone();
    let action_worker_latch = worker_state.clone();
    let action_worker = match thread::Builder::new()
        .name(format!("terminal-actions-{}", service_id))
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_action_worker(proxy, action_service, action_worker_state, action_rx)
            }));
            action_worker_latch.mark_fatal_authority();
            if result.is_err() {
                log::error!("Terminal action worker panicked");
            }
        }) {
        Ok(worker) => worker,
        Err(err) => {
            release_service_attachment(
                &service_id,
                &reservation.service,
                reservation.attachment_generation,
                reservation.created_entry,
                false,
            )?;
            return Err(anyhow!("Failed to start terminal action worker: {}", err));
        }
    };
    let output_worker_state = worker_state.clone();
    let output_start = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        GenericService::run(&svc.clone(), move |service| match std::panic::catch_unwind(
            std::panic::AssertUnwindSafe(|| run(service)),
        ) {
            Ok(result) => result,
            Err(_) => {
                output_worker_state.mark_fatal_authority();
                Err(anyhow!("Terminal output worker panicked"))
            }
        });
    }));
    if output_start.is_err() {
        drop(action_tx);
        if action_worker.join().is_err() {
            log::error!("Terminal action worker panicked during startup rollback");
        }
        release_service_attachment(
            &service_id,
            &reservation.service,
            reservation.attachment_generation,
            reservation.created_entry,
            false,
        )?;
        return Err(anyhow!("Failed to start terminal output worker"));
    }
    Ok(TerminalServiceLease {
        service_id,
        service: reservation.service,
        attachment_generation: reservation.attachment_generation,
        authority_epoch: reservation.authority_epoch,
        created_entry: reservation.created_entry,
        requested_persistent: AtomicBool::new(is_persistent),
        activation_checkpoint: Mutex::new(None),
        sp: svc.sp,
        worker_state,
        action_tx: Some(action_tx),
        action_worker: Some(action_worker),
        teardown_permit: Some(teardown_permit),
        activated: false,
    })
}

enum TerminalOutputPoll {
    Responses(Vec<TerminalOutputResponse>),
    Quiescent,
}

struct TerminalOutputResponse {
    response: TerminalResponse,
    condition: TerminalOutputCondition,
}

struct TerminalSessionPublication {
    terminal_id: i32,
    expected: SharedTerminalSession,
    output_visible: Arc<AtomicBool>,
}

struct TerminalActionResponse {
    response: TerminalResponse,
    publication: Option<TerminalSessionPublication>,
}

impl TerminalActionResponse {
    fn immediate(response: TerminalResponse) -> Self {
        Self {
            response,
            publication: None,
        }
    }
}

enum TerminalOutputCondition {
    SessionCurrent {
        terminal_id: i32,
        expected: SharedTerminalSession,
    },
    SessionRemove {
        terminal_id: i32,
        expected: SharedTerminalSession,
    },
}

impl TerminalOutputCondition {
    fn matches(&self, service: &PersistentTerminalService) -> bool {
        match self {
            Self::SessionCurrent {
                terminal_id,
                expected,
            } => service
                .sessions
                .get(terminal_id)
                .map(|current| Arc::ptr_eq(current, expected))
                .unwrap_or(false),
            Self::SessionRemove {
                terminal_id,
                expected,
            } => service
                .sessions
                .get(terminal_id)
                .map(|current| Arc::ptr_eq(current, expected))
                .unwrap_or(false),
        }
    }
}

fn poll_terminal_outputs(
    proxy: &TerminalServiceProxy,
    worker_state: &TerminalWorkerState,
) -> Result<TerminalOutputPoll> {
    if worker_state.fatal_authority.load(Ordering::Acquire) {
        return Ok(TerminalOutputPoll::Quiescent);
    }
    match proxy.read_outputs() {
        Ok(responses) => Ok(TerminalOutputPoll::Responses(responses)),
        Err(err) if is_fatal_authority_error(&err) => {
            worker_state.mark_fatal_authority();
            Ok(TerminalOutputPoll::Quiescent)
        }
        Err(err) => Err(err),
    }
}

fn send_terminal_response_if_authoritative(
    proxy: &TerminalServiceProxy,
    service: &GenericService,
    worker_state: &TerminalWorkerState,
    response: TerminalResponse,
    condition: Option<&TerminalOutputCondition>,
) -> Result<bool> {
    worker_state.ensure_authoritative()?;
    let mut state = proxy.service.lock().unwrap();
    state.validate_attachment(proxy.attachment_generation, proxy.authority_epoch)?;
    worker_state.ensure_authoritative()?;
    if condition
        .map(|condition| !condition.matches(&state))
        .unwrap_or(false)
    {
        return Ok(true);
    }
    let Some(subscriber_id) = worker_state.subscriber_id() else {
        return Ok(false);
    };
    let mut msg_out = Message::new();
    msg_out.set_terminal_response(response);
    service.send_to(msg_out, subscriber_id);
    let removed = match condition {
        Some(TerminalOutputCondition::SessionRemove {
            terminal_id,
            expected,
        }) if state
            .sessions
            .get(terminal_id)
            .map(|current| Arc::ptr_eq(current, expected))
            .unwrap_or(false) =>
        {
            state.sessions.remove(terminal_id)
        }
        _ => None,
    };
    drop(state);
    if let Some(removed) = removed {
        enqueue_session_teardown(removed);
    }
    Ok(true)
}

fn send_terminal_action_response_if_authoritative(
    proxy: &TerminalServiceProxy,
    service: &GenericService,
    worker_state: &TerminalWorkerState,
    action_response: TerminalActionResponse,
) -> Result<()> {
    worker_state.ensure_authoritative()?;
    let state = proxy.service.lock().unwrap();
    state.validate_attachment(proxy.attachment_generation, proxy.authority_epoch)?;
    worker_state.ensure_authoritative()?;
    if let Some(publication) = &action_response.publication {
        let current = state
            .sessions
            .get(&publication.terminal_id)
            .ok_or_else(|| authority_error("Opened terminal session was removed before publish"))?;
        if !Arc::ptr_eq(current, &publication.expected) {
            return Err(authority_error(
                "Opened terminal session changed before publish",
            ));
        }
    }
    let subscriber_id = worker_state
        .subscriber_id()
        .ok_or_else(|| authority_error("Terminal subscriber detached before response"))?;
    let mut msg_out = Message::new();
    msg_out.set_terminal_response(action_response.response);
    service.send_to(msg_out, subscriber_id);
    if let Some(publication) = action_response.publication {
        publication.output_visible.store(true, Ordering::Release);
    }
    drop(state);
    Ok(())
}

fn run(sp: TerminalService) -> ResultType<()> {
    let proxy = TerminalServiceProxy {
        service: sp.service.clone(),
        attachment_generation: sp.attachment_generation,
        authority_epoch: sp.authority_epoch,
    };
    while sp.active() {
        if !sp.has_subscribes() {
            thread::sleep(Duration::from_millis(30));
            continue;
        }
        let responses = match poll_terminal_outputs(&proxy, &sp.worker_state)? {
            TerminalOutputPoll::Responses(responses) => responses,
            TerminalOutputPoll::Quiescent => {
                thread::sleep(Duration::from_millis(30));
                continue;
            }
        };
        for response in responses {
            match send_terminal_response_if_authoritative(
                &proxy,
                &sp.sp,
                &sp.worker_state,
                response.response,
                Some(&response.condition),
            ) {
                Ok(true) => {}
                Ok(false) => break,
                Err(err) if is_fatal_authority_error(&err) => {
                    sp.worker_state.mark_fatal_authority();
                    break;
                }
                Err(err) => return Err(err),
            }
        }

        thread::sleep(Duration::from_millis(30)); // Read at ~33fps for responsive terminal
    }
    Ok(())
}

fn run_action_worker(
    mut proxy: TerminalServiceProxy,
    service: GenericService,
    worker_state: Arc<TerminalWorkerState>,
    actions: Receiver<TerminalAction>,
) {
    while let Ok(action) = actions.recv() {
        if worker_state.ensure_authoritative().is_err() {
            break;
        }
        match proxy.handle_action(&action) {
            Ok(Some(response)) => {
                if let Err(err) = send_terminal_action_response_if_authoritative(
                    &proxy,
                    &service,
                    &worker_state,
                    response,
                ) {
                    if !is_fatal_authority_error(&err) {
                        log::error!("Terminal response dispatch failed: {}", err);
                    }
                    worker_state.mark_fatal_authority();
                    break;
                }
            }
            Ok(None) => {}
            Err(err) if is_fatal_authority_error(&err) => {
                worker_state.mark_fatal_authority();
                break;
            }
            Err(err) => {
                log::warn!("Terminal action failed: {}", err);
                let mut response = TerminalResponse::new();
                let mut error = TerminalError::new();
                error.message = "Failed to handle terminal action".to_owned();
                response.set_error(error);
                if let Err(dispatch_err) = send_terminal_action_response_if_authoritative(
                    &proxy,
                    &service,
                    &worker_state,
                    TerminalActionResponse::immediate(response),
                ) {
                    if !is_fatal_authority_error(&dispatch_err) {
                        log::error!("Terminal error response dispatch failed: {}", dispatch_err);
                    }
                    worker_state.mark_fatal_authority();
                    break;
                }
            }
        }
    }
}

/// Output buffer for terminal session
struct OutputBuffer {
    lines: VecDeque<Vec<u8>>,
    total_size: usize,
    last_line_incomplete: bool,
}

impl OutputBuffer {
    fn new() -> Self {
        Self {
            lines: VecDeque::new(),
            total_size: 0,
            last_line_incomplete: false,
        }
    }

    fn append(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        // Handle incomplete lines
        let mut start = 0;
        if self.last_line_incomplete {
            if let Some(last_line) = self.lines.back_mut() {
                // Find first newline in new data
                if let Some(newline_pos) = data.iter().position(|&b| b == b'\n') {
                    last_line.extend_from_slice(&data[..=newline_pos]);
                    self.total_size += newline_pos + 1;
                    start = newline_pos + 1;
                    self.last_line_incomplete = false;
                } else {
                    // Still no newline, append all
                    last_line.extend_from_slice(data);
                    self.total_size += data.len();
                    return;
                }
            }
        }

        // Process remaining data
        let remaining = &data[start..];
        let ends_with_newline = remaining.last() == Some(&b'\n');

        // Split by lines
        let lines: Vec<&[u8]> = remaining.split(|&b| b == b'\n').collect();

        for (i, line) in lines.iter().enumerate() {
            if i == lines.len() - 1 && !ends_with_newline && !line.is_empty() {
                // Last line without newline
                self.last_line_incomplete = true;
            }

            if !line.is_empty() || i < lines.len() - 1 {
                let mut line_data = line.to_vec();
                if i < lines.len() - 1 || ends_with_newline {
                    line_data.push(b'\n');
                }

                self.total_size += line_data.len();
                self.lines.push_back(line_data);
            }
        }

        // Trim old data if buffer is too large
        while self.total_size > MAX_OUTPUT_BUFFER_SIZE || self.lines.len() > MAX_BUFFER_LINES {
            if let Some(removed) = self.lines.pop_front() {
                if removed.len() > self.total_size {
                    log::error!(
                        "OutputBuffer total_size underflow avoided: total_size={}, removed_len={}, lines_len={}",
                        self.total_size,
                        removed.len(),
                        self.lines.len()
                    );
                    self.total_size = self.lines.iter().map(|line| line.len()).sum();
                } else {
                    self.total_size -= removed.len();
                }
                if self.lines.is_empty() {
                    self.last_line_incomplete = false;
                }
            } else {
                log::error!(
                    "OutputBuffer trim invariant broken: total_size={}, lines_len=0",
                    self.total_size
                );
                self.total_size = 0;
                self.last_line_incomplete = false;
                break;
            }
        }
    }

    fn get_recent(&self, max_bytes: usize) -> Vec<u8> {
        if max_bytes == 0 {
            return Vec::new();
        }
        let mut chunks: Vec<&[u8]> = Vec::new();
        let mut size = 0;

        // Collect whole chunks from newest to oldest, preserving chronological continuity.
        // If the newest chunk alone exceeds max_bytes, take its tail (truncation may split
        // an ANSI escape, but the terminal will self-correct on subsequent output).
        for line in self.lines.iter().rev() {
            if size + line.len() > max_bytes {
                if size == 0 && line.len() > max_bytes {
                    // Single oversized chunk: take the tail to preserve the most recent content.
                    // Align offset forward to a UTF-8 char boundary so that downstream
                    // clients (e.g. Dart) that decode the payload as UTF-8 text don't
                    // encounter split code points. The protobuf bytes field itself allows
                    // arbitrary bytes; this is a best-effort mitigation for client-side decoding.
                    let mut offset = line.len() - max_bytes;
                    // Skip at most 3 continuation bytes (UTF-8 max 4-byte sequence).
                    // Prevents runaway skipping on non-UTF-8 binary data.
                    let mut skipped = 0u8;
                    while skipped < 3
                        && offset < line.len()
                        && (line[offset] & 0b1100_0000) == 0b1000_0000
                    {
                        offset += 1;
                        skipped += 1;
                    }
                    // If we skipped past all remaining bytes (degenerate data), drop the
                    // chunk entirely rather than emitting a slice that decodes poorly on the client.
                    if offset < line.len() {
                        chunks.push(&line[offset..]);
                        size = line.len() - offset;
                    }
                }
                break;
            }
            size += line.len();
            chunks.push(line);
        }

        // Reverse to restore chronological order and concatenate
        chunks.reverse();
        let mut result = Vec::with_capacity(size);
        for chunk in chunks {
            result.extend_from_slice(chunk);
        }

        result
    }
}

/// Find the largest prefix of `buf` that does not end in the middle of a UTF-8
/// code point. Invalid bytes are treated as complete so they can continue
/// downstream and be rendered with replacement characters if needed.
fn find_utf8_split_point(buf: &[u8]) -> usize {
    if buf.is_empty() {
        return 0;
    }

    let start = buf.len().saturating_sub(3);
    for i in (start..buf.len()).rev() {
        let b = buf[i];
        if b & 0x80 == 0 {
            return buf.len();
        }
        if b & 0xC0 == 0x80 {
            continue;
        }

        let seq_len = if b & 0xE0 == 0xC0 {
            2
        } else if b & 0xF0 == 0xE0 {
            3
        } else if b & 0xF8 == 0xF0 {
            4
        } else {
            return buf.len();
        };

        return if buf.len() - i >= seq_len {
            buf.len()
        } else {
            i
        };
    }

    buf.len()
}

// Terminal output currently follows a UTF-8 text model end to end: the service
// keeps replay buffers on UTF-8 boundaries, and Flutter decodes payload bytes as
// UTF-8 before writing to xterm. This accumulator only prevents splitting a
// trailing UTF-8 code point across PTY reads. Supporting non-UTF-8 terminals
// would need a separate design covering remote encoding detection, Flutter
// decoding, replay truncation, and input transcoding.
#[derive(Default)]
struct Utf8ChunkAccumulator {
    remainder: Vec<u8>,
}

impl Utf8ChunkAccumulator {
    fn push_chunk(&mut self, mut data: Vec<u8>) -> Option<Vec<u8>> {
        if data.is_empty() {
            return None;
        }

        let had_remainder = !self.remainder.is_empty();
        if had_remainder {
            let mut combined = std::mem::take(&mut self.remainder);
            combined.extend_from_slice(&data);
            data = combined;
        }

        let split = find_utf8_split_point(&data);
        if split == data.len() {
            return Some(data);
        }

        // Only hold back a candidate incomplete suffix when we have evidence that
        // the bytes before it are already UTF-8 text. If split is 0, the whole
        // read may be the start of a UTF-8 character, so keep it for the next read.
        if !had_remainder && split > 0 && std::str::from_utf8(&data[..split]).is_err() {
            return Some(data);
        }

        self.remainder = data.split_off(split);
        if data.is_empty() {
            None
        } else {
            Some(data)
        }
    }

    fn finish(&mut self) -> Option<Vec<u8>> {
        if self.remainder.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut self.remainder))
        }
    }
}

/// Try to send data through the output channel with rate-limited drop logging.
/// Returns `true` if the caller should break out of the read loop (channel disconnected).
fn try_send_output(
    output_tx: &mpsc::SyncSender<Vec<u8>>,
    data: Vec<u8>,
    terminal_id: i32,
    label: &str,
    drop_count: &mut u64,
    last_drop_warn: &mut Instant,
) -> bool {
    match output_tx.try_send(data) {
        Ok(_) => {
            if *drop_count > 0 {
                log::trace!(
                    "Terminal {}{} output channel recovered, dropped {} chunks since last report",
                    terminal_id,
                    label,
                    *drop_count
                );
                *drop_count = 0;
            }
            false
        }
        Err(mpsc::TrySendError::Full(_)) => {
            *drop_count += 1;
            if last_drop_warn.elapsed() >= Duration::from_secs(5) {
                log::trace!(
                    "Terminal {}{} output channel full, dropped {} chunks in last {:?}",
                    terminal_id,
                    label,
                    *drop_count,
                    last_drop_warn.elapsed()
                );
                *drop_count = 0;
                *last_drop_warn = Instant::now();
            }
            false
        }
        Err(mpsc::TrySendError::Disconnected(_)) => {
            log::debug!(
                "Terminal {}{} output channel disconnected",
                terminal_id,
                label
            );
            true
        }
    }
}

fn take_bounded_output_batch(
    output_rx: &Receiver<Vec<u8>>,
    deferred_output: &mut VecDeque<Vec<u8>>,
    remaining_chunks: &mut usize,
    remaining_bytes: &mut usize,
) -> Vec<Vec<u8>> {
    let mut batch = Vec::new();
    while *remaining_chunks > 0 && *remaining_bytes > 0 {
        let mut data = match deferred_output.pop_front() {
            Some(data) => data,
            None => match output_rx.try_recv() {
                Ok(data) => data,
                Err(_) => break,
            },
        };
        if data.len() > *remaining_bytes {
            let tail = data.split_off(*remaining_bytes);
            deferred_output.push_front(tail);
        }
        *remaining_chunks -= 1;
        *remaining_bytes -= data.len();
        batch.push(data);
    }
    batch
}

fn take_bounded_replay(
    pending_buffer: &mut Option<Vec<u8>>,
    remaining_chunks: &mut usize,
    remaining_bytes: &mut usize,
) -> Option<Vec<u8>> {
    if *remaining_chunks == 0 || *remaining_bytes == 0 {
        return None;
    }
    let mut data = pending_buffer.take()?;
    if data.is_empty() {
        return None;
    }
    if data.len() > *remaining_bytes {
        let tail = data.split_off(*remaining_bytes);
        *pending_buffer = Some(tail);
    }
    *remaining_chunks -= 1;
    *remaining_bytes -= data.len();
    Some(data)
}

fn transport_failure_is_reportable(
    reader_finished: bool,
    writer_finished: bool,
    helper_mode: bool,
    reader_finished_at: &mut Option<Instant>,
    now: Instant,
) -> bool {
    if writer_finished {
        return true;
    }
    if !reader_finished {
        return false;
    }
    let first_seen = reader_finished_at.get_or_insert(now);
    let grace = if helper_mode {
        HELPER_EXIT_STATUS_GRACE
    } else {
        DIRECT_EXIT_STATUS_GRACE
    };
    now.duration_since(*first_seen) >= grace
}

#[derive(Clone, Copy)]
struct PendingTerminalExit {
    exit_code: i32,
    drain_output: bool,
}

type SharedTerminalSession = Arc<TerminalSessionEntry>;

struct TerminalSessionEntry {
    state: Mutex<TerminalSession>,
    exiting: Arc<AtomicBool>,
    #[cfg(target_os = "windows")]
    helper_terminator: Option<HelperProcessTerminator>,
}

impl TerminalSessionEntry {
    fn new(session: TerminalSession) -> SharedTerminalSession {
        let exiting = session.exiting.clone();
        #[cfg(target_os = "windows")]
        let helper_terminator = session
            .helper_process
            .as_ref()
            .map(HelperProcessTree::terminator);
        Arc::new(Self {
            state: Mutex::new(session),
            exiting,
            #[cfg(target_os = "windows")]
            helper_terminator,
        })
    }

    fn signal_shutdown(&self) {
        self.exiting.store(true, Ordering::Release);
        #[cfg(target_os = "windows")]
        if let Some(terminator) = &self.helper_terminator {
            if let Err(err) = terminator.terminate() {
                log::error!("Failed to terminate terminal helper job: {err}");
                std::process::abort();
            }
        }
    }

    fn stop_for_teardown(&self) {
        self.signal_shutdown();
        let (workers, permit) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let workers = state.stop_resources();
            let permit = state._teardown_permit.take();
            (workers, permit)
        };
        for worker in workers {
            if worker.join().is_err() {
                log::error!("Terminal I/O worker panicked during teardown");
            }
        }
        drop(permit);
    }
}

impl Deref for TerminalSessionEntry {
    type Target = Mutex<TerminalSession>;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

struct TerminalSession {
    last_activity: Instant,
    pty_master: Option<Box<dyn MasterPty + Send>>,
    child: Option<Box<dyn Child + std::marker::Send + Sync>>,
    // Channel for sending input to the writer thread
    input_tx: Option<SyncSender<Vec<u8>>>,
    // Channel for receiving output from the reader thread
    output_rx: Option<Receiver<Vec<u8>>>,
    deferred_output: VecDeque<Vec<u8>>,
    exiting: Arc<AtomicBool>,
    // Thread handles
    reader_thread: Option<thread::JoinHandle<()>>,
    writer_thread: Option<thread::JoinHandle<()>>,
    output_buffer: OutputBuffer,
    pid: u32,
    rows: u16,
    cols: u16,
    pending_exit: Option<PendingTerminalExit>,
    output_visible: Arc<AtomicBool>,
    reader_finished_at: Option<Instant>,
    _teardown_permit: Option<Arc<TerminalTeardownPermit>>,
    // Session state machine for reconnection handling
    state: SessionState,
    // Helper mode: PTY is managed by helper process, communication via message protocol
    #[cfg(target_os = "windows")]
    is_helper_mode: bool,
    // Kill-on-close owner for the helper and every process in its job.
    #[cfg(target_os = "windows")]
    helper_process: Option<HelperProcessTree>,
}

impl TerminalSession {
    fn new(rows: u16, cols: u16) -> Self {
        Self {
            last_activity: Instant::now(),
            pty_master: None,
            child: None,
            input_tx: None,
            output_rx: None,
            deferred_output: VecDeque::new(),
            exiting: Arc::new(AtomicBool::new(false)),
            reader_thread: None,
            writer_thread: None,
            output_buffer: OutputBuffer::new(),
            pid: 0,
            rows,
            cols,
            pending_exit: None,
            output_visible: Arc::new(AtomicBool::new(false)),
            reader_finished_at: None,
            _teardown_permit: None,
            state: SessionState::Closed,
            #[cfg(target_os = "windows")]
            is_helper_mode: false,
            #[cfg(target_os = "windows")]
            helper_process: None,
        }
    }

    fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    fn exit_status_if_exited(&mut self) -> Option<PendingTerminalExit> {
        #[cfg(target_os = "windows")]
        if let Some(helper) = self.helper_process.as_ref() {
            match helper.exit_code_if_exited() {
                Ok(Some(exit_code)) => {
                    return Some(PendingTerminalExit {
                        exit_code: exit_code as i32,
                        drain_output: true,
                    });
                }
                Ok(None) => {}
                Err(err) => {
                    log::error!("Failed to query terminal helper status: {err}");
                    return Some(PendingTerminalExit {
                        exit_code: -1,
                        drain_output: false,
                    });
                }
            }
        }
        let reader_finished = self
            .reader_thread
            .as_ref()
            .map(|thread| thread.is_finished())
            .unwrap_or(false);
        let writer_finished = self
            .writer_thread
            .as_ref()
            .map(|thread| thread.is_finished())
            .unwrap_or(false);
        #[cfg(target_os = "windows")]
        let helper_mode = self.is_helper_mode;
        #[cfg(not(target_os = "windows"))]
        let helper_mode = false;
        if transport_failure_is_reportable(
            reader_finished,
            writer_finished,
            helper_mode,
            &mut self.reader_finished_at,
            Instant::now(),
        ) {
            return Some(match self.child.as_mut() {
                Some(child) => match child.try_wait() {
                    Ok(Some(status)) => PendingTerminalExit {
                        exit_code: status.exit_code() as i32,
                        drain_output: true,
                    },
                    Ok(None) => PendingTerminalExit {
                        exit_code: -1,
                        drain_output: !writer_finished,
                    },
                    Err(err) => {
                        log::error!("Failed to query terminal child status: {err}");
                        PendingTerminalExit {
                            exit_code: -1,
                            drain_output: false,
                        }
                    }
                },
                None => PendingTerminalExit {
                    exit_code: -1,
                    drain_output: !writer_finished,
                },
            });
        }
        match self.child.as_mut() {
            Some(child) => match child.try_wait() {
                Ok(status) => status.map(|status| PendingTerminalExit {
                    exit_code: status.exit_code() as i32,
                    drain_output: true,
                }),
                Err(err) => {
                    log::error!("Failed to query terminal child status: {err}");
                    Some(PendingTerminalExit {
                        exit_code: -1,
                        drain_output: false,
                    })
                }
            },
            None => None,
        }
    }

    fn has_exited(&mut self) -> bool {
        if self
            .reader_thread
            .as_ref()
            .map(|thread| thread.is_finished())
            .unwrap_or(false)
            || self
                .writer_thread
                .as_ref()
                .map(|thread| thread.is_finished())
                .unwrap_or(false)
        {
            return true;
        }
        self.exit_status_if_exited().is_some()
    }

    fn output_is_exhausted(&mut self) -> bool {
        if self
            .state
            .active_pending_buffer()
            .map(|buffer| !buffer.is_empty())
            .unwrap_or(false)
            || !self.deferred_output.is_empty()
        {
            return false;
        }
        if self
            .reader_thread
            .as_ref()
            .map(|thread| !thread.is_finished())
            .unwrap_or(false)
        {
            return false;
        }
        let Some(output_rx) = self.output_rx.as_ref() else {
            return true;
        };
        match output_rx.try_recv() {
            Err(mpsc::TryRecvError::Disconnected) => true,
            Err(mpsc::TryRecvError::Empty) => false,
            Ok(data) => {
                self.deferred_output.push_back(data);
                false
            }
        }
    }

    fn stop_resources(&mut self) -> Vec<thread::JoinHandle<()>> {
        self.state = SessionState::Closed;
        self.exiting.store(true, Ordering::SeqCst);
        self.input_tx = None;
        self.output_rx = None;

        #[cfg(target_os = "windows")]
        drop(self.helper_process.take());

        if let Some(mut child) = self.child.take() {
            if let Err(err) = child.kill() {
                log::warn!("Failed to terminate terminal child {}: {}", self.pid, err);
            }
            add_to_reaper(child);
        }
        self.pty_master = None;

        let mut workers = Vec::with_capacity(2);
        if let Some(reader_thread) = self.reader_thread.take() {
            workers.push(reader_thread);
        }
        if let Some(writer_thread) = self.writer_thread.take() {
            workers.push(writer_thread);
        }
        workers
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let workers = self.stop_resources();
        for worker in workers {
            if worker.join().is_err() {
                log::error!("Terminal I/O worker panicked during rollback teardown");
            }
        }
    }
}

/// Persistent terminal service that can survive connection drops
struct PersistentTerminalService {
    service_id: String,
    sessions: HashMap<i32, SharedTerminalSession>,
    opening_sessions: HashMap<i32, OpeningReservation>,
    pub created_at: Instant,
    last_activity: Instant,
    pub is_persistent: bool,
    needs_session_sync: bool,
    principal: TerminalPrincipal,
    launch_authority: Option<TerminalLaunchAuthority>,
    attachment_worker_state: Option<Weak<TerminalWorkerState>>,
    authority_epoch: u64,
    attachment_generation: u64,
    opening_generation: u64,
    output_poll_cursor: usize,
    attached: bool,
}

#[derive(Clone)]
struct OpeningReservation {
    attachment_generation: u64,
    authority_epoch: u64,
    opening_generation: u64,
    cancelled: Arc<AtomicBool>,
    teardown_permit: Arc<TerminalTeardownPermit>,
}

impl OpeningReservation {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    fn ensure_not_cancelled(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(authority_error("Terminal opening was cancelled"))
        } else {
            Ok(())
        }
    }

    fn same_identity(&self, other: &Self) -> bool {
        self.attachment_generation == other.attachment_generation
            && self.authority_epoch == other.authority_epoch
            && self.opening_generation == other.opening_generation
            && Arc::ptr_eq(&self.cancelled, &other.cancelled)
    }
}

struct OpeningGuard {
    service: Arc<Mutex<PersistentTerminalService>>,
    terminal_id: i32,
    reservation: OpeningReservation,
    committed: bool,
}

impl OpeningGuard {
    fn new(
        service: Arc<Mutex<PersistentTerminalService>>,
        terminal_id: i32,
        reservation: OpeningReservation,
    ) -> Self {
        Self {
            service,
            terminal_id,
            reservation,
            committed: false,
        }
    }

    fn ensure_current(&self) -> Result<()> {
        self.reservation.ensure_not_cancelled()?;
        let state = self.service.lock().unwrap();
        state.validate_attachment(
            self.reservation.attachment_generation,
            self.reservation.authority_epoch,
        )?;
        let current = state
            .opening_sessions
            .get(&self.terminal_id)
            .ok_or_else(|| authority_error("Terminal opening reservation was removed"))?;
        if !current.same_identity(&self.reservation) {
            return Err(authority_error("Terminal opening reservation is stale"));
        }
        self.reservation.ensure_not_cancelled()
    }
}

impl Drop for OpeningGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let mut state = self.service.lock().unwrap();
        if state
            .opening_sessions
            .get(&self.terminal_id)
            .map(|current| current.same_identity(&self.reservation))
            .unwrap_or(false)
        {
            state.opening_sessions.remove(&self.terminal_id);
        }
    }
}

impl PersistentTerminalService {
    fn new(
        service_id: String,
        principal: TerminalPrincipal,
        launch_authority: TerminalLaunchAuthority,
    ) -> Self {
        Self {
            service_id,
            sessions: HashMap::new(),
            opening_sessions: HashMap::new(),
            created_at: Instant::now(),
            last_activity: Instant::now(),
            is_persistent: false,
            needs_session_sync: false,
            principal,
            launch_authority: Some(launch_authority),
            attachment_worker_state: None,
            authority_epoch: 1,
            attachment_generation: 1,
            opening_generation: 0,
            output_poll_cursor: 0,
            attached: true,
        }
    }

    fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    fn commit_attachment(&mut self, is_persistent: bool) {
        self.is_persistent = is_persistent;
        self.needs_session_sync = true;
    }

    fn validate_attachment(&self, attachment_generation: u64, authority_epoch: u64) -> Result<()> {
        if !self.attached || self.attachment_generation != attachment_generation {
            return Err(authority_error(
                "Terminal service attachment is no longer authoritative",
            ));
        }
        if self.launch_authority.is_none() || self.authority_epoch != authority_epoch {
            return Err(authority_error(
                "Terminal service launch authority was revoked",
            ));
        }
        Ok(())
    }

    fn reserve_opening(
        &mut self,
        terminal_id: i32,
        attachment_generation: u64,
        authority_epoch: u64,
    ) -> Result<OpeningReservation> {
        self.validate_attachment(attachment_generation, authority_epoch)?;
        if self.opening_sessions.contains_key(&terminal_id) {
            return Err(anyhow!("Terminal is already opening"));
        }
        let reserved = self
            .sessions
            .len()
            .checked_add(self.opening_sessions.len())
            .ok_or_else(|| anyhow!("Terminal session count overflow"))?;
        if reserved >= MAX_SESSIONS_PER_SERVICE {
            return Err(anyhow!(
                "Maximum number of terminal sessions ({MAX_SESSIONS_PER_SERVICE}) reached"
            ));
        }
        self.opening_generation = self
            .opening_generation
            .checked_add(1)
            .ok_or_else(|| anyhow!("Terminal opening generation exhausted"))?;
        let teardown_permit = acquire_teardown_permit()?;
        let reservation = OpeningReservation {
            attachment_generation,
            authority_epoch,
            opening_generation: self.opening_generation,
            cancelled: Arc::new(AtomicBool::new(false)),
            teardown_permit,
        };
        self.opening_sessions
            .insert(terminal_id, reservation.clone());
        Ok(reservation)
    }
}

pub(crate) struct TerminalServiceProxy {
    service: Arc<Mutex<PersistentTerminalService>>,
    attachment_generation: u64,
    authority_epoch: u64,
}

impl TerminalServiceProxy {
    fn service_for_attachment(&self) -> Result<Arc<Mutex<PersistentTerminalService>>> {
        let service = self.service.clone();
        {
            let state = service.lock().unwrap();
            state.validate_attachment(self.attachment_generation, self.authority_epoch)?;
        }
        Ok(service)
    }

    fn validate_current_authority(&self) -> Result<()> {
        let service = self.service_for_attachment()?;
        let authority = service
            .lock()
            .unwrap()
            .launch_authority
            .clone()
            .ok_or_else(|| authority_error("Terminal service launch authority was revoked"))?;
        validate_launch_authority_value(&authority)?;
        let result = service
            .lock()
            .unwrap()
            .validate_attachment(self.attachment_generation, self.authority_epoch);
        result
    }

    fn handle_action(&mut self, action: &TerminalAction) -> Result<Option<TerminalActionResponse>> {
        self.validate_current_authority()?;
        let result = match &action.union {
            Some(terminal_action::Union::Open(open)) => self.handle_open(open),
            Some(terminal_action::Union::Resize(resize)) => self
                .handle_resize(resize)
                .map(|response| response.map(TerminalActionResponse::immediate)),
            Some(terminal_action::Union::Data(data)) => self
                .handle_data(data)
                .map(|response| response.map(TerminalActionResponse::immediate)),
            Some(terminal_action::Union::Close(close)) => self
                .handle_close(close)
                .map(|response| response.map(TerminalActionResponse::immediate)),
            _ => Ok(None),
        };
        match result {
            Err(err) => {
                if is_fatal_authority_error(&err) {
                    return Err(err);
                }
                self.validate_current_authority()?;
                Err(err)
            }
            ok => ok,
        }
    }

    fn handle_open(&self, open: &OpenTerminal) -> Result<Option<TerminalActionResponse>> {
        let service_arc = self.service_for_attachment()?;
        let mut service = service_arc.lock().unwrap();
        service.validate_attachment(self.attachment_generation, self.authority_epoch)?;
        service.update_activity();
        let mut response = TerminalResponse::new();

        // When the client requests a terminal_id that doesn't exist but there are
        // surviving persistent sessions, remap the lowest-ID session to the requested
        // terminal_id. This handles the case where _nextTerminalId resets to 1 on
        // reconnect but the server-side sessions have non-contiguous IDs (e.g. {2: htop}).
        //
        // The client's requested terminal_id may not match any surviving session ID
        // (e.g. _nextTerminalId incremented beyond the surviving IDs). This remap is a
        // one-time handle reassignment — only the first reconnect triggers it because
        // needs_session_sync is cleared afterward. Remaining sessions are communicated
        // back via `persistent_sessions` with their original server-side IDs.
        if !service.sessions.contains_key(&open.terminal_id)
            && service.needs_session_sync
            && !service.sessions.is_empty()
        {
            if let Some(&lowest_id) = service.sessions.keys().min() {
                log::info!(
                    "Remapping persistent session {} -> {} for reconnection",
                    lowest_id,
                    open.terminal_id
                );
                if let Some(session_arc) = service.sessions.remove(&lowest_id) {
                    service.sessions.insert(open.terminal_id, session_arc);
                }
            }
        }

        // Check if terminal already exists
        if let Some(session_arc) = service.sessions.get(&open.terminal_id).cloned() {
            drop(service);
            let mut session = session_arc.lock().unwrap();
            if session.has_exited() {
                drop(session);
                if let Some(removed) =
                    remove_session_if_current(&service_arc, open.terminal_id, &session_arc)
                {
                    enqueue_session_teardown(removed);
                }
                return Err(anyhow!("Terminal session has exited"));
            }
            let (service_id, persistent_sessions, needs_session_sync) = {
                let mut service = service_arc.lock().unwrap();
                service.validate_attachment(self.attachment_generation, self.authority_epoch)?;
                let current = service
                    .sessions
                    .get(&open.terminal_id)
                    .ok_or_else(|| anyhow!("Terminal session changed during reconnect"))?;
                if !Arc::ptr_eq(current, &session_arc) {
                    return Err(anyhow!("Terminal session changed during reconnect"));
                }
                service.update_activity();
                let needs_session_sync = service.needs_session_sync;
                let persistent_sessions = if needs_session_sync {
                    service
                        .sessions
                        .keys()
                        .filter(|&id| *id != open.terminal_id)
                        .cloned()
                        .collect()
                } else {
                    Vec::new()
                };
                if needs_session_sync {
                    service.needs_session_sync = false;
                }
                (
                    service.service_id.clone(),
                    persistent_sessions,
                    needs_session_sync,
                )
            };
            // Directly enter Active state with pending replay for immediate streaming.
            // The replay combines output_buffer history and the channel backlog that was
            // already pending at reconnect time so the client can suppress stale xterm
            // query answers without requiring a protobuf schema change.
            // During disconnect, read_outputs() is not called; channel data can still be lost
            // if output_rx fills before reconnect drains it.
            let mut buffer = session
                .output_buffer
                .get_recent(DEFAULT_RECONNECT_BUFFER_BYTES);
            let mut reconnect_backlog = Vec::new();
            if let Some(output_rx) = &session.output_rx {
                // Cap reconnect-time drain so a chatty PTY cannot keep OpenTerminal
                // inside this loop indefinitely. Remaining output is drained by read_outputs().
                for _ in 0..CHANNEL_BUFFER_SIZE {
                    let Ok(data) = output_rx.try_recv() else {
                        break;
                    };
                    reconnect_backlog.push(data);
                }
            }
            let has_reconnect_backlog = !reconnect_backlog.is_empty();
            for data in reconnect_backlog {
                session.output_buffer.append(&data);
            }
            if has_reconnect_backlog {
                buffer = session
                    .output_buffer
                    .get_recent(DEFAULT_RECONNECT_BUFFER_BYTES);
            }
            let has_pending = !buffer.is_empty();
            session.state = SessionState::Active {
                attachment_generation: self.attachment_generation,
                pending_buffer: if has_pending { Some(buffer) } else { None },
                // Always trigger two-phase SIGWINCH on reconnect to force TUI app redraw,
                // regardless of whether there's pending buffer data. This avoids edge cases
                // where buffer is empty but a TUI app (top/htop) still needs a full redraw.
                sigwinch: SigwinchPhase::TempResize {
                    retries: MAX_SIGWINCH_PHASE_ATTEMPTS,
                },
            };
            let mut opened = TerminalOpened::new();
            opened.terminal_id = open.terminal_id;
            opened.success = true;
            opened.message = if has_pending {
                "Reconnected to existing terminal with pending output".to_string()
            } else {
                "Reconnected to existing terminal".to_string()
            };
            opened.pid = session.pid;
            opened.service_id = service_id;
            opened.replay_terminal_output = has_pending;
            if needs_session_sync {
                opened.persistent_sessions = persistent_sessions;
            }
            response.set_opened(opened);
            session.output_visible.store(false, Ordering::Release);
            let publication = TerminalSessionPublication {
                terminal_id: open.terminal_id,
                expected: session_arc.clone(),
                output_visible: session.output_visible.clone(),
            };
            drop(session);
            self.service_for_attachment()?;
            return Ok(Some(TerminalActionResponse {
                response,
                publication: Some(publication),
            }));
        }

        let opening = service.reserve_opening(
            open.terminal_id,
            self.attachment_generation,
            self.authority_epoch,
        )?;
        #[cfg(target_os = "windows")]
        let launch_authority = service
            .launch_authority
            .clone()
            .ok_or_else(|| authority_error("Terminal service launch authority was revoked"))?;
        let service_id = service.service_id.clone();
        drop(service);
        let opening = OpeningGuard::new(service_arc, open.terminal_id, opening);
        opening.ensure_current()?;

        // Windows service-session authority uses a helper process as the logged-in user.
        // This solves the ConPTY + CreateProcessAsUserW incompatibility issue where
        // vim, Claude Code, and other TUI applications hang when ConPTY is created
        // by SYSTEM service but shell runs as user via CreateProcessAsUserW.
        #[cfg(target_os = "windows")]
        match &launch_authority.kind {
            TerminalLaunchAuthorityKind::WindowsSession { token } => {
                let token = token.clone();
                return self.handle_open_with_helper(open, &token, opening);
            }
            TerminalLaunchAuthorityKind::ProcessOwner => {}
            #[cfg(test)]
            TerminalLaunchAuthorityKind::TestPrincipal { .. } => {
                return Err(anyhow!("Test terminal authority cannot launch a shell"));
            }
        }

        // Create new terminal session
        log::info!(
            "Creating new terminal {} for service {}",
            open.terminal_id,
            service_id
        );
        let mut session = TerminalSession::new(open.rows as u16, open.cols as u16);
        session._teardown_permit = Some(opening.reservation.teardown_permit.clone());

        let pty_size = PtySize {
            rows: open.rows as u16,
            cols: open.cols as u16,
            pixel_width: 0,
            pixel_height: 0,
        };

        log::debug!("Opening PTY with size: {}x{}", open.rows, open.cols);
        opening.ensure_current()?;
        let pty_system = portable_pty::native_pty_system();
        let pty_pair = pty_system.openpty(pty_size).context("Failed to open PTY")?;
        let portable_pty::PtyPair { master, slave } = pty_pair;

        // Use default shell for the platform
        let shell = get_default_shell()?;
        log::debug!("Using shell: {}", shell);

        #[allow(unused_mut)]
        let mut cmd = CommandBuilder::new(&shell);

        #[cfg(target_os = "windows")]
        configure_utf8_shell_command(&shell, &mut cmd);

        // macOS-specific terminal configuration
        // 1. Use login shell (-l) to load user's shell profile (~/.zprofile, ~/.bash_profile)
        //    This ensures PATH includes Homebrew paths (/opt/homebrew/bin, /usr/local/bin)
        // 2. Set TERM environment variable for proper terminal behavior
        //    This fixes issues with control sequences (e.g., Delete/Backspace keys)
        //    macOS terminfo uses hex naming: '78' = 'x' for xterm entries
        // Note: For Linux, `TERM` is set in src/platform/linux.rs try_start_server_()
        #[cfg(target_os = "macos")]
        {
            // Start as login shell to load user environment (PATH, etc.)
            cmd.arg("-l");
            log::debug!("Added -l flag for macOS login shell");

            let term = if std::path::Path::new("/usr/share/terminfo/78/xterm-256color").exists() {
                "xterm-256color"
            } else {
                "xterm"
            };
            cmd.env("TERM", term);
            log::debug!("Set TERM={} for macOS PTY", term);

            if should_force_process_utf8_ctype() {
                cmd.env_remove("LC_ALL");
                cmd.env("LC_CTYPE", "en_US.UTF-8");
                log::debug!("Set LC_CTYPE=en_US.UTF-8 for macOS PTY");
            }
        }

        // Windows service-session launches were dispatched to the helper above. This path is the
        // direct process-owner authority.

        log::debug!("Spawning shell process...");
        opening.ensure_current()?;
        let child = slave
            .spawn_command(cmd)
            .context("Failed to spawn command")?;
        drop(slave);
        session.pid = child.process_id().unwrap_or(0) as u32;
        session.child = Some(child);
        opening.ensure_current()?;

        let writer = master.take_writer().context("Failed to get writer")?;

        let reader = master.try_clone_reader().context("Failed to get reader")?;

        // Create channels for input/output
        let (input_tx, input_rx) = mpsc::sync_channel::<Vec<u8>>(CHANNEL_BUFFER_SIZE);
        let (output_tx, output_rx) = mpsc::sync_channel::<Vec<u8>>(CHANNEL_BUFFER_SIZE);
        session.input_tx = Some(input_tx);
        session.output_rx = Some(output_rx);

        // Spawn writer thread
        let terminal_id = open.terminal_id;
        let writer_thread = thread::Builder::new()
            .name(format!("terminal-writer-{}", terminal_id))
            .spawn(move || {
                let mut writer = writer;
                while let Ok(data) = input_rx.recv() {
                    if let Err(e) = writer.write_all(&data) {
                        log::error!("Terminal {} write error: {}", terminal_id, e);
                        break;
                    }
                    if let Err(e) = writer.flush() {
                        log::error!("Terminal {} flush error: {}", terminal_id, e);
                    }
                }
                log::debug!("Terminal {} writer thread exiting", terminal_id);
            })
            .context("Failed to start terminal writer")?;
        session.writer_thread = Some(writer_thread);

        let exiting = session.exiting.clone();
        // Spawn reader thread
        let terminal_id = open.terminal_id;
        let reader_thread = thread::Builder::new()
            .name(format!("terminal-reader-{}", terminal_id))
            .spawn(move || {
                let mut reader = reader;
                let mut buf = vec![0u8; 4096];
                let mut utf8_chunks = Utf8ChunkAccumulator::default();
                let mut drop_count: u64 = 0;
                // Initialize to > 5s ago so the first drop triggers a warning immediately.
                let mut last_drop_warn = Instant::now() - Duration::from_secs(6);
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => {
                            // EOF
                            // This branch can be reached when the child process exits on macOS.
                            // But not on Linux and Windows in my tests.
                            if let Some(data) = utf8_chunks.finish() {
                                let _ = try_send_output(
                                    &output_tx,
                                    data,
                                    terminal_id,
                                    "",
                                    &mut drop_count,
                                    &mut last_drop_warn,
                                );
                            }
                            break;
                        }
                        Ok(n) => {
                            if exiting.load(Ordering::SeqCst) {
                                break;
                            }
                            let Some(data) = utf8_chunks.push_chunk(buf[..n].to_vec()) else {
                                continue;
                            };
                            // Use try_send to avoid blocking the reader thread when channel is full.
                            // During disconnect, the run loop (sp.ok()) stops and read_outputs() is
                            // no longer called, so the channel won't be drained. Blocking send would
                            // deadlock the reader thread in that case.
                            // Note: data produced during disconnect may be lost if channel fills up,
                            // since output_buffer is only updated in read_outputs(). The buffer will
                            // contain history from before the disconnect, not data produced after it.
                            if try_send_output(
                                &output_tx,
                                data,
                                terminal_id,
                                "",
                                &mut drop_count,
                                &mut last_drop_warn,
                            ) {
                                break;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // This branch is not reached in my tests, but we still add `exiting` check to ensure we can exit.
                            if exiting.load(Ordering::SeqCst) {
                                break;
                            }
                            // For non-blocking I/O, sleep briefly
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(e) => {
                            log::error!("Terminal {} read error: {}", terminal_id, e);
                            break;
                        }
                    }
                }
                log::debug!("Terminal {} reader thread exiting", terminal_id);
            })
            .context("Failed to start terminal reader")?;
        session.reader_thread = Some(reader_thread);

        session.pty_master = Some(master);
        session.state = SessionState::Active {
            attachment_generation: self.attachment_generation,
            pending_buffer: None,
            sigwinch: SigwinchPhase::Idle,
        };

        log::info!(
            "Terminal {} opened successfully with PID {}",
            open.terminal_id,
            session.pid
        );

        self.commit_opened_session(open, session, opening, "Terminal opened")
    }

    /// Windows-only: Open terminal using helper process pattern
    /// This solves the ConPTY + CreateProcessAsUserW incompatibility issue.
    /// The helper process runs as the logged-in user and creates ConPTY + shell,
    /// communicating with this service via named pipes.
    #[cfg(target_os = "windows")]
    fn handle_open_with_helper(
        &self,
        open: &OpenTerminal,
        user_token: &Arc<OwnedPrimaryToken>,
        opening: OpeningGuard,
    ) -> Result<Option<TerminalActionResponse>> {
        opening.ensure_current()?;
        log::info!(
            "Creating new terminal {} using helper process",
            open.terminal_id
        );

        let mut session = TerminalSession::new(open.rows as u16, open.cols as u16);
        session._teardown_permit = Some(opening.reservation.teardown_permit.clone());

        // Generate unique pipe names for this terminal
        let pipe_id = uuid::Uuid::new_v4();
        let input_pipe_name = format!(r"\\.\pipe\rustdesk_term_in_{}", pipe_id);
        let output_pipe_name = format!(r"\\.\pipe\rustdesk_term_out_{}", pipe_id);

        log::debug!(
            "Creating terminal helper pipes for terminal {}",
            open.terminal_id
        );

        // Create pipes (server side, don't wait for connection yet)
        // input_pipe: service WRITES to this, helper READS from this
        // output_pipe: service READS from this, helper WRITES to this
        // Using OwnedHandle for RAII - handles are automatically closed on error
        // Pass user_token to create a DACL restricted to SYSTEM and this exact logon session.
        opening.ensure_current()?;
        let input_pipe_handle = OwnedHandle::new(create_named_pipe_server(
            &input_pipe_name,
            false,
            user_token.as_ref(),
        )?);
        opening.ensure_current()?;
        let output_pipe_handle = OwnedHandle::new(create_named_pipe_server(
            &output_pipe_name,
            true,
            user_token.as_ref(),
        )?);

        opening.ensure_current()?;
        let helper_process = launch_terminal_helper_with_token(
            user_token.as_ref(),
            &input_pipe_name,
            &output_pipe_name,
            open.terminal_id,
            open.rows as u16,
            open.cols as u16,
        )?;
        opening.ensure_current()?;

        let helper_pid = helper_process.pid();

        // Wait for the launched helper process to connect to both pipes.
        let mut input_pipe = wait_for_pipe_connection(
            input_pipe_handle,
            "input",
            PIPE_CONNECTION_TIMEOUT_MS,
            &opening.reservation.cancelled,
            &helper_process,
            user_token.as_ref(),
        )?;
        opening.ensure_current()?;
        let mut output_pipe = wait_for_pipe_connection(
            output_pipe_handle,
            "output",
            PIPE_CONNECTION_TIMEOUT_MS,
            &opening.reservation.cancelled,
            &helper_process,
            user_token.as_ref(),
        )?;

        helper_process.ensure_running()?;
        opening.ensure_current()?;

        // Use helper process PID for session tracking
        // Note: This is the helper process PID, not the actual shell PID.
        // The real shell runs inside the helper process but its PID is not exposed here.
        // For process management (termination, status), the helper PID is what we need.
        session.pid = helper_pid;
        session.is_helper_mode = true;
        session.helper_process = Some(helper_process);

        // Create channels for input/output (same as direct PTY mode)
        let (input_tx, input_rx) = mpsc::sync_channel::<Vec<u8>>(CHANNEL_BUFFER_SIZE);
        let (output_tx, output_rx) = mpsc::sync_channel::<Vec<u8>>(CHANNEL_BUFFER_SIZE);
        session.input_tx = Some(input_tx);
        session.output_rx = Some(output_rx);

        // Spawn writer thread: reads from channel, writes to input pipe
        let terminal_id = open.terminal_id;
        let writer_thread = thread::Builder::new()
            .name(format!("terminal-helper-writer-{}", terminal_id))
            .spawn(move || {
                while let Ok(data) = input_rx.recv() {
                    if let Err(e) = input_pipe.write_all(&data) {
                        log::error!("Terminal {} pipe write error: {}", terminal_id, e);
                        break;
                    }
                    if let Err(e) = input_pipe.flush() {
                        log::error!("Terminal {} pipe flush error: {}", terminal_id, e);
                    }
                }
                log::debug!(
                    "Terminal {} writer thread (helper mode) exiting",
                    terminal_id
                );
            })
            .context("Failed to start terminal helper writer")?;
        session.writer_thread = Some(writer_thread);

        // Spawn reader thread: reads from output pipe, sends to channel.
        let exiting = session.exiting.clone();
        let terminal_id = open.terminal_id;
        let reader_thread = thread::Builder::new()
            .name(format!("terminal-helper-reader-{}", terminal_id))
            .spawn(move || {
                let mut buf = vec![0u8; 4096];
                let mut utf8_chunks = Utf8ChunkAccumulator::default();
                let mut drop_count: u64 = 0;
                // Initialize to > 5s ago so the first drop triggers a warning immediately.
                let mut last_drop_warn = Instant::now() - Duration::from_secs(6);
                loop {
                    match output_pipe.read(&mut buf) {
                        Ok(0) => {
                            if let Some(data) = utf8_chunks.finish() {
                                let _ = try_send_output(
                                    &output_tx,
                                    data,
                                    terminal_id,
                                    " (helper)",
                                    &mut drop_count,
                                    &mut last_drop_warn,
                                );
                            }
                            // EOF - helper process exited
                            log::debug!("Terminal {} helper output EOF", terminal_id);
                            break;
                        }
                        Ok(n) => {
                            if exiting.load(Ordering::SeqCst) {
                                break;
                            }
                            let Some(data) = utf8_chunks.push_chunk(buf[..n].to_vec()) else {
                                continue;
                            };
                            // Use try_send to avoid blocking the reader thread (same as direct PTY mode)
                            if try_send_output(
                                &output_tx,
                                data,
                                terminal_id,
                                " (helper)",
                                &mut drop_count,
                                &mut last_drop_warn,
                            ) {
                                break;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            if exiting.load(Ordering::SeqCst) {
                                break;
                            }
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(e) => {
                            log::error!("Terminal {} pipe read error: {}", terminal_id, e);
                            break;
                        }
                    }
                }
                log::debug!(
                    "Terminal {} reader thread (helper mode) exiting",
                    terminal_id
                );
            })
            .context("Failed to start terminal helper reader")?;
        session.reader_thread = Some(reader_thread);

        session.pty_master = None;
        session.child = None;
        session.state = SessionState::Active {
            attachment_generation: self.attachment_generation,
            pending_buffer: None,
            sigwinch: SigwinchPhase::Idle,
        };
        opening.ensure_current()?;

        log::info!(
            "Terminal {} opened successfully using helper process (PID {})",
            open.terminal_id,
            session.pid
        );

        self.commit_opened_session(open, session, opening, "Terminal opened (helper mode)")
    }

    fn commit_opened_session(
        &self,
        open: &OpenTerminal,
        mut session: TerminalSession,
        mut opening: OpeningGuard,
        message: &str,
    ) -> Result<Option<TerminalActionResponse>> {
        opening.ensure_current()?;
        let mut service = opening.service.lock().unwrap();
        service.validate_attachment(self.attachment_generation, self.authority_epoch)?;
        opening.reservation.ensure_not_cancelled()?;
        if !service
            .opening_sessions
            .get(&open.terminal_id)
            .map(|current| current.same_identity(&opening.reservation))
            .unwrap_or(false)
        {
            return Err(authority_error("Terminal opening reservation is stale"));
        }
        service.opening_sessions.remove(&open.terminal_id);

        let mut opened = TerminalOpened::new();
        opened.terminal_id = open.terminal_id;
        opened.success = true;
        opened.message = message.to_string();
        opened.pid = session.pid;
        opened.service_id = service.service_id.clone();
        if service.needs_session_sync {
            if !service.sessions.is_empty() {
                opened.persistent_sessions = service.sessions.keys().cloned().collect();
            }
            service.needs_session_sync = false;
        }
        session._teardown_permit = Some(opening.reservation.teardown_permit.clone());
        session.output_visible.store(false, Ordering::Release);
        let output_visible = session.output_visible.clone();
        let session = TerminalSessionEntry::new(session);
        service.sessions.insert(open.terminal_id, session.clone());
        drop(service);
        opening.committed = true;

        let mut response = TerminalResponse::new();
        response.set_opened(opened);
        Ok(Some(TerminalActionResponse {
            response,
            publication: Some(TerminalSessionPublication {
                terminal_id: open.terminal_id,
                expected: session,
                output_visible,
            }),
        }))
    }

    fn handle_resize(&self, resize: &ResizeTerminal) -> Result<Option<TerminalResponse>> {
        let session_arc = {
            let service = self.service.lock().unwrap();
            service.validate_attachment(self.attachment_generation, self.authority_epoch)?;
            service.sessions.get(&resize.terminal_id).cloned()
        };
        if let Some(session_arc) = session_arc {
            let mut session = session_arc.lock().unwrap();
            let mut service = self.service.lock().unwrap();
            service.validate_attachment(self.attachment_generation, self.authority_epoch)?;
            let Some(current) = service.sessions.get(&resize.terminal_id) else {
                return Ok(None);
            };
            if !Arc::ptr_eq(current, &session_arc) {
                return Ok(None);
            }
            service.update_activity();
            #[cfg(target_os = "windows")]
            {
                if session.is_helper_mode {
                    let input_tx = session
                        .input_tx
                        .as_ref()
                        .ok_or_else(|| anyhow!("Terminal helper input channel is closed"))?;
                    input_tx
                        .try_send(encode_resize_message(
                            resize.rows as u16,
                            resize.cols as u16,
                        ))
                        .map_err(|err| anyhow!("Failed to queue terminal resize: {}", err))?;
                } else {
                    Self::resize_pty(&session, resize)?;
                }
            }
            #[cfg(not(target_os = "windows"))]
            Self::resize_pty(&session, resize)?;
            session.rows = resize.rows as u16;
            session.cols = resize.cols as u16;
            session.update_activity();
        }
        Ok(None)
    }

    /// Resize PTY directly (used for non-helper mode)
    fn resize_pty(session: &TerminalSession, resize: &ResizeTerminal) -> Result<()> {
        if let Some(pty_master) = &session.pty_master {
            pty_master.resize(PtySize {
                rows: resize.rows as u16,
                cols: resize.cols as u16,
                pixel_width: 0,
                pixel_height: 0,
            })?;
        }
        Ok(())
    }

    fn handle_data(&self, data: &TerminalData) -> Result<Option<TerminalResponse>> {
        let session_arc = {
            let service = self.service.lock().unwrap();
            service.validate_attachment(self.attachment_generation, self.authority_epoch)?;
            service.sessions.get(&data.terminal_id).cloned()
        };
        if let Some(session_arc) = session_arc {
            let mut session = session_arc.lock().unwrap();
            let mut service = self.service.lock().unwrap();
            service.validate_attachment(self.attachment_generation, self.authority_epoch)?;
            let Some(current) = service.sessions.get(&data.terminal_id) else {
                return Ok(None);
            };
            if !Arc::ptr_eq(current, &session_arc) {
                return Ok(None);
            }
            service.update_activity();
            #[cfg(target_os = "windows")]
            let message = if session.is_helper_mode {
                encode_helper_message(MSG_TYPE_DATA, &data.data)
            } else {
                data.data.to_vec()
            };
            #[cfg(not(target_os = "windows"))]
            let message = data.data.to_vec();
            let input_tx = session
                .input_tx
                .as_ref()
                .ok_or_else(|| anyhow!("Terminal input channel is closed"))?;
            input_tx
                .try_send(message)
                .map_err(|err| anyhow!("Failed to queue terminal input: {}", err))?;
            session.update_activity();
        }
        Ok(None)
    }

    fn handle_close(&self, close: &CloseTerminal) -> Result<Option<TerminalResponse>> {
        let session = {
            let mut service = self.service.lock().unwrap();
            service.validate_attachment(self.attachment_generation, self.authority_epoch)?;
            service.update_activity();
            service.sessions.remove(&close.terminal_id)
        };
        if let Some(session_arc) = session {
            enqueue_session_teardown(session_arc);
            let mut response = TerminalResponse::new();
            let mut closed = TerminalClosed::new();
            closed.terminal_id = close.terminal_id;
            closed.exit_code = -1;
            response.set_closed(closed);
            Ok(Some(response))
        } else {
            Ok(None)
        }
    }

    /// Perform a single PTY resize as part of the two-phase SIGWINCH sequence.
    /// Returns true if the resize succeeded.
    ///
    /// Takes individual field references to avoid borrowing the entire TerminalSession,
    /// which would conflict with the mutable borrow of session.state in read_outputs().
    fn do_sigwinch_resize(
        terminal_id: i32,
        rows: u16,
        cols: u16,
        pty_master: &Option<Box<dyn MasterPty + Send>>,
        input_tx: &Option<SyncSender<Vec<u8>>>,
        _is_helper_mode: bool,
        action: &SigwinchAction,
    ) -> bool {
        // Skip if dimensions are not initialized (shouldn't happen on reconnect,
        // but guard against it to avoid resizing to nonsensical values).
        if rows == 0 || cols == 0 {
            return false;
        }

        let target_rows = match action {
            SigwinchAction::TempResize => {
                // For very small terminals (≤2 rows), subtracting 1 would result in an unusable
                // size (0 or 1 row), so we add 1 instead. Either direction triggers SIGWINCH.
                if rows > 2 {
                    rows.saturating_sub(1)
                } else {
                    rows.saturating_add(1)
                }
            }
            SigwinchAction::Restore => rows,
        };

        let phase_name = match action {
            SigwinchAction::TempResize => "temp resize",
            SigwinchAction::Restore => "restore",
        };

        #[cfg(target_os = "windows")]
        let use_helper = _is_helper_mode;
        #[cfg(not(target_os = "windows"))]
        let use_helper = false;

        if use_helper {
            #[cfg(target_os = "windows")]
            {
                let input_tx = match input_tx {
                    Some(tx) => tx,
                    None => return false,
                };
                let msg = encode_resize_message(target_rows, cols);
                if let Err(e) = input_tx.try_send(msg) {
                    log::warn!(
                        "Terminal {} SIGWINCH {} via helper failed: {}",
                        terminal_id,
                        phase_name,
                        e
                    );
                    return false;
                }
                true
            }
            #[cfg(not(target_os = "windows"))]
            {
                let _ = (input_tx, phase_name);
                false
            }
        } else if let Some(pty_master) = pty_master {
            if let Err(e) = pty_master.resize(PtySize {
                rows: target_rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            }) {
                log::warn!(
                    "Terminal {} SIGWINCH {} failed: {}",
                    terminal_id,
                    phase_name,
                    e
                );
                return false;
            }
            true
        } else {
            false
        }
    }

    /// Helper to create a TerminalResponse with optional compression.
    fn create_terminal_data_response(terminal_id: i32, data: Vec<u8>) -> TerminalResponse {
        let mut response = TerminalResponse::new();
        let mut terminal_data = TerminalData::new();
        terminal_data.terminal_id = terminal_id;

        if data.len() > COMPRESS_THRESHOLD {
            let compressed = compress::compress(&data);
            if compressed.len() < data.len() {
                terminal_data.data = bytes::Bytes::from(compressed);
                terminal_data.compressed = true;
            } else {
                terminal_data.data = bytes::Bytes::from(data);
            }
        } else {
            terminal_data.data = bytes::Bytes::from(data);
        }

        response.set_data(terminal_data);
        response
    }

    fn current_session_output(
        terminal_id: i32,
        expected: &SharedTerminalSession,
        response: TerminalResponse,
    ) -> TerminalOutputResponse {
        TerminalOutputResponse {
            response,
            condition: TerminalOutputCondition::SessionCurrent {
                terminal_id,
                expected: expected.clone(),
            },
        }
    }

    fn read_outputs(&self) -> Result<Vec<TerminalOutputResponse>> {
        let service = self.service_for_attachment()?;

        let sessions: Vec<(i32, SharedTerminalSession)> = {
            let mut service = service.lock().unwrap();
            let mut sessions = service
                .sessions
                .iter()
                .map(|(id, session)| (*id, session.clone()))
                .collect::<Vec<_>>();
            sessions.sort_unstable_by_key(|(terminal_id, _)| *terminal_id);
            if !sessions.is_empty() {
                let start = service.output_poll_cursor % sessions.len();
                sessions.rotate_left(start);
                service.output_poll_cursor = (start + 1) % sessions.len();
            }
            sessions
        };

        let mut responses = Vec::new();
        let mut closed_sessions = Vec::new();
        let mut remaining_output_chunks = MAX_OUTPUT_CHUNKS_PER_POLL;
        let mut remaining_output_bytes = MAX_OUTPUT_BYTES_PER_POLL;
        let session_count = sessions.len().max(1);
        let chunks_per_session = (MAX_OUTPUT_CHUNKS_PER_POLL / session_count).max(1);
        let bytes_per_session = (MAX_OUTPUT_BYTES_PER_POLL / session_count).max(1);

        // Process each session with its own lock
        for (terminal_id, session_arc) in sessions {
            if let Ok(mut session) = session_arc.try_lock() {
                if !session.output_visible.load(Ordering::Acquire) {
                    continue;
                }
                if session.pending_exit.is_none() {
                    session.pending_exit = session.exit_status_if_exited();
                }
                let mut session_output_chunks = remaining_output_chunks.min(chunks_per_session);
                let mut session_output_bytes = remaining_output_bytes.min(bytes_per_session);
                let initial_session_chunks = session_output_chunks;
                let initial_session_bytes = session_output_bytes;

                let (is_active, replay_buffer, sigwinch_action) = {
                    match &mut session.state {
                        SessionState::Active {
                            attachment_generation,
                            pending_buffer,
                            sigwinch,
                        } if *attachment_generation == self.attachment_generation => {
                            let replay_buffer = take_bounded_replay(
                                pending_buffer,
                                &mut session_output_chunks,
                                &mut session_output_bytes,
                            );
                            let sigwinch_action = match sigwinch {
                                SigwinchPhase::TempResize { retries } => {
                                    if *retries == 0 {
                                        log::warn!(
                                            "Terminal {} SIGWINCH phase 1 (temp resize) failed after {} attempts, giving up",
                                            terminal_id, MAX_SIGWINCH_PHASE_ATTEMPTS
                                        );
                                        *sigwinch = SigwinchPhase::Idle;
                                        None
                                    } else {
                                        *retries -= 1;
                                        Some(SigwinchAction::TempResize)
                                    }
                                }
                                SigwinchPhase::Restore { retries } => {
                                    if *retries == 0 {
                                        log::warn!(
                                            "Terminal {} SIGWINCH phase 2 (restore) failed after {} attempts, giving up",
                                            terminal_id, MAX_SIGWINCH_PHASE_ATTEMPTS
                                        );
                                        *sigwinch = SigwinchPhase::Idle;
                                        None
                                    } else {
                                        *retries -= 1;
                                        Some(SigwinchAction::Restore)
                                    }
                                }
                                SigwinchPhase::Idle => None,
                            };
                            (true, replay_buffer, sigwinch_action)
                        }
                        _ => (false, None, None),
                    }
                };

                let received_data = match session.output_rx.take() {
                    Some(output_rx) => {
                        let batch = take_bounded_output_batch(
                            &output_rx,
                            &mut session.deferred_output,
                            &mut session_output_chunks,
                            &mut session_output_bytes,
                        );
                        session.output_rx = Some(output_rx);
                        batch
                    }
                    None => Vec::new(),
                };
                remaining_output_chunks -= initial_session_chunks - session_output_chunks;
                remaining_output_bytes -= initial_session_bytes - session_output_bytes;
                let has_activity = !received_data.is_empty();

                // Update buffer (always buffer for reconnection support)
                for data in &received_data {
                    session.output_buffer.append(data);
                }

                if !is_active {
                    continue;
                }

                if let Some(buffer) = replay_buffer {
                    if !buffer.is_empty() {
                        responses.push(Self::current_session_output(
                            terminal_id,
                            &session_arc,
                            Self::create_terminal_data_response(terminal_id, buffer),
                        ));
                    }
                }

                if has_activity {
                    session.update_activity();
                }

                // Execute SIGWINCH resize outside the mutable borrow scope of session.state.
                if let Some(action) = sigwinch_action {
                    #[cfg(target_os = "windows")]
                    let is_helper = session.is_helper_mode;
                    #[cfg(not(target_os = "windows"))]
                    let is_helper = false;
                    let resize_ok = Self::do_sigwinch_resize(
                        terminal_id,
                        session.rows,
                        session.cols,
                        &session.pty_master,
                        &session.input_tx,
                        is_helper,
                        &action,
                    );
                    if let SessionState::Active { sigwinch, .. } = &mut session.state {
                        match action {
                            SigwinchAction::TempResize => {
                                if resize_ok {
                                    // Phase 1 succeeded — advance to phase 2 (restore).
                                    *sigwinch = SigwinchPhase::Restore {
                                        retries: MAX_SIGWINCH_PHASE_ATTEMPTS,
                                    };
                                }
                                // If failed, retries already decremented; will retry phase 1.
                            }
                            SigwinchAction::Restore => {
                                if resize_ok {
                                    // Phase 2 succeeded — SIGWINCH sequence complete.
                                    *sigwinch = SigwinchPhase::Idle;
                                }
                                // If failed, retries already decremented; will retry phase 2.
                            }
                        }
                    }
                }

                // Send real-time data after historical buffer
                for data in received_data {
                    responses.push(Self::current_session_output(
                        terminal_id,
                        &session_arc,
                        Self::create_terminal_data_response(terminal_id, data),
                    ));
                }
                let output_exhaustion_is_observable =
                    session_output_chunks > 0 && session_output_bytes > 0;
                if let Some(pending_exit) = session.pending_exit {
                    if !pending_exit.drain_output
                        || (output_exhaustion_is_observable && session.output_is_exhausted())
                    {
                        session.pending_exit = None;
                        closed_sessions.push((
                            terminal_id,
                            session_arc.clone(),
                            pending_exit.exit_code,
                        ));
                    }
                }
            }
        }

        // Close dispatch and exact removal share the service lock, so the terminal ID cannot be
        // reused between the response and removal.
        for (terminal_id, expected, exit_code) in closed_sessions {
            let mut response = TerminalResponse::new();
            let mut closed = TerminalClosed::new();
            closed.terminal_id = terminal_id;
            closed.exit_code = exit_code;
            response.set_closed(closed);
            responses.push(TerminalOutputResponse {
                response,
                condition: TerminalOutputCondition::SessionRemove {
                    terminal_id,
                    expected,
                },
            });
        }

        self.service_for_attachment()?;
        Ok(responses)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_service_id, controlled_test_launch_authority, find_utf8_split_point,
        generate_service_id, is_fatal_authority_error, monitor_detached_sessions_once,
        monitor_service_authority_once, poll_terminal_outputs, prepare, release_service_attachment,
        remove_session_if_current, reserve_service_attachment, revoke_service_authority,
        run as run_terminal_service, test_launch_authority, test_principal,
        try_enqueue_terminal_action, ConnInner, GenericService, OpenTerminal, OpeningGuard,
        OutputBuffer, Service, SessionState, TerminalAction, TerminalData, TerminalOutputCondition,
        TerminalOutputPoll, TerminalPrincipal, TerminalService, TerminalServiceProxy,
        TerminalSession, TerminalSessionEntry, TerminalWorkerState, Utf8ChunkAccumulator,
        MAX_BUFFER_LINES, TERMINAL_SERVICES,
    };
    #[cfg(not(target_os = "windows"))]
    use super::{
        trusted_unix_terminal_shell_path, unix_path_is_clean_absolute, UNIX_TERMINAL_SHELLS,
    };
    #[cfg(not(target_os = "windows"))]
    use std::path::Path;

    fn wait_for_session_teardown(session: &super::SharedTerminalSession) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::sync::Arc::strong_count(session) > 1 {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(session
            .lock()
            .unwrap()
            .exiting
            .load(std::sync::atomic::Ordering::Acquire));
    }

    #[derive(Debug)]
    struct ControlledChild {
        remaining_running_polls: usize,
        exit_code: Option<u32>,
    }

    #[derive(Debug)]
    struct ControlledChildKiller;

    impl portable_pty::ChildKiller for ControlledChildKiller {
        fn kill(&mut self) -> std::io::Result<()> {
            Ok(())
        }

        fn clone_killer(&self) -> Box<dyn portable_pty::ChildKiller + Send + Sync> {
            Box::new(Self)
        }
    }

    impl portable_pty::ChildKiller for ControlledChild {
        fn kill(&mut self) -> std::io::Result<()> {
            Ok(())
        }

        fn clone_killer(&self) -> Box<dyn portable_pty::ChildKiller + Send + Sync> {
            Box::new(ControlledChildKiller)
        }
    }

    impl portable_pty::Child for ControlledChild {
        fn try_wait(&mut self) -> std::io::Result<Option<portable_pty::ExitStatus>> {
            if self.remaining_running_polls > 0 {
                self.remaining_running_polls -= 1;
                return Ok(None);
            }
            Ok(self.exit_code.map(portable_pty::ExitStatus::with_exit_code))
        }

        fn wait(&mut self) -> std::io::Result<portable_pty::ExitStatus> {
            self.exit_code
                .map(portable_pty::ExitStatus::with_exit_code)
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::WouldBlock, "running"))
        }

        fn process_id(&self) -> Option<u32> {
            Some(1)
        }

        #[cfg(windows)]
        fn as_raw_handle(&self) -> Option<std::os::windows::io::RawHandle> {
            None
        }
    }

    #[test]
    fn terminal_service_id_requires_canonical_generated_form() {
        let service_id = generate_service_id();
        assert!(canonical_service_id(&service_id));
        assert!(!canonical_service_id(""));
        assert!(!canonical_service_id("terminal"));
        assert!(!canonical_service_id("ts_not-a-uuid"));
        assert!(!canonical_service_id(&service_id.to_ascii_uppercase()));
    }

    #[test]
    fn persistent_service_binds_exact_terminal_principal() {
        let service_id = generate_service_id();
        let principal = test_principal(7, &[1, 2, 3], 11);
        let same_principal = principal.clone();
        let other_session = test_principal(8, &[1, 2, 3], 11);
        let other_user = test_principal(7, &[1, 2, 4], 11);
        let other_logon = test_principal(7, &[1, 2, 3], 12);

        let first =
            reserve_service_attachment(service_id.clone(), test_launch_authority(principal))
                .unwrap();
        assert!(reserve_service_attachment(
            service_id.clone(),
            test_launch_authority(same_principal.clone()),
        )
        .is_err());
        first.service.lock().unwrap().commit_attachment(true);
        release_service_attachment(
            &service_id,
            &first.service,
            first.attachment_generation,
            first.created_entry,
            true,
        )
        .unwrap();

        for mismatched in [other_session, other_user, other_logon] {
            assert!(reserve_service_attachment(
                service_id.clone(),
                test_launch_authority(mismatched),
            )
            .is_err());
        }

        let same =
            reserve_service_attachment(service_id.clone(), test_launch_authority(same_principal))
                .unwrap();
        assert!(std::sync::Arc::ptr_eq(&first.service, &same.service));
        assert!(same.attachment_generation > first.attachment_generation);
        same.service.lock().unwrap().is_persistent = false;
        release_service_attachment(
            &service_id,
            &same.service,
            same.attachment_generation,
            same.created_entry,
            true,
        )
        .unwrap();
        assert!(!TERMINAL_SERVICES.lock().unwrap().contains_key(&service_id));

        let replacement_principal = TerminalPrincipal::ProcessOwner;
        let replacement = reserve_service_attachment(
            service_id.clone(),
            test_launch_authority(replacement_principal),
        )
        .unwrap();
        assert!(release_service_attachment(
            &service_id,
            &first.service,
            first.attachment_generation,
            first.created_entry,
            true,
        )
        .is_err());
        assert!(TERMINAL_SERVICES.lock().unwrap().contains_key(&service_id));
        release_service_attachment(
            &service_id,
            &replacement.service,
            replacement.attachment_generation,
            replacement.created_entry,
            false,
        )
        .unwrap();
        assert!(!TERMINAL_SERVICES.lock().unwrap().contains_key(&service_id));
    }

    #[test]
    fn preactivation_rollback_preserves_existing_committed_service() {
        let service_id = generate_service_id();
        let principal = test_principal(9, &[4, 5, 6], 17);
        let first = reserve_service_attachment(
            service_id.clone(),
            test_launch_authority(principal.clone()),
        )
        .unwrap();
        {
            let mut state = first.service.lock().unwrap();
            state.commit_attachment(true);
            let mut session = TerminalSession::new(24, 80);
            session.state = SessionState::Active {
                attachment_generation: first.attachment_generation,
                pending_buffer: None,
                sigwinch: super::SigwinchPhase::Idle,
            };
            state
                .sessions
                .insert(41, TerminalSessionEntry::new(session));
        }
        release_service_attachment(
            &service_id,
            &first.service,
            first.attachment_generation,
            first.created_entry,
            true,
        )
        .unwrap();

        let reconnect = reserve_service_attachment(
            service_id.clone(),
            test_launch_authority(principal.clone()),
        )
        .unwrap();
        {
            let state = reconnect.service.lock().unwrap();
            assert!(state.is_persistent);
            assert!(matches!(
                state.sessions.get(&41).unwrap().lock().unwrap().state,
                SessionState::Active { .. }
            ));
        }
        release_service_attachment(
            &service_id,
            &reconnect.service,
            reconnect.attachment_generation,
            reconnect.created_entry,
            false,
        )
        .unwrap();
        let state = first.service.lock().unwrap();
        assert!(state.is_persistent);
        assert!(state.sessions.contains_key(&41));
        drop(state);

        let committed =
            reserve_service_attachment(service_id.clone(), test_launch_authority(principal))
                .unwrap();
        {
            let mut state = committed.service.lock().unwrap();
            state.commit_attachment(false);
            assert!(!state.is_persistent);
            assert!(state.needs_session_sync);
            assert!(matches!(
                state.sessions.get(&41).unwrap().lock().unwrap().state,
                SessionState::Active {
                    attachment_generation,
                    ..
                } if attachment_generation == first.attachment_generation
                    && attachment_generation != committed.attachment_generation
            ));
        }
        release_service_attachment(
            &service_id,
            &committed.service,
            committed.attachment_generation,
            committed.created_entry,
            true,
        )
        .unwrap();
        assert!(!TERMINAL_SERVICES.lock().unwrap().contains_key(&service_id));

        let uncommitted_id = generate_service_id();
        let uncommitted = reserve_service_attachment(
            uncommitted_id.clone(),
            test_launch_authority(TerminalPrincipal::ProcessOwner),
        )
        .unwrap();
        release_service_attachment(
            &uncommitted_id,
            &uncommitted.service,
            uncommitted.attachment_generation,
            uncommitted.created_entry,
            false,
        )
        .unwrap();
        assert!(!TERMINAL_SERVICES
            .lock()
            .unwrap()
            .contains_key(&uncommitted_id));
    }

    #[test]
    fn detached_monitor_revokes_authority_and_sessions() {
        let service_id = generate_service_id();
        let (authority, valid) = controlled_test_launch_authority(test_principal(3, &[8, 8], 21));
        let reservation = reserve_service_attachment(service_id.clone(), authority).unwrap();
        {
            let mut state = reservation.service.lock().unwrap();
            state.commit_attachment(true);
            state
                .sessions
                .insert(1, TerminalSessionEntry::new(TerminalSession::new(24, 80)));
        }
        release_service_attachment(
            &service_id,
            &reservation.service,
            reservation.attachment_generation,
            reservation.created_entry,
            true,
        )
        .unwrap();
        let old_epoch = reservation.authority_epoch;
        valid.store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(monitor_service_authority_once(&reservation.service));
        let state = reservation.service.lock().unwrap();
        assert!(state.launch_authority.is_none());
        assert!(state.sessions.is_empty());
        assert!(state.authority_epoch > old_epoch);
        assert!(!state.attached);
        drop(state);
        TERMINAL_SERVICES.lock().unwrap().remove(&service_id);
    }

    #[test]
    fn stale_proxy_and_opening_are_rejected_after_epoch_change() {
        let service_id = generate_service_id();
        let reservation = reserve_service_attachment(
            service_id.clone(),
            test_launch_authority(TerminalPrincipal::ProcessOwner),
        )
        .unwrap();
        let opening = {
            let mut state = reservation.service.lock().unwrap();
            state
                .reserve_opening(
                    5,
                    reservation.attachment_generation,
                    reservation.authority_epoch,
                )
                .unwrap()
        };
        let opening_guard = OpeningGuard::new(reservation.service.clone(), 5, opening);
        let proxy = TerminalServiceProxy {
            service: reservation.service.clone(),
            attachment_generation: reservation.attachment_generation,
            authority_epoch: reservation.authority_epoch,
        };
        assert!(revoke_service_authority(
            &reservation.service,
            reservation.authority_epoch
        ));
        let error = match proxy.service_for_attachment() {
            Ok(_) => panic!("stale proxy unexpectedly retained authority"),
            Err(error) => error,
        };
        assert!(is_fatal_authority_error(&error));
        drop(opening_guard);
        assert!(reservation
            .service
            .lock()
            .unwrap()
            .opening_sessions
            .is_empty());
        TERMINAL_SERVICES.lock().unwrap().remove(&service_id);
    }

    #[test]
    fn simultaneous_opening_reservation_is_exclusive() {
        let service_id = generate_service_id();
        let reservation = reserve_service_attachment(
            service_id.clone(),
            test_launch_authority(TerminalPrincipal::ProcessOwner),
        )
        .unwrap();
        let mut state = reservation.service.lock().unwrap();
        let first = state
            .reserve_opening(
                7,
                reservation.attachment_generation,
                reservation.authority_epoch,
            )
            .unwrap();
        assert!(state
            .reserve_opening(
                7,
                reservation.attachment_generation,
                reservation.authority_epoch,
            )
            .is_err());
        assert!(state
            .opening_sessions
            .get(&7)
            .map(|current| current.same_identity(&first))
            .unwrap_or(false));
        drop(state);
        release_service_attachment(
            &service_id,
            &reservation.service,
            reservation.attachment_generation,
            reservation.created_entry,
            false,
        )
        .unwrap();
        assert!(!TERMINAL_SERVICES.lock().unwrap().contains_key(&service_id));
    }

    #[test]
    fn terminal_session_limit_includes_opening_reservations() {
        let service_id = generate_service_id();
        let reservation = reserve_service_attachment(
            service_id.clone(),
            test_launch_authority(TerminalPrincipal::ProcessOwner),
        )
        .unwrap();
        let mut state = reservation.service.lock().unwrap();
        for terminal_id in 0..(super::MAX_SESSIONS_PER_SERVICE - 1) as i32 {
            state.sessions.insert(
                terminal_id,
                TerminalSessionEntry::new(TerminalSession::new(24, 80)),
            );
        }
        state
            .reserve_opening(
                1000,
                reservation.attachment_generation,
                reservation.authority_epoch,
            )
            .unwrap();
        assert!(state
            .reserve_opening(
                1001,
                reservation.attachment_generation,
                reservation.authority_epoch,
            )
            .is_err());
        drop(state);
        release_service_attachment(
            &service_id,
            &reservation.service,
            reservation.attachment_generation,
            reservation.created_entry,
            false,
        )
        .unwrap();
        assert!(!TERMINAL_SERVICES.lock().unwrap().contains_key(&service_id));
    }

    #[test]
    fn lease_timer_detects_monitor_revocation_while_attached() {
        let service_id = generate_service_id();
        let (authority, valid) =
            controlled_test_launch_authority(test_principal(12, &[3, 1, 4], 29));
        let lease = prepare(service_id.clone(), true, authority).unwrap();
        lease.validate_for_activation().unwrap();
        valid.store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(monitor_service_authority_once(&lease.service));
        let error = lease.ensure_attached_authority().unwrap_err();
        assert!(is_fatal_authority_error(&error));
        drop(lease);
        assert!(!TERMINAL_SERVICES.lock().unwrap().contains_key(&service_id));
    }

    #[test]
    fn terminal_input_backpressure_is_nonblocking() {
        let service_id = generate_service_id();
        let reservation = reserve_service_attachment(
            service_id.clone(),
            test_launch_authority(TerminalPrincipal::ProcessOwner),
        )
        .unwrap();
        let (input_tx, _input_rx) = std::sync::mpsc::sync_channel(0);
        {
            let mut session = TerminalSession::new(24, 80);
            session.input_tx = Some(input_tx);
            reservation
                .service
                .lock()
                .unwrap()
                .sessions
                .insert(15, TerminalSessionEntry::new(session));
        }
        let proxy = TerminalServiceProxy {
            service: reservation.service.clone(),
            attachment_generation: reservation.attachment_generation,
            authority_epoch: reservation.authority_epoch,
        };
        let mut data = TerminalData::new();
        data.terminal_id = 15;
        data.data = bytes::Bytes::from_static(b"full");
        let error = proxy.handle_data(&data).unwrap_err();
        assert!(error.to_string().contains("Failed to queue terminal input"));
        release_service_attachment(
            &service_id,
            &reservation.service,
            reservation.attachment_generation,
            reservation.created_entry,
            false,
        )
        .unwrap();
    }

    #[test]
    fn revocation_cancels_in_flight_opening_at_barrier() {
        let service_id = generate_service_id();
        let reservation = reserve_service_attachment(
            service_id.clone(),
            test_launch_authority(TerminalPrincipal::ProcessOwner),
        )
        .unwrap();
        let opening = reservation
            .service
            .lock()
            .unwrap()
            .reserve_opening(
                51,
                reservation.attachment_generation,
                reservation.authority_epoch,
            )
            .unwrap();
        let worker_opening = opening.clone();
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(0);
        let (continue_tx, continue_rx) = std::sync::mpsc::sync_channel(0);
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(0);
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            continue_rx.recv().unwrap();
            result_tx
                .send(worker_opening.ensure_not_cancelled())
                .unwrap();
        });
        started_rx.recv().unwrap();
        assert!(revoke_service_authority(
            &reservation.service,
            reservation.authority_epoch
        ));
        continue_tx.send(()).unwrap();
        let error = result_rx.recv().unwrap().unwrap_err();
        assert!(is_fatal_authority_error(&error));
        worker.join().unwrap();
        release_service_attachment(
            &service_id,
            &reservation.service,
            reservation.attachment_generation,
            reservation.created_entry,
            false,
        )
        .unwrap();
    }

    #[test]
    fn revoked_registry_entry_is_immediately_replaceable() {
        let service_id = generate_service_id();
        let old = reserve_service_attachment(
            service_id.clone(),
            test_launch_authority(test_principal(4, &[1, 4], 7)),
        )
        .unwrap();
        assert!(revoke_service_authority(&old.service, old.authority_epoch));
        assert!(!TERMINAL_SERVICES.lock().unwrap().contains_key(&service_id));

        let replacement = reserve_service_attachment(
            service_id.clone(),
            test_launch_authority(test_principal(5, &[1, 4], 8)),
        )
        .unwrap();
        release_service_attachment(
            &service_id,
            &old.service,
            old.attachment_generation,
            old.created_entry,
            false,
        )
        .unwrap();
        let current = TERMINAL_SERVICES
            .lock()
            .unwrap()
            .get(&service_id)
            .cloned()
            .unwrap();
        assert!(std::sync::Arc::ptr_eq(&current, &replacement.service));
        release_service_attachment(
            &service_id,
            &replacement.service,
            replacement.attachment_generation,
            replacement.created_entry,
            false,
        )
        .unwrap();
    }

    #[test]
    fn authority_monitor_does_not_wait_for_held_session_mutex() {
        let service_id = generate_service_id();
        let (authority, valid) = controlled_test_launch_authority(test_principal(6, &[2, 5], 9));
        let reservation = reserve_service_attachment(service_id.clone(), authority).unwrap();
        let session = TerminalSessionEntry::new(TerminalSession::new(24, 80));
        reservation
            .service
            .lock()
            .unwrap()
            .sessions
            .insert(61, session.clone());
        let session_guard = session.lock().unwrap();
        valid.store(false, std::sync::atomic::Ordering::SeqCst);
        let monitored = reservation.service.clone();
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(0);
        let monitor = std::thread::spawn(move || {
            done_tx
                .send(monitor_service_authority_once(&monitored))
                .unwrap();
        });
        assert!(done_rx
            .recv_timeout(std::time::Duration::from_millis(250))
            .unwrap());
        monitor.join().unwrap();
        drop(session_guard);
        release_service_attachment(
            &service_id,
            &reservation.service,
            reservation.attachment_generation,
            reservation.created_entry,
            false,
        )
        .unwrap();
    }

    #[test]
    fn activation_does_not_wait_for_held_session_mutex() {
        let service_id = generate_service_id();
        let mut lease = prepare(
            service_id.clone(),
            false,
            test_launch_authority(TerminalPrincipal::ProcessOwner),
        )
        .unwrap();
        let session = TerminalSessionEntry::new(TerminalSession::new(24, 80));
        lease
            .service
            .lock()
            .unwrap()
            .sessions
            .insert(62, session.clone());
        lease.validate_for_activation().unwrap();
        let session_guard = session.lock().unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(0);
        let activation = std::thread::spawn(move || {
            let result = lease.activate(ConnInner::default());
            done_tx.send((result, lease)).unwrap();
        });
        let (result, lease) = done_rx
            .recv_timeout(std::time::Duration::from_millis(250))
            .unwrap();
        result.unwrap();
        drop(session_guard);
        activation.join().unwrap();
        drop(lease);
        assert!(!TERMINAL_SERVICES.lock().unwrap().contains_key(&service_id));
    }

    #[test]
    fn activation_rejects_worker_failure_after_checkpoint() {
        let service_id = generate_service_id();
        let mut lease = prepare(
            service_id.clone(),
            false,
            test_launch_authority(TerminalPrincipal::ProcessOwner),
        )
        .unwrap();
        lease.validate_for_activation().unwrap();
        lease.worker_state.mark_fatal_authority();
        let error = lease.activate(ConnInner::default()).unwrap_err();
        assert!(is_fatal_authority_error(&error));
        assert!(!lease.service.lock().unwrap().needs_session_sync);
        drop(lease);
        assert!(!TERMINAL_SERVICES.lock().unwrap().contains_key(&service_id));
    }

    #[test]
    fn generic_output_stays_quiescent_after_fatal_authority() {
        let service_id = generate_service_id();
        let reservation = reserve_service_attachment(
            service_id.clone(),
            test_launch_authority(TerminalPrincipal::ProcessOwner),
        )
        .unwrap();
        let proxy = TerminalServiceProxy {
            service: reservation.service.clone(),
            attachment_generation: reservation.attachment_generation,
            authority_epoch: reservation.authority_epoch,
        };
        let worker_state = TerminalWorkerState::new();
        assert!(revoke_service_authority(
            &reservation.service,
            reservation.authority_epoch
        ));
        assert!(matches!(
            poll_terminal_outputs(&proxy, &worker_state).unwrap(),
            TerminalOutputPoll::Quiescent
        ));
        assert!(worker_state
            .fatal_authority
            .load(std::sync::atomic::Ordering::Acquire));
        assert!(matches!(
            poll_terminal_outputs(&proxy, &worker_state).unwrap(),
            TerminalOutputPoll::Quiescent
        ));

        let service = TerminalService {
            sp: GenericService::new(service_id.clone(), false),
            service: reservation.service.clone(),
            attachment_generation: reservation.attachment_generation,
            authority_epoch: reservation.authority_epoch,
            worker_state: std::sync::Arc::new(TerminalWorkerState::new()),
        };
        service.sp.on_subscribe(ConnInner::default());
        let (entry_tx, entry_rx) = std::sync::mpsc::channel();
        GenericService::run(&service.clone(), move |service| {
            entry_tx.send(()).unwrap();
            run_terminal_service(service)
        });
        entry_rx
            .recv_timeout(std::time::Duration::from_millis(250))
            .unwrap();
        assert!(entry_rx
            .recv_timeout(std::time::Duration::from_millis(250))
            .is_err());
        service.sp.join();

        release_service_attachment(
            &service_id,
            &reservation.service,
            reservation.attachment_generation,
            reservation.created_entry,
            false,
        )
        .unwrap();
    }

    #[test]
    fn closed_session_arc_aba_preserves_replacement() {
        let service_id = generate_service_id();
        let reservation = reserve_service_attachment(
            service_id.clone(),
            test_launch_authority(TerminalPrincipal::ProcessOwner),
        )
        .unwrap();
        let stale = TerminalSessionEntry::new(TerminalSession::new(24, 80));
        let replacement = TerminalSessionEntry::new(TerminalSession::new(30, 100));
        {
            let mut state = reservation.service.lock().unwrap();
            state.sessions.insert(71, stale.clone());
            state.sessions.insert(71, replacement.clone());
        }
        assert!(remove_session_if_current(&reservation.service, 71, &stale).is_none());
        let current = reservation
            .service
            .lock()
            .unwrap()
            .sessions
            .get(&71)
            .cloned()
            .unwrap();
        assert!(std::sync::Arc::ptr_eq(&current, &replacement));
        let current_condition = TerminalOutputCondition::SessionCurrent {
            terminal_id: 71,
            expected: stale.clone(),
        };
        let remove_condition = TerminalOutputCondition::SessionRemove {
            terminal_id: 71,
            expected: stale.clone(),
        };
        let state = reservation.service.lock().unwrap();
        assert!(!current_condition.matches(&state));
        assert!(!remove_condition.matches(&state));
        drop(state);
        reservation.service.lock().unwrap().sessions.remove(&71);
        let state = reservation.service.lock().unwrap();
        assert!(!remove_condition.matches(&state));
        drop(state);
        release_service_attachment(
            &service_id,
            &reservation.service,
            reservation.attachment_generation,
            reservation.created_entry,
            false,
        )
        .unwrap();
    }

    #[test]
    fn opened_response_publication_precedes_session_output() {
        let service_id = generate_service_id();
        let reservation = reserve_service_attachment(
            service_id.clone(),
            test_launch_authority(TerminalPrincipal::ProcessOwner),
        )
        .unwrap();
        let (output_tx, output_rx) = std::sync::mpsc::sync_channel(1);
        output_tx.send(b"ready".to_vec()).unwrap();
        let mut session = TerminalSession::new(24, 80);
        session.output_rx = Some(output_rx);
        session.state = SessionState::Active {
            attachment_generation: reservation.attachment_generation,
            pending_buffer: None,
            sigwinch: super::SigwinchPhase::Idle,
        };
        let output_visible = session.output_visible.clone();
        let session = TerminalSessionEntry::new(session);
        reservation
            .service
            .lock()
            .unwrap()
            .sessions
            .insert(72, session.clone());
        let proxy = TerminalServiceProxy {
            service: reservation.service.clone(),
            attachment_generation: reservation.attachment_generation,
            authority_epoch: reservation.authority_epoch,
        };
        assert!(proxy.read_outputs().unwrap().is_empty());

        let generic = GenericService::new(service_id.clone(), false);
        generic.on_subscribe(ConnInner::default());
        let worker_state = TerminalWorkerState::new();
        worker_state
            .subscriber_id
            .store(0, std::sync::atomic::Ordering::Release);
        super::send_terminal_action_response_if_authoritative(
            &proxy,
            &generic,
            &worker_state,
            super::TerminalActionResponse {
                response: super::TerminalResponse::new(),
                publication: Some(super::TerminalSessionPublication {
                    terminal_id: 72,
                    expected: session,
                    output_visible: output_visible.clone(),
                }),
            },
        )
        .unwrap();
        assert!(output_visible.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(proxy.read_outputs().unwrap().len(), 1);
        release_service_attachment(
            &service_id,
            &reservation.service,
            reservation.attachment_generation,
            reservation.created_entry,
            false,
        )
        .unwrap();
    }

    #[test]
    fn output_poll_batch_is_bounded_during_continuous_refill() {
        let (tx, rx) = std::sync::mpsc::sync_channel(super::CHANNEL_BUFFER_SIZE);
        for _ in 0..super::MAX_OUTPUT_CHUNKS_PER_POLL {
            tx.send(vec![7; 4096]).unwrap();
        }
        let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let producer_running = running.clone();
        let producer = std::thread::spawn(move || {
            while producer_running.load(std::sync::atomic::Ordering::Acquire) {
                let _ = tx.try_send(vec![9; 4096]);
                std::thread::yield_now();
            }
        });
        let mut deferred = std::collections::VecDeque::new();
        let mut remaining_chunks = super::MAX_OUTPUT_CHUNKS_PER_POLL;
        let mut remaining_bytes = super::MAX_OUTPUT_BYTES_PER_POLL;
        let started = std::time::Instant::now();
        let batch = super::take_bounded_output_batch(
            &rx,
            &mut deferred,
            &mut remaining_chunks,
            &mut remaining_bytes,
        );
        running.store(false, std::sync::atomic::Ordering::Release);
        producer.join().unwrap();
        assert!(started.elapsed() < std::time::Duration::from_millis(250));
        assert!(batch.len() <= super::MAX_OUTPUT_CHUNKS_PER_POLL);
        assert!(batch.iter().map(Vec::len).sum::<usize>() <= super::MAX_OUTPUT_BYTES_PER_POLL);

        let (oversized_tx, oversized_rx) = std::sync::mpsc::sync_channel(1);
        oversized_tx
            .send(vec![1; super::MAX_OUTPUT_BYTES_PER_POLL + 17])
            .unwrap();
        let mut remaining_chunks = super::MAX_OUTPUT_CHUNKS_PER_POLL;
        let mut remaining_bytes = super::MAX_OUTPUT_BYTES_PER_POLL;
        let first = super::take_bounded_output_batch(
            &oversized_rx,
            &mut deferred,
            &mut remaining_chunks,
            &mut remaining_bytes,
        );
        assert_eq!(
            first.iter().map(Vec::len).sum::<usize>(),
            super::MAX_OUTPUT_BYTES_PER_POLL
        );
        assert_eq!(deferred.front().map(Vec::len), Some(17));
    }

    #[test]
    fn output_poll_is_fair_across_continuous_sessions() {
        let service_id = generate_service_id();
        let reservation = reserve_service_attachment(
            service_id.clone(),
            test_launch_authority(TerminalPrincipal::ProcessOwner),
        )
        .unwrap();
        let (first_tx, first_rx) = std::sync::mpsc::sync_channel(super::CHANNEL_BUFFER_SIZE);
        for _ in 0..super::MAX_OUTPUT_CHUNKS_PER_POLL {
            first_tx.send(vec![1; 4096]).unwrap();
        }
        let producer_running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let producer_flag = producer_running.clone();
        let producer = std::thread::spawn(move || {
            while producer_flag.load(std::sync::atomic::Ordering::Acquire) {
                let _ = first_tx.try_send(vec![2; 4096]);
                std::thread::yield_now();
            }
        });
        let (second_tx, second_rx) = std::sync::mpsc::sync_channel(1);
        second_tx.send(b"second".to_vec()).unwrap();

        let mut first = TerminalSession::new(24, 80);
        first.output_rx = Some(first_rx);
        first
            .output_visible
            .store(true, std::sync::atomic::Ordering::Release);
        first.state = SessionState::Active {
            attachment_generation: reservation.attachment_generation,
            pending_buffer: None,
            sigwinch: super::SigwinchPhase::Idle,
        };
        let first = TerminalSessionEntry::new(first);
        let mut second = TerminalSession::new(24, 80);
        second.output_rx = Some(second_rx);
        second
            .output_visible
            .store(true, std::sync::atomic::Ordering::Release);
        second.state = SessionState::Active {
            attachment_generation: reservation.attachment_generation,
            pending_buffer: None,
            sigwinch: super::SigwinchPhase::Idle,
        };
        let second = TerminalSessionEntry::new(second);
        {
            let mut state = reservation.service.lock().unwrap();
            state.sessions.insert(1, first);
            state.sessions.insert(2, second.clone());
        }
        let proxy = TerminalServiceProxy {
            service: reservation.service.clone(),
            attachment_generation: reservation.attachment_generation,
            authority_epoch: reservation.authority_epoch,
        };
        proxy.read_outputs().unwrap();
        producer_running.store(false, std::sync::atomic::Ordering::Release);
        producer.join().unwrap();
        assert!(second.lock().unwrap().output_buffer.total_size > 0);
        release_service_attachment(
            &service_id,
            &reservation.service,
            reservation.attachment_generation,
            reservation.created_entry,
            false,
        )
        .unwrap();
    }

    #[test]
    fn orderly_exit_drains_all_output_before_close() {
        let service_id = generate_service_id();
        let reservation = reserve_service_attachment(
            service_id.clone(),
            test_launch_authority(TerminalPrincipal::ProcessOwner),
        )
        .unwrap();
        let (output_tx, output_rx) = std::sync::mpsc::sync_channel(100);
        for _ in 0..100 {
            output_tx.send(vec![3; 4096]).unwrap();
        }
        drop(output_tx);
        let finished_reader = std::thread::spawn(|| {});
        while !finished_reader.is_finished() {
            std::thread::yield_now();
        }
        let mut session = TerminalSession::new(24, 80);
        session.output_rx = Some(output_rx);
        session.reader_thread = Some(finished_reader);
        session.pending_exit = Some(super::PendingTerminalExit {
            exit_code: 7,
            drain_output: true,
        });
        session
            .output_visible
            .store(true, std::sync::atomic::Ordering::Release);
        session.state = SessionState::Active {
            attachment_generation: reservation.attachment_generation,
            pending_buffer: None,
            sigwinch: super::SigwinchPhase::Idle,
        };
        let session = TerminalSessionEntry::new(session);
        reservation
            .service
            .lock()
            .unwrap()
            .sessions
            .insert(73, session);
        let proxy = TerminalServiceProxy {
            service: reservation.service.clone(),
            attachment_generation: reservation.attachment_generation,
            authority_epoch: reservation.authority_epoch,
        };
        let first = proxy.read_outputs().unwrap();
        assert!(!first.iter().any(|response| {
            matches!(
                response.response.union,
                Some(super::terminal_response::Union::Closed(_))
            )
        }));
        let second = proxy.read_outputs().unwrap();
        assert!(second.iter().any(|response| {
            matches!(
                response.response.union,
                Some(super::terminal_response::Union::Closed(ref closed)) if closed.exit_code == 7
            )
        }));
        release_service_attachment(
            &service_id,
            &reservation.service,
            reservation.attachment_generation,
            reservation.created_entry,
            false,
        )
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn direct_pty_exit_drains_real_output_before_close() {
        let service_id = generate_service_id();
        let reservation = reserve_service_attachment(
            service_id.clone(),
            test_launch_authority(TerminalPrincipal::ProcessOwner),
        )
        .unwrap();
        let pair = portable_pty::native_pty_system()
            .openpty(super::PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .unwrap();
        let portable_pty::PtyPair { master, slave } = pair;
        let mut command = super::CommandBuilder::new("/bin/sh");
        command.arg("-c");
        command.arg(
            "i=0; while [ \"$i\" -lt 4096 ]; do printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'; i=$((i+1)); done",
        );
        let child = slave.spawn_command(command).unwrap();
        drop(slave);
        let mut reader = master.try_clone_reader().unwrap();
        let (output_tx, output_rx) = std::sync::mpsc::sync_channel(super::CHANNEL_BUFFER_SIZE);
        let reader_thread = std::thread::spawn(move || {
            let mut buffer = vec![0u8; 4096];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => output_tx.send(buffer[..read].to_vec()).unwrap(),
                    Err(_) => break,
                }
            }
        });
        let mut session = TerminalSession::new(24, 80);
        session.pid = child.process_id().unwrap_or(0) as u32;
        session.child = Some(child);
        session.output_rx = Some(output_rx);
        session.reader_thread = Some(reader_thread);
        session.pty_master = Some(master);
        session
            .output_visible
            .store(true, std::sync::atomic::Ordering::Release);
        session.state = SessionState::Active {
            attachment_generation: reservation.attachment_generation,
            pending_buffer: None,
            sigwinch: super::SigwinchPhase::Idle,
        };
        reservation
            .service
            .lock()
            .unwrap()
            .sessions
            .insert(74, TerminalSessionEntry::new(session));
        let proxy = TerminalServiceProxy {
            service: reservation.service.clone(),
            attachment_generation: reservation.attachment_generation,
            authority_epoch: reservation.authority_epoch,
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut data_responses = 0usize;
        let mut saw_close = false;
        while !saw_close {
            assert!(std::time::Instant::now() < deadline);
            for response in proxy.read_outputs().unwrap() {
                match response.response.union.as_ref() {
                    Some(super::terminal_response::Union::Data(_)) => {
                        assert!(!saw_close);
                        data_responses += 1;
                    }
                    Some(super::terminal_response::Union::Closed(closed)) => {
                        assert_eq!(closed.exit_code, 0);
                        saw_close = true;
                    }
                    _ => {}
                }
            }
            if !saw_close {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        assert!(data_responses > super::MAX_OUTPUT_CHUNKS_PER_POLL);
        release_service_attachment(
            &service_id,
            &reservation.service,
            reservation.attachment_generation,
            reservation.created_entry,
            false,
        )
        .unwrap();
    }

    #[test]
    fn helper_reader_completion_waits_for_process_status() {
        let now = std::time::Instant::now();
        let mut first_seen = None;
        assert!(!super::transport_failure_is_reportable(
            true,
            false,
            true,
            &mut first_seen,
            now,
        ));
        assert!(!super::transport_failure_is_reportable(
            true,
            false,
            true,
            &mut first_seen,
            now + super::HELPER_EXIT_STATUS_GRACE - std::time::Duration::from_millis(1),
        ));
        assert!(super::transport_failure_is_reportable(
            true,
            false,
            true,
            &mut first_seen,
            now + super::HELPER_EXIT_STATUS_GRACE,
        ));
        let mut writer_first_seen = None;
        assert!(super::transport_failure_is_reportable(
            false,
            true,
            true,
            &mut writer_first_seen,
            now,
        ));
    }

    #[test]
    fn direct_reader_completion_requeries_child_status_before_close() {
        let service_id = generate_service_id();
        let reservation = reserve_service_attachment(
            service_id.clone(),
            test_launch_authority(TerminalPrincipal::ProcessOwner),
        )
        .unwrap();
        let reader = std::thread::spawn(|| {});
        while !reader.is_finished() {
            std::thread::yield_now();
        }
        let (output_tx, output_rx) = std::sync::mpsc::sync_channel(1);
        drop(output_tx);
        let mut session = TerminalSession::new(24, 80);
        session.reader_thread = Some(reader);
        session.output_rx = Some(output_rx);
        session.child = Some(Box::new(ControlledChild {
            remaining_running_polls: 1,
            exit_code: Some(0),
        }));
        session
            .output_visible
            .store(true, std::sync::atomic::Ordering::Release);
        session.state = SessionState::Active {
            attachment_generation: reservation.attachment_generation,
            pending_buffer: None,
            sigwinch: super::SigwinchPhase::Idle,
        };
        reservation
            .service
            .lock()
            .unwrap()
            .sessions
            .insert(75, TerminalSessionEntry::new(session));
        let proxy = TerminalServiceProxy {
            service: reservation.service.clone(),
            attachment_generation: reservation.attachment_generation,
            authority_epoch: reservation.authority_epoch,
        };
        let first = proxy.read_outputs().unwrap();
        assert!(!first.iter().any(|response| {
            matches!(
                response.response.union,
                Some(super::terminal_response::Union::Closed(_))
            )
        }));
        let second = proxy.read_outputs().unwrap();
        assert!(second.iter().any(|response| {
            matches!(
                response.response.union,
                Some(super::terminal_response::Union::Closed(ref closed)) if closed.exit_code == 0
            )
        }));
        release_service_attachment(
            &service_id,
            &reservation.service,
            reservation.attachment_generation,
            reservation.created_entry,
            false,
        )
        .unwrap();
    }

    #[test]
    fn direct_reader_status_grace_expires_as_failure() {
        let reader = std::thread::spawn(|| {});
        while !reader.is_finished() {
            std::thread::yield_now();
        }
        let mut session = TerminalSession::new(24, 80);
        session.reader_thread = Some(reader);
        session.reader_finished_at =
            Some(std::time::Instant::now() - super::DIRECT_EXIT_STATUS_GRACE);
        session.child = Some(Box::new(ControlledChild {
            remaining_running_polls: usize::MAX,
            exit_code: None,
        }));
        let status = session.exit_status_if_exited().unwrap();
        assert_eq!(status.exit_code, -1);
        assert!(status.drain_output);
    }

    #[test]
    fn writer_completion_is_immediate_transport_failure() {
        let writer = std::thread::spawn(|| {});
        while !writer.is_finished() {
            std::thread::yield_now();
        }
        let mut session = TerminalSession::new(24, 80);
        session.writer_thread = Some(writer);
        session.child = Some(Box::new(ControlledChild {
            remaining_running_polls: usize::MAX,
            exit_code: None,
        }));
        let status = session.exit_status_if_exited().unwrap();
        assert_eq!(status.exit_code, -1);
        assert!(!status.drain_output);
    }

    #[test]
    fn teardown_permit_pool_is_bounded_and_released() {
        let pool = std::sync::Arc::new(super::TerminalTeardownPermitPool::new(1));
        let permit = pool.acquire().unwrap();
        assert!(pool.acquire().is_err());
        drop(permit);
        assert!(pool.acquire().is_ok());
    }

    #[test]
    fn teardown_admission_does_not_wait_for_session_cleanup() {
        super::ensure_teardown_workers().unwrap();
        let pool = std::sync::Arc::new(super::TerminalTeardownPermitPool::new(1));
        let mut blocked_state = TerminalSession::new(24, 80);
        blocked_state._teardown_permit = Some(pool.acquire().unwrap());
        let blocked = TerminalSessionEntry::new(blocked_state);
        let blocked_guard = blocked.lock().unwrap();
        super::enqueue_session_teardown(blocked.clone());
        assert!(pool.acquire().is_err());

        let independent = TerminalSessionEntry::new(TerminalSession::new(24, 80));
        let started = std::time::Instant::now();
        super::enqueue_session_teardown(independent.clone());
        assert!(started.elapsed() < std::time::Duration::from_millis(250));
        wait_for_session_teardown(&independent);

        drop(blocked_guard);
        wait_for_session_teardown(&blocked);
        assert!(pool.acquire().is_ok());
    }

    #[test]
    fn terminal_action_queue_backpressure_is_nonblocking() {
        let worker_state = TerminalWorkerState::new();
        let (tx, _rx) = std::sync::mpsc::sync_channel(1);
        try_enqueue_terminal_action(&tx, &worker_state, TerminalAction::new()).unwrap();
        let error =
            try_enqueue_terminal_action(&tx, &worker_state, TerminalAction::new()).unwrap_err();
        assert!(error.to_string().contains("queue is full"));
        assert!(!is_fatal_authority_error(&error));

        let disconnected_state = TerminalWorkerState::new();
        let (disconnected_tx, disconnected_rx) = std::sync::mpsc::sync_channel(1);
        drop(disconnected_rx);
        let error = try_enqueue_terminal_action(
            &disconnected_tx,
            &disconnected_state,
            TerminalAction::new(),
        )
        .unwrap_err();
        assert!(is_fatal_authority_error(&error));
        assert!(disconnected_state
            .fatal_authority
            .load(std::sync::atomic::Ordering::Acquire));
    }

    #[test]
    fn fatal_authority_propagates_through_persistence_and_action_admission() {
        let service_id = generate_service_id();
        let mut lease = prepare(
            service_id.clone(),
            true,
            test_launch_authority(TerminalPrincipal::ProcessOwner),
        )
        .unwrap();
        lease.activated = true;
        assert!(revoke_service_authority(
            &lease.service,
            lease.authority_epoch
        ));
        let persistence_error = lease.set_persistent(false).unwrap_err();
        assert!(is_fatal_authority_error(&persistence_error));
        let action_error = lease.enqueue_action(TerminalAction::new()).unwrap_err();
        assert!(is_fatal_authority_error(&action_error));
        drop(lease);
        assert!(!TERMINAL_SERVICES.lock().unwrap().contains_key(&service_id));
    }

    #[test]
    fn detached_dead_session_is_removed_and_reaped() {
        let service_id = generate_service_id();
        let reservation = reserve_service_attachment(
            service_id.clone(),
            test_launch_authority(TerminalPrincipal::ProcessOwner),
        )
        .unwrap();
        let finished_reader = std::thread::spawn(|| {});
        while !finished_reader.is_finished() {
            std::thread::yield_now();
        }
        let mut session = TerminalSession::new(24, 80);
        session.reader_thread = Some(finished_reader);
        session.child = Some(Box::new(ControlledChild {
            remaining_running_polls: usize::MAX,
            exit_code: None,
        }));
        let session = TerminalSessionEntry::new(session);
        reservation
            .service
            .lock()
            .unwrap()
            .sessions
            .insert(81, session.clone());
        reservation.service.lock().unwrap().commit_attachment(true);
        release_service_attachment(
            &service_id,
            &reservation.service,
            reservation.attachment_generation,
            reservation.created_entry,
            true,
        )
        .unwrap();
        monitor_detached_sessions_once();
        assert!(reservation.service.lock().unwrap().sessions.is_empty());
        wait_for_session_teardown(&session);
        TERMINAL_SERVICES.lock().unwrap().remove(&service_id);
    }

    #[test]
    fn detached_broken_writer_is_removed_and_reaped() {
        let service_id = generate_service_id();
        let reservation = reserve_service_attachment(
            service_id.clone(),
            test_launch_authority(TerminalPrincipal::ProcessOwner),
        )
        .unwrap();
        let finished_writer = std::thread::spawn(|| {});
        while !finished_writer.is_finished() {
            std::thread::yield_now();
        }
        let mut session = TerminalSession::new(24, 80);
        session.writer_thread = Some(finished_writer);
        let session = TerminalSessionEntry::new(session);
        reservation
            .service
            .lock()
            .unwrap()
            .sessions
            .insert(82, session.clone());
        reservation.service.lock().unwrap().commit_attachment(true);
        release_service_attachment(
            &service_id,
            &reservation.service,
            reservation.attachment_generation,
            reservation.created_entry,
            true,
        )
        .unwrap();
        monitor_detached_sessions_once();
        assert!(reservation.service.lock().unwrap().sessions.is_empty());
        wait_for_session_teardown(&session);
        TERMINAL_SERVICES.lock().unwrap().remove(&service_id);
    }

    #[test]
    fn dead_reconnect_preserves_surviving_session_sync() {
        let service_id = generate_service_id();
        let reservation = reserve_service_attachment(
            service_id.clone(),
            test_launch_authority(TerminalPrincipal::ProcessOwner),
        )
        .unwrap();
        let finished_reader = std::thread::spawn(|| {});
        while !finished_reader.is_finished() {
            std::thread::yield_now();
        }
        let mut dead = TerminalSession::new(24, 80);
        dead.reader_thread = Some(finished_reader);
        dead.child = Some(Box::new(ControlledChild {
            remaining_running_polls: usize::MAX,
            exit_code: None,
        }));
        let dead = TerminalSessionEntry::new(dead);
        let surviving = TerminalSessionEntry::new(TerminalSession::new(24, 80));
        {
            let mut state = reservation.service.lock().unwrap();
            state.sessions.insert(91, dead);
            state.sessions.insert(92, surviving.clone());
            state.commit_attachment(true);
        }
        let proxy = TerminalServiceProxy {
            service: reservation.service.clone(),
            attachment_generation: reservation.attachment_generation,
            authority_epoch: reservation.authority_epoch,
        };
        let mut open = OpenTerminal::new();
        open.terminal_id = 91;
        open.rows = 24;
        open.cols = 80;
        assert!(proxy.handle_open(&open).is_err());
        {
            let state = reservation.service.lock().unwrap();
            assert!(state.needs_session_sync);
            assert!(state
                .sessions
                .get(&92)
                .map(|current| std::sync::Arc::ptr_eq(current, &surviving))
                .unwrap_or(false));
        }
        release_service_attachment(
            &service_id,
            &reservation.service,
            reservation.attachment_generation,
            reservation.created_entry,
            true,
        )
        .unwrap();
        TERMINAL_SERVICES.lock().unwrap().remove(&service_id);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn unix_terminal_shell_candidates_are_clean_absolute_paths() {
        for candidate in UNIX_TERMINAL_SHELLS {
            assert!(unix_path_is_clean_absolute(Path::new(candidate)));
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn trusted_unix_terminal_shell_rejects_relative_and_parent_paths() {
        assert!(trusted_unix_terminal_shell_path(Path::new("sh")).is_none());
        assert!(trusted_unix_terminal_shell_path(Path::new("/bin/../bin/sh")).is_none());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn trusted_unix_terminal_shell_returns_absolute_candidate_when_available() {
        let mut found = false;
        for candidate in UNIX_TERMINAL_SHELLS {
            if let Some(shell) = trusted_unix_terminal_shell_path(Path::new(candidate)) {
                assert!(shell.is_absolute());
                assert!(unix_path_is_clean_absolute(&shell));
                found = true;
                break;
            }
        }
        assert!(found, "expected one trusted Unix terminal shell candidate");
    }

    #[test]
    fn utf8_split_point_returns_full_len_for_complete_input() {
        assert_eq!(find_utf8_split_point(b"hello"), 5);
        assert_eq!(find_utf8_split_point("中文".as_bytes()), "中文".len());
        assert_eq!(find_utf8_split_point("😀".as_bytes()), "😀".len());
    }

    #[test]
    fn utf8_split_point_detects_incomplete_trailing_sequence() {
        let data = [b'a', 0xE4, 0xB8];
        assert_eq!(find_utf8_split_point(&data), 1);
    }

    #[test]
    fn utf8_split_point_keeps_malformed_prefix_but_buffers_trailing_lead_byte() {
        let data = [0xFF, 0xE4];
        assert_eq!(find_utf8_split_point(&data), 1);
    }

    #[test]
    fn utf8_split_point_treats_orphan_continuations_as_complete() {
        let data = [0x80, 0x81, 0x82];
        assert_eq!(find_utf8_split_point(&data), data.len());
    }

    #[test]
    fn utf8_chunk_accumulator_reassembles_split_multibyte_output() {
        let full = "你好世界".as_bytes();
        let mut chunker = Utf8ChunkAccumulator::default();
        let mut output = Vec::new();

        for chunk in full.chunks(5) {
            if let Some(data) = chunker.push_chunk(chunk.to_vec()) {
                output.extend_from_slice(&data);
            }
        }

        if let Some(data) = chunker.finish() {
            output.extend_from_slice(&data);
        }

        assert_eq!(output, full);
    }

    #[test]
    fn utf8_chunk_accumulator_buffers_leading_split_multibyte_output() {
        let mut chunker = Utf8ChunkAccumulator::default();

        assert!(chunker.push_chunk(vec![0xE4]).is_none());
        assert!(chunker.push_chunk(vec![0xB8]).is_none());
        assert_eq!(
            chunker.push_chunk(vec![0xAD]),
            Some("中".as_bytes().to_vec())
        );
        assert!(chunker.finish().is_none());
    }

    #[test]
    fn utf8_chunk_accumulator_flushes_incomplete_tail_on_finish() {
        let mut chunker = Utf8ChunkAccumulator::default();
        assert_eq!(chunker.push_chunk(vec![b'a', 0xE4]), Some(vec![b'a']));
        assert_eq!(chunker.finish(), Some(vec![0xE4]));
        assert!(chunker.finish().is_none());
    }

    #[test]
    fn utf8_chunk_accumulator_does_not_stall_on_malformed_bytes() {
        let mut chunker = Utf8ChunkAccumulator::default();
        assert_eq!(chunker.push_chunk(vec![0xFF]), Some(vec![0xFF]));
        assert!(chunker.finish().is_none());
    }

    #[test]
    fn utf8_chunk_accumulator_buffers_lone_utf8_lead_bytes() {
        let mut chunker = Utf8ChunkAccumulator::default();
        assert!(chunker.push_chunk(vec![0xE4]).is_none());
        assert_eq!(chunker.finish(), Some(vec![0xE4]));
    }

    #[test]
    fn utf8_chunk_accumulator_does_not_hold_back_non_utf8_prefixes() {
        let mut chunker = Utf8ChunkAccumulator::default();
        assert_eq!(chunker.push_chunk(vec![0xFF, 0xE4]), Some(vec![0xFF, 0xE4]));
        assert!(chunker.finish().is_none());
    }

    #[test]
    fn output_buffer_trim_after_incomplete_merge_does_not_underflow() {
        let mut buffer = OutputBuffer::new();

        // Create an incomplete line first.
        buffer.append(b"hello");

        // Merge a large chunk that contains the first newline at the tail.
        // This exercises the "append to last incomplete line" branch.
        let mut large = vec![b'a'; 30_000];
        large.push(b'\n');
        buffer.append(&large);

        // Exceed MAX_BUFFER_LINES so trim pops the first large merged line.
        for _ in 0..=MAX_BUFFER_LINES {
            buffer.append(b"x\n");
        }

        let actual_size: usize = buffer.lines.iter().map(|line| line.len()).sum();
        assert_eq!(buffer.total_size, actual_size);
    }
}
