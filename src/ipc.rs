#[path = "ipc/auth.rs"]
mod ipc_auth;
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[path = "ipc/fs.rs"]
mod ipc_fs;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[path = "ipc/password.rs"]
pub(crate) mod password;

use crate::{common::is_service_owned_server_process, privacy_mode::PrivacyModeState};
use bytes::Bytes;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub use clipboard::ClipboardFile;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use hbb_common::anyhow;
use hbb_common::{
    bail, bytes,
    bytes_codec::BytesCodec,
    config::{self, Config},
    futures::StreamExt as _,
    futures_util::sink::SinkExt,
    log, timeout,
    tokio::{
        self,
        io::{AsyncRead, AsyncWrite},
    },
    tokio_util::codec::Framed,
    ResultType,
};
#[cfg(target_os = "linux")]
use ipc_auth::authenticate_linux_service_owned_password_parent;
#[cfg(target_os = "macos")]
pub(crate) use ipc_auth::authenticate_macos_cm_endpoint;
#[cfg(target_os = "windows")]
pub(crate) use ipc_auth::authenticate_windows_cm_endpoint;
#[cfg(windows)]
pub(crate) use ipc_auth::current_windows_process_identity_key;
#[cfg(windows)]
pub(crate) use ipc_auth::ensure_peer_executable_matches_current_by_pid_opt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use ipc_auth::ensure_user_owned_main_server_is_trusted;
#[cfg(target_os = "linux")]
use ipc_auth::linux_proc_start_time;
#[cfg(all(target_os = "linux", test))]
use ipc_auth::linux_proc_stat_start_time;
#[cfg(windows)]
pub(crate) use ipc_auth::log_rejected_windows_ipc_connection;
#[cfg(windows)]
pub(crate) use ipc_auth::seal_windows_cm_launch_parent_handle;
#[cfg(target_os = "macos")]
pub(crate) use ipc_auth::macos_deployed_helper_matches_installed_app_bytes;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use ipc_auth::{active_uid, authorize_service_scoped_ipc_connection};
#[cfg(target_os = "linux")]
pub(crate) use ipc_auth::{
    authenticate_cm_endpoint, authenticate_linux_service_owned_main_server,
    authenticate_linux_service_owned_password_replica_server, current_linux_process_identity,
    ensure_linux_process_identity_matches, ensure_linux_root_service_connection,
    ensure_linux_root_service_stream, linux_cm_child_identity_is_live,
    linux_process_identity_is_live, peer_process_identity_from_stream,
    peer_process_identity_is_live, LinuxProcessIdentity, PeerProcessIdentity,
};
#[cfg(windows)]
pub(crate) use ipc_auth::{
    authenticate_windows_sensitive_pipe_server, authorize_windows_sensitive_pipe_client,
    authorize_windows_service_main_ipc_connection, ensure_windows_ipc_server_matches_current,
    ensure_windows_service_main_server_pid, preauthorize_windows_sensitive_pipe_client,
    windows_ipc_listener_sddl, windows_ipc_listener_security_attributes,
    windows_named_pipe_client_access_mask, windows_sensitive_pipe_security,
    WindowsSensitivePipeClientProof, WindowsSensitivePipeSecurity, WindowsSensitivePipeServerProof,
};
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) use ipc_auth::{authorize_cm_ipc_connection, authorize_whiteboard_ipc_connection};
#[cfg(windows)]
use ipc_auth::{authorize_windows_main_ipc_connection, authorize_windows_url_ipc_connection};
#[cfg(windows)]
pub(crate) use ipc_auth::{
    authorize_windows_service_owned_sas_requester, WindowsProcessIdentityKey,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use ipc_auth::{
    ensure_user_owned_password_client_is_trusted, ensure_user_owned_password_server_is_trusted,
};
// R-X13 (§8): the ipc_auth re-exports (ensure_peer_executable_matches_current_by_fd /
// is_allowed_service_peer_uid / log_rejected_uinput_connection / peer_uid_from_fd) were the uinput
// peer-authorization accessors, removed with the uinput module. The _service-channel authorization
// keeps using is_allowed_service_peer_uid / peer_uid_from_fd INTERNALLY inside ipc_auth.
// R-X6/R-S11c-9: the `_url` deep-link IPC listener is separate from the main handle() service-accept
// gate, so it authenticates its sender before honoring a rustdesk:// URL.
#[cfg(target_os = "macos")]
pub(crate) fn authorize_url_ipc_sender(stream: &Connection) -> bool {
    authorize_service_scoped_ipc_connection(stream, "_url")
}
#[cfg(target_os = "windows")]
pub(crate) fn authorize_url_ipc_sender(stream: &Connection) -> bool {
    authorize_windows_url_ipc_connection(stream, "_url")
}
#[cfg(target_os = "windows")]
use hbb_common::tokio::sync::mpsc;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use hbb_common::tokio::{
    sync::{oneshot, Notify, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};
#[cfg(target_os = "linux")]
use ipc_fs::terminal_count_candidate_uids;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use ipc_fs::{
    check_pid, ensure_secure_ipc_parent_dir, scrub_secure_ipc_parent_dir,
    should_scrub_parent_entries_after_check_pid, write_pid,
};
use parity_tokio_ipc::{
    Connection as Conn, ConnectionClient as ConnClient, Endpoint, Incoming, SecurityAttributes,
};
use serde_derive::{Deserialize, Serialize};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::cell::Cell;
use std::collections::HashMap;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::fs::PermissionsExt;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use std::sync::{
    atomic::{AtomicU8, Ordering as AtomicOrdering},
    Arc, OnceLock,
};
#[cfg(target_os = "linux")]
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

#[cfg(target_os = "macos")]
const MACOS_LAUNCHCTL: &str = "/bin/launchctl";
#[cfg(any(target_os = "macos", all(target_os = "linux", test)))]
const MACOS_LAUNCHCTL_STDOUT_MAX_BYTES: usize = 256 * 1024;
#[cfg(any(target_os = "macos", all(target_os = "linux", test)))]
const MACOS_LAUNCHCTL_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(2);
#[cfg(target_os = "macos")]
const MACOS_LAUNCHCTL_REAP_RESERVE: std::time::Duration = std::time::Duration::from_millis(50);
pub(crate) const SERVICE_IPC_MAX_FRAME_BYTES: usize = 32 * 1024;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) const MAIN_IPC_MAX_FRAME_BYTES: usize = 256 * 1024;
#[cfg(target_os = "linux")]
pub(crate) const PULSE_AUDIO_IPC_MAX_FRAME_BYTES: usize = 8 * 1024;
#[cfg(target_os = "linux")]
pub(crate) const PULSE_AUDIO_IPC_AUDIO_FRAME_BYTES: usize = 960 * 4;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) const WHITEBOARD_IPC_MAX_FRAME_BYTES: usize = 64 * 1024;
pub(crate) const DESKTOP_URL_IPC_MAX_FRAME_BYTES: usize = 8 * 1024;
const DESKTOP_URL_IPC_MAX_LINK_BYTES: usize = 1024;
const DESKTOP_URL_IPC_MAX_ADDRESS_BYTES: usize = 512;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) const WHITEBOARD_IPC_COMMAND_CAPACITY: usize = 64;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) const WHITEBOARD_IPC_MAX_ACTIVE_CONNECTIONS: usize = 16;
pub(crate) const CM_IPC_MAX_FRAME_BYTES: usize = 128 * 1024 * 1024;
pub(crate) const CM_FILE_BLOCK_MAX_FRAME_BYTES: usize = 256 * 1024;
pub(crate) const SERVICE_IPC_REQUEST_TIMEOUT_MS: u64 = 1_000;
#[cfg(target_os = "linux")]
pub(crate) const PULSE_AUDIO_IPC_IO_TIMEOUT_MS: u64 = 1_000;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) const WHITEBOARD_IPC_IO_TIMEOUT_MS: u64 = 1_000;
pub(crate) const DESKTOP_URL_IPC_IO_TIMEOUT_MS: u64 = 1_000;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const MAIN_IPC_TRANSACTION_TIMEOUT_MS: u64 = 2_000;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const MAIN_IPC_MAX_OPTION_COUNT: usize = 64;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const MAIN_IPC_MAX_OPTION_VALUE_BYTES: usize = 4 * 1024;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const MAIN_IPC_MAX_ID_BYTES: usize = 256;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const MAIN_IPC_MAX_CONFIG_VALUE_BYTES: usize = 64 * 1024;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const MAIN_IPC_MAX_AUTH_TOKEN_BYTES: usize = 4 * 1024;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const PASSWORD_MUTATION_ID_BYTES: usize = 36;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const PASSWORD_MUTATION_RESULT_BUDGET: usize = 64;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
/// Maximum time a client may spend resolving one admitted password mutation.
pub const PASSWORD_MUTATION_RECOVERY_TIMEOUT_SECONDS: u64 = 600;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const PASSWORD_MUTATION_RECOVERY_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(PASSWORD_MUTATION_RECOVERY_TIMEOUT_SECONDS);
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) const UNATTENDED_PASSWORD_MAX_BYTES: usize = 4096;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) use password::{zeroize_sensitive_bytes, SensitivePassword};
#[cfg(not(any(target_os = "android", target_os = "ios")))]
type MainPasswordMutationValue = SensitivePassword;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const SERVICE_IPC_TRANSACTION_BUDGET: usize = 4;
#[cfg(any(target_os = "linux", target_os = "macos"))]
static SERVICE_IPC_TRANSACTION_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
#[cfg(any(target_os = "linux", target_os = "macos"))]
const SERVICE_PASSWORD_IPC_TRANSACTION_BUDGET: usize = 4;
#[cfg(any(target_os = "linux", target_os = "macos"))]
static SERVICE_PASSWORD_IPC_TRANSACTION_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
#[cfg(any(target_os = "linux", target_os = "macos"))]
const SERVICE_CREDENTIAL_IPC_TRANSACTION_BUDGET: usize = 2;
#[cfg(any(target_os = "linux", target_os = "macos"))]
static SERVICE_CREDENTIAL_IPC_TRANSACTION_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
#[cfg(any(target_os = "linux", target_os = "macos"))]
const MAIN_PASSWORD_IPC_TRANSACTION_BUDGET: usize = 16;
#[cfg(any(target_os = "linux", target_os = "macos"))]
static MAIN_PASSWORD_IPC_TRANSACTION_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const MAIN_IPC_TRANSACTION_BUDGET: usize = 16;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
static MAIN_IPC_TRANSACTION_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const MAIN_IPC_BLOCKING_MUTATION_BUDGET: usize = 1;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
static MAIN_IPC_BLOCKING_MUTATION_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
#[cfg(not(any(target_os = "android", target_os = "ios")))]
static PASSWORD_MUTATIONS: OnceLock<Arc<PasswordMutationCoordinator>> = OnceLock::new();
#[cfg(target_os = "linux")]
static LINUX_PASSWORD_ADMISSIONS: OnceLock<Arc<LinuxPasswordAdmissionCoordinator>> =
    OnceLock::new();
#[cfg(not(any(target_os = "android", target_os = "ios")))]
static MAIN_IPC_LISTENER_STATE: AtomicU8 = AtomicU8::new(0);
#[cfg(any(target_os = "linux", target_os = "macos"))]
static SERVICE_IPC_LISTENER_STATE: AtomicU8 = AtomicU8::new(0);
#[cfg(target_os = "windows")]
static WINDOWS_SERVICE_MAIN_LISTENER_STATE: AtomicU8 = AtomicU8::new(0);

/// The desktop controlled-server's one native local-IPC worker. The worker owns its
/// current-thread Tokio runtime; the async controlled-server owner retains readiness,
/// completion, and the exact native thread until shutdown is complete.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) struct DesktopIpcWorker {
    readiness: oneshot::Receiver<Result<(), String>>,
    completion: oneshot::Receiver<Result<(), String>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl DesktopIpcWorker {
    pub(crate) fn startup_receivers(
        &mut self,
    ) -> (
        &mut oneshot::Receiver<Result<(), String>>,
        &mut oneshot::Receiver<Result<(), String>>,
    ) {
        (&mut self.readiness, &mut self.completion)
    }

    pub(crate) async fn wait_for_completion(&mut self) -> Result<(), String> {
        (&mut self.completion)
            .await
            .map_err(|_| "desktop IPC worker ended without reporting an outcome".to_owned())?
    }

    pub(crate) async fn join(mut self) -> Result<(), String> {
        let thread = self
            .thread
            .take()
            .ok_or_else(|| "desktop IPC worker ownership was already consumed".to_owned())?;
        tokio::task::spawn_blocking(move || thread.join())
            .await
            .map_err(|err| format!("desktop IPC join task failed: {err}"))?
            .map_err(|_| "desktop IPC worker panicked".to_owned())
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) fn spawn_desktop_ipc_worker() -> ResultType<DesktopIpcWorker> {
    let (readiness_tx, readiness) = oneshot::channel();
    let (completion_tx, completion) = oneshot::channel();
    let thread = std::thread::Builder::new()
        .name("rustdesk-desktop-ipc".to_owned())
        .spawn(move || {
            let outcome = run_desktop_ipc(readiness_tx).map_err(|err| err.to_string());
            if completion_tx.send(outcome).is_err() {
                log::error!("Desktop IPC worker completed after its lifecycle owner was lost");
            }
        })
        .map_err(|err| hbb_common::anyhow::anyhow!("failed to spawn desktop IPC worker: {err}"))?;
    Ok(DesktopIpcWorker {
        readiness,
        completion,
        thread: Some(thread),
    })
}

#[cfg(target_os = "windows")]
const WINDOWS_SERVICE_CREDENTIAL_TRANSACTION_BUDGET: usize = 6;
#[cfg(target_os = "windows")]
const WINDOWS_SERVICE_MAIN_CONTROL_TRANSACTION_BUDGET: usize = 2;
#[cfg(target_os = "windows")]
const WINDOWS_SERVICE_MAIN_TRANSACTION_DRAIN_TIMEOUT_MS: u64 = 3_000;
#[cfg(target_os = "windows")]
const WINDOWS_CREDENTIAL_SNAPSHOT_COMPONENT_MAX_BYTES: usize = 16 * 1024;
#[cfg(target_os = "windows")]
static WINDOWS_SERVICE_CREDENTIAL_TRANSACTION_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
#[cfg(target_os = "windows")]
static WINDOWS_SERVICE_MAIN_CONTROL_TRANSACTION_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
#[cfg(any(target_os = "linux", target_os = "macos"))]
const PRIVILEGED_MAIN_IPC_TRANSACTION_BUDGET: usize = 2;
#[cfg(any(target_os = "linux", target_os = "macos"))]
static PRIVILEGED_MAIN_IPC_TRANSACTION_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
#[cfg(target_os = "macos")]
const MACOS_SERVICE_IPC_AUTHORIZATION_BUDGET: usize = 4;
#[cfg(target_os = "macos")]
static MACOS_SERVICE_IPC_AUTHORIZATION_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
#[cfg(target_os = "macos")]
const MACOS_SERVICE_PASSWORD_IPC_AUTHORIZATION_BUDGET: usize = 4;
#[cfg(target_os = "macos")]
static MACOS_SERVICE_PASSWORD_IPC_AUTHORIZATION_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
#[cfg(target_os = "macos")]
const MACOS_SERVICE_CREDENTIAL_IPC_AUTHORIZATION_BUDGET: usize = 2;
#[cfg(target_os = "macos")]
static MACOS_SERVICE_CREDENTIAL_IPC_AUTHORIZATION_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();

#[cfg(windows)]
use std::{
    ffi::OsStr,
    os::windows::{ffi::OsStrExt, io::RawHandle},
};
#[cfg(windows)]
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{CloseHandle, ERROR_PIPE_BUSY},
        Storage::FileSystem::{
            CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_OVERLAPPED, FILE_SHARE_MODE,
            OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
        },
    },
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
thread_local! {
    static USE_USER_MAIN_IPC: Cell<bool> = Cell::new(false);
}

#[must_use = "bind this guard to a local variable to keep the IPC scope active"]
/// Thread-local guard for routing root main IPC to the active user on Linux/macOS.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) struct UserMainIpcScope {
    previous: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl UserMainIpcScope {
    pub(crate) fn new() -> Self {
        let previous = USE_USER_MAIN_IPC.with(|use_user_main| {
            let previous = use_user_main.get();
            use_user_main.set(true);
            previous
        });
        Self { previous }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for UserMainIpcScope {
    fn drop(&mut self) {
        USE_USER_MAIN_IPC.with(|use_user_main| use_user_main.set(self.previous));
    }
}

#[cfg(target_os = "macos")]
fn try_acquire_macos_service_ipc_authorization_slot() -> Option<OwnedSemaphorePermit> {
    let semaphore = MACOS_SERVICE_IPC_AUTHORIZATION_SLOTS
        .get_or_init(|| Arc::new(Semaphore::new(MACOS_SERVICE_IPC_AUTHORIZATION_BUDGET)))
        .clone();
    match semaphore.try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(_) => {
            log::debug!(
                "Rejected macOS _service IPC connection because service authorization work is at capacity"
            );
            None
        }
    }
}

#[cfg(target_os = "macos")]
fn try_acquire_macos_service_password_ipc_authorization_slot() -> Option<OwnedSemaphorePermit> {
    let semaphore = MACOS_SERVICE_PASSWORD_IPC_AUTHORIZATION_SLOTS
        .get_or_init(|| {
            Arc::new(Semaphore::new(
                MACOS_SERVICE_PASSWORD_IPC_AUTHORIZATION_BUDGET,
            ))
        })
        .clone();
    match semaphore.try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(_) => {
            log::debug!(
                "Rejected macOS service password IPC connection because password authorization work is at capacity"
            );
            None
        }
    }
}

#[cfg(target_os = "macos")]
fn try_acquire_macos_service_credential_ipc_authorization_slot() -> Option<OwnedSemaphorePermit> {
    let semaphore = MACOS_SERVICE_CREDENTIAL_IPC_AUTHORIZATION_SLOTS
        .get_or_init(|| {
            Arc::new(Semaphore::new(
                MACOS_SERVICE_CREDENTIAL_IPC_AUTHORIZATION_BUDGET,
            ))
        })
        .clone();
    match semaphore.try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(_) => {
            log::debug!(
                "Rejected macOS service credential IPC connection because credential authorization work is at capacity"
            );
            None
        }
    }
}

#[cfg(target_os = "macos")]
struct MacosSecurityProofWorker {
    worker: Option<std::thread::JoinHandle<()>>,
}

#[cfg(target_os = "macos")]
impl MacosSecurityProofWorker {
    fn finish(mut self) {
        let Some(worker) = self.worker.take() else {
            std::process::abort();
        };
        if worker.join().is_err() {
            log::error!("macOS Security.framework proof worker panicked");
            std::process::abort();
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacosSecurityProofWorker {
    fn drop(&mut self) {
        if self.worker.is_some() {
            log::error!("macOS Security.framework proof lost exact worker ownership");
            std::process::abort();
        }
    }
}

#[cfg(target_os = "macos")]
async fn run_bounded_macos_security_proof<T, F>(
    deadline: tokio::time::Instant,
    thread_name: &'static str,
    proof: F,
) -> ResultType<T>
where
    T: Send + 'static,
    F: FnOnce() -> ResultType<T> + Send + 'static,
{
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    let worker = std::thread::Builder::new()
        .name(thread_name.to_owned())
        .spawn(move || {
            let result = proof();
            let _ = result_tx.send(result);
        })
        .map_err(|err| anyhow!("Could not start macOS Security.framework proof worker: {err}"))?;
    let owner = MacosSecurityProofWorker {
        worker: Some(worker),
    };
    let result = match tokio::time::timeout_at(deadline, result_rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => {
            log::error!("macOS Security.framework proof worker ended without a result");
            std::process::abort();
        }
        Err(_) => {
            log::error!("macOS Security.framework proof exceeded its absolute deadline");
            std::process::abort();
        }
    };
    owner.finish();
    result
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn try_acquire_service_ipc_transaction_slot() -> Option<OwnedSemaphorePermit> {
    let semaphore = SERVICE_IPC_TRANSACTION_SLOTS
        .get_or_init(|| Arc::new(Semaphore::new(SERVICE_IPC_TRANSACTION_BUDGET)))
        .clone();
    match semaphore.try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(_) => {
            log::debug!("Rejected _service IPC connection because service work is at capacity");
            None
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn try_acquire_service_password_ipc_transaction_slot() -> Option<OwnedSemaphorePermit> {
    let semaphore = SERVICE_PASSWORD_IPC_TRANSACTION_SLOTS
        .get_or_init(|| Arc::new(Semaphore::new(SERVICE_PASSWORD_IPC_TRANSACTION_BUDGET)))
        .clone();
    match semaphore.try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(_) => {
            log::debug!(
                "Rejected _service_password IPC connection because password work is at capacity"
            );
            None
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn try_acquire_service_credential_ipc_transaction_slot() -> Option<OwnedSemaphorePermit> {
    let semaphore = SERVICE_CREDENTIAL_IPC_TRANSACTION_SLOTS
        .get_or_init(|| Arc::new(Semaphore::new(SERVICE_CREDENTIAL_IPC_TRANSACTION_BUDGET)))
        .clone();
    match semaphore.try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(_) => {
            log::debug!(
                "Rejected _service_credential IPC connection because credential replica work is at capacity"
            );
            None
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn try_acquire_main_ipc_transaction_slot(stream: &Connection) -> Option<OwnedSemaphorePermit> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let (slots, description) = if stream.peer_uid() == Some(0) {
        (
            PRIVILEGED_MAIN_IPC_TRANSACTION_SLOTS
                .get_or_init(|| Arc::new(Semaphore::new(PRIVILEGED_MAIN_IPC_TRANSACTION_BUDGET))),
            "privileged main IPC",
        )
    } else {
        (
            MAIN_IPC_TRANSACTION_SLOTS
                .get_or_init(|| Arc::new(Semaphore::new(MAIN_IPC_TRANSACTION_BUDGET))),
            "main IPC",
        )
    };
    #[cfg(target_os = "windows")]
    let (slots, description) = (
        MAIN_IPC_TRANSACTION_SLOTS
            .get_or_init(|| Arc::new(Semaphore::new(MAIN_IPC_TRANSACTION_BUDGET))),
        "main IPC",
    );

    match slots.clone().try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(_) => {
            log::debug!("Rejected {description} connection because work is at capacity");
            None
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn try_acquire_sensitive_main_ipc_transaction_slot(
    kind: PasswordMutationKind,
) -> Option<OwnedSemaphorePermit> {
    let description = match kind {
        PasswordMutationKind::ServiceOwned => "privileged main password IPC",
        PasswordMutationKind::UserOwned => "main password IPC",
    };
    let slots = MAIN_PASSWORD_IPC_TRANSACTION_SLOTS
        .get_or_init(|| Arc::new(Semaphore::new(MAIN_PASSWORD_IPC_TRANSACTION_BUDGET)));

    match slots.clone().try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(_) => {
            log::debug!("Rejected {description} connection because work is at capacity");
            None
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn try_acquire_main_ipc_blocking_mutation_slot() -> Option<OwnedSemaphorePermit> {
    MAIN_IPC_BLOCKING_MUTATION_SLOTS
        .get_or_init(|| Arc::new(Semaphore::new(MAIN_IPC_BLOCKING_MUTATION_BUDGET)))
        .clone()
        .try_acquire_owned()
        .ok()
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct LocalIpcListenerGuard {
    state: &'static AtomicU8,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl LocalIpcListenerGuard {
    fn activate(state: &'static AtomicU8, description: &str) -> ResultType<Self> {
        state
            .compare_exchange(0, 1, AtomicOrdering::AcqRel, AtomicOrdering::Acquire)
            .map_err(|_| hbb_common::anyhow::anyhow!("{description} started more than once"))?;
        Ok(Self { state })
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl Drop for LocalIpcListenerGuard {
    fn drop(&mut self) {
        self.state.store(2, AtomicOrdering::Release);
    }
}

#[cfg(target_os = "windows")]
#[derive(Clone, Copy, Eq, PartialEq)]
enum WindowsServiceMainEndpoint {
    Credential,
    Control,
}

#[cfg(target_os = "windows")]
fn try_acquire_windows_service_main_transaction_slot(
    endpoint: WindowsServiceMainEndpoint,
) -> Option<OwnedSemaphorePermit> {
    let slots = match endpoint {
        WindowsServiceMainEndpoint::Credential => WINDOWS_SERVICE_CREDENTIAL_TRANSACTION_SLOTS
            .get_or_init(|| {
                Arc::new(Semaphore::new(
                    WINDOWS_SERVICE_CREDENTIAL_TRANSACTION_BUDGET,
                ))
            }),
        WindowsServiceMainEndpoint::Control => WINDOWS_SERVICE_MAIN_CONTROL_TRANSACTION_SLOTS
            .get_or_init(|| {
                Arc::new(Semaphore::new(
                    WINDOWS_SERVICE_MAIN_CONTROL_TRANSACTION_BUDGET,
                ))
            }),
    };
    slots.clone().try_acquire_owned().ok()
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PasswordMutationKind {
    UserOwned,
    ServiceOwned,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PasswordMutationState {
    Prepared,
    Pending,
    Complete(IpcMutationResult, std::time::Instant),
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct PasswordMutationFingerprint(hbb_common::sodiumoxide::crypto::auth::hmacsha256::Tag);

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl PartialEq for PasswordMutationFingerprint {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl Eq for PasswordMutationFingerprint {}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl Drop for PasswordMutationFingerprint {
    fn drop(&mut self) {
        zeroize_sensitive_bytes(&mut self.0 .0);
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct PasswordMutationEntry {
    kind: PasswordMutationKind,
    fingerprint: PasswordMutationFingerprint,
    state: PasswordMutationState,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct PasswordMutationLedger {
    shutting_down: bool,
    fingerprint_key: hbb_common::sodiumoxide::crypto::auth::hmacsha256::Key,
    entries: HashMap<String, PasswordMutationEntry>,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl PasswordMutationLedger {
    fn new() -> Self {
        Self {
            shutting_down: false,
            fingerprint_key: hbb_common::sodiumoxide::crypto::auth::hmacsha256::gen_key(),
            entries: HashMap::new(),
        }
    }

    fn fingerprint(&self, value: &str) -> PasswordMutationFingerprint {
        password_mutation_fingerprint(&self.fingerprint_key, value)
    }

    fn clear_sensitive_state(&mut self) {
        self.entries.clear();
        zeroize_sensitive_bytes(&mut self.fingerprint_key.0);
    }

    fn evict_oldest_complete(&mut self) -> bool {
        let oldest = self
            .entries
            .iter()
            .filter_map(|(operation_id, entry)| match entry.state {
                PasswordMutationState::Complete(_, completed_at) => {
                    Some((operation_id.clone(), completed_at))
                }
                PasswordMutationState::Prepared | PasswordMutationState::Pending => None,
            })
            .min_by_key(|(_, completed_at)| *completed_at)
            .map(|(operation_id, _)| operation_id);
        oldest
            .and_then(|operation_id| self.entries.remove(&operation_id))
            .is_some()
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct PasswordMutationCoordinator {
    ledger: std::sync::Mutex<PasswordMutationLedger>,
    changed: Notify,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct PasswordMutationPreparation {
    status: PasswordMutationStatus,
    owns_preparation: bool,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct LinuxPasswordCaller {
    pid: u32,
    uid: u32,
    start_time: String,
}

#[cfg(target_os = "linux")]
impl From<&PeerProcessIdentity> for LinuxPasswordCaller {
    fn from(identity: &PeerProcessIdentity) -> Self {
        Self {
            pid: identity.pid(),
            uid: identity.uid(),
            start_time: identity.start_time().to_owned(),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinuxPasswordAdmissionState {
    Authorizing,
    Committing,
    Recoverable,
    Complete(IpcMutationResult, std::time::Instant),
}

#[cfg(target_os = "linux")]
struct LinuxPasswordAdmissionEntry {
    kind: PasswordMutationKind,
    fingerprint: PasswordMutationFingerprint,
    caller: LinuxPasswordCaller,
    state: LinuxPasswordAdmissionState,
}

#[cfg(target_os = "linux")]
struct LinuxPasswordAdmissionLedger {
    shutting_down: bool,
    fingerprint_key: hbb_common::sodiumoxide::crypto::auth::hmacsha256::Key,
    entries: HashMap<String, LinuxPasswordAdmissionEntry>,
}

#[cfg(target_os = "linux")]
impl LinuxPasswordAdmissionLedger {
    fn new() -> Self {
        Self {
            shutting_down: false,
            fingerprint_key: hbb_common::sodiumoxide::crypto::auth::hmacsha256::gen_key(),
            entries: HashMap::new(),
        }
    }

    fn fingerprint(&self, value: &str) -> PasswordMutationFingerprint {
        password_mutation_fingerprint(&self.fingerprint_key, value)
    }

    fn clear_sensitive_state(&mut self) {
        self.entries.clear();
        zeroize_sensitive_bytes(&mut self.fingerprint_key.0);
    }

    fn evict_oldest_complete(&mut self) -> bool {
        let oldest = self
            .entries
            .iter()
            .filter_map(|(operation_id, entry)| match entry.state {
                LinuxPasswordAdmissionState::Complete(_, completed_at) => {
                    Some((operation_id.clone(), completed_at))
                }
                LinuxPasswordAdmissionState::Authorizing
                | LinuxPasswordAdmissionState::Committing
                | LinuxPasswordAdmissionState::Recoverable => None,
            })
            .min_by_key(|(_, completed_at)| *completed_at)
            .map(|(operation_id, _)| operation_id);
        oldest
            .and_then(|operation_id| self.entries.remove(&operation_id))
            .is_some()
    }
}

#[cfg(target_os = "linux")]
struct LinuxPasswordAdmissionCoordinator {
    ledger: std::sync::Mutex<LinuxPasswordAdmissionLedger>,
    changed: Notify,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinuxPasswordAdmissionDecision {
    Authorize,
    Wait,
    Recover,
    Complete(IpcMutationResult),
    Rejected,
    ShuttingDown,
}

#[cfg(target_os = "linux")]
impl LinuxPasswordAdmissionCoordinator {
    fn new() -> Self {
        Self {
            ledger: std::sync::Mutex::new(LinuxPasswordAdmissionLedger::new()),
            changed: Notify::new(),
        }
    }

    fn begin(
        &self,
        operation_id: &str,
        kind: PasswordMutationKind,
        value: &str,
        caller: &LinuxPasswordCaller,
    ) -> LinuxPasswordAdmissionDecision {
        let mut ledger = self.ledger.lock().unwrap();
        let fingerprint = ledger.fingerprint(value);
        if let Some(entry) = ledger.entries.get_mut(operation_id) {
            if entry.kind != kind || entry.fingerprint != fingerprint || entry.caller != *caller {
                return LinuxPasswordAdmissionDecision::Rejected;
            }
            return match entry.state {
                LinuxPasswordAdmissionState::Authorizing
                | LinuxPasswordAdmissionState::Committing => LinuxPasswordAdmissionDecision::Wait,
                LinuxPasswordAdmissionState::Recoverable => {
                    entry.state = LinuxPasswordAdmissionState::Committing;
                    LinuxPasswordAdmissionDecision::Recover
                }
                LinuxPasswordAdmissionState::Complete(result, _) => {
                    LinuxPasswordAdmissionDecision::Complete(result)
                }
            };
        }
        if ledger.shutting_down {
            return LinuxPasswordAdmissionDecision::ShuttingDown;
        }
        if ledger.entries.len() >= PASSWORD_MUTATION_RESULT_BUDGET
            && !ledger.evict_oldest_complete()
        {
            return LinuxPasswordAdmissionDecision::Rejected;
        }
        ledger.entries.insert(
            operation_id.to_owned(),
            LinuxPasswordAdmissionEntry {
                kind,
                fingerprint,
                caller: caller.clone(),
                state: LinuxPasswordAdmissionState::Authorizing,
            },
        );
        LinuxPasswordAdmissionDecision::Authorize
    }

    fn finish_authorization(
        &self,
        operation_id: &str,
        caller: &LinuxPasswordCaller,
        admitted: bool,
    ) -> bool {
        let mut ledger = self.ledger.lock().unwrap();
        let Some(entry) = ledger.entries.get_mut(operation_id) else {
            return false;
        };
        if entry.caller != *caller || entry.state != LinuxPasswordAdmissionState::Authorizing {
            return false;
        }
        if admitted {
            entry.state = LinuxPasswordAdmissionState::Committing;
        } else {
            ledger.entries.remove(operation_id);
        }
        drop(ledger);
        self.changed.notify_waiters();
        true
    }

    fn complete(
        &self,
        operation_id: &str,
        caller: &LinuxPasswordCaller,
        result: IpcMutationResult,
    ) -> bool {
        let mut ledger = self.ledger.lock().unwrap();
        let Some(entry) = ledger.entries.get_mut(operation_id) else {
            return false;
        };
        if entry.caller != *caller {
            return false;
        }
        if let LinuxPasswordAdmissionState::Complete(existing, _) = entry.state {
            return existing == result;
        }
        if entry.state != LinuxPasswordAdmissionState::Committing {
            return false;
        }
        entry.state = LinuxPasswordAdmissionState::Complete(result, std::time::Instant::now());
        drop(ledger);
        self.changed.notify_waiters();
        true
    }

    fn release_failed_commit(&self, operation_id: &str, caller: &LinuxPasswordCaller) -> bool {
        let mut ledger = self.ledger.lock().unwrap();
        let Some(entry) = ledger.entries.get_mut(operation_id) else {
            return false;
        };
        if entry.caller != *caller || entry.state != LinuxPasswordAdmissionState::Committing {
            return false;
        }
        entry.state = LinuxPasswordAdmissionState::Recoverable;
        drop(ledger);
        self.changed.notify_waiters();
        true
    }

    fn begin_shutdown(&self) {
        let mut ledger = self.ledger.lock().unwrap();
        ledger.shutting_down = true;
        drop(ledger);
        self.changed.notify_waiters();
    }

    fn clear_after_transactions_drain(&self) {
        let mut ledger = self.ledger.lock().unwrap();
        if !ledger
            .entries
            .values()
            .all(|entry| matches!(entry.state, LinuxPasswordAdmissionState::Complete(_, _)))
        {
            log::error!(
                "Linux password admission transactions drained with unresolved authority; terminating instead of evicting replay authority"
            );
            std::process::abort();
        }
        ledger.clear_sensitive_state();
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl PasswordMutationCoordinator {
    fn new() -> Self {
        Self {
            ledger: std::sync::Mutex::new(PasswordMutationLedger::new()),
            changed: Notify::new(),
        }
    }

    fn prepare_if_allowed(
        &self,
        operation_id: &str,
        kind: PasswordMutationKind,
        value: &str,
        admission_allowed: bool,
    ) -> PasswordMutationPreparation {
        if !password_mutation_id_is_valid(operation_id) {
            return PasswordMutationPreparation {
                status: PasswordMutationStatus::Complete(IpcMutationResult::Rejected),
                owns_preparation: false,
            };
        }
        let mut ledger = self.ledger.lock().unwrap();
        let fingerprint = ledger.fingerprint(value);
        if let Some(entry) = ledger.entries.get(operation_id) {
            if entry.kind != kind || entry.fingerprint != fingerprint {
                return PasswordMutationPreparation {
                    status: PasswordMutationStatus::Complete(IpcMutationResult::Rejected),
                    owns_preparation: false,
                };
            }
            return PasswordMutationPreparation {
                status: password_mutation_status(entry.state),
                owns_preparation: false,
            };
        }
        if !admission_allowed {
            return PasswordMutationPreparation {
                status: PasswordMutationStatus::Complete(IpcMutationResult::Rejected),
                owns_preparation: false,
            };
        }
        if ledger.shutting_down {
            return PasswordMutationPreparation {
                status: PasswordMutationStatus::ShuttingDown,
                owns_preparation: false,
            };
        }
        if ledger.entries.len() >= PASSWORD_MUTATION_RESULT_BUDGET
            && !ledger.evict_oldest_complete()
        {
            return PasswordMutationPreparation {
                status: PasswordMutationStatus::Complete(IpcMutationResult::Rejected),
                owns_preparation: false,
            };
        }
        ledger.entries.insert(
            operation_id.to_owned(),
            PasswordMutationEntry {
                kind,
                fingerprint,
                state: PasswordMutationState::Prepared,
            },
        );
        PasswordMutationPreparation {
            status: PasswordMutationStatus::Prepared,
            owns_preparation: true,
        }
    }

    #[cfg(test)]
    fn prepare(
        &self,
        operation_id: &str,
        kind: PasswordMutationKind,
        value: &str,
    ) -> PasswordMutationPreparation {
        self.prepare_if_allowed(operation_id, kind, value, true)
    }

    fn acknowledge(&self, operation_id: &str, kind: PasswordMutationKind, value: &str) -> bool {
        let mut ledger = self.ledger.lock().unwrap();
        let fingerprint = ledger.fingerprint(value);
        let Some(entry) = ledger.entries.get_mut(operation_id) else {
            return false;
        };
        if entry.kind != kind
            || entry.fingerprint != fingerprint
            || entry.state != PasswordMutationState::Prepared
        {
            return false;
        }
        entry.state = PasswordMutationState::Pending;
        true
    }

    fn complete(&self, operation_id: &str, kind: PasswordMutationKind, result: IpcMutationResult) {
        let mut ledger = self.ledger.lock().unwrap();
        let Some(entry) = ledger.entries.get_mut(operation_id) else {
            log::error!("password mutation completed without a ledger entry");
            return;
        };
        if entry.kind != kind || entry.state != PasswordMutationState::Pending {
            log::error!("password mutation completed from an invalid ledger state");
            return;
        }
        entry.state = PasswordMutationState::Complete(result, std::time::Instant::now());
        drop(ledger);
        self.changed.notify_waiters();
    }

    fn fail_admitted(&self, operation_id: &str, kind: PasswordMutationKind, value: &str) -> bool {
        let mut ledger = self.ledger.lock().unwrap();
        let fingerprint = ledger.fingerprint(value);
        let Some(entry) = ledger.entries.get_mut(operation_id) else {
            return false;
        };
        if entry.kind != kind
            || entry.fingerprint != fingerprint
            || !matches!(
                entry.state,
                PasswordMutationState::Prepared | PasswordMutationState::Pending
            )
        {
            return false;
        }
        entry.state = PasswordMutationState::Complete(
            IpcMutationResult::InternalFailure,
            std::time::Instant::now(),
        );
        drop(ledger);
        self.changed.notify_waiters();
        true
    }

    fn status(&self, operation_id: &str, kind: PasswordMutationKind) -> PasswordMutationStatus {
        if !password_mutation_id_is_valid(operation_id) {
            return PasswordMutationStatus::Unknown;
        }
        let ledger = self.ledger.lock().unwrap();
        ledger
            .entries
            .get(operation_id)
            .filter(|entry| entry.kind == kind)
            .map(|entry| password_mutation_status(entry.state))
            .unwrap_or(PasswordMutationStatus::Unknown)
    }

    #[cfg(target_os = "windows")]
    fn classify_during_shutdown(
        &self,
        operation_id: &str,
        kind: PasswordMutationKind,
        value: &str,
    ) -> PasswordMutationStatus {
        let ledger = self.ledger.lock().unwrap();
        let fingerprint = ledger.fingerprint(value);
        match ledger.entries.get(operation_id) {
            Some(entry) if entry.kind == kind && entry.fingerprint == fingerprint => {
                password_mutation_status(entry.state)
            }
            Some(_) => PasswordMutationStatus::Complete(IpcMutationResult::Rejected),
            None => PasswordMutationStatus::ShuttingDown,
        }
    }

    fn begin_shutdown(&self) {
        let mut ledger = self.ledger.lock().unwrap();
        ledger.shutting_down = true;
        drop(ledger);
        self.changed.notify_waiters();
    }

    async fn drain(&self) {
        loop {
            let notified = self.changed.notified();
            let drained = {
                let ledger = self.ledger.lock().unwrap();
                ledger
                    .entries
                    .values()
                    .all(|entry| matches!(entry.state, PasswordMutationState::Complete(_, _)))
            };
            if drained {
                return;
            }
            notified.await;
        }
    }

    fn clear_after_transactions_drain(&self) {
        let mut ledger = self.ledger.lock().unwrap();
        if !ledger
            .entries
            .values()
            .all(|entry| matches!(entry.state, PasswordMutationState::Complete(_, _)))
        {
            log::error!("Password mutation transactions drained with unresolved replay authority");
            std::process::abort();
        }
        ledger.clear_sensitive_state();
    }

    async fn wait_for_complete(
        &self,
        operation_id: &str,
        kind: PasswordMutationKind,
    ) -> Option<IpcMutationResult> {
        loop {
            let notified = self.changed.notified();
            match self.status(operation_id, kind) {
                PasswordMutationStatus::Complete(result) => return Some(result),
                PasswordMutationStatus::Prepared | PasswordMutationStatus::Pending => {}
                PasswordMutationStatus::Unknown | PasswordMutationStatus::ShuttingDown => {
                    return None
                }
            }
            notified.await;
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct PasswordMutationCompletion {
    coordinator: Arc<PasswordMutationCoordinator>,
    operation_id: String,
    kind: PasswordMutationKind,
    result: IpcMutationResult,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl Drop for PasswordMutationCompletion {
    fn drop(&mut self) {
        self.coordinator
            .complete(&self.operation_id, self.kind, self.result);
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn spawn_password_mutation(
    operation_id: String,
    value: MainPasswordMutationValue,
    kind: PasswordMutationKind,
    permit: OwnedSemaphorePermit,
) -> tokio::task::JoinHandle<IpcMutationResult> {
    let coordinator = Arc::clone(password_mutations());
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut completion = PasswordMutationCompletion {
            coordinator,
            operation_id,
            kind,
            result: IpcMutationResult::InternalFailure,
        };
        #[cfg(target_os = "linux")]
        let service_owned_runtime_replica = kind == PasswordMutationKind::ServiceOwned
            && crate::common::is_service_owned_server_process();
        #[cfg(not(target_os = "linux"))]
        let service_owned_runtime_replica = false;
        let persisted = if service_owned_runtime_replica {
            Config::set_permanent_password_prs_for_runtime(value.as_str()).map(|_| true)
        } else {
            Config::set_permanent_password_persisted(value.as_str())
        };
        let result = match persisted {
            Ok(true) => IpcMutationResult::Applied,
            Ok(false) => IpcMutationResult::Rejected,
            Err(err) => {
                log::error!("password mutation persistence failed: {err}");
                IpcMutationResult::InternalFailure
            }
        };
        completion.result = result;
        result
    })
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn password_mutations() -> &'static Arc<PasswordMutationCoordinator> {
    PASSWORD_MUTATIONS.get_or_init(|| Arc::new(PasswordMutationCoordinator::new()))
}

#[cfg(target_os = "linux")]
fn linux_password_admissions() -> &'static Arc<LinuxPasswordAdmissionCoordinator> {
    LINUX_PASSWORD_ADMISSIONS.get_or_init(|| Arc::new(LinuxPasswordAdmissionCoordinator::new()))
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) fn password_mutation_id_is_valid(operation_id: &str) -> bool {
    operation_id.len() == PASSWORD_MUTATION_ID_BYTES
        && hbb_common::uuid::Uuid::parse_str(operation_id)
            .is_ok_and(|id| id.to_string() == operation_id)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn password_mutation_fingerprint(
    key: &hbb_common::sodiumoxide::crypto::auth::hmacsha256::Key,
    value: &str,
) -> PasswordMutationFingerprint {
    PasswordMutationFingerprint(
        hbb_common::sodiumoxide::crypto::auth::hmacsha256::authenticate(value.as_bytes(), key),
    )
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn password_mutation_status(state: PasswordMutationState) -> PasswordMutationStatus {
    match state {
        PasswordMutationState::Prepared => PasswordMutationStatus::Prepared,
        PasswordMutationState::Pending => PasswordMutationStatus::Pending,
        PasswordMutationState::Complete(result, _) => PasswordMutationStatus::Complete(result),
    }
}

#[cfg(target_os = "macos")]
async fn authorize_macos_service_scoped_ipc_connection_for_task(
    stream: &Connection,
    postfix: &str,
    _authorization_slot: OwnedSemaphorePermit,
    deadline: tokio::time::Instant,
) -> bool {
    let authorization = ipc_auth::service_scoped_ipc_authorization_snapshot(stream, postfix);
    match run_bounded_macos_security_proof(deadline, "macos-service-ipc-proof", move || {
        Ok(ipc_auth::authorize_service_scoped_ipc_authorization_snapshot(authorization))
    })
    .await
    {
        Ok(authorized) => authorized,
        Err(err) => {
            log::error!("macOS _service IPC authorization task failed: {err}");
            false
        }
    }
}

#[cfg(target_os = "macos")]
async fn authorize_macos_service_scoped_password_stream_for_task(
    stream: &Conn,
    postfix: &str,
    _authorization_slot: OwnedSemaphorePermit,
    deadline: tokio::time::Instant,
) -> bool {
    let authorization =
        ipc_auth::service_scoped_ipc_authorization_snapshot_from_stream(stream, postfix);
    match run_bounded_macos_security_proof(deadline, "macos-password-ipc-proof", move || {
        Ok(ipc_auth::authorize_service_scoped_ipc_authorization_snapshot(authorization))
    })
    .await
    {
        Ok(authorized) => authorized,
        Err(err) => {
            log::error!("macOS service password IPC authorization task failed: {err}");
            false
        }
    }
}

#[cfg(target_os = "macos")]
async fn authorize_macos_service_scoped_credential_stream_for_task(
    authorization: ipc_auth::ServiceScopedIpcAuthorization,
    _authorization_slot: OwnedSemaphorePermit,
    deadline: tokio::time::Instant,
) -> bool {
    match run_bounded_macos_security_proof(deadline, "macos-credential-ipc-proof", move || {
        Ok(ipc_auth::authorize_service_scoped_ipc_authorization_snapshot(authorization))
    })
    .await
    {
        Ok(authorized) => authorized,
        Err(err) => {
            log::error!("macOS service credential IPC authorization task failed: {err}");
            false
        }
    }
}

#[cfg(target_os = "macos")]
async fn authorize_macos_service_server_snapshot_for_task(
    authorization: ipc_auth::MacosServiceServerAuthorization,
    deadline: tokio::time::Instant,
) -> ResultType<()> {
    run_bounded_macos_security_proof(deadline, "macos-service-server-proof", move || {
        ipc_auth::authorize_macos_service_server_snapshot(authorization)
    })
    .await
}

#[inline]
pub async fn connect_service(ms_timeout: u64) -> ResultType<ConnectionTmpl<ConnClient>> {
    connect(ms_timeout, crate::POSTFIX_SERVICE).await
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq)]
pub enum CmFileEntryType {
    Directory,
    DirectoryLink,
    DirectoryDrive,
    File,
    FileLink,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct CmFileEntry {
    pub entry_type: CmFileEntryType,
    pub name: String,
    pub is_hidden: bool,
    pub size: u64,
    pub modified_time: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct CmFileDirectory {
    pub id: i32,
    pub path: String,
    pub entries: Vec<CmFileEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum CmFileOperation {
    RemoveDirectory { path: String, recursive: bool },
    RemoveFile { path: String },
    CreateDirectory { path: String },
    Rename { path: String, new_name: String },
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum CmWriteDigestResult {
    SendConfirm {
        skip: bool,
    },
    Digest {
        last_modified: u64,
        file_size: u64,
        is_identical: bool,
        transferred_size: u64,
    },
    Error(String),
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum CmFileResponseKind {
    ReadDirectory {
        request_id: u64,
        path: String,
        result: Result<CmFileDirectory, String>,
    },
    ReadEmptyDirectories {
        request_id: u64,
        path: String,
        result: Result<Vec<CmFileDirectory>, String>,
    },
    Operation {
        request_id: u64,
        operation: CmFileOperation,
        result: Result<(), String>,
    },
    ReadJobInit {
        id: i32,
        generation: u64,
        result: Result<CmFileDirectory, String>,
    },
    ReadBlock {
        id: i32,
        generation: u64,
        file_num: i32,
        #[serde(skip)]
        data: Bytes,
        compressed: bool,
    },
    ReadDone {
        id: i32,
        generation: u64,
        file_num: i32,
    },
    ReadError {
        id: i32,
        generation: u64,
        file_num: i32,
        error: String,
    },
    ReadDigest {
        id: i32,
        generation: u64,
        file_num: i32,
        last_modified: u64,
        file_size: u64,
        is_resume: bool,
    },
    AllFiles {
        request_id: u64,
        result: Result<CmFileDirectory, String>,
    },
    WriteFailed {
        id: i32,
        generation: u64,
        file_num: i32,
        error: String,
    },
    WriteFinalized {
        id: i32,
        generation: u64,
        result: Result<(), String>,
    },
    WriteDigest {
        id: i32,
        generation: u64,
        request_id: u64,
        file_num: i32,
        result: CmWriteDigestResult,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct CmFileResponse {
    pub conn_id: i32,
    pub cm_auth_token: String,
    pub response: Box<CmFileResponseKind>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "t", content = "c")]
pub enum FS {
    ReadEmptyDirs {
        dir: String,
        include_hidden: bool,
        request_id: u64,
    },
    ReadDir {
        dir: String,
        include_hidden: bool,
        request_id: u64,
    },
    RemoveDir {
        path: String,
        id: i32,
        recursive: bool,
        request_id: u64,
    },
    RemoveFile {
        path: String,
        id: i32,
        file_num: i32,
        request_id: u64,
    },
    CreateDir {
        path: String,
        id: i32,
        request_id: u64,
    },
    NewWrite {
        path: String,
        id: i32,
        file_num: i32,
        files: Vec<(String, u64)>,
        overwrite_detection: bool,
        total_size: u64,
        conn_id: i32,
        generation: u64,
    },
    CancelWrite {
        id: i32,
        conn_id: i32,
        generation: u64,
    },
    WriteBlock {
        id: i32,
        file_num: i32,
        conn_id: i32,
        data: Bytes,
        compressed: bool,
        generation: u64,
    },
    WriteDone {
        id: i32,
        file_num: i32,
        conn_id: i32,
        generation: u64,
    },
    WriteError {
        id: i32,
        file_num: i32,
        conn_id: i32,
        err: String,
        generation: u64,
    },
    CheckDigest {
        id: i32,
        file_num: i32,
        conn_id: i32,
        file_size: u64,
        last_modified: u64,
        is_upload: bool,
        is_resume: bool,
        generation: u64,
        request_id: u64,
    },
    SendConfirm {
        id: i32,
        file_num: i32,
        skip: bool,
        offset_blk: u32,
        conn_id: i32,
        generation: u64,
    },
    Rename {
        id: i32,
        path: String,
        new_name: String,
        request_id: u64,
    },
    // CM-side file reading operations (Windows only)
    // These enable Connection Manager to read files and stream them back to Connection
    ReadFile {
        path: String,
        id: i32,
        file_num: i32,
        include_hidden: bool,
        conn_id: i32,
        overwrite_detection: bool,
        generation: u64,
    },
    CancelRead {
        id: i32,
        conn_id: i32,
        generation: u64,
    },
    SendConfirmForRead {
        id: i32,
        file_num: i32,
        skip: bool,
        offset_blk: u32,
        conn_id: i32,
        generation: u64,
    },
    ReadAllFiles {
        path: String,
        id: i32,
        include_hidden: bool,
        conn_id: i32,
        request_id: u64,
    },
}

#[cfg(target_os = "windows")]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "t")]
pub struct ClipboardNonFile {
    pub compress: bool,
    pub content: bytes::Bytes,
    pub content_len: usize,
    pub next_raw: bool,
    pub width: i32,
    pub height: i32,
    // message.proto: ClipboardFormat
    pub format: i32,
    pub special_name: String,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "t", content = "c")]
pub enum DataKeyboard {
    Sequence(String),
    KeyDown(enigo::Key),
    KeyUp(enigo::Key),
    KeyClick(enigo::Key),
    GetKeyState(enigo::Key),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "t", content = "c")]
pub enum DataKeyboardResponse {
    GetKeyState(bool),
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "t", content = "c")]
pub enum DataMouse {
    MoveTo(i32, i32),
    MoveRelative(i32, i32),
    Down(enigo::MouseButton),
    Up(enigo::MouseButton),
    Click(enigo::MouseButton),
    ScrollX(i32),
    ScrollY(i32),
    Refresh,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "t", content = "c")]
pub enum DataControl {
    Resolution {
        minx: i32,
        maxx: i32,
        miny: i32,
        maxy: i32,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(tag = "t")]
pub enum CmAuthConnType {
    Remote,
    FileTransfer,
    ViewCamera,
    Terminal,
    PortForward,
}

impl CmAuthConnType {
    pub(crate) fn allows_file_authority(self) -> bool {
        matches!(self, Self::FileTransfer)
    }

    pub(crate) fn allows_clipboard_authority(self) -> bool {
        matches!(self, Self::Remote)
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(tag = "t", deny_unknown_fields)]
pub(crate) enum ServiceIpcRequest {
    LivenessProbe {},
    #[cfg(target_os = "macos")]
    EnsurePasswordRightReady {},
    #[cfg(target_os = "windows")]
    SetShareRdp { enabled: bool },
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(tag = "t", deny_unknown_fields)]
pub(crate) enum ServiceIpcResponse {
    Liveness {},
    #[cfg(target_os = "macos")]
    PasswordRightReady { ready: bool },
    #[cfg(target_os = "windows")]
    ShareRdpSet { accepted: bool },
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(tag = "t", deny_unknown_fields)]
pub(crate) enum LinuxPulseAudioIpcRequest {
    StartCapture {
        owner: LinuxProcessIdentity,
        token: String,
        source: String,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(tag = "t", deny_unknown_fields)]
pub(crate) enum DesktopUrlIpcRequest {
    OpenUrl { url: String },
    Activate {},
    CloseAll {},
}

impl DesktopUrlIpcRequest {
    fn from_url(url: String) -> ResultType<Self> {
        if url.len() > DESKTOP_URL_IPC_MAX_LINK_BYTES {
            bail!("desktop URL IPC link exceeds its semantic limit");
        }
        if crate::common::is_empty_uni_link(&url) {
            return Ok(Self::Activate {});
        }
        validate_desktop_url_ipc_open_url(&url)?;
        Ok(Self::OpenUrl { url })
    }

    pub(crate) fn validate(self) -> ResultType<Self> {
        if let Self::OpenUrl { url } = &self {
            validate_desktop_url_ipc_open_url(url)?;
        }
        Ok(self)
    }
}

fn validate_desktop_url_ipc_open_url(url: &str) -> ResultType<()> {
    if url.is_empty() || url.len() > DESKTOP_URL_IPC_MAX_LINK_BYTES {
        bail!("desktop URL IPC link is empty or oversized");
    }
    let prefix = crate::get_uri_prefix();
    let Some(remainder) = url.strip_prefix(&prefix) else {
        bail!("desktop URL IPC link has the wrong scheme");
    };
    let Some((authority, address)) = remainder.split_once('/') else {
        bail!("desktop URL IPC link is not a canonical operation/address pair");
    };
    if !matches!(
        authority,
        "connect"
            | "play"
            | "file-transfer"
            | "view-camera"
            | "port-forward"
            | "rdp"
            | "terminal"
    ) {
        bail!("desktop URL IPC link has an unsupported operation");
    }
    if address.is_empty() || address.len() > DESKTOP_URL_IPC_MAX_ADDRESS_BYTES {
        bail!("desktop URL IPC address is empty or oversized");
    }
    if !hbb_common::is_ip_str(address) && !hbb_common::is_domain_port_str(address) {
        bail!("desktop URL IPC address is not a direct address");
    }
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(tag = "t", deny_unknown_fields)]
pub(crate) enum WhiteboardOwnerHandshake {
    ServerProof { proof: String },
    EndpointChallenge { challenge: String },
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(tag = "t", deny_unknown_fields)]
pub(crate) enum WhiteboardHelperHandshake {
    ServerChallenge { challenge: String },
    EndpointProof { proof: String },
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "t", deny_unknown_fields)]
pub(crate) enum WhiteboardIpcCommand {
    Bind {
        conn_id: i32,
        token: String,
    },
    Event {
        conn_id: i32,
        token: String,
        event: crate::whiteboard::CustomEvent,
    },
    Close {
        conn_id: i32,
        token: String,
    },
    Shutdown,
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(tag = "t", deny_unknown_fields)]
pub(crate) enum WindowsServiceSasIpcRequest {
    Dispatch {},
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(tag = "t", deny_unknown_fields)]
pub(crate) enum WindowsServiceSasIpcResponse {
    DispatchAccepted { accepted: bool },
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq, Default)]
pub struct CmConnectionAuthority {
    pub valid: bool,
    pub file: bool,
    pub clipboard: bool,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct CmClipboardAuthority {
    pub id: i32,
    pub conn_type: CmAuthConnType,
    pub cm_auth_token: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "t", content = "c")]
pub enum Data {
    Login {
        id: i32,
        is_file_transfer: bool,
        is_view_camera: bool,
        is_terminal: bool,
        peer_id: String,
        name: String,
        avatar: String,
        authorized: bool,
        port_forward: String,
        conn_type: CmAuthConnType,
        keyboard: bool,
        clipboard: bool,
        audio: bool,
        file: bool,
        file_transfer_enabled: bool,
        privacy_mode: bool,
        cm_auth_token: String,
    },
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    CmEndpointChallenge {
        challenge: String,
    },
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    CmEndpointProof {
        proof: String,
    },
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    CmServerChallenge {
        challenge: String,
    },
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    CmServerProof {
        proof: String,
    },
    ChatMessage {
        text: String,
    },
    ClickTime(i64),
    Close,
    CmFileResponse(CmFileResponse),
    FS(FS),
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    AuthorizedFS {
        cm_auth_token: String,
        fs: FS,
    },
    #[cfg(target_os = "windows")]
    ClipboardFile(ClipboardFile),
    ClipboardFileEnabled(bool),
    #[cfg(target_os = "windows")]
    AuthorizedClipboardNonFile {
        id: i32,
        conn_type: CmAuthConnType,
        cm_auth_token: String,
    },
    #[cfg(target_os = "windows")]
    ClipboardNonFile(Option<(String, Vec<ClipboardNonFile>)>),
    PrivacyModeState((i32, PrivacyModeState, String)),
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    Keyboard(DataKeyboard),
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    KeyboardResponse(DataKeyboardResponse),
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    Mouse(DataMouse),
    Control(DataControl),
    Empty,
    Disconnected,
    VoiceCallIncoming,
    StartVoiceCall,
    VoiceCallResponse(bool),
    CloseVoiceCall(String),
    FileTransferLog((String, String)),
    CmErr(String),
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(tag = "t")]
pub enum MainConfigKey {
    Id,
    PermanentPasswordSet,
    UserOwnedPermanentPasswordWritable,
    HideConnectionManager,
    VoiceCallInput,
    DirectListenerBound,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct MainStatusSnapshot {
    pub options: MainStatusOptions,
    pub id: String,
    pub file_transfer_enabled: Option<bool>,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq)]
pub struct MainReadinessSnapshot {
    pub permanent_password_set: bool,
    pub user_owned_permanent_password_writable: bool,
    pub direct_listener_bound: bool,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq, Hash)]
pub enum MainStatusOptionKey {
    AccessMode,
    EnableKeyboard,
    EnableClipboard,
    EnableFileTransfer,
    EnableCamera,
    EnableTerminal,
    EnableAudio,
    EnableTunnel,
    EnableRemoteRestart,
    EnableRecordSession,
    EnableBlockInput,
    EnableVirtualDisplay,
    AllowAutoDisconnect,
    AutoDisconnectTimeout,
    AllowOnlyConnectionWindowOpen,
    AllowAutoRecordIncoming,
    EnableAbr,
    AllowRemoveWallpaper,
    AllowAlwaysSoftwareRender,
    AllowLinuxHeadless,
    EnableHwcodec,
    ApproveMode,
    VerificationMethod,
    CustomRendezvousServer,
    AllowWebsocket,
    PresetAddressBookName,
    PresetAddressBookTag,
    PresetAddressBookAlias,
    PresetAddressBookNote,
    PresetDeviceUsername,
    PresetDeviceName,
    PresetNote,
    EnableDirectxCapture,
    EnableAndroidSoftwareEncodingHalfScale,
    RelayServer,
    AllowInsecureTlsFallback,
    KeepAwakeDuringIncomingSessions,
    AudioInput,
    VoiceCallInput,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl MainStatusOptionKey {
    fn as_str(self) -> &'static str {
        use hbb_common::config::keys;
        match self {
            Self::AccessMode => keys::OPTION_ACCESS_MODE,
            Self::EnableKeyboard => keys::OPTION_ENABLE_KEYBOARD,
            Self::EnableClipboard => keys::OPTION_ENABLE_CLIPBOARD,
            Self::EnableFileTransfer => keys::OPTION_ENABLE_FILE_TRANSFER,
            Self::EnableCamera => keys::OPTION_ENABLE_CAMERA,
            Self::EnableTerminal => keys::OPTION_ENABLE_TERMINAL,
            Self::EnableAudio => keys::OPTION_ENABLE_AUDIO,
            Self::EnableTunnel => keys::OPTION_ENABLE_TUNNEL,
            Self::EnableRemoteRestart => keys::OPTION_ENABLE_REMOTE_RESTART,
            Self::EnableRecordSession => keys::OPTION_ENABLE_RECORD_SESSION,
            Self::EnableBlockInput => keys::OPTION_ENABLE_BLOCK_INPUT,
            Self::EnableVirtualDisplay => keys::OPTION_ENABLE_VIRTUAL_DISPLAY,
            Self::AllowAutoDisconnect => keys::OPTION_ALLOW_AUTO_DISCONNECT,
            Self::AutoDisconnectTimeout => keys::OPTION_AUTO_DISCONNECT_TIMEOUT,
            Self::AllowOnlyConnectionWindowOpen => keys::OPTION_ALLOW_ONLY_CONN_WINDOW_OPEN,
            Self::AllowAutoRecordIncoming => keys::OPTION_ALLOW_AUTO_RECORD_INCOMING,
            Self::EnableAbr => keys::OPTION_ENABLE_ABR,
            Self::AllowRemoveWallpaper => keys::OPTION_ALLOW_REMOVE_WALLPAPER,
            Self::AllowAlwaysSoftwareRender => keys::OPTION_ALLOW_ALWAYS_SOFTWARE_RENDER,
            Self::AllowLinuxHeadless => keys::OPTION_ALLOW_LINUX_HEADLESS,
            Self::EnableHwcodec => keys::OPTION_ENABLE_HWCODEC,
            Self::ApproveMode => keys::OPTION_APPROVE_MODE,
            Self::VerificationMethod => keys::OPTION_VERIFICATION_METHOD,
            Self::CustomRendezvousServer => keys::OPTION_CUSTOM_RENDEZVOUS_SERVER,
            Self::AllowWebsocket => keys::OPTION_ALLOW_WEBSOCKET,
            Self::PresetAddressBookName => keys::OPTION_PRESET_ADDRESS_BOOK_NAME,
            Self::PresetAddressBookTag => keys::OPTION_PRESET_ADDRESS_BOOK_TAG,
            Self::PresetAddressBookAlias => keys::OPTION_PRESET_ADDRESS_BOOK_ALIAS,
            Self::PresetAddressBookNote => keys::OPTION_PRESET_ADDRESS_BOOK_NOTE,
            Self::PresetDeviceUsername => keys::OPTION_PRESET_DEVICE_USERNAME,
            Self::PresetDeviceName => keys::OPTION_PRESET_DEVICE_NAME,
            Self::PresetNote => keys::OPTION_PRESET_NOTE,
            Self::EnableDirectxCapture => keys::OPTION_ENABLE_DIRECTX_CAPTURE,
            Self::EnableAndroidSoftwareEncodingHalfScale => {
                keys::OPTION_ENABLE_ANDROID_SOFTWARE_ENCODING_HALF_SCALE
            }
            Self::RelayServer => keys::OPTION_RELAY_SERVER,
            Self::AllowInsecureTlsFallback => keys::OPTION_ALLOW_INSECURE_TLS_FALLBACK,
            Self::KeepAwakeDuringIncomingSessions => {
                keys::OPTION_KEEP_AWAKE_DURING_INCOMING_SESSIONS
            }
            Self::AudioInput => "audio-input",
            Self::VoiceCallInput => "voice-call-input",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        use hbb_common::config::keys;
        Some(match value {
            keys::OPTION_ACCESS_MODE => Self::AccessMode,
            keys::OPTION_ENABLE_KEYBOARD => Self::EnableKeyboard,
            keys::OPTION_ENABLE_CLIPBOARD => Self::EnableClipboard,
            keys::OPTION_ENABLE_FILE_TRANSFER => Self::EnableFileTransfer,
            keys::OPTION_ENABLE_CAMERA => Self::EnableCamera,
            keys::OPTION_ENABLE_TERMINAL => Self::EnableTerminal,
            keys::OPTION_ENABLE_AUDIO => Self::EnableAudio,
            keys::OPTION_ENABLE_TUNNEL => Self::EnableTunnel,
            keys::OPTION_ENABLE_REMOTE_RESTART => Self::EnableRemoteRestart,
            keys::OPTION_ENABLE_RECORD_SESSION => Self::EnableRecordSession,
            keys::OPTION_ENABLE_BLOCK_INPUT => Self::EnableBlockInput,
            keys::OPTION_ENABLE_VIRTUAL_DISPLAY => Self::EnableVirtualDisplay,
            keys::OPTION_ALLOW_AUTO_DISCONNECT => Self::AllowAutoDisconnect,
            keys::OPTION_AUTO_DISCONNECT_TIMEOUT => Self::AutoDisconnectTimeout,
            keys::OPTION_ALLOW_ONLY_CONN_WINDOW_OPEN => Self::AllowOnlyConnectionWindowOpen,
            keys::OPTION_ALLOW_AUTO_RECORD_INCOMING => Self::AllowAutoRecordIncoming,
            keys::OPTION_ENABLE_ABR => Self::EnableAbr,
            keys::OPTION_ALLOW_REMOVE_WALLPAPER => Self::AllowRemoveWallpaper,
            keys::OPTION_ALLOW_ALWAYS_SOFTWARE_RENDER => Self::AllowAlwaysSoftwareRender,
            keys::OPTION_ALLOW_LINUX_HEADLESS => Self::AllowLinuxHeadless,
            keys::OPTION_ENABLE_HWCODEC => Self::EnableHwcodec,
            keys::OPTION_APPROVE_MODE => Self::ApproveMode,
            keys::OPTION_VERIFICATION_METHOD => Self::VerificationMethod,
            keys::OPTION_CUSTOM_RENDEZVOUS_SERVER => Self::CustomRendezvousServer,
            keys::OPTION_ALLOW_WEBSOCKET => Self::AllowWebsocket,
            keys::OPTION_PRESET_ADDRESS_BOOK_NAME => Self::PresetAddressBookName,
            keys::OPTION_PRESET_ADDRESS_BOOK_TAG => Self::PresetAddressBookTag,
            keys::OPTION_PRESET_ADDRESS_BOOK_ALIAS => Self::PresetAddressBookAlias,
            keys::OPTION_PRESET_ADDRESS_BOOK_NOTE => Self::PresetAddressBookNote,
            keys::OPTION_PRESET_DEVICE_USERNAME => Self::PresetDeviceUsername,
            keys::OPTION_PRESET_DEVICE_NAME => Self::PresetDeviceName,
            keys::OPTION_PRESET_NOTE => Self::PresetNote,
            keys::OPTION_ENABLE_DIRECTX_CAPTURE => Self::EnableDirectxCapture,
            keys::OPTION_ENABLE_ANDROID_SOFTWARE_ENCODING_HALF_SCALE => {
                Self::EnableAndroidSoftwareEncodingHalfScale
            }
            keys::OPTION_RELAY_SERVER => Self::RelayServer,
            keys::OPTION_ALLOW_INSECURE_TLS_FALLBACK => Self::AllowInsecureTlsFallback,
            keys::OPTION_KEEP_AWAKE_DURING_INCOMING_SESSIONS => {
                Self::KeepAwakeDuringIncomingSessions
            }
            "audio-input" => Self::AudioInput,
            "voice-call-input" => Self::VoiceCallInput,
            _ => return None,
        })
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct MainStatusOption {
    key: MainStatusOptionKey,
    value: String,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct MainStatusOptions(Vec<MainStatusOption>);

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl MainStatusOptions {
    fn from_map(options: HashMap<String, String>) -> ResultType<Self> {
        if options.len() > MAIN_IPC_MAX_OPTION_COUNT {
            bail!("too many main IPC options");
        }
        let mut entries = Vec::with_capacity(options.len());
        for (key, value) in options {
            entries.push(MainStatusOption::from_pair(&key, value)?);
        }
        entries.sort_by_key(|entry| entry.key.as_str());
        if entries.windows(2).any(|pair| pair[0].key == pair[1].key) {
            bail!("duplicate main IPC option");
        }
        Ok(Self(entries))
    }

    fn from_config() -> ResultType<Self> {
        let options = Config::get_options()
            .into_iter()
            .filter(|(key, _)| MainStatusOptionKey::from_str(key).is_some())
            .collect();
        Self::from_map(options)
    }

    fn validate(self) -> ResultType<Self> {
        if self.0.len() > MAIN_IPC_MAX_OPTION_COUNT {
            bail!("too many main IPC options");
        }
        let mut seen = std::collections::HashSet::with_capacity(self.0.len());
        for entry in &self.0 {
            if entry.value.len() > MAIN_IPC_MAX_OPTION_VALUE_BYTES {
                bail!("main IPC option value is oversized");
            }
            if !seen.insert(entry.key) {
                bail!("duplicate main IPC option");
            }
        }
        Ok(self)
    }

    pub fn into_map(self) -> ResultType<HashMap<String, String>> {
        Ok(self
            .validate()?
            .0
            .into_iter()
            .map(|entry| (entry.key.as_str().to_owned(), entry.value))
            .collect())
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl MainStatusOption {
    fn from_pair(key: &str, value: String) -> ResultType<Self> {
        let Some(key) = MainStatusOptionKey::from_str(key) else {
            bail!("main IPC option is not allowlisted");
        };
        Self { key, value }.validate()
    }

    fn validate(self) -> ResultType<Self> {
        if self.value.len() > MAIN_IPC_MAX_OPTION_VALUE_BYTES {
            bail!("main IPC option value is oversized");
        }
        Ok(self)
    }

    fn into_pair(self) -> ResultType<(MainStatusOptionKey, String)> {
        let value = self.validate()?;
        Ok((value.key, value.value))
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq)]
pub enum IpcMutationResult {
    Applied,
    Rejected,
    InternalFailure,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq)]
pub enum PasswordMutationStatus {
    Prepared,
    Pending,
    Complete(IpcMutationResult),
    Unknown,
    ShuttingDown,
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_credential_queue_uncertainty_status() -> PasswordMutationStatus {
    PasswordMutationStatus::Pending
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsCredentialClientDecision {
    Continue,
    Applied,
    Rejected,
    InternalFailure,
    NotAdmitted,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn windows_credential_client_decision(
    status: PasswordMutationStatus,
    recovery_required: bool,
) -> WindowsCredentialClientDecision {
    match status {
        PasswordMutationStatus::Prepared | PasswordMutationStatus::Pending => {
            WindowsCredentialClientDecision::Continue
        }
        PasswordMutationStatus::Complete(IpcMutationResult::Applied) => {
            WindowsCredentialClientDecision::Applied
        }
        PasswordMutationStatus::Complete(IpcMutationResult::Rejected) => {
            WindowsCredentialClientDecision::Rejected
        }
        PasswordMutationStatus::Complete(IpcMutationResult::InternalFailure) => {
            WindowsCredentialClientDecision::InternalFailure
        }
        PasswordMutationStatus::ShuttingDown => WindowsCredentialClientDecision::NotAdmitted,
        PasswordMutationStatus::Unknown if recovery_required => {
            WindowsCredentialClientDecision::Continue
        }
        PasswordMutationStatus::Unknown => WindowsCredentialClientDecision::NotAdmitted,
    }
}

#[cfg(any(target_os = "windows", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsJobStopDecision {
    Empty,
    Retry,
    Abort,
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_job_stop_decision(
    active_processes: Option<u32>,
    operation_error: Option<i32>,
) -> WindowsJobStopDecision {
    if active_processes == Some(0) {
        return WindowsJobStopDecision::Empty;
    }
    if matches!(operation_error, Some(5) | Some(6))
        || (active_processes.is_none() && operation_error.is_none())
    {
        return WindowsJobStopDecision::Abort;
    }
    WindowsJobStopDecision::Retry
}

#[cfg(any(target_os = "windows", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsCredentialOperationState {
    Active,
    Complete(IpcMutationResult, std::time::Instant),
}

#[cfg(any(target_os = "windows", test))]
struct WindowsCredentialOperationEntry {
    request_tag: PasswordMutationFingerprint,
    state: WindowsCredentialOperationState,
}

#[cfg(any(target_os = "windows", test))]
pub(crate) struct WindowsCredentialOperationLedger {
    request_key: hbb_common::sodiumoxide::crypto::auth::hmacsha256::Key,
    entries: HashMap<String, WindowsCredentialOperationEntry>,
    capacity: usize,
    shutting_down: bool,
}

#[cfg(any(target_os = "windows", test))]
impl WindowsCredentialOperationLedger {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            request_key: hbb_common::sodiumoxide::crypto::auth::hmacsha256::gen_key(),
            entries: HashMap::new(),
            capacity,
            shutting_down: false,
        }
    }

    fn request_tag(&self, value: &str) -> PasswordMutationFingerprint {
        password_mutation_fingerprint(&self.request_key, value)
    }

    fn evict_oldest_complete(&mut self) -> bool {
        let oldest = self
            .entries
            .iter()
            .filter_map(|(operation_id, entry)| match entry.state {
                WindowsCredentialOperationState::Complete(_, completed_at) => {
                    Some((operation_id.clone(), completed_at))
                }
                WindowsCredentialOperationState::Active => None,
            })
            .min_by_key(|(_, completed_at)| *completed_at)
            .map(|(operation_id, _)| operation_id);
        oldest
            .and_then(|operation_id| self.entries.remove(&operation_id))
            .is_some()
    }

    pub(crate) fn status(&self, operation_id: &str, value: &str) -> Option<PasswordMutationStatus> {
        let request_tag = self.request_tag(value);
        self.entries.get(operation_id).map(|entry| {
            if entry.request_tag != request_tag {
                PasswordMutationStatus::Complete(IpcMutationResult::Rejected)
            } else {
                match entry.state {
                    WindowsCredentialOperationState::Active => PasswordMutationStatus::Pending,
                    WindowsCredentialOperationState::Complete(result, _) => {
                        PasswordMutationStatus::Complete(result)
                    }
                }
            }
        })
    }

    pub(crate) fn classify_during_shutdown(
        &self,
        operation_id: &str,
        value: &str,
    ) -> PasswordMutationStatus {
        self.status(operation_id, value)
            .unwrap_or(PasswordMutationStatus::ShuttingDown)
    }

    pub(crate) fn admit(
        &mut self,
        operation_id: &str,
        value: &str,
        transaction_active: bool,
    ) -> bool {
        if self.shutting_down || transaction_active || self.entries.contains_key(operation_id) {
            return false;
        }
        if self.entries.len() >= self.capacity && !self.evict_oldest_complete() {
            return false;
        }
        let request_tag = self.request_tag(value);
        self.entries.insert(
            operation_id.to_owned(),
            WindowsCredentialOperationEntry {
                request_tag,
                state: WindowsCredentialOperationState::Active,
            },
        );
        true
    }

    pub(crate) fn complete(
        &mut self,
        operation_id: &str,
        result: IpcMutationResult,
    ) -> ResultType<()> {
        let Some(entry) = self.entries.get_mut(operation_id) else {
            bail!("Windows credential transaction completed without replay authority");
        };
        if entry.state != WindowsCredentialOperationState::Active {
            bail!("Windows credential transaction completed from a non-active state");
        }
        entry.state = WindowsCredentialOperationState::Complete(result, std::time::Instant::now());
        Ok(())
    }

    pub(crate) fn begin_shutdown(&mut self) {
        self.shutting_down = true;
    }

    pub(crate) fn is_shutting_down(&self) -> bool {
        self.shutting_down
    }
}

#[cfg(any(target_os = "windows", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsCredentialTransactionPhase {
    Admitted,
    Quiesced,
    Committed,
    Complete(IpcMutationResult),
}

#[cfg(any(target_os = "windows", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WindowsCredentialTransactionResolution {
    pub(crate) result: IpcMutationResult,
    pub(crate) retire_child: bool,
}

#[cfg(any(target_os = "windows", test))]
pub(crate) struct WindowsCredentialTransactionModel {
    expected_child_identity: Option<(u32, u64)>,
    phase: WindowsCredentialTransactionPhase,
    stop_requested: bool,
}

#[cfg(any(target_os = "windows", test))]
impl WindowsCredentialTransactionModel {
    pub(crate) fn admitted(expected_child_identity: Option<(u32, u64)>) -> Self {
        Self {
            expected_child_identity,
            phase: WindowsCredentialTransactionPhase::Admitted,
            stop_requested: false,
        }
    }

    pub(crate) fn exact_child_is_live(&self, observed_identity: Option<(u32, u64)>) -> bool {
        self.expected_child_identity.is_some() && self.expected_child_identity == observed_identity
    }

    pub(crate) fn note_quiesced(&mut self) -> ResultType<()> {
        match self.phase {
            WindowsCredentialTransactionPhase::Admitted
            | WindowsCredentialTransactionPhase::Quiesced => {
                self.phase = WindowsCredentialTransactionPhase::Quiesced;
                Ok(())
            }
            _ => bail!("Windows credential quiesce arrived after the durable decision"),
        }
    }

    pub(crate) fn precommit_failure(
        &mut self,
        resume_proven: bool,
        result: IpcMutationResult,
    ) -> ResultType<WindowsCredentialTransactionResolution> {
        if !matches!(
            self.phase,
            WindowsCredentialTransactionPhase::Admitted
                | WindowsCredentialTransactionPhase::Quiesced
        ) || result == IpcMutationResult::Applied
        {
            bail!("invalid Windows credential precommit completion");
        }
        self.phase = WindowsCredentialTransactionPhase::Complete(result);
        Ok(WindowsCredentialTransactionResolution {
            result,
            retire_child: self.expected_child_identity.is_some() && !resume_proven,
        })
    }

    pub(crate) fn note_committed(&mut self) -> ResultType<()> {
        if !matches!(
            self.phase,
            WindowsCredentialTransactionPhase::Admitted
                | WindowsCredentialTransactionPhase::Quiesced
        ) {
            bail!("invalid Windows credential durable commit transition");
        }
        self.phase = WindowsCredentialTransactionPhase::Committed;
        Ok(())
    }

    pub(crate) fn request_stop(&mut self) {
        self.stop_requested = true;
    }

    pub(crate) fn should_skip_replica_apply(&self) -> bool {
        self.stop_requested && self.phase == WindowsCredentialTransactionPhase::Committed
    }

    pub(crate) fn postcommit_complete(
        &mut self,
        exact_replica_applied: bool,
    ) -> ResultType<WindowsCredentialTransactionResolution> {
        match self.phase {
            WindowsCredentialTransactionPhase::Committed
            | WindowsCredentialTransactionPhase::Complete(IpcMutationResult::Applied) => {}
            _ => bail!("Windows credential postcommit completion preceded durable commit"),
        }
        let skip_replica_apply = self.should_skip_replica_apply();
        self.phase = WindowsCredentialTransactionPhase::Complete(IpcMutationResult::Applied);
        Ok(WindowsCredentialTransactionResolution {
            result: IpcMutationResult::Applied,
            retire_child: self.expected_child_identity.is_some()
                && !exact_replica_applied
                && !skip_replica_apply,
        })
    }
}

#[cfg(any(target_os = "windows", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsCredentialStopApplyState {
    Open,
    Applying,
    StopBeforeApply,
    StopPendingApply,
    ReadyToStop,
    Stopped,
}

#[cfg(any(target_os = "windows", test))]
pub(crate) struct WindowsCredentialStopApplyModel {
    state: WindowsCredentialStopApplyState,
}

#[cfg(any(target_os = "windows", test))]
impl WindowsCredentialStopApplyModel {
    pub(crate) fn new() -> Self {
        Self {
            state: WindowsCredentialStopApplyState::Open,
        }
    }

    pub(crate) fn request_stop(&mut self) -> bool {
        match self.state {
            WindowsCredentialStopApplyState::Open => {
                self.state = WindowsCredentialStopApplyState::StopBeforeApply;
                false
            }
            WindowsCredentialStopApplyState::Applying => {
                self.state = WindowsCredentialStopApplyState::StopPendingApply;
                false
            }
            WindowsCredentialStopApplyState::StopBeforeApply
            | WindowsCredentialStopApplyState::StopPendingApply
            | WindowsCredentialStopApplyState::ReadyToStop => false,
            WindowsCredentialStopApplyState::Stopped => true,
        }
    }

    pub(crate) fn admit_apply(&mut self) -> bool {
        if self.state != WindowsCredentialStopApplyState::Open {
            return false;
        }
        self.state = WindowsCredentialStopApplyState::Applying;
        true
    }

    pub(crate) fn finish_apply(&mut self) -> bool {
        match self.state {
            WindowsCredentialStopApplyState::Applying => {
                self.state = WindowsCredentialStopApplyState::Open;
                false
            }
            WindowsCredentialStopApplyState::StopPendingApply => {
                self.state = WindowsCredentialStopApplyState::ReadyToStop;
                false
            }
            WindowsCredentialStopApplyState::Open
            | WindowsCredentialStopApplyState::StopBeforeApply
            | WindowsCredentialStopApplyState::ReadyToStop
            | WindowsCredentialStopApplyState::Stopped => false,
        }
    }

    pub(crate) fn complete_stop(&mut self) -> bool {
        if matches!(
            self.state,
            WindowsCredentialStopApplyState::StopBeforeApply
                | WindowsCredentialStopApplyState::ReadyToStop
        ) {
            self.state = WindowsCredentialStopApplyState::Stopped;
            return true;
        }
        self.state == WindowsCredentialStopApplyState::Stopped
    }

    pub(crate) fn stop_is_linearized(&self) -> bool {
        self.state == WindowsCredentialStopApplyState::Stopped
    }

    pub(crate) fn state(&self) -> WindowsCredentialStopApplyState {
        self.state
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "t", content = "c")]
pub enum MainIpcRequest {
    StatusSnapshot,
    ReadinessSnapshot,
    Config(MainConfigKey),
    SetVoiceCallInput(String),
    PasswordMutationStatus {
        operation_id: String,
    },
    SetOption(MainStatusOption),
    ValidateCmConnection {
        id: i32,
        conn_type: CmAuthConnType,
        cm_auth_token: String,
    },
    #[cfg(target_os = "linux")]
    ValidatePulseAudioStart {
        token: String,
    },
    #[cfg(target_os = "windows")]
    CpuUsage,
    #[cfg(target_os = "windows")]
    ControlledSessionCount,
    #[cfg(target_os = "linux")]
    TerminalSessionCount,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "t", content = "c")]
pub enum MainIpcResponse {
    StatusSnapshot(MainStatusSnapshot),
    ReadinessSnapshot(MainReadinessSnapshot),
    Config {
        key: MainConfigKey,
        value: Option<String>,
    },
    VoiceCallInputSet(IpcMutationResult),
    PasswordMutation(PasswordMutationStatus),
    OptionSet {
        result: IpcMutationResult,
        effective: Option<MainStatusOption>,
    },
    RequestFailed(IpcMutationResult),
    CmConnectionValidation(CmConnectionAuthority),
    #[cfg(target_os = "linux")]
    PulseAudioStartValidation(bool),
    #[cfg(target_os = "windows")]
    CpuUsage(Option<f64>),
    #[cfg(target_os = "windows")]
    ControlledSessionCount(usize),
    #[cfg(target_os = "linux")]
    TerminalSessionCount(usize),
}

#[cfg(any(target_os = "windows", test))]
pub(crate) const WINDOWS_SERVICE_CREDENTIAL_IPC_POSTFIX: &str = "_service_credential";
#[cfg(any(target_os = "windows", test))]
pub(crate) const WINDOWS_SERVICE_MAIN_CONTROL_IPC_POSTFIX: &str = "_service_main_control";
#[cfg(any(target_os = "windows", test))]
pub(crate) const WINDOWS_SERVICE_SAS_IPC_POSTFIX: &str = "_service_sas";
#[cfg(target_os = "windows")]
pub(crate) const WINDOWS_SERVICE_SAS_CLIENT_TIMEOUT_MS: u64 = 5_000;
#[cfg(target_os = "windows")]
pub(crate) const WINDOWS_SERVICE_SUPERVISOR_PID_ENV: &str =
    "RUSTDESK_WINDOWS_SERVICE_SUPERVISOR_PID";
#[cfg(target_os = "windows")]
pub(crate) const WINDOWS_SERVICE_SUPERVISOR_CREATION_ENV: &str =
    "RUSTDESK_WINDOWS_SERVICE_SUPERVISOR_CREATION";

#[cfg(target_os = "windows")]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t", content = "c")]
enum WindowsServiceMainRequest {
    QuiesceCredentialReplica {
        transition_id: String,
    },
    ApplyCredentialReplica {
        transition_id: String,
        storage: String,
        salt: String,
        replica_tag: [u8; 32],
    },
    QueryCredentialReplica,
    ResumeCredentialReplica {
        transition_id: String,
    },
    PortForwardSessionCount,
    Shutdown,
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub(crate) struct WindowsCredentialReplicaState {
    pub(crate) transition_id: Option<String>,
    pub(crate) replica_tag: [u8; 32],
    pub(crate) quiesced: bool,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Serialize, Deserialize)]
enum WindowsCredentialReplicaResponse {
    State(WindowsCredentialReplicaState),
    Rejected,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t", content = "c")]
enum WindowsServiceMainResponse {
    CredentialReplica(WindowsCredentialReplicaResponse),
    PortForwardSessionCount(usize),
    ShutdownAccepted,
}

#[tokio::main(flavor = "current_thread")]
pub async fn start(postfix: &str) -> ResultType<()> {
    if postfix.is_empty() {
        Config::ensure_loaded();
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            let listeners = prepare_main_ipc().await?;
            return run_main_ipc(listeners).await;
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        bail!("desktop main IPC is unavailable on mobile");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    return start_service_ipc(postfix).await;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    bail!("unsupported IPC listener postfix: {postfix}");
}

/// Construct every desktop local listener on one new native thread, report readiness only after
/// every required listener guard is active, and return the complete post-drain outcome to the
/// retained controlled-server owner. This function is called only from that new thread, so its
/// current-thread runtime is never nested inside the server's existing Tokio runtime.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[tokio::main(flavor = "current_thread")]
async fn run_desktop_ipc(readiness: oneshot::Sender<Result<(), String>>) -> ResultType<()> {
    Config::ensure_loaded();
    let main = match prepare_main_ipc().await {
        Ok(main) => main,
        Err(err) => {
            let _ = readiness.send(Err(err.to_string()));
            return Err(err);
        }
    };
    #[cfg(target_os = "windows")]
    let service_main = if is_service_owned_server_process() {
        match prepare_windows_service_main_ipc().await {
            Ok(service_main) => Some(service_main),
            Err(err) => {
                let _ = readiness.send(Err(err.to_string()));
                return Err(err);
            }
        }
    } else {
        None
    };

    readiness.send(Ok(())).map_err(|_| {
        hbb_common::anyhow::anyhow!("desktop IPC lifecycle owner stopped before readiness")
    })?;

    #[cfg(target_os = "windows")]
    if let Some(service_main) = service_main {
        let (main_outcome, service_main_outcome) = tokio::join!(
            run_main_ipc(main),
            run_windows_service_main_ipc(service_main),
        );
        main_outcome?;
        return service_main_outcome;
    }
    run_main_ipc(main).await
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
pub(crate) async fn start_linux_service_ipc_with_readiness(
    startup: std::sync::mpsc::SyncSender<Result<(), String>>,
) -> ResultType<()> {
    let listeners = match prepare_service_ipc(crate::POSTFIX_SERVICE).await {
        Ok(listeners) => listeners,
        Err(err) => {
            if startup.send(Err(err.to_string())).is_err() {
                log::error!(
                    "Linux service IPC failed before readiness after its supervisor stopped waiting"
                );
            }
            return Err(err);
        }
    };
    startup.send(Ok(())).map_err(|_| {
        anyhow::anyhow!("Linux service supervisor stopped before protected IPC became ready")
    })?;
    run_service_ipc(crate::POSTFIX_SERVICE, listeners).await
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
enum SensitiveMainListenerEvent {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Accepted(Conn),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    AcceptFailed(String),
    #[cfg(target_os = "windows")]
    Request(crate::platform::windows::WindowsSensitivePasswordRequest),
    Ended,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn next_sensitive_main_listener_event(listener: &mut Incoming) -> SensitiveMainListenerEvent {
    match listener.next().await {
        Some(Ok(stream)) => SensitiveMainListenerEvent::Accepted(stream),
        Some(Err(err)) => SensitiveMainListenerEvent::AcceptFailed(err.to_string()),
        None => SensitiveMainListenerEvent::Ended,
    }
}

#[cfg(target_os = "windows")]
async fn next_sensitive_main_listener_event(
    listener: &mut Option<
        mpsc::Receiver<crate::platform::windows::WindowsSensitivePasswordRequest>,
    >,
) -> SensitiveMainListenerEvent {
    match listener.as_mut() {
        Some(listener) => listener
            .recv()
            .await
            .map(SensitiveMainListenerEvent::Request)
            .unwrap_or(SensitiveMainListenerEvent::Ended),
        None => std::future::pending().await,
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct PreparedMainIpc {
    incoming: Incoming,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    password_events: Incoming,
    #[cfg(target_os = "windows")]
    password_events:
        Option<mpsc::Receiver<crate::platform::windows::WindowsSensitivePasswordRequest>>,
    #[cfg(target_os = "windows")]
    password_listener: Option<crate::platform::windows::WindowsSensitivePasswordListener>,
    listener_guard: LocalIpcListenerGuard,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn prepare_main_ipc() -> ResultType<PreparedMainIpc> {
    let incoming = new_listener("").await?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let password_events = new_listener(password::USER_PASSWORD_IPC_POSTFIX).await?;
    #[cfg(target_os = "windows")]
    let (password_events, password_listener) = if crate::common::is_service_owned_server_process() {
        (None, None)
    } else {
        let (password_request_tx, password_events) = mpsc::channel(MAIN_IPC_TRANSACTION_BUDGET);
        let password_listener =
            crate::platform::windows::start_windows_sensitive_password_listener(
                password::USER_PASSWORD_IPC_POSTFIX,
                password_request_tx,
            )?;
        (Some(password_events), Some(password_listener))
    };
    let listener_guard =
        LocalIpcListenerGuard::activate(&MAIN_IPC_LISTENER_STATE, "main IPC listener")?;
    Ok(PreparedMainIpc {
        incoming,
        password_events,
        #[cfg(target_os = "windows")]
        password_listener,
        listener_guard,
    })
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn run_main_ipc(listeners: PreparedMainIpc) -> ResultType<()> {
    let PreparedMainIpc {
        mut incoming,
        mut password_events,
        #[cfg(target_os = "windows")]
        password_listener,
        listener_guard,
    } = listeners;
    let mut transactions = JoinSet::new();
    let shutdown = crate::server::shutdown_token();
    let mut listener_error = None;
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            completed = transactions.join_next(), if !transactions.is_empty() => {
                if let Some(Err(err)) = completed {
                    log::error!("main IPC transaction task failed: {err}");
                }
            }
            event = next_sensitive_main_listener_event(&mut password_events) => {
                match event {
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    SensitiveMainListenerEvent::Accepted(stream) => {
                        let Some(authority) = sensitive_main_ipc_authority(&stream) else { continue; };
                        let Some(permit) = try_acquire_sensitive_main_ipc_transaction_slot(authority) else { continue; };
                        transactions.spawn(handle_sensitive_main_ipc_transaction(
                            stream,
                            authority,
                            permit,
                        ));
                    }
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    SensitiveMainListenerEvent::AcceptFailed(err) => {
                        log::error!("Could not accept main password IPC client: {err}");
                    }
                    #[cfg(target_os = "windows")]
                    SensitiveMainListenerEvent::Request(request) => {
                        let authority_allowed = current_process_allows_user_owned_permanent_password_write()
                            && !Config::is_disable_change_permanent_password();
                        let (status, worker) = begin_password_mutation(
                            request.operation_id,
                            request.value,
                            PasswordMutationKind::UserOwned,
                            authority_allowed,
                        );
                        let _ = request.response.send(status);
                        if let Some(worker) = worker {
                            transactions.spawn(async move {
                                if let Err(err) = worker.await {
                                    log::error!("password mutation worker failed: {err}");
                                }
                            });
                        }
                    }
                    SensitiveMainListenerEvent::Ended => {
                        listener_error = Some("main password IPC listener ended unexpectedly".to_owned());
                        crate::server::request_graceful_shutdown_after_listener_failure();
                        break;
                    }
                }
            }
            result = incoming.next() => {
                let Some(result) = result else {
                    listener_error = Some("main IPC listener ended unexpectedly".to_owned());
                    crate::server::request_graceful_shutdown_after_listener_failure();
                    break;
                };
                let stream = match result {
                    Ok(stream) => stream,
                    Err(err) => {
                        log::error!("Could not accept main IPC client: {err}");
                        continue;
                    }
                };
                let stream = Connection::new_main(stream);
                #[cfg(windows)]
                if !authorize_windows_main_ipc_connection(&stream, "") {
                    continue;
                }
                let Some(permit) = try_acquire_main_ipc_transaction_slot(&stream) else { continue; };
                transactions.spawn(handle_main_ipc_transaction(stream, permit));
            }
        }
    }
    #[cfg(target_os = "windows")]
    if let Some(listener) = password_listener.as_ref() {
        listener.quiesce().await;
    }
    password_mutations().begin_shutdown();
    #[cfg(target_os = "windows")]
    if let Some(password_events) = password_events.as_mut() {
        while let Ok(request) = password_events.try_recv() {
            let status = password_mutations().classify_during_shutdown(
                &request.operation_id,
                PasswordMutationKind::UserOwned,
                request.value.as_str(),
            );
            let _ = request.response.send(status);
        }
    }
    while let Some(result) = transactions.join_next().await {
        if let Err(err) = result {
            log::error!("main IPC transaction did not drain cleanly: {err}");
        }
    }
    password_mutations().drain().await;
    password_mutations().clear_after_transactions_drain();
    drop(listener_guard);
    match listener_error {
        Some(err) => Err(hbb_common::anyhow::anyhow!(err)),
        None => Ok(()),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn sensitive_main_ipc_authority(stream: &Conn) -> Option<PasswordMutationKind> {
    #[cfg(target_os = "linux")]
    if MainIpcAuthority::for_current_process() == MainIpcAuthority::ServiceOwned {
        return match authenticate_linux_service_owned_password_parent(
            stream,
            password::USER_PASSWORD_IPC_POSTFIX,
        ) {
            Ok(_) => Some(PasswordMutationKind::ServiceOwned),
            Err(err) => {
                log::warn!("Rejected service-owned main password IPC client: {err}");
                None
            }
        };
    }

    match ensure_user_owned_password_client_is_trusted(stream, password::USER_PASSWORD_IPC_POSTFIX)
    {
        Ok(()) => Some(PasswordMutationKind::UserOwned),
        Err(err) => {
            log::warn!("Rejected user-owned main password IPC client: {err}");
            None
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn handle_sensitive_main_ipc_transaction(
    mut stream: Conn,
    kind: PasswordMutationKind,
    _permit: OwnedSemaphorePermit,
) {
    let deadline = tokio::time::Instant::now()
        + std::time::Duration::from_millis(MAIN_IPC_TRANSACTION_TIMEOUT_MS);
    let request = match password::receive_request_unix(
        &mut stream,
        password::SensitivePayloadKind::Password,
        deadline,
    )
    .await
    {
        Ok(request) => request,
        Err(err) => {
            log::trace!("main password IPC request was rejected: {err}");
            return;
        }
    };
    let operation_id = request.operation_id();
    let value = match request.into_password() {
        Ok(value) => value,
        Err(err) => {
            log::trace!("main password IPC value was rejected: {err}");
            return;
        }
    };
    let authority_allowed = match kind {
        PasswordMutationKind::UserOwned => {
            current_process_allows_user_owned_permanent_password_write()
                && !Config::is_disable_change_permanent_password()
        }
        PasswordMutationKind::ServiceOwned => {
            MainIpcAuthority::for_current_process() == MainIpcAuthority::ServiceOwned
        }
    };
    let (status, worker) =
        begin_password_mutation(operation_id.to_string(), value, kind, authority_allowed);
    if let Err(err) = password::send_status_unix(&mut stream, operation_id, status, deadline).await
    {
        log::trace!("main password IPC status could not be returned: {err}");
    }
    if let Some(worker) = worker {
        if let Err(err) = worker.await {
            log::error!("password mutation worker failed: {err}");
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct PreparedServiceIpc {
    incoming: Incoming,
    password_incoming: Incoming,
    credential_incoming: Incoming,
    listener_guard: LocalIpcListenerGuard,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn prepare_service_ipc(postfix: &str) -> ResultType<PreparedServiceIpc> {
    if postfix != crate::POSTFIX_SERVICE {
        bail!("unsupported service IPC postfix: {postfix}");
    }
    let incoming = new_listener(postfix).await?;
    let password_incoming = new_listener(password::SERVICE_PASSWORD_IPC_POSTFIX).await?;
    let credential_incoming = new_listener(password::SERVICE_CREDENTIAL_IPC_POSTFIX).await?;
    let listener_guard = LocalIpcListenerGuard::activate(
        &SERVICE_IPC_LISTENER_STATE,
        "protected service IPC listener",
    )?;
    Ok(PreparedServiceIpc {
        incoming,
        password_incoming,
        credential_incoming,
        listener_guard,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn start_service_ipc(postfix: &str) -> ResultType<()> {
    let listeners = prepare_service_ipc(postfix).await?;
    run_service_ipc(postfix, listeners).await
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn protected_service_ipc_result(listener_error: Option<String>) -> ResultType<()> {
    match listener_error {
        Some(err) => Err(anyhow::anyhow!(err)),
        None => Ok(()),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn run_service_ipc(postfix: &str, listeners: PreparedServiceIpc) -> ResultType<()> {
    let PreparedServiceIpc {
        mut incoming,
        mut password_incoming,
        mut credential_incoming,
        listener_guard,
    } = listeners;
    let mut transactions = JoinSet::new();
    let shutdown = crate::server::shutdown_token();
    let mut listener_error = None;
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            completed = transactions.join_next(), if !transactions.is_empty() => {
                if let Some(Err(err)) = completed {
                    log::error!("protected _service IPC transaction failed: {err}");
                }
            }
            result = credential_incoming.next() => {
                #[cfg(target_os = "linux")]
                {
                    let Some(result) = result else {
                        listener_error = Some("protected service credential IPC listener ended unexpectedly".to_owned());
                        crate::server::request_graceful_shutdown_after_listener_failure();
                        break;
                    };
                    let stream = match result {
                        Ok(stream) => stream,
                        Err(err) => {
                            log::error!("Could not accept protected service credential IPC client: {err}");
                            continue;
                        }
                    };
                    let Some(permit) = try_acquire_service_credential_ipc_transaction_slot() else {
                        continue;
                    };
                    let identity = match authenticate_linux_service_owned_password_replica_server(
                        &stream,
                        password::SERVICE_CREDENTIAL_IPC_POSTFIX,
                    ) {
                        Ok(identity) => identity,
                        Err(err) => {
                            log::warn!("Rejected Linux service credential replica requester: {err}");
                            continue;
                        }
                    };
                    transactions.spawn(handle_linux_service_credential_snapshot_transaction(
                        stream,
                        identity,
                        permit,
                    ));
                }
                #[cfg(target_os = "macos")]
                {
                    let Some(result) = result else {
                        listener_error = Some("protected macOS service credential IPC listener ended unexpectedly".to_owned());
                        crate::server::request_graceful_shutdown_after_listener_failure();
                        break;
                    };
                    let stream = match result {
                        Ok(stream) => stream,
                        Err(err) => {
                            log::error!("Could not accept protected service credential IPC client: {err}");
                            continue;
                        }
                    };
                    let Some(permit) = try_acquire_service_credential_ipc_transaction_slot() else {
                        continue;
                    };
                    let Some(authorization_permit) =
                        try_acquire_macos_service_credential_ipc_authorization_slot()
                    else {
                        continue;
                    };
                    let authorization =
                        ipc_auth::service_scoped_ipc_authorization_snapshot_from_stream(
                            &stream,
                            password::SERVICE_CREDENTIAL_IPC_POSTFIX,
                        );
                    transactions.spawn(async move {
                        let deadline = tokio::time::Instant::now()
                            + std::time::Duration::from_millis(
                                SERVICE_IPC_REQUEST_TIMEOUT_MS,
                            );
                        if authorize_macos_service_scoped_credential_stream_for_task(
                            authorization,
                            authorization_permit,
                            deadline,
                        )
                        .await
                        {
                            handle_macos_service_credential_snapshot_transaction(
                                stream, permit,
                            )
                            .await;
                        }
                    });
                }
            }
            result = password_incoming.next() => {
                let Some(result) = result else {
                    listener_error = Some("protected service password IPC listener ended unexpectedly".to_owned());
                    crate::server::request_graceful_shutdown_after_listener_failure();
                    break;
                };
                let stream = match result {
                    Ok(stream) => stream,
                    Err(err) => {
                        log::error!("Could not accept protected service password IPC client: {err}");
                        continue;
                    }
                };
                let Some(permit) = try_acquire_service_password_ipc_transaction_slot() else {
                    continue;
                };
                #[cfg(target_os = "linux")]
                if !ipc_auth::authorize_service_scoped_ipc_authorization_snapshot(
                    ipc_auth::service_scoped_ipc_authorization_snapshot_from_stream(
                        &stream,
                        password::SERVICE_PASSWORD_IPC_POSTFIX,
                    ),
                ) {
                    continue;
                }
                #[cfg(target_os = "linux")]
                {
                    let identity = match peer_process_identity_from_stream(
                        &stream,
                        password::SERVICE_PASSWORD_IPC_POSTFIX,
                    ) {
                        Ok(identity) => identity,
                        Err(err) => {
                            log::warn!("Rejected Linux service password IPC peer: {err}");
                            continue;
                        }
                    };
                    transactions.spawn(handle_sensitive_linux_service_ipc_transaction(
                        stream,
                        identity,
                        permit,
                    ));
                }
                #[cfg(target_os = "macos")]
                {
                    let Some(authorization_permit) = try_acquire_macos_service_password_ipc_authorization_slot() else { continue; };
                    transactions.spawn(async move {
                        let deadline = tokio::time::Instant::now()
                            + std::time::Duration::from_millis(SERVICE_IPC_REQUEST_TIMEOUT_MS);
                        let authorized = authorize_macos_service_scoped_password_stream_for_task(
                            &stream,
                            password::SERVICE_PASSWORD_IPC_POSTFIX,
                            authorization_permit,
                            deadline,
                        )
                        .await;
                        if authorized {
                            handle_sensitive_macos_service_ipc_transaction(
                                stream,
                                permit,
                                deadline,
                            )
                            .await;
                        }
                    });
                }
            }
            result = incoming.next() => {
                let Some(result) = result else {
                    listener_error = Some("protected _service IPC listener ended unexpectedly".to_owned());
                    crate::server::request_graceful_shutdown_after_listener_failure();
                    break;
                };
                let stream = match result {
                    Ok(stream) => stream,
                    Err(err) => {
                        log::error!("Could not accept protected _service IPC client: {err}");
                        continue;
                    }
                };
                let stream = Connection::new_protected_service(stream);
                let Some(permit) = try_acquire_service_ipc_transaction_slot() else {
                    continue;
                };
                #[cfg(target_os = "linux")]
                if !authorize_service_scoped_ipc_connection(&stream, postfix) {
                    continue;
                }
                #[cfg(target_os = "macos")]
                let Some(authorization_permit) = try_acquire_macos_service_ipc_authorization_slot() else { continue; };
                let postfix = postfix.to_owned();
                transactions.spawn(async move {
                    let _permit = permit;
                    #[cfg(target_os = "macos")]
                    {
                        let deadline = tokio::time::Instant::now()
                            + std::time::Duration::from_millis(SERVICE_IPC_REQUEST_TIMEOUT_MS);
                        if !authorize_macos_service_scoped_ipc_connection_for_task(
                            &stream,
                            &postfix,
                            authorization_permit,
                            deadline,
                        )
                        .await
                        {
                            return;
                        }
                    }
                    handle_service_ipc_transaction(stream, &postfix).await;
                });
            }
        }
    }
    #[cfg(target_os = "macos")]
    password_mutations().begin_shutdown();
    #[cfg(target_os = "linux")]
    linux_password_admissions().begin_shutdown();
    while let Some(result) = transactions.join_next().await {
        if let Err(err) = result {
            log::error!("protected _service IPC transaction did not drain cleanly: {err}");
        }
    }
    #[cfg(target_os = "macos")]
    {
        password_mutations().drain().await;
        password_mutations().clear_after_transactions_drain();
    }
    #[cfg(target_os = "linux")]
    linux_password_admissions().clear_after_transactions_drain();
    drop(listener_guard);
    protected_service_ipc_result(listener_error)
}

#[cfg(target_os = "linux")]
async fn handle_sensitive_linux_service_ipc_transaction(
    mut stream: Conn,
    identity: PeerProcessIdentity,
    _permit: OwnedSemaphorePermit,
) {
    let deadline = tokio::time::Instant::now()
        + std::time::Duration::from_millis(SERVICE_IPC_REQUEST_TIMEOUT_MS);
    let request = match password::receive_request_unix(
        &mut stream,
        password::SensitivePayloadKind::Password,
        deadline,
    )
    .await
    {
        Ok(request) => request,
        Err(err) => {
            log::trace!("Linux service password IPC request was rejected: {err}");
            return;
        }
    };
    let operation_id = request.operation_id();
    let value = match request.into_password() {
        Ok(value) => value,
        Err(err) => {
            log::trace!("Linux service password IPC value was rejected: {err}");
            return;
        }
    };
    let status = execute_linux_service_owned_unattended_password_request(
        operation_id.to_string(),
        value,
        identity,
    )
    .await;
    if let Err(err) = password::send_status_unix(&mut stream, operation_id, status, deadline).await
    {
        log::trace!("Linux service password status could not be returned: {err}");
    }
}

#[cfg(target_os = "linux")]
async fn handle_linux_service_credential_snapshot_transaction(
    mut stream: Conn,
    identity: PeerProcessIdentity,
    _permit: OwnedSemaphorePermit,
) {
    let deadline = tokio::time::Instant::now()
        + std::time::Duration::from_millis(SERVICE_IPC_REQUEST_TIMEOUT_MS);
    let operation_id =
        match password::receive_credential_snapshot_request_unix(&mut stream, deadline).await {
            Ok(operation_id) => operation_id,
            Err(err) => {
                log::trace!("Linux service credential snapshot request was rejected: {err}");
                return;
            }
        };
    let refreshed = match authenticate_linux_service_owned_password_replica_server(
        &stream,
        password::SERVICE_CREDENTIAL_IPC_POSTFIX,
    ) {
        Ok(refreshed) => refreshed,
        Err(err) => {
            log::warn!("Rejected stale Linux service credential replica requester: {err}");
            return;
        }
    };
    if refreshed != identity {
        log::warn!("Rejected Linux service credential requester whose identity changed");
        return;
    }
    let replica = match service_owned_runtime_prs_replica("Linux") {
        Ok(replica) => replica,
        Err(err) => {
            log::error!("Linux root service credential snapshot is unavailable: {err}");
            return;
        }
    };
    if let Err(err) =
        password::send_credential_replica_unix(&mut stream, operation_id, &replica, deadline).await
    {
        log::trace!("Linux service credential snapshot could not be returned: {err}");
    }
}

#[cfg(target_os = "macos")]
async fn handle_macos_service_credential_snapshot_transaction(
    mut stream: Conn,
    _permit: OwnedSemaphorePermit,
) {
    let deadline = tokio::time::Instant::now()
        + std::time::Duration::from_millis(SERVICE_IPC_REQUEST_TIMEOUT_MS);
    let operation_id =
        match password::receive_credential_snapshot_request_unix(&mut stream, deadline).await {
            Ok(operation_id) => operation_id,
            Err(err) => {
                log::trace!("macOS service credential snapshot request was rejected: {err}");
                return;
            }
        };
    if !macos_peer_is_service_owned_server(&stream, deadline).await {
        log::warn!("Rejected macOS service credential snapshot requester");
        return;
    }
    let replica = match service_owned_runtime_prs_replica("macOS") {
        Ok(replica) => replica,
        Err(err) => {
            log::error!("macOS root service credential snapshot is unavailable: {err}");
            return;
        }
    };
    if let Err(err) =
        password::send_credential_replica_unix(&mut stream, operation_id, &replica, deadline).await
    {
        log::trace!("macOS service credential snapshot could not be returned: {err}");
    }
}

#[cfg(target_os = "macos")]
async fn handle_sensitive_macos_service_ipc_transaction(
    mut stream: Conn,
    _permit: OwnedSemaphorePermit,
    deadline: tokio::time::Instant,
) {
    let request = match password::receive_request_unix(
        &mut stream,
        password::SensitivePayloadKind::PasswordWithAuthorization,
        deadline,
    )
    .await
    {
        Ok(request) => request,
        Err(err) => {
            log::trace!("macOS service password IPC request was rejected: {err}");
            return;
        }
    };
    let operation_id = request.operation_id();
    let Some(_authorization_slot) = try_acquire_macos_service_password_ipc_authorization_slot()
    else {
        return;
    };
    let (request, authority_allowed) = match run_bounded_macos_security_proof(
        deadline,
        "macos-password-capability-proof",
        move || {
            let authority_allowed =
                crate::platform::ensure_service_owned_unattended_password_authorization_right()
                    && macos_peer_is_authorized_for_service_owned_password_change(
                        request.authorization(),
                    );
            Ok((request, authority_allowed))
        },
    )
    .await
    {
        Ok(result) => result,
        Err(err) => {
            log::warn!("macOS password authorization capability proof failed: {err}");
            return;
        }
    };
    let value = match request.into_password() {
        Ok(value) => value,
        Err(err) => {
            log::trace!("macOS service password IPC value was rejected: {err}");
            return;
        }
    };
    let status = handle_macos_service_owned_unattended_password_request(
        operation_id.to_string(),
        value,
        authority_allowed,
    )
    .await;
    if let Err(err) = password::send_status_unix(&mut stream, operation_id, status, deadline).await
    {
        log::trace!("macOS service password status could not be returned: {err}");
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn handle_main_ipc_transaction(mut stream: Connection, _permit: OwnedSemaphorePermit) {
    let request = stream
        .next_main_timeout(MAIN_IPC_TRANSACTION_TIMEOUT_MS)
        .await;
    let request = match request {
        Ok(Some(request)) => request,
        Ok(None) => {
            log::warn!("Rejected malformed main IPC request");
            return;
        }
        Err(err) => {
            log::trace!("main IPC request ended before its bounded frame: {err}");
            return;
        }
    };
    let response = handle_main_ipc_request(request, &stream).await;
    write_response_with_deadline(&mut stream, &response, "main IPC").await;
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn begin_password_mutation(
    operation_id: String,
    value: MainPasswordMutationValue,
    kind: PasswordMutationKind,
    authority_allowed: bool,
) -> (
    PasswordMutationStatus,
    Option<tokio::task::JoinHandle<IpcMutationResult>>,
) {
    let admission_allowed =
        authority_allowed && value.as_str().len() <= UNATTENDED_PASSWORD_MAX_BYTES;
    let preparation = password_mutations().prepare_if_allowed(
        &operation_id,
        kind,
        value.as_str(),
        admission_allowed,
    );
    if !preparation.owns_preparation {
        return (preparation.status, None);
    }

    let Some(permit) = try_acquire_main_ipc_blocking_mutation_slot() else {
        if !password_mutations().fail_admitted(&operation_id, kind, value.as_str()) {
            log::error!("password mutation capacity failure could not be finalized");
        }
        return (
            PasswordMutationStatus::Complete(IpcMutationResult::InternalFailure),
            None,
        );
    };
    if !password_mutations().acknowledge(&operation_id, kind, value.as_str()) {
        log::error!("password mutation preparation could not be acknowledged");
        if !password_mutations().fail_admitted(&operation_id, kind, value.as_str()) {
            log::error!("password mutation acknowledgement failure could not be finalized");
        }
        return (
            PasswordMutationStatus::Complete(IpcMutationResult::InternalFailure),
            None,
        );
    }
    let worker = spawn_password_mutation(operation_id.clone(), value, kind, permit);
    (PasswordMutationStatus::Prepared, Some(worker))
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn handle_main_ipc_request(request: MainIpcRequest, stream: &Connection) -> MainIpcResponse {
    match request {
        MainIpcRequest::StatusSnapshot => {
            #[cfg(target_os = "windows")]
            let file_transfer_enabled = {
                use hbb_common::rendezvous_proto::control_permissions::Permission;
                Some(
                    crate::server::get_control_permission_state(Permission::file, false)
                        .unwrap_or_else(|| {
                            crate::server::Connection::is_permission_enabled_locally(
                                config::keys::OPTION_ENABLE_FILE_TRANSFER,
                            )
                        }),
                )
            };
            #[cfg(not(target_os = "windows"))]
            let file_transfer_enabled = None;
            let id = Config::get_id();
            if id.len() > MAIN_IPC_MAX_ID_BYTES {
                log::error!("main IPC status ID exceeds its protocol limit");
                return MainIpcResponse::RequestFailed(IpcMutationResult::InternalFailure);
            }
            let options = match MainStatusOptions::from_config() {
                Ok(options) => options,
                Err(err) => {
                    log::error!("main IPC status options are invalid: {err}");
                    return MainIpcResponse::RequestFailed(IpcMutationResult::InternalFailure);
                }
            };
            MainIpcResponse::StatusSnapshot(MainStatusSnapshot {
                options,
                id,
                file_transfer_enabled,
            })
        }
        MainIpcRequest::ReadinessSnapshot => {
            MainIpcResponse::ReadinessSnapshot(MainReadinessSnapshot {
                permanent_password_set: permanent_password_is_set_for_current_process().await,
                user_owned_permanent_password_writable:
                    current_process_allows_user_owned_permanent_password_write()
                        && !Config::is_disable_change_permanent_password(),
                direct_listener_bound: crate::direct_service::is_direct_listener_bound(),
            })
        }
        MainIpcRequest::Config(key) => {
            let value = match key {
                MainConfigKey::Id => Some(Config::get_id()),
                MainConfigKey::PermanentPasswordSet => Some(
                    if permanent_password_is_set_for_current_process().await {
                        "Y"
                    } else {
                        "N"
                    }
                    .to_owned(),
                ),
                MainConfigKey::UserOwnedPermanentPasswordWritable => Some(
                    if current_process_allows_user_owned_permanent_password_write()
                        && !Config::is_disable_change_permanent_password()
                    {
                        "Y"
                    } else {
                        "N"
                    }
                    .to_owned(),
                ),
                MainConfigKey::HideConnectionManager => {
                    if crate::common::is_custom_client() {
                        Some(hbb_common::password_security::hide_cm().to_string())
                    } else {
                        None
                    }
                }
                MainConfigKey::VoiceCallInput => {
                    crate::audio_service::get_voice_call_input_device()
                }
                MainConfigKey::DirectListenerBound => {
                    Some(crate::direct_service::is_direct_listener_bound().to_string())
                }
            };
            if value
                .as_ref()
                .is_some_and(|value| value.len() > MAIN_IPC_MAX_CONFIG_VALUE_BYTES)
            {
                log::error!("main IPC config value exceeds its protocol limit");
                return MainIpcResponse::RequestFailed(IpcMutationResult::InternalFailure);
            }
            MainIpcResponse::Config { key, value }
        }
        MainIpcRequest::SetVoiceCallInput(value) => {
            if !MainIpcAuthority::for_current_process().allows_main_channel_voice_call_input_write()
            {
                return MainIpcResponse::VoiceCallInputSet(IpcMutationResult::Rejected);
            }
            if value.len() > MAIN_IPC_MAX_OPTION_VALUE_BYTES {
                return MainIpcResponse::VoiceCallInputSet(IpcMutationResult::Rejected);
            }
            let Some(permit) = try_acquire_main_ipc_blocking_mutation_slot() else {
                return MainIpcResponse::VoiceCallInputSet(IpcMutationResult::InternalFailure);
            };
            let applied = match tokio::task::spawn_blocking(move || {
                let _permit = permit;
                crate::audio_service::set_voice_call_input_device(value);
            })
            .await
            {
                Ok(()) => IpcMutationResult::Applied,
                Err(err) => {
                    log::error!("voice-call input mutation worker failed: {err}");
                    IpcMutationResult::InternalFailure
                }
            };
            MainIpcResponse::VoiceCallInputSet(applied)
        }
        MainIpcRequest::PasswordMutationStatus { operation_id } => {
            let kind = if MainIpcAuthority::for_current_process() == MainIpcAuthority::ServiceOwned
            {
                PasswordMutationKind::ServiceOwned
            } else {
                PasswordMutationKind::UserOwned
            };
            MainIpcResponse::PasswordMutation(password_mutations().status(&operation_id, kind))
        }
        MainIpcRequest::SetOption(value) => {
            if !current_process_allows_main_channel_options_write() {
                return MainIpcResponse::OptionSet {
                    result: IpcMutationResult::Rejected,
                    effective: None,
                };
            }
            let value = match value.validate() {
                Ok(value) => value,
                Err(err) => {
                    log::warn!("Rejected invalid main IPC option write: {err}");
                    return MainIpcResponse::OptionSet {
                        result: IpcMutationResult::Rejected,
                        effective: None,
                    };
                }
            };
            let Some(permit) = try_acquire_main_ipc_blocking_mutation_slot() else {
                return MainIpcResponse::OptionSet {
                    result: IpcMutationResult::InternalFailure,
                    effective: None,
                };
            };
            let applied = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let _restart = CheckIfRestart::new();
                let key = value.key;
                let key_name = key.as_str().to_owned();
                Config::set_option(key_name.clone(), value.value);
                MainStatusOption {
                    key,
                    value: Config::get_option(&key_name),
                }
            })
            .await;
            match applied {
                Ok(effective) => MainIpcResponse::OptionSet {
                    result: IpcMutationResult::Applied,
                    effective: Some(effective),
                },
                Err(err) => {
                    log::error!("option mutation worker failed: {err}");
                    MainIpcResponse::OptionSet {
                        result: IpcMutationResult::InternalFailure,
                        effective: None,
                    }
                }
            }
        }
        MainIpcRequest::ValidateCmConnection {
            id,
            conn_type,
            cm_auth_token,
        } => {
            if id <= 0
                || cm_auth_token.is_empty()
                || cm_auth_token.len() > MAIN_IPC_MAX_AUTH_TOKEN_BYTES
            {
                return MainIpcResponse::CmConnectionValidation(CmConnectionAuthority::default());
            }
            MainIpcResponse::CmConnectionValidation(
                crate::server::validate_cm_connection_authority(id, conn_type, &cm_auth_token),
            )
        }
        #[cfg(target_os = "linux")]
        MainIpcRequest::ValidatePulseAudioStart { token } => {
            let valid = !token.is_empty()
                && token.len() <= MAIN_IPC_MAX_AUTH_TOKEN_BYTES
                && ipc_auth::linux_kernel_peer_process_identity(stream, "")
                    .map(|peer| crate::audio_service::validate_pa_capture_authority(&token, &peer))
                    .unwrap_or(false);
            MainIpcResponse::PulseAudioStartValidation(valid)
        }
        #[cfg(target_os = "windows")]
        MainIpcRequest::CpuUsage => {
            MainIpcResponse::CpuUsage(hbb_common::platform::windows::cpu_uage_one_minute())
        }
        #[cfg(target_os = "windows")]
        MainIpcRequest::ControlledSessionCount => {
            MainIpcResponse::ControlledSessionCount(crate::Connection::alive_conns().len())
        }
        #[cfg(target_os = "linux")]
        MainIpcRequest::TerminalSessionCount => MainIpcResponse::TerminalSessionCount(
            crate::terminal_service::get_terminal_session_count(true),
        ),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn handle_service_ipc_transaction(mut stream: Connection, postfix: &str) {
    match stream
        .next_service_request_timeout(SERVICE_IPC_REQUEST_TIMEOUT_MS)
        .await
    {
        Err(err) => log::trace!(
            "protected _service IPC request closed before a bounded request frame: {err}"
        ),
        Ok(Some(request)) => handle_service_request(request, &mut stream).await,
        Ok(None) => log::warn!(
            "Rejected malformed data on protected _service IPC channel: postfix={}, peer_uid={:?}",
            postfix,
            stream.peer_uid()
        ),
    }
}

#[cfg(target_os = "windows")]
struct PreparedWindowsServiceMainIpc {
    credential_incoming: Incoming,
    control_incoming: Incoming,
    listener_guard: LocalIpcListenerGuard,
}

#[cfg(target_os = "windows")]
async fn prepare_windows_service_main_ipc() -> ResultType<PreparedWindowsServiceMainIpc> {
    if !is_service_owned_server_process() || !crate::platform::is_root() {
        bail!("Windows service-main IPC requires the service-owned LocalSystem server role");
    }
    let credential_incoming = new_listener(WINDOWS_SERVICE_CREDENTIAL_IPC_POSTFIX).await?;
    let control_incoming = new_listener(WINDOWS_SERVICE_MAIN_CONTROL_IPC_POSTFIX).await?;
    let listener_guard = LocalIpcListenerGuard::activate(
        &WINDOWS_SERVICE_MAIN_LISTENER_STATE,
        "Windows service-main listeners",
    )?;
    Ok(PreparedWindowsServiceMainIpc {
        credential_incoming,
        control_incoming,
        listener_guard,
    })
}

#[cfg(target_os = "windows")]
async fn run_windows_service_main_ipc(listeners: PreparedWindowsServiceMainIpc) -> ResultType<()> {
    let PreparedWindowsServiceMainIpc {
        mut credential_incoming,
        mut control_incoming,
        listener_guard,
    } = listeners;
    let mut transactions = JoinSet::new();
    let shutdown = crate::server::shutdown_token();
    let mut listener_error = None;
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            result = control_incoming.next() => {
                let Some(result) = result else {
                    listener_error = Some("Windows service-main control IPC listener ended unexpectedly".to_owned());
                    crate::server::request_graceful_shutdown_after_listener_failure();
                    break;
                };
                let stream = match result {
                    Ok(stream) => stream,
                    Err(err) => {
                        log::error!("Could not accept Windows service-main IPC client: {err}");
                        continue;
                    }
                };
                let stream = Connection::new_protected_service(stream);
                if !authorize_windows_service_main_ipc_connection(&stream) {
                    continue;
                }
                let endpoint = WindowsServiceMainEndpoint::Control;
                let Some(permit) = try_acquire_windows_service_main_transaction_slot(endpoint) else {
                    log::debug!("Rejected Windows service-main control connection because work is at capacity");
                    continue;
                };
                transactions.spawn(handle_windows_service_main_transaction(
                    stream,
                    permit,
                    endpoint,
                ));
            }
            completed = transactions.join_next(), if !transactions.is_empty() => {
                if let Some(Err(err)) = completed {
                    log::error!("Windows service-main transaction task failed: {err}");
                }
            }
            result = credential_incoming.next() => {
                let Some(result) = result else {
                    listener_error = Some("Windows service credential IPC listener ended unexpectedly".to_owned());
                    crate::server::request_graceful_shutdown_after_listener_failure();
                    break;
                };
                let stream = match result {
                    Ok(stream) => stream,
                    Err(err) => {
                        log::error!("Could not accept Windows service-main control IPC client: {err}");
                        continue;
                    }
                };
                let stream = Connection::new_protected_service(stream);
                if !authorize_windows_service_main_ipc_connection(&stream) {
                    continue;
                }
                let endpoint = WindowsServiceMainEndpoint::Credential;
                let Some(permit) = try_acquire_windows_service_main_transaction_slot(endpoint) else {
                    log::debug!("Rejected Windows service credential connection because work is at capacity");
                    continue;
                };
                transactions.spawn(handle_windows_service_main_transaction(
                    stream,
                    permit,
                    endpoint,
                ));
            }
        }
    }
    let drain = async {
        while let Some(result) = transactions.join_next().await {
            if let Err(err) = result {
                log::error!("Windows service-main transaction did not drain cleanly: {err}");
            }
        }
    };
    if tokio::time::timeout(
        std::time::Duration::from_millis(WINDOWS_SERVICE_MAIN_TRANSACTION_DRAIN_TIMEOUT_MS),
        drain,
    )
    .await
    .is_err()
    {
        log::error!("Windows service-main transactions exceeded their shutdown deadline");
        transactions.abort_all();
        while transactions.join_next().await.is_some() {}
    }
    drop(listener_guard);
    match listener_error {
        Some(err) => Err(hbb_common::anyhow::anyhow!(err)),
        None => Ok(()),
    }
}

#[cfg(target_os = "windows")]
async fn handle_windows_service_main_transaction(
    mut stream: Connection,
    _permit: OwnedSemaphorePermit,
    endpoint: WindowsServiceMainEndpoint,
) {
    let request = match stream
        .next_windows_service_main_request_timeout(SERVICE_IPC_REQUEST_TIMEOUT_MS)
        .await
    {
        Ok(Some(request)) => request,
        Ok(None) => {
            log::warn!("Rejected malformed Windows service-main IPC request");
            return;
        }
        Err(err) => {
            log::trace!("Windows service-main IPC request timed out: {err}");
            return;
        }
    };
    if !authorize_windows_service_main_ipc_connection(&stream) {
        return;
    }
    match request {
        WindowsServiceMainRequest::QuiesceCredentialReplica { transition_id } => {
            if endpoint != WindowsServiceMainEndpoint::Credential {
                log::warn!("Rejected credential quiesce on Windows service-main control IPC");
                return;
            }
            let response = if !password_mutation_id_is_valid(&transition_id) {
                WindowsCredentialReplicaResponse::Rejected
            } else {
                match crate::server::quiesce_windows_credential_replica(&transition_id) {
                    Ok(state) => WindowsCredentialReplicaResponse::State(state),
                    Err(err) => {
                        log::warn!("Rejected Windows credential replica quiesce: {err}");
                        WindowsCredentialReplicaResponse::Rejected
                    }
                }
            };
            write_response_with_deadline(
                &mut stream,
                &WindowsServiceMainResponse::CredentialReplica(response),
                "Windows credential replica quiesce",
            )
            .await;
        }
        WindowsServiceMainRequest::ApplyCredentialReplica {
            transition_id,
            storage,
            salt,
            replica_tag,
        } => {
            if endpoint != WindowsServiceMainEndpoint::Credential {
                log::warn!("Rejected credential apply on Windows service-main control IPC");
                return;
            }
            let response = if !password_mutation_id_is_valid(&transition_id)
                || storage.len() > WINDOWS_CREDENTIAL_SNAPSHOT_COMPONENT_MAX_BYTES
                || salt.len() > WINDOWS_CREDENTIAL_SNAPSHOT_COMPONENT_MAX_BYTES
            {
                WindowsCredentialReplicaResponse::Rejected
            } else {
                match crate::server::apply_windows_credential_replica(
                    &transition_id,
                    &storage,
                    &salt,
                    replica_tag,
                ) {
                    Ok(state) => WindowsCredentialReplicaResponse::State(state),
                    Err(err) => {
                        log::warn!("Rejected Windows credential replica apply: {err}");
                        WindowsCredentialReplicaResponse::Rejected
                    }
                }
            };
            write_response_with_deadline(
                &mut stream,
                &WindowsServiceMainResponse::CredentialReplica(response),
                "Windows credential replica apply",
            )
            .await;
        }
        WindowsServiceMainRequest::QueryCredentialReplica => {
            if endpoint != WindowsServiceMainEndpoint::Credential {
                log::warn!("Rejected credential query on Windows service-main control IPC");
                return;
            }
            let response = WindowsCredentialReplicaResponse::State(
                crate::server::query_windows_credential_replica(),
            );
            write_response_with_deadline(
                &mut stream,
                &WindowsServiceMainResponse::CredentialReplica(response),
                "Windows credential replica query",
            )
            .await;
        }
        WindowsServiceMainRequest::ResumeCredentialReplica { transition_id } => {
            if endpoint != WindowsServiceMainEndpoint::Credential {
                log::warn!("Rejected credential resume on Windows service-main control IPC");
                return;
            }
            let response = if !password_mutation_id_is_valid(&transition_id) {
                WindowsCredentialReplicaResponse::Rejected
            } else {
                match crate::server::resume_windows_credential_replica(&transition_id) {
                    Ok(state) => WindowsCredentialReplicaResponse::State(state),
                    Err(err) => {
                        log::warn!("Rejected Windows credential replica resume: {err}");
                        WindowsCredentialReplicaResponse::Rejected
                    }
                }
            };
            write_response_with_deadline(
                &mut stream,
                &WindowsServiceMainResponse::CredentialReplica(response),
                "Windows credential replica resume",
            )
            .await;
        }
        WindowsServiceMainRequest::PortForwardSessionCount => {
            if endpoint != WindowsServiceMainEndpoint::Control {
                log::warn!("Rejected port-forward count on Windows service credential IPC");
                return;
            }
            let count = crate::server::AUTHED_CONNS
                .lock()
                .unwrap()
                .iter()
                .filter(|connection| {
                    connection.conn_type == crate::server::AuthConnType::PortForward
                })
                .count();
            let response = WindowsServiceMainResponse::PortForwardSessionCount(count);
            write_response_with_deadline(
                &mut stream,
                &response,
                "Windows service-main session count",
            )
            .await;
        }
        WindowsServiceMainRequest::Shutdown => {
            if endpoint != WindowsServiceMainEndpoint::Control {
                log::warn!("Rejected shutdown on Windows service credential IPC");
                return;
            }
            let response = WindowsServiceMainResponse::ShutdownAccepted;
            if !write_response_with_deadline(
                &mut stream,
                &response,
                "Windows service-main shutdown acknowledgement",
            )
            .await
            {
                return;
            }
            crate::server::request_graceful_shutdown();
        }
    }
}
pub async fn new_listener(postfix: &str) -> ResultType<Incoming> {
    let path = Config::ipc_path(postfix);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let should_scrub_parent_entries = ensure_secure_ipc_parent_dir(&path, postfix)?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let existing_listener_alive = check_pid(postfix).await?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if should_scrub_parent_entries_after_check_pid(
        should_scrub_parent_entries,
        existing_listener_alive,
    ) {
        scrub_secure_ipc_parent_dir(&path, postfix)?;
    }
    let mut endpoint = Endpoint::new(path.clone());
    #[cfg(windows)]
    let attr = windows_ipc_listener_security_attributes(postfix).map_err(|err| {
        log::error!("Failed to set ipc{} security: {}", postfix, err);
        err
    })?;
    #[cfg(not(windows))]
    let attr = SecurityAttributes::allow_everyone_create().map_err(|err| {
        log::error!("Failed to set ipc{} security: {}", postfix, err);
        hbb_common::anyhow::Error::from(err)
    })?;
    endpoint.set_security_attributes(attr);
    match endpoint.incoming() {
        Ok(incoming) => {
            if postfix == crate::POSTFIX_SERVICE {
                log::info!("Started protected ipc service server: postfix={}", postfix);
            } else {
                log::info!("Started ipc{} server at path: {}", postfix, &path);
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                // NOTE: On Linux/macOS, some IPC sockets are intentionally world-connectable
                // (0666) so the active (non-root) user process can connect. Authorization is
                // enforced at accept-time for these channels, and the protected `_service`
                // channel is further restricted by an explicit message allowlist.
                let socket_mode = if config::is_service_ipc_postfix(postfix) {
                    0o0666
                } else {
                    0o0600
                };
                if let Err(err) =
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(socket_mode))
                {
                    log::error!(
                        "Failed to set permissions on ipc{} socket at path {}: {}",
                        postfix,
                        &path,
                        err
                    );
                    std::fs::remove_file(&path).ok();
                    return Err(err.into());
                }
                write_pid(postfix);
            }
            Ok(incoming)
        }
        Err(err) => {
            log::error!(
                "Failed to start ipc{} server at path {}: {}",
                postfix,
                path,
                err
            );
            Err(err.into())
        }
    }
}

pub struct CheckIfRestart {
    audio_input: String,
    voice_call_input: String,
}

impl CheckIfRestart {
    pub fn new() -> CheckIfRestart {
        CheckIfRestart {
            audio_input: Config::get_option("audio-input"),
            voice_call_input: Config::get_option("voice-call-input"),
        }
    }
}
impl Drop for CheckIfRestart {
    fn drop(&mut self) {
        // R-D4: the audio-device watches are the ONLY live restart triggers on the direct-only
        // build. The former mediator-restart watch (stop-service / rendezvous-servers / disable-udp)
        // is removed: RendezvousMediator::restart() is a no-op here (no rendezvous registration loop
        // to break — the direct listener runs continuously, R-D4); stop-service and
        // custom-rendezvous-server are lockdown-pinned (so constant); and disable-udp is vestigial
        // (UDP is excised — no transport path reads it). The earlier allow-websocket /
        // allow-insecure-tls-fallback / api-server watches (+ the tls-cache reset they gated) were
        // already removed for the same dead-change-detection reason.
        if self.audio_input != Config::get_option("audio-input") {
            crate::audio_service::restart();
        }
        if self.voice_call_input != Config::get_option("voice-call-input") {
            crate::audio_service::set_voice_call_input_device(Config::get_option(
                "voice-call-input",
            ))
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainIpcAuthority {
    UserOwned,
    ServiceOwned,
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
impl MainIpcAuthority {
    fn for_current_process() -> Self {
        #[cfg(target_os = "windows")]
        if crate::platform::is_root() {
            return Self::ServiceOwned;
        }
        if is_service_owned_server_process() {
            Self::ServiceOwned
        } else {
            Self::UserOwned
        }
    }

    fn allows_main_channel_user_owned_password_write(self) -> bool {
        matches!(self, Self::UserOwned)
    }
    fn allows_main_channel_options_write(self) -> bool {
        matches!(self, Self::UserOwned)
    }
    fn allows_main_channel_voice_call_input_write(self) -> bool {
        matches!(self, Self::UserOwned)
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[inline]
fn current_process_allows_user_owned_permanent_password_write() -> bool {
    MainIpcAuthority::for_current_process().allows_main_channel_user_owned_password_write()
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[inline]
fn current_process_allows_main_channel_options_write() -> bool {
    MainIpcAuthority::for_current_process().allows_main_channel_options_write()
}

#[cfg(target_os = "linux")]
#[inline]
fn current_process_allows_service_owned_unattended_password_commit(stream: &Connection) -> bool {
    MainIpcAuthority::for_current_process() == MainIpcAuthority::ServiceOwned
        && stream.peer_uid() == Some(0)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const CM_ENDPOINT_PROOF_CONTEXT: &[u8] = b"rustdesk.cm.endpoint-proof.v1";

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const CM_SERVER_PROOF_CONTEXT: &[u8] = b"rustdesk.cm.server-proof.v1";

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const CM_ENDPOINT_AUTH_TIMEOUT_MS: u64 = 1_000;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
const WHITEBOARD_ENDPOINT_PROOF_CONTEXT: &[u8] = b"rustdesk.whiteboard.endpoint-proof.v1";

#[cfg(not(any(target_os = "android", target_os = "ios")))]
const WHITEBOARD_SERVER_PROOF_CONTEXT: &[u8] = b"rustdesk.whiteboard.server-proof.v1";

#[cfg(not(any(target_os = "android", target_os = "ios")))]
const WHITEBOARD_ENDPOINT_NAME_CONTEXT: &[u8] = b"rustdesk.whiteboard.endpoint-name.v1";

#[cfg(any(not(any(target_os = "android", target_os = "ios")), test))]
const WHITEBOARD_ENDPOINT_POSTFIX_PREFIX: &str = "_whiteboard_";

#[cfg(any(not(any(target_os = "android", target_os = "ios")), test))]
pub(crate) fn whiteboard_ipc_postfix_is_valid(postfix: &str) -> bool {
    postfix
        .strip_prefix(WHITEBOARD_ENDPOINT_POSTFIX_PREFIX)
        .is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
const WHITEBOARD_PROCESS_ROLE: &str = "--whiteboard";

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn helper_endpoint_hmac_key(
    helper_name: &str,
    launch_token: &str,
) -> ResultType<hbb_common::sodiumoxide::crypto::auth::hmacsha256::Key> {
    if launch_token.is_empty() {
        bail!("missing {helper_name} launch token");
    }
    let token = match crate::decode64(launch_token) {
        Ok(token) => token,
        Err(err) => bail!("invalid {helper_name} launch token: {err}"),
    };
    if token.len() != hbb_common::sodiumoxide::crypto::auth::hmacsha256::KEYBYTES {
        bail!("invalid {helper_name} launch token length");
    }
    let mut key = [0u8; hbb_common::sodiumoxide::crypto::auth::hmacsha256::KEYBYTES];
    key.copy_from_slice(&token);
    Ok(hbb_common::sodiumoxide::crypto::auth::hmacsha256::Key(key))
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn helper_launch_proof_message(
    helper_name: &str,
    context: &[u8],
    challenge: &str,
) -> ResultType<Vec<u8>> {
    if challenge.is_empty() {
        bail!("missing {helper_name} endpoint challenge");
    }
    let mut message = Vec::with_capacity(context.len() + 1 + challenge.len());
    message.extend_from_slice(context);
    message.push(0);
    message.extend_from_slice(challenge.as_bytes());
    Ok(message)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn helper_launch_proof_for_challenge(
    helper_name: &str,
    context: &[u8],
    challenge: &str,
    launch_token: &str,
) -> ResultType<String> {
    let key = helper_endpoint_hmac_key(helper_name, launch_token)?;
    let message = helper_launch_proof_message(helper_name, context, challenge)?;
    let proof = hbb_common::sodiumoxide::crypto::auth::hmacsha256::authenticate(&message, &key);
    Ok(crate::encode64(proof.as_ref()))
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn verify_helper_launch_proof(
    helper_name: &str,
    context: &[u8],
    challenge: &str,
    proof: &str,
    launch_token: &str,
) -> ResultType<()> {
    let key = helper_endpoint_hmac_key(helper_name, launch_token)?;
    let message = helper_launch_proof_message(helper_name, context, challenge)?;
    let proof = match crate::decode64(proof) {
        Ok(proof) => proof,
        Err(err) => bail!("invalid {helper_name} endpoint proof: {err}"),
    };
    let Some(proof) = hbb_common::sodiumoxide::crypto::auth::hmacsha256::Tag::from_slice(&proof)
    else {
        bail!("invalid {helper_name} endpoint proof length");
    };
    if !hbb_common::sodiumoxide::crypto::auth::hmacsha256::verify(&proof, &message, &key) {
        bail!("{helper_name} endpoint proof rejected");
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn cm_role_bound_challenge(role: &str, challenge: &str) -> ResultType<String> {
    if !matches!(role, "--cm" | "--cm-no-ui") {
        bail!("invalid connection-manager role");
    }
    if challenge.is_empty() {
        bail!("missing connection-manager endpoint challenge");
    }
    Ok(format!("{role}\0{challenge}"))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn cm_launch_proof_for_challenge(
    context: &[u8],
    challenge: &str,
    launch_token: &str,
    role: &str,
) -> ResultType<String> {
    let challenge = cm_role_bound_challenge(role, challenge)?;
    helper_launch_proof_for_challenge("connection-manager", context, &challenge, launch_token)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn verify_cm_launch_proof(
    context: &[u8],
    challenge: &str,
    proof: &str,
    launch_token: &str,
    role: &str,
) -> ResultType<()> {
    let challenge = cm_role_bound_challenge(role, challenge)?;
    verify_helper_launch_proof(
        "connection-manager",
        context,
        &challenge,
        proof,
        launch_token,
    )
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn cm_endpoint_proof_for_challenge(
    challenge: &str,
    launch_token: &str,
    role: &str,
) -> ResultType<String> {
    cm_launch_proof_for_challenge(CM_ENDPOINT_PROOF_CONTEXT, challenge, launch_token, role)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn verify_cm_endpoint_proof(
    challenge: &str,
    proof: &str,
    launch_token: &str,
    role: &str,
) -> ResultType<()> {
    verify_cm_launch_proof(
        CM_ENDPOINT_PROOF_CONTEXT,
        challenge,
        proof,
        launch_token,
        role,
    )
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn cm_server_proof_for_challenge(
    challenge: &str,
    launch_token: &str,
    role: &str,
) -> ResultType<String> {
    cm_launch_proof_for_challenge(CM_SERVER_PROOF_CONTEXT, challenge, launch_token, role)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn verify_cm_server_proof(
    challenge: &str,
    proof: &str,
    launch_token: &str,
    role: &str,
) -> ResultType<()> {
    verify_cm_launch_proof(
        CM_SERVER_PROOF_CONTEXT,
        challenge,
        proof,
        launch_token,
        role,
    )
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn whiteboard_endpoint_name_suffix(launch_token: &str) -> ResultType<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let key = helper_endpoint_hmac_key("whiteboard", launch_token)?;
    let tag = hbb_common::sodiumoxide::crypto::auth::hmacsha256::authenticate(
        WHITEBOARD_ENDPOINT_NAME_CONTEXT,
        &key,
    );
    let mut out = String::with_capacity(32);
    for byte in tag.as_ref().iter().take(16) {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(out)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn whiteboard_role_bound_challenge(role: &str, challenge: &str) -> ResultType<String> {
    if role != WHITEBOARD_PROCESS_ROLE {
        bail!("invalid whiteboard role");
    }
    if challenge.is_empty() {
        bail!("missing whiteboard endpoint challenge");
    }
    Ok(format!("{WHITEBOARD_PROCESS_ROLE}\0{challenge}"))
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn whiteboard_launch_proof_for_challenge(
    context: &[u8],
    challenge: &str,
    launch_token: &str,
    role: &str,
) -> ResultType<String> {
    let challenge = whiteboard_role_bound_challenge(role, challenge)?;
    helper_launch_proof_for_challenge("whiteboard", context, &challenge, launch_token)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn verify_whiteboard_launch_proof(
    context: &[u8],
    challenge: &str,
    proof: &str,
    launch_token: &str,
    role: &str,
) -> ResultType<()> {
    let challenge = whiteboard_role_bound_challenge(role, challenge)?;
    verify_helper_launch_proof("whiteboard", context, &challenge, proof, launch_token)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) fn whiteboard_endpoint_postfix(launch_token: &str) -> ResultType<String> {
    Ok(format!(
        "{}{}",
        WHITEBOARD_ENDPOINT_POSTFIX_PREFIX,
        whiteboard_endpoint_name_suffix(launch_token)?
    ))
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) fn whiteboard_endpoint_postfix_from_env() -> ResultType<String> {
    let launch_token = std::env::var(crate::common::WHITEBOARD_LAUNCH_TOKEN_ENV)
        .map_err(|err| hbb_common::anyhow::anyhow!("missing whiteboard launch token: {err}"))?;
    whiteboard_endpoint_postfix(&launch_token)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) fn whiteboard_endpoint_proof_for_challenge(
    challenge: &str,
    launch_token: &str,
    role: &str,
) -> ResultType<String> {
    whiteboard_launch_proof_for_challenge(
        WHITEBOARD_ENDPOINT_PROOF_CONTEXT,
        challenge,
        launch_token,
        role,
    )
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) fn verify_whiteboard_endpoint_proof(
    challenge: &str,
    proof: &str,
    launch_token: &str,
    role: &str,
) -> ResultType<()> {
    verify_whiteboard_launch_proof(
        WHITEBOARD_ENDPOINT_PROOF_CONTEXT,
        challenge,
        proof,
        launch_token,
        role,
    )
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn whiteboard_server_proof_for_challenge(
    challenge: &str,
    launch_token: &str,
    role: &str,
) -> ResultType<String> {
    whiteboard_launch_proof_for_challenge(
        WHITEBOARD_SERVER_PROOF_CONTEXT,
        challenge,
        launch_token,
        role,
    )
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn verify_whiteboard_server_proof(
    challenge: &str,
    proof: &str,
    launch_token: &str,
    role: &str,
) -> ResultType<()> {
    verify_whiteboard_launch_proof(
        WHITEBOARD_SERVER_PROOF_CONTEXT,
        challenge,
        proof,
        launch_token,
        role,
    )
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn current_whiteboard_process_role() -> ResultType<String> {
    let mut args = std::env::args();
    let _executable = args.next();
    let role = args
        .next()
        .ok_or_else(|| hbb_common::anyhow::anyhow!("whiteboard process role is unavailable"))?;
    if args.next().is_some() || role != WHITEBOARD_PROCESS_ROLE {
        bail!("invalid whiteboard process role");
    }
    Ok(role)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) async fn authenticate_cm_endpoint_launch_proof<T>(
    stream: &mut ConnectionTmpl<T>,
    launch_token: &str,
    expected_role: &str,
) -> ResultType<()>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin,
{
    match stream.next_timeout(CM_ENDPOINT_AUTH_TIMEOUT_MS).await? {
        Some(Data::CmServerChallenge { challenge }) => {
            let proof = cm_server_proof_for_challenge(&challenge, launch_token, expected_role)?;
            stream
                .send_json_timeout(&Data::CmServerProof { proof }, CM_ENDPOINT_AUTH_TIMEOUT_MS)
                .await?;
        }
        _ => bail!("connection-manager server launch challenge missing"),
    }

    let challenge = crate::encode64(hbb_common::rand::random::<[u8; 32]>());
    stream
        .send_json_timeout(
            &Data::CmEndpointChallenge {
                challenge: challenge.clone(),
            },
            CM_ENDPOINT_AUTH_TIMEOUT_MS,
        )
        .await?;
    match stream.next_timeout(CM_ENDPOINT_AUTH_TIMEOUT_MS).await? {
        Some(Data::CmEndpointProof { proof }) => {
            verify_cm_endpoint_proof(&challenge, &proof, launch_token, expected_role)
        }
        _ => bail!("connection-manager endpoint did not prove launch authority"),
    }
}

#[cfg(target_os = "windows")]
pub(crate) async fn connect_authenticated_windows_cm(
    ms_timeout: u64,
    expected_arg: &str,
    launch_token: &str,
    expected_identity: ipc_auth::WindowsProcessIdentityKey,
) -> ResultType<ConnectionTmpl<ConnClient>> {
    let mut stream = connect(ms_timeout, "_cm").await?;
    authenticate_windows_cm_endpoint(&stream, expected_arg, expected_identity)?;
    authenticate_cm_endpoint_launch_proof(&mut stream, launch_token, expected_arg).await?;
    Ok(stream)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn current_cm_process_role() -> ResultType<String> {
    let mut args = std::env::args();
    let _executable = args.next();
    let role = args
        .next()
        .ok_or_else(|| hbb_common::anyhow::anyhow!("connection-manager role is unavailable"))?;
    if args.next().is_some() || !matches!(role.as_str(), "--cm" | "--cm-no-ui") {
        bail!("invalid connection-manager process role");
    }
    Ok(role)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) async fn answer_cm_endpoint_challenge<T>(
    stream: &mut ConnectionTmpl<T>,
) -> ResultType<()>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin,
{
    let launch_token = match std::env::var(crate::common::CM_LAUNCH_TOKEN_ENV) {
        Ok(token) => token,
        Err(err) => bail!("missing connection-manager launch token: {err}"),
    };
    let role = current_cm_process_role()?;
    let server_challenge = crate::encode64(hbb_common::rand::random::<[u8; 32]>());
    stream
        .send_json_timeout(
            &Data::CmServerChallenge {
                challenge: server_challenge.clone(),
            },
            CM_ENDPOINT_AUTH_TIMEOUT_MS,
        )
        .await?;
    match stream.next_timeout(CM_ENDPOINT_AUTH_TIMEOUT_MS).await? {
        Some(Data::CmServerProof { proof }) => {
            verify_cm_server_proof(&server_challenge, &proof, &launch_token, &role)?;
        }
        _ => bail!("connection-manager server launch proof missing"),
    }

    match stream.next_timeout(CM_ENDPOINT_AUTH_TIMEOUT_MS).await? {
        Some(Data::CmEndpointChallenge { challenge }) => {
            let proof = cm_endpoint_proof_for_challenge(&challenge, &launch_token, &role)?;
            stream
                .send_json_timeout(
                    &Data::CmEndpointProof { proof },
                    CM_ENDPOINT_AUTH_TIMEOUT_MS,
                )
                .await
        }
        _ => bail!("connection-manager endpoint challenge missing"),
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) async fn authenticate_whiteboard_endpoint_launch_proof<T>(
    stream: &mut ConnectionTmpl<T>,
    launch_token: &str,
) -> ResultType<()>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin,
{
    match stream
        .next_whiteboard_helper_handshake_timeout(WHITEBOARD_IPC_IO_TIMEOUT_MS)
        .await?
    {
        WhiteboardHelperHandshake::ServerChallenge { challenge } => {
            let proof = whiteboard_server_proof_for_challenge(
                &challenge,
                launch_token,
                WHITEBOARD_PROCESS_ROLE,
            )?;
            stream
                .send_whiteboard_owner_handshake_timeout(
                    &WhiteboardOwnerHandshake::ServerProof { proof },
                    WHITEBOARD_IPC_IO_TIMEOUT_MS,
                )
                .await?;
        }
        WhiteboardHelperHandshake::EndpointProof { .. } => {
            bail!("whiteboard server launch challenge missing")
        }
    }

    let challenge = crate::encode64(hbb_common::rand::random::<[u8; 32]>());
    stream
        .send_whiteboard_owner_handshake_timeout(
            &WhiteboardOwnerHandshake::EndpointChallenge {
                challenge: challenge.clone(),
            },
            WHITEBOARD_IPC_IO_TIMEOUT_MS,
        )
        .await?;
    match stream
        .next_whiteboard_helper_handshake_timeout(WHITEBOARD_IPC_IO_TIMEOUT_MS)
        .await?
    {
        WhiteboardHelperHandshake::EndpointProof { proof } => verify_whiteboard_endpoint_proof(
            &challenge,
            &proof,
            launch_token,
            WHITEBOARD_PROCESS_ROLE,
        ),
        WhiteboardHelperHandshake::ServerChallenge { .. } => {
            bail!("whiteboard endpoint did not prove launch authority")
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) async fn answer_whiteboard_endpoint_challenge<T>(
    stream: &mut ConnectionTmpl<T>,
) -> ResultType<()>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin,
{
    let launch_token = std::env::var(crate::common::WHITEBOARD_LAUNCH_TOKEN_ENV)
        .map_err(|err| hbb_common::anyhow::anyhow!("missing whiteboard launch token: {err}"))?;
    let role = current_whiteboard_process_role()?;
    let server_challenge = crate::encode64(hbb_common::rand::random::<[u8; 32]>());
    stream
        .send_whiteboard_helper_handshake_timeout(
            &WhiteboardHelperHandshake::ServerChallenge {
                challenge: server_challenge.clone(),
            },
            WHITEBOARD_IPC_IO_TIMEOUT_MS,
        )
        .await?;
    match stream
        .next_whiteboard_owner_handshake_timeout(WHITEBOARD_IPC_IO_TIMEOUT_MS)
        .await?
    {
        WhiteboardOwnerHandshake::ServerProof { proof } => {
            verify_whiteboard_server_proof(&server_challenge, &proof, &launch_token, &role)?;
        }
        WhiteboardOwnerHandshake::EndpointChallenge { .. } => {
            bail!("whiteboard server launch proof missing")
        }
    }

    match stream
        .next_whiteboard_owner_handshake_timeout(WHITEBOARD_IPC_IO_TIMEOUT_MS)
        .await?
    {
        WhiteboardOwnerHandshake::EndpointChallenge { challenge } => {
            let proof = whiteboard_endpoint_proof_for_challenge(&challenge, &launch_token, &role)?;
            stream
                .send_whiteboard_helper_handshake_timeout(
                    &WhiteboardHelperHandshake::EndpointProof { proof },
                    WHITEBOARD_IPC_IO_TIMEOUT_MS,
                )
                .await
        }
        WhiteboardOwnerHandshake::ServerProof { .. } => {
            bail!("whiteboard endpoint challenge missing")
        }
    }
}

#[cfg(target_os = "linux")]
const SET_UNATTENDED_PASSWORD_POLKIT_ACTION: &str = "com.carriez.RustDesk.set-unattended-password";
#[cfg(target_os = "linux")]
const PKCHECK_PATH: &str = "/usr/bin/pkcheck";
#[cfg(target_os = "linux")]
const PKCHECK_AUTHORIZATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
#[cfg(target_os = "linux")]
const PKCHECK_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(25);

#[cfg(target_os = "linux")]
fn linux_path_is_clean_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

#[cfg(target_os = "linux")]
fn linux_trusted_command_file_metadata(is_file: bool, uid: u32, mode: u32) -> bool {
    is_file && uid == 0 && mode & 0o022 == 0 && mode & 0o111 != 0
}

#[cfg(target_os = "linux")]
fn linux_trusted_command_parent_metadata(is_dir: bool, uid: u32, mode: u32) -> bool {
    is_dir && uid == 0 && mode & 0o022 == 0
}

#[cfg(target_os = "linux")]
fn linux_trusted_command_file(metadata: &fs::Metadata) -> bool {
    linux_trusted_command_file_metadata(metadata.is_file(), metadata.uid(), metadata.mode())
}

#[cfg(target_os = "linux")]
fn linux_trusted_command_parent(metadata: &fs::Metadata) -> bool {
    linux_trusted_command_parent_metadata(metadata.is_dir(), metadata.uid(), metadata.mode())
}

#[cfg(target_os = "linux")]
fn linux_trusted_authority_command_path(path: &Path) -> Option<PathBuf> {
    if !linux_path_is_clean_absolute(path) {
        return None;
    }
    let candidate_parent = path.parent()?;
    if !linux_trusted_command_parent(&fs::metadata(candidate_parent).ok()?) {
        return None;
    }
    let canonical = fs::canonicalize(path).ok()?;
    if !linux_path_is_clean_absolute(&canonical) {
        return None;
    }
    let canonical_parent = canonical.parent()?;
    if !linux_trusted_command_parent(&fs::metadata(canonical_parent).ok()?) {
        return None;
    }
    if !linux_trusted_command_file(&fs::metadata(&canonical).ok()?) {
        return None;
    }
    Some(canonical)
}

#[cfg(target_os = "linux")]
fn trusted_linux_pkcheck_path() -> Option<PathBuf> {
    linux_trusted_authority_command_path(Path::new(PKCHECK_PATH))
}

#[cfg(target_os = "linux")]
fn linux_polkit_subject_for_identity(identity: &PeerProcessIdentity) -> String {
    format!(
        "{},{},{}",
        identity.pid(),
        identity.start_time(),
        identity.uid()
    )
}

#[cfg(target_os = "linux")]
fn terminate_and_reap_linux_pkcheck(child: &mut std::process::Child, reason: &str) {
    if let Err(err) = child.kill() {
        log::debug!("pkcheck termination after {reason} returned: {err}");
    }
    if let Err(err) = child.wait() {
        log::error!("Failed to reap pkcheck after {reason}: {err}");
    }
}

#[cfg(target_os = "linux")]
fn configure_linux_pkcheck_environment(command: &mut std::process::Command) {
    command.env_clear();
}

#[cfg(target_os = "linux")]
fn linux_pkcheck_authorizes_service_owned_password_change(
    subject: String,
    shutdown: hbb_common::tokio_util::sync::CancellationToken,
) -> bool {
    let Some(pkcheck) = trusted_linux_pkcheck_path() else {
        log::warn!(
            "Rejected service-owned unattended password change: no trusted pkcheck executable at {}",
            PKCHECK_PATH
        );
        return false;
    };
    let mut command = std::process::Command::new(pkcheck);
    configure_linux_pkcheck_environment(&mut command);
    command
        .arg("--action-id")
        .arg(SET_UNATTENDED_PASSWORD_POLKIT_ACTION)
        .arg("--process")
        .arg(&subject)
        .arg("--allow-user-interaction")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Err(err) =
        hbb_common::platform::linux::configure_command_close_nonstdio_on_exec(&mut command)
    {
        log::warn!(
            "Rejected service-owned unattended password change: failed to constrain pkcheck descriptors for action={}, subject={}, err={}",
            SET_UNATTENDED_PASSWORD_POLKIT_ACTION,
            subject,
            err
        );
        return false;
    }
    let child = command.spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(err) => {
            log::warn!(
                "Rejected service-owned unattended password change: failed to run pkcheck for action={}, subject={}, err={}",
                SET_UNATTENDED_PASSWORD_POLKIT_ACTION,
                subject,
                err
            );
            return false;
        }
    };
    let deadline = std::time::Instant::now() + PKCHECK_AUTHORIZATION_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return true,
            Ok(Some(status)) => {
                log::warn!(
                    "Rejected service-owned unattended password change: polkit denied action={}, subject={}, status={}",
                    SET_UNATTENDED_PASSWORD_POLKIT_ACTION,
                    subject,
                    status
                );
                return false;
            }
            Ok(None) if shutdown.is_cancelled() => {
                terminate_and_reap_linux_pkcheck(&mut child, "service shutdown");
                return false;
            }
            Ok(None) if std::time::Instant::now() >= deadline => {
                log::warn!(
                    "Rejected service-owned unattended password change: pkcheck exceeded its authorization deadline"
                );
                terminate_and_reap_linux_pkcheck(&mut child, "authorization timeout");
                return false;
            }
            Ok(None) => std::thread::sleep(PKCHECK_POLL_INTERVAL),
            Err(err) => {
                log::warn!(
                    "Rejected service-owned unattended password change: failed to poll pkcheck for action={}, subject={}, err={}",
                    SET_UNATTENDED_PASSWORD_POLKIT_ACTION,
                    subject,
                    err
                );
                terminate_and_reap_linux_pkcheck(&mut child, "status failure");
                return false;
            }
        }
    }
}

#[cfg(target_os = "linux")]
async fn linux_peer_is_authorized_for_service_owned_password_change(
    identity: &PeerProcessIdentity,
) -> bool {
    let subject = linux_polkit_subject_for_identity(identity);
    let shutdown = crate::server::shutdown_token();
    match tokio::task::spawn_blocking(move || {
        linux_pkcheck_authorizes_service_owned_password_change(subject, shutdown)
    })
    .await
    {
        Ok(authorized) => {
            authorized
                && peer_process_identity_is_live(identity, password::SERVICE_PASSWORD_IPC_POSTFIX)
        }
        Err(err) => {
            log::warn!(
                "Rejected service-owned unattended password change: pkcheck task failed: {err}"
            );
            false
        }
    }
}

#[cfg(target_os = "linux")]
async fn execute_linux_service_owned_password_operation<
    Authorize,
    AuthorizeFuture,
    Commit,
    CommitFuture,
>(
    coordinator: &LinuxPasswordAdmissionCoordinator,
    operation_id: &str,
    value: &str,
    caller: &LinuxPasswordCaller,
    mut authorize: Authorize,
    mut commit: Commit,
) -> ResultType<IpcMutationResult>
where
    Authorize: FnMut() -> AuthorizeFuture,
    AuthorizeFuture: std::future::Future<Output = bool>,
    Commit: FnMut() -> CommitFuture,
    CommitFuture: std::future::Future<Output = ResultType<IpcMutationResult>>,
{
    let kind = PasswordMutationKind::ServiceOwned;
    let shutdown = crate::server::shutdown_token();
    loop {
        let changed = coordinator.changed.notified();
        match coordinator.begin(operation_id, kind, value, caller) {
            LinuxPasswordAdmissionDecision::Authorize => {
                let admitted = authorize().await;
                if !coordinator.finish_authorization(operation_id, caller, admitted) {
                    bail!("Linux password authorization admission state changed unexpectedly");
                }
                if !admitted {
                    return Ok(IpcMutationResult::Rejected);
                }
            }
            LinuxPasswordAdmissionDecision::Wait => {
                tokio::select! {
                    _ = changed => {}
                    _ = shutdown.cancelled() => {
                        bail!("Linux password authorization stopped during service shutdown")
                    }
                }
                continue;
            }
            LinuxPasswordAdmissionDecision::Recover => {}
            LinuxPasswordAdmissionDecision::Complete(result) => return Ok(result),
            LinuxPasswordAdmissionDecision::Rejected => return Ok(IpcMutationResult::Rejected),
            LinuxPasswordAdmissionDecision::ShuttingDown => {
                bail!("Linux password admission is shutting down")
            }
        }

        let result = match commit().await {
            Ok(result) => result,
            Err(err) => {
                if !coordinator.release_failed_commit(operation_id, caller) {
                    bail!("Linux password commit ownership changed after a commit failure");
                }
                return Err(err);
            }
        };
        if !coordinator.complete(operation_id, caller, result) {
            bail!("Linux admitted password operation could not record its terminal result");
        }
        return Ok(result);
    }
}

#[cfg(target_os = "linux")]
async fn commit_service_owned_unattended_password_change(
    operation_id: String,
    value: SensitivePassword,
) -> ResultType<IpcMutationResult> {
    let durable_value = value.clone();
    let durable_result = tokio::task::spawn_blocking(move || {
        Config::set_permanent_password_persisted(durable_value.as_str())
    })
    .await
    .map_err(|err| anyhow::anyhow!("Linux root credential writer failed to join: {err}"))??;
    if !durable_result {
        return Ok(IpcMutationResult::Rejected);
    }
    let replica = match service_owned_runtime_prs_replica("Linux") {
        Ok(replica) => replica,
        Err(err) => {
            crate::server::request_graceful_shutdown_after_authority_failure();
            return Err(anyhow::anyhow!(
                "Linux durable credential changed but its runtime replica is unavailable; service generation is stopping: {err}"
            ));
        }
    };
    let ms_timeout = 1_000;
    match complete_main_password_mutation(operation_id, &replica, true, ms_timeout).await {
        Ok(IpcMutationResult::Applied) => Ok(IpcMutationResult::Applied),
        Ok(result) => {
            crate::server::request_graceful_shutdown_after_authority_failure();
            bail!(
                "Linux durable credential changed but its runtime replica finished as {result:?}; service generation is stopping"
            )
        }
        Err(err) => {
            crate::server::request_graceful_shutdown_after_authority_failure();
            Err(anyhow::anyhow!(
                "Linux durable credential changed but its runtime replica did not converge; service generation is stopping: {err}"
            ))
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn service_owned_runtime_prs_replica(platform: &str) -> ResultType<SensitivePassword> {
    match Config::read_permanent_password_prs() {
        hbb_common::config::PermanentPasswordPrsRead::Available(prs) => {
            Ok(SensitivePassword::new(prs))
        }
        hbb_common::config::PermanentPasswordPrsRead::Empty => {
            Ok(SensitivePassword::new(String::new()))
        }
        hbb_common::config::PermanentPasswordPrsRead::UndecryptableStorage => {
            bail!("{platform} root service credential storage is undecryptable")
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn service_owned_password_value_is_valid(platform: &str, password: &str) -> bool {
    if unattended_password_value_is_valid(password) {
        true
    } else {
        log::warn!(
            "Rejected {platform} service-owned password request with oversized password value"
        );
        false
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn unattended_password_value_is_valid(password: &str) -> bool {
    password.len() <= UNATTENDED_PASSWORD_MAX_BYTES
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn validate_unattended_password_value(password: &SensitivePassword) -> ResultType<()> {
    if !unattended_password_value_is_valid(password.as_str()) {
        bail!("Permanent password exceeds its protocol limit");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn execute_linux_service_owned_unattended_password_request(
    operation_id: String,
    value: SensitivePassword,
    identity: PeerProcessIdentity,
) -> PasswordMutationStatus {
    if !password_mutation_id_is_valid(&operation_id)
        || !service_owned_password_value_is_valid("Linux", value.as_str())
    {
        log::warn!("Rejected service-owned unattended password change");
        return PasswordMutationStatus::Complete(IpcMutationResult::Rejected);
    }
    let caller = LinuxPasswordCaller::from(&identity);
    let commit_operation_id = operation_id.clone();
    let mut commit_value = Some(value.clone());
    let result = match execute_linux_service_owned_password_operation(
        linux_password_admissions(),
        &operation_id,
        value.as_str(),
        &caller,
        || linux_peer_is_authorized_for_service_owned_password_change(&identity),
        || {
            let value = commit_value.take();
            let operation_id = commit_operation_id.clone();
            async move {
                let value = value.ok_or_else(|| {
                    hbb_common::anyhow::anyhow!(
                        "Linux password operation attempted more than one commit"
                    )
                })?;
                commit_service_owned_unattended_password_change(operation_id, value).await
            }
        },
    )
    .await
    {
        Ok(result) => PasswordMutationStatus::Complete(result),
        Err(err) => {
            log::warn!(
                "Linux service-owned password operation remains unresolved after transport failure: {err}"
            );
            PasswordMutationStatus::Pending
        }
    };
    result
}

#[cfg(target_os = "macos")]
fn macos_peer_is_authorized_for_service_owned_password_change(authorization: &[u8]) -> bool {
    if crate::platform::verify_service_owned_unattended_password_authorization(authorization) {
        return true;
    }
    log::warn!("Rejected macOS service-owned unattended password change: authorization denied");
    false
}

#[cfg(target_os = "macos")]
async fn macos_service_owned_password_authorization_right_is_ready(
    deadline: tokio::time::Instant,
) -> bool {
    let Some(_authorization_slot) = try_acquire_macos_service_password_ipc_authorization_slot()
    else {
        return false;
    };
    match run_bounded_macos_security_proof(deadline, "macos-password-right-proof", || {
        Ok(crate::platform::ensure_service_owned_unattended_password_authorization_right())
    })
    .await
    {
        Ok(true) => true,
        Ok(false) => {
            log::warn!(
                "Rejected macOS service-owned unattended password change: authorization right is unavailable"
            );
            false
        }
        Err(err) => {
            log::warn!("macOS password authorization right proof failed: {err}");
            false
        }
    }
}

#[cfg(target_os = "macos")]
async fn macos_peer_is_service_owned_server<T>(stream: &T, deadline: tokio::time::Instant) -> bool
where
    T: std::os::unix::io::AsRawFd,
{
    let identity = match ipc_auth::macos_peer_process_identity_from_stream(
        stream,
        "macOS service-owned credential snapshot requester",
    ) {
        Ok(identity) => identity,
        Err(err) => {
            log::warn!("Rejected macOS service-owned credential snapshot request: {err}");
            return false;
        }
    };
    let Some(_authorization_slot) = try_acquire_macos_service_credential_ipc_authorization_slot()
    else {
        return false;
    };
    let proof_deadline = deadline.into_std();
    match run_bounded_macos_security_proof(deadline, "macos-credential-snapshot-proof", move || {
        Ok(macos_peer_is_service_owned_server_blocking(
            identity,
            proof_deadline,
        ))
    })
    .await
    {
        Ok(accepted) => accepted,
        Err(err) => {
            log::warn!(
                "Rejected macOS service-owned credential snapshot request: peer proof task failed: {err}"
            );
            false
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn macos_service_owned_server_live_argv_is_expected(cmd: &[String]) -> bool {
    cmd.len() == 3
        && cmd.get(1).map(String::as_str) == Some("--server")
        && cmd.get(2).map(String::as_str) == Some(crate::common::SERVICE_OWNED_SERVER_ARG)
}

#[cfg(target_os = "macos")]
fn macos_peer_is_service_owned_server_blocking(
    identity: ipc_auth::MacosPeerProcessIdentity,
    proof_deadline: std::time::Instant,
) -> bool {
    if !ipc_auth::macos_peer_is_trusted_installed_app(&identity) {
        log::warn!(
            "Rejected macOS service-owned credential snapshot request: peer code is not the trusted installed app, peer_pid={}",
            identity.pid()
        );
        return false;
    }
    let peer_uid = identity.uid();
    let peer_pid = identity.pid();
    let app_name = crate::get_app_name();
    let system = hbb_common::sysinfo::System::new_all();
    let Some(process) = system
        .processes()
        .values()
        .find(|process| process.pid().as_u32() == peer_pid)
    else {
        log::warn!(
            "Rejected macOS service-owned credential snapshot request: peer process disappeared, peer_pid={peer_pid}"
        );
        return false;
    };
    if !process.name().eq_ignore_ascii_case(&app_name) {
        log::warn!(
            "Rejected macOS service-owned credential snapshot request: peer process is not {app_name}, peer_pid={peer_pid}"
        );
        return false;
    }
    if !macos_service_owned_server_live_argv_is_expected(process.cmd()) {
        log::warn!(
            "Rejected macOS service-owned credential snapshot request: peer process is not service-owned --server, peer_pid={peer_pid}"
        );
        return false;
    }
    macos_launch_agent_owns_service_owned_server_pid(peer_uid, peer_pid, proof_deadline)
        && ipc_auth::macos_peer_is_trusted_installed_app(&identity)
}

#[cfg(target_os = "macos")]
fn macos_service_owned_server_launch_agent_label() -> String {
    format!("{}_server", crate::get_full_name())
}

#[cfg(target_os = "macos")]
fn macos_service_owned_server_launch_agent_executable() -> String {
    let app_name = crate::get_app_name();
    format!("/Applications/{app_name}.app/Contents/MacOS/{app_name}")
}

#[cfg(target_os = "macos")]
fn macos_service_owned_server_launch_agent_plist() -> String {
    format!(
        "/Library/LaunchAgents/{}.plist",
        macos_service_owned_server_launch_agent_label()
    )
}

#[cfg(target_os = "macos")]
enum MacosTrustedPathKind {
    File,
    Directory,
}

#[cfg(target_os = "macos")]
fn macos_root_wheel_path_is_trusted(
    path: &std::path::Path,
    expected_kind: MacosTrustedPathKind,
) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    let expected_type = match expected_kind {
        MacosTrustedPathKind::File => metadata.is_file(),
        MacosTrustedPathKind::Directory => metadata.is_dir(),
    };
    expected_type
        && !metadata.file_type().is_symlink()
        && metadata.uid() == 0
        && metadata.gid() == 0
        && metadata.permissions().mode() & 0o022 == 0
        && ipc_auth::macos_path_has_no_extended_acl(path)
}

#[cfg(target_os = "macos")]
fn macos_service_owned_server_launch_agent_plist_is_trusted(path: &std::path::Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    macos_root_wheel_path_is_trusted(parent, MacosTrustedPathKind::Directory)
        && macos_root_wheel_path_is_trusted(path, MacosTrustedPathKind::File)
}

#[cfg(any(target_os = "macos", test))]
fn macos_service_owned_server_launch_agent_plist_value_is_expected(
    value: &plist::Value,
    expected_label: &str,
    expected_executable: &str,
) -> bool {
    let Some(dict) = value.as_dictionary() else {
        return false;
    };
    if dict.get("Label").and_then(|value| value.as_string()) != Some(expected_label) {
        return false;
    }
    let Some(program_arguments) = dict
        .get("ProgramArguments")
        .and_then(|value| value.as_array())
    else {
        return false;
    };
    let expected_arguments = [
        expected_executable,
        "--server",
        crate::common::SERVICE_OWNED_SERVER_ARG,
    ];
    if program_arguments.len() != expected_arguments.len() {
        return false;
    }
    if !program_arguments
        .iter()
        .zip(expected_arguments.iter())
        .all(|(actual, expected)| actual.as_string() == Some(*expected))
    {
        return false;
    }
    if dict.get("RunAtLoad").and_then(|value| value.as_boolean()) != Some(true) {
        return false;
    }
    let Some(keep_alive) = dict
        .get("KeepAlive")
        .and_then(|value| value.as_dictionary())
    else {
        return false;
    };
    if keep_alive.len() != 2 {
        return false;
    }
    keep_alive
        .get("SuccessfulExit")
        .and_then(|value| value.as_boolean())
        == Some(false)
        && keep_alive
            .get("AfterInitialDemand")
            .and_then(|value| value.as_boolean())
            == Some(false)
}

#[cfg(target_os = "macos")]
fn macos_service_owned_server_launch_agent_plist_content_is_expected(
    path: &std::path::Path,
) -> bool {
    let expected_label = macos_service_owned_server_launch_agent_label();
    let expected_executable = macos_service_owned_server_launch_agent_executable();
    match plist::Value::from_file(path) {
        Ok(value)
            if macos_service_owned_server_launch_agent_plist_value_is_expected(
                &value,
                &expected_label,
                &expected_executable,
            ) =>
        {
            true
        }
        Ok(_) => {
            log::warn!(
                "Rejected macOS service-owned credential snapshot request: LaunchAgent plist does not match service-owned server command shape: {}",
                path.display()
            );
            false
        }
        Err(err) => {
            log::warn!(
                "Rejected macOS service-owned credential snapshot request: failed to parse LaunchAgent plist '{}': {err}",
                path.display()
            );
            false
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn macos_launchctl_scalar_value(value: &str) -> Option<&str> {
    let value = value.trim();
    let value = value.strip_suffix(';').unwrap_or(value).trim();
    match (value.strip_prefix('"'), value.strip_suffix('"')) {
        (Some(_), None) | (None, Some(_)) => None,
        (Some(value), Some(_)) => value.strip_suffix('"'),
        (None, None) => Some(value),
    }
}

#[cfg(any(target_os = "macos", test))]
fn macos_launchctl_service_identity<'a>(
    output: &'a [u8],
    expected_target: &str,
) -> Option<(u32, &'a str)> {
    let output = std::str::from_utf8(output).ok()?;
    let mut lines = output.lines();
    let expected_header = format!("{expected_target} = {{");
    if lines.next()?.trim() != expected_header {
        return None;
    }

    let mut depth = 1usize;
    let mut pid = None;
    let mut path = None;
    let mut closed = false;
    while let Some(line) = lines.next() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == "}" {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                closed = true;
                break;
            }
            continue;
        }
        if line.ends_with(" = {") || line.ends_with(" => {") {
            depth = depth.checked_add(1)?;
            continue;
        }
        if depth != 1 {
            continue;
        }

        let Some((key, value)) = line.split_once(" = ") else {
            continue;
        };
        match key {
            "pid" => {
                if pid.is_some() {
                    return None;
                }
                let value = macos_launchctl_scalar_value(value)?;
                let parsed = value.parse::<u32>().ok().filter(|pid| *pid != 0)?;
                if parsed.to_string() != value {
                    return None;
                }
                pid = Some(parsed);
            }
            "path" => {
                if path.is_some() {
                    return None;
                }
                path = Some(macos_launchctl_scalar_value(value)?);
            }
            _ => {}
        }
    }
    if !closed || lines.any(|line| !line.trim().is_empty()) {
        return None;
    }
    Some((pid?, path?))
}

#[cfg(any(target_os = "macos", all(target_os = "linux", test)))]
#[derive(Debug)]
struct MacosBoundedChildOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
}

#[cfg(any(target_os = "macos", all(target_os = "linux", test)))]
fn set_macos_bounded_child_stdout_nonblocking(
    stdout: &std::process::ChildStdout,
) -> ResultType<()> {
    use std::os::fd::AsRawFd;

    let fd = stdout.as_raw_fd();
    let flags = unsafe { hbb_common::libc::fcntl(fd, hbb_common::libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe {
        hbb_common::libc::fcntl(
            fd,
            hbb_common::libc::F_SETFL,
            flags | hbb_common::libc::O_NONBLOCK,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(any(target_os = "macos", all(target_os = "linux", test)))]
fn terminate_and_reap_macos_bounded_child(child: &mut std::process::Child) -> ResultType<()> {
    match child.try_wait() {
        Ok(Some(_)) => return Ok(()),
        Ok(None) | Err(_) => {}
    }
    let kill_error = child.kill().err();
    match child.wait() {
        Ok(_) => Ok(()),
        Err(wait_error) => match kill_error {
            Some(kill_error) => Err(anyhow::anyhow!(
                "child termination failed ({kill_error}) and reap failed ({wait_error})"
            )),
            None => Err(anyhow::anyhow!(
                "child reap failed after termination: {wait_error}"
            )),
        },
    }
}

#[cfg(any(target_os = "macos", all(target_os = "linux", test)))]
fn macos_bounded_child_failure(
    child: &mut std::process::Child,
    reason: impl std::fmt::Display,
) -> hbb_common::anyhow::Error {
    match terminate_and_reap_macos_bounded_child(child) {
        Ok(()) => anyhow::anyhow!("{reason}"),
        Err(cleanup_error) => {
            anyhow::anyhow!("{reason}; child cleanup failed: {cleanup_error}")
        }
    }
}

/// Run only from the exactly owned blocking macOS proof worker. The nonblocking pipe keeps
/// capture, child status, and the caller's absolute deadline under one synchronous owner.
#[cfg(any(target_os = "macos", all(target_os = "linux", test)))]
fn run_macos_bounded_child_stdout(
    command: &mut std::process::Command,
    deadline: std::time::Instant,
    stdout_limit: usize,
) -> ResultType<MacosBoundedChildOutput> {
    use std::io::Read;

    if stdout_limit == 0 {
        bail!("bounded child stdout limit must be nonzero");
    }
    if std::time::Instant::now() >= deadline {
        bail!("bounded child deadline elapsed before spawn");
    }
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|err| anyhow::anyhow!("failed to spawn bounded child: {err}"))?;
    let mut stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            return Err(macos_bounded_child_failure(
                &mut child,
                "bounded child stdout pipe is unavailable",
            ));
        }
    };
    if let Err(err) = set_macos_bounded_child_stdout_nonblocking(&stdout) {
        return Err(macos_bounded_child_failure(
            &mut child,
            format_args!("failed to make bounded child stdout nonblocking: {err}"),
        ));
    }

    let mut captured = Vec::with_capacity(stdout_limit.min(16 * 1024));
    let mut buffer = [0u8; 8 * 1024];
    let mut status = None;
    let mut stdout_closed = false;
    loop {
        while !stdout_closed {
            match stdout.read(&mut buffer) {
                Ok(0) => {
                    stdout_closed = true;
                }
                Ok(count) => {
                    if count > stdout_limit.saturating_sub(captured.len()) {
                        return Err(macos_bounded_child_failure(
                            &mut child,
                            format_args!("bounded child stdout exceeded {stdout_limit} bytes"),
                        ));
                    }
                    captured.extend_from_slice(&buffer[..count]);
                }
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(err) => {
                    return Err(macos_bounded_child_failure(
                        &mut child,
                        format_args!("failed to read bounded child stdout: {err}"),
                    ));
                }
            }
        }

        if status.is_none() {
            match child.try_wait() {
                Ok(Some(child_status)) => status = Some(child_status),
                Ok(None) => {}
                Err(err) => {
                    return Err(macos_bounded_child_failure(
                        &mut child,
                        format_args!("failed to poll bounded child: {err}"),
                    ));
                }
            }
        }
        if stdout_closed {
            if let Some(status) = status.take() {
                return Ok(MacosBoundedChildOutput {
                    status,
                    stdout: captured,
                });
            }
        }

        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(macos_bounded_child_failure(
                &mut child,
                "bounded child exceeded its absolute deadline",
            ));
        }
        std::thread::sleep(
            MACOS_LAUNCHCTL_POLL_INTERVAL.min(deadline.saturating_duration_since(now)),
        );
    }
}

#[cfg(target_os = "macos")]
fn macos_launch_agent_owns_service_owned_server_pid(
    peer_uid: u32,
    peer_pid: u32,
    proof_deadline: std::time::Instant,
) -> bool {
    let label = macos_service_owned_server_launch_agent_label();
    let expected_plist = macos_service_owned_server_launch_agent_plist();
    let expected_plist_path = std::path::Path::new(&expected_plist);
    if !macos_service_owned_server_launch_agent_plist_is_trusted(expected_plist_path) {
        log::warn!(
            "Rejected macOS service-owned credential snapshot request: LaunchAgent plist is not trusted: {expected_plist}"
        );
        return false;
    }
    if !macos_service_owned_server_launch_agent_plist_content_is_expected(expected_plist_path) {
        return false;
    }
    let Some(child_deadline) = proof_deadline.checked_sub(MACOS_LAUNCHCTL_REAP_RESERVE) else {
        log::warn!(
            "Rejected macOS service-owned credential snapshot request: launchctl proof deadline is unavailable"
        );
        return false;
    };
    if std::time::Instant::now() >= child_deadline {
        log::warn!(
            "Rejected macOS service-owned credential snapshot request: launchctl proof deadline elapsed"
        );
        return false;
    }

    let target = format!("gui/{peer_uid}/{label}");
    let mut command = std::process::Command::new(MACOS_LAUNCHCTL);
    command
        .arg("print")
        .arg(&target)
        .current_dir("/")
        .env_clear()
        .env("LC_ALL", "C");
    if let Err(err) =
        hbb_common::platform::macos::configure_command_close_nonstdio_on_exec(&mut command)
    {
        log::warn!(
            "Rejected macOS service-owned credential snapshot request: failed to constrain launchctl descriptors: {err}"
        );
        return false;
    }
    let output = match run_macos_bounded_child_stdout(
        &mut command,
        child_deadline,
        MACOS_LAUNCHCTL_STDOUT_MAX_BYTES,
    ) {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            log::warn!(
                "Rejected macOS service-owned credential snapshot request: launchctl print {target} failed with status {}",
                output.status
            );
            return false;
        }
        Err(err) => {
            log::warn!(
                "Rejected macOS service-owned credential snapshot request: bounded launchctl print {target} failed: {err}"
            );
            return false;
        }
    };
    let reported_identity = macos_launchctl_service_identity(&output.stdout, &target);
    if reported_identity != Some((peer_pid, expected_plist.as_str())) {
        log::warn!(
            "Rejected macOS service-owned credential snapshot request: LaunchAgent target={target} did not report the exact top-level pid and plist path"
        );
        return false;
    }
    true
}

#[cfg(target_os = "macos")]
async fn permanent_password_is_set_for_current_process() -> bool {
    if crate::common::is_service_owned_server_process() {
        return refresh_macos_service_owned_permanent_password_snapshot_for_status().await;
    }
    Config::has_permanent_password()
}

#[cfg(target_os = "macos")]
async fn refresh_macos_service_owned_permanent_password_snapshot_for_status() -> bool {
    match refresh_macos_service_owned_permanent_password_snapshot(1_000).await {
        Ok(is_set) => is_set,
        Err(err) => {
            log::debug!("Failed to refresh macOS service-owned password status snapshot: {err}");
            if let Err(clear_err) = Config::set_permanent_password_prs_for_runtime("") {
                log::warn!(
                    "Failed to clear macOS service-owned runtime PRS after snapshot refresh failure: {clear_err}"
                );
            }
            false
        }
    }
}

#[cfg(not(target_os = "macos"))]
async fn permanent_password_is_set_for_current_process() -> bool {
    Config::has_permanent_password()
}

#[cfg(target_os = "macos")]
async fn handle_macos_service_owned_unattended_password_request(
    operation_id: String,
    password: SensitivePassword,
    authority_allowed: bool,
) -> PasswordMutationStatus {
    let kind = PasswordMutationKind::ServiceOwned;
    let admission_allowed = password_mutation_id_is_valid(&operation_id)
        && authority_allowed
        && service_owned_password_value_is_valid("macOS", password.as_str());
    let preparation = password_mutations().prepare_if_allowed(
        &operation_id,
        kind,
        password.as_str(),
        admission_allowed,
    );
    let result = if preparation.owns_preparation {
        let Some(permit) = try_acquire_main_ipc_blocking_mutation_slot() else {
            if !password_mutations().fail_admitted(&operation_id, kind, password.as_str()) {
                log::error!("macOS password admission failure could not be finalized");
            }
            return PasswordMutationStatus::Complete(IpcMutationResult::InternalFailure);
        };
        if !password_mutations().acknowledge(&operation_id, kind, password.as_str()) {
            log::error!("macOS password preparation could not be acknowledged");
            if !password_mutations().fail_admitted(&operation_id, kind, password.as_str()) {
                log::error!("macOS password acknowledgement failure could not be finalized");
            }
            IpcMutationResult::InternalFailure
        } else {
            let worker = spawn_password_mutation(operation_id.clone(), password, kind, permit);
            match worker.await {
                Ok(result) => result,
                Err(err) => {
                    log::error!("macOS password mutation worker failed: {err}");
                    IpcMutationResult::InternalFailure
                }
            }
        }
    } else {
        match preparation.status {
            PasswordMutationStatus::Complete(result) => result,
            PasswordMutationStatus::Prepared | PasswordMutationStatus::Pending => {
                match tokio::time::timeout(
                    Duration::from_millis(SERVICE_IPC_REQUEST_TIMEOUT_MS),
                    password_mutations().wait_for_complete(&operation_id, kind),
                )
                .await
                {
                    Ok(Some(result)) => result,
                    Ok(None) | Err(_) => return PasswordMutationStatus::Pending,
                }
            }
            PasswordMutationStatus::Unknown | PasswordMutationStatus::ShuttingDown => {
                IpcMutationResult::InternalFailure
            }
        }
    };
    PasswordMutationStatus::Complete(result)
}

#[cfg(target_os = "windows")]
pub(crate) async fn handle_windows_service_owned_share_rdp_request(
    enable: bool,
    stream: &mut Connection,
) {
    let accepted = windows_peer_is_authorized_for_service_owned_share_rdp_change(stream)
        && match crate::platform::windows::set_service_owned_share_rdp(enable) {
            Ok(()) => true,
            Err(err) => {
                log::warn!("Rejected Windows service-owned RDP session-sharing change: {err}");
                false
            }
        };
    if !accepted {
        log::warn!("Rejected Windows service-owned RDP session-sharing change");
    }
    if let Err(err) = stream
        .send_service_response_timeout(
            &ServiceIpcResponse::ShareRdpSet { accepted },
            SERVICE_IPC_REQUEST_TIMEOUT_MS,
        )
        .await
    {
        log::warn!("Failed to send Windows service-owned RDP result: {err}");
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn handle_service_request(request: ServiceIpcRequest, stream: &mut Connection) {
    match request {
        ServiceIpcRequest::LivenessProbe {} => {
            if let Err(err) = stream
                .send_service_response_timeout(
                    &ServiceIpcResponse::Liveness {},
                    SERVICE_IPC_REQUEST_TIMEOUT_MS,
                )
                .await
            {
                log::debug!("Failed to send service IPC liveness response: {err}");
            }
        }
        #[cfg(target_os = "macos")]
        ServiceIpcRequest::EnsurePasswordRightReady {} => {
            let deadline = tokio::time::Instant::now()
                + std::time::Duration::from_millis(SERVICE_IPC_REQUEST_TIMEOUT_MS);
            let ready = macos_service_owned_password_authorization_right_is_ready(deadline).await;
            let response_timeout = match password::remaining_millis(deadline) {
                Ok(timeout) => timeout,
                Err(err) => {
                    log::warn!("macOS password-right readiness deadline expired: {err}");
                    return;
                }
            };
            if let Err(err) = stream
                .send_service_response_timeout(
                    &ServiceIpcResponse::PasswordRightReady { ready },
                    response_timeout,
                )
                .await
            {
                log::warn!("Failed to send macOS password-right readiness result: {err}");
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn windows_peer_is_authorized_for_service_owned_share_rdp_change(stream: &Connection) -> bool {
    windows_peer_is_authorized_for_service_owned_request(
        stream,
        "Windows service-owned RDP session-sharing change",
    )
}

#[cfg(target_os = "windows")]
fn windows_peer_is_authorized_for_service_owned_request(stream: &Connection, action: &str) -> bool {
    match stream.windows_pipe_client_token_is_elevated() {
        Ok(true) => true,
        Ok(false) => {
            log::warn!("Rejected {action}: caller token is not elevated");
            false
        }
        Err(err) => {
            log::warn!("Rejected {action}: failed to verify caller token elevation: {err}");
            false
        }
    }
}

#[inline]
async fn connect_with_path(
    ms_timeout: u64,
    path: &str,
    postfix: &str,
) -> ResultType<ConnectionTmpl<ConnClient>> {
    #[cfg(target_os = "macos")]
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(ms_timeout);
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    if matches!(
        postfix,
        password::USER_PASSWORD_IPC_POSTFIX | password::SERVICE_PASSWORD_IPC_POSTFIX
    ) {
        bail!("sensitive password endpoints require the raw transport");
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if postfix == password::SERVICE_CREDENTIAL_IPC_POSTFIX {
        bail!("the service credential endpoint requires the raw transport");
    }
    #[cfg(windows)]
    {
        let client = timeout(ms_timeout, connect_windows_named_pipe(path)).await??;
        ensure_windows_ipc_server_matches_current(&client, postfix)?;
        let mut connection = if config::is_service_ipc_postfix(postfix)
            || postfix == WINDOWS_SERVICE_CREDENTIAL_IPC_POSTFIX
            || postfix == WINDOWS_SERVICE_MAIN_CONTROL_IPC_POSTFIX
            || postfix == WINDOWS_SERVICE_SAS_IPC_POSTFIX
        {
            ConnectionTmpl::new_protected_service(client)
        } else if postfix.is_empty() {
            ConnectionTmpl::new_main(client)
        } else if postfix == "_url" {
            ConnectionTmpl::new_desktop_url(client)
        } else if whiteboard_ipc_postfix_is_valid(postfix) {
            ConnectionTmpl::new_whiteboard(client)
        } else {
            ConnectionTmpl::new(client)
        };
        if postfix == "_cm" {
            connection.set_max_packet_length(CM_IPC_MAX_FRAME_BYTES);
        }
        return Ok(connection);
    }
    #[cfg(not(windows))]
    {
        #[cfg(target_os = "macos")]
        let connect_timeout = password::remaining_millis(deadline)?;
        #[cfg(not(target_os = "macos"))]
        let connect_timeout = ms_timeout;
        let client = timeout(connect_timeout, Endpoint::connect(path)).await??;
        let mut connection = if config::is_service_ipc_postfix(postfix) {
            ConnectionTmpl::new_protected_service(client)
        } else if postfix.is_empty() {
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            {
                ConnectionTmpl::new_main(client)
            }
            #[cfg(any(target_os = "android", target_os = "ios"))]
            {
                bail!("desktop main IPC is unavailable on mobile");
            }
        } else {
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            {
                if postfix == "_url" {
                    ConnectionTmpl::new_desktop_url(client)
                } else if whiteboard_ipc_postfix_is_valid(postfix) {
                    ConnectionTmpl::new_whiteboard(client)
                } else {
                    #[cfg(target_os = "linux")]
                    {
                        if postfix == "_pa" {
                            ConnectionTmpl::new_pulse_audio(client)
                        } else {
                            ConnectionTmpl::new(client)
                        }
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        ConnectionTmpl::new(client)
                    }
                }
            }
            #[cfg(any(target_os = "android", target_os = "ios"))]
            {
                ConnectionTmpl::new(client)
            }
        };
        if postfix == "_cm" {
            connection.set_max_packet_length(CM_IPC_MAX_FRAME_BYTES);
        }
        #[cfg(target_os = "linux")]
        if config::is_service_ipc_postfix(postfix) {
            ensure_linux_root_service_connection(&connection, postfix)?;
        }
        #[cfg(target_os = "macos")]
        if config::is_service_ipc_postfix(postfix) {
            let authorization = ipc_auth::macos_service_server_authorization_snapshot(
                connection.inner.get_ref(),
                "macOS _service server",
            )?;
            authorize_macos_service_server_snapshot_for_task(authorization, deadline).await?;
            password::remaining_millis(deadline)?;
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let _ = postfix;
        Ok(connection)
    }
}

#[cfg(windows)]
async fn connect_windows_named_pipe(path: &str) -> std::io::Result<ConnClient> {
    loop {
        match open_windows_named_pipe_client(path) {
            Ok(client) => return Ok(client),
            Err(err) if err.raw_os_error() == Some(ERROR_PIPE_BUSY.0 as i32) => {}
            Err(err) => return Err(err),
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[cfg(windows)]
fn open_windows_named_pipe_client(path: &str) -> std::io::Result<ConnClient> {
    let wide_path: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let flags = FILE_FLAGS_AND_ATTRIBUTES(
        FILE_FLAG_OVERLAPPED.0 | SECURITY_IDENTIFICATION.0 | SECURITY_SQOS_PRESENT.0,
    );
    let handle = match unsafe {
        CreateFileW(
            PCWSTR::from_raw(wide_path.as_ptr()),
            windows_named_pipe_client_access_mask(),
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    } {
        Ok(handle) => handle,
        Err(_) => return Err(std::io::Error::last_os_error()),
    };
    let client = unsafe { ConnClient::from_raw_handle(handle.0 as RawHandle) };
    match client {
        Ok(client) => Ok(client),
        Err(err) => {
            unsafe {
                let _ = CloseHandle(handle);
            }
            Err(err)
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[inline]
fn select_server_uid_for_user_main_ipc(
    server_uids: &[u32],
    active_uid: Option<u32>,
    prefer_root: bool,
) -> ResultType<u32> {
    let mut server_uids = server_uids.to_vec();
    server_uids.sort_unstable();
    server_uids.dedup();

    match server_uids.as_slice() {
        [] => {
            if let Some(uid) = active_uid {
                // If no `--server` processes are found but the active user is identifiable,
                // try the active user anyway because the main process may also listen on "" IPC.
                return Ok(uid);
            } else {
                bail!("No --server process found for user main IPC")
            }
        }
        [uid] => return Ok(*uid),
        _ => {}
    }

    if prefer_root && server_uids.contains(&0) {
        return Ok(0);
    }
    if let Some(active_uid) = active_uid.filter(|uid| server_uids.contains(uid)) {
        return Ok(active_uid);
    }
    bail!("Multiple --server processes found for user main IPC");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn running_server_uids_for_current_exe() -> ResultType<Vec<u32>> {
    let current_exe = std::env::current_exe()?;
    let current_exe_path = std::fs::canonicalize(&current_exe)?;
    let current_pid = hbb_common::sysinfo::Pid::from_u32(std::process::id());
    let mut sys = hbb_common::sysinfo::System::new();
    sys.refresh_processes();
    let mut server_uids = Vec::new();
    for process in sys.processes().values() {
        if process.pid() == current_pid {
            continue;
        }
        if process.cmd().get(1).map_or(true, |arg| arg != "--server") {
            continue;
        }
        let Ok(process_path) = std::fs::canonicalize(process.exe()) else {
            continue;
        };
        if process_path != current_exe_path {
            continue;
        }
        let Some(uid) = process.user_id().map(|uid| **uid as u32) else {
            // Root CLI management commands need a stable matching `--server` target.
            // If this key process races during enumeration, failing the command is clearer
            // than silently skipping it; `--server` is not expected to exit frequently.
            bail!("Failed to read --server process uid");
        };
        server_uids.push(uid);
    }
    Ok(server_uids)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn user_main_ipc_server_uid() -> ResultType<u32> {
    let server_uids = running_server_uids_for_current_exe()?;
    #[cfg(target_os = "linux")]
    let prefer_root = crate::platform::linux::is_login_screen_wayland();
    #[cfg(target_os = "macos")]
    let prefer_root = false;
    select_server_uid_for_user_main_ipc(&server_uids, active_uid(), prefer_root)
}

pub async fn connect(ms_timeout: u64, postfix: &str) -> ResultType<ConnectionTmpl<ConnClient>> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    if matches!(
        postfix,
        password::USER_PASSWORD_IPC_POSTFIX | password::SERVICE_PASSWORD_IPC_POSTFIX
    ) {
        bail!("sensitive password endpoints require the raw transport");
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if postfix == password::SERVICE_CREDENTIAL_IPC_POSTFIX {
        bail!("the service credential endpoint requires the raw transport");
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let use_user_main_ipc = USE_USER_MAIN_IPC.with(|use_user_main| use_user_main.get());
        let is_user_main_endpoint = postfix.is_empty();
        let is_root_main_ipc = unsafe { hbb_common::libc::geteuid() == 0 }
            && is_user_main_endpoint
            && use_user_main_ipc;
        if is_root_main_ipc {
            let uid = user_main_ipc_server_uid()?;
            let path = Config::ipc_path_for_uid(uid, postfix);
            return connect_with_path(ms_timeout, &path, postfix).await;
        }
        let path = Config::ipc_path(postfix);
        return connect_with_path(ms_timeout, &path, postfix).await;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let path = Config::ipc_path(postfix);
        connect_with_path(ms_timeout, &path, postfix).await
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn connect_sensitive_unix(
    deadline: tokio::time::Instant,
    postfix: &str,
    service_owned_replica: bool,
) -> ResultType<ConnClient> {
    let use_user_main_ipc = USE_USER_MAIN_IPC.with(|use_user_main| use_user_main.get());
    let route_to_user_main = unsafe { hbb_common::libc::geteuid() == 0 }
        && postfix == password::USER_PASSWORD_IPC_POSTFIX
        && use_user_main_ipc;
    let (path, expected_user_uid) = if route_to_user_main {
        let uid = user_main_ipc_server_uid()?;
        (Config::ipc_path_for_uid(uid, postfix), Some(uid))
    } else {
        (
            Config::ipc_path(postfix),
            (postfix == password::USER_PASSWORD_IPC_POSTFIX)
                .then(|| unsafe { hbb_common::libc::geteuid() as u32 }),
        )
    };
    let stream = timeout(
        password::remaining_millis(deadline)?,
        Endpoint::connect(path),
    )
    .await??;
    match postfix {
        password::USER_PASSWORD_IPC_POSTFIX => {
            if service_owned_replica {
                #[cfg(target_os = "linux")]
                {
                    let identity = authenticate_linux_service_owned_password_replica_server(
                        &stream,
                        password::USER_PASSWORD_IPC_POSTFIX,
                    )?;
                    let expected_uid = expected_user_uid.ok_or_else(|| {
                        hbb_common::anyhow::anyhow!(
                            "service-owned password replica route has no expected uid"
                        )
                    })?;
                    if identity.uid() != expected_uid {
                        bail!(
                            "service-owned password replica uid mismatch: expected={}, actual={}",
                            expected_uid,
                            identity.uid()
                        );
                    }
                }
                #[cfg(target_os = "macos")]
                {
                    bail!("service-owned password replicas are unavailable on macOS");
                }
            } else {
                let expected_uid = expected_user_uid.ok_or_else(|| {
                    hbb_common::anyhow::anyhow!("user password IPC route has no expected uid")
                })?;
                ensure_user_owned_password_server_is_trusted(&stream, expected_uid)?;
            }
        }
        password::SERVICE_PASSWORD_IPC_POSTFIX => {
            #[cfg(target_os = "linux")]
            {
                ensure_linux_root_service_stream(&stream, postfix)?;
            }
            #[cfg(target_os = "macos")]
            {
                let authorization = ipc_auth::macos_service_server_authorization_snapshot(
                    &stream,
                    "macOS service password server",
                )?;
                authorize_macos_service_server_snapshot_for_task(authorization, deadline).await?;
            }
        }
        _ => bail!("unsupported sensitive Unix IPC endpoint"),
    }
    password::remaining_millis(deadline)?;
    Ok(stream)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn main_ipc_request(request: MainIpcRequest, ms_timeout: u64) -> ResultType<MainIpcResponse> {
    let stream = connect(ms_timeout, "").await?;
    main_ipc_request_on_stream(stream, request, ms_timeout).await
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn main_ipc_request_on_stream(
    mut stream: ConnectionTmpl<ConnClient>,
    request: MainIpcRequest,
    ms_timeout: u64,
) -> ResultType<MainIpcResponse> {
    stream
        .send_main_request_timeout(&request, ms_timeout)
        .await?;
    stream
        .next_main_response_timeout(ms_timeout)
        .await?
        .ok_or_else(|| hbb_common::anyhow::anyhow!("main IPC returned a malformed response"))
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn main_ipc_request_on_stream_deadline(
    mut stream: ConnectionTmpl<ConnClient>,
    request: MainIpcRequest,
    deadline: tokio::time::Instant,
) -> ResultType<MainIpcResponse> {
    stream
        .send_main_request_timeout(&request, password::remaining_millis(deadline)?)
        .await?;
    stream
        .next_main_response_timeout(password::remaining_millis(deadline)?)
        .await?
        .ok_or_else(|| hbb_common::anyhow::anyhow!("main IPC returned a malformed response"))
}

#[cfg(target_os = "windows")]
async fn connect_windows_cm_main(
    ms_timeout: u64,
) -> ResultType<ConnectionTmpl<ConnClient>> {
    let path = Config::ipc_path("");
    let client = timeout(ms_timeout, connect_windows_named_pipe(&path)).await??;
    ipc_auth::authenticate_windows_cm_main_server(&client)?;
    Ok(ConnectionTmpl::new_main(client))
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) async fn validate_cm_connection_authority(
    id: i32,
    conn_type: CmAuthConnType,
    cm_auth_token: &str,
) -> ResultType<CmConnectionAuthority> {
    if id <= 0 {
        bail!("invalid cm connection id");
    }
    if cm_auth_token.is_empty() {
        bail!("missing cm authority token");
    }

    let request = MainIpcRequest::ValidateCmConnection {
        id,
        conn_type,
        cm_auth_token: cm_auth_token.to_owned(),
    };
    #[cfg(target_os = "linux")]
    let response = {
        let stream = connect(1_000, "").await?;
        ipc_auth::authenticate_linux_cm_owner_stream(&stream)?;
        main_ipc_request_on_stream(stream, request, 1_000).await?
    };
    #[cfg(target_os = "windows")]
    let response = {
        let stream = connect_windows_cm_main(1_000).await?;
        main_ipc_request_on_stream(stream, request, 1_000).await?
    };
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    let response = main_ipc_request(request, 1_000).await?;
    match response {
        MainIpcResponse::CmConnectionValidation(result) => Ok(result),
        _ => bail!("invalid cm authority validation response"),
    }
}

#[cfg(target_os = "linux")]
async fn validate_pulse_audio_start_authority(
    owner: &LinuxProcessIdentity,
    token: &str,
) -> ResultType<()> {
    if token.is_empty() {
        bail!("missing pulse audio capture authority token");
    }
    if owner.pid() == std::process::id() {
        if let Ok(peer) = current_linux_process_identity() {
            if &peer == owner && crate::audio_service::validate_pa_capture_authority(token, &peer) {
                return Ok(());
            }
        }
        bail!("local pulse audio capture authority rejected");
    }

    let expected_owner = ipc_auth::linux_cm_owner_identity()?;
    if &expected_owner != owner {
        bail!("pulse audio capture owner is not the connection-manager launch parent");
    }
    let stream = connect_for_uid(1_000, owner.uid(), "").await?;
    ensure_linux_process_identity_matches(&stream, owner, "")?;
    match main_ipc_request_on_stream(
        stream,
        MainIpcRequest::ValidatePulseAudioStart {
            token: token.to_owned(),
        },
        1_000,
    )
    .await?
    {
        MainIpcResponse::PulseAudioStartValidation(true) => Ok(()),
        MainIpcResponse::PulseAudioStartValidation(false) => {
            bail!("pulse audio capture authority rejected")
        }
        _ => bail!("invalid pulse audio capture authority validation response"),
    }
}

#[cfg(target_os = "linux")]
pub async fn connect_for_uid(
    ms_timeout: u64,
    uid: u32,
    postfix: &str,
) -> ResultType<ConnectionTmpl<ConnClient>> {
    let path = Config::ipc_path_for_uid(uid, postfix);
    connect_with_path(ms_timeout, &path, postfix).await
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
pub async fn start_pa() {
    use crate::audio_service::AUDIO_DATA_SIZE_U8;

    match new_listener("_pa").await {
        Ok(mut incoming) => {
            loop {
                if let Some(result) = incoming.next().await {
                    match result {
                        Ok(stream) => {
                            let mut stream = Connection::new_pulse_audio(stream);
                            let request = match stream
                                .next_pulse_audio_request_timeout(
                                    PULSE_AUDIO_IPC_IO_TIMEOUT_MS,
                                )
                                .await
                            {
                                Ok(Some(request)) => request,
                                Ok(None) => {
                                    log::warn!(
                                        "Rejected _pa client with malformed capture request"
                                    );
                                    continue;
                                }
                                Err(err) => {
                                    log::warn!(
                                        "Rejected _pa client without timely capture authority: {}",
                                        err
                                    );
                                    continue;
                                }
                            };
                            let LinuxPulseAudioIpcRequest::StartCapture {
                                owner,
                                token,
                                source,
                            } = request;
                            if let Err(err) =
                                validate_pulse_audio_start_authority(&owner, &token).await
                            {
                                log::warn!(
                                    "Rejected _pa client with invalid audio capture authority: {}",
                                    err
                                );
                                continue;
                            }
                            let mut device = source;
                            if !device.is_empty() {
                                device = crate::platform::linux::get_pa_source_name(&device);
                            }
                            if device.is_empty() {
                                device = crate::platform::linux::get_pa_monitor();
                            }
                            if device.is_empty() {
                                continue;
                            }
                            let spec = pulse::sample::Spec {
                                format: pulse::sample::Format::F32le,
                                channels: 2,
                                rate: crate::platform::PA_SAMPLE_RATE,
                            };
                            log::info!("pa monitor: {:?}", device);
                            // systemctl --user status pulseaudio.service
                            let mut buf: Vec<u8> = vec![0; AUDIO_DATA_SIZE_U8];
                            match psimple::Simple::new(
                                None,                             // Use the default server
                                &crate::get_app_name(),           // Our application’s name
                                pulse::stream::Direction::Record, // We want a record stream
                                Some(&device),                    // Use the default device
                                "record",                         // Description of our stream
                                &spec,                            // Our sample format
                                None,                             // Use default channel map
                                None, // Use default buffering attributes
                            ) {
                                Ok(s) => loop {
                                    if let Err(err) = s.read(&mut buf) {
                                        log::error!("Failed to read PulseAudio capture data: {err}");
                                        break;
                                    }
                                    let out = if buf.iter().all(|byte| *byte == 0) {
                                        vec![]
                                    } else {
                                        buf.clone()
                                    };
                                    if let Err(err) = stream
                                        .send_pulse_audio_frame_timeout(
                                            out.into(),
                                            PULSE_AUDIO_IPC_IO_TIMEOUT_MS,
                                        )
                                        .await
                                    {
                                        log::error!("Failed to send audio data: {err}");
                                        break;
                                    }
                                },
                                Err(err) => {
                                    log::error!("Could not create simple pulse: {}", err);
                                }
                            }
                        }
                        Err(err) => {
                            log::error!("Couldn't get pa client: {:?}", err);
                        }
                    }
                }
            }
        }
        Err(err) => {
            log::error!("Failed to start pa ipc server: {}", err);
        }
    }
}
pub struct ConnectionTmpl<T> {
    inner: Framed<T, BytesCodec>,
}

pub type Connection = ConnectionTmpl<Conn>;

impl<T> ConnectionTmpl<T>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin,
{
    pub fn new(conn: T) -> Self {
        Self {
            inner: Framed::new(conn, BytesCodec::new()),
        }
    }

    fn new_with_max_packet_length(conn: T, max_packet_length: usize) -> Self {
        let mut codec = BytesCodec::new();
        codec.set_max_packet_length(max_packet_length);
        Self {
            inner: Framed::new(conn, codec),
        }
    }

    pub(crate) fn new_protected_service(conn: T) -> Self {
        Self::new_with_max_packet_length(conn, SERVICE_IPC_MAX_FRAME_BYTES)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn new_pulse_audio(conn: T) -> Self {
        Self::new_with_max_packet_length(conn, PULSE_AUDIO_IPC_MAX_FRAME_BYTES)
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub(crate) fn new_whiteboard(conn: T) -> Self {
        Self::new_with_max_packet_length(conn, WHITEBOARD_IPC_MAX_FRAME_BYTES)
    }

    pub(crate) fn new_desktop_url(conn: T) -> Self {
        Self::new_with_max_packet_length(conn, DESKTOP_URL_IPC_MAX_FRAME_BYTES)
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub(crate) fn new_main(conn: T) -> Self {
        Self::new_with_max_packet_length(conn, MAIN_IPC_MAX_FRAME_BYTES)
    }

    async fn send_json<S: serde::Serialize>(&mut self, value: &S) -> ResultType<()> {
        let value = serde_json::to_vec(value)?;
        let max_packet_length = self.inner.codec().max_packet_length();
        if value.len() > max_packet_length {
            bail!(
                "outbound IPC frame exceeds codec limit: frame={}, limit={}",
                value.len(),
                max_packet_length
            );
        }
        self.inner.send(bytes::Bytes::from(value)).await?;
        Ok(())
    }

    pub(crate) async fn send_json_timeout<S: serde::Serialize>(
        &mut self,
        value: &S,
        ms_timeout: u64,
    ) -> ResultType<()> {
        timeout(ms_timeout, self.send_json(value)).await??;
        Ok(())
    }

    async fn next_json<D: serde::de::DeserializeOwned>(&mut self) -> ResultType<Option<D>> {
        let Some(bytes) = self.inner.next().await else {
            bail!("reset by the peer");
        };
        let bytes = bytes?;
        let Ok(text) = std::str::from_utf8(&bytes) else {
            return Ok(None);
        };
        Ok(serde_json::from_str(text).ok())
    }

    async fn next_json_strict<D: serde::de::DeserializeOwned>(&mut self) -> ResultType<D> {
        let Some(bytes) = self.inner.next().await else {
            bail!("reset by the peer");
        };
        let bytes = bytes?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub async fn send(&mut self, data: &Data) -> ResultType<()> {
        self.send_json(data).await
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    async fn send_main_request_timeout(
        &mut self,
        request: &MainIpcRequest,
        ms_timeout: u64,
    ) -> ResultType<()> {
        self.send_json_timeout(request, ms_timeout).await
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    async fn next_main_timeout(&mut self, ms_timeout: u64) -> ResultType<Option<MainIpcRequest>> {
        Ok(timeout(ms_timeout, self.next_json()).await??)
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    async fn next_main_response_timeout(
        &mut self,
        ms_timeout: u64,
    ) -> ResultType<Option<MainIpcResponse>> {
        Ok(timeout(ms_timeout, self.next_json()).await??)
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub(crate) async fn send_service_request_timeout(
        &mut self,
        request: &ServiceIpcRequest,
        ms_timeout: u64,
    ) -> ResultType<()> {
        self.send_json_timeout(request, ms_timeout).await
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub(crate) async fn next_service_request_timeout(
        &mut self,
        ms_timeout: u64,
    ) -> ResultType<Option<ServiceIpcRequest>> {
        Ok(timeout(ms_timeout, self.next_json()).await??)
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub(crate) async fn send_service_response_timeout(
        &mut self,
        response: &ServiceIpcResponse,
        ms_timeout: u64,
    ) -> ResultType<()> {
        self.send_json_timeout(response, ms_timeout).await
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub(crate) async fn next_service_response_timeout(
        &mut self,
        ms_timeout: u64,
    ) -> ResultType<Option<ServiceIpcResponse>> {
        Ok(timeout(ms_timeout, self.next_json()).await??)
    }
    #[cfg(target_os = "linux")]
    pub(crate) async fn send_pulse_audio_request_timeout(
        &mut self,
        request: &LinuxPulseAudioIpcRequest,
        ms_timeout: u64,
    ) -> ResultType<()> {
        self.send_json_timeout(request, ms_timeout).await
    }
    #[cfg(target_os = "linux")]
    pub(crate) async fn next_pulse_audio_request_timeout(
        &mut self,
        ms_timeout: u64,
    ) -> ResultType<Option<LinuxPulseAudioIpcRequest>> {
        Ok(timeout(ms_timeout, self.next_json()).await??)
    }
    #[cfg(target_os = "linux")]
    pub(crate) async fn send_pulse_audio_frame_timeout(
        &mut self,
        data: Bytes,
        ms_timeout: u64,
    ) -> ResultType<()> {
        if !data.is_empty() && data.len() != PULSE_AUDIO_IPC_AUDIO_FRAME_BYTES {
            bail!(
                "invalid outbound PulseAudio IPC frame length: frame={}, expected={}",
                data.len(),
                PULSE_AUDIO_IPC_AUDIO_FRAME_BYTES
            );
        }
        timeout(ms_timeout, self.send_raw(data)).await??;
        Ok(())
    }
    #[cfg(target_os = "linux")]
    pub(crate) async fn next_pulse_audio_frame_timeout(
        &mut self,
        ms_timeout: u64,
    ) -> ResultType<Option<bytes::BytesMut>> {
        let frame = match tokio::time::timeout(
            std::time::Duration::from_millis(ms_timeout),
            self.inner.next(),
        )
        .await
        {
            Err(_) => return Ok(None),
            Ok(Some(Ok(frame))) => frame,
            Ok(Some(Err(err))) => return Err(err.into()),
            Ok(None) => bail!("reset by the peer"),
        };
        if !frame.is_empty() && frame.len() != PULSE_AUDIO_IPC_AUDIO_FRAME_BYTES {
            bail!(
                "invalid inbound PulseAudio IPC frame length: frame={}, expected={}",
                frame.len(),
                PULSE_AUDIO_IPC_AUDIO_FRAME_BYTES
            );
        }
        Ok(Some(frame))
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub(crate) async fn send_whiteboard_owner_handshake_timeout(
        &mut self,
        message: &WhiteboardOwnerHandshake,
        ms_timeout: u64,
    ) -> ResultType<()> {
        self.send_json_timeout(message, ms_timeout).await
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub(crate) async fn next_whiteboard_owner_handshake_timeout(
        &mut self,
        ms_timeout: u64,
    ) -> ResultType<WhiteboardOwnerHandshake> {
        Ok(timeout(ms_timeout, self.next_json_strict()).await??)
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub(crate) async fn send_whiteboard_helper_handshake_timeout(
        &mut self,
        message: &WhiteboardHelperHandshake,
        ms_timeout: u64,
    ) -> ResultType<()> {
        self.send_json_timeout(message, ms_timeout).await
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub(crate) async fn next_whiteboard_helper_handshake_timeout(
        &mut self,
        ms_timeout: u64,
    ) -> ResultType<WhiteboardHelperHandshake> {
        Ok(timeout(ms_timeout, self.next_json_strict()).await??)
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub(crate) async fn send_whiteboard_command_timeout(
        &mut self,
        command: &WhiteboardIpcCommand,
        ms_timeout: u64,
    ) -> ResultType<()> {
        self.send_json_timeout(command, ms_timeout).await
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub(crate) async fn next_whiteboard_command_timeout(
        &mut self,
        ms_timeout: u64,
    ) -> ResultType<Option<WhiteboardIpcCommand>> {
        match tokio::time::timeout(
            std::time::Duration::from_millis(ms_timeout),
            self.next_json_strict(),
        )
        .await
        {
            Ok(result) => result.map(Some),
            Err(_) => Ok(None),
        }
    }
    pub(crate) async fn send_desktop_url_request_timeout(
        &mut self,
        request: &DesktopUrlIpcRequest,
        ms_timeout: u64,
    ) -> ResultType<()> {
        self.send_json_timeout(request, ms_timeout).await
    }
    pub(crate) async fn next_desktop_url_request_timeout(
        &mut self,
        ms_timeout: u64,
    ) -> ResultType<DesktopUrlIpcRequest> {
        Ok(timeout(ms_timeout, self.next_json_strict()).await??)
    }
    #[cfg(target_os = "windows")]
    pub(crate) async fn send_windows_service_sas_request_timeout(
        &mut self,
        request: &WindowsServiceSasIpcRequest,
        ms_timeout: u64,
    ) -> ResultType<()> {
        self.send_json_timeout(request, ms_timeout).await
    }
    #[cfg(target_os = "windows")]
    pub(crate) async fn next_windows_service_sas_request_timeout(
        &mut self,
        ms_timeout: u64,
    ) -> ResultType<Option<WindowsServiceSasIpcRequest>> {
        Ok(timeout(ms_timeout, self.next_json()).await??)
    }
    #[cfg(target_os = "windows")]
    pub(crate) async fn send_windows_service_sas_response_timeout(
        &mut self,
        response: &WindowsServiceSasIpcResponse,
        ms_timeout: u64,
    ) -> ResultType<()> {
        self.send_json_timeout(response, ms_timeout).await
    }
    #[cfg(target_os = "windows")]
    pub(crate) async fn next_windows_service_sas_response_timeout(
        &mut self,
        ms_timeout: u64,
    ) -> ResultType<Option<WindowsServiceSasIpcResponse>> {
        Ok(timeout(ms_timeout, self.next_json()).await??)
    }
    #[cfg(target_os = "windows")]
    async fn send_windows_service_main_request_timeout(
        &mut self,
        request: &WindowsServiceMainRequest,
        ms_timeout: u64,
    ) -> ResultType<()> {
        self.send_json_timeout(request, ms_timeout).await
    }
    #[cfg(target_os = "windows")]
    async fn next_windows_service_main_request_timeout(
        &mut self,
        ms_timeout: u64,
    ) -> ResultType<Option<WindowsServiceMainRequest>> {
        Ok(timeout(ms_timeout, self.next_json()).await??)
    }
    #[cfg(target_os = "windows")]
    async fn next_windows_service_main_response_timeout(
        &mut self,
        ms_timeout: u64,
    ) -> ResultType<Option<WindowsServiceMainResponse>> {
        Ok(timeout(ms_timeout, self.next_json()).await??)
    }

    pub(crate) fn set_max_packet_length(&mut self, max_packet_length: usize) {
        self.inner
            .codec_mut()
            .set_max_packet_length(max_packet_length);
    }

    pub async fn next_timeout(&mut self, ms_timeout: u64) -> ResultType<Option<Data>> {
        Ok(timeout(ms_timeout, self.next()).await??)
    }

    pub async fn next_timeout2(&mut self, ms_timeout: u64) -> Option<ResultType<Option<Data>>> {
        if let Ok(x) = timeout(ms_timeout, self.next()).await {
            Some(x)
        } else {
            None
        }
    }

    pub async fn next(&mut self) -> ResultType<Option<Data>> {
        self.next_json().await
    }

    pub async fn send_raw(&mut self, data: Bytes) -> ResultType<()> {
        let max_packet_length = self.inner.codec().max_packet_length();
        if data.len() > max_packet_length {
            bail!(
                "outbound raw IPC frame exceeds codec limit: frame={}, limit={}",
                data.len(),
                max_packet_length
            );
        }
        self.inner.send(data).await?;
        Ok(())
    }

    pub async fn next_raw(&mut self) -> ResultType<bytes::BytesMut> {
        match self.inner.next().await {
            Some(Ok(res)) => Ok(res),
            _ => {
                bail!("reset by the peer");
            }
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn write_response_with_deadline<T, S>(
    stream: &mut ConnectionTmpl<T>,
    response: &S,
    context: &str,
) -> bool
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin,
    S: serde::Serialize,
{
    match stream
        .send_json_timeout(response, MAIN_IPC_TRANSACTION_TIMEOUT_MS)
        .await
    {
        Ok(()) => true,
        Err(err) => {
            log::warn!("{context} response failed: {err}");
            false
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[tokio::main(flavor = "current_thread")]
pub async fn get_config(name: &str) -> ResultType<Option<String>> {
    get_config_async(name, 1_000).await
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn get_config_async(name: &str, ms_timeout: u64) -> ResultType<Option<String>> {
    let Some(key) = main_config_key(name) else {
        return Ok(None);
    };
    match main_ipc_request(MainIpcRequest::Config(key), ms_timeout).await? {
        MainIpcResponse::Config {
            key: response_key,
            value,
        } if response_key == key => Ok(value),
        _ => bail!("invalid main IPC config response"),
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn main_config_key(name: &str) -> Option<MainConfigKey> {
    match name {
        "id" => Some(MainConfigKey::Id),
        "permanent-password-set" => Some(MainConfigKey::PermanentPasswordSet),
        "permanent-password-user-owned-writable" => {
            Some(MainConfigKey::UserOwnedPermanentPasswordWritable)
        }
        "hide_cm" => Some(MainConfigKey::HideConnectionManager),
        "voice-call-input" => Some(MainConfigKey::VoiceCallInput),
        "direct-listener-bound" => Some(MainConfigKey::DirectListenerBound),
        _ => None,
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn connect_user_owned_password_main(
    ms_timeout: u64,
) -> ResultType<ConnectionTmpl<ConnClient>> {
    let connection = connect(ms_timeout, "").await?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    ensure_user_owned_main_server_is_trusted(&connection)?;
    Ok(connection)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn connect_user_owned_password_stream(
    deadline: tokio::time::Instant,
) -> ResultType<ConnClient> {
    connect_sensitive_unix(deadline, password::USER_PASSWORD_IPC_POSTFIX, false).await
}

#[cfg(target_os = "linux")]
async fn connect_service_owned_password_replica_stream(
    deadline: tokio::time::Instant,
) -> ResultType<ConnClient> {
    let connection = {
        let _scope = UserMainIpcScope::new();
        connect_sensitive_unix(deadline, password::USER_PASSWORD_IPC_POSTFIX, true).await?
    };
    Ok(connection)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn complete_main_password_mutation(
    operation_id: String,
    value: &MainPasswordMutationValue,
    service_owned: bool,
    ms_timeout: u64,
) -> ResultType<IpcMutationResult> {
    let operation_uuid = hbb_common::uuid::Uuid::parse_str(&operation_id)
        .map_err(|err| hbb_common::anyhow::anyhow!("invalid password operation UUID: {err}"))?;
    let mut query_only = false;
    let mut recovery_required = service_owned;
    let recovery_deadline = tokio::time::Instant::now() + PASSWORD_MUTATION_RECOVERY_TIMEOUT;
    loop {
        if recovery_required && tokio::time::Instant::now() >= recovery_deadline {
            bail!("password mutation outcome remains unknown after bounded recovery");
        }
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(ms_timeout);
        if query_only {
            let stream = if service_owned {
                #[cfg(target_os = "linux")]
                {
                    let stream = {
                        let _scope = UserMainIpcScope::new();
                        connect(password::remaining_millis(deadline)?, "").await
                    };
                    match stream {
                        Ok(stream) => {
                            if let Err(err) = authenticate_linux_service_owned_main_server(&stream)
                            {
                                log::warn!(
                                    "Retrying admitted password mutation after child identity failure: {err}"
                                );
                                hbb_common::sleep(0.1).await;
                                continue;
                            }
                            if let Err(err) = password::remaining_millis(deadline) {
                                log::warn!(
                                    "Retrying admitted password mutation after child proof exceeded its deadline: {err}"
                                );
                                hbb_common::sleep(0.1).await;
                                continue;
                            }
                            stream
                        }
                        Err(err) => {
                            log::warn!(
                                "Retrying accepted password mutation after reconnect failure: {err}"
                            );
                            hbb_common::sleep(0.1).await;
                            continue;
                        }
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    bail!("service-owned main password mutation is unsupported on this platform");
                }
            } else {
                match connect_user_owned_password_main(password::remaining_millis(deadline)?).await
                {
                    Ok(stream) => stream,
                    Err(err) if !recovery_required => return Err(err),
                    Err(err) => {
                        log::warn!(
                            "Retrying accepted password mutation after reconnect failure: {err}"
                        );
                        hbb_common::sleep(0.1).await;
                        continue;
                    }
                }
            };
            let response = main_ipc_request_on_stream_deadline(
                stream,
                MainIpcRequest::PasswordMutationStatus {
                    operation_id: operation_id.clone(),
                },
                deadline,
            )
            .await;
            let response = match response {
                Ok(MainIpcResponse::PasswordMutation(status)) => status,
                Ok(_) => {
                    log::warn!("Retrying password mutation after an invalid status response");
                    hbb_common::sleep(0.1).await;
                    continue;
                }
                Err(err) => {
                    log::warn!("Retrying password mutation until its final state is known: {err}");
                    hbb_common::sleep(0.1).await;
                    continue;
                }
            };
            match windows_credential_client_decision(response, recovery_required) {
                WindowsCredentialClientDecision::Continue => {
                    recovery_required = true;
                    query_only = matches!(
                        response,
                        PasswordMutationStatus::Prepared | PasswordMutationStatus::Pending
                    );
                }
                WindowsCredentialClientDecision::Applied => return Ok(IpcMutationResult::Applied),
                WindowsCredentialClientDecision::Rejected => {
                    return Ok(IpcMutationResult::Rejected)
                }
                WindowsCredentialClientDecision::InternalFailure => {
                    return Ok(IpcMutationResult::InternalFailure)
                }
                WindowsCredentialClientDecision::NotAdmitted => {
                    bail!("password mutation was not accepted because the daemon is shutting down")
                }
            }
            hbb_common::sleep(0.05).await;
            continue;
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let mut stream = if service_owned {
            #[cfg(target_os = "linux")]
            {
                match connect_service_owned_password_replica_stream(deadline).await {
                    Ok(stream) => stream,
                    Err(err) => {
                        log::warn!("Retrying admitted password mutation after child identity failure: {err}");
                        hbb_common::sleep(0.1).await;
                        continue;
                    }
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                bail!("service-owned main password mutation is unsupported on this platform");
            }
        } else {
            match connect_user_owned_password_stream(deadline).await {
                Ok(stream) => stream,
                Err(err) if !recovery_required => return Err(err),
                Err(err) => {
                    log::warn!(
                        "Retrying accepted password mutation after reconnect failure: {err}"
                    );
                    hbb_common::sleep(0.1).await;
                    continue;
                }
            }
        };

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let response: ResultType<PasswordMutationStatus> = {
            match password::send_request_unix(&mut stream, operation_uuid, value, None, deadline)
                .await
            {
                Ok(()) => {
                    match password::receive_status_unix(&mut stream, operation_uuid, deadline).await
                    {
                        Ok(status) => Ok(status),
                        Err(err) => {
                            recovery_required = true;
                            Err(err)
                        }
                    }
                }
                Err(password::UnixSensitivePasswordSendError::NotSent(err))
                    if !recovery_required =>
                {
                    return Err(err)
                }
                Err(password::UnixSensitivePasswordSendError::NotSent(err)) => Err(err),
                Err(password::UnixSensitivePasswordSendError::Uncertain(err)) => {
                    recovery_required = true;
                    Err(err)
                }
            }
        };
        #[cfg(target_os = "windows")]
        let response = match crate::platform::windows::transact_sensitive_password(
            password::USER_PASSWORD_IPC_POSTFIX,
            operation_uuid,
            value,
            std::time::Duration::from_millis(ms_timeout),
        )
        .await
        {
            crate::platform::windows::WindowsSensitivePasswordAttempt::Status(status) => Ok(status),
            crate::platform::windows::WindowsSensitivePasswordAttempt::NotSent(err)
                if !recovery_required =>
            {
                return Err(hbb_common::anyhow::anyhow!(err));
            }
            crate::platform::windows::WindowsSensitivePasswordAttempt::NotSent(err) => {
                Err(hbb_common::anyhow::anyhow!(err))
            }
            crate::platform::windows::WindowsSensitivePasswordAttempt::Uncertain(err) => {
                recovery_required = true;
                Err(hbb_common::anyhow::anyhow!(err))
            }
        };
        let response = match response {
            Ok(status) => status,
            Err(err) => {
                log::warn!("Retrying password mutation until its final state is known: {err}");
                hbb_common::sleep(0.1).await;
                continue;
            }
        };
        match windows_credential_client_decision(response, recovery_required) {
            WindowsCredentialClientDecision::Continue => {
                recovery_required = true;
                query_only = matches!(
                    response,
                    PasswordMutationStatus::Prepared | PasswordMutationStatus::Pending
                );
            }
            WindowsCredentialClientDecision::Applied => return Ok(IpcMutationResult::Applied),
            WindowsCredentialClientDecision::Rejected => return Ok(IpcMutationResult::Rejected),
            WindowsCredentialClientDecision::InternalFailure => {
                return Ok(IpcMutationResult::InternalFailure)
            }
            WindowsCredentialClientDecision::NotAdmitted => {
                bail!("password mutation was not accepted because the daemon is shutting down")
            }
        }
        hbb_common::sleep(0.05).await;
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[tokio::main(flavor = "current_thread")]
async fn user_owned_permanent_password_is_writable() -> ResultType<bool> {
    let ms_timeout = 1_000;
    let stream = connect_user_owned_password_main(ms_timeout).await?;
    match main_ipc_request_on_stream(
        stream,
        MainIpcRequest::Config(MainConfigKey::UserOwnedPermanentPasswordWritable),
        ms_timeout,
    )
    .await?
    {
        MainIpcResponse::Config {
            key: MainConfigKey::UserOwnedPermanentPasswordWritable,
            value,
        } => Ok(value.as_deref().is_some_and(|value| value.trim() == "Y")),
        _ => bail!("invalid user-owned password capability response"),
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn set_voice_call_input_device_async(value: String) -> ResultType<()> {
    match main_ipc_request(MainIpcRequest::SetVoiceCallInput(value), 1_000).await? {
        MainIpcResponse::VoiceCallInputSet(IpcMutationResult::Applied) => Ok(()),
        MainIpcResponse::VoiceCallInputSet(IpcMutationResult::Rejected) => {
            bail!("voice-call input change was rejected by daemon")
        }
        MainIpcResponse::VoiceCallInputSet(IpcMutationResult::InternalFailure) => {
            bail!("voice-call input change failed internally")
        }
        _ => bail!("invalid voice-call input response"),
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[tokio::main(flavor = "current_thread")]
pub async fn set_voice_call_input_device(value: String) -> ResultType<()> {
    set_voice_call_input_device_async(value).await
}

#[cfg(target_os = "macos")]
pub async fn refresh_macos_service_owned_permanent_password_snapshot(
    ms_timeout: u64,
) -> ResultType<bool> {
    if !crate::common::is_service_owned_server_process() {
        bail!("macOS service credential snapshots require the exact service-owned server role");
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(ms_timeout);
    let path = Config::ipc_path_for_uid(0, password::SERVICE_CREDENTIAL_IPC_POSTFIX);
    let mut stream = timeout(
        password::remaining_millis(deadline)?,
        Endpoint::connect(path),
    )
    .await??;
    let authorization = ipc_auth::macos_service_server_authorization_snapshot(
        &stream,
        "macOS service credential server",
    )?;
    authorize_macos_service_server_snapshot_for_task(authorization, deadline).await?;
    password::remaining_millis(deadline)?;
    let operation_id = hbb_common::uuid::Uuid::new_v4();
    password::send_credential_snapshot_request_unix(&mut stream, operation_id, deadline).await?;
    let replica =
        password::receive_credential_replica_unix(&mut stream, operation_id, deadline).await?;
    Config::set_permanent_password_prs_for_runtime(replica.as_str())?;
    Ok(!replica.as_str().is_empty())
}

#[cfg(target_os = "linux")]
pub async fn refresh_linux_service_owned_permanent_password_snapshot(
    ms_timeout: u64,
) -> ResultType<bool> {
    if !crate::common::is_service_owned_server_process() {
        bail!("Linux service credential snapshots require the exact service-owned server role");
    }
    if crate::platform::linux::service_child_is_unsupervised_recovery_fixture() {
        Config::set_permanent_password_prs_for_runtime("")?;
        return Ok(false);
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(ms_timeout);
    let path = Config::ipc_path_for_uid(0, password::SERVICE_CREDENTIAL_IPC_POSTFIX);
    let mut stream = timeout(
        password::remaining_millis(deadline)?,
        Endpoint::connect(path),
    )
    .await??;
    authenticate_linux_service_owned_password_parent(
        &stream,
        password::SERVICE_CREDENTIAL_IPC_POSTFIX,
    )?;
    let operation_id = hbb_common::uuid::Uuid::new_v4();
    password::send_credential_snapshot_request_unix(&mut stream, operation_id, deadline).await?;
    let replica =
        password::receive_credential_replica_unix(&mut stream, operation_id, deadline).await?;
    Config::set_permanent_password_prs_for_runtime(replica.as_str())?;
    Ok(!replica.as_str().is_empty())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn is_permanent_password_set() -> bool {
    match get_config("permanent-password-set") {
        Ok(Some(v)) => {
            let v = v.trim();
            return v == "Y";
        }
        Ok(None) => {
            // No response/value (timeout).
        }
        Err(_) => {
            // Connection error.
        }
    }
    log::warn!("Failed to query permanent password state from daemon");
    false
}

/// T1 / BR-4 (verify-ground-truth): query the daemon (`--server`) for the REAL direct-listener
/// state over the main "" IPC channel. Used by the desktop GUI, which runs in a SEPARATE process
/// from the `--server` that binds :21118 (so reading its own `direct_service` atomic would always
/// yield false). A dead/wedged service (the "" channel is unreachable → `get_config` errors) and a
/// parked/rebinding listener (atomic false in the daemon) both correctly read as NOT bound, so the
/// desktop "Reachable on :21118" status can never over-claim.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn get_direct_listener_bound() -> bool {
    matches!(get_config("direct-listener-bound"), Ok(Some(v)) if v.trim() == "true")
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn can_set_user_owned_permanent_password() -> bool {
    matches!(user_owned_permanent_password_is_writable(), Ok(true))
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn set_user_owned_permanent_password(v: String) -> ResultType<()> {
    set_user_owned_permanent_password_sensitive(SensitivePassword::new(v))
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn set_user_owned_permanent_password_sensitive(v: SensitivePassword) -> ResultType<()> {
    validate_unattended_password_value(&v)?;
    if Config::is_disable_change_permanent_password() {
        bail!("Changing permanent password is disabled");
    }
    if set_user_owned_permanent_password_with_ack_sensitive(v)? {
        Ok(())
    } else {
        bail!("Changing permanent password was rejected by daemon");
    }
}

#[cfg(target_os = "linux")]
pub fn can_request_service_owned_unattended_password_change() -> bool {
    crate::platform::is_installed()
}

#[cfg(target_os = "windows")]
pub fn can_request_service_owned_unattended_password_change() -> bool {
    crate::platform::is_installed()
}

#[cfg(target_os = "macos")]
pub fn can_request_service_owned_unattended_password_change() -> bool {
    crate::platform::is_installed()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn can_request_service_owned_unattended_password_change() -> bool {
    false
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn can_set_permanent_password() -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    if can_request_service_owned_unattended_password_change() {
        return true;
    }
    can_set_user_owned_permanent_password()
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn set_permanent_password(v: String) -> ResultType<()> {
    set_permanent_password_sensitive(SensitivePassword::new(v))
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) fn set_permanent_password_sensitive(v: SensitivePassword) -> ResultType<()> {
    validate_unattended_password_value(&v)?;
    if Config::is_disable_change_permanent_password() {
        bail!("Changing permanent password is disabled");
    }
    if can_request_service_owned_unattended_password_change() {
        #[cfg(target_os = "windows")]
        return set_windows_service_owned_unattended_password(v);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        return set_service_owned_unattended_password_sensitive(v);
    }
    if can_set_user_owned_permanent_password() {
        return set_user_owned_permanent_password_sensitive(v);
    }
    bail!("Changing service-owned unattended password requires administrator authorization");
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[tokio::main(flavor = "current_thread")]
pub async fn set_user_owned_permanent_password_with_ack(v: String) -> ResultType<bool> {
    set_user_owned_permanent_password_with_ack_async(SensitivePassword::new(v)).await
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[tokio::main(flavor = "current_thread")]
async fn set_user_owned_permanent_password_with_ack_sensitive(
    v: SensitivePassword,
) -> ResultType<bool> {
    set_user_owned_permanent_password_with_ack_async(v).await
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn set_user_owned_permanent_password_with_ack_async(
    v: MainPasswordMutationValue,
) -> ResultType<bool> {
    validate_unattended_password_value(&v)?;
    let ms_timeout = 5_000;
    let operation_id = hbb_common::uuid::Uuid::new_v4().to_string();
    let result = complete_main_password_mutation(operation_id, &v, false, ms_timeout).await?;
    Ok(match result {
        IpcMutationResult::Applied => true,
        IpcMutationResult::Rejected => false,
        IpcMutationResult::InternalFailure => bail!("password mutation failed internally"),
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn set_service_owned_unattended_password(v: String) -> ResultType<()> {
    set_service_owned_unattended_password_sensitive(SensitivePassword::new(v))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn set_service_owned_unattended_password_sensitive(v: SensitivePassword) -> ResultType<()> {
    validate_unattended_password_value(&v)?;
    if set_service_owned_unattended_password_with_ack(v)? {
        Ok(())
    } else {
        bail!("Changing service-owned unattended password was rejected by service");
    }
}

#[cfg(target_os = "windows")]
fn set_windows_service_owned_unattended_password(v: SensitivePassword) -> ResultType<()> {
    validate_unattended_password_value(&v)?;
    // The service independently authenticates the live pipe peer before it
    // reads the password body. Reject a copied/portable caller here as well:
    // otherwise a server-side pre-admission disconnect can become an
    // indeterminate buffered-pipe write and enter the admitted-operation
    // recovery loop even though this image can never be authorized.
    crate::platform::windows::require_current_exe_is_fixed_service_runtime()?;
    if set_windows_service_owned_unattended_password_with_ack(v)? {
        Ok(())
    } else {
        bail!("Changing service-owned unattended password was rejected by service");
    }
}

#[cfg(target_os = "macos")]
async fn macos_service_owned_password_authorization_right_ready(
    deadline: tokio::time::Instant,
) -> ResultType<bool> {
    let mut c = connect_service(password::remaining_millis(deadline)?).await?;
    c.send_service_request_timeout(
        &ServiceIpcRequest::EnsurePasswordRightReady {},
        password::remaining_millis(deadline)?,
    )
    .await?;
    match c
        .next_service_response_timeout(password::remaining_millis(deadline)?)
        .await?
    {
        Some(ServiceIpcResponse::PasswordRightReady { ready }) => Ok(ready),
        _ => Ok(false),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tokio::main(flavor = "current_thread")]
async fn set_service_owned_unattended_password_with_ack(v: SensitivePassword) -> ResultType<bool> {
    let ms_timeout = 1_000;
    let operation_id = hbb_common::uuid::Uuid::new_v4();
    let mut recovery_required = false;
    let recovery_deadline = tokio::time::Instant::now() + PASSWORD_MUTATION_RECOVERY_TIMEOUT;
    loop {
        if recovery_required && tokio::time::Instant::now() >= recovery_deadline {
            bail!("service-owned password mutation outcome remains unknown after bounded recovery");
        }
        #[cfg(target_os = "linux")]
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(ms_timeout);
        #[cfg(target_os = "macos")]
        let authorization = {
            let readiness_deadline =
                tokio::time::Instant::now() + std::time::Duration::from_millis(ms_timeout);
            match macos_service_owned_password_authorization_right_ready(readiness_deadline).await {
                Ok(true) => {}
                Ok(false) if !recovery_required => return Ok(false),
                Err(err) if !recovery_required => return Err(err),
                Ok(false) => {
                    log::warn!(
                        "Retrying accepted macOS password operation until its authorization service recovers"
                    );
                    hbb_common::sleep(0.1).await;
                    continue;
                }
                Err(err) => {
                    log::warn!(
                        "Retrying accepted macOS password operation after authorization readiness failure: {err}"
                    );
                    hbb_common::sleep(0.1).await;
                    continue;
                }
            }
            match tokio::task::spawn_blocking(|| {
                crate::platform::service_owned_unattended_password_authorization()
            })
            .await
            .map_err(|err| {
                hbb_common::anyhow::anyhow!("macOS administrator authorization task failed: {err}")
            })
            .and_then(|authorization| authorization)
            {
                Ok(authorization) => Some(authorization),
                Err(err) if !recovery_required => return Err(err),
                Err(err) => {
                    log::warn!(
                        "Retrying accepted macOS password operation after authorization failure: {err}"
                    );
                    hbb_common::sleep(0.1).await;
                    continue;
                }
            }
        };
        #[cfg(target_os = "macos")]
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(ms_timeout);
        #[cfg(target_os = "linux")]
        let authorization: Option<password::SensitiveAuthorization> = None;

        let mut stream =
            match connect_sensitive_unix(deadline, password::SERVICE_PASSWORD_IPC_POSTFIX, false)
                .await
            {
                Ok(connection) => connection,
                Err(err) if !recovery_required => return Err(err),
                Err(err) => {
                    log::warn!(
                        "Retrying service-owned password operation after reconnect failure: {err}"
                    );
                    hbb_common::sleep(0.1).await;
                    continue;
                }
            };
        let status: ResultType<PasswordMutationStatus> = match password::send_request_unix(
            &mut stream,
            operation_id,
            &v,
            authorization.as_ref(),
            deadline,
        )
        .await
        {
            Ok(()) => {
                match password::receive_status_unix(&mut stream, operation_id, deadline).await {
                    Ok(status) => Ok(status),
                    Err(err) => {
                        recovery_required = true;
                        Err(err)
                    }
                }
            }
            Err(password::UnixSensitivePasswordSendError::NotSent(err)) if !recovery_required => {
                return Err(err)
            }
            Err(password::UnixSensitivePasswordSendError::NotSent(err)) => Err(err),
            Err(password::UnixSensitivePasswordSendError::Uncertain(err)) => {
                recovery_required = true;
                Err(err)
            }
        };
        match status {
            Ok(status) => match windows_credential_client_decision(status, recovery_required) {
                WindowsCredentialClientDecision::Continue => recovery_required = true,
                WindowsCredentialClientDecision::Applied => return Ok(true),
                WindowsCredentialClientDecision::Rejected => return Ok(false),
                WindowsCredentialClientDecision::InternalFailure => {
                    bail!("service-owned password mutation failed internally")
                }
                WindowsCredentialClientDecision::NotAdmitted => {
                    bail!("service stopped before password mutation admission")
                }
            },
            Err(err) => log::warn!(
                "Retrying service-owned password operation until its final state is known: {err}"
            ),
        }
        hbb_common::sleep(0.1).await;
    }
}

#[cfg(target_os = "windows")]
#[tokio::main(flavor = "current_thread")]
async fn set_windows_service_owned_unattended_password_with_ack(
    value: SensitivePassword,
) -> ResultType<bool> {
    let ms_timeout = 1_000;
    let operation_id = hbb_common::uuid::Uuid::new_v4();
    let mut recovery_required = false;
    let recovery_deadline = tokio::time::Instant::now() + PASSWORD_MUTATION_RECOVERY_TIMEOUT;
    loop {
        if recovery_required && tokio::time::Instant::now() >= recovery_deadline {
            bail!("Windows service-owned password mutation outcome remains unknown after bounded recovery");
        }
        let attempt = crate::platform::windows::transact_sensitive_password(
            password::SERVICE_PASSWORD_IPC_POSTFIX,
            operation_id,
            &value,
            std::time::Duration::from_millis(ms_timeout),
        )
        .await;
        match attempt {
            crate::platform::windows::WindowsSensitivePasswordAttempt::Status(status) => {
                match windows_credential_client_decision(status, recovery_required) {
                    WindowsCredentialClientDecision::Continue => recovery_required = true,
                    WindowsCredentialClientDecision::Applied => return Ok(true),
                    WindowsCredentialClientDecision::Rejected => return Ok(false),
                    WindowsCredentialClientDecision::InternalFailure => {
                        bail!("Windows service-owned password mutation failed internally")
                    }
                    WindowsCredentialClientDecision::NotAdmitted => {
                        bail!("Windows service stopped before password mutation admission")
                    }
                }
            }
            crate::platform::windows::WindowsSensitivePasswordAttempt::NotSent(err)
                if !recovery_required =>
            {
                return Err(hbb_common::anyhow::anyhow!(err));
            }
            crate::platform::windows::WindowsSensitivePasswordAttempt::NotSent(err) => {
                log::warn!(
                    "Retrying Windows service-owned password operation after pre-admission transport failure: {err}"
                );
            }
            crate::platform::windows::WindowsSensitivePasswordAttempt::Uncertain(err) => {
                recovery_required = true;
                log::warn!(
                    "Retrying Windows service-owned password operation until its final state is known: {err}"
                );
            }
        }
        hbb_common::sleep(0.1).await;
    }
}

#[cfg(target_os = "windows")]
pub fn set_service_owned_share_rdp(enable: bool) -> ResultType<()> {
    if !crate::platform::is_installed() {
        bail!("Changing RDP session sharing requires an installed service");
    }
    if set_service_owned_share_rdp_with_ack(enable)? {
        Ok(())
    } else {
        bail!("Changing RDP session sharing was rejected by service");
    }
}

#[cfg(target_os = "windows")]
#[tokio::main(flavor = "current_thread")]
async fn set_service_owned_share_rdp_with_ack(enable: bool) -> ResultType<bool> {
    let ms_timeout = 1_000;
    let mut c = connect_service(ms_timeout).await?;
    c.send_service_request_timeout(
        &ServiceIpcRequest::SetShareRdp { enabled: enable },
        ms_timeout,
    )
    .await?;
    match c.next_service_response_timeout(ms_timeout).await? {
        Some(ServiceIpcResponse::ShareRdpSet { accepted }) => Ok(accepted),
        Some(other) => bail!("Unexpected RDP session-sharing response: {:?}", other),
        None => Ok(false),
    }
}

#[cfg(target_os = "windows")]
pub(crate) async fn request_windows_service_owned_sas() -> ResultType<()> {
    if !is_service_owned_server_process() || !crate::platform::is_root() {
        bail!("service-owned SAS requires the LocalSystem service-owned server role");
    }
    let mut stream = connect(
        WINDOWS_SERVICE_SAS_CLIENT_TIMEOUT_MS,
        WINDOWS_SERVICE_SAS_IPC_POSTFIX,
    )
    .await?;
    stream
        .send_windows_service_sas_request_timeout(
            &WindowsServiceSasIpcRequest::Dispatch {},
            WINDOWS_SERVICE_SAS_CLIENT_TIMEOUT_MS,
        )
        .await?;
    match stream
        .next_windows_service_sas_response_timeout(WINDOWS_SERVICE_SAS_CLIENT_TIMEOUT_MS)
        .await?
    {
        Some(WindowsServiceSasIpcResponse::DispatchAccepted { accepted: true }) => Ok(()),
        Some(WindowsServiceSasIpcResponse::DispatchAccepted { accepted: false }) => {
            bail!("Windows service rejected the service-owned SAS dispatch request")
        }
        None => bail!("Windows service returned a malformed service-owned SAS response"),
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn get_id() -> String {
    if let Ok(Some(v)) = get_config("id") {
        v
    } else {
        Config::get_id()
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
async fn get_options_(ms_timeout: u64) -> ResultType<HashMap<String, String>> {
    let snapshot = get_main_status_snapshot(ms_timeout).await?;
    snapshot.options.into_map()
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub async fn get_main_status_snapshot(ms_timeout: u64) -> ResultType<MainStatusSnapshot> {
    match main_ipc_request(MainIpcRequest::StatusSnapshot, ms_timeout).await? {
        MainIpcResponse::StatusSnapshot(snapshot) => Ok(snapshot),
        _ => bail!("invalid main IPC status response"),
    }
}

#[cfg(target_os = "linux")]
pub async fn get_main_readiness_snapshot_for_process(
    expected_pid: u32,
    expected_start_time: &str,
    ms_timeout: u64,
) -> ResultType<MainReadinessSnapshot> {
    if expected_pid == 0 || ms_timeout == 0 {
        bail!("main IPC readiness identity and timeout must be nonzero");
    }
    let canonical_start_time = expected_start_time
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("main IPC readiness start identity is invalid"))?;
    if canonical_start_time == 0 || canonical_start_time.to_string() != expected_start_time {
        bail!("main IPC readiness start identity is not canonical");
    }
    let deadline = tokio::time::Instant::now()
        .checked_add(std::time::Duration::from_millis(ms_timeout))
        .ok_or_else(|| anyhow::anyhow!("main IPC readiness deadline is invalid"))?;
    tokio::time::timeout_at(deadline, async {
        let mut stream = connect(password::remaining_millis(deadline)?, "").await?;
        let peer_pid = stream
            .peer_pid()
            .ok_or_else(|| anyhow::anyhow!("main IPC readiness peer pid is unavailable"))?;
        if peer_pid != expected_pid {
            bail!(
                "main IPC readiness peer pid mismatch: expected={expected_pid}, actual={peer_pid}"
            );
        }
        if linux_proc_start_time(peer_pid)? != expected_start_time {
            bail!("main IPC readiness peer identity changed before request");
        }
        stream
            .send_main_request_timeout(
                &MainIpcRequest::ReadinessSnapshot,
                password::remaining_millis(deadline)?,
            )
            .await?;
        let response = stream
            .next_main_response_timeout(password::remaining_millis(deadline)?)
            .await?
            .ok_or_else(|| anyhow::anyhow!("main IPC readiness returned a malformed response"))?;
        if linux_proc_start_time(peer_pid)? != expected_start_time {
            bail!("main IPC readiness peer identity changed after response");
        }
        match response {
            MainIpcResponse::ReadinessSnapshot(snapshot) => Ok(snapshot),
            _ => bail!("invalid main IPC readiness response"),
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("main IPC readiness transaction timed out"))?
}

#[cfg(target_os = "windows")]
pub async fn get_windows_cpu_usage(ms_timeout: u64) -> ResultType<Option<f64>> {
    match main_ipc_request(MainIpcRequest::CpuUsage, ms_timeout).await? {
        MainIpcResponse::CpuUsage(usage) => Ok(usage),
        _ => bail!("invalid main IPC CPU-usage response"),
    }
}

#[cfg(target_os = "windows")]
pub async fn get_controlled_session_count(ms_timeout: u64) -> ResultType<usize> {
    match main_ipc_request(MainIpcRequest::ControlledSessionCount, ms_timeout).await? {
        MainIpcResponse::ControlledSessionCount(count) => Ok(count),
        _ => bail!("invalid main IPC controlled-session response"),
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub async fn get_options_async() -> HashMap<String, String> {
    get_options_(1000).await.unwrap_or(Config::get_options())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[tokio::main(flavor = "current_thread")]
pub async fn get_options() -> HashMap<String, String> {
    get_options_async().await
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub async fn get_option_async(key: &str) -> String {
    if let Some(v) = get_options_async().await.get(key) {
        v.clone()
    } else {
        "".to_owned()
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[tokio::main(flavor = "current_thread")]
pub async fn set_option(key: &str, value: &str) -> ResultType<String> {
    let requested = MainStatusOption::from_pair(key, value.to_owned())?;
    let requested_key = requested.key;
    match main_ipc_request(MainIpcRequest::SetOption(requested), 2_000).await {
        Ok(MainIpcResponse::OptionSet {
            result: IpcMutationResult::Applied,
            effective: Some(effective),
        }) => {
            let (effective_key, effective_value) = effective.into_pair()?;
            if effective_key != requested_key {
                bail!("Option write response did not match the requested key");
            }
            Ok(effective_value)
        }
        Ok(MainIpcResponse::OptionSet {
            result: IpcMutationResult::Applied,
            effective: None,
        }) => bail!("Option write response omitted receiver-derived state"),
        Ok(MainIpcResponse::OptionSet {
            result: IpcMutationResult::Rejected,
            ..
        }) => {
            bail!("Option write was rejected by daemon")
        }
        Ok(MainIpcResponse::OptionSet {
            result: IpcMutationResult::InternalFailure,
            ..
        }) => {
            bail!("Option write failed internally")
        }
        Ok(_) => bail!("Invalid option write response"),
        Err(err) => bail!("Option write requires daemon ACK: {err}"),
    }
}

// R-SV6a/R-D4: `notify_deployed()` and `Data::Deployed` are removed with the account deployment
// control plane. No deployment UI, bridge, or API actuator remains.

#[tokio::main(flavor = "current_thread")]
pub async fn send_url_scheme(url: String) -> ResultType<()> {
    send_desktop_url_ipc_request(DesktopUrlIpcRequest::from_url(url)?).await
}

async fn send_desktop_url_ipc_request(request: DesktopUrlIpcRequest) -> ResultType<()> {
    connect(DESKTOP_URL_IPC_IO_TIMEOUT_MS, "_url")
        .await?
        .send_desktop_url_request_timeout(&request, DESKTOP_URL_IPC_IO_TIMEOUT_MS)
        .await?;
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
pub async fn close_all_instances() -> ResultType<bool> {
    match send_desktop_url_ipc_request(DesktopUrlIpcRequest::CloseAll {}).await {
        Ok(_) => Ok(true),
        Err(err) => Err(err),
    }
}

#[tokio::main(flavor = "current_thread")]
pub async fn activate_main_instance() -> ResultType<bool> {
    match send_desktop_url_ipc_request(DesktopUrlIpcRequest::Activate {}).await {
        Ok(_) => Ok(true),
        Err(err) => Err(err),
    }
}

#[cfg(target_os = "windows")]
async fn windows_service_main_request(
    expected_identity: Option<WindowsProcessIdentityKey>,
    request: WindowsServiceMainRequest,
    ms_timeout: u64,
) -> ResultType<WindowsServiceMainResponse> {
    let mut stream = connect(ms_timeout, WINDOWS_SERVICE_MAIN_CONTROL_IPC_POSTFIX).await?;
    if let Some(expected_identity) = expected_identity {
        ensure_windows_service_main_server_pid(&stream, expected_identity)?;
    }
    stream
        .send_windows_service_main_request_timeout(&request, ms_timeout)
        .await?;
    stream
        .next_windows_service_main_response_timeout(ms_timeout)
        .await?
        .ok_or_else(|| {
            hbb_common::anyhow::anyhow!("Windows service-main IPC returned a malformed response")
        })
}

#[cfg(target_os = "windows")]
async fn windows_service_credential_request(
    expected_identity: WindowsProcessIdentityKey,
    request: WindowsServiceMainRequest,
    ms_timeout: u64,
) -> ResultType<WindowsCredentialReplicaState> {
    let mut stream = connect(ms_timeout, WINDOWS_SERVICE_CREDENTIAL_IPC_POSTFIX).await?;
    ensure_windows_service_main_server_pid(&stream, expected_identity)?;
    stream
        .send_windows_service_main_request_timeout(&request, ms_timeout)
        .await?;
    match stream
        .next_windows_service_main_response_timeout(ms_timeout)
        .await?
    {
        Some(WindowsServiceMainResponse::CredentialReplica(
            WindowsCredentialReplicaResponse::State(state),
        )) => Ok(state),
        Some(WindowsServiceMainResponse::CredentialReplica(
            WindowsCredentialReplicaResponse::Rejected,
        )) => bail!("Windows service-owned credential replica rejected the request"),
        _ => bail!("invalid Windows service-owned credential replica response"),
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn windows_credential_replica_tag(storage: &str, salt: &str) -> [u8; 32] {
    let mut state = hbb_common::sodiumoxide::crypto::hash::sha256::State::new();
    state.update(b"rustdesk.windows.credential-replica.v1\0");
    state.update(&(storage.len() as u64).to_be_bytes());
    state.update(storage.as_bytes());
    state.update(&(salt.len() as u64).to_be_bytes());
    state.update(salt.as_bytes());
    state.finalize().0
}

#[cfg(target_os = "windows")]
pub(crate) async fn quiesce_windows_service_owned_credential(
    expected_identity: WindowsProcessIdentityKey,
    transition_id: String,
    ms_timeout: u64,
) -> ResultType<WindowsCredentialReplicaState> {
    windows_service_credential_request(
        expected_identity,
        WindowsServiceMainRequest::QuiesceCredentialReplica { transition_id },
        ms_timeout,
    )
    .await
}

#[cfg(target_os = "windows")]
pub(crate) async fn apply_windows_service_owned_credential(
    expected_identity: WindowsProcessIdentityKey,
    transition_id: String,
    storage: String,
    salt: String,
    replica_tag: [u8; 32],
    ms_timeout: u64,
) -> ResultType<WindowsCredentialReplicaState> {
    windows_service_credential_request(
        expected_identity,
        WindowsServiceMainRequest::ApplyCredentialReplica {
            transition_id,
            storage,
            salt,
            replica_tag,
        },
        ms_timeout,
    )
    .await
}

#[cfg(target_os = "windows")]
pub(crate) async fn query_windows_service_owned_credential(
    expected_identity: WindowsProcessIdentityKey,
    ms_timeout: u64,
) -> ResultType<WindowsCredentialReplicaState> {
    windows_service_credential_request(
        expected_identity,
        WindowsServiceMainRequest::QueryCredentialReplica,
        ms_timeout,
    )
    .await
}

#[cfg(target_os = "windows")]
pub(crate) async fn resume_windows_service_owned_credential(
    expected_identity: WindowsProcessIdentityKey,
    transition_id: String,
    ms_timeout: u64,
) -> ResultType<WindowsCredentialReplicaState> {
    windows_service_credential_request(
        expected_identity,
        WindowsServiceMainRequest::ResumeCredentialReplica { transition_id },
        ms_timeout,
    )
    .await
}

#[cfg(target_os = "windows")]
pub async fn get_windows_service_owned_port_forward_session_count(
    expected_identity: WindowsProcessIdentityKey,
    ms_timeout: u64,
) -> ResultType<usize> {
    match windows_service_main_request(
        Some(expected_identity),
        WindowsServiceMainRequest::PortForwardSessionCount,
        ms_timeout,
    )
    .await?
    {
        WindowsServiceMainResponse::PortForwardSessionCount(count) => Ok(count),
        _ => bail!("invalid Windows service-main port-forward response"),
    }
}

#[cfg(target_os = "windows")]
pub async fn close_windows_service_owned_main_server(
    expected_identity: WindowsProcessIdentityKey,
    ms_timeout: u64,
) -> ResultType<()> {
    match windows_service_main_request(
        Some(expected_identity),
        WindowsServiceMainRequest::Shutdown,
        ms_timeout,
    )
    .await?
    {
        WindowsServiceMainResponse::ShutdownAccepted => Ok(()),
        _ => bail!("invalid Windows service-main shutdown response"),
    }
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
pub async fn get_terminal_session_count() -> ResultType<usize> {
    let timeout_ms = 1_000;
    let effective_uid = unsafe { hbb_common::libc::geteuid() as u32 };
    let candidate_uids = terminal_count_candidate_uids(effective_uid);
    let mut last_err: Option<anyhow::Error> = None;
    for candidate_uid in candidate_uids {
        let socket_path = Config::ipc_path_for_uid(candidate_uid, "");
        let connect_result = timeout(timeout_ms, Endpoint::connect(&socket_path))
            .await
            .map_err(|err| {
                anyhow::anyhow!(
                    "Timeout connecting to terminal ipc at {}: {}",
                    socket_path,
                    err
                )
            });
        let connection = match connect_result {
            Ok(Ok(connection)) => connection,
            Ok(Err(err)) => {
                last_err = Some(anyhow::anyhow!(
                    "Failed to connect to terminal ipc at {}: {}",
                    socket_path,
                    err
                ));
                continue;
            }
            Err(err) => {
                last_err = Some(err);
                continue;
            }
        };
        let ipc_conn = ConnectionTmpl::new_main(connection);
        match main_ipc_request_on_stream(ipc_conn, MainIpcRequest::TerminalSessionCount, timeout_ms)
            .await
        {
            Ok(MainIpcResponse::TerminalSessionCount(session_count)) => {
                return Ok(session_count);
            }
            Ok(_) => {
                last_err = Some(anyhow::anyhow!(
                    "Unexpected terminal session count response via ipc at {}",
                    socket_path
                ));
            }
            Err(err) => {
                last_err = Some(anyhow::anyhow!(
                    "Failed to read terminal session count via ipc at {}: {}",
                    socket_path,
                    err
                ));
            }
        }
    }
    if let Some(err) = last_err {
        Err(err.into())
    } else {
        Ok(0)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn r_s11e58_protected_service_ipc_returns_listener_failure_to_its_owner() {
        assert!(protected_service_ipc_result(None).is_ok());

        let failure = protected_service_ipc_result(Some(
            "protected service IPC listener ended unexpectedly".to_owned(),
        ))
        .unwrap_err();
        assert_eq!(
            failure.to_string(),
            "protected service IPC listener ended unexpectedly"
        );
    }

    #[test]
    fn windows_credential_ledger_replays_lost_ack_without_password_retention() {
        let mut ledger = WindowsCredentialOperationLedger::new(4);
        assert!(ledger.admit("operation", "new-password", false));
        assert_eq!(
            ledger.status("operation", "new-password"),
            Some(PasswordMutationStatus::Pending)
        );
        assert_eq!(
            ledger.status("operation", "different-password"),
            Some(PasswordMutationStatus::Complete(
                IpcMutationResult::Rejected
            ))
        );
        ledger
            .complete("operation", IpcMutationResult::Applied)
            .unwrap();
        assert_eq!(
            ledger.status("operation", "new-password"),
            Some(PasswordMutationStatus::Complete(IpcMutationResult::Applied))
        );
    }

    #[test]
    fn windows_credential_ledger_evicts_only_completed_replay_entries() {
        let mut ledger = WindowsCredentialOperationLedger::new(1);
        assert!(ledger.admit("first", "one", false));
        ledger
            .complete("first", IpcMutationResult::Rejected)
            .unwrap();
        assert!(ledger.admit("second", "two", false));
        assert_eq!(ledger.status("first", "one"), None);
        assert_eq!(
            ledger.status("second", "two"),
            Some(PasswordMutationStatus::Pending)
        );

        let mut active = WindowsCredentialOperationLedger::new(1);
        assert!(active.admit("first", "one", false));
        assert!(!active.admit("second", "two", false));

        let mut stopping = WindowsCredentialOperationLedger::new(2);
        stopping.begin_shutdown();
        assert!(stopping.is_shutting_down());
        assert!(!stopping.admit("after-stop", "secret", false));
    }

    #[test]
    fn windows_credential_queue_saturation_never_contradicts_replay_state() {
        let mut ledger = WindowsCredentialOperationLedger::new(2);
        assert!(ledger.admit("committed", "secret", false));
        ledger
            .complete("committed", IpcMutationResult::Applied)
            .unwrap();

        assert_eq!(
            windows_credential_queue_uncertainty_status(),
            PasswordMutationStatus::Pending
        );
        assert_eq!(
            ledger.status("committed", "secret"),
            Some(PasswordMutationStatus::Complete(IpcMutationResult::Applied))
        );
        assert_eq!(
            windows_credential_queue_uncertainty_status(),
            PasswordMutationStatus::Pending
        );
    }

    #[test]
    fn windows_credential_shutdown_drain_replays_active_duplicate() {
        let mut ledger = WindowsCredentialOperationLedger::new(2);
        assert!(ledger.admit("operation", "secret", false));
        ledger.begin_shutdown();

        assert_eq!(
            ledger.classify_during_shutdown("operation", "secret"),
            PasswordMutationStatus::Pending
        );
    }

    #[test]
    fn windows_credential_shutdown_drain_replays_completed_duplicate() {
        let mut ledger = WindowsCredentialOperationLedger::new(2);
        assert!(ledger.admit("operation", "secret", false));
        ledger
            .complete("operation", IpcMutationResult::Applied)
            .unwrap();
        ledger.begin_shutdown();

        assert_eq!(
            ledger.classify_during_shutdown("operation", "secret"),
            PasswordMutationStatus::Complete(IpcMutationResult::Applied)
        );
    }

    #[test]
    fn windows_credential_shutdown_drain_rejects_only_unmatched_request() {
        let mut ledger = WindowsCredentialOperationLedger::new(2);
        ledger.begin_shutdown();

        assert_eq!(
            ledger.classify_during_shutdown("fresh-operation", "secret"),
            PasswordMutationStatus::ShuttingDown
        );
    }

    #[test]
    fn windows_credential_closed_queue_is_nonterminal() {
        assert_eq!(
            windows_credential_queue_uncertainty_status(),
            PasswordMutationStatus::Pending
        );
    }

    #[test]
    fn windows_credential_lost_reply_stop_and_apply_remain_consistent() {
        let mut ledger = WindowsCredentialOperationLedger::new(2);
        assert!(ledger.admit("operation", "secret", false));
        ledger.begin_shutdown();

        let drained = ledger.classify_during_shutdown("operation", "secret");
        assert_eq!(drained, PasswordMutationStatus::Pending);
        assert_eq!(
            windows_credential_client_decision(drained, false),
            WindowsCredentialClientDecision::Continue
        );

        ledger
            .complete("operation", IpcMutationResult::Applied)
            .unwrap();
        let final_status = ledger.classify_during_shutdown("operation", "secret");
        assert_eq!(
            windows_credential_client_decision(final_status, true),
            WindowsCredentialClientDecision::Applied
        );
    }

    #[test]
    fn windows_credential_client_only_retries_explicitly_unknown_recovery() {
        assert_eq!(
            windows_credential_client_decision(PasswordMutationStatus::ShuttingDown, false),
            WindowsCredentialClientDecision::NotAdmitted
        );
        assert_eq!(
            windows_credential_client_decision(PasswordMutationStatus::ShuttingDown, true),
            WindowsCredentialClientDecision::NotAdmitted
        );
        assert_eq!(
            windows_credential_client_decision(PasswordMutationStatus::Unknown, true),
            WindowsCredentialClientDecision::Continue
        );
        assert_eq!(
            windows_credential_client_decision(PasswordMutationStatus::Unknown, false),
            WindowsCredentialClientDecision::NotAdmitted
        );
    }

    #[test]
    fn windows_credential_operation_bound_failures_remain_terminal_during_recovery() {
        let mut first_service = WindowsCredentialOperationLedger::new(2);
        assert!(first_service.admit("operation", "secret", false));
        first_service
            .complete("operation", IpcMutationResult::Applied)
            .unwrap();

        let mut transaction_busy_service = WindowsCredentialOperationLedger::new(2);
        assert!(!transaction_busy_service.admit("operation", "secret", true));
        assert_eq!(
            windows_credential_client_decision(
                PasswordMutationStatus::Complete(IpcMutationResult::Rejected),
                true,
            ),
            WindowsCredentialClientDecision::Rejected
        );

        let mut capacity_full_service = WindowsCredentialOperationLedger::new(1);
        assert!(capacity_full_service.admit("other-operation", "other-secret", false));
        assert!(!capacity_full_service.admit("operation", "secret", false));
        assert_eq!(
            windows_credential_client_decision(
                PasswordMutationStatus::Complete(IpcMutationResult::Rejected),
                true,
            ),
            WindowsCredentialClientDecision::Rejected
        );

        let mut liveness_failure_service = WindowsCredentialOperationLedger::new(2);
        assert!(liveness_failure_service.admit("operation", "secret", false));
        liveness_failure_service
            .complete("operation", IpcMutationResult::InternalFailure)
            .unwrap();
        let liveness_status = liveness_failure_service
            .status("operation", "secret")
            .unwrap();
        assert_eq!(
            windows_credential_client_decision(
                PasswordMutationStatus::Complete(IpcMutationResult::Rejected),
                true,
            ),
            WindowsCredentialClientDecision::Rejected
        );
        assert_eq!(
            windows_credential_client_decision(liveness_status, true),
            WindowsCredentialClientDecision::InternalFailure
        );

        let mut reapplying_service = WindowsCredentialOperationLedger::new(2);
        assert!(reapplying_service.admit("operation", "secret", false));
        reapplying_service
            .complete("operation", IpcMutationResult::Applied)
            .unwrap();
        assert_eq!(
            windows_credential_client_decision(
                reapplying_service.status("operation", "secret").unwrap(),
                true,
            ),
            WindowsCredentialClientDecision::Applied
        );
    }

    #[test]
    fn windows_credential_first_authoritative_failure_remains_terminal() {
        assert_eq!(
            windows_credential_client_decision(
                PasswordMutationStatus::Complete(IpcMutationResult::Rejected),
                false,
            ),
            WindowsCredentialClientDecision::Rejected
        );
        assert_eq!(
            windows_credential_client_decision(
                PasswordMutationStatus::Complete(IpcMutationResult::InternalFailure),
                false,
            ),
            WindowsCredentialClientDecision::InternalFailure
        );
    }

    #[test]
    fn windows_credential_sensitive_password_uses_tested_in_place_erasure() {
        let mut password = SensitivePassword::new("password-secret".to_owned());
        assert!(password.zeroize());
        assert!(password.as_str().as_bytes().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn windows_credential_stop_before_apply_prevents_replica_admission() {
        let mut authority = WindowsCredentialStopApplyModel::new();
        assert!(!authority.request_stop());
        assert_eq!(
            authority.state(),
            WindowsCredentialStopApplyState::StopBeforeApply
        );
        assert!(!authority.admit_apply());
        assert!(!authority.stop_is_linearized());
        assert!(authority.complete_stop());
        assert!(authority.stop_is_linearized());
    }

    #[test]
    fn windows_credential_apply_before_stop_is_awaited_before_stop_linearizes() {
        let mut authority = WindowsCredentialStopApplyModel::new();
        assert!(authority.admit_apply());
        assert!(!authority.request_stop());
        assert_eq!(
            authority.state(),
            WindowsCredentialStopApplyState::StopPendingApply
        );
        assert!(!authority.complete_stop());
        assert!(!authority.stop_is_linearized());
        assert!(!authority.finish_apply());
        assert_eq!(
            authority.state(),
            WindowsCredentialStopApplyState::ReadyToStop
        );
        assert!(authority.complete_stop());
        assert!(authority.stop_is_linearized());
        assert!(!authority.admit_apply());
    }

    #[test]
    fn windows_credential_job_stop_retries_until_empty_and_aborts_on_lost_authority() {
        assert_eq!(
            windows_job_stop_decision(Some(2), Some(123)),
            WindowsJobStopDecision::Retry
        );
        assert_eq!(
            windows_job_stop_decision(Some(1), None),
            WindowsJobStopDecision::Retry
        );
        assert_eq!(
            windows_job_stop_decision(Some(0), None),
            WindowsJobStopDecision::Empty
        );
        assert_eq!(
            windows_job_stop_decision(None, Some(5)),
            WindowsJobStopDecision::Abort
        );
        assert_eq!(
            windows_job_stop_decision(None, Some(6)),
            WindowsJobStopDecision::Abort
        );
        assert_eq!(
            windows_job_stop_decision(None, None),
            WindowsJobStopDecision::Abort
        );
    }

    #[test]
    fn windows_credential_model_binds_to_exact_child_identity() {
        let model = WindowsCredentialTransactionModel::admitted(Some((7, 100)));
        assert!(model.exact_child_is_live(Some((7, 100))));
        assert!(!model.exact_child_is_live(Some((7, 101))));
        assert!(!model.exact_child_is_live(Some((8, 100))));
        assert!(!model.exact_child_is_live(None));
    }

    #[test]
    fn windows_credential_model_accepts_idempotent_quiesce_replay() {
        let mut model = WindowsCredentialTransactionModel::admitted(Some((7, 100)));
        model.note_quiesced().unwrap();
        model.note_quiesced().unwrap();
        let resolution = model
            .precommit_failure(true, IpcMutationResult::InternalFailure)
            .unwrap();
        assert_eq!(resolution.result, IpcMutationResult::InternalFailure);
        assert!(!resolution.retire_child);
    }

    #[test]
    fn windows_credential_model_precommit_death_requires_retirement() {
        let mut dead = WindowsCredentialTransactionModel::admitted(Some((7, 100)));
        dead.note_quiesced().unwrap();
        let resolution = dead
            .precommit_failure(false, IpcMutationResult::InternalFailure)
            .unwrap();
        assert!(resolution.retire_child);

        let mut resumed = WindowsCredentialTransactionModel::admitted(Some((7, 100)));
        resumed.note_quiesced().unwrap();
        let resolution = resumed
            .precommit_failure(true, IpcMutationResult::InternalFailure)
            .unwrap();
        assert!(!resolution.retire_child);
    }

    #[test]
    fn windows_credential_model_postcommit_death_stays_applied() {
        let mut model = WindowsCredentialTransactionModel::admitted(Some((7, 100)));
        model.note_quiesced().unwrap();
        model.note_committed().unwrap();
        let resolution = model.postcommit_complete(false).unwrap();
        assert_eq!(resolution.result, IpcMutationResult::Applied);
        assert!(resolution.retire_child);
        assert!(model
            .precommit_failure(false, IpcMutationResult::InternalFailure)
            .is_err());
        assert_eq!(
            model.postcommit_complete(false).unwrap().result,
            IpcMutationResult::Applied
        );
    }

    #[test]
    fn windows_credential_model_lost_apply_ack_resolves_as_applied() {
        let mut model = WindowsCredentialTransactionModel::admitted(Some((7, 100)));
        model.note_quiesced().unwrap();
        model.note_committed().unwrap();

        let resolution = model.postcommit_complete(true).unwrap();
        assert_eq!(resolution.result, IpcMutationResult::Applied);
        assert!(!resolution.retire_child);
        assert!(model
            .precommit_failure(false, IpcMutationResult::InternalFailure)
            .is_err());
    }

    #[test]
    fn windows_credential_model_stop_after_admission_finishes_commit_and_skips_replica() {
        let mut model = WindowsCredentialTransactionModel::admitted(Some((7, 100)));
        model.request_stop();
        model.note_quiesced().unwrap();
        model.note_committed().unwrap();
        assert!(model.should_skip_replica_apply());
        let resolution = model.postcommit_complete(false).unwrap();
        assert_eq!(resolution.result, IpcMutationResult::Applied);
        assert!(!resolution.retire_child);
    }

    #[test]
    fn verify_ffi_enum_data_size() {
        println!("{}", std::mem::size_of::<Data>());
        assert!(std::mem::size_of::<Data>() <= 120);
    }

    #[test]
    fn cm_clipboard_authority_is_remote_only() {
        assert!(CmAuthConnType::Remote.allows_clipboard_authority());
        assert!(!CmAuthConnType::FileTransfer.allows_clipboard_authority());
        assert!(!CmAuthConnType::ViewCamera.allows_clipboard_authority());
        assert!(!CmAuthConnType::Terminal.allows_clipboard_authority());
        assert!(!CmAuthConnType::PortForward.allows_clipboard_authority());
    }

    #[test]
    fn cm_file_authority_is_file_transfer_only() {
        assert!(!CmAuthConnType::Remote.allows_file_authority());
        assert!(CmAuthConnType::FileTransfer.allows_file_authority());
        assert!(!CmAuthConnType::ViewCamera.allows_file_authority());
        assert!(!CmAuthConnType::Terminal.allows_file_authority());
        assert!(!CmAuthConnType::PortForward.allows_file_authority());
    }

    #[test]
    fn cm_read_block_serialization_keeps_authority_metadata_and_splits_payload() {
        let data = Data::CmFileResponse(CmFileResponse {
            conn_id: 7,
            cm_auth_token: "session-token".to_owned(),
            response: Box::new(CmFileResponseKind::ReadBlock {
                id: 3,
                generation: 11,
                file_num: 2,
                data: Bytes::from_static(b"block-payload"),
                compressed: true,
            }),
        });
        let encoded = serde_json::to_vec(&data).unwrap();
        assert!(!encoded
            .windows(b"block-payload".len())
            .any(|window| window == b"block-payload"));

        let decoded: Data = serde_json::from_slice(&encoded).unwrap();
        let Data::CmFileResponse(response) = decoded else {
            panic!("unexpected data variant");
        };
        assert_eq!(response.conn_id, 7);
        assert_eq!(response.cm_auth_token, "session-token");
        let CmFileResponseKind::ReadBlock {
            id,
            generation,
            file_num,
            data,
            compressed,
        } = *response.response
        else {
            panic!("unexpected CM file response");
        };
        assert_eq!((id, generation, file_num), (3, 11, 2));
        assert!(data.is_empty());
        assert!(compressed);
    }

    #[test]
    fn cm_operation_serialization_preserves_exact_descriptor() {
        let operation = CmFileOperation::Rename {
            path: "/source/name".to_owned(),
            new_name: "renamed".to_owned(),
        };
        let data = Data::CmFileResponse(CmFileResponse {
            conn_id: 7,
            cm_auth_token: "session-token".to_owned(),
            response: Box::new(CmFileResponseKind::Operation {
                request_id: 13,
                operation: operation.clone(),
                result: Ok(()),
            }),
        });

        let decoded: Data = serde_json::from_slice(&serde_json::to_vec(&data).unwrap()).unwrap();
        let Data::CmFileResponse(response) = decoded else {
            panic!("unexpected data variant");
        };
        let CmFileResponseKind::Operation {
            request_id,
            operation: decoded_operation,
            result,
        } = *response.response
        else {
            panic!("unexpected CM file response");
        };
        assert_eq!(request_id, 13);
        assert_eq!(decoded_operation, operation);
        assert_eq!(result, Ok(()));
    }

    fn macos_service_owned_launch_agent_test_plist(label: &str, args: &[&str]) -> plist::Value {
        let args_xml = args
            .iter()
            .map(|arg| format!("            <string>{arg}</string>\n"))
            .collect::<String>();
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Label</key>
        <string>{label}</string>
        <key>KeepAlive</key>
        <dict>
            <key>SuccessfulExit</key>
            <false />
            <key>AfterInitialDemand</key>
            <false />
        </dict>
        <key>RunAtLoad</key>
        <true />
        <key>ProgramArguments</key>
        <array>
{args_xml}        </array>
    </dict>
</plist>
"#
        );
        plist::Value::from_reader_xml(xml.as_bytes()).unwrap()
    }

    #[test]
    fn macos_launchctl_service_identity_accepts_exact_top_level_record() {
        let target = "gui/501/com.carriez.RustDesk_server";
        let path = "/Library/LaunchAgents/com.carriez.RustDesk_server.plist";
        let output = format!(
            r#"{target} = {{
    active count = 1
    path = "{path}";
    environment = {{
        pid = 7
        path = /tmp/untrusted.plist
    }}
    pid = 4242
}}
"#
        );

        assert_eq!(
            macos_launchctl_service_identity(output.as_bytes(), target),
            Some((4242, path))
        );
    }

    #[test]
    fn macos_launchctl_service_identity_rejects_nested_substitution() {
        let target = "gui/501/com.carriez.RustDesk_server";
        let path = "/Library/LaunchAgents/com.carriez.RustDesk_server.plist";
        let output = format!(
            r#"{target} = {{
    environment = {{
        pid = 4242
        path = {path}
    }}
    pid = 7
    path = /tmp/untrusted.plist
}}
"#
        );

        assert_ne!(
            macos_launchctl_service_identity(output.as_bytes(), target),
            Some((4242, path))
        );
    }

    #[test]
    fn macos_launchctl_service_identity_rejects_duplicate_top_level_authority() {
        let target = "gui/501/com.carriez.RustDesk_server";
        let path = "/Library/LaunchAgents/com.carriez.RustDesk_server.plist";
        for duplicate in ["pid = 4242".to_owned(), format!("path = {path}")] {
            let output = format!(
                r#"{target} = {{
    path = {path}
    pid = 4242
    {duplicate}
}}
"#
            );
            assert_eq!(
                macos_launchctl_service_identity(output.as_bytes(), target),
                None,
                "duplicate authority field was accepted: {duplicate}"
            );
        }
    }

    #[test]
    fn macos_launchctl_service_identity_rejects_wrong_target_or_trailing_record() {
        let target = "gui/501/com.carriez.RustDesk_server";
        let record = b"gui/502/com.carriez.RustDesk_server = {\npath = /Library/LaunchAgents/com.carriez.RustDesk_server.plist\npid = 4242\n}\n";
        assert_eq!(macos_launchctl_service_identity(record, target), None);

        let trailing = b"gui/501/com.carriez.RustDesk_server = {\npath = /Library/LaunchAgents/com.carriez.RustDesk_server.plist\npid = 4242\n}\nunrelated = {\n}\n";
        assert_eq!(macos_launchctl_service_identity(trailing, target), None);
    }

    #[test]
    fn macos_launchctl_service_identity_rejects_non_utf8_or_noncanonical_pid() {
        let target = "gui/501/com.carriez.RustDesk_server";
        assert_eq!(macos_launchctl_service_identity(&[0xff], target), None);

        let output = b"gui/501/com.carriez.RustDesk_server = {\npath = /Library/LaunchAgents/com.carriez.RustDesk_server.plist\npid = 04242\n}\n";
        assert_eq!(macos_launchctl_service_identity(output, target), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn macos_bounded_child_stdout_accepts_exact_output() {
        let mut command = std::process::Command::new("/usr/bin/printf");
        command.args(["%s", "exact-output"]);
        let output = run_macos_bounded_child_stdout(
            &mut command,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            b"exact-output".len(),
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"exact-output");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn macos_bounded_child_stdout_terminates_on_overflow() {
        let mut command = std::process::Command::new("/usr/bin/yes");
        let started = std::time::Instant::now();
        let error = run_macos_bounded_child_stdout(
            &mut command,
            started + std::time::Duration::from_secs(1),
            4 * 1024,
        )
        .unwrap_err();
        assert!(error.to_string().contains("stdout exceeded 4096 bytes"));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn macos_bounded_child_stdout_terminates_on_deadline() {
        let mut command = std::process::Command::new("/bin/sleep");
        command.arg("5");
        let started = std::time::Instant::now();
        let error = run_macos_bounded_child_stdout(
            &mut command,
            started + std::time::Duration::from_millis(50),
            MACOS_LAUNCHCTL_STDOUT_MAX_BYTES,
        )
        .unwrap_err();
        assert!(error.to_string().contains("absolute deadline"));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn macos_service_owned_launch_agent_plist_validation_accepts_expected_program_arguments() {
        let label = "com.carriez.RustDesk_server";
        let executable = "/Applications/RustDesk.app/Contents/MacOS/RustDesk";
        let value = macos_service_owned_launch_agent_test_plist(
            label,
            &[
                executable,
                "--server",
                crate::common::SERVICE_OWNED_SERVER_ARG,
            ],
        );

        assert!(
            macos_service_owned_server_launch_agent_plist_value_is_expected(
                &value, label, executable
            )
        );
    }

    #[test]
    fn macos_service_owned_launch_agent_plist_validation_rejects_missing_service_arg() {
        let label = "com.carriez.RustDesk_server";
        let executable = "/Applications/RustDesk.app/Contents/MacOS/RustDesk";
        let value = macos_service_owned_launch_agent_test_plist(label, &[executable, "--server"]);

        assert!(
            !macos_service_owned_server_launch_agent_plist_value_is_expected(
                &value, label, executable
            )
        );
    }

    #[test]
    fn macos_service_owned_launch_agent_plist_validation_rejects_extra_arg() {
        let label = "com.carriez.RustDesk_server";
        let executable = "/Applications/RustDesk.app/Contents/MacOS/RustDesk";
        let value = macos_service_owned_launch_agent_test_plist(
            label,
            &[
                executable,
                "--server",
                crate::common::SERVICE_OWNED_SERVER_ARG,
                "--unexpected",
            ],
        );

        assert!(
            !macos_service_owned_server_launch_agent_plist_value_is_expected(
                &value, label, executable
            )
        );
    }

    #[test]
    fn macos_service_owned_launch_agent_plist_validation_rejects_wrong_executable() {
        let label = "com.carriez.RustDesk_server";
        let executable = "/Applications/RustDesk.app/Contents/MacOS/RustDesk";
        let value = macos_service_owned_launch_agent_test_plist(
            label,
            &[
                "/tmp/RustDesk",
                "--server",
                crate::common::SERVICE_OWNED_SERVER_ARG,
            ],
        );

        assert!(
            !macos_service_owned_server_launch_agent_plist_value_is_expected(
                &value, label, executable
            )
        );
    }

    #[test]
    fn macos_service_owned_launch_agent_plist_validation_rejects_wrong_label() {
        let label = "com.carriez.RustDesk_server";
        let executable = "/Applications/RustDesk.app/Contents/MacOS/RustDesk";
        let value = macos_service_owned_launch_agent_test_plist(
            "com.attacker.RustDesk_server",
            &[
                executable,
                "--server",
                crate::common::SERVICE_OWNED_SERVER_ARG,
            ],
        );

        assert!(
            !macos_service_owned_server_launch_agent_plist_value_is_expected(
                &value, label, executable
            )
        );
    }

    #[test]
    fn macos_service_owned_launch_agent_plist_validation_rejects_run_at_load_false() {
        let label = "com.carriez.RustDesk_server";
        let executable = "/Applications/RustDesk.app/Contents/MacOS/RustDesk";
        let mut value = macos_service_owned_launch_agent_test_plist(
            label,
            &[
                executable,
                "--server",
                crate::common::SERVICE_OWNED_SERVER_ARG,
            ],
        );
        value
            .as_dictionary_mut()
            .unwrap()
            .insert("RunAtLoad".to_owned(), plist::Value::Boolean(false));

        assert!(
            !macos_service_owned_server_launch_agent_plist_value_is_expected(
                &value, label, executable
            )
        );
    }

    #[test]
    fn macos_service_owned_launch_agent_plist_validation_rejects_missing_keep_alive() {
        let label = "com.carriez.RustDesk_server";
        let executable = "/Applications/RustDesk.app/Contents/MacOS/RustDesk";
        let mut value = macos_service_owned_launch_agent_test_plist(
            label,
            &[
                executable,
                "--server",
                crate::common::SERVICE_OWNED_SERVER_ARG,
            ],
        );
        value.as_dictionary_mut().unwrap().remove("KeepAlive");

        assert!(
            !macos_service_owned_server_launch_agent_plist_value_is_expected(
                &value, label, executable
            )
        );
    }

    #[test]
    fn macos_service_owned_launch_agent_plist_validation_rejects_extra_keep_alive_key() {
        let label = "com.carriez.RustDesk_server";
        let executable = "/Applications/RustDesk.app/Contents/MacOS/RustDesk";
        let mut value = macos_service_owned_launch_agent_test_plist(
            label,
            &[
                executable,
                "--server",
                crate::common::SERVICE_OWNED_SERVER_ARG,
            ],
        );
        value
            .as_dictionary_mut()
            .unwrap()
            .get_mut("KeepAlive")
            .unwrap()
            .as_dictionary_mut()
            .unwrap()
            .insert("OtherCondition".to_owned(), plist::Value::Boolean(true));

        assert!(
            !macos_service_owned_server_launch_agent_plist_value_is_expected(
                &value, label, executable
            )
        );
    }

    #[test]
    fn macos_service_owned_server_live_argv_accepts_exact_service_owned_server() {
        let cmd = vec![
            "/Applications/RustDesk.app/Contents/MacOS/RustDesk".to_owned(),
            "--server".to_owned(),
            crate::common::SERVICE_OWNED_SERVER_ARG.to_owned(),
        ];

        assert!(macos_service_owned_server_live_argv_is_expected(&cmd));
    }

    #[test]
    fn macos_service_owned_server_live_argv_rejects_extra_arg() {
        let cmd = vec![
            "/Applications/RustDesk.app/Contents/MacOS/RustDesk".to_owned(),
            "--server".to_owned(),
            crate::common::SERVICE_OWNED_SERVER_ARG.to_owned(),
            "--tray".to_owned(),
        ];

        assert!(!macos_service_owned_server_live_argv_is_expected(&cmd));
    }

    #[test]
    fn macos_service_owned_server_live_argv_rejects_missing_service_arg() {
        let cmd = vec![
            "/Applications/RustDesk.app/Contents/MacOS/RustDesk".to_owned(),
            "--server".to_owned(),
        ];

        assert!(!macos_service_owned_server_live_argv_is_expected(&cmd));
    }

    #[test]
    fn macos_service_owned_server_live_argv_rejects_wrong_service_arg() {
        let cmd = vec![
            "/Applications/RustDesk.app/Contents/MacOS/RustDesk".to_owned(),
            "--server".to_owned(),
            "--tray".to_owned(),
        ];

        assert!(!macos_service_owned_server_live_argv_is_expected(&cmd));
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn main_protocol_rejects_global_data_frames() {
        let frame = serde_json::to_vec(&Data::Close).unwrap();
        assert!(serde_json::from_slice::<MainIpcRequest>(&frame).is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn desktop_url_ipc_uses_closed_bounded_protocol() {
        let prefix = crate::get_uri_prefix();
        let url = format!("{prefix}connect/127.0.0.1:21118");
        let open = DesktopUrlIpcRequest::from_url(url.clone()).unwrap();
        assert_eq!(
            open,
            DesktopUrlIpcRequest::OpenUrl { url: url.clone() }
        );
        assert_eq!(
            DesktopUrlIpcRequest::from_url(prefix.clone()).unwrap(),
            DesktopUrlIpcRequest::Activate {}
        );
        assert_eq!(
            DesktopUrlIpcRequest::from_url(format!("{prefix}///")).unwrap(),
            DesktopUrlIpcRequest::Activate {}
        );
        let domain_url = format!("{prefix}file-transfer/example.com:21118");
        assert_eq!(
            DesktopUrlIpcRequest::from_url(domain_url.clone()).unwrap(),
            DesktopUrlIpcRequest::OpenUrl { url: domain_url }
        );
        assert!(DesktopUrlIpcRequest::from_url(String::new()).is_err());
        assert!(DesktopUrlIpcRequest::from_url("close".to_owned()).is_err());
        assert!(
            DesktopUrlIpcRequest::from_url("https://connect/127.0.0.1:21118".to_owned())
                .is_err()
        );
        assert!(
            DesktopUrlIpcRequest::from_url(format!("{prefix}connect/123456789")).is_err()
        );
        assert!(
            DesktopUrlIpcRequest::from_url(format!(
                "{prefix}connect/123456789@relay.example:21117"
            ))
            .is_err()
        );
        assert!(
            DesktopUrlIpcRequest::from_url(format!("{prefix}connect/example.com")).is_err()
        );
        assert!(
            DesktopUrlIpcRequest::from_url(format!(
                "{prefix}connect/127.0.0.1:21118?password=secret"
            ))
            .is_err()
        );
        assert!(
            DesktopUrlIpcRequest::from_url(format!(
                "{prefix}config/example.org:21118"
            ))
            .is_err()
        );
        assert!(
            DesktopUrlIpcRequest::from_url(format!(
                "{prefix}connect/{}",
                "a".repeat(DESKTOP_URL_IPC_MAX_ADDRESS_BYTES + 1)
            ))
            .is_err()
        );
        assert!(
            DesktopUrlIpcRequest::OpenUrl {
                url: prefix.clone()
            }
            .validate()
            .is_err()
        );

        let encoded = serde_json::to_vec(&open).unwrap();
        assert_eq!(
            encoded,
            format!(r#"{{"t":"OpenUrl","url":"{url}"}}"#).as_bytes()
        );
        assert_eq!(
            serde_json::from_slice::<DesktopUrlIpcRequest>(&encoded).unwrap(),
            open
        );
        assert!(
            serde_json::from_slice::<DesktopUrlIpcRequest>(
                br#"{"t":"OpenUrl","url":"rustdesk://connect/127.0.0.1","extra":true}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_slice::<DesktopUrlIpcRequest>(
                &serde_json::to_vec(&Data::Close).unwrap()
            )
            .is_err()
        );

        let (client_end, server_end) =
            tokio::io::duplex(DESKTOP_URL_IPC_MAX_FRAME_BYTES * 2);
        let mut client = ConnectionTmpl::new_desktop_url(client_end);
        let mut server = ConnectionTmpl::new_desktop_url(server_end);
        assert_eq!(
            client.inner.codec().max_packet_length(),
            DESKTOP_URL_IPC_MAX_FRAME_BYTES
        );
        client
            .send_desktop_url_request_timeout(&open, DESKTOP_URL_IPC_IO_TIMEOUT_MS)
            .await
            .unwrap();
        assert_eq!(
            server
                .next_desktop_url_request_timeout(DESKTOP_URL_IPC_IO_TIMEOUT_MS)
                .await
                .unwrap()
                .validate()
                .unwrap(),
            open
        );

        let (bad_sender_end, bad_receiver_end) =
            tokio::io::duplex(DESKTOP_URL_IPC_MAX_FRAME_BYTES * 2);
        let mut bad_sender = ConnectionTmpl::new(bad_sender_end);
        let mut bad_receiver = ConnectionTmpl::new_desktop_url(bad_receiver_end);
        bad_sender.send(&Data::Close).await.unwrap();
        assert!(
            bad_receiver
                .next_desktop_url_request_timeout(DESKTOP_URL_IPC_IO_TIMEOUT_MS)
                .await
                .is_err()
        );

        let (oversize_sender_end, oversize_receiver_end) =
            tokio::io::duplex(DESKTOP_URL_IPC_MAX_FRAME_BYTES * 2);
        let mut oversize_sender = ConnectionTmpl::new(oversize_sender_end);
        let mut oversize_receiver =
            ConnectionTmpl::new_desktop_url(oversize_receiver_end);
        oversize_sender
            .send_raw(Bytes::from(vec![0; DESKTOP_URL_IPC_MAX_FRAME_BYTES + 1]))
            .await
            .unwrap();
        assert!(
            oversize_receiver
                .next_desktop_url_request_timeout(DESKTOP_URL_IPC_IO_TIMEOUT_MS)
                .await
                .is_err()
        );

        let (idle_end, idle_peer) = tokio::io::duplex(DESKTOP_URL_IPC_MAX_FRAME_BYTES);
        let mut idle = ConnectionTmpl::new_desktop_url(idle_end);
        assert!(idle.next_desktop_url_request_timeout(1).await.is_err());
        drop(idle_peer);
        assert!(
            idle.next_desktop_url_request_timeout(DESKTOP_URL_IPC_IO_TIMEOUT_MS)
                .await
                .is_err()
        );
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn main_authority_keeps_service_owned_mutations_closed() {
        let user_owned = MainIpcAuthority::UserOwned;
        let service_owned = MainIpcAuthority::ServiceOwned;

        assert!(user_owned.allows_main_channel_user_owned_password_write());
        assert!(user_owned.allows_main_channel_options_write());
        assert!(user_owned.allows_main_channel_voice_call_input_write());
        assert!(!service_owned.allows_main_channel_user_owned_password_write());
        assert!(!service_owned.allows_main_channel_options_write());
        assert!(!service_owned.allows_main_channel_voice_call_input_write());
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn main_config_keys_expose_typed_password_status_but_not_credential_storage() {
        assert_eq!(
            main_config_key("permanent-password-set"),
            Some(MainConfigKey::PermanentPasswordSet)
        );
        assert!(main_config_key("local-permanent-password-set").is_none());
        assert!(main_config_key("permanent-password-is-preset").is_none());
        assert!(main_config_key("permanent-password-storage-and-salt").is_none());
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn service_channel_uses_closed_directional_protocol() {
        let request = serde_json::to_vec(&ServiceIpcRequest::LivenessProbe {}).unwrap();
        assert_eq!(request, br#"{"t":"LivenessProbe"}"#);
        assert_eq!(
            serde_json::from_slice::<ServiceIpcRequest>(&request).unwrap(),
            ServiceIpcRequest::LivenessProbe {}
        );
        assert!(serde_json::from_slice::<ServiceIpcResponse>(&request).is_err());
        assert!(
            serde_json::from_slice::<ServiceIpcRequest>(
                br#"{"t":"LivenessProbe","c":null}"#
            )
            .is_err()
        );

        let response = serde_json::to_vec(&ServiceIpcResponse::Liveness {}).unwrap();
        assert_eq!(response, br#"{"t":"Liveness"}"#);
        assert_eq!(
            serde_json::from_slice::<ServiceIpcResponse>(&response).unwrap(),
            ServiceIpcResponse::Liveness {}
        );
        assert!(serde_json::from_slice::<ServiceIpcRequest>(&response).is_err());
        assert!(
            serde_json::from_slice::<ServiceIpcResponse>(br#"{"t":"Liveness","c":null}"#)
                .is_err()
        );

        #[cfg(target_os = "macos")]
        {
            let readiness_request =
                serde_json::to_vec(&ServiceIpcRequest::EnsurePasswordRightReady {}).unwrap();
            assert_eq!(
                readiness_request,
                br#"{"t":"EnsurePasswordRightReady"}"#
            );
            assert_eq!(
                serde_json::from_slice::<ServiceIpcRequest>(&readiness_request).unwrap(),
                ServiceIpcRequest::EnsurePasswordRightReady {}
            );
            assert!(
                serde_json::from_slice::<ServiceIpcResponse>(&readiness_request).is_err()
            );
            assert!(serde_json::from_slice::<ServiceIpcRequest>(
                br#"{"t":"EnsurePasswordRightReady","c":null}"#
            )
            .is_err());

            let readiness_response = serde_json::to_vec(
                &ServiceIpcResponse::PasswordRightReady { ready: true },
            )
            .unwrap();
            assert_eq!(
                readiness_response,
                br#"{"t":"PasswordRightReady","ready":true}"#
            );
            assert_eq!(
                serde_json::from_slice::<ServiceIpcResponse>(&readiness_response).unwrap(),
                ServiceIpcResponse::PasswordRightReady { ready: true }
            );
            assert!(
                serde_json::from_slice::<ServiceIpcRequest>(&readiness_response).is_err()
            );
            assert!(serde_json::from_slice::<ServiceIpcResponse>(
                br#"{"t":"PasswordRightReady","ready":true,"c":null}"#
            )
            .is_err());
        }

        #[cfg(target_os = "windows")]
        {
            let share_rdp_request =
                serde_json::to_vec(&ServiceIpcRequest::SetShareRdp { enabled: true }).unwrap();
            assert_eq!(
                share_rdp_request,
                br#"{"t":"SetShareRdp","enabled":true}"#
            );
            assert_eq!(
                serde_json::from_slice::<ServiceIpcRequest>(&share_rdp_request).unwrap(),
                ServiceIpcRequest::SetShareRdp { enabled: true }
            );
            assert!(
                serde_json::from_slice::<ServiceIpcResponse>(&share_rdp_request).is_err()
            );
            assert!(serde_json::from_slice::<ServiceIpcRequest>(
                br#"{"t":"SetShareRdp","enabled":true,"c":null}"#
            )
            .is_err());

            let share_rdp_response =
                serde_json::to_vec(&ServiceIpcResponse::ShareRdpSet { accepted: true }).unwrap();
            assert_eq!(
                share_rdp_response,
                br#"{"t":"ShareRdpSet","accepted":true}"#
            );
            assert_eq!(
                serde_json::from_slice::<ServiceIpcResponse>(&share_rdp_response).unwrap(),
                ServiceIpcResponse::ShareRdpSet { accepted: true }
            );
            assert!(
                serde_json::from_slice::<ServiceIpcRequest>(&share_rdp_response).is_err()
            );
            assert!(serde_json::from_slice::<ServiceIpcResponse>(
                br#"{"t":"ShareRdpSet","accepted":true,"c":null}"#
            )
            .is_err());
        }

        let cross_purpose = serde_json::to_vec(&Data::Close).unwrap();
        assert!(serde_json::from_slice::<ServiceIpcRequest>(&cross_purpose).is_err());
        assert!(serde_json::from_slice::<ServiceIpcResponse>(&cross_purpose).is_err());

        let retired_credential_request = br#"{"t":"PermanentPasswordSnapshot"}"#;
        assert!(
            serde_json::from_slice::<ServiceIpcRequest>(retired_credential_request).is_err()
        );
        assert!(
            serde_json::from_slice::<ServiceIpcResponse>(retired_credential_request).is_err()
        );
    }

    #[test]
    fn windows_service_sas_channel_uses_closed_directional_protocol() {
        let request = serde_json::to_vec(&WindowsServiceSasIpcRequest::Dispatch {}).unwrap();
        assert_eq!(request, br#"{"t":"Dispatch"}"#);
        assert_eq!(
            serde_json::from_slice::<WindowsServiceSasIpcRequest>(&request).unwrap(),
            WindowsServiceSasIpcRequest::Dispatch {}
        );
        assert!(serde_json::from_slice::<WindowsServiceSasIpcResponse>(&request).is_err());
        assert!(
            serde_json::from_slice::<WindowsServiceSasIpcRequest>(
                br#"{"t":"Dispatch","c":null}"#
            )
            .is_err()
        );

        let response =
            serde_json::to_vec(&WindowsServiceSasIpcResponse::DispatchAccepted { accepted: true })
                .unwrap();
        assert_eq!(response, br#"{"t":"DispatchAccepted","accepted":true}"#);
        assert_eq!(
            serde_json::from_slice::<WindowsServiceSasIpcResponse>(&response).unwrap(),
            WindowsServiceSasIpcResponse::DispatchAccepted { accepted: true }
        );
        assert!(serde_json::from_slice::<WindowsServiceSasIpcRequest>(&response).is_err());
        assert!(serde_json::from_slice::<WindowsServiceSasIpcResponse>(
            br#"{"t":"DispatchAccepted","accepted":true,"c":null}"#
        )
        .is_err());

        let cross_purpose = serde_json::to_vec(&Data::Close).unwrap();
        assert!(serde_json::from_slice::<WindowsServiceSasIpcRequest>(&cross_purpose).is_err());
        assert!(serde_json::from_slice::<WindowsServiceSasIpcResponse>(&cross_purpose).is_err());
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[tokio::test(flavor = "current_thread")]
    async fn whiteboard_channel_uses_closed_directional_bounded_protocols() {
        let owner_proof = WhiteboardOwnerHandshake::ServerProof {
            proof: "owner-proof".to_owned(),
        };
        let encoded_owner = serde_json::to_vec(&owner_proof).unwrap();
        assert_eq!(
            encoded_owner,
            br#"{"t":"ServerProof","proof":"owner-proof"}"#
        );
        assert_eq!(
            serde_json::from_slice::<WhiteboardOwnerHandshake>(&encoded_owner).unwrap(),
            owner_proof
        );
        assert!(
            serde_json::from_slice::<WhiteboardHelperHandshake>(&encoded_owner).is_err()
        );
        assert!(
            serde_json::from_slice::<WhiteboardOwnerHandshake>(
                br#"{"t":"ServerProof","proof":"owner-proof","extra":true}"#
            )
            .is_err()
        );

        let helper_challenge = WhiteboardHelperHandshake::ServerChallenge {
            challenge: "helper-challenge".to_owned(),
        };
        let encoded_helper = serde_json::to_vec(&helper_challenge).unwrap();
        assert_eq!(
            encoded_helper,
            br#"{"t":"ServerChallenge","challenge":"helper-challenge"}"#
        );
        assert_eq!(
            serde_json::from_slice::<WhiteboardHelperHandshake>(&encoded_helper).unwrap(),
            helper_challenge
        );
        assert!(
            serde_json::from_slice::<WhiteboardOwnerHandshake>(&encoded_helper).is_err()
        );

        let command = WhiteboardIpcCommand::Bind {
            conn_id: 7,
            token: "token".to_owned(),
        };
        let encoded_command = serde_json::to_vec(&command).unwrap();
        assert_eq!(
            encoded_command,
            br#"{"t":"Bind","conn_id":7,"token":"token"}"#
        );
        assert!(
            serde_json::from_slice::<WhiteboardOwnerHandshake>(&encoded_command).is_err()
        );
        assert!(
            serde_json::from_slice::<WhiteboardHelperHandshake>(&encoded_command).is_err()
        );
        assert!(
            serde_json::from_slice::<WhiteboardIpcCommand>(
                br#"{"t":"Bind","conn_id":7,"token":"token","extra":true}"#
            )
            .is_err()
        );
        let cross_purpose = serde_json::to_vec(&Data::Close).unwrap();
        assert!(
            serde_json::from_slice::<WhiteboardOwnerHandshake>(&cross_purpose).is_err()
        );
        assert!(
            serde_json::from_slice::<WhiteboardHelperHandshake>(&cross_purpose).is_err()
        );
        assert!(serde_json::from_slice::<WhiteboardIpcCommand>(&cross_purpose).is_err());

        let (owner_end, helper_end) = tokio::io::duplex(WHITEBOARD_IPC_MAX_FRAME_BYTES * 2);
        let mut owner = ConnectionTmpl::new_whiteboard(owner_end);
        let mut helper = ConnectionTmpl::new_whiteboard(helper_end);
        assert_eq!(
            owner.inner.codec().max_packet_length(),
            WHITEBOARD_IPC_MAX_FRAME_BYTES
        );
        helper
            .send_whiteboard_helper_handshake_timeout(
                &helper_challenge,
                WHITEBOARD_IPC_IO_TIMEOUT_MS,
            )
            .await
            .unwrap();
        assert_eq!(
            owner
                .next_whiteboard_helper_handshake_timeout(WHITEBOARD_IPC_IO_TIMEOUT_MS)
                .await
                .unwrap(),
            helper_challenge
        );
        owner
            .send_whiteboard_owner_handshake_timeout(
                &owner_proof,
                WHITEBOARD_IPC_IO_TIMEOUT_MS,
            )
            .await
            .unwrap();
        assert_eq!(
            helper
                .next_whiteboard_owner_handshake_timeout(WHITEBOARD_IPC_IO_TIMEOUT_MS)
                .await
                .unwrap(),
            owner_proof
        );
        owner
            .send_whiteboard_command_timeout(&command, WHITEBOARD_IPC_IO_TIMEOUT_MS)
            .await
            .unwrap();
        match helper
            .next_whiteboard_command_timeout(WHITEBOARD_IPC_IO_TIMEOUT_MS)
            .await
            .unwrap()
            .unwrap()
        {
            WhiteboardIpcCommand::Bind { conn_id, token } => {
                assert_eq!(conn_id, 7);
                assert_eq!(token, "token");
            }
            _ => panic!("unexpected whiteboard command"),
        }

        assert!(helper
            .next_whiteboard_command_timeout(1)
            .await
            .unwrap()
            .is_none());
        owner.send(&Data::Close).await.unwrap();
        assert!(
            helper
                .next_whiteboard_command_timeout(WHITEBOARD_IPC_IO_TIMEOUT_MS)
                .await
                .is_err()
        );

        let (oversize_end, _oversize_peer) =
            tokio::io::duplex(WHITEBOARD_IPC_MAX_FRAME_BYTES * 2);
        let mut oversize = ConnectionTmpl::new_whiteboard(oversize_end);
        let oversize_command = WhiteboardIpcCommand::Event {
            conn_id: 7,
            token: "token".to_owned(),
            event: crate::whiteboard::CustomEvent::Cursor(crate::whiteboard::Cursor {
                x: 0.0,
                y: 0.0,
                argb: 0,
                btns: 0,
                text: "x".repeat(WHITEBOARD_IPC_MAX_FRAME_BYTES),
            }),
        };
        assert!(
            oversize
                .send_whiteboard_command_timeout(
                    &oversize_command,
                    WHITEBOARD_IPC_IO_TIMEOUT_MS,
                )
                .await
                .is_err()
        );

        let (reset_end, reset_peer) = tokio::io::duplex(WHITEBOARD_IPC_MAX_FRAME_BYTES);
        let mut reset = ConnectionTmpl::new_whiteboard(reset_end);
        drop(reset_peer);
        assert!(
            reset
                .next_whiteboard_command_timeout(WHITEBOARD_IPC_IO_TIMEOUT_MS)
                .await
                .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn linux_pulse_audio_channel_uses_closed_bounded_protocol() {
        let request = LinuxPulseAudioIpcRequest::StartCapture {
            owner: LinuxProcessIdentity::for_test(7, 1_000, "42".to_owned()),
            token: "token".to_owned(),
            source: "monitor".to_owned(),
        };
        let encoded = serde_json::to_vec(&request).unwrap();
        assert_eq!(
            encoded,
            br#"{"t":"StartCapture","owner":{"pid":7,"uid":1000,"start_time":"42"},"token":"token","source":"monitor"}"#
        );
        assert_eq!(
            serde_json::from_slice::<LinuxPulseAudioIpcRequest>(&encoded).unwrap(),
            request
        );
        assert!(
            serde_json::from_slice::<LinuxPulseAudioIpcRequest>(
                br#"{"t":"StartCapture","owner":{"pid":7,"uid":1000,"start_time":"42"},"token":"token","source":"monitor","extra":true}"#
            )
            .is_err()
        );
        let cross_purpose = serde_json::to_vec(&Data::Close).unwrap();
        assert!(
            serde_json::from_slice::<LinuxPulseAudioIpcRequest>(&cross_purpose).is_err()
        );
        assert_eq!(
            PULSE_AUDIO_IPC_AUDIO_FRAME_BYTES,
            crate::audio_service::AUDIO_DATA_SIZE_U8
        );

        let (client_end, server_end) =
            tokio::io::duplex(PULSE_AUDIO_IPC_MAX_FRAME_BYTES * 2);
        let mut client = ConnectionTmpl::new_pulse_audio(client_end);
        let mut server = ConnectionTmpl::new_pulse_audio(server_end);
        assert_eq!(
            client.inner.codec().max_packet_length(),
            PULSE_AUDIO_IPC_MAX_FRAME_BYTES
        );
        client
            .send_pulse_audio_request_timeout(&request, PULSE_AUDIO_IPC_IO_TIMEOUT_MS)
            .await
            .unwrap();
        assert_eq!(
            server
                .next_pulse_audio_request_timeout(PULSE_AUDIO_IPC_IO_TIMEOUT_MS)
                .await
                .unwrap(),
            Some(request)
        );

        let audio = Bytes::from(vec![1; PULSE_AUDIO_IPC_AUDIO_FRAME_BYTES]);
        server
            .send_pulse_audio_frame_timeout(audio.clone(), PULSE_AUDIO_IPC_IO_TIMEOUT_MS)
            .await
            .unwrap();
        let received = client
            .next_pulse_audio_frame_timeout(PULSE_AUDIO_IPC_IO_TIMEOUT_MS)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.as_ref(), audio.as_ref());
        server
            .send_pulse_audio_frame_timeout(Bytes::new(), PULSE_AUDIO_IPC_IO_TIMEOUT_MS)
            .await
            .unwrap();
        assert!(
            client
                .next_pulse_audio_frame_timeout(PULSE_AUDIO_IPC_IO_TIMEOUT_MS)
                .await
                .unwrap()
                .unwrap()
                .is_empty()
        );
        assert!(
            server
                .send_pulse_audio_frame_timeout(
                    Bytes::from(vec![1; PULSE_AUDIO_IPC_AUDIO_FRAME_BYTES - 1]),
                    PULSE_AUDIO_IPC_IO_TIMEOUT_MS,
                )
                .await
                .is_err()
        );
        assert!(
            server
                .send_pulse_audio_frame_timeout(
                    Bytes::from(vec![1; PULSE_AUDIO_IPC_MAX_FRAME_BYTES + 1]),
                    PULSE_AUDIO_IPC_IO_TIMEOUT_MS,
                )
                .await
                .is_err()
        );

        let (bad_sender_end, bad_receiver_end) =
            tokio::io::duplex(PULSE_AUDIO_IPC_MAX_FRAME_BYTES);
        let mut bad_sender = ConnectionTmpl::new(bad_sender_end);
        let mut bad_receiver = ConnectionTmpl::new_pulse_audio(bad_receiver_end);
        bad_sender
            .send_raw(Bytes::from(vec![
                1;
                PULSE_AUDIO_IPC_AUDIO_FRAME_BYTES - 1
            ]))
            .await
            .unwrap();
        assert!(
            bad_receiver
                .next_pulse_audio_frame_timeout(PULSE_AUDIO_IPC_IO_TIMEOUT_MS)
                .await
                .is_err()
        );

        let (idle_end, idle_peer) = tokio::io::duplex(PULSE_AUDIO_IPC_MAX_FRAME_BYTES);
        let mut idle = ConnectionTmpl::new_pulse_audio(idle_end);
        assert_eq!(
            idle.next_pulse_audio_frame_timeout(1).await.unwrap(),
            None
        );
        drop(idle_peer);
        assert!(
            idle.next_pulse_audio_frame_timeout(PULSE_AUDIO_IPC_IO_TIMEOUT_MS)
                .await
                .is_err()
        );
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn privileged_and_main_connections_use_bounded_frame_codecs() {
        let (service_end, _peer_end) = tokio::io::duplex(SERVICE_IPC_MAX_FRAME_BYTES * 2);
        let service = ConnectionTmpl::new_protected_service(service_end);
        assert_eq!(
            service.inner.codec().max_packet_length(),
            SERVICE_IPC_MAX_FRAME_BYTES
        );

        let (main_end, _peer_end) = tokio::io::duplex(MAIN_IPC_MAX_FRAME_BYTES * 2);
        let main = ConnectionTmpl::new_main(main_end);
        assert_eq!(
            main.inner.codec().max_packet_length(),
            MAIN_IPC_MAX_FRAME_BYTES
        );

        let (generic_end, _peer_end) = tokio::io::duplex(SERVICE_IPC_MAX_FRAME_BYTES * 2);
        let generic = ConnectionTmpl::new(generic_end);
        assert_eq!(generic.inner.codec().max_packet_length(), usize::MAX);
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn main_status_options_are_explicitly_allowlisted_and_bounded() {
        use hbb_common::config::keys;

        let options = MainStatusOptions::from_map(HashMap::from([
            (keys::OPTION_ENABLE_KEYBOARD.to_owned(), "Y".to_owned()),
            ("audio-input".to_owned(), "default".to_owned()),
        ]))
        .unwrap()
        .into_map()
        .unwrap();
        assert_eq!(options.get(keys::OPTION_ENABLE_KEYBOARD).unwrap(), "Y");
        assert_eq!(options.get("audio-input").unwrap(), "default");

        assert!(MainStatusOptions::from_map(HashMap::from([(
            keys::OPTION_KEY.to_owned(),
            "secret".to_owned(),
        )]))
        .is_err());
        assert!(MainStatusOptions::from_map(HashMap::from([(
            keys::OPTION_PROXY_PASSWORD.to_owned(),
            "secret".to_owned(),
        )]))
        .is_err());
        assert!(MainStatusOptions::from_map(HashMap::from([(
            keys::OPTION_API_SERVER.to_owned(),
            "retired".to_owned(),
        )]))
        .is_err());
        assert!(MainStatusOptions::from_map(HashMap::from([(
            "future-credential".to_owned(),
            "secret".to_owned(),
        )]))
        .is_err());
        assert!(MainStatusOptions::from_map(HashMap::from([(
            keys::OPTION_ENABLE_KEYBOARD.to_owned(),
            "x".repeat(MAIN_IPC_MAX_OPTION_VALUE_BYTES + 1),
        )]))
        .is_err());
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn main_status_options_reject_duplicate_typed_keys() {
        let options = MainStatusOptions(vec![
            MainStatusOption {
                key: MainStatusOptionKey::EnableKeyboard,
                value: "Y".to_owned(),
            },
            MainStatusOption {
                key: MainStatusOptionKey::EnableKeyboard,
                value: "N".to_owned(),
            },
        ]);
        assert!(options.into_map().is_err());
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn main_option_mutation_is_single_key_and_receiver_effective() {
        let request = MainIpcRequest::SetOption(
            MainStatusOption::from_pair("audio-input", "microphone".to_owned()).unwrap(),
        );
        let request_json = serde_json::to_string(&request).unwrap();
        assert_eq!(
            request_json,
            r#"{"t":"SetOption","c":{"key":"AudioInput","value":"microphone"}}"#
        );

        let response = MainIpcResponse::OptionSet {
            result: IpcMutationResult::Applied,
            effective: Some(
                MainStatusOption::from_pair("audio-input", "receiver-device".to_owned()).unwrap(),
            ),
        };
        let response_json = serde_json::to_string(&response).unwrap();
        let response: MainIpcResponse = serde_json::from_str(&response_json).unwrap();
        match response {
            MainIpcResponse::OptionSet {
                result: IpcMutationResult::Applied,
                effective: Some(effective),
            } => {
                let (key, value) = effective.into_pair().unwrap();
                assert_eq!(key, MainStatusOptionKey::AudioInput);
                assert_eq!(value, "receiver-device");
            }
            _ => panic!("unexpected option mutation response"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn outbound_frames_are_rejected_before_exceeding_the_active_codec_limit() {
        let (json_end, _peer_end) = tokio::io::duplex(64);
        let mut json = ConnectionTmpl::new_with_max_packet_length(json_end, 16);
        assert!(json.send_json(&"x".repeat(32)).await.is_err());

        let (raw_end, _peer_end) = tokio::io::duplex(64);
        let mut raw = ConnectionTmpl::new_with_max_packet_length(raw_end, 16);
        assert!(raw.send_raw(Bytes::from(vec![0; 17])).await.is_err());
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn password_mutation_ledger_is_idempotent_value_bound_and_shutdown_aware() {
        let coordinator = PasswordMutationCoordinator::new();
        let operation_id = hbb_common::uuid::Uuid::new_v4().to_string();
        let kind = PasswordMutationKind::UserOwned;

        let first = coordinator.prepare(&operation_id, kind, "first");
        assert_eq!(first.status, PasswordMutationStatus::Prepared);
        assert!(first.owns_preparation);
        let retry = coordinator.prepare(&operation_id, kind, "first");
        assert_eq!(retry.status, PasswordMutationStatus::Prepared);
        assert!(!retry.owns_preparation);
        let mismatch = coordinator.prepare(&operation_id, kind, "second");
        assert_eq!(
            mismatch.status,
            PasswordMutationStatus::Complete(IpcMutationResult::Rejected)
        );
        assert!(!mismatch.owns_preparation);
        let kind_mismatch =
            coordinator.prepare(&operation_id, PasswordMutationKind::ServiceOwned, "first");
        assert_eq!(
            kind_mismatch.status,
            PasswordMutationStatus::Complete(IpcMutationResult::Rejected)
        );
        assert!(coordinator.acknowledge(&operation_id, kind, "first"));
        assert_eq!(
            coordinator.status(&operation_id, kind),
            PasswordMutationStatus::Pending
        );
        coordinator.complete(&operation_id, kind, IpcMutationResult::Applied);
        coordinator.begin_shutdown();
        assert_eq!(
            coordinator.status(&operation_id, kind),
            PasswordMutationStatus::Complete(IpcMutationResult::Applied)
        );
        let after_shutdown =
            coordinator.prepare(&hbb_common::uuid::Uuid::new_v4().to_string(), kind, "new");
        assert_eq!(after_shutdown.status, PasswordMutationStatus::ShuttingDown);
        assert!(!after_shutdown.owns_preparation);
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn password_mutation_replay_secrets_are_keyed_and_erased_on_clear() {
        let coordinator = PasswordMutationCoordinator::new();
        let operation_id = hbb_common::uuid::Uuid::new_v4().to_string();
        let kind = PasswordMutationKind::UserOwned;
        assert!(
            coordinator
                .prepare(&operation_id, kind, "secret")
                .owns_preparation
        );
        assert!(coordinator.acknowledge(&operation_id, kind, "secret"));
        coordinator.complete(&operation_id, kind, IpcMutationResult::Applied);

        {
            let ledger = coordinator.ledger.lock().unwrap();
            let entry = ledger.entries.get(&operation_id).unwrap();
            let raw = hbb_common::sodiumoxide::crypto::hash::sha256::hash(b"secret");
            assert_ne!(entry.fingerprint.0.as_ref(), raw.0.as_slice());
            assert!(ledger.fingerprint_key.0.iter().any(|byte| *byte != 0));
        }

        coordinator.begin_shutdown();
        coordinator.clear_after_transactions_drain();
        let ledger = coordinator.ledger.lock().unwrap();
        assert!(ledger.entries.is_empty());
        assert!(ledger.fingerprint_key.0.iter().all(|byte| *byte == 0));
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn unattended_password_length_is_rejected_before_transport() {
        let maximum = SensitivePassword::new("x".repeat(UNATTENDED_PASSWORD_MAX_BYTES));
        assert!(validate_unattended_password_value(&maximum).is_ok());
        let oversized = SensitivePassword::new("x".repeat(UNATTENDED_PASSWORD_MAX_BYTES + 1));
        assert!(validate_unattended_password_value(&oversized).is_err());
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn password_mutation_prepared_is_irrevocable_and_retry_cannot_release_owner() {
        let coordinator = PasswordMutationCoordinator::new();
        let operation_id = hbb_common::uuid::Uuid::new_v4().to_string();
        let kind = PasswordMutationKind::UserOwned;

        let owner = coordinator.prepare(&operation_id, kind, "value");
        assert_eq!(owner.status, PasswordMutationStatus::Prepared);
        assert!(owner.owns_preparation);

        let retry = coordinator.prepare(&operation_id, kind, "value");
        assert_eq!(retry.status, PasswordMutationStatus::Prepared);
        assert!(!retry.owns_preparation);
        assert!(coordinator.acknowledge(&operation_id, kind, "value"));
        coordinator.complete(&operation_id, kind, IpcMutationResult::Applied);

        assert_eq!(
            coordinator.status(&operation_id, kind),
            PasswordMutationStatus::Complete(IpcMutationResult::Applied)
        );
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn password_mutation_admission_failure_is_terminal() {
        let coordinator = PasswordMutationCoordinator::new();
        let operation_id = hbb_common::uuid::Uuid::new_v4().to_string();
        let kind = PasswordMutationKind::ServiceOwned;

        let owner = coordinator.prepare(&operation_id, kind, "value");
        assert!(owner.owns_preparation);
        assert!(coordinator.fail_admitted(&operation_id, kind, "value"));
        assert_eq!(
            coordinator.status(&operation_id, kind),
            PasswordMutationStatus::Complete(IpcMutationResult::InternalFailure)
        );
        assert!(!coordinator.fail_admitted(&operation_id, kind, "value"));
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn password_mutation_capacity_never_evicts_live_operations() {
        let coordinator = PasswordMutationCoordinator::new();
        for index in 0..PASSWORD_MUTATION_RESULT_BUDGET {
            let operation_id = hbb_common::uuid::Uuid::from_u128(index as u128 + 1).to_string();
            let preparation =
                coordinator.prepare(&operation_id, PasswordMutationKind::UserOwned, "value");
            assert!(preparation.owns_preparation);
        }
        let overflow = coordinator.prepare(
            &hbb_common::uuid::Uuid::from_u128(10_000).to_string(),
            PasswordMutationKind::UserOwned,
            "value",
        );
        assert_eq!(
            overflow.status,
            PasswordMutationStatus::Complete(IpcMutationResult::Rejected)
        );
        assert!(!overflow.owns_preparation);
        assert_eq!(
            coordinator
                .ledger
                .lock()
                .unwrap()
                .entries
                .values()
                .filter(|entry| entry.state == PasswordMutationState::Prepared)
                .count(),
            PASSWORD_MUTATION_RESULT_BUDGET
        );
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn password_mutation_completed_results_are_value_bound_until_bounded_eviction() {
        let coordinator = PasswordMutationCoordinator::new();
        let first_id = hbb_common::uuid::Uuid::from_u128(1).to_string();
        let last_id =
            hbb_common::uuid::Uuid::from_u128(PASSWORD_MUTATION_RESULT_BUDGET as u128).to_string();
        for index in 0..PASSWORD_MUTATION_RESULT_BUDGET {
            let operation_id = hbb_common::uuid::Uuid::from_u128(index as u128 + 1).to_string();
            assert!(
                coordinator
                    .prepare(&operation_id, PasswordMutationKind::UserOwned, "value")
                    .owns_preparation
            );
            assert!(coordinator.acknowledge(
                &operation_id,
                PasswordMutationKind::UserOwned,
                "value"
            ));
            coordinator.complete(
                &operation_id,
                PasswordMutationKind::UserOwned,
                IpcMutationResult::Applied,
            );
            if index == 0 {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        assert_eq!(
            coordinator.status(&first_id, PasswordMutationKind::UserOwned),
            PasswordMutationStatus::Complete(IpcMutationResult::Applied)
        );
        let changed_value = coordinator.prepare(
            &first_id,
            PasswordMutationKind::UserOwned,
            "different-value",
        );
        assert_eq!(
            changed_value.status,
            PasswordMutationStatus::Complete(IpcMutationResult::Rejected)
        );
        assert!(!changed_value.owns_preparation);
        let replacement_id = hbb_common::uuid::Uuid::from_u128(10_000).to_string();
        let replacement =
            coordinator.prepare(&replacement_id, PasswordMutationKind::UserOwned, "value");
        assert_eq!(replacement.status, PasswordMutationStatus::Prepared);
        assert!(replacement.owns_preparation);
        assert_eq!(
            coordinator.status(&first_id, PasswordMutationKind::UserOwned),
            PasswordMutationStatus::Unknown
        );
        assert_eq!(
            coordinator.status(&last_id, PasswordMutationKind::UserOwned),
            PasswordMutationStatus::Complete(IpcMutationResult::Applied)
        );
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn password_mutation_completion_owner_prevents_orphaned_pending_state() {
        let coordinator = Arc::new(PasswordMutationCoordinator::new());
        let operation_id = hbb_common::uuid::Uuid::new_v4().to_string();
        let kind = PasswordMutationKind::ServiceOwned;
        assert!(
            coordinator
                .prepare(&operation_id, kind, "value")
                .owns_preparation
        );
        assert!(coordinator.acknowledge(&operation_id, kind, "value"));
        drop(PasswordMutationCompletion {
            coordinator: Arc::clone(&coordinator),
            operation_id: operation_id.clone(),
            kind,
            result: IpcMutationResult::InternalFailure,
        });
        assert_eq!(
            coordinator.status(&operation_id, kind),
            PasswordMutationStatus::Complete(IpcMutationResult::InternalFailure)
        );
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[tokio::test(flavor = "current_thread")]
    async fn password_mutation_shutdown_drain_waits_for_terminal_result() {
        let coordinator = Arc::new(PasswordMutationCoordinator::new());
        let operation_id = hbb_common::uuid::Uuid::new_v4().to_string();
        let kind = PasswordMutationKind::ServiceOwned;
        assert!(
            coordinator
                .prepare(&operation_id, kind, "value")
                .owns_preparation
        );
        assert!(coordinator.acknowledge(&operation_id, kind, "value"));
        coordinator.begin_shutdown();

        let drain_coordinator = Arc::clone(&coordinator);
        let drain = tokio::spawn(async move { drain_coordinator.drain().await });
        tokio::task::yield_now().await;
        assert!(!drain.is_finished());

        coordinator.complete(&operation_id, kind, IpcMutationResult::Applied);
        drain.await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn linux_admitted_replay_after_lost_response_does_not_repeat_denied_polkit() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let coordinator = LinuxPasswordAdmissionCoordinator::new();
        let operation_id = hbb_common::uuid::Uuid::new_v4().to_string();
        let caller = LinuxPasswordCaller {
            pid: 100,
            uid: 1000,
            start_time: "10".to_owned(),
        };
        let authorization_calls = AtomicUsize::new(0);
        let first = execute_linux_service_owned_password_operation(
            &coordinator,
            &operation_id,
            "new-password",
            &caller,
            || {
                authorization_calls.fetch_add(1, Ordering::Relaxed);
                async { true }
            },
            || async { Ok(IpcMutationResult::Applied) },
        )
        .await
        .unwrap();
        assert_eq!(first, IpcMutationResult::Applied);

        // Model loss of the outer result: replay the exact request. This closure models a fresh
        // polkit denial and must never run because the operation is already admitted/complete.
        let replay = execute_linux_service_owned_password_operation(
            &coordinator,
            &operation_id,
            "new-password",
            &caller,
            || {
                authorization_calls.fetch_add(1, Ordering::Relaxed);
                async { false }
            },
            || async { Ok(IpcMutationResult::InternalFailure) },
        )
        .await
        .unwrap();
        assert_eq!(replay, IpcMutationResult::Applied);
        assert_eq!(authorization_calls.load(Ordering::Relaxed), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_password_admission_denials_do_not_consume_replay_capacity() {
        let coordinator = LinuxPasswordAdmissionCoordinator::new();
        let caller = LinuxPasswordCaller {
            pid: 100,
            uid: 1000,
            start_time: "10".to_owned(),
        };
        for index in 0..=PASSWORD_MUTATION_RESULT_BUDGET {
            let operation_id = hbb_common::uuid::Uuid::from_u128(index as u128 + 1).to_string();
            assert_eq!(
                coordinator.begin(
                    &operation_id,
                    PasswordMutationKind::ServiceOwned,
                    "secret",
                    &caller,
                ),
                LinuxPasswordAdmissionDecision::Authorize
            );
            assert!(coordinator.finish_authorization(&operation_id, &caller, false));
        }
        assert!(coordinator.ledger.lock().unwrap().entries.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_password_admission_evicts_only_completed_replay_entries() {
        let coordinator = LinuxPasswordAdmissionCoordinator::new();
        let caller = LinuxPasswordCaller {
            pid: 100,
            uid: 1000,
            start_time: "10".to_owned(),
        };
        let first_id = hbb_common::uuid::Uuid::from_u128(1).to_string();
        for index in 0..PASSWORD_MUTATION_RESULT_BUDGET {
            let operation_id = hbb_common::uuid::Uuid::from_u128(index as u128 + 1).to_string();
            assert_eq!(
                coordinator.begin(
                    &operation_id,
                    PasswordMutationKind::ServiceOwned,
                    "secret",
                    &caller,
                ),
                LinuxPasswordAdmissionDecision::Authorize
            );
            assert!(coordinator.finish_authorization(&operation_id, &caller, true));
            assert!(coordinator.complete(&operation_id, &caller, IpcMutationResult::Applied));
            if index == 0 {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }

        let replacement_id = hbb_common::uuid::Uuid::from_u128(10_000).to_string();
        assert_eq!(
            coordinator.begin(
                &replacement_id,
                PasswordMutationKind::ServiceOwned,
                "secret",
                &caller,
            ),
            LinuxPasswordAdmissionDecision::Authorize
        );
        assert!(!coordinator
            .ledger
            .lock()
            .unwrap()
            .entries
            .contains_key(&first_id));

        let live = LinuxPasswordAdmissionCoordinator::new();
        for index in 0..PASSWORD_MUTATION_RESULT_BUDGET {
            let operation_id = hbb_common::uuid::Uuid::from_u128(index as u128 + 1).to_string();
            assert_eq!(
                live.begin(
                    &operation_id,
                    PasswordMutationKind::ServiceOwned,
                    "secret",
                    &caller,
                ),
                LinuxPasswordAdmissionDecision::Authorize
            );
        }
        assert_eq!(
            live.begin(
                &hbb_common::uuid::Uuid::from_u128(10_000).to_string(),
                PasswordMutationKind::ServiceOwned,
                "secret",
                &caller,
            ),
            LinuxPasswordAdmissionDecision::Rejected
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_password_commit_has_one_owner_and_one_recovery_claimant() {
        let coordinator = LinuxPasswordAdmissionCoordinator::new();
        let operation_id = hbb_common::uuid::Uuid::new_v4().to_string();
        let caller = LinuxPasswordCaller {
            pid: 100,
            uid: 1000,
            start_time: "10".to_owned(),
        };
        assert_eq!(
            coordinator.begin(
                &operation_id,
                PasswordMutationKind::ServiceOwned,
                "secret",
                &caller,
            ),
            LinuxPasswordAdmissionDecision::Authorize
        );
        assert!(coordinator.finish_authorization(&operation_id, &caller, true));
        assert_eq!(
            coordinator.begin(
                &operation_id,
                PasswordMutationKind::ServiceOwned,
                "secret",
                &caller,
            ),
            LinuxPasswordAdmissionDecision::Wait
        );
        assert!(coordinator.release_failed_commit(&operation_id, &caller));
        assert_eq!(
            coordinator.begin(
                &operation_id,
                PasswordMutationKind::ServiceOwned,
                "secret",
                &caller,
            ),
            LinuxPasswordAdmissionDecision::Recover
        );
        assert_eq!(
            coordinator.begin(
                &operation_id,
                PasswordMutationKind::ServiceOwned,
                "secret",
                &caller,
            ),
            LinuxPasswordAdmissionDecision::Wait
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn linux_admitted_unresolved_replay_recovers_when_polkit_is_unavailable() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let coordinator = LinuxPasswordAdmissionCoordinator::new();
        let operation_id = hbb_common::uuid::Uuid::new_v4().to_string();
        let caller = LinuxPasswordCaller {
            pid: 101,
            uid: 1000,
            start_time: "11".to_owned(),
        };
        let authorization_calls = AtomicUsize::new(0);
        let first = execute_linux_service_owned_password_operation(
            &coordinator,
            &operation_id,
            "new-password",
            &caller,
            || {
                authorization_calls.fetch_add(1, Ordering::Relaxed);
                async { true }
            },
            || async { Err(hbb_common::anyhow::anyhow!("lost child response")) },
        )
        .await;
        assert!(first.is_err());

        let replay = execute_linux_service_owned_password_operation(
            &coordinator,
            &operation_id,
            "new-password",
            &caller,
            || {
                authorization_calls.fetch_add(1, Ordering::Relaxed);
                async { false }
            },
            || async { Ok(IpcMutationResult::Applied) },
        )
        .await
        .unwrap();
        assert_eq!(replay, IpcMutationResult::Applied);
        assert_eq!(authorization_calls.load(Ordering::Relaxed), 1);

        let mismatched_caller = LinuxPasswordCaller {
            pid: 102,
            ..caller.clone()
        };
        assert_eq!(
            coordinator.begin(
                &operation_id,
                PasswordMutationKind::ServiceOwned,
                "new-password",
                &mismatched_caller,
            ),
            LinuxPasswordAdmissionDecision::Rejected
        );
        assert_eq!(
            coordinator.begin(
                &operation_id,
                PasswordMutationKind::ServiceOwned,
                "different-password",
                &caller,
            ),
            LinuxPasswordAdmissionDecision::Rejected
        );
    }

    #[test]
    fn cm_connection_codec_switches_between_aggregate_and_block_limits() {
        assert!(CM_FILE_BLOCK_MAX_FRAME_BYTES < CM_IPC_MAX_FRAME_BYTES);
        let (cm_end, _peer_end) = tokio::io::duplex(CM_FILE_BLOCK_MAX_FRAME_BYTES * 2);
        let mut cm = ConnectionTmpl::new(cm_end);

        cm.set_max_packet_length(CM_IPC_MAX_FRAME_BYTES);
        assert_eq!(cm.inner.codec().max_packet_length(), CM_IPC_MAX_FRAME_BYTES);
        cm.set_max_packet_length(CM_FILE_BLOCK_MAX_FRAME_BYTES);
        assert_eq!(
            cm.inner.codec().max_packet_length(),
            CM_FILE_BLOCK_MAX_FRAME_BYTES
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn service_owned_password_value_limit_is_common() {
        assert!(service_owned_password_value_is_valid(
            "test",
            &"a".repeat(UNATTENDED_PASSWORD_MAX_BYTES)
        ));
        assert!(!service_owned_password_value_is_valid(
            "test",
            &"a".repeat(UNATTENDED_PASSWORD_MAX_BYTES + 1)
        ));
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[test]
    fn r_s11e95_cm_endpoint_proof_is_launch_token_and_role_bound() {
        let challenge = crate::encode64([7u8; 32]);
        let other_challenge = crate::encode64([8u8; 32]);
        let launch_token = crate::encode64([9u8; 32]);
        let other_launch_token = crate::encode64([10u8; 32]);
        let role = "--cm";
        let proof = cm_endpoint_proof_for_challenge(&challenge, &launch_token, role).unwrap();
        let server_proof = cm_server_proof_for_challenge(&challenge, &launch_token, role).unwrap();

        assert!(verify_cm_endpoint_proof(&challenge, &proof, &launch_token, role).is_ok());
        assert!(verify_cm_endpoint_proof(&other_challenge, &proof, &launch_token, role).is_err());
        assert!(verify_cm_endpoint_proof(&challenge, &proof, &other_launch_token, role).is_err());
        assert!(verify_cm_endpoint_proof(&challenge, &proof, &launch_token, "--cm-no-ui").is_err());
        assert!(verify_cm_server_proof(&challenge, &server_proof, &launch_token, role).is_ok());
        assert!(
            verify_cm_server_proof(&other_challenge, &server_proof, &launch_token, role).is_err()
        );
        assert!(verify_cm_server_proof(&challenge, &proof, &launch_token, role).is_err());
        assert!(verify_cm_endpoint_proof(&challenge, &server_proof, &launch_token, role).is_err());
        assert!(cm_endpoint_proof_for_challenge("", &launch_token, role).is_err());
        assert!(cm_endpoint_proof_for_challenge(&challenge, "", role).is_err());
        assert!(cm_endpoint_proof_for_challenge(&challenge, &launch_token, "--server").is_err());
        assert!(cm_server_proof_for_challenge("", &launch_token, role).is_err());
        assert!(cm_server_proof_for_challenge(&challenge, "", role).is_err());
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn r_s11e96_whiteboard_endpoint_proof_is_launch_token_and_role_bound() {
        let challenge = crate::encode64([11u8; 32]);
        let other_challenge = crate::encode64([12u8; 32]);
        let launch_token = crate::encode64([13u8; 32]);
        let other_launch_token = crate::encode64([14u8; 32]);
        let role = WHITEBOARD_PROCESS_ROLE;
        let endpoint_proof =
            whiteboard_endpoint_proof_for_challenge(&challenge, &launch_token, role).unwrap();
        let server_proof =
            whiteboard_server_proof_for_challenge(&challenge, &launch_token, role).unwrap();
        let endpoint = whiteboard_endpoint_postfix(&launch_token).unwrap();
        let other_endpoint = whiteboard_endpoint_postfix(&other_launch_token).unwrap();

        assert!(endpoint.starts_with("_whiteboard_"));
        assert_ne!(endpoint, other_endpoint);
        assert!(
            verify_whiteboard_endpoint_proof(&challenge, &endpoint_proof, &launch_token, role)
                .is_ok()
        );
        assert!(verify_whiteboard_endpoint_proof(
            &other_challenge,
            &endpoint_proof,
            &launch_token,
            role,
        )
        .is_err());
        assert!(verify_whiteboard_endpoint_proof(
            &challenge,
            &endpoint_proof,
            &other_launch_token,
            role,
        )
        .is_err());
        assert!(verify_whiteboard_endpoint_proof(
            &challenge,
            &endpoint_proof,
            &launch_token,
            "--server",
        )
        .is_err());
        assert!(
            verify_whiteboard_server_proof(&challenge, &server_proof, &launch_token, role).is_ok()
        );
        assert!(verify_whiteboard_server_proof(
            &other_challenge,
            &server_proof,
            &launch_token,
            role,
        )
        .is_err());
        assert!(
            verify_whiteboard_server_proof(&challenge, &endpoint_proof, &launch_token, role,)
                .is_err()
        );
        assert!(
            verify_whiteboard_endpoint_proof(&challenge, &server_proof, &launch_token, role,)
                .is_err()
        );
        assert!(whiteboard_endpoint_proof_for_challenge("", &launch_token, role).is_err());
        assert!(whiteboard_endpoint_proof_for_challenge(&challenge, "", role).is_err());
        assert!(
            whiteboard_endpoint_proof_for_challenge(&challenge, &launch_token, "--server",)
                .is_err()
        );
        assert!(whiteboard_server_proof_for_challenge("", &launch_token, role).is_err());
        assert!(whiteboard_server_proof_for_challenge(&challenge, "", role).is_err());
        assert!(whiteboard_endpoint_postfix("").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_proc_stat_start_time_parses_comm_with_spaces() {
        let stat =
            "123 (name with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 20 21";
        assert_eq!(
            linux_proc_stat_start_time(123, stat).unwrap(),
            "424242".to_owned()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_proc_stat_start_time_rejects_missing_start_time() {
        let stat = "123 (rustdesk) S 1 2 3";
        assert!(linux_proc_stat_start_time(123, stat).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_pkcheck_path_is_clean_absolute() {
        assert!(linux_path_is_clean_absolute(Path::new(PKCHECK_PATH)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_pkcheck_child_excludes_inherited_environment() {
        const ROLE: &str = "RUSTDESK_TEST_PKCHECK_ENVIRONMENT_ROLE";
        const HOSTILE_BUS: &str = "unix:path=/tmp/rustdesk-hostile-system-bus";
        const TEST_FILTER: &str = "linux_pkcheck_child_excludes_inherited_environment";

        match std::env::var(ROLE).as_deref() {
            Ok("launcher") => {
                assert_eq!(
                    std::env::var("DBUS_SYSTEM_BUS_ADDRESS").as_deref(),
                    Ok(HOSTILE_BUS)
                );
                let mut worker = std::process::Command::new(std::env::current_exe().unwrap());
                configure_linux_pkcheck_environment(&mut worker);
                let status = worker
                    .env(ROLE, "worker")
                    .arg(TEST_FILTER)
                    .arg("--nocapture")
                    .status()
                    .unwrap();
                assert!(status.success());
            }
            Ok("worker") => {
                assert!(std::env::var_os("DBUS_SYSTEM_BUS_ADDRESS").is_none());
                let unexpected: Vec<_> = std::env::vars_os()
                    .filter(|(key, _)| key != std::ffi::OsStr::new(ROLE))
                    .collect();
                assert!(
                    unexpected.is_empty(),
                    "unexpected environment: {unexpected:?}"
                );
            }
            _ => {
                let status = std::process::Command::new(std::env::current_exe().unwrap())
                    .env(ROLE, "launcher")
                    .env("DBUS_SYSTEM_BUS_ADDRESS", HOSTILE_BUS)
                    .arg(TEST_FILTER)
                    .arg("--nocapture")
                    .status()
                    .unwrap();
                assert!(status.success());
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_password_authorization_is_bounded_reaped_and_capacity_isolated() {
        let source = include_str!("ipc.rs");
        let start = source.find("fn terminate_and_reap_linux_pkcheck").unwrap();
        let end = source[start..]
            .find("async fn execute_linux_service_owned_password_operation")
            .map(|offset| start + offset)
            .unwrap();
        let authorization = &source[start..end];
        for required in [
            "PKCHECK_AUTHORIZATION_TIMEOUT",
            "let mut command = std::process::Command::new(pkcheck);",
            "configure_linux_pkcheck_environment(&mut command)",
            "configure_command_close_nonstdio_on_exec(&mut command)",
            "let child = command.spawn();",
            "child.try_wait()",
            "shutdown.is_cancelled()",
            "child.kill()",
            "child.wait()",
        ] {
            assert!(authorization.contains(required), "missing {required}");
        }
        assert!(source.contains("SERVICE_PASSWORD_IPC_TRANSACTION_SLOTS"));
        assert!(source.contains("try_acquire_service_password_ipc_transaction_slot"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_authority_command_path_rejects_relative_and_parent_paths() {
        assert!(linux_trusted_authority_command_path(Path::new("pkcheck")).is_none());
        assert!(
            linux_trusted_authority_command_path(Path::new("/usr/bin/../bin/pkcheck")).is_none()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_trusted_command_metadata_requires_root_unwritable_executable_file() {
        assert!(linux_trusted_command_file_metadata(true, 0, 0o755));
        assert!(!linux_trusted_command_file_metadata(false, 0, 0o755));
        assert!(!linux_trusted_command_file_metadata(true, 1000, 0o755));
        assert!(!linux_trusted_command_file_metadata(true, 0, 0o775));
        assert!(!linux_trusted_command_file_metadata(true, 0, 0o777));
        assert!(!linux_trusted_command_file_metadata(true, 0, 0o644));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_trusted_command_parent_requires_root_unwritable_directory() {
        assert!(linux_trusted_command_parent_metadata(true, 0, 0o755));
        assert!(!linux_trusted_command_parent_metadata(false, 0, 0o755));
        assert!(!linux_trusted_command_parent_metadata(true, 1000, 0o755));
        assert!(!linux_trusted_command_parent_metadata(true, 0, 0o775));
        assert!(!linux_trusted_command_parent_metadata(true, 0, 0o777));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_service_ipc_path_is_shared_across_uids() {
        assert_eq!(
            Config::ipc_path_for_uid(0, crate::POSTFIX_SERVICE),
            Config::ipc_path_for_uid(501, crate::POSTFIX_SERVICE)
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_ipc_path_differs_by_uid_for_cm() {
        let effective_uid = unsafe { hbb_common::libc::geteuid() as u32 };
        let other_uid = effective_uid.saturating_add(1);
        let postfix = "_cm";

        // Default connect path targets the current effective uid.
        assert_eq!(
            Config::ipc_path(postfix),
            Config::ipc_path_for_uid(effective_uid, postfix)
        );
        // A different uid yields a different socket path - this is the root cause of the
        // cross-user regression when root spawns a user process but still connects as uid 0.
        assert_ne!(
            Config::ipc_path(postfix),
            Config::ipc_path_for_uid(other_uid, postfix)
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_select_server_uid_uses_active_uid_when_no_server_found() {
        assert_eq!(
            select_server_uid_for_user_main_ipc(&[], Some(501), false).unwrap(),
            501
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_select_server_uid_uses_single_server_uid() {
        assert_eq!(
            select_server_uid_for_user_main_ipc(&[501], None, false).unwrap(),
            501
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_select_server_uid_prefers_active_uid_with_multiple_servers() {
        assert_eq!(
            select_server_uid_for_user_main_ipc(&[0, 501], Some(501), false).unwrap(),
            501
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_select_server_uid_prefers_root_on_wayland_login_screen() {
        assert_eq!(
            select_server_uid_for_user_main_ipc(&[0, 501], Some(501), true).unwrap(),
            0
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_select_server_uid_fails_when_multiple_servers_are_ambiguous() {
        assert!(select_server_uid_for_user_main_ipc(&[501, 502], None, false).is_err());
    }
}
