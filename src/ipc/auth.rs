use crate::ipc::{Connection, ConnectionTmpl};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use hbb_common::{anyhow, bail, log, ResultType};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use hbb_common::{
    libc,
    tokio::io::{AsyncRead, AsyncWrite},
};
#[cfg(target_os = "macos")]
use std::os::unix::fs::MetadataExt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::io::RawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};
#[cfg(windows)]
use windows::Win32::{Foundation::HANDLE, System::Pipes::GetNamedPipeClientProcessId};

#[cfg(windows)]
#[inline]
pub(crate) fn should_allow_everyone_create_on_windows(postfix: &str) -> bool {
    postfix.is_empty() || hbb_common::config::is_service_ipc_postfix(postfix)
}

#[cfg(target_os = "macos")]
#[inline]
fn macos_service_ipc_allows_gui_and_service_binaries(
    peer_exe: &Path,
    current_exe: &Path,
    postfix: &str,
) -> bool {
    if postfix != crate::POSTFIX_SERVICE {
        return false;
    }
    let Some(peer_dir) = peer_exe.parent() else {
        return false;
    };
    let Some(current_dir) = current_exe.parent() else {
        return false;
    };
    if !executable_paths_match(peer_dir, current_dir) {
        return false;
    }

    // On installed macOS builds, `_service` is listened by the `service` binary while the GUI
    // process connects from the app executable within the same app bundle.
    let gui_exe_name = std::ffi::OsString::from(crate::get_app_name());
    let gui_exe = gui_exe_name.as_os_str();
    let service_exe = std::ffi::OsStr::new("service");
    let allowed_exe = [Some(gui_exe), Some(service_exe)];
    let peer_name = peer_exe.file_name();
    let current_name = current_exe.file_name();
    allowed_exe
        .iter()
        .any(|name| os_str_eq_ignore_ascii_case(peer_name, *name))
        && allowed_exe
            .iter()
            .any(|name| os_str_eq_ignore_ascii_case(current_name, *name))
}

#[cfg(windows)]
#[inline]
pub(crate) fn is_allowed_windows_session_scoped_peer(
    client_is_system: bool,
    client_session_id: Option<u32>,
    expected_session_id: Option<u32>,
) -> bool {
    client_is_system
        || matches!(
            (client_session_id, expected_session_id),
            (Some(client), Some(expected)) if client == expected
        )
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[inline]
pub(crate) fn is_allowed_service_peer_uid(peer_uid: u32, active_uid: Option<u32>) -> bool {
    // Root is allowed at the UID gate because the service side may run as root.
    // Callers still enforce executable matching before accepting service-scoped peers.
    peer_uid == 0 || active_uid.is_some_and(|uid| uid == peer_uid)
}

#[cfg(target_os = "macos")]
#[inline]
fn console_owner_uid() -> Option<u32> {
    fs::metadata("/dev/console")
        .ok()
        .map(|metadata| metadata.uid())
}

#[cfg(target_os = "macos")]
#[inline]
fn active_uid_strict() -> Option<u32> {
    // Prefer the filesystem metadata over parsing external command output.
    console_owner_uid()
}

#[cfg(target_os = "linux")]
#[inline]
fn active_uid_strict() -> Option<u32> {
    let reported_uid_raw = crate::platform::linux::get_active_userid();
    let trimmed = reported_uid_raw.trim();
    if let Ok(uid) = trimmed.parse::<u32>() {
        return Some(uid);
    }
    if trimmed.is_empty() {
        log::debug!("Failed to resolve active user uid on linux: active uid is empty");
    } else {
        log::warn!("Failed to parse active user uid on linux: '{}'", trimmed);
    }
    None
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[inline]
pub(crate) fn active_uid() -> Option<u32> {
    active_uid_strict()
}

// R-S11a(a): a FRESH active-user lookup for AUTHORIZATION — bypassing the service-loop cache — so
// a just-switched-out user cannot pass the `_service` UID gate during the cache-lag window. This
// matches the fresh lookup the `_uinput_*` authorizer already does. The cached `active_uid()` is
// kept ONLY for stable config-sync ROUTING (ipc.rs `select_server_uid_for_user_main_ipc`, fs.rs) —
// which is not authorization. On macOS `/dev/console` ownership is already a live fs lookup.
#[cfg(target_os = "macos")]
#[inline]
fn active_uid_fresh() -> Option<u32> {
    console_owner_uid()
}

#[cfg(target_os = "linux")]
#[inline]
fn active_uid_fresh() -> Option<u32> {
    let reported_uid_raw = crate::platform::linux::get_active_userid_fresh();
    let trimmed = reported_uid_raw.trim();
    if let Ok(uid) = trimmed.parse::<u32>() {
        return Some(uid);
    }
    if trimmed.is_empty() {
        log::debug!("R-S11a(a): fresh active uid lookup is empty");
    } else {
        log::warn!("R-S11a(a): failed to parse fresh active uid: '{}'", trimmed);
    }
    None
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[inline]
pub(crate) fn peer_uid_from_fd(fd: RawFd) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        return peer_cred_from_fd(fd).map(|cred| cred.uid as u32);
    }
    #[cfg(target_os = "macos")]
    {
        let mut uid = 0;
        let mut gid = 0;
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } == 0 {
            Some(uid as u32)
        } else {
            None
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[inline]
fn peer_pid_from_fd(fd: RawFd) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        return peer_cred_from_fd(fd).and_then(|cred| (cred.pid > 0).then_some(cred.pid as u32));
    }
    #[cfg(target_os = "macos")]
    {
        let mut pid = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as _;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                &mut pid as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc == 0 && pid > 0 {
            Some(pid as _)
        } else {
            None
        }
    }
}

#[cfg(target_os = "linux")]
#[inline]
fn peer_cred_from_fd(fd: RawFd) -> Option<libc::ucred> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as _;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 {
        Some(cred)
    } else {
        None
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[inline]
fn current_exe_canonical_path() -> ResultType<PathBuf> {
    let current = std::env::current_exe()
        .map_err(|err| anyhow::anyhow!("Failed to resolve current executable path: {}", err))?;
    fs::canonicalize(&current).map_err(|err| {
        anyhow::anyhow!(
            "Failed to canonicalize current executable path '{}': {}",
            current.display(),
            err
        )
        .into()
    })
}

#[cfg(target_os = "linux")]
#[inline]
fn peer_exe_canonical_path_by_pid(peer_pid: u32) -> ResultType<PathBuf> {
    let proc_exe = PathBuf::from(format!("/proc/{peer_pid}/exe"));
    let peer_exe = fs::read_link(&proc_exe).map_err(|err| {
        anyhow::anyhow!(
            "Failed to read peer executable link '{}': {}",
            proc_exe.display(),
            err
        )
    })?;
    fs::canonicalize(&peer_exe).map_err(|err| {
        anyhow::anyhow!(
            "Failed to canonicalize peer executable path '{}': {}",
            peer_exe.display(),
            err
        )
        .into()
    })
}

#[cfg(target_os = "macos")]
#[inline]
fn peer_exe_canonical_path_by_pid(peer_pid: u32) -> ResultType<PathBuf> {
    const PROC_PIDPATH_BUF_SIZE: usize = libc::PROC_PIDPATHINFO_MAXSIZE as _;
    let mut buffer = vec![0u8; PROC_PIDPATH_BUF_SIZE];
    let length = unsafe {
        libc::proc_pidpath(
            peer_pid as _,
            buffer.as_mut_ptr() as _,
            PROC_PIDPATH_BUF_SIZE as _,
        )
    };
    if length <= 0 {
        bail!("Failed to query peer process path from pid {}", peer_pid);
    }
    buffer.truncate(length as _);
    let path = PathBuf::from(String::from_utf8_lossy(&buffer).to_string());
    fs::canonicalize(&path).map_err(|err| {
        anyhow::anyhow!(
            "Failed to canonicalize peer executable path '{}': {}",
            path.display(),
            err
        )
        .into()
    })
}

#[cfg(target_os = "windows")]
#[inline]
fn peer_exe_canonical_path_by_pid(peer_pid: u32) -> ResultType<PathBuf> {
    let path = crate::platform::windows::get_process_executable_path(peer_pid)?;
    fs::canonicalize(&path).map_err(|err| {
        anyhow::anyhow!(
            "Failed to canonicalize peer executable path '{}': {}",
            path.display(),
            err
        )
        .into()
    })
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[inline]
pub(crate) fn executable_paths_match(left: &Path, right: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        // Callers pass paths resolved through fs::canonicalize() first, so NT
        // namespace paths and 8.3 short names are expected to be resolved before
        // this check. Keep this normalization limited to remaining Win32 spelling
        // differences.
        fn normalize(path: &Path) -> String {
            let mut normalized = path.to_string_lossy().replace('/', "\\");
            if let Some(stripped) = normalized.strip_prefix(r"\\?\") {
                normalized = stripped.to_owned();
            }
            normalized.to_ascii_lowercase()
        }
        return normalize(left) == normalize(right);
    }
    #[cfg(target_os = "macos")]
    {
        return paths_refer_to_same_file(left, right);
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        left == right
    }
}

#[cfg(target_os = "macos")]
#[inline]
fn paths_refer_to_same_file(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    let (Ok(left), Ok(right)) = (fs::metadata(left), fs::metadata(right)) else {
        return false;
    };
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(target_os = "macos")]
#[inline]
fn os_str_eq_ignore_ascii_case(
    left: Option<&std::ffi::OsStr>,
    right: Option<&std::ffi::OsStr>,
) -> bool {
    let (Some(left), Some(right)) = (left, right) else {
        return false;
    };
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[inline]
fn ensure_peer_executable_matches_current_by_pid(peer_pid: u32, postfix: &str) -> ResultType<()> {
    let peer_exe = peer_exe_canonical_path_by_pid(peer_pid)?;
    let current_exe = current_exe_canonical_path()?;
    if executable_paths_match(&peer_exe, &current_exe) {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    if macos_service_ipc_allows_gui_and_service_binaries(&peer_exe, &current_exe, postfix) {
        return Ok(());
    }
    bail!(
        "Peer executable path mismatch on ipc channel '{}': peer_pid={}, peer_exe='{}', current_exe='{}'",
        postfix,
        peer_pid,
        peer_exe.display(),
        current_exe.display()
    );
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[inline]
pub(crate) fn ensure_peer_executable_matches_current_by_pid_opt(
    peer_pid: Option<u32>,
    postfix: &str,
) -> ResultType<()> {
    let peer_pid = peer_pid.ok_or_else(|| {
        anyhow::anyhow!("Failed to resolve peer pid on ipc channel '{}'", postfix)
    })?;
    ensure_peer_executable_matches_current_by_pid(peer_pid, postfix)
}

// R-X13 (§8): ensure_peer_executable_matches_current_by_fd (the FD-based exe-match used ONLY by the
// uinput peer authorizer) is removed with the uinput module. The _service authorizer uses the
// _by_pid variant; peer_pid_from_fd / ensure_peer_executable_matches_current_by_pid remain.

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
const UNAUTHORIZED_IPC_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
#[derive(Default)]
struct UnauthorizedIpcLogThrottle {
    last_log_at: Option<std::time::Instant>,
    suppressed: u64,
}

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
impl UnauthorizedIpcLogThrottle {
    #[inline]
    fn on_reject(&mut self, now: std::time::Instant) -> Option<u64> {
        if let Some(last) = self.last_log_at {
            if now.saturating_duration_since(last) < UNAUTHORIZED_IPC_LOG_INTERVAL {
                self.suppressed += 1;
                return None;
            }
        }
        self.last_log_at = Some(now);
        Some(std::mem::take(&mut self.suppressed))
    }
}

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
#[inline]
fn throttled_unauthorized_ipc_log(
    throttle_cell: &OnceLock<Mutex<UnauthorizedIpcLogThrottle>>,
    emit: impl FnOnce(u64),
) {
    let throttle = throttle_cell.get_or_init(|| Mutex::new(UnauthorizedIpcLogThrottle::default()));
    let should_log = match throttle.lock() {
        Ok(mut throttle) => throttle.on_reject(std::time::Instant::now()),
        Err(_) => Some(0),
    };
    if let Some(suppressed) = should_log {
        emit(suppressed);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[inline]
fn log_rejected_service_connection(postfix: &str, peer_uid: Option<u32>, active_uid: Option<u32>) {
    static LOG_THROTTLE: OnceLock<Mutex<UnauthorizedIpcLogThrottle>> = OnceLock::new();
    throttled_unauthorized_ipc_log(&LOG_THROTTLE, |suppressed| {
        if suppressed > 0 {
            log::warn!(
                "Rejected unauthorized connection on protected service-scoped IPC channel: postfix={}, peer_uid={:?}, active_uid={:?} (suppressed {} similar events)",
                postfix,
                peer_uid,
                active_uid,
                suppressed
            );
        } else {
            log::warn!(
                "Rejected unauthorized connection on protected service-scoped IPC channel: postfix={}, peer_uid={:?}, active_uid={:?}",
                postfix,
                peer_uid,
                active_uid
            );
        }
    });
}

// R-X13 (§8): log_rejected_uinput_connection (the throttled reject-log for the uinput IPC channel)
// is removed with the uinput module. log_rejected_service_connection remains for the _service channel.

#[cfg(windows)]
#[inline]
pub(crate) fn log_rejected_windows_ipc_connection(
    postfix: &str,
    peer_pid: Option<u32>,
    peer_session_id: Option<u32>,
    expected_session_id: Option<u32>,
    peer_is_system: Option<bool>,
    peer_is_elevated: Option<bool>,
) {
    static LOG_THROTTLE: OnceLock<Mutex<UnauthorizedIpcLogThrottle>> = OnceLock::new();
    throttled_unauthorized_ipc_log(&LOG_THROTTLE, |suppressed| {
        if suppressed > 0 {
            log::warn!(
                "Rejected unauthorized connection on ipc channel: postfix={}, peer_pid={:?}, peer_session_id={:?}, expected_session_id={:?}, peer_is_system={:?}, peer_is_elevated={:?} (suppressed {} similar events)",
                postfix,
                peer_pid,
                peer_session_id,
                expected_session_id,
                peer_is_system,
                peer_is_elevated,
                suppressed
            );
        } else {
            log::warn!(
                "Rejected unauthorized connection on ipc channel: postfix={}, peer_pid={:?}, peer_session_id={:?}, expected_session_id={:?}, peer_is_system={:?}, peer_is_elevated={:?}",
                postfix,
                peer_pid,
                peer_session_id,
                expected_session_id,
                peer_is_system,
                peer_is_elevated
            );
        }
    });
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn authorize_service_scoped_ipc_connection(stream: &Connection, postfix: &str) -> bool {
    let peer_pid = stream.peer_pid();
    let (authorized, peer_uid, active_uid) = stream.service_authorization_status();
    if !authorized {
        log_rejected_service_connection(postfix, peer_uid, active_uid);
        return false;
    }
    if let Err(err) = ensure_peer_executable_matches_current_by_pid_opt(peer_pid, postfix) {
        log::warn!(
            "Rejected unauthorized connection on protected service-scoped IPC channel due to executable mismatch: postfix={}, peer_pid={:?}, err={}",
            postfix,
            peer_pid,
            err
        );
        return false;
    }
    true
}

#[cfg(windows)]
pub(crate) fn authorize_windows_main_ipc_connection(stream: &Connection, postfix: &str) -> bool {
    let (
        authorized,
        peer_pid,
        peer_session_id,
        server_session_id,
        peer_is_system,
        peer_is_elevated,
    ) = stream.server_authorization_status();
    if !authorized {
        log_rejected_windows_ipc_connection(
            postfix,
            peer_pid,
            peer_session_id,
            server_session_id,
            peer_is_system,
            peer_is_elevated,
        );
        return false;
    }
    if let Err(err) = ensure_peer_executable_matches_current_by_pid_opt(peer_pid, postfix) {
        log::warn!(
            "Rejected unauthorized connection on ipc channel due to executable mismatch: postfix={}, peer_pid={:?}, err={}",
            postfix,
            peer_pid,
            err
        );
        return false;
    }
    true
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl<T> ConnectionTmpl<T>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::os::unix::io::AsRawFd,
{
    pub(super) fn peer_uid(&self) -> Option<u32> {
        peer_uid_from_fd(self.inner.get_ref().as_raw_fd())
    }

    fn service_authorization_status(&self) -> (bool, Option<u32>, Option<u32>) {
        let peer_uid = self.peer_uid();
        // R-S11a(a): authorize against a FRESH active-user lookup, NOT the service-loop cache —
        // otherwise a just-switched-out user could pass this `_service` UID gate in the cache-lag
        // window. Matches the `_uinput_*` authorizer's fresh lookup. (The cached active_uid() stays
        // for stable config-sync routing elsewhere; that is not authorization.) Fail-closed: if the
        // live lookup yields None, only root (uid 0) is admitted until it resolves.
        let active_uid = active_uid_fresh();
        let authorized = peer_uid.is_some_and(|uid| is_allowed_service_peer_uid(uid, active_uid));
        (authorized, peer_uid, active_uid)
    }

    pub(super) fn peer_pid(&self) -> Option<u32> {
        peer_pid_from_fd(self.inner.get_ref().as_raw_fd())
    }
}

#[cfg(windows)]
impl ConnectionTmpl<parity_tokio_ipc::Connection> {
    fn peer_pid(&self) -> Option<u32> {
        let pipe_handle = self.inner.get_ref().as_raw_handle();
        if pipe_handle.is_null() {
            return None;
        }
        let mut pid = 0u32;
        let ok = unsafe { GetNamedPipeClientProcessId(HANDLE(pipe_handle), &mut pid as *mut u32) }
            .is_ok();
        if ok && pid != 0 {
            Some(pid)
        } else {
            None
        }
    }

    fn server_authorization_status(
        &self,
    ) -> (
        bool,
        Option<u32>,
        Option<u32>,
        Option<u32>,
        Option<bool>,
        Option<bool>,
    ) {
        let peer_pid = self.peer_pid();
        let server_session_id = crate::platform::windows::get_current_process_session_id();
        let peer_session_id =
            peer_pid.and_then(crate::platform::windows::get_session_id_of_process);
        let peer_is_system_result =
            peer_pid.map(crate::platform::windows::is_process_running_as_system);
        let peer_is_system = peer_is_system_result
            .as_ref()
            .and_then(|r| r.as_ref().ok().copied());
        let session_authorized = is_allowed_windows_session_scoped_peer(
            peer_is_system.unwrap_or(false),
            peer_session_id,
            server_session_id,
        );
        let peer_is_elevated_result = if session_authorized {
            None
        } else {
            peer_pid.map(|pid| crate::platform::windows::is_elevated(Some(pid)))
        };
        let peer_is_elevated = peer_is_elevated_result
            .as_ref()
            .and_then(|r| r.as_ref().ok().copied());
        if server_session_id.is_none()
            && !peer_is_system.unwrap_or(false)
            && !peer_is_elevated.unwrap_or(false)
        {
            // When the server session id cannot be determined, the session-id allow-path is
            // disabled and only privileged peers can be authorized.
            log::debug!(
                "IPC authorization: server session id unavailable; rejecting non-privileged peer, peer_pid={:?}, peer_session_id={:?}",
                peer_pid,
                peer_session_id
            );
        }
        // Main IPC trusts same-session peers, LocalSystem, and elevated administrators.
        // Service-scoped IPC channels keep their own stricter authorization paths.
        let authorized = session_authorized || peer_is_elevated.unwrap_or(false);
        if !authorized {
            if let (Some(pid), Some(Err(err))) = (peer_pid, peer_is_system_result.as_ref()) {
                log::debug!(
                    "Failed to determine whether peer process is SYSTEM, pid={}, err={}",
                    pid,
                    err
                );
            }
            if let (Some(pid), Some(Err(err))) = (peer_pid, peer_is_elevated_result.as_ref()) {
                log::debug!(
                    "Failed to determine whether peer process is elevated, pid={}, err={}",
                    pid,
                    err
                );
            }
        }
        (
            authorized,
            peer_pid,
            peer_session_id,
            server_session_id,
            peer_is_system,
            peer_is_elevated,
        )
    }

    pub(crate) fn service_authorization_status_for_session(
        &self,
        expected_active_session_id: Option<u32>,
    ) -> (bool, Option<u32>, Option<u32>, Option<bool>) {
        let peer_pid = self.peer_pid();
        let peer_session_id =
            peer_pid.and_then(crate::platform::windows::get_session_id_of_process);
        let peer_is_system_result =
            peer_pid.map(crate::platform::windows::is_process_running_as_system);
        let peer_is_system = peer_is_system_result
            .as_ref()
            .and_then(|r| r.as_ref().ok().copied());
        let authorized = is_allowed_windows_session_scoped_peer(
            peer_is_system.unwrap_or(false),
            peer_session_id,
            expected_active_session_id,
        );
        if !authorized {
            if let (Some(pid), Some(Err(err))) = (peer_pid, peer_is_system_result.as_ref()) {
                log::debug!(
                    "Failed to determine whether peer process is SYSTEM, pid={}, err={}",
                    pid,
                    err
                );
            }
        }
        (authorized, peer_pid, peer_session_id, peer_is_system)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn test_service_peer_uid_policy() {
        assert!(super::is_allowed_service_peer_uid(0, None));
        assert!(super::is_allowed_service_peer_uid(501, Some(501)));
        assert!(!super::is_allowed_service_peer_uid(502, Some(501)));
        assert!(!super::is_allowed_service_peer_uid(501, None));
    }

    #[test]
    #[cfg(windows)]
    fn test_windows_server_peer_policy() {
        assert!(super::is_allowed_windows_session_scoped_peer(
            true, None, None
        ));
        assert!(super::is_allowed_windows_session_scoped_peer(
            false,
            Some(1),
            Some(1)
        ));
        assert!(!super::is_allowed_windows_session_scoped_peer(
            false,
            Some(1),
            Some(2)
        ));
        assert!(!super::is_allowed_windows_session_scoped_peer(
            false,
            None,
            Some(1)
        ));
    }

    #[test]
    #[cfg(windows)]
    fn test_should_allow_everyone_create_on_windows_policy() {
        assert!(super::should_allow_everyone_create_on_windows(""));
        assert!(super::should_allow_everyone_create_on_windows("_service"));
        assert!(!super::should_allow_everyone_create_on_windows(
            "_portable_service"
        ));
    }

    #[test]
    #[cfg(windows)]
    fn test_executable_paths_match_windows_normalization() {
        let left = std::path::PathBuf::from(r"\\?\C:\Program Files\RustDesk\RustDesk.exe");
        let right = std::path::PathBuf::from(r"c:\program files\rustdesk\rustdesk.exe");
        assert!(super::executable_paths_match(&left, &right));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_os_str_eq_ignore_ascii_case_for_process_names() {
        assert!(super::os_str_eq_ignore_ascii_case(
            Some(std::ffi::OsStr::new("RustDesk")),
            Some(std::ffi::OsStr::new("rustdesk"))
        ));
        assert!(!super::os_str_eq_ignore_ascii_case(
            Some(std::ffi::OsStr::new("RustDesk")),
            Some(std::ffi::OsStr::new("service"))
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_console_owner_uid_matches_get_active_userid() {
        let console_uid =
            super::console_owner_uid().expect("/dev/console must have a resolvable uid");
        let raw_uid = crate::platform::macos::get_active_userid();
        let parsed_uid: u32 = raw_uid
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("failed to parse get_active_userid() output: '{raw_uid}'"));
        assert_eq!(parsed_uid, console_uid);
    }
}
