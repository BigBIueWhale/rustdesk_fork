use crate::ipc::{Connection, ConnectionTmpl};
#[cfg(target_os = "macos")]
use core_foundation::{base::TCFType, data::CFData, url::CFURL};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use hbb_common::{anyhow, bail, log, ResultType};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use hbb_common::{
    libc,
    tokio::io::{AsyncRead, AsyncWrite},
};
#[cfg(target_os = "macos")]
use security_framework::os::macos::code_signing::{
    Flags as MacosCodeSigningFlags, GuestAttributes as MacosGuestAttributes,
    SecCode as MacosSecCode, SecRequirement as MacosSecRequirement,
    SecStaticCode as MacosSecStaticCode,
};
#[cfg(target_os = "linux")]
use serde_derive::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use std::ffi::{c_void, CString};
#[cfg(target_os = "linux")]
use std::fmt;
#[cfg(target_os = "macos")]
use std::io::{BufReader, Read};
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStrExt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::io::RawFd;
#[cfg(windows)]
use std::os::windows::{ffi::OsStringExt, io::AsRawHandle};
#[cfg(windows)]
use std::{
    collections::{BTreeSet, VecDeque},
    ffi::{c_void, OsString},
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    time::Instant,
};
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};
#[cfg(windows)]
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{
            CloseHandle, DuplicateHandle, LocalFree, DUPLICATE_SAME_ACCESS, FILETIME, HANDLE,
            HLOCAL, UNICODE_STRING, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Security::{
            Authorization::ConvertSidToStringSidW, GetTokenInformation, RevertToSelf,
            TokenElevation, TokenGroups, TokenSessionId, TokenUser, PSID, SID_AND_ATTRIBUTES,
            TOKEN_ELEVATION, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER,
        },
        System::{
            Pipes::{
                GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
                ImpersonateNamedPipeClient,
            },
            Threading::{
                ExitThread, GetCurrentProcess, GetCurrentThread, GetProcessTimes, OpenProcess,
                OpenProcessToken, OpenThreadToken, QueryFullProcessImageNameW, WaitForSingleObject,
                INFINITE, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_SYNCHRONIZE,
            },
        },
        UI::Shell::CommandLineToArgvW,
    },
};

#[cfg(any(windows, test))]
const WINDOWS_URL_IPC_POSTFIX: &str = "_url";

#[cfg(any(windows, test))]
#[inline]
fn windows_whiteboard_ipc_postfix_is_valid(postfix: &str) -> bool {
    super::whiteboard_ipc_postfix_is_valid(postfix)
}

#[cfg(any(windows, test))]
#[inline]
pub(crate) fn windows_ipc_postfix_uses_restricted_dacl(postfix: &str) -> bool {
    postfix.is_empty()
        || postfix == super::password::USER_PASSWORD_IPC_POSTFIX
        || hbb_common::config::is_service_ipc_postfix(postfix)
        || postfix == super::WINDOWS_SERVICE_CREDENTIAL_IPC_POSTFIX
        || postfix == super::WINDOWS_SERVICE_MAIN_CONTROL_IPC_POSTFIX
        || postfix == super::WINDOWS_SERVICE_SAS_IPC_POSTFIX
        || postfix == WINDOWS_URL_IPC_POSTFIX
        || postfix == "_cm"
        || windows_whiteboard_ipc_postfix_is_valid(postfix)
}

#[cfg(windows)]
pub(crate) const WINDOWS_NAMED_PIPE_CLIENT_ACCESS_MASK: u32 = 0x0012_019b;
#[cfg(windows)]
const SE_GROUP_LOGON_ID: u32 = 0xc000_0000;
#[cfg(windows)]
const LOCAL_SYSTEM_SID: &str = "S-1-5-18";
#[cfg(windows)]
const INTERACTIVE_USERS_SID: &str = "S-1-5-4";
#[cfg(windows)]
const WINDOWS_PROCESS_IDENTITY_CACHE_CAPACITY: usize = 128;
#[cfg(windows)]
const WINDOWS_PROCESS_COMMAND_LINE_MAX_BYTES: usize = 128 * 1024;
#[cfg(windows)]
const WINDOWS_PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;
#[cfg(windows)]
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xc000_0004u32 as i32;

#[cfg(target_os = "macos")]
const MACOS_PRIVILEGED_HELPER_EXEC: &str =
    "/Library/PrivilegedHelperTools/com.carriez.rustdesk_service";
#[cfg(target_os = "macos")]
const MACOS_PRIVILEGED_HELPER_DIR: &str = "/Library/PrivilegedHelperTools";
#[cfg(target_os = "macos")]
const MACOS_PRIVILEGED_HELPER_REQUIREMENT: &str = r#"=anchor apple generic and certificate leaf[subject.OU] = "HZF9JMC8YN" and (identifier "service" or identifier "com.carriez.rustdesk_service")"#;
#[cfg(target_os = "macos")]
const MACOS_INSTALLED_APP_REQUIREMENT: &str = r#"=anchor apple generic and certificate leaf[subject.OU] = "HZF9JMC8YN" and identifier "com.carriez.rustdesk""#;
#[cfg(target_os = "macos")]
const MACOS_AUDIT_TOKEN_BYTES: usize = 32;
#[cfg(target_os = "macos")]
type MacosAcl = *mut c_void;
#[cfg(target_os = "macos")]
type MacosAclEntry = *mut c_void;
#[cfg(target_os = "macos")]
const MACOS_ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
#[cfg(target_os = "macos")]
const MACOS_ACL_FIRST_ENTRY: libc::c_int = 0;

#[cfg(target_os = "macos")]
extern "C" {
    fn acl_get_link_np(path_p: *const libc::c_char, acl_type: libc::c_int) -> MacosAcl;
    fn acl_get_entry(
        acl: MacosAcl,
        entry_id: libc::c_int,
        entry_p: *mut MacosAclEntry,
    ) -> libc::c_int;
    fn acl_valid_link_np(
        path_p: *const libc::c_char,
        acl_type: libc::c_int,
        acl: MacosAcl,
    ) -> libc::c_int;
    fn acl_free(obj_p: *mut c_void) -> libc::c_int;
}

#[cfg(windows)]
struct WindowsIpcDaclSids {
    server_sids: Vec<String>,
    client_sids: Vec<String>,
}

#[cfg(target_os = "macos")]
struct MacosAclGuard(MacosAcl);

#[cfg(target_os = "macos")]
#[derive(Clone)]
pub(crate) struct MacosPeerProcessIdentity {
    uid: u32,
    pid: u32,
    audit_token: [u8; MACOS_AUDIT_TOKEN_BYTES],
}

#[cfg(target_os = "macos")]
impl MacosPeerProcessIdentity {
    #[inline]
    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }

    #[inline]
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacosAclGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = acl_free(self.0);
        }
    }
}

#[cfg(windows)]
struct WindowsHandle(HANDLE);

#[cfg(windows)]
unsafe impl Send for WindowsHandle {}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WindowsProcessIdentityKey {
    pub(crate) pid: u32,
    pub(crate) creation_time: u64,
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct WindowsProcessImmutableIdentity {
    key: WindowsProcessIdentityKey,
    executable: PathBuf,
    argv: Vec<String>,
}

#[cfg(windows)]
struct WindowsPeerProcess {
    key: WindowsProcessIdentityKey,
    handle: WindowsHandle,
}

#[cfg(windows)]
pub(crate) struct WindowsSasPipeDispatch {
    pipe: WindowsHandle,
    requester: WindowsPeerProcess,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WindowsLiveTokenAuthority {
    is_local_system: bool,
    is_elevated: bool,
    session_id: u32,
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WindowsTokenPrincipal {
    user_sid: String,
    logon_sid: Option<String>,
    session_id: u32,
}

#[cfg(windows)]
impl WindowsTokenPrincipal {
    fn boundary_sid(&self) -> &str {
        self.logon_sid.as_deref().unwrap_or(&self.user_sid)
    }
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WindowsSensitivePipeSecurity {
    pub(crate) sddl: String,
    pub(crate) expected_client_principal: Option<WindowsTokenPrincipal>,
    pub(crate) expected_session_id: Option<u32>,
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct WindowsLiveTokenProof {
    authority: WindowsLiveTokenAuthority,
    principal: WindowsTokenPrincipal,
}

#[cfg(windows)]
struct WindowsProcessIdentityCache {
    capacity: usize,
    entries: VecDeque<Arc<WindowsProcessImmutableIdentity>>,
}

#[cfg(windows)]
type NtQueryInformationProcessFn =
    unsafe extern "system" fn(HANDLE, u32, *mut c_void, u32, *mut u32) -> i32;

#[cfg(windows)]
static WINDOWS_PROCESS_IDENTITY_CACHE: OnceLock<Mutex<WindowsProcessIdentityCache>> =
    OnceLock::new();

#[cfg(windows)]
static NT_QUERY_INFORMATION_PROCESS: OnceLock<Option<NtQueryInformationProcessFn>> =
    OnceLock::new();

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    #[link_name = "GetModuleHandleW"]
    fn windows_get_module_handle_w(module_name: *const u16) -> *mut c_void;
    #[link_name = "GetProcAddress"]
    fn windows_get_proc_address(module: *mut c_void, procedure_name: *const u8) -> *mut c_void;
}

#[cfg(windows)]
impl Drop for WindowsHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

#[cfg(windows)]
fn duplicate_windows_handle(handle: HANDLE, context: &str) -> ResultType<WindowsHandle> {
    if handle.is_invalid() {
        bail!("Cannot duplicate invalid {context} handle");
    }
    let mut duplicate = HANDLE::default();
    unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &mut duplicate,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
        .map_err(|err| anyhow::anyhow!("Failed to duplicate {context} handle: {err}"))?;
    }
    Ok(WindowsHandle(duplicate))
}

#[cfg(windows)]
fn run_windows_pipe_client_impersonation<T, F>(
    pipe: HANDLE,
    context: &'static str,
    operation: F,
) -> ResultType<T>
where
    T: Send + 'static,
    F: FnOnce(HANDLE) -> ResultType<T> + Send + 'static,
{
    run_windows_pipe_client_impersonation_inner(pipe, context, None, operation)
}

#[cfg(windows)]
fn run_windows_pipe_client_impersonation_until<T, F>(
    pipe: HANDLE,
    context: &'static str,
    deadline: Instant,
    operation: F,
) -> ResultType<T>
where
    T: Send + 'static,
    F: FnOnce(HANDLE) -> ResultType<T> + Send + 'static,
{
    windows_sensitive_auth_deadline_live(deadline, context)?;
    run_windows_pipe_client_impersonation_inner(pipe, context, Some(deadline), operation)
}

#[cfg(windows)]
fn windows_sensitive_auth_deadline_live(deadline: Instant, context: &str) -> ResultType<()> {
    if Instant::now() >= deadline {
        bail!("{context} exceeded the sensitive IPC deadline");
    }
    Ok(())
}

#[cfg(windows)]
fn windows_sensitive_auth_remaining_millis(deadline: Instant, context: &str) -> ResultType<u32> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| anyhow::anyhow!("{context} exceeded the sensitive IPC deadline"))?;
    Ok(remaining.as_millis().max(1).min((u32::MAX - 1) as u128) as u32)
}

#[cfg(windows)]
fn run_windows_pipe_client_impersonation_inner<T, F>(
    pipe: HANDLE,
    context: &'static str,
    deadline: Option<Instant>,
    operation: F,
) -> ResultType<T>
where
    T: Send + 'static,
    F: FnOnce(HANDLE) -> ResultType<T> + Send + 'static,
{
    const RUNNING: u8 = 0;
    const COMPLETE: u8 = 1;
    const RESTORATION_FAILED: u8 = 2;
    const RESULT_STORAGE_FAILED: u8 = 3;

    let pipe = duplicate_windows_handle(pipe, context)?;
    let pipe_value = (pipe.0).0 as usize;
    let state = Arc::new(AtomicU8::new(RUNNING));
    let result = Arc::new(Mutex::new(None::<std::result::Result<T, String>>));
    let worker_state = Arc::clone(&state);
    let worker_result = Arc::clone(&result);
    let worker = std::thread::Builder::new()
        .name("windows-pipe-impersonation".to_owned())
        .spawn(move || {
            let pipe_handle = HANDLE(pipe_value as *mut c_void);
            let impersonated = unsafe { ImpersonateNamedPipeClient(pipe_handle) };
            if let Err(err) = impersonated {
                if let Ok(mut slot) = worker_result.lock() {
                    *slot = Some(Err(format!("Failed to impersonate {context}: {err}")));
                    worker_state.store(COMPLETE, Ordering::Release);
                } else {
                    worker_state.store(RESULT_STORAGE_FAILED, Ordering::Release);
                }
                return;
            }

            let operation_result = operation(pipe_handle).map_err(|err| err.to_string());
            let stored = if let Ok(mut slot) = worker_result.lock() {
                *slot = Some(operation_result);
                true
            } else {
                false
            };
            if unsafe { RevertToSelf() }.is_err() {
                worker_state.store(RESTORATION_FAILED, Ordering::Release);
                unsafe { ExitThread(1) };
            }
            worker_state.store(
                if stored {
                    COMPLETE
                } else {
                    RESULT_STORAGE_FAILED
                },
                Ordering::Release,
            );
        })
        .map_err(|err| anyhow::anyhow!("Failed to start {context} impersonation worker: {err}"))?;

    let (wait_timeout, deadline_expired_before_wait) = match deadline {
        Some(deadline) => match windows_sensitive_auth_remaining_millis(deadline, context) {
            Ok(timeout) => (timeout, false),
            Err(_) => (INFINITE, true),
        },
        None => (INFINITE, false),
    };
    let wait = unsafe { WaitForSingleObject(HANDLE(worker.as_raw_handle()), wait_timeout) };
    let deadline_expired = deadline_expired_before_wait
        || deadline.is_some()
            && (wait == WAIT_TIMEOUT
                || deadline.is_some_and(|deadline| Instant::now() >= deadline));
    if wait != WAIT_OBJECT_0 {
        let drained = unsafe { WaitForSingleObject(HANDLE(worker.as_raw_handle()), INFINITE) };
        if drained != WAIT_OBJECT_0 {
            log::error!(
                "Could not conclusively drain {context} impersonation worker: initial_status={}, drain_status={}",
                wait.0,
                drained.0
            );
            std::process::abort();
        }
    }
    match state.load(Ordering::Acquire) {
        RESTORATION_FAILED => {
            drop(worker);
            bail!("Failed to restore {context} impersonation; the disposable worker was terminated")
        }
        COMPLETE => {
            if worker.join().is_err() {
                bail!("{context} impersonation worker panicked");
            }
        }
        RESULT_STORAGE_FAILED => {
            if worker.join().is_err() {
                bail!("{context} impersonation worker panicked");
            }
            bail!("{context} impersonation worker could not retain its result");
        }
        status => {
            drop(worker);
            bail!("{context} impersonation worker ended in invalid state {status}");
        }
    }
    if deadline_expired {
        bail!("{context} exceeded the sensitive IPC deadline");
    }
    let mut result = result
        .lock()
        .map_err(|_| anyhow::anyhow!("{context} impersonation result lock poisoned"))?;
    match result.take() {
        Some(Ok(value)) => Ok(value),
        Some(Err(err)) => Err(anyhow::anyhow!(err)),
        None => bail!("{context} impersonation worker returned no result"),
    }
}

#[cfg(windows)]
fn windows_named_pipe_client_pid(pipe: HANDLE) -> ResultType<u32> {
    let mut pid = 0u32;
    unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) }
        .map_err(|err| anyhow::anyhow!("Failed to resolve Windows named-pipe client pid: {err}"))?;
    if pid == 0 {
        bail!("Windows named-pipe client pid is zero");
    }
    Ok(pid)
}

#[cfg(windows)]
fn windows_named_pipe_client_token_proof(
    pipe: HANDLE,
    deadline: Instant,
) -> ResultType<WindowsLiveTokenProof> {
    run_windows_pipe_client_impersonation_until(
        pipe,
        "Windows sensitive IPC client",
        deadline,
        move |_pipe_handle| {
            let mut token = HANDLE::default();
            unsafe {
                OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token).map_err(
                    |err| {
                        anyhow::anyhow!("Failed to open Windows sensitive IPC client token: {err}")
                    },
                )?;
            }
            let _token_guard = WindowsHandle(token);
            windows_live_token_proof(token)
        },
    )
}

#[cfg(windows)]
impl WindowsSasPipeDispatch {
    pub(crate) fn dispatch(
        self,
        expected_requester: WindowsProcessIdentityKey,
        expected_session_id: u32,
    ) -> ResultType<()> {
        let peer_pid = windows_named_pipe_client_pid(self.pipe.0)?;
        if peer_pid != expected_requester.pid || self.requester.key != expected_requester {
            bail!(
                "Windows SAS requester process identity changed: expected {}:{}, got {}:{}",
                expected_requester.pid,
                expected_requester.creation_time,
                self.requester.key.pid,
                self.requester.key.creation_time
            );
        }
        self.requester.require_running("Windows SAS requester")?;
        let WindowsSasPipeDispatch { pipe, requester } = self;
        run_windows_pipe_client_impersonation(pipe.0, "Windows SAS requester", move |pipe_handle| {
            if windows_named_pipe_client_pid(pipe_handle)? != peer_pid {
                bail!(
                    "Windows SAS requester named-pipe pid changed during authorization: expected {}",
                    peer_pid
                );
            }
            if windows_process_creation_time(requester.handle.0)?
                != expected_requester.creation_time
            {
                bail!("Windows SAS requester process generation changed before dispatch");
            }
            requester.require_running("Windows SAS requester")?;
            let mut token = HANDLE::default();
            unsafe {
                OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token).map_err(
                    |err| {
                        anyhow::anyhow!(
                            "Failed to open Windows SAS requester impersonation token: {err}"
                        )
                    },
                )?;
            }
            let _token_guard = WindowsHandle(token);
            let authority = windows_token_authority(token)?;
            if !windows_token_authority_matches_sas_session(authority, expected_session_id) {
                if !authority.is_local_system {
                    bail!(
                        "Windows SAS requester impersonation token is not LocalSystem: peer_pid={}",
                        peer_pid
                    );
                }
                bail!(
                    "Windows SAS requester session mismatch: peer_pid={}, expected={}, actual={}",
                    peer_pid,
                    expected_session_id,
                    authority.session_id
                );
            }
            requester.require_running("Windows SAS requester")?;
            crate::platform::send_sas()
        })
    }
}

#[cfg(windows)]
impl WindowsPeerProcess {
    fn open(pid: u32) -> ResultType<Self> {
        Self::open_with_access(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE)
    }

    fn open_for_sas_dispatch(pid: u32) -> ResultType<Self> {
        Self::open_with_access(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE)
    }

    fn open_with_access(
        pid: u32,
        access: windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS,
    ) -> ResultType<Self> {
        if pid == 0 {
            bail!("Refused to open Windows IPC peer process with pid 0");
        }
        let handle = unsafe { OpenProcess(access, false, pid) }
            .map_err(|err| anyhow::anyhow!("Failed to open Windows IPC peer pid {pid}: {err}"))?;
        let handle = WindowsHandle(handle);
        let creation_time = windows_process_creation_time(handle.0)?;
        Ok(Self {
            key: WindowsProcessIdentityKey { pid, creation_time },
            handle,
        })
    }

    fn require_running(&self, context: &str) -> ResultType<()> {
        match unsafe { WaitForSingleObject(self.handle.0, 0) } {
            WAIT_TIMEOUT => Ok(()),
            WAIT_OBJECT_0 => bail!("{context} process exited"),
            WAIT_FAILED => bail!("Failed to query {context} process liveness"),
            status => bail!("Unexpected {context} process wait status: {}", status.0),
        }
    }

    fn inspect_identity(&self) -> ResultType<WindowsProcessImmutableIdentity> {
        let executable = windows_process_executable_path(self.handle.0)?;
        let executable = fs::canonicalize(&executable).map_err(|err| {
            anyhow::anyhow!(
                "Failed to canonicalize Windows IPC peer executable '{}': {}",
                executable.display(),
                err
            )
        })?;
        let argv = windows_process_command_line_args(self.handle.0)?;
        let creation_time_after = windows_process_creation_time(self.handle.0)?;
        if creation_time_after != self.key.creation_time {
            bail!(
                "Windows IPC peer process identity changed while being inspected: pid={}",
                self.key.pid
            );
        }
        Ok(WindowsProcessImmutableIdentity {
            key: self.key,
            executable,
            argv,
        })
    }

    fn immutable_identity(&self) -> ResultType<Arc<WindowsProcessImmutableIdentity>> {
        let cache = WINDOWS_PROCESS_IDENTITY_CACHE.get_or_init(|| {
            Mutex::new(WindowsProcessIdentityCache::new(
                WINDOWS_PROCESS_IDENTITY_CACHE_CAPACITY,
            ))
        });
        if let Some(identity) = cache
            .lock()
            .map_err(|_| anyhow::anyhow!("Windows IPC process identity cache lock poisoned"))?
            .get(self.key)
        {
            return Ok(identity);
        }

        let identity = Arc::new(self.inspect_identity()?);
        cache
            .lock()
            .map_err(|_| anyhow::anyhow!("Windows IPC process identity cache lock poisoned"))?
            .insert(identity.clone());
        Ok(identity)
    }

    fn fresh_identity(&self) -> ResultType<WindowsProcessImmutableIdentity> {
        self.inspect_identity()
    }

    fn live_token_authority(&self) -> ResultType<WindowsLiveTokenAuthority> {
        Ok(self.live_token_proof()?.authority)
    }

    fn live_token_proof(&self) -> ResultType<WindowsLiveTokenProof> {
        let mut token = HANDLE::default();
        unsafe {
            OpenProcessToken(self.handle.0, TOKEN_QUERY, &mut token).map_err(|err| {
                anyhow::anyhow!(
                    "Failed to open Windows IPC peer process token: pid={}, err={}",
                    self.key.pid,
                    err
                )
            })?;
        }
        let _token_guard = WindowsHandle(token);
        windows_live_token_proof(token)
    }
}

#[cfg(windows)]
impl WindowsProcessIdentityCache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: VecDeque::with_capacity(capacity),
        }
    }

    fn get(
        &mut self,
        key: WindowsProcessIdentityKey,
    ) -> Option<Arc<WindowsProcessImmutableIdentity>> {
        let index = self.entries.iter().position(|entry| entry.key == key)?;
        let entry = self.entries.remove(index)?;
        self.entries.push_back(entry.clone());
        Some(entry)
    }

    fn insert(&mut self, identity: Arc<WindowsProcessImmutableIdentity>) {
        if self.capacity == 0 {
            return;
        }
        self.entries
            .retain(|entry| entry.key.pid != identity.key.pid);
        self.entries.push_back(identity);
        while self.entries.len() > self.capacity {
            self.entries.pop_front();
        }
    }
}

#[cfg(windows)]
fn windows_process_creation_time(process: HANDLE) -> ResultType<u64> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe {
        GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user)
            .map_err(|err| anyhow::anyhow!("GetProcessTimes failed for Windows IPC peer: {err}"))?;
    }
    let creation_time = ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
    if creation_time == 0 {
        bail!("GetProcessTimes returned a zero creation time for Windows IPC peer");
    }
    Ok(creation_time)
}

#[cfg(windows)]
pub(crate) fn current_windows_process_identity_key() -> ResultType<WindowsProcessIdentityKey> {
    let pid = std::process::id();
    let process = WindowsPeerProcess::open(pid)?;
    Ok(process.key)
}

#[cfg(windows)]
fn windows_process_executable_path(process: HANDLE) -> ResultType<PathBuf> {
    const PROCESS_IMAGE_PATH_BUFFER_LEN: usize = 32 * 1024;
    let mut buffer = vec![0u16; PROCESS_IMAGE_PATH_BUFFER_LEN];
    let mut length = PROCESS_IMAGE_PATH_BUFFER_LEN as u32;
    unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )
        .map_err(|err| {
            anyhow::anyhow!("QueryFullProcessImageNameW failed for Windows IPC peer: {err}")
        })?;
    }
    if length == 0 || length as usize > buffer.len() {
        bail!(
            "QueryFullProcessImageNameW returned an invalid length for Windows IPC peer: {}",
            length
        );
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(OsString::from_wide(&buffer)))
}

#[cfg(windows)]
fn resolve_nt_query_information_process() -> Option<NtQueryInformationProcessFn> {
    const NTDLL: [u16; 10] = [
        b'n' as u16,
        b't' as u16,
        b'd' as u16,
        b'l' as u16,
        b'l' as u16,
        b'.' as u16,
        b'd' as u16,
        b'l' as u16,
        b'l' as u16,
        0,
    ];
    let module = unsafe { windows_get_module_handle_w(NTDLL.as_ptr()) };
    if module.is_null() {
        return None;
    }
    let procedure =
        unsafe { windows_get_proc_address(module, b"NtQueryInformationProcess\0".as_ptr()) };
    if procedure.is_null() {
        return None;
    }
    Some(unsafe { std::mem::transmute::<*mut c_void, NtQueryInformationProcessFn>(procedure) })
}

#[cfg(windows)]
fn windows_process_command_line(process: HANDLE) -> ResultType<Vec<u16>> {
    let query = NT_QUERY_INFORMATION_PROCESS
        .get_or_init(resolve_nt_query_information_process)
        .as_ref()
        .copied()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "NtQueryInformationProcess is unavailable for Windows IPC peer verification"
            )
        })?;
    let mut required = 0u32;
    let initial_status = unsafe {
        query(
            process,
            WINDOWS_PROCESS_COMMAND_LINE_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut required,
        )
    };
    if initial_status != STATUS_INFO_LENGTH_MISMATCH || required == 0 {
        bail!(
            "NtQueryInformationProcess command-line size query failed: status=0x{:08x}, required={}",
            initial_status as u32,
            required
        );
    }
    let required = required as usize;
    if required < std::mem::size_of::<UNICODE_STRING>()
        || required > WINDOWS_PROCESS_COMMAND_LINE_MAX_BYTES
    {
        bail!(
            "NtQueryInformationProcess returned an invalid command-line buffer size: {}",
            required
        );
    }
    let words = required
        .checked_add(std::mem::size_of::<usize>() - 1)
        .and_then(|size| size.checked_div(std::mem::size_of::<usize>()))
        .ok_or_else(|| anyhow::anyhow!("Windows IPC command-line buffer size overflow"))?;
    let mut buffer = vec![0usize; words];
    let buffer_bytes = buffer
        .len()
        .checked_mul(std::mem::size_of::<usize>())
        .ok_or_else(|| anyhow::anyhow!("Windows IPC command-line allocation overflow"))?;
    let mut returned = 0u32;
    let status = unsafe {
        query(
            process,
            WINDOWS_PROCESS_COMMAND_LINE_INFORMATION,
            buffer.as_mut_ptr() as *mut c_void,
            buffer_bytes as u32,
            &mut returned,
        )
    };
    if status < 0 {
        bail!(
            "NtQueryInformationProcess command-line query failed: status=0x{:08x}",
            status as u32
        );
    }
    if returned as usize > buffer_bytes
        || (returned as usize) < std::mem::size_of::<UNICODE_STRING>()
    {
        bail!(
            "NtQueryInformationProcess returned an invalid command-line result size: {}",
            returned
        );
    }
    let value = unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const UNICODE_STRING) };
    let length = value.Length as usize;
    if length == 0
        || length % std::mem::size_of::<u16>() != 0
        || length > value.MaximumLength as usize
    {
        bail!(
            "NtQueryInformationProcess returned invalid command-line string lengths: length={}, maximum={}",
            length,
            value.MaximumLength
        );
    }
    let start = buffer.as_ptr() as usize;
    let end = start
        .checked_add(returned as usize)
        .ok_or_else(|| anyhow::anyhow!("Windows IPC command-line result range overflow"))?;
    let string_start = value.Buffer.as_ptr() as usize;
    let string_end = string_start
        .checked_add(length)
        .ok_or_else(|| anyhow::anyhow!("Windows IPC command-line string range overflow"))?;
    if value.Buffer.is_null() || string_start < start || string_end > end {
        bail!("NtQueryInformationProcess returned an out-of-buffer command-line string");
    }
    Ok(unsafe {
        std::slice::from_raw_parts(value.Buffer.as_ptr(), length / std::mem::size_of::<u16>())
            .to_vec()
    })
}

#[cfg(windows)]
fn windows_process_command_line_args(process: HANDLE) -> ResultType<Vec<String>> {
    let mut command_line = windows_process_command_line(process)?;
    command_line.push(0);
    let mut count = 0i32;
    let argv = unsafe { CommandLineToArgvW(PCWSTR(command_line.as_ptr()), &mut count) };
    if argv.is_null() || count <= 0 || count > 256 {
        bail!(
            "CommandLineToArgvW returned an invalid argv for Windows IPC peer: count={}",
            count
        );
    }
    let _argv_guard = WindowsLocalMemory(argv as *mut c_void);
    let mut args = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        let argument = unsafe { *argv.add(index) };
        if argument.is_null() {
            bail!("CommandLineToArgvW returned a null argument at index {index}");
        }
        args.push(unsafe { argument.to_string() }.map_err(|err| {
            anyhow::anyhow!("Windows IPC peer argv[{index}] is invalid UTF-16: {err}")
        })?);
    }
    Ok(args)
}

#[cfg(windows)]
struct LocalString(PWSTR);

#[cfg(windows)]
struct WindowsLocalMemory(*mut c_void);

#[cfg(windows)]
impl Drop for LocalString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0.as_ptr() as *mut c_void)));
            }
        }
    }
}

#[cfg(windows)]
impl Drop for WindowsLocalMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0)));
            }
        }
    }
}

#[cfg(windows)]
#[derive(Clone, Copy)]
enum WindowsPipeClientTokenRequirement {
    Elevated,
    LocalSystem,
}

#[cfg(windows)]
impl WindowsPipeClientTokenRequirement {
    fn context(self) -> &'static str {
        match self {
            Self::Elevated => "Windows service-owned request caller",
            Self::LocalSystem => "Windows service-owned main IPC peer",
        }
    }

    fn is_satisfied(self, authority: WindowsLiveTokenAuthority) -> bool {
        match self {
            Self::Elevated => authority.is_elevated,
            Self::LocalSystem => authority.is_local_system,
        }
    }
}

#[cfg(windows)]
#[inline]
pub(crate) fn windows_named_pipe_client_access_mask() -> u32 {
    WINDOWS_NAMED_PIPE_CLIENT_ACCESS_MASK
}

#[cfg(windows)]
pub(crate) fn windows_ipc_listener_security_attributes(
    postfix: &str,
) -> ResultType<parity_tokio_ipc::SecurityAttributes> {
    let sddl = windows_ipc_listener_sddl(postfix)?;
    parity_tokio_ipc::SecurityAttributes::from_sddl(&sddl).map_err(|err| {
        anyhow::anyhow!(
            "Failed to build Windows IPC security descriptor for '{}': {}",
            postfix,
            err
        )
        .into()
    })
}

#[cfg(windows)]
pub(crate) fn windows_ipc_listener_sddl(postfix: &str) -> ResultType<String> {
    if !windows_ipc_postfix_uses_restricted_dacl(postfix) {
        bail!("Unsupported Windows IPC endpoint has no explicit DACL policy");
    }
    Ok(windows_restricted_ipc_sddl(
        &windows_ipc_dacl_sids_for_postfix(postfix)?,
    ))
}

#[cfg(windows)]
pub(crate) fn windows_sensitive_pipe_security(
    postfix: &str,
) -> ResultType<WindowsSensitivePipeSecurity> {
    windows_sensitive_pipe_security_inner(postfix, None)
}

#[cfg(windows)]
fn windows_sensitive_pipe_security_at_deadline(
    postfix: &str,
    deadline: Instant,
) -> ResultType<WindowsSensitivePipeSecurity> {
    windows_sensitive_pipe_security_inner(postfix, Some(deadline))
}

#[cfg(windows)]
fn windows_sensitive_pipe_security_inner(
    postfix: &str,
    deadline: Option<Instant>,
) -> ResultType<WindowsSensitivePipeSecurity> {
    if let Some(deadline) = deadline {
        windows_sensitive_auth_deadline_live(deadline, "Windows sensitive IPC security snapshot")?;
    }
    let current_token = current_process_token()?;
    let current = windows_live_token_proof(current_token.0)?;
    let mut sids = WindowsIpcDaclSids {
        server_sids: Vec::new(),
        client_sids: Vec::new(),
    };

    let (expected_client_principal, expected_session_id) = match postfix {
        super::password::USER_PASSWORD_IPC_POSTFIX => {
            if current.authority.is_local_system {
                bail!("Windows user password endpoint cannot be owned by LocalSystem");
            }
            sids.server_sids
                .push(current.principal.boundary_sid().to_owned());
            (
                Some(current.principal.clone()),
                Some(current.principal.session_id),
            )
        }
        super::password::SERVICE_PASSWORD_IPC_POSTFIX => {
            if !current.authority.is_local_system {
                bail!("Windows service password endpoint must be owned by LocalSystem");
            }
            sids.client_sids.push(INTERACTIVE_USERS_SID.to_owned());
            match stable_active_session_principal(deadline)? {
                Some((session_id, principal)) => (Some(principal), Some(session_id)),
                None => (None, None),
            }
        }
        _ => bail!("Unsupported Windows sensitive IPC endpoint"),
    };

    Ok(WindowsSensitivePipeSecurity {
        sddl: windows_restricted_ipc_sddl(&sids),
        expected_client_principal,
        expected_session_id,
    })
}

#[cfg(windows)]
fn windows_ipc_dacl_sids_for_postfix(postfix: &str) -> ResultType<WindowsIpcDaclSids> {
    if matches!(
        postfix,
        super::WINDOWS_SERVICE_CREDENTIAL_IPC_POSTFIX
            | super::WINDOWS_SERVICE_MAIN_CONTROL_IPC_POSTFIX
            | super::WINDOWS_SERVICE_SAS_IPC_POSTFIX
    ) {
        return Ok(WindowsIpcDaclSids {
            server_sids: Vec::new(),
            client_sids: Vec::new(),
        });
    }
    let mut server_sids = BTreeSet::new();
    let mut client_sids = BTreeSet::new();

    let current_token = current_process_token()?;
    if let Some(current_sid) = preferred_token_boundary_sid(current_token.0)? {
        if current_sid != LOCAL_SYSTEM_SID {
            server_sids.insert(current_sid);
        }
    }

    let session_id =
        crate::platform::windows::get_current_session_id(crate::platform::windows::is_share_rdp());
    if session_id != u32::MAX {
        match active_session_user_token(session_id) {
            Ok(token) => {
                if let Some(active_sid) = preferred_token_boundary_sid(token.0)? {
                    if active_sid != LOCAL_SYSTEM_SID {
                        client_sids.insert(active_sid);
                    }
                }
            }
            Err(err) => log::warn!(
                "Active-session IPC DACL sid unavailable for postfix '{}', session_id={}: {}",
                postfix,
                session_id,
                err
            ),
        }
    }

    for sid in &server_sids {
        client_sids.remove(sid);
    }
    Ok(WindowsIpcDaclSids {
        server_sids: server_sids.into_iter().collect(),
        client_sids: client_sids.into_iter().collect(),
    })
}

#[cfg(windows)]
fn current_process_token() -> ResultType<WindowsHandle> {
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|err| anyhow::anyhow!("OpenProcessToken(current) failed: {}", err))?;
    }
    Ok(WindowsHandle(token))
}

#[cfg(windows)]
fn active_session_user_token(session_id: u32) -> ResultType<WindowsHandle> {
    let token = crate::platform::windows::get_user_token(session_id, true);
    if token.is_null() {
        bail!("GetSessionUserTokenWin returned null");
    }
    Ok(WindowsHandle(HANDLE(token as *mut c_void)))
}

#[cfg(windows)]
fn stable_active_session_principal(
    deadline: Option<Instant>,
) -> ResultType<Option<(u32, WindowsTokenPrincipal)>> {
    let read_session = || {
        crate::platform::windows::get_current_session_id(crate::platform::windows::is_share_rdp())
    };
    let check_deadline = || match deadline {
        Some(deadline) => windows_sensitive_auth_deadline_live(
            deadline,
            "Windows active-session principal snapshot",
        ),
        None => Ok(()),
    };

    check_deadline()?;
    let session_before = read_session();
    if session_before == u32::MAX {
        check_deadline()?;
        if read_session() != u32::MAX {
            bail!("Windows active session appeared while its absence was being sampled");
        }
        return Ok(None);
    }

    let first_token = active_session_user_token(session_before)?;
    let first_principal = windows_token_principal(first_token.0)?;
    check_deadline()?;
    let session_between = read_session();
    if session_between != session_before || first_principal.session_id != session_before {
        bail!("Windows active session changed during its first principal sample");
    }

    let second_token = active_session_user_token(session_between)?;
    let second_principal = windows_token_principal(second_token.0)?;
    check_deadline()?;
    let session_after = read_session();
    if session_after != session_before
        || second_principal.session_id != session_before
        || second_principal != first_principal
    {
        bail!("Windows active session or principal changed while being sampled");
    }
    Ok(Some((session_after, second_principal)))
}

#[cfg(windows)]
fn preferred_token_boundary_sid(token: HANDLE) -> ResultType<Option<String>> {
    Ok(token_logon_sid_string(token)?.or(Some(token_user_sid_string(token)?)))
}

#[cfg(windows)]
fn token_information_buffer(
    token: HANDLE,
    token_information_class: TOKEN_INFORMATION_CLASS,
) -> ResultType<Vec<u8>> {
    let mut len = 0u32;
    let _ = unsafe { GetTokenInformation(token, token_information_class, None, 0, &mut len) };
    if len == 0 {
        bail!(
            "GetTokenInformation({:?}) did not return a buffer size: {}",
            token_information_class,
            std::io::Error::last_os_error()
        );
    }
    let mut buffer = vec![0u8; len as usize];
    unsafe {
        GetTokenInformation(
            token,
            token_information_class,
            Some(buffer.as_mut_ptr() as *mut c_void),
            len,
            &mut len,
        )
        .map_err(|err| {
            anyhow::anyhow!(
                "GetTokenInformation({:?}) failed: {}",
                token_information_class,
                err
            )
        })?;
    }
    if len as usize > buffer.len() {
        bail!(
            "GetTokenInformation({:?}) returned an oversized length: {} > {}",
            token_information_class,
            len,
            buffer.len()
        );
    }
    buffer.truncate(len as usize);
    Ok(buffer)
}

#[cfg(windows)]
fn token_user_sid_string(token: HANDLE) -> ResultType<String> {
    let buffer = token_information_buffer(token, TokenUser)?;
    if buffer.len() < std::mem::size_of::<TOKEN_USER>() {
        bail!(
            "GetTokenInformation(TokenUser) returned a short buffer: {}",
            buffer.len()
        );
    }
    let token_user = unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const TOKEN_USER) };
    sid_to_string(token_user.User.Sid)
}

#[cfg(windows)]
fn token_is_elevated(token: HANDLE) -> ResultType<bool> {
    let buffer = token_information_buffer(token, TokenElevation)?;
    if buffer.len() < std::mem::size_of::<TOKEN_ELEVATION>() {
        bail!(
            "GetTokenInformation(TokenElevation) returned a short buffer: {}",
            buffer.len()
        );
    }
    let elevation = unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const TOKEN_ELEVATION) };
    Ok(elevation.TokenIsElevated != 0)
}

#[cfg(windows)]
fn token_session_id(token: HANDLE) -> ResultType<u32> {
    let buffer = token_information_buffer(token, TokenSessionId)?;
    if buffer.len() < std::mem::size_of::<u32>() {
        bail!(
            "GetTokenInformation(TokenSessionId) returned a short buffer: {}",
            buffer.len()
        );
    }
    Ok(unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const u32) })
}

#[cfg(windows)]
fn windows_token_authority(token: HANDLE) -> ResultType<WindowsLiveTokenAuthority> {
    Ok(windows_live_token_proof(token)?.authority)
}

#[cfg(windows)]
fn windows_token_principal(token: HANDLE) -> ResultType<WindowsTokenPrincipal> {
    Ok(WindowsTokenPrincipal {
        user_sid: token_user_sid_string(token)?,
        logon_sid: token_logon_sid_string(token)?,
        session_id: token_session_id(token)?,
    })
}

#[cfg(windows)]
fn windows_live_token_proof(token: HANDLE) -> ResultType<WindowsLiveTokenProof> {
    let principal = windows_token_principal(token)?;
    Ok(WindowsLiveTokenProof {
        authority: WindowsLiveTokenAuthority {
            is_local_system: principal.user_sid == LOCAL_SYSTEM_SID,
            is_elevated: token_is_elevated(token)?,
            session_id: principal.session_id,
        },
        principal,
    })
}

#[cfg(windows)]
fn windows_token_authority_matches_sas_session(
    authority: WindowsLiveTokenAuthority,
    expected_session_id: u32,
) -> bool {
    authority.is_local_system && authority.session_id == expected_session_id
}

#[cfg(windows)]
fn token_logon_sid_string(token: HANDLE) -> ResultType<Option<String>> {
    let buffer = token_information_buffer(token, TokenGroups)?;
    if buffer.len() < std::mem::size_of::<TOKEN_GROUPS>() {
        bail!(
            "GetTokenInformation(TokenGroups) returned a short buffer: {}",
            buffer.len()
        );
    }
    let token_groups = buffer.as_ptr() as *const TOKEN_GROUPS;
    let group_count =
        unsafe { std::ptr::read_unaligned(std::ptr::addr_of!((*token_groups).GroupCount)) }
            as usize;
    let groups = unsafe { std::ptr::addr_of!((*token_groups).Groups) as *const SID_AND_ATTRIBUTES };
    let groups_offset = (groups as usize)
        .checked_sub(buffer.as_ptr() as usize)
        .ok_or_else(|| anyhow::anyhow!("TokenGroups array offset underflow"))?;
    let required = group_count
        .checked_mul(std::mem::size_of::<SID_AND_ATTRIBUTES>())
        .and_then(|size| groups_offset.checked_add(size))
        .ok_or_else(|| anyhow::anyhow!("TokenGroups array size overflow"))?;
    if required > buffer.len() {
        bail!(
            "GetTokenInformation(TokenGroups) returned a truncated group array: need {}, got {}",
            required,
            buffer.len()
        );
    }
    for index in 0..group_count {
        let group = unsafe { std::ptr::read_unaligned(groups.add(index)) };
        if (group.Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID {
            return sid_to_string(group.Sid).map(Some);
        }
    }
    Ok(None)
}

#[cfg(windows)]
fn sid_to_string(sid: PSID) -> ResultType<String> {
    if sid.is_invalid() {
        bail!("SID pointer is null");
    }
    let mut sid_string = PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(sid, &mut sid_string)
            .map_err(|err| anyhow::anyhow!("ConvertSidToStringSidW failed: {}", err))?;
    }
    if sid_string.is_null() {
        bail!("ConvertSidToStringSidW returned null");
    }
    let _sid_guard = LocalString(sid_string);
    let sid = unsafe { sid_string.to_string() }
        .map_err(|err| anyhow::anyhow!("Converted SID was not valid UTF-16: {}", err))?;
    if !is_numeric_sid_string(&sid) {
        bail!("Converted SID has unexpected SDDL form: {}", sid);
    }
    Ok(sid)
}

#[cfg(windows)]
fn is_numeric_sid_string(sid: &str) -> bool {
    sid.strip_prefix("S-")
        .is_some_and(|rest| rest.bytes().all(|b| b.is_ascii_digit() || b == b'-'))
}

#[cfg(windows)]
fn windows_restricted_ipc_sddl(sids: &WindowsIpcDaclSids) -> String {
    let mut sddl = String::from("D:P(D;;GA;;;NU)(A;;GA;;;SY)");
    for sid in &sids.server_sids {
        sddl.push_str(&format!("(A;;GA;;;{})", sid));
    }
    for sid in &sids.client_sids {
        sddl.push_str(&format!(
            "(A;;0x{:08x};;;{})",
            WINDOWS_NAMED_PIPE_CLIENT_ACCESS_MASK, sid
        ));
    }
    sddl
}

#[cfg(windows)]
pub(crate) fn ensure_windows_ipc_server_matches_current(
    client: &parity_tokio_ipc::ConnectionClient,
    postfix: &str,
) -> ResultType<()> {
    let server_pid = windows_named_pipe_server_pid(client)?;
    let process = WindowsPeerProcess::open(server_pid)?;
    let identity = process.immutable_identity()?;
    if matches!(
        postfix,
        super::WINDOWS_SERVICE_CREDENTIAL_IPC_POSTFIX
            | super::WINDOWS_SERVICE_MAIN_CONTROL_IPC_POSTFIX
    ) {
        ensure_windows_identity_matches_fixed_service(&identity, postfix)?;
        if !process.live_token_authority()?.is_local_system {
            bail!("Windows service-main IPC server is not running as LocalSystem");
        }
        if !windows_identity_has_exact_role(&identity, &windows_service_owned_main_server_args()) {
            bail!("Windows service-main IPC server has the wrong process role");
        }
    } else {
        ensure_windows_identity_matches_current(&identity, postfix)?;
        if postfix.is_empty() && !windows_identity_is_main_server(&identity) {
            bail!("Windows main IPC server has the wrong exact --server process role");
        }
        if hbb_common::config::is_service_ipc_postfix(postfix)
            || postfix == super::WINDOWS_SERVICE_SAS_IPC_POSTFIX
        {
            if !process.live_token_authority()?.is_local_system {
                bail!("Windows _service IPC server is not running as LocalSystem");
            }
            if !windows_identity_has_exact_role(&identity, &["--service"]) {
                bail!("Windows _service IPC server has the wrong exact process role");
            }
        }
    }
    if windows_named_pipe_server_pid(client)? != server_pid {
        bail!("Windows IPC named-pipe server pid changed during identity verification");
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) fn ensure_windows_service_main_server_pid(
    stream: &ConnectionTmpl<parity_tokio_ipc::ConnectionClient>,
    expected_identity: WindowsProcessIdentityKey,
) -> ResultType<()> {
    let server_pid = windows_named_pipe_server_pid(stream.inner.get_ref())?;
    if server_pid != expected_identity.pid {
        bail!(
            "Windows service-main IPC server pid mismatch: expected {}, got {}",
            expected_identity.pid,
            server_pid
        );
    }
    let process = WindowsPeerProcess::open(server_pid)?;
    if process.key != expected_identity {
        bail!(
            "Windows service-main IPC server process generation mismatch: pid={}, expected_creation={}, actual_creation={}",
            server_pid,
            expected_identity.creation_time,
            process.key.creation_time
        );
    }
    Ok(())
}

#[cfg(windows)]
fn windows_named_pipe_server_pid(client: &parity_tokio_ipc::ConnectionClient) -> ResultType<u32> {
    let pipe_handle = client.as_raw_handle();
    if pipe_handle.is_null() {
        bail!("Windows IPC client handle is null");
    }
    let mut server_pid = 0u32;
    unsafe {
        GetNamedPipeServerProcessId(HANDLE(pipe_handle), &mut server_pid)
            .map_err(|err| anyhow::anyhow!("GetNamedPipeServerProcessId failed: {}", err))?;
    }
    if server_pid == 0 {
        bail!("GetNamedPipeServerProcessId returned pid 0");
    }
    Ok(server_pid)
}

#[cfg(windows)]
fn windows_named_pipe_server_pid_from_handle(pipe: HANDLE) -> ResultType<u32> {
    if pipe.is_invalid() {
        bail!("Windows sensitive IPC client handle is invalid");
    }
    let mut server_pid = 0u32;
    unsafe {
        GetNamedPipeServerProcessId(pipe, &mut server_pid).map_err(|err| {
            anyhow::anyhow!("Failed to resolve Windows sensitive IPC server pid: {err}")
        })?;
    }
    if server_pid == 0 {
        bail!("Windows sensitive IPC server pid is zero");
    }
    Ok(server_pid)
}

#[cfg(windows)]
pub(crate) struct WindowsSensitivePipeClientProof {
    process: WindowsPeerProcess,
    identity: Arc<WindowsProcessImmutableIdentity>,
    process_token: WindowsLiveTokenProof,
    pipe_token: WindowsLiveTokenProof,
    security: WindowsSensitivePipeSecurity,
    require_elevated: bool,
    postfix: &'static str,
}

#[cfg(windows)]
impl WindowsSensitivePipeClientProof {
    pub(crate) fn revalidate(&self, pipe: HANDLE, deadline: Instant) -> ResultType<()> {
        windows_sensitive_auth_deadline_live(deadline, "Windows sensitive IPC client proof")?;
        if windows_named_pipe_client_pid(pipe)? != self.process.key.pid {
            bail!("Windows sensitive IPC client pid changed before admission");
        }
        self.process
            .require_running("Windows sensitive IPC client")?;
        if windows_process_creation_time(self.process.handle.0)? != self.process.key.creation_time {
            bail!("Windows sensitive IPC client process generation changed");
        }
        let current_identity = self.process.fresh_identity()?;
        if current_identity != *self.identity {
            bail!("Windows sensitive IPC client immutable identity changed");
        }
        require_windows_sensitive_password_client_role(&current_identity)?;
        let process_token = self.process.live_token_proof()?;
        let pipe_token = windows_named_pipe_client_token_proof(pipe, deadline)?;
        let current_security = windows_sensitive_pipe_security_at_deadline(self.postfix, deadline)?;
        if current_security != self.security {
            bail!("Windows sensitive IPC endpoint principal or session changed before admission");
        }
        let expected_principal = current_security
            .expected_client_principal
            .as_ref()
            .ok_or_else(|| {
                anyhow::anyhow!("Windows sensitive IPC endpoint has no active principal")
            })?;
        let authority_allowed = process_token.principal == *expected_principal
            && pipe_token.principal == *expected_principal
            && process_token == pipe_token
            && (!self.require_elevated
                || (process_token.authority.is_elevated && pipe_token.authority.is_elevated));
        if process_token != self.process_token
            || pipe_token != self.pipe_token
            || !authority_allowed
        {
            bail!("Windows sensitive IPC client authority changed before admission");
        }
        windows_sensitive_auth_deadline_live(deadline, "Windows sensitive IPC client proof")?;
        Ok(())
    }
}

#[cfg(windows)]
pub(crate) fn preauthorize_windows_sensitive_pipe_client(
    pipe: HANDLE,
    postfix: &'static str,
    security: &WindowsSensitivePipeSecurity,
    deadline: Instant,
) -> ResultType<()> {
    windows_sensitive_auth_deadline_live(
        deadline,
        "Windows sensitive IPC client preauthorization",
    )?;
    let require_elevated = match postfix {
        super::password::USER_PASSWORD_IPC_POSTFIX => false,
        super::password::SERVICE_PASSWORD_IPC_POSTFIX => true,
        _ => bail!("Unsupported Windows sensitive IPC server endpoint"),
    };
    if windows_sensitive_pipe_security_at_deadline(postfix, deadline)? != *security {
        bail!(
            "Windows sensitive IPC endpoint principal or session changed before preauthorization"
        );
    }
    let expected_principal = security
        .expected_client_principal
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Windows sensitive IPC endpoint has no active principal"))?;
    let process = WindowsPeerProcess::open(windows_named_pipe_client_pid(pipe)?)?;
    let identity = process.fresh_identity()?;
    ensure_windows_identity_matches_current(&identity, postfix)?;
    require_windows_sensitive_password_client_role(&identity)?;
    let process_token = process.live_token_proof()?;
    if process_token.principal != *expected_principal
        || (require_elevated && !process_token.authority.is_elevated)
    {
        bail!("Windows sensitive IPC client process token is not authorized for the endpoint");
    }
    process.require_running("Windows sensitive IPC client")?;
    windows_sensitive_auth_deadline_live(deadline, "Windows sensitive IPC client preauthorization")
}

#[cfg(windows)]
pub(crate) fn authorize_windows_sensitive_pipe_client(
    pipe: HANDLE,
    postfix: &'static str,
    security: &WindowsSensitivePipeSecurity,
    deadline: Instant,
) -> ResultType<WindowsSensitivePipeClientProof> {
    windows_sensitive_auth_deadline_live(deadline, "Windows sensitive IPC client authorization")?;
    let require_elevated = match postfix {
        super::password::USER_PASSWORD_IPC_POSTFIX => false,
        super::password::SERVICE_PASSWORD_IPC_POSTFIX => true,
        _ => bail!("Unsupported Windows sensitive IPC server endpoint"),
    };
    if windows_sensitive_pipe_security_at_deadline(postfix, deadline)? != *security {
        bail!("Windows sensitive IPC endpoint principal or session changed before authorization");
    }
    let expected_principal = security
        .expected_client_principal
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Windows sensitive IPC endpoint has no active principal"))?;
    let process = WindowsPeerProcess::open(windows_named_pipe_client_pid(pipe)?)?;
    let identity = process.immutable_identity()?;
    ensure_windows_identity_matches_current(&identity, postfix)?;
    require_windows_sensitive_password_client_role(&identity)?;
    let process_token = process.live_token_proof()?;
    let pipe_token = windows_named_pipe_client_token_proof(pipe, deadline)?;
    let authority_allowed = process_token.principal == *expected_principal
        && pipe_token.principal == *expected_principal
        && process_token == pipe_token
        && (!require_elevated
            || (process_token.authority.is_elevated && pipe_token.authority.is_elevated));
    if !authority_allowed {
        bail!("Windows sensitive IPC client token does not match the endpoint DACL principal");
    }
    process.require_running("Windows sensitive IPC client")?;
    let proof = WindowsSensitivePipeClientProof {
        process,
        identity,
        process_token,
        pipe_token,
        security: security.clone(),
        require_elevated,
        postfix,
    };
    proof.revalidate(pipe, deadline)?;
    Ok(proof)
}

#[cfg(windows)]
pub(crate) struct WindowsSensitivePipeServerProof {
    process: WindowsPeerProcess,
    identity: Arc<WindowsProcessImmutableIdentity>,
    server_token: WindowsLiveTokenProof,
    requester_principal: Option<WindowsTokenPrincipal>,
    postfix: &'static str,
}

#[cfg(windows)]
impl WindowsSensitivePipeServerProof {
    pub(crate) fn revalidate(&self, pipe: HANDLE, deadline: Instant) -> ResultType<()> {
        windows_sensitive_auth_deadline_live(deadline, "Windows sensitive IPC server proof")?;
        if windows_named_pipe_server_pid_from_handle(pipe)? != self.process.key.pid {
            bail!("Windows sensitive IPC server pid changed during transaction");
        }
        self.process
            .require_running("Windows sensitive IPC server")?;
        if windows_process_creation_time(self.process.handle.0)? != self.process.key.creation_time {
            bail!("Windows sensitive IPC server process generation changed");
        }
        let current_identity = self.process.fresh_identity()?;
        if current_identity != *self.identity {
            bail!("Windows sensitive IPC server immutable identity changed");
        }
        require_windows_sensitive_password_server_role(&current_identity, self.postfix)?;
        if self.process.live_token_proof()? != self.server_token {
            bail!("Windows sensitive IPC server authority changed during transaction");
        }
        if let Some(expected) = self.requester_principal.as_ref() {
            let current_token = current_process_token()?;
            if windows_token_principal(current_token.0)? != *expected {
                bail!("Windows sensitive IPC requesting principal changed during transaction");
            }
        }
        windows_sensitive_auth_deadline_live(deadline, "Windows sensitive IPC server proof")?;
        Ok(())
    }
}

#[cfg(windows)]
pub(crate) fn authenticate_windows_sensitive_pipe_server(
    pipe: HANDLE,
    postfix: &'static str,
    deadline: Instant,
) -> ResultType<WindowsSensitivePipeServerProof> {
    windows_sensitive_auth_deadline_live(deadline, "Windows sensitive IPC server authentication")?;
    let process = WindowsPeerProcess::open(windows_named_pipe_server_pid_from_handle(pipe)?)?;
    let identity = process.immutable_identity()?;
    let server_token = process.live_token_proof()?;
    let requester_principal = match postfix {
        super::password::USER_PASSWORD_IPC_POSTFIX => {
            ensure_windows_identity_matches_current(&identity, postfix)?;
            require_windows_sensitive_password_server_role(&identity, postfix)?;
            let current_token = current_process_token()?;
            let requester = windows_token_principal(current_token.0)?;
            if server_token.principal != requester {
                bail!(
                    "Windows sensitive main IPC server does not match the requesting user/logon/session principal"
                );
            }
            Some(requester)
        }
        super::password::SERVICE_PASSWORD_IPC_POSTFIX => {
            ensure_windows_identity_matches_fixed_service(&identity, postfix)?;
            if !server_token.authority.is_local_system {
                bail!("Windows sensitive service IPC server is not LocalSystem");
            }
            require_windows_sensitive_password_server_role(&identity, postfix)?;
            None
        }
        _ => bail!("Unsupported Windows sensitive IPC client endpoint"),
    };
    process.require_running("Windows sensitive IPC server")?;
    let proof = WindowsSensitivePipeServerProof {
        process,
        identity,
        server_token,
        requester_principal,
        postfix,
    };
    proof.revalidate(pipe, deadline)?;
    Ok(proof)
}

#[cfg(target_os = "macos")]
#[inline]
fn macos_installed_app_executable_path() -> PathBuf {
    let app_name = crate::get_app_name();
    PathBuf::from(format!(
        "/Applications/{app_name}.app/Contents/MacOS/{app_name}"
    ))
}

#[cfg(target_os = "macos")]
#[inline]
fn macos_installed_app_bundle_path() -> PathBuf {
    PathBuf::from(format!("/Applications/{}.app", crate::get_app_name()))
}

#[cfg(target_os = "macos")]
#[inline]
fn macos_installed_app_bundled_helper_path() -> PathBuf {
    macos_installed_app_bundle_path().join("Contents/MacOS/service")
}

#[cfg(target_os = "macos")]
fn macos_open_regular_file_no_follow(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(crate::libc::O_CLOEXEC | crate::libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(target_os = "macos")]
fn macos_regular_files_have_same_contents(left: &Path, right: &Path) -> bool {
    let (Ok(left_file), Ok(right_file)) = (
        macos_open_regular_file_no_follow(left),
        macos_open_regular_file_no_follow(right),
    ) else {
        return false;
    };
    let (Ok(left_metadata), Ok(right_metadata)) =
        (left_file.metadata(), right_file.metadata())
    else {
        return false;
    };
    if !left_metadata.is_file()
        || !right_metadata.is_file()
        || left_metadata.len() != right_metadata.len()
    {
        return false;
    }

    let mut left_file = BufReader::new(left_file);
    let mut right_file = BufReader::new(right_file);
    let mut left_buffer = [0u8; 64 * 1024];
    let mut right_buffer = [0u8; 64 * 1024];
    loop {
        let (Ok(left_read), Ok(right_read)) = (
            left_file.read(&mut left_buffer),
            right_file.read(&mut right_buffer),
        ) else {
            return false;
        };
        if left_read != right_read || left_buffer[..left_read] != right_buffer[..right_read] {
            return false;
        }
        if left_read == 0 {
            return true;
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_deployed_helper_matches_installed_app_bytes() -> bool {
    macos_regular_files_have_same_contents(
        Path::new(MACOS_PRIVILEGED_HELPER_EXEC),
        &macos_installed_app_bundled_helper_path(),
    )
}

#[cfg(target_os = "macos")]
#[inline]
fn macos_executable_matches_expected_path(actual: &Path, expected: &Path) -> bool {
    actual == expected || paths_refer_to_same_file(actual, expected)
}

#[cfg(target_os = "macos")]
#[inline]
fn macos_root_wheel_not_group_world_writable(metadata: &fs::Metadata) -> bool {
    metadata.uid() == 0 && metadata.gid() == 0 && metadata.permissions().mode() & 0o022 == 0
}

#[cfg(target_os = "macos")]
#[inline]
fn macos_root_owned_not_group_world_writable(metadata: &fs::Metadata) -> bool {
    metadata.uid() == 0 && metadata.permissions().mode() & 0o022 == 0
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_path_has_no_extended_acl(path: &Path) -> bool {
    let path_c = match CString::new(path.as_os_str().as_bytes().to_vec()) {
        Ok(path_c) => path_c,
        Err(err) => {
            log::error!(
                "Rejected macOS ACL inspection for path containing NUL '{}': {}",
                path.display(),
                err
            );
            return false;
        }
    };
    let acl = unsafe { acl_get_link_np(path_c.as_ptr(), MACOS_ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        log::error!(
            "Failed to retrieve macOS extended ACL for '{}': {}",
            path.display(),
            std::io::Error::last_os_error()
        );
        return false;
    }
    let _acl_guard = MacosAclGuard(acl);
    if unsafe { acl_valid_link_np(path_c.as_ptr(), MACOS_ACL_TYPE_EXTENDED, acl) } != 0 {
        log::error!(
            "Rejected invalid macOS extended ACL for '{}': {}",
            path.display(),
            std::io::Error::last_os_error()
        );
        return false;
    }
    let mut entry: MacosAclEntry = std::ptr::null_mut();
    (unsafe { acl_get_entry(acl, MACOS_ACL_FIRST_ENTRY, &mut entry) }) != 0
}

#[cfg(target_os = "macos")]
fn macos_path_has_expected_type_and_permissions(
    path: &Path,
    is_dir: bool,
    require_executable: bool,
    require_wheel: bool,
) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if metadata.file_type().is_symlink() {
        return false;
    }
    if is_dir {
        if !metadata.is_dir() {
            return false;
        }
    } else if !metadata.is_file() {
        return false;
    }
    if require_wheel {
        if !macos_root_wheel_not_group_world_writable(&metadata) {
            return false;
        }
    } else if !macos_root_owned_not_group_world_writable(&metadata) {
        return false;
    }
    if require_executable && metadata.permissions().mode() & 0o111 == 0 {
        return false;
    }
    macos_path_has_no_extended_acl(path)
}

#[cfg(target_os = "macos")]
fn macos_code_requirement(requirement: &str, description: &str) -> ResultType<MacosSecRequirement> {
    let requirement = requirement.strip_prefix('=').unwrap_or(requirement);
    requirement.parse::<MacosSecRequirement>().map_err(|err| {
        anyhow::anyhow!("Failed to parse macOS {description} code requirement: {err:?}").into()
    })
}

#[cfg(target_os = "macos")]
fn macos_static_code_satisfies_requirement(
    path: &Path,
    is_dir: bool,
    requirement: &str,
    description: &str,
) -> bool {
    let Some(url) = CFURL::from_path(path, is_dir) else {
        log::error!(
            "Failed to build macOS {description} code-signing URL for '{}'",
            path.display()
        );
        return false;
    };
    let requirement = match macos_code_requirement(requirement, description) {
        Ok(requirement) => requirement,
        Err(err) => {
            log::error!("{err}");
            return false;
        }
    };
    let code = match MacosSecStaticCode::from_path(&url, MacosCodeSigningFlags::NONE) {
        Ok(code) => code,
        Err(err) => {
            log::error!(
                "Failed to resolve macOS {description} static code '{}': {err:?}",
                path.display()
            );
            return false;
        }
    };
    let mut validation_flags =
        MacosCodeSigningFlags::STRICT_VALIDATE | MacosCodeSigningFlags::CHECK_ALL_ARCHITECTURES;
    if is_dir {
        validation_flags |= MacosCodeSigningFlags::CHECK_NESTED_CODE;
    }
    match code.check_validity(validation_flags, &requirement) {
        Ok(()) => true,
        Err(err) => {
            log::error!("macOS {description} static code-signing check failed: {err:?}");
            false
        }
    }
}

#[cfg(target_os = "macos")]
fn macos_peer_code(
    identity: &MacosPeerProcessIdentity,
    description: &str,
) -> ResultType<MacosSecCode> {
    let audit_token = CFData::from_buffer(&identity.audit_token);
    let mut attributes = MacosGuestAttributes::new();
    attributes.set_audit_token(audit_token.as_concrete_TypeRef());
    MacosSecCode::copy_guest_with_attribues(None, &attributes, MacosCodeSigningFlags::NONE)
        .map_err(|err| {
            anyhow::anyhow!(
                "Failed to resolve macOS {description} peer code from audit token: pid={}, uid={}, err={err:?}",
                identity.pid,
                identity.uid
            )
            .into()
        })
}

#[cfg(target_os = "macos")]
fn macos_peer_code_path(code: &MacosSecCode, description: &str) -> ResultType<PathBuf> {
    let url = code.path(MacosCodeSigningFlags::NONE).map_err(|err| {
        anyhow::anyhow!("Failed to resolve macOS {description} peer code path: {err:?}")
    })?;
    let path = url.to_path().ok_or_else(|| {
        anyhow::anyhow!("macOS {description} peer code path is not a filesystem path")
    })?;
    fs::canonicalize(&path).map_err(|err| {
        anyhow::anyhow!(
            "Failed to canonicalize macOS {description} peer code path '{}': {}",
            path.display(),
            err
        )
        .into()
    })
}

#[cfg(target_os = "macos")]
fn macos_peer_code_satisfies_requirement(
    code: &MacosSecCode,
    requirement: &str,
    description: &str,
) -> bool {
    let requirement = match macos_code_requirement(requirement, description) {
        Ok(requirement) => requirement,
        Err(err) => {
            log::error!("{err}");
            return false;
        }
    };
    match code.check_validity(MacosCodeSigningFlags::STRICT_VALIDATE, &requirement) {
        Ok(()) => true,
        Err(err) => {
            log::error!("macOS {description} peer code-signing check failed: {err:?}");
            false
        }
    }
}

#[cfg(target_os = "macos")]
#[inline]
fn macos_privileged_helper_satisfies_code_requirement(path: &Path) -> bool {
    macos_static_code_satisfies_requirement(
        path,
        false,
        MACOS_PRIVILEGED_HELPER_REQUIREMENT,
        "privileged helper",
    )
}

#[cfg(target_os = "macos")]
#[inline]
fn macos_installed_app_satisfies_code_requirement(path: &Path) -> bool {
    macos_static_code_satisfies_requirement(
        path,
        true,
        MACOS_INSTALLED_APP_REQUIREMENT,
        "installed app",
    )
}

#[cfg(target_os = "macos")]
#[inline]
fn macos_privileged_helper_path_is_expected_and_trusted(current_exe: &Path) -> bool {
    let expected = Path::new(MACOS_PRIVILEGED_HELPER_EXEC);
    if !macos_executable_matches_expected_path(current_exe, expected) {
        return false;
    }
    if !macos_path_has_expected_type_and_permissions(
        Path::new(MACOS_PRIVILEGED_HELPER_DIR),
        true,
        false,
        true,
    ) {
        return false;
    }
    if !macos_path_has_expected_type_and_permissions(expected, false, true, true) {
        return false;
    };
    macos_privileged_helper_satisfies_code_requirement(expected)
        && macos_installed_app_path_is_expected_and_trusted(&macos_installed_app_executable_path())
        && macos_deployed_helper_matches_installed_app_bytes()
}

#[cfg(target_os = "macos")]
#[inline]
fn macos_installed_app_path_is_expected_and_trusted(peer_exe: &Path) -> bool {
    let app_bundle = macos_installed_app_bundle_path();
    let app_contents = app_bundle.join("Contents");
    let app_macos = app_contents.join("MacOS");
    let app_executable = macos_installed_app_executable_path();
    if !macos_executable_matches_expected_path(peer_exe, &app_executable) {
        return false;
    }
    for app_dir in [&app_bundle, &app_contents, &app_macos] {
        if !macos_path_has_expected_type_and_permissions(app_dir, true, false, false) {
            return false;
        }
    }
    if !macos_path_has_expected_type_and_permissions(&app_executable, false, true, false) {
        return false;
    }
    macos_installed_app_satisfies_code_requirement(&app_bundle)
}

#[cfg(target_os = "macos")]
fn macos_peer_code_path_satisfies(
    identity: &MacosPeerProcessIdentity,
    requirement: &str,
    description: &str,
    path_is_trusted: impl FnOnce(&Path) -> bool,
) -> bool {
    let code = match macos_peer_code(identity, description) {
        Ok(code) => code,
        Err(err) => {
            log::error!("{err}");
            return false;
        }
    };
    if !macos_peer_code_satisfies_requirement(&code, requirement, description) {
        return false;
    }
    let path = match macos_peer_code_path(&code, description) {
        Ok(path) => path,
        Err(err) => {
            log::error!("{err}");
            return false;
        }
    };
    path_is_trusted(&path)
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_peer_is_trusted_installed_app(identity: &MacosPeerProcessIdentity) -> bool {
    macos_peer_code_path_satisfies(
        identity,
        MACOS_INSTALLED_APP_REQUIREMENT,
        "installed app",
        macos_installed_app_path_is_expected_and_trusted,
    )
}

#[cfg(target_os = "macos")]
fn macos_peer_is_trusted_privileged_helper(identity: &MacosPeerProcessIdentity) -> bool {
    macos_peer_code_path_satisfies(
        identity,
        MACOS_PRIVILEGED_HELPER_REQUIREMENT,
        "privileged helper",
        macos_privileged_helper_path_is_expected_and_trusted,
    )
}

#[cfg(target_os = "macos")]
#[inline]
fn macos_service_ipc_allows_installed_app_and_privileged_helper(
    peer_identity: &MacosPeerProcessIdentity,
    current_exe: &Path,
    postfix: &str,
) -> bool {
    hbb_common::config::is_service_ipc_postfix(postfix)
        && macos_peer_is_trusted_installed_app(peer_identity)
        && macos_privileged_helper_path_is_expected_and_trusted(current_exe)
}

#[cfg(target_os = "macos")]
pub(crate) struct MacosServiceServerAuthorization {
    identity: MacosPeerProcessIdentity,
    context: &'static str,
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_peer_process_identity_from_stream<T>(
    stream: &T,
    description: &str,
) -> ResultType<MacosPeerProcessIdentity>
where
    T: std::os::unix::io::AsRawFd,
{
    let fd = stream.as_raw_fd();
    Ok(MacosPeerProcessIdentity {
        uid: peer_uid_from_fd(fd)
            .ok_or_else(|| anyhow::anyhow!("Failed to resolve {description} uid"))?,
        pid: peer_pid_from_fd(fd)
            .ok_or_else(|| anyhow::anyhow!("Failed to resolve {description} effective pid"))?,
        audit_token: peer_audit_token_from_fd(fd)
            .ok_or_else(|| anyhow::anyhow!("Failed to resolve {description} audit token"))?,
    })
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_service_server_authorization_snapshot<T>(
    stream: &T,
    context: &'static str,
) -> ResultType<MacosServiceServerAuthorization>
where
    T: std::os::unix::io::AsRawFd,
{
    Ok(MacosServiceServerAuthorization {
        identity: macos_peer_process_identity_from_stream(stream, context)?,
        context,
    })
}

#[cfg(target_os = "macos")]
pub(crate) fn authorize_macos_service_server_snapshot(
    authorization: MacosServiceServerAuthorization,
) -> ResultType<()> {
    if authorization.identity.uid != 0 {
        bail!(
            "{} is not root: peer_uid={}",
            authorization.context,
            authorization.identity.uid
        );
    }
    if !macos_peer_is_trusted_privileged_helper(&authorization.identity) {
        bail!(
            "{} is not the trusted privileged helper: peer_pid={}",
            authorization.context,
            authorization.identity.pid
        );
    }
    Ok(())
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

#[cfg(target_os = "linux")]
#[inline]
fn active_uid_cached() -> Option<u32> {
    let reported_uid_raw = crate::platform::linux::get_active_userid_cached()?;
    let trimmed = reported_uid_raw.trim();
    if let Ok(uid) = trimmed.parse::<u32>() {
        return Some(uid);
    }
    if trimmed.is_empty() {
        log::debug!("R-S11at: cached active uid is empty");
    } else {
        log::warn!(
            "R-S11at: failed to parse cached active uid: '{}'",
            trimmed
        );
    }
    None
}

#[cfg(target_os = "linux")]
#[inline]
fn linux_service_peer_requires_fresh_active_uid_lookup(
    peer_uid: Option<u32>,
    cached_active_uid: Option<u32>,
) -> bool {
    matches!(
        (peer_uid, cached_active_uid),
        (Some(peer_uid), Some(active_uid)) if peer_uid != 0 && peer_uid == active_uid
    )
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
                libc::LOCAL_PEEREPID,
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

#[cfg(target_os = "macos")]
#[inline]
fn peer_audit_token_from_fd(fd: RawFd) -> Option<[u8; MACOS_AUDIT_TOKEN_BYTES]> {
    let mut token = [0u8; MACOS_AUDIT_TOKEN_BYTES];
    let mut len = token.len() as _;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 && len as usize == token.len() {
        Some(token)
    } else {
        None
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

#[cfg(target_os = "linux")]
#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct PeerProcessIdentity {
    pid: u32,
    uid: u32,
    start_time: String,
    first_arg: String,
    cm_launch_token: String,
    cm_launch_parent: u32,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for PeerProcessIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerProcessIdentity")
            .field("pid", &self.pid)
            .field("uid", &self.uid)
            .field("start_time", &self.start_time)
            .field("first_arg", &self.first_arg)
            .field("cm_launch_token", &"<redacted>")
            .field("cm_launch_parent", &self.cm_launch_parent)
            .finish()
    }
}

#[cfg(target_os = "linux")]
impl PeerProcessIdentity {
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }

    pub(crate) fn start_time(&self) -> &str {
        &self.start_time
    }

    #[cfg(test)]
    pub(crate) fn for_test(pid: u32, uid: u32, start_time: String, first_arg: String) -> Self {
        Self {
            pid,
            uid,
            start_time,
            first_arg,
            cm_launch_token: String::new(),
            cm_launch_parent: 0,
        }
    }
}

/// Kernel-visible Linux process identity used across a nondumpable helper boundary.
///
/// Unlike `PeerProcessIdentity`, this type deliberately contains no executable, argv, or
/// environment-derived fields. Those `/proc` surfaces are ptrace-gated and are therefore
/// unavailable to the same-UID server/connection-manager pair after the installed service child
/// becomes nondumpable. The socket credential supplies PID/UID and `/proc/<pid>/stat` supplies the
/// non-reused start identity; protected helper admission additionally requires the exact direct
/// parent relationship.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct LinuxProcessIdentity {
    pid: u32,
    uid: u32,
    start_time: String,
}

#[cfg(target_os = "linux")]
impl LinuxProcessIdentity {
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }

    #[cfg(test)]
    pub(crate) fn for_test(pid: u32, uid: u32, start_time: String) -> Self {
        Self {
            pid,
            uid,
            start_time,
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_proc_stat_start_time(pid: u32, stat: &str) -> ResultType<String> {
    let Some((_, after_comm)) = stat.rsplit_once(") ") else {
        bail!("Failed to parse /proc/{pid}/stat: missing command terminator");
    };
    let fields: Vec<_> = after_comm.split_whitespace().collect();
    let Some(start_time) = fields.get(19) else {
        bail!("Failed to parse /proc/{pid}/stat: missing start time");
    };
    Ok((*start_time).to_owned())
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_proc_start_time(pid: u32) -> ResultType<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    linux_proc_stat_start_time(pid, &stat)
}

#[cfg(target_os = "linux")]
fn linux_proc_parent_pid(pid: u32) -> ResultType<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let Some((_, after_comm)) = stat.rsplit_once(") ") else {
        bail!("Failed to parse /proc/{pid}/stat: missing command terminator");
    };
    let fields: Vec<_> = after_comm.split_whitespace().collect();
    let Some(ppid) = fields.get(1) else {
        bail!("Failed to parse /proc/{pid}/stat: missing parent pid");
    };
    ppid.parse::<u32>()
        .map_err(|err| anyhow::anyhow!("Failed to parse /proc/{pid}/stat parent pid: {err}"))
}

#[cfg(target_os = "linux")]
fn linux_kernel_process_identity_by_pid(pid: u32) -> ResultType<LinuxProcessIdentity> {
    if pid == 0 {
        bail!("invalid Linux process pid");
    }
    Ok(LinuxProcessIdentity {
        pid,
        uid: linux_proc_uid(pid)?,
        start_time: linux_proc_start_time(pid)?,
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn current_linux_process_identity() -> ResultType<LinuxProcessIdentity> {
    linux_kernel_process_identity_by_pid(std::process::id())
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_kernel_peer_process_identity<T>(
    stream: &ConnectionTmpl<T>,
    postfix: &str,
) -> ResultType<LinuxProcessIdentity>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::os::unix::io::AsRawFd,
{
    let peer_pid = stream.peer_pid().ok_or_else(|| {
        anyhow::anyhow!("Failed to resolve peer pid on ipc channel '{}'", postfix)
    })?;
    let peer_uid = stream.peer_uid().ok_or_else(|| {
        anyhow::anyhow!("Failed to resolve peer uid on ipc channel '{}'", postfix)
    })?;
    let identity = linux_kernel_process_identity_by_pid(peer_pid)?;
    if identity.uid != peer_uid {
        bail!(
            "Peer uid changed while authenticating ipc channel '{}': pid={}, socket_uid={}, proc_uid={}",
            postfix,
            peer_pid,
            peer_uid,
            identity.uid
        );
    }
    Ok(identity)
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_process_identity_is_live(identity: &LinuxProcessIdentity) -> bool {
    linux_kernel_process_identity_by_pid(identity.pid)
        .map(|live| live == *identity)
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
pub(crate) fn ensure_linux_process_identity_matches<T>(
    stream: &ConnectionTmpl<T>,
    expected: &LinuxProcessIdentity,
    postfix: &str,
) -> ResultType<()>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::os::unix::io::AsRawFd,
{
    let observed = linux_kernel_peer_process_identity(stream, postfix)?;
    if &observed != expected {
        bail!(
            "IPC peer identity mismatch on '{}': expected {:?}, got {:?}",
            postfix,
            expected,
            observed
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_cm_child_identity_is_live(
    identity: &LinuxProcessIdentity,
    expected_parent: u32,
) -> bool {
    expected_parent > 0
        && linux_process_identity_is_live(identity)
        && linux_proc_parent_pid(identity.pid).is_ok_and(|parent| parent == expected_parent)
}

#[cfg(target_os = "linux")]
pub(crate) fn authenticate_cm_endpoint<T>(
    stream: &ConnectionTmpl<T>,
    expected_uid: u32,
    expected_parent: u32,
) -> ResultType<LinuxProcessIdentity>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::os::unix::io::AsRawFd,
{
    if expected_parent == 0 {
        bail!("connection-manager launch parent is unavailable");
    }
    let identity = linux_kernel_peer_process_identity(stream, "_cm")?;
    if identity.uid != expected_uid {
        bail!(
            "_cm endpoint uid mismatch: expected {}, got {}",
            expected_uid,
            identity.uid
        );
    }
    let actual_parent = linux_proc_parent_pid(identity.pid)?;
    if actual_parent != expected_parent {
        bail!(
            "_cm endpoint parent mismatch: expected {}, got {}",
            expected_parent,
            actual_parent
        );
    }
    Ok(identity)
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_cm_owner_identity() -> ResultType<LinuxProcessIdentity> {
    let expected_parent = std::env::var(crate::common::CM_LAUNCH_PARENT_ENV)
        .map_err(|_| anyhow::anyhow!("connection-manager launch parent is unavailable"))?
        .parse::<u32>()
        .map_err(|err| anyhow::anyhow!("connection-manager launch parent is invalid: {err}"))?;
    if expected_parent == 0 {
        bail!("connection-manager launch parent is invalid");
    }
    let actual_parent = linux_proc_parent_pid(std::process::id())?;
    if actual_parent != expected_parent {
        bail!(
            "connection-manager owner changed: expected {}, got {}",
            expected_parent,
            actual_parent
        );
    }
    linux_kernel_process_identity_by_pid(expected_parent)
}

#[cfg(target_os = "linux")]
pub(crate) fn authenticate_linux_cm_owner_stream<T>(
    stream: &ConnectionTmpl<T>,
) -> ResultType<LinuxProcessIdentity>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::os::unix::io::AsRawFd,
{
    let expected = linux_cm_owner_identity()?;
    ensure_linux_process_identity_matches(stream, &expected, "")?;
    Ok(expected)
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_whiteboard_owner_identity(
    expected_parent: u32,
) -> ResultType<LinuxProcessIdentity> {
    if expected_parent == 0 {
        bail!("whiteboard launch parent is unavailable");
    }
    let actual_parent = linux_proc_parent_pid(std::process::id())?;
    if actual_parent != expected_parent {
        bail!(
            "whiteboard owner changed: expected {}, got {}",
            expected_parent,
            actual_parent
        );
    }
    linux_kernel_process_identity_by_pid(expected_parent)
}

#[cfg(target_os = "linux")]
pub(crate) fn authenticate_linux_whiteboard_owner_stream<T>(
    stream: &ConnectionTmpl<T>,
    expected_parent: u32,
) -> ResultType<LinuxProcessIdentity>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::os::unix::io::AsRawFd,
{
    let expected = linux_whiteboard_owner_identity(expected_parent)?;
    ensure_linux_process_identity_matches(stream, &expected, "_whiteboard")?;
    Ok(expected)
}

#[cfg(target_os = "linux")]
fn linux_process_has_ancestor(pid: u32, ancestor_pid: u32) -> bool {
    if pid == 0 || ancestor_pid == 0 {
        return false;
    }
    let mut current = pid;
    for _ in 0..128 {
        let Ok(parent) = linux_proc_parent_pid(current) else {
            return false;
        };
        if parent == ancestor_pid {
            return true;
        }
        if parent == 0 || parent == 1 || parent == current {
            return false;
        }
        current = parent;
    }
    false
}

#[cfg(target_os = "linux")]
fn linux_proc_cmdline_args(pid: u32) -> ResultType<Vec<String>> {
    let cmdline = fs::read(format!("/proc/{pid}/cmdline"))?;
    Ok(cmdline
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn user_owned_main_server_argv_is_expected(args: &[String]) -> bool {
    args.len() == 2 && args.get(1).map(String::as_str) == Some("--server")
}

#[cfg(target_os = "linux")]
fn validate_linux_root_service_peer(
    peer_uid: Option<u32>,
    peer_pid: Option<u32>,
    postfix: &str,
) -> ResultType<u32> {
    let peer_uid = peer_uid.ok_or_else(|| {
        anyhow::anyhow!("Failed to resolve Linux root service uid on ipc channel '{postfix}'")
    })?;
    if peer_uid != 0 {
        bail!(
            "Linux root service uid mismatch on ipc channel '{}': peer_uid={}",
            postfix,
            peer_uid
        );
    }
    let peer_pid = peer_pid.ok_or_else(|| {
        anyhow::anyhow!("Failed to resolve Linux root service pid on ipc channel '{postfix}'")
    })?;
    if peer_pid == 0 {
        bail!("Linux root service has pid 0 on ipc channel '{postfix}'");
    }
    Ok(peer_pid)
}

/// Authenticate a connected Linux service endpoint from kernel socket credentials only.
///
/// An unprivileged installed-service client cannot inspect the root service's ptrace-gated
/// executable, argv, or environment. The fixed service socket lives in the separately hardened
/// root-owned service IPC directory; after connecting, a positive uid-0 `SO_PEERCRED` identity is
/// the exact authority available to this side of the boundary. A process that can impersonate that
/// identity is already inside the root authority boundary.
#[cfg(target_os = "linux")]
pub(crate) fn ensure_linux_root_service_connection<T>(
    stream: &ConnectionTmpl<T>,
    postfix: &str,
) -> ResultType<u32>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::os::unix::io::AsRawFd,
{
    validate_linux_root_service_peer(stream.peer_uid(), stream.peer_pid(), postfix)
}

#[cfg(target_os = "linux")]
pub(crate) fn ensure_linux_root_service_stream<T>(stream: &T, postfix: &str) -> ResultType<u32>
where
    T: std::os::unix::io::AsRawFd,
{
    let fd = stream.as_raw_fd();
    validate_linux_root_service_peer(peer_uid_from_fd(fd), peer_pid_from_fd(fd), postfix)
}

#[cfg(target_os = "macos")]
fn macos_process_cmdline_args(pid: u32) -> ResultType<Vec<String>> {
    let mut sys = hbb_common::sysinfo::System::new_all();
    sys.refresh_processes();
    sys.processes()
        .values()
        .find(|process| process.pid().as_u32() == pid)
        .map(|process| process.cmd().to_vec())
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve macOS process argv: pid={pid}"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main_server_cmdline_args(pid: u32) -> ResultType<Vec<String>> {
    #[cfg(target_os = "linux")]
    {
        linux_proc_cmdline_args(pid)
    }
    #[cfg(target_os = "macos")]
    {
        macos_process_cmdline_args(pid)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn ensure_user_owned_main_server_is_trusted<T>(
    stream: &ConnectionTmpl<T>,
) -> ResultType<()>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::os::unix::io::AsRawFd,
{
    let peer_uid = stream
        .peer_uid()
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve user-owned main IPC server uid"))?;
    let current_uid = unsafe { libc::geteuid() as u32 };
    if peer_uid != current_uid {
        bail!(
            "user-owned main IPC server uid mismatch: peer_uid={}, current_uid={}",
            peer_uid,
            current_uid
        );
    }
    let peer_pid = stream
        .peer_pid()
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve user-owned main IPC server pid"))?;
    ensure_peer_executable_matches_current_by_pid(peer_pid, "")?;
    let args = main_server_cmdline_args(peer_pid)?;
    if !user_owned_main_server_argv_is_expected(&args) {
        bail!(
            "user-owned main IPC server argv mismatch: pid={}, args={:?}",
            peer_pid,
            args
        );
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn ensure_user_owned_password_client_is_trusted<T>(
    stream: &T,
    postfix: &str,
) -> ResultType<()>
where
    T: std::os::unix::io::AsRawFd,
{
    let fd = stream.as_raw_fd();
    let peer_uid = peer_uid_from_fd(fd)
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve user password IPC client uid"))?;
    let current_uid = unsafe { libc::geteuid() as u32 };
    if peer_uid != current_uid {
        bail!(
            "user password IPC client uid mismatch: peer_uid={}, current_uid={}",
            peer_uid,
            current_uid
        );
    }
    let peer_pid = peer_pid_from_fd(fd)
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve user password IPC client pid"))?;
    ensure_peer_executable_matches_current_by_pid(peer_pid, postfix)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn ensure_user_owned_password_server_is_trusted<T>(
    stream: &T,
    expected_uid: u32,
) -> ResultType<()>
where
    T: std::os::unix::io::AsRawFd,
{
    let fd = stream.as_raw_fd();
    let peer_uid = peer_uid_from_fd(fd)
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve user password IPC server uid"))?;
    if peer_uid != expected_uid {
        bail!(
            "user password IPC server uid mismatch: peer_uid={}, expected_uid={}",
            peer_uid,
            expected_uid
        );
    }
    let peer_pid = peer_pid_from_fd(fd)
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve user password IPC server pid"))?;
    ensure_peer_executable_matches_current_by_pid(
        peer_pid,
        super::password::USER_PASSWORD_IPC_POSTFIX,
    )?;
    let args = main_server_cmdline_args(peer_pid)?;
    if !user_owned_main_server_argv_is_expected(&args) {
        bail!(
            "user password IPC server argv mismatch: pid={}, args={:?}",
            peer_pid,
            args
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_proc_environ_value(pid: u32, name: &str) -> ResultType<String> {
    if name.is_empty() || name.as_bytes().contains(&b'=') {
        bail!("invalid environment key");
    }
    let environ = fs::read(format!("/proc/{pid}/environ"))?;
    let prefix = format!("{name}=");
    for part in environ.split(|byte| *byte == 0) {
        if part.starts_with(prefix.as_bytes()) {
            return Ok(String::from_utf8_lossy(&part[prefix.len()..]).into_owned());
        }
    }
    Ok(String::new())
}

#[cfg(target_os = "linux")]
fn linux_proc_uid(pid: u32) -> ResultType<u32> {
    let metadata = fs::metadata(format!("/proc/{pid}"))?;
    Ok(metadata.uid())
}

#[cfg(target_os = "linux")]
fn linux_proc_u32_env(pid: u32, name: &str) -> ResultType<u32> {
    let value = linux_proc_environ_value(pid, name)?;
    if value.is_empty() {
        return Ok(0);
    }
    value
        .parse::<u32>()
        .map_err(|err| anyhow::anyhow!("Failed to parse environment key {name}: {err}"))
}

#[cfg(target_os = "linux")]
fn linux_process_identity_by_pid(pid: u32, postfix: &str) -> ResultType<PeerProcessIdentity> {
    if pid == 0 {
        bail!("invalid pid 0 on ipc channel '{}'", postfix);
    }
    ensure_peer_executable_matches_current_by_pid(pid, postfix)?;
    linux_process_identity_fields_by_pid(pid)
}

#[cfg(target_os = "linux")]
fn linux_process_identity_fields_by_pid(pid: u32) -> ResultType<PeerProcessIdentity> {
    let args = linux_proc_cmdline_args(pid)?;
    Ok(PeerProcessIdentity {
        pid,
        uid: linux_proc_uid(pid)?,
        start_time: linux_proc_start_time(pid)?,
        first_arg: args.get(1).cloned().unwrap_or_default(),
        cm_launch_token: linux_proc_environ_value(pid, crate::common::CM_LAUNCH_TOKEN_ENV)?,
        cm_launch_parent: linux_proc_u32_env(pid, crate::common::CM_LAUNCH_PARENT_ENV)?,
    })
}

#[cfg(target_os = "linux")]
fn linux_service_child_process_identity_by_pid(
    pid: u32,
    postfix: &str,
) -> ResultType<PeerProcessIdentity> {
    if pid == 0 {
        bail!("invalid service-child pid 0 on ipc channel '{}'", postfix);
    }
    if !crate::platform::linux::service_child_executable_identity_matches(pid)? {
        bail!(
            "Service-child executable identity mismatch on ipc channel '{}': pid={}",
            postfix,
            pid
        );
    }
    linux_process_identity_fields_by_pid(pid)
}

#[cfg(target_os = "linux")]
pub(crate) fn peer_process_identity<T>(
    stream: &ConnectionTmpl<T>,
    postfix: &str,
) -> ResultType<PeerProcessIdentity>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::os::unix::io::AsRawFd,
{
    let peer_pid = stream.peer_pid().ok_or_else(|| {
        anyhow::anyhow!("Failed to resolve peer pid on ipc channel '{}'", postfix)
    })?;
    let peer_uid = stream.peer_uid().ok_or_else(|| {
        anyhow::anyhow!("Failed to resolve peer uid on ipc channel '{}'", postfix)
    })?;
    let identity = linux_process_identity_by_pid(peer_pid, postfix)?;
    if identity.uid != peer_uid {
        bail!(
            "Peer uid changed while authenticating ipc channel '{}': pid={}, socket_uid={}, proc_uid={}",
            postfix,
            peer_pid,
            peer_uid,
            identity.uid
        );
    }
    Ok(identity)
}

#[cfg(target_os = "linux")]
pub(crate) fn peer_process_identity_from_stream<T>(
    stream: &T,
    postfix: &str,
) -> ResultType<PeerProcessIdentity>
where
    T: std::os::unix::io::AsRawFd,
{
    let fd = stream.as_raw_fd();
    let peer_pid = peer_pid_from_fd(fd).ok_or_else(|| {
        anyhow::anyhow!("Failed to resolve peer pid on ipc channel '{}'", postfix)
    })?;
    let peer_uid = peer_uid_from_fd(fd).ok_or_else(|| {
        anyhow::anyhow!("Failed to resolve peer uid on ipc channel '{}'", postfix)
    })?;
    let identity = linux_process_identity_by_pid(peer_pid, postfix)?;
    if identity.uid != peer_uid {
        bail!(
            "Peer uid changed while authenticating ipc channel '{}': pid={}, socket_uid={}, proc_uid={}",
            postfix,
            peer_pid,
            peer_uid,
            identity.uid
        );
    }
    Ok(identity)
}

#[cfg(target_os = "linux")]
fn service_child_peer_process_identity<T>(
    stream: &ConnectionTmpl<T>,
    postfix: &str,
) -> ResultType<PeerProcessIdentity>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::os::unix::io::AsRawFd,
{
    let peer_pid = stream.peer_pid().ok_or_else(|| {
        anyhow::anyhow!(
            "Failed to resolve service-child pid on ipc channel '{}'",
            postfix
        )
    })?;
    let peer_uid = stream.peer_uid().ok_or_else(|| {
        anyhow::anyhow!(
            "Failed to resolve service-child uid on ipc channel '{}'",
            postfix
        )
    })?;
    let identity = linux_service_child_process_identity_by_pid(peer_pid, postfix)?;
    if identity.uid != peer_uid {
        bail!(
            "Service-child uid changed on ipc channel '{}': pid={}, socket_uid={}, proc_uid={}",
            postfix,
            peer_pid,
            peer_uid,
            identity.uid
        );
    }
    Ok(identity)
}

#[cfg(target_os = "linux")]
fn service_child_peer_process_identity_from_stream<T>(
    stream: &T,
    postfix: &str,
) -> ResultType<PeerProcessIdentity>
where
    T: std::os::unix::io::AsRawFd,
{
    let fd = stream.as_raw_fd();
    let peer_pid = peer_pid_from_fd(fd).ok_or_else(|| {
        anyhow::anyhow!(
            "Failed to resolve service-child pid on ipc channel '{}'",
            postfix
        )
    })?;
    let peer_uid = peer_uid_from_fd(fd).ok_or_else(|| {
        anyhow::anyhow!(
            "Failed to resolve service-child uid on ipc channel '{}'",
            postfix
        )
    })?;
    let identity = linux_service_child_process_identity_by_pid(peer_pid, postfix)?;
    if identity.uid != peer_uid {
        bail!(
            "Service-child uid changed on ipc channel '{}': pid={}, socket_uid={}, proc_uid={}",
            postfix,
            peer_pid,
            peer_uid,
            identity.uid
        );
    }
    Ok(identity)
}

#[cfg(target_os = "linux")]
fn linux_service_owned_server_argv_is_expected(args: &[String]) -> bool {
    args.len() == 3
        && args.get(1).map(String::as_str) == Some("--server")
        && args.get(2).map(String::as_str) == Some(crate::common::SERVICE_OWNED_SERVER_ARG)
}

#[cfg(target_os = "linux")]
pub(crate) fn authenticate_linux_service_owned_main_server<T>(
    stream: &ConnectionTmpl<T>,
) -> ResultType<PeerProcessIdentity>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::os::unix::io::AsRawFd,
{
    let identity = service_child_peer_process_identity(stream, "")?;
    let args = linux_proc_cmdline_args(identity.pid)?;
    if !linux_service_owned_server_argv_is_expected(&args) {
        bail!(
            "service-owned main server argv mismatch: pid={}, args={:?}",
            identity.pid,
            args
        );
    }
    let expected_parent = std::process::id();
    let launch_parent = linux_proc_u32_env(
        identity.pid,
        crate::common::SERVICE_OWNED_SERVER_LAUNCH_PARENT_ENV,
    )?;
    let actual_parent = linux_proc_parent_pid(identity.pid)?;
    let generation = linux_proc_environ_value(
        identity.pid,
        crate::common::SERVICE_OWNED_SERVER_GENERATION_ENV,
    )?;
    if launch_parent != expected_parent
        || actual_parent != expected_parent
        || !crate::platform::linux::service_runtime_generation_matches(&generation)
    {
        bail!(
            "service-owned main server owner mismatch: pid={}, expected_parent={}, actual_parent={}, launch_parent={}",
            identity.pid,
            expected_parent,
            actual_parent,
            launch_parent
        );
    }
    Ok(identity)
}

#[cfg(target_os = "linux")]
pub(crate) fn authenticate_linux_service_owned_password_parent<T>(
    stream: &T,
    postfix: &str,
) -> ResultType<()>
where
    T: std::os::unix::io::AsRawFd,
{
    let fd = stream.as_raw_fd();
    let peer_uid = peer_uid_from_fd(fd)
        .ok_or_else(|| anyhow::anyhow!("service-owned parent uid is unavailable for {postfix}"))?;
    if peer_uid != 0 {
        bail!("service-owned password parent is not root");
    }
    let peer_pid = peer_pid_from_fd(fd)
        .filter(|pid| *pid > 0)
        .ok_or_else(|| anyhow::anyhow!("service-owned parent pid is unavailable for {postfix}"))?;
    let expected_parent = std::env::var(crate::common::SERVICE_OWNED_SERVER_LAUNCH_PARENT_ENV)
        .map_err(|_| anyhow::anyhow!("service-owned server launch parent is unavailable"))?
        .parse::<u32>()
        .map_err(|err| anyhow::anyhow!("service-owned server launch parent is invalid: {err}"))?;
    let actual_parent = linux_proc_parent_pid(std::process::id())?;
    if peer_pid != expected_parent || actual_parent != expected_parent {
        bail!(
            "service-owned password parent identity mismatch: expected={}, actual={}, process_parent={}",
            expected_parent,
            peer_pid,
            actual_parent
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn authenticate_linux_service_owned_password_replica_server<T>(
    stream: &T,
    postfix: &str,
) -> ResultType<PeerProcessIdentity>
where
    T: std::os::unix::io::AsRawFd,
{
    let identity = service_child_peer_process_identity_from_stream(stream, postfix)?;
    let args = linux_proc_cmdline_args(identity.pid)?;
    if !linux_service_owned_server_argv_is_expected(&args) {
        bail!(
            "service-owned password replica argv mismatch: pid={}, args={:?}",
            identity.pid,
            args
        );
    }
    let expected_parent = std::process::id();
    let launch_parent = linux_proc_u32_env(
        identity.pid,
        crate::common::SERVICE_OWNED_SERVER_LAUNCH_PARENT_ENV,
    )?;
    let actual_parent = linux_proc_parent_pid(identity.pid)?;
    let generation = linux_proc_environ_value(
        identity.pid,
        crate::common::SERVICE_OWNED_SERVER_GENERATION_ENV,
    )?;
    if launch_parent != expected_parent
        || actual_parent != expected_parent
        || !crate::platform::linux::service_runtime_generation_matches(&generation)
    {
        bail!(
            "service-owned password replica owner mismatch: pid={}, expected_parent={}, actual_parent={}, launch_parent={}",
            identity.pid,
            expected_parent,
            actual_parent,
            launch_parent
        );
    }
    Ok(identity)
}

#[cfg(target_os = "linux")]
pub(crate) fn peer_process_identity_is_live(identity: &PeerProcessIdentity, postfix: &str) -> bool {
    if !is_allowed_service_peer_uid(identity.uid, active_uid_fresh()) {
        return false;
    }
    linux_process_identity_by_pid(identity.pid, postfix)
        .map(|live| {
            live == *identity
                && (identity.cm_launch_parent == 0
                    || linux_process_has_ancestor(identity.pid, identity.cm_launch_parent))
        })
        .unwrap_or(false)
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

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[inline]
fn ensure_peer_executable_matches_current_by_pid(peer_pid: u32, postfix: &str) -> ResultType<()> {
    #[cfg(target_os = "windows")]
    {
        let identity = WindowsPeerProcess::open(peer_pid)?.immutable_identity()?;
        return ensure_windows_identity_matches_current(&identity, postfix);
    }
    #[cfg(not(target_os = "windows"))]
    {
        let peer_exe = peer_exe_canonical_path_by_pid(peer_pid)?;
        let current_exe = current_exe_canonical_path()?;
        if executable_paths_match(&peer_exe, &current_exe) {
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
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn peer_executable_is_current_by_pid(peer_pid: u32) -> ResultType<bool> {
    let peer_exe = peer_exe_canonical_path_by_pid(peer_pid)?;
    let current_exe = current_exe_canonical_path()?;
    Ok(executable_paths_match(&peer_exe, &current_exe))
}

#[cfg(target_os = "windows")]
fn ensure_windows_identity_matches_current(
    identity: &WindowsProcessImmutableIdentity,
    postfix: &str,
) -> ResultType<()> {
    let current_exe = current_exe_canonical_path()?;
    if executable_paths_match(&identity.executable, &current_exe) {
        return Ok(());
    }
    bail!(
        "Peer executable path mismatch on ipc channel '{}': peer_pid={}, peer_exe='{}', current_exe='{}'",
        postfix,
        identity.key.pid,
        identity.executable.display(),
        current_exe.display()
    );
}

#[cfg(target_os = "macos")]
#[inline]
fn ensure_peer_executable_matches_current_macos_identity(
    identity: &MacosPeerProcessIdentity,
    postfix: &str,
) -> ResultType<()> {
    let code = macos_peer_code(identity, "IPC peer")?;
    let peer_exe = macos_peer_code_path(&code, "IPC peer")?;
    let current_exe = current_exe_canonical_path()?;
    if executable_paths_match(&peer_exe, &current_exe) {
        if !hbb_common::config::is_service_ipc_postfix(postfix)
            || (macos_peer_code_satisfies_requirement(
                &code,
                MACOS_PRIVILEGED_HELPER_REQUIREMENT,
                "privileged helper",
            ) && macos_privileged_helper_path_is_expected_and_trusted(&current_exe))
        {
            return Ok(());
        }
    }
    if macos_service_ipc_allows_installed_app_and_privileged_helper(identity, &current_exe, postfix)
    {
        return Ok(());
    }
    bail!(
        "Peer executable path mismatch on ipc channel '{}': peer_pid={}, peer_exe='{}', current_exe='{}'",
        postfix,
        identity.pid,
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

#[cfg(target_os = "windows")]
fn ensure_windows_identity_matches_fixed_service(
    identity: &WindowsProcessImmutableIdentity,
    postfix: &str,
) -> ResultType<()> {
    let expected_exe = crate::platform::windows::fixed_service_install_exe_path()?;
    let expected_exe = fs::canonicalize(&expected_exe).map_err(|err| {
        anyhow::anyhow!(
            "Failed to canonicalize fixed Windows service executable path '{}': {}",
            expected_exe.display(),
            err
        )
    })?;
    if executable_paths_match(&identity.executable, &expected_exe) {
        return Ok(());
    }
    bail!(
        "Peer executable path mismatch on service-owned ipc channel '{}': peer_pid={}, peer_exe='{}', expected_exe='{}'",
        postfix,
        identity.key.pid,
        identity.executable.display(),
        expected_exe.display()
    );
}

// R-X13 (§8): ensure_peer_executable_matches_current_by_fd (the FD-based exe-match used ONLY by the
// uinput peer authorizer) is removed with the uinput module. Linux _service and non-service
// helper channels still use the _by_pid variant; macOS _service uses the audit-token identity path.

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
pub(crate) struct ServiceScopedIpcAuthorization {
    postfix: String,
    #[cfg(target_os = "linux")]
    peer_pid: Option<u32>,
    #[cfg(target_os = "macos")]
    macos_peer_identity: Option<MacosPeerProcessIdentity>,
    peer_uid: Option<u32>,
    active_uid: Option<u32>,
    uid_authorized: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn service_scoped_ipc_authorization_snapshot(
    stream: &Connection,
    postfix: &str,
) -> ServiceScopedIpcAuthorization {
    service_scoped_ipc_authorization_snapshot_from_stream(stream.inner.get_ref(), postfix)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn service_scoped_ipc_authorization_snapshot_from_stream<T>(
    stream: &T,
    postfix: &str,
) -> ServiceScopedIpcAuthorization
where
    T: std::os::unix::io::AsRawFd,
{
    let fd = stream.as_raw_fd();
    let peer_uid = peer_uid_from_fd(fd);
    #[cfg(target_os = "linux")]
    let peer_pid = peer_pid_from_fd(fd);
    #[cfg(target_os = "macos")]
    let macos_peer_identity = match (peer_uid, peer_pid_from_fd(fd), peer_audit_token_from_fd(fd)) {
        (Some(uid), Some(pid), Some(audit_token)) => Some(MacosPeerProcessIdentity {
            uid,
            pid,
            audit_token,
        }),
        _ => None,
    };
    #[cfg(target_os = "macos")]
    let active_uid = active_uid_fresh();
    #[cfg(target_os = "linux")]
    let active_uid = if peer_uid == Some(0) {
        // Root does not need an active-session lookup to pass the UID gate.
        None
    } else {
        // The service-loop cache is only a negative prefilter. A match merely permits the
        // bounded caller to perform the fresh lookup that remains the final authority.
        let cached_active_uid = active_uid_cached();
        if linux_service_peer_requires_fresh_active_uid_lookup(peer_uid, cached_active_uid) {
            active_uid_fresh()
        } else {
            cached_active_uid
        }
    };
    let uid_authorized = peer_uid.is_some_and(|uid| is_allowed_service_peer_uid(uid, active_uid));
    ServiceScopedIpcAuthorization {
        postfix: postfix.to_owned(),
        #[cfg(target_os = "linux")]
        peer_pid,
        #[cfg(target_os = "macos")]
        macos_peer_identity,
        peer_uid,
        active_uid,
        uid_authorized,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn authorize_service_scoped_ipc_authorization_snapshot(
    authorization: ServiceScopedIpcAuthorization,
) -> bool {
    if !authorization.uid_authorized {
        log_rejected_service_connection(
            &authorization.postfix,
            authorization.peer_uid,
            authorization.active_uid,
        );
        return false;
    }
    #[cfg(target_os = "macos")]
    {
        let Some(identity) = authorization.macos_peer_identity else {
            log::warn!(
                "Rejected unauthorized connection on protected service-scoped IPC channel due to missing macOS peer identity: postfix={}",
                authorization.postfix
            );
            return false;
        };
        if let Err(err) =
            ensure_peer_executable_matches_current_macos_identity(&identity, &authorization.postfix)
        {
            log::warn!(
                "Rejected unauthorized connection on protected service-scoped IPC channel due to executable mismatch: postfix={}, peer_pid={}, err={}",
                authorization.postfix,
                identity.pid,
                err
            );
            return false;
        }
        return true;
    }
    #[cfg(target_os = "linux")]
    if let Err(err) = ensure_peer_executable_matches_current_by_pid_opt(
        authorization.peer_pid,
        &authorization.postfix,
    ) {
        log::warn!(
            "Rejected unauthorized connection on protected service-scoped IPC channel due to executable mismatch: postfix={}, peer_pid={:?}, err={}",
            authorization.postfix,
            authorization.peer_pid,
            err
        );
        return false;
    }
    true
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn authorize_service_scoped_ipc_connection(stream: &Connection, postfix: &str) -> bool {
    authorize_service_scoped_ipc_authorization_snapshot(service_scoped_ipc_authorization_snapshot(
        stream, postfix,
    ))
}

#[cfg(windows)]
fn authorize_windows_session_current_exe_ipc_connection(
    stream: &Connection,
    postfix: &str,
    channel: &str,
) -> bool {
    let peer_pid = stream.peer_pid();
    let server_session_id = crate::platform::windows::get_current_process_session_id();
    let process = match peer_pid.map(WindowsPeerProcess::open) {
        Some(Ok(process)) => Some(process),
        Some(Err(err)) => {
            log::debug!(
                "Failed to open live Windows IPC peer process: postfix={}, peer_pid={:?}, err={}",
                postfix,
                peer_pid,
                err
            );
            None
        }
        None => None,
    };
    let authority = match process
        .as_ref()
        .map(WindowsPeerProcess::live_token_authority)
    {
        Some(Ok(authority)) => Some(authority),
        Some(Err(err)) => {
            log::debug!(
                "Failed to inspect live Windows IPC peer process token: postfix={}, peer_pid={:?}, err={}",
                postfix,
                peer_pid,
                err
            );
            None
        }
        None => None,
    };
    let peer_session_id = authority.map(|value| value.session_id);
    let peer_is_system = authority.map(|value| value.is_local_system);
    let peer_is_elevated = authority.map(|value| value.is_elevated);
    let authorized = process.is_some()
        && authority.is_some()
        && (is_allowed_windows_session_scoped_peer(
            peer_is_system.unwrap_or(false),
            peer_session_id,
            server_session_id,
        ) || peer_is_elevated.unwrap_or(false));
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
    let Some(process) = process else {
        return false;
    };
    let identity = match process.immutable_identity() {
        Ok(identity) => identity,
        Err(err) => {
            log::warn!(
                "Rejected unauthorized connection on {} due to identity query failure: postfix={}, peer_pid={:?}, err={}",
                channel,
                postfix,
                peer_pid,
                err
            );
            return false;
        }
    };
    if let Err(err) = ensure_windows_identity_matches_current(&identity, postfix) {
        log::warn!(
            "Rejected unauthorized connection on {} due to executable mismatch: postfix={}, peer_pid={:?}, err={}",
            channel,
            postfix,
            peer_pid,
            err
        );
        return false;
    }
    if peer_pid.is_none() || stream.peer_pid() != peer_pid {
        log::warn!(
            "Rejected unauthorized connection on {} after named-pipe peer pid changed: postfix={}, peer_pid={:?}",
            channel,
            postfix,
            peer_pid
        );
        return false;
    }
    true
}

#[cfg(windows)]
pub(crate) fn authorize_windows_main_ipc_connection(stream: &Connection, postfix: &str) -> bool {
    authorize_windows_session_current_exe_ipc_connection(stream, postfix, "ipc channel")
}

#[cfg(windows)]
pub(crate) fn authorize_windows_service_main_ipc_connection(stream: &Connection) -> bool {
    match stream.windows_pipe_client_token_is_local_system() {
        Ok(true) => {}
        Ok(false) => {
            log::warn!("Rejected non-LocalSystem Windows service-main IPC client");
            return false;
        }
        Err(err) => {
            log::warn!("Rejected Windows service-main IPC client token: {err}");
            return false;
        }
    }
    let Some(peer_pid) = stream.peer_pid() else {
        log::warn!("Rejected Windows service-main IPC client without a process id");
        return false;
    };
    let identity =
        match WindowsPeerProcess::open(peer_pid).and_then(|process| process.immutable_identity()) {
            Ok(identity) => identity,
            Err(err) => {
                log::warn!("Rejected Windows service-main IPC client identity: {err}");
                return false;
            }
        };
    let expected_parent = (|| -> ResultType<WindowsProcessIdentityKey> {
        let pid = std::env::var(super::WINDOWS_SERVICE_SUPERVISOR_PID_ENV)
            .map_err(|err| anyhow::anyhow!("missing Windows service supervisor pid: {err}"))?
            .parse::<u32>()
            .map_err(|err| anyhow::anyhow!("invalid Windows service supervisor pid: {err}"))?;
        let creation_time = std::env::var(super::WINDOWS_SERVICE_SUPERVISOR_CREATION_ENV)
            .map_err(|err| {
                anyhow::anyhow!("missing Windows service supervisor creation time: {err}")
            })?
            .parse::<u64>()
            .map_err(|err| {
                anyhow::anyhow!("invalid Windows service supervisor creation time: {err}")
            })?;
        if pid == 0 || creation_time == 0 {
            bail!("invalid zero Windows service supervisor identity");
        }
        Ok(WindowsProcessIdentityKey { pid, creation_time })
    })();
    let expected_parent = match expected_parent {
        Ok(identity) => identity,
        Err(err) => {
            log::warn!("Rejected Windows service-main IPC client without launch-bound supervisor identity: {err}");
            return false;
        }
    };
    if identity.key != expected_parent {
        log::warn!(
            "Rejected Windows service-main IPC client identity: expected {}:{}, got {}:{}",
            expected_parent.pid,
            expected_parent.creation_time,
            identity.key.pid,
            identity.key.creation_time
        );
        return false;
    }
    if let Err(err) = ensure_windows_identity_matches_fixed_service(
        &identity,
        super::WINDOWS_SERVICE_CREDENTIAL_IPC_POSTFIX,
    ) {
        log::warn!("Rejected Windows service-main IPC client executable: {err}");
        return false;
    }
    if !windows_identity_has_exact_role(&identity, &["--service"]) {
        log::warn!("Rejected Windows service-main IPC client with the wrong process role");
        return false;
    }
    if stream.peer_pid() != Some(peer_pid) {
        log::warn!("Rejected Windows service-main IPC client after named-pipe peer pid changed");
        return false;
    }
    true
}

#[cfg(windows)]
pub(crate) fn authorize_windows_service_owned_sas_requester(
    stream: &Connection,
) -> Option<WindowsProcessIdentityKey> {
    let peer_pid = stream.peer_pid()?;
    match stream.windows_pipe_client_authority() {
        Ok(authority) if authority.is_local_system => {}
        Ok(_) => {
            log::warn!(
                "Rejected non-LocalSystem Windows service-owned SAS requester: peer_pid={peer_pid}"
            );
            return None;
        }
        Err(err) => {
            log::warn!(
                "Rejected Windows service-owned SAS requester token: peer_pid={peer_pid}, err={err}"
            );
            return None;
        }
    }
    let process = match WindowsPeerProcess::open(peer_pid) {
        Ok(process) => process,
        Err(err) => {
            log::warn!(
                "Rejected Windows service-owned SAS requester identity: peer_pid={peer_pid}, err={err}"
            );
            return None;
        }
    };
    let process_key = process.key;
    let identity = match process.immutable_identity() {
        Ok(identity) => identity,
        Err(err) => {
            log::warn!(
                "Rejected Windows service-owned SAS requester identity: peer_pid={peer_pid}, err={err}"
            );
            return None;
        }
    };
    if let Err(err) = ensure_windows_identity_matches_fixed_service(
        &identity,
        super::WINDOWS_SERVICE_SAS_IPC_POSTFIX,
    ) {
        log::warn!(
            "Rejected Windows service-owned SAS requester executable: peer_pid={peer_pid}, err={err}"
        );
        return None;
    }
    if !windows_identity_has_exact_role(&identity, &windows_service_owned_main_server_args()) {
        log::warn!(
            "Rejected Windows service-owned SAS requester with the wrong process role: peer_pid={peer_pid}"
        );
        return None;
    }
    if stream.peer_pid() != Some(peer_pid) {
        log::warn!(
            "Rejected Windows service-owned SAS requester after named-pipe peer pid changed: peer_pid={peer_pid}"
        );
        return None;
    }
    Some(process_key)
}

#[cfg(windows)]
pub(crate) fn authorize_windows_url_ipc_connection(stream: &Connection, postfix: &str) -> bool {
    authorize_windows_session_current_exe_ipc_connection(
        stream,
        postfix,
        "protected _url IPC channel",
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn process_argv_is_exact(args: &[String], expected_args: &[&str]) -> bool {
    args.len() == expected_args.len() + 1
        && expected_args
            .iter()
            .enumerate()
            .all(|(index, expected)| args[index + 1] == *expected)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn cm_process_argv_is_expected(args: &[String], expected_arg: &str) -> bool {
    process_argv_is_exact(args, &[expected_arg])
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn helper_server_argv_is_expected(args: &[String]) -> bool {
    process_argv_is_exact(args, &["--server"])
        || process_argv_is_exact(args, &["--server", crate::common::SERVICE_OWNED_SERVER_ARG])
}

#[cfg(target_os = "windows")]
fn windows_process_argv_is_exact(argv: &[String], expected_args: &[&str]) -> bool {
    argv.len() == expected_args.len() + 1
        && expected_args
            .iter()
            .enumerate()
            .all(|(index, expected)| argv[index + 1].eq_ignore_ascii_case(expected))
}

#[cfg(target_os = "windows")]
fn windows_identity_has_exact_role(
    identity: &WindowsProcessImmutableIdentity,
    expected_args: &[&str],
) -> bool {
    windows_process_argv_is_exact(&identity.argv, expected_args)
}

#[cfg(target_os = "windows")]
fn windows_identity_is_main_server(identity: &WindowsProcessImmutableIdentity) -> bool {
    windows_identity_has_exact_role(identity, &["--server"])
        || windows_identity_has_exact_role(identity, &windows_service_owned_main_server_args())
}

#[cfg(target_os = "windows")]
fn windows_identity_is_sensitive_password_client(
    identity: &WindowsProcessImmutableIdentity,
) -> bool {
    windows_process_argv_is_exact(&identity.argv, &[])
        || windows_identity_has_exact_role(identity, &["--password"])
        || windows_identity_has_exact_role(identity, &["--password-stdin"])
}

#[cfg(target_os = "windows")]
fn require_windows_sensitive_password_client_role(
    identity: &WindowsProcessImmutableIdentity,
) -> ResultType<()> {
    if windows_identity_is_sensitive_password_client(identity) {
        Ok(())
    } else {
        bail!("Windows sensitive IPC client has the wrong exact process role")
    }
}

#[cfg(target_os = "windows")]
fn require_windows_sensitive_password_server_role(
    identity: &WindowsProcessImmutableIdentity,
    postfix: &str,
) -> ResultType<()> {
    match postfix {
        super::password::USER_PASSWORD_IPC_POSTFIX if windows_identity_is_main_server(identity) => {
            Ok(())
        }
        super::password::SERVICE_PASSWORD_IPC_POSTFIX
            if windows_identity_has_exact_role(identity, &["--service"]) =>
        {
            Ok(())
        }
        super::password::USER_PASSWORD_IPC_POSTFIX
        | super::password::SERVICE_PASSWORD_IPC_POSTFIX => {
            bail!("Windows sensitive IPC server has the wrong exact process role")
        }
        _ => bail!("Unsupported Windows sensitive IPC endpoint"),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn peer_process_is_current_exe_server(peer_pid: u32) -> bool {
    #[cfg(target_os = "windows")]
    {
        let result = (|| -> ResultType<bool> {
            let identity = WindowsPeerProcess::open(peer_pid)?.immutable_identity()?;
            ensure_windows_identity_matches_current(&identity, "server role check")?;
            Ok(windows_identity_is_main_server(&identity))
        })();
        return match result {
            Ok(matches) => matches,
            Err(err) => {
                log::debug!(
                    "Failed direct Windows main-server role check: pid={}, err={}",
                    peer_pid,
                    err
                );
                false
            }
        };
    }
    #[cfg(not(target_os = "windows"))]
    {
        match main_server_cmdline_args(peer_pid) {
            Ok(args) => helper_server_argv_is_expected(&args),
            Err(err) => {
                log::debug!(
                    "Failed direct Unix main-server role check: pid={}, err={}",
                    peer_pid,
                    err
                );
                false
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn windows_service_owned_main_server_args() -> [&'static str; 2] {
    ["--server", crate::common::SERVICE_OWNED_SERVER_ARG]
}

#[cfg(target_os = "macos")]
pub(crate) fn authenticate_macos_cm_endpoint<T>(
    stream: &ConnectionTmpl<T>,
    expected_arg: &str,
) -> ResultType<()>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::os::unix::io::AsRawFd,
{
    let peer_pid = stream
        .peer_pid()
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve peer pid on ipc channel '_cm'"))?;
    ensure_peer_executable_matches_current_by_pid(peer_pid, "_cm")?;
    let args = macos_process_cmdline_args(peer_pid)?;
    if !cm_process_argv_is_expected(&args, expected_arg) {
        bail!("_cm endpoint mode mismatch: expected {}", expected_arg);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub(crate) fn authenticate_windows_cm_endpoint(
    stream: &ConnectionTmpl<parity_tokio_ipc::ConnectionClient>,
    expected_arg: &str,
) -> ResultType<()> {
    let peer_pid = windows_named_pipe_server_pid(stream.inner.get_ref())?;
    let identity = WindowsPeerProcess::open(peer_pid)?.immutable_identity()?;
    ensure_windows_identity_matches_current(&identity, "_cm")?;
    if !windows_identity_has_exact_role(&identity, &[expected_arg]) {
        bail!("_cm endpoint mode mismatch: expected {}", expected_arg);
    }
    if windows_named_pipe_server_pid(stream.inner.get_ref())? != peer_pid {
        bail!("_cm endpoint named-pipe server pid changed during authentication");
    }
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) fn authorize_cm_ipc_connection(stream: &Connection) -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Err(err) = authenticate_linux_cm_owner_stream(stream) {
            log::warn!(
                "Rejected unauthorized _cm IPC peer outside the exact launch-parent boundary: {err}"
            );
            return false;
        }
        return true;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let peer_pid = stream.peer_pid();
        if let Err(err) = ensure_peer_executable_matches_current_by_pid_opt(peer_pid, "_cm") {
            log::warn!(
                "Rejected unauthorized connection on _cm IPC channel due to executable mismatch: peer_pid={:?}, err={}",
                peer_pid,
                err
            );
            return false;
        }
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            let Some(peer_pid) = peer_pid else {
                log::warn!(
                    "Rejected unauthorized connection on _cm IPC channel: peer pid unavailable"
                );
                return false;
            };
            if !peer_process_is_current_exe_server(peer_pid) {
                log::warn!(
                    "Rejected unauthorized connection on _cm IPC channel: peer is not the current executable's --server process, peer_pid={}",
                    peer_pid
                );
                return false;
            }
        }
        true
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) fn authorize_whiteboard_ipc_connection(
    stream: &Connection,
    expected_parent_pid: u32,
) -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Err(err) = authenticate_linux_whiteboard_owner_stream(stream, expected_parent_pid) {
            log::warn!(
                "Rejected unauthorized _whiteboard IPC peer outside the exact launch-parent boundary: {err}"
            );
            return false;
        }
        return true;
    }
    #[cfg(not(target_os = "linux"))]
    {
        if expected_parent_pid == 0 {
            log::warn!("Rejected _whiteboard IPC peer: missing launch parent pid");
            return false;
        }
        let peer_pid = stream.peer_pid();
        if peer_pid != Some(expected_parent_pid) {
            log::warn!(
                "Rejected _whiteboard IPC peer: expected parent pid {}, got {:?}",
                expected_parent_pid,
                peer_pid
            );
            return false;
        }
        if let Err(err) = ensure_peer_executable_matches_current_by_pid_opt(peer_pid, "_whiteboard")
        {
            log::warn!(
                "Rejected _whiteboard IPC peer due to executable mismatch: peer_pid={:?}, err={}",
                peer_pid,
                err
            );
            return false;
        }
        if !peer_process_is_current_exe_server(expected_parent_pid) {
            log::warn!(
                "Rejected _whiteboard IPC peer: launch parent is not the current executable's --server process, peer_pid={}",
                expected_parent_pid
            );
            return false;
        }
        true
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl<T> ConnectionTmpl<T>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin + std::os::unix::io::AsRawFd,
{
    pub(super) fn peer_uid(&self) -> Option<u32> {
        peer_uid_from_fd(self.inner.get_ref().as_raw_fd())
    }

    pub(crate) fn peer_pid(&self) -> Option<u32> {
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

    fn windows_pipe_client_token_satisfies(
        &self,
        requirement: WindowsPipeClientTokenRequirement,
    ) -> ResultType<bool> {
        let authority = self.windows_pipe_client_authority().map_err(|err| {
            anyhow::anyhow!("Failed to authorize {}: {}", requirement.context(), err)
        })?;
        Ok(requirement.is_satisfied(authority))
    }

    fn windows_pipe_client_authority(&self) -> ResultType<WindowsLiveTokenAuthority> {
        let context = "Windows named-pipe client";
        let pipe_handle = self.inner.get_ref().as_raw_handle();
        if pipe_handle.is_null() {
            bail!(
                "Failed to impersonate {}: named pipe handle is null",
                context
            );
        }
        run_windows_pipe_client_impersonation(HANDLE(pipe_handle), context, move |_pipe_handle| {
            let mut token = HANDLE::default();
            unsafe {
                OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token).map_err(
                    |err| {
                        anyhow::anyhow!("Failed to open {} impersonation token: {}", context, err)
                    },
                )?;
            }
            let _token_guard = WindowsHandle(token);
            windows_token_authority(token)
        })
    }

    pub(crate) fn windows_pipe_client_token_is_elevated(&self) -> ResultType<bool> {
        self.windows_pipe_client_token_satisfies(WindowsPipeClientTokenRequirement::Elevated)
    }

    pub(crate) fn windows_pipe_client_token_is_local_system(&self) -> ResultType<bool> {
        self.windows_pipe_client_token_satisfies(WindowsPipeClientTokenRequirement::LocalSystem)
    }

    pub(crate) fn prepare_sas_as_windows_pipe_client(
        &self,
        expected_requester: WindowsProcessIdentityKey,
    ) -> ResultType<WindowsSasPipeDispatch> {
        let peer_pid = self
            .peer_pid()
            .ok_or_else(|| anyhow::anyhow!("Failed to resolve Windows SAS requester pipe pid"))?;
        let requester_process = WindowsPeerProcess::open_for_sas_dispatch(peer_pid)?;
        if requester_process.key != expected_requester {
            bail!(
                "Windows SAS requester process identity changed: expected {}:{}, got {}:{}",
                expected_requester.pid,
                expected_requester.creation_time,
                requester_process.key.pid,
                requester_process.key.creation_time
            );
        }
        let pipe_handle = self.inner.get_ref().as_raw_handle();
        if pipe_handle.is_null() {
            bail!("Failed to retain Windows SAS requester: named pipe handle is null");
        }
        let pipe = duplicate_windows_handle(HANDLE(pipe_handle), "Windows SAS pipe")?;
        requester_process.require_running("Windows SAS requester")?;
        Ok(WindowsSasPipeDispatch {
            pipe,
            requester: requester_process,
        })
    }

    pub(crate) fn service_authorization_status_for_session(
        &self,
        expected_active_session_id: Option<u32>,
    ) -> (bool, Option<u32>, Option<u32>, Option<bool>) {
        let peer_pid = self.peer_pid();
        let authority_result = peer_pid
            .ok_or_else(|| anyhow::anyhow!("Windows service IPC peer pid unavailable"))
            .and_then(WindowsPeerProcess::open)
            .and_then(|process| process.live_token_authority());
        let authority = authority_result.as_ref().ok().copied();
        let peer_session_id = authority.map(|value| value.session_id);
        let peer_is_system = authority.map(|value| value.is_local_system);
        let authorized = peer_pid.is_some()
            && authority.is_some()
            && is_allowed_windows_session_scoped_peer(
                peer_is_system.unwrap_or(false),
                peer_session_id,
                expected_active_session_id,
            );
        if !authorized {
            if let Err(err) = authority_result {
                log::debug!(
                    "Failed to inspect live Windows service IPC client token, peer_pid={:?}, err={}",
                    peer_pid,
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
    #[cfg(target_os = "linux")]
    fn r_s11e60_linux_service_active_uid_lookup_prefilter_is_negative_only() {
        assert!(!super::linux_service_peer_requires_fresh_active_uid_lookup(
            Some(0),
            Some(501),
        ));
        assert!(super::linux_service_peer_requires_fresh_active_uid_lookup(
            Some(501),
            Some(501),
        ));
        assert!(!super::linux_service_peer_requires_fresh_active_uid_lookup(
            Some(502),
            Some(501),
        ));
        assert!(!super::linux_service_peer_requires_fresh_active_uid_lookup(
            Some(501),
            None,
        ));
        assert!(!super::linux_service_peer_requires_fresh_active_uid_lookup(
            None,
            Some(501),
        ));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_linux_process_has_ancestor_requires_parent_chain() {
        let pid = std::process::id();
        let parent = super::linux_proc_parent_pid(pid).unwrap();
        assert!(!super::linux_process_has_ancestor(0, parent));
        assert!(!super::linux_process_has_ancestor(pid, 0));
        assert!(!super::linux_process_has_ancestor(pid, pid));
        if parent > 1 {
            assert!(super::linux_process_has_ancestor(pid, parent));
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_linux_service_owned_server_argv_is_exact() {
        assert!(super::linux_service_owned_server_argv_is_expected(&[
            "/usr/bin/rustdesk".to_owned(),
            "--server".to_owned(),
            crate::common::SERVICE_OWNED_SERVER_ARG.to_owned(),
        ]));
        assert!(!super::linux_service_owned_server_argv_is_expected(&[
            "/usr/bin/rustdesk".to_owned(),
            "--server".to_owned(),
        ]));
        assert!(!super::linux_service_owned_server_argv_is_expected(&[
            "/usr/bin/rustdesk".to_owned(),
            "--server".to_owned(),
            crate::common::SERVICE_OWNED_SERVER_ARG.to_owned(),
            "--extra".to_owned(),
        ]));
        assert!(!super::linux_service_owned_server_argv_is_expected(&[
            "/usr/bin/rustdesk".to_owned(),
            "--cm".to_owned(),
            crate::common::SERVICE_OWNED_SERVER_ARG.to_owned(),
        ]));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_windows_service_owned_server_args_are_exact() {
        let args = super::windows_service_owned_main_server_args();
        assert_eq!(args.len(), 2);
        assert_eq!(
            args,
            ["--server", crate::common::SERVICE_OWNED_SERVER_ARG],
            "R-S11e-11: the Windows service-owned main-server authenticator must require the exact service-owned server argv shape"
        );
    }

    #[cfg(target_os = "windows")]
    fn windows_identity_for_test(
        pid: u32,
        creation_time: u64,
        args: &[&str],
    ) -> std::sync::Arc<super::WindowsProcessImmutableIdentity> {
        let mut argv = vec![r"C:\Program Files\RustDesk\RustDesk.exe".to_owned()];
        argv.extend(args.iter().map(|arg| (*arg).to_owned()));
        std::sync::Arc::new(super::WindowsProcessImmutableIdentity {
            key: super::WindowsProcessIdentityKey { pid, creation_time },
            executable: std::path::PathBuf::from(&argv[0]),
            argv,
        })
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn windows_exact_role_policy_rejects_missing_and_extra_arguments() {
        assert!(super::windows_process_argv_is_exact(
            &["rustdesk.exe".to_owned(), "--SERVER".to_owned()],
            &["--server"]
        ));
        assert!(!super::windows_process_argv_is_exact(
            &["rustdesk.exe".to_owned()],
            &["--server"]
        ));
        assert!(!super::windows_process_argv_is_exact(
            &[
                "rustdesk.exe".to_owned(),
                "--server".to_owned(),
                "--unexpected".to_owned(),
            ],
            &["--server"]
        ));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn windows_sensitive_password_client_roles_are_finite() {
        for args in [&[][..], &["--password"][..], &["--password-stdin"][..]] {
            let identity = windows_identity_for_test(1, 10, args);
            assert!(super::windows_identity_is_sensitive_password_client(
                &identity
            ));
        }
        for args in [
            &["--server"][..],
            &["--service"][..],
            &["--cm"][..],
            &["--password", "extra"][..],
        ] {
            let identity = windows_identity_for_test(1, 10, args);
            assert!(!super::windows_identity_is_sensitive_password_client(
                &identity
            ));
        }
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn windows_main_server_role_allows_only_user_and_service_owned_shapes() {
        let user = windows_identity_for_test(1, 10, &["--server"]);
        let service_owned = windows_identity_for_test(
            2,
            20,
            &["--server", crate::common::SERVICE_OWNED_SERVER_ARG],
        );
        let extra = windows_identity_for_test(3, 30, &["--server", "--unexpected"]);
        assert!(super::windows_identity_is_main_server(&user));
        assert!(super::windows_identity_is_main_server(&service_owned));
        assert!(!super::windows_identity_is_main_server(&extra));
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn r_s11e81_unix_helper_process_roles_require_exact_argument_vectors() {
        let cm = ["rustdesk".to_owned(), "--cm".to_owned()];
        let headless_cm = ["rustdesk".to_owned(), "--cm-no-ui".to_owned()];
        assert!(super::cm_process_argv_is_expected(&cm, "--cm"));
        assert!(super::cm_process_argv_is_expected(
            &headless_cm,
            "--cm-no-ui"
        ));
        for rejected in [
            vec!["rustdesk".to_owned()],
            vec!["rustdesk".to_owned(), "--CM".to_owned()],
            vec![
                "rustdesk".to_owned(),
                "--cm".to_owned(),
                "--unexpected".to_owned(),
            ],
        ] {
            assert!(!super::cm_process_argv_is_expected(&rejected, "--cm"));
        }

        let user_server = ["rustdesk".to_owned(), "--server".to_owned()];
        let service_server = [
            "rustdesk".to_owned(),
            "--server".to_owned(),
            crate::common::SERVICE_OWNED_SERVER_ARG.to_owned(),
        ];
        assert!(super::helper_server_argv_is_expected(&user_server));
        assert!(super::helper_server_argv_is_expected(&service_server));
        for rejected in [
            vec!["rustdesk".to_owned()],
            vec!["rustdesk".to_owned(), "--SERVER".to_owned()],
            vec![
                "rustdesk".to_owned(),
                "--server".to_owned(),
                "--unexpected".to_owned(),
            ],
            vec![
                "rustdesk".to_owned(),
                "--server".to_owned(),
                crate::common::SERVICE_OWNED_SERVER_ARG.to_owned(),
                "--unexpected".to_owned(),
            ],
            vec!["rustdesk".to_owned(), "--cm".to_owned()],
        ] {
            assert!(!super::helper_server_argv_is_expected(&rejected));
        }
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn windows_sas_token_authority_requires_local_system_in_exact_session() {
        let valid = super::WindowsLiveTokenAuthority {
            is_local_system: true,
            is_elevated: true,
            session_id: 7,
        };
        let user = super::WindowsLiveTokenAuthority {
            is_local_system: false,
            is_elevated: true,
            session_id: 7,
        };
        assert!(super::windows_token_authority_matches_sas_session(valid, 7));
        assert!(!super::windows_token_authority_matches_sas_session(
            valid, 8
        ));
        assert!(!super::windows_token_authority_matches_sas_session(user, 7));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn windows_identity_cache_is_bounded_and_lru() {
        let mut cache = super::WindowsProcessIdentityCache::new(2);
        let first = windows_identity_for_test(1, 10, &["--server"]);
        let second = windows_identity_for_test(2, 20, &["--server"]);
        let third = windows_identity_for_test(3, 30, &["--server"]);
        cache.insert(first.clone());
        cache.insert(second.clone());
        assert!(cache.get(first.key).is_some());
        cache.insert(third.clone());
        assert!(cache.get(first.key).is_some());
        assert!(cache.get(second.key).is_none());
        assert!(cache.get(third.key).is_some());
        assert_eq!(cache.entries.len(), 2);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn windows_identity_cache_replaces_reused_pid_generation() {
        let mut cache = super::WindowsProcessIdentityCache::new(4);
        let old = windows_identity_for_test(7, 100, &["--server"]);
        let reused = windows_identity_for_test(7, 200, &["--service"]);
        cache.insert(old.clone());
        cache.insert(reused.clone());
        assert!(cache.get(old.key).is_none());
        let observed = cache.get(reused.key).expect("reused pid generation cached");
        assert_eq!(observed.key, reused.key);
        assert_eq!(cache.entries.len(), 1);
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_user_owned_main_server_argv_is_exact() {
        assert!(super::user_owned_main_server_argv_is_expected(&[
            "/usr/bin/rustdesk".to_owned(),
            "--server".to_owned(),
        ]));
        assert!(!super::user_owned_main_server_argv_is_expected(&[
            "/usr/bin/rustdesk".to_owned(),
        ]));
        assert!(!super::user_owned_main_server_argv_is_expected(&[
            "/usr/bin/rustdesk".to_owned(),
            "--server".to_owned(),
            crate::common::SERVICE_OWNED_SERVER_ARG.to_owned(),
        ]));
        assert!(!super::user_owned_main_server_argv_is_expected(&[
            "/usr/bin/rustdesk".to_owned(),
            "--server".to_owned(),
            "--tray".to_owned(),
        ]));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn r_s11e97_linux_root_service_peer_requires_kernel_uid_and_positive_pid() {
        assert_eq!(
            super::validate_linux_root_service_peer(Some(0), Some(41), "_service").unwrap(),
            41
        );
        assert!(super::validate_linux_root_service_peer(Some(1000), Some(41), "_service").is_err());
        assert!(super::validate_linux_root_service_peer(None, Some(41), "_service").is_err());
        assert!(super::validate_linux_root_service_peer(Some(0), None, "_service").is_err());
        assert!(super::validate_linux_root_service_peer(Some(0), Some(0), "_service").is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_peer_process_identity_debug_redacts_launch_token() {
        let mut identity =
            super::PeerProcessIdentity::for_test(10, 20, "30".to_owned(), "--cm".to_owned());
        identity.cm_launch_token = "secret-token".to_owned();
        identity.cm_launch_parent = 40;

        let formatted = format!("{identity:?}");
        assert!(!formatted.contains("secret-token"));
        assert!(formatted.contains("<redacted>"));
        assert!(formatted.contains("cm_launch_parent"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn r_s11e95_linux_kernel_identity_is_pid_reuse_and_direct_parent_bound() {
        let identity = super::current_linux_process_identity().unwrap();
        let parent = super::linux_proc_parent_pid(identity.pid()).unwrap();

        assert!(super::linux_process_identity_is_live(&identity));
        assert!(super::linux_cm_child_identity_is_live(&identity, parent));
        assert!(!super::linux_cm_child_identity_is_live(&identity, 0));
        assert!(!super::linux_cm_child_identity_is_live(
            &identity,
            parent.saturating_add(1)
        ));
        let wrong_start = super::LinuxProcessIdentity::for_test(
            identity.pid(),
            identity.uid(),
            "wrong-start-time".to_owned(),
        );
        assert!(!super::linux_process_identity_is_live(&wrong_start));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn r_s11e96_linux_whiteboard_owner_is_exact_direct_parent() {
        let parent = super::linux_proc_parent_pid(std::process::id()).unwrap();
        let identity = super::linux_whiteboard_owner_identity(parent).unwrap();

        assert_eq!(identity.pid(), parent);
        assert!(super::linux_process_identity_is_live(&identity));
        assert!(super::linux_whiteboard_owner_identity(0).is_err());
        assert!(super::linux_whiteboard_owner_identity(parent.saturating_add(1)).is_err());
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
    fn r_s11e63_windows_ipc_postfix_uses_restricted_dacl_policy() {
        assert!(super::windows_ipc_postfix_uses_restricted_dacl(""));
        assert!(super::windows_ipc_postfix_uses_restricted_dacl("_service"));
        assert!(super::windows_ipc_postfix_uses_restricted_dacl(
            super::super::password::USER_PASSWORD_IPC_POSTFIX
        ));
        assert!(super::windows_ipc_postfix_uses_restricted_dacl(
            super::super::password::SERVICE_PASSWORD_IPC_POSTFIX
        ));
        assert!(super::windows_ipc_postfix_uses_restricted_dacl(
            super::super::WINDOWS_SERVICE_CREDENTIAL_IPC_POSTFIX
        ));
        assert!(super::windows_ipc_postfix_uses_restricted_dacl(
            super::super::WINDOWS_SERVICE_MAIN_CONTROL_IPC_POSTFIX
        ));
        assert!(super::windows_ipc_postfix_uses_restricted_dacl(
            super::super::WINDOWS_SERVICE_SAS_IPC_POSTFIX
        ));
        assert!(super::windows_ipc_postfix_uses_restricted_dacl("_url"));
        assert!(super::windows_ipc_postfix_uses_restricted_dacl("_cm"));
        assert!(super::windows_ipc_postfix_uses_restricted_dacl(
            "_whiteboard_0123456789abcdef0123456789abcdef"
        ));
        assert!(!super::windows_ipc_postfix_uses_restricted_dacl(
            "_whiteboard_0123456789abcdef0123456789abcde"
        ));
        assert!(!super::windows_ipc_postfix_uses_restricted_dacl(
            "_whiteboard_0123456789abcdef0123456789abcdeg"
        ));
        assert!(!super::windows_ipc_postfix_uses_restricted_dacl(
            "_portable_service"
        ));
    }

    #[test]
    #[cfg(windows)]
    fn r_s11e63_windows_unknown_ipc_listener_has_no_default_dacl_fallback() {
        assert!(super::windows_ipc_listener_security_attributes("_portable_service").is_err());
    }

    #[test]
    #[cfg(windows)]
    fn windows_service_control_and_sas_dacls_are_system_only() {
        for postfix in [
            super::super::WINDOWS_SERVICE_CREDENTIAL_IPC_POSTFIX,
            super::super::WINDOWS_SERVICE_MAIN_CONTROL_IPC_POSTFIX,
            super::super::WINDOWS_SERVICE_SAS_IPC_POSTFIX,
        ] {
            let sids = super::windows_ipc_dacl_sids_for_postfix(postfix).unwrap();
            assert!(sids.server_sids.is_empty());
            assert!(sids.client_sids.is_empty());
            let sddl = super::windows_restricted_ipc_sddl(&sids);
            assert_eq!(sddl, "D:P(D;;GA;;;NU)(A;;GA;;;SY)");
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_windows_restricted_ipc_sddl_omits_world_and_administrators() {
        let sddl = super::windows_restricted_ipc_sddl(&super::WindowsIpcDaclSids {
            server_sids: vec!["S-1-5-5-100-200".to_owned()],
            client_sids: vec!["S-1-5-21-1-2-3-1001".to_owned()],
        });
        assert!(sddl.starts_with("D:P(D;;GA;;;NU)(A;;GA;;;SY)"));
        assert_eq!(sddl.matches(";;;NU").count(), 1);
        assert!(sddl.contains("(A;;GA;;;S-1-5-5-100-200)"));
        assert!(sddl.contains("(A;;0x0012019b;;;S-1-5-21-1-2-3-1001)"));
        assert!(!sddl.contains(";;;BA"));
        assert!(!sddl.contains(";;;WD"));

        let system_only = super::windows_restricted_ipc_sddl(&super::WindowsIpcDaclSids {
            server_sids: Vec::new(),
            client_sids: Vec::new(),
        });
        assert_eq!(system_only, "D:P(D;;GA;;;NU)(A;;GA;;;SY)");

        let interactive_client = super::windows_restricted_ipc_sddl(&super::WindowsIpcDaclSids {
            server_sids: Vec::new(),
            client_sids: vec![super::INTERACTIVE_USERS_SID.to_owned()],
        });
        assert_eq!(
            interactive_client,
            "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;0x0012019b;;;S-1-5-4)"
        );
    }

    #[test]
    #[cfg(windows)]
    fn test_windows_client_pipe_access_does_not_grant_create_instance() {
        const FILE_CREATE_PIPE_INSTANCE: u32 = 0x0000_0004;
        assert_eq!(
            super::WINDOWS_NAMED_PIPE_CLIENT_ACCESS_MASK & FILE_CREATE_PIPE_INSTANCE,
            0
        );
    }

    #[test]
    #[cfg(windows)]
    fn test_executable_paths_match_windows_normalization() {
        let left = std::path::PathBuf::from(r"\\?\C:\Program Files\RustDesk\RustDesk.exe");
        let right = std::path::PathBuf::from(r"c:\program files\rustdesk\rustdesk.exe");
        assert!(super::executable_paths_match(&left, &right));
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
