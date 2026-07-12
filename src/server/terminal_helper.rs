//! Terminal Helper Process
//!
//! This module implements a helper process that runs as the logged-in user and creates
//! the ConPTY + Shell. This is necessary because ConPTY has compatibility issues with
//! CreateProcessAsUserW when the ConPTY is created by a different user (SYSTEM service).
//!
//! Architecture:
//! ```
//! SYSTEM Service (terminal_service.rs)
//!     |
//!     +-- CreateProcessAsUserW --> Terminal Helper (this module, runs as user)
//!     |                                |
//!     |                                +-- CreateProcessW + ConPTY --> Shell
//!     |                                |
//!     +-- Named Pipes <----------------+
//! ```
//!
//! This module also contains Windows-specific utility functions used by terminal_service.rs:
//! - Named pipe creation and connection
//! - User token and SID handling
//! - Helper process launching

use hbb_common::{
    anyhow::{anyhow, Context, Result},
    log,
};
use portable_pty::{CommandBuilder, MasterPty, PtySize};
use std::{
    ffi::{c_void, OsStr, OsString},
    fs::File,
    io::{Read, Write},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle},
        raw::HANDLE as RawHandle,
    },
    path::PathBuf,
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use windows::{
    core::{Error as WindowsError, HRESULT, PCWSTR, PWSTR},
    Win32::{
        Foundation::{
            CloseHandle, LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_FOUND,
            ERROR_OPERATION_ABORTED, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING, HANDLE, HLOCAL,
            INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT, WIN32_ERROR,
        },
        Security::{
            Authorization::{
                SetEntriesInAclW, EXPLICIT_ACCESS_W, SET_ACCESS, TRUSTEE_IS_SID,
                TRUSTEE_IS_UNKNOWN, TRUSTEE_IS_USER, TRUSTEE_W,
            },
            CreateWellKnownSid, GetLengthSid, GetTokenInformation, InitializeSecurityDescriptor,
            IsValidSid, SetSecurityDescriptorDacl, TokenGroups, TokenPrimary, TokenSessionId,
            TokenStatistics, TokenUser, WinLocalSystemSid, ACE_FLAGS, ACL, PSECURITY_DESCRIPTOR,
            PSID, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SID_AND_ATTRIBUTES, TOKEN_GROUPS,
            TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER,
        },
        Storage::FileSystem::{
            CreateFileW, FILE_CREATE_PIPE_INSTANCE, FILE_FLAGS_AND_ATTRIBUTES,
            FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_DATA,
            FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
            SYNCHRONIZE,
        },
        System::{
            Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock},
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
                SetNamedPipeHandleState, PIPE_NOWAIT, PIPE_READMODE_BYTE,
                PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
            },
            SystemInformation::GetSystemDirectoryW,
            Threading::{
                CreateProcessAsUserW, GetExitCodeProcess, OpenProcessToken, ResumeThread,
                TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED,
                CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
            },
            IO::CancelSynchronousIo,
        },
        UI::Shell::GetUserProfileDirectoryW,
    },
};

fn is_windows_error(error: &WindowsError, expected: WIN32_ERROR) -> bool {
    error.code() == HRESULT::from_win32(expected.0)
}

#[derive(Clone, Eq, PartialEq)]
struct AlignedSid {
    words: Vec<usize>,
    byte_len: usize,
}

impl std::fmt::Debug for AlignedSid {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AlignedSid")
            .field("byte_len", &self.byte_len)
            .finish_non_exhaustive()
    }
}

impl AlignedSid {
    fn copy_from(sid: PSID) -> Result<Self> {
        if sid.is_invalid() || !unsafe { IsValidSid(sid).as_bool() } {
            return Err(anyhow!("Token contains an invalid SID"));
        }
        let byte_len = unsafe { GetLengthSid(sid) } as usize;
        if byte_len == 0 {
            return Err(anyhow!("Token contains a zero-length SID"));
        }
        let word_count = byte_len
            .checked_add(std::mem::size_of::<usize>() - 1)
            .ok_or_else(|| anyhow!("SID length overflow"))?
            / std::mem::size_of::<usize>();
        let mut words = vec![0usize; word_count];
        unsafe {
            ptr::copy_nonoverlapping(sid.0.cast::<u8>(), words.as_mut_ptr().cast(), byte_len);
        }
        Ok(Self { words, byte_len })
    }

    fn as_psid(&self) -> PSID {
        PSID(self.words.as_ptr() as *mut c_void)
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.byte_len) }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsTokenIdentity {
    pub session_id: u32,
    pub user_sid: Vec<u8>,
    logon_sid: AlignedSid,
    pub authentication_id_low: u32,
    pub authentication_id_high: i32,
    pub token_id_low: u32,
    pub token_id_high: i32,
    pub modified_id_low: u32,
    pub modified_id_high: i32,
}

impl WindowsTokenIdentity {
    fn same_principal(&self, other: &Self) -> bool {
        self.session_id == other.session_id
            && self.user_sid == other.user_sid
            && self.logon_sid == other.logon_sid
            && self.authentication_id_low == other.authentication_id_low
            && self.authentication_id_high == other.authentication_id_high
    }
}

#[derive(Debug)]
pub struct OwnedPrimaryToken {
    handle: HANDLE,
    identity: WindowsTokenIdentity,
}

impl OwnedPrimaryToken {
    pub fn from_raw(handle: usize) -> Result<Self> {
        let handle = HANDLE(handle as _);
        let identity = match get_windows_token_identity(handle) {
            Ok(identity) => identity,
            Err(err) => {
                if !handle.is_invalid() {
                    unsafe {
                        if let Err(close_err) = CloseHandle(handle) {
                            log::warn!("Failed to close rejected terminal token: {close_err}");
                        }
                    }
                }
                return Err(err);
            }
        };
        Ok(Self { handle, identity })
    }

    pub fn handle(&self) -> HANDLE {
        self.handle
    }

    pub fn identity(&self) -> &WindowsTokenIdentity {
        &self.identity
    }

    pub fn validate_unchanged(&self) -> Result<()> {
        let current = get_windows_token_identity(self.handle)?;
        if current != self.identity {
            return Err(anyhow!("Windows terminal launch token identity changed"));
        }
        Ok(())
    }
}

impl Drop for OwnedPrimaryToken {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                if let Err(err) = CloseHandle(self.handle) {
                    log::warn!("Failed to close terminal launch token: {err}");
                }
            }
        }
    }
}

// Windows kernel handles are process-wide; this owner exposes only immutable token queries and
// process creation, while CloseHandle runs once after the last Arc is dropped.
unsafe impl Send for OwnedPrimaryToken {}
unsafe impl Sync for OwnedPrimaryToken {}

// Named pipe configuration constants
const PIPE_BUFFER_SIZE: u32 = 65536; // 64KB for better throughput with large terminal output
const PIPE_DEFAULT_TIMEOUT_MS: u32 = 5000;
/// Timeout for waiting for helper process to connect to pipes
pub const PIPE_CONNECTION_TIMEOUT_MS: u32 = 10000;

/// Message type constants for helper protocol.
/// Used to distinguish between terminal data and control commands.
/// Note: Using non-zero values to make debugging easier (0x00 could indicate uninitialized memory).
pub const MSG_TYPE_DATA: u8 = 0x01;
pub const MSG_TYPE_RESIZE: u8 = 0x02;

/// Message header size: 1 byte type + 4 bytes length
pub const MSG_HEADER_SIZE: usize = 5;

/// Maximum payload size to prevent denial of service from malicious messages.
/// 16MB should be more than enough for any legitimate terminal data.
const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

/// RAII wrapper for Windows HANDLE that automatically closes the handle on drop.
/// This ensures proper resource cleanup even when errors occur or code paths diverge.
#[derive(Debug)]
pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    /// Create a new OwnedHandle from a raw HANDLE.
    /// The handle will be closed when this OwnedHandle is dropped.
    pub fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    /// Consume the OwnedHandle and return the raw HANDLE without closing it.
    /// Use this when transferring ownership to another resource (e.g., File).
    pub fn into_raw(self) -> HANDLE {
        let handle = self.0;
        std::mem::forget(self); // Prevent Drop from closing the handle
        handle
    }

    /// Get the raw HANDLE value.
    pub fn as_raw(&self) -> HANDLE {
        self.0
    }
}

// Kernel handles are process-wide values. Ownership is unique and closing occurs once in Drop.
unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE && !self.0.is_invalid() {
            unsafe {
                if let Err(err) = CloseHandle(self.0) {
                    log::warn!("CloseHandle failed while releasing terminal helper state: {err}");
                }
            }
        }
    }
}

const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: i32 = 9;

#[repr(C)]
#[derive(Default)]
struct JobObjectBasicLimitInformation {
    per_process_user_time_limit: i64,
    per_job_user_time_limit: i64,
    limit_flags: u32,
    minimum_working_set_size: usize,
    maximum_working_set_size: usize,
    active_process_limit: u32,
    affinity: usize,
    priority_class: u32,
    scheduling_class: u32,
}

#[repr(C)]
#[derive(Default)]
struct IoCounters {
    read_operation_count: u64,
    write_operation_count: u64,
    other_operation_count: u64,
    read_transfer_count: u64,
    write_transfer_count: u64,
    other_transfer_count: u64,
}

#[repr(C)]
#[derive(Default)]
struct JobObjectExtendedLimitInformation {
    basic_limit_information: JobObjectBasicLimitInformation,
    io_info: IoCounters,
    process_memory_limit: usize,
    job_memory_limit: usize,
    peak_process_memory_used: usize,
    peak_job_memory_used: usize,
}

#[link(name = "kernel32")]
extern "system" {
    #[link_name = "CreateJobObjectW"]
    fn create_job_object(attributes: *const SECURITY_ATTRIBUTES, name: *const u16) -> HANDLE;
    #[link_name = "SetInformationJobObject"]
    fn set_information_job_object(
        job: HANDLE,
        information_class: i32,
        information: *const c_void,
        information_length: u32,
    ) -> i32;
    #[link_name = "AssignProcessToJobObject"]
    fn assign_process_to_job_object(job: HANDLE, process: HANDLE) -> i32;
    #[link_name = "TerminateJobObject"]
    fn terminate_job_object(job: HANDLE, exit_code: u32) -> i32;
}

fn create_kill_on_close_job() -> Result<OwnedHandle> {
    let job = unsafe { create_job_object(ptr::null(), ptr::null()) };
    if job.is_invalid() {
        return Err(anyhow!(
            "CreateJobObjectW failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let job = OwnedHandle::new(job);
    let mut limits = JobObjectExtendedLimitInformation::default();
    limits.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let configured = unsafe {
        set_information_job_object(
            job.as_raw(),
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            &limits as *const _ as *const c_void,
            std::mem::size_of_val(&limits) as u32,
        )
    };
    if configured == 0 {
        return Err(anyhow!(
            "SetInformationJobObject failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(job)
}

struct SuspendedHelperProcess {
    process: Option<OwnedHandle>,
    thread: Option<OwnedHandle>,
    pid: u32,
}

impl SuspendedHelperProcess {
    fn new(info: PROCESS_INFORMATION) -> Result<Self> {
        if info.hProcess.is_invalid() || info.hThread.is_invalid() || info.dwProcessId == 0 {
            if !info.hProcess.is_invalid() {
                unsafe {
                    if let Err(err) = TerminateProcess(info.hProcess, 1) {
                        log::warn!("Failed to terminate incomplete helper process: {err}");
                    }
                    if let Err(err) = CloseHandle(info.hProcess) {
                        log::warn!("Failed to close incomplete helper process: {err}");
                    }
                }
            }
            if !info.hThread.is_invalid() {
                unsafe {
                    if let Err(err) = CloseHandle(info.hThread) {
                        log::warn!("Failed to close incomplete helper thread: {err}");
                    }
                }
            }
            return Err(anyhow!(
                "CreateProcessAsUserW returned incomplete process information"
            ));
        }
        Ok(Self {
            process: Some(OwnedHandle::new(info.hProcess)),
            thread: Some(OwnedHandle::new(info.hThread)),
            pid: info.dwProcessId,
        })
    }

    fn process_handle(&self) -> Result<HANDLE> {
        self.process
            .as_ref()
            .map(OwnedHandle::as_raw)
            .ok_or_else(|| anyhow!("Suspended helper process ownership was transferred"))
    }

    fn assign_and_resume(mut self, job: OwnedHandle) -> Result<HelperProcessTree> {
        let process = self.process_handle()?;
        if unsafe { assign_process_to_job_object(job.as_raw(), process) } == 0 {
            return Err(anyhow!(
                "AssignProcessToJobObject failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let thread = self
            .thread
            .as_ref()
            .ok_or_else(|| anyhow!("Suspended helper thread ownership was transferred"))?;
        let previous_suspend_count = unsafe { ResumeThread(thread.as_raw()) };
        if previous_suspend_count == u32::MAX {
            return Err(anyhow!(
                "ResumeThread failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if previous_suspend_count != 1 {
            return Err(anyhow!(
                "Terminal helper primary thread had unexpected suspend count {}",
                previous_suspend_count
            ));
        }
        drop(self.thread.take());
        let process = self
            .process
            .take()
            .ok_or_else(|| anyhow!("Suspended helper process ownership was transferred"))?;
        Ok(HelperProcessTree {
            job: Arc::new(job),
            process: Some(process),
            pid: self.pid,
        })
    }
}

impl Drop for SuspendedHelperProcess {
    fn drop(&mut self) {
        if let Some(process) = self.process.as_ref() {
            unsafe {
                if let Err(err) = TerminateProcess(process.as_raw(), 1) {
                    log::warn!("Failed to terminate uncommitted helper process: {err}");
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct HelperProcessTree {
    job: Arc<OwnedHandle>,
    process: Option<OwnedHandle>,
    pid: u32,
}

#[derive(Clone, Debug)]
pub struct HelperProcessTerminator {
    job: Arc<OwnedHandle>,
}

impl HelperProcessTerminator {
    pub fn terminate(&self) -> Result<()> {
        if unsafe { terminate_job_object(self.job.as_raw(), 1) } == 0 {
            return Err(anyhow!(
                "TerminateJobObject failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

impl HelperProcessTree {
    fn process_handle(&self) -> HANDLE {
        match self.process.as_ref() {
            Some(process) => process.as_raw(),
            None => HANDLE::default(),
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn terminator(&self) -> HelperProcessTerminator {
        HelperProcessTerminator {
            job: self.job.clone(),
        }
    }

    pub fn ensure_running(&self) -> Result<()> {
        if let Some(exit_code) = self.exit_code_if_exited()? {
            return Err(anyhow!(
                "Terminal helper process exited during startup with code {exit_code}"
            ));
        }
        Ok(())
    }

    pub fn exit_code_if_exited(&self) -> Result<Option<u32>> {
        let wait = unsafe { WaitForSingleObject(self.process_handle(), 0) };
        if wait == WAIT_TIMEOUT {
            return Ok(None);
        }
        if wait == WAIT_OBJECT_0 {
            let mut exit_code = 0;
            unsafe { GetExitCodeProcess(self.process_handle(), &mut exit_code) }
                .map_err(|err| anyhow!("GetExitCodeProcess failed for terminal helper: {err}"))?;
            return Ok(Some(exit_code));
        }
        if wait == WAIT_FAILED {
            return Err(anyhow!(
                "WaitForSingleObject failed for terminal helper: {}",
                std::io::Error::last_os_error()
            ));
        }
        Err(anyhow!(
            "WaitForSingleObject returned unexpected status {} for terminal helper",
            wait.0
        ))
    }
}

impl Drop for HelperProcessTree {
    fn drop(&mut self) {
        drop(self.process.take());
    }
}

unsafe impl Send for HelperProcessTree {}

/// Encode a message for the helper protocol.
/// Format: [type: u8][length: u32 LE][payload: bytes]
pub fn encode_helper_message(msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(MSG_HEADER_SIZE + payload.len());
    msg.push(msg_type);
    msg.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    msg.extend_from_slice(payload);
    msg
}

/// Encode a resize message for the helper protocol.
/// Payload: rows (u16 LE) + cols (u16 LE)
pub fn encode_resize_message(rows: u16, cols: u16) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4);
    payload.extend_from_slice(&rows.to_le_bytes());
    payload.extend_from_slice(&cols.to_le_bytes());
    encode_helper_message(MSG_TYPE_RESIZE, &payload)
}

fn trusted_system_dir() -> Result<PathBuf> {
    let mut buffer = [0u16; 260];
    let len = unsafe { GetSystemDirectoryW(Some(&mut buffer)) } as usize;
    if len == 0 {
        return Err(anyhow!(
            "GetSystemDirectoryW failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if len >= buffer.len() {
        return Err(anyhow!("GetSystemDirectoryW returned an oversized path"));
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..len])))
}

fn shell_path_string(path: PathBuf) -> Result<String> {
    let display = path.display().to_string();
    path.into_os_string().into_string().map_err(|_| {
        anyhow!(
            "trusted terminal shell path is not valid UTF-8: {}",
            display
        )
    })
}

/// Get the default shell for Windows.
pub fn get_default_shell() -> Result<String> {
    let system_dir = trusted_system_dir()?;
    let shell_paths = [
        PathBuf::from(r"C:\Program Files\PowerShell\7\pwsh.exe"),
        PathBuf::from(r"C:\Program Files\PowerShell\6\pwsh.exe"),
        system_dir
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe"),
        system_dir.join("cmd.exe"),
    ];

    for path in shell_paths {
        if path.is_file() {
            log::debug!("Found trusted terminal shell: {}", path.display());
            return shell_path_string(path);
        }
    }

    Err(anyhow!("no trusted Windows terminal shell found"))
}

fn utf8_shell_args(shell: &str) -> Vec<String> {
    let name = std::path::Path::new(shell)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(shell)
        .to_ascii_lowercase();

    if name == "cmd.exe" || name == "cmd" {
        return vec!["/K".to_string(), "chcp 65001 >NUL".to_string()];
    }

    if name == "pwsh.exe" || name == "pwsh" || name == "powershell.exe" {
        return vec![
            "-NoLogo".to_string(),
            "-NoExit".to_string(),
            "-Command".to_string(),
            "chcp.com 65001 > $null; [Console]::InputEncoding = [System.Text.Encoding]::UTF8; [Console]::OutputEncoding = [System.Text.Encoding]::UTF8".to_string(),
        ];
    }

    Vec::new()
}

pub fn configure_utf8_shell_command(shell: &str, cmd: &mut CommandBuilder) {
    for arg in utf8_shell_args(shell) {
        cmd.arg(arg);
    }
}

struct AlignedTokenInformation {
    words: Vec<usize>,
    byte_len: usize,
}

impl AlignedTokenInformation {
    fn query(
        token_handle: HANDLE,
        information_class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
    ) -> Result<Self> {
        if token_handle.is_invalid() {
            return Err(anyhow!("Invalid Windows token handle"));
        }

        let mut return_length = 0u32;
        let size_result = unsafe {
            GetTokenInformation(token_handle, information_class, None, 0, &mut return_length)
        };
        match size_result {
            Err(err) if is_windows_error(&err, ERROR_INSUFFICIENT_BUFFER) => {}
            Err(err) => {
                return Err(anyhow!("GetTokenInformation size query failed: {err}"));
            }
            Ok(()) => {}
        }
        if return_length == 0 {
            return Err(anyhow!(
                "GetTokenInformation did not report a required buffer size: {}",
                std::io::Error::last_os_error()
            ));
        }
        let byte_len = return_length as usize;
        let word_count = byte_len
            .checked_add(std::mem::size_of::<usize>() - 1)
            .ok_or_else(|| anyhow!("Token information length overflow"))?
            / std::mem::size_of::<usize>();
        let mut words = vec![0usize; word_count];
        unsafe {
            GetTokenInformation(
                token_handle,
                information_class,
                Some(words.as_mut_ptr().cast()),
                (words.len() * std::mem::size_of::<usize>()) as u32,
                &mut return_length,
            )
            .map_err(|err| anyhow!("GetTokenInformation failed: {err}"))?;
        }
        if return_length as usize > words.len() * std::mem::size_of::<usize>() {
            return Err(anyhow!(
                "GetTokenInformation returned a length larger than its buffer"
            ));
        }
        Ok(Self {
            words,
            byte_len: return_length as usize,
        })
    }

    fn as_ptr<T>(&self) -> Result<*const T> {
        if self.byte_len < std::mem::size_of::<T>() {
            return Err(anyhow!("Token information buffer is undersized"));
        }
        Ok(self.words.as_ptr().cast())
    }
}

fn get_user_sid_from_token(token_handle: HANDLE) -> Result<AlignedSid> {
    let information = AlignedTokenInformation::query(token_handle, TokenUser)?;
    let token_user = unsafe { &*information.as_ptr::<TOKEN_USER>()? };
    AlignedSid::copy_from(token_user.User.Sid)
}

const SE_GROUP_ENABLED_VALUE: u32 = 0x0000_0004;
const SE_GROUP_LOGON_ID_VALUE: u32 = 0xC000_0000;

fn get_logon_sid_from_token(token_handle: HANDLE) -> Result<AlignedSid> {
    let information = AlignedTokenInformation::query(token_handle, TokenGroups)?;
    let groups = information.as_ptr::<TOKEN_GROUPS>()?;
    let group_count = unsafe { (*groups).GroupCount as usize };
    let first_group = unsafe { ptr::addr_of!((*groups).Groups).cast::<SID_AND_ATTRIBUTES>() };
    let prefix_len = first_group as usize - groups as usize;
    let available_groups = information
        .byte_len
        .checked_sub(prefix_len)
        .ok_or_else(|| anyhow!("TOKEN_GROUPS has an invalid layout"))?
        / std::mem::size_of::<SID_AND_ATTRIBUTES>();
    if group_count > available_groups {
        return Err(anyhow!("TOKEN_GROUPS count exceeds its buffer"));
    }

    let mut logon_sid = None;
    for index in 0..group_count {
        let group = unsafe { &*first_group.add(index) };
        let is_logon = group.Attributes & SE_GROUP_LOGON_ID_VALUE == SE_GROUP_LOGON_ID_VALUE;
        let is_enabled = group.Attributes & SE_GROUP_ENABLED_VALUE != 0;
        if is_logon && is_enabled {
            if logon_sid.is_some() {
                return Err(anyhow!("Token contains multiple enabled logon SIDs"));
            }
            logon_sid = Some(AlignedSid::copy_from(group.Sid)?);
        }
    }
    logon_sid.ok_or_else(|| anyhow!("Token does not contain an enabled logon SID"))
}

fn get_windows_token_identity(token_handle: HANDLE) -> Result<WindowsTokenIdentity> {
    if token_handle.is_invalid() {
        return Err(anyhow!("Invalid Windows terminal user token"));
    }

    let mut return_length = 0u32;
    let mut session_id = 0u32;
    unsafe {
        GetTokenInformation(
            token_handle,
            TokenSessionId,
            Some(&mut session_id as *mut _ as *mut c_void),
            std::mem::size_of_val(&session_id) as u32,
            &mut return_length,
        )
        .map_err(|err| anyhow!("Failed to read terminal token session: {err}"))?;
    }

    let mut statistics = TOKEN_STATISTICS::default();
    unsafe {
        GetTokenInformation(
            token_handle,
            TokenStatistics,
            Some(&mut statistics as *mut _ as *mut c_void),
            std::mem::size_of_val(&statistics) as u32,
            &mut return_length,
        )
        .map_err(|err| anyhow!("Failed to read terminal token statistics: {err}"))?;
    }
    if statistics.TokenType != TokenPrimary {
        return Err(anyhow!(
            "Windows terminal user token is not a primary token"
        ));
    }

    let user_sid = get_user_sid_from_token(token_handle)?;
    Ok(WindowsTokenIdentity {
        session_id,
        user_sid: user_sid.as_bytes().to_vec(),
        logon_sid: get_logon_sid_from_token(token_handle)?,
        authentication_id_low: statistics.AuthenticationId.LowPart,
        authentication_id_high: statistics.AuthenticationId.HighPart,
        token_id_low: statistics.TokenId.LowPart,
        token_id_high: statistics.TokenId.HighPart,
        modified_id_low: statistics.ModifiedId.LowPart,
        modified_id_high: statistics.ModifiedId.HighPart,
    })
}

struct OwnedAcl(*mut ACL);

impl OwnedAcl {
    fn as_ptr(&self) -> *mut ACL {
        self.0
    }
}

impl Drop for OwnedAcl {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let not_freed = LocalFree(Some(HLOCAL(self.0.cast())));
                if !not_freed.0.is_null() {
                    log::warn!(
                        "LocalFree failed while releasing terminal helper pipe ACL: {}",
                        std::io::Error::last_os_error()
                    );
                }
            }
        }
    }
}

fn system_sid() -> Result<AlignedSid> {
    const SECURITY_MAX_SID_SIZE: usize = 68;
    let word_count =
        (SECURITY_MAX_SID_SIZE + std::mem::size_of::<usize>() - 1) / std::mem::size_of::<usize>();
    let mut storage = vec![0usize; word_count];
    let mut sid_size = SECURITY_MAX_SID_SIZE as u32;
    unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            None,
            Some(PSID(storage.as_mut_ptr().cast())),
            &mut sid_size,
        )
        .map_err(|e| anyhow!("Failed to create SYSTEM SID: {}", e))?;
    }
    AlignedSid::copy_from(PSID(storage.as_mut_ptr().cast()))
}

fn create_restricted_dacl(
    server_sid: &AlignedSid,
    logon_sid: &AlignedSid,
    system_access: u32,
    helper_access: u32,
) -> Result<OwnedAcl> {
    let mut explicit_access: [EXPLICIT_ACCESS_W; 2] = unsafe { std::mem::zeroed() };
    explicit_access[0].grfAccessPermissions = system_access;
    explicit_access[0].grfAccessMode = SET_ACCESS;
    explicit_access[0].grfInheritance = ACE_FLAGS(0);
    explicit_access[0].Trustee = TRUSTEE_W {
        pMultipleTrustee: ptr::null_mut(),
        MultipleTrusteeOperation: Default::default(),
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_USER,
        ptstrName: PWSTR::from_raw(server_sid.as_psid().0.cast()),
    };

    explicit_access[1].grfAccessPermissions = helper_access;
    explicit_access[1].grfAccessMode = SET_ACCESS;
    explicit_access[1].grfInheritance = ACE_FLAGS(0);
    explicit_access[1].Trustee = TRUSTEE_W {
        pMultipleTrustee: ptr::null_mut(),
        MultipleTrusteeOperation: Default::default(),
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: PWSTR::from_raw(logon_sid.as_psid().0.cast()),
    };

    let mut new_acl: *mut ACL = ptr::null_mut();
    let result = unsafe { SetEntriesInAclW(Some(&explicit_access), None, &mut new_acl) };

    if result.0 != 0 {
        return Err(anyhow!(
            "SetEntriesInAclW failed with error code: {}",
            result.0
        ));
    }

    if new_acl.is_null() {
        return Err(anyhow!("SetEntriesInAclW returned null ACL"));
    }

    Ok(OwnedAcl(new_acl))
}

fn pipe_access_rights(for_input: bool) -> (u32, u32) {
    let server_access = FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | FILE_CREATE_PIPE_INSTANCE.0;
    let client_access = if for_input {
        FILE_WRITE_DATA.0 | SYNCHRONIZE.0
    } else {
        FILE_READ_DATA.0 | SYNCHRONIZE.0
    };
    (server_access, client_access)
}

/// Create a synchronous named pipe restricted to SYSTEM and the token's logon session.
///
/// # Arguments
/// * `pipe_name` - The name of the pipe to create
/// * `for_input` - True when the service reads from the pipe (helper writes)
/// * `user_token` - Required user token for creating restricted DACL
///
pub fn create_named_pipe_server(
    pipe_name: &str,
    for_input: bool,
    user_token: &OwnedPrimaryToken,
) -> Result<HANDLE> {
    user_token.validate_unchanged()?;
    let server_sid = system_sid()?;
    create_named_pipe_server_for_principals(
        pipe_name,
        for_input,
        &server_sid,
        &user_token.identity().logon_sid,
    )
}

fn create_named_pipe_server_for_principals(
    pipe_name: &str,
    for_input: bool,
    server_sid: &AlignedSid,
    client_logon_sid: &AlignedSid,
) -> Result<HANDLE> {
    let mut security_descriptor = SECURITY_DESCRIPTOR::default();
    let sd_ptr =
        PSECURITY_DESCRIPTOR((&mut security_descriptor as *mut SECURITY_DESCRIPTOR).cast());

    // Initialize security descriptor
    unsafe {
        InitializeSecurityDescriptor(sd_ptr, 1)
            .map_err(|e| anyhow!("Failed to initialize security descriptor: {}", e))?;
    }

    let (system_access, helper_access) = pipe_access_rights(for_input);
    let acl = create_restricted_dacl(server_sid, client_logon_sid, system_access, helper_access)
        .context("Failed to create logon-scoped DACL for pipe")?;

    log::debug!(
        "Created restricted DACL for terminal helper pipe (for_input={})",
        for_input
    );

    // Set DACL on security descriptor
    unsafe {
        SetSecurityDescriptorDacl(sd_ptr, true, Some(acl.as_ptr()), false)
            .map_err(|e| anyhow!("Failed to set restricted DACL: {}", e))?;
    }

    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: (&mut security_descriptor as *mut SECURITY_DESCRIPTOR).cast(),
        bInheritHandle: false.into(),
    };

    let wide_name: Vec<u16> = OsStr::new(pipe_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let access_mode =
        FILE_FLAGS_AND_ATTRIBUTES(PIPE_ACCESS_DUPLEX.0 | FILE_FLAG_FIRST_PIPE_INSTANCE.0);

    log::debug!(
        "Creating terminal helper pipe (for_input={}, restricted_dacl=true, first_instance=true, local_only=true)",
        for_input
    );

    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR::from_raw(wide_name.as_ptr()),
            access_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1, // max instances
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            PIPE_DEFAULT_TIMEOUT_MS,
            Some(&sa),
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(anyhow!(
            "Failed to create terminal helper pipe (for_input={}): {}",
            for_input,
            std::io::Error::last_os_error()
        ));
    }

    log::debug!("Terminal helper pipe created (for_input={})", for_input);
    Ok(handle)
}

fn ensure_named_pipe_client_pid(
    pipe_handle: HANDLE,
    pipe_role: &str,
    helper: &HelperProcessTree,
) -> Result<()> {
    let expected_client_pid = helper.pid();
    if expected_client_pid == 0 {
        return Err(anyhow!(
            "Refusing {} terminal helper pipe connection without an expected client PID",
            pipe_role
        ));
    }

    let mut client_pid = 0u32;
    unsafe {
        GetNamedPipeClientProcessId(pipe_handle, &mut client_pid).map_err(|e| {
            anyhow!(
                "Failed to query {} terminal helper pipe client PID: {}",
                pipe_role,
                e
            )
        })?;
    }
    if client_pid == 0 {
        return Err(anyhow!(
            "{} terminal helper pipe client PID query returned pid 0",
            pipe_role
        ));
    }
    if client_pid != expected_client_pid {
        return Err(anyhow!(
            "Rejected {} terminal helper pipe client PID {} (expected {})",
            pipe_role,
            client_pid,
            expected_client_pid
        ));
    }

    log::debug!(
        "Accepted {} terminal helper pipe client PID {}",
        pipe_role,
        client_pid
    );
    Ok(())
}

fn validate_helper_process_principal(
    helper: &HelperProcessTree,
    expected_token: &OwnedPrimaryToken,
) -> Result<()> {
    let process = helper.process_handle();
    if process.is_invalid() {
        return Err(anyhow!("Terminal helper process handle is invalid"));
    }
    let mut process_token = HANDLE::default();
    unsafe {
        OpenProcessToken(process, TOKEN_QUERY, &mut process_token)
            .map_err(|err| anyhow!("Failed to open terminal helper process token: {err}"))?;
    }
    let process_token = OwnedHandle::new(process_token);
    let actual = get_windows_token_identity(process_token.as_raw())?;
    if !actual.same_principal(expected_token.identity()) {
        return Err(anyhow!(
            "Terminal helper process principal does not match its launch authority"
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct TerminalOpeningCancelled;

impl std::fmt::Display for TerminalOpeningCancelled {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Terminal helper opening was cancelled")
    }
}

impl std::error::Error for TerminalOpeningCancelled {}

fn ensure_pipe_connection_active(
    timeout_cancelled: &AtomicBool,
    opening_cancelled: &AtomicBool,
) -> Result<()> {
    if opening_cancelled.load(Ordering::Acquire) {
        return Err(anyhow!(TerminalOpeningCancelled));
    }
    if timeout_cancelled.load(Ordering::Acquire) {
        return Err(anyhow!("Terminal helper pipe timeout was cancelled"));
    }
    Ok(())
}

fn connect_named_pipe_synchronously(
    pipe_handle: OwnedHandle,
    timeout_cancelled: &AtomicBool,
    opening_cancelled: &AtomicBool,
) -> Result<OwnedHandle> {
    loop {
        ensure_pipe_connection_active(timeout_cancelled, opening_cancelled)?;
        match unsafe { ConnectNamedPipe(pipe_handle.as_raw(), None) } {
            Ok(()) => break,
            Err(err) if is_windows_error(&err, ERROR_PIPE_CONNECTED) => break,
            Err(err) if is_windows_error(&err, ERROR_PIPE_LISTENING) => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(err) => return Err(anyhow!("ConnectNamedPipe failed: {err}")),
        }
    }

    ensure_pipe_connection_active(timeout_cancelled, opening_cancelled)?;
    let blocking_mode = PIPE_READMODE_BYTE | PIPE_WAIT;
    unsafe {
        SetNamedPipeHandleState(pipe_handle.as_raw(), Some(&blocking_mode), None, None)
            .map_err(|err| anyhow!("Failed to restore blocking pipe mode: {err}"))?;
    }
    ensure_pipe_connection_active(timeout_cancelled, opening_cancelled)?;
    Ok(pipe_handle)
}

fn join_pipe_worker(worker: thread::JoinHandle<()>, pipe_role: &str) -> Result<()> {
    worker
        .join()
        .map_err(|_| anyhow!("{} terminal helper pipe worker panicked", pipe_role))
}

/// Connect a non-overlapped pipe on a cancellable worker, then restore blocking mode before the
/// handle is used for synchronous reads or writes. The worker is always joined before return.
pub fn wait_for_pipe_connection(
    pipe_handle: OwnedHandle,
    pipe_role: &str,
    timeout_ms: u32,
    opening_cancelled: &Arc<AtomicBool>,
    helper: &HelperProcessTree,
    expected_token: &OwnedPrimaryToken,
) -> Result<File> {
    log::debug!("Waiting for {} terminal helper pipe connection", pipe_role);
    let timeout_cancelled = Arc::new(AtomicBool::new(false));
    let worker_timeout_cancelled = Arc::clone(&timeout_cancelled);
    let worker_opening_cancelled = Arc::clone(opening_cancelled);
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let worker = thread::Builder::new()
        .name(format!("terminal-pipe-connect-{pipe_role}"))
        .spawn(move || {
            let result = connect_named_pipe_synchronously(
                pipe_handle,
                worker_timeout_cancelled.as_ref(),
                worker_opening_cancelled.as_ref(),
            );
            if result_tx.send(result).is_err() {
                log::debug!("Terminal helper pipe connection receiver was dropped");
            }
        })
        .map_err(|err| anyhow!("Failed to spawn {} pipe worker: {err}", pipe_role))?;

    let connected_pipe = match result_rx.recv_timeout(Duration::from_millis(timeout_ms as u64)) {
        Ok(result) => {
            join_pipe_worker(worker, pipe_role)?;
            result?
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            timeout_cancelled.store(true, Ordering::Release);
            join_pipe_worker(worker, pipe_role)?;
            return Err(anyhow!(
                "Timeout waiting for {} terminal helper pipe connection",
                pipe_role
            ));
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            join_pipe_worker(worker, pipe_role)?;
            return Err(anyhow!(
                "{} terminal helper pipe worker exited without a result",
                pipe_role
            ));
        }
    };

    ensure_pipe_connection_active(timeout_cancelled.as_ref(), opening_cancelled.as_ref())?;
    ensure_named_pipe_client_pid(connected_pipe.as_raw(), pipe_role, helper)?;
    validate_helper_process_principal(helper, expected_token)?;
    ensure_pipe_connection_active(timeout_cancelled.as_ref(), opening_cancelled.as_ref())?;
    Ok(unsafe { File::from_raw_handle(connected_pipe.into_raw().0 as RawHandle) })
}

/// Launch terminal helper process as the logged-in user using the provided token.
/// The helper process creates ConPTY and shell, communicating via named pipes.
/// This uses CreateProcessAsUserW directly with the user token, which works because
/// the helper process itself doesn't need ConPTY - it creates ConPTY internally.
///
/// RAII guard for environment block cleanup.
/// Ensures DestroyEnvironmentBlock is called even if an error occurs.
struct EnvironmentBlockGuard {
    ptr: *mut c_void,
}

impl EnvironmentBlockGuard {
    fn for_token(token: HANDLE) -> Result<Self> {
        let mut environment = ptr::null_mut();
        unsafe {
            CreateEnvironmentBlock(&mut environment, Some(token), false)
                .map_err(|err| anyhow!("CreateEnvironmentBlock failed: {err}"))?;
        }
        if environment.is_null() {
            return Err(anyhow!("CreateEnvironmentBlock returned a null block"));
        }
        Ok(Self { ptr: environment })
    }
}

impl Drop for EnvironmentBlockGuard {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                if let Err(err) = DestroyEnvironmentBlock(self.ptr) {
                    log::warn!("DestroyEnvironmentBlock failed: {err}");
                }
            }
        }
    }
}

fn profile_directory_for_token(token: HANDLE) -> Result<Vec<u16>> {
    let mut required_chars = 0u32;
    match unsafe { GetUserProfileDirectoryW(token, None, &mut required_chars) } {
        Err(err) if is_windows_error(&err, ERROR_INSUFFICIENT_BUFFER) => {}
        Err(err) => {
            return Err(anyhow!("GetUserProfileDirectoryW size query failed: {err}"));
        }
        Ok(()) => {}
    }
    if required_chars < 2 {
        return Err(anyhow!(
            "GetUserProfileDirectoryW did not report a valid buffer size: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut profile = vec![0u16; required_chars as usize];
    unsafe {
        GetUserProfileDirectoryW(
            token,
            Some(PWSTR::from_raw(profile.as_mut_ptr())),
            &mut required_chars,
        )
        .map_err(|err| anyhow!("GetUserProfileDirectoryW failed: {err}"))?;
    }
    let returned_chars = required_chars as usize;
    if returned_chars < 2
        || returned_chars > profile.len()
        || profile.get(returned_chars - 1) != Some(&0)
    {
        return Err(anyhow!(
            "GetUserProfileDirectoryW returned an invalid terminated path"
        ));
    }
    profile.truncate(returned_chars);
    let path = PathBuf::from(OsString::from_wide(&profile[..returned_chars - 1]));
    if !path.is_absolute() || !path.is_dir() {
        return Err(anyhow!(
            "User profile working directory is not an existing absolute directory"
        ));
    }
    Ok(profile)
}

pub fn launch_terminal_helper_with_token(
    user_token: &OwnedPrimaryToken,
    input_pipe_name: &str,
    output_pipe_name: &str,
    terminal_id: i32,
    rows: u16,
    cols: u16,
) -> Result<HelperProcessTree> {
    user_token.validate_unchanged()?;
    let exe_path =
        std::env::current_exe().map_err(|e| anyhow!("Failed to get current exe path: {}", e))?;

    // Build command line arguments (without exe path to avoid escaping issues)
    // lpApplicationName will contain the exe path separately
    let cmd_args = format!(
        "--terminal-helper {} {} {} {} {}",
        input_pipe_name, output_pipe_name, rows, cols, terminal_id
    );

    log::debug!("Launching terminal helper for terminal {}", terminal_id);

    // Convert exe path to wide string for lpApplicationName
    let exe_path_wide: Vec<u16> = OsStr::new(exe_path.as_os_str())
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Command line must include exe name as first argument per Windows convention
    let cmd_line = format!("\"{}\" {}", exe_path.display(), cmd_args);
    let mut cmd_wide: Vec<u16> = OsStr::new(&cmd_line)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let environment = EnvironmentBlockGuard::for_token(user_token.handle())?;
    let profile_directory = profile_directory_for_token(user_token.handle())?;
    let job = create_kill_on_close_job()?;
    let creation_flags = CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;

    // Use lpApplicationName to pass exe path separately from command line
    // This avoids potential issues with special characters in the exe path
    let result = unsafe {
        CreateProcessAsUserW(
            Some(user_token.handle()),
            PCWSTR::from_raw(exe_path_wide.as_ptr()), // lpApplicationName: exe path
            Some(PWSTR::from_raw(cmd_wide.as_mut_ptr())), // lpCommandLine: full command
            None,
            None,
            false, // Don't inherit handles
            creation_flags,
            Some(environment.ptr),
            PCWSTR::from_raw(profile_directory.as_ptr()),
            &si,
            &mut pi,
        )
    };

    if let Err(e) = result {
        log::error!("CreateProcessAsUserW failed: {}", e);
        return Err(anyhow!("Failed to launch terminal helper: {}", e));
    }

    let process = SuspendedHelperProcess::new(pi)?;
    let helper = process.assign_and_resume(job)?;
    validate_helper_process_principal(&helper, user_token)?;
    helper.ensure_running()?;
    log::info!("Terminal helper launched with PID {}", helper.pid());
    Ok(helper)
}

const SYNCHRONOUS_IO_CANCELLATION_TIMEOUT: Duration = Duration::from_secs(2);

fn cancel_pending_synchronous_io<T>(
    worker: &thread::JoinHandle<T>,
    worker_name: &str,
) -> Result<()> {
    let deadline = Instant::now() + SYNCHRONOUS_IO_CANCELLATION_TIMEOUT;
    loop {
        if worker.is_finished() {
            return Ok(());
        }

        let thread_handle = HANDLE(worker.as_raw_handle() as _);
        match unsafe { CancelSynchronousIo(thread_handle) } {
            Ok(()) => {}
            Err(err) if is_windows_error(&err, ERROR_NOT_FOUND) => {}
            Err(err) => {
                return Err(anyhow!(
                    "CancelSynchronousIo failed for {worker_name}: {err}"
                ));
            }
        }
        if Instant::now() >= deadline {
            if worker.is_finished() {
                return Ok(());
            }
            return Err(anyhow!(
                "Timed out waiting for {worker_name} to finish after synchronous I/O cancellation"
            ));
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn join_cancelled_io_thread(worker: thread::JoinHandle<()>, worker_name: &str) -> Result<()> {
    worker
        .join()
        .map_err(|_| anyhow!("{worker_name} panicked during terminal helper shutdown"))
}

fn shutdown_helper_io_threads(
    input_thread: thread::JoinHandle<()>,
    output_thread: thread::JoinHandle<()>,
) -> Result<()> {
    let input_cancellation = cancel_pending_synchronous_io(&input_thread, "input pipe worker");
    let output_cancellation = cancel_pending_synchronous_io(&output_thread, "output pipe worker");
    if input_cancellation.is_err() || output_cancellation.is_err() {
        if let Err(err) = input_cancellation {
            log::error!("Terminal helper input cancellation failed: {err}");
        }
        if let Err(err) = output_cancellation {
            log::error!("Terminal helper output cancellation failed: {err}");
        }
        std::process::exit(1);
    }
    let input_result = join_cancelled_io_thread(input_thread, "Input pipe worker");
    let output_result = join_cancelled_io_thread(output_thread, "Output pipe worker");

    match (input_result, output_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(input), Ok(())) => Err(input),
        (Ok(()), Err(output)) => Err(output),
        (Err(input), Err(output)) => Err(anyhow!(
            "Terminal helper I/O shutdown failed: input: {input}; output: {output}"
        )),
    }
}

fn is_expected_shutdown_io_error(error: &std::io::Error, exiting: &AtomicBool) -> bool {
    exiting.load(Ordering::Acquire) && is_operation_aborted(error)
}

fn is_operation_aborted(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(ERROR_OPERATION_ABORTED.0 as i32)
}

fn write_all_or_shutdown<W: Write>(
    writer: &mut W,
    mut data: &[u8],
    exiting: &AtomicBool,
) -> std::io::Result<()> {
    while !data.is_empty() {
        if exiting.load(Ordering::Acquire) {
            return Err(std::io::Error::from_raw_os_error(
                ERROR_OPERATION_ABORTED.0 as i32,
            ));
        }
        match writer.write(data) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write the terminal helper stream",
                ));
            }
            Ok(written) => data = &data[written..],
            Err(err) if is_operation_aborted(&err) => return Err(err),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// Run terminal helper process
/// Args: --terminal-helper <input_pipe_name> <output_pipe_name> <rows> <cols> <terminal_id>
pub fn run_terminal_helper(args: &[String]) -> Result<i32> {
    if crate::platform::is_root() {
        return Err(anyhow!(
            "Refusing to run the terminal helper as LocalSystem"
        ));
    }
    if args.len() < 5 {
        return Err(anyhow!(
            "Usage: --terminal-helper <input_pipe> <output_pipe> <rows> <cols> <terminal_id>"
        ));
    }

    let input_pipe_name = &args[0];
    let output_pipe_name = &args[1];
    let rows: u16 = args[2]
        .parse()
        .map_err(|e| anyhow!("Failed to parse rows '{}': {}", args[2], e))?;
    let cols: u16 = args[3]
        .parse()
        .map_err(|e| anyhow!("Failed to parse cols '{}': {}", args[3], e))?;
    let terminal_id: i32 = args[4]
        .parse()
        .map_err(|e| anyhow!("Failed to parse terminal_id '{}': {}", args[4], e))?;

    log::debug!(
        "Terminal helper starting: terminal_id={}, size={}x{}",
        terminal_id,
        cols,
        rows
    );

    // Open named pipes (created by the service)
    let input_pipe = open_pipe(input_pipe_name, true)?;
    let output_pipe = open_pipe(output_pipe_name, false)?;

    // Create ConPTY and shell
    let pty_size = PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    };

    let pty_system = portable_pty::native_pty_system();
    let pty_pair = pty_system.openpty(pty_size).context("Failed to open PTY")?;

    let shell = get_default_shell()?;
    log::debug!("Using shell: {}", shell);

    let mut cmd = CommandBuilder::new(&shell);
    configure_utf8_shell_command(&shell, &mut cmd);
    let mut child = pty_pair
        .slave
        .spawn_command(cmd)
        .context("Failed to spawn shell")?;

    // Explicitly drop slave after spawning to release resources
    drop(pty_pair.slave);

    let pid = child.process_id().unwrap_or(0);
    log::debug!("Shell started with PID: {}", pid);

    let mut pty_writer = pty_pair
        .master
        .take_writer()
        .context("Failed to get PTY writer")?;

    let mut pty_reader = pty_pair
        .master
        .try_clone_reader()
        .context("Failed to get PTY reader")?;

    // Wrap pty_pair.master in Arc<Mutex> for sharing with input thread (for resize).
    let pty_master: Arc<Mutex<Box<dyn MasterPty + Send>>> = Arc::new(Mutex::new(pty_pair.master));

    let exiting = Arc::new(AtomicBool::new(false));

    // Thread: Read from input pipe, parse messages, write data to PTY or handle control commands
    let exiting_clone = exiting.clone();
    let pty_master_clone = pty_master.clone();
    let input_thread = thread::spawn(move || {
        let mut input_pipe = input_pipe;
        let mut header_buf = [0u8; MSG_HEADER_SIZE];
        let mut payload_buf = vec![0u8; 4096];

        loop {
            if exiting_clone.load(Ordering::SeqCst) {
                break;
            }

            // Read message header
            match read_exact_or_eof(&mut input_pipe, &mut header_buf, exiting_clone.as_ref()) {
                Ok(false) => {
                    log::debug!("Input pipe EOF");
                    break;
                }
                Ok(true) => {}
                Err(e) => {
                    if is_expected_shutdown_io_error(&e, exiting_clone.as_ref()) {
                        log::debug!("Input pipe read cancelled during helper shutdown");
                    } else {
                        log::error!("Input pipe header read error: {}", e);
                    }
                    break;
                }
            }

            let msg_type = header_buf[0];
            let payload_len =
                u32::from_le_bytes([header_buf[1], header_buf[2], header_buf[3], header_buf[4]])
                    as usize;

            // Validate payload length to prevent denial of service
            if payload_len > MAX_PAYLOAD_SIZE {
                log::error!(
                    "Payload too large: {} bytes (max {})",
                    payload_len,
                    MAX_PAYLOAD_SIZE
                );
                break;
            }

            // Ensure payload buffer is large enough
            if payload_buf.len() < payload_len {
                payload_buf.resize(payload_len, 0);
            }

            // Read payload
            if payload_len > 0 {
                match read_exact_or_eof(
                    &mut input_pipe,
                    &mut payload_buf[..payload_len],
                    exiting_clone.as_ref(),
                ) {
                    Ok(false) => {
                        log::debug!("Input pipe EOF during payload read");
                        break;
                    }
                    Ok(true) => {}
                    Err(e) => {
                        if is_expected_shutdown_io_error(&e, exiting_clone.as_ref()) {
                            log::debug!("Input pipe payload read cancelled during helper shutdown");
                        } else {
                            log::error!("Input pipe payload read error: {}", e);
                        }
                        break;
                    }
                }
            }

            match msg_type {
                MSG_TYPE_DATA => {
                    // Write terminal data to PTY
                    if let Err(e) = write_all_or_shutdown(
                        &mut pty_writer,
                        &payload_buf[..payload_len],
                        exiting_clone.as_ref(),
                    ) {
                        if is_expected_shutdown_io_error(&e, exiting_clone.as_ref()) {
                            log::debug!("PTY write cancelled during helper shutdown");
                        } else {
                            log::error!("PTY write error: {}", e);
                        }
                        break;
                    }
                    if let Err(e) = pty_writer.flush() {
                        if is_expected_shutdown_io_error(&e, exiting_clone.as_ref()) {
                            log::debug!("PTY flush cancelled during helper shutdown");
                        } else {
                            log::error!("PTY flush error: {}", e);
                        }
                        break;
                    }
                }
                MSG_TYPE_RESIZE => {
                    if payload_len >= 4 {
                        let rows = u16::from_le_bytes([payload_buf[0], payload_buf[1]]);
                        let cols = u16::from_le_bytes([payload_buf[2], payload_buf[3]]);
                        log::debug!("Resize: {}x{}", cols, rows);
                        match pty_master_clone.lock() {
                            Ok(master) => {
                                if let Err(err) = master.resize(PtySize {
                                    rows,
                                    cols,
                                    pixel_width: 0,
                                    pixel_height: 0,
                                }) {
                                    log::error!("PTY resize failed: {err}");
                                    break;
                                }
                            }
                            Err(err) => {
                                log::error!("PTY resize lock was poisoned: {err}");
                                break;
                            }
                        }
                    }
                }
                _ => {
                    // Unknown type may indicate data corruption - stop to avoid parse errors
                    log::error!("Unknown message type: {}, terminating", msg_type);
                    break;
                }
            }
        }
        log::debug!("Input thread exiting");
    });

    // Thread: Read from PTY, write to output pipe
    let exiting_clone = exiting.clone();
    let output_thread = thread::spawn(move || {
        let mut output_pipe = output_pipe;
        let mut buf = vec![0u8; 4096];
        loop {
            if exiting_clone.load(Ordering::SeqCst) {
                break;
            }
            match pty_reader.read(&mut buf) {
                Ok(0) => {
                    log::debug!("PTY EOF");
                    break;
                }
                Ok(n) => {
                    if let Err(e) =
                        write_all_or_shutdown(&mut output_pipe, &buf[..n], exiting_clone.as_ref())
                    {
                        if is_expected_shutdown_io_error(&e, exiting_clone.as_ref()) {
                            log::debug!("Output pipe write cancelled during helper shutdown");
                        } else {
                            log::error!("Output pipe write error: {}", e);
                        }
                        break;
                    }
                    if let Err(e) = output_pipe.flush() {
                        if is_expected_shutdown_io_error(&e, exiting_clone.as_ref()) {
                            log::debug!("Output pipe flush cancelled during helper shutdown");
                        } else {
                            log::error!("Output pipe flush error: {}", e);
                        }
                        break;
                    }
                }
                Err(e) => {
                    if is_expected_shutdown_io_error(&e, exiting_clone.as_ref()) {
                        log::debug!("PTY read cancelled during helper shutdown");
                        break;
                    } else if e.kind() != std::io::ErrorKind::WouldBlock {
                        log::error!("PTY read error: {}", e);
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
        log::debug!("Output thread exiting");
    });

    // Wait for child process to exit
    let exit_status = child.wait().context("Failed to wait for terminal shell");
    match &exit_status {
        Ok(status) => log::info!("Shell exited: {:?}", status),
        Err(err) => log::error!("Terminal shell wait failed: {err}"),
    }

    exiting.store(true, Ordering::SeqCst);
    let io_shutdown = shutdown_helper_io_threads(input_thread, output_thread);

    // pty_master will be dropped here, releasing PTY resources
    drop(pty_master);

    let exit_code = match (exit_status, io_shutdown) {
        (Err(wait), Err(shutdown)) => {
            return Err(anyhow!(
                "Terminal helper shutdown failed: shell wait: {wait}; I/O shutdown: {shutdown}"
            ));
        }
        (Err(wait), Ok(())) => return Err(wait),
        (Ok(_), Err(shutdown)) => return Err(shutdown),
        (Ok(status), Ok(())) => status.exit_code() as i32,
    };

    log::info!("Terminal helper exiting");
    Ok(exit_code)
}

/// Read exactly `buf.len()` bytes from reader.
/// Returns Ok(true) if successful, Ok(false) on EOF, Err on error.
fn read_exact_or_eof<R: Read>(
    reader: &mut R,
    buf: &mut [u8],
    exiting: &AtomicBool,
) -> std::io::Result<bool> {
    let mut pos = 0;
    while pos < buf.len() {
        if exiting.load(Ordering::Acquire) {
            return Err(std::io::Error::from_raw_os_error(
                ERROR_OPERATION_ABORTED.0 as i32,
            ));
        }
        match reader.read(&mut buf[pos..]) {
            Ok(0) => return Ok(false), // EOF
            Ok(n) => pos += n,
            Err(e) if is_operation_aborted(&e) => return Err(e),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Open a named pipe as a client.
/// `for_read`: true for reading (input pipe), false for writing (output pipe).
fn open_pipe(pipe_name: &str, for_read: bool) -> Result<File> {
    let wide_name: Vec<u16> = OsStr::new(pipe_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let access = if for_read {
        FILE_READ_DATA.0 | SYNCHRONIZE.0
    } else {
        FILE_WRITE_DATA.0 | SYNCHRONIZE.0
    };

    let handle = unsafe {
        CreateFileW(
            PCWSTR::from_raw(wide_name.as_ptr()),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    };

    match handle {
        Ok(h) => Ok(unsafe { File::from_raw_handle(h.0 as _) }),
        Err(e) => Err(anyhow!(
            "Failed to open {} pipe '{}': {}",
            if for_read { "input" } else { "output" },
            pipe_name,
            e
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{atomic::AtomicU32, mpsc::RecvTimeoutError};
    use windows::Win32::Storage::FileSystem::FILE_APPEND_DATA;

    fn identity(logon_tag: usize) -> WindowsTokenIdentity {
        WindowsTokenIdentity {
            session_id: 7,
            user_sid: vec![1, 2, 3],
            logon_sid: AlignedSid {
                words: vec![logon_tag],
                byte_len: std::mem::size_of::<usize>(),
            },
            authentication_id_low: 11,
            authentication_id_high: 13,
            token_id_low: 17,
            token_id_high: 19,
            modified_id_low: 23,
            modified_id_high: 29,
        }
    }

    #[test]
    fn helper_principal_uses_logon_authority_not_token_object_identity() {
        let expected = identity(31);
        let mut same_principal = expected.clone();
        same_principal.token_id_low += 1;
        same_principal.modified_id_low += 1;
        assert!(expected.same_principal(&same_principal));

        let mut different_logon = expected.clone();
        different_logon.logon_sid = identity(37).logon_sid;
        assert!(!expected.same_principal(&different_logon));

        let mut different_authentication = expected.clone();
        different_authentication.authentication_id_low += 1;
        assert!(!expected.same_principal(&different_authentication));

        let mut different_session = expected.clone();
        different_session.session_id += 1;
        assert!(!expected.same_principal(&different_session));

        let mut different_user = expected.clone();
        different_user.user_sid.push(4);
        assert!(!expected.same_principal(&different_user));
    }

    #[test]
    fn pipe_acl_rights_are_directional() {
        let required_server_access =
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | FILE_CREATE_PIPE_INSTANCE.0;

        let (server_access, helper_write) = pipe_access_rights(true);
        assert_eq!(server_access, required_server_access);
        assert_eq!(helper_write, FILE_WRITE_DATA.0 | SYNCHRONIZE.0);
        assert_eq!(helper_write & FILE_APPEND_DATA.0, 0);
        assert_eq!(helper_write & FILE_CREATE_PIPE_INSTANCE.0, 0);

        let (server_access, helper_read) = pipe_access_rights(false);
        assert_eq!(server_access, required_server_access);
        assert_eq!(helper_read, FILE_READ_DATA.0 | SYNCHRONIZE.0);
        assert_eq!(helper_read & FILE_APPEND_DATA.0, 0);
        assert_eq!(helper_read & FILE_CREATE_PIPE_INSTANCE.0, 0);
    }

    fn current_process_token() -> Result<OwnedPrimaryToken> {
        let mut token = HANDLE::default();
        unsafe {
            OpenProcessToken(
                windows::Win32::System::Threading::GetCurrentProcess(),
                TOKEN_QUERY,
                &mut token,
            )
            .map_err(|err| anyhow!("Failed to open test process token: {err}"))?;
        }
        OwnedPrimaryToken::from_raw(token.0 as usize)
    }

    fn test_pipe_name() -> String {
        static NEXT_PIPE: AtomicU32 = AtomicU32::new(1);
        format!(
            r"\\.\pipe\rustdesk_terminal_test_{}_{}",
            std::process::id(),
            NEXT_PIPE.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn connected_test_pipe(for_input: bool) -> Result<(File, File)> {
        let token = current_process_token()?;
        let server_sid = get_user_sid_from_token(token.handle())?;
        let pipe_name = test_pipe_name();
        let server = OwnedHandle::new(create_named_pipe_server_for_principals(
            &pipe_name,
            for_input,
            &server_sid,
            &token.identity().logon_sid,
        )?);
        let timeout_cancelled = Arc::new(AtomicBool::new(false));
        let opening_cancelled = Arc::new(AtomicBool::new(false));
        let worker_timeout_cancelled = Arc::clone(&timeout_cancelled);
        let worker_opening_cancelled = Arc::clone(&opening_cancelled);
        let worker = thread::spawn(move || {
            connect_named_pipe_synchronously(
                server,
                worker_timeout_cancelled.as_ref(),
                worker_opening_cancelled.as_ref(),
            )
        });
        let client = open_pipe(&pipe_name, !for_input)?;
        let server = worker
            .join()
            .map_err(|_| anyhow!("Test pipe connection worker panicked"))??;
        let server = unsafe { File::from_raw_handle(server.into_raw().0 as RawHandle) };
        Ok((server, client))
    }

    fn assert_blocking_round_trip(mut reader: File, mut writer: File) {
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        let reader_thread = thread::spawn(move || {
            let mut received = [0u8; 4];
            started_tx.send(()).unwrap();
            let result = reader.read_exact(&mut received).map(|()| received);
            result_tx.send(result).unwrap();
        });

        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            result_rx.recv_timeout(Duration::from_millis(50)),
            Err(RecvTimeoutError::Timeout)
        ));
        writer.write_all(b"pipe").unwrap();
        writer.flush().unwrap();
        assert_eq!(
            result_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap(),
            *b"pipe"
        );
        reader_thread.join().unwrap();
    }

    #[test]
    fn synchronous_pipe_directions_restore_blocking_io() {
        let (service_reader, helper_writer) = connected_test_pipe(true).unwrap();
        assert_blocking_round_trip(service_reader, helper_writer);

        let (service_writer, helper_reader) = connected_test_pipe(false).unwrap();
        assert_blocking_round_trip(helper_reader, service_writer);
    }

    #[test]
    fn external_opening_cancellation_stops_pipe_polling() {
        let token = current_process_token().unwrap();
        let server_sid = get_user_sid_from_token(token.handle()).unwrap();
        let pipe_name = test_pipe_name();
        let server = OwnedHandle::new(
            create_named_pipe_server_for_principals(
                &pipe_name,
                true,
                &server_sid,
                &token.identity().logon_sid,
            )
            .unwrap(),
        );
        let timeout_cancelled = Arc::new(AtomicBool::new(false));
        let opening_cancelled = Arc::new(AtomicBool::new(false));
        let worker_timeout_cancelled = Arc::clone(&timeout_cancelled);
        let worker_opening_cancelled = Arc::clone(&opening_cancelled);
        let worker = thread::spawn(move || {
            connect_named_pipe_synchronously(
                server,
                worker_timeout_cancelled.as_ref(),
                worker_opening_cancelled.as_ref(),
            )
        });

        thread::sleep(Duration::from_millis(20));
        opening_cancelled.store(true, Ordering::Release);
        let error = worker.join().unwrap().unwrap_err();
        assert!(error.downcast_ref::<TerminalOpeningCancelled>().is_some());
    }

    #[test]
    fn synchronous_read_is_cancelled_before_join() {
        let (mut service_reader, _helper_writer) = connected_test_pipe(true).unwrap();
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let reader_thread = thread::spawn(move || {
            let mut byte = [0u8; 1];
            started_tx.send(()).unwrap();
            service_reader.read(&mut byte).map(|_| ())
        });

        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        cancel_pending_synchronous_io(&reader_thread, "test pipe reader").unwrap();
        let error = reader_thread.join().unwrap().unwrap_err();
        assert_eq!(error.raw_os_error(), Some(ERROR_OPERATION_ABORTED.0 as i32));
    }

    #[test]
    fn repeated_synchronous_reads_are_cancelled_before_join() {
        let (mut service_reader, _helper_writer) = connected_test_pipe(true).unwrap();
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let entered_second_read = Arc::new(AtomicBool::new(false));
        let worker_entered_second_read = Arc::clone(&entered_second_read);
        let reader_thread = thread::spawn(move || {
            let mut byte = [0u8; 1];
            started_tx.send(()).unwrap();
            let first_error = service_reader.read(&mut byte).unwrap_err();
            assert_eq!(
                first_error.raw_os_error(),
                Some(ERROR_OPERATION_ABORTED.0 as i32)
            );
            worker_entered_second_read.store(true, Ordering::Release);
            service_reader.read(&mut byte).map(|_| ())
        });

        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        cancel_pending_synchronous_io(&reader_thread, "repeating test pipe reader").unwrap();
        assert!(entered_second_read.load(Ordering::Acquire));
        let error = reader_thread.join().unwrap().unwrap_err();
        assert_eq!(error.raw_os_error(), Some(ERROR_OPERATION_ABORTED.0 as i32));
    }

    #[test]
    fn job_limit_information_matches_win32_abi_size() {
        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            std::mem::size_of::<JobObjectExtendedLimitInformation>(),
            144
        );
        #[cfg(target_pointer_width = "32")]
        assert_eq!(
            std::mem::size_of::<JobObjectExtendedLimitInformation>(),
            112
        );
    }
}
