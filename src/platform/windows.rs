use super::{CursorData, ResultType};
use crate::{ipc, privacy_mode::win_topmost_window};
use hbb_common::{
    allow_err,
    anyhow::anyhow,
    bail,
    config::{self, Config},
    libc::{c_int, wchar_t},
    log,
    message_proto::{DisplayInfo, Resolution, WindowsSession},
    sha2::{Digest, Sha256},
    tokio::{
        self,
        sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore},
        task::JoinSet,
    },
};
use std::{
    collections::HashMap,
    ffi::{CString, OsStr, OsString},
    fs,
    io::{self, prelude::*},
    mem,
    os::{
        raw::c_ulong,
        windows::{
            ffi::OsStrExt,
            ffi::OsStringExt,
            fs::{MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::*,
    ptr::null_mut,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc as std_mpsc, Arc, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};
use wallpaper;
#[cfg(not(debug_assertions))]
use winapi::um::libloaderapi::{LoadLibraryExW, LOAD_LIBRARY_SEARCH_USER_DIRS};
use winapi::{
    ctypes::c_void,
    shared::{minwindef::*, ntdef::NULL, windef::*, winerror::*},
    um::{
        errhandlingapi::GetLastError,
        fileapi::{
            CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, OPEN_EXISTING,
        },
        handleapi::{CloseHandle, SetHandleInformation, INVALID_HANDLE_VALUE},
        jobapi2::{
            CreateJobObjectW, QueryInformationJobObject, SetInformationJobObject,
            TerminateJobObject,
        },
        libloaderapi::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32},
        processthreadsapi::{
            GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, OpenProcess, OpenProcessToken,
            ProcessIdToSessionId,
        },
        securitybaseapi::GetTokenInformation,
        synchapi::WaitForSingleObject,
        sysinfoapi::{GetNativeSystemInfo, SYSTEM_INFO},
        winbase::*,
        wingdi::*,
        winnt::{
            JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation, TokenElevation,
            ES_AWAYMODE_REQUIRED, ES_CONTINUOUS, ES_DISPLAY_REQUIRED, ES_SYSTEM_REQUIRED,
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_TEMPORARY, FILE_READ_ATTRIBUTES,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, HANDLE,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, PROCESS_QUERY_LIMITED_INFORMATION, SYNCHRONIZE,
            TOKEN_ELEVATION, TOKEN_QUERY,
        },
        winreg::HKEY_CURRENT_USER,
        winuser::*,
    },
};
use windows::{
    core::{Interface, GUID, PCWSTR, PWSTR},
    Win32::{
        Foundation::{
            CloseHandle as WinCloseHandle, LocalFree as WinLocalFree, ERROR_IO_INCOMPLETE,
            ERROR_IO_PENDING, ERROR_MORE_DATA, ERROR_NOT_FOUND, ERROR_NO_MORE_FILES,
            ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED,
            ERROR_PIPE_NOT_CONNECTED, GENERIC_READ, HANDLE as WinHANDLE, HLOCAL as WinHLOCAL,
            RPC_E_CHANGED_MODE,
            WAIT_TIMEOUT as WINDOWS_WAIT_TIMEOUT, WIN32_ERROR,
        },
        Security::{
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW,
                ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
                SE_KERNEL_OBJECT,
            },
            GetTokenInformation as WinGetTokenInformation, IsWellKnownSid, TokenUser,
            WinLocalSystemSid, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            SECURITY_ATTRIBUTES, TOKEN_QUERY as WIN_TOKEN_QUERY, TOKEN_USER,
        },
        Storage::FileSystem::{
            CreateFileW as WinCreateFileW, ReadFile as WinReadFile,
            ReplaceFileW as WinReplaceFileW, WriteFile as WinWriteFile,
            FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_SHARE_MODE,
            FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, OPEN_EXISTING as WIN_OPEN_EXISTING,
            PIPE_ACCESS_DUPLEX, REPLACEFILE_WRITE_THROUGH as WIN_REPLACEFILE_WRITE_THROUGH,
            SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
        },
        System::Com::{
            CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, IPersistFile,
            CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
        },
        System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        },
        System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PeekNamedPipe,
            SetNamedPipeHandleState, WaitNamedPipeW, PIPE_READMODE_MESSAGE,
            PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_WAIT,
        },
        System::SystemInformation::GetSystemDirectoryW,
        System::SystemServices::SECURITY_DESCRIPTOR_REVISION,
        System::Threading::{
            CreateEventW, OpenProcess as WinOpenProcess, OpenProcessToken as WinOpenProcessToken,
            QueryFullProcessImageNameW as WinQueryFullProcessImageNameW,
            INFINITE as WINDOWS_INFINITE,
            PROCESS_QUERY_LIMITED_INFORMATION as WIN_PROCESS_QUERY_LIMITED_INFORMATION,
        },
        System::IO::{CancelIoEx, GetOverlappedResultEx, OVERLAPPED},
        UI::Shell::{
            FOLDERID_Desktop, FOLDERID_ProgramData, FOLDERID_ProgramFiles,
            FOLDERID_ProgramFilesX86, FOLDERID_UserProfiles, FOLDERID_Windows, IShellLinkW,
            SHGetKnownFolderPath, ShellLink, KF_FLAG_DEFAULT,
        },
    },
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
};
use winreg::{enums::*, RegKey};

mod acl;
pub use acl::set_path_permission;

pub const FLUTTER_RUNNER_WIN32_WINDOW_CLASS: &'static str = "FLUTTER_RUNNER_WIN32_WINDOW";
pub const SET_FOREGROUND_WINDOW: &'static str = "SET_FOREGROUND_WINDOW";

const FILE_ATTRIBUTE_REPARSE_POINT_FLAG: u32 = 0x400;
static BROKER_UPDATE_NONCE: AtomicU64 = AtomicU64::new(0);
static BROKER_UPDATE_MUTEX: Mutex<()> = Mutex::new(());

pub fn get_focused_display(displays: Vec<DisplayInfo>) -> Option<usize> {
    unsafe {
        let hwnd = GetForegroundWindow();
        let mut rect: RECT = mem::zeroed();
        if GetWindowRect(hwnd, &mut rect as *mut RECT) == 0 {
            return None;
        }
        displays.iter().position(|display| {
            let center_x = rect.left + (rect.right - rect.left) / 2;
            let center_y = rect.top + (rect.bottom - rect.top) / 2;
            center_x >= display.x
                && center_x < display.x + display.width
                && center_y >= display.y
                && center_y < display.y + display.height
        })
    }
}

pub fn get_cursor_pos() -> Option<(i32, i32)> {
    unsafe {
        let mut out = mem::MaybeUninit::<POINT>::uninit();
        if GetCursorPos(out.as_mut_ptr()) == FALSE {
            return None;
        }
        let out = out.assume_init();
        Some((out.x, out.y))
    }
}

pub fn set_cursor_pos(x: i32, y: i32) -> bool {
    unsafe {
        if SetCursorPos(x, y) == FALSE {
            let err = GetLastError();
            log::warn!("SetCursorPos failed: x={}, y={}, error_code={}", x, y, err);
            return false;
        }
        true
    }
}

/// Clip cursor to a rectangle. Pass None to unclip.
pub fn clip_cursor(rect: Option<(i32, i32, i32, i32)>) -> bool {
    unsafe {
        let result = match rect {
            Some((left, top, right, bottom)) => {
                let r = RECT {
                    left,
                    top,
                    right,
                    bottom,
                };
                ClipCursor(&r)
            }
            None => ClipCursor(std::ptr::null()),
        };
        if result == FALSE {
            let err = GetLastError();
            log::warn!("ClipCursor failed: rect={:?}, error_code={}", rect, err);
            return false;
        }
        true
    }
}

pub fn reset_input_cache() {}

pub fn get_cursor() -> ResultType<Option<u64>> {
    unsafe {
        #[allow(invalid_value)]
        let mut ci: CURSORINFO = mem::MaybeUninit::uninit().assume_init();
        ci.cbSize = std::mem::size_of::<CURSORINFO>() as _;
        // R-X9: the portable-service cursor route is excised; query the cursor directly
        // (the old non-portable `else` branch of portable_service::client::get_cursor_info).
        if GetCursorInfo(&mut ci) == FALSE {
            return Err(io::Error::last_os_error().into());
        }
        if ci.flags & CURSOR_SHOWING == 0 {
            Ok(None)
        } else {
            Ok(Some(ci.hCursor as _))
        }
    }
}

struct IconInfo(ICONINFO);

impl IconInfo {
    fn new(icon: HICON) -> ResultType<Self> {
        unsafe {
            #[allow(invalid_value)]
            let mut ii = mem::MaybeUninit::uninit().assume_init();
            if GetIconInfo(icon, &mut ii) == FALSE {
                Err(io::Error::last_os_error().into())
            } else {
                let ii = Self(ii);
                if ii.0.hbmMask.is_null() {
                    bail!("Cursor bitmap handle is NULL");
                }
                return Ok(ii);
            }
        }
    }

    fn is_color(&self) -> bool {
        !self.0.hbmColor.is_null()
    }
}

impl Drop for IconInfo {
    fn drop(&mut self) {
        unsafe {
            if !self.0.hbmColor.is_null() {
                DeleteObject(self.0.hbmColor as _);
            }
            if !self.0.hbmMask.is_null() {
                DeleteObject(self.0.hbmMask as _);
            }
        }
    }
}

// https://github.com/TurboVNC/tightvnc/blob/a235bae328c12fd1c3aed6f3f034a37a6ffbbd22/vnc_winsrc/winvnc/vncEncoder.cpp
// https://github.com/TigerVNC/tigervnc/blob/master/win/rfb_win32/DeviceFrameBuffer.cxx
pub fn get_cursor_data(hcursor: u64) -> ResultType<CursorData> {
    unsafe {
        let mut ii = IconInfo::new(hcursor as _)?;
        let bm_mask = get_bitmap(ii.0.hbmMask)?;
        let mut width = bm_mask.bmWidth;
        let mut height = if ii.is_color() {
            bm_mask.bmHeight
        } else {
            bm_mask.bmHeight / 2
        };
        let cbits_size = width * height * 4;
        if cbits_size < 16 {
            bail!("Invalid icon: too small"); // solve some crash
        }
        let mut cbits: Vec<u8> = Vec::new();
        cbits.resize(cbits_size as _, 0);
        let mut mbits: Vec<u8> = Vec::new();
        mbits.resize((bm_mask.bmWidthBytes * bm_mask.bmHeight) as _, 0);
        let r = GetBitmapBits(ii.0.hbmMask, mbits.len() as _, mbits.as_mut_ptr() as _);
        if r == 0 {
            bail!("Failed to copy bitmap data");
        }
        if r != (mbits.len() as i32) {
            bail!(
                "Invalid mask cursor buffer size, got {} bytes, expected {}",
                r,
                mbits.len()
            );
        }
        let do_outline;
        if ii.is_color() {
            get_rich_cursor_data(ii.0.hbmColor, width, height, &mut cbits)?;
            do_outline = fix_cursor_mask(
                &mut mbits,
                &mut cbits,
                width as _,
                height as _,
                bm_mask.bmWidthBytes as _,
            );
        } else {
            do_outline = handleMask(
                cbits.as_mut_ptr(),
                mbits.as_ptr(),
                width,
                height,
                bm_mask.bmWidthBytes,
                bm_mask.bmHeight,
            ) > 0;
        }
        if do_outline {
            let mut outline = Vec::new();
            outline.resize(((width + 2) * (height + 2) * 4) as _, 0);
            drawOutline(
                outline.as_mut_ptr(),
                cbits.as_ptr(),
                width,
                height,
                outline.len() as _,
            );
            cbits = outline;
            width += 2;
            height += 2;
            ii.0.xHotspot += 1;
            ii.0.yHotspot += 1;
        }

        Ok(CursorData {
            id: hcursor,
            colors: cbits.into(),
            hotx: ii.0.xHotspot as _,
            hoty: ii.0.yHotspot as _,
            width: width as _,
            height: height as _,
            ..Default::default()
        })
    }
}

#[inline]
fn get_bitmap(handle: HBITMAP) -> ResultType<BITMAP> {
    unsafe {
        let mut bm: BITMAP = mem::zeroed();
        if GetObjectA(
            handle as _,
            std::mem::size_of::<BITMAP>() as _,
            &mut bm as *mut BITMAP as *mut _,
        ) == FALSE
        {
            return Err(io::Error::last_os_error().into());
        }
        if bm.bmPlanes != 1 {
            bail!("Unsupported multi-plane cursor");
        }
        if bm.bmBitsPixel != 1 {
            bail!("Unsupported cursor mask format");
        }
        Ok(bm)
    }
}

struct DC(HDC);

impl DC {
    fn new() -> ResultType<Self> {
        unsafe {
            let dc = GetDC(0 as _);
            if dc.is_null() {
                bail!("Failed to get a drawing context");
            }
            Ok(Self(dc))
        }
    }
}

impl Drop for DC {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_null() {
                ReleaseDC(0 as _, self.0);
            }
        }
    }
}

struct CompatibleDC(HDC);

impl CompatibleDC {
    fn new(existing: HDC) -> ResultType<Self> {
        unsafe {
            let dc = CreateCompatibleDC(existing);
            if dc.is_null() {
                bail!("Failed to get a compatible drawing context");
            }
            Ok(Self(dc))
        }
    }
}

impl Drop for CompatibleDC {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_null() {
                DeleteDC(self.0);
            }
        }
    }
}

struct BitmapDC(CompatibleDC, HBITMAP);

impl BitmapDC {
    fn new(hdc: HDC, hbitmap: HBITMAP) -> ResultType<Self> {
        unsafe {
            let dc = CompatibleDC::new(hdc)?;
            let oldbitmap = SelectObject(dc.0, hbitmap as _) as HBITMAP;
            if oldbitmap.is_null() {
                bail!("Failed to select CompatibleDC");
            }
            Ok(Self(dc, oldbitmap))
        }
    }

    fn dc(&self) -> HDC {
        (self.0).0
    }
}

impl Drop for BitmapDC {
    fn drop(&mut self) {
        unsafe {
            if !self.1.is_null() {
                SelectObject((self.0).0, self.1 as _);
            }
        }
    }
}

#[inline]
fn get_rich_cursor_data(
    hbm_color: HBITMAP,
    width: i32,
    height: i32,
    out: &mut Vec<u8>,
) -> ResultType<()> {
    unsafe {
        let dc = DC::new()?;
        let bitmap_dc = BitmapDC::new(dc.0, hbm_color)?;
        if get_di_bits(out.as_mut_ptr(), bitmap_dc.dc(), hbm_color, width, height) > 0 {
            bail!("Failed to get di bits: {}", io::Error::last_os_error());
        }
    }
    Ok(())
}

fn fix_cursor_mask(
    mbits: &mut Vec<u8>,
    cbits: &mut Vec<u8>,
    width: usize,
    height: usize,
    bm_width_bytes: usize,
) -> bool {
    let mut pix_idx = 0;
    for _ in 0..height {
        for _ in 0..width {
            if cbits[pix_idx + 3] != 0 {
                return false;
            }
            pix_idx += 4;
        }
    }

    let packed_width_bytes = (width + 7) >> 3;
    let bm_size = mbits.len();
    let c_size = cbits.len();

    // Pack and invert bitmap data (mbits)
    // borrow from tigervnc
    for y in 0..height {
        for x in 0..packed_width_bytes {
            let a = y * packed_width_bytes + x;
            let b = y * bm_width_bytes + x;
            if a < bm_size && b < bm_size {
                mbits[a] = !mbits[b];
            }
        }
    }

    // Replace "inverted background" bits with black color to ensure
    // cross-platform interoperability. Not beautiful but necessary code.
    // borrow from tigervnc
    let bytes_row = width << 2;
    for y in 0..height {
        let mut bitmask: u8 = 0x80;
        for x in 0..width {
            let mask_idx = y * packed_width_bytes + (x >> 3);
            if mask_idx < bm_size {
                let pix_idx = y * bytes_row + (x << 2);
                if (mbits[mask_idx] & bitmask) == 0 {
                    for b1 in 0..4 {
                        let a = pix_idx + b1;
                        if a < c_size {
                            if cbits[a] != 0 {
                                mbits[mask_idx] ^= bitmask;
                                for b2 in b1..4 {
                                    let b = pix_idx + b2;
                                    if b < c_size {
                                        cbits[b] = 0x00;
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
            bitmask >>= 1;
            if bitmask == 0 {
                bitmask = 0x80;
            }
        }
    }

    // borrow from noVNC
    let mut pix_idx = 0;
    for y in 0..height {
        for x in 0..width {
            let mask_idx = y * packed_width_bytes + (x >> 3);
            let mut alpha = 255;
            if mask_idx < bm_size {
                if (mbits[mask_idx] << (x & 0x7)) & 0x80 == 0 {
                    alpha = 0;
                }
            }
            let a = cbits[pix_idx + 2];
            let b = cbits[pix_idx + 1];
            let c = cbits[pix_idx];
            cbits[pix_idx] = a;
            cbits[pix_idx + 1] = b;
            cbits[pix_idx + 2] = c;
            cbits[pix_idx + 3] = alpha;
            pix_idx += 4;
        }
    }
    return true;
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(arguments: Vec<OsString>) {
    if let Err(e) = run_service(arguments) {
        log::error!("run_service failed: {}", e);
    }
}

pub fn start_os_service() -> ResultType<()> {
    // This is an OWN_PROCESS service, so Windows ignores the table's service
    // name. The signed custom identity is deliberately loaded later, inside
    // ServiceMain, after this call has proved the SCM-owned entry.
    windows_service::service_dispatcher::start(crate::get_app_name(), ffi_service_main)
        .map_err(|err| anyhow!("Failed to connect the Windows service process to the SCM: {err}"))
}

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

extern "C" {
    fn get_current_session(rdp: BOOL) -> DWORD;
    fn is_session_locked(session_id: DWORD) -> BOOL;
    fn LaunchProcessWin(
        application: *const u16,
        cmd: *const u16,
        current_directory: *const u16,
        session_id: DWORD,
        as_user: BOOL,
        show: BOOL,
        extra_env: *const u16,
        job: HANDLE,
        inherited_handle: HANDLE,
        process_id: LPDWORD,
        token_pid: &mut DWORD,
    ) -> HANDLE;
    fn LaunchProcessCurrentWin(
        application: *const u16,
        cmd: *const u16,
        current_directory: *const u16,
        extra_env: *const u16,
        job: HANDLE,
        process_id: LPDWORD,
    ) -> HANDLE;
    fn GetSessionUserTokenWin(
        lphUserToken: LPHANDLE,
        dwSessionId: DWORD,
        as_user: BOOL,
        token_pid: &mut DWORD,
    ) -> BOOL;
    fn selectInputDesktop() -> BOOL;
    fn inputDesktopSelected() -> BOOL;
    fn is_windows_server() -> BOOL;
    fn is_windows_10_or_greater() -> BOOL;
    fn handleMask(
        out: *mut u8,
        mask: *const u8,
        width: i32,
        height: i32,
        bmWidthBytes: i32,
        bmHeight: i32,
    ) -> i32;
    fn drawOutline(out: *mut u8, in_: *const u8, width: i32, height: i32, out_size: i32);
    fn get_di_bits(out: *mut u8, dc: HDC, hbmColor: HBITMAP, width: i32, height: i32) -> i32;
    fn blank_screen(v: BOOL);
    fn is_local_system() -> BOOL;
    fn alloc_console_and_redirect();
    fn is_service_running_w(svc_name: *const u16) -> bool;
}

pub fn get_current_session_id(share_rdp: bool) -> DWORD {
    unsafe { get_current_session(if share_rdp { TRUE } else { FALSE }) }
}

fn current_service_session_id() -> Option<DWORD> {
    let session_id = unsafe { get_current_session(share_rdp()) };
    (session_id != u32::MAX).then_some(session_id)
}

const WINDOWS_SENSITIVE_PIPE_BUFFER_BYTES: u32 =
    (ipc::UNATTENDED_PASSWORD_MAX_BYTES + ipc::password::MACOS_AUTHORIZATION_MAX_BYTES) as u32;
const WINDOWS_SENSITIVE_PIPE_ACCEPT_POLL: Duration = Duration::from_millis(100);
const WINDOWS_SENSITIVE_PIPE_MAX_INSTANCES: u32 = 1;
const WINDOWS_OVERLAPPED_WAIT_TIMEOUT: WIN32_ERROR = WIN32_ERROR(WINDOWS_WAIT_TIMEOUT.0);

struct WindowsSensitiveHandle(WinHANDLE);

unsafe impl Send for WindowsSensitiveHandle {}

impl Drop for WindowsSensitiveHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = WinCloseHandle(self.0);
            }
        }
    }
}

struct WindowsSensitiveSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for WindowsSensitiveSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = WinLocalFree(Some(WinHLOCAL(self.0 .0)));
            }
        }
    }
}

struct WindowsSensitiveLocalString(PWSTR);

impl Drop for WindowsSensitiveLocalString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = WinLocalFree(Some(WinHLOCAL(self.0 .0 as *mut std::ffi::c_void)));
            }
        }
    }
}

fn windows_sensitive_security_descriptor_sddl(
    descriptor: PSECURITY_DESCRIPTOR,
) -> ResultType<String> {
    let mut sddl = PWSTR::null();
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SECURITY_DESCRIPTOR_REVISION,
            DACL_SECURITY_INFORMATION,
            &mut sddl,
            None,
        )
        .map_err(|err| anyhow!("Could not canonicalize Windows sensitive IPC DACL: {err}"))?;
    }
    let sddl = WindowsSensitiveLocalString(sddl);
    unsafe { sddl.0.to_string() }
        .map_err(|err| anyhow!("Windows sensitive IPC DACL is invalid UTF-16: {err}"))
}

fn windows_sensitive_pipe_kernel_sddl(handle: WinHANDLE) -> ResultType<String> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    };
    status
        .ok()
        .map_err(|err| anyhow!("Could not read Windows sensitive IPC kernel DACL: {err}"))?;
    let descriptor = WindowsSensitiveSecurityDescriptor(descriptor);
    windows_sensitive_security_descriptor_sddl(descriptor.0)
}

struct WindowsSensitiveStack<const N: usize>([u8; N]);

impl<const N: usize> WindowsSensitiveStack<N> {
    fn zeroed() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> Drop for WindowsSensitiveStack<N> {
    fn drop(&mut self) {
        ipc::zeroize_sensitive_bytes(&mut self.0);
    }
}

struct WindowsSensitiveOverlapped {
    _event: WindowsSensitiveHandle,
    value: OVERLAPPED,
}

enum WindowsSensitiveWait {
    Complete(u32),
    TimedOut,
}

fn windows_error_is(
    error: &windows::core::Error,
    code: windows::Win32::Foundation::WIN32_ERROR,
) -> bool {
    error.code().0 == (0x8007_0000u32 | code.0) as i32
}

fn windows_sensitive_remaining_millis(deadline: Instant) -> ResultType<u32> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| anyhow!("Windows sensitive IPC transaction timed out"))?;
    Ok(remaining.as_millis().max(1).min((u32::MAX - 1) as u128) as u32)
}

fn windows_sensitive_deadline_live(deadline: Instant, context: &str) -> ResultType<()> {
    if Instant::now() >= deadline {
        bail!("{context} exceeded the Windows sensitive IPC deadline");
    }
    Ok(())
}

impl WindowsSensitiveOverlapped {
    fn new() -> ResultType<Self> {
        let event = unsafe { CreateEventW(None, true, false, None) }
            .map_err(|err| anyhow!("Could not create Windows sensitive IPC event: {err}"))?;
        let event = WindowsSensitiveHandle(event);
        let mut value = OVERLAPPED::default();
        value.hEvent = event.0;
        Ok(Self {
            _event: event,
            value,
        })
    }

    fn wait(&mut self, handle: WinHANDLE, deadline: Instant) -> ResultType<WindowsSensitiveWait> {
        loop {
            let timeout = match windows_sensitive_remaining_millis(deadline) {
                Ok(timeout) => timeout,
                Err(_) => {
                    self.cancel_and_drain(handle)?;
                    return Ok(WindowsSensitiveWait::TimedOut);
                }
            };
            let mut transferred = 0u32;
            let result = unsafe {
                GetOverlappedResultEx(handle, &self.value, &mut transferred, timeout, false)
            };
            match result {
                Ok(()) => {
                    if Instant::now() >= deadline {
                        return Ok(WindowsSensitiveWait::TimedOut);
                    }
                    return Ok(WindowsSensitiveWait::Complete(transferred));
                }
                Err(err) if windows_error_is(&err, ERROR_IO_INCOMPLETE) => continue,
                Err(err) if windows_error_is(&err, WINDOWS_OVERLAPPED_WAIT_TIMEOUT) => {
                    self.cancel_and_drain(handle)?;
                    return Ok(WindowsSensitiveWait::TimedOut);
                }
                Err(err) => {
                    self.cancel_and_drain(handle)?;
                    return Err(anyhow!(
                        "Windows sensitive IPC overlapped operation failed: {err}"
                    ));
                }
            }
        }
    }

    fn cancel_and_drain(&mut self, handle: WinHANDLE) -> ResultType<()> {
        let cancellation = unsafe { CancelIoEx(handle, Some(&self.value)) };
        if let Err(err) = cancellation {
            if !windows_error_is(&err, ERROR_NOT_FOUND) {
                log::trace!("Windows sensitive IPC cancellation request failed: {err}");
            }
        }
        loop {
            let mut transferred = 0u32;
            let result = unsafe {
                GetOverlappedResultEx(
                    handle,
                    &self.value,
                    &mut transferred,
                    WINDOWS_INFINITE,
                    false,
                )
            };
            match result {
                Ok(()) => return Ok(()),
                Err(err) if windows_error_is(&err, ERROR_IO_INCOMPLETE) => continue,
                Err(err) if windows_error_is(&err, ERROR_OPERATION_ABORTED) => return Ok(()),
                Err(err) => {
                    log::trace!(
                        "Windows sensitive IPC cancellation completed with operation error: {err}"
                    );
                    return Ok(());
                }
            }
        }
    }
}

struct WindowsSensitivePipe {
    handle: WindowsSensitiveHandle,
    security: Option<ipc::WindowsSensitivePipeSecurity>,
    kernel_dacl_sddl: Option<String>,
}

impl WindowsSensitivePipe {
    fn create_initial_server(postfix: &'static str) -> ResultType<Self> {
        let path_value = config::Config::ipc_path(postfix);
        let path = wide_string(&path_value);
        let security = ipc::windows_sensitive_pipe_security(postfix)?;
        let sddl = wide_string(&security.sddl);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SECURITY_DESCRIPTOR_REVISION,
                &mut descriptor,
                None,
            )
            .map_err(|err| anyhow!("Could not build Windows sensitive IPC DACL: {err}"))?;
        }
        let descriptor = WindowsSensitiveSecurityDescriptor(descriptor);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0 .0,
            bInheritHandle: false.into(),
        };
        let open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE;
        let pipe_mode =
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(path.as_ptr()),
                open_mode,
                pipe_mode,
                WINDOWS_SENSITIVE_PIPE_MAX_INSTANCES,
                WINDOWS_SENSITIVE_PIPE_BUFFER_BYTES,
                WINDOWS_SENSITIVE_PIPE_BUFFER_BYTES,
                0,
                Some(&attributes),
            )
        };
        if handle.is_invalid() {
            bail!(
                "Could not create Windows sensitive IPC pipe instance: {}",
                io::Error::last_os_error()
            );
        }
        let handle = WindowsSensitiveHandle(handle);
        let expected_kernel_sddl = windows_sensitive_security_descriptor_sddl(descriptor.0)?;
        let observed_kernel_sddl = windows_sensitive_pipe_kernel_sddl(handle.0)?;
        if observed_kernel_sddl != expected_kernel_sddl {
            bail!("Windows sensitive IPC kernel DACL does not match its creation descriptor");
        }
        Ok(Self {
            handle,
            security: Some(security),
            kernel_dacl_sddl: Some(observed_kernel_sddl),
        })
    }

    fn current_server_security(
        &self,
        postfix: &'static str,
    ) -> ResultType<ipc::WindowsSensitivePipeSecurity> {
        let retained = self
            .security
            .as_ref()
            .ok_or_else(|| anyhow!("Windows sensitive client pipe has no listener security"))?;
        self.ensure_kernel_dacl_retained()?;
        let current = ipc::windows_sensitive_pipe_security(postfix)?;
        if current.sddl != retained.sddl {
            bail!("Windows sensitive IPC pipe DACL changed while its first instance was retained");
        }
        Ok(current)
    }

    fn ensure_kernel_dacl_retained(&self) -> ResultType<()> {
        let retained_kernel_sddl = self
            .kernel_dacl_sddl
            .as_ref()
            .ok_or_else(|| anyhow!("Windows sensitive client pipe has no retained kernel DACL"))?;
        if windows_sensitive_pipe_kernel_sddl(self.handle.0)? != *retained_kernel_sddl {
            bail!(
                "Windows sensitive IPC kernel DACL changed while its first instance was retained"
            );
        }
        Ok(())
    }

    fn connect_client(postfix: &str, deadline: Instant) -> ResultType<Self> {
        let path_value = config::Config::ipc_path(postfix);
        let path = wide_string(&path_value);
        loop {
            windows_sensitive_deadline_live(deadline, "Windows sensitive pipe connection")?;
            let flags = FILE_FLAG_OVERLAPPED | SECURITY_IDENTIFICATION | SECURITY_SQOS_PRESENT;
            let handle = unsafe {
                WinCreateFileW(
                    PCWSTR(path.as_ptr()),
                    GENERIC_READ.0 | FILE_WRITE_DATA.0 | FILE_WRITE_ATTRIBUTES.0,
                    FILE_SHARE_MODE(0),
                    None,
                    WIN_OPEN_EXISTING,
                    flags,
                    None,
                )
            };
            match handle {
                Ok(handle) => {
                    let pipe = Self {
                        handle: WindowsSensitiveHandle(handle),
                        security: None,
                        kernel_dacl_sddl: None,
                    };
                    windows_sensitive_deadline_live(deadline, "Windows sensitive pipe connection")?;
                    let mode = PIPE_READMODE_MESSAGE;
                    unsafe {
                        SetNamedPipeHandleState(pipe.handle.0, Some(&mode), None, None).map_err(
                            |err| {
                                anyhow!(
                                    "Could not enable Windows sensitive IPC message mode: {err}"
                                )
                            },
                        )?;
                    }
                    windows_sensitive_deadline_live(deadline, "Windows sensitive pipe connection")?;
                    return Ok(pipe);
                }
                Err(err) if windows_error_is(&err, ERROR_PIPE_BUSY) => {
                    let remaining = windows_sensitive_remaining_millis(deadline)?;
                    let waited = unsafe { WaitNamedPipeW(PCWSTR(path.as_ptr()), remaining) };
                    if !waited.as_bool() {
                        bail!(
                            "Windows sensitive IPC endpoint remained busy: {}",
                            windows::core::Error::from_win32()
                        );
                    }
                    windows_sensitive_deadline_live(deadline, "Windows sensitive pipe wait")?;
                }
                Err(err) => bail!("Could not connect to Windows sensitive IPC pipe: {err}"),
            }
        }
    }

    fn accept(&self, deadline: Instant) -> ResultType<bool> {
        windows_sensitive_deadline_live(deadline, "Windows sensitive pipe accept")?;
        let mut operation = WindowsSensitiveOverlapped::new()?;
        windows_sensitive_deadline_live(deadline, "Windows sensitive pipe accept")?;
        let accepted = match unsafe { ConnectNamedPipe(self.handle.0, Some(&mut operation.value)) }
        {
            Ok(()) => Ok(true),
            Err(err) if windows_error_is(&err, ERROR_PIPE_CONNECTED) => Ok(true),
            Err(err) if windows_error_is(&err, ERROR_IO_PENDING) => {
                match operation.wait(self.handle.0, deadline)? {
                    WindowsSensitiveWait::Complete(_) => Ok(true),
                    WindowsSensitiveWait::TimedOut => Ok(false),
                }
            }
            Err(err) => Err(anyhow!(
                "Could not accept Windows sensitive IPC client: {err}"
            )),
        }?;
        if accepted {
            windows_sensitive_deadline_live(deadline, "Windows sensitive pipe accept")?;
        }
        Ok(accepted)
    }

    fn read_message(&self, value: &mut [u8], deadline: Instant) -> ResultType<()> {
        windows_sensitive_deadline_live(deadline, "Windows sensitive IPC read")?;
        if value.is_empty() {
            return Ok(());
        }
        let mut operation = WindowsSensitiveOverlapped::new()?;
        let mut transferred = 0u32;
        windows_sensitive_deadline_live(deadline, "Windows sensitive IPC read")?;
        let result = unsafe {
            WinReadFile(
                self.handle.0,
                Some(value),
                Some(&mut transferred),
                Some(&mut operation.value),
            )
        };
        let transferred = match result {
            Ok(()) => transferred,
            Err(err) if windows_error_is(&err, ERROR_IO_PENDING) => {
                match operation.wait(self.handle.0, deadline)? {
                    WindowsSensitiveWait::Complete(transferred) => transferred,
                    WindowsSensitiveWait::TimedOut => {
                        bail!("Windows sensitive IPC read timed out")
                    }
                }
            }
            Err(err) if windows_error_is(&err, ERROR_MORE_DATA) => {
                bail!("Windows sensitive IPC message exceeds its canonical length")
            }
            Err(err) => bail!("Windows sensitive IPC read failed: {err}"),
        };
        if transferred as usize != value.len() {
            bail!(
                "Windows sensitive IPC message has invalid length: expected {}, got {}",
                value.len(),
                transferred
            );
        }
        windows_sensitive_deadline_live(deadline, "Windows sensitive IPC read")?;
        Ok(())
    }

    fn write_message(&self, value: &[u8], deadline: Instant) -> ResultType<()> {
        windows_sensitive_deadline_live(deadline, "Windows sensitive IPC write")?;
        if value.is_empty() {
            return Ok(());
        }
        let mut operation = WindowsSensitiveOverlapped::new()?;
        let mut transferred = 0u32;
        windows_sensitive_deadline_live(deadline, "Windows sensitive IPC write")?;
        let result = unsafe {
            WinWriteFile(
                self.handle.0,
                Some(value),
                Some(&mut transferred),
                Some(&mut operation.value),
            )
        };
        let transferred = match result {
            Ok(()) => transferred,
            Err(err) if windows_error_is(&err, ERROR_IO_PENDING) => {
                match operation.wait(self.handle.0, deadline)? {
                    WindowsSensitiveWait::Complete(transferred) => transferred,
                    WindowsSensitiveWait::TimedOut => {
                        bail!("Windows sensitive IPC write timed out")
                    }
                }
            }
            Err(err) => bail!("Windows sensitive IPC write failed: {err}"),
        };
        if transferred as usize != value.len() {
            bail!(
                "Windows sensitive IPC write was incomplete: expected {}, got {}",
                value.len(),
                transferred
            );
        }
        windows_sensitive_deadline_live(deadline, "Windows sensitive IPC write")?;
        Ok(())
    }

    fn require_no_queued_bytes(&self, deadline: Instant) -> ResultType<()> {
        windows_sensitive_deadline_live(deadline, "Windows sensitive IPC framing check")?;
        let mut available = 0u32;
        unsafe {
            PeekNamedPipe(self.handle.0, None, 0, None, Some(&mut available), None)
                .map_err(|err| anyhow!("Could not inspect Windows sensitive IPC framing: {err}"))?;
        }
        if available != 0 {
            bail!("Windows sensitive IPC request has trailing data");
        }
        windows_sensitive_deadline_live(deadline, "Windows sensitive IPC framing check")?;
        Ok(())
    }

    fn disconnect_client(&self) -> ResultType<()> {
        match unsafe { DisconnectNamedPipe(self.handle.0) } {
            Ok(()) => Ok(()),
            Err(err) if windows_error_is(&err, ERROR_PIPE_NOT_CONNECTED) => Ok(()),
            Err(err) => bail!("Could not disconnect Windows sensitive IPC client: {err}"),
        }
    }
}

pub(crate) struct WindowsSensitivePasswordRequest {
    pub(crate) operation_id: String,
    pub(crate) value: ipc::SensitivePassword,
    pub(crate) response: std_mpsc::SyncSender<ipc::PasswordMutationStatus>,
}

pub(crate) struct WindowsSensitivePasswordListener {
    accepting: Arc<AtomicBool>,
    quiesced: Arc<AtomicBool>,
}

impl WindowsSensitivePasswordListener {
    pub(crate) async fn quiesce(&self) {
        self.accepting.store(false, Ordering::Release);
        while !self.quiesced.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

impl Drop for WindowsSensitivePasswordListener {
    fn drop(&mut self) {
        self.accepting.store(false, Ordering::Release);
    }
}

static WINDOWS_SENSITIVE_PASSWORD_LISTENER_WORKERS: OnceLock<
    Mutex<Vec<std::thread::JoinHandle<()>>>,
> = OnceLock::new();

fn retain_windows_sensitive_password_listener(worker: std::thread::JoinHandle<()>) {
    let workers = WINDOWS_SENSITIVE_PASSWORD_LISTENER_WORKERS.get_or_init(Default::default);
    match workers.lock() {
        Ok(mut workers) => workers.push(worker),
        Err(_) => {
            log::error!("Windows sensitive IPC listener registry lock poisoned");
            std::process::abort();
        }
    }
}

fn handle_windows_sensitive_password_pipe(
    pipe: &WindowsSensitivePipe,
    postfix: &'static str,
    requests: &mpsc::Sender<WindowsSensitivePasswordRequest>,
    deadline: Instant,
) -> ResultType<()> {
    let security = pipe.current_server_security(postfix)?;
    ipc::preauthorize_windows_sensitive_pipe_client(pipe.handle.0, postfix, &security, deadline)?;
    let mut header_bytes =
        WindowsSensitiveStack::<{ ipc::password::REQUEST_HEADER_BYTES }>::zeroed();
    pipe.read_message(&mut header_bytes.0, deadline)?;
    let header = ipc::password::SensitiveRequestHeader::decode(
        &header_bytes.0,
        ipc::password::SensitivePayloadKind::Password,
    )?;
    let proof =
        ipc::authorize_windows_sensitive_pipe_client(pipe.handle.0, postfix, &security, deadline)?;
    let mut request = ipc::password::InboundSensitiveRequest::allocate(header)?;
    pipe.read_message(request.body_mut(), deadline)?;
    pipe.require_no_queued_bytes(deadline)?;
    request.validate_utf8()?;
    let operation_id = request.operation_id();
    let value = request.into_password()?;
    let (response_tx, response_rx) = std_mpsc::sync_channel(1);
    let request = WindowsSensitivePasswordRequest {
        operation_id: operation_id.to_string(),
        value,
        response: response_tx,
    };
    proof.revalidate(pipe.handle.0, deadline)?;
    let status = match requests.try_send(request) {
        Ok(()) => match deadline.checked_duration_since(Instant::now()) {
            Some(remaining) => response_rx
                .recv_timeout(remaining)
                .unwrap_or(ipc::PasswordMutationStatus::Pending),
            None => ipc::PasswordMutationStatus::Pending,
        },
        Err(mpsc::error::TrySendError::Full(_)) => {
            ipc::windows_credential_queue_uncertainty_status()
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            bail!("Windows sensitive IPC mutation receiver closed")
        }
    };
    let mut response = WindowsSensitiveStack::<{ ipc::password::STATUS_FRAME_BYTES }>(
        ipc::password::encode_status(operation_id, status),
    );
    pipe.write_message(&response.0, deadline)?;
    ipc::zeroize_sensitive_bytes(&mut response.0);
    let mut acknowledgement = WindowsSensitiveStack::<{ ipc::password::ACK_FRAME_BYTES }>::zeroed();
    pipe.read_message(&mut acknowledgement.0, deadline)?;
    ipc::password::decode_ack(&acknowledgement.0, operation_id)?;
    pipe.require_no_queued_bytes(deadline)?;
    Ok(())
}

pub(crate) fn start_windows_sensitive_password_listener(
    postfix: &'static str,
    requests: mpsc::Sender<WindowsSensitivePasswordRequest>,
) -> ResultType<WindowsSensitivePasswordListener> {
    if !matches!(
        postfix,
        ipc::password::USER_PASSWORD_IPC_POSTFIX | ipc::password::SERVICE_PASSWORD_IPC_POSTFIX
    ) {
        bail!("Unsupported Windows sensitive password listener endpoint");
    }
    let pipe = WindowsSensitivePipe::create_initial_server(postfix)?;
    let accepting = Arc::new(AtomicBool::new(true));
    let quiesced = Arc::new(AtomicBool::new(false));
    let worker_accepting = Arc::clone(&accepting);
    let worker_quiesced = Arc::clone(&quiesced);
    let worker = std::thread::Builder::new()
        .name("windows-sensitive-ipc".to_owned())
        .spawn(move || {
            let mut requests = Some(requests);
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| loop {
                if !worker_accepting.load(Ordering::Acquire) {
                    worker_quiesced.store(true, Ordering::Release);
                    std::thread::sleep(WINDOWS_SENSITIVE_PIPE_ACCEPT_POLL);
                    continue;
                }
                let accepted = pipe.ensure_kernel_dacl_retained().and_then(|()| {
                    pipe.accept(Instant::now() + WINDOWS_SENSITIVE_PIPE_ACCEPT_POLL)
                });
                let mut fatal = None;
                match accepted {
                    Ok(false) => {
                        if let Err(err) = pipe.disconnect_client() {
                            fatal = Some(err);
                        }
                    }
                    Ok(true) => {
                        let deadline = Instant::now()
                            + Duration::from_millis(ipc::SERVICE_IPC_REQUEST_TIMEOUT_MS);
                        match requests.as_ref() {
                            Some(sender) => {
                                if let Err(err) = handle_windows_sensitive_password_pipe(
                                    &pipe, postfix, sender, deadline,
                                ) {
                                    if sender.is_closed() {
                                        fatal = Some(err);
                                    } else {
                                        log::trace!(
                                            "Windows sensitive IPC transaction did not complete cleanly: {err}"
                                        );
                                    }
                                }
                            }
                            None => fatal = Some(anyhow!(
                                "Windows sensitive IPC mutation receiver is unavailable"
                            )),
                        }
                        if let Err(err) = pipe.disconnect_client() {
                            fatal = Some(err);
                        }
                    }
                    Err(err) => fatal = Some(err),
                }
                if let Some(err) = fatal {
                    log::error!("Windows sensitive IPC listener failed closed: {err}");
                    requests.take();
                    worker_accepting.store(false, Ordering::Release);
                    crate::server::request_graceful_shutdown();
                    if let Err(disconnect_err) = pipe.disconnect_client() {
                        log::error!(
                            "Windows sensitive IPC listener could not normalize its retained sentinel: {disconnect_err}"
                        );
                    }
                }
            }));
            if outcome.is_err() {
                log::error!("Windows sensitive IPC listener thread panicked");
                std::process::abort();
            }
        })
        .map_err(|err| anyhow!("Could not start Windows sensitive IPC listener: {err}"))?;
    retain_windows_sensitive_password_listener(worker);
    Ok(WindowsSensitivePasswordListener {
        accepting,
        quiesced,
    })
}

pub(crate) enum WindowsSensitivePasswordAttempt {
    Status(ipc::PasswordMutationStatus),
    NotSent(String),
    Uncertain(String),
}

fn transact_windows_sensitive_password_blocking(
    postfix: &'static str,
    operation_id: hbb_common::uuid::Uuid,
    password: ipc::SensitivePassword,
    deadline: Instant,
) -> WindowsSensitivePasswordAttempt {
    if let Err(err) = windows_sensitive_deadline_live(deadline, "Windows sensitive IPC client") {
        return WindowsSensitivePasswordAttempt::NotSent(err.to_string());
    }
    let pipe = match WindowsSensitivePipe::connect_client(postfix, deadline) {
        Ok(pipe) => pipe,
        Err(err) => return WindowsSensitivePasswordAttempt::NotSent(err.to_string()),
    };
    let proof =
        match ipc::authenticate_windows_sensitive_pipe_server(pipe.handle.0, postfix, deadline) {
            Ok(proof) => proof,
            Err(err) => return WindowsSensitivePasswordAttempt::NotSent(err.to_string()),
        };
    let header_value = match ipc::password::SensitiveRequestHeader::new(
        operation_id,
        ipc::password::SensitivePayloadKind::Password,
        password.as_bytes().len(),
        0,
    ) {
        Ok(header) => header.encode(),
        Err(err) => return WindowsSensitivePasswordAttempt::NotSent(err.to_string()),
    };
    let mut header = WindowsSensitiveStack::<{ ipc::password::REQUEST_HEADER_BYTES }>(header_value);
    if let Err(err) = pipe.write_message(&header.0, deadline) {
        return if password.as_bytes().is_empty() {
            WindowsSensitivePasswordAttempt::Uncertain(err.to_string())
        } else {
            WindowsSensitivePasswordAttempt::NotSent(err.to_string())
        };
    }
    ipc::zeroize_sensitive_bytes(&mut header.0);
    if let Err(err) = proof.revalidate(pipe.handle.0, deadline) {
        return if password.as_bytes().is_empty() {
            WindowsSensitivePasswordAttempt::Uncertain(err.to_string())
        } else {
            WindowsSensitivePasswordAttempt::NotSent(err.to_string())
        };
    }
    if let Err(err) = pipe.write_message(password.as_bytes(), deadline) {
        return WindowsSensitivePasswordAttempt::Uncertain(err.to_string());
    }
    let mut response = WindowsSensitiveStack::<{ ipc::password::STATUS_FRAME_BYTES }>::zeroed();
    if let Err(err) = pipe.read_message(&mut response.0, deadline) {
        return WindowsSensitivePasswordAttempt::Uncertain(err.to_string());
    }
    if let Err(err) = pipe.require_no_queued_bytes(deadline) {
        return WindowsSensitivePasswordAttempt::Uncertain(err.to_string());
    }
    if let Err(err) = proof.revalidate(pipe.handle.0, deadline) {
        return WindowsSensitivePasswordAttempt::Uncertain(err.to_string());
    }
    let status = match ipc::password::decode_status(&response.0, operation_id) {
        Ok(status) => status,
        Err(err) => return WindowsSensitivePasswordAttempt::Uncertain(err.to_string()),
    };
    let acknowledgement_value = ipc::password::encode_ack(operation_id);
    let acknowledgement =
        WindowsSensitiveStack::<{ ipc::password::ACK_FRAME_BYTES }>(acknowledgement_value);
    if let Err(err) = pipe.write_message(&acknowledgement.0, deadline) {
        log::trace!("Windows sensitive IPC status acknowledgement failed: {err}");
    }
    if let Err(err) = windows_sensitive_deadline_live(deadline, "Windows sensitive IPC status") {
        return WindowsSensitivePasswordAttempt::Uncertain(err.to_string());
    }
    WindowsSensitivePasswordAttempt::Status(status)
}

pub(crate) async fn transact_sensitive_password(
    postfix: &'static str,
    operation_id: hbb_common::uuid::Uuid,
    password: &ipc::SensitivePassword,
    timeout: Duration,
) -> WindowsSensitivePasswordAttempt {
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return WindowsSensitivePasswordAttempt::NotSent(
            "Windows sensitive IPC deadline overflow".to_owned(),
        );
    };
    let password = password.clone();
    let (result_tx, mut result_rx) = oneshot::channel();
    let supervisor = std::thread::Builder::new()
        .name("windows-sensitive-ipc-client-supervisor".to_owned())
        .spawn(move || {
            let worker = std::thread::Builder::new()
                .name("windows-sensitive-ipc-client".to_owned())
                .spawn(move || {
                    transact_windows_sensitive_password_blocking(
                        postfix,
                        operation_id,
                        password,
                        deadline,
                    )
                });
            let result = match worker {
                Ok(worker) => match worker.join() {
                    Ok(result) => result,
                    Err(_) => WindowsSensitivePasswordAttempt::Uncertain(
                        "Windows sensitive IPC client thread panicked".to_owned(),
                    ),
                },
                Err(err) => WindowsSensitivePasswordAttempt::NotSent(format!(
                    "Could not start Windows sensitive IPC client: {err}"
                )),
            };
            let _ = result_tx.send(result);
        });
    let supervisor = match supervisor {
        Ok(supervisor) => supervisor,
        Err(err) => {
            return WindowsSensitivePasswordAttempt::NotSent(format!(
                "Could not start Windows sensitive IPC client supervisor: {err}"
            ))
        }
    };
    let (wrapper_timed_out, result) =
        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), &mut result_rx)
            .await
        {
            Ok(Ok(result)) => (false, result),
            Ok(Err(_)) => (
                false,
                WindowsSensitivePasswordAttempt::Uncertain(
                    "Windows sensitive IPC client ended without a result".to_owned(),
                ),
            ),
            Err(_) => {
                let result = match result_rx.await {
                    Ok(result) => result,
                    Err(_) => WindowsSensitivePasswordAttempt::Uncertain(
                        "Windows sensitive IPC client ended without a result".to_owned(),
                    ),
                };
                (true, result)
            }
        };
    while !supervisor.is_finished() {
        tokio::task::yield_now().await;
    }
    if supervisor.join().is_err() {
        return WindowsSensitivePasswordAttempt::Uncertain(
            "Windows sensitive IPC client supervisor panicked".to_owned(),
        );
    }
    if wrapper_timed_out {
        WindowsSensitivePasswordAttempt::Uncertain(
            "Windows sensitive IPC client exceeded its end-to-end deadline".to_owned(),
        )
    } else {
        result
    }
}

#[inline]
fn authorize_service_scoped_ipc_connection(
    stream: &ipc::Connection,
    expected_active_session_id: Option<u32>,
) -> bool {
    let (authorized, peer_pid, peer_session_id, peer_is_system) =
        stream.service_authorization_status_for_session(expected_active_session_id);
    if !authorized {
        ipc::log_rejected_windows_ipc_connection(
            crate::POSTFIX_SERVICE,
            peer_pid,
            peer_session_id,
            expected_active_session_id,
            peer_is_system,
            None,
        );
        return false;
    }
    if let Err(err) =
        ipc::ensure_peer_executable_matches_current_by_pid_opt(peer_pid, crate::POSTFIX_SERVICE)
    {
        log::warn!(
                "Rejected unauthorized connection on protected service-scoped IPC channel due to executable mismatch: postfix={}, peer_pid={:?}, err={}",
                crate::POSTFIX_SERVICE,
                peer_pid,
                err
            );
        return false;
    }
    true
}

async fn refresh_service_ipc_listener(
    incoming: &mut Option<parity_tokio_ipc::Incoming>,
) -> ResultType<()> {
    let previous = incoming
        .take()
        .ok_or_else(|| anyhow!("Windows _service IPC listener was absent during refresh"))?;
    drop(previous);
    *incoming = Some(ipc::new_listener(crate::POSTFIX_SERVICE).await?);
    Ok(())
}

async fn refresh_service_sas_ipc_listener(
    incoming: &mut Option<parity_tokio_ipc::Incoming>,
) -> ResultType<()> {
    let previous = incoming
        .take()
        .ok_or_else(|| anyhow!("Windows service SAS IPC listener was absent during refresh"))?;
    drop(previous);
    *incoming = Some(ipc::new_listener(ipc::WINDOWS_SERVICE_SAS_IPC_POSTFIX).await?);
    Ok(())
}

const WINDOWS_SERVICE_IPC_TRANSACTION_BUDGET: usize = 4;
static WINDOWS_SERVICE_IPC_TRANSACTION_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
const WINDOWS_SERVICE_SAS_IPC_TRANSACTION_BUDGET: usize = 1;
static WINDOWS_SERVICE_SAS_IPC_TRANSACTION_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();

fn try_acquire_windows_service_ipc_transaction_slot() -> Option<OwnedSemaphorePermit> {
    let semaphore = WINDOWS_SERVICE_IPC_TRANSACTION_SLOTS
        .get_or_init(|| Arc::new(Semaphore::new(WINDOWS_SERVICE_IPC_TRANSACTION_BUDGET)))
        .clone();
    match semaphore.try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(_) => {
            log::debug!(
                "Rejected Windows _service IPC connection because service work is at capacity"
            );
            None
        }
    }
}

fn try_acquire_windows_service_sas_ipc_transaction_slot() -> Option<OwnedSemaphorePermit> {
    WINDOWS_SERVICE_SAS_IPC_TRANSACTION_SLOTS
        .get_or_init(|| Arc::new(Semaphore::new(WINDOWS_SERVICE_SAS_IPC_TRANSACTION_BUDGET)))
        .clone()
        .try_acquire_owned()
        .ok()
}

async fn handle_windows_service_ipc_request(
    mut stream: ipc::Connection,
    _transaction_slot: OwnedSemaphorePermit,
) {
    match stream
        .next_service_request_timeout(ipc::SERVICE_IPC_REQUEST_TIMEOUT_MS)
        .await
    {
        Err(err) => {
            log::trace!(
                "protected Windows _service IPC request closed before a bounded request frame: {}",
                err
            );
        }
        Ok(None) => {
            log::warn!("Rejected malformed request on protected Windows _service IPC channel");
        }
        Ok(Some(request)) => match request {
            ipc::ServiceIpcRequest::LivenessProbe {} => {
                send_windows_service_ipc_response(
                    &mut stream,
                    &ipc::ServiceIpcResponse::Liveness {},
                )
                .await;
            }
            ipc::ServiceIpcRequest::SetShareRdp { enabled } => {
                ipc::handle_windows_service_owned_share_rdp_request(enabled, &mut stream).await;
            }
        },
    }
}

async fn handle_windows_service_sas_ipc_request(
    mut stream: ipc::Connection,
    _transaction_slot: OwnedSemaphorePermit,
    sas_requests: mpsc::Sender<WindowsServiceSasRequest>,
) {
    match stream
        .next_windows_service_sas_request_timeout(ipc::SERVICE_IPC_REQUEST_TIMEOUT_MS)
        .await
    {
        Ok(Some(ipc::WindowsServiceSasIpcRequest::Dispatch {})) => {
            handle_windows_service_owned_sas_request(&mut stream, sas_requests).await;
        }
        Ok(None) => log::warn!("Rejected malformed request on protected Windows SAS IPC channel"),
        Err(err) => log::trace!(
            "protected Windows SAS IPC request closed before a bounded request frame: {err}"
        ),
    }
}

async fn send_windows_service_ipc_response(
    stream: &mut ipc::Connection,
    response: &ipc::ServiceIpcResponse,
) {
    if let Err(err) = stream
        .send_service_response_timeout(response, ipc::SERVICE_IPC_REQUEST_TIMEOUT_MS)
        .await
    {
        log::warn!("Could not send protected Windows service response: {err}");
    }
}

async fn send_windows_service_sas_ipc_response(
    stream: &mut ipc::Connection,
    response: &ipc::WindowsServiceSasIpcResponse,
) {
    if let Err(err) = stream
        .send_windows_service_sas_response_timeout(response, ipc::SERVICE_IPC_REQUEST_TIMEOUT_MS)
        .await
    {
        log::warn!("Could not send protected Windows service SAS response: {err}");
    }
}

struct WindowsServiceSasRequest {
    requester: ipc::WindowsProcessIdentityKey,
    permit: oneshot::Sender<Result<DWORD, String>>,
}

const WINDOWS_SERVICE_SAS_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(2);

async fn handle_windows_service_owned_sas_request(
    stream: &mut ipc::Connection,
    sas_requests: mpsc::Sender<WindowsServiceSasRequest>,
) {
    let Some(requester) = ipc::authorize_windows_service_owned_sas_requester(stream) else {
        send_windows_service_sas_ipc_response(
            stream,
            &ipc::WindowsServiceSasIpcResponse::DispatchAccepted { accepted: false },
        )
        .await;
        return;
    };
    let dispatch = match stream.prepare_sas_as_windows_pipe_client(requester) {
        Ok(dispatch) => dispatch,
        Err(err) => {
            log::warn!("Rejected service-owned SAS request before supervisor admission: {err}");
            send_windows_service_sas_ipc_response(
                stream,
                &ipc::WindowsServiceSasIpcResponse::DispatchAccepted { accepted: false },
            )
            .await;
            return;
        }
    };
    let (permit_tx, permit_rx) = oneshot::channel();
    if sas_requests
        .try_send(WindowsServiceSasRequest {
            requester,
            permit: permit_tx,
        })
        .is_err()
    {
        log::warn!("Rejected service-owned SAS request because the supervisor is busy");
        send_windows_service_sas_ipc_response(
            stream,
            &ipc::WindowsServiceSasIpcResponse::DispatchAccepted { accepted: false },
        )
        .await;
        return;
    }

    let dispatch_accepted =
        match tokio::time::timeout(WINDOWS_SERVICE_SAS_TRANSACTION_TIMEOUT, permit_rx).await {
            Ok(Ok(Ok(session_id))) => {
                let (result_tx, result_rx) = oneshot::channel();
                let worker = match std::thread::Builder::new()
                    .name("windows-service-sas".to_owned())
                    .spawn(move || {
                        let result = dispatch
                            .dispatch(requester, session_id)
                            .map_err(|err| err.to_string());
                        let _ = result_tx.send(result);
                    }) {
                    Ok(worker) => worker,
                    Err(err) => {
                        log::error!("Could not start Windows SAS dispatch worker: {err}");
                        send_windows_service_sas_ipc_response(
                            stream,
                            &ipc::WindowsServiceSasIpcResponse::DispatchAccepted { accepted: false },
                        )
                        .await;
                        return;
                    }
                };
                let result = match result_rx.await {
                    Ok(result) => result,
                    Err(_) => Err("Windows SAS dispatch worker ended without a result".to_owned()),
                };
                if worker.join().is_err() {
                    log::error!("Windows SAS dispatch worker panicked");
                    false
                } else if let Err(err) = result {
                    log::warn!("Windows SAS dispatch was rejected: {err}");
                    false
                } else {
                    true
                }
            }
            Ok(Ok(Err(err))) => {
                log::warn!("Rejected service-owned SAS request: {err}");
                false
            }
            Ok(Err(_)) => {
                log::error!("Windows service SAS supervisor dropped its permit channel");
                false
            }
            Err(_) => {
                log::error!("Windows service SAS supervisor did not authorize within its deadline");
                false
            }
        };
    send_windows_service_sas_ipc_response(
        stream,
        &ipc::WindowsServiceSasIpcResponse::DispatchAccepted {
            accepted: dispatch_accepted,
        },
    )
    .await;
}

extern "system" {
    fn BlockInput(v: BOOL) -> BOOL;
}

const WINDOWS_SERVICE_STOP_WAIT_HINT: Duration = Duration::from_secs(30);
const WINDOWS_SERVICE_RUNTIME_GRACEFUL_CHILD_EXIT_TIMEOUT: Duration = Duration::from_secs(12);
const WINDOWS_SERVICE_FORCED_CHILD_EXIT_TIMEOUT: Duration = Duration::from_secs(3);
const WINDOWS_SERVICE_CHILD_POLL_INTERVAL: Duration = Duration::from_millis(50);
const WINDOWS_SERVICE_MAIN_IPC_TIMEOUT_MS: u64 = 1_000;
const WINDOWS_SERVICE_TRANSACTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(3);
fn windows_service_status(
    current_state: ServiceState,
    controls_accepted: ServiceControlAccept,
    exit_code: ServiceExitCode,
    checkpoint: u32,
    wait_hint: Duration,
) -> ServiceStatus {
    ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state,
        controls_accepted,
        exit_code,
        checkpoint,
        wait_hint,
        process_id: None,
    }
}

struct WindowsServiceStopReporter<'a> {
    status_handle: &'a ServiceStatusHandle,
    checkpoint: &'a mut u32,
    status_error: &'a mut Option<String>,
}

impl WindowsServiceStopReporter<'_> {
    fn report_progress(&mut self) {
        *self.checkpoint = self.checkpoint.saturating_add(1);
        if let Err(err) = self
            .status_handle
            .set_service_status(windows_service_status(
                ServiceState::StopPending,
                ServiceControlAccept::empty(),
                ServiceExitCode::Win32(0),
                *self.checkpoint,
                WINDOWS_SERVICE_STOP_WAIT_HINT,
            ))
        {
            log::error!("Failed to report Windows service stop progress: {err}");
            if self.status_error.is_none() {
                *self.status_error = Some(err.to_string());
            }
        }
    }
}

struct ServiceOwnedWindowsHandle {
    handle: HANDLE,
    label: &'static str,
}

// This wrapper uniquely owns a kernel handle and only closes it on drop. Moving that ownership to
// another thread does not change the underlying Windows object or introduce concurrent access.
unsafe impl Send for ServiceOwnedWindowsHandle {}

impl ServiceOwnedWindowsHandle {
    fn new(handle: HANDLE, label: &'static str) -> ResultType<Self> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            bail!("received invalid {label} handle");
        }
        Ok(Self { handle, label })
    }

    fn raw(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for ServiceOwnedWindowsHandle {
    fn drop(&mut self) {
        if unsafe { CloseHandle(self.handle) } == FALSE {
            log::error!(
                "Failed to close {} handle: {}",
                self.label,
                io::Error::last_os_error()
            );
        }
    }
}

struct WindowsServiceProcessTree {
    job: ServiceOwnedWindowsHandle,
    process: ServiceOwnedWindowsHandle,
    identity: ipc::WindowsProcessIdentityKey,
    session_id: DWORD,
}

impl WindowsServiceProcessTree {
    fn main_process_is_running(&self) -> ResultType<bool> {
        match unsafe { WaitForSingleObject(self.process.raw(), 0) } {
            WAIT_TIMEOUT => Ok(true),
            WAIT_OBJECT_0 => Ok(false),
            WAIT_FAILED => bail!(
                "WaitForSingleObject failed for service-owned child {}: {}",
                self.identity.pid,
                io::Error::last_os_error()
            ),
                status => bail!(
                "WaitForSingleObject returned unexpected status {status:#x} for service-owned child {}",
                self.identity.pid
            ),
        }
    }

    fn active_process_count(&self) -> ResultType<DWORD> {
        self.active_process_count_io().map_err(Into::into)
    }

    fn active_process_count_io(&self) -> io::Result<DWORD> {
        windows_job_active_process_count(self.job.raw())
    }

    fn terminate(&self) -> ResultType<()> {
        self.terminate_io().map_err(Into::into)
    }

    fn terminate_io(&self) -> io::Result<()> {
        if unsafe { TerminateJobObject(self.job.raw(), 1) } == FALSE {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    async fn wait_until_empty(&self, timeout: Duration) -> ResultType<bool> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.active_process_count()? == 0 {
                return Ok(true);
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(false);
            }
            tokio::time::sleep(WINDOWS_SERVICE_CHILD_POLL_INTERVAL).await;
        }
    }

    async fn wait_until_main_exit(&self, timeout: Duration) -> ResultType<bool> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if !self.main_process_is_running()? {
                return Ok(true);
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(false);
            }
            tokio::time::sleep(WINDOWS_SERVICE_CHILD_POLL_INTERVAL).await;
        }
    }
}

fn windows_job_active_process_count(job: HANDLE) -> io::Result<DWORD> {
    let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { mem::zeroed() };
    let queried = unsafe {
        QueryInformationJobObject(
            job,
            JobObjectBasicAccountingInformation,
            &mut accounting as *mut _ as *mut c_void,
            mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as DWORD,
            std::ptr::null_mut(),
        )
    };
    if queried == FALSE {
        return Err(io::Error::last_os_error());
    }
    Ok(accounting.ActiveProcesses)
}

fn require_windows_job_empty_before_launch_failure(job: &ServiceOwnedWindowsHandle, context: &str) {
    match windows_job_active_process_count(job.raw()) {
        Ok(0) => {}
        Ok(active) => {
            log::error!(
                "{context} left {active} process(es) in the retained service job; terminating without reporting SERVICE_STOPPED"
            );
            std::process::abort();
        }
        Err(err) => {
            log::error!(
                "{context} lost retained service-job accounting: {err}; terminating without reporting SERVICE_STOPPED"
            );
            std::process::abort();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsServicePortForwardState {
    Unknown,
    Active,
    Idle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsServiceProcessDecision {
    Keep,
    Launch(DWORD),
    RetireThenLaunch(Option<DWORD>),
}

fn windows_service_sas_target(
    child: Option<(ipc::WindowsProcessIdentityKey, DWORD, bool)>,
    requester: ipc::WindowsProcessIdentityKey,
) -> Result<DWORD, String> {
    match child {
        Some((identity, session_id, true)) if identity == requester => Ok(session_id),
        Some((identity, _, _)) => Err(format!(
            "requester {}:{} is not the live supervised child {}:{}",
            requester.pid, requester.creation_time, identity.pid, identity.creation_time
        )),
        None => Err("there is no supervised service child".to_owned()),
    }
}

fn windows_service_process_decision(
    child: Option<(DWORD, bool)>,
    desired_session_id: Option<DWORD>,
    port_forward_state: WindowsServicePortForwardState,
) -> WindowsServiceProcessDecision {
    let Some((child_session_id, main_process_running)) = child else {
        return desired_session_id
            .map(WindowsServiceProcessDecision::Launch)
            .unwrap_or(WindowsServiceProcessDecision::Keep);
    };
    if !main_process_running {
        return WindowsServiceProcessDecision::RetireThenLaunch(desired_session_id);
    }
    if Some(child_session_id) == desired_session_id {
        return WindowsServiceProcessDecision::Keep;
    }
    match port_forward_state {
        WindowsServicePortForwardState::Idle => {
            WindowsServiceProcessDecision::RetireThenLaunch(desired_session_id)
        }
        WindowsServicePortForwardState::Unknown | WindowsServicePortForwardState::Active => {
            WindowsServiceProcessDecision::Keep
        }
    }
}

const WINDOWS_SERVICE_CREDENTIAL_LEDGER_CAPACITY: usize = 64;
const WINDOWS_SERVICE_CREDENTIAL_REQUEST_CAPACITY: usize = 4;
const WINDOWS_SERVICE_CREDENTIAL_CONTROL_ATTEMPTS: usize = 3;

struct WindowsServiceCredentialSnapshot {
    storage: String,
    salt: String,
    tag: [u8; 32],
}

struct WindowsServiceCredentialTransactionOutcome {
    result: ipc::IpcMutationResult,
    retire_child: Option<ipc::WindowsProcessIdentityKey>,
    committed: bool,
}

async fn query_exact_windows_credential_replica(
    child: ipc::WindowsProcessIdentityKey,
) -> ResultType<ipc::WindowsCredentialReplicaState> {
    ipc::query_windows_service_owned_credential(child, WINDOWS_SERVICE_MAIN_IPC_TIMEOUT_MS).await
}

async fn quiesce_exact_windows_credential_replica(
    child: ipc::WindowsProcessIdentityKey,
    transition_id: &str,
) -> ResultType<()> {
    let mut last_error = None;
    for _ in 0..WINDOWS_SERVICE_CREDENTIAL_CONTROL_ATTEMPTS {
        match ipc::quiesce_windows_service_owned_credential(
            child,
            transition_id.to_owned(),
            WINDOWS_SERVICE_MAIN_IPC_TIMEOUT_MS,
        )
        .await
        {
            Ok(state)
                if state.transition_id.as_deref() == Some(transition_id) && state.quiesced =>
            {
                return Ok(())
            }
            Ok(_) => {
                last_error = Some("credential replica returned the wrong transition".to_owned())
            }
            Err(err) => last_error = Some(err.to_string()),
        }
        match query_exact_windows_credential_replica(child).await {
            Ok(state)
                if state.transition_id.as_deref() == Some(transition_id) && state.quiesced =>
            {
                return Ok(())
            }
            Ok(_) => {}
            Err(err) => last_error = Some(err.to_string()),
        }
    }
    bail!(
        "could not prove exact-child credential quiesce: {}",
        last_error.unwrap_or_else(|| "no replica response".to_owned())
    )
}

async fn resume_exact_windows_credential_replica(
    child: ipc::WindowsProcessIdentityKey,
    transition_id: &str,
) -> bool {
    for _ in 0..WINDOWS_SERVICE_CREDENTIAL_CONTROL_ATTEMPTS {
        if let Ok(state) = ipc::resume_windows_service_owned_credential(
            child,
            transition_id.to_owned(),
            WINDOWS_SERVICE_MAIN_IPC_TIMEOUT_MS,
        )
        .await
        {
            if state.transition_id.is_none() && !state.quiesced {
                return true;
            }
        }
        if let Ok(state) = query_exact_windows_credential_replica(child).await {
            if state.transition_id.is_none() && !state.quiesced {
                return true;
            }
        }
    }
    false
}

async fn apply_exact_windows_credential_replica(
    child: ipc::WindowsProcessIdentityKey,
    transition_id: &str,
    snapshot: &WindowsServiceCredentialSnapshot,
) -> bool {
    for _ in 0..WINDOWS_SERVICE_CREDENTIAL_CONTROL_ATTEMPTS {
        if let Ok(state) = ipc::apply_windows_service_owned_credential(
            child,
            transition_id.to_owned(),
            snapshot.storage.clone(),
            snapshot.salt.clone(),
            snapshot.tag,
            WINDOWS_SERVICE_MAIN_IPC_TIMEOUT_MS,
        )
        .await
        {
            if state.transition_id.is_none() && !state.quiesced && state.replica_tag == snapshot.tag
            {
                return true;
            }
        }
        if let Ok(state) = query_exact_windows_credential_replica(child).await {
            if state.transition_id.is_none() && !state.quiesced && state.replica_tag == snapshot.tag
            {
                return true;
            }
        }
    }
    false
}

async fn execute_windows_service_credential_transaction(
    operation_id: String,
    value: ipc::SensitivePassword,
    child: Option<ipc::WindowsProcessIdentityKey>,
    stop_apply: Arc<Mutex<ipc::WindowsCredentialStopApplyModel>>,
) -> WindowsServiceCredentialTransactionOutcome {
    let mut model = ipc::WindowsCredentialTransactionModel::admitted(
        child.map(|identity| (identity.pid, identity.creation_time)),
    );
    if let Some(child) = child {
        if let Err(err) = quiesce_exact_windows_credential_replica(child, &operation_id).await {
            log::warn!("Windows credential transaction could not prove exact-child quiesce: {err}");
            let resumed = resume_exact_windows_credential_replica(child, &operation_id).await;
            let resolution =
                match model.precommit_failure(resumed, ipc::IpcMutationResult::InternalFailure) {
                    Ok(resolution) => resolution,
                    Err(err) => {
                        log::error!(
                            "Windows credential precommit model rejected quiesce failure: {err}"
                        );
                        return WindowsServiceCredentialTransactionOutcome {
                            result: ipc::IpcMutationResult::InternalFailure,
                            retire_child: Some(child),
                            committed: false,
                        };
                    }
                };
            return WindowsServiceCredentialTransactionOutcome {
                result: resolution.result,
                retire_child: resolution.retire_child.then_some(child),
                committed: false,
            };
        }
        if let Err(err) = model.note_quiesced() {
            log::error!("Windows credential model rejected exact-child quiesce: {err}");
            return WindowsServiceCredentialTransactionOutcome {
                result: ipc::IpcMutationResult::InternalFailure,
                retire_child: Some(child),
                committed: false,
            };
        }
    }

    let persistence = tokio::task::spawn_blocking(move || {
        let applied = Config::set_permanent_password_persisted(value.as_str())?;
        if !applied {
            return Ok(None);
        }
        let (storage, salt) = Config::get_local_permanent_password_storage_and_salt();
        let tag = ipc::windows_credential_replica_tag(&storage, &salt);
        Ok::<_, hbb_common::anyhow::Error>(Some(WindowsServiceCredentialSnapshot {
            storage,
            salt,
            tag,
        }))
    })
    .await;

    let snapshot = match persistence {
        Ok(Ok(Some(snapshot))) => snapshot,
        Ok(Ok(None)) => {
            let resumed = if let Some(child) = child {
                resume_exact_windows_credential_replica(child, &operation_id).await
            } else {
                true
            };
            let resolution =
                match model.precommit_failure(resumed, ipc::IpcMutationResult::Rejected) {
                    Ok(resolution) => resolution,
                    Err(err) => {
                        log::error!("Windows credential model rejected a precommit refusal: {err}");
                        return WindowsServiceCredentialTransactionOutcome {
                            result: ipc::IpcMutationResult::InternalFailure,
                            retire_child: child,
                            committed: false,
                        };
                    }
                };
            return WindowsServiceCredentialTransactionOutcome {
                result: resolution.result,
                retire_child: child.filter(|_| resolution.retire_child),
                committed: false,
            };
        }
        Ok(Err(err)) => {
            log::error!("Windows service-owned password persistence failed: {err}");
            let resumed = if let Some(child) = child {
                resume_exact_windows_credential_replica(child, &operation_id).await
            } else {
                true
            };
            let resolution = match model
                .precommit_failure(resumed, ipc::IpcMutationResult::InternalFailure)
            {
                Ok(resolution) => resolution,
                Err(model_err) => {
                    log::error!(
                        "Windows credential model rejected a precommit persistence failure: {model_err}"
                    );
                    return WindowsServiceCredentialTransactionOutcome {
                        result: ipc::IpcMutationResult::InternalFailure,
                        retire_child: child,
                        committed: false,
                    };
                }
            };
            return WindowsServiceCredentialTransactionOutcome {
                result: resolution.result,
                retire_child: child.filter(|_| resolution.retire_child),
                committed: false,
            };
        }
        Err(err) => {
            log::error!(
                "Windows credential persistence worker ended ambiguously; terminating without publishing a mutation result: {err}"
            );
            std::process::abort();
        }
    };

    if let Err(err) = model.note_committed() {
        log::error!(
            "Windows credential model rejected a durable commit; terminating without weakening finality: {err}"
        );
        std::process::abort();
    }
    if child.is_none() {
        let resolution = match model.postcommit_complete(true) {
            Ok(resolution) => resolution,
            Err(err) => {
                log::error!(
                    "Windows credential model rejected postcommit completion; terminating without weakening finality: {err}"
                );
                std::process::abort();
            }
        };
        return WindowsServiceCredentialTransactionOutcome {
            result: resolution.result,
            retire_child: None,
            committed: true,
        };
    }
    let apply_admitted = stop_apply.lock().unwrap().admit_apply();
    if !apply_admitted {
        model.request_stop();
        let resolution = match model.postcommit_complete(true) {
            Ok(resolution) => resolution,
            Err(err) => {
                log::error!(
                    "Windows credential model rejected stop-before-apply completion; terminating without weakening finality: {err}"
                );
                std::process::abort();
            }
        };
        return WindowsServiceCredentialTransactionOutcome {
            result: resolution.result,
            retire_child: None,
            committed: true,
        };
    }
    let Some(child) = child else {
        log::error!(
            "Windows credential transaction lost its child identity after selecting replica apply; terminating without weakening finality"
        );
        std::process::abort();
    };
    let applied = apply_exact_windows_credential_replica(child, &operation_id, &snapshot).await;
    stop_apply.lock().unwrap().finish_apply();
    let resolution = match model.postcommit_complete(applied) {
        Ok(resolution) => resolution,
        Err(err) => {
            log::error!(
                "Windows credential model rejected replica completion after commit; terminating without weakening finality: {err}"
            );
            std::process::abort();
        }
    };
    WindowsServiceCredentialTransactionOutcome {
        result: resolution.result,
        retire_child: resolution.retire_child.then_some(child),
        committed: true,
    }
}

#[cfg(test)]
mod windows_service_supervision_tests {
    use super::{
        ipc, windows_service_process_decision, windows_service_sas_target, Duration,
        WindowsServicePortForwardState, WindowsServiceProcessDecision,
        WINDOWS_SERVICE_FORCED_CHILD_EXIT_TIMEOUT, WINDOWS_SERVICE_MAIN_IPC_TIMEOUT_MS,
        WINDOWS_SERVICE_RUNTIME_GRACEFUL_CHILD_EXIT_TIMEOUT,
        WINDOWS_SERVICE_SAS_TRANSACTION_TIMEOUT, WINDOWS_SERVICE_STOP_WAIT_HINT,
    };

    #[test]
    fn windows_service_launches_only_for_a_current_target_session() {
        assert_eq!(
            windows_service_process_decision(
                None,
                Some(7),
                WindowsServicePortForwardState::Unknown,
            ),
            WindowsServiceProcessDecision::Launch(7)
        );
        assert_eq!(
            windows_service_process_decision(None, None, WindowsServicePortForwardState::Unknown,),
            WindowsServiceProcessDecision::Keep
        );
    }

    #[test]
    fn windows_service_preserves_live_port_forwards_during_session_handoff() {
        for port_forward_state in [
            WindowsServicePortForwardState::Active,
            WindowsServicePortForwardState::Unknown,
        ] {
            assert_eq!(
                windows_service_process_decision(Some((3, true)), Some(7), port_forward_state,),
                WindowsServiceProcessDecision::Keep
            );
        }
    }

    #[test]
    fn windows_service_retires_idle_child_before_replacement() {
        assert_eq!(
            windows_service_process_decision(
                Some((3, true)),
                Some(7),
                WindowsServicePortForwardState::Idle,
            ),
            WindowsServiceProcessDecision::RetireThenLaunch(Some(7))
        );
        assert_eq!(
            windows_service_process_decision(
                Some((3, true)),
                None,
                WindowsServicePortForwardState::Idle,
            ),
            WindowsServiceProcessDecision::RetireThenLaunch(None)
        );
    }

    #[test]
    fn windows_service_reaps_a_dead_main_process_regardless_of_forward_state() {
        assert_eq!(
            windows_service_process_decision(
                Some((3, false)),
                Some(9),
                WindowsServicePortForwardState::Active,
            ),
            WindowsServiceProcessDecision::RetireThenLaunch(Some(9))
        );
    }

    #[test]
    fn windows_service_keeps_the_tree_for_its_current_session() {
        assert_eq!(
            windows_service_process_decision(
                Some((7, true)),
                Some(7),
                WindowsServicePortForwardState::Idle,
            ),
            WindowsServiceProcessDecision::Keep
        );
    }

    #[test]
    fn windows_service_sas_targets_only_the_live_supervised_child() {
        let child = crate::ipc::WindowsProcessIdentityKey {
            pid: 17,
            creation_time: 100,
        };
        let reused_pid = crate::ipc::WindowsProcessIdentityKey {
            pid: 17,
            creation_time: 101,
        };
        assert_eq!(
            windows_service_sas_target(Some((child, 4, true)), child),
            Ok(4)
        );
        assert!(windows_service_sas_target(Some((child, 4, false)), child).is_err());
        assert!(windows_service_sas_target(Some((child, 4, true)), reused_pid).is_err());
        assert!(windows_service_sas_target(None, child).is_err());
    }

    #[test]
    fn windows_service_child_shutdown_has_a_fixed_deadline() {
        let bounded_retirement = Duration::from_millis(WINDOWS_SERVICE_MAIN_IPC_TIMEOUT_MS)
            + WINDOWS_SERVICE_RUNTIME_GRACEFUL_CHILD_EXIT_TIMEOUT
            + WINDOWS_SERVICE_FORCED_CHILD_EXIT_TIMEOUT;
        assert!(bounded_retirement < Duration::from_secs(30));
    }

    #[test]
    fn windows_service_sas_client_deadline_covers_server_admission_and_response() {
        let server_envelope = WINDOWS_SERVICE_SAS_TRANSACTION_TIMEOUT
            + Duration::from_millis(ipc::SERVICE_IPC_REQUEST_TIMEOUT_MS);
        assert!(
            Duration::from_millis(ipc::WINDOWS_SERVICE_SAS_CLIENT_TIMEOUT_MS) > server_envelope
        );
    }
}

fn create_windows_service_process_job() -> ResultType<ServiceOwnedWindowsHandle> {
    let raw_job = unsafe { CreateJobObjectW(std::ptr::null_mut(), std::ptr::null()) };
    let job = ServiceOwnedWindowsHandle::new(raw_job, "service-owned process job")?;
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            &mut limits as *mut _ as *mut c_void,
            mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as DWORD,
        )
    } == FALSE
    {
        bail!(
            "SetInformationJobObject failed for service-owned process job: {}",
            io::Error::last_os_error()
        );
    }
    Ok(job)
}

fn create_inheritable_current_process_proof() -> ResultType<ServiceOwnedWindowsHandle> {
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            FALSE,
            GetCurrentProcessId(),
        )
    };
    let process = ServiceOwnedWindowsHandle::new(raw, "connection-manager parent proof")?;
    if unsafe { SetHandleInformation(process.raw(), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) }
        == FALSE
    {
        bail!(
            "SetHandleInformation failed for connection-manager parent proof: {}",
            io::Error::last_os_error()
        );
    }
    Ok(process)
}

fn windows_process_identity(
    process_id: DWORD,
    process: HANDLE,
) -> ResultType<ipc::WindowsProcessIdentityKey> {
    let mut creation: FILETIME = unsafe { mem::zeroed() };
    let mut exit: FILETIME = unsafe { mem::zeroed() };
    let mut kernel: FILETIME = unsafe { mem::zeroed() };
    let mut user: FILETIME = unsafe { mem::zeroed() };
    if unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) }
        == FALSE
    {
        bail!(
            "GetProcessTimes failed for service-owned child {}: {}",
            process_id,
            io::Error::last_os_error()
        );
    }
    let creation_time = ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
    if creation_time == 0 {
        bail!("service-owned child {process_id} has a zero creation time");
    }
    Ok(ipc::WindowsProcessIdentityKey {
        pid: process_id,
        creation_time,
    })
}

fn launch_windows_service_server(session_id: DWORD) -> ResultType<WindowsServiceProcessTree> {
    let job = create_windows_service_process_job()?;
    let exe = require_current_exe_is_fixed_service_runtime()?;
    let supervisor_identity = ipc::current_windows_process_identity_key()?;
    let supervisor_pid = supervisor_identity.pid.to_string();
    let supervisor_creation = supervisor_identity.creation_time.to_string();
    let launched = launch_process_in_session_with_env(
        &exe,
        &["--server", crate::common::SERVICE_OWNED_SERVER_ARG],
        session_id,
        FALSE,
        FALSE,
        [
            (
                ipc::WINDOWS_SERVICE_SUPERVISOR_PID_ENV,
                supervisor_pid.as_str(),
            ),
            (
                ipc::WINDOWS_SERVICE_SUPERVISOR_CREATION_ENV,
                supervisor_creation.as_str(),
            ),
        ],
        job.raw(),
        NULL,
    )?;
    if launched.process.is_null() || launched.process == INVALID_HANDLE_VALUE {
        require_windows_job_empty_before_launch_failure(
            &job,
            "Windows service child launch failure",
        );
        if launched.token_pid == 0 {
            bail!(
                "Failed to launch service-owned server in session {session_id}: no trusted LocalSystem session token"
            );
        }
        bail!(
            "Failed to launch service-owned server in session {session_id}: {}",
            io::Error::last_os_error()
        );
    }
    if launched.process_id == 0 {
        log::error!(
            "CreateProcessAsUserW returned a service-owned child without a process id; terminating without reporting SERVICE_STOPPED"
        );
        std::process::abort();
    }
    let process = ServiceOwnedWindowsHandle::new(launched.process, "service-owned child process")?;
    let identity = match windows_process_identity(launched.process_id, process.raw()) {
        Ok(identity) => identity,
        Err(err) => {
            log::error!(
                "Could not bind the launched service child to a creation identity: {err}; terminating without reporting SERVICE_STOPPED"
            );
            std::process::abort();
        }
    };
    Ok(WindowsServiceProcessTree {
        job,
        process,
        identity,
        session_id,
    })
}

async fn stop_windows_service_process_tree(
    tree: &WindowsServiceProcessTree,
    mut reporter: Option<&mut WindowsServiceStopReporter<'_>>,
) -> ResultType<()> {
    if let Some(reporter) = reporter.as_deref_mut() {
        return stop_windows_service_process_tree_for_scm(tree, reporter).await;
    }
    if tree.main_process_is_running()? {
        ipc::close_windows_service_owned_main_server(
            tree.identity,
            WINDOWS_SERVICE_MAIN_IPC_TIMEOUT_MS,
        )
        .await?;
        if !tree
            .wait_until_main_exit(WINDOWS_SERVICE_RUNTIME_GRACEFUL_CHILD_EXIT_TIMEOUT)
            .await?
        {
            bail!(
                "service-owned main child {} is still draining and remains owned",
                tree.identity.pid
            );
        }
    }
    if tree.active_process_count()? == 0 {
        return Ok(());
    }
    tree.terminate()?;
    if !tree
        .wait_until_empty(WINDOWS_SERVICE_FORCED_CHILD_EXIT_TIMEOUT)
        .await?
    {
        bail!(
            "service-owned child tree {} remained active after TerminateJobObject",
            tree.identity.pid
        );
    }
    Ok(())
}

async fn stop_windows_service_process_tree_for_scm(
    tree: &WindowsServiceProcessTree,
    reporter: &mut WindowsServiceStopReporter<'_>,
) -> ResultType<()> {
    match tree.main_process_is_running() {
        Ok(true) => {
            if let Err(err) = ipc::close_windows_service_owned_main_server(
                tree.identity,
                WINDOWS_SERVICE_MAIN_IPC_TIMEOUT_MS,
            )
            .await
            {
                log::warn!(
                    "Authenticated close of service-owned child {} failed: {err}",
                    tree.identity.pid
                );
            }
            let deadline =
                tokio::time::Instant::now() + WINDOWS_SERVICE_RUNTIME_GRACEFUL_CHILD_EXIT_TIMEOUT;
            let mut next_progress = tokio::time::Instant::now() + Duration::from_secs(1);
            while tokio::time::Instant::now() < deadline {
                match tree.main_process_is_running() {
                    Ok(false) => break,
                    Ok(true) => {}
                    Err(err) => {
                        log::warn!(
                            "Could not prove service-owned main child state during graceful shutdown: {err}"
                        );
                        break;
                    }
                }
                if tokio::time::Instant::now() >= next_progress {
                    reporter.report_progress();
                    next_progress += Duration::from_secs(1);
                }
                tokio::time::sleep(WINDOWS_SERVICE_CHILD_POLL_INTERVAL).await;
            }
        }
        Ok(false) => {}
        Err(err) => {
            log::warn!("Could not prove service-owned main child state before shutdown: {err}")
        }
    }

    let mut next_progress = tokio::time::Instant::now();
    loop {
        let observation = match tree.active_process_count_io() {
            Ok(active) => {
                if active == 0 {
                    ipc::WindowsJobStopDecision::Empty
                } else {
                    let terminate_error = tree.terminate_io().err();
                    ipc::windows_job_stop_decision(
                        Some(active),
                        terminate_error.as_ref().and_then(io::Error::raw_os_error),
                    )
                }
            }
            Err(err) => ipc::windows_job_stop_decision(None, err.raw_os_error()),
        };
        match observation {
            ipc::WindowsJobStopDecision::Empty => return Ok(()),
            ipc::WindowsJobStopDecision::Retry => {}
            ipc::WindowsJobStopDecision::Abort => {
                log::error!(
                    "Lost authoritative Windows job accounting or termination access for child tree {}; terminating without reporting SERVICE_STOPPED",
                    tree.identity.pid
                );
                std::process::abort();
            }
        }
        if tokio::time::Instant::now() >= next_progress {
            reporter.report_progress();
            next_progress = tokio::time::Instant::now() + Duration::from_secs(1);
        }
        tokio::time::sleep(WINDOWS_SERVICE_CHILD_POLL_INTERVAL).await;
    }
}

async fn reconcile_windows_service_process(
    tree: &mut Option<WindowsServiceProcessTree>,
    desired_session_id: Option<DWORD>,
    stop_latched: &AtomicBool,
    status_transition: &Mutex<()>,
) -> ResultType<()> {
    let child = match tree.as_ref() {
        Some(tree) => Some((tree.session_id, tree.main_process_is_running()?)),
        None => None,
    };
    let port_forward_state = if let (Some((child_session_id, true)), Some(tree)) =
        (child, tree.as_ref())
    {
        if Some(child_session_id) != desired_session_id {
            match ipc::get_windows_service_owned_port_forward_session_count(
                tree.identity,
                WINDOWS_SERVICE_MAIN_IPC_TIMEOUT_MS,
            )
            .await
            {
                Ok(0) => WindowsServicePortForwardState::Idle,
                Ok(_) => WindowsServicePortForwardState::Active,
                Err(err) => {
                    log::warn!(
                        "Preserving service-owned child {} because its port-forward state is unknown: {}",
                        tree.identity.pid,
                        err
                    );
                    WindowsServicePortForwardState::Unknown
                }
            }
        } else {
            WindowsServicePortForwardState::Unknown
        }
    } else {
        WindowsServicePortForwardState::Unknown
    };
    match windows_service_process_decision(child, desired_session_id, port_forward_state) {
        WindowsServiceProcessDecision::Keep => {}
        WindowsServiceProcessDecision::Launch(session_id) => {
            let _transition = status_transition.lock().unwrap();
            if stop_latched.load(Ordering::Acquire) {
                return Ok(());
            }
            match launch_windows_service_server(session_id) {
                Ok(new_tree) => *tree = Some(new_tree),
                Err(err) => log::error!(
                    "Failed to launch service-owned server in session {}: {}",
                    session_id,
                    err
                ),
            }
        }
        WindowsServiceProcessDecision::RetireThenLaunch(next_session_id) => {
            if let Some(old_tree) = tree.take() {
                if let Err(err) = stop_windows_service_process_tree(&old_tree, None).await {
                    *tree = Some(old_tree);
                    return Err(err);
                }
            }
            if let Some(session_id) =
                next_session_id.filter(|_| !stop_latched.load(Ordering::Acquire))
            {
                let _transition = status_transition.lock().unwrap();
                if stop_latched.load(Ordering::Acquire) {
                    return Ok(());
                }
                match launch_windows_service_server(session_id) {
                    Ok(new_tree) => *tree = Some(new_tree),
                    Err(err) => log::error!(
                        "Failed to launch replacement service-owned server in session {}: {}",
                        session_id,
                        err
                    ),
                }
            }
        }
    }
    Ok(())
}

async fn retire_exact_windows_service_process(
    tree: &mut Option<WindowsServiceProcessTree>,
    identity: ipc::WindowsProcessIdentityKey,
) -> ResultType<()> {
    if tree.as_ref().map(|tree| tree.identity) != Some(identity) {
        return Ok(());
    }
    let Some(owned_tree) = tree.take() else {
        return Ok(());
    };
    if let Err(graceful_error) = stop_windows_service_process_tree(&owned_tree, None).await {
        log::warn!(
            "Forcing retirement of exact service child {}:{} after graceful failure: {graceful_error}",
            identity.pid,
            identity.creation_time
        );
        owned_tree.terminate()?;
        if !owned_tree
            .wait_until_empty(WINDOWS_SERVICE_FORCED_CHILD_EXIT_TIMEOUT)
            .await?
        {
            *tree = Some(owned_tree);
            bail!(
                "exact service child {}:{} remained active after forced retirement",
                identity.pid,
                identity.creation_time
            );
        }
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn run_service(arguments: Vec<OsString>) -> ResultType<()> {
    let (stop_tx, mut stop_rx) = mpsc::unbounded_channel();
    let stop_latched = Arc::new(AtomicBool::new(false));
    let stop_apply = Arc::new(Mutex::new(ipc::WindowsCredentialStopApplyModel::new()));
    let status_slot = Arc::new(OnceLock::<ServiceStatusHandle>::new());
    let status_transition = Arc::new(Mutex::new(()));
    let handler_stop_latched = Arc::clone(&stop_latched);
    let handler_stop_apply = Arc::clone(&stop_apply);
    let handler_status_slot = Arc::clone(&status_slot);
    let handler_status_transition = Arc::clone(&status_transition);
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        log::info!("Got service control event: {:?}", control_event);
        match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Preshutdown => {
                let _transition = handler_status_transition.lock().unwrap();
                if !handler_stop_latched.swap(true, Ordering::AcqRel) {
                    handler_stop_apply.lock().unwrap().request_stop();
                    if let Some(status_handle) = handler_status_slot.get() {
                        if let Err(err) = status_handle.set_service_status(windows_service_status(
                            ServiceState::StopPending,
                            ServiceControlAccept::empty(),
                            ServiceExitCode::Win32(0),
                            1,
                            WINDOWS_SERVICE_STOP_WAIT_HINT,
                        )) {
                            log::error!(
                                "Failed to report Windows service stop-pending state: {err}"
                            );
                        }
                    }
                    if stop_tx.send(()).is_err() {
                        log::warn!("Windows service stop arrived after the service loop ended");
                    }
                }
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // The SCM guarantees that ServiceMain argument zero is the registered
    // service name. Use that dispatcher-owned value instead of depending on
    // custom identity initialization that intentionally occurs below.
    let service_name = arguments
        .first()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow!("SCM did not supply the Windows service name"))?;
    let status_handle = service_control_handler::register(service_name, event_handler)?;
    if status_slot.set(status_handle).is_err() {
        bail!("Windows service status handle was initialized more than once");
    }
    {
        let _transition = status_transition.lock().unwrap();
        let state = if stop_latched.load(Ordering::Acquire) {
            ServiceState::StopPending
        } else {
            ServiceState::StartPending
        };
        status_handle.set_service_status(windows_service_status(
            state,
            ServiceControlAccept::empty(),
            ServiceExitCode::Win32(0),
            1,
            WINDOWS_SERVICE_STOP_WAIT_HINT,
        ))?;
    }

    // StartServiceCtrlDispatcher has established SCM ownership and the status
    // handle above makes initialization failure observable to the SCM. Only
    // now select the signed application identity, durable machine-config
    // writer, and service log namespace. Config independently requires the
    // LocalSystem token, so SCM ownership and OS principal remain separate
    // receiver proofs.
    let initialization = (|| -> ResultType<()> {
        if !crate::common::global_init() {
            bail!("Windows service global initialization failed");
        }
        crate::load_custom_client();
        let program_data = program_data_dir()?;
        Config::initialize_windows_service_owned_root(&program_data, true)?;
        hbb_common::init_log(false, "service");
        Ok(())
    })();
    if let Err(err) = initialization {
        status_handle.set_service_status(windows_service_status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            ServiceExitCode::ServiceSpecific(1),
            0,
            Duration::default(),
        ))?;
        return Err(err);
    }

    let (credential_request_tx, mut credential_request_rx) =
        mpsc::channel(WINDOWS_SERVICE_CREDENTIAL_REQUEST_CAPACITY);
    let mut incoming = Some(match ipc::new_listener(crate::POSTFIX_SERVICE).await {
        Ok(incoming) => incoming,
        Err(err) => {
            status_handle.set_service_status(windows_service_status(
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                ServiceExitCode::ServiceSpecific(1),
                0,
                Duration::default(),
            ))?;
            return Err(err);
        }
    });
    let mut sas_incoming = Some(
        match ipc::new_listener(ipc::WINDOWS_SERVICE_SAS_IPC_POSTFIX).await {
            Ok(incoming) => incoming,
            Err(err) => {
                status_handle.set_service_status(windows_service_status(
                    ServiceState::Stopped,
                    ServiceControlAccept::empty(),
                    ServiceExitCode::ServiceSpecific(1),
                    0,
                    Duration::default(),
                ))?;
                return Err(err);
            }
        },
    );
    let password_listener = match start_windows_sensitive_password_listener(
        ipc::password::SERVICE_PASSWORD_IPC_POSTFIX,
        credential_request_tx,
    ) {
        Ok(listener) => listener,
        Err(err) => {
            status_handle.set_service_status(windows_service_status(
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                ServiceExitCode::ServiceSpecific(1),
                0,
                Duration::default(),
            ))?;
            return Err(err);
        }
    };
    let mut desired_session_id = current_service_session_id();
    let mut process_tree = {
        let _transition = status_transition.lock().unwrap();
        if stop_latched.load(Ordering::Acquire) {
            None
        } else {
            match desired_session_id {
                Some(session_id) => match launch_windows_service_server(session_id) {
                    Ok(tree) => Some(tree),
                    Err(err) => {
                        status_handle.set_service_status(windows_service_status(
                            ServiceState::Stopped,
                            ServiceControlAccept::empty(),
                            ServiceExitCode::ServiceSpecific(1),
                            0,
                            Duration::default(),
                        ))?;
                        return Err(err);
                    }
                },
                None => None,
            }
        }
    };
    let running_status_result = {
        let _transition = status_transition.lock().unwrap();
        if !stop_latched.load(Ordering::Acquire) {
            status_handle.set_service_status(windows_service_status(
                ServiceState::Running,
                ServiceControlAccept::STOP | ServiceControlAccept::PRESHUTDOWN,
                ServiceExitCode::Win32(0),
                0,
                Duration::default(),
            ))
        } else {
            Ok(())
        }
    };

    let mut transaction_tasks = JoinSet::new();
    let (sas_request_tx, mut sas_request_rx) = mpsc::channel::<WindowsServiceSasRequest>(1);
    let mut credential_tasks = JoinSet::new();
    let mut credential_operation_id: Option<String> = None;
    let mut credential_ledger =
        ipc::WindowsCredentialOperationLedger::new(WINDOWS_SERVICE_CREDENTIAL_LEDGER_CAPACITY);
    let mut service_tick = tokio::time::interval(Duration::from_millis(super::SERVICE_INTERVAL));
    service_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    service_tick.tick().await;
    let loop_result: ResultType<()> = if let Err(err) = running_status_result {
        Err(anyhow!(
            "Failed to report Windows service running state: {err}"
        ))
    } else {
        loop {
            tokio::select! {
            biased;
            stop = stop_rx.recv() => {
                match stop {
                    Some(()) => {
                        credential_ledger.begin_shutdown();
                        break Ok(())
                    },
                    None => break Err(anyhow!("Windows service control channel closed")),
                }
            }
            request = credential_request_rx.recv() => {
                let Some(request) = request else {
                    break Err(anyhow!("Windows service credential request channel closed"));
                };
                if let Some(status) = credential_ledger.status(
                    &request.operation_id,
                    request.value.as_str(),
                ) {
                    let _ = request.response.send(status);
                    continue;
                }
                if !ipc::password_mutation_id_is_valid(&request.operation_id)
                    || !ipc::service_owned_password_value_is_valid(
                        "Windows",
                        request.value.as_str(),
                    )
                {
                    let _ = request.response.send(ipc::PasswordMutationStatus::Complete(
                        ipc::IpcMutationResult::Rejected,
                    ));
                    continue;
                }
                let _admission = status_transition.lock().unwrap();
                if stop_latched.load(Ordering::Acquire) || credential_ledger.is_shutting_down() {
                    let status = credential_ledger
                        .classify_during_shutdown(&request.operation_id, request.value.as_str());
                    let _ = request.response.send(status);
                    continue;
                }
                if Config::is_disable_change_permanent_password()
                    || !credential_ledger.admit(
                        &request.operation_id,
                        request.value.as_str(),
                        !credential_tasks.is_empty(),
                    )
                {
                    let _ = request.response.send(ipc::PasswordMutationStatus::Complete(
                        ipc::IpcMutationResult::Rejected,
                    ));
                    continue;
                }
                let child = match process_tree.as_ref() {
                    Some(tree) => match tree.main_process_is_running() {
                        Ok(true) => Some(tree.identity),
                        Ok(false) => None,
                        Err(err) => {
                            credential_ledger.complete(
                                &request.operation_id,
                                ipc::IpcMutationResult::InternalFailure,
                            )?;
                            let _ = request.response.send(ipc::PasswordMutationStatus::Complete(
                                ipc::IpcMutationResult::InternalFailure,
                            ));
                            log::error!("Could not prove service child liveness before credential admission: {err}");
                            continue;
                        }
                    },
                    None => None,
                };
                credential_operation_id = Some(request.operation_id.clone());
                credential_tasks.spawn(execute_windows_service_credential_transaction(
                    request.operation_id,
                    request.value,
                    child,
                    Arc::clone(&stop_apply),
                ));
                let _ = request.response.send(ipc::PasswordMutationStatus::Pending);
            }
            sas_request = sas_request_rx.recv() => {
                let Some(sas_request) = sas_request else {
                    break Err(anyhow!("Windows service SAS authorization channel closed"));
                };
                let child = match process_tree.as_ref() {
                    Some(tree) => match tree.main_process_is_running() {
                        Ok(running) => Some((tree.identity, tree.session_id, running)),
                        Err(err) => {
                            let rejection = Err(format!(
                                "could not prove the supervised child is live: {err}"
                            ));
                            if sas_request.permit.send(rejection).is_err() {
                                log::warn!("Service-owned SAS requester closed before liveness rejection");
                            }
                            continue;
                        }
                    },
                    None => None,
                };
                let authorization = windows_service_sas_target(child, sas_request.requester);
                if sas_request.permit.send(authorization).is_err() {
                    log::warn!("Service-owned SAS requester closed before authorization");
                }
            }
            accepted = async {
                match sas_incoming.as_mut() {
                    Some(incoming) => incoming.next().await,
                    None => None,
                }
            } => {
                match accepted {
                    Some(Ok(stream)) => {
                        if stop_latched.load(Ordering::Acquire) {
                            continue;
                        }
                        let stream = ipc::Connection::new_protected_service(stream);
                        let expected_active_session_id = current_service_session_id();
                        if !authorize_service_scoped_ipc_connection(
                            &stream,
                            expected_active_session_id,
                        ) {
                            continue;
                        }
                        let _admission = status_transition.lock().unwrap();
                        if stop_latched.load(Ordering::Acquire) {
                            continue;
                        }
                        let Some(transaction_slot) =
                            try_acquire_windows_service_sas_ipc_transaction_slot()
                        else {
                            continue;
                        };
                        transaction_tasks.spawn(handle_windows_service_sas_ipc_request(
                            stream,
                            transaction_slot,
                            sas_request_tx.clone(),
                        ));
                    }
                    Some(Err(err)) => {
                        break Err(anyhow!("Windows SAS IPC listener failed: {err}"))
                    }
                    None => break Err(anyhow!("Windows SAS IPC listener ended")),
                }
            }
            completed = transaction_tasks.join_next(), if !transaction_tasks.is_empty() => {
                if let Some(Err(err)) = completed {
                    log::error!("Windows _service IPC transaction task failed: {err}");
                }
            }
            completed = credential_tasks.join_next(), if !credential_tasks.is_empty() => {
                let operation_id = credential_operation_id.take().ok_or_else(|| {
                    anyhow!("Windows credential task completed without an operation identity")
                })?;
                let outcome = match completed {
                    Some(Ok(outcome)) => outcome,
                    Some(Err(err)) => {
                        log::error!(
                            "Windows credential transaction task ended across an ambiguous durability boundary; terminating without publishing a mutation result: {err}"
                        );
                        std::process::abort();
                    }
                    None => break Err(anyhow!("Windows credential transaction set ended unexpectedly")),
                };
                if outcome.committed && outcome.result != ipc::IpcMutationResult::Applied {
                    log::error!(
                        "Committed Windows credential transaction lost its Applied result; terminating without publishing a contradictory result"
                    );
                    std::process::abort();
                }
                if outcome.committed {
                    if let Err(err) = credential_ledger.complete(&operation_id, outcome.result) {
                        log::error!(
                            "Windows credential replay ledger rejected a committed result; terminating without losing finality: {err}"
                        );
                        std::process::abort();
                    }
                }
                if let Some(identity) = outcome.retire_child {
                    retire_exact_windows_service_process(&mut process_tree, identity).await?;
                }
                if !outcome.committed {
                    credential_ledger.complete(&operation_id, outcome.result)?;
                }
            }
            _ = service_tick.tick() => {
                let current_session_id = current_service_session_id();
                if current_session_id != desired_session_id {
                    log::info!(
                        "Windows service target session changed from {:?} to {:?}",
                        desired_session_id,
                        current_session_id
                    );
                    if let Err(err) = refresh_service_ipc_listener(&mut incoming).await {
                        break Err(err);
                    }
                    if let Err(err) = refresh_service_sas_ipc_listener(&mut sas_incoming).await {
                        break Err(err);
                    }
                    desired_session_id = current_session_id;
                }
                if credential_tasks.is_empty() {
                    if let Err(err) = reconcile_windows_service_process(
                        &mut process_tree,
                        desired_session_id,
                        &stop_latched,
                        &status_transition,
                    ).await {
                        break Err(err);
                    }
                } else if let Some(tree) = process_tree.as_ref() {
                    match tree.main_process_is_running() {
                        Ok(true) => {}
                        Ok(false) => log::warn!(
                            "Exact service child {}:{} exited during credential transition; replacement remains suppressed until the durable decision",
                            tree.identity.pid,
                            tree.identity.creation_time
                        ),
                        Err(err) => log::error!(
                            "Could not observe exact service child liveness during credential transition: {err}"
                        ),
                    }
                }
            }
            accepted = async {
                match incoming.as_mut() {
                    Some(incoming) => incoming.next().await,
                    None => None,
                }
            } => {
                match accepted {
                    Some(Ok(stream)) => {
                        if stop_latched.load(Ordering::Acquire) {
                            continue;
                        }
                        let stream = ipc::Connection::new_protected_service(stream);
                        let expected_active_session_id = current_service_session_id();
                        if !authorize_service_scoped_ipc_connection(
                            &stream,
                            expected_active_session_id,
                        ) {
                            continue;
                        }
                        let _admission = status_transition.lock().unwrap();
                        if stop_latched.load(Ordering::Acquire) {
                            continue;
                        }
                        let Some(transaction_slot) = try_acquire_windows_service_ipc_transaction_slot() else {
                            continue;
                        };
                        transaction_tasks.spawn(handle_windows_service_ipc_request(
                            stream,
                            transaction_slot,
                        ));
                    }
                    Some(Err(err)) => break Err(anyhow!("Windows _service IPC listener failed: {err}")),
                    None => break Err(anyhow!("Windows _service IPC listener ended")),
                }
            }
            }
        }
    };

    let mut shutdown_error = loop_result.err();
    stop_latched.store(true, Ordering::Release);
    stop_apply.lock().unwrap().request_stop();
    password_listener.quiesce().await;
    credential_ledger.begin_shutdown();
    while let Ok(request) = credential_request_rx.try_recv() {
        let status = credential_ledger
            .classify_during_shutdown(&request.operation_id, request.value.as_str());
        let _ = request.response.send(status);
    }
    drop(credential_request_rx);
    {
        let _transition = status_transition.lock().unwrap();
        if let Err(err) = status_handle.set_service_status(windows_service_status(
            ServiceState::StopPending,
            ServiceControlAccept::empty(),
            ServiceExitCode::Win32(0),
            1,
            WINDOWS_SERVICE_STOP_WAIT_HINT,
        )) {
            log::error!("Failed to report Windows service stop-pending state: {err}");
            if shutdown_error.is_none() {
                shutdown_error = Some(anyhow!(
                    "Failed to report Windows service stop-pending state: {err}"
                ));
            }
        }
    }
    drop(incoming);
    drop(sas_incoming);
    let mut stop_checkpoint = 1u32;
    let mut stop_status_error = None;
    {
        let mut stop_reporter = WindowsServiceStopReporter {
            status_handle: &status_handle,
            checkpoint: &mut stop_checkpoint,
            status_error: &mut stop_status_error,
        };
        while !credential_tasks.is_empty() {
            let completed = tokio::select! {
                completed = credential_tasks.join_next() => completed,
                _ = tokio::time::sleep(Duration::from_secs(1)) => {
                    stop_reporter.report_progress();
                    continue;
                }
            };
            let Some(completed) = completed else {
                break;
            };
            let operation_id = credential_operation_id.take().ok_or_else(|| {
                anyhow!("Windows credential shutdown completion lost its operation identity")
            })?;
            match completed {
                Ok(outcome) => {
                    if outcome.committed && outcome.result != ipc::IpcMutationResult::Applied {
                        log::error!(
                            "Committed Windows credential transaction lost its Applied result during shutdown; terminating without publishing a contradictory result"
                        );
                        std::process::abort();
                    }
                    if outcome.committed {
                        if let Err(err) = credential_ledger.complete(&operation_id, outcome.result)
                        {
                            log::error!(
                                "Windows credential replay ledger rejected a committed shutdown result: {err}"
                            );
                            std::process::abort();
                        }
                    }
                    if let Some(identity) = outcome.retire_child {
                        if let Err(err) =
                            retire_exact_windows_service_process(&mut process_tree, identity).await
                        {
                            log::error!("Windows credential shutdown retirement failed: {err}");
                            if shutdown_error.is_none() {
                                shutdown_error = Some(err);
                            }
                        }
                    }
                    if !outcome.committed {
                        if let Err(err) = credential_ledger.complete(&operation_id, outcome.result)
                        {
                            if shutdown_error.is_none() {
                                shutdown_error = Some(err);
                            }
                        }
                    }
                }
                Err(err) => {
                    log::error!(
                        "Windows credential transaction task ended during shutdown across an ambiguous durability boundary; terminating without publishing a mutation result: {err}"
                    );
                    std::process::abort();
                }
            }
            stop_reporter.report_progress();
        }
        let transaction_deadline =
            tokio::time::Instant::now() + WINDOWS_SERVICE_TRANSACTION_DRAIN_TIMEOUT;
        while !transaction_tasks.is_empty() {
            match tokio::time::timeout_at(transaction_deadline, transaction_tasks.join_next()).await
            {
                Ok(Some(Ok(()))) => stop_reporter.report_progress(),
                Ok(Some(Err(err))) => {
                    log::error!("Windows _service IPC transaction did not drain cleanly: {err}");
                    if shutdown_error.is_none() {
                        shutdown_error = Some(anyhow!(
                            "Windows _service IPC transaction did not drain cleanly: {err}"
                        ));
                    }
                    stop_reporter.report_progress();
                }
                Ok(None) => break,
                Err(_) => {
                    log::error!(
                        "Windows _service IPC transactions exceeded their shutdown deadline"
                    );
                    transaction_tasks.abort_all();
                    while transaction_tasks.join_next().await.is_some() {}
                    if shutdown_error.is_none() {
                        shutdown_error = Some(anyhow!(
                            "Windows _service IPC transactions exceeded their shutdown deadline"
                        ));
                    }
                    break;
                }
            }
        }
        stop_reporter.report_progress();
        if let Some(tree) = process_tree.take() {
            if let Err(err) =
                stop_windows_service_process_tree(&tree, Some(&mut stop_reporter)).await
            {
                log::error!("Windows service-owned child shutdown failed: {err}");
                if shutdown_error.is_none() {
                    shutdown_error = Some(err);
                }
            }
        }
        if !stop_apply.lock().unwrap().complete_stop() {
            log::error!(
                "Windows stop/apply authority could not prove stop linearization after the child job became empty"
            );
            std::process::abort();
        }
    }
    if let Some(err) = stop_status_error {
        if shutdown_error.is_none() {
            shutdown_error = Some(anyhow!("Windows service status reporting failed: {err}"));
        }
    }

    let (exit_code, result) = match shutdown_error {
        Some(err) => (ServiceExitCode::ServiceSpecific(1), Err(err)),
        None => (ServiceExitCode::Win32(0), Ok(())),
    };
    status_handle.set_service_status(windows_service_status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit_code,
        0,
        Duration::default(),
    ))?;
    result
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WindowsPathIdentity {
    volume_serial_number: u32,
    file_index_high: u32,
    file_index_low: u32,
}

fn windows_path_identity_from_info(info: &BY_HANDLE_FILE_INFORMATION) -> WindowsPathIdentity {
    WindowsPathIdentity {
        volume_serial_number: info.dwVolumeSerialNumber,
        file_index_high: info.nFileIndexHigh,
        file_index_low: info.nFileIndexLow,
    }
}

fn path_identity_from_handle(handle: HANDLE, label: &str) -> ResultType<WindowsPathIdentity> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    if ok == 0 {
        bail!(
            "failed to query Windows path identity for {label}: {}",
            io::Error::last_os_error()
        );
    }
    Ok(windows_path_identity_from_info(&info))
}

fn windows_path_identity_and_attributes(
    path: &Path,
    label: &str,
) -> ResultType<(WindowsPathIdentity, DWORD)> {
    let path_w = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            path_w.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        bail!(
            "failed to open {label} for Windows path identity '{}': {}",
            path.display(),
            io::Error::last_os_error()
        );
    }
    let _handle = hbb_common::platform::windows::RAIIHandle(handle);
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    if ok == 0 {
        bail!(
            "failed to query Windows path identity for {label}: {}",
            io::Error::last_os_error()
        );
    }
    Ok((
        windows_path_identity_from_info(&info),
        info.dwFileAttributes,
    ))
}

fn require_existing_directory_no_reparse(
    path: &Path,
    label: &str,
) -> ResultType<WindowsPathIdentity> {
    let (identity, attributes) = windows_path_identity_and_attributes(path, label)?;
    if attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || attributes & FILE_ATTRIBUTE_REPARSE_POINT_FLAG != 0
    {
        bail!("{label} is not a trusted directory: {}", path.display());
    }
    Ok(identity)
}

pub(crate) fn require_existing_file_no_reparse(
    path: &Path,
    label: &str,
) -> ResultType<WindowsPathIdentity> {
    let (identity, attributes) = windows_path_identity_and_attributes(path, label)?;
    if attributes & FILE_ATTRIBUTE_DIRECTORY != 0
        || attributes & FILE_ATTRIBUTE_REPARSE_POINT_FLAG != 0
    {
        bail!("{label} is not a trusted file: {}", path.display());
    }
    Ok(identity)
}

pub(crate) fn fixed_service_install_exe_path() -> ResultType<PathBuf> {
    Ok(fixed_service_install_path("")?.join(format!("{}.exe", crate::get_app_name())))
}

pub(crate) fn require_current_exe_is_fixed_service_runtime() -> ResultType<PathBuf> {
    let current_exe = std::env::current_exe()
        .map_err(|err| anyhow!("failed to resolve current Windows service executable: {err}"))?;
    let current_dir = current_exe
        .parent()
        .ok_or_else(|| anyhow!("current Windows service executable has no parent directory"))?;
    let install_dir = fixed_service_install_path("")?;
    let expected_exe = fixed_service_install_exe_path()?;

    let install_dir_identity = require_existing_directory_no_reparse(
        &install_dir,
        "Windows fixed service install directory",
    )?;
    let current_dir_identity = require_existing_directory_no_reparse(
        current_dir,
        "Windows running service executable directory",
    )?;
    let current_exe_identity =
        require_existing_file_no_reparse(&current_exe, "Windows running service executable")?;
    let expected_exe_identity =
        require_existing_file_no_reparse(&expected_exe, "Windows fixed service executable")?;

    if current_dir_identity != install_dir_identity {
        bail!(
            "Windows service-owned server launch requires the fixed service install directory: {}",
            install_dir.display()
        );
    }
    if current_exe_identity != expected_exe_identity {
        bail!(
            "Windows service-owned server launch requires the fixed service executable: {}",
            expected_exe.display()
        );
    }

    Ok(expected_exe)
}

fn launch_executable_path(exe: &Path) -> ResultType<&Path> {
    if !exe.is_absolute() {
        bail!(
            "token-switched Windows launch requires an absolute executable path: {}",
            exe.display()
        );
    }
    if !exe.is_file() {
        bail!("Windows launch executable is not a file: {}", exe.display());
    }
    Ok(exe)
}

fn null_terminated_wide(value: &OsStr, label: &str) -> ResultType<Vec<u16>> {
    let mut wide = value.encode_wide().collect::<Vec<_>>();
    if wide.is_empty() {
        bail!("empty Windows {}", label);
    }
    if wide.iter().any(|value| *value == 0) {
        bail!("Windows {} contains NUL", label);
    }
    wide.push(0);
    Ok(wide)
}

fn append_windows_command_arg(command_line: &mut Vec<u16>, arg: &OsStr) -> ResultType<()> {
    const BACKSLASH: u16 = b'\\' as u16;
    const QUOTE: u16 = b'"' as u16;
    const SPACE: u16 = b' ' as u16;
    const TAB: u16 = b'\t' as u16;

    let value = arg.encode_wide().collect::<Vec<_>>();
    if value.iter().any(|value| *value == 0) {
        bail!("Windows command argument contains NUL");
    }
    let needs_quotes = value.is_empty()
        || value
            .iter()
            .any(|value| matches!(*value, SPACE | TAB | QUOTE));
    if !needs_quotes {
        command_line.extend_from_slice(&value);
        return Ok(());
    }

    command_line.push(QUOTE);
    let mut backslashes = 0usize;
    for value in value {
        if value == BACKSLASH {
            backslashes += 1;
            continue;
        }
        if value == QUOTE {
            for _ in 0..(backslashes * 2 + 1) {
                command_line.push(BACKSLASH);
            }
            command_line.push(QUOTE);
            backslashes = 0;
            continue;
        }
        for _ in 0..backslashes {
            command_line.push(BACKSLASH);
        }
        backslashes = 0;
        command_line.push(value);
    }
    for _ in 0..(backslashes * 2) {
        command_line.push(BACKSLASH);
    }
    command_line.push(QUOTE);
    Ok(())
}

fn windows_command_line(exe: &Path, arg: &[&str]) -> ResultType<Vec<u16>> {
    let mut command_line = Vec::new();
    append_windows_command_arg(&mut command_line, exe.as_os_str())?;
    for arg in arg {
        command_line.push(b' ' as u16);
        append_windows_command_arg(&mut command_line, OsStr::new(arg))?;
    }
    command_line.push(0);
    Ok(command_line)
}

pub(crate) enum WindowsUserHelperLaunch<'a> {
    Tray,
    Whiteboard { launch_token: &'a str },
}

fn validate_windows_user_helper_launch_token(role: &str, launch_token: &str) -> ResultType<()> {
    let mut decoded = crate::decode64(launch_token)
        .map_err(|err| anyhow!("Invalid {role} launch token: {err}"))?;
    let valid = decoded.len() == hbb_common::sodiumoxide::crypto::auth::hmacsha256::KEYBYTES;
    decoded.fill(0);
    if !valid {
        bail!("Invalid {role} launch token length");
    }
    Ok(())
}

fn windows_user_helper_launch_parts(
    launch: &WindowsUserHelperLaunch<'_>,
) -> ResultType<(&'static str, Vec<(OsString, OsString)>)> {
    let parent = OsString::from(std::process::id().to_string());
    match launch {
        WindowsUserHelperLaunch::Tray => Ok(("--tray", Vec::new())),
        WindowsUserHelperLaunch::Whiteboard { launch_token } => {
            validate_windows_user_helper_launch_token("whiteboard", launch_token)?;
            Ok((
                "--whiteboard",
                vec![
                    (
                        OsString::from(crate::common::WHITEBOARD_LAUNCH_TOKEN_ENV),
                        OsString::from(launch_token),
                    ),
                    (
                        OsString::from(crate::common::WHITEBOARD_LAUNCH_PARENT_ENV),
                        parent,
                    ),
                ],
            ))
        }
    }
}

fn windows_connection_manager_launch_environment(
    launch_token: &str,
    parent: ipc::WindowsProcessIdentityKey,
    parent_handle: Option<HANDLE>,
) -> ResultType<Vec<(OsString, OsString)>> {
    validate_windows_user_helper_launch_token("connection-manager", launch_token)?;
    let mut environment = vec![
        (
            OsString::from(crate::common::CM_LAUNCH_TOKEN_ENV),
            OsString::from(launch_token),
        ),
        (
            OsString::from(crate::common::CM_LAUNCH_PARENT_ENV),
            OsString::from(parent.pid.to_string()),
        ),
        (
            OsString::from(crate::common::CM_LAUNCH_PARENT_CREATION_ENV),
            OsString::from(parent.creation_time.to_string()),
        ),
    ];
    let parent_handle = match parent_handle {
        Some(parent_handle) => {
            if parent_handle.is_null() || parent_handle == INVALID_HANDLE_VALUE {
                bail!("Invalid inherited Windows connection-manager parent handle");
            }
            OsString::from((parent_handle as usize).to_string())
        }
        None => OsString::from(crate::common::CM_LAUNCH_PARENT_HANDLE_NONE),
    };
    environment.push((
        OsString::from(crate::common::CM_LAUNCH_PARENT_HANDLE_ENV),
        parent_handle,
    ));
    Ok(environment)
}

#[cfg(test)]
mod process_launch_tests {
    use super::*;
    use std::os::windows::ffi::OsStringExt;

    fn command_line_string(exe: &str, arg: &[&str]) -> String {
        let mut command_line = windows_command_line(Path::new(exe), arg).unwrap();
        assert_eq!(command_line.pop(), Some(0));
        OsString::from_wide(&command_line)
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn windows_command_line_quotes_executable_and_args() {
        let command_line = command_line_string(
            r"C:\Program Files\RustDesk\rustdesk.exe",
            &[
                "--server",
                crate::common::SERVICE_OWNED_SERVER_ARG,
                "has space",
                r#"quote"arg"#,
                r"needs space\",
            ],
        );

        assert_eq!(
            command_line,
            r#""C:\Program Files\RustDesk\rustdesk.exe" --server --service-owned-server "has space" "quote\"arg" "needs space\\""#
        );
    }

    #[test]
    fn windows_command_line_rejects_nul() {
        assert!(
            windows_command_line(Path::new(r"C:\RustDesk\rustdesk.exe"), &["bad\0arg"]).is_err()
        );
    }

    #[test]
    fn windows_user_helper_launch_shape_is_typed_and_exact() {
        let launch_token = crate::encode64([7u8; 32]);
        let parent = OsString::from(std::process::id().to_string());

        let parent_identity = ipc::current_windows_process_identity_key().unwrap();
        let environment =
            windows_connection_manager_launch_environment(&launch_token, parent_identity, None)
                .unwrap();
        assert_eq!(
            environment,
            vec![
                (
                    OsString::from(crate::common::CM_LAUNCH_TOKEN_ENV),
                    OsString::from(&launch_token),
                ),
                (
                    OsString::from(crate::common::CM_LAUNCH_PARENT_ENV),
                    OsString::from(parent_identity.pid.to_string()),
                ),
                (
                    OsString::from(crate::common::CM_LAUNCH_PARENT_CREATION_ENV),
                    OsString::from(parent_identity.creation_time.to_string()),
                ),
                (
                    OsString::from(crate::common::CM_LAUNCH_PARENT_HANDLE_ENV),
                    OsString::from(crate::common::CM_LAUNCH_PARENT_HANDLE_NONE),
                ),
            ]
        );
        let inherited_parent = 7usize as HANDLE;
        let inherited_environment = windows_connection_manager_launch_environment(
            &launch_token,
            parent_identity,
            Some(inherited_parent),
        )
        .unwrap();
        assert_eq!(
            inherited_environment.last(),
            Some(&(
                OsString::from(crate::common::CM_LAUNCH_PARENT_HANDLE_ENV),
                OsString::from("7"),
            ))
        );

        let (role, environment) =
            windows_user_helper_launch_parts(&WindowsUserHelperLaunch::Whiteboard {
                launch_token: &launch_token,
            })
            .unwrap();
        assert_eq!(role, "--whiteboard");
        assert_eq!(
            environment,
            vec![
                (
                    OsString::from(crate::common::WHITEBOARD_LAUNCH_TOKEN_ENV),
                    OsString::from(&launch_token),
                ),
                (
                    OsString::from(crate::common::WHITEBOARD_LAUNCH_PARENT_ENV),
                    parent,
                ),
            ]
        );

        assert_eq!(
            windows_user_helper_launch_parts(&WindowsUserHelperLaunch::Tray).unwrap(),
            ("--tray", Vec::new())
        );
        assert!(windows_connection_manager_launch_environment("", parent_identity).is_err());
        assert!(
            windows_user_helper_launch_parts(&WindowsUserHelperLaunch::Whiteboard {
                launch_token: &crate::encode64([0u8; 31]),
            })
            .is_err()
        );
    }
}

struct WindowsLaunchedProcess {
    process: HANDLE,
    process_id: DWORD,
    token_pid: DWORD,
}

struct WindowsConnectionManagerProcessHandle {
    _job: ServiceOwnedWindowsHandle,
    process: ServiceOwnedWindowsHandle,
}

pub(crate) struct WindowsConnectionManagerProcess {
    handle: WindowsConnectionManagerProcessHandle,
    identity: ipc::WindowsProcessIdentityKey,
}

impl WindowsConnectionManagerProcess {
    pub(crate) fn identity(&self) -> ipc::WindowsProcessIdentityKey {
        self.identity
    }

    pub(crate) fn try_reap_exited(&mut self) -> ResultType<bool> {
        match unsafe { WaitForSingleObject(self.handle.process.raw(), 0) } {
            WAIT_TIMEOUT => Ok(false),
            WAIT_OBJECT_0 => Ok(true),
            WAIT_FAILED => bail!(
                "WaitForSingleObject failed for connection-manager child {}: {}",
                self.identity.pid,
                io::Error::last_os_error()
            ),
            status => bail!(
                "WaitForSingleObject returned unexpected status {status:#x} for connection-manager child {}",
                self.identity.pid
            ),
        }
    }
}

fn launch_process_in_session_with_env<I, K, V>(
    exe: &Path,
    arg: &[&str],
    session_id: DWORD,
    as_user: BOOL,
    show: BOOL,
    envs: I,
    job: HANDLE,
    inherited_handle: HANDLE,
) -> ResultType<WindowsLaunchedProcess>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    if !inherited_handle.is_null() && job.is_null() {
        bail!("Windows inherited-handle launch requires an atomic process-creation job");
    }
    let exe = launch_executable_path(exe)?;
    let current_dir = exe
        .parent()
        .ok_or_else(|| anyhow!("Windows launch executable has no parent: {}", exe.display()))?;
    let application = null_terminated_wide(exe.as_os_str(), "application path")?;
    let command_line = windows_command_line(exe, arg)?;
    let current_directory = null_terminated_wide(current_dir.as_os_str(), "current directory")?;
    let extra_env_block = windows_env_block(envs)?;
    let extra_env = if extra_env_block.len() > 1 {
        extra_env_block.as_ptr()
    } else {
        std::ptr::null()
    };
    let mut token_pid = 0;
    let mut process_id = 0;
    let process = unsafe {
        LaunchProcessWin(
            application.as_ptr(),
            command_line.as_ptr(),
            current_directory.as_ptr(),
            session_id,
            as_user,
            show,
            extra_env,
            job,
            inherited_handle,
            &mut process_id,
            &mut token_pid,
        )
    };
    Ok(WindowsLaunchedProcess {
        process,
        process_id,
        token_pid,
    })
}

fn launch_current_process_with_env_and_job<I, K, V>(
    exe: &Path,
    arg: &[&str],
    envs: I,
    job: HANDLE,
) -> ResultType<WindowsLaunchedProcess>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    if job.is_null() || job == INVALID_HANDLE_VALUE {
        bail!("current-token Windows launch requires an owned process job");
    }
    let exe = launch_executable_path(exe)?;
    let current_dir = exe
        .parent()
        .ok_or_else(|| anyhow!("Windows launch executable has no parent: {}", exe.display()))?;
    let application = null_terminated_wide(exe.as_os_str(), "application path")?;
    let command_line = windows_command_line(exe, arg)?;
    let current_directory = null_terminated_wide(current_dir.as_os_str(), "current directory")?;
    let extra_env = windows_env_block(envs)?;
    if extra_env.len() <= 1 {
        bail!("current-token Windows launch requires an explicit environment overlay");
    }
    let mut process_id = 0;
    let process = unsafe {
        LaunchProcessCurrentWin(
            application.as_ptr(),
            command_line.as_ptr(),
            current_directory.as_ptr(),
            extra_env.as_ptr(),
            job,
            &mut process_id,
        )
    };
    Ok(WindowsLaunchedProcess {
        process,
        process_id,
        token_pid: 0,
    })
}

pub(crate) fn run_user_helper(
    launch: WindowsUserHelperLaunch<'_>,
) -> ResultType<Option<std::process::Child>> {
    let (arg, envs) = windows_user_helper_launch_parts(&launch)?;
    let arg = vec![arg];
    if is_root() {
        return run_current_exe_in_current_session_with_env(
            arg,
            envs.iter().map(|(key, value)| (key, value)),
        );
    }

    let exe = std::env::current_exe()?;
    let mut command = std::process::Command::new(exe);
    command
        .envs(envs.iter().map(|(key, value)| (key, value)))
        .args(arg)
        .creation_flags(CREATE_NO_WINDOW);
    command
        .spawn()
        .map(Some)
        .map_err(|err| anyhow!("Failed to start current RustDesk process: {err}"))
}

pub(crate) fn run_connection_manager_user_helper(
    launch_token: &str,
) -> ResultType<WindowsConnectionManagerProcess> {
    let parent = ipc::current_windows_process_identity_key().map_err(|err| {
        anyhow!("Failed to identify the Windows connection-manager owner: {err:#}")
    })?;
    let inherited_parent = if is_root() {
        Some(create_inheritable_current_process_proof().map_err(|err| {
            anyhow!("Failed to create the Windows connection-manager parent proof: {err:#}")
        })?)
    } else {
        None
    };
    let envs = windows_connection_manager_launch_environment(
        launch_token,
        parent,
        inherited_parent
            .as_ref()
            .map(ServiceOwnedWindowsHandle::raw),
    )
    .map_err(|err| {
        anyhow!("Failed to prepare the Windows connection-manager launch proof: {err:#}")
    })?;
    let job = create_windows_service_process_job()?;
    let launched = if is_root() {
        let Some(session_id) = get_current_process_session_id() else {
            bail!("Failed to get current process session id");
        };
        let exe = std::env::current_exe().map_err(|err| {
            anyhow!("Failed to resolve the LocalSystem connection-manager executable: {err}")
        })?;
        let launch_result = launch_process_in_session_with_env(
            &exe,
            &["--cm"],
            session_id,
            TRUE,
            FALSE,
            envs.iter().map(|(key, value)| (key, value)),
            job.raw(),
            inherited_parent
                .as_ref()
                .map(ServiceOwnedWindowsHandle::raw)
                .unwrap_or(NULL),
        );
        // The child has its own explicitly allowlisted copy after process creation. Close the
        // temporarily inheritable service-side copy before inspecting the launch result so no
        // subsequent child launch can inherit this capability.
        drop(inherited_parent);
        let launched = launch_result?;
        if launched.process.is_null() || launched.process == INVALID_HANDLE_VALUE {
            require_windows_job_empty_before_launch_failure(
                &job,
                "Windows connection-manager launch failure",
            );
            if launched.token_pid == 0 {
                bail!(
                    "Failed to launch connection manager in session {session_id}: no trusted logged-on user token"
                );
            }
            bail!(
                "Failed to launch connection manager in session {session_id}: {}",
                io::Error::last_os_error()
            );
        }
        launched
    } else {
        let exe = std::env::current_exe().map_err(|err| {
            anyhow!("Failed to resolve the same-user connection-manager executable: {err}")
        })?;
        let launched = launch_current_process_with_env_and_job(
            &exe,
            &["--cm"],
            envs.iter().map(|(key, value)| (key, value)),
            job.raw(),
        )?;
        if launched.process.is_null() || launched.process == INVALID_HANDLE_VALUE {
            require_windows_job_empty_before_launch_failure(
                &job,
                "Windows same-user connection-manager launch failure",
            );
            bail!(
                "Failed to launch same-user connection manager: {}",
                io::Error::last_os_error()
            );
        }
        launched
    };
    if launched.process_id == 0 {
        let process =
            ServiceOwnedWindowsHandle::new(launched.process, "connection-manager child process")?;
        drop(process);
        bail!("Windows process creation returned a connection manager without a process id");
    }
    let process =
        ServiceOwnedWindowsHandle::new(launched.process, "connection-manager child process")?;
    let identity = windows_process_identity(launched.process_id, process.raw())?;
    Ok(WindowsConnectionManagerProcess {
        handle: WindowsConnectionManagerProcessHandle { _job: job, process },
        identity,
    })
}

fn windows_env_block<I, K, V>(envs: I) -> ResultType<Vec<u16>>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    let mut block = Vec::new();
    for (key, value) in envs {
        let key = key.as_ref().encode_wide().collect::<Vec<_>>();
        if key.is_empty() || key.iter().any(|value| *value == 0 || *value == b'=' as u16) {
            bail!("invalid Windows environment key");
        }
        let value = value.as_ref().encode_wide().collect::<Vec<_>>();
        if value.iter().any(|value| *value == 0) {
            bail!("invalid Windows environment value");
        }
        block.extend_from_slice(&key);
        block.push(b'=' as u16);
        block.extend_from_slice(&value);
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

fn run_current_exe_in_current_session_with_env<I, K, V>(
    arg: Vec<&str>,
    envs: I,
) -> ResultType<Option<std::process::Child>>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    let Some(session_id) = get_current_process_session_id() else {
        bail!("Failed to get current process session id");
    };
    let exe = std::env::current_exe()?;
    let launched =
        launch_process_in_session_with_env(&exe, &arg, session_id, TRUE, FALSE, envs, NULL, NULL)?;
    if launched.process.is_null() {
        if launched.token_pid == 0 {
            bail!(
                "Failed to launch {:?} with session id {}: no trusted logged-on user token",
                arg,
                session_id
            );
        }
        bail!(
            "Failed to launch {:?} with session id {}: {}",
            arg,
            session_id,
            io::Error::last_os_error()
        );
    }
    if unsafe { CloseHandle(launched.process) } == FALSE {
        log::error!(
            "Failed to release launched Windows helper process handle: {}",
            io::Error::last_os_error()
        );
    }
    Ok(None)
}

const SOFTWARE_SAS_GENERATION_NONE: u32 = 0;
const SOFTWARE_SAS_GENERATION_SERVICES: u32 = 1;
const SOFTWARE_SAS_GENERATION_EASE_OF_ACCESS: u32 = 2;
const SOFTWARE_SAS_GENERATION_SERVICES_AND_EASE_OF_ACCESS: u32 =
    SOFTWARE_SAS_GENERATION_SERVICES | SOFTWARE_SAS_GENERATION_EASE_OF_ACCESS;

fn read_software_sas_generation_policy() -> ResultType<Option<u32>> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let policy_key = hklm
        .open_subkey_with_flags(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            KEY_READ,
        )
        .map_err(|err| anyhow!("Failed to open SoftwareSASGeneration policy key: {err}"))?;
    match policy_key.get_value::<u32, _>("SoftwareSASGeneration") {
        Ok(value) => Ok(Some(value)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => bail!("Failed to read SoftwareSASGeneration: {err}"),
    }
}

fn send_sas_with<R, S>(read_policy: R, send: S) -> ResultType<()>
where
    R: FnOnce() -> ResultType<Option<u32>>,
    S: FnOnce(),
{
    match read_policy()? {
        Some(SOFTWARE_SAS_GENERATION_SERVICES)
        | Some(SOFTWARE_SAS_GENERATION_SERVICES_AND_EASE_OF_ACCESS) => {
            send();
            Ok(())
        }
        Some(SOFTWARE_SAS_GENERATION_NONE) => {
            bail!("SoftwareSASGeneration policy denies software SAS")
        }
        Some(SOFTWARE_SAS_GENERATION_EASE_OF_ACCESS) => {
            bail!("SoftwareSASGeneration policy does not authorize services")
        }
        Some(value) => bail!("Unsupported SoftwareSASGeneration value: {value}"),
        None => bail!("SoftwareSASGeneration policy is not configured for services"),
    }
}

// https://learn.microsoft.com/en-us/windows/win32/api/sas/nf-sas-sendsas
pub(crate) fn send_sas() -> ResultType<()> {
    #[link(name = "sas")]
    extern "system" {
        pub fn SendSAS(AsUser: BOOL);
    }

    log::info!("Dispatching service-mediated SAS request");
    send_sas_with(read_software_sas_generation_policy, || unsafe {
        SendSAS(FALSE);
    })
}

#[cfg(test)]
mod windows_sas_policy_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn windows_sas_policy_matrix_is_read_only_and_fail_closed() {
        for value in [
            SOFTWARE_SAS_GENERATION_SERVICES,
            SOFTWARE_SAS_GENERATION_SERVICES_AND_EASE_OF_ACCESS,
        ] {
            let calls = AtomicUsize::new(0);
            assert!(send_sas_with(
                || Ok(Some(value)),
                || {
                    calls.fetch_add(1, Ordering::SeqCst);
                }
            )
            .is_ok());
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }

        for value in [
            None,
            Some(SOFTWARE_SAS_GENERATION_NONE),
            Some(SOFTWARE_SAS_GENERATION_EASE_OF_ACCESS),
            Some(4),
        ] {
            let calls = AtomicUsize::new(0);
            assert!(send_sas_with(
                || Ok(value),
                || {
                    calls.fetch_add(1, Ordering::SeqCst);
                }
            )
            .is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }

        let calls = AtomicUsize::new(0);
        assert!(send_sas_with(
            || -> ResultType<Option<u32>> { bail!("policy read failed") },
            || {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        )
        .is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

lazy_static::lazy_static! {
    static ref SUPPRESS: Arc<Mutex<Instant>> = Arc::new(Mutex::new(Instant::now()));
}

pub fn desktop_changed() -> bool {
    unsafe { inputDesktopSelected() == FALSE }
}

pub fn try_change_desktop() -> bool {
    unsafe {
        if inputDesktopSelected() == FALSE {
            let res = selectInputDesktop() == TRUE;
            if !res {
                let mut s = SUPPRESS.lock().unwrap();
                if s.elapsed() > std::time::Duration::from_secs(3) {
                    log::error!("Failed to switch desktop: {}", io::Error::last_os_error());
                    *s = Instant::now();
                }
            } else {
                log::info!("Desktop switched");
            }
            return res;
        }
    }
    return false;
}

fn share_rdp() -> BOOL {
    if current_package_registry_value("share_rdp").unwrap_or_default() != "false" {
        TRUE
    } else {
        FALSE
    }
}

pub fn is_share_rdp() -> bool {
    share_rdp() == TRUE
}

pub(crate) fn set_service_owned_share_rdp(enable: bool) -> ResultType<()> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm.open_subkey_with_flags(
        current_package_uninstall_subkey(),
        KEY_SET_VALUE | KEY_WOW64_64KEY,
    )?;
    let value = (if enable { "true" } else { "false" }).to_owned();
    key.set_value("share_rdp", &value)?;
    Ok(())
}

pub fn get_current_process_session_id() -> Option<u32> {
    get_session_id_of_process(unsafe { GetCurrentProcessId() })
}

pub fn get_session_id_of_process(pid: DWORD) -> Option<u32> {
    let mut sid = 0;
    if unsafe { ProcessIdToSessionId(pid, &mut sid) == TRUE } {
        Some(sid)
    } else {
        None
    }
}

pub fn is_physical_console_session() -> Option<bool> {
    if let Some(sid) = get_current_process_session_id() {
        let physical_console_session_id = unsafe { get_current_session(FALSE) };
        if physical_console_session_id == u32::MAX {
            return None;
        }
        return Some(physical_console_session_id == sid);
    }
    None
}

pub fn get_active_username() -> String {
    // get_active_user will give console username higher priority
    if let Some(name) = get_current_session_username() {
        return name;
    }
    if !is_root() {
        return crate::username();
    }

    extern "C" {
        fn get_active_user(path: *mut u16, n: u32, rdp: BOOL) -> u32;
    }
    let buff_size = 256;
    let mut buff: Vec<u16> = Vec::with_capacity(buff_size);
    buff.resize(buff_size, 0);
    let n = unsafe { get_active_user(buff.as_mut_ptr(), buff_size as _, share_rdp()) };
    if n == 0 {
        return "".to_owned();
    }
    let sl = unsafe { std::slice::from_raw_parts(buff.as_ptr(), n as _) };
    String::from_utf16(sl)
        .unwrap_or("??".to_owned())
        .trim_end_matches('\0')
        .to_owned()
}

fn get_current_session_username() -> Option<String> {
    let Some(sid) = get_current_process_session_id() else {
        log::error!("get_current_process_session_id failed");
        return None;
    };
    Some(get_session_username(sid))
}

fn get_session_username(session_id: u32) -> String {
    extern "C" {
        fn get_session_user_info(path: *mut u16, n: u32, session_id: u32) -> u32;
    }
    let buff_size = 256;
    let mut buff: Vec<u16> = Vec::with_capacity(buff_size);
    buff.resize(buff_size, 0);
    let n = unsafe { get_session_user_info(buff.as_mut_ptr(), buff_size as _, session_id) };
    if n == 0 {
        return "".to_owned();
    }
    let sl = unsafe { std::slice::from_raw_parts(buff.as_ptr(), n as _) };
    String::from_utf16(sl)
        .unwrap_or("".to_owned())
        .trim_end_matches('\0')
        .to_owned()
}

pub fn get_available_sessions(name: bool) -> Vec<WindowsSession> {
    extern "C" {
        fn get_available_session_ids(buf: *mut wchar_t, buf_size: c_int, include_rdp: bool);
    }
    const BUF_SIZE: c_int = 1024;
    let mut buf: Vec<wchar_t> = vec![0; BUF_SIZE as usize];

    let station_session_id_array = unsafe {
        get_available_session_ids(buf.as_mut_ptr(), BUF_SIZE, true);
        let session_ids = String::from_utf16_lossy(&buf);
        session_ids.trim_matches(char::from(0)).trim().to_string()
    };
    let mut v: Vec<WindowsSession> = vec![];
    // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-wtsgetactiveconsolesessionid
    let physical_console_sid = unsafe { get_current_session(FALSE) };
    if physical_console_sid != u32::MAX {
        let physical_console_name = if name {
            let physical_console_username = get_session_username(physical_console_sid);
            if physical_console_username.is_empty() {
                "Console".to_owned()
            } else {
                format!("Console: {physical_console_username}")
            }
        } else {
            "".to_owned()
        };
        v.push(WindowsSession {
            sid: physical_console_sid,
            name: physical_console_name,
            ..Default::default()
        });
    }
    // https://learn.microsoft.com/en-us/previous-versions//cc722458(v=technet.10)?redirectedfrom=MSDN
    for type_session_id in station_session_id_array.split(",") {
        let split: Vec<_> = type_session_id.split(":").collect();
        if split.len() == 2 {
            if let Ok(sid) = split[1].parse::<u32>() {
                if !v.iter().any(|e| (*e).sid == sid) {
                    let name = if name {
                        let name = get_session_username(sid);
                        if name.is_empty() {
                            split[0].to_string()
                        } else {
                            format!("{}: {}", split[0], name)
                        }
                    } else {
                        "".to_owned()
                    };
                    v.push(WindowsSession {
                        sid,
                        name,
                        ..Default::default()
                    });
                }
            }
        }
    }
    if name {
        let mut name_count: HashMap<String, usize> = HashMap::new();
        for session in &v {
            *name_count.entry(session.name.clone()).or_insert(0) += 1;
        }
        let current_sid = get_current_process_session_id().unwrap_or_default();
        for e in v.iter_mut() {
            let running = e.sid == current_sid && current_sid != 0;
            if name_count.get(&e.name).map(|v| *v).unwrap_or_default() > 1 {
                e.name = format!("{} (sid = {})", e.name, e.sid);
            }
            if running {
                e.name = format!("{} (running)", e.name);
            }
        }
    }
    v
}

pub fn get_active_user_home() -> Option<PathBuf> {
    let username = get_active_username();
    if !username.is_empty() {
        if username.contains(['\\', '/', ':']) || username.bytes().any(|byte| byte < 0x20) {
            return None;
        }
        let home = user_profiles_dir().ok()?.join(username);
        if home.exists() {
            return Some(home);
        }
    }
    None
}

pub fn is_prelogin() -> bool {
    let Some(username) = get_current_session_username() else {
        return false;
    };
    username.is_empty() || username == "SYSTEM"
}

pub fn is_locked() -> bool {
    let Some(session_id) = get_current_process_session_id() else {
        return false;
    };
    unsafe { is_session_locked(session_id) == TRUE }
}

pub fn is_root() -> bool {
    // https://stackoverflow.com/questions/4023586/correct-way-to-find-out-if-a-service-is-running-as-the-system-user
    unsafe { is_local_system() == TRUE }
}

pub fn lock_workstation() -> ResultType<()> {
    extern "system" {
        pub fn LockWorkStation() -> BOOL;
    }
    unsafe {
        if LockWorkStation() == FALSE {
            let error = GetLastError();
            bail!("LockWorkStation failed with Windows error {error}");
        }
    }
    Ok(())
}

const UNINSTALL_REGISTRY_ROOT: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

fn package_uninstall_subkey(product: &str) -> String {
    format!("{UNINSTALL_REGISTRY_ROOT}\\{product}")
}

fn current_package_uninstall_subkey() -> String {
    package_uninstall_subkey(&crate::get_app_name())
}

fn current_package_registry_value(name: &str) -> ResultType<String> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm.open_subkey_with_flags(
        current_package_uninstall_subkey(),
        KEY_READ | KEY_WOW64_64KEY,
    )?;
    Ok(key.get_value(name)?)
}

fn installed_package_executable() -> ResultType<PathBuf> {
    let install_location = current_package_registry_value("InstallLocation")?;
    if install_location.trim().is_empty() {
        bail!("current Windows package has no install location");
    }
    let install_dir = fixed_service_install_path(&install_location)?;
    require_existing_directory_no_reparse(&install_dir, "current Windows package directory")?;
    let executable = install_dir.join(format!("{}.exe", crate::get_app_name()));
    require_existing_file_no_reparse(&executable, "current Windows package executable")?;
    Ok(executable)
}

fn path_from_cotaskmem_pwstr(path: windows::core::PWSTR, label: &str) -> ResultType<PathBuf> {
    let ptr = path.0;
    if ptr.is_null() {
        bail!("{label} returned a null path");
    }
    let mut len = 0usize;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let value = OsString::from_wide(std::slice::from_raw_parts(ptr, len));
        CoTaskMemFree(Some(ptr as _));
        Ok(PathBuf::from(value))
    }
}

fn known_folder_path(folder: &GUID, label: &'static str) -> ResultType<PathBuf> {
    let path = unsafe { SHGetKnownFolderPath(folder, KF_FLAG_DEFAULT, None) }
        .map_err(|e| anyhow!("{label} failed: {e}"))?;
    path_from_cotaskmem_pwstr(path, label)
}

fn program_files_dir() -> ResultType<PathBuf> {
    let folder = if cfg!(target_pointer_width = "32") {
        &FOLDERID_ProgramFilesX86
    } else {
        &FOLDERID_ProgramFiles
    };
    let path = unsafe { SHGetKnownFolderPath(folder, KF_FLAG_DEFAULT, None) }
        .map_err(|e| anyhow!("SHGetKnownFolderPath(Program Files) failed: {e}"))?;
    path_from_cotaskmem_pwstr(path, "SHGetKnownFolderPath(Program Files)")
}

pub(crate) fn program_data_dir() -> ResultType<PathBuf> {
    known_folder_path(&FOLDERID_ProgramData, "SHGetKnownFolderPath(ProgramData)")
}

fn user_profiles_dir() -> ResultType<PathBuf> {
    known_folder_path(&FOLDERID_UserProfiles, "SHGetKnownFolderPath(UserProfiles)")
}

fn windows_dir() -> ResultType<PathBuf> {
    known_folder_path(&FOLDERID_Windows, "SHGetKnownFolderPath(Windows)")
}

fn default_install_path_buf() -> ResultType<PathBuf> {
    Ok(program_files_dir()?.join(crate::get_app_name()))
}

fn normalized_windows_path_text(path: &Path) -> String {
    path.to_string_lossy()
        .trim_end_matches(['\\', '/'])
        .to_ascii_lowercase()
}

pub(crate) fn fixed_service_install_path(requested_path: &str) -> ResultType<PathBuf> {
    let default = default_install_path_buf()?;
    if requested_path.trim().is_empty() {
        return Ok(default);
    }
    let requested = PathBuf::from(requested_path.trim().trim_end_matches(['\\', '/']));
    if normalized_windows_path_text(&requested) == normalized_windows_path_text(&default) {
        return Ok(default);
    }
    bail!("custom Windows install paths are not supported for the installed service")
}

fn trusted_system_dir() -> ResultType<PathBuf> {
    let mut buffer = vec![0u16; 32768];
    let len = unsafe { GetSystemDirectoryW(Some(&mut buffer)) } as usize;
    if len == 0 {
        bail!("GetSystemDirectoryW failed: {}", io::Error::last_os_error());
    }
    if len >= buffer.len() {
        bail!("GetSystemDirectoryW returned an oversized path");
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..len])))
}

pub(crate) fn trusted_system_tool_path(tool: &str) -> ResultType<PathBuf> {
    if tool.contains('\\') || tool.contains('/') || tool.contains('"') || tool.trim() != tool {
        bail!("invalid trusted system tool name: {tool}");
    }
    let path = trusted_system_dir()?.join(tool);
    require_existing_file_no_reparse(&path, "trusted Windows system tool")?;
    Ok(path)
}

pub fn check_update_broker_process() -> ResultType<PathBuf> {
    let _update_guard = BROKER_UPDATE_MUTEX.lock().unwrap();
    let installed_exe = require_current_exe_is_fixed_service_runtime()?;
    let install_dir = installed_exe
        .parent()
        .ok_or_else(|| anyhow!("fixed Windows service executable has no parent directory"))?;
    let source = trusted_system_tool_path("RuntimeBroker.exe")?;
    let destination = install_dir.join(win_topmost_window::INJECTED_PROCESS_EXE);

    if destination.exists() {
        require_existing_file_no_reparse(&destination, "installed privacy broker")?;
        if sha256_file(&source)? == sha256_file(&destination)? {
            return Ok(destination);
        }
    }

    let pending = install_dir.join(format!(
        ".{}.{}.pending",
        win_topmost_window::INJECTED_PROCESS_EXE,
        BROKER_UPDATE_NONCE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut input = fs::File::open(&source)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .attributes(FILE_ATTRIBUTE_TEMPORARY)
        .open(&pending)?;
    let copy_result = io::copy(&mut input, &mut output).and_then(|_| output.sync_all());
    drop(output);
    if let Err(err) = copy_result {
        let _ = fs::remove_file(&pending);
        return Err(err.into());
    }
    if sha256_file(&source)? != sha256_file(&pending)? {
        let _ = fs::remove_file(&pending);
        bail!("pending privacy broker does not match the trusted Windows image");
    }

    if destination.exists() {
        require_existing_file_no_reparse(&destination, "installed privacy broker")?;
        let destination_wide = null_terminated_wide(destination.as_os_str(), "broker destination")?;
        let pending_wide = null_terminated_wide(pending.as_os_str(), "pending broker")?;
        let replace_result = unsafe {
            WinReplaceFileW(
                PCWSTR(destination_wide.as_ptr()),
                PCWSTR(pending_wide.as_ptr()),
                PCWSTR::null(),
                WIN_REPLACEFILE_WRITE_THROUGH,
                None,
                None,
            )
        };
        if let Err(err) = replace_result {
            let _ = fs::remove_file(&pending);
            return Err(err.into());
        }
    } else if let Err(err) = fs::rename(&pending, &destination) {
        let _ = fs::remove_file(&pending);
        return Err(err.into());
    }
    require_existing_file_no_reparse(&destination, "installed privacy broker")?;
    if sha256_file(&source)? != sha256_file(&destination)? {
        bail!("installed privacy broker does not match the trusted Windows image");
    }
    Ok(destination)
}

fn sha256_file(path: &Path) -> ResultType<[u8; 32]> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

pub fn toggle_blank_screen(v: bool) {
    let v = if v { TRUE } else { FALSE };
    unsafe {
        blank_screen(v);
    }
}

pub fn block_input(v: bool) -> (bool, String) {
    let v = if v { TRUE } else { FALSE };
    unsafe {
        if BlockInput(v) == TRUE {
            (true, "".to_owned())
        } else {
            (false, format!("Error: {}", io::Error::last_os_error()))
        }
    }
}

pub fn send_input_scan_click(scan: u32) -> ResultType<()> {
    let mut flags = KEYEVENTF_SCANCODE;
    if scan >> 8 == 0xE0 || scan >> 8 == 0xE1 {
        flags |= KEYEVENTF_EXTENDEDKEY;
    }
    let make_input = |event_flags| {
        let mut input_union = INPUT_u::default();
        unsafe {
            *input_union.ki_mut() = KEYBDINPUT {
                wVk: 0,
                wScan: scan as u16,
                dwFlags: event_flags,
                time: 0,
                dwExtraInfo: enigo::ENIGO_INPUT_EXTRA_VALUE,
            };
        }
        INPUT {
            type_: INPUT_KEYBOARD,
            u: input_union,
        }
    };
    let mut inputs = [make_input(flags), make_input(flags | KEYEVENTF_KEYUP)];
    let inserted = unsafe {
        SendInput(
            inputs.len() as UINT,
            inputs.as_mut_ptr(),
            mem::size_of::<INPUT>() as c_int,
        )
    };
    match inserted {
        2 => Ok(()),
        0 => {
            let error = unsafe { GetLastError() };
            bail!(
                "SendInput inserted no semantic key events (error {error}; UIPI may not report details)"
            )
        }
        partial => {
            log::error!(
                "SendInput inserted {partial} of 2 semantic key events; key state is unknown"
            );
            std::process::abort();
        }
    }
}

pub fn send_input_unicode_text(text: &str) -> ResultType<()> {
    let mut inputs = Vec::with_capacity(text.encode_utf16().count().saturating_mul(2));
    for code_unit in text.encode_utf16() {
        for flags in [KEYEVENTF_UNICODE, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP] {
            let mut input_union = INPUT_u::default();
            unsafe {
                *input_union.ki_mut() = KEYBDINPUT {
                    wVk: 0,
                    wScan: code_unit,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: enigo::ENIGO_INPUT_EXTRA_VALUE,
                };
            }
            inputs.push(INPUT {
                type_: INPUT_KEYBOARD,
                u: input_union,
            });
        }
    }
    if inputs.is_empty() {
        return Ok(());
    }
    let requested = inputs.len() as UINT;
    let inserted = unsafe {
        SendInput(
            requested,
            inputs.as_mut_ptr(),
            mem::size_of::<INPUT>() as c_int,
        )
    };
    if inserted == requested {
        return Ok(());
    }
    if inserted == 0 {
        let error = unsafe { GetLastError() };
        bail!(
            "SendInput inserted no Unicode key events (error {error}; UIPI may not report details)"
        );
    }
    log::error!(
        "SendInput inserted {inserted} of {requested} Unicode key events; semantic state is partial"
    );
    std::process::abort();
}

pub fn add_recent_document(path: &str) {
    extern "C" {
        fn AddRecentDocument(path: *const u16);
    }
    use std::os::windows::ffi::OsStrExt;
    let wstr: Vec<u16> = std::ffi::OsStr::new(path)
        .encode_wide()
        .chain(Some(0).into_iter())
        .collect();
    let wstr = wstr.as_ptr();
    unsafe {
        AddRecentDocument(wstr);
    }
}

pub fn is_installed() -> bool {
    installed_package_executable().is_ok()
}

pub fn installed_build_date() -> String {
    current_package_registry_value("BuildDate").unwrap_or_default()
}

// R-X4: get_license_from_exe_name (the custom-rendezvous-server-from-exe-name parser) removed.

#[inline]
pub fn is_win_server() -> bool {
    unsafe { is_windows_server() > 0 }
}

#[inline]
pub fn is_win_10_or_greater() -> bool {
    unsafe { is_windows_10_or_greater() > 0 }
}

pub fn bootstrap() -> bool {
    if crate::common::is_service_owned_server_process() {
        let root = program_data_dir().and_then(|program_data| {
            Config::initialize_windows_service_owned_root(&program_data, false)
        });
        if let Err(err) = root {
            eprintln!("Failed to initialize Windows service-owned config root: {err}");
            return false;
        }
    }
    // R-X4: exe-name license EXE_RENDEZVOUS_SERVER injection removed (direct-IP only).

    #[cfg(debug_assertions)]
    {
        true
    }
    #[cfg(not(debug_assertions))]
    {
        // This function will cause `'sciter.dll' was not found neither in PATH nor near the current executable.` when debugging RustDesk.
        // Only call set_safe_load_dll() on Windows 10 or greater
        if is_win_10_or_greater() {
            set_safe_load_dll()
        } else {
            true
        }
    }
}

#[cfg(not(debug_assertions))]
fn set_safe_load_dll() -> bool {
    if !unsafe { set_default_dll_directories() } {
        return false;
    }

    // `SetDllDirectoryW` should never fail.
    // https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setdlldirectoryw
    if unsafe { SetDllDirectoryW(wide_string("").as_ptr()) == FALSE } {
        eprintln!("SetDllDirectoryW failed: {}", io::Error::last_os_error());
        return false;
    }

    true
}

// https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-setdefaultdlldirectories
#[cfg(not(debug_assertions))]
unsafe fn set_default_dll_directories() -> bool {
    let module = LoadLibraryExW(
        wide_string("Kernel32.dll").as_ptr(),
        0 as _,
        LOAD_LIBRARY_SEARCH_SYSTEM32,
    );
    if module.is_null() {
        return false;
    }

    match CString::new("SetDefaultDllDirectories") {
        Err(e) => {
            eprintln!("CString::new failed: {}", e);
            return false;
        }
        Ok(func_name) => {
            let func = GetProcAddress(module, func_name.as_ptr());
            if func.is_null() {
                eprintln!("GetProcAddress failed: {}", io::Error::last_os_error());
                return false;
            }
            type SetDefaultDllDirectories = unsafe extern "system" fn(DWORD) -> BOOL;
            let func: SetDefaultDllDirectories = std::mem::transmute(func);
            if func(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS) == FALSE {
                eprintln!(
                    "SetDefaultDllDirectories failed: {}",
                    io::Error::last_os_error()
                );
                return false;
            }
        }
    }
    true
}

fn get_custom_icon(install_dir: &str, exe: &str) -> Option<String> {
    const RELATIVE_ICON_PATH: &str = "data\\flutter_assets\\assets\\icon.ico";
    if crate::is_custom_client() {
        if let Some(p) = PathBuf::from(exe).parent() {
            let alter_icon_path = p.join(RELATIVE_ICON_PATH);
            if alter_icon_path.exists() {
                // During installation, files under `install_dir` may not exist yet.
                // So we validate the icon from the current executable directory first.
                // But for shortcut/registry icon location, we should point to the final
                // installed path so the icon works across different Windows users.
                if let Ok(metadata) = std::fs::symlink_metadata(&alter_icon_path) {
                    if metadata.is_symlink() {
                        log::warn!(
                            "Custom icon at {:?} is a symlink, refusing to use it.",
                            alter_icon_path
                        );
                        return None;
                    }
                    if metadata.is_file() {
                        return if install_dir.is_empty() {
                            Some(alter_icon_path.to_string_lossy().to_string())
                        } else {
                            Some(format!("{}\\{}", install_dir, RELATIVE_ICON_PATH))
                        };
                    }
                }
            }
        }
    }
    None
}

struct ComApartment {
    uninitialize: bool,
}

impl ComApartment {
    fn init() -> ResultType<Self> {
        let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        if hr.is_ok() {
            return Ok(Self { uninitialize: true });
        }
        if hr == RPC_E_CHANGED_MODE {
            return Ok(Self {
                uninitialize: false,
            });
        }
        Err(anyhow!("CoInitializeEx failed: {}", hr.message()))
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.uninitialize {
            unsafe {
                CoUninitialize();
            }
        }
    }
}

fn user_desktop_dir() -> ResultType<PathBuf> {
    known_folder_path(&FOLDERID_Desktop, "SHGetKnownFolderPath(Desktop)")
}

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn wide_str(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn validate_shortcut_connect_id(id: &str) -> ResultType<()> {
    if id.is_empty() {
        bail!("Shortcut connection id is empty");
    }
    if id.len() > 512 {
        bail!("Shortcut connection id is too long");
    }
    for byte in id.bytes() {
        if !byte.is_ascii()
            || byte.is_ascii_control()
            || byte.is_ascii_whitespace()
            || matches!(
                byte,
                b'"' | b'\'' | b'`' | b'<' | b'>' | b'|' | b'&' | b';' | b'/' | b'\\' | b'?' | b'*'
            )
        {
            bail!("Shortcut connection id contains unsupported characters");
        }
    }
    Ok(())
}

fn shortcut_filename_from_id(id: &str) -> ResultType<String> {
    validate_shortcut_connect_id(id)?;
    let mut filename = id
        .chars()
        .map(|ch| match ch {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            ch if ch.is_control() => '_',
            ch => ch,
        })
        .collect::<String>();
    while filename.ends_with(' ') || filename.ends_with('.') {
        filename.pop();
    }
    if filename.is_empty() {
        bail!("Shortcut filename is empty");
    }
    Ok(filename)
}

pub fn create_shortcut(id: &str) -> ResultType<()> {
    validate_shortcut_connect_id(id)?;
    let exe = std::env::current_exe()?;
    if !exe.is_file() {
        bail!("Current executable is not a file: {}", exe.display());
    }
    let shortcut = user_desktop_dir()?.join(format!("{}.lnk", shortcut_filename_from_id(id)?));
    let _com = ComApartment::init()?;
    let shell_link: IShellLinkW =
        unsafe { CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER) }
            .map_err(|err| anyhow!("CoCreateInstance(ShellLink) failed: {err}"))?;

    let exe_w = wide_path(&exe);
    let args = wide_str(&format!("--connect {id}"));
    unsafe {
        shell_link
            .SetPath(PCWSTR(exe_w.as_ptr()))
            .map_err(|err| anyhow!("IShellLinkW::SetPath failed: {err}"))?;
        shell_link
            .SetArguments(PCWSTR(args.as_ptr()))
            .map_err(|err| anyhow!("IShellLinkW::SetArguments failed: {err}"))?;
        if let Some(parent) = exe.parent() {
            let working_dir = wide_path(parent);
            shell_link
                .SetWorkingDirectory(PCWSTR(working_dir.as_ptr()))
                .map_err(|err| anyhow!("IShellLinkW::SetWorkingDirectory failed: {err}"))?;
        }
        let exe_str = exe.to_string_lossy();
        if let Some(icon) = get_custom_icon("", exe_str.as_ref()) {
            let icon_w = wide_str(&icon);
            shell_link
                .SetIconLocation(PCWSTR(icon_w.as_ptr()), 0)
                .map_err(|err| anyhow!("IShellLinkW::SetIconLocation failed: {err}"))?;
        }
        let persist: IPersistFile = shell_link
            .cast()
            .map_err(|err| anyhow!("IShellLinkW::IPersistFile cast failed: {err}"))?;
        let shortcut_w = wide_path(&shortcut);
        persist
            .Save(PCWSTR(shortcut_w.as_ptr()), true)
            .map_err(|err| anyhow!("IPersistFile::Save failed: {err}"))?;
    }
    Ok(())
}

pub fn quit_gui() {
    std::process::exit(0);
    // unsafe { PostQuitMessage(0) }; // some how not work
}

pub fn get_user_token(session_id: u32, as_user: bool) -> HANDLE {
    let mut token = NULL as HANDLE;
    unsafe {
        let mut _token_pid = 0;
        if FALSE
            == GetSessionUserTokenWin(
                &mut token as _,
                session_id,
                if as_user { TRUE } else { FALSE },
                &mut _token_pid,
            )
        {
            NULL as _
        } else {
            token
        }
    }
}

// R-X9 (slices 2-4): `run_uac` (ShellExecuteW "runas" self-relaunch), `elevate`,
// `run_as_system` (impersonate_system token-theft to SYSTEM), and
// `elevate_or_run_as_system` (the --elevate/--run-as-system/--quick_support /
// --portable-service run-mode dispatch that started the portable SYSTEM helper) are
// excised. On the installed-service fork the sole controlled entry is the installed
// LocalSystem service (`--service` -> CreateProcessAsUserW -> `--server` -> `--tray`);
// there is no interactive UAC elevation and no
// peer-OS-credential / token-theft escalation. `check_super_user_permission` (still used
// by the R-X11 UI via ui_interface / flutter_ffi::main_check_super_user_permission) is
// converted to a PASSIVE elevation check: it reports whether this process is already
// elevated, and never relaunches anything via UAC.
pub fn check_super_user_permission() -> ResultType<bool> {
    is_elevated(None)
}

pub fn is_elevated(process_id: Option<DWORD>) -> ResultType<bool> {
    use hbb_common::platform::windows::RAIIHandle;
    unsafe {
        let handle: HANDLE = match process_id {
            Some(process_id) => OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id),
            None => GetCurrentProcess(),
        };
        if handle == NULL {
            bail!(
                "Failed to open process, error {}",
                io::Error::last_os_error()
            )
        }
        let _handle = process_id.map(|_| RAIIHandle(handle));
        let mut token: HANDLE = mem::zeroed();
        if OpenProcessToken(handle, TOKEN_QUERY, &mut token) == FALSE {
            bail!(
                "Failed to open process token, error {}",
                io::Error::last_os_error()
            )
        }
        let _token = RAIIHandle(token);
        let mut token_elevation: TOKEN_ELEVATION = mem::zeroed();
        let mut size: DWORD = 0;
        if GetTokenInformation(
            token,
            TokenElevation,
            (&mut token_elevation) as *mut _ as *mut c_void,
            mem::size_of::<TOKEN_ELEVATION>() as _,
            &mut size,
        ) == FALSE
        {
            bail!(
                "Failed to get token information, error {}",
                io::Error::last_os_error()
            )
        }

        Ok(token_elevation.TokenIsElevated != 0)
    }
}

#[inline]
unsafe fn read_token_user_buffer(token: WinHANDLE, subject: &str) -> ResultType<Vec<u8>> {
    let mut token_user_size = 0u32;
    let get_info_result = WinGetTokenInformation(token, TokenUser, None, 0, &mut token_user_size);
    match get_info_result {
        Ok(()) => {
            if token_user_size == 0 {
                bail!(
                    "Failed to get {} token user size: unexpected zero buffer size",
                    subject
                );
            }
        }
        Err(e) => {
            // Allow expected size-probe failures if Windows still returns required size.
            let is_insufficient_buffer =
                e.code() == windows::core::HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER as u32);
            let is_bad_length =
                e.code() == windows::core::HRESULT::from_win32(ERROR_BAD_LENGTH as u32);
            if (!is_insufficient_buffer && !is_bad_length) || token_user_size == 0 {
                bail!("Failed to get {} token user size: {}", subject, e);
            }
        }
    }

    let mut buffer = vec![0u8; token_user_size as usize];
    WinGetTokenInformation(
        token,
        TokenUser,
        Some(buffer.as_mut_ptr() as *mut core::ffi::c_void),
        token_user_size,
        &mut token_user_size,
    )
    .map_err(|e| anyhow!("Failed to get {} token user: {}", subject, e))?;

    let min_size = std::mem::size_of::<TOKEN_USER>();
    if buffer.len() < min_size {
        bail!(
            "Failed to parse {} token user: buffer too small (got {}, need >= {})",
            subject,
            buffer.len(),
            min_size
        );
    }
    Ok(buffer)
}

/// Similar to `is_root()` / `is_local_system()` but for an arbitrary process.
///
/// Returns `true` if the target process is running as LocalSystem (SID: S-1-5-18).
///
/// TODO: After a few releases of real-world validation, consider replacing
/// the legacy `is_local_system()` with this implementation.
pub fn is_process_running_as_system(process_id: DWORD) -> ResultType<bool> {
    unsafe {
        let process = WinOpenProcess(WIN_PROCESS_QUERY_LIMITED_INFORMATION, false, process_id)
            .map_err(|e| anyhow!("Failed to open process {}: {}", process_id, e))?;

        let mut token = WinHANDLE::default();
        let result = (|| -> ResultType<bool> {
            WinOpenProcessToken(process, WIN_TOKEN_QUERY, &mut token)
                .map_err(|e| anyhow!("Failed to open process {} token: {}", process_id, e))?;

            let token_subject = format!("process {}", process_id);
            let buffer = read_token_user_buffer(token, token_subject.as_str())?;
            let token_user: TOKEN_USER =
                std::ptr::read_unaligned(buffer.as_ptr() as *const TOKEN_USER);
            Ok(IsWellKnownSid(token_user.User.Sid, WinLocalSystemSid).as_bool())
        })();

        if !token.is_invalid() {
            let _ = WinCloseHandle(token);
        }
        let _ = WinCloseHandle(process);
        result
    }
}

fn open_process_executable_path(process_id: DWORD) -> ResultType<(WinHandleGuard, PathBuf)> {
    const PROCESS_IMAGE_PATH_BUFFER_LEN: usize = 32 * 1024;
    unsafe {
        let process = WinHandleGuard::new(
            WinOpenProcess(WIN_PROCESS_QUERY_LIMITED_INFORMATION, false, process_id)
                .map_err(|e| anyhow!("Failed to open process {}: {}", process_id, e))?,
        )?;
        let mut buffer = vec![0u16; PROCESS_IMAGE_PATH_BUFFER_LEN];
        let mut length = PROCESS_IMAGE_PATH_BUFFER_LEN as u32;
        WinQueryFullProcessImageNameW(
            process.get(),
            windows::Win32::System::Threading::PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(buffer.as_mut_ptr()),
            &mut length,
        )
        .map_err(|e| anyhow!("Failed to query process {} image path: {}", process_id, e))?;
        if length == 0 {
            bail!(
                "Failed to query process {} image path: empty result",
                process_id
            );
        }
        buffer.truncate(length as usize);
        Ok((process, PathBuf::from(OsString::from_wide(&buffer))))
    }
}

pub fn get_process_executable_path(process_id: DWORD) -> ResultType<PathBuf> {
    let (_process, path) = open_process_executable_path(process_id)?;
    Ok(path)
}

pub fn is_foreground_window_elevated() -> ResultType<bool> {
    unsafe {
        let mut process_id: DWORD = 0;
        GetWindowThreadProcessId(GetForegroundWindow(), &mut process_id);
        if process_id == 0 {
            bail!(
                "Failed to get processId, error {}",
                io::Error::last_os_error()
            )
        }
        is_elevated(Some(process_id))
    }
}

fn get_current_pid() -> u32 {
    unsafe { GetCurrentProcessId() }
}

pub fn get_double_click_time() -> u32 {
    unsafe { GetDoubleClickTime() }
}

pub fn wide_string(s: &str) -> Vec<u16> {
    use std::os::windows::prelude::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(Some(0).into_iter())
        .collect()
}

// R-X8: get_logon_user_token (LogonUserW — the terminal OS second-credential logon) removed.

// R-X8: is_user_token_admin removed with handle_administrator_check (its only caller).

// R-X9: create_process_with_logon (CreateProcessWithLogonW — peer-OS-credential elevation)
// removed. Slices 2-4 also remove the remaining interactive UAC elevation
// (run_uac/elevate) and the run_as_system token-theft; no elevation self-relaunch remains.

#[inline]
fn str_to_device_name(name: &str) -> [u16; 32] {
    let mut device_name: Vec<u16> = wide_string(name);
    if device_name.len() < 32 {
        device_name.resize(32, 0);
    }
    let mut result = [0; 32];
    result.copy_from_slice(&device_name[..32]);
    result
}

pub fn resolutions(name: &str) -> Vec<Resolution> {
    unsafe {
        let mut dm: DEVMODEW = std::mem::zeroed();
        let mut v = vec![];
        let mut num = 0;
        let device_name = str_to_device_name(name);
        loop {
            if EnumDisplaySettingsW(device_name.as_ptr(), num, &mut dm) == 0 {
                break;
            }
            let r = Resolution {
                width: dm.dmPelsWidth as _,
                height: dm.dmPelsHeight as _,
                ..Default::default()
            };
            if !v.contains(&r) {
                v.push(r);
            }
            num += 1;
        }
        v
    }
}

pub fn current_resolution(name: &str) -> ResultType<Resolution> {
    let device_name = str_to_device_name(name);
    unsafe {
        let mut dm: DEVMODEW = std::mem::zeroed();
        dm.dmSize = std::mem::size_of::<DEVMODEW>() as _;
        if EnumDisplaySettingsW(device_name.as_ptr(), ENUM_CURRENT_SETTINGS, &mut dm) == 0 {
            bail!(
                "failed to get current resolution, error {}",
                io::Error::last_os_error()
            );
        }
        let r = Resolution {
            width: dm.dmPelsWidth as _,
            height: dm.dmPelsHeight as _,
            ..Default::default()
        };
        Ok(r)
    }
}

pub(super) fn change_resolution_directly(
    name: &str,
    width: usize,
    height: usize,
) -> ResultType<()> {
    let device_name = str_to_device_name(name);
    unsafe {
        let mut dm: DEVMODEW = std::mem::zeroed();
        dm.dmSize = std::mem::size_of::<DEVMODEW>() as _;
        dm.dmPelsWidth = width as _;
        dm.dmPelsHeight = height as _;
        dm.dmFields = DM_PELSHEIGHT | DM_PELSWIDTH;
        let res = ChangeDisplaySettingsExW(
            device_name.as_ptr(),
            &mut dm,
            NULL as _,
            CDS_UPDATEREGISTRY | CDS_GLOBAL | CDS_RESET,
            NULL,
        );
        if res != DISP_CHANGE_SUCCESSFUL {
            bail!(
                "ChangeDisplaySettingsExW failed, res={}, error {}",
                res,
                io::Error::last_os_error()
            );
        }
        Ok(())
    }
}

pub fn user_accessible_folder() -> ResultType<PathBuf> {
    if let Ok(program_data) = program_data_dir() {
        if program_data.exists() {
            return Ok(program_data);
        }
    }

    // NOTICE: "C:\Windows\Temp" requires permanent authorization.
    let windows_temp = windows_dir()?.join("Temp");
    if windows_temp.exists() {
        return Ok(windows_temp);
    }

    bail!("no valid user accessible folder")
}

#[inline]
pub fn get_char_from_vk(vk: u32) -> Option<char> {
    get_char_from_unicode(get_unicode_from_vk(vk)?)
}

pub fn get_char_from_unicode(unicode: u16) -> Option<char> {
    let buff = [unicode];
    if let Some(chr) = String::from_utf16(&buff[..1]).ok()?.chars().next() {
        if chr.is_control() {
            return None;
        } else {
            Some(chr)
        }
    } else {
        None
    }
}

pub fn get_unicode_from_vk(vk: u32) -> Option<u16> {
    const BUF_LEN: i32 = 32;
    let mut buff = [0_u16; BUF_LEN as usize];
    let buff_ptr = buff.as_mut_ptr();
    let len = unsafe {
        let current_window_thread_id = GetWindowThreadProcessId(GetForegroundWindow(), null_mut());
        let layout = GetKeyboardLayout(current_window_thread_id);

        // refs: https://github.com/rustdesk-org/rdev/blob/25a99ce71ab42843ad253dd51e6a35e83e87a8a4/src/windows/keyboard.rs#L115
        let press_state = 129;
        let mut state: [BYTE; 256] = [0; 256];
        let shift_left = rdev::get_modifier(rdev::Key::ShiftLeft);
        let shift_right = rdev::get_modifier(rdev::Key::ShiftRight);
        if shift_left {
            state[VK_LSHIFT as usize] = press_state;
        }
        if shift_right {
            state[VK_RSHIFT as usize] = press_state;
        }
        if shift_left || shift_right {
            state[VK_SHIFT as usize] = press_state;
        }
        ToUnicodeEx(vk, 0x00, &state as _, buff_ptr, BUF_LEN, 0, layout)
    };
    if len == 1 {
        Some(buff[0])
    } else {
        None
    }
}

struct WinHandleGuard(WinHANDLE);

impl WinHandleGuard {
    #[inline]
    fn new(handle: WinHANDLE) -> ResultType<Self> {
        if handle.is_invalid() {
            bail!("invalid Windows handle");
        }
        Ok(Self(handle))
    }

    #[inline]
    fn get(&self) -> WinHANDLE {
        self.0
    }
}

impl Drop for WinHandleGuard {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_invalid() {
                let _ = WinCloseHandle(self.0);
            }
        }
    }
}

fn process_entry_image_name(entry: &PROCESSENTRY32W) -> String {
    let len = entry
        .szExeFile
        .iter()
        .position(|c| *c == 0)
        .unwrap_or(entry.szExeFile.len());
    OsString::from_wide(&entry.szExeFile[..len])
        .to_string_lossy()
        .into_owned()
}

const WINDOWS_CONSENT_IMAGE_NAME: &str = "consent.exe";

fn trusted_system_process_candidate_matches(
    expected_path: &Path,
    expected_session_id: u32,
    candidate_path: &Path,
    candidate_session_id: u32,
) -> bool {
    candidate_session_id == expected_session_id
        && normalized_windows_path_text(candidate_path)
            == normalized_windows_path_text(expected_path)
}

pub fn is_process_consent_running() -> ResultType<bool> {
    let expected_session_id = get_current_process_session_id()
        .ok_or_else(|| anyhow!("Failed to resolve current session for UAC consent detection"))?;
    let expected_path = trusted_system_tool_path(WINDOWS_CONSENT_IMAGE_NAME)?;
    unsafe {
        let snapshot = WinHandleGuard::new(
            CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                .map_err(|e| anyhow!("Failed to create process snapshot: {}", e))?,
        )?;

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        Process32FirstW(snapshot.get(), &mut entry)
            .map_err(|e| anyhow!("Failed to read first process snapshot entry: {}", e))?;
        loop {
            if process_entry_image_name(&entry)
                .eq_ignore_ascii_case(WINDOWS_CONSENT_IMAGE_NAME)
            {
                let process_id = entry.th32ProcessID;
                match get_session_id_of_process(process_id) {
                    Some(candidate_session_id) if candidate_session_id == expected_session_id => {
                        let (process, candidate_path) = open_process_executable_path(process_id)
                            .map_err(|e| {
                                anyhow!(
                                    "Failed to authenticate current-session UAC consent candidate {}: {}",
                                    process_id,
                                    e
                                )
                            })?;
                        let pinned_session_id = get_session_id_of_process(process_id).ok_or_else(|| {
                            anyhow!(
                                "Failed to revalidate current-session UAC consent candidate {} while its process handle is retained",
                                process_id
                            )
                        })?;
                        let is_trusted_candidate = trusted_system_process_candidate_matches(
                            &expected_path,
                            expected_session_id,
                            &candidate_path,
                            pinned_session_id,
                        );
                        drop(process);
                        if is_trusted_candidate {
                            return Ok(true);
                        }
                        log::debug!(
                            "Ignoring current-session consent.exe candidate {} with untrusted image {}",
                            process_id,
                            candidate_path.display()
                        );
                    }
                    Some(_) => {}
                    None => log::debug!(
                        "Ignoring consent.exe candidate {} whose session cannot be authenticated",
                        process_id
                    ),
                }
            }
            if let Err(error) = Process32NextW(snapshot.get(), &mut entry) {
                if error.code()
                    != windows::core::HRESULT::from_win32(ERROR_NO_MORE_FILES.0)
                {
                    bail!("Failed to advance process snapshot: {}", error);
                }
                break;
            }
        }
    }
    Ok(false)
}

pub struct WakeLock(u32);
// Failed to compile keepawake-rs on i686
impl WakeLock {
    pub fn new(display: bool, idle: bool, sleep: bool) -> Self {
        let mut flag = ES_CONTINUOUS;
        if display {
            flag |= ES_DISPLAY_REQUIRED;
        }
        if idle {
            flag |= ES_SYSTEM_REQUIRED;
        }
        if sleep {
            flag |= ES_AWAYMODE_REQUIRED;
        }
        unsafe { SetThreadExecutionState(flag) };
        WakeLock(flag)
    }

    pub fn set_display(&mut self, display: bool) -> ResultType<()> {
        let flag = if display {
            self.0 | ES_DISPLAY_REQUIRED
        } else {
            self.0 & !ES_DISPLAY_REQUIRED
        };
        if flag != self.0 {
            unsafe { SetThreadExecutionState(flag) };
            self.0 = flag;
        }
        Ok(())
    }
}

impl Drop for WakeLock {
    fn drop(&mut self) {
        unsafe { SetThreadExecutionState(ES_CONTINUOUS) };
    }
}

pub fn alloc_console() {
    unsafe {
        alloc_console_and_redirect();
    }
}

// R-X4: get_license (the custom_server license from exe-name / registry) removed.

pub struct WallPaperRemover {
    old_path: String,
}

impl WallPaperRemover {
    pub fn new() -> ResultType<Self> {
        let start = std::time::Instant::now();
        if !Self::need_remove() {
            bail!("already solid color");
        }
        let old_path = match Self::get_recent_wallpaper() {
            Ok(old_path) => old_path,
            Err(e) => {
                log::info!("Failed to get recent wallpaper: {:?}, use fallback", e);
                wallpaper::get().map_err(|e| anyhow!(e.to_string()))?
            }
        };
        Self::set_wallpaper(None)?;
        log::info!(
            "created wallpaper remover,  old_path: {:?},  elapsed: {:?}",
            old_path,
            start.elapsed(),
        );
        Ok(Self { old_path })
    }

    pub fn support() -> bool {
        wallpaper::get().is_ok() || !Self::get_recent_wallpaper().unwrap_or_default().is_empty()
    }

    fn get_recent_wallpaper() -> ResultType<String> {
        // SystemParametersInfoW may return %appdata%\Microsoft\Windows\Themes\TranscodedWallpaper, not real path and may not real cache
        // https://www.makeuseof.com/find-desktop-wallpapers-file-location-windows-11/
        // https://superuser.com/questions/1218413/write-to-current-users-registry-through-a-different-admin-account
        let (hkcu, sid) = if is_root() {
            let sid = get_current_process_session_id().ok_or(anyhow!("failed to get sid"))?;
            (RegKey::predef(HKEY_USERS), format!("{}\\", sid))
        } else {
            (RegKey::predef(HKEY_CURRENT_USER), "".to_string())
        };
        let explorer_key = hkcu.open_subkey_with_flags(
            &format!(
                "{}Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Wallpapers",
                sid
            ),
            KEY_READ,
        )?;
        Ok(explorer_key.get_value("BackgroundHistoryPath0")?)
    }

    fn need_remove() -> bool {
        if let Ok(wallpaper) = wallpaper::get() {
            return !wallpaper.is_empty();
        }
        false
    }

    fn set_wallpaper(path: Option<String>) -> ResultType<()> {
        wallpaper::set_from_path(&path.unwrap_or_default()).map_err(|e| anyhow!(e.to_string()))
    }
}

impl Drop for WallPaperRemover {
    fn drop(&mut self) {
        // If the old background is a slideshow, it will be converted into an image. AnyDesk does the same.
        allow_err!(Self::set_wallpaper(Some(self.old_path.clone())));
    }
}

#[inline]
pub fn is_self_service_running() -> bool {
    is_service_running(&crate::get_app_name())
}

pub fn is_service_running(service_name: &str) -> bool {
    unsafe {
        let service_name = wide_string(service_name);
        is_service_running_w(service_name.as_ptr() as _)
    }
}

pub fn is_x64() -> bool {
    const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;

    let mut sys_info = SYSTEM_INFO::default();
    unsafe {
        GetNativeSystemInfo(&mut sys_info as _);
    }
    unsafe { sys_info.u.s().wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 }
}

pub fn try_set_window_foreground(window: HWND) {
    let env_key = SET_FOREGROUND_WINDOW;
    if let Ok(value) = std::env::var(env_key) {
        if value == "1" {
            unsafe {
                SetForegroundWindow(window);
            }
            std::env::remove_var(env_key);
        }
    }
}

pub(crate) mod reg_display_settings {
    use hbb_common::{bail, log, ResultType};
    use std::collections::HashMap;
    use std::io::ErrorKind;
    use winreg::{enums::*, RegValue};
    const REG_GRAPHICS_DRIVERS_PATH: &str = "SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers";
    const REG_CONNECTIVITY_PATH: &str = "Connectivity";
    const REG_RECENT_VALUE: &str = "Recent";
    const MAX_REGISTRY_SUBKEY_NAME_UTF16: usize = 255;
    type ConnectivitySnapshot = HashMap<String, RegValue>;

    #[derive(Debug)]
    pub(crate) struct RegRecovery {
        subkey: String,
        old_recent: RegValue,
    }

    fn connectivity_subkey_path(subkey: &str) -> ResultType<String> {
        if subkey.is_empty()
            || subkey.contains('\\')
            || subkey.chars().any(|value| value.is_control())
        {
            bail!("invalid display connectivity registry subkey");
        }
        if subkey.encode_utf16().count() > MAX_REGISTRY_SUBKEY_NAME_UTF16 {
            bail!("display connectivity registry subkey is too long");
        }
        Ok(format!(
            "{}\\{}\\{}",
            REG_GRAPHICS_DRIVERS_PATH, REG_CONNECTIVITY_PATH, subkey
        ))
    }

    pub(crate) fn read_reg_connectivity() -> ResultType<ConnectivitySnapshot> {
        let hklm = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
        let reg_connectivity = hklm.open_subkey_with_flags(
            format!("{}\\{}", REG_GRAPHICS_DRIVERS_PATH, REG_CONNECTIVITY_PATH),
            KEY_READ,
        )?;

        let mut map_connectivity = HashMap::new();
        for key in reg_connectivity.enum_keys() {
            let key = key?;
            connectivity_subkey_path(&key)?;
            let reg_item = reg_connectivity.open_subkey_with_flags(&key, KEY_READ)?;
            match reg_item.get_raw_value(REG_RECENT_VALUE) {
                Ok(value) => {
                    map_connectivity.insert(key, value);
                }
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
        }
        Ok(map_connectivity)
    }

    pub(crate) fn diff_recent_connectivity(
        map1: ConnectivitySnapshot,
        map2: ConnectivitySnapshot,
    ) -> ResultType<Vec<RegRecovery>> {
        let mut recoveries = Vec::new();
        for (subkey, value2) in map2 {
            if let Some(value1) = map1.get(&subkey) {
                connectivity_subkey_path(&subkey)?;
                if value1 != &value2 {
                    recoveries.push(RegRecovery {
                        subkey,
                        old_recent: RegValue {
                            bytes: value1.bytes.clone(),
                            vtype: value1.vtype.clone(),
                        },
                    });
                }
            }
        }
        Ok(recoveries)
    }

    fn restore_one_reg_connectivity(reg_recovery: &RegRecovery) -> ResultType<()> {
        let path = connectivity_subkey_path(&reg_recovery.subkey)?;
        let hklm = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
        let reg_item = hklm.open_subkey_with_flags(path, KEY_SET_VALUE)?;
        reg_item.set_raw_value(REG_RECENT_VALUE, &reg_recovery.old_recent)?;
        Ok(())
    }

    pub(crate) fn restore_reg_connectivity(recoveries: &[RegRecovery]) -> ResultType<()> {
        let mut failed = false;
        for recovery in recoveries {
            if let Err(err) = restore_one_reg_connectivity(recovery) {
                failed = true;
                log::error!(
                    "Failed to restore display connectivity subkey '{}': {}",
                    recovery.subkey,
                    err
                );
            }
        }
        if failed {
            bail!("one or more display connectivity values could not be restored");
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn recent_map(subkey: &str, bytes: &[u8]) -> ConnectivitySnapshot {
            HashMap::from([(
                subkey.to_owned(),
                RegValue {
                    bytes: bytes.to_vec(),
                    vtype: RegType::REG_BINARY,
                },
            )])
        }

        #[test]
        fn connectivity_recovery_contains_only_enumerated_subkey_and_snapshot() {
            let recoveries = diff_recent_connectivity(
                recent_map("fixed-child", b"before"),
                recent_map("fixed-child", b"after"),
            )
            .unwrap();

            assert_eq!(recoveries.len(), 1);
            let recovery = &recoveries[0];
            assert_eq!(recovery.subkey, "fixed-child");
            assert_eq!(recovery.old_recent.bytes, b"before");
            assert_eq!(recovery.old_recent.vtype, RegType::REG_BINARY);
            assert_eq!(
                connectivity_subkey_path(&recovery.subkey).unwrap(),
                "SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\Connectivity\\fixed-child"
            );
        }

        #[test]
        fn connectivity_recovery_rejects_invalid_subkeys() {
            for subkey in ["", "nested\\child", "line\nbreak"] {
                assert!(connectivity_subkey_path(subkey).is_err());
            }
            assert!(connectivity_subkey_path(&"x".repeat(256)).is_err());
        }

        #[test]
        fn connectivity_recovery_retains_every_changed_subkey() {
            let mut before = recent_map("first", b"first-before");
            before.extend(recent_map("second", b"second-before"));
            let mut after = recent_map("first", b"first-after");
            after.extend(recent_map("second", b"second-after"));

            let mut recoveries = diff_recent_connectivity(before, after).unwrap();
            recoveries.sort_by(|left, right| left.subkey.cmp(&right.subkey));

            assert_eq!(recoveries.len(), 2);
            assert_eq!(recoveries[0].subkey, "first");
            assert_eq!(recoveries[0].old_recent.bytes, b"first-before");
            assert_eq!(recoveries[1].subkey, "second");
            assert_eq!(recoveries[1].old_recent.bytes, b"second-before");
        }
    }
}

pub fn is_cur_exe_the_installed() -> bool {
    is_installed() && require_current_exe_is_fixed_service_runtime().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_uninstall_subkey_is_the_current_msi_namespace() {
        assert_eq!(
            package_uninstall_subkey("RustDesk"),
            "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\RustDesk"
        );
    }

    #[test]
    fn test_is_process_running_as_system_invalid_pid_errors() {
        assert!(is_process_running_as_system(u32::MAX).is_err());
    }

    #[test]
    fn test_is_process_running_as_system_matches_current_process_token_user() {
        let pid = unsafe { windows::Win32::System::Threading::GetCurrentProcessId() };
        let actual = is_process_running_as_system(pid).unwrap();

        let expected = unsafe {
            // Keep this test consistent: use only the `windows` crate APIs/types.
            let process = WinHandleGuard::new(
                WinOpenProcess(WIN_PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
                    .expect("WinOpenProcess should succeed for current process"),
            )
            .expect("current process handle should be valid");
            let mut token = WinHANDLE::default();
            WinOpenProcessToken(process.get(), WIN_TOKEN_QUERY, &mut token)
                .expect("WinOpenProcessToken should succeed for current process");
            let token = WinHandleGuard::new(token).expect("current process token should be valid");

            let mut token_user_size = 0u32;
            let _ = WinGetTokenInformation(token.get(), TokenUser, None, 0, &mut token_user_size);
            assert_ne!(token_user_size, 0, "TokenUser size should be non-zero");

            let mut buffer = vec![0u8; token_user_size as usize];
            WinGetTokenInformation(
                token.get(),
                TokenUser,
                Some(buffer.as_mut_ptr() as *mut core::ffi::c_void),
                token_user_size,
                &mut token_user_size,
            )
            .expect("WinGetTokenInformation(TokenUser) should succeed for current process");

            let min_size = std::mem::size_of::<TOKEN_USER>();
            assert!(
                buffer.len() >= min_size,
                "TokenUser buffer too small (got {}, need >= {})",
                buffer.len(),
                min_size
            );
            let token_user: TOKEN_USER =
                std::ptr::read_unaligned(buffer.as_ptr() as *const TOKEN_USER);
            let expected = IsWellKnownSid(token_user.User.Sid, WinLocalSystemSid).as_bool();
            expected
        };

        assert_eq!(actual, expected);
    }

    #[test]
    fn consent_candidate_requires_exact_system_image_and_current_session() {
        let expected = Path::new(r"C:\Windows\System32\consent.exe");
        assert!(trusted_system_process_candidate_matches(
            expected,
            7,
            Path::new(r"c:\WINDOWS\system32\CONSENT.EXE"),
            7,
        ));
        assert!(!trusted_system_process_candidate_matches(
            expected,
            7,
            Path::new(r"C:\Users\alice\consent.exe"),
            7,
        ));
        assert!(!trusted_system_process_candidate_matches(
            expected,
            7,
            expected,
            8,
        ));
    }

    #[test]
    fn test_get_unicode_char_by_vk() {
        let chr = get_char_from_vk(0x41); // VK_A
        assert_eq!(chr, Some('a'));
        let chr = get_char_from_vk(VK_ESCAPE as u32); // VK_ESC
        assert_eq!(chr, None)
    }
}
