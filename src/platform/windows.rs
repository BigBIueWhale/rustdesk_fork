use super::{CursorData, ResultType};
use crate::{
    ipc,
    privacy_mode::win_topmost_window::{self, WIN_TOPMOST_INJECTED_PROCESS_EXE},
};
use hbb_common::{
    allow_err,
    anyhow::anyhow,
    bail,
    config::{self, Config},
    libc::{c_int, wchar_t},
    log,
    message_proto::{DisplayInfo, Resolution, WindowsSession},
    sha2::{Digest, Sha256},
    sleep, timeout, tokio,
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
            io::AsRawHandle,
            process::CommandExt,
        },
    },
    path::*,
    ptr::null_mut,
    sync::{atomic::Ordering, Arc, Mutex},
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
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        libloaderapi::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32},
        minwinbase::STILL_ACTIVE,
        processthreadsapi::{
            GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess, OpenProcess,
            OpenProcessToken, ProcessIdToSessionId,
        },
        securitybaseapi::{DuplicateToken, GetTokenInformation},
        shellapi::ShellExecuteW,
        sysinfoapi::{GetNativeSystemInfo, SYSTEM_INFO},
        winbase::*,
        wingdi::*,
        winnt::{
            SecurityImpersonation, TokenElevation, TokenImpersonation, TokenType,
            ES_AWAYMODE_REQUIRED, ES_CONTINUOUS, ES_DISPLAY_REQUIRED, ES_SYSTEM_REQUIRED,
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_TEMPORARY, FILE_READ_ATTRIBUTES,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, HANDLE,
            PROCESS_QUERY_LIMITED_INFORMATION, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_TYPE,
        },
        winreg::HKEY_CURRENT_USER,
        winuser::*,
    },
};
use windows::{
    core::{Interface, GUID, PCWSTR, PWSTR},
    Win32::{
        Foundation::{CloseHandle as WinCloseHandle, HANDLE as WinHANDLE, RPC_E_CHANGED_MODE},
        Security::{
            GetTokenInformation as WinGetTokenInformation, IsWellKnownSid, TokenUser,
            WinLocalSystemSid, TOKEN_QUERY as WIN_TOKEN_QUERY, TOKEN_USER,
        },
        System::ApplicationInstallationAndServicing::{
            MsiGetProductInfoW, INSTALLPROPERTY_PRODUCTNAME,
        },
        System::Com::{
            CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize, IPersistFile,
            CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
        },
        System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        },
        System::SystemInformation::GetSystemDirectoryW,
        System::Threading::{
            OpenProcess as WinOpenProcess, OpenProcessToken as WinOpenProcessToken,
            QueryFullProcessImageNameW as WinQueryFullProcessImageNameW,
            TerminateProcess as WinTerminateProcess,
            PROCESS_QUERY_LIMITED_INFORMATION as WIN_PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_TERMINATE as WIN_PROCESS_TERMINATE,
        },
        UI::Shell::{
            FOLDERID_CommonPrograms, FOLDERID_CommonStartup, FOLDERID_Desktop,
            FOLDERID_ProgramData, FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86,
            FOLDERID_PublicDesktop, FOLDERID_UserProfiles, FOLDERID_Windows, IShellLinkW,
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
    service_control_handler::{self, ServiceControlHandlerResult},
};
use winreg::{enums::*, RegKey};

mod acl;
pub use acl::set_path_permission;

pub const FLUTTER_RUNNER_WIN32_WINDOW_CLASS: &'static str = "FLUTTER_RUNNER_WIN32_WINDOW"; // main window, install window
pub const SET_FOREGROUND_WINDOW: &'static str = "SET_FOREGROUND_WINDOW";

const REG_NAME_INSTALL_DESKTOPSHORTCUTS: &str = "DESKTOPSHORTCUTS";
const REG_NAME_INSTALL_STARTMENUSHORTCUTS: &str = "STARTMENUSHORTCUTS";
const PROTECTED_INSTALL_ENV_KEY: &str = "RUSTDESK_PROTECTED_INSTALL";
const PROTECTED_INSTALL_STAGING_PREFIX: &str = "RustDesk-staging-";
const FILE_ATTRIBUTE_REPARSE_POINT_FLAG: u32 = 0x400;

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

pub fn start_os_service() {
    if let Err(e) =
        windows_service::service_dispatcher::start(crate::get_app_name(), ffi_service_main)
    {
        log::error!("start_service failed: {}", e);
    }
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
        token_pid: &mut DWORD,
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
    fn win32_enable_lowlevel_keyboard(hwnd: HWND) -> i32;
    fn win32_disable_lowlevel_keyboard(hwnd: HWND);
    fn win_stop_system_key_propagate(v: BOOL);
    fn is_win_down() -> BOOL;
    fn is_local_system() -> BOOL;
    fn alloc_console_and_redirect();
    fn is_service_running_w(svc_name: *const u16) -> bool;
}

pub fn get_current_session_id(share_rdp: bool) -> DWORD {
    unsafe { get_current_session(if share_rdp { TRUE } else { FALSE }) }
}

#[inline]
fn resolve_expected_active_session_id_for_service(session_id: u32) -> Option<u32> {
    let share_rdp_enabled = is_share_rdp();
    if get_available_sessions(false)
        .iter()
        .any(|e| e.sid == session_id)
    {
        return Some(session_id);
    }
    let current_active_session =
        unsafe { get_current_session(if share_rdp_enabled { TRUE } else { FALSE }) };
    if current_active_session == u32::MAX {
        None
    } else {
        Some(current_active_session)
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
    incoming: parity_tokio_ipc::Incoming,
) -> ResultType<parity_tokio_ipc::Incoming> {
    drop(incoming);
    ipc::new_listener(crate::POSTFIX_SERVICE).await
}

extern "system" {
    fn BlockInput(v: BOOL) -> BOOL;
}

#[tokio::main(flavor = "current_thread")]
async fn run_service(_arguments: Vec<OsString>) -> ResultType<()> {
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        log::info!("Got service control event: {:?}", control_event);
        match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Preshutdown | ServiceControl::Shutdown => {
                send_close(crate::POSTFIX_SERVICE).ok();
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // Register system service event handler
    let status_handle = service_control_handler::register(crate::get_app_name(), event_handler)?;

    let next_status = ServiceStatus {
        // Should match the one from system service registry
        service_type: SERVICE_TYPE,
        // The new state
        current_state: ServiceState::Running,
        // Accept stop events when running
        controls_accepted: ServiceControlAccept::STOP,
        // Used to report an error when starting or stopping only, otherwise must be zero
        exit_code: ServiceExitCode::Win32(0),
        // Only used for pending states, otherwise must be zero
        checkpoint: 0,
        // Only used for pending states, otherwise must be zero
        wait_hint: Duration::default(),
        process_id: None,
    };

    // Tell the system that the service is running now
    status_handle.set_service_status(next_status)?;

    let mut session_id = unsafe { get_current_session(share_rdp()) };
    log::info!("session id {}", session_id);
    let mut h_process = launch_server(session_id, true).await.unwrap_or(NULL);
    let mut incoming = ipc::new_listener(crate::POSTFIX_SERVICE).await?;
    loop {
        let sids: Vec<_> = get_available_sessions(false)
            .iter()
            .map(|e| e.sid)
            .collect();
        if !sids.contains(&session_id) || !is_share_rdp() {
            let current_active_session = unsafe { get_current_session(share_rdp()) };
            if session_id != current_active_session {
                session_id = current_active_session;
                incoming = refresh_service_ipc_listener(incoming).await?;
                // https://github.com/rustdesk/rustdesk/discussions/10039
                let count = ipc::get_port_forward_session_count(1000).await.unwrap_or(0);
                if count == 0 {
                    h_process = launch_server(session_id, true).await.unwrap_or(NULL);
                }
            }
        }
        let res = timeout(super::SERVICE_INTERVAL, incoming.next()).await;
        match res {
            Ok(res) => match res {
                Some(Ok(stream)) => {
                    let mut stream = ipc::Connection::new(stream);
                    // Keep IPC authorization consistent with the session we are currently serving.
                    // Recompute expected session right before authorization to avoid using a stale
                    // session_id after awaiting incoming.next().
                    let expected_active_session_id =
                        resolve_expected_active_session_id_for_service(session_id);
                    if !authorize_service_scoped_ipc_connection(&stream, expected_active_session_id)
                    {
                        continue;
                    }
                    if let Ok(Some(data)) = stream.next_timeout(1000).await {
                        match data {
                            ipc::Data::Close => {
                                match stream.windows_pipe_client_token_is_local_system() {
                                    Ok(true) => {
                                        log::info!("close received");
                                        break;
                                    }
                                    Ok(false) => {
                                        log::warn!(
                                            "Rejected Windows _service close: caller is not LocalSystem"
                                        );
                                    }
                                    Err(err) => {
                                        log::warn!(
                                            "Rejected Windows _service close: failed to verify caller token: {err}"
                                        );
                                    }
                                }
                            }
                            ipc::Data::Test => {
                                allow_err!(stream.send(&ipc::Data::Test).await);
                            }
                            ipc::Data::RequestServiceOwnedUnattendedPasswordChange(value) => {
                                ipc::handle_windows_service_owned_unattended_password_request(
                                    value,
                                    &mut stream,
                                )
                                .await;
                            }
                            ipc::Data::RequestServiceOwnedShareRdp(enable) => {
                                ipc::handle_windows_service_owned_share_rdp_request(
                                    enable,
                                    &mut stream,
                                )
                                .await;
                            }
                            _ => {
                                log::warn!(
                                    "Rejected unauthorized data on protected Windows _service IPC channel: data_kind={:?}",
                                    std::mem::discriminant(&data)
                                );
                            }
                        }
                    }
                }
                _ => {}
            },
            Err(_) => {
                // timeout
                unsafe {
                    let tmp = get_current_session(share_rdp());
                    if tmp == 0xFFFFFFFF {
                        continue;
                    }
                    let mut close_sent = false;
                    if tmp != session_id {
                        log::info!("session changed from {} to {}", session_id, tmp);
                        session_id = tmp;
                        incoming = refresh_service_ipc_listener(incoming).await?;
                        let count = ipc::get_port_forward_session_count(1000).await.unwrap_or(0);
                        if count == 0 {
                            send_close_async("").await.ok();
                            close_sent = true;
                        }
                    }
                    let mut exit_code: DWORD = 0;
                    if h_process.is_null()
                        || (GetExitCodeProcess(h_process, &mut exit_code) == TRUE
                            && exit_code != STILL_ACTIVE
                            && CloseHandle(h_process) == TRUE)
                    {
                        match launch_server(session_id, !close_sent).await {
                            Ok(ptr) => {
                                h_process = ptr;
                            }
                            Err(err) => {
                                log::error!("Failed to launch server: {}", err);
                            }
                        }
                    }
                }
            }
        }
    }

    if !h_process.is_null() {
        send_close_async("").await.ok();
        unsafe { CloseHandle(h_process) };
    }

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

async fn launch_server(session_id: DWORD, close_first: bool) -> ResultType<HANDLE> {
    if close_first {
        // in case started some elsewhere
        send_close_async("").await.ok();
    }
    let exe = require_current_exe_is_fixed_service_runtime()?;
    let (h, token_pid) = launch_process_in_session_with_env(
        &exe,
        &["--server", crate::common::SERVICE_OWNED_SERVER_ARG],
        session_id,
        FALSE,
        FALSE,
        std::iter::empty::<(&str, &str)>(),
    )?;
    if h.is_null() {
        log::error!(
            "Failed to launch privileged process: {}",
            io::Error::last_os_error()
        );
        if token_pid == 0 {
            log::error!("No trusted LocalSystem session token");
        }
    }
    Ok(h)
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

fn require_existing_file_no_reparse(path: &Path, label: &str) -> ResultType<WindowsPathIdentity> {
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
}

fn launch_process_in_session_with_env<I, K, V>(
    exe: &Path,
    arg: &[&str],
    session_id: DWORD,
    as_user: BOOL,
    show: BOOL,
    envs: I,
) -> ResultType<(HANDLE, DWORD)>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
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
    let h = unsafe {
        LaunchProcessWin(
            application.as_ptr(),
            command_line.as_ptr(),
            current_directory.as_ptr(),
            session_id,
            as_user,
            show,
            extra_env,
            &mut token_pid,
        )
    };
    Ok((h, token_pid))
}

pub fn run_as_user(arg: Vec<&str>) -> ResultType<Option<std::process::Child>> {
    run_as_user_with_env(arg, std::iter::empty::<(&str, &str)>())
}

pub fn run_as_user_with_env<I, K, V>(
    arg: Vec<&str>,
    envs: I,
) -> ResultType<Option<std::process::Child>>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    let exe = std::env::current_exe()?;
    run_exe_path_in_cur_session_with_env(&exe, arg, false, envs)
}

pub fn run_exe_direct(
    exe: &str,
    arg: Vec<&str>,
    show: bool,
) -> ResultType<Option<std::process::Child>> {
    run_exe_direct_with_env(exe, arg, show, std::iter::empty::<(&str, &str)>())
}

pub fn run_exe_direct_with_env<I, K, V>(
    exe: &str,
    arg: Vec<&str>,
    show: bool,
    envs: I,
) -> ResultType<Option<std::process::Child>>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    run_exe_path_direct_with_env(Path::new(exe), arg, show, envs)
}

fn run_exe_path_direct_with_env<I, K, V>(
    exe: &Path,
    arg: Vec<&str>,
    show: bool,
    envs: I,
) -> ResultType<Option<std::process::Child>>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    let mut cmd = std::process::Command::new(exe);
    cmd.envs(envs);
    for a in arg {
        cmd.arg(a);
    }
    if !show {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    match cmd.spawn() {
        Ok(child) => Ok(Some(child)),
        Err(e) => bail!("Failed to start process: {}", e),
    }
}

pub fn run_exe_in_cur_session(
    exe: &str,
    arg: Vec<&str>,
    show: bool,
) -> ResultType<Option<std::process::Child>> {
    run_exe_in_cur_session_with_env(exe, arg, show, std::iter::empty::<(&str, &str)>())
}

pub fn run_exe_in_cur_session_with_env<I, K, V>(
    exe: &str,
    arg: Vec<&str>,
    show: bool,
    envs: I,
) -> ResultType<Option<std::process::Child>>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    run_exe_path_in_cur_session_with_env(Path::new(exe), arg, show, envs)
}

fn run_exe_path_in_cur_session_with_env<I, K, V>(
    exe: &Path,
    arg: Vec<&str>,
    show: bool,
    envs: I,
) -> ResultType<Option<std::process::Child>>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    if is_root() {
        let Some(session_id) = get_current_process_session_id() else {
            bail!("Failed to get current process session id");
        };
        run_exe_path_in_session_with_env(exe, arg, session_id, show, envs)
    } else {
        run_exe_path_direct_with_env(exe, arg, show, envs)
    }
}

pub fn run_exe_in_session(
    exe: &str,
    arg: Vec<&str>,
    session_id: DWORD,
    show: bool,
) -> ResultType<Option<std::process::Child>> {
    run_exe_in_session_with_env(
        exe,
        arg,
        session_id,
        show,
        std::iter::empty::<(&str, &str)>(),
    )
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

pub fn run_exe_in_session_with_env<I, K, V>(
    exe: &str,
    arg: Vec<&str>,
    session_id: DWORD,
    show: bool,
    envs: I,
) -> ResultType<Option<std::process::Child>>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    run_exe_path_in_session_with_env(Path::new(exe), arg, session_id, show, envs)
}

fn run_exe_path_in_session_with_env<I, K, V>(
    exe: &Path,
    arg: Vec<&str>,
    session_id: DWORD,
    show: bool,
    envs: I,
) -> ResultType<Option<std::process::Child>>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    let (h, token_pid) = launch_process_in_session_with_env(
        exe,
        &arg,
        session_id,
        TRUE,
        if show { TRUE } else { FALSE },
        envs,
    )?;
    if h.is_null() {
        if token_pid == 0 {
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
    Ok(None)
}

#[tokio::main(flavor = "current_thread")]
async fn send_close(postfix: &str) -> ResultType<()> {
    send_close_async(postfix).await
}

async fn send_close_async(postfix: &str) -> ResultType<()> {
    ipc::connect(1000, postfix)
        .await?
        .send(&ipc::Data::Close)
        .await?;
    // sleep a while to wait for closing and exit
    sleep(0.1).await;
    Ok(())
}

const SOFTWARE_SAS_GENERATION_NONE: u32 = 0;
const SOFTWARE_SAS_GENERATION_SERVICES: u32 = 1;
const SOFTWARE_SAS_GENERATION_EASE_OF_ACCESS: u32 = 2;
const SOFTWARE_SAS_GENERATION_SERVICES_AND_EASE_OF_ACCESS: u32 =
    SOFTWARE_SAS_GENERATION_SERVICES | SOFTWARE_SAS_GENERATION_EASE_OF_ACCESS;

lazy_static::lazy_static! {
    static ref SEND_SAS_POLICY_MUTEX: Mutex<()> = Mutex::new(());
}

enum OriginalSasPolicy {
    Absent,
    Present(u32),
}

// https://docs.microsoft.com/en-us/windows/win32/api/sas/nf-sas-sendsas
// https://www.cnblogs.com/doutu/p/4892726.html
pub fn send_sas() -> ResultType<()> {
    #[link(name = "sas")]
    extern "system" {
        pub fn SendSAS(AsUser: BOOL);
    }

    log::info!("SAS received");
    let _sas_policy_guard = SEND_SAS_POLICY_MUTEX.lock().unwrap();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let policy_key = hklm
        .open_subkey_with_flags(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            KEY_READ | KEY_WRITE,
        )
        .map_err(|err| anyhow!("Failed to open SoftwareSASGeneration policy key: {err}"))?;

    let original_policy = match policy_key.get_value::<u32, _>("SoftwareSASGeneration") {
        Ok(value)
            if value == SOFTWARE_SAS_GENERATION_SERVICES
                || value == SOFTWARE_SAS_GENERATION_SERVICES_AND_EASE_OF_ACCESS =>
        {
            None
        }
        Ok(value)
            if value == SOFTWARE_SAS_GENERATION_NONE
                || value == SOFTWARE_SAS_GENERATION_EASE_OF_ACCESS =>
        {
            let temporary_value = value | SOFTWARE_SAS_GENERATION_SERVICES;
            log::info!(
                "SoftwareSASGeneration is {}, temporarily setting to {}",
                value,
                temporary_value
            );
            policy_key
                .set_value("SoftwareSASGeneration", &temporary_value)
                .map_err(|err| anyhow!("Failed to set SoftwareSASGeneration: {err}"))?;
            Some(OriginalSasPolicy::Present(value))
        }
        Ok(value) => bail!("Unsupported SoftwareSASGeneration value: {value}"),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            log::info!("SoftwareSASGeneration is absent, temporarily setting to 1");
            policy_key
                .set_value("SoftwareSASGeneration", &1u32)
                .map_err(|err| anyhow!("Failed to set SoftwareSASGeneration: {err}"))?;
            Some(OriginalSasPolicy::Absent)
        }
        Err(err) => bail!("Failed to read SoftwareSASGeneration: {err}"),
    };

    unsafe {
        SendSAS(FALSE);
    }

    if let Some(original_policy) = original_policy {
        match original_policy {
            OriginalSasPolicy::Absent => {
                policy_key
                    .delete_value("SoftwareSASGeneration")
                    .map_err(|err| anyhow!("Failed to delete SoftwareSASGeneration: {err}"))?;
                log::info!("Deleted SoftwareSASGeneration");
            }
            OriginalSasPolicy::Present(original) => {
                policy_key
                    .set_value("SoftwareSASGeneration", &original)
                    .map_err(|err| {
                        anyhow!("Failed to restore SoftwareSASGeneration to {original}: {err}")
                    })?;
                log::info!("Restored SoftwareSASGeneration to {}", original);
            }
        }
    }
    Ok(())
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
    if get_reg("share_rdp") != "false" {
        TRUE
    } else {
        FALSE
    }
}

pub fn is_share_rdp() -> bool {
    share_rdp() == TRUE
}

pub(crate) fn set_service_owned_share_rdp(enable: bool) -> ResultType<()> {
    let subkey = get_uninstall_registry_subkey();
    let subkey = subkey.replace("HKEY_LOCAL_MACHINE\\", "");
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm.open_subkey_with_flags(subkey, KEY_SET_VALUE)?;
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

#[inline]
pub fn is_logon_ui() -> ResultType<bool> {
    let Some(current_sid) = get_current_process_session_id() else {
        return Ok(false);
    };
    let pids = get_pids("LogonUI.exe")?;
    Ok(pids
        .into_iter()
        .any(|pid| get_session_id_of_process(pid) == Some(current_sid)))
}

pub fn is_root() -> bool {
    // https://stackoverflow.com/questions/4023586/correct-way-to-find-out-if-a-service-is-running-as-the-system-user
    unsafe { is_local_system() == TRUE }
}

pub fn lock_screen() {
    extern "system" {
        pub fn LockWorkStation() -> BOOL;
    }
    unsafe {
        LockWorkStation();
    }
}

const IS1: &str = "{54E86BC2-6C85-41F3-A9EB-1A94AC9B1F93}_is1";

fn get_subkey(name: &str, wow: bool) -> String {
    let tmp = format!(
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{}",
        name
    );
    if wow {
        tmp.replace("Microsoft", "Wow6432Node\\Microsoft")
    } else {
        tmp
    }
}

fn get_uninstall_registry_subkey() -> String {
    let subkey = get_subkey(IS1, false);
    if !get_reg_of(&subkey, "InstallLocation").is_empty() {
        return subkey;
    }
    let subkey = get_subkey(IS1, true);
    if !get_reg_of(&subkey, "InstallLocation").is_empty() {
        return subkey;
    }
    let app_name = crate::get_app_name();
    let subkey = get_subkey(&app_name, true);
    if !get_reg_of(&subkey, "InstallLocation").is_empty() {
        return subkey;
    }
    return get_subkey(&app_name, false);
}

// Return install options other than InstallLocation.
pub fn get_install_options() -> String {
    let app_name = crate::get_app_name();
    let subkey = format!(".{}", app_name.to_lowercase());
    let mut opts = HashMap::new();

    let desktop_shortcuts = get_reg_of_hkcr(&subkey, REG_NAME_INSTALL_DESKTOPSHORTCUTS);
    if let Some(desktop_shortcuts) = desktop_shortcuts {
        opts.insert(REG_NAME_INSTALL_DESKTOPSHORTCUTS, desktop_shortcuts);
    }
    let start_menu_shortcuts = get_reg_of_hkcr(&subkey, REG_NAME_INSTALL_STARTMENUSHORTCUTS);
    if let Some(start_menu_shortcuts) = start_menu_shortcuts {
        opts.insert(REG_NAME_INSTALL_STARTMENUSHORTCUTS, start_menu_shortcuts);
    }
    serde_json::to_string(&opts).unwrap_or("{}".to_owned())
}

// This function return Option<String>, because some registry value may be empty.
fn get_reg_of_hkcr(subkey: &str, name: &str) -> Option<String> {
    let hkcr = RegKey::predef(HKEY_CLASSES_ROOT);
    if let Ok(tmp) = hkcr.open_subkey(subkey.replace("HKEY_CLASSES_ROOT\\", "")) {
        return tmp.get_value(name).ok();
    }
    None
}

pub fn get_install_info() -> (String, String, String) {
    get_install_info_with_subkey(get_uninstall_registry_subkey())
}

fn get_default_install_info() -> (String, String, String) {
    get_install_info_with_subkey(get_subkey(&crate::get_app_name(), false))
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

fn common_programs_dir() -> ResultType<PathBuf> {
    known_folder_path(
        &FOLDERID_CommonPrograms,
        "SHGetKnownFolderPath(Common Programs)",
    )
}

fn common_startup_dir() -> ResultType<PathBuf> {
    known_folder_path(
        &FOLDERID_CommonStartup,
        "SHGetKnownFolderPath(Common Startup)",
    )
}

fn common_programs_app_dir() -> ResultType<PathBuf> {
    Ok(common_programs_dir()?.join(crate::get_app_name()))
}

fn common_startup_tray_shortcut_path() -> ResultType<PathBuf> {
    Ok(common_startup_dir()?.join(format!("{} Tray.lnk", crate::get_app_name())))
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

fn public_desktop_dir() -> ResultType<PathBuf> {
    known_folder_path(
        &FOLDERID_PublicDesktop,
        "SHGetKnownFolderPath(Public Desktop)",
    )
}

fn public_desktop_app_shortcut_path() -> ResultType<PathBuf> {
    Ok(public_desktop_dir()?.join(format!("{}.lnk", crate::get_app_name())))
}

fn default_install_path_buf() -> ResultType<PathBuf> {
    Ok(program_files_dir()?.join(crate::get_app_name()))
}

fn get_default_install_path() -> String {
    default_install_path_buf()
        .unwrap_or_else(|err| {
            log::error!("Failed to resolve Program Files install path: {err}");
            PathBuf::from("C:\\Program Files").join(crate::get_app_name())
        })
        .to_string_lossy()
        .into_owned()
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

fn has_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT_FLAG != 0
}

fn require_protected_install_source(
    current_exe: PathBuf,
    install_dir: &Path,
) -> ResultType<(PathBuf, PathBuf)> {
    if std::env::var_os(PROTECTED_INSTALL_ENV_KEY).as_deref() != Some(OsStr::new("1")) {
        bail!("Windows EXE install requires protected installer staging");
    }
    if !is_elevated(None)? {
        bail!("Windows EXE install requires an elevated protected installer process");
    }

    let exe_metadata = fs::symlink_metadata(&current_exe)?;
    if !exe_metadata.is_file()
        || exe_metadata.file_type().is_symlink()
        || has_reparse_point(&exe_metadata)
    {
        bail!(
            "Windows EXE install source is not a regular protected file: {:?}",
            current_exe
        );
    }

    let source_dir = current_exe
        .parent()
        .ok_or_else(|| anyhow!("Windows EXE install source has no parent directory"))?
        .to_path_buf();
    let source_metadata = fs::symlink_metadata(&source_dir)?;
    if !source_metadata.is_dir()
        || source_metadata.file_type().is_symlink()
        || has_reparse_point(&source_metadata)
    {
        bail!(
            "Windows EXE install source directory is not a regular protected directory: {:?}",
            source_dir
        );
    }

    let source_name = source_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("Windows EXE install source directory has no valid name"))?;
    if !source_name.starts_with(PROTECTED_INSTALL_STAGING_PREFIX) {
        bail!(
            "Windows EXE install source is not protected installer staging: {:?}",
            source_dir
        );
    }

    let program_files = program_files_dir()?;
    let source_parent = source_dir
        .parent()
        .ok_or_else(|| anyhow!("Windows EXE install source directory has no parent"))?;
    if normalized_windows_path_text(source_parent) != normalized_windows_path_text(&program_files) {
        bail!(
            "Windows EXE install source is outside protected Program Files staging: {:?}",
            source_dir
        );
    }

    let source = normalized_windows_path_text(&source_dir);
    let final_install = normalized_windows_path_text(install_dir);
    if source == final_install || source.starts_with(&(final_install + "\\")) {
        bail!(
            "Windows EXE install source overlaps the final install directory: {:?}",
            source_dir
        );
    }

    Ok((current_exe, source_dir))
}

fn fixed_service_install_dir_and_exe() -> ResultType<(String, String)> {
    let install_dir = fixed_service_install_path("")?;
    let exe_path = fixed_service_install_exe_path()?;
    let path = install_dir.to_string_lossy().into_owned();
    let exe = exe_path.to_string_lossy().into_owned();
    Ok((path, exe))
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
    if !path.is_file() {
        bail!("trusted system tool is missing: {:?}", path);
    }
    Ok(path)
}

fn quoted_batch_path(path: &Path) -> ResultType<String> {
    let text = batch_path_text(path, "batch path")?;
    Ok(format!("\"{text}\""))
}

fn fixed_service_install_dir_batch_path() -> ResultType<String> {
    quoted_batch_path(&fixed_service_install_path("")?)
}

fn batch_path_text(path: &Path, label: &str) -> ResultType<String> {
    let text = path
        .to_str()
        .ok_or_else(|| anyhow!("{label} is not valid UTF-8: {:?}", path))?;
    batch_literal_text(text, label)?;
    Ok(text.to_owned())
}

fn batch_literal_text<'a>(text: &'a str, label: &str) -> ResultType<&'a str> {
    if text.is_empty() {
        bail!("{label} is empty");
    }
    if text.chars().any(|c| {
        matches!(
            c,
            '"' | '%' | '!' | '&' | '|' | '<' | '>' | '^' | '@' | '\r' | '\n'
        ) || c.is_control()
    }) {
        bail!("{label} contains characters unsafe for elevated cmd.exe execution: {text}");
    }
    Ok(text)
}

fn checked_batch_cmd(command: impl AsRef<str>) -> String {
    format!(
        "
{}
if errorlevel 1 exit /b 1
",
        command.as_ref()
    )
}

fn checked_reg_add(command: String) -> String {
    checked_batch_cmd(command)
}

fn require_batch_path_exists(quoted_path: &str) -> String {
    format!("if not exist {quoted_path} exit /b 1")
}

fn require_batch_path_absent(quoted_path: &str) -> String {
    format!("if exist {quoted_path} exit /b 1")
}

fn checked_copy_to_path(command: String, quoted_target: &str) -> String {
    format!(
        "
{}
{}
",
        checked_batch_cmd(command),
        require_batch_path_exists(quoted_target)
    )
}

fn ensure_batch_dir_exists(path: &Path) -> ResultType<String> {
    let quoted_path = quoted_batch_path(path)?;
    Ok(format!(
        "
if not exist {quoted_path} md {quoted_path}
{}
",
        require_batch_path_exists(&quoted_path)
    ))
}

fn delete_batch_path_absent_ok(command: String, quoted_path: &str) -> String {
    format!(
        "
{command}
{}
",
        require_batch_path_absent(quoted_path)
    )
}

fn delete_reg_key_absent_ok(reg: &str, key: &str) -> String {
    format!(
        "
{reg} delete {key} /f >nul 2>nul
{reg} query {key} >nul 2>nul && exit /b 1
"
    )
}

fn delete_firewall_rule_absent_ok(netsh: &str, rule_name: &str) -> String {
    format!(
        "
{netsh} advfirewall firewall delete rule name=\"{rule_name}\" >nul 2>nul
{netsh} advfirewall firewall show rule name=\"{rule_name}\" >nul 2>nul && exit /b 1
"
    )
}

fn delete_service_absent_ok(
    sc: &str,
    timeout: &str,
    service_name: &str,
    absent_label: &str,
) -> String {
    format!(
        "
{sc} query \"{service_name}\" >nul 2>nul
if not errorlevel 1 (
  {sc} delete \"{service_name}\" >nul 2>nul
)
for /L %%i in (1,1,20) do (
  {sc} query \"{service_name}\" >nul 2>nul
  if errorlevel 1 goto {absent_label}
  {timeout} /T 1 /NOBREAK >nul 2>nul
)
exit /b 1
:{absent_label}
"
    )
}

fn checked_msi_uninstall_command(command: String) -> String {
    format!(
        "
{command}
if %ERRORLEVEL% EQU 3010 goto rustdesk_msi_uninstall_ok
if %ERRORLEVEL% EQU 1605 goto rustdesk_msi_uninstall_ok
if errorlevel 1 exit /b 1
:rustdesk_msi_uninstall_ok
"
    )
}

fn trusted_system_cmd_path() -> ResultType<PathBuf> {
    trusted_system_tool_path("cmd.exe")
}

struct WindowsSystemTools {
    chcp: String,
    cscript: String,
    msiexec: String,
    msiexec_path: PathBuf,
    netsh: String,
    reg: String,
    sc: String,
    taskkill: String,
    timeout: String,
    xcopy: String,
}

impl WindowsSystemTools {
    fn resolve() -> ResultType<Self> {
        let msiexec_path = trusted_system_tool_path("msiexec.exe")?;
        let msiexec = quoted_batch_path(&msiexec_path)?;
        Ok(Self {
            chcp: quoted_batch_path(&trusted_system_tool_path("chcp.com")?)?,
            cscript: quoted_batch_path(&trusted_system_tool_path("cscript.exe")?)?,
            msiexec,
            msiexec_path,
            netsh: quoted_batch_path(&trusted_system_tool_path("netsh.exe")?)?,
            reg: quoted_batch_path(&trusted_system_tool_path("reg.exe")?)?,
            sc: quoted_batch_path(&trusted_system_tool_path("sc.exe")?)?,
            taskkill: quoted_batch_path(&trusted_system_tool_path("taskkill.exe")?)?,
            timeout: quoted_batch_path(&trusted_system_tool_path("timeout.exe")?)?,
            xcopy: quoted_batch_path(&trusted_system_tool_path("xcopy.exe")?)?,
        })
    }
}

pub fn check_update_broker_process() -> ResultType<()> {
    let tools = WindowsSystemTools::resolve()?;
    let process_exe = win_topmost_window::INJECTED_PROCESS_EXE;
    let origin_process_exe = win_topmost_window::ORIGIN_PROCESS_EXE;

    let exe_file = std::env::current_exe()?;
    let Some(cur_dir) = exe_file.parent() else {
        bail!("Cannot get parent of current exe file");
    };
    let cur_exe = cur_dir.join(process_exe);
    let cur_exe_quoted = quoted_batch_path(&cur_exe)?;
    let copy_broker = checked_copy_to_path(
        format!("copy /Y \"{origin_process_exe}\" {cur_exe_quoted}"),
        &cur_exe_quoted,
    );

    // Force update broker exe if failed to check modified time.
    let cmds = format!(
        "
        {chcp} 65001
        {taskkill} /F /IM {process_exe}
        {copy_broker}
    ",
        chcp = tools.chcp,
        taskkill = tools.taskkill,
    );

    if !std::path::Path::new(&cur_exe).exists() {
        run_cmds(cmds, false, "update_broker")?;
        return Ok(());
    }

    let ori_modified = fs::metadata(origin_process_exe)?.modified()?;
    if let Ok(metadata) = fs::metadata(&cur_exe) {
        if let Ok(cur_modified) = metadata.modified() {
            if cur_modified == ori_modified {
                return Ok(());
            } else {
                log::info!(
                    "broker process updated, modify time from {:?} to {:?}",
                    cur_modified,
                    ori_modified
                );
            }
        }
    }

    run_cmds(cmds, false, "update_broker")?;

    Ok(())
}

fn get_install_info_with_subkey(subkey: String) -> (String, String, String) {
    let mut path = get_reg_of(&subkey, "InstallLocation");
    if path.is_empty() {
        path = get_default_install_path();
    }
    path = path.trim_end_matches('\\').to_owned();
    let exe = format!("{}\\{}.exe", path, crate::get_app_name());
    (subkey, path, exe)
}

fn copy_source_dir_cmd(
    source_dir: &Path,
    expected_exe: &str,
    install_dir: &str,
    tools: &WindowsSystemTools,
) -> ResultType<String> {
    let src_parent = quoted_batch_path(source_dir)?;
    let install_dir = quoted_batch_path(Path::new(install_dir))?;
    let expected_exe = quoted_batch_path(Path::new(expected_exe))?;
    let main_copy = checked_copy_to_path(
        format!(
            "{} {src_parent} {install_dir} /Y /E /H /I /K /R /Z",
            tools.xcopy,
        ),
        &expected_exe,
    );
    Ok(main_copy)
}

fn copy_exe_cmd(
    source_dir: &Path,
    exe: &str,
    path: &str,
    tools: &WindowsSystemTools,
) -> ResultType<String> {
    let main_exe = copy_source_dir_cmd(source_dir, exe, path, tools)?;
    let broker_exe = win_topmost_window::INJECTED_PROCESS_EXE;
    let broker_dst = Path::new(path).join(broker_exe);
    let broker_dst = quoted_batch_path(&broker_dst)?;
    let copy_broker = checked_copy_to_path(
        format!(
            "copy /Y \"{}\" {broker_dst}",
            win_topmost_window::ORIGIN_PROCESS_EXE,
        ),
        &broker_dst,
    );
    Ok(format!(
        "
        {main_exe}
        {copy_broker}
        ",
    ))
}

#[inline]
pub fn rename_exe_cmd(src_exe: &str, path: &str) -> ResultType<String> {
    let src_exe_filename = PathBuf::from(src_exe)
        .file_name()
        .ok_or(anyhow!("Can't get file name of {src_exe}"))?
        .to_string_lossy()
        .to_string();
    let app_name = crate::get_app_name().to_lowercase();
    if src_exe_filename.to_lowercase() == format!("{app_name}.exe") {
        Ok("".to_owned())
    } else {
        Ok(format!(
            "
        move /Y \"{path}\\{src_exe_filename}\" \"{path}\\{app_name}.exe\"
        ",
        ))
    }
}

#[inline]
pub fn remove_meta_toml_cmd(is_msi: bool, path: &str) -> String {
    if is_msi && crate::is_custom_client() {
        format!(
            "
        del /F /Q \"{path}\\meta.toml\"
        ",
        )
    } else {
        "".to_owned()
    }
}

fn get_after_install(
    exe: &str,
    reg_value_start_menu_shortcuts: Option<String>,
    reg_value_desktop_shortcuts: Option<String>,
    tools: &WindowsSystemTools,
) -> String {
    let app_name = crate::get_app_name();
    let ext = app_name.to_lowercase();

    // reg delete HKEY_CURRENT_USER\Software\Classes for
    // https://github.com/rustdesk/rustdesk/commit/f4bdfb6936ae4804fc8ab1cf560db192622ad01a
    // and https://github.com/leanflutter/uni_links_desktop/blob/1b72b0226cec9943ca8a84e244c149773f384e46/lib/src/protocol_registrar_impl_windows.dart#L30
    let hcu = RegKey::predef(HKEY_CURRENT_USER);
    hcu.delete_subkey_all(format!("Software\\Classes\\{}", exe))
        .ok();

    let mut commands = Vec::new();
    commands.push(checked_reg_add(format!(
        "{reg} add HKEY_CLASSES_ROOT\\.{ext} /f",
        reg = tools.reg
    )));
    if let Some(v) = reg_value_desktop_shortcuts {
        commands.push(checked_reg_add(format!("{reg} add HKEY_CLASSES_ROOT\\.{ext} /f /v {REG_NAME_INSTALL_DESKTOPSHORTCUTS} /t REG_SZ /d \"{v}\"", reg = tools.reg)));
    }
    if let Some(v) = reg_value_start_menu_shortcuts {
        commands.push(checked_reg_add(format!("{reg} add HKEY_CLASSES_ROOT\\.{ext} /f /v {REG_NAME_INSTALL_STARTMENUSHORTCUTS} /t REG_SZ /d \"{v}\"", reg = tools.reg)));
    }
    commands.extend([
        checked_reg_add(format!(
            "{reg} add HKEY_CLASSES_ROOT\\.{ext}\\DefaultIcon /f",
            reg = tools.reg
        )),
        checked_reg_add(format!(
            "{reg} add HKEY_CLASSES_ROOT\\.{ext}\\DefaultIcon /f /ve /t REG_SZ  /d \"\\\"{exe}\\\",0\"",
            reg = tools.reg
        )),
        checked_reg_add(format!(
            "{reg} add HKEY_CLASSES_ROOT\\.{ext}\\shell /f",
            reg = tools.reg
        )),
        checked_reg_add(format!(
            "{reg} add HKEY_CLASSES_ROOT\\.{ext}\\shell\\open /f",
            reg = tools.reg
        )),
        checked_reg_add(format!(
            "{reg} add HKEY_CLASSES_ROOT\\.{ext}\\shell\\open\\command /f",
            reg = tools.reg
        )),
        checked_reg_add(format!(
            "{reg} add HKEY_CLASSES_ROOT\\.{ext}\\shell\\open\\command /f /ve /t REG_SZ /d \"\\\"{exe}\\\" --play \\\"%%1\\\"\"",
            reg = tools.reg
        )),
        checked_reg_add(format!(
            "{reg} add HKEY_CLASSES_ROOT\\{ext} /f",
            reg = tools.reg
        )),
        checked_reg_add(format!(
            "{reg} add HKEY_CLASSES_ROOT\\{ext} /f /v \"URL Protocol\" /t REG_SZ /d \"\"",
            reg = tools.reg
        )),
        checked_reg_add(format!(
            "{reg} add HKEY_CLASSES_ROOT\\{ext}\\shell /f",
            reg = tools.reg
        )),
        checked_reg_add(format!(
            "{reg} add HKEY_CLASSES_ROOT\\{ext}\\shell\\open /f",
            reg = tools.reg
        )),
        checked_reg_add(format!(
            "{reg} add HKEY_CLASSES_ROOT\\{ext}\\shell\\open\\command /f",
            reg = tools.reg
        )),
        checked_reg_add(format!(
            "{reg} add HKEY_CLASSES_ROOT\\{ext}\\shell\\open\\command /f /ve /t REG_SZ /d \"\\\"{exe}\\\" \\\"%%1\\\"\"",
            reg = tools.reg
        )),
        checked_batch_cmd(format!(
            "{netsh} advfirewall firewall add rule name=\"{app_name} Service\" dir=out action=allow program=\"{exe}\" enable=yes",
            netsh = tools.netsh
        )),
        checked_batch_cmd(format!(
            "{netsh} advfirewall firewall add rule name=\"{app_name} Service\" dir=in action=allow program=\"{exe}\" enable=yes",
            netsh = tools.netsh
        )),
    ]);
    let create_service = get_create_service(exe, tools);
    if !create_service.trim().is_empty() {
        commands.push(create_service);
    }

    format!(
        "
    {chcp} 65001
    {commands}
    ",
        chcp = tools.chcp,
        commands = commands.join("\n"),
    )
}

pub fn install_me(options: &str, path: String, silent: bool, debug: bool) -> ResultType<()> {
    let tools = WindowsSystemTools::resolve()?;
    let uninstall_str = get_uninstall(false, &tools)?;
    let install_dir = fixed_service_install_path(&path)?;
    let path = install_dir.to_string_lossy().into_owned();
    let (subkey, _path, exe) = get_default_install_info();
    let mut exe = exe;
    exe = exe.replace(&_path, &path);
    let mut version_major = "0";
    let mut version_minor = "0";
    let mut version_build = "0";
    let versions: Vec<&str> = crate::VERSION.split(".").collect();
    if versions.len() > 0 {
        version_major = versions[0];
    }
    if versions.len() > 1 {
        version_minor = versions[1];
    }
    if versions.len() > 2 {
        version_build = versions[2];
    }
    let app_name = crate::get_app_name();

    let current_exe = std::env::current_exe()?;
    let (current_exe, source_dir) = require_protected_install_source(current_exe, &install_dir)?;
    let cur_exe = batch_path_text(&current_exe, "current exe")?;
    let mut reg_value_desktop_shortcuts = "0".to_owned();
    let mut reg_value_start_menu_shortcuts = "0".to_owned();
    let mut shortcut_scripts = Vec::new();
    let mut shortcut_cmds = String::new();
    if options.contains("desktopicon") {
        let desktop_shortcut_path = public_desktop_app_shortcut_path()?;
        let desktop_shortcut = create_shortcut_command_file(
            &desktop_shortcut_path,
            &exe,
            None,
            None,
            &path,
            &cur_exe,
            "desktop_shortcut",
        );
        let desktop_shortcut = desktop_shortcut?;
        shortcut_cmds.push_str(&run_shortcut_script_cmd(
            desktop_shortcut.path_str()?,
            &desktop_shortcut_path,
            &tools,
        )?);
        shortcut_scripts.push(desktop_shortcut);
        reg_value_desktop_shortcuts = "1".to_owned();
    }
    if options.contains("startmenu") {
        let start_menu = common_programs_app_dir()?;
        let quoted_start_menu = quoted_batch_path(&start_menu)?;
        shortcut_cmds.push_str(&format!(
            "
if not exist {quoted_start_menu} md {quoted_start_menu}
if not exist {quoted_start_menu} exit /b 1
"
        ));
        let start_menu_shortcut_path = start_menu.join(format!("{app_name}.lnk"));
        let start_menu_shortcut = create_shortcut_command_file(
            &start_menu_shortcut_path,
            &exe,
            None,
            None,
            &path,
            &cur_exe,
            "start_menu_shortcut",
        )?;
        shortcut_cmds.push_str(&run_shortcut_script_cmd(
            start_menu_shortcut.path_str()?,
            &start_menu_shortcut_path,
            &tools,
        )?);
        shortcut_scripts.push(start_menu_shortcut);
        let start_menu_uninstall_shortcut_path =
            start_menu.join(format!("Uninstall {app_name}.lnk"));
        let start_menu_uninstall_shortcut = create_shortcut_command_file(
            &start_menu_uninstall_shortcut_path,
            &exe,
            Some("--uninstall"),
            Some("msiexec.exe"),
            "",
            "",
            "start_menu_uninstall_shortcut",
        )?;
        shortcut_cmds.push_str(&run_shortcut_script_cmd(
            start_menu_uninstall_shortcut.path_str()?,
            &start_menu_uninstall_shortcut_path,
            &tools,
        )?);
        shortcut_scripts.push(start_menu_uninstall_shortcut);
        reg_value_start_menu_shortcuts = "1".to_owned();
    }
    if !config::is_outgoing_only() {
        let tray_shortcut_path = common_startup_tray_shortcut_path()?;
        let tray_shortcut = create_shortcut_command_file(
            &tray_shortcut_path,
            &exe,
            Some("--tray"),
            None,
            &path,
            &cur_exe,
            "tray_shortcut",
        )?;
        shortcut_cmds.push_str(&run_shortcut_script_cmd(
            tray_shortcut.path_str()?,
            &tray_shortcut_path,
            &tools,
        )?);
        shortcut_scripts.push(tray_shortcut);
    }
    let install_uninstall_shortcut_path =
        Path::new(&path).join(format!("Uninstall {app_name}.lnk"));
    let install_uninstall_shortcut = create_shortcut_command_file(
        &install_uninstall_shortcut_path,
        &exe,
        Some("--uninstall"),
        Some("msiexec.exe"),
        "",
        "",
        "install_uninstall_shortcut",
    )?;
    shortcut_cmds.push_str(&run_shortcut_script_cmd(
        install_uninstall_shortcut.path_str()?,
        &install_uninstall_shortcut_path,
        &tools,
    )?);
    shortcut_scripts.push(install_uninstall_shortcut);

    let meta = std::fs::symlink_metadata(&current_exe)?;
    let mut size = meta.len() / 1024;
    if let Some(d) = source_dir.to_str() {
        size = get_directory_size_kb(d);
    }
    // https://docs.microsoft.com/zh-cn/windows/win32/msi/uninstall-registry-key?redirectedfrom=MSDNa
    // https://www.windowscentral.com/how-edit-registry-using-command-prompt-windows-10
    // https://www.tenforums.com/tutorials/70903-add-remove-allowed-apps-through-windows-firewall-windows-10-a.html
    // R-X4: the install-time license injection (custom_server-from-exe-name -> key /
    // custom-rendezvous-server / api-server) is excised; the fork is direct-IP only.

    let display_icon = get_custom_icon(&path, &cur_exe).unwrap_or(exe.to_string());
    let install_dir_cmd = ensure_batch_dir_exists(Path::new(&path))?;
    let copy_exe = copy_exe_cmd(&source_dir, &exe, &path, &tools)?;
    let install_reg_cmds = [
        checked_reg_add(format!("{reg} add {subkey} /f", reg = tools.reg)),
        checked_reg_add(format!(
            "{reg} add {subkey} /f /v DisplayIcon /t REG_SZ /d \"{display_icon}\"",
            reg = tools.reg
        )),
        checked_reg_add(format!(
            "{reg} add {subkey} /f /v DisplayName /t REG_SZ /d \"{app_name}\"",
            reg = tools.reg
        )),
        checked_reg_add(format!(
            "{reg} add {subkey} /f /v DisplayVersion /t REG_SZ /d \"{version}\"",
            reg = tools.reg,
            version = crate::VERSION.replace("-", "."),
        )),
        checked_reg_add(format!(
            "{reg} add {subkey} /f /v Version /t REG_SZ /d \"{version}\"",
            reg = tools.reg,
            version = crate::VERSION.replace("-", "."),
        )),
        checked_reg_add(format!(
            "{reg} add {subkey} /f /v BuildDate /t REG_SZ /d \"{build_date}\"",
            reg = tools.reg,
            build_date = crate::BUILD_DATE,
        )),
        checked_reg_add(format!(
            "{reg} add {subkey} /f /v InstallLocation /t REG_SZ /d \"{path}\"",
            reg = tools.reg,
        )),
        checked_reg_add(format!(
            "{reg} add {subkey} /f /v Publisher /t REG_SZ /d \"{app_name}\"",
            reg = tools.reg,
        )),
        checked_reg_add(format!(
            "{reg} add {subkey} /f /v VersionMajor /t REG_DWORD /d {version_major}",
            reg = tools.reg,
        )),
        checked_reg_add(format!(
            "{reg} add {subkey} /f /v VersionMinor /t REG_DWORD /d {version_minor}",
            reg = tools.reg,
        )),
        checked_reg_add(format!(
            "{reg} add {subkey} /f /v VersionBuild /t REG_DWORD /d {version_build}",
            reg = tools.reg,
        )),
        checked_reg_add(format!(
            "{reg} add {subkey} /f /v UninstallString /t REG_SZ /d \"\\\"{exe}\\\" --uninstall\"",
            reg = tools.reg,
        )),
        checked_reg_add(format!(
            "{reg} add {subkey} /f /v EstimatedSize /t REG_DWORD /d {size}",
            reg = tools.reg,
        )),
        checked_reg_add(format!(
            "{reg} add {subkey} /f /v WindowsInstaller /t REG_DWORD /d 0",
            reg = tools.reg,
        )),
    ]
    .join("\n");

    let cmds = format!(
        "
	{uninstall_str}
		{chcp} 65001
		{install_dir_cmd}
		{copy_exe}
		{install_reg_cmds}
		{shortcut_cmds}
	{import_config}
	{after_install}
	{sleep}
	    ",
        chcp = tools.chcp,
        after_install = get_after_install(
            &exe,
            Some(reg_value_start_menu_shortcuts),
            Some(reg_value_desktop_shortcuts),
            &tools,
        ),
        sleep = if debug {
            format!("{} /T 300", tools.timeout)
        } else {
            String::new()
        },
        import_config = get_import_config(&exe),
        shortcut_cmds = shortcut_cmds,
    );
    run_cmds(cmds, debug, "install")?;
    run_after_elevated_service_cmds(&exe, silent)?;
    Ok(())
}

pub fn run_after_install() -> ResultType<()> {
    let tools = WindowsSystemTools::resolve()?;
    let (_, exe) = fixed_service_install_dir_and_exe()?;
    run_cmds(
        get_after_install(&exe, None, None, &tools),
        true,
        "after_install",
    )
}

pub fn run_before_uninstall() -> ResultType<()> {
    let tools = WindowsSystemTools::resolve()?;
    run_cmds(get_before_uninstall(true, &tools), true, "before_install")
}

fn get_before_uninstall(kill_self: bool, tools: &WindowsSystemTools) -> String {
    let app_name = crate::get_app_name();
    let ext = app_name.to_lowercase();
    let filter = if kill_self {
        "".to_string()
    } else {
        format!(" /FI \"PID ne {}\"", get_current_pid())
    };
    let delete_service = delete_service_absent_ok(
        &tools.sc,
        &tools.timeout,
        &app_name,
        "rustdesk_service_deleted_before_uninstall",
    );
    let delete_hkcr_ext =
        delete_reg_key_absent_ok(&tools.reg, &format!("HKEY_CLASSES_ROOT\\.{ext}"));
    let delete_hkcr_protocol =
        delete_reg_key_absent_ok(&tools.reg, &format!("HKEY_CLASSES_ROOT\\{ext}"));
    let delete_firewall_rule =
        delete_firewall_rule_absent_ok(&tools.netsh, &format!("{app_name} Service"));
    format!(
        "
    {chcp} 65001
    {sc} stop \"{app_name}\" >nul 2>nul
    {taskkill} /F /IM {broker_exe}
    {taskkill} /F /IM {app_name}.exe{filter}
    {delete_service}
    {delete_hkcr_ext}
    {delete_hkcr_protocol}
    {delete_firewall_rule}
    ",
        chcp = tools.chcp,
        sc = tools.sc,
        taskkill = tools.taskkill,
        broker_exe = WIN_TOPMOST_INJECTED_PROCESS_EXE,
    )
}

/// Constructs the uninstall command string for the application.
///
/// # Parameters
/// - `kill_self`: The command will kill the process of current app name. If `true`, it will kill
///   the current process as well. If `false`, it will exclude the current process from the kill
///   command.
fn split_windows_command_tokens(command: &str) -> ResultType<Vec<String>> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut in_quotes = false;

    for ch in command.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            '\0' | '\r' | '\n' => bail!("MSI uninstall string contains a control character"),
            ch if ch.is_whitespace() && !in_quotes => {
                if !token.is_empty() {
                    tokens.push(std::mem::take(&mut token));
                }
            }
            ch => token.push(ch),
        }
    }

    if in_quotes {
        bail!("MSI uninstall string contains an unterminated quote");
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    Ok(tokens)
}

fn normalize_msi_product_code(value: &str) -> ResultType<String> {
    let value = value.trim();
    let bytes = value.as_bytes();
    if bytes.len() != 38 || bytes.first() != Some(&b'{') || bytes.last() != Some(&b'}') {
        bail!("MSI product code is not a braced GUID");
    }

    for (idx, byte) in bytes.iter().enumerate() {
        let valid = match idx {
            0 => *byte == b'{',
            37 => *byte == b'}',
            9 | 14 | 19 | 24 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        };
        if !valid {
            bail!("MSI product code is not a braced GUID");
        }
    }

    Ok(value.to_ascii_uppercase())
}

fn is_msiexec_token(token: &str, trusted_msiexec_path: &Path) -> bool {
    if token.eq_ignore_ascii_case("msiexec.exe") {
        return true;
    }
    let token = token.replace('/', "\\");
    let trusted = trusted_msiexec_path.to_string_lossy().replace('/', "\\");
    token.eq_ignore_ascii_case(&trusted)
}

fn take_prior_msi_product_code(slot: &mut Option<String>, raw: &str) -> ResultType<()> {
    let product_code = normalize_msi_product_code(raw)?;
    if slot.replace(product_code).is_some() {
        bail!("MSI uninstall string contains more than one product code");
    }
    Ok(())
}

fn prior_msi_uninstall_product_code(
    command: &str,
    trusted_msiexec_path: &Path,
) -> ResultType<String> {
    let tokens = split_windows_command_tokens(command)?;
    if tokens.is_empty() {
        bail!("MSI uninstall string is empty");
    }
    if !is_msiexec_token(&tokens[0], trusted_msiexec_path) {
        bail!("MSI uninstall string does not start with trusted msiexec.exe");
    }

    let mut product_code = None;
    let mut index = 1usize;
    while index < tokens.len() {
        let token = &tokens[index];
        let lower = token.to_ascii_lowercase();
        if lower == "/x" || lower == "-x" {
            index += 1;
            let Some(raw_product_code) = tokens.get(index) else {
                bail!("MSI uninstall flag is missing a product code");
            };
            take_prior_msi_product_code(&mut product_code, raw_product_code)?;
        } else if lower.starts_with("/x") || lower.starts_with("-x") {
            take_prior_msi_product_code(&mut product_code, &token[2..])?;
        } else if matches!(lower.as_str(), "/qn" | "/quiet" | "/norestart") {
            // Accepted only as inert legacy MSI UI flags; the command is reconstructed below.
        } else {
            bail!("MSI uninstall string contains unsupported arguments");
        }
        index += 1;
    }

    product_code.ok_or_else(|| anyhow!("MSI uninstall string has no product code"))
}

fn msi_product_name(product_code: &str) -> ResultType<String> {
    let product_code = null_terminated_wide(OsStr::new(product_code), "MSI product code")?;
    let mut len = 0u32;
    let query = unsafe {
        MsiGetProductInfoW(
            PCWSTR(product_code.as_ptr()),
            INSTALLPROPERTY_PRODUCTNAME,
            None,
            Some(&mut len),
        )
    };
    if query != ERROR_MORE_DATA && query != ERROR_SUCCESS {
        bail!("MsiGetProductInfoW(ProductName) failed before sizing: {query}");
    }
    let mut buffer = vec![0u16; len as usize + 1];
    let status = unsafe {
        MsiGetProductInfoW(
            PCWSTR(product_code.as_ptr()),
            INSTALLPROPERTY_PRODUCTNAME,
            Some(PWSTR(buffer.as_mut_ptr())),
            Some(&mut len),
        )
    };
    if status != ERROR_SUCCESS {
        bail!("MsiGetProductInfoW(ProductName) failed: {status}");
    }
    if len == 0 {
        bail!("MSI ProductName is empty");
    }
    Ok(OsString::from_wide(&buffer[..len as usize])
        .to_string_lossy()
        .into_owned())
}

fn trusted_prior_msi_uninstall_command(
    command: &str,
    tools: &WindowsSystemTools,
) -> ResultType<String> {
    let product_code = prior_msi_uninstall_product_code(command, &tools.msiexec_path)?;
    let product_name = msi_product_name(&product_code)?;
    let app_name = crate::get_app_name();
    if product_name != app_name {
        bail!(
            "Refusing prior MSI uninstall for product {product_code}: ProductName {product_name:?} does not match {app_name:?}"
        );
    }
    Ok(checked_msi_uninstall_command(format!(
        "{} /X {}",
        tools.msiexec, product_code
    )))
}

fn get_uninstall(kill_self: bool, tools: &WindowsSystemTools) -> ResultType<String> {
    let reg_uninstall_string = get_reg("UninstallString");
    if reg_uninstall_string.to_lowercase().contains("msiexec.exe") {
        return trusted_prior_msi_uninstall_command(&reg_uninstall_string, tools);
    }

    let exe = std::env::current_exe()
        .map_err(|err| anyhow!("Failed to resolve current exe for EXE uninstall helpers: {err}"))?;
    let uninstall_cert_cmd =
        checked_batch_cmd(format!("{} --uninstall-cert", quoted_batch_path(&exe)?));
    let uninstall_amyuni_idd = checked_batch_cmd(format!(
        "{} --uninstall-amyuni-idd",
        quoted_batch_path(&exe)?
    ));
    let subkey = get_uninstall_registry_subkey();
    let install_dir = fixed_service_install_dir_batch_path()?;
    let start_menu = quoted_batch_path(&common_programs_app_dir()?)?;
    let public_desktop_shortcut = quoted_batch_path(&public_desktop_app_shortcut_path()?)?;
    let startup_tray_shortcut = quoted_batch_path(&common_startup_tray_shortcut_path()?)?;
    let delete_uninstall_key = delete_reg_key_absent_ok(&tools.reg, &subkey);
    let remove_install_dir = delete_batch_path_absent_ok(
        format!("if exist {install_dir} rd /s /q {install_dir}"),
        &install_dir,
    );
    let remove_start_menu = delete_batch_path_absent_ok(
        format!("if exist {start_menu} rd /s /q {start_menu}"),
        &start_menu,
    );
    let remove_public_desktop_shortcut = delete_batch_path_absent_ok(
        format!("if exist {public_desktop_shortcut} del /f /q {public_desktop_shortcut}"),
        &public_desktop_shortcut,
    );
    let remove_startup_tray_shortcut = delete_batch_path_absent_ok(
        format!("if exist {startup_tray_shortcut} del /f /q {startup_tray_shortcut}"),
        &startup_tray_shortcut,
    );
    Ok(format!(
        "
    {before_uninstall}
    {uninstall_cert_cmd}
    {delete_uninstall_key}
    {uninstall_amyuni_idd}
    {remove_install_dir}
    {remove_start_menu}
    {remove_public_desktop_shortcut}
    {remove_startup_tray_shortcut}
    ",
        before_uninstall = get_before_uninstall(kill_self, tools),
    ))
}

pub fn uninstall_me(kill_self: bool) -> ResultType<()> {
    let tools = WindowsSystemTools::resolve()?;
    run_cmds(get_uninstall(kill_self, &tools)?, true, "uninstall")
}

struct InstallerCommandFile {
    path: PathBuf,
    file: Option<fs::File>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WindowsPathIdentity {
    volume_serial_number: u32,
    file_index_high: u32,
    file_index_low: u32,
}

impl InstallerCommandFile {
    fn path_str(&self) -> ResultType<&str> {
        self.path.to_str().ok_or_else(|| {
            anyhow!(
                "installer command file path is not valid UTF-8: {:?}",
                self.path
            )
        })
    }
}

fn installer_command_file_identity(file: &fs::File) -> ResultType<WindowsPathIdentity> {
    path_identity_from_handle(file.as_raw_handle() as HANDLE, "installer command file")
}

fn installer_command_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn reopen_verified_installer_command_file(
    path: &Path,
    expected_identity: WindowsPathIdentity,
    expected_digest: [u8; 32],
    expected_len: u64,
) -> ResultType<fs::File> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)?;
    let actual_identity = installer_command_file_identity(&file)?;
    if actual_identity != expected_identity {
        bail!(
            "installer command file identity changed before elevation: {:?}",
            path
        );
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if bytes.len() as u64 != expected_len || installer_command_digest(&bytes) != expected_digest {
        bail!(
            "installer command file content changed before elevation: {:?}",
            path
        );
    }
    Ok(file)
}

impl Drop for InstallerCommandFile {
    fn drop(&mut self) {
        self.file.take();
        allow_err!(fs::remove_file(&self.path));
    }
}

fn push_installer_command_dir(
    dirs: &mut Vec<PathBuf>,
    candidate: ResultType<PathBuf>,
    label: &str,
) {
    if let Ok(dir) = candidate.and_then(|dir| {
        batch_path_text(&dir, label)?;
        Ok(dir)
    }) {
        if !dirs.iter().any(|existing| existing == &dir) {
            dirs.push(dir);
        }
    }
}

fn installer_command_dirs() -> ResultType<Vec<PathBuf>> {
    let mut dirs = Vec::new();
    let tmp = std::env::temp_dir();
    push_installer_command_dir(&mut dirs, Ok(tmp), "installer command temp directory");
    push_installer_command_dir(
        &mut dirs,
        program_data_dir(),
        "installer command ProgramData directory",
    );
    push_installer_command_dir(
        &mut dirs,
        user_accessible_folder(),
        "installer command user-accessible directory",
    );
    if dirs.is_empty() {
        bail!("no safe installer command directory is available");
    }
    Ok(dirs)
}

fn create_installer_command_file(ext: &str, tip: &str) -> ResultType<InstallerCommandFile> {
    let mut create_errors = Vec::new();
    for dir in installer_command_dirs()? {
        let mut exhausted_names = true;
        for _ in 0..16 {
            let path = dir.join(format!(
                "{}_{}_{}.{}",
                crate::get_app_name(),
                tip,
                uuid::Uuid::new_v4(),
                ext
            ));
            batch_path_text(&path, "installer command file path")?;
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_ATTRIBUTE_TEMPORARY)
                .open(&path)
            {
                Ok(file) => {
                    return Ok(InstallerCommandFile {
                        path,
                        file: Some(file),
                    });
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    exhausted_names = false;
                    create_errors.push(format!("{}: {err}", dir.display()));
                    break;
                }
            }
        }
        if exhausted_names {
            create_errors.push(format!(
                "{}: generated installer command names already exist",
                dir.display()
            ));
        }
    }
    bail!(
        "failed to create an installer command file: {}",
        create_errors.join("; ")
    )
}

fn write_cmds(cmds: String, ext: &str, tip: &str) -> ResultType<InstallerCommandFile> {
    let mut cmds = cmds;
    let mut command_file = create_installer_command_file(ext, tip)?;
    if ext == "bat" {
        let tmp2 = get_undone_file(&command_file.path)?;
        let tmp2_quoted = quoted_batch_path(&tmp2)?;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp2)?;
        cmds = format!(
            "
{cmds}
if exist {path} del /f /q {path}
",
            path = tmp2_quoted
        );
    }
    // in case cmds mixed with \r\n and \n, make sure all ending with \r\n
    // in some windows, \r\n required for cmd file to run
    cmds = cmds.replace("\r\n", "\n").replace("\n", "\r\n");
    let command_bytes = if ext == "vbs" {
        let mut v: Vec<u16> = cmds.encode_utf16().collect();
        // utf8 -> utf16le which vbs support it only
        to_le(&mut v).to_vec()
    } else {
        cmds.as_bytes().to_vec()
    };
    let file = command_file
        .file
        .as_mut()
        .ok_or_else(|| anyhow!("installer command file closed before write"))?;
    file.write_all(&command_bytes)?;
    file.sync_all()?;
    let identity = installer_command_file_identity(file)?;
    let digest = installer_command_digest(&command_bytes);
    let len = command_bytes.len() as u64;
    command_file.file.take();
    command_file.file = Some(reopen_verified_installer_command_file(
        &command_file.path,
        identity,
        digest,
        len,
    )?);
    Ok(command_file)
}

fn installer_script_literal(value: &str, label: &str) -> ResultType<String> {
    if value.contains('"') || value.contains('\r') || value.contains('\n') {
        bail!("{label} contains characters unsafe for an installer script literal");
    }
    Ok(value.to_owned())
}

fn installer_path_literal(path: &Path, label: &str) -> ResultType<String> {
    let text = path
        .to_str()
        .ok_or_else(|| anyhow!("{label} is not valid UTF-8: {:?}", path))?;
    installer_script_literal(text, label)
}

fn shortcut_icon_assignment(install_dir: &str, exe: &str) -> ResultType<String> {
    if exe.is_empty() {
        return Ok(String::new());
    }
    let Some(icon_path) = get_custom_icon(install_dir, exe) else {
        return Ok(String::new());
    };
    let icon_path = installer_script_literal(&icon_path, "shortcut icon path")?;
    Ok(format!("    oLink.IconLocation = \"{icon_path}\""))
}

fn create_shortcut_command_file(
    shortcut_path: &Path,
    target_path: &str,
    arguments: Option<&str>,
    explicit_icon: Option<&str>,
    icon_install_dir: &str,
    icon_source_exe: &str,
    tip: &str,
) -> ResultType<InstallerCommandFile> {
    let shortcut_path = installer_path_literal(shortcut_path, "shortcut path")?;
    let target_path = installer_script_literal(target_path, "shortcut target path")?;
    let arguments = match arguments {
        Some(arguments) if !arguments.is_empty() => {
            let arguments = installer_script_literal(arguments, "shortcut arguments")?;
            format!("    oLink.Arguments = \"{arguments}\"")
        }
        _ => String::new(),
    };
    let shortcut_icon_location = if let Some(icon_path) = explicit_icon {
        let icon_path = installer_script_literal(icon_path, "shortcut icon path")?;
        format!("    oLink.IconLocation = \"{icon_path}\"")
    } else {
        shortcut_icon_assignment(icon_install_dir, icon_source_exe)?
    };
    write_cmds(
        format!(
            "
Set oWS = WScript.CreateObject(\"WScript.Shell\")
sLinkFile = \"{shortcut_path}\"
Set oLink = oWS.CreateShortcut(sLinkFile)
    oLink.TargetPath = \"{target_path}\"
{arguments}
{shortcut_icon_location}
oLink.Save
        "
        ),
        "vbs",
        tip,
    )
}

fn run_shortcut_script_cmd(
    script_path: &str,
    shortcut_path: &Path,
    tools: &WindowsSystemTools,
) -> ResultType<String> {
    batch_literal_text(script_path, "shortcut script path")?;
    let shortcut_path = quoted_batch_path(shortcut_path)?;
    Ok(format!(
        "
{}
{}
",
        checked_batch_cmd(format!("{} //NoLogo \"{script_path}\"", tools.cscript)),
        require_batch_path_exists(&shortcut_path),
    ))
}

fn to_le(v: &mut [u16]) -> &[u8] {
    for b in v.iter_mut() {
        *b = b.to_le()
    }
    unsafe { v.align_to().1 }
}

fn get_undone_file(tmp: &Path) -> ResultType<PathBuf> {
    Ok(tmp.with_file_name(format!(
        "{}.undone",
        tmp.file_name()
            .ok_or(anyhow!("Failed to get filename of {:?}", tmp))?
            .to_string_lossy()
    )))
}

fn run_cmds(cmds: String, show: bool, tip: &str) -> ResultType<()> {
    let tmp = write_cmds(cmds, "bat", tip)?;
    let tmp2 = get_undone_file(&tmp.path)?;
    let tmp_fn = batch_path_text(&tmp.path, "installer command file path")?;
    let cmd = trusted_system_cmd_path()?;
    let already_elevated = match is_elevated(None) {
        Ok(elevated) => elevated,
        Err(err) => {
            log::warn!("Failed to determine installer command elevation state: {err}");
            false
        }
    };
    let status = if already_elevated {
        let mut command = std::process::Command::new(&cmd);
        command.args(["/D", "/V:OFF", "/S", "/C", tmp_fn.as_str()]);
        if !show {
            command.creation_flags(CREATE_NO_WINDOW);
        }
        command.status()?
    } else {
        runas::Command::new(cmd)
            .args(&["/D", "/V:OFF", "/S", "/C", tmp_fn.as_str()])
            .show(show)
            .force_prompt(true)
            .status()?
    };
    let marker_left = tmp2.exists();
    if marker_left {
        allow_err!(std::fs::remove_file(tmp2));
    }
    if !status.success() || marker_left {
        bail!(
            "{} failed: elevated command status {}, completion marker {}",
            tip,
            status,
            if marker_left {
                "left behind"
            } else {
                "cleared"
            }
        );
    }
    Ok(())
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
    let (_, _, exe) = get_install_info();
    std::fs::metadata(exe).is_ok()
}

pub fn get_reg(name: &str) -> String {
    let subkey = get_uninstall_registry_subkey();
    get_reg_of(&subkey, name)
}

fn get_reg_of(subkey: &str, name: &str) -> String {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(tmp) = hklm.open_subkey(subkey.replace("HKEY_LOCAL_MACHINE\\", "")) {
        if let Ok(v) = tmp.get_value(name) {
            return v;
        }
    }
    "".to_owned()
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

pub fn enable_lowlevel_keyboard(hwnd: HWND) {
    let ret = unsafe { win32_enable_lowlevel_keyboard(hwnd) };
    if ret != 0 {
        log::error!("Failure grabbing keyboard");
        return;
    }
}

pub fn disable_lowlevel_keyboard(hwnd: HWND) {
    unsafe { win32_disable_lowlevel_keyboard(hwnd) };
}

pub fn stop_system_key_propagate(v: bool) {
    unsafe { win_stop_system_key_propagate(if v { TRUE } else { FALSE }) };
}

pub fn get_win_key_state() -> bool {
    unsafe { is_win_down() == TRUE }
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

pub fn run_background(exe: &str, arg: &str) -> ResultType<bool> {
    let wexe = wide_string(exe);
    let warg;
    unsafe {
        let ret = ShellExecuteW(
            NULL as _,
            NULL as _,
            wexe.as_ptr() as _,
            if arg.is_empty() {
                NULL as _
            } else {
                warg = wide_string(arg);
                warg.as_ptr() as _
            },
            NULL as _,
            SW_HIDE,
        );
        return Ok(ret as i32 > 32);
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

pub fn get_process_executable_path(process_id: DWORD) -> ResultType<PathBuf> {
    const PROCESS_IMAGE_PATH_BUFFER_LEN: usize = 32 * 1024;
    unsafe {
        let process = WinOpenProcess(WIN_PROCESS_QUERY_LIMITED_INFORMATION, false, process_id)
            .map_err(|e| anyhow!("Failed to open process {}: {}", process_id, e))?;

        let result = (|| -> ResultType<PathBuf> {
            let mut buffer = vec![0u16; PROCESS_IMAGE_PATH_BUFFER_LEN];
            let mut length = PROCESS_IMAGE_PATH_BUFFER_LEN as u32;
            WinQueryFullProcessImageNameW(
                process,
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
            Ok(PathBuf::from(OsString::from_wide(&buffer)))
        })();

        let _ = WinCloseHandle(process);
        result
    }
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

// Ensure the token returned is a primary token.
// If the provided token is an impersonation token, it duplicates it to a primary token.
// If the provided token is already a primary token, it returns it as is.
// The caller is responsible for closing the returned token handle.
pub fn ensure_primary_token(user_token: HANDLE) -> ResultType<HANDLE> {
    if user_token.is_null() || user_token == INVALID_HANDLE_VALUE {
        bail!("Invalid user token provided");
    }

    unsafe {
        let mut token_type: TOKEN_TYPE = 0;
        let mut return_length: DWORD = 0;

        if GetTokenInformation(
            user_token,
            TokenType,
            &mut token_type as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_TYPE>() as DWORD,
            &mut return_length,
        ) == FALSE
        {
            bail!(
                "Failed to get token type, error {}",
                io::Error::last_os_error()
            );
        }

        if token_type == TokenImpersonation {
            let mut duplicate_token: HANDLE = std::ptr::null_mut();
            let dup_res = DuplicateToken(user_token, SecurityImpersonation, &mut duplicate_token);
            CloseHandle(user_token);
            if dup_res == FALSE {
                bail!(
                    "Failed to duplicate token, error {}",
                    io::Error::last_os_error()
                );
            }
            Ok(duplicate_token)
        } else {
            Ok(user_token)
        }
    }
}

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
pub fn uninstall_cert() -> ResultType<()> {
    cert::uninstall_cert()
}

mod cert {
    use hbb_common::{anyhow::anyhow, ResultType};
    use winapi::shared::minwindef::BOOL;

    extern "C" {
        fn DeleteRustDeskTestCertsW() -> BOOL;
    }
    pub fn uninstall_cert() -> ResultType<()> {
        if unsafe { DeleteRustDeskTestCertsW() } == 0 {
            return Err(anyhow!("Failed to delete RustDesk test certificates"));
        }
        Ok(())
    }
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

fn pids_by_exact_process_name(name: &str) -> ResultType<Vec<u32>> {
    if name.is_empty() {
        bail!("empty process name");
    }

    let mut pids = Vec::new();
    unsafe {
        let snapshot = WinHandleGuard::new(
            CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                .map_err(|e| anyhow!("Failed to create process snapshot: {}", e))?,
        )?;

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot.get(), &mut entry).is_ok() {
            loop {
                if process_entry_image_name(&entry).eq_ignore_ascii_case(name) {
                    pids.push(entry.th32ProcessID);
                }
                if !Process32NextW(snapshot.get(), &mut entry).is_ok() {
                    break;
                }
            }
        }
    }

    Ok(pids)
}

fn terminate_processes_by_exact_process_name(name: &str) -> ResultType<usize> {
    let pids = pids_by_exact_process_name(name)?;
    let mut terminated = 0usize;

    for pid in pids {
        let result = unsafe {
            let process = WinOpenProcess(WIN_PROCESS_TERMINATE, false, pid)
                .map_err(|e| anyhow!("Failed to open process {} for termination: {}", pid, e))
                .and_then(|handle| WinHandleGuard::new(handle))?;
            WinTerminateProcess(process.get(), 0)
                .map_err(|e| anyhow!("Failed to terminate process {}: {}", pid, e))
        };

        match result {
            Ok(()) => terminated += 1,
            Err(err) => log::warn!("Failed to terminate {} pid {}: {}", name, pid, err),
        }
    }

    Ok(terminated)
}

pub fn is_process_consent_running() -> ResultType<bool> {
    Ok(!pids_by_exact_process_name("consent.exe")?.is_empty())
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

pub fn uninstall_service(show_new_window: bool, _: bool) -> bool {
    log::info!("Uninstalling service...");
    let tools = match WindowsSystemTools::resolve() {
        Ok(tools) => tools,
        Err(err) => {
            log::error!("Failed to resolve Windows system tools: {err}");
            return false;
        }
    };
    let (_, exe) = match fixed_service_install_dir_and_exe() {
        Ok(info) => info,
        Err(err) => {
            log::error!("Failed to resolve fixed Windows service executable: {err}");
            return false;
        }
    };
    let filter = format!(" /FI \"PID ne {}\"", get_current_pid());
    let startup_tray_shortcut =
        match common_startup_tray_shortcut_path().and_then(|path| quoted_batch_path(&path)) {
            Ok(path) => path,
            Err(err) => {
                log::error!("Failed to resolve common startup shortcut path: {err}");
                return false;
            }
        };
    let app_name = crate::get_app_name();
    let delete_service = delete_service_absent_ok(
        &tools.sc,
        &tools.timeout,
        &app_name,
        "rustdesk_service_deleted_service_uninstall",
    );
    let remove_startup_tray_shortcut = delete_batch_path_absent_ok(
        format!("if exist {startup_tray_shortcut} del /f /q {startup_tray_shortcut}"),
        &startup_tray_shortcut,
    );
    let cmds = format!(
        "
    {chcp} 65001
    {sc} stop \"{app_name}\" >nul 2>nul
    {taskkill} /F /IM {broker_exe}
    {taskkill} /F /IM {app_name}.exe{filter}
    {delete_service}
    {remove_startup_tray_shortcut}
    ",
        chcp = tools.chcp,
        sc = tools.sc,
        taskkill = tools.taskkill,
        broker_exe = WIN_TOPMOST_INJECTED_PROCESS_EXE,
    );
    if let Err(err) = run_cmds(cmds, false, "uninstall") {
        log::error!("{err}");
        return false;
    }
    if let Err(err) = run_after_elevated_service_cmds(&exe, !show_new_window) {
        log::error!("{err}");
        return false;
    }
    std::process::exit(0);
}

pub fn install_service() -> bool {
    log::info!("Installing service...");
    let tools = match WindowsSystemTools::resolve() {
        Ok(tools) => tools,
        Err(err) => {
            log::error!("Failed to resolve Windows system tools: {err}");
            return false;
        }
    };
    let _installing = crate::platform::InstallingService::new();
    let (path, exe) = match fixed_service_install_dir_and_exe() {
        Ok(info) => info,
        Err(err) => {
            log::error!("Failed to resolve fixed Windows service install path: {err}");
            return false;
        }
    };
    if !Path::new(&exe).exists() {
        log::error!("Fixed Windows service executable does not exist: {exe}");
        return false;
    }
    let tray_shortcut_path = match common_startup_tray_shortcut_path() {
        Ok(path) => path,
        Err(err) => {
            log::error!("Failed to resolve common startup shortcut path: {err}");
            return false;
        }
    };
    let tray_shortcut = match create_shortcut_command_file(
        &tray_shortcut_path,
        &exe,
        Some("--tray"),
        None,
        &path,
        &exe,
        "tray_shortcut",
    ) {
        Ok(shortcut) => shortcut,
        Err(err) => {
            log::error!("Failed to create tray shortcut command file: {err}");
            return false;
        }
    };
    let tray_shortcut_command_path = match tray_shortcut.path_str() {
        Ok(path) => path.to_owned(),
        Err(err) => {
            log::error!("Failed to resolve tray shortcut command path: {err}");
            return false;
        }
    };
    let run_tray_shortcut =
        match run_shortcut_script_cmd(&tray_shortcut_command_path, &tray_shortcut_path, &tools) {
            Ok(cmd) => cmd,
            Err(err) => {
                log::error!("Failed to prepare tray shortcut command: {err}");
                return false;
            }
        };
    let filter = format!(" /FI \"PID ne {}\"", get_current_pid());
    crate::ipc::EXIT_RECV_CLOSE.store(false, Ordering::Relaxed);
    let cmds = format!(
        "
			{chcp} 65001
			{taskkill} /F /IM {app_name}.exe{filter}
			{run_tray_shortcut}
			{import_config}
			{create_service}
			    ",
        chcp = tools.chcp,
        taskkill = tools.taskkill,
        app_name = crate::get_app_name(),
        import_config = get_import_config(&exe),
        create_service = get_create_service(&exe, &tools),
    );
    if let Err(err) = run_cmds(cmds, false, "install") {
        crate::ipc::EXIT_RECV_CLOSE.store(true, Ordering::Relaxed);
        log::error!("{err}");
        return false;
    }
    if let Err(err) = run_after_elevated_service_cmds(&exe, false) {
        log::error!("{err}");
        return false;
    }
    std::process::exit(0);
}

/// Calculate the total size of a directory in KB
/// Does not follow symlinks to prevent directory traversal attacks.
fn get_directory_size_kb(path: &str) -> u64 {
    let mut total_size = 0u64;
    let mut stack = vec![PathBuf::from(path)];

    while let Some(current_path) = stack.pop() {
        let entries = match std::fs::read_dir(&current_path) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };

            let metadata = match std::fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };

            if metadata.is_symlink() {
                continue;
            }

            if metadata.is_dir() {
                stack.push(entry.path());
            } else {
                total_size = total_size.saturating_add(metadata.len());
            }
        }
    }

    total_size / 1024
}

// R-X1 / R-SV2 / R-A6 (§18): the Windows self-updater cluster — update_me,
// update_to, update_me_msi, and the updater-only helpers get_reg_msi_key /
// kill_process_by_pids (the run_uac "--update" MSI re-install) — is excised,
// not disabled. The fork ships signed releases (§12); there is no fetch-and-run path.
fn get_import_config(_exe: &str) -> String {
    // R-X4: `--import-config` is excised from core_main (its arg-arm overwrote the entire config —
    // trust anchor + servers — from an attacker-suppliable file). The upstream installer's
    // service-recreation dance that ran `rustdesk --import-config <path>` is therefore a no-op, so it
    // is dropped here entirely — carrying no such literal into the shipped installer.
    String::new()
}

fn get_create_service(exe: &str, tools: &WindowsSystemTools) -> String {
    if config::is_outgoing_only() {
        return "".to_string();
    }
    // R-X9: the installed service is ALWAYS created + auto-start; the runtime-writable stop-service
    // toggle that could suppress it (a local --option/IPC write) is excised — the key stays pinned
    // "N" in PINNED_SETTINGS (R-S16) and is not IPC-writable (R-S11).
    //
    // T1 / BR-9..BR-12 (Windows service resilience): `sc create ... start= auto` restarts the
    // `--service` only at BOOT, so a mid-session crash / `panic='abort'` / elevated kill of the
    // `--service` left the box PERMANENTLY unreachable — the direct listener died with no supervisor
    // to relaunch it (the cavity-1 wedge), whereas Linux systemd (`Restart=on-failure`) and macOS
    // launchd (`KeepAlive`) already self-heal the same fault. `sc failure` configures the SCM's OWN
    // recovery actions so the OS service manager restarts the service on unexpected termination —
    // exact PARITY with systemd/launchd, and R-X9/R-X10-clean: the OS supervisor restarts ITS OWN
    // service (no new privilege transition, no GUI/in-process self-restart, no self-escalation; the
    // single installed-service privilege model is unchanged). With the default failure flag
    // (SERVICE_CONFIG_FAILURE_ACTIONS_FLAG = 0, guaranteed on a fresh `sc create`) the actions fire
    // ONLY when the process terminates WITHOUT reporting SERVICE_STOPPED — a crash / abort / Task-
    // Manager kill — and NOT on a clean `sc stop` / services.msc stop (which reports SERVICE_STOPPED
    // with exit 0), so a DELIBERATE stop stays stopped (recover from a fault, never fight the
    // operator). Backoff 5s/10s/30s and then 30s forever (SCM repeats the last action, never gives
    // up → "always recover", the N3 twin of the systemd start-limit fix); the failure counter resets
    // after a day of uptime so a genuine one-off does not inherit a stale 30s delay.
    format!("
		if not exist \"{exe}\" exit /b 1
		{sc} create {app_name} binpath= \"\\\"{exe}\\\" --service\" start= auto DisplayName= \"{app_name} Service\"
		if errorlevel 1 exit /b 1
		{sc} failure {app_name} reset= 86400 actions= restart/5000/restart/10000/restart/30000
		if errorlevel 1 exit /b 1
		{sc} start {app_name}
		if errorlevel 1 exit /b 1
		",
    sc = tools.sc,
    app_name = crate::get_app_name())
}

fn run_after_elevated_service_cmds(installed_exe: &str, silent: bool) -> ResultType<()> {
    let (_, fixed_exe) = fixed_service_install_dir_and_exe()?;
    if normalized_windows_path_text(Path::new(installed_exe))
        != normalized_windows_path_text(Path::new(&fixed_exe))
    {
        bail!("post-service command executable is not the fixed installed executable");
    }

    let exe = Path::new(installed_exe);
    if !exe.is_file() {
        bail!("fixed installed executable is missing: {installed_exe}");
    }

    if !silent {
        log::debug!("Spawn new window");
        std::process::Command::new(exe).spawn()?;
    }
    // R-X9: the stop-service toggle is excised — the tray (re)spawns with the always-present service.
    std::process::Command::new(exe).arg("--tray").spawn()?;
    std::thread::sleep(std::time::Duration::from_millis(300));
    Ok(())
}

#[inline]
pub fn try_remove_temp_update_files() {
    let temp_dir = std::env::temp_dir();
    let Ok(entries) = std::fs::read_dir(&temp_dir) else {
        log::debug!("Failed to read temp directory: {:?}", temp_dir);
        return;
    };

    let one_hour = std::time::Duration::from_secs(60 * 60);
    for entry in entries {
        if let Ok(entry) = entry {
            let path = entry.path();
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                // Match files like rustdesk-*.msi or rustdesk-*.exe
                if file_name.starts_with("rustdesk-")
                    && (file_name.ends_with(".msi") || file_name.ends_with(".exe"))
                {
                    // Skip files modified within the last hour to avoid deleting files being downloaded
                    if let Ok(metadata) = std::fs::metadata(&path) {
                        if let Ok(modified) = metadata.modified() {
                            if let Ok(elapsed) = modified.elapsed() {
                                if elapsed < one_hour {
                                    continue;
                                }
                            }
                        }
                    }
                    if let Err(e) = std::fs::remove_file(&path) {
                        log::debug!("Failed to remove temp update file {:?}: {}", path, e);
                    } else {
                        log::info!("Removed temp update file: {:?}", path);
                    }
                }
            }
        }
    }
}

#[inline]
pub fn try_kill_broker() {
    match terminate_processes_by_exact_process_name(WIN_TOPMOST_INJECTED_PROCESS_EXE) {
        Ok(0) => {}
        Ok(count) => log::info!(
            "Terminated {} stale {} process(es)",
            count,
            WIN_TOPMOST_INJECTED_PROCESS_EXE
        ),
        Err(err) => log::warn!(
            "Failed to enumerate stale {} processes: {}",
            WIN_TOPMOST_INJECTED_PROCESS_EXE,
            err
        ),
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

pub mod reg_display_settings {
    use hbb_common::ResultType;
    use serde_derive::{Deserialize, Serialize};
    use std::collections::HashMap;
    use winreg::{enums::*, RegValue};
    const REG_GRAPHICS_DRIVERS_PATH: &str = "SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers";
    const REG_CONNECTIVITY_PATH: &str = "Connectivity";

    #[derive(Serialize, Deserialize, Debug)]
    pub struct RegRecovery {
        path: String,
        key: String,
        old: (Vec<u8>, isize),
        new: (Vec<u8>, isize),
    }

    pub fn read_reg_connectivity() -> ResultType<HashMap<String, HashMap<String, RegValue>>> {
        let hklm = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
        let reg_connectivity = hklm.open_subkey_with_flags(
            format!("{}\\{}", REG_GRAPHICS_DRIVERS_PATH, REG_CONNECTIVITY_PATH),
            KEY_READ,
        )?;

        let mut map_connectivity = HashMap::new();
        for key in reg_connectivity.enum_keys() {
            let key = key?;
            let mut map_item = HashMap::new();
            let reg_item = reg_connectivity.open_subkey_with_flags(&key, KEY_READ)?;
            for value in reg_item.enum_values() {
                let (name, value) = value?;
                map_item.insert(name, value);
            }
            map_connectivity.insert(key, map_item);
        }
        Ok(map_connectivity)
    }

    pub fn diff_recent_connectivity(
        map1: HashMap<String, HashMap<String, RegValue>>,
        map2: HashMap<String, HashMap<String, RegValue>>,
    ) -> Option<RegRecovery> {
        for (subkey, map_item2) in map2 {
            if let Some(map_item1) = map1.get(&subkey) {
                let key = "Recent";
                if let Some(value1) = map_item1.get(key) {
                    if let Some(value2) = map_item2.get(key) {
                        if value1 != value2 {
                            return Some(RegRecovery {
                                path: format!(
                                    "{}\\{}\\{}",
                                    REG_GRAPHICS_DRIVERS_PATH, REG_CONNECTIVITY_PATH, subkey
                                ),
                                key: key.to_owned(),
                                old: (value1.bytes.clone(), value1.vtype.clone() as isize),
                                new: (value2.bytes.clone(), value2.vtype.clone() as isize),
                            });
                        }
                    }
                }
            }
        }
        None
    }

    pub fn restore_reg_connectivity(reg_recovery: RegRecovery, force: bool) -> ResultType<()> {
        let hklm = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
        let reg_item = hklm.open_subkey_with_flags(&reg_recovery.path, KEY_READ | KEY_WRITE)?;
        if !force {
            let cur_reg_value = reg_item.get_raw_value(&reg_recovery.key)?;
            let new_reg_value = RegValue {
                bytes: reg_recovery.new.0,
                vtype: isize_to_reg_type(reg_recovery.new.1),
            };
            // Compare if the current value is the same as the new value.
            // If they are not the same, the registry value has been changed by other processes.
            // So we do not restore the registry value.
            if cur_reg_value != new_reg_value {
                return Ok(());
            }
        }
        let reg_value = RegValue {
            bytes: reg_recovery.old.0,
            vtype: isize_to_reg_type(reg_recovery.old.1),
        };
        reg_item.set_raw_value(&reg_recovery.key, &reg_value)?;
        Ok(())
    }

    #[inline]
    fn isize_to_reg_type(i: isize) -> RegType {
        match i {
            0 => RegType::REG_NONE,
            1 => RegType::REG_SZ,
            2 => RegType::REG_EXPAND_SZ,
            3 => RegType::REG_BINARY,
            4 => RegType::REG_DWORD,
            5 => RegType::REG_DWORD_BIG_ENDIAN,
            6 => RegType::REG_LINK,
            7 => RegType::REG_MULTI_SZ,
            8 => RegType::REG_RESOURCE_LIST,
            9 => RegType::REG_FULL_RESOURCE_DESCRIPTOR,
            10 => RegType::REG_RESOURCE_REQUIREMENTS_LIST,
            11 => RegType::REG_QWORD,
            _ => RegType::REG_NONE,
        }
    }
}

fn get_pids<S: AsRef<str>>(name: S) -> ResultType<Vec<u32>> {
    let name = name.as_ref().to_lowercase();
    let mut pids = Vec::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
        if snapshot == WinHANDLE::default() {
            return Ok(pids);
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let proc_name = OsString::from_wide(&entry.szExeFile)
                    .to_string_lossy()
                    .to_lowercase();

                if proc_name.contains(&name) {
                    pids.push(entry.th32ProcessID);
                }

                if !Process32NextW(snapshot, &mut entry).is_ok() {
                    break;
                }
            }
        }

        let _ = WinCloseHandle(snapshot);
    }

    Ok(pids)
}

pub fn is_msi_installed() -> std::io::Result<bool> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let uninstall_key = hklm.open_subkey(format!(
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{}",
        crate::get_app_name()
    ))?;
    Ok(1 == uninstall_key.get_value::<u32, _>("WindowsInstaller")?)
}

pub fn is_cur_exe_the_installed() -> bool {
    let (_, _, exe) = get_install_info();
    // Check if is installed, because `exe` is the default path if is not installed.
    if !std::fs::metadata(&exe).is_ok() {
        return false;
    }
    let mut path = std::env::current_exe().unwrap_or_default();
    if let Ok(linked) = path.read_link() {
        path = linked;
    }
    let path = path.to_string_lossy().to_lowercase();
    path == exe.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r_s11d32_installer_command_digest_is_byte_exact() {
        let first = installer_command_digest(b"echo one\r\n");
        let same = installer_command_digest(b"echo one\r\n");
        let second = installer_command_digest(b"echo one\n");
        assert_eq!(first, same);
        assert_ne!(first, second);
    }

    #[test]
    fn r_s11d32_installer_command_identity_compares_volume_and_index() {
        let baseline = WindowsPathIdentity {
            volume_serial_number: 1,
            file_index_high: 2,
            file_index_low: 3,
        };
        assert_eq!(baseline, baseline);
        assert_ne!(
            baseline,
            WindowsPathIdentity {
                volume_serial_number: 9,
                ..baseline
            }
        );
        assert_ne!(
            baseline,
            WindowsPathIdentity {
                file_index_high: 9,
                ..baseline
            }
        );
        assert_ne!(
            baseline,
            WindowsPathIdentity {
                file_index_low: 9,
                ..baseline
            }
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
    fn test_uninstall_cert() {
        println!("uninstall driver certs: {:?}", cert::uninstall_cert());
    }

    #[test]
    fn test_get_unicode_char_by_vk() {
        let chr = get_char_from_vk(0x41); // VK_A
        assert_eq!(chr, Some('a'));
        let chr = get_char_from_vk(VK_ESCAPE as u32); // VK_ESC
        assert_eq!(chr, None)
    }
}
