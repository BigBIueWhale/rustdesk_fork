use super::{CursorData, ResultType};
use desktop::Desktop;
pub use hbb_common::platform::linux::*;
use hbb_common::{
    allow_err,
    anyhow::anyhow,
    bail,
    config::{keys::OPTION_ALLOW_LINUX_HEADLESS, Config},
    libc::{c_char, c_int, c_long, c_uint, c_ulong, c_void},
    log,
    message_proto::{DisplayInfo, Resolution},
    regex::{Captures, Regex},
    users::{get_user_by_name, os::unix::UserExt},
};
use libxdo_sys::{self, xdo_t, Window};
use std::{
    cell::RefCell,
    ffi::OsStr,
    fs::{self, File},
    io::{Read as _, Write as _},
    os::{
        fd::{AsRawFd as _, FromRawFd as _},
        unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::{Component, Path, PathBuf},
    process::{Child, Command},
    string::String,
    sync::atomic::{AtomicBool, Ordering},
    sync::{mpsc, Arc, OnceLock},
    time::{Duration, Instant},
};
use wallpaper;

pub const PA_SAMPLE_RATE: u32 = 48000;
static mut UNMODIFIED: bool = true;

#[derive(Clone, Debug)]
struct ActiveUserLookupCache {
    uid: String,
    username: String,
}

const SERVICE_CHILD_GRACEFUL_STOP_TIMEOUT: Duration = Duration::from_secs(8);
const SERVICE_CHILD_FORCED_STOP_TIMEOUT: Duration = Duration::from_secs(8);
const SERVICE_IPC_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const SERVICE_CHILD_RECORD_MAX_BYTES: usize = 1024;
const SERVICE_CHILD_RECORD_ROLE: &str = "--server+--service-owned-server";
const SERVICE_RUNTIME_DIR: &[u8] = b"/run/rustdesk\0";
const SERVICE_RUNTIME_LOCK: &[u8] = b"service-supervisor.lock\0";
const SERVICE_CHILD_RECORD: &[u8] = b"service-child.record\0";
const SERVICE_CHILD_RECORD_TMP: &[u8] = b"service-child.record.tmp\0";
const SERVICE_CHILD_BOOTSTRAP_READY: u8 = 0xa7;
const SERVICE_CHILD_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(10);
const XRANDR_PATHS: [&str; 2] = ["/usr/bin/xrandr", "/bin/xrandr"];
const LINUX_INSTALLED_EXECUTABLE_PATHS: [&str; 2] =
    ["/usr/share/rustdesk/rustdesk", "/usr/bin/rustdesk"];
const LINUX_INSTALLED_SERVICE_CHILD_EXECUTABLE: &str = "/usr/share/rustdesk/rustdesk-service-child";
pub const REOPEN_AFTER_SERVICE_STOP_ARG: &str = "--reopen-after-service-stop";

const PROC_SNAPSHOT_MAX_NUMERIC_ENTRIES: usize = 16_384;
const PROC_SNAPSHOT_MAX_SELECTED_PROCESSES: usize = 2_048;
const PROC_SNAPSHOT_MAX_ENVIRONMENT_CANDIDATES: usize = 64;
const PROC_SNAPSHOT_MAX_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const PROC_CMDLINE_MAX_BYTES: usize = 16 * 1024;
const PROC_CMDLINE_MAX_ARGS: usize = 256;
const PROC_CGROUP_MAX_BYTES: usize = 16 * 1024;
const PROC_ENVIRON_MAX_BYTES: usize = 64 * 1024;
const PROC_ENV_VALUE_MAX_BYTES: usize = 4 * 1024;
const X11_SOCKET_DIRECTORY: &str = "/tmp/.X11-unix";
const X11_SOCKET_MAX_CANDIDATES: usize = 64;
const X11_SOCKET_CONNECT_TIMEOUT_MS: c_int = 25;
const X11_SOCKET_DISCOVERY_TIMEOUT: Duration = Duration::from_millis(500);
// Linux UAPI asm-generic/socket.h. Kernels before SO_PEERPIDFD fail closed here.
const LINUX_SO_PEERPIDFD: c_int = 77;

static SERVICE_RUNTIME_GENERATION: OnceLock<String> = OnceLock::new();
static SERVICE_CHILD_EXECUTABLE_IDENTITY: OnceLock<std::sync::RwLock<Option<(u64, u64)>>> =
    OnceLock::new();

// Terminal type constants
const TERM_XTERM_256COLOR: &str = "xterm-256color";
const TERM_XTERM: &str = "xterm";
const SERVICE_XTERM_256COLOR_PATHS: [&str; 6] = [
    "/etc/terminfo/x/xterm-256color",
    "/etc/terminfo/78/xterm-256color",
    "/lib/terminfo/x/xterm-256color",
    "/lib/terminfo/78/xterm-256color",
    "/usr/share/terminfo/x/xterm-256color",
    "/usr/share/terminfo/78/xterm-256color",
];

lazy_static::lazy_static! {
    // R-X12: IS_X11 removed — is_x11() is compile-pinned `true` (no runtime detection cache).
    static ref ACTIVE_USER_LOOKUP_CACHE: std::sync::Mutex<Option<ActiveUserLookupCache>> =
        std::sync::Mutex::new(None);
}

#[inline]
fn update_active_user_lookup_cache(desktop: &Desktop) {
    if let Ok(mut cache) = ACTIVE_USER_LOOKUP_CACHE.lock() {
        if desktop.uid.is_empty() || desktop.username.is_empty() {
            *cache = None;
        } else {
            *cache = Some(ActiveUserLookupCache {
                uid: desktop.uid.clone(),
                username: desktop.username.clone(),
            });
        }
    }
}

#[inline]
fn get_active_user_id_name_from_cache() -> Option<(String, String)> {
    let cache = ACTIVE_USER_LOOKUP_CACHE.lock().ok()?;
    let entry = cache.as_ref()?;
    Some((entry.uid.clone(), entry.username.clone()))
}

thread_local! {
    // XDO context - created via libxdo-sys (which uses dynamic loading stub).
    // If libxdo is not available, xdo will be null and xdo-based functions become no-ops.
    static XDO: RefCell<*mut xdo_t> = RefCell::new({
        let xdo = unsafe { libxdo_sys::xdo_new(std::ptr::null()) };
        if xdo.is_null() {
            log::warn!("Failed to create xdo context, xdo functions will be disabled");
        } else {
            log::info!("xdo context created successfully");
        }
        xdo
    });
    static DISPLAY: RefCell<*mut c_void> = RefCell::new(unsafe { XOpenDisplay(std::ptr::null())});
}

// X11 error event structure for the custom error handler.
// See: https://www.x.org/releases/current/doc/libX11/libX11/libX11.html#Using-the-Default-Error-Handlers
#[repr(C)]
struct XErrorEvent {
    type_: c_int,
    display: *mut c_void, // Display*
    resourceid: c_ulong,  // XID
    serial: c_ulong,
    error_code: u8,
    request_code: u8,
    minor_code: u8,
}

type XErrorHandler = unsafe extern "C" fn(*mut c_void, *mut XErrorEvent) -> c_int;

const X11_BAD_WINDOW: u8 = 3;
const XDO_SUCCESS: c_int = 0;
const XDO_ERROR: c_int = 1;

/// Atomic flag set by the custom X error handler when a BadWindow error occurs.
static X_BAD_WINDOW_DETECTED: AtomicBool = AtomicBool::new(false);
static X_UNEXPECTED_ERROR_DETECTED: AtomicBool = AtomicBool::new(false);

/// Custom X error handler that catches BadWindow errors (error_code == 3) instead of
/// letting the default handler terminate the process.
/// See issue: https://github.com/rustdesk/rustdesk/issues/9003
unsafe extern "C" fn handle_x_error(_display: *mut c_void, event: *mut XErrorEvent) -> c_int {
    if !event.is_null() && (*event).error_code == X11_BAD_WINDOW {
        X_BAD_WINDOW_DETECTED.store(true, Ordering::SeqCst);
        log::debug!("Caught X11 BadWindow error (suppressed), window was likely destroyed");
        return 0;
    }
    X_UNEXPECTED_ERROR_DETECTED.store(true, Ordering::SeqCst);
    if !event.is_null() {
        log::warn!(
            "X11 error: error_code={}, request_code={}, minor_code={}",
            (*event).error_code,
            (*event).request_code,
            (*event).minor_code,
        );
    }
    0
}

#[link(name = "X11")]
extern "C" {
    fn XOpenDisplay(display_name: *const c_char) -> *mut c_void;
    // fn XCloseDisplay(d: *mut c_void) -> c_int;
    fn XSetErrorHandler(handler: Option<XErrorHandler>) -> Option<XErrorHandler>;
}

#[link(name = "Xfixes")]
extern "C" {
    // fn XFixesQueryExtension(dpy: *mut c_void, event: *mut c_int, error: *mut c_int) -> c_int;
    fn XFixesGetCursorImage(dpy: *mut c_void) -> *const xcb_xfixes_get_cursor_image;
    fn XFree(data: *mut c_void);
}

// /usr/include/X11/extensions/Xfixes.h
#[repr(C)]
pub struct xcb_xfixes_get_cursor_image {
    pub x: i16,
    pub y: i16,
    pub width: u16,
    pub height: u16,
    pub xhot: u16,
    pub yhot: u16,
    pub cursor_serial: c_long,
    pub pixels: *const c_long,
}

#[inline]
pub fn is_headless_allowed() -> bool {
    Config::get_option(OPTION_ALLOW_LINUX_HEADLESS) == "Y"
}

#[inline]
pub fn is_login_screen_wayland() -> bool {
    let values = get_values_of_seat0_with_gdm_wayland(&[0, 2]);
    is_gdm_user(&values[1]) && get_display_server_of_session(&values[0]) == DISPLAY_SERVER_WAYLAND
}

#[inline]
fn sleep_millis(millis: u64) {
    std::thread::sleep(Duration::from_millis(millis));
}

pub fn get_cursor_pos() -> Option<(i32, i32)> {
    let mut res = None;
    XDO.with(|xdo| {
        if let Ok(xdo) = xdo.try_borrow() {
            if xdo.is_null() {
                return;
            }
            let mut x: c_int = 0;
            let mut y: c_int = 0;
            unsafe {
                libxdo_sys::xdo_get_mouse_location(
                    *xdo as *const _,
                    &mut x as _,
                    &mut y as _,
                    std::ptr::null_mut(),
                );
            }
            res = Some((x, y));
        }
    });
    res
}

pub fn set_cursor_pos(x: i32, y: i32) -> bool {
    let mut res = false;
    XDO.with(|xdo| {
        match xdo.try_borrow() {
            Ok(xdo) => {
                if xdo.is_null() {
                    log::debug!("set_cursor_pos: xdo is null");
                    return;
                }
                unsafe {
                    let ret = libxdo_sys::xdo_move_mouse(*xdo as *const _, x, y, 0);
                    if ret != 0 {
                        log::debug!(
                            "set_cursor_pos: xdo_move_mouse failed with code {} for coordinates ({}, {})",
                            ret, x, y
                        );
                    }
                    res = ret == 0;
                }
            }
            Err(_) => {
                log::debug!("set_cursor_pos: failed to borrow xdo");
            }
        }
    });
    res
}

/// Clip cursor - Linux implementation is a no-op.
///
/// On X11, there's no direct equivalent to Windows ClipCursor. XGrabPointer
/// can confine the pointer but requires a window handle and has side effects.
///
/// On Wayland, pointer constraints require the zwp_pointer_constraints_v1
/// protocol which is compositor-dependent.
///
/// For relative mouse mode on Linux, the Flutter side uses pointer warping
/// (set_cursor_pos) to re-center the cursor after each movement, which achieves
/// a similar effect without requiring cursor clipping.
///
/// Returns true (always succeeds as no-op).
pub fn clip_cursor(_rect: Option<(i32, i32, i32, i32)>) -> bool {
    // Log only once per process to avoid flooding logs when called frequently.
    static LOGGED: AtomicBool = AtomicBool::new(false);
    if !LOGGED.swap(true, Ordering::Relaxed) {
        log::debug!("clip_cursor called (no-op on Linux, this message is logged only once)");
    }
    true
}

pub fn reset_input_cache() {}

pub fn get_focused_display(displays: Vec<DisplayInfo>) -> Option<usize> {
    let mut res = None;
    XDO.with(|xdo| {
        if let Ok(xdo) = xdo.try_borrow() {
            if xdo.is_null() {
                return;
            }
            let mut x: c_int = 0;
            let mut y: c_int = 0;
            let mut width: c_uint = 0;
            let mut height: c_uint = 0;
            let mut window: Window = 0;

            unsafe {
                if libxdo_sys::xdo_get_active_window(*xdo as *const _, &mut window) != 0 {
                    return;
                }

                // XSetErrorHandler is process-global, not scoped to this Display/thread.
                // This path is currently called by the single window_focus service thread.
                // While installed, this handler can still observe unrelated X11 errors from
                // other threads; unexpected errors make this geometry query fail.
                X_BAD_WINDOW_DETECTED.store(false, Ordering::SeqCst);
                X_UNEXPECTED_ERROR_DETECTED.store(false, Ordering::SeqCst);
                let prev_handler = XSetErrorHandler(Some(handle_x_error));

                let loc_ret = libxdo_sys::xdo_get_window_location(
                    *xdo as *const _,
                    window,
                    &mut x as _,
                    &mut y as _,
                    std::ptr::null_mut(),
                );
                let size_ret = if loc_ret == XDO_SUCCESS {
                    libxdo_sys::xdo_get_window_size(
                        *xdo as *const _,
                        window,
                        &mut width,
                        &mut height,
                    )
                } else {
                    XDO_ERROR
                };

                // Do not call XSync(DISPLAY) here: DISPLAY is a separate
                // XOpenDisplay() connection, while libxdo owns the Display*
                // used by these geometry queries. These libxdo calls are
                // synchronous XGetWindowAttributes-based queries, so the target
                // BadWindow is expected to be delivered before the calls return.
                XSetErrorHandler(prev_handler);
                if X_BAD_WINDOW_DETECTED.load(Ordering::SeqCst)
                    || X_UNEXPECTED_ERROR_DETECTED.load(Ordering::SeqCst)
                    || loc_ret != XDO_SUCCESS
                    || size_ret != XDO_SUCCESS
                {
                    return;
                }

                let center_x = x + (width / 2) as c_int;
                let center_y = y + (height / 2) as c_int;
                res = displays.iter().position(|d| {
                    center_x >= d.x
                        && center_x < d.x + d.width
                        && center_y >= d.y
                        && center_y < d.y + d.height
                });
            }
        }
    });
    res
}

pub fn get_cursor() -> ResultType<Option<u64>> {
    let mut res = None;
    DISPLAY.with(|conn| {
        if let Ok(d) = conn.try_borrow_mut() {
            if !d.is_null() {
                unsafe {
                    let img = XFixesGetCursorImage(*d);
                    if !img.is_null() {
                        res = Some((*img).cursor_serial as u64);
                        XFree(img as _);
                    }
                }
            }
        }
    });
    Ok(res)
}

pub fn get_cursor_data(hcursor: u64) -> ResultType<CursorData> {
    let mut res = None;
    DISPLAY.with(|conn| {
        if let Ok(ref mut d) = conn.try_borrow_mut() {
            if !d.is_null() {
                unsafe {
                    let img = XFixesGetCursorImage(**d);
                    if !img.is_null() && hcursor == (*img).cursor_serial as u64 {
                        let mut cd: CursorData = Default::default();
                        cd.hotx = (*img).xhot as _;
                        cd.hoty = (*img).yhot as _;
                        cd.width = (*img).width as _;
                        cd.height = (*img).height as _;
                        let Some(rgba_len) = super::cursor_rgba_len(cd.width, cd.height) else {
                            XFree(img as _);
                            return;
                        };
                        if (*img).pixels.is_null() {
                            XFree(img as _);
                            return;
                        }
                        // to-do: how about if it is 0
                        cd.id = (*img).cursor_serial as _;
                        let pixels = std::slice::from_raw_parts((*img).pixels, rgba_len / 4);
                        // cd.colors.resize(pixels.len() * 4, 0);
                        let mut cd_colors = vec![0_u8; rgba_len];
                        for y in 0..cd.height {
                            for x in 0..cd.width {
                                let pos = (y * cd.width + x) as usize;
                                let p = pixels[pos];
                                let a = (p >> 24) & 0xff;
                                let r = (p >> 16) & 0xff;
                                let g = (p >> 8) & 0xff;
                                let b = (p >> 0) & 0xff;
                                if a == 0 {
                                    continue;
                                }
                                let pos = pos * 4;
                                cd_colors[pos] = r as _;
                                cd_colors[pos + 1] = g as _;
                                cd_colors[pos + 2] = b as _;
                                cd_colors[pos + 3] = a as _;
                            }
                        }
                        cd.colors = cd_colors.into();
                        res = Some(cd);
                    }
                    if !img.is_null() {
                        XFree(img as _);
                    }
                }
            }
        }
    });
    match res {
        Some(x) => Ok(x),
        _ => bail!("Failed to get cursor image of {}", hcursor),
    }
}

fn select_service_child_terminal_type(has_xterm_256color: bool) -> &'static str {
    if has_xterm_256color {
        TERM_XTERM_256COLOR
    } else {
        TERM_XTERM
    }
}

/// Select one service-owned terminal type without reading a desktop user's
/// process environment or parsing an environment-selected terminfo database.
fn service_child_terminal_type() -> &'static str {
    let has_xterm_256color = SERVICE_XTERM_256COLOR_PATHS
        .iter()
        .any(|path| match fs::metadata(Path::new(path)) {
            Ok(metadata) => metadata.is_file(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
            Err(err) => {
                log::warn!(
                    "Unable to inspect fixed system terminal capability {}: {}",
                    path,
                    err
                );
                false
            }
        });
    select_service_child_terminal_type(has_xterm_256color)
}

struct ServiceChildCredentials {
    uid: hbb_common::libc::uid_t,
    gid: hbb_common::libc::gid_t,
    supplementary_groups: Vec<hbb_common::libc::gid_t>,
    username: String,
    home: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServiceChildPrincipal {
    RootService,
    ActiveDesktopUser,
}

fn selected_service_child_principal(
    desktop: &Desktop,
) -> ResultType<Option<ServiceChildPrincipal>> {
    if desktop.uid.is_empty() && desktop.username.is_empty() {
        return Ok(None);
    }
    if desktop.uid.is_empty() || desktop.username.is_empty() {
        bail!("Selected desktop has an incomplete user identity");
    }
    let uid = desktop
        .uid
        .parse::<hbb_common::libc::uid_t>()
        .map_err(|err| anyhow!("Invalid selected desktop uid {}: {err}", desktop.uid))?;
    if uid.to_string() != desktop.uid {
        bail!("Selected desktop uid is not canonical decimal");
    }
    if uid == 0 || desktop.is_login_wayland() {
        Ok(Some(ServiceChildPrincipal::RootService))
    } else {
        Ok(Some(ServiceChildPrincipal::ActiveDesktopUser))
    }
}

impl ServiceChildCredentials {
    fn resolve(uid: &str, username: &str) -> ResultType<Self> {
        let expected_uid = uid
            .parse::<hbb_common::libc::uid_t>()
            .map_err(|err| anyhow!("Invalid service child uid {uid}: {err}"))?;
        if expected_uid == 0 || username.is_empty() {
            bail!("Refusing a root or unnamed active-user service child");
        }
        let user = get_user_by_name(username)
            .ok_or_else(|| anyhow!("Service child user '{username}' is unavailable"))?;
        if user.uid() != expected_uid || user.name() != OsStr::new(username) {
            bail!(
                "Service child user identity mismatch: requested uid={expected_uid}, username={username}"
            );
        }
        let gid = user.primary_group_id();
        let groups = hbb_common::users::get_user_groups(username, gid)
            .ok_or_else(|| anyhow!("Failed to resolve supplementary groups for '{username}'"))?;
        let supplementary_groups = groups.into_iter().map(|group| group.gid()).collect();
        Ok(Self {
            uid: expected_uid,
            gid,
            supplementary_groups,
            username: username.to_owned(),
            home: user.home_dir().to_path_buf(),
        })
    }
}

// Linux service-child authority has two deliberately separate paths:
//
// * While the supervisor is alive, `OwnedServiceChild` retains the direct `Child`; routine
//   restart and shutdown never rediscover a PID.
// * After a supervisor crash, a new supervisor first takes the close-on-exec `flock` lease,
//   consumes one bounded root-only record, opens a pidfd, and
//   revalidates every recorded field immediately before each signal. `pidfd_send_signal(2)`
//   then binds the signal to that opened process rather than to a recyclable integer PID.
//
// Publication is temp-file fsync -> renameat2(RENAME_NOREPLACE) -> directory fsync. A malformed
// or ambiguous record is preserved and stops service startup; it is never replaced by a new child.
// If pidfd_open(2) is unavailable, an already-exited or absent child record may be removed without
// signaling. A live or unverifiable record is preserved and startup fails closed: process metadata
// cannot turn a recyclable integer PID into stable signaling authority.
#[cfg(debug_assertions)]
const SERVICE_CHILD_FORCE_PIDFD_UNAVAILABLE_FOR_SMOKE_ENV: &str =
    "RD_SERVICE_SMOKE_FORCE_PIDFD_UNAVAILABLE";
#[cfg(debug_assertions)]
const SERVICE_CHILD_UNSUPERVISED_RECOVERY_FIXTURE_ENV: &str =
    "RD_SERVICE_SMOKE_UNSUPERVISED_RECOVERY_FIXTURE";

#[derive(Clone, Debug, Eq, PartialEq)]
struct ServiceChildRecord {
    pid: u32,
    start_time: u64,
    boot_id: String,
    executable_device: u64,
    executable_inode: u64,
    uid: u32,
    generation: String,
}

impl ServiceChildRecord {
    fn encode(&self) -> Vec<u8> {
        format!(
            "version=1\npid={}\nstart_time={}\nboot_id={}\nexe_dev={}\nexe_ino={}\nuid={}\ngeneration={}\nrole={}\n",
            self.pid,
            self.start_time,
            self.boot_id,
            self.executable_device,
            self.executable_inode,
            self.uid,
            self.generation,
            SERVICE_CHILD_RECORD_ROLE,
        )
        .into_bytes()
    }

    fn decode(bytes: &[u8]) -> ResultType<Self> {
        if bytes.is_empty() || bytes.len() > SERVICE_CHILD_RECORD_MAX_BYTES {
            bail!("Service child record has an invalid length");
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|err| anyhow!("Service child record is not UTF-8: {err}"))?;
        if !text.ends_with('\n') {
            bail!("Service child record is not newline terminated");
        }
        let mut lines = text.lines();
        let version = service_child_record_field(&mut lines, "version")?;
        if version != "1" {
            bail!("Unsupported service child record version");
        }
        let pid = parse_service_child_record_number::<u32>(
            service_child_record_field(&mut lines, "pid")?,
            "pid",
        )?;
        if pid == 0 || pid > hbb_common::libc::pid_t::MAX as u32 {
            bail!("Service child record pid is outside pid_t range");
        }
        let start_time = parse_service_child_record_number::<u64>(
            service_child_record_field(&mut lines, "start_time")?,
            "start_time",
        )?;
        if start_time == 0 {
            bail!("Service child record start time is zero");
        }
        let boot_id = service_child_record_field(&mut lines, "boot_id")?.to_owned();
        validate_canonical_uuid(&boot_id, "boot id")?;
        let executable_device = parse_service_child_record_number::<u64>(
            service_child_record_field(&mut lines, "exe_dev")?,
            "executable device",
        )?;
        let executable_inode = parse_service_child_record_number::<u64>(
            service_child_record_field(&mut lines, "exe_ino")?,
            "executable inode",
        )?;
        if executable_inode == 0 {
            bail!("Service child record executable inode is zero");
        }
        let uid = parse_service_child_record_number::<u32>(
            service_child_record_field(&mut lines, "uid")?,
            "uid",
        )?;
        let generation = service_child_record_field(&mut lines, "generation")?.to_owned();
        validate_canonical_uuid(&generation, "service generation")?;
        if service_child_record_field(&mut lines, "role")? != SERVICE_CHILD_RECORD_ROLE {
            bail!("Service child record role marker is invalid");
        }
        if lines.next().is_some() {
            bail!("Service child record has trailing fields");
        }
        Ok(Self {
            pid,
            start_time,
            boot_id,
            executable_device,
            executable_inode,
            uid,
            generation,
        })
    }
}

fn service_child_record_field<'a>(
    lines: &mut std::str::Lines<'a>,
    expected_name: &str,
) -> ResultType<&'a str> {
    let line = lines
        .next()
        .ok_or_else(|| anyhow!("Service child record is missing '{expected_name}'"))?;
    let expected_prefix = format!("{expected_name}=");
    line.strip_prefix(&expected_prefix)
        .ok_or_else(|| anyhow!("Service child record field order is invalid at '{expected_name}'"))
}

fn parse_service_child_record_number<T>(value: &str, label: &str) -> ResultType<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("Service child record {label} is not canonical decimal");
    }
    if value.len() > 1 && value.starts_with('0') {
        bail!("Service child record {label} has a leading zero");
    }
    value
        .parse::<T>()
        .map_err(|err| anyhow!("Service child record {label} is invalid: {err}"))
}

fn validate_canonical_uuid(value: &str, label: &str) -> ResultType<()> {
    let parsed = hbb_common::uuid::Uuid::parse_str(value)
        .map_err(|err| anyhow!("Linux service child {label} is invalid: {err}"))?;
    if parsed.to_string() != value {
        bail!("Linux service child {label} is not canonical");
    }
    Ok(())
}

struct ServiceRuntime {
    directory: File,
    _lease: File,
    generation: String,
    owner_uid: u32,
}

impl ServiceRuntime {
    fn acquire() -> ResultType<Self> {
        let owner_uid = unsafe { hbb_common::libc::geteuid() as u32 };
        if owner_uid != 0 {
            bail!("Linux --service requires root for its lifecycle authority directory");
        }

        let mkdir_rc = unsafe {
            hbb_common::libc::mkdir(
                SERVICE_RUNTIME_DIR.as_ptr() as *const c_char,
                0o700 as hbb_common::libc::mode_t,
            )
        };
        let created_directory = mkdir_rc == 0;
        if mkdir_rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(hbb_common::libc::EEXIST) {
                return Err(anyhow!("Failed to create /run/rustdesk: {err}"));
            }
        }

        let directory_fd = unsafe {
            hbb_common::libc::open(
                SERVICE_RUNTIME_DIR.as_ptr() as *const c_char,
                hbb_common::libc::O_RDONLY
                    | hbb_common::libc::O_DIRECTORY
                    | hbb_common::libc::O_NOFOLLOW
                    | hbb_common::libc::O_CLOEXEC,
            )
        };
        if directory_fd < 0 {
            return Err(anyhow!(
                "Failed to open /run/rustdesk without following links: {}",
                std::io::Error::last_os_error()
            ));
        }
        let directory = unsafe { File::from_raw_fd(directory_fd) };
        if created_directory {
            set_service_runtime_mode(&directory, 0o700, "new service runtime directory")?;
        }
        validate_service_runtime_directory(&directory, owner_uid)?;

        let lease = open_service_runtime_file(
            &directory,
            SERVICE_RUNTIME_LOCK,
            hbb_common::libc::O_RDWR
                | hbb_common::libc::O_CREAT
                | hbb_common::libc::O_NOFOLLOW
                | hbb_common::libc::O_CLOEXEC
                | hbb_common::libc::O_NONBLOCK,
            0o600,
            "service supervisor lease",
        )?;
        set_service_runtime_mode(&lease, 0o600, "service supervisor lease")?;
        validate_service_runtime_regular_file(&lease, owner_uid, "service supervisor lease")?;
        acquire_service_runtime_lease(&lease, "service supervisor lease")?;

        let runtime = Self {
            directory,
            _lease: lease,
            generation: read_kernel_uuid("/proc/sys/kernel/random/uuid", "service generation")?,
            owner_uid,
        };
        runtime.remove_incomplete_record()?;
        SERVICE_RUNTIME_GENERATION
            .set(runtime.generation.clone())
            .map_err(|_| anyhow!("Linux service runtime generation was initialized twice"))?;
        Ok(runtime)
    }

    fn publish_record(&self, record: &ServiceChildRecord) -> ResultType<()> {
        if self.read_record()?.is_some() {
            bail!("Refusing to overwrite an existing service child record");
        }
        self.remove_incomplete_record()?;

        let mut temporary = open_service_runtime_file(
            &self.directory,
            SERVICE_CHILD_RECORD_TMP,
            hbb_common::libc::O_WRONLY
                | hbb_common::libc::O_CREAT
                | hbb_common::libc::O_EXCL
                | hbb_common::libc::O_NOFOLLOW
                | hbb_common::libc::O_CLOEXEC
                | hbb_common::libc::O_NONBLOCK,
            0o600,
            "temporary service child record",
        )?;
        if let Err(err) =
            set_service_runtime_mode(&temporary, 0o600, "temporary service child record").and_then(
                |_| {
                    validate_service_runtime_regular_file(
                        &temporary,
                        self.owner_uid,
                        "temporary service child record",
                    )
                },
            )
        {
            drop(temporary);
            let _ = self.remove_runtime_entry(SERVICE_CHILD_RECORD_TMP, "temporary record");
            return Err(err);
        }
        let encoded = record.encode();
        if encoded.len() > SERVICE_CHILD_RECORD_MAX_BYTES {
            bail!("Encoded service child record exceeds its bound");
        }
        if let Err(err) = temporary
            .write_all(&encoded)
            .and_then(|_| temporary.sync_all())
        {
            drop(temporary);
            let _ = self.remove_runtime_entry(SERVICE_CHILD_RECORD_TMP, "temporary record");
            return Err(anyhow!("Failed to persist service child record: {err}"));
        }
        drop(temporary);

        let rename_rc = unsafe {
            hbb_common::libc::syscall(
                hbb_common::libc::SYS_renameat2,
                self.directory.as_raw_fd(),
                SERVICE_CHILD_RECORD_TMP.as_ptr() as *const c_char,
                self.directory.as_raw_fd(),
                SERVICE_CHILD_RECORD.as_ptr() as *const c_char,
                hbb_common::libc::RENAME_NOREPLACE,
            )
        };
        if rename_rc != 0 {
            let err = std::io::Error::last_os_error();
            if matches!(
                err.raw_os_error(),
                Some(hbb_common::libc::ENOSYS) | Some(hbb_common::libc::EINVAL)
            ) {
                if self.read_record()?.is_some() {
                    let _ = self.remove_runtime_entry(SERVICE_CHILD_RECORD_TMP, "temporary record");
                    bail!("Refusing to replace a service child record during rename fallback");
                }
                if unsafe {
                    hbb_common::libc::renameat(
                        self.directory.as_raw_fd(),
                        SERVICE_CHILD_RECORD_TMP.as_ptr() as *const c_char,
                        self.directory.as_raw_fd(),
                        SERVICE_CHILD_RECORD.as_ptr() as *const c_char,
                    )
                } != 0
                {
                    let fallback_err = std::io::Error::last_os_error();
                    let _ = self.remove_runtime_entry(SERVICE_CHILD_RECORD_TMP, "temporary record");
                    return Err(anyhow!(
                        "Failed to atomically publish service child record: {fallback_err}"
                    ));
                }
            } else {
                let _ = self.remove_runtime_entry(SERVICE_CHILD_RECORD_TMP, "temporary record");
                return Err(anyhow!(
                    "Failed to atomically publish service child record: {err}"
                ));
            }
        }
        self.directory
            .sync_all()
            .map_err(|err| anyhow!("Failed to sync service runtime directory: {err}"))?;
        Ok(())
    }

    fn read_record(&self) -> ResultType<Option<ServiceChildRecord>> {
        let fd = unsafe {
            hbb_common::libc::openat(
                self.directory.as_raw_fd(),
                SERVICE_CHILD_RECORD.as_ptr() as *const c_char,
                hbb_common::libc::O_RDONLY
                    | hbb_common::libc::O_NOFOLLOW
                    | hbb_common::libc::O_CLOEXEC
                    | hbb_common::libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(hbb_common::libc::ENOENT) {
                return Ok(None);
            }
            return Err(anyhow!("Failed to open service child record: {err}"));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        validate_service_runtime_regular_file(&file, self.owner_uid, "service child record")?;
        let metadata = file
            .metadata()
            .map_err(|err| anyhow!("Failed to inspect service child record size: {err}"))?;
        if metadata.len() == 0 || metadata.len() > SERVICE_CHILD_RECORD_MAX_BYTES as u64 {
            bail!("Service child record has an invalid on-disk length");
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take((SERVICE_CHILD_RECORD_MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|err| anyhow!("Failed to read service child record: {err}"))?;
        if bytes.len() > SERVICE_CHILD_RECORD_MAX_BYTES {
            bail!("Service child record exceeds its read bound");
        }
        ServiceChildRecord::decode(&bytes).map(Some)
    }

    fn remove_record(&self, expected: &ServiceChildRecord) -> ResultType<()> {
        let Some(actual) = self.read_record()? else {
            bail!("Service child record disappeared before exact removal");
        };
        if actual != *expected {
            bail!("Refusing to remove a service child record for a different identity");
        }
        self.remove_runtime_entry(SERVICE_CHILD_RECORD, "service child record")?;
        self.directory
            .sync_all()
            .map_err(|err| anyhow!("Failed to sync removal of service child record: {err}"))
    }

    fn remove_incomplete_record(&self) -> ResultType<()> {
        self.remove_runtime_entry_if_present(
            SERVICE_CHILD_RECORD_TMP,
            "incomplete temporary service child record",
        )
    }

    fn remove_runtime_entry_if_present(&self, name: &[u8], label: &str) -> ResultType<()> {
        let mut stat: hbb_common::libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            hbb_common::libc::fstatat(
                self.directory.as_raw_fd(),
                name.as_ptr() as *const c_char,
                &mut stat,
                hbb_common::libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(hbb_common::libc::ENOENT) {
                return Ok(());
            }
            return Err(anyhow!("Failed to inspect {label}: {err}"));
        }
        let file_type = stat.st_mode & hbb_common::libc::S_IFMT;
        if file_type != hbb_common::libc::S_IFREG
            || stat.st_uid as u32 != self.owner_uid
            || stat.st_mode & 0o7777 != 0o600
            || stat.st_nlink != 1
        {
            bail!("Refusing to remove an untrusted {label}");
        }
        self.remove_runtime_entry(name, label)
    }

    fn remove_runtime_entry(&self, name: &[u8], label: &str) -> ResultType<()> {
        if unsafe {
            hbb_common::libc::unlinkat(
                self.directory.as_raw_fd(),
                name.as_ptr() as *const c_char,
                0,
            )
        } != 0
        {
            return Err(anyhow!(
                "Failed to remove {label}: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

pub(crate) fn service_runtime_generation_matches(candidate: &str) -> bool {
    SERVICE_RUNTIME_GENERATION
        .get()
        .is_some_and(|generation| generation == candidate)
}

fn set_service_child_executable_identity(metadata: &fs::Metadata) -> ResultType<()> {
    let identity = (metadata.dev(), metadata.ino());
    let mut expected = SERVICE_CHILD_EXECUTABLE_IDENTITY
        .get_or_init(|| std::sync::RwLock::new(None))
        .write()
        .map_err(|_| anyhow!("Linux service-child executable identity lock was poisoned"))?;
    *expected = Some(identity);
    Ok(())
}

pub(crate) fn service_child_executable_identity_matches(pid: u32) -> ResultType<bool> {
    let expected = SERVICE_CHILD_EXECUTABLE_IDENTITY
        .get()
        .ok_or_else(|| anyhow!("Linux service-child executable identity is unavailable"))?
        .read()
        .map_err(|_| anyhow!("Linux service-child executable identity lock was poisoned"))?
        .ok_or_else(|| anyhow!("Linux service-child executable identity is unavailable"))?;
    let executable = fs::metadata(format!("/proc/{pid}/exe"))
        .map_err(|err| anyhow!("Failed to inspect Linux service-child executable: {err}"))?;
    Ok((executable.dev(), executable.ino()) == expected)
}

#[cfg(test)]
impl ServiceRuntime {
    fn for_test(directory_path: &Path, generation: &str) -> ResultType<Self> {
        validate_canonical_uuid(generation, "test service generation")?;
        let owner_uid = unsafe { hbb_common::libc::geteuid() as u32 };
        let directory = File::open(directory_path).map_err(|err| {
            anyhow!(
                "Failed to open test service runtime directory '{}': {err}",
                directory_path.display()
            )
        })?;
        validate_service_runtime_directory(&directory, owner_uid)?;
        let lease = open_service_runtime_file(
            &directory,
            SERVICE_RUNTIME_LOCK,
            hbb_common::libc::O_RDWR
                | hbb_common::libc::O_CREAT
                | hbb_common::libc::O_NOFOLLOW
                | hbb_common::libc::O_CLOEXEC
                | hbb_common::libc::O_NONBLOCK,
            0o600,
            "test service supervisor lease",
        )?;
        set_service_runtime_mode(&lease, 0o600, "test service supervisor lease")?;
        validate_service_runtime_regular_file(&lease, owner_uid, "test service supervisor lease")?;
        acquire_service_runtime_lease(&lease, "test service supervisor lease")?;
        let runtime = Self {
            directory,
            _lease: lease,
            generation: generation.to_owned(),
            owner_uid,
        };
        runtime.remove_incomplete_record()?;
        Ok(runtime)
    }
}

fn open_service_runtime_file(
    directory: &File,
    name: &[u8],
    flags: c_int,
    mode: hbb_common::libc::mode_t,
    label: &str,
) -> ResultType<File> {
    let fd = unsafe {
        hbb_common::libc::openat(
            directory.as_raw_fd(),
            name.as_ptr() as *const c_char,
            flags,
            mode,
        )
    };
    if fd < 0 {
        return Err(anyhow!(
            "Failed to open {label}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn acquire_service_runtime_lease(lease: &File, label: &str) -> ResultType<()> {
    if unsafe {
        hbb_common::libc::flock(
            lease.as_raw_fd(),
            hbb_common::libc::LOCK_EX | hbb_common::libc::LOCK_NB,
        )
    } != 0
    {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(hbb_common::libc::EWOULDBLOCK) {
            bail!("Another Linux service supervisor owns the lifecycle lease");
        }
        return Err(anyhow!("Failed to acquire {label}: {err}"));
    }
    Ok(())
}

fn validate_service_runtime_directory(directory: &File, owner_uid: u32) -> ResultType<()> {
    let metadata = directory
        .metadata()
        .map_err(|err| anyhow!("Failed to inspect /run/rustdesk: {err}"))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o7777 != 0o700
    {
        bail!("Refusing untrusted /run/rustdesk ownership, type, or mode");
    }
    Ok(())
}

fn set_service_runtime_mode(
    file: &File,
    mode: hbb_common::libc::mode_t,
    label: &str,
) -> ResultType<()> {
    if unsafe { hbb_common::libc::fchmod(file.as_raw_fd(), mode) } != 0 {
        return Err(anyhow!(
            "Failed to set owner-only mode on {label}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn validate_service_runtime_regular_file(
    file: &File,
    owner_uid: u32,
    label: &str,
) -> ResultType<()> {
    let metadata = file
        .metadata()
        .map_err(|err| anyhow!("Failed to inspect {label}: {err}"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        bail!("Refusing untrusted {label} ownership, type, mode, or link count");
    }
    Ok(())
}

fn read_kernel_uuid(path: &str, label: &str) -> ResultType<String> {
    let value = fs::read_to_string(path)
        .map_err(|err| anyhow!("Failed to read Linux {label} from {path}: {err}"))?;
    let value = value.trim();
    validate_canonical_uuid(value, label)?;
    Ok(value.to_owned())
}

struct OwnedServiceChild {
    process: Child,
    record: ServiceChildRecord,
}

enum ServiceChildIdentityState {
    Match,
    Exited,
    Absent,
    Mismatch(String),
    Unavailable(String),
}

enum PidFdOpen {
    Available(File),
    Unsupported,
    Absent,
}

impl ServiceRuntime {
    fn recover_previous_child(&self) -> ResultType<()> {
        let Some(record) = self.read_record()? else {
            log::info!("No prior Linux service child record; recovery signals nothing");
            return Ok(());
        };
        let current_boot_id = read_kernel_uuid("/proc/sys/kernel/random/boot_id", "boot id")?;
        if record.boot_id != current_boot_id {
            log::warn!(
                "Discarding stale Linux service child record from boot {} without signaling pid {}",
                record.boot_id,
                record.pid
            );
            return self.remove_record(&record);
        }

        match open_service_child_pidfd(record.pid)? {
            PidFdOpen::Available(pidfd) => self.recover_previous_child_with_pidfd(&record, &pidfd),
            PidFdOpen::Unsupported => self.handle_previous_child_without_pidfd(&record),
            PidFdOpen::Absent => {
                log::warn!(
                    "Discarding stale Linux service child record for absent pid {} without signaling",
                    record.pid
                );
                self.remove_record(&record)
            }
        }
    }

    fn recover_previous_child_with_pidfd(
        &self,
        record: &ServiceChildRecord,
        pidfd: &File,
    ) -> ResultType<()> {
        if service_child_pidfd_exited(pidfd, Duration::ZERO)? {
            log::warn!(
                "Discarding exited Linux service child record for pid {} without signaling",
                record.pid
            );
            return self.remove_record(record);
        }
        require_service_child_identity_match(record, "pidfd recovery before SIGTERM")?;
        if send_service_child_pidfd_signal(pidfd, hbb_common::libc::SIGTERM)? {
            log::warn!(
                "Prior Linux service child pid {} exited before recovery SIGTERM",
                record.pid
            );
            return self.remove_record(record);
        }
        if service_child_pidfd_exited(pidfd, SERVICE_CHILD_GRACEFUL_STOP_TIMEOUT)? {
            log::info!(
                "Recovered prior Linux service child pid {} with bounded SIGTERM",
                record.pid
            );
            return self.remove_record(record);
        }

        require_service_child_identity_match(record, "pidfd recovery before SIGKILL")?;
        log::warn!(
            "Prior Linux service child pid {} did not exit after SIGTERM; sending pidfd-bound SIGKILL",
            record.pid
        );
        if !send_service_child_pidfd_signal(pidfd, hbb_common::libc::SIGKILL)?
            && !service_child_pidfd_exited(pidfd, SERVICE_CHILD_FORCED_STOP_TIMEOUT)?
        {
            bail!(
                "Prior Linux service child pid {} remained live after pidfd-bound SIGKILL",
                record.pid
            );
        }
        self.remove_record(record)
    }

    fn handle_previous_child_without_pidfd(&self, record: &ServiceChildRecord) -> ResultType<()> {
        match inspect_service_child_identity(record) {
            ServiceChildIdentityState::Exited | ServiceChildIdentityState::Absent => {
                log::warn!(
                    "Discarding stale Linux service child record for pid {} without signaling because pidfd_open is unavailable",
                    record.pid
                );
                self.remove_record(record)
            }
            ServiceChildIdentityState::Match => {
                bail!(
                    "Kernel lacks required pidfd_open for live Linux service child pid {}; preserving the record and refusing recovery without signaling",
                    record.pid
                );
            }
            ServiceChildIdentityState::Mismatch(reason) => {
                bail!(
                    "Refusing ambiguous Linux service child recovery without pidfd for pid {}; preserving the record and signaling nothing: {reason}",
                    record.pid
                );
            }
            ServiceChildIdentityState::Unavailable(reason) => {
                bail!(
                    "Refusing unverifiable Linux service child recovery without pidfd for pid {}; preserving the record and signaling nothing: {reason}",
                    record.pid
                );
            }
        }
    }
}

fn service_child_record_for_process(
    pid: u32,
    uid: u32,
    generation: &str,
) -> ResultType<ServiceChildRecord> {
    let (start_time, state) = read_service_child_proc_stat(pid)?;
    if matches!(state, 'Z' | 'X' | 'x') {
        bail!("Service child pid {pid} exited before record publication");
    }
    let proc_dir = PathBuf::from(format!("/proc/{pid}"));
    let proc_metadata = fs::metadata(&proc_dir)
        .map_err(|err| anyhow!("Failed to inspect service child pid {pid}: {err}"))?;
    if proc_metadata.uid() != uid {
        bail!(
            "Service child uid mismatch before record publication: expected {uid}, got {}",
            proc_metadata.uid()
        );
    }
    let executable = fs::metadata(proc_dir.join("exe"))
        .map_err(|err| anyhow!("Failed to inspect service child executable pid {pid}: {err}"))?;
    let record = ServiceChildRecord {
        pid,
        start_time,
        boot_id: read_kernel_uuid("/proc/sys/kernel/random/boot_id", "boot id")?,
        executable_device: executable.dev(),
        executable_inode: executable.ino(),
        uid,
        generation: generation.to_owned(),
    };
    require_service_child_identity_match(&record, "record publication")?;
    Ok(record)
}

fn inspect_service_child_identity(record: &ServiceChildRecord) -> ServiceChildIdentityState {
    let current_boot_id = match read_kernel_uuid("/proc/sys/kernel/random/boot_id", "boot id") {
        Ok(value) => value,
        Err(err) => {
            return ServiceChildIdentityState::Unavailable(format!(
                "boot identity unavailable: {err}"
            ));
        }
    };
    if current_boot_id != record.boot_id {
        return ServiceChildIdentityState::Mismatch("boot identity changed".to_owned());
    }

    let (first_start_time, state) = match read_service_child_proc_stat(record.pid) {
        Ok(identity) => identity,
        Err(err) => return classify_service_child_proc_error(record.pid, "stat", err),
    };
    if matches!(state, 'Z' | 'X' | 'x') {
        return ServiceChildIdentityState::Exited;
    }
    if first_start_time != record.start_time {
        return ServiceChildIdentityState::Mismatch(format!(
            "start time changed from {} to {first_start_time}",
            record.start_time
        ));
    }

    let proc_dir = PathBuf::from(format!("/proc/{}", record.pid));
    let proc_metadata = match fs::metadata(&proc_dir) {
        Ok(metadata) => metadata,
        Err(err) => return classify_service_child_proc_error(record.pid, "directory", err.into()),
    };
    if proc_metadata.uid() != record.uid {
        return ServiceChildIdentityState::Mismatch(format!(
            "uid changed from {} to {}",
            record.uid,
            proc_metadata.uid()
        ));
    }

    let executable = match fs::metadata(proc_dir.join("exe")) {
        Ok(metadata) => metadata,
        Err(err) => {
            return classify_service_child_proc_error(record.pid, "executable", err.into());
        }
    };
    if executable.dev() != record.executable_device || executable.ino() != record.executable_inode {
        return ServiceChildIdentityState::Mismatch(format!(
            "executable identity changed from {}:{} to {}:{}",
            record.executable_device,
            record.executable_inode,
            executable.dev(),
            executable.ino()
        ));
    }

    let cmdline = match read_bounded_service_proc_file(&proc_dir.join("cmdline"), 64 * 1024) {
        Ok(bytes) => bytes,
        Err(err) => return classify_service_child_proc_error(record.pid, "cmdline", err),
    };
    if !service_child_cmdline_has_exact_role(&cmdline) {
        return ServiceChildIdentityState::Mismatch(
            "exact service-owned role marker is absent".to_owned(),
        );
    }

    let environ = match read_bounded_service_proc_file(&proc_dir.join("environ"), 64 * 1024) {
        Ok(bytes) => bytes,
        Err(err) => return classify_service_child_proc_error(record.pid, "environment", err),
    };
    if !service_child_environment_has_generation(&environ, &record.generation) {
        return ServiceChildIdentityState::Mismatch(
            "service generation is absent or duplicated".to_owned(),
        );
    }

    let (last_start_time, last_state) = match read_service_child_proc_stat(record.pid) {
        Ok(identity) => identity,
        Err(err) => return classify_service_child_proc_error(record.pid, "final stat", err),
    };
    if matches!(last_state, 'Z' | 'X' | 'x') {
        return ServiceChildIdentityState::Exited;
    }
    if last_start_time != record.start_time || last_start_time != first_start_time {
        return ServiceChildIdentityState::Mismatch(
            "process identity changed during revalidation".to_owned(),
        );
    }
    ServiceChildIdentityState::Match
}

fn require_service_child_identity_match(
    record: &ServiceChildRecord,
    operation: &str,
) -> ResultType<()> {
    match inspect_service_child_identity(record) {
        ServiceChildIdentityState::Match => Ok(()),
        ServiceChildIdentityState::Exited | ServiceChildIdentityState::Absent => bail!(
            "Service child pid {} exited during {operation}; signaling nothing",
            record.pid
        ),
        ServiceChildIdentityState::Mismatch(reason) => bail!(
            "Service child pid {} identity mismatch during {operation}: {reason}; signaling nothing",
            record.pid
        ),
        ServiceChildIdentityState::Unavailable(reason) => bail!(
            "Service child pid {} identity unavailable during {operation}: {reason}; signaling nothing",
            record.pid
        ),
    }
}

fn read_service_child_proc_stat(pid: u32) -> ResultType<(u64, char)> {
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let bytes = read_bounded_service_proc_file(&path, 4096)?;
    let stat = std::str::from_utf8(&bytes)
        .map_err(|err| anyhow!("Failed to parse /proc/{pid}/stat as UTF-8: {err}"))?;
    let Some((_, after_comm)) = stat.rsplit_once(") ") else {
        bail!("Failed to parse /proc/{pid}/stat: missing command terminator");
    };
    let fields: Vec<_> = after_comm.split_whitespace().collect();
    let state = fields
        .first()
        .and_then(|field| field.chars().next())
        .ok_or_else(|| anyhow!("Failed to parse /proc/{pid}/stat state"))?;
    let start_time = fields
        .get(19)
        .ok_or_else(|| anyhow!("Failed to parse /proc/{pid}/stat start time"))?
        .parse::<u64>()
        .map_err(|err| anyhow!("Failed to parse /proc/{pid}/stat start time: {err}"))?;
    Ok((start_time, state))
}

fn read_bounded_service_proc_file(path: &Path, max_bytes: usize) -> ResultType<Vec<u8>> {
    let file =
        File::open(path).map_err(|err| anyhow!("Failed to open '{}': {err}", path.display()))?;
    let mut bytes = Vec::new();
    file.take((max_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|err| anyhow!("Failed to read '{}': {err}", path.display()))?;
    if bytes.len() > max_bytes {
        bail!("Bounded proc file '{}' is too large", path.display());
    }
    Ok(bytes)
}

fn service_child_cmdline_has_exact_role(cmdline: &[u8]) -> bool {
    let args: Vec<_> = cmdline
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .collect();
    args.len() == 3
        && args[1] == b"--server"
        && args[2] == crate::common::SERVICE_OWNED_SERVER_ARG.as_bytes()
}

fn service_child_environment_has_generation(environ: &[u8], generation: &str) -> bool {
    let prefix = format!("{}=", crate::common::SERVICE_OWNED_SERVER_GENERATION_ENV);
    let mut matches = environ
        .split(|byte| *byte == 0)
        .filter(|entry| entry.starts_with(prefix.as_bytes()))
        .map(|entry| &entry[prefix.len()..]);
    matches.next() == Some(generation.as_bytes()) && matches.next().is_none()
}

fn classify_service_child_proc_error(
    pid: u32,
    label: &str,
    err: hbb_common::anyhow::Error,
) -> ServiceChildIdentityState {
    if !service_child_pid_exists(pid) {
        ServiceChildIdentityState::Absent
    } else {
        ServiceChildIdentityState::Unavailable(format!("{label} unavailable: {err}"))
    }
}

fn service_child_pid_exists(pid: u32) -> bool {
    let Ok(pid) = hbb_common::libc::pid_t::try_from(pid) else {
        return false;
    };
    if unsafe { hbb_common::libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() != Some(hbb_common::libc::ESRCH)
}

fn service_child_pidfd_open_is_forced_unavailable_for_smoke() -> bool {
    #[cfg(debug_assertions)]
    {
        std::env::var_os(SERVICE_CHILD_FORCE_PIDFD_UNAVAILABLE_FOR_SMOKE_ENV).as_deref()
            == Some(std::ffi::OsStr::new("1"))
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

pub(crate) fn service_child_is_unsupervised_recovery_fixture() -> bool {
    #[cfg(debug_assertions)]
    {
        std::env::var_os(SERVICE_CHILD_UNSUPERVISED_RECOVERY_FIXTURE_ENV).as_deref()
            == Some(std::ffi::OsStr::new("1"))
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

fn open_service_child_pidfd(pid: u32) -> ResultType<PidFdOpen> {
    let pid = hbb_common::libc::pid_t::try_from(pid)
        .map_err(|_| anyhow!("Service child pid does not fit pid_t"))?;
    if service_child_pidfd_open_is_forced_unavailable_for_smoke() {
        log::warn!(
            "Smoke forced pidfd_open unavailable for service child pid {pid}; exercising fail-closed recovery refusal"
        );
        return Ok(PidFdOpen::Unsupported);
    }
    let fd = unsafe { hbb_common::libc::syscall(hbb_common::libc::SYS_pidfd_open, pid, 0) };
    if fd >= 0 {
        let fd = c_int::try_from(fd).map_err(|_| anyhow!("pidfd does not fit c_int"))?;
        return Ok(PidFdOpen::Available(unsafe { File::from_raw_fd(fd) }));
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(hbb_common::libc::ENOSYS) => Ok(PidFdOpen::Unsupported),
        Some(hbb_common::libc::ESRCH) => Ok(PidFdOpen::Absent),
        _ => Err(anyhow!(
            "Failed to open pidfd for service child pid {pid}: {err}"
        )),
    }
}

fn service_child_pidfd_exited(pidfd: &File, timeout: Duration) -> ResultType<bool> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout_ms = if timeout.is_zero() {
            0
        } else {
            i32::try_from(remaining.as_millis().min(i32::MAX as u128)).unwrap_or(i32::MAX)
        };
        let mut pollfd = hbb_common::libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: hbb_common::libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { hbb_common::libc::poll(&mut pollfd, 1, timeout_ms) };
        if rc > 0 {
            if pollfd.revents & (hbb_common::libc::POLLIN | hbb_common::libc::POLLHUP) != 0 {
                return Ok(true);
            }
            bail!("Unexpected pidfd poll events: {}", pollfd.revents);
        }
        if rc == 0 {
            return Ok(false);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(hbb_common::libc::EINTR) {
            return Err(anyhow!("Failed to poll service child pidfd: {err}"));
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
    }
}

fn send_service_child_pidfd_signal(pidfd: &File, signal: c_int) -> ResultType<bool> {
    let rc = unsafe {
        hbb_common::libc::syscall(
            hbb_common::libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<hbb_common::libc::siginfo_t>(),
            0,
        )
    };
    if rc == 0 {
        return Ok(false);
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(hbb_common::libc::ESRCH) {
        return Ok(true);
    }
    Err(anyhow!(
        "Failed to signal service child through pidfd: {err}"
    ))
}

fn syscall_succeeded(result: hbb_common::libc::c_long) -> std::io::Result<()> {
    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

struct ServiceChildBootstrap {
    ready: File,
}

impl ServiceChildBootstrap {
    fn create() -> ResultType<(Self, File)> {
        let mut descriptors = [-1; 2];
        let rc = unsafe {
            hbb_common::libc::pipe2(
                descriptors.as_mut_ptr(),
                hbb_common::libc::O_CLOEXEC | hbb_common::libc::O_NONBLOCK,
            )
        };
        if rc != 0 {
            return Err(anyhow!(
                "Failed to create the Linux service-child bootstrap pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        let ready = unsafe { File::from_raw_fd(descriptors[0]) };
        let child = unsafe { File::from_raw_fd(descriptors[1]) };
        Ok((Self { ready }, child))
    }

    fn wait_for_stop(
        pid: hbb_common::libc::pid_t,
        expected_signal: c_int,
        deadline: Instant,
        label: &str,
    ) -> ResultType<()> {
        loop {
            let mut status = 0;
            let observed = unsafe {
                hbb_common::libc::waitpid(
                    pid,
                    &mut status,
                    hbb_common::libc::WNOHANG | hbb_common::libc::WUNTRACED,
                )
            };
            if observed == pid {
                if hbb_common::libc::WIFSTOPPED(status)
                    && hbb_common::libc::WSTOPSIG(status) == expected_signal
                {
                    return Ok(());
                }
                if hbb_common::libc::WIFEXITED(status) {
                    bail!(
                        "Linux service child exited during {label}: status={}",
                        hbb_common::libc::WEXITSTATUS(status)
                    );
                }
                if hbb_common::libc::WIFSIGNALED(status) {
                    bail!(
                        "Linux service child was killed during {label}: signal={}",
                        hbb_common::libc::WTERMSIG(status)
                    );
                }
                bail!("Linux service child stopped unexpectedly during {label}");
            }
            if observed == -1 {
                return Err(anyhow!(
                    "Failed waiting for the Linux service child during {label}: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if Instant::now() >= deadline {
                bail!("Timed out waiting for the Linux service child during {label}");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn wait_for_ready_marker(&mut self, deadline: Instant) -> ResultType<()> {
        let mut marker = [0u8; 1];
        loop {
            match self.ready.read(&mut marker) {
                Ok(1) if marker[0] == SERVICE_CHILD_BOOTSTRAP_READY => return Ok(()),
                Ok(1) => bail!("Linux service child returned an invalid bootstrap marker"),
                Ok(0) => bail!("Linux service child closed its bootstrap pipe before readiness"),
                Ok(_) => bail!("Linux service child returned an invalid bootstrap marker length"),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(err) => {
                    return Err(anyhow!(
                        "Failed reading the Linux service-child bootstrap marker: {err}"
                    ))
                }
            }
            if Instant::now() >= deadline {
                bail!("Timed out waiting for the Linux service-child bootstrap marker");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn prepare_stopped(&mut self, pid: hbb_common::libc::pid_t) -> ResultType<()> {
        let deadline = Instant::now() + SERVICE_CHILD_BOOTSTRAP_TIMEOUT;
        self.wait_for_ready_marker(deadline)?;
        Self::wait_for_stop(
            pid,
            hbb_common::libc::SIGSTOP,
            deadline,
            "nondumpable readiness stop",
        )
    }

    fn resume(self, pid: hbb_common::libc::pid_t) -> ResultType<()> {
        drop(self.ready);
        syscall_succeeded(unsafe {
            hbb_common::libc::syscall(hbb_common::libc::SYS_kill, pid, hbb_common::libc::SIGCONT)
        })
        .map_err(|err| anyhow!("Failed to continue the protected service child: {err}"))
    }
}

fn clear_descriptor_close_on_exec(fd: c_int) -> std::io::Result<()> {
    syscall_succeeded(unsafe {
        hbb_common::libc::syscall(
            hbb_common::libc::SYS_fcntl,
            fd,
            hbb_common::libc::F_SETFD,
            0,
        )
    })
}

fn service_owned_process_dumpability() -> hbb_common::libc::c_long {
    unsafe {
        hbb_common::libc::syscall(
            hbb_common::libc::SYS_prctl,
            hbb_common::libc::PR_GET_DUMPABLE,
            0,
            0,
            0,
            0,
        )
    }
}

fn make_service_owned_process_nondumpable() -> ResultType<()> {
    let started_dumpable = service_owned_process_dumpability();
    if hbb_common::users::get_current_uid() != 0
        && !service_child_is_unsupervised_recovery_fixture()
        && started_dumpable != 0
    {
        bail!("Active-user service child did not enter its final image nondumpable");
    }
    syscall_succeeded(unsafe {
        hbb_common::libc::syscall(
            hbb_common::libc::SYS_prctl,
            hbb_common::libc::PR_SET_DUMPABLE,
            0,
            0,
            0,
            0,
        )
    })
    .map_err(|err| anyhow!("Failed to disable Linux service-child dumpability: {err}"))?;
    let dumpable = service_owned_process_dumpability();
    if dumpable != 0 {
        bail!("Linux service child remained dumpable after hardening");
    }
    Ok(())
}

fn publish_service_child_bootstrap_ready(bootstrap_fd: c_int) -> ResultType<()> {
    let marker = [SERVICE_CHILD_BOOTSTRAP_READY];
    let written = unsafe {
        hbb_common::libc::syscall(
            hbb_common::libc::SYS_write,
            bootstrap_fd,
            marker.as_ptr(),
            marker.len(),
        )
    };
    let write_result = if written == marker.len() as c_long {
        Ok(())
    } else if written == -1 {
        Err(anyhow!(
            "Failed to publish Linux service-child bootstrap readiness: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Err(anyhow!(
            "Linux service-child bootstrap readiness write was incomplete"
        ))
    };
    let close_result = syscall_succeeded(unsafe {
        hbb_common::libc::syscall(hbb_common::libc::SYS_close, bootstrap_fd)
    })
    .map_err(|err| anyhow!("Failed to close the service-child bootstrap descriptor: {err}"));
    write_result?;
    close_result?;
    syscall_succeeded(unsafe {
        hbb_common::libc::syscall(
            hbb_common::libc::SYS_kill,
            hbb_common::libc::syscall(hbb_common::libc::SYS_getpid),
            hbb_common::libc::SIGSTOP,
        )
    })
    .map_err(|err| anyhow!("Failed to enter the service-child readiness stop: {err}"))
}

#[derive(Clone, Copy)]
enum ServiceDescriptorDisposition {
    Close,
    CloseOnExec,
}

fn linux_service_descriptor_upper_bound() -> ResultType<c_int> {
    let raw = fs::read_to_string("/proc/sys/fs/nr_open")
        .map_err(|err| anyhow!("Failed to read the Linux descriptor-table bound: {err}"))?;
    let value = raw.trim_end_matches('\n');
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        bail!("Linux descriptor-table bound is not canonical decimal");
    }
    let last_fd = value
        .parse::<c_int>()
        .map_err(|err| anyhow!("Linux descriptor-table bound is invalid: {err}"))?;
    if last_fd <= hbb_common::libc::STDERR_FILENO {
        bail!("Linux descriptor-table bound does not cover non-stdio descriptors");
    }
    Ok(last_fd)
}

fn constrain_service_owned_nonstdio_descriptors(
    last_fd: c_int,
    disposition: ServiceDescriptorDisposition,
) -> std::io::Result<()> {
    let close_range_flags = match disposition {
        ServiceDescriptorDisposition::Close => 0,
        ServiceDescriptorDisposition::CloseOnExec => hbb_common::libc::CLOSE_RANGE_CLOEXEC,
    };
    unsafe {
        if hbb_common::libc::syscall(
            hbb_common::libc::SYS_close_range,
            (hbb_common::libc::STDERR_FILENO + 1) as c_uint,
            c_uint::MAX,
            close_range_flags,
        ) == 0
        {
            return Ok(());
        }

        for fd in (hbb_common::libc::STDERR_FILENO + 1)..=last_fd {
            match disposition {
                ServiceDescriptorDisposition::Close => {
                    if hbb_common::libc::syscall(hbb_common::libc::SYS_close, fd) == -1 {
                        let close_err = std::io::Error::last_os_error();
                        if hbb_common::libc::syscall(
                            hbb_common::libc::SYS_fcntl,
                            fd,
                            hbb_common::libc::F_GETFD,
                        ) != -1
                            || std::io::Error::last_os_error().raw_os_error()
                                != Some(hbb_common::libc::EBADF)
                        {
                            return Err(close_err);
                        }
                    }
                }
                ServiceDescriptorDisposition::CloseOnExec => {
                    let descriptor_flags = hbb_common::libc::syscall(
                        hbb_common::libc::SYS_fcntl,
                        fd,
                        hbb_common::libc::F_GETFD,
                    );
                    if descriptor_flags == -1 {
                        let err = std::io::Error::last_os_error();
                        if err.raw_os_error() == Some(hbb_common::libc::EBADF) {
                            continue;
                        }
                        return Err(err);
                    }
                    if descriptor_flags & c_long::from(hbb_common::libc::FD_CLOEXEC) == 0
                        && hbb_common::libc::syscall(
                            hbb_common::libc::SYS_fcntl,
                            fd,
                            hbb_common::libc::F_SETFD,
                            descriptor_flags | c_long::from(hbb_common::libc::FD_CLOEXEC),
                        ) == -1
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn close_service_owned_nonstdio_descriptors() -> ResultType<()> {
    let last_fd = linux_service_descriptor_upper_bound()?;
    constrain_service_owned_nonstdio_descriptors(last_fd, ServiceDescriptorDisposition::Close)
        .map_err(|err| anyhow!("Failed to close inherited non-stdio descriptors: {err}"))
}

fn arm_linux_child_parent_death(expected_parent: hbb_common::libc::pid_t) -> std::io::Result<()> {
    // `PR_SET_PDEATHSIG` is cleared by a credential change and can also be cleared by
    // executing a privileged file. The service bootstrap calls this after its optional
    // uid/gid drop and again in the final server image; same-principal children arm it
    // directly before exec. Setting it before checking getppid closes the parent-exit
    // race: an earlier exit changes the observed parent, while a later exit delivers
    // SIGKILL to this exact child.
    syscall_succeeded(unsafe {
        hbb_common::libc::syscall(
            hbb_common::libc::SYS_prctl,
            hbb_common::libc::PR_SET_PDEATHSIG,
            hbb_common::libc::SIGKILL,
            0,
            0,
            0,
        )
    })?;
    let actual_parent = unsafe { hbb_common::libc::syscall(hbb_common::libc::SYS_getppid) };
    if actual_parent != hbb_common::libc::c_long::from(expected_parent) {
        // Keep the pre-exec error path allocation-free as well as the success path.
        return Err(std::io::Error::from_raw_os_error(hbb_common::libc::ESRCH));
    }
    Ok(())
}

pub(crate) fn configure_command_kill_on_parent_death(command: &mut Command) -> std::io::Result<()> {
    let expected_parent = hbb_common::libc::pid_t::try_from(std::process::id()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "RustDesk parent pid does not fit pid_t",
        )
    })?;
    // This hook runs before the ordinary descriptor-policy hook registered by
    // `run_me_with_env_inner`. Both callbacks use only raw syscalls and captured data.
    unsafe {
        command.pre_exec(move || arm_linux_child_parent_death(expected_parent));
    }
    Ok(())
}

fn configure_service_child_pre_exec(
    command: &mut Command,
    expected_parent: hbb_common::libc::pid_t,
    credentials: Option<ServiceChildCredentials>,
    executable_fd: Option<c_int>,
    bootstrap_fd: Option<c_int>,
) -> ResultType<()> {
    let descriptor_upper_bound = linux_service_descriptor_upper_bound()?;
    // The closure performs only raw Linux syscalls and reads already-owned memory. It does
    // not allocate, lock, inspect the environment, or call NSS after fork. The parent
    // resolves the complete credential set before registering this hook.
    unsafe {
        command.pre_exec(move || {
            constrain_service_owned_nonstdio_descriptors(
                descriptor_upper_bound,
                ServiceDescriptorDisposition::CloseOnExec,
            )?;
            if let Some(credentials) = credentials.as_ref() {
                syscall_succeeded(hbb_common::libc::syscall(
                    hbb_common::libc::SYS_setgroups,
                    credentials.supplementary_groups.len(),
                    credentials.supplementary_groups.as_ptr(),
                ))?;
                syscall_succeeded(hbb_common::libc::syscall(
                    hbb_common::libc::SYS_setresgid,
                    credentials.gid,
                    credentials.gid,
                    credentials.gid,
                ))?;
                syscall_succeeded(hbb_common::libc::syscall(
                    hbb_common::libc::SYS_setresuid,
                    credentials.uid,
                    credentials.uid,
                    credentials.uid,
                ))?;
            }
            if let Some(executable_fd) = executable_fd {
                // Keep the descriptor close-on-exec in the multithreaded parent, then clear
                // the flag only in this forked child. /proc/self/fd/N cannot be executed
                // while N is close-on-exec; the final image closes N immediately at entry.
                clear_descriptor_close_on_exec(executable_fd)?;
            }
            if let Some(bootstrap_fd) = bootstrap_fd {
                clear_descriptor_close_on_exec(bootstrap_fd)?;
            }
            syscall_succeeded(hbb_common::libc::syscall(
                hbb_common::libc::SYS_prctl,
                hbb_common::libc::PR_SET_NO_NEW_PRIVS,
                1,
                0,
                0,
                0,
            ))?;
            arm_linux_child_parent_death(expected_parent)
        });
    }
    Ok(())
}

fn insert_nonempty_env(command: &mut Command, key: &str, value: &str) {
    if !value.is_empty() {
        command.env(key, value);
    }
}

fn files_have_exact_contents(
    left: &mut File,
    right: &mut File,
    length: u64,
) -> std::io::Result<bool> {
    let mut left_buffer = [0u8; 16 * 1024];
    let mut right_buffer = [0u8; 16 * 1024];
    let mut remaining = length;
    while remaining != 0 {
        let count = usize::try_from(remaining.min(left_buffer.len() as u64)).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "service executable comparison length does not fit usize",
            )
        })?;
        left.read_exact(&mut left_buffer[..count])?;
        right.read_exact(&mut right_buffer[..count])?;
        if left_buffer[..count] != right_buffer[..count] {
            return Ok(false);
        }
        remaining -= count as u64;
    }
    let mut left_tail = [0u8; 1];
    let mut right_tail = [0u8; 1];
    Ok(left.read(&mut left_tail)? == 0 && right.read(&mut right_tail)? == 0)
}

fn open_active_user_service_child_executable() -> ResultType<File> {
    let mut running = fs::OpenOptions::new()
        .read(true)
        .custom_flags(hbb_common::libc::O_CLOEXEC)
        .open("/proc/self/exe")
        .map_err(|err| anyhow!("Failed to open the running service executable object: {err}"))?;
    let running_metadata = running
        .metadata()
        .map_err(|err| anyhow!("Failed to inspect the running service executable object: {err}"))?;
    if !running_metadata.is_file() || running_metadata.uid() != 0 || running_metadata.gid() != 0 {
        bail!("Active-user service children require a root-owned regular service executable");
    }

    if running_metadata.mode() & 0o7777 == 0o711 {
        return Ok(running);
    }
    if running_metadata.mode() & 0o7777 != 0o755
        || fs::canonicalize("/proc/self/exe")? != Path::new(LINUX_INSTALLED_EXECUTABLE_PATHS[0])
    {
        bail!(
            "Active-user service children require the exact installed service image or an execute-only manual image"
        );
    }

    let child_path = Path::new(LINUX_INSTALLED_SERVICE_CHILD_EXECUTABLE);
    let child_parent = child_path
        .parent()
        .ok_or_else(|| anyhow!("Installed service-child executable has no parent"))?;
    let parent_metadata = fs::symlink_metadata(child_parent)
        .map_err(|err| anyhow!("Failed to inspect the service-child executable parent: {err}"))?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != 0
        || parent_metadata.gid() != 0
        || parent_metadata.mode() & 0o022 != 0
    {
        bail!("Installed service-child executable parent is not trusted root-owned state");
    }
    let mut child = fs::OpenOptions::new()
        .read(true)
        .custom_flags(hbb_common::libc::O_CLOEXEC | hbb_common::libc::O_NOFOLLOW)
        .open(child_path)
        .map_err(|err| anyhow!("Failed to open the installed service-child executable: {err}"))?;
    let child_metadata = child.metadata().map_err(|err| {
        anyhow!("Failed to inspect the installed service-child executable: {err}")
    })?;
    if !child_metadata.is_file()
        || child_metadata.uid() != 0
        || child_metadata.gid() != 0
        || child_metadata.mode() & 0o7777 != 0o711
        || child_metadata.len() != running_metadata.len()
    {
        bail!("Installed service-child executable is not exact root/root mode 0711 state");
    }
    if !files_have_exact_contents(&mut running, &mut child, running_metadata.len())
        .map_err(|err| anyhow!("Failed to compare the installed service-child executable: {err}"))?
    {
        bail!("Installed service-child executable differs from the running service image");
    }
    Ok(child)
}

fn try_start_server_(desktop: &Desktop, runtime: &ServiceRuntime) -> ResultType<OwnedServiceChild> {
    let principal = selected_service_child_principal(desktop)?
        .ok_or_else(|| anyhow!("Cannot start a service child without a selected desktop"))?;
    let parent_pid = hbb_common::libc::pid_t::try_from(std::process::id())
        .map_err(|_| anyhow!("Service supervisor pid does not fit pid_t"))?;
    let credentials = match principal {
        ServiceChildPrincipal::RootService => None,
        ServiceChildPrincipal::ActiveDesktopUser => Some(ServiceChildCredentials::resolve(
            &desktop.uid,
            &desktop.username,
        )?),
    };
    let expected_child_uid = credentials
        .as_ref()
        .map(|credentials| credentials.uid as u32)
        .unwrap_or_else(|| unsafe { hbb_common::libc::geteuid() as u32 });

    // A credential-changing pre_exec hook makes /proc/self/exe inaccessible before Command
    // performs execve: procfs guards that symlink with a ptrace credential check and the UID
    // transition resets dumpability. Open the selected execute-only object while still privileged
    // and let the post-drop child execute its inherited descriptor instead. An installed readable
    // UI/service image must have an exact byte-identical root/root mode-0711 package twin; an
    // execute-only manual image can use its current inode directly. Keep FD_CLOEXEC set in the
    // multithreaded supervisor, clear it only inside the forked child, and require the final image
    // to close that one descriptor immediately. The root-principal path retains /proc/self/exe.
    let child_executable = if credentials.is_some() {
        let executable = open_active_user_service_child_executable()?;
        let suid_dumpable = fs::read_to_string("/proc/sys/fs/suid_dumpable")
            .map_err(|err| anyhow!("Failed to read the Linux suid_dumpable policy: {err}"))?;
        if suid_dumpable.trim() != "0" {
            bail!("Active-user service children require fs.suid_dumpable=0");
        }
        Some(executable)
    } else {
        None
    };
    let child_executable_metadata = match child_executable.as_ref() {
        Some(executable) => executable
            .metadata()
            .map_err(|err| anyhow!("Failed to inspect the selected service-child image: {err}"))?,
        None => fs::metadata("/proc/self/exe")
            .map_err(|err| anyhow!("Failed to inspect the root service-child image: {err}"))?,
    };
    set_service_child_executable_identity(&child_executable_metadata)?;
    let executable_path = child_executable
        .as_ref()
        .map(|executable| format!("/proc/self/fd/{}", executable.as_raw_fd()))
        .unwrap_or_else(|| "/proc/self/exe".to_owned());
    let mut command = Command::new(executable_path);
    let (mut bootstrap, bootstrap_child) = ServiceChildBootstrap::create()?;
    let bootstrap_fd = bootstrap_child.as_raw_fd();
    command
        .arg("--server")
        .arg(crate::common::SERVICE_OWNED_SERVER_ARG)
        .current_dir("/")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env(
            crate::common::SERVICE_OWNED_SERVER_LAUNCH_PARENT_ENV,
            parent_pid.to_string(),
        )
        .env(
            crate::common::SERVICE_OWNED_SERVER_GENERATION_ENV,
            &runtime.generation,
        )
        .env(
            crate::common::SERVICE_OWNED_SERVER_BOOTSTRAP_FD_ENV,
            bootstrap_fd.to_string(),
        );
    if let Some(executable) = child_executable.as_ref() {
        command.env(
            crate::common::SERVICE_OWNED_SERVER_EXECUTABLE_FD_ENV,
            executable.as_raw_fd().to_string(),
        );
    }

    match &credentials {
        Some(credentials) => {
            command
                .env("HOME", &credentials.home)
                .env("USER", &credentials.username)
                .env("LOGNAME", &credentials.username)
                .env("XDG_RUNTIME_DIR", format!("/run/user/{}", credentials.uid));
        }
        None => {
            let trusted_home = hbb_common::platform::linux::get_effective_home_dir_trusted()
                .ok_or_else(|| anyhow!("Root service child home is unavailable"))?;
            command.env("HOME", trusted_home);
        }
    }
    insert_nonempty_env(&mut command, "DISPLAY", &desktop.display);
    insert_nonempty_env(&mut command, "XAUTHORITY", &desktop.xauth);
    insert_nonempty_env(&mut command, "WAYLAND_DISPLAY", &desktop.wl_display);
    insert_nonempty_env(&mut command, "DBUS_SESSION_BUS_ADDRESS", &desktop.dbus);
    command.env("TERM", service_child_terminal_type());

    let executable_fd = child_executable
        .as_ref()
        .map(|executable| executable.as_raw_fd());
    configure_service_child_pre_exec(
        &mut command,
        parent_pid,
        credentials,
        executable_fd,
        Some(bootstrap_fd),
    )?;
    let spawn_result = command.spawn();
    drop(child_executable);
    drop(bootstrap_child);
    let mut process = spawn_result?;
    let pid = process.id();
    let child_pid = hbb_common::libc::pid_t::try_from(pid)
        .map_err(|_| anyhow!("Service child pid does not fit pid_t"))?;
    if let Err(err) = bootstrap.prepare_stopped(child_pid) {
        stop_unregistered_service_child(&mut process, pid);
        return Err(err);
    }
    let record =
        match service_child_record_for_process(pid, expected_child_uid, &runtime.generation) {
            Ok(record) => record,
            Err(err) => {
                stop_unregistered_service_child(&mut process, pid);
                return Err(err);
            }
        };
    if let Err(err) = runtime.publish_record(&record) {
        stop_unregistered_service_child(&mut process, pid);
        match runtime.read_record() {
            Ok(Some(actual)) if actual == record => {
                if let Err(remove_err) = runtime.remove_record(&record) {
                    log::error!(
                        "Failed to remove the exact record after child registration failed: {remove_err}"
                    );
                }
            }
            Ok(_) => {}
            Err(read_err) => log::error!(
                "Failed to inspect the record after child registration failed: {read_err}"
            ),
        }
        return Err(err);
    }
    if let Err(err) = bootstrap.resume(child_pid) {
        stop_unregistered_service_child(&mut process, pid);
        if let Err(remove_err) = runtime.remove_record(&record) {
            log::error!(
                "Failed to remove the exact record after child bootstrap failed: {remove_err}"
            );
        }
        return Err(err);
    }
    Ok(OwnedServiceChild { process, record })
}

fn stop_unregistered_service_child(process: &mut Child, pid: u32) {
    if let Err(err) = process.kill() {
        log::error!("Failed to force-stop unregistered Linux service child pid {pid}: {err}");
    }
    if let Err(err) = process.wait() {
        log::error!("Failed to reap unregistered Linux service child pid {pid}: {err}");
    }
}

pub fn require_service_owned_server_parent_liveness() -> ResultType<()> {
    if !crate::common::is_service_owned_server_process() {
        bail!("Parent liveness is available only to a service-owned server");
    }
    // The root-owned mode-0711 installed image and fs.suid_dumpable=0 keep an active-user child
    // nondumpable across exec. Reassert and verify that state as the first final-image operation,
    // before any service-owned credential or configuration is loaded.
    make_service_owned_process_nondumpable()?;
    let expected_parent = std::env::var(crate::common::SERVICE_OWNED_SERVER_LAUNCH_PARENT_ENV)
        .map_err(|_| anyhow!("Service-owned server launch parent is unavailable"))?
        .parse::<hbb_common::libc::pid_t>()
        .map_err(|err| anyhow!("Service-owned server launch parent is invalid: {err}"))?;
    if expected_parent <= 0 {
        bail!("Service-owned server launch parent is invalid");
    }
    let generation = std::env::var(crate::common::SERVICE_OWNED_SERVER_GENERATION_ENV)
        .map_err(|_| anyhow!("Service-owned server generation is unavailable"))?;
    validate_canonical_uuid(&generation, "service generation")?;
    if service_child_is_unsupervised_recovery_fixture() {
        // A debug-only lifecycle fixture needs one exact live service-role process whose parent
        // intentionally remains alive while a second supervisor exercises stale-record refusal
        // and numeric-PID reuse. Production builds compile this branch to false. Real supervisor
        // launches clear the ambient environment and always use the bootstrap descriptor below.
        arm_linux_child_parent_death(expected_parent)?;
        return Ok(());
    }
    let executable_fd = match std::env::var(crate::common::SERVICE_OWNED_SERVER_EXECUTABLE_FD_ENV) {
        Ok(value) => Some(
            value
                .parse::<c_int>()
                .map_err(|err| anyhow!("Service executable descriptor is invalid: {err}"))?,
        ),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("Service executable descriptor is not valid Unicode")
        }
    };
    let bootstrap_fd = std::env::var(crate::common::SERVICE_OWNED_SERVER_BOOTSTRAP_FD_ENV)
        .map_err(|_| anyhow!("Service-owned server bootstrap descriptor is unavailable"))?
        .parse::<c_int>()
        .map_err(|err| anyhow!("Service-owned server bootstrap descriptor is invalid: {err}"))?;
    if bootstrap_fd <= hbb_common::libc::STDERR_FILENO || Some(bootstrap_fd) == executable_fd {
        bail!("Service-owned server bootstrap descriptor is invalid");
    }
    if hbb_common::users::get_current_uid() == 0 {
        if executable_fd.is_some() {
            bail!("Root service child unexpectedly inherited an executable descriptor");
        }
    } else {
        let executable_fd = executable_fd
            .filter(|fd| *fd > hbb_common::libc::STDERR_FILENO)
            .ok_or_else(|| {
                anyhow!("Non-root service child executable descriptor is unavailable")
            })?;
        nix::unistd::close(executable_fd)
            .map_err(|err| anyhow!("Failed to close the service executable descriptor: {err}"))?;
    }
    arm_linux_child_parent_death(expected_parent)?;
    publish_service_child_bootstrap_ready(bootstrap_fd)
}

#[inline]
fn start_server(
    desktop: &Desktop,
    server: &mut Option<OwnedServiceChild>,
    runtime: &ServiceRuntime,
) {
    match try_start_server_(desktop, runtime) {
        Ok(ps) => *server = Some(ps),
        Err(err) => {
            log::error!("Failed to start server: {}", err);
        }
    }
}

fn child_pid(child: &OwnedServiceChild, label: &str) -> Option<hbb_common::libc::pid_t> {
    match hbb_common::libc::pid_t::try_from(child.process.id()) {
        Ok(pid) if pid > 0 => Some(pid),
        _ => {
            log::warn!(
                "Refusing to signal {label} child with invalid pid {}",
                child.process.id()
            );
            None
        }
    }
}

fn signal_child(child: &OwnedServiceChild, signal: c_int, label: &str) -> bool {
    let Some(pid) = child_pid(child, label) else {
        return false;
    };
    let rc = unsafe { hbb_common::libc::kill(pid, signal) };
    if rc == 0 {
        return true;
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(hbb_common::libc::ESRCH) {
        return true;
    }
    log::warn!("Failed to signal {label} child pid={pid}: {err}");
    false
}

fn wait_child_exit(
    child: &mut OwnedServiceChild,
    timeout: Duration,
    label: &str,
) -> ResultType<bool> {
    let started = Instant::now();
    loop {
        match child.process.try_wait() {
            Ok(Some(status)) => {
                log::info!("{label} child exited with {status}");
                return Ok(true);
            }
            Ok(None) if started.elapsed() < timeout => sleep_millis(50),
            Ok(None) => return Ok(false),
            Err(err) => return Err(anyhow!("Failed waiting for {label} child: {err}")),
        }
    }
}

fn remove_reaped_service_child_record(
    runtime: &ServiceRuntime,
    child: &OwnedServiceChild,
    label: &str,
) -> ResultType<()> {
    runtime.remove_record(&child.record).map_err(|err| {
        anyhow!(
            "Failed to remove exact {label} child record for pid {}: {err}",
            child.record.pid
        )
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServiceChildTermination {
    Absent,
    Graceful,
    Forced,
}

fn terminate_child_with_timeouts(
    child: &mut Option<OwnedServiceChild>,
    label: &str,
    runtime: &ServiceRuntime,
    graceful_timeout: Duration,
    forced_timeout: Duration,
) -> ResultType<ServiceChildTermination> {
    let Some(owned_child) = child.as_mut() else {
        return Ok(ServiceChildTermination::Absent);
    };
    let pid = owned_child.record.pid;
    if signal_child(owned_child, hbb_common::libc::SIGTERM, label)
        && wait_child_exit(owned_child, graceful_timeout, label).map_err(|err| {
            anyhow!("{err}; preserving exact {label} child pid {pid} ownership and recovery record")
        })?
    {
        remove_reaped_service_child_record(runtime, owned_child, label)?;
        drop(child.take());
        return Ok(ServiceChildTermination::Graceful);
    }

    log::warn!("{label} child did not exit after SIGTERM; forcing stop");
    let forced_kill_error = owned_child.process.kill().err();
    if wait_child_exit(owned_child, forced_timeout, label).map_err(|err| {
        anyhow!("{err}; preserving exact {label} child pid {pid} ownership and recovery record")
    })? {
        remove_reaped_service_child_record(runtime, owned_child, label)?;
        drop(child.take());
        return Ok(ServiceChildTermination::Forced);
    }

    if let Some(err) = forced_kill_error {
        bail!(
            "Failed to SIGKILL exact {label} child pid {pid}: {err}; bounded forced wait also expired, preserving direct child ownership and recovery record"
        );
    }
    bail!(
        "Exact {label} child pid {pid} remained unreaped after bounded SIGKILL wait; preserving direct child ownership and recovery record"
    )
}

fn terminate_child(
    child: &mut Option<OwnedServiceChild>,
    label: &str,
    runtime: &ServiceRuntime,
) -> ResultType<ServiceChildTermination> {
    terminate_child_with_timeouts(
        child,
        label,
        runtime,
        SERVICE_CHILD_GRACEFUL_STOP_TIMEOUT,
        SERVICE_CHILD_FORCED_STOP_TIMEOUT,
    )
}

fn stop_server(server: &mut Option<OwnedServiceChild>, runtime: &ServiceRuntime) -> ResultType<()> {
    terminate_child(server, "--server", runtime).map(|_| ())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ServiceChildDesktopIdentity {
    sid: String,
    username: String,
    uid: String,
    protocol: String,
    environment: DesktopSessionEnvironment,
}

impl ServiceChildDesktopIdentity {
    fn from_desktop(desktop: &Desktop) -> Self {
        Self {
            sid: desktop.sid.clone(),
            username: desktop.username.clone(),
            uid: desktop.uid.clone(),
            protocol: desktop.protocol.clone(),
            environment: DesktopSessionEnvironment {
                display: desktop.display.clone(),
                xauth: desktop.xauth.clone(),
                wl_display: desktop.wl_display.clone(),
                dbus: desktop.dbus.clone(),
            },
        }
    }
}

fn update_service_child_desktop_identity(
    previous: &mut ServiceChildDesktopIdentity,
    desktop: &Desktop,
) -> bool {
    let selected = ServiceChildDesktopIdentity::from_desktop(desktop);
    if *previous == selected {
        false
    } else {
        *previous = selected;
        true
    }
}

fn service_child_needs_replacement(
    desktop_identity_changed: bool,
    uid: &mut String,
    desktop: &Desktop,
) -> bool {
    if desktop.is_headless() {
        if !uid.is_empty() {
            // From having a monitor to not having a monitor.
            uid.clear();
            return true;
        }
    } else if !desktop.uid.is_empty() && (desktop_identity_changed || desktop.uid != *uid) {
        *uid = desktop.uid.clone();
        return true;
    }
    false
}

fn should_start_server(
    desktop_identity_changed: bool,
    uid: &mut String,
    desktop: &Desktop,
    server: &mut Option<OwnedServiceChild>,
    runtime: &ServiceRuntime,
) -> ResultType<bool> {
    let mut start_new = false;
    let should_kill =
        service_child_needs_replacement(desktop_identity_changed, uid, desktop);

    if should_kill {
        if server.is_some() {
            terminate_child(server, "--server", runtime)?;
        }
    }

    let exited = if let Some(ps) = server.as_mut() {
        match ps.process.try_wait() {
            Ok(Some(status)) => {
                log::info!("--server child exited with {status}");
                true
            }
            Ok(None) => false,
            Err(err) => {
                log::error!(
                    "Failed to inspect owned --server child pid {}; preserving ownership: {err}",
                    ps.record.pid
                );
                false
            }
        }
    } else {
        start_new = true;
        false
    };
    if exited {
        if let Some(ps) = server.take() {
            remove_reaped_service_child_record(runtime, &ps, "--server")?;
        }
        start_new = true;
    }
    Ok(start_new)
}

type LinuxServiceIpcThread = std::thread::JoinHandle<ResultType<()>>;

fn wait_for_linux_service_ipc_startup(
    startup: &mpsc::Receiver<Result<(), String>>,
    timeout: Duration,
) -> ResultType<()> {
    match startup.recv_timeout(timeout) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => bail!("Protected service IPC failed before readiness: {err}"),
        Err(mpsc::RecvTimeoutError::Timeout) => bail!(
            "Protected service IPC did not become ready within {} ms",
            timeout.as_millis()
        ),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            bail!("Protected service IPC thread ended before reporting readiness")
        }
    }
}

fn classify_linux_service_ipc_thread_outcome(
    outcome: std::thread::Result<ResultType<()>>,
    expected_shutdown: bool,
) -> ResultType<()> {
    match outcome {
        Ok(Ok(())) if expected_shutdown => Ok(()),
        Ok(Ok(())) => bail!("Protected service IPC thread stopped unexpectedly"),
        Ok(Err(err)) => Err(anyhow!("Protected service IPC thread failed: {err}")),
        Err(_) => bail!("Protected service IPC thread panicked"),
    }
}

fn observe_linux_service_ipc_thread(
    ipc_thread: &mut Option<LinuxServiceIpcThread>,
    running: &AtomicBool,
) -> ResultType<()> {
    let Some(handle) = ipc_thread.as_ref() else {
        bail!("Protected service IPC thread ownership disappeared");
    };
    if !handle.is_finished() {
        return Ok(());
    }
    let expected_shutdown = !running.load(Ordering::SeqCst);
    let handle = ipc_thread
        .take()
        .ok_or_else(|| anyhow!("Protected service IPC thread ownership disappeared"))?;
    classify_linux_service_ipc_thread_outcome(handle.join(), expected_shutdown)
}

fn merge_linux_service_result(
    result: &mut ResultType<()>,
    next: ResultType<()>,
    phase: &str,
) {
    if let Err(err) = next {
        if result.is_ok() {
            *result = Err(anyhow!("{phase}: {err}"));
        } else {
            log::error!("Linux service {phase} also failed: {err}");
        }
    }
}

pub fn start_os_service() -> ResultType<()> {
    let running = Arc::new(AtomicBool::new(true));
    let signal_running = running.clone();
    ctrlc::set_handler(move || {
        signal_running.store(false, Ordering::SeqCst);
        crate::server::request_graceful_shutdown();
    })
    .map_err(|err| anyhow!("Failed to install Linux service shutdown handlers: {err}"))?;

    let runtime = ServiceRuntime::acquire()?;
    runtime.recover_previous_child()?;
    // R-X13: the dormant uinput IPC listener is NOT stood up — on the pinned-X11
    // fork XTEST/enigo is the sole injection backend, so the world-mode _uinput_*
    // cross-uid sockets the X11 --server never connects to are absent (shrinking
    // the R-S11a cross-uid socket surface to _service alone).

    let (ipc_startup_tx, ipc_startup_rx) = mpsc::sync_channel(1);
    let mut ipc_thread = Some(
        std::thread::Builder::new()
            .name("rustdesk-service-ipc".to_owned())
            .spawn(move || {
                crate::ipc::start_linux_service_ipc_with_readiness(ipc_startup_tx)
            })
            .map_err(|err| anyhow!("Failed to start protected service IPC thread: {err}"))?,
    );
    if let Err(startup_err) =
        wait_for_linux_service_ipc_startup(&ipc_startup_rx, SERVICE_IPC_STARTUP_TIMEOUT)
    {
        crate::server::request_graceful_shutdown();
        let mut result = Err(startup_err);
        if let Some(handle) = ipc_thread.take() {
            merge_linux_service_result(
                &mut result,
                classify_linux_service_ipc_thread_outcome(handle.join(), true),
                "protected IPC startup cleanup",
            );
        }
        return result;
    }

    let mut desktop = Desktop::default();
    let mut sid = "".to_owned();
    let mut uid = "".to_owned();
    let mut server: Option<OwnedServiceChild> = None;
    let mut user_server: Option<OwnedServiceChild> = None;
    let mut root_server_desktop = ServiceChildDesktopIdentity::default();
    let mut user_server_desktop = ServiceChildDesktopIdentity::default();
    let mut result = (|| -> ResultType<()> {
        while running.load(Ordering::SeqCst) {
            observe_linux_service_ipc_thread(&mut ipc_thread, &running)?;
            if !running.load(Ordering::SeqCst) {
                break;
            }
            desktop.refresh();
            update_active_user_lookup_cache(&desktop);

            match selected_service_child_principal(&desktop)? {
                // Login wayland will try to start a headless root --server.
                Some(ServiceChildPrincipal::RootService) => {
                    // try kill subprocess "--server"
                    stop_server(&mut user_server, &runtime)?;
                    // try start subprocess "--server"
                    let desktop_identity_changed =
                        update_service_child_desktop_identity(&mut root_server_desktop, &desktop);
                    if should_start_server(
                        desktop_identity_changed,
                        &mut uid,
                        &desktop,
                        &mut server,
                        &runtime,
                    )? {
                        start_server(&desktop, &mut server, &runtime);
                    }
                }
                Some(ServiceChildPrincipal::ActiveDesktopUser) => {
                    // try kill subprocess "--server"
                    stop_server(&mut server, &runtime)?;

                    let desktop_identity_changed =
                        update_service_child_desktop_identity(&mut user_server_desktop, &desktop);

                    // try start subprocess "--server"
                    if should_start_server(
                        desktop_identity_changed,
                        &mut uid,
                        &desktop,
                        &mut user_server,
                        &runtime,
                    )? {
                        start_server(&desktop, &mut user_server, &runtime);
                    }
                }
                None => {
                    stop_server(&mut user_server, &runtime)?;
                    stop_server(&mut server, &runtime)?;
                }
            }

            let keeps_headless = sid.is_empty() && desktop.is_headless();
            let keeps_session = sid == desktop.sid;
            if keeps_headless || keeps_session {
                // for fixing https://github.com/rustdesk/rustdesk/issues/3129 to avoid too much dbus calling,
                sleep_millis(500);
            } else {
                sleep_millis(super::SERVICE_INTERVAL);
            }
            if !desktop.is_headless() {
                sid = desktop.sid.clone();
            }
        }
        Ok(())
    })();

    crate::server::request_graceful_shutdown();
    if let Some(handle) = ipc_thread.take() {
        merge_linux_service_result(
            &mut result,
            classify_linux_service_ipc_thread_outcome(handle.join(), true),
            "protected IPC drain",
        );
    }
    merge_linux_service_result(
        &mut result,
        terminate_child(&mut user_server, "--server", &runtime).map(|_| ()),
        "active-user service-child termination",
    );
    merge_linux_service_result(
        &mut result,
        terminate_child(&mut server, "--server", &runtime).map(|_| ()),
        "root service-child termination",
    );
    log::info!("Exit");
    result
}

#[inline]
/// Returns the cached active `(uid, username)` snapshot when available.
/// Callers that require a fresh seat0 lookup should call `get_values_of_seat0` directly.
pub fn get_active_user_id_name() -> (String, String) {
    if let Some(id_name) = get_active_user_id_name_from_cache() {
        return id_name;
    }
    let vec_id_name = get_values_of_seat0(&[1, 2]);
    (vec_id_name[0].clone(), vec_id_name[1].clone())
}

#[inline]
/// Returns the cached active uid when available.
/// Callers that require a fresh seat0 lookup should call `get_values_of_seat0` directly.
pub fn get_active_userid() -> String {
    if let Some((uid, _)) = get_active_user_id_name_from_cache() {
        return uid;
    }
    get_values_of_seat0(&[1])[0].clone()
}

#[inline]
/// Returns only the service loop's cached active uid, without performing a seat0 lookup.
pub fn get_active_userid_cached() -> Option<String> {
    get_active_user_id_name_from_cache().map(|(uid, _)| uid)
}

#[inline]
/// Returns the active uid from a fresh seat0 lookup, bypassing the service-loop cache.
pub fn get_active_userid_fresh() -> String {
    get_values_of_seat0(&[1])[0].clone()
}

pub fn is_login_wayland() -> bool {
    let files = ["/etc/gdm3/custom.conf", "/etc/gdm/custom.conf"];
    match (
        Regex::new(r"# *WaylandEnable *= *false"),
        Regex::new(r"WaylandEnable *= *true"),
    ) {
        (Ok(pat1), Ok(pat2)) => {
            for file in files {
                if let Ok(contents) = std::fs::read_to_string(file) {
                    return pat1.is_match(&contents) || pat2.is_match(&contents);
                }
            }
        }
        _ => {}
    }
    false
}

#[inline]
pub fn current_is_wayland() -> bool {
    return is_desktop_wayland() && unsafe { UNMODIFIED };
}

// to-do: test the other display manager
fn _get_display_manager() -> String {
    if let Ok(x) = std::fs::read_to_string("/etc/X11/default-display-manager") {
        if let Some(x) = x.split("/").last() {
            return x.to_owned();
        }
    }
    "gdm3".to_owned()
}

#[inline]
/// Returns the cached active username when available.
/// Callers that require a fresh seat0 lookup should call `get_values_of_seat0` directly.
pub fn get_active_username() -> String {
    if let Some((_, username)) = get_active_user_id_name_from_cache() {
        return username;
    }
    get_values_of_seat0(&[2])[0].clone()
}

pub fn get_user_home_by_name(username: &str) -> Option<PathBuf> {
    get_user_by_name(username).and_then(|user| {
        let home = user.home_dir();
        if Path::is_dir(home) {
            Some(PathBuf::from(home))
        } else {
            None
        }
    })
}

pub fn get_active_user_home() -> Option<PathBuf> {
    let username = get_active_username();
    if !username.is_empty() {
        match get_user_home_by_name(&username) {
            None => {
                // fallback to most common default pattern
                let home = PathBuf::from(format!("/home/{}", username));
                if home.exists() {
                    return Some(home);
                }
            }
            Some(home) => {
                return Some(home);
            }
        }
    }
    None
}

pub fn get_env_var(k: &str) -> String {
    match std::env::var(k) {
        Ok(v) => v,
        Err(_e) => "".to_owned(),
    }
}

fn is_flatpak() -> bool {
    std::path::PathBuf::from("/.flatpak-info").exists()
}

// True when seat0's active user is a non-login system account (shell /bin/false or nologin) — i.e.
// only the display-manager greeter is running and no real user has logged in yet. (Flatpak has no
// host seat visibility, so it is treated as not-prelogin.)
pub fn is_prelogin() -> bool {
    if is_flatpak() {
        return false;
    }
    let name = get_active_username();
    get_user_by_name(&name)
        .map(|user| is_non_login_shell(user.shell()))
        .unwrap_or(false)
}

fn is_non_login_shell(shell: &Path) -> bool {
    shell == Path::new("/bin/false")
        || shell
            .file_name()
            .map(|name| name == OsStr::new("nologin"))
            .unwrap_or(false)
}

// Check "Lock".
// "Switch user" can't be checked, because `get_values_of_seat0(&[0])` does not return the session.
// The logged in session is "online" not "active".
// And the "Switch user" screen is usually Wayland login session, which we do not support.
pub fn is_locked() -> bool {
    if is_prelogin() {
        return false;
    }

    let values = get_values_of_seat0(&[0]);
    // Though the values can't be empty, we still add check here for safety.
    // Because we cannot guarantee whether the internal implementation will change in the future.
    // https://github.com/rustdesk/hbb_common/blob/ebb4d4a48cf7ed6ca62e93f8ed124065c6408536/src/platform/linux.rs#L119
    if values.is_empty() {
        log::debug!("Failed to check is locked, values vector is empty.");
        return false;
    }
    let session = &values[0];
    if session.is_empty() {
        log::debug!("Failed to check is locked, session is empty.");
        return false;
    }
    is_session_locked(session)
}

fn effective_uid_is_root(effective_uid: hbb_common::libc::uid_t) -> bool {
    effective_uid == 0
}

pub fn is_root() -> bool {
    effective_uid_is_root(hbb_common::users::get_effective_uid())
}

pub fn get_pa_monitor() -> String {
    get_pa_sources()
        .drain(..)
        .map(|x| x.0)
        .filter(|x| x.contains("monitor"))
        .next()
        .unwrap_or("".to_owned())
}

pub fn get_pa_source_name(desc: &str) -> String {
    get_pa_sources()
        .drain(..)
        .filter(|x| x.1 == desc)
        .map(|x| x.0)
        .next()
        .unwrap_or("".to_owned())
}

pub fn get_pa_sources() -> Vec<(String, String)> {
    use pulsectl::controllers::*;
    let mut out = Vec::new();
    match SourceController::create() {
        Ok(mut handler) => {
            if let Ok(devices) = handler.list_devices() {
                for dev in devices.clone() {
                    out.push((
                        dev.name.unwrap_or("".to_owned()),
                        dev.description.unwrap_or("".to_owned()),
                    ));
                }
            }
        }
        Err(err) => {
            log::error!("Failed to get_pa_sources: {:?}", err);
        }
    }
    out
}

pub fn get_default_pa_source() -> Option<(String, String)> {
    use pulsectl::controllers::*;
    match SourceController::create() {
        Ok(mut handler) => {
            if let Ok(dev) = handler.get_default_device() {
                return Some((
                    dev.name.unwrap_or("".to_owned()),
                    dev.description.unwrap_or("".to_owned()),
                ));
            }
        }
        Err(err) => {
            log::error!("Failed to get_pa_source: {:?}", err);
        }
    }
    None
}

pub fn toggle_blank_screen(_v: bool) {
    // https://unix.stackexchange.com/questions/17170/disable-keyboard-mouse-input-on-unix-under-x
}

pub fn block_input(_v: bool) -> (bool, String) {
    (true, "".to_owned())
}

fn linux_path_is_supported_installed_executable(path: &Path) -> bool {
    LINUX_INSTALLED_EXECUTABLE_PATHS
        .iter()
        .any(|expected| path == Path::new(expected))
}

pub fn is_installed() -> bool {
    match std::env::current_exe() {
        Ok(path) => linux_path_is_supported_installed_executable(&path),
        Err(err) => {
            log::warn!("Failed to identify the current Linux executable: {err}");
            false
        }
    }
}

#[cfg(test)]
mod installed_executable_path_tests {
    use super::linux_path_is_supported_installed_executable;
    use std::path::Path;

    #[test]
    fn r_s11e80_linux_installed_classifier_requires_an_exact_supported_executable() {
        assert!(linux_path_is_supported_installed_executable(Path::new(
            "/usr/share/rustdesk/rustdesk"
        )));
        assert!(linux_path_is_supported_installed_executable(Path::new(
            "/usr/bin/rustdesk"
        )));
        for path in [
            "/usr/share/rustdesk",
            "/usr/share/rustdesk/rustdesk-helper",
            "/usr-malicious/rustdesk",
            "/nix/store/attacker-selected/bin/rustdesk",
        ] {
            assert!(
                !linux_path_is_supported_installed_executable(Path::new(path)),
                "unexpected installed executable classification: {path}"
            );
        }
    }
}

#[derive(Debug)]
struct ProcCommand {
    pid: u32,
    args: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcSnapshotLimit {
    NumericEntries,
    SelectedProcesses,
    EnvironmentCandidates,
    TotalBytes,
}

impl std::fmt::Display for ProcSnapshotLimit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::NumericEntries => "numeric /proc entry",
            Self::SelectedProcesses => "selected process",
            Self::EnvironmentCandidates => "desktop environment candidate",
            Self::TotalBytes => "aggregate /proc byte",
        };
        write!(formatter, "Linux desktop observation exceeded its {name} limit")
    }
}

#[derive(Debug)]
enum ProcSnapshotError {
    ProcUnavailable(std::io::Error),
    InvalidUid,
    Limit(ProcSnapshotLimit),
}

impl std::fmt::Display for ProcSnapshotError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProcUnavailable(err) => write!(formatter, "Linux /proc is unavailable: {err}"),
            Self::InvalidUid => formatter.write_str("selected desktop uid is not canonical"),
            Self::Limit(limit) => limit.fmt(formatter),
        }
    }
}

#[derive(Default)]
struct ProcSnapshotBudget {
    numeric_entries: usize,
    selected_processes: usize,
    environment_candidates: usize,
    total_bytes: usize,
}

impl ProcSnapshotBudget {
    fn charge_numeric_entry(&mut self) -> Result<(), ProcSnapshotError> {
        self.numeric_entries += 1;
        if self.numeric_entries > PROC_SNAPSHOT_MAX_NUMERIC_ENTRIES {
            return Err(ProcSnapshotError::Limit(
                ProcSnapshotLimit::NumericEntries,
            ));
        }
        Ok(())
    }

    fn charge_selected_process(&mut self) -> Result<(), ProcSnapshotError> {
        self.selected_processes += 1;
        if self.selected_processes > PROC_SNAPSHOT_MAX_SELECTED_PROCESSES {
            return Err(ProcSnapshotError::Limit(
                ProcSnapshotLimit::SelectedProcesses,
            ));
        }
        Ok(())
    }

    fn charge_environment_candidate(&mut self) -> Result<(), ProcSnapshotError> {
        self.environment_candidates += 1;
        if self.environment_candidates > PROC_SNAPSHOT_MAX_ENVIRONMENT_CANDIDATES {
            return Err(ProcSnapshotError::Limit(
                ProcSnapshotLimit::EnvironmentCandidates,
            ));
        }
        Ok(())
    }

    fn charge_bytes(&mut self, count: usize) -> Result<(), ProcSnapshotError> {
        self.total_bytes = self
            .total_bytes
            .checked_add(count)
            .filter(|total| *total <= PROC_SNAPSHOT_MAX_TOTAL_BYTES)
            .ok_or(ProcSnapshotError::Limit(ProcSnapshotLimit::TotalBytes))?;
        Ok(())
    }
}

fn proc_entry_pid(entry: &std::fs::DirEntry) -> Option<u32> {
    let file_name = entry.file_name();
    let pid_str = file_name.to_str()?;
    if !pid_str.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    pid_str.parse::<u32>().ok()
}

fn open_proc_process_dir(entry: &std::fs::DirEntry) -> Option<File> {
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(
            hbb_common::libc::O_CLOEXEC
                | hbb_common::libc::O_DIRECTORY
                | hbb_common::libc::O_NOFOLLOW,
        )
        .open(entry.path())
        .ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcNamespaceIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcSelectorNamespaceIdentity {
    mount: ProcNamespaceIdentity,
    network: ProcNamespaceIdentity,
}

struct ProcSelectorNamespaceAuthority {
    identity: ProcSelectorNamespaceIdentity,
    _mount_handle: File,
    _network_handle: File,
}

#[derive(Clone, Copy)]
enum SelectorNamespace {
    Mount,
    Network,
}

impl SelectorNamespace {
    fn current_path(self) -> &'static str {
        match self {
            Self::Mount => "/proc/self/ns/mnt",
            Self::Network => "/proc/self/ns/net",
        }
    }

    fn process_member(self) -> &'static [u8] {
        match self {
            Self::Mount => b"ns/mnt\0",
            Self::Network => b"ns/net\0",
        }
    }
}

fn proc_namespace_identity(namespace: &File) -> Option<ProcNamespaceIdentity> {
    let metadata = namespace.metadata().ok()?;
    metadata.is_file().then_some(ProcNamespaceIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn open_current_proc_namespace(namespace: SelectorNamespace) -> Result<File, ProcSnapshotError> {
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(hbb_common::libc::O_CLOEXEC)
        .open(namespace.current_path())
        .map_err(ProcSnapshotError::ProcUnavailable)
}

fn current_selector_namespace_authority(
) -> Result<ProcSelectorNamespaceAuthority, ProcSnapshotError> {
    let mount = open_current_proc_namespace(SelectorNamespace::Mount)?;
    let network = open_current_proc_namespace(SelectorNamespace::Network)?;
    let invalid = || {
        ProcSnapshotError::ProcUnavailable(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "current selector namespace has no stable file identity",
        ))
    };
    let identity = ProcSelectorNamespaceIdentity {
        mount: proc_namespace_identity(&mount).ok_or_else(invalid)?,
        network: proc_namespace_identity(&network).ok_or_else(invalid)?,
    };
    Ok(ProcSelectorNamespaceAuthority {
        identity,
        _mount_handle: mount,
        _network_handle: network,
    })
}

fn process_namespace_identity(
    process_dir: &File,
    namespace: SelectorNamespace,
) -> Option<ProcNamespaceIdentity> {
    // proc namespace entries are kernel-owned magic links. Following this fixed member is
    // intentional: the opened namespace object, not the procfs link inode, carries identity.
    let fd = unsafe {
        hbb_common::libc::openat(
            process_dir.as_raw_fd(),
            namespace.process_member().as_ptr().cast::<c_char>(),
            hbb_common::libc::O_RDONLY | hbb_common::libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    let namespace = unsafe { File::from_raw_fd(fd) };
    proc_namespace_identity(&namespace)
}

fn process_selector_namespace_identity(
    process_dir: &File,
) -> Option<ProcSelectorNamespaceIdentity> {
    Some(ProcSelectorNamespaceIdentity {
        mount: process_namespace_identity(process_dir, SelectorNamespace::Mount)?,
        network: process_namespace_identity(process_dir, SelectorNamespace::Network)?,
    })
}

fn process_shares_selector_namespaces(
    process_dir: &File,
    expected: ProcSelectorNamespaceIdentity,
) -> bool {
    process_selector_namespace_identity(process_dir) == Some(expected)
}

enum BoundedProcFile {
    Value(Vec<u8>),
    Unavailable,
    Oversized,
}

#[derive(Clone, Copy)]
enum ProcMember {
    Cgroup,
    Cmdline,
    Environ,
}

impl ProcMember {
    fn nul_terminated_name(self) -> &'static [u8] {
        match self {
            Self::Cgroup => b"cgroup\0",
            Self::Cmdline => b"cmdline\0",
            Self::Environ => b"environ\0",
        }
    }
}

fn read_bounded_proc_reader(
    reader: &mut impl std::io::Read,
    per_file_limit: usize,
    budget: &mut ProcSnapshotBudget,
) -> Result<BoundedProcFile, ProcSnapshotError> {
    let remaining = PROC_SNAPSHOT_MAX_TOTAL_BYTES.saturating_sub(budget.total_bytes);
    if remaining == 0 {
        return Err(ProcSnapshotError::Limit(ProcSnapshotLimit::TotalBytes));
    }
    let read_limit = per_file_limit.min(remaining);
    let mut bytes = Vec::new();
    let read_result = reader
        .take((read_limit as u64).saturating_add(1))
        .read_to_end(&mut bytes);
    budget.charge_bytes(bytes.len())?;
    if read_result.is_err() {
        return Ok(BoundedProcFile::Unavailable);
    }
    if bytes.len() > per_file_limit {
        return Ok(BoundedProcFile::Oversized);
    }
    Ok(BoundedProcFile::Value(bytes))
}

fn read_bounded_proc_member(
    process_dir: &File,
    member: ProcMember,
    per_file_limit: usize,
    budget: &mut ProcSnapshotBudget,
) -> Result<BoundedProcFile, ProcSnapshotError> {
    let member = member.nul_terminated_name().as_ptr().cast::<c_char>();
    let fd = unsafe {
        hbb_common::libc::openat(
            process_dir.as_raw_fd(),
            member,
            hbb_common::libc::O_RDONLY
                | hbb_common::libc::O_CLOEXEC
                | hbb_common::libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Ok(BoundedProcFile::Unavailable);
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    read_bounded_proc_reader(&mut file, per_file_limit, budget)
}

fn read_proc_cmdline_args(
    process_dir: &File,
    budget: &mut ProcSnapshotBudget,
) -> Result<Option<Vec<String>>, ProcSnapshotError> {
    let BoundedProcFile::Value(cmdline) =
        read_bounded_proc_member(process_dir, ProcMember::Cmdline, PROC_CMDLINE_MAX_BYTES, budget)?
    else {
        return Ok(None);
    };
    Ok(parse_proc_cmdline_args(&cmdline))
}

fn parse_proc_cmdline_args(cmdline: &[u8]) -> Option<Vec<String>> {
    if cmdline.last() != Some(&0) {
        return None;
    }
    let mut args = Vec::new();
    for part in cmdline.split(|&byte| byte == 0).filter(|part| !part.is_empty()) {
        if args.len() == PROC_CMDLINE_MAX_ARGS {
            return None;
        }
        let Ok(part) = std::str::from_utf8(part) else {
            return None;
        };
        args.push(part.to_owned());
    }
    if args.is_empty() {
        None
    } else {
        Some(args)
    }
}

fn all_process_cmdlines() -> Result<Vec<ProcCommand>, ProcSnapshotError> {
    let entries = std::fs::read_dir("/proc").map_err(ProcSnapshotError::ProcUnavailable)?;

    let mut budget = ProcSnapshotBudget::default();
    let mut processes = Vec::new();
    for entry in entries {
        let entry = entry.map_err(ProcSnapshotError::ProcUnavailable)?;
        let Some(pid) = proc_entry_pid(&entry) else {
            continue;
        };
        budget.charge_numeric_entry()?;
        budget.charge_selected_process()?;
        let Some(process_dir) = open_proc_process_dir(&entry) else {
            continue;
        };
        let Some(args) = read_proc_cmdline_args(&process_dir, &mut budget)? else {
            continue;
        };
        processes.push(ProcCommand { pid, args });
    }

    processes.sort_by_key(|process| process.pid);
    Ok(processes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DesktopProcessKind {
    Portal,
    Xwayland,
    Ibus,
    Goa,
    Kded,
    Tray,
    XfcePanel,
    SddmGreeter,
}

#[derive(Debug)]
struct DesktopProcessEnvironment {
    pid: u32,
    kind: DesktopProcessKind,
    environ: Vec<u8>,
}

#[derive(Debug, Default)]
struct DesktopProcessSnapshot {
    environments: Vec<DesktopProcessEnvironment>,
    xwayland_running: bool,
}

fn process_is_kded(args: &[String]) -> bool {
    let Some(suffix) = process_basename(args).and_then(|name| name.strip_prefix("kded")) else {
        return false;
    };
    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
}

fn process_is_rustdesk_tray(args: &[String], app_name: &str) -> bool {
    process_basename(args)
        .map(|basename| basename.eq_ignore_ascii_case(app_name))
        .unwrap_or(false)
        && args.iter().skip(1).any(|arg| arg == "--tray")
}

fn classify_desktop_process(args: &[String], app_name: &str) -> Option<DesktopProcessKind> {
    if process_basename_eq(args, "xdg-desktop-portal") {
        Some(DesktopProcessKind::Portal)
    } else if process_is_xwayland(args) {
        Some(DesktopProcessKind::Xwayland)
    } else if process_basename_eq(args, "ibus-daemon") {
        Some(DesktopProcessKind::Ibus)
    } else if process_basename_eq(args, "goa-daemon") {
        Some(DesktopProcessKind::Goa)
    } else if process_is_kded(args) {
        Some(DesktopProcessKind::Kded)
    } else if process_is_rustdesk_tray(args, app_name) {
        Some(DesktopProcessKind::Tray)
    } else if process_basename_eq(args, "xfce4-panel") {
        Some(DesktopProcessKind::XfcePanel)
    } else if process_basename_eq(args, "sddm-greeter") {
        Some(DesktopProcessKind::SddmGreeter)
    } else {
        None
    }
}

fn observe_desktop_processes(uid: &str) -> Result<DesktopProcessSnapshot, ProcSnapshotError> {
    let uid_num = uid
        .parse::<u32>()
        .ok()
        .filter(|parsed| parsed.to_string() == uid)
        .ok_or(ProcSnapshotError::InvalidUid)?;
    let current_selector_namespaces = current_selector_namespace_authority()?;
    let entries = std::fs::read_dir("/proc").map_err(ProcSnapshotError::ProcUnavailable)?;
    let app_name = crate::get_app_name();
    let mut budget = ProcSnapshotBudget::default();
    let mut snapshot = DesktopProcessSnapshot::default();

    for entry in entries {
        let entry = entry.map_err(ProcSnapshotError::ProcUnavailable)?;
        let Some(pid) = proc_entry_pid(&entry) else {
            continue;
        };
        budget.charge_numeric_entry()?;
        let Some(process_dir) = open_proc_process_dir(&entry) else {
            continue;
        };
        let Ok(metadata) = process_dir.metadata() else {
            continue;
        };
        if !metadata.is_dir()
            || metadata.uid() != uid_num
            || !process_shares_selector_namespaces(
                &process_dir,
                current_selector_namespaces.identity,
            )
        {
            continue;
        }
        budget.charge_selected_process()?;
        let Some(args) = read_proc_cmdline_args(&process_dir, &mut budget)? else {
            continue;
        };
        let Some(kind) = classify_desktop_process(&args, &app_name) else {
            continue;
        };
        budget.charge_environment_candidate()?;
        let BoundedProcFile::Value(environ) = read_bounded_proc_member(
            &process_dir,
            ProcMember::Environ,
            PROC_ENVIRON_MAX_BYTES,
            &mut budget,
        )?
        else {
            continue;
        };
        let Ok(metadata) = process_dir.metadata() else {
            continue;
        };
        if !metadata.is_dir()
            || metadata.uid() != uid_num
            || !process_shares_selector_namespaces(
                &process_dir,
                current_selector_namespaces.identity,
            )
        {
            continue;
        }
        if kind == DesktopProcessKind::Xwayland {
            snapshot.xwayland_running = true;
        }
        snapshot
            .environments
            .push(DesktopProcessEnvironment { pid, kind, environ });
    }

    snapshot.environments.sort_by_key(|process| process.pid);
    Ok(snapshot)
}

fn process_basename(args: &[String]) -> Option<&str> {
    args.first()
        .and_then(|arg0| Path::new(arg0).file_name())
        .and_then(|name| name.to_str())
}

fn process_basename_eq(args: &[String], expected: &str) -> bool {
    process_basename(args)
        .map(|name| name == expected)
        .unwrap_or(false)
}

fn process_is_xwayland(args: &[String]) -> bool {
    process_basename_eq(args, "Xwayland")
}

fn is_local_x_display_arg(arg: &str) -> bool {
    normalize_local_x_display_name(arg).is_some()
}

fn xwayland_display_arg(args: &[String]) -> Option<&str> {
    if !process_is_xwayland(args) {
        return None;
    }
    args.iter()
        .skip(1)
        .find(|arg| is_local_x_display_arg(arg))
        .map(String::as_str)
}

pub(crate) fn xwayland_display_from_proc() -> Option<String> {
    let processes = match all_process_cmdlines() {
        Ok(processes) => processes,
        Err(err) => {
            log::warn!("Failed bounded Xwayland process observation: {err}");
            return None;
        }
    };
    for process in processes {
        if let Some(display) = xwayland_display_arg(&process.args) {
            return Some(display.to_owned());
        }
    }
    None
}

fn proc_env_name_is_valid(name: &str) -> bool {
    !name.is_empty() && !name.as_bytes().contains(&b'=') && !name.as_bytes().contains(&0)
}

fn proc_environ_value(environ: &[u8], name: &str) -> Option<String> {
    if !proc_env_name_is_valid(name) {
        return None;
    }
    let name = name.as_bytes();
    let mut found = None;
    for part in environ.split(|&b| b == 0) {
        if part.len() <= name.len() || !part.starts_with(name) || part[name.len()] != b'=' {
            continue;
        }
        let value = &part[name.len() + 1..];
        if value.len() > PROC_ENV_VALUE_MAX_BYTES {
            return None;
        }
        let value = std::str::from_utf8(value).ok()?;
        if found.replace(value).is_some() {
            return None;
        }
    }
    found.map(str::to_owned)
}

fn proc_session_selector_value(environ: &[u8], name: &str) -> Option<String> {
    let value = proc_environ_value(environ, name)?;
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return None;
    }
    Some(value)
}

fn xauthority_from_environ_for_display(environ: &[u8], display: &str) -> Option<String> {
    let observed_display = proc_environ_value(environ, "DISPLAY")?;
    if !local_x_display_names_share_server(&observed_display, display) {
        return None;
    }
    let xauthority = proc_environ_value(environ, "XAUTHORITY")?;
    if xauthority.is_empty()
        || xauthority.bytes().any(|byte| byte.is_ascii_control())
        || !Path::new(&xauthority).is_absolute()
    {
        return None;
    }
    Some(xauthority)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DesktopSessionEnvironment {
    display: String,
    xauth: String,
    wl_display: String,
    dbus: String,
}

#[derive(Debug, Clone, Copy)]
enum DesktopEnvironmentKey {
    Display,
    Xauthority,
    WaylandDisplay,
    Dbus,
}

impl DesktopSessionEnvironment {
    fn from_environ(environ: &[u8]) -> Option<Self> {
        if !environ.is_empty() && environ.last() != Some(&0) {
            return None;
        }
        let display = proc_environ_value(environ, "DISPLAY")
            .and_then(|display| normalize_local_x_display_name(&display))
            .unwrap_or_default();
        let xauth = if display.is_empty() {
            String::new()
        } else {
            xauthority_from_environ_for_display(environ, &display).unwrap_or_default()
        };
        Some(Self {
            display,
            xauth,
            wl_display: proc_session_selector_value(environ, "WAYLAND_DISPLAY")
                .unwrap_or_default(),
            dbus: proc_session_selector_value(environ, "DBUS_SESSION_BUS_ADDRESS")
                .unwrap_or_default(),
        })
    }

    fn value(&self, key: DesktopEnvironmentKey) -> &str {
        match key {
            DesktopEnvironmentKey::Display => &self.display,
            DesktopEnvironmentKey::Xauthority => &self.xauth,
            DesktopEnvironmentKey::WaylandDisplay => &self.wl_display,
            DesktopEnvironmentKey::Dbus => &self.dbus,
        }
    }

    fn priority_mask(&self, keys: &[DesktopEnvironmentKey; 4]) -> u8 {
        keys.iter().fold(0u8, |mask, key| {
            (mask << 1) | u8::from(!self.value(*key).is_empty())
        })
    }

    fn populated_count(&self) -> u8 {
        [
            &self.display,
            &self.xauth,
            &self.wl_display,
            &self.dbus,
        ]
        .iter()
        .filter(|value| !value.is_empty())
        .count() as u8
    }

    fn has_x11_pair(&self) -> bool {
        !self.display.is_empty() && !self.xauth.is_empty()
    }
}

impl DesktopProcessSnapshot {
    fn best_environment(
        &self,
        kind: DesktopProcessKind,
        priorities: &[DesktopEnvironmentKey; 4],
    ) -> DesktopSessionEnvironment {
        let mut best = DesktopSessionEnvironment::default();
        let mut best_count = 0u8;
        let mut best_mask = 0u8;
        let mut best_pid = 0u32;
        for process in self
            .environments
            .iter()
            .filter(|process| process.kind == kind)
        {
            let Some(environment) = DesktopSessionEnvironment::from_environ(&process.environ)
            else {
                continue;
            };
            let count = environment.populated_count();
            let mask = environment.priority_mask(priorities);
            if count > best_count
                || (count == best_count && mask > best_mask)
                || (count == best_count && mask == best_mask && process.pid > best_pid)
            {
                best = environment;
                best_count = count;
                best_mask = mask;
                best_pid = process.pid;
            }
        }
        best
    }

    fn xauthority_for_display(
        &self,
        kind: DesktopProcessKind,
        display: &str,
    ) -> Option<String> {
        self.environments
            .iter()
            .rev()
            .filter(|process| process.kind == kind)
            .find_map(|process| {
                let environment = DesktopSessionEnvironment::from_environ(&process.environ)?;
                if local_x_display_names_share_server(&environment.display, display) {
                    Some(environment.xauth).filter(|xauth| !xauth.is_empty())
                } else {
                    None
                }
            })
    }
}

#[link(name = "gtk-3")]
extern "C" {
    fn gtk_main_quit();
}

#[cfg(test)]
mod process_cleanup_tests {
    use super::*;

    #[test]
    fn r_s11e54_linux_service_requires_protected_ipc_readiness() {
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        ready_tx.send(Ok(())).unwrap();
        assert!(wait_for_linux_service_ipc_startup(&ready_rx, Duration::ZERO).is_ok());

        let (failed_tx, failed_rx) = mpsc::sync_channel(1);
        failed_tx
            .send(Err("listener bind failed".to_owned()))
            .unwrap();
        assert!(wait_for_linux_service_ipc_startup(&failed_rx, Duration::ZERO).is_err());

        let (pending_tx, pending_rx) = mpsc::sync_channel::<Result<(), String>>(1);
        assert!(wait_for_linux_service_ipc_startup(&pending_rx, Duration::ZERO).is_err());
        drop(pending_tx);

        let (disconnected_tx, disconnected_rx) = mpsc::sync_channel(1);
        drop(disconnected_tx);
        assert!(
            wait_for_linux_service_ipc_startup(&disconnected_rx, Duration::ZERO).is_err()
        );
    }

    #[test]
    fn r_s11e54_linux_service_owns_protected_ipc_thread_outcome() {
        assert!(classify_linux_service_ipc_thread_outcome(Ok(Ok(())), true).is_ok());
        assert!(classify_linux_service_ipc_thread_outcome(Ok(Ok(())), false).is_err());
        assert!(classify_linux_service_ipc_thread_outcome(
            Ok(Err(anyhow!("listener failed"))),
            true,
        )
        .is_err());
        let panic: std::thread::Result<ResultType<()>> = Err(Box::new("listener panicked"));
        assert!(classify_linux_service_ipc_thread_outcome(panic, true).is_err());
    }

    struct ServiceChildTestSupervisor(Child);

    impl Drop for ServiceChildTestSupervisor {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    struct ServiceChildTestSocketDir(PathBuf);

    impl Drop for ServiceChildTestSocketDir {
        fn drop(&mut self) {
            let _ = fs::remove_file(self.0.join("ready.sock"));
            let _ = fs::remove_dir(&self.0);
        }
    }

    struct ServiceRuntimeTestDir(PathBuf);

    impl Drop for ServiceRuntimeTestDir {
        fn drop(&mut self) {
            if let Ok(entries) = fs::read_dir(&self.0) {
                for entry in entries.flatten() {
                    let _ = fs::remove_file(entry.path());
                }
            }
            let _ = fs::remove_dir(&self.0);
        }
    }

    struct ServiceChildTerminationTestOwner {
        child: Option<OwnedServiceChild>,
    }

    impl Drop for ServiceChildTerminationTestOwner {
        fn drop(&mut self) {
            if let Some(child) = self.child.as_mut() {
                let _ = child.process.kill();
                let _ = child.process.wait();
            }
        }
    }

    fn sample_service_child_record() -> ServiceChildRecord {
        ServiceChildRecord {
            pid: 4242,
            start_time: 991_337,
            boot_id: "11111111-2222-4333-8444-555555555555".to_owned(),
            executable_device: 2049,
            executable_inode: 123_456,
            uid: 1000,
            generation: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".to_owned(),
        }
    }

    #[test]
    fn r_s11c27b_service_child_record_is_strict_and_canonical() {
        let record = sample_service_child_record();
        assert_eq!(
            ServiceChildRecord::decode(&record.encode()).unwrap(),
            record
        );

        let valid = String::from_utf8(record.encode()).unwrap();
        for malformed in [
            valid.trim_end().to_owned(),
            valid.replace("version=1", "version=2"),
            valid.replace("pid=4242", "pid=04242"),
            valid.replace(
                "boot_id=11111111-2222-4333-8444-555555555555",
                "boot_id=11111111-2222-4333-8444-555555555555\nunknown=x",
            ),
            valid.replace(
                "generation=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "generation=AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE",
            ),
            valid.replace("role=--server+--service-owned-server", "role=--server"),
        ] {
            assert!(
                ServiceChildRecord::decode(malformed.as_bytes()).is_err(),
                "malformed record was accepted: {malformed:?}"
            );
        }
    }

    #[test]
    fn r_s11c27b_service_child_record_publication_is_atomic_and_exact() {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "rustdesk-service-runtime-{}-{nonce}",
            std::process::id()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let _guard = ServiceRuntimeTestDir(root.clone());
        let runtime =
            ServiceRuntime::for_test(&root, "01234567-89ab-4cde-8fab-0123456789ab").unwrap();
        let record = sample_service_child_record();

        runtime.publish_record(&record).unwrap();
        assert_eq!(runtime.read_record().unwrap(), Some(record.clone()));
        let metadata = fs::symlink_metadata(root.join("service-child.record")).unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert!(!root.join("service-child.record.tmp").exists());

        let mut other = record.clone();
        other.start_time += 1;
        assert!(runtime.publish_record(&other).is_err());
        assert!(runtime.remove_record(&other).is_err());
        assert_eq!(runtime.read_record().unwrap(), Some(record.clone()));

        runtime.remove_record(&record).unwrap();
        assert!(runtime.read_record().unwrap().is_none());
        fs::write(root.join("service-child.record"), b"version=1\n").unwrap();
        fs::set_permissions(
            root.join("service-child.record"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(runtime.read_record().is_err());
        assert!(runtime.publish_record(&record).is_err());
        assert_eq!(
            fs::read(root.join("service-child.record")).unwrap(),
            b"version=1\n"
        );
    }

    #[test]
    fn r_s11c27b_service_child_role_and_generation_are_exact() {
        let exact_cmdline = b"/proc/self/exe\0--server\0--service-owned-server\0";
        assert!(service_child_cmdline_has_exact_role(exact_cmdline));
        assert!(!service_child_cmdline_has_exact_role(
            b"/proc/self/exe\0--server\0--service-owned-server-extra\0"
        ));
        assert!(!service_child_cmdline_has_exact_role(
            b"/proc/self/exe\0--server\0--service-owned-server\0extra\0"
        ));

        let generation = "01234567-89ab-4cde-8fab-0123456789ab";
        let exact_environment = format!(
            "PATH=/usr/bin:/bin\0{}={}\0",
            crate::common::SERVICE_OWNED_SERVER_GENERATION_ENV,
            generation
        );
        assert!(service_child_environment_has_generation(
            exact_environment.as_bytes(),
            generation
        ));
        let duplicate = format!(
            "{}{}={}\0",
            exact_environment,
            crate::common::SERVICE_OWNED_SERVER_GENERATION_ENV,
            generation
        );
        assert!(!service_child_environment_has_generation(
            duplicate.as_bytes(),
            generation
        ));
        assert!(!service_child_environment_has_generation(
            exact_environment.as_bytes(),
            "fedcba98-7654-4cba-8fed-fedcba987654"
        ));
    }

    #[test]
    fn r_s11c27c_linux_service_child_term_then_bounded_kill() {
        use std::{
            io::ErrorKind,
            os::unix::{fs::DirBuilderExt as _, net::UnixListener},
        };

        const TEST_NAME: &str = "platform::linux::process_cleanup_tests::r_s11c27c_linux_service_child_term_then_bounded_kill";
        const ROLE_ENV: &str = "RUSTDESK_TEST_SERVICE_CHILD_TERMINATION_ROLE";
        const SOCKET_ENV: &str = "RUSTDESK_TEST_SERVICE_CHILD_TERMINATION_SOCKET";

        match std::env::var(ROLE_ENV).as_deref() {
            Ok("worker") => {
                let _ready =
                    std::os::unix::net::UnixStream::connect(std::env::var_os(SOCKET_ENV).unwrap())
                        .unwrap();
                loop {
                    std::thread::sleep(Duration::from_secs(60));
                }
            }
            Ok(role) => panic!("unexpected service-child termination test role: {role}"),
            Err(_) => {}
        }

        let run_case = |case: &str, stop_before_term: bool, expected| {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "rustdesk-service-termination-{}-{case}-{nonce}",
                std::process::id()
            ));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            let _runtime_guard = ServiceRuntimeTestDir(root.clone());
            let runtime =
                ServiceRuntime::for_test(&root, "01234567-89ab-4cde-8fab-0123456789ab").unwrap();
            let socket_path = root.join("ready.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();
            listener.set_nonblocking(true).unwrap();

            let process = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST_NAME, "--nocapture"])
                .env(ROLE_ENV, "worker")
                .env(SOCKET_ENV, &socket_path)
                .spawn()
                .unwrap();
            let pid = process.id();
            let mut record = sample_service_child_record();
            record.pid = pid;
            let mut owner = ServiceChildTerminationTestOwner {
                child: Some(OwnedServiceChild {
                    process,
                    record: record.clone(),
                }),
            };
            runtime.publish_record(&record).unwrap();

            let ready_deadline = Instant::now() + Duration::from_secs(5);
            let _worker_stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(err)
                        if err.kind() == ErrorKind::WouldBlock
                            && Instant::now() < ready_deadline =>
                    {
                        if let Some(status) =
                            owner.child.as_mut().unwrap().process.try_wait().unwrap()
                        {
                            panic!("service-child termination worker exited early: {status}");
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(err) => panic!("service-child termination worker did not connect: {err}"),
                }
            };

            if stop_before_term {
                assert!(signal_child(
                    owner.child.as_ref().unwrap(),
                    hbb_common::libc::SIGSTOP,
                    "test --server"
                ));
                let stop_deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    let (_, state) = read_service_child_proc_stat(pid).unwrap();
                    if matches!(state, 'T' | 't') {
                        break;
                    }
                    assert!(
                        Instant::now() < stop_deadline,
                        "service-child termination worker did not enter stopped state"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
            }

            let started = Instant::now();
            let outcome = terminate_child_with_timeouts(
                &mut owner.child,
                "test --server",
                &runtime,
                Duration::from_millis(150),
                Duration::from_secs(2),
            )
            .unwrap();
            assert_eq!(outcome, expected);
            assert!(
                started.elapsed() < Duration::from_secs(3),
                "service-child termination exceeded its bounded waits"
            );
            assert!(owner.child.is_none());
            assert!(runtime.read_record().unwrap().is_none());
        };

        run_case("graceful", false, ServiceChildTermination::Graceful);
        run_case("forced", true, ServiceChildTermination::Forced);
    }

    fn busybox_executable_for_test() -> &'static Path {
        ["/usr/bin/busybox", "/bin/busybox"]
            .into_iter()
            .map(Path::new)
            .find(|path| path.is_file())
            .unwrap()
    }

    fn spawn_exact_role_service_child_from_executable_for_test(
        executable: &Path,
        generation: &str,
        bind_to_parent: bool,
    ) -> Child {
        use std::process::Stdio;

        let parent_pid = hbb_common::libc::pid_t::try_from(std::process::id()).unwrap();
        let mut command = Command::new(executable);
        command
            .arg0("yes")
            .arg("--server")
            .arg(crate::common::SERVICE_OWNED_SERVER_ARG)
            .env_clear()
            .env(
                crate::common::SERVICE_OWNED_SERVER_LAUNCH_PARENT_ENV,
                parent_pid.to_string(),
            )
            .env(
                crate::common::SERVICE_OWNED_SERVER_GENERATION_ENV,
                generation,
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if bind_to_parent {
            configure_service_child_pre_exec(&mut command, parent_pid, None, None, None).unwrap();
        }
        let mut child = command.spawn().unwrap();
        let proc_dir = PathBuf::from(format!("/proc/{}/", child.id()));
        let readiness_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let role_is_ready =
                read_bounded_service_proc_file(&proc_dir.join("cmdline"), 64 * 1024)
                    .map(|cmdline| service_child_cmdline_has_exact_role(&cmdline))
                    .unwrap_or(false);
            let generation_is_ready =
                read_bounded_service_proc_file(&proc_dir.join("environ"), 64 * 1024)
                    .map(|environ| service_child_environment_has_generation(&environ, generation))
                    .unwrap_or(false);
            if role_is_ready && generation_is_ready {
                return child;
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("service-child test fixture exited before identity readiness: {status}");
            }
            assert!(
                Instant::now() < readiness_deadline,
                "service-child test fixture did not publish its exact role and generation"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn spawn_exact_role_service_child_for_test(generation: &str, bind_to_parent: bool) -> Child {
        spawn_exact_role_service_child_from_executable_for_test(
            busybox_executable_for_test(),
            generation,
            bind_to_parent,
        )
    }

    #[test]
    fn r_s11c27d_linux_service_child_crash_restart_recovery_is_exact() {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

        const TEST_NAME: &str = "platform::linux::process_cleanup_tests::r_s11c27d_linux_service_child_crash_restart_recovery_is_exact";
        const ROLE_ENV: &str = "RUSTDESK_TEST_SERVICE_CHILD_RECOVERY_ROLE";
        const RUNTIME_ENV: &str = "RUSTDESK_TEST_SERVICE_CHILD_RECOVERY_RUNTIME";
        const GENERATION: &str = "01234567-89ab-4cde-8fab-0123456789ab";

        match std::env::var(ROLE_ENV).as_deref() {
            Ok("supervisor") => {
                let root = PathBuf::from(std::env::var_os(RUNTIME_ENV).unwrap());
                let runtime = ServiceRuntime::for_test(&root, GENERATION).unwrap();
                let process = spawn_exact_role_service_child_for_test(GENERATION, true);
                let record = service_child_record_for_process(
                    process.id(),
                    runtime.owner_uid,
                    GENERATION,
                )
                .unwrap();
                runtime.publish_record(&record).unwrap();
                let _owner = ServiceChildTerminationTestOwner {
                    child: Some(OwnedServiceChild { process, record }),
                };
                loop {
                    std::thread::sleep(Duration::from_secs(60));
                }
            }
            Ok("contender") => {
                let root = PathBuf::from(std::env::var_os(RUNTIME_ENV).unwrap());
                assert!(
                    ServiceRuntime::for_test(&root, GENERATION).is_err(),
                    "a second supervisor acquired the live lifecycle lease"
                );
                return;
            }
            Ok("recoverer") => {
                let root = PathBuf::from(std::env::var_os(RUNTIME_ENV).unwrap());
                let runtime = ServiceRuntime::for_test(&root, GENERATION).unwrap();
                runtime.recover_previous_child().unwrap();
                assert!(runtime.read_record().unwrap().is_none());
                return;
            }
            Ok(role) => panic!("unexpected service-child recovery test role: {role}"),
            Err(_) => {}
        }

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "rustdesk-service-recovery-{}-{nonce}",
            std::process::id()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let _runtime_guard = ServiceRuntimeTestDir(root.clone());
        let current_test = std::env::current_exe().unwrap();
        let mut supervisor = ServiceChildTestSupervisor(
            Command::new(&current_test)
                .args(["--exact", TEST_NAME, "--nocapture"])
                .env(ROLE_ENV, "supervisor")
                .env(RUNTIME_ENV, &root)
                .spawn()
                .unwrap(),
        );

        let record_path = root.join("service-child.record");
        let ready_deadline = Instant::now() + Duration::from_secs(5);
        let crashed_record = loop {
            match fs::read(&record_path) {
                Ok(bytes) => break ServiceChildRecord::decode(&bytes).unwrap(),
                Err(err)
                    if err.kind() == std::io::ErrorKind::NotFound
                        && Instant::now() < ready_deadline =>
                {
                    if let Some(status) = supervisor.0.try_wait().unwrap() {
                        panic!("service-child recovery supervisor exited early: {status}");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("service-child recovery record was not published: {err}"),
            }
        };

        let contender = Command::new(&current_test)
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(ROLE_ENV, "contender")
            .env(RUNTIME_ENV, &root)
            .status()
            .unwrap();
        assert!(contender.success(), "live-lease contender test failed");

        let PidFdOpen::Available(crashed_child_pidfd) =
            open_service_child_pidfd(crashed_record.pid).unwrap()
        else {
            panic!("pidfd_open is required for the service-child recovery test");
        };
        supervisor.0.kill().unwrap();
        supervisor.0.wait().unwrap();
        assert!(
            service_child_pidfd_exited(&crashed_child_pidfd, Duration::from_secs(5)).unwrap(),
            "post-exec service child survived its supervisor crash"
        );

        let recoverer = Command::new(&current_test)
            .args(["--exact", TEST_NAME, "--nocapture"])
            .env(ROLE_ENV, "recoverer")
            .env(RUNTIME_ENV, &root)
            .status()
            .unwrap();
        assert!(recoverer.success(), "fresh-process crash recovery failed");
        assert!(!record_path.exists());

        let runtime = ServiceRuntime::for_test(&root, GENERATION).unwrap();
        let exact_process = spawn_exact_role_service_child_for_test(GENERATION, false);
        let exact_record = service_child_record_for_process(
            exact_process.id(),
            runtime.owner_uid,
            GENERATION,
        )
        .unwrap();
        let mut exact_owner = ServiceChildTestSupervisor(exact_process);

        let mut reused_pid_record = exact_record.clone();
        reused_pid_record.start_time += 1;
        let mut different_executable_record = exact_record.clone();
        different_executable_record.executable_inode = different_executable_record
            .executable_inode
            .checked_add(1)
            .unwrap();
        let mut wrong_generation_record = exact_record.clone();
        wrong_generation_record.generation = "fedcba98-7654-4cba-8fed-fedcba987654".to_owned();

        for (label, hostile_record, expected_error) in [
            ("reused pid", reused_pid_record, "start time changed"),
            (
                "different executable with identical argv",
                different_executable_record,
                "executable identity changed",
            ),
            (
                "wrong generation",
                wrong_generation_record,
                "service generation is absent or duplicated",
            ),
        ] {
            runtime.publish_record(&hostile_record).unwrap();
            let err = runtime.recover_previous_child().unwrap_err();
            assert!(
                err.to_string().contains(expected_error),
                "{label} recovery failed for the wrong reason: {err}"
            );
            assert_eq!(
                runtime.read_record().unwrap(),
                Some(hostile_record.clone()),
                "{label} record was not preserved"
            );
            assert!(
                exact_owner.0.try_wait().unwrap().is_none(),
                "{label} evidence signaled an unrelated live process"
            );
            runtime.remove_record(&hostile_record).unwrap();
        }

        let malformed = String::from_utf8(exact_record.encode())
            .unwrap()
            .replace("role=--server+--service-owned-server", "role=--server")
            .into_bytes();
        fs::write(&record_path, &malformed).unwrap();
        fs::set_permissions(&record_path, fs::Permissions::from_mode(0o600)).unwrap();
        let malformed_error = runtime.recover_previous_child().unwrap_err();
        assert!(malformed_error
            .to_string()
            .contains("record role marker is invalid"));
        assert_eq!(fs::read(&record_path).unwrap(), malformed);
        assert!(exact_owner.0.try_wait().unwrap().is_none());
        fs::remove_file(&record_path).unwrap();

        runtime.publish_record(&exact_record).unwrap();
        runtime.recover_previous_child().unwrap();
        let status = exact_owner.0.wait().unwrap();
        assert!(
            !status.success(),
            "recovered exact service child exited cleanly"
        );
        assert!(runtime.read_record().unwrap().is_none());
    }

    #[test]
    fn r_s11c27e_linux_service_child_executable_object_recovery_is_exact() {
        use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};

        const GENERATION: &str = "01234567-89ab-4cde-8fab-0123456789ab";

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "rustdesk-service-executable-object-{}-{nonce}",
            std::process::id()
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let _runtime_guard = ServiceRuntimeTestDir(root.clone());
        let runtime = ServiceRuntime::for_test(&root, GENERATION).unwrap();

        let owned_path = root.join("owned-service-child");
        let replacement_path = root.join("replacement-service-child");
        fs::copy(busybox_executable_for_test(), &owned_path).unwrap();
        fs::copy(busybox_executable_for_test(), &replacement_path).unwrap();
        fs::set_permissions(&owned_path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&replacement_path, fs::Permissions::from_mode(0o700)).unwrap();

        let mut owned_owner = ServiceChildTestSupervisor(
            spawn_exact_role_service_child_from_executable_for_test(
                &owned_path,
                GENERATION,
                false,
            ),
        );
        let owned_record = service_child_record_for_process(
            owned_owner.0.id(),
            runtime.owner_uid,
            GENERATION,
        )
        .unwrap();

        let replacement_metadata = fs::metadata(&replacement_path).unwrap();
        assert_ne!(
            (owned_record.executable_device, owned_record.executable_inode),
            (replacement_metadata.dev(), replacement_metadata.ino())
        );
        fs::rename(&replacement_path, &owned_path).unwrap();
        let owned_proc_exe = PathBuf::from(format!("/proc/{}/exe", owned_record.pid));
        let owned_proc_metadata = fs::metadata(&owned_proc_exe).unwrap();
        assert_eq!(owned_proc_metadata.dev(), owned_record.executable_device);
        assert_eq!(owned_proc_metadata.ino(), owned_record.executable_inode);
        assert!(fs::read_link(&owned_proc_exe)
            .unwrap()
            .as_os_str()
            .as_encoded_bytes()
            .ends_with(b" (deleted)"));

        let mut replacement_owner = ServiceChildTestSupervisor(
            spawn_exact_role_service_child_from_executable_for_test(
                &owned_path,
                GENERATION,
                false,
            ),
        );
        let replacement_record = service_child_record_for_process(
            replacement_owner.0.id(),
            runtime.owner_uid,
            GENERATION,
        )
        .unwrap();
        assert_ne!(
            (
                replacement_record.executable_device,
                replacement_record.executable_inode,
            ),
            (owned_record.executable_device, owned_record.executable_inode)
        );

        let mut mismatched_replacement_record = replacement_record.clone();
        mismatched_replacement_record.executable_device = owned_record.executable_device;
        mismatched_replacement_record.executable_inode = owned_record.executable_inode;
        runtime
            .publish_record(&mismatched_replacement_record)
            .unwrap();
        let mismatch_error = runtime.recover_previous_child().unwrap_err();
        assert!(mismatch_error
            .to_string()
            .contains("executable identity changed"));
        assert_eq!(
            runtime.read_record().unwrap(),
            Some(mismatched_replacement_record.clone())
        );
        assert!(owned_owner.0.try_wait().unwrap().is_none());
        assert!(replacement_owner.0.try_wait().unwrap().is_none());
        runtime
            .remove_record(&mismatched_replacement_record)
            .unwrap();

        runtime.publish_record(&owned_record).unwrap();
        runtime.recover_previous_child().unwrap();
        assert!(!owned_owner.0.wait().unwrap().success());
        assert!(runtime.read_record().unwrap().is_none());
        assert!(replacement_owner.0.try_wait().unwrap().is_none());

        let unlinked_path = root.join("unlinked-service-child");
        fs::copy(busybox_executable_for_test(), &unlinked_path).unwrap();
        fs::set_permissions(&unlinked_path, fs::Permissions::from_mode(0o700)).unwrap();
        let mut unlinked_owner = ServiceChildTestSupervisor(
            spawn_exact_role_service_child_from_executable_for_test(
                &unlinked_path,
                GENERATION,
                false,
            ),
        );
        let unlinked_record = service_child_record_for_process(
            unlinked_owner.0.id(),
            runtime.owner_uid,
            GENERATION,
        )
        .unwrap();
        fs::remove_file(&unlinked_path).unwrap();
        assert!(!unlinked_path.exists());
        let unlinked_proc_metadata =
            fs::metadata(format!("/proc/{}/exe", unlinked_record.pid)).unwrap();
        assert_eq!(
            (
                unlinked_proc_metadata.dev(),
                unlinked_proc_metadata.ino(),
            ),
            (
                unlinked_record.executable_device,
                unlinked_record.executable_inode,
            )
        );

        runtime.publish_record(&unlinked_record).unwrap();
        runtime.recover_previous_child().unwrap();
        assert!(!unlinked_owner.0.wait().unwrap().success());
        assert!(runtime.read_record().unwrap().is_none());
        assert!(replacement_owner.0.try_wait().unwrap().is_none());
    }

    #[test]
    fn r_s11c27a_linux_service_child_parent_death_kills_owned_child() {
        use std::{
            io::{ErrorKind, Read as _, Write as _},
            os::{
                fd::{AsRawFd as _, FromRawFd as _, OwnedFd},
                unix::{
                    fs::DirBuilderExt as _,
                    net::{UnixListener, UnixStream},
                },
            },
        };

        const TEST_NAME: &str = "platform::linux::process_cleanup_tests::r_s11c27a_linux_service_child_parent_death_kills_owned_child";
        const ROLE_ENV: &str = "RUSTDESK_TEST_SERVICE_CHILD_ROLE";
        const SOCKET_ENV: &str = "RUSTDESK_TEST_SERVICE_CHILD_SOCKET";
        const PARENT_ENV: &str = "RUSTDESK_TEST_SERVICE_CHILD_PARENT";

        match std::env::var(ROLE_ENV).as_deref() {
            Ok("supervisor") => {
                let expected_parent = std::process::id().to_string();
                let _worker = Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", TEST_NAME, "--nocapture"])
                    .env(ROLE_ENV, "worker")
                    .env(SOCKET_ENV, std::env::var_os(SOCKET_ENV).unwrap())
                    .env(PARENT_ENV, expected_parent)
                    .spawn()
                    .unwrap();
                loop {
                    std::thread::sleep(Duration::from_secs(60));
                }
            }
            Ok("worker") => {
                let expected_parent = std::env::var(PARENT_ENV)
                    .unwrap()
                    .parse::<hbb_common::libc::pid_t>()
                    .unwrap();
                arm_linux_child_parent_death(expected_parent).unwrap();
                let mut stream =
                    UnixStream::connect(std::env::var_os(SOCKET_ENV).unwrap()).unwrap();
                stream.write_all(&std::process::id().to_ne_bytes()).unwrap();
                loop {
                    std::thread::sleep(Duration::from_secs(60));
                }
            }
            Ok(role) => panic!("unexpected service-child test role: {role}"),
            Err(_) => {}
        }

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let socket_root = std::env::temp_dir().join(format!(
            "rustdesk-service-child-{}-{nonce}",
            std::process::id()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&socket_root)
            .unwrap();
        let _socket_guard = ServiceChildTestSocketDir(socket_root.clone());
        let socket_path = socket_root.join("ready.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut supervisor = ServiceChildTestSupervisor(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST_NAME, "--nocapture"])
                .env(ROLE_ENV, "supervisor")
                .env(SOCKET_ENV, &socket_path)
                .spawn()
                .unwrap(),
        );

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut worker_stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                    if let Some(status) = supervisor.0.try_wait().unwrap() {
                        panic!("service-child test supervisor exited early: {status}");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(err) => {
                    panic!("service-child test worker did not connect: {err}");
                }
            }
        };
        let mut worker_pid = [0u8; std::mem::size_of::<u32>()];
        worker_stream.read_exact(&mut worker_pid).unwrap();
        let worker_pid = hbb_common::libc::pid_t::try_from(u32::from_ne_bytes(worker_pid)).unwrap();

        let pidfd =
            unsafe { hbb_common::libc::syscall(hbb_common::libc::SYS_pidfd_open, worker_pid, 0) };
        if pidfd < 0 {
            panic!("pidfd_open is required for the service-child lifecycle test");
        }
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as c_int) };

        supervisor.0.kill().unwrap();
        supervisor.0.wait().unwrap();
        let mut pollfd = hbb_common::libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: hbb_common::libc::POLLIN,
            revents: 0,
        };
        let observed = unsafe { hbb_common::libc::poll(&mut pollfd, 1, 5_000) };
        if observed != 1 || pollfd.revents & hbb_common::libc::POLLIN == 0 {
            unsafe {
                hbb_common::libc::syscall(
                    hbb_common::libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    hbb_common::libc::SIGKILL,
                    std::ptr::null::<hbb_common::libc::siginfo_t>(),
                    0,
                );
            }
        }
        assert_eq!(observed, 1, "owned worker survived supervisor death");
        assert_ne!(pollfd.revents & hbb_common::libc::POLLIN, 0);
    }

    #[test]
    fn r_s11e45_linux_service_child_replacement_uses_owned_state_only() {
        let mut uid = "1000".to_owned();
        let stable = Desktop {
            sid: "session-1".to_owned(),
            uid: uid.clone(),
            ..Default::default()
        };
        assert!(!service_child_needs_replacement(false, &mut uid, &stable));

        assert!(service_child_needs_replacement(true, &mut uid, &stable));
        assert_eq!(uid, "1000");

        let changed_user = Desktop {
            sid: "session-2".to_owned(),
            uid: "1001".to_owned(),
            ..Default::default()
        };
        assert!(service_child_needs_replacement(
            false,
            &mut uid,
            &changed_user
        ));
        assert_eq!(uid, "1001");

        let headless = Desktop::default();
        assert!(service_child_needs_replacement(false, &mut uid, &headless));
        assert!(uid.is_empty());
        assert!(!service_child_needs_replacement(false, &mut uid, &headless));
    }

    #[test]
    fn r_s11e46_linux_root_principal_is_numeric_effective_uid() {
        assert!(effective_uid_is_root(0));
        assert!(!effective_uid_is_root(1));
        assert!(!effective_uid_is_root(1_000));
    }

    #[test]
    fn r_s11e48_linux_service_child_principal_uses_selected_numeric_uid() {
        let renamed_root = Desktop {
            uid: "0".to_owned(),
            username: "renamed-admin".to_owned(),
            ..Default::default()
        };
        assert_eq!(
            selected_service_child_principal(&renamed_root).unwrap(),
            Some(ServiceChildPrincipal::RootService)
        );

        let misleading_name = Desktop {
            uid: "1000".to_owned(),
            username: "root".to_owned(),
            ..Default::default()
        };
        assert_eq!(
            selected_service_child_principal(&misleading_name).unwrap(),
            Some(ServiceChildPrincipal::ActiveDesktopUser)
        );

        let login_wayland = Desktop {
            uid: "120".to_owned(),
            username: "gdm".to_owned(),
            protocol: DISPLAY_SERVER_WAYLAND.to_owned(),
            ..Default::default()
        };
        assert_eq!(
            selected_service_child_principal(&login_wayland).unwrap(),
            Some(ServiceChildPrincipal::RootService)
        );

        assert_eq!(
            selected_service_child_principal(&Desktop::default()).unwrap(),
            None
        );
        let noncanonical_uid = Desktop {
            uid: "01000".to_owned(),
            username: "owner".to_owned(),
            ..Default::default()
        };
        let malformed_uid = Desktop {
            uid: "not-a-uid".to_owned(),
            username: "owner".to_owned(),
            ..Default::default()
        };
        let missing_username = Desktop {
            uid: "1000".to_owned(),
            ..Default::default()
        };
        let missing_uid = Desktop {
            username: "owner".to_owned(),
            ..Default::default()
        };
        for invalid in [
            noncanonical_uid,
            malformed_uid,
            missing_username,
            missing_uid,
        ] {
            assert!(selected_service_child_principal(&invalid).is_err());
        }
    }

    #[test]
    fn r_s11e204_linux_service_term_is_service_owned_and_fixed() {
        assert_eq!(
            select_service_child_terminal_type(true),
            TERM_XTERM_256COLOR
        );
        assert_eq!(select_service_child_terminal_type(false), TERM_XTERM);

        let permitted_roots = [
            Path::new("/etc/terminfo"),
            Path::new("/lib/terminfo"),
            Path::new("/usr/share/terminfo"),
        ];
        assert_eq!(SERVICE_XTERM_256COLOR_PATHS.len(), 6);
        for path in SERVICE_XTERM_256COLOR_PATHS.map(Path::new) {
            assert!(path.is_absolute());
            assert_eq!(path.file_name(), Some(OsStr::new(TERM_XTERM_256COLOR)));
            assert!(permitted_roots.iter().any(|root| path.starts_with(root)));
        }
    }

    #[test]
    fn r_s11c10_process_discovery_matches_xwayland_by_argv() {
        let xwayland = vec![
            "/usr/bin/Xwayland".to_owned(),
            ":1".to_owned(),
            "-auth".to_owned(),
            "/run/user/1000/xauth_RoDZey".to_owned(),
        ];
        assert!(process_is_xwayland(&xwayland));
        assert_eq!(xwayland_display_arg(&xwayland), Some(":1"));

        let no_display = vec![
            "/usr/bin/Xwayland".to_owned(),
            "-displayfd".to_owned(),
            "76".to_owned(),
        ];
        assert!(process_is_xwayland(&no_display));
        assert_eq!(xwayland_display_arg(&no_display), None);

        let grep = vec![
            "/usr/bin/grep".to_owned(),
            "Xwayland".to_owned(),
            ":2".to_owned(),
        ];
        assert!(!process_is_xwayland(&grep));
        assert_eq!(xwayland_display_arg(&grep), None);

        let lower_case = vec!["/usr/bin/xwayland".to_owned(), ":3".to_owned()];
        assert!(!process_is_xwayland(&lower_case));

        assert!(is_local_x_display_arg(":0"));
        assert!(is_local_x_display_arg(":1.0"));
        assert!(!is_local_x_display_arg(":"));
        assert!(!is_local_x_display_arg(":1."));
        assert!(!is_local_x_display_arg(":1.0.2"));
        assert!(!is_local_x_display_arg(":abc"));
        assert!(!is_local_x_display_arg("localhost:0"));
    }

    #[test]
    fn r_s11e207_desktop_process_classification_is_exact() {
        let cases = [
            (
                vec!["/usr/libexec/xdg-desktop-portal".to_owned()],
                Some(DesktopProcessKind::Portal),
            ),
            (
                vec!["/usr/bin/Xwayland".to_owned(), ":7".to_owned()],
                Some(DesktopProcessKind::Xwayland),
            ),
            (
                vec!["/usr/bin/kded6".to_owned()],
                Some(DesktopProcessKind::Kded),
            ),
            (
                vec!["/usr/bin/rustdesk".to_owned(), "--tray".to_owned()],
                Some(DesktopProcessKind::Tray),
            ),
        ];
        for (args, expected) in cases {
            assert_eq!(classify_desktop_process(&args, "RustDesk"), expected);
        }
        for args in [
            vec!["/tmp/not-Xwayland".to_owned(), "Xwayland".to_owned()],
            vec!["/tmp/kded6-suffix".to_owned()],
            vec!["/tmp/rustdesk-helper".to_owned(), "--tray".to_owned()],
            vec!["/usr/bin/rustdesk".to_owned(), "+--tray".to_owned()],
            vec!["/usr/bin/rustdesk".to_owned(), "--server".to_owned()],
        ] {
            assert_eq!(classify_desktop_process(&args, "RustDesk"), None);
        }
    }

    #[test]
    fn r_s11e207_proc_observation_rejects_oversized_or_partial_values() {
        struct BytesThenError {
            offset: usize,
        }

        impl std::io::Read for BytesThenError {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                let bytes = b"abc";
                if self.offset == bytes.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "fixture read failure",
                    ));
                }
                let count = (bytes.len() - self.offset).min(buffer.len());
                buffer[..count].copy_from_slice(&bytes[self.offset..self.offset + count]);
                self.offset += count;
                Ok(count)
            }
        }

        let mut budget = ProcSnapshotBudget::default();
        let mut oversized = std::io::Cursor::new(vec![b'a'; PROC_CMDLINE_MAX_BYTES + 1]);
        assert!(matches!(
            read_bounded_proc_reader(&mut oversized, PROC_CMDLINE_MAX_BYTES, &mut budget),
            Ok(BoundedProcFile::Oversized)
        ));
        assert_eq!(budget.total_bytes, PROC_CMDLINE_MAX_BYTES + 1);

        let mut aggregate_budget = ProcSnapshotBudget {
            total_bytes: PROC_SNAPSHOT_MAX_TOTAL_BYTES - 2,
            ..Default::default()
        };
        let mut over_aggregate = std::io::Cursor::new(vec![b'b'; 3]);
        assert!(matches!(
            read_bounded_proc_reader(&mut over_aggregate, 8, &mut aggregate_budget),
            Err(ProcSnapshotError::Limit(ProcSnapshotLimit::TotalBytes))
        ));

        let mut failed_read_budget = ProcSnapshotBudget::default();
        assert!(matches!(
            read_bounded_proc_reader(
                &mut BytesThenError { offset: 0 },
                PROC_CMDLINE_MAX_BYTES,
                &mut failed_read_budget
            ),
            Ok(BoundedProcFile::Unavailable)
        ));
        assert_eq!(failed_read_budget.total_bytes, 3);

        assert_eq!(parse_proc_cmdline_args(b"/usr/bin/Xwayland"), None);
        assert_eq!(parse_proc_cmdline_args(b"/usr/bin/Xwayland\0:\xff\0"), None);

        let oversized_value = format!(
            "WAYLAND_DISPLAY={}",
            "w".repeat(PROC_ENV_VALUE_MAX_BYTES + 1)
        );
        assert_eq!(
            proc_environ_value(oversized_value.as_bytes(), "WAYLAND_DISPLAY"),
            None
        );
        assert_eq!(proc_environ_value(b"DISPLAY=:\xff\0", "DISPLAY"), None);
        assert_eq!(
            proc_environ_value(b"DISPLAY=:7\0DISPLAY=:8\0", "DISPLAY"),
            None
        );
        assert_eq!(
            DesktopSessionEnvironment::from_environ(b"WAYLAND_DISPLAY=wayland-0"),
            None
        );
    }

    #[test]
    fn r_s11e207_service_child_replacement_tracks_complete_selected_desktop() {
        let mut selected = Desktop {
            sid: "session-1".to_owned(),
            username: "owner".to_owned(),
            uid: "1000".to_owned(),
            protocol: DISPLAY_SERVER_WAYLAND.to_owned(),
            display: ":7".to_owned(),
            xauth: "/run/user/1000/xauth".to_owned(),
            wl_display: "wayland-0".to_owned(),
            dbus: "unix:path=/run/user/1000/bus".to_owned(),
            ..Default::default()
        };
        let mut previous = ServiceChildDesktopIdentity::default();
        assert!(update_service_child_desktop_identity(
            &mut previous,
            &selected
        ));
        assert!(!update_service_child_desktop_identity(
            &mut previous,
            &selected
        ));

        selected.wl_display = "wayland-1".to_owned();
        assert!(update_service_child_desktop_identity(
            &mut previous,
            &selected
        ));
        selected.dbus = "unix:path=/run/user/1000/other-bus".to_owned();
        assert!(update_service_child_desktop_identity(
            &mut previous,
            &selected
        ));
        selected.sid = "session-2".to_owned();
        assert!(update_service_child_desktop_identity(
            &mut previous,
            &selected
        ));
    }

    #[test]
    fn r_s11e207_desktop_snapshot_keeps_one_validated_process_environment() {
        let snapshot = DesktopProcessSnapshot {
            environments: vec![
                DesktopProcessEnvironment {
                    pid: 10,
                    kind: DesktopProcessKind::Portal,
                    environ: b"DISPLAY=:7\0WAYLAND_DISPLAY=wayland-0\0".to_vec(),
                },
                DesktopProcessEnvironment {
                    pid: 11,
                    kind: DesktopProcessKind::Portal,
                    environ: b"DISPLAY=:8\0XAUTHORITY=/run/user/1000/xauth\0WAYLAND_DISPLAY=wayland-1\0DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus\0".to_vec(),
                },
                DesktopProcessEnvironment {
                    pid: 12,
                    kind: DesktopProcessKind::Portal,
                    environ: b"DISPLAY=remote:9\0XAUTHORITY=relative\0WAYLAND_DISPLAY=bad\nname\0DBUS_SESSION_BUS_ADDRESS=tcp:host=127.0.0.1\n\0".to_vec(),
                },
            ],
            xwayland_running: false,
        };
        let environment = snapshot.best_environment(
            DesktopProcessKind::Portal,
            &[
                DesktopEnvironmentKey::WaylandDisplay,
                DesktopEnvironmentKey::Dbus,
                DesktopEnvironmentKey::Display,
                DesktopEnvironmentKey::Xauthority,
            ],
        );
        assert_eq!(environment.display, ":8");
        assert_eq!(environment.xauth, "/run/user/1000/xauth");
        assert_eq!(environment.wl_display, "wayland-1");
        assert_eq!(environment.dbus, "unix:path=/run/user/1000/bus");
        assert_eq!(
            snapshot
                .xauthority_for_display(DesktopProcessKind::Portal, ":8")
                .as_deref(),
            Some("/run/user/1000/xauth")
        );
        assert_eq!(
            snapshot.xauthority_for_display(DesktopProcessKind::Portal, ":7"),
            None
        );
    }

    #[test]
    fn r_s11e257_desktop_selector_process_requires_the_same_interpretation_namespaces() {
        let current_authority = current_selector_namespace_authority().unwrap();
        let current = current_authority.identity;
        let process_dir = fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                hbb_common::libc::O_CLOEXEC
                    | hbb_common::libc::O_DIRECTORY
                    | hbb_common::libc::O_NOFOLLOW,
            )
            .open("/proc/self")
            .unwrap();
        assert!(process_shares_selector_namespaces(&process_dir, current));

        let foreign_mount = ProcSelectorNamespaceIdentity {
            mount: ProcNamespaceIdentity {
                device: current.mount.device,
                inode: current.mount.inode.wrapping_add(1),
            },
            network: current.network,
        };
        assert!(!process_shares_selector_namespaces(
            &process_dir,
            foreign_mount
        ));

        let foreign_network = ProcSelectorNamespaceIdentity {
            mount: current.mount,
            network: ProcNamespaceIdentity {
                device: current.network.device,
                inode: current.network.inode.wrapping_add(1),
            },
        };
        assert!(!process_shares_selector_namespaces(
            &process_dir,
            foreign_network
        ));
    }

    #[test]
    fn r_s11e42_xauthority_is_bound_to_the_selected_display() {
        let selected = b"DISPLAY=:7.0\0XAUTHORITY=/run/user/1000/selected.auth\0";
        assert_eq!(
            xauthority_from_environ_for_display(selected, ":7").as_deref(),
            Some("/run/user/1000/selected.auth")
        );
        assert_eq!(xauthority_from_environ_for_display(selected, ":8"), None);
        assert_eq!(
            xauthority_from_environ_for_display(b"DISPLAY=:7\0XAUTHORITY=relative.auth\0", ":7"),
            None
        );
        assert_eq!(
            xauthority_from_environ_for_display(
                b"DISPLAY=host:7\0XAUTHORITY=/tmp/remote.auth\0",
                ":7"
            ),
            None
        );
    }
}

#[cfg(test)]
mod xrandr_tests {
    use super::*;

    #[test]
    fn r_s11c10_xrandr_query_normalization_matches_space_squeeze() {
        let normalized = normalize_xrandr_query_output(
            "eDP-1  connected   primary 1920x1080+0+0\n  1920x1080     60.01*+  59.97\n",
        );
        assert_eq!(
            normalized,
            "eDP-1 connected primary 1920x1080+0+0\n 1920x1080 60.01*+ 59.97\n"
        );

        let re = Regex::new(&get_xrandr_conn_pat("eDP-1")).unwrap();
        let caps = re
            .captures(&normalized)
            .expect("normalized xrandr output should parse");
        assert_eq!(get_width_height_from_captures(&caps), Some((1920, 1080)));
    }
}

pub fn quit_gui() {
    unsafe { gtk_main_quit() };
}

pub fn check_super_user_permission() -> ResultType<bool> {
    // R-X11: no in-process interactive elevation — the GTK sudo/su
    // password-driver front-end is excised. The sanctioned model is the installed root
    // systemd service (R-D1/R-D3/R-X10), so "super-user permission" is whether
    // this process already holds root, never an elevation prompt.
    Ok(is_root())
}

type GtkSettingsPtr = *mut c_void;
type GObjectPtr = *mut c_void;
#[link(name = "gtk-3")]
extern "C" {
    // fn gtk_init(argc: *mut c_int, argv: *mut *mut c_char);
    fn gtk_settings_get_default() -> GtkSettingsPtr;
}

#[link(name = "gobject-2.0")]
extern "C" {
    fn g_object_get(object: GObjectPtr, first_property_name: *const c_char, ...);
}

pub fn get_double_click_time() -> u32 {
    // GtkSettings *settings = gtk_settings_get_default ();
    // g_object_get (settings, "gtk-double-click-time", &double_click_time, NULL);
    unsafe {
        let mut double_click_time = 0u32;
        let Ok(property) = std::ffi::CString::new("gtk-double-click-time") else {
            return 0;
        };
        let settings = gtk_settings_get_default();
        g_object_get(
            settings,
            property.as_ptr(),
            &mut double_click_time as *mut u32,
            0 as *const c_void,
        );
        double_click_time
    }
}

#[inline]
fn get_width_height_from_captures<'t>(caps: &Captures<'t>) -> Option<(i32, i32)> {
    match (caps.name("width"), caps.name("height")) {
        (Some(width), Some(height)) => {
            match (
                width.as_str().parse::<i32>(),
                height.as_str().parse::<i32>(),
            ) {
                (Ok(width), Ok(height)) => {
                    return Some((width, height));
                }
                _ => {}
            }
        }
        _ => {}
    }
    None
}

#[inline]
fn get_xrandr_conn_pat(name: &str) -> String {
    format!(
        r"{}\s+connected.+?(?P<width>\d+)x(?P<height>\d+)\+(?P<x>\d+)\+(?P<y>\d+).*?\n",
        name
    )
}

fn normalize_xrandr_query_output(output: &str) -> String {
    let mut normalized = String::with_capacity(output.len());
    let mut previous_was_space = false;
    for c in output.chars() {
        if c == ' ' {
            if !previous_was_space {
                normalized.push(c);
            }
            previous_was_space = true;
        } else {
            normalized.push(c);
            previous_was_space = false;
        }
    }
    normalized
}

fn xrandr_query() -> ResultType<String> {
    let Some(xrandr) = xrandr_path() else {
        bail!("xrandr was not found at a trusted fixed path");
    };
    let mut command = Command::new(xrandr);
    command.arg("--query");
    configure_command_close_nonstdio_on_exec(&mut command)?;
    let output = command.output()?;
    Ok(normalize_xrandr_query_output(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

pub fn resolutions(name: &str) -> Vec<Resolution> {
    let resolutions_pat = r"(?P<resolutions>(\s*\d+x\d+\s+\d+.*\n)+)";
    let connected_pat = get_xrandr_conn_pat(name);
    let mut v = vec![];
    if let Ok(re) = Regex::new(&format!("{}{}", connected_pat, resolutions_pat)) {
        match xrandr_query() {
            Ok(xrandr_output) => {
                // There'are different kinds of xrandr output.
                /*
                1.
                Screen 0: minimum 320 x 175, current 1920 x 1080, maximum 1920 x 1080
                default connected 1920x1080+0+0 0mm x 0mm
                 1920x1080 10.00*
                 1280x720 25.00
                 1680x1050 60.00
                Virtual2 disconnected (normal left inverted right x axis y axis)
                Virtual3 disconnected (normal left inverted right x axis y axis)

                Screen 0: minimum 320 x 200, current 1920 x 1080, maximum 16384 x 16384
                eDP-1 connected primary 1920x1080+0+0 (normal left inverted right x axis y axis) 344mm x 193mm
                1920x1080     60.01*+  60.01    59.97    59.96    59.93
                1680x1050     59.95    59.88
                1600x1024     60.17

                XWAYLAND0 connected primary 1920x984+0+0 (normal left inverted right x axis y axis) 0mm x 0mm
                Virtual1 connected primary 1920x984+0+0 (normal left inverted right x axis y axis) 0mm x 0mm
                HDMI-0 connected (normal left inverted right x axis y axis)

                rdp0 connected primary 1920x1080+0+0 0mm x 0mm
                    */
                if let Some(caps) = re.captures(&xrandr_output) {
                    if let Some(resolutions) = caps.name("resolutions") {
                        let resolution_pat =
                            r"\s*(?P<width>\d+)x(?P<height>\d+)\s+(?P<rates>(\d+\.\d+\D*)+)\s*\n";
                        let Ok(resolution_re) = Regex::new(&format!(r"{}", resolution_pat)) else {
                            log::error!("Regex new failed");
                            return vec![];
                        };
                        for resolution_caps in resolution_re.captures_iter(resolutions.as_str()) {
                            if let Some((width, height)) =
                                get_width_height_from_captures(&resolution_caps)
                            {
                                let resolution = Resolution {
                                    width,
                                    height,
                                    ..Default::default()
                                };
                                if !v.contains(&resolution) {
                                    v.push(resolution);
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => log::error!("Failed to run xrandr query, {}", e),
        }
    }

    v
}

pub fn current_resolution(name: &str) -> ResultType<Resolution> {
    let xrandr_output = xrandr_query()?;
    let re = Regex::new(&get_xrandr_conn_pat(name))?;
    if let Some(caps) = re.captures(&xrandr_output) {
        if let Some((width, height)) = get_width_height_from_captures(&caps) {
            return Ok(Resolution {
                width,
                height,
                ..Default::default()
            });
        }
    }
    bail!("Failed to find current resolution for {}", name);
}

pub fn change_resolution_directly(name: &str, width: usize, height: usize) -> ResultType<()> {
    let Some(xrandr) = xrandr_path() else {
        bail!("xrandr was not found at a trusted fixed path");
    };
    let mode = format!("{}x{}", width, height);
    let mut command = Command::new(xrandr);
    command.args(["--output", name, "--mode", &mode]);
    configure_command_close_nonstdio_on_exec(&mut command)?;
    command.spawn()?;
    Ok(())
}

fn canonical_x11_socket_display_number(name: &OsStr) -> Option<u32> {
    let bytes = name.as_bytes();
    let digits = bytes.strip_prefix(b"X")?;
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let digits = std::str::from_utf8(digits).ok()?;
    let display = digits.parse::<u32>().ok()?;
    (display.to_string() == digits).then_some(display)
}

fn cgroup_v2_path_has_exact_session_scope(bytes: &[u8], scope: &str) -> bool {
    if bytes.is_empty() || bytes.last() != Some(&b'\n') {
        return false;
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut unified_path = None;
    for line in text.lines() {
        let mut fields = line.splitn(3, ':');
        let (Some(hierarchy), Some(controllers), Some(path), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return false;
        };
        if path.is_empty()
            || !path.starts_with('/')
            || path.bytes().any(|byte| byte.is_ascii_control())
        {
            return false;
        }
        if hierarchy == "0" {
            if !controllers.is_empty() || unified_path.replace(path).is_some() {
                return false;
            }
        }
    }
    let Some(path) = unified_path else {
        return false;
    };
    !path.ends_with(" (deleted)") && path.rsplit('/').next() == Some(scope)
}

fn poll_descriptor_is_live(fd: c_int) -> bool {
    let mut pollfd = hbb_common::libc::pollfd {
        fd,
        events: hbb_common::libc::POLLIN,
        revents: 0,
    };
    (unsafe { hbb_common::libc::poll(&mut pollfd, 1, 0) }) == 0
}

fn x11_socket_peer_pidfd(socket: &File) -> Option<File> {
    let mut pidfd = -1;
    let mut len = std::mem::size_of::<c_int>() as hbb_common::libc::socklen_t;
    let rc = unsafe {
        hbb_common::libc::getsockopt(
            socket.as_raw_fd(),
            hbb_common::libc::SOL_SOCKET,
            LINUX_SO_PEERPIDFD,
            (&mut pidfd as *mut c_int).cast::<c_void>(),
            &mut len,
        )
    };
    if rc != 0 || len as usize != std::mem::size_of::<c_int>() || pidfd < 0 {
        return None;
    }
    Some(unsafe { File::from_raw_fd(pidfd) })
}

fn x11_socket_peer_cred(socket: &File) -> Option<hbb_common::libc::ucred> {
    let mut cred: hbb_common::libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<hbb_common::libc::ucred>() as hbb_common::libc::socklen_t;
    let rc = unsafe {
        hbb_common::libc::getsockopt(
            socket.as_raw_fd(),
            hbb_common::libc::SOL_SOCKET,
            hbb_common::libc::SO_PEERCRED,
            (&mut cred as *mut hbb_common::libc::ucred).cast::<c_void>(),
            &mut len,
        )
    };
    if rc == 0 && len as usize == std::mem::size_of::<hbb_common::libc::ucred>() {
        Some(cred)
    } else {
        None
    }
}

fn connect_x11_socket(path: &Path, deadline: Instant) -> Option<File> {
    if Instant::now() >= deadline {
        return None;
    }
    let path = path.as_os_str().as_bytes();
    let mut address: hbb_common::libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if path.is_empty() || path.contains(&0) || path.len() >= address.sun_path.len() {
        return None;
    }
    let fd = unsafe {
        hbb_common::libc::socket(
            hbb_common::libc::AF_UNIX,
            hbb_common::libc::SOCK_STREAM
                | hbb_common::libc::SOCK_CLOEXEC
                | hbb_common::libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return None;
    }
    let socket = unsafe { File::from_raw_fd(fd) };
    address.sun_family = hbb_common::libc::AF_UNIX as hbb_common::libc::sa_family_t;
    unsafe {
        std::ptr::copy_nonoverlapping(
            path.as_ptr(),
            address.sun_path.as_mut_ptr().cast::<u8>(),
            path.len(),
        );
    }
    let address_len = std::mem::size_of::<hbb_common::libc::sa_family_t>()
        .checked_add(path.len())?
        .checked_add(1)?;
    let address_len = hbb_common::libc::socklen_t::try_from(address_len).ok()?;
    let rc = unsafe {
        hbb_common::libc::connect(
            socket.as_raw_fd(),
            (&address as *const hbb_common::libc::sockaddr_un).cast::<hbb_common::libc::sockaddr>(),
            address_len,
        )
    };
    if rc == 0 {
        return (Instant::now() < deadline).then_some(socket);
    }
    let err = std::io::Error::last_os_error().raw_os_error();
    if !matches!(
        err,
        Some(hbb_common::libc::EINPROGRESS) | Some(hbb_common::libc::EAGAIN)
    ) {
        return None;
    }
    let remaining = deadline.checked_duration_since(Instant::now())?;
    let timeout_ms = remaining
        .as_millis()
        .min(X11_SOCKET_CONNECT_TIMEOUT_MS as u128)
        .max(1) as c_int;
    let mut pollfd = hbb_common::libc::pollfd {
        fd: socket.as_raw_fd(),
        events: hbb_common::libc::POLLOUT,
        revents: 0,
    };
    if unsafe { hbb_common::libc::poll(&mut pollfd, 1, timeout_ms) } != 1
        || pollfd.revents & hbb_common::libc::POLLOUT == 0
        || pollfd.revents
            & (hbb_common::libc::POLLERR | hbb_common::libc::POLLHUP | hbb_common::libc::POLLNVAL)
            != 0
    {
        return None;
    }
    let mut socket_error = 0;
    let mut socket_error_len = std::mem::size_of::<c_int>() as hbb_common::libc::socklen_t;
    let rc = unsafe {
        hbb_common::libc::getsockopt(
            socket.as_raw_fd(),
            hbb_common::libc::SOL_SOCKET,
            hbb_common::libc::SO_ERROR,
            (&mut socket_error as *mut c_int).cast::<c_void>(),
            &mut socket_error_len,
        )
    };
    (rc == 0
        && socket_error_len as usize == std::mem::size_of::<c_int>()
        && socket_error == 0
        && Instant::now() < deadline)
        .then_some(socket)
}

fn x11_socket_peer_is_in_session(socket: &File, uid: u32, scope: &str) -> bool {
    let Some(cred) = x11_socket_peer_cred(socket) else {
        return false;
    };
    if cred.pid <= 0 || cred.uid != uid {
        return false;
    }
    let Some(pidfd) = x11_socket_peer_pidfd(socket) else {
        return false;
    };
    if !poll_descriptor_is_live(pidfd.as_raw_fd()) {
        return false;
    }
    let process_dir = PathBuf::from("/proc").join(cred.pid.to_string());
    let Ok(process_dir) = fs::OpenOptions::new()
        .read(true)
        .custom_flags(
            hbb_common::libc::O_CLOEXEC
                | hbb_common::libc::O_DIRECTORY
                | hbb_common::libc::O_NOFOLLOW,
        )
        .open(process_dir)
    else {
        return false;
    };
    let Ok(metadata) = process_dir.metadata() else {
        return false;
    };
    if !metadata.is_dir() || metadata.uid() != uid {
        return false;
    }
    let mut budget = ProcSnapshotBudget::default();
    let Ok(BoundedProcFile::Value(first)) = read_bounded_proc_member(
        &process_dir,
        ProcMember::Cgroup,
        PROC_CGROUP_MAX_BYTES,
        &mut budget,
    ) else {
        return false;
    };
    if !cgroup_v2_path_has_exact_session_scope(&first, scope) {
        return false;
    }
    let Ok(BoundedProcFile::Value(second)) = read_bounded_proc_member(
        &process_dir,
        ProcMember::Cgroup,
        PROC_CGROUP_MAX_BYTES,
        &mut budget,
    ) else {
        return false;
    };
    first == second && poll_descriptor_is_live(pidfd.as_raw_fd())
}

fn unique_x11_socket_display(displays: impl IntoIterator<Item = u32>) -> Option<String> {
    let mut selected = None;
    for display in displays {
        if selected.replace(display).is_some() {
            return None;
        }
    }
    selected.map(|display| format!(":{display}"))
}

fn selected_session_x11_socket_display(uid: &str, scope: &str) -> Option<String> {
    let uid = uid
        .parse::<u32>()
        .ok()
        .filter(|parsed| parsed.to_string() == uid)?;
    let tmp_metadata = fs::symlink_metadata("/tmp").ok()?;
    let directory_metadata = fs::symlink_metadata(X11_SOCKET_DIRECTORY).ok()?;
    if !tmp_metadata.is_dir()
        || tmp_metadata.uid() != 0
        || tmp_metadata.mode() & 0o1000 == 0
        || !directory_metadata.is_dir()
        || directory_metadata.uid() != 0
        || directory_metadata.mode() & 0o1000 == 0
    {
        return None;
    }

    let deadline = Instant::now().checked_add(X11_SOCKET_DISCOVERY_TIMEOUT)?;
    let mut candidates = Vec::new();
    let entries = fs::read_dir(X11_SOCKET_DIRECTORY).ok()?;
    for entry in entries {
        if Instant::now() >= deadline {
            return None;
        }
        let entry = entry.ok()?;
        let Some(display) = canonical_x11_socket_display_number(&entry.file_name()) else {
            continue;
        };
        let metadata = fs::symlink_metadata(entry.path()).ok()?;
        if !metadata.file_type().is_socket() || metadata.uid() != uid {
            continue;
        }
        if candidates.len() == X11_SOCKET_MAX_CANDIDATES {
            return None;
        }
        candidates.push((display, entry.path(), metadata.dev(), metadata.ino()));
    }
    candidates.sort_by_key(|candidate| candidate.0);

    let mut validated = Vec::new();
    for (display, path, device, inode) in candidates {
        if Instant::now() >= deadline {
            return None;
        }
        let Some(socket) = connect_x11_socket(&path, deadline) else {
            continue;
        };
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !metadata.file_type().is_socket()
            || metadata.uid() != uid
            || metadata.dev() != device
            || metadata.ino() != inode
            || !x11_socket_peer_is_in_session(&socket, uid, scope)
        {
            continue;
        }
        validated.push(display);
    }
    if Instant::now() >= deadline {
        return None;
    }
    unique_x11_socket_display(validated)
}

mod desktop {
    use super::*;

    const WAYLAND_ENVIRONMENT_PRIORITY: [DesktopEnvironmentKey; 4] = [
        DesktopEnvironmentKey::WaylandDisplay,
        DesktopEnvironmentKey::Dbus,
        DesktopEnvironmentKey::Display,
        DesktopEnvironmentKey::Xauthority,
    ];
    const XWAYLAND_ENVIRONMENT_PRIORITY: [DesktopEnvironmentKey; 4] = [
        DesktopEnvironmentKey::Display,
        DesktopEnvironmentKey::Xauthority,
        DesktopEnvironmentKey::WaylandDisplay,
        DesktopEnvironmentKey::Dbus,
    ];
    const XWAYLAND_ENVIRONMENT_KINDS: [DesktopProcessKind; 6] = [
        DesktopProcessKind::Portal,
        DesktopProcessKind::Xwayland,
        DesktopProcessKind::Ibus,
        DesktopProcessKind::Goa,
        DesktopProcessKind::Kded,
        DesktopProcessKind::Tray,
    ];
    const X11_XAUTHORITY_KINDS: [DesktopProcessKind; 7] = [
        DesktopProcessKind::Xwayland,
        DesktopProcessKind::Ibus,
        DesktopProcessKind::Goa,
        DesktopProcessKind::Kded,
        DesktopProcessKind::XfcePanel,
        DesktopProcessKind::SddmGreeter,
        DesktopProcessKind::Tray,
    ];

    #[derive(Debug, Clone, Default)]
    pub struct Desktop {
        pub sid: String,
        pub username: String,
        pub uid: String,
        pub protocol: String,
        pub display: String,
        pub xauth: String,
        pub home: String,
        pub dbus: String,
        pub wl_display: String,
    }

    impl Desktop {
        #[inline]
        pub fn is_wayland(&self) -> bool {
            self.protocol == DISPLAY_SERVER_WAYLAND
        }

        #[inline]
        pub fn is_login_wayland(&self) -> bool {
            super::is_gdm_user(&self.username) && self.protocol == DISPLAY_SERVER_WAYLAND
        }

        #[inline]
        pub fn is_headless(&self) -> bool {
            self.sid.is_empty()
        }

        fn apply_environment(&mut self, environment: DesktopSessionEnvironment) {
            self.display = environment.display;
            self.xauth = environment.xauth;
            self.wl_display = environment.wl_display;
            self.dbus = environment.dbus;
        }

        fn get_display_xauth_wayland(&mut self, snapshot: &DesktopProcessSnapshot) {
            self.apply_environment(snapshot.best_environment(
                DesktopProcessKind::Portal,
                &WAYLAND_ENVIRONMENT_PRIORITY,
            ));
        }

        fn get_display_xauth_xwayland(&mut self, snapshot: &DesktopProcessSnapshot) {
            let mut fallback = DesktopSessionEnvironment::default();
            let mut fallback_count = 0u8;
            let mut fallback_mask = 0u8;
            for kind in XWAYLAND_ENVIRONMENT_KINDS {
                let environment =
                    snapshot.best_environment(kind, &XWAYLAND_ENVIRONMENT_PRIORITY);
                if environment.has_x11_pair() {
                    self.apply_environment(environment);
                    return;
                }
                let count = environment.populated_count();
                let mask = environment.priority_mask(&WAYLAND_ENVIRONMENT_PRIORITY);
                if count > fallback_count || (count == fallback_count && mask > fallback_mask) {
                    fallback = environment;
                    fallback_count = count;
                    fallback_mask = mask;
                }
            }
            self.apply_environment(fallback);
        }

        fn get_display_x11(&mut self) {
            self.display = get_x11_session_authority(&self.sid)
                .and_then(|authority| {
                    authority.display.or_else(|| {
                        selected_session_x11_socket_display(&self.uid, &authority.scope)
                    })
                })
                .unwrap_or_default();
            self.wl_display.clear();
            self.dbus.clear();
        }

        fn get_home(&mut self) {
            self.home = get_user_home_by_name(&self.username)
                .map(|home| home.to_string_lossy().to_string())
                .unwrap_or_else(|| format!("/home/{}", &self.username));
        }

        fn get_xauth_x11(&mut self, snapshot: &DesktopProcessSnapshot) {
            self.xauth.clear();
            if self.display.is_empty() {
                return;
            }
            for kind in X11_XAUTHORITY_KINDS {
                if let Some(xauthority) = snapshot.xauthority_for_display(kind, &self.display) {
                    self.xauth = xauthority;
                    return;
                }
            }

            let gdm = format!("/run/user/{}/gdm/Xauthority", self.uid);
            if Path::new(&gdm).is_file() {
                self.xauth = gdm;
            }
        }

        fn clear_session_environment(&mut self) {
            self.display.clear();
            self.xauth.clear();
            self.wl_display.clear();
            self.dbus.clear();
        }

        fn refresh_selected_environment(&mut self) -> Result<(), ProcSnapshotError> {
            if self.is_login_wayland() {
                self.clear_session_environment();
                return Ok(());
            }
            let is_wayland = self.is_wayland();
            if !is_wayland {
                self.get_display_x11();
                if self.display.is_empty() {
                    self.xauth.clear();
                    return Ok(());
                }
            }
            let snapshot = observe_desktop_processes(&self.uid)?;
            if is_wayland {
                if snapshot.xwayland_running {
                    self.get_display_xauth_xwayland(&snapshot);
                } else {
                    self.get_display_xauth_wayland(&snapshot);
                }
            } else {
                self.get_xauth_x11(&snapshot);
            }
            Ok(())
        }

        fn fail_closed_observation(&mut self, err: ProcSnapshotError) {
            log::warn!("Refusing incomplete selected desktop observation: {err}");
            *self = Self::default();
        }

        pub fn refresh(&mut self) {
            if !self.sid.is_empty() && is_active_and_seat0(&self.sid) {
                if let Err(err) = self.refresh_selected_environment() {
                    self.fail_closed_observation(err);
                }
                return;
            }

            let seat0_values = get_values_of_seat0_with_gdm_wayland(&[0, 1, 2]);
            if seat0_values[0].is_empty() {
                *self = Self::default();
                return;
            }

            self.sid = seat0_values[0].clone();
            self.uid = seat0_values[1].clone();
            self.username = seat0_values[2].clone();
            self.protocol = get_display_server_of_session(&self.sid).into();
            self.get_home();
            if let Err(err) = self.refresh_selected_environment() {
                self.fail_closed_observation(err);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn r_s11hs_x11_socket_names_and_ambiguity_fail_closed() {
            assert_eq!(
                canonical_x11_socket_display_number(OsStr::new("X0")),
                Some(0)
            );
            assert_eq!(
                canonical_x11_socket_display_number(OsStr::new("X17")),
                Some(17)
            );
            for invalid in ["", "X", "X00", "X+1", "X-1", "X1.0", "x1", "Xone"] {
                assert_eq!(
                    canonical_x11_socket_display_number(OsStr::new(invalid)),
                    None,
                    "accepted {invalid:?}"
                );
            }
            assert_eq!(unique_x11_socket_display([7]).as_deref(), Some(":7"));
            assert_eq!(unique_x11_socket_display([]), None);
            assert_eq!(unique_x11_socket_display([0, 7]), None);
        }

        #[test]
        fn r_s11hs_x11_socket_peer_cgroup_is_the_exact_session_scope() {
            assert!(cgroup_v2_path_has_exact_session_scope(
                b"0::/user.slice/user-1000.slice/session-2.scope\n",
                "session-2.scope"
            ));
            assert!(cgroup_v2_path_has_exact_session_scope(
                b"7:cpu:/legacy\n0::/user.slice/user-1000.slice/session-c7.scope\n",
                "session-c7.scope"
            ));
            for invalid in [
                b"0::/system.slice/docker.scope\n".as_slice(),
                b"0::/user.slice/user-1000.slice/session-3.scope\n".as_slice(),
                b"0::/user.slice/user-1000.slice/session-2.scope/child\n".as_slice(),
                b"0::/user.slice/user-1000.slice/session-2.scope (deleted)\n".as_slice(),
                b"0::/user.slice/user-1000.slice/session-2.scope".as_slice(),
                b"0:cpu:/user.slice/user-1000.slice/session-2.scope\n".as_slice(),
                b"0::/user.slice/user-1000.slice/session-2.scope\n0::/other\n".as_slice(),
            ] {
                assert!(
                    !cgroup_v2_path_has_exact_session_scope(invalid, "session-2.scope"),
                    "accepted {invalid:?}"
                );
            }
        }

        #[test]
        fn r_s11e43_headless_state_is_derived_from_the_selected_session() {
            let mut desktop = Desktop::default();
            assert!(desktop.is_headless());

            desktop.sid = "selected-session".to_owned();
            assert!(!desktop.is_headless());
        }

        #[test]
        fn test_desktop_env() {
            let mut d = Desktop::default();
            d.refresh();
            if d.username == "root" {
                assert_eq!(d.home, "/root");
            } else {
                if !d.username.is_empty() {
                    let home = super::super::get_env_var("HOME");
                    if !home.is_empty() {
                        assert_eq!(d.home, home);
                    } else {
                        //
                    }
                }
            }
        }

        #[test]
        fn r_s11c10_proc_environ_value_matches_exact_key() {
            let environ = b"DISPLAY=:1\0DISPLAY_SUFFIX=bad\0XAUTHORITY=/tmp/auth\0";
            assert_eq!(
                proc_environ_value(environ, "DISPLAY"),
                Some(":1".to_string())
            );
            assert_eq!(
                proc_environ_value(environ, "XAUTHORITY"),
                Some("/tmp/auth".to_string())
            );
            assert_eq!(proc_environ_value(environ, "MISSING"), None);
            assert_eq!(proc_environ_value(environ, "BAD=KEY"), None);
        }

        #[test]
        fn r_s11c10_non_login_shell_detection_is_path_based() {
            assert!(is_non_login_shell(Path::new("/bin/false")));
            assert!(is_non_login_shell(Path::new("/usr/sbin/nologin")));
            assert!(is_non_login_shell(Path::new("/sbin/nologin")));
            assert!(!is_non_login_shell(Path::new("/bin/bash")));
        }
    }
}

pub struct WakeLock(Option<keepawake::AwakeHandle>);

impl WakeLock {
    pub fn new(display: bool, idle: bool, sleep: bool) -> Self {
        WakeLock(
            keepawake::Builder::new()
                .display(display)
                .idle(idle)
                .sleep(sleep)
                .create()
                .ok(),
        )
    }
}

const SYSTEMCTL_PATHS: [&str; 2] = ["/usr/bin/systemctl", "/bin/systemctl"];

pub fn schedule_reopen_after_service_stop(secs: u32) {
    let exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(e) => {
            log::error!("Failed to get current exe: {}", e);
            return;
        }
    };

    let mut command = Command::new(&exe);
    command
        .arg(REOPEN_AFTER_SERVICE_STOP_ARG)
        .arg(secs.to_string());
    if let Err(err) = configure_command_close_nonstdio_on_exec(&mut command) {
        log::warn!("Failed to constrain RustDesk reopen descriptors: {}", err);
        return;
    }
    if let Err(err) = command.spawn() {
        log::warn!("Failed to schedule RustDesk reopen: {}", err);
    }
}

pub fn reopen_after_service_stop(secs: u32) {
    std::thread::sleep(Duration::from_secs(secs as u64));
    match std::env::current_exe() {
        Ok(exe) => {
            let mut command = Command::new(exe);
            if let Err(err) = configure_command_close_nonstdio_on_exec(&mut command) {
                log::warn!("Failed to constrain RustDesk reopen descriptors: {}", err);
                return;
            }
            if let Err(err) = command.spawn() {
                log::warn!("Failed to reopen RustDesk after service stop: {}", err);
            }
        }
        Err(err) => {
            log::warn!("Failed to resolve current executable for reopen: {}", err);
        }
    }
}

fn linux_helper_path_is_clean_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn trusted_command_file_metadata(is_file: bool, uid: u32, mode: u32) -> bool {
    is_file && uid == 0 && mode & 0o022 == 0 && mode & 0o111 != 0
}

fn trusted_command_parent_metadata(is_dir: bool, uid: u32, mode: u32) -> bool {
    is_dir && uid == 0 && mode & 0o022 == 0
}

fn trusted_command_file(metadata: &fs::Metadata) -> bool {
    trusted_command_file_metadata(metadata.is_file(), metadata.uid(), metadata.mode())
}

fn trusted_command_parent(metadata: &fs::Metadata) -> bool {
    trusted_command_parent_metadata(metadata.is_dir(), metadata.uid(), metadata.mode())
}

fn trusted_fixed_executable_path(path: &Path) -> Option<PathBuf> {
    if !linux_helper_path_is_clean_absolute(path) {
        return None;
    }
    let candidate_parent = path.parent()?;
    if !trusted_command_parent(&fs::metadata(candidate_parent).ok()?) {
        return None;
    }
    let canonical = fs::canonicalize(path).ok()?;
    if !linux_helper_path_is_clean_absolute(&canonical) {
        return None;
    }
    let canonical_parent = canonical.parent()?;
    if !trusted_command_parent(&fs::metadata(canonical_parent).ok()?) {
        return None;
    }
    if !trusted_command_file(&fs::metadata(&canonical).ok()?) {
        return None;
    }
    Some(canonical)
}

fn trusted_command_path(paths: &'static [&'static str]) -> Option<PathBuf> {
    paths
        .iter()
        .find_map(|path| trusted_fixed_executable_path(Path::new(path)))
}

fn xrandr_path() -> Option<PathBuf> {
    trusted_command_path(&XRANDR_PATHS)
}

fn systemctl_path() -> Option<PathBuf> {
    trusted_command_path(&SYSTEMCTL_PATHS)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SystemctlServiceAction {
    Enable,
    Start,
    Disable,
    Stop,
}

impl SystemctlServiceAction {
    fn verb(self) -> &'static str {
        match self {
            Self::Enable => "enable",
            Self::Start => "start",
            Self::Disable => "disable",
            Self::Stop => "stop",
        }
    }
}

fn systemctl_service_unit(app_name: &str) -> Option<String> {
    const MAX_APP_NAME_LEN: usize = 64;

    let bytes = app_name.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_APP_NAME_LEN
        || !bytes[0].is_ascii_alphabetic()
        || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    {
        return None;
    }
    Some(format!("{}.service", app_name.to_ascii_lowercase()))
}

fn configure_systemctl_environment(command: &mut Command) {
    command.env_clear();
}

fn configure_systemctl_command(command: &mut Command, action: SystemctlServiceAction, unit: &str) {
    configure_systemctl_environment(command);
    command
        .args([
            "--system",
            "--no-pager",
            "--no-ask-password",
            "--",
            action.verb(),
            unit,
        ])
        .stdin(std::process::Stdio::null());
}

fn systemctl_service(action: SystemctlServiceAction, app_name: &str) -> bool {
    let Some(unit) = systemctl_service_unit(app_name) else {
        log::error!("Refusing invalid systemctl service application name: {app_name:?}");
        return false;
    };
    let Some(systemctl) = systemctl_path() else {
        log::error!("systemctl was not found at a trusted fixed path");
        return false;
    };
    let mut command = Command::new(systemctl);
    configure_systemctl_command(&mut command, action, &unit);
    if let Err(err) = configure_command_close_nonstdio_on_exec(&mut command) {
        log::error!(
            "Failed to constrain systemctl {} {unit} descriptors: {err}",
            action.verb()
        );
        return false;
    }
    match command.status() {
        Ok(status) if status.success() => true,
        Ok(status) => {
            log::error!(
                "systemctl {} {unit} failed with status {status}",
                action.verb()
            );
            false
        }
        Err(err) => {
            log::error!("Failed to run systemctl {} {unit}: {err}", action.verb());
            false
        }
    }
}

pub fn uninstall_service(show_new_window: bool, _: bool) -> bool {
    if systemctl_path().is_none() {
        // Failed when installed + flutter run + started by `show_new_window`.
        return false;
    }
    log::info!("Uninstalling service...");
    let app_name = crate::get_app_name();
    if !systemctl_service(SystemctlServiceAction::Disable, &app_name) {
        return false;
    }
    if !systemctl_service(SystemctlServiceAction::Stop, &app_name) {
        return false;
    }
    // Stopping the service can terminate child processes before this branch runs.
    if show_new_window {
        schedule_reopen_after_service_stop(2);
    }
    std::process::exit(0);
}

pub fn install_service() -> bool {
    let _installing = crate::platform::InstallingService::new();
    if systemctl_path().is_none() {
        return false;
    }
    log::info!("Installing service...");
    let app_name = crate::get_app_name();
    if !systemctl_service(SystemctlServiceAction::Enable, &app_name) {
        return false;
    }
    if !systemctl_service(SystemctlServiceAction::Start, &app_name) {
        log::error!("Failed to enable/start the {app_name} service");
        return false;
    }
    true
}

#[cfg(test)]
mod service_lifecycle_tests {
    use super::*;

    #[test]
    fn r_s11cb_service_child_comparison_requires_exact_contents() {
        let directory = std::env::temp_dir().join(format!(
            "rustdesk-service-child-comparison-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let left_path = directory.join("left");
        let right_path = directory.join("right");
        let contents = vec![0x5a; 16 * 1024 + 7];
        fs::write(&left_path, &contents).unwrap();
        fs::write(&right_path, &contents).unwrap();

        let mut left = File::open(&left_path).unwrap();
        let mut right = File::open(&right_path).unwrap();
        assert!(files_have_exact_contents(&mut left, &mut right, contents.len() as u64).unwrap());

        let mut changed = contents.clone();
        changed[16 * 1024 + 1] ^= 0xff;
        fs::write(&right_path, &changed).unwrap();
        let mut left = File::open(&left_path).unwrap();
        let mut right = File::open(&right_path).unwrap();
        assert!(!files_have_exact_contents(&mut left, &mut right, contents.len() as u64).unwrap());

        let mut longer = contents.clone();
        longer.push(0);
        fs::write(&right_path, &longer).unwrap();
        let mut left = File::open(&left_path).unwrap();
        let mut right = File::open(&right_path).unwrap();
        assert!(!files_have_exact_contents(&mut left, &mut right, contents.len() as u64).unwrap());

        fs::write(&right_path, &contents[..contents.len() - 1]).unwrap();
        let mut left = File::open(&left_path).unwrap();
        let mut right = File::open(&right_path).unwrap();
        assert!(files_have_exact_contents(&mut left, &mut right, contents.len() as u64).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn r_s11c10_service_lifecycle_uses_absolute_systemctl_candidates() {
        for path in SYSTEMCTL_PATHS {
            assert!(Path::new(path).is_absolute());
            assert!(path.ends_with("/systemctl"));
        }
    }

    #[test]
    fn r_s11e41_systemctl_service_actions_and_unit_are_exact() {
        let cases = [
            (SystemctlServiceAction::Enable, "enable"),
            (SystemctlServiceAction::Start, "start"),
            (SystemctlServiceAction::Disable, "disable"),
            (SystemctlServiceAction::Stop, "stop"),
        ];
        for (action, verb) in cases {
            let mut command = Command::new("/usr/bin/systemctl");
            configure_systemctl_command(&mut command, action, "rustdesk.service");
            let arguments: Vec<_> = command.get_args().collect();
            assert_eq!(
                arguments,
                [
                    "--system",
                    "--no-pager",
                    "--no-ask-password",
                    "--",
                    verb,
                    "rustdesk.service",
                ]
            );
        }

        assert_eq!(
            systemctl_service_unit("RustDesk-Haggai7").as_deref(),
            Some("rustdesk-haggai7.service")
        );
        for invalid in [
            "",
            "-rustdesk",
            "rustdesk-",
            "rustdesk.service",
            "rust/desk",
            "rust desk",
            "rüstdesk",
        ] {
            assert!(systemctl_service_unit(invalid).is_none(), "{invalid:?}");
        }
        assert!(systemctl_service_unit(&format!("r{}", "a".repeat(63))).is_some());
        assert!(systemctl_service_unit(&format!("r{}", "a".repeat(64))).is_none());
    }

    #[test]
    fn r_s11e41_systemctl_child_excludes_inherited_environment() {
        const ROLE: &str = "RUSTDESK_TEST_SYSTEMCTL_ENVIRONMENT_ROLE";
        const TEST_NAME: &str = "platform::linux::service_lifecycle_tests::r_s11e41_systemctl_child_excludes_inherited_environment";
        const HOSTILE_BUS: &str = "unix:path=/tmp/rustdesk-hostile-systemctl-system-bus";
        const HOSTILE_UNIT_PATH: &str = "/tmp/rustdesk-hostile-systemctl-units";

        match std::env::var(ROLE).as_deref() {
            Ok("launcher") => {
                assert_eq!(
                    std::env::var("DBUS_SYSTEM_BUS_ADDRESS").as_deref(),
                    Ok(HOSTILE_BUS)
                );
                assert_eq!(std::env::var("SYSTEMCTL_FORCE_BUS").as_deref(), Ok("1"));
                assert_eq!(
                    std::env::var("SYSTEMD_UNIT_PATH").as_deref(),
                    Ok(HOSTILE_UNIT_PATH)
                );
                assert_eq!(std::env::var("SYSTEMD_PAGER").as_deref(), Ok("/bin/sh"));
                assert_eq!(std::env::var("SYSTEMD_OFFLINE").as_deref(), Ok("1"));
                let mut worker = Command::new(std::env::current_exe().unwrap());
                configure_systemctl_environment(&mut worker);
                let status = worker
                    .env(ROLE, "worker")
                    .args(["--exact", TEST_NAME, "--nocapture"])
                    .status()
                    .unwrap();
                assert!(status.success());
            }
            Ok("worker") => {
                for variable in [
                    "DBUS_SYSTEM_BUS_ADDRESS",
                    "SYSTEMCTL_FORCE_BUS",
                    "SYSTEMD_UNIT_PATH",
                    "SYSTEMD_PAGER",
                    "SYSTEMD_OFFLINE",
                ] {
                    assert!(
                        std::env::var_os(variable).is_none(),
                        "{} survived",
                        variable
                    );
                }
                let unexpected: Vec<_> = std::env::vars_os()
                    .filter(|(key, _)| key != std::ffi::OsStr::new(ROLE))
                    .collect();
                assert!(
                    unexpected.is_empty(),
                    "unexpected environment: {:?}",
                    unexpected
                );
            }
            _ => {
                let status = Command::new(std::env::current_exe().unwrap())
                    .env(ROLE, "launcher")
                    .env("DBUS_SYSTEM_BUS_ADDRESS", HOSTILE_BUS)
                    .env("SYSTEMCTL_FORCE_BUS", "1")
                    .env("SYSTEMD_UNIT_PATH", HOSTILE_UNIT_PATH)
                    .env("SYSTEMD_PAGER", "/bin/sh")
                    .env("SYSTEMD_OFFLINE", "1")
                    .args(["--exact", TEST_NAME, "--nocapture"])
                    .status()
                    .unwrap();
                assert!(status.success());
            }
        }
    }

    #[test]
    fn r_s11c10_privileged_command_candidates_are_fixed_system_paths() {
        let command_sets: [&[&str]; 2] = [&XRANDR_PATHS, &SYSTEMCTL_PATHS];
        for paths in command_sets {
            for path in paths {
                assert!(Path::new(path).is_absolute());
                assert!(path.starts_with("/usr/bin/") || path.starts_with("/bin/"));
            }
        }
    }

    #[test]
    fn r_s11c10k_command_resolver_rejects_relative_parent_and_missing_paths() {
        assert!(trusted_command_path(&["sudo"]).is_none());
        assert!(trusted_command_path(&["/usr/bin/../bin/sudo"]).is_none());
        assert!(trusted_command_path(&["/definitely/not/rustdesk/sudo"]).is_none());
    }

    #[test]
    fn r_s11c10k_command_metadata_requires_root_unwritable_executable() {
        assert!(trusted_command_file_metadata(true, 0, 0o755));
        assert!(!trusted_command_file_metadata(false, 0, 0o755));
        assert!(!trusted_command_file_metadata(true, 1, 0o755));
        assert!(!trusted_command_file_metadata(true, 0, 0o775));
        assert!(!trusted_command_file_metadata(true, 0, 0o644));

        assert!(trusted_command_parent_metadata(true, 0, 0o755));
        assert!(!trusted_command_parent_metadata(false, 0, 0o755));
        assert!(!trusted_command_parent_metadata(true, 1, 0o755));
        assert!(!trusted_command_parent_metadata(true, 0, 0o775));
    }
}

pub fn check_autostart_config() -> ResultType<()> {
    // SECURITY: Use trusted home directory lookup via getpwuid instead of $HOME env var
    // to prevent confused-deputy attacks where an attacker manipulates environment variables.
    let home = match get_home_dir_trusted() {
        Some(p) => p.to_string_lossy().to_string(),
        None => {
            log::warn!("Failed to get trusted home directory for autostart config check");
            return Ok(());
        }
    };
    let app_name = crate::get_app_name().to_lowercase();
    let path = format!("{home}/.config/autostart");
    let file = format!("{path}/{app_name}.desktop");
    // https://github.com/rustdesk/rustdesk/issues/4863
    std::fs::remove_file(&file).ok();
    /*
        std::fs::create_dir_all(&path).ok();
        if !Path::new(&file).exists() {
            // write text to the desktop file
            let mut file = std::fs::File::create(&file)?;
            file.write_all(
                format!(
                    "
    [Desktop Entry]
    Type=Application
    Exec={app_name} --tray
    NoDisplay=false
            "
                )
                .as_bytes(),
            )?;
        }
        */
    Ok(())
}

pub struct WallPaperRemover {
    old_path: String,
    old_path_dark: Option<String>, // ubuntu 22.04 light/dark theme have different uri
}

impl WallPaperRemover {
    pub fn new() -> ResultType<Self> {
        let start = std::time::Instant::now();
        let old_path = wallpaper::get().map_err(|e| anyhow!(e.to_string()))?;
        let old_path_dark = wallpaper::get_dark().ok();
        if old_path.is_empty() && old_path_dark.clone().unwrap_or_default().is_empty() {
            bail!("already solid color");
        }
        wallpaper::set_from_path("").map_err(|e| anyhow!(e.to_string()))?;
        wallpaper::set_dark_from_path("").ok();
        log::info!(
            "created wallpaper remover,  old_path: {:?}, old_path_dark: {:?}, elapsed: {:?}",
            old_path,
            old_path_dark,
            start.elapsed(),
        );
        Ok(Self {
            old_path,
            old_path_dark,
        })
    }

    pub fn support() -> bool {
        let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
        if wallpaper::gnome::is_compliant(&desktop) || desktop.as_str() == "XFCE" {
            return wallpaper::get().is_ok();
        }
        false
    }
}

impl Drop for WallPaperRemover {
    fn drop(&mut self) {
        allow_err!(wallpaper::set_from_path(&self.old_path).map_err(|e| anyhow!(e.to_string())));
        if let Some(old_path_dark) = &self.old_path_dark {
            allow_err!(wallpaper::set_dark_from_path(old_path_dark.as_str())
                .map_err(|e| anyhow!(e.to_string())));
        }
    }
}

// R-X12 (§8): the capture+input backend is pinned to X11. is_x11() is a compile-time `true` — the §17
// box is Xorg; the Wayland/pipewire scrap path + the RUSTDESK_FORCED_DISPLAY_SERVER override are
// removed, so there is no runtime selector. Asserted at startup (direct_service, R-A4).
#[inline]
pub fn is_x11() -> bool {
    true
}

const SELINUX_ENFORCE_PATHS: [&str; 2] = ["/sys/fs/selinux/enforce", "/selinux/enforce"];

#[inline]
pub fn is_selinux_enforcing() -> bool {
    selinux_enforcing_from_paths(&SELINUX_ENFORCE_PATHS)
}

fn selinux_enforcing_from_paths(paths: &[&str]) -> bool {
    for path in paths {
        if let Some(enforcing) = selinux_enforce_file_state(Path::new(path)) {
            return enforcing;
        }
    }
    false
}

fn selinux_enforce_file_state(path: &Path) -> Option<bool> {
    std::fs::read_to_string(path)
        .map(|contents| parse_selinux_enforce(&contents))
        .ok()
        .flatten()
}

fn selinux_enforce_file_is_enforcing(path: &Path) -> bool {
    selinux_enforce_file_state(path).unwrap_or(false)
}

fn parse_selinux_enforce(contents: &str) -> Option<bool> {
    match contents.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod selinux_tests {
    use super::*;

    #[test]
    fn r_s11c10_selinux_enforce_parser_accepts_only_kernel_enforcing_value() {
        assert_eq!(parse_selinux_enforce("1\n"), Some(true));
        assert_eq!(parse_selinux_enforce(" 1 "), Some(true));
        assert_eq!(parse_selinux_enforce("0\n"), Some(false));
        assert_eq!(parse_selinux_enforce("Enforcing\n"), None);
        assert_eq!(parse_selinux_enforce("Current mode: enforcing\n"), None);
        assert_eq!(parse_selinux_enforce("1 0\n"), None);
        assert_eq!(parse_selinux_enforce(""), None);
    }

    #[test]
    fn r_s11c10_selinux_enforce_file_read_fails_closed() {
        let missing = std::env::temp_dir().join(format!(
            "rustdesk-missing-selinux-enforce-{}",
            std::process::id()
        ));
        assert!(!selinux_enforce_file_is_enforcing(&missing));
    }

    #[test]
    fn r_s11c10_selinux_enforce_paths_use_first_valid_state() {
        let root = std::env::temp_dir().join(format!(
            "rustdesk-selinux-enforce-{}",
            std::process::id()
        ));
        let primary = root.join("primary");
        let fallback = root.join("fallback");
        std::fs::create_dir_all(&root).unwrap();

        std::fs::write(&primary, "0\n").unwrap();
        std::fs::write(&fallback, "1\n").unwrap();
        assert!(!selinux_enforcing_from_paths(&[
            primary.to_str().unwrap(),
            fallback.to_str().unwrap()
        ]));

        std::fs::write(&primary, "unknown\n").unwrap();
        assert!(selinux_enforcing_from_paths(&[
            primary.to_str().unwrap(),
            fallback.to_str().unwrap()
        ]));

        std::fs::remove_dir_all(root).unwrap();
    }
}

/// Get the app ID for shortcuts inhibitor permission.
/// Returns different ID based on whether running in Flatpak or native.
/// The ID must match the installed .desktop filename, as GNOME Shell's
/// inhibitShortcutsDialog uses `Shell.WindowTracker.get_window_app(window).get_id()`.
fn get_shortcuts_inhibitor_app_id() -> String {
    if is_flatpak() {
        // In Flatpak, FLATPAK_ID is set automatically by the runtime to the app ID
        // (e.g., "com.rustdesk.RustDesk"). This is the most reliable source.
        // Fall back to constructing from app name if not available.
        match std::env::var("FLATPAK_ID") {
            Ok(id) if !id.is_empty() => format!("{}.desktop", id),
            _ => {
                let app_name = crate::get_app_name();
                format!("com.{}.{}.desktop", app_name.to_lowercase(), app_name)
            }
        }
    } else {
        format!("{}.desktop", crate::get_app_name().to_lowercase())
    }
}

const PERMISSION_STORE_DEST: &str = "org.freedesktop.impl.portal.PermissionStore";
const PERMISSION_STORE_PATH: &str = "/org/freedesktop/impl/portal/PermissionStore";
const PERMISSION_STORE_IFACE: &str = "org.freedesktop.impl.portal.PermissionStore";

/// Clear GNOME shortcuts inhibitor permission via D-Bus.
/// This allows the permission dialog to be shown again.
pub fn clear_gnome_shortcuts_inhibitor_permission() -> ResultType<()> {
    let app_id = get_shortcuts_inhibitor_app_id();
    log::info!(
        "Clearing shortcuts inhibitor permission for app_id: {}, is_flatpak: {}",
        app_id,
        is_flatpak()
    );

    let conn = dbus::blocking::Connection::new_session()?;
    let proxy = conn.with_proxy(
        PERMISSION_STORE_DEST,
        PERMISSION_STORE_PATH,
        std::time::Duration::from_secs(3),
    );

    // DeletePermission(s table, s id, s app) -> ()
    let result: Result<(), dbus::Error> = proxy.method_call(
        PERMISSION_STORE_IFACE,
        "DeletePermission",
        ("gnome", "shortcuts-inhibitor", app_id.as_str()),
    );

    match result {
        Ok(()) => {
            log::info!("Successfully cleared GNOME shortcuts inhibitor permission");
            Ok(())
        }
        Err(e) => {
            let err_name = e.name().unwrap_or("");
            // If the permission doesn't exist, that's also fine
            if err_name == "org.freedesktop.portal.Error.NotFound"
                || err_name == "org.freedesktop.DBus.Error.UnknownObject"
                || err_name == "org.freedesktop.DBus.Error.ServiceUnknown"
            {
                log::info!(
                    "GNOME shortcuts inhibitor permission was not set ({})",
                    err_name
                );
                Ok(())
            } else {
                bail!("Failed to clear permission: {}", e)
            }
        }
    }
}

/// Check if GNOME shortcuts inhibitor permission exists.
pub fn has_gnome_shortcuts_inhibitor_permission() -> bool {
    let app_id = get_shortcuts_inhibitor_app_id();

    let conn = match dbus::blocking::Connection::new_session() {
        Ok(c) => c,
        Err(e) => {
            log::debug!("Failed to connect to session bus: {}", e);
            return false;
        }
    };
    let proxy = conn.with_proxy(
        PERMISSION_STORE_DEST,
        PERMISSION_STORE_PATH,
        std::time::Duration::from_secs(3),
    );

    // Lookup(s table, s id) -> (a{sas} permissions, v data)
    // We only need the permissions dict; check if app_id is a key.
    let result: Result<
        (
            std::collections::HashMap<String, Vec<String>>,
            dbus::arg::Variant<Box<dyn dbus::arg::RefArg>>,
        ),
        dbus::Error,
    > = proxy.method_call(
        PERMISSION_STORE_IFACE,
        "Lookup",
        ("gnome", "shortcuts-inhibitor"),
    );

    match result {
        Ok((permissions, _)) => {
            let found = permissions.contains_key(&app_id);
            log::debug!(
                "Shortcuts inhibitor permission lookup: app_id={}, found={}, keys={:?}",
                app_id,
                found,
                permissions.keys().collect::<Vec<_>>()
            );
            found
        }
        Err(e) => {
            log::debug!("Failed to query shortcuts inhibitor permission: {}", e);
            false
        }
    }
}
