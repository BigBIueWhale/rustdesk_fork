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
    users::{get_user_by_name, get_user_by_uid, os::unix::UserExt},
};
use libxdo_sys::{self, xdo_t, Window};
use std::{
    cell::RefCell,
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{Read as _, Write as _},
    os::{
        fd::{AsRawFd as _, FromRawFd as _},
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::{Component, Path, PathBuf},
    process::{Child, Command},
    string::String,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    time::{Duration, Instant},
};
use terminfo::{capability as cap, Database};
use wallpaper;

pub const PA_SAMPLE_RATE: u32 = 48000;
static mut UNMODIFIED: bool = true;

#[derive(Clone, Debug)]
struct ActiveUserLookupCache {
    uid: String,
    username: String,
}

const INVALID_TERM_VALUES: [&str; 3] = ["", "unknown", "dumb"];
const SHELL_PROCESSES: [&str; 4] = ["bash", "zsh", "fish", "sh"];
const SERVICE_CHILD_GRACEFUL_STOP_TIMEOUT: Duration = Duration::from_secs(8);
const SERVICE_CHILD_FORCED_STOP_TIMEOUT: Duration = Duration::from_secs(8);
const SERVICE_CHILD_RECORD_MAX_BYTES: usize = 1024;
const SERVICE_CHILD_RECORD_ROLE: &str = "--server+--service-owned-server";
const SERVICE_RUNTIME_DIR: &[u8] = b"/run/rustdesk\0";
const SERVICE_RUNTIME_LOCK: &[u8] = b"service-supervisor.lock\0";
const SERVICE_CHILD_RECORD: &[u8] = b"service-child.record\0";
const SERVICE_CHILD_RECORD_TMP: &[u8] = b"service-child.record.tmp\0";
const SUDO_PATHS: [&str; 2] = ["/usr/bin/sudo", "/bin/sudo"];
const ENV_PATHS: [&str; 2] = ["/usr/bin/env", "/bin/env"];
const W_PATHS: [&str; 2] = ["/usr/bin/w", "/bin/w"];
const XRANDR_PATHS: [&str; 2] = ["/usr/bin/xrandr", "/bin/xrandr"];
const XDG_SCREENSAVER_PATHS: [&str; 2] = ["/usr/bin/xdg-screensaver", "/bin/xdg-screensaver"];
pub const REOPEN_AFTER_SERVICE_STOP_ARG: &str = "--reopen-after-service-stop";

// Terminal type constants
const TERM_XTERM_256COLOR: &str = "xterm-256color";
const TERM_SCREEN_256COLOR: &str = "screen-256color";
const TERM_XTERM: &str = "xterm";

lazy_static::lazy_static! {
    // R-X12: IS_X11 removed — is_x11() is compile-pinned `true` (no runtime detection cache).
    // Cache for TERM value - once TERM_XTERM_256COLOR is found, reuse it directly
    static ref CACHED_TERM: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
    static ref DATABASE_XTERM_256COLOR: Option<Database> = {
        match Database::from_name(TERM_XTERM_256COLOR) {
            Ok(database) => Some(database),
            Err(err) => {
                log::error!("Failed to initialize {} database: {}", TERM_XTERM_256COLOR, err);
                None
            }
        }
    };
    static ref ACTIVE_USER_LOOKUP_CACHE: std::sync::Mutex<Option<ActiveUserLookupCache>> =
        std::sync::Mutex::new(None);
    // https://github.com/rustdesk/rustdesk/issues/13705
    // Check if `sudo -E` actually preserves environment.
    //
    // This flag is only used by `run_as_user()` (root service -> user session). If the current process is not
    // running as `root`, this check is meaningless (and `sudo -n` may fail), so we return `false` directly.
    //
    // On Ubuntu 25.10, `sudo -E` may still succeed but effectively ignores `-E`. Some versions print a warning
    // to stderr (wording may vary by locale), so we verify behavior instead:
    // - Inject a sentinel environment variable into the `sudo` process
    // - Run `sudo -n -E env` and check whether the sentinel is present in stdout
    static ref SUDO_E_PRESERVES_ENV: bool = {
        if !is_root() {
            log::warn!("Not running as root, SUDO_E_PRESERVES_ENV check skipped");
            false
        } else {
            let key = format!("__RUSTDESK_SUDO_E_TEST_{}", std::process::id());
            let val = "1";
            let expected = format!("{key}={val}");
            match (sudo_path(), env_path()) {
                (Some(sudo), Some(env)) => Command::new(&sudo)
                    // -n for non-interactive to avoid password prompt
                    .env(&key, val)
                    .args(["-n", "-E"])
                    .arg(&env)
                    .output()
                    .map(|o| {
                        o.status.success()
                            && String::from_utf8_lossy(&o.stdout).contains(expected.as_str())
                    })
                    .unwrap_or(false),
                _ => {
                    log::warn!("Trusted sudo/env path not found, SUDO_E_PRESERVES_ENV check skipped");
                    false
                }
            }
        }
    };
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
                        // to-do: how about if it is 0
                        cd.id = (*img).cursor_serial as _;
                        let pixels =
                            std::slice::from_raw_parts((*img).pixels, (cd.width * cd.height) as _);
                        // cd.colors.resize(pixels.len() * 4, 0);
                        let mut cd_colors = vec![0_u8; pixels.len() * 4];
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

/// Suggests the best terminal type based on the environment.
///
/// The function prioritizes terminal types in the following order:
/// 1. `screen-256color`: Preferred when running inside `tmux` or `screen` sessions,
///    as these multiplexers often support advanced terminal features.
/// 2. `xterm-256color`: Selected if the terminal supports 256 colors, which is
///    suitable for modern terminal applications.
/// 3. `xterm`: Used as a fallback for basic terminal compatibility.
///
/// Terminals like `linux` and `vt100` are excluded because they lack support for
/// modern features required by many applications.
fn suggest_best_term() -> String {
    if is_running_in_tmux() || is_running_in_screen() {
        return TERM_SCREEN_256COLOR.to_string();
    }
    if term_supports_256_colors(TERM_XTERM_256COLOR) {
        return TERM_XTERM_256COLOR.to_string();
    }
    TERM_XTERM.to_string()
}

fn is_running_in_tmux() -> bool {
    std::env::var("TMUX").is_ok()
}

fn is_running_in_screen() -> bool {
    std::env::var("STY").is_ok()
}

fn supports_256_colors(db: &Database) -> bool {
    db.get::<cap::MaxColors>().map_or(false, |n| n.0 >= 256)
}

fn term_supports_256_colors(term: &str) -> bool {
    match term {
        TERM_XTERM_256COLOR => DATABASE_XTERM_256COLOR
            .as_ref()
            .map_or(false, |db| supports_256_colors(db)),
        _ => Database::from_name(term).map_or(false, |db| supports_256_colors(&db)),
    }
}

fn get_cur_term(uid: &str) -> Option<String> {
    // Check cache first - if TERM_XTERM_256COLOR was found before, reuse it
    if let Ok(cache) = CACHED_TERM.lock() {
        if let Some(ref cached) = *cache {
            if cached == TERM_XTERM_256COLOR {
                return Some(cached.clone());
            }
        }
    }

    if uid.is_empty() {
        return None;
    }

    // Check current process environment
    if let Ok(term) = std::env::var("TERM") {
        if term == TERM_XTERM_256COLOR {
            if let Ok(mut cache) = CACHED_TERM.lock() {
                *cache = Some(term.clone());
            }
            return Some(term);
        }
    }

    // Collect all TERM values from shell processes, looking for TERM_XTERM_256COLOR
    let terms = get_all_term_values(uid);

    // Prefer TERM_XTERM_256COLOR
    if terms.iter().any(|t| t == TERM_XTERM_256COLOR) {
        if let Ok(mut cache) = CACHED_TERM.lock() {
            *cache = Some(TERM_XTERM_256COLOR.to_string());
        }
        return Some(TERM_XTERM_256COLOR.to_string());
    }

    // Return first valid TERM if no TERM_XTERM_256COLOR found
    let fallback = terms.into_iter().next();
    if let Some(ref term) = fallback {
        log::debug!(
            "TERM_XTERM_256COLOR not found, using fallback TERM: {}",
            term
        );
    }
    fallback
}

/// Get all TERM values from shell processes (bash, zsh, fish, sh).
/// Returns a Vec of unique, valid TERM values.
fn get_all_term_values(uid: &str) -> Vec<String> {
    let Ok(uid_num) = uid.parse::<u32>() else {
        return Vec::new();
    };

    // Build regex pattern to match shell processes using only argv[0] (the executable path)
    // Pattern: match process name at start or after '/', followed by space or end
    // e.g., "bash", "/bin/bash", "/usr/bin/zsh"
    let shell_pattern = SHELL_PROCESSES
        .iter()
        .map(|p| format!(r"(^|/){p}(\s|$)"))
        .collect::<Vec<_>>()
        .join("|");
    let Ok(re) = Regex::new(&shell_pattern) else {
        return Vec::new();
    };

    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };

    let mut terms = Vec::new();

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(pid_str) = file_name.to_str() else {
            continue;
        };
        if !pid_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let proc_path = entry.path();

        // Check if process belongs to the specified uid
        if let Ok(meta) = std::fs::metadata(&proc_path) {
            if meta.uid() != uid_num {
                continue;
            }
        } else {
            continue;
        }

        // Check cmdline matches process pattern
        // /proc/<pid>/cmdline is a sequence of null-terminated strings; the first
        // one (argv[0]) is the executable path. Match the regex only against that
        // to avoid false positives from arguments (e.g., "python /path/to/bash-script.py").
        let cmdline_path = proc_path.join("cmdline");
        let Ok(cmdline) = std::fs::read(&cmdline_path) else {
            continue;
        };
        let exe_end = cmdline
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(cmdline.len());
        let exe_str = String::from_utf8_lossy(&cmdline[..exe_end]);
        if !re.is_match(&exe_str) {
            continue;
        }

        // Read environ and extract TERM
        let environ_path = proc_path.join("environ");
        let Ok(environ) = std::fs::read(&environ_path) else {
            continue;
        };

        for part in environ.split(|&b| b == 0) {
            if part.is_empty() {
                continue;
            }
            if let Some(eq) = part.iter().position(|&b| b == b'=') {
                let key_bytes = &part[..eq];
                if key_bytes == b"TERM" {
                    let val_bytes = &part[eq + 1..];
                    let term = String::from_utf8_lossy(val_bytes).into_owned();
                    if !INVALID_TERM_VALUES.contains(&term.as_str()) && !terms.contains(&term) {
                        // Early return if we found the preferred term
                        if term == TERM_XTERM_256COLOR {
                            return vec![term];
                        }
                        terms.push(term);
                    }
                    break;
                }
            }
        }
    }

    terms
}

struct ServiceChildCredentials {
    uid: hbb_common::libc::uid_t,
    gid: hbb_common::libc::gid_t,
    supplementary_groups: Vec<hbb_common::libc::gid_t>,
    username: String,
    home: PathBuf,
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
//   consumes one bounded root-only record, opens a pidfd where the kernel supports it, and
//   revalidates every recorded field immediately before each signal. `pidfd_send_signal(2)`
//   then binds the signal to that opened process rather than to a recyclable integer PID.
//
// Publication is temp-file fsync -> renameat2(RENAME_NOREPLACE) -> directory fsync. A malformed
// or ambiguous record is preserved and stops service startup; it is never replaced by a new child.
// Linux before pidfd_open(2) gets the same full checks around kill(2), with the irreducible final
// check-to-kill race reported explicitly instead of being presented as equivalent assurance.
#[cfg(debug_assertions)]
const SERVICE_CHILD_FORCE_PRE_PIDFD_FOR_SMOKE_ENV: &str = "RD_SERVICE_SMOKE_FORCE_PRE_PIDFD";

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
            hbb_common::libc::renameat2(
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
            PidFdOpen::Unsupported => self.recover_previous_child_without_pidfd(&record),
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

    fn recover_previous_child_without_pidfd(&self, record: &ServiceChildRecord) -> ResultType<()> {
        match inspect_service_child_identity(record) {
            ServiceChildIdentityState::Match => {}
            ServiceChildIdentityState::Exited | ServiceChildIdentityState::Absent => {
                log::warn!(
                    "Discarding stale Linux service child record for pid {} on a pre-pidfd kernel",
                    record.pid
                );
                return self.remove_record(record);
            }
            ServiceChildIdentityState::Mismatch(reason) => {
                bail!(
                    "Refusing ambiguous pre-pidfd Linux service child recovery for pid {}: {reason}",
                    record.pid
                );
            }
            ServiceChildIdentityState::Unavailable(reason) => {
                bail!(
                    "Refusing unverifiable pre-pidfd Linux service child recovery for pid {}: {reason}",
                    record.pid
                );
            }
        }
        log::warn!(
            "Kernel lacks pidfd_open; recovery revalidates pid {} immediately before each kill(2), but the final identity-check-to-kill race cannot be eliminated on this kernel",
            record.pid
        );

        if send_revalidated_service_child_pid_signal(record, hbb_common::libc::SIGTERM)? {
            return self.remove_record(record);
        }
        if wait_revalidated_service_child_pid_exit(record, SERVICE_CHILD_GRACEFUL_STOP_TIMEOUT)? {
            return self.remove_record(record);
        }

        log::warn!(
            "Prior Linux service child pid {} did not exit after SIGTERM; using revalidated kill(2) SIGKILL fallback",
            record.pid
        );
        if !send_revalidated_service_child_pid_signal(record, hbb_common::libc::SIGKILL)?
            && !wait_revalidated_service_child_pid_exit(record, SERVICE_CHILD_FORCED_STOP_TIMEOUT)?
        {
            bail!(
                "Prior Linux service child pid {} remained live after fallback SIGKILL",
                record.pid
            );
        }
        self.remove_record(record)
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

fn service_child_pidfd_open_is_forced_unsupported_for_smoke() -> bool {
    #[cfg(debug_assertions)]
    {
        std::env::var_os(SERVICE_CHILD_FORCE_PRE_PIDFD_FOR_SMOKE_ENV).as_deref()
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
    if service_child_pidfd_open_is_forced_unsupported_for_smoke() {
        log::warn!(
            "Smoke forced pidfd_open unavailable for service child pid {pid}; exercising pre-pidfd recovery"
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

fn send_revalidated_service_child_pid_signal(
    record: &ServiceChildRecord,
    signal: c_int,
) -> ResultType<bool> {
    require_service_child_identity_match(record, "pre-pidfd kill fallback")?;
    let pid = hbb_common::libc::pid_t::try_from(record.pid)
        .map_err(|_| anyhow!("Service child pid does not fit pid_t"))?;
    if unsafe { hbb_common::libc::kill(pid, signal) } == 0 {
        return Ok(false);
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(hbb_common::libc::ESRCH) {
        return Ok(true);
    }
    Err(anyhow!(
        "Failed to signal revalidated service child pid {pid}: {err}"
    ))
}

fn wait_revalidated_service_child_pid_exit(
    record: &ServiceChildRecord,
    timeout: Duration,
) -> ResultType<bool> {
    let deadline = Instant::now() + timeout;
    loop {
        match inspect_service_child_identity(record) {
            ServiceChildIdentityState::Match if Instant::now() < deadline => sleep_millis(50),
            ServiceChildIdentityState::Match => return Ok(false),
            ServiceChildIdentityState::Exited | ServiceChildIdentityState::Absent => {
                return Ok(true);
            }
            ServiceChildIdentityState::Mismatch(reason) => bail!(
                "Service child pid {} changed identity while awaiting exit: {reason}; signaling nothing further",
                record.pid
            ),
            ServiceChildIdentityState::Unavailable(reason) => bail!(
                "Service child pid {} became unverifiable while awaiting exit: {reason}; signaling nothing further",
                record.pid
            ),
        }
    }
}

fn syscall_succeeded(result: hbb_common::libc::c_long) -> std::io::Result<()> {
    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn arm_service_child_parent_death(expected_parent: hbb_common::libc::pid_t) -> std::io::Result<()> {
    // `PR_SET_PDEATHSIG` is cleared by a credential change and can also be cleared by
    // executing a privileged file. Arm it after the optional uid/gid drop in the pre-exec
    // hook, and arm it again in the final RustDesk image before server startup. Setting it
    // before checking getppid closes the parent-exit race: an earlier exit changes the
    // observed parent, while a later exit delivers SIGKILL to this exact child.
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

fn configure_service_child_pre_exec(
    command: &mut Command,
    expected_parent: hbb_common::libc::pid_t,
    credentials: Option<ServiceChildCredentials>,
    executable_fd: Option<c_int>,
) {
    // The closure performs only raw Linux syscalls and reads already-owned memory. It does
    // not allocate, lock, inspect the environment, or call NSS after fork. The parent
    // resolves the complete credential set before registering this hook.
    unsafe {
        command.pre_exec(move || {
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
                syscall_succeeded(hbb_common::libc::syscall(
                    hbb_common::libc::SYS_fcntl,
                    executable_fd,
                    hbb_common::libc::F_SETFD,
                    0,
                ))?;
            }
            syscall_succeeded(hbb_common::libc::syscall(
                hbb_common::libc::SYS_prctl,
                hbb_common::libc::PR_SET_NO_NEW_PRIVS,
                1,
                0,
                0,
                0,
            ))?;
            arm_service_child_parent_death(expected_parent)
        });
    }
}

fn insert_nonempty_env(command: &mut Command, key: &str, value: &str) {
    if !value.is_empty() {
        command.env(key, value);
    }
}

fn try_start_server_(
    desktop: Option<&Desktop>,
    runtime: &ServiceRuntime,
) -> ResultType<OwnedServiceChild> {
    let parent_pid = hbb_common::libc::pid_t::try_from(std::process::id())
        .map_err(|_| anyhow!("Service supervisor pid does not fit pid_t"))?;
    let credentials = match desktop {
        Some(desktop) => Some(ServiceChildCredentials::resolve(
            &desktop.uid,
            &desktop.username,
        )?),
        None => None,
    };
    let expected_child_uid = credentials
        .as_ref()
        .map(|credentials| credentials.uid as u32)
        .unwrap_or_else(|| unsafe { hbb_common::libc::geteuid() as u32 });

    // A credential-changing pre_exec hook makes /proc/self/exe inaccessible before Command
    // performs execve: procfs guards that symlink with a ptrace credential check and the UID
    // transition resets dumpability. Open the exact executable object while still privileged
    // and let the post-drop child execute its own inherited descriptor instead. Keep FD_CLOEXEC
    // set in the multithreaded supervisor, clear it only inside the forked child, and require the
    // final image to close that one descriptor immediately. The root path can retain
    // /proc/self/exe directly. Both forms remain bound to the supervisor's executable object
    // across concurrent package replacement, with no sudo/env wrapper.
    let child_executable = if credentials.is_some() {
        let executable = fs::OpenOptions::new()
            .read(true)
            .custom_flags(hbb_common::libc::O_CLOEXEC)
            .open("/proc/self/exe")
            .map_err(|err| anyhow!("Failed to open the service executable object: {err}"))?;
        Some(executable)
    } else {
        None
    };
    let executable_path = child_executable
        .as_ref()
        .map(|executable| format!("/proc/self/fd/{}", executable.as_raw_fd()))
        .unwrap_or_else(|| "/proc/self/exe".to_owned());
    let mut command = Command::new(executable_path);
    command
        .arg("--server")
        .arg(crate::common::SERVICE_OWNED_SERVER_ARG)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env(
            crate::common::SERVICE_OWNED_SERVER_LAUNCH_PARENT_ENV,
            parent_pid.to_string(),
        )
        .env(
            crate::common::SERVICE_OWNED_SERVER_GENERATION_ENV,
            &runtime.generation,
        );
    if let Some(executable) = child_executable.as_ref() {
        command.env(
            crate::common::SERVICE_OWNED_SERVER_EXECUTABLE_FD_ENV,
            executable.as_raw_fd().to_string(),
        );
    }

    match (&credentials, desktop) {
        (Some(credentials), Some(desktop)) => {
            command
                .env("HOME", &credentials.home)
                .env("USER", &credentials.username)
                .env("LOGNAME", &credentials.username)
                .env("XDG_RUNTIME_DIR", format!("/run/user/{}", credentials.uid));
            insert_nonempty_env(&mut command, "DISPLAY", &desktop.display);
            insert_nonempty_env(&mut command, "XAUTHORITY", &desktop.xauth);
            insert_nonempty_env(&mut command, "WAYLAND_DISPLAY", &desktop.wl_display);
            insert_nonempty_env(&mut command, "DBUS_SESSION_BUS_ADDRESS", &desktop.dbus);
            command.env(
                "TERM",
                get_cur_term(&desktop.uid).unwrap_or_else(|| suggest_best_term()),
            );
        }
        (None, None) => {
            for key in [
                "DISPLAY",
                "XAUTHORITY",
                "WAYLAND_DISPLAY",
                "HOME",
                "DBUS_SESSION_BUS_ADDRESS",
                "TERM",
                "PULSE_LATENCY_MSEC",
                "PIPEWIRE_LATENCY",
            ] {
                if let Some(value) = std::env::var_os(key) {
                    command.env(key, value);
                }
            }
        }
        _ => bail!("Inconsistent service child desktop credential state"),
    }

    let executable_fd = child_executable
        .as_ref()
        .map(|executable| executable.as_raw_fd());
    configure_service_child_pre_exec(&mut command, parent_pid, credentials, executable_fd);
    let spawn_result = command.spawn();
    drop(child_executable);
    let mut process = spawn_result?;
    let pid = process.id();
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
    arm_service_child_parent_death(expected_parent)?;
    Ok(())
}

#[inline]
fn start_server(
    desktop: Option<&Desktop>,
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

fn set_x11_env(desktop: &Desktop) {
    log::info!("DISPLAY: {}", desktop.display);
    log::info!("XAUTHORITY: {}", desktop.xauth);
    if !desktop.display.is_empty() {
        std::env::set_var("DISPLAY", &desktop.display);
    }
    if !desktop.xauth.is_empty() {
        std::env::set_var("XAUTHORITY", &desktop.xauth);
    }
}

#[inline]
fn stop_subprocess() {
    let xorg_config = format!("/etc/{}/xorg.conf", crate::get_app_name().to_lowercase());
    kill_xorg_processes_with_config(&xorg_config);
    kill_current_exe_processes_with_arg("--cm-no-ui", "--cm-no-ui");
}

fn should_start_server(
    try_x11: bool,
    is_display_changed: bool,
    uid: &mut String,
    desktop: &Desktop,
    cm0: &mut bool,
    last_restart: &mut Instant,
    server: &mut Option<OwnedServiceChild>,
    runtime: &ServiceRuntime,
) -> ResultType<bool> {
    let cm = get_cm();
    let mut start_new = false;
    let mut should_kill = false;

    if desktop.is_headless() {
        if !uid.is_empty() {
            // From having a monitor to not having a monitor.
            *uid = "".to_owned();
            should_kill = true;
        }
    } else if is_display_changed || desktop.uid != *uid && !desktop.uid.is_empty() {
        *uid = desktop.uid.clone();
        if try_x11 {
            set_x11_env(&desktop);
        }
        should_kill = true;
    }

    if !should_kill
        && !cm
        && ((*cm0 && last_restart.elapsed().as_secs() > 60)
            || last_restart.elapsed().as_secs() > 3600)
    {
        let terminal_session_count = crate::ipc::get_terminal_session_count().unwrap_or(0);
        if terminal_session_count > 0 {
            // There are terminal sessions, so we don't restart the server.
            // We also need to keep `cm0` unchanged, so that we can reach this branch the next time.
            return Ok(false);
        }
        // restart server if new connections all closed, or every one hour,
        // as a workaround to resolve "SpotUdp" (dns resolve)
        // and x server get displays failure issue
        should_kill = true;
        log::info!("restart server");
    }

    if should_kill {
        if server.is_some() {
            terminate_child(server, "--server", runtime)?;
            *last_restart = Instant::now();
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
    *cm0 = cm;
    Ok(start_new)
}

pub fn start_os_service() -> ResultType<()> {
    let running = Arc::new(AtomicBool::new(true));
    let signal_running = running.clone();
    ctrlc::set_handler(move || {
        signal_running.store(false, Ordering::SeqCst);
    })
    .map_err(|err| anyhow!("Failed to install Linux service shutdown handlers: {err}"))?;

    let runtime = ServiceRuntime::acquire()?;
    runtime.recover_previous_child()?;
    stop_subprocess();
    // R-X13: the dormant uinput IPC listener is NOT stood up — on the pinned-X11
    // fork XTEST/enigo is the sole injection backend, so the world-mode _uinput_*
    // cross-uid sockets the X11 --server never connects to are absent (shrinking
    // the R-S11a cross-uid socket surface to _service alone).

    std::thread::spawn(|| {
        allow_err!(crate::ipc::start(crate::POSTFIX_SERVICE));
    });

    let (mut display, mut xauth): (String, String) = ("".to_owned(), "".to_owned());
    let mut desktop = Desktop::default();
    let mut sid = "".to_owned();
    let mut uid = "".to_owned();
    let mut server: Option<OwnedServiceChild> = None;
    let mut user_server: Option<OwnedServiceChild> = None;
    let mut cm0 = false;
    let mut last_restart = Instant::now();
    while running.load(Ordering::SeqCst) {
        desktop.refresh();
        update_active_user_lookup_cache(&desktop);

        // Duplicate logic here with should_start_server
        // Login wayland will try to start a headless --server.
        if desktop.username == "root" || desktop.is_login_wayland() {
            // try kill subprocess "--server"
            stop_server(&mut user_server, &runtime)?;
            // try start subprocess "--server"
            // No need to check is_display_changed here.
            if should_start_server(
                true,
                false,
                &mut uid,
                &desktop,
                &mut cm0,
                &mut last_restart,
                &mut server,
                &runtime,
            )? {
                stop_subprocess();
                start_server(None, &mut server, &runtime);
            }
        } else if desktop.username != "" {
            // try kill subprocess "--server"
            stop_server(&mut server, &runtime)?;

            let is_display_changed = desktop.display != display || desktop.xauth != xauth;
            display = desktop.display.clone();
            xauth = desktop.xauth.clone();

            // try start subprocess "--server"
            if should_start_server(
                !desktop.is_wayland(),
                is_display_changed,
                &mut uid,
                &desktop,
                &mut cm0,
                &mut last_restart,
                &mut user_server,
                &runtime,
            )? {
                stop_subprocess();
                start_server(Some(&desktop), &mut user_server, &runtime);
            }
        } else {
            stop_server(&mut user_server, &runtime)?;
            stop_server(&mut server, &runtime)?;
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

    terminate_child(&mut user_server, "--server", &runtime)?;
    terminate_child(&mut server, "--server", &runtime)?;
    log::info!("Exit");
    Ok(())
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
/// Returns the active uid from a fresh seat0 lookup, bypassing the service-loop cache.
pub fn get_active_userid_fresh() -> String {
    get_values_of_seat0(&[1])[0].clone()
}

fn get_cm() -> bool {
    current_exe_process_cmdlines()
        .iter()
        .any(|process| process_has_exact_arg(&process.args, "--cm"))
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

pub fn is_root() -> bool {
    crate::username() == "root"
}

fn is_valid_sudo_env_key(key: &OsStr) -> bool {
    let Some(key) = key.to_str() else {
        return false;
    };
    let mut it = key.chars();
    match it.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    it.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn valid_sudo_envs<I, K, V>(envs: I) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    let mut valid = Vec::new();
    for (k, v) in envs {
        let key = k.as_ref();
        if !is_valid_sudo_env_key(key) {
            log::warn!(
                "Skipping environment variable with invalid key: '{}'. Only [A-Za-z_][A-Za-z0-9_]* are allowed in sudo context.",
                key.to_string_lossy()
            );
            continue;
        }
        valid.push((key.to_os_string(), v.as_ref().to_os_string()));
    }
    valid
}

pub fn run_as_user<I, K, V>(
    arg: Vec<&str>,
    user: Option<(String, String)>,
    envs: I,
) -> ResultType<Option<Child>>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    let (uid, username) = match user {
        Some(id_name) => id_name,
        None => get_active_user_id_name(),
    };
    let cmd = std::env::current_exe()?;
    if uid.is_empty() {
        bail!("No valid uid");
    }

    let Some(sudo_path) = sudo_path() else {
        bail!("sudo was not found at a trusted fixed path");
    };
    let valid_envs = valid_sudo_envs(envs);
    let xdg_runtime_dir = format!("/run/user/{uid}");
    if *SUDO_E_PRESERVES_ENV {
        let task = Command::new(&sudo_path)
            .env("XDG_RUNTIME_DIR", &xdg_runtime_dir)
            .envs(
                valid_envs
                    .iter()
                    .map(|(k, v)| (k.as_os_str(), v.as_os_str())),
            )
            .arg("-E")
            .arg("-u")
            .arg(&username)
            .arg("--")
            .arg(&cmd)
            .args(arg)
            .spawn()?;
        Ok(Some(task))
    } else {
        let Some(env_path) = env_path() else {
            bail!("env was not found at a trusted fixed path");
        };
        let mut sudo = Command::new(&sudo_path);
        sudo.arg("-u")
            .arg(&username)
            .arg("--")
            .arg(&env_path)
            .arg(format!("XDG_RUNTIME_DIR={xdg_runtime_dir}"));

        for (k, v) in valid_envs {
            let mut assignment = k;
            assignment.push("=");
            assignment.push(v);
            sudo.arg(assignment);
        }

        sudo.arg(&cmd).args(arg);
        let task = sudo.spawn()?;
        Ok(Some(task))
    }
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

pub fn lock_screen() {
    let Some(xdg_screensaver) = xdg_screensaver_path() else {
        log::warn!("xdg-screensaver was not found at a trusted fixed path");
        return;
    };
    Command::new(xdg_screensaver).arg("lock").spawn().ok();
}

pub fn toggle_blank_screen(_v: bool) {
    // https://unix.stackexchange.com/questions/17170/disable-keyboard-mouse-input-on-unix-under-x
}

pub fn block_input(_v: bool) -> (bool, String) {
    (true, "".to_owned())
}

pub fn is_installed() -> bool {
    if let Ok(p) = std::env::current_exe() {
        p.to_str().unwrap_or_default().starts_with("/usr")
            || p.to_str().unwrap_or_default().starts_with("/nix/store")
    } else {
        false
    }
}

/// Get multiple environment variables from a process matching the given criteria.
/// This version reads /proc directly instead of spawning shell commands.
///
/// # Arguments
/// * `uid` - User ID to filter processes
/// * `process_pat` - Regex pattern to match process cmdline
/// * `names` - Environment variable names to retrieve. **Must be <= 64 elements** due to
///   the internal bitmask used for tie-breaking.
///
/// # Panics (debug builds)
/// Panics if `names.len() > 64`.
///
/// # Implementation notes
/// - Returns values from a *single* best-matching process_pat (for consistency).
/// - Avoids repeated scanning by parsing `environ` once per process.
#[derive(Debug)]
struct ProcCommand {
    pid: u32,
    args: Vec<String>,
}

fn proc_dir_is_owned_by_uid(proc_path: &Path, uid: u32) -> bool {
    std::fs::metadata(proc_path)
        .map(|meta| meta.uid() == uid)
        .unwrap_or(false)
}

fn proc_entry_pid(entry: &std::fs::DirEntry) -> Option<u32> {
    let file_name = entry.file_name();
    let pid_str = file_name.to_str()?;
    if !pid_str.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    pid_str.parse::<u32>().ok()
}

fn read_proc_cmdline_args(proc_path: &Path) -> Option<Vec<String>> {
    let cmdline = std::fs::read(proc_path.join("cmdline")).ok()?;
    let args = cmdline
        .split(|&b| b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect::<Vec<_>>();
    if args.is_empty() {
        None
    } else {
        Some(args)
    }
}

fn proc_cmdline_string(args: &[String]) -> String {
    args.join(" ")
}

fn all_process_cmdlines() -> Vec<ProcCommand> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };

    let mut processes = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = proc_entry_pid(&entry) else {
            continue;
        };
        let Some(args) = read_proc_cmdline_args(&entry.path()) else {
            continue;
        };
        processes.push(ProcCommand { pid, args });
    }

    processes.sort_by_key(|process| process.pid);
    processes
}

fn current_executable_path() -> Option<PathBuf> {
    std::env::current_exe().ok()
}

fn proc_exe_matches_path(proc_path: &Path, expected: &Path) -> bool {
    std::fs::read_link(proc_path.join("exe"))
        .map(|path| path == expected)
        .unwrap_or(false)
}

fn current_exe_process_cmdlines() -> Vec<ProcCommand> {
    let Some(current_exe) = current_executable_path() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };

    let mut processes = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = proc_entry_pid(&entry) else {
            continue;
        };
        let proc_path = entry.path();
        if !proc_exe_matches_path(&proc_path, &current_exe) {
            continue;
        }
        let Some(args) = read_proc_cmdline_args(&proc_path) else {
            continue;
        };
        processes.push(ProcCommand { pid, args });
    }

    processes.sort_by_key(|process| process.pid);
    processes
}

fn matching_process_cmdlines(uid: &str, process_pat: &str) -> Vec<ProcCommand> {
    let Ok(uid_num) = uid.parse::<u32>() else {
        return Vec::new();
    };
    let Ok(re) = Regex::new(process_pat) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };

    let mut processes = Vec::new();
    for entry in entries.flatten() {
        let Some(pid) = proc_entry_pid(&entry) else {
            continue;
        };
        let proc_path = entry.path();
        if !proc_dir_is_owned_by_uid(&proc_path, uid_num) {
            continue;
        }
        let Some(args) = read_proc_cmdline_args(&proc_path) else {
            continue;
        };
        if re.is_match(&proc_cmdline_string(&args)) {
            processes.push(ProcCommand { pid, args });
        }
    }

    processes.sort_by_key(|process| process.pid);
    processes
}

fn process_has_exact_arg(args: &[String], expected: &str) -> bool {
    args.iter().any(|arg| arg == expected)
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

fn process_basename_eq_ignore_ascii_case(args: &[String], expected: &str) -> bool {
    process_basename(args)
        .map(|name| name.eq_ignore_ascii_case(expected))
        .unwrap_or(false)
}

fn process_is_xorg_with_config(args: &[String], xorg_config: &str) -> bool {
    process_basename_eq_ignore_ascii_case(args, "Xorg") && process_has_exact_arg(args, xorg_config)
}

fn process_is_xwayland(args: &[String]) -> bool {
    process_basename_eq(args, "Xwayland")
}

fn is_ascii_digit_string(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| c.is_ascii_digit())
}

fn is_local_x_display_arg(arg: &str) -> bool {
    let Some(rest) = arg.strip_prefix(':') else {
        return false;
    };
    let mut parts = rest.split('.');
    let Some(display) = parts.next() else {
        return false;
    };
    if !is_ascii_digit_string(display) {
        return false;
    }
    match (parts.next(), parts.next()) {
        (None, None) => true,
        (Some(screen), None) => is_ascii_digit_string(screen),
        _ => false,
    }
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
    for process in all_process_cmdlines() {
        if let Some(display) = xwayland_display_arg(&process.args) {
            return Some(display.to_owned());
        }
    }
    None
}

fn x11_socket_display_name(name: &OsStr) -> Option<(u32, String)> {
    let name = name.to_str()?;
    let display = name.strip_prefix('X')?;
    if !is_ascii_digit_string(display) {
        return None;
    }
    let display_num = display.parse::<u32>().ok()?;
    Some((display_num, format!(":{display}")))
}

fn x11_socket_owner_matches_user(path: &Path, user: &str) -> Option<bool> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_socket() {
        return None;
    }
    let owner = get_user_by_uid(metadata.uid())?;
    Some(owner.name() == OsStr::new(user))
}

fn display_from_x11_socket_dir_for_user(user: &str, dir: &Path) -> String {
    let Ok(entries) = fs::read_dir(dir) else {
        return String::new();
    };
    let mut displays = Vec::new();
    for entry in entries.flatten() {
        let Some((display_num, display)) = x11_socket_display_name(&entry.file_name()) else {
            continue;
        };
        let Some(owner_matches) = x11_socket_owner_matches_user(&entry.path(), user) else {
            continue;
        };
        displays.push((display_num, display, owner_matches));
    }
    displays.sort_by_key(|(display_num, _, _)| *display_num);

    let mut last = String::new();
    for (_, display, owner_matches) in displays {
        if owner_matches {
            return display;
        }
        last = display;
    }
    last
}

fn signal_process(pid: u32, label: &str, signal: i32) {
    if pid == 0 || pid == std::process::id() {
        return;
    }
    let rc = unsafe {
        hbb_common::libc::kill(pid as hbb_common::libc::pid_t, signal)
    };
    if rc == 0 {
        return;
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() != Some(hbb_common::libc::ESRCH) {
        log::warn!("Failed to signal {label} process pid={pid} signal={signal}: {err}");
    }
}

fn kill_process(pid: u32, label: &str) {
    signal_process(pid, label, hbb_common::libc::SIGKILL);
}

fn kill_current_exe_processes_with_arg(arg: &str, label: &str) {
    for process in current_exe_process_cmdlines() {
        if process_has_exact_arg(&process.args, arg) {
            kill_process(process.pid, label);
        }
    }
}

fn signal_current_exe_processes_with_arg(arg: &str, label: &str, signal: i32) {
    for process in current_exe_process_cmdlines() {
        if process_has_exact_arg(&process.args, arg) {
            signal_process(process.pid, label, signal);
        }
    }
}

pub fn stop_tray_processes() {
    signal_current_exe_processes_with_arg(
        "--tray",
        "--tray",
        hbb_common::libc::SIGTERM,
    );
}

fn kill_xorg_processes_with_config(xorg_config: &str) {
    for process in all_process_cmdlines() {
        if process_is_xorg_with_config(&process.args, xorg_config) {
            kill_process(process.pid, "Xorg");
        }
    }
}

fn any_process_cmdline_contains(needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let Some(_) = proc_entry_pid(&entry) else {
            continue;
        };
        let Some(args) = read_proc_cmdline_args(&entry.path()) else {
            continue;
        };
        if proc_cmdline_string(&args).contains(needle) {
            return true;
        }
    }
    false
}

fn proc_env_name_is_valid(name: &str) -> bool {
    !name.is_empty() && !name.as_bytes().contains(&b'=') && !name.as_bytes().contains(&0)
}

fn proc_environ_value(environ: &[u8], name: &str) -> Option<String> {
    if !proc_env_name_is_valid(name) {
        return None;
    }
    let name = name.as_bytes();
    for part in environ.split(|&b| b == 0) {
        if part.len() <= name.len() || !part.starts_with(name) || part[name.len()] != b'=' {
            continue;
        }
        return Some(String::from_utf8_lossy(&part[name.len() + 1..]).into_owned());
    }
    None
}

fn read_proc_environ_value(pid: u32, name: &str) -> Option<String> {
    let environ = std::fs::read(PathBuf::from(format!("/proc/{pid}/environ"))).ok()?;
    proc_environ_value(&environ, name)
}

fn get_envs<'a>(
    uid: &str,
    process_pat: &str,
    names: &[&'a str],
) -> std::collections::HashMap<&'a str, String> {
    // The tie-breaking logic uses a u64 bitmask, limiting us to 64 variables.
    debug_assert!(
        names.len() <= 64,
        "get_envs: names.len() must be <= 64, got {}",
        names.len()
    );

    let empty: std::collections::HashMap<&'a str, String> =
        names.iter().map(|&n| (n, String::new())).collect();

    if names.iter().any(|name| !proc_env_name_is_valid(name)) {
        return empty;
    }

    // Used for stable tie-breaking when multiple processes match.
    // Higher bits correspond to earlier entries in `names`.
    let name_indices: std::collections::HashMap<&'a str, usize> =
        names.iter().enumerate().map(|(i, &n)| (n, i)).collect();

    let mut best = empty.clone();
    let mut best_count = 0usize;
    let mut best_mask: u64 = 0;
    let mut best_pid: u32 = 0;

    for process in matching_process_cmdlines(uid, process_pat) {
        let Ok(environ) = std::fs::read(PathBuf::from(format!("/proc/{}/environ", process.pid)))
        else {
            continue;
        };

        let mut found = empty.clone();
        let mut found_count = 0usize;
        let mut found_mask: u64 = 0;

        for part in environ.split(|&b| b == 0) {
            if part.is_empty() {
                continue;
            }
            let Some(eq) = part.iter().position(|&b| b == b'=') else {
                continue;
            };
            let key_bytes = &part[..eq];
            let val_bytes = &part[eq + 1..];

            let Ok(key) = std::str::from_utf8(key_bytes) else {
                continue;
            };
            if let Some(slot) = found.get_mut(key) {
                if slot.is_empty() {
                    *slot = String::from_utf8_lossy(val_bytes).into_owned();
                    found_count += 1;

                    if let Some(&idx) = name_indices.get(key) {
                        let total = names.len();
                        if total <= 64 {
                            let bit = 1u64 << (total - 1 - idx);
                            found_mask |= bit;
                        }
                    }
                }
            }
        }

        if found_count > best_count
            || (found_count == best_count && found_mask > best_mask)
            || (found_count == best_count && found_mask == best_mask && process.pid > best_pid)
        {
            best = found;
            best_count = found_count;
            best_mask = found_mask;
            best_pid = process.pid;
        }
    }

    best
}

#[inline]
fn get_env(name: &str, uid: &str, process: &str) -> String {
    get_envs(uid, process, &[name])
        .remove(name)
        .unwrap_or_default()
}

#[inline]
fn get_env_from_pid(name: &str, pid: &str) -> String {
    pid.parse::<u32>()
        .ok()
        .and_then(|pid| read_proc_environ_value(pid, name))
        .unwrap_or_default()
}

#[link(name = "gtk-3")]
extern "C" {
    fn gtk_main_quit();
}

#[cfg(test)]
mod process_cleanup_tests {
    use super::*;

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
            configure_service_child_pre_exec(&mut command, parent_pid, None, None);
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
                arm_service_child_parent_death(expected_parent).unwrap();
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
    fn r_s11c10_process_kill_matchers_are_exact_argv_based() {
        let server = vec!["/usr/bin/rustdesk".to_owned(), "--server".to_owned()];
        assert!(process_has_exact_arg(&server, "--server"));
        assert!(!process_has_exact_arg(&server, "--serverless"));

        let tray = vec!["/usr/bin/rustdesk".to_owned(), "--tray".to_owned()];
        assert!(process_has_exact_arg(&tray, "--tray"));
        assert!(!process_has_exact_arg(&tray, "rustdesk --tray"));
        assert!(!process_has_exact_arg(&tray, "--tray-extra"));

        let current_processes = current_exe_process_cmdlines();
        assert!(current_processes
            .iter()
            .any(|process| process.pid == std::process::id()));

        let xorg_config = "/etc/rustdesk/xorg.conf";
        let xorg = vec![
            "/usr/lib/xorg/Xorg".to_owned(),
            "-config".to_owned(),
            xorg_config.to_owned(),
        ];
        assert!(process_is_xorg_with_config(&xorg, xorg_config));

        let other_process = vec!["/bin/grep".to_owned(), xorg_config.to_owned()];
        assert!(!process_is_xorg_with_config(&other_process, xorg_config));

        let partial = vec![
            "/usr/lib/xorg/Xorg".to_owned(),
            format!("{xorg_config}.old"),
        ];
        assert!(!process_is_xorg_with_config(&partial, xorg_config));
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
    fn r_s11c10_x11_socket_display_discovery_reads_metadata() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = PathBuf::from(format!(
            "/tmp/rd-x11-{}-{}",
            std::process::id(),
            nonce
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let socket_path = root.join("X7");
        let _listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        fs::write(root.join("X9"), "not a socket").unwrap();
        fs::write(root.join("not-x"), "ignored").unwrap();

        let uid = unsafe { hbb_common::libc::geteuid() };
        let username = get_user_by_uid(uid)
            .unwrap()
            .name()
            .to_string_lossy()
            .into_owned();
        assert_eq!(display_from_x11_socket_dir_for_user(&username, &root), ":7");
        assert_eq!(
            display_from_x11_socket_dir_for_user("__missing__", &root),
            ":7"
        );

        fs::remove_dir_all(root).unwrap();
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
    let output = Command::new(xrandr).arg("--query").output()?;
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
    Command::new(xrandr)
        .args(vec![
            "--output",
            name,
            "--mode",
            &format!("{}x{}", width, height),
        ])
        .spawn()?;
    Ok(())
}

#[inline]
pub fn is_xwayland_running() -> bool {
    all_process_cmdlines()
        .iter()
        .any(|process| process_is_xwayland(&process.args))
}

mod desktop {
    use super::*;

    pub const XFCE4_PANEL: &str = "xfce4-panel";
    pub const SDDM_GREETER: &str = "sddm-greeter";

    // xdg-desktop-portal runs on all Wayland desktops (GNOME, KDE, wlroots, etc.)
    const XDG_DESKTOP_PORTAL: &str = "xdg-desktop-portal";
    const XWAYLAND: &str = "Xwayland";
    const IBUS_DAEMON: &str = "ibus-daemon";
    const PLASMA_KDED: &str = "kded[0-9]+";
    const GNOME_GOA_DAEMON: &str = "goa-daemon";

    const ENV_KEY_DISPLAY: &str = "DISPLAY";
    const ENV_KEY_XAUTHORITY: &str = "XAUTHORITY";
    const ENV_KEY_WAYLAND_DISPLAY: &str = "WAYLAND_DISPLAY";
    const ENV_KEY_DBUS_SESSION_BUS_ADDRESS: &str = "DBUS_SESSION_BUS_ADDRESS";

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
        pub is_rustdesk_subprocess: bool,
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
            self.sid.is_empty() || self.is_rustdesk_subprocess
        }

        fn get_display_xauth_wayland(&mut self) {
            for _ in 1..=10 {
                // Prefer Wayland-related variables first when multiple portal processes match.
                let mut envs = get_envs(
                    &self.uid,
                    XDG_DESKTOP_PORTAL,
                    &[
                        ENV_KEY_WAYLAND_DISPLAY,
                        ENV_KEY_DBUS_SESSION_BUS_ADDRESS,
                        ENV_KEY_DISPLAY,
                        ENV_KEY_XAUTHORITY,
                    ],
                );
                self.display = envs.remove(ENV_KEY_DISPLAY).unwrap_or_default();
                self.xauth = envs.remove(ENV_KEY_XAUTHORITY).unwrap_or_default();
                self.wl_display = envs.remove(ENV_KEY_WAYLAND_DISPLAY).unwrap_or_default();
                self.dbus = envs
                    .remove(ENV_KEY_DBUS_SESSION_BUS_ADDRESS)
                    .unwrap_or_default();
                // For pure Wayland sessions, prefer `WAYLAND_DISPLAY`.
                // NOTE: On some systems (e.g. Ubuntu 25.10), `DISPLAY`/`XAUTHORITY` may exist even when XWayland
                // is not running, so do NOT treat them as a success condition here.
                let has_wayland = !self.wl_display.is_empty();
                let has_dbus = !self.dbus.is_empty();
                if has_wayland && has_dbus {
                    return;
                }
                sleep_millis(300);
            }
        }

        fn get_display_xauth_xwayland(&mut self) {
            let tray = format!("{} +--tray", crate::get_app_name().to_lowercase());
            for _ in 1..=10 {
                let display_proc = vec![
                    XDG_DESKTOP_PORTAL,
                    XWAYLAND,
                    IBUS_DAEMON,
                    GNOME_GOA_DAEMON,
                    PLASMA_KDED,
                    tray.as_str(),
                ];
                for proc in display_proc {
                    self.display = get_env(ENV_KEY_DISPLAY, &self.uid, proc);
                    self.xauth = get_env(ENV_KEY_XAUTHORITY, &self.uid, proc);
                    self.wl_display = get_env(ENV_KEY_WAYLAND_DISPLAY, &self.uid, proc);
                    self.dbus = get_env(ENV_KEY_DBUS_SESSION_BUS_ADDRESS, &self.uid, proc);
                    if !self.display.is_empty() && !self.xauth.is_empty() {
                        return;
                    }
                }
                sleep_millis(300);
            }
        }

        fn get_display_x11(&mut self) {
            for _ in 1..=10 {
                let display_proc = vec![
                    XWAYLAND,
                    IBUS_DAEMON,
                    GNOME_GOA_DAEMON,
                    PLASMA_KDED,
                    XFCE4_PANEL,
                    SDDM_GREETER,
                ];
                for proc in display_proc {
                    self.display = get_env(ENV_KEY_DISPLAY, &self.uid, proc);
                    if !self.display.is_empty() {
                        break;
                    }
                }
                if !self.display.is_empty() {
                    break;
                }
                sleep_millis(300);
            }

            if self.display.is_empty() {
                self.display = Self::get_display_by_user(&self.username);
            }
            if self.display.is_empty() {
                self.display = ":0".to_owned();
            }
            self.display = self
                .display
                .replace(&hbb_common::whoami::hostname(), "")
                .replace("localhost", "");
        }

        fn get_home(&mut self) {
            self.home = get_user_home_by_name(&self.username)
                .map(|home| home.to_string_lossy().to_string())
                .unwrap_or_else(|| format!("/home/{}", &self.username));
        }

        fn get_xauth_from_xorg(&mut self) {
            for process in matching_process_cmdlines(&self.uid, "Xorg") {
                let mut args = process.args.iter();
                while let Some(arg) = args.next() {
                    if arg != "-auth" {
                        continue;
                    }
                    let Some(auth) = args.next() else {
                        continue;
                    };
                    let auth_path = Path::new(auth);
                    if auth_path.is_absolute() {
                        if auth_path.exists() {
                            self.xauth = auth.to_string();
                        }
                        return;
                    }
                    let home_dir = get_env_from_pid("HOME", &process.pid.to_string());
                    let base_dir = if home_dir.is_empty() {
                        get_user_home_by_name(&self.username)
                            .map(|home| home.to_string_lossy().to_string())
                            .unwrap_or_else(|| "/home".to_string())
                    } else {
                        home_dir
                    };
                    if Path::new(&base_dir).exists() {
                        self.xauth = Path::new(&base_dir)
                            .join(auth)
                            .to_string_lossy()
                            .to_string();
                    }
                    return;
                }
            }
        }

        fn get_xauth_x11(&mut self) {
            // try by direct access to window manager process by name
            let tray = format!("{} +--tray", crate::get_app_name().to_lowercase());
            for _ in 1..=10 {
                let display_proc = vec![
                    XWAYLAND,
                    IBUS_DAEMON,
                    GNOME_GOA_DAEMON,
                    PLASMA_KDED,
                    XFCE4_PANEL,
                    SDDM_GREETER,
                    tray.as_str(),
                ];
                for proc in display_proc {
                    self.xauth = get_env("XAUTHORITY", &self.uid, proc);
                    if !self.xauth.is_empty() {
                        break;
                    }
                }
                if !self.xauth.is_empty() {
                    break;
                }
                sleep_millis(300);
            }

            // get from Xorg process, parameter and environment
            if self.xauth.is_empty() {
                self.get_xauth_from_xorg();
            }

            // fallback to default file name
            if self.xauth.is_empty() {
                let gdm = format!("/run/user/{}/gdm/Xauthority", self.uid);
                self.xauth = if std::path::Path::new(&gdm).exists() {
                    gdm
                } else {
                    let username = &self.username;
                    match get_user_home_by_name(username) {
                        None => {
                            if username == "root" {
                                format!("/{}/.Xauthority", username)
                            } else {
                                let tmp = format!("/home/{}/.Xauthority", username);
                                if std::path::Path::new(&tmp).exists() {
                                    tmp
                                } else {
                                    format!("/var/lib/{}/.Xauthority", username)
                                }
                            }
                        }
                        Some(home) => {
                            format!(
                                "{}/.Xauthority",
                                home.as_path().to_string_lossy().to_string()
                            )
                        }
                    }
                };
            }
        }

        fn get_display_by_user(user: &str) -> String {
            // log::debug!("w {}", &user);
            if let Some(w) = w_path() {
                if let Ok(output) = Command::new(w).arg(user).output() {
                    for line in String::from_utf8_lossy(&output.stdout).lines() {
                        let mut iter = line.split_whitespace();
                        let b = iter.nth(2);
                        if let Some(b) = b {
                            if b.starts_with(":") {
                                return b.to_owned();
                            }
                        }
                    }
                }
            }
            display_from_x11_socket_dir_for_user(user, Path::new("/tmp/.X11-unix"))
        }

        fn set_is_subprocess(&mut self) {
            self.is_rustdesk_subprocess = any_process_cmdline_contains(&format!(
                "/etc/{}/xorg.conf",
                crate::get_app_name().to_lowercase()
            ));
        }

        pub fn refresh(&mut self) {
            if !self.sid.is_empty() && is_active_and_seat0(&self.sid) {
                // Xwayland display and xauth may not be available in a short time after login.
                if is_xwayland_running() && !self.is_login_wayland() {
                    self.get_display_xauth_xwayland();
                    self.is_rustdesk_subprocess = false;
                } else if self.is_wayland() {
                    self.get_display_xauth_wayland();
                }
                return;
            }

            let seat0_values = get_values_of_seat0_with_gdm_wayland(&[0, 1, 2]);
            if seat0_values[0].is_empty() {
                *self = Self::default();
                self.is_rustdesk_subprocess = false;
                return;
            }

            self.sid = seat0_values[0].clone();
            self.uid = seat0_values[1].clone();
            self.username = seat0_values[2].clone();
            self.protocol = get_display_server_of_session(&self.sid).into();
            if self.is_login_wayland() {
                self.display = "".to_owned();
                self.xauth = "".to_owned();
                self.is_rustdesk_subprocess = false;
                return;
            }

            self.get_home();
            if self.is_wayland() {
                if is_xwayland_running() {
                    self.get_display_xauth_xwayland();
                } else {
                    self.get_display_xauth_wayland();
                }
                self.is_rustdesk_subprocess = false;
            } else {
                self.get_display_x11();
                self.get_xauth_x11();
                self.set_is_subprocess();
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

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

    if let Err(err) = Command::new(&exe)
        .arg(REOPEN_AFTER_SERVICE_STOP_ARG)
        .arg(secs.to_string())
        .spawn()
    {
        log::warn!("Failed to schedule RustDesk reopen: {}", err);
    }
}

pub fn reopen_after_service_stop(secs: u32) {
    std::thread::sleep(Duration::from_secs(secs as u64));
    match std::env::current_exe() {
        Ok(exe) => {
            if let Err(err) = Command::new(exe).spawn() {
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

fn sudo_path() -> Option<PathBuf> {
    trusted_command_path(&SUDO_PATHS)
}

fn env_path() -> Option<PathBuf> {
    trusted_command_path(&ENV_PATHS)
}

fn w_path() -> Option<PathBuf> {
    trusted_command_path(&W_PATHS)
}

fn xrandr_path() -> Option<PathBuf> {
    trusted_command_path(&XRANDR_PATHS)
}

fn xdg_screensaver_path() -> Option<PathBuf> {
    trusted_command_path(&XDG_SCREENSAVER_PATHS)
}

fn systemctl_path() -> Option<PathBuf> {
    trusted_command_path(&SYSTEMCTL_PATHS)
}

fn systemctl_service(action: &str, app_name: &str) -> bool {
    let Some(systemctl) = systemctl_path() else {
        log::error!("systemctl was not found at a trusted fixed path");
        return false;
    };
    match Command::new(systemctl).arg(action).arg(app_name).status() {
        Ok(status) if status.success() => true,
        Ok(status) => {
            log::error!("systemctl {action} {app_name} failed with status {status}");
            false
        }
        Err(err) => {
            log::error!("Failed to run systemctl {action} {app_name}: {err}");
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
    let app_name = crate::get_app_name().to_lowercase();
    if !systemctl_service("disable", &app_name) {
        return false;
    }
    if !systemctl_service("stop", &app_name) {
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
    let app_name = crate::get_app_name().to_lowercase();
    if !systemctl_service("enable", &app_name) {
        return false;
    }
    if !systemctl_service("start", &app_name) {
        log::error!("Failed to enable/start the {app_name} service");
        return false;
    }
    true
}

#[cfg(test)]
mod service_lifecycle_tests {
    use super::*;

    #[test]
    fn r_s11c10_service_lifecycle_uses_absolute_systemctl_candidates() {
        for path in SYSTEMCTL_PATHS {
            assert!(Path::new(path).is_absolute());
            assert!(path.ends_with("/systemctl"));
        }
    }

    #[test]
    fn r_s11c10_privileged_command_candidates_are_fixed_system_paths() {
        let command_sets: [&[&str]; 6] = [
            &SUDO_PATHS,
            &ENV_PATHS,
            &W_PATHS,
            &XRANDR_PATHS,
            &XDG_SCREENSAVER_PATHS,
            &SYSTEMCTL_PATHS,
        ];
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

    #[test]
    fn r_s11c10_sudo_env_validation_is_portable_key_only() {
        assert!(is_valid_sudo_env_key(OsStr::new("DISPLAY")));
        assert!(is_valid_sudo_env_key(OsStr::new("_RUSTDESK_TEST")));
        assert!(!is_valid_sudo_env_key(OsStr::new("1BAD")));
        assert!(!is_valid_sudo_env_key(OsStr::new("BAD-NAME")));

        let envs = valid_sudo_envs([
            (OsString::from("DISPLAY"), OsString::from(":1")),
            (OsString::from("BAD-NAME"), OsString::from("ignored")),
        ]);
        assert_eq!(envs.len(), 1);
        assert_eq!(envs[0].0, OsString::from("DISPLAY"));
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
