//! Dynamic loading wrapper for the fork's private libxdo.
//!
//! Loads the packaged private library at runtime,
//! allowing the program to run on systems without libxdo installed
//! (e.g., Wayland-only environments).

use hbb_common::{
    libc::{c_char, c_int, c_uint, c_ulong},
    libloading::os::unix::{Library, RTLD_LOCAL, RTLD_NOW},
    log,
};
use std::{
    ffi::CStr,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::OnceLock,
};

pub use hbb_common::x11::xlib::{Display, Screen, Window};

#[repr(C)]
pub struct xdo_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct xdo_search_t {
    _private: [u8; 0],
}

pub type useconds_t = c_uint;

pub const CURRENTWINDOW: Window = 0;

#[derive(Clone, Copy)]
pub enum XdoKey {
    Keysym(c_ulong),
    Keycode(c_uint),
}

#[repr(u32)]
#[derive(Clone, Copy)]
pub enum XdoKeyAction {
    Down = 1,
    Up = 2,
    Click = 3,
}

const TRUSTED_LIBXDO_PATHS: &[&str] = &[
    "/usr/lib/rustdesk-fork/libxdo.so.3",
];
const EXPECTED_XDO_VERSION: &[u8] = b"3.20160805.1-rustdesk7";

fn root_owned_non_writable(mode: u32, uid: u32) -> bool {
    uid == 0 && mode & 0o022 == 0
}

fn trusted_dir_metadata(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_dir() && root_owned_non_writable(metadata.mode(), metadata.uid())
}

fn trusted_file_metadata(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_file() && root_owned_non_writable(metadata.mode(), metadata.uid())
}

fn trusted_directory_chain(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    path.ancestors().all(|ancestor| {
        fs::metadata(ancestor)
            .map(|metadata| trusted_dir_metadata(&metadata))
            .unwrap_or(false)
    })
}

fn trusted_libxdo_path(candidate: &Path) -> Option<PathBuf> {
    if !candidate.is_absolute() {
        return None;
    }
    if !trusted_directory_chain(candidate.parent()?) {
        return None;
    }
    let canonical = fs::canonicalize(candidate).ok()?;
    if !canonical.is_absolute() {
        return None;
    }
    if !trusted_directory_chain(canonical.parent()?) {
        return None;
    }
    let metadata = fs::metadata(&canonical).ok()?;
    if !trusted_file_metadata(&metadata) {
        return None;
    }
    Some(canonical)
}

fn trusted_libxdo_paths() -> impl Iterator<Item = PathBuf> {
    TRUSTED_LIBXDO_PATHS
        .iter()
        .filter_map(|path| trusted_libxdo_path(Path::new(path)))
}

type FnXdoNew = unsafe extern "C" fn(*const c_char) -> *mut xdo_t;
type FnXdoVersion = unsafe extern "C" fn() -> *const c_char;
type FnXdoNewWithOpenedDisplay =
    unsafe extern "C" fn(*mut Display, *const c_char, c_int) -> *mut xdo_t;
type FnXdoFree = unsafe extern "C" fn(*mut xdo_t);
type FnXdoSendKeyWindow =
    unsafe extern "C" fn(*const xdo_t, Window, c_uint, c_ulong, c_uint, useconds_t) -> c_int;
type FnXdoClickWindow = unsafe extern "C" fn(*const xdo_t, Window, c_int) -> c_int;
type FnXdoMouseDown = unsafe extern "C" fn(*const xdo_t, Window, c_int) -> c_int;
type FnXdoMouseUp = unsafe extern "C" fn(*const xdo_t, Window, c_int) -> c_int;
type FnXdoMoveMouse = unsafe extern "C" fn(*const xdo_t, c_int, c_int, c_int) -> c_int;
type FnXdoMoveMouseRelative = unsafe extern "C" fn(*const xdo_t, c_int, c_int) -> c_int;
type FnXdoMoveMouseRelativeToWindow =
    unsafe extern "C" fn(*const xdo_t, Window, c_int, c_int) -> c_int;
type FnXdoGetMouseLocation =
    unsafe extern "C" fn(*const xdo_t, *mut c_int, *mut c_int, *mut c_int) -> c_int;
type FnXdoGetMouseLocation2 =
    unsafe extern "C" fn(*const xdo_t, *mut c_int, *mut c_int, *mut c_int, *mut Window) -> c_int;
type FnXdoGetActiveWindow = unsafe extern "C" fn(*const xdo_t, *mut Window) -> c_int;
type FnXdoGetFocusedWindow = unsafe extern "C" fn(*const xdo_t, *mut Window) -> c_int;
type FnXdoGetFocusedWindowSane = unsafe extern "C" fn(*const xdo_t, *mut Window) -> c_int;
type FnXdoGetWindowLocation =
    unsafe extern "C" fn(*const xdo_t, Window, *mut c_int, *mut c_int, *mut *mut Screen) -> c_int;
type FnXdoGetWindowSize =
    unsafe extern "C" fn(*const xdo_t, Window, *mut c_uint, *mut c_uint) -> c_int;
type FnXdoGetInputState = unsafe extern "C" fn(*const xdo_t) -> c_uint;
type FnXdoActivateWindow = unsafe extern "C" fn(*const xdo_t, Window) -> c_int;
type FnXdoWaitForMouseMoveFrom = unsafe extern "C" fn(*const xdo_t, c_int, c_int) -> c_int;
type FnXdoWaitForMouseMoveTo = unsafe extern "C" fn(*const xdo_t, c_int, c_int) -> c_int;
type FnXdoSearchWindows =
    unsafe extern "C" fn(*const xdo_t, *const xdo_search_t, *mut *mut Window, *mut c_uint) -> c_int;

struct XdoLib {
    _lib: Library,
    xdo_new: FnXdoNew,
    xdo_new_with_opened_display: FnXdoNewWithOpenedDisplay,
    xdo_free: FnXdoFree,
    xdo_send_key_window: FnXdoSendKeyWindow,
    xdo_click_window: FnXdoClickWindow,
    xdo_mouse_down: FnXdoMouseDown,
    xdo_mouse_up: FnXdoMouseUp,
    xdo_move_mouse: FnXdoMoveMouse,
    xdo_move_mouse_relative: FnXdoMoveMouseRelative,
    xdo_move_mouse_relative_to_window: FnXdoMoveMouseRelativeToWindow,
    xdo_get_mouse_location: FnXdoGetMouseLocation,
    xdo_get_mouse_location2: FnXdoGetMouseLocation2,
    xdo_get_active_window: FnXdoGetActiveWindow,
    xdo_get_focused_window: FnXdoGetFocusedWindow,
    xdo_get_focused_window_sane: FnXdoGetFocusedWindowSane,
    xdo_get_window_location: FnXdoGetWindowLocation,
    xdo_get_window_size: FnXdoGetWindowSize,
    xdo_get_input_state: FnXdoGetInputState,
    xdo_activate_window: FnXdoActivateWindow,
    xdo_wait_for_mouse_move_from: FnXdoWaitForMouseMoveFrom,
    xdo_wait_for_mouse_move_to: FnXdoWaitForMouseMoveTo,
    xdo_search_windows: FnXdoSearchWindows,
}

unsafe fn required_symbol<T: Copy>(lib: &Library, name: &[u8]) -> Option<T> {
    match lib.get::<T>(name) {
        Ok(symbol) => Some(*symbol),
        Err(err) => {
            log::warn!(
                "Private XDO is missing required symbol {}: {err}",
                String::from_utf8_lossy(name)
            );
            None
        }
    }
}

impl XdoLib {
    fn load() -> Option<Self> {
        unsafe {
            let (lib, lib_path) = trusted_libxdo_paths().find_map(|path| {
                Library::open(Some(path.as_path()), RTLD_NOW | RTLD_LOCAL)
                    .ok()
                    .map(|lib| (lib, path))
            })?;

            let version: FnXdoVersion = required_symbol(&lib, b"xdo_version")?;
            let version = version();
            if version.is_null() || CStr::from_ptr(version).to_bytes() != EXPECTED_XDO_VERSION {
                log::warn!("The private XDO library has an unexpected version");
                return None;
            }
            let xdo_new = required_symbol(&lib, b"xdo_new")?;
            let xdo_free = required_symbol(&lib, b"xdo_free")?;
            let xdo_send_key_window = required_symbol(&lib, b"xdo_send_key_window")?;
            let xdo_new_with_opened_display = required_symbol(&lib, b"xdo_new_with_opened_display")?;
            let xdo_click_window = required_symbol(&lib, b"xdo_click_window")?;
            let xdo_mouse_down = required_symbol(&lib, b"xdo_mouse_down")?;
            let xdo_mouse_up = required_symbol(&lib, b"xdo_mouse_up")?;
            let xdo_move_mouse = required_symbol(&lib, b"xdo_move_mouse")?;
            let xdo_move_mouse_relative = required_symbol(&lib, b"xdo_move_mouse_relative")?;
            let xdo_move_mouse_relative_to_window =
                required_symbol(&lib, b"xdo_move_mouse_relative_to_window")?;
            let xdo_get_mouse_location = required_symbol(&lib, b"xdo_get_mouse_location")?;
            let xdo_get_mouse_location2 = required_symbol(&lib, b"xdo_get_mouse_location2")?;
            let xdo_get_active_window = required_symbol(&lib, b"xdo_get_active_window")?;
            let xdo_get_focused_window = required_symbol(&lib, b"xdo_get_focused_window")?;
            let xdo_get_focused_window_sane = required_symbol(&lib, b"xdo_get_focused_window_sane")?;
            let xdo_get_window_location = required_symbol(&lib, b"xdo_get_window_location")?;
            let xdo_get_window_size = required_symbol(&lib, b"xdo_get_window_size")?;
            let xdo_get_input_state = required_symbol(&lib, b"xdo_get_input_state")?;
            let xdo_activate_window = required_symbol(&lib, b"xdo_activate_window")?;
            let xdo_wait_for_mouse_move_from = required_symbol(&lib, b"xdo_wait_for_mouse_move_from")?;
            let xdo_wait_for_mouse_move_to = required_symbol(&lib, b"xdo_wait_for_mouse_move_to")?;
            let xdo_search_windows = required_symbol(&lib, b"xdo_search_windows")?;

            log::info!("libxdo-sys Loaded {}", lib_path.display());

            Some(Self {
                _lib: lib,
                xdo_new,
                xdo_new_with_opened_display,
                xdo_free,
                xdo_send_key_window,
                xdo_click_window,
                xdo_mouse_down,
                xdo_mouse_up,
                xdo_move_mouse,
                xdo_move_mouse_relative,
                xdo_move_mouse_relative_to_window,
                xdo_get_mouse_location,
                xdo_get_mouse_location2,
                xdo_get_active_window,
                xdo_get_focused_window,
                xdo_get_focused_window_sane,
                xdo_get_window_location,
                xdo_get_window_size,
                xdo_get_input_state,
                xdo_activate_window,
                xdo_wait_for_mouse_move_from,
                xdo_wait_for_mouse_move_to,
                xdo_search_windows,
            })
        }
    }
}

static XDO_LIB: OnceLock<Option<XdoLib>> = OnceLock::new();

fn get_lib() -> Option<&'static XdoLib> {
    XDO_LIB
        .get_or_init(|| {
            let lib = XdoLib::load();
            if lib.is_none() {
                log::info!("libxdo-sys libxdo not found, xdo functions will be disabled");
            }
            lib
        })
        .as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::libc;
    use std::{
        fs::{self, File},
        os::unix::fs::{symlink, PermissionsExt},
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn unique_root_test_dir(label: &str) -> Option<PathBuf> {
        if unsafe { libc::geteuid() } != 0 {
            return None;
        }
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_nanos();
        let path = PathBuf::from(format!(
            "/run/rustdesk-libxdo-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir(&path).ok()?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).ok()?;
        Some(path)
    }

    #[test]
    fn trusted_libxdo_candidates_are_fixed_absolute_sonames() {
        assert_eq!(TRUSTED_LIBXDO_PATHS, &["/usr/lib/rustdesk-fork/libxdo.so.3"]);
        for path in TRUSTED_LIBXDO_PATHS {
            let path = Path::new(path);
            assert!(path.is_absolute());
            assert!(
                path.starts_with("/usr/lib")
                    || path.starts_with("/usr/lib64")
                    || path.starts_with("/lib")
                    || path.starts_with("/lib64")
            );
            let name = path.file_name().and_then(|name| name.to_str());
            assert!(matches!(name, Some("libxdo.so.3" | "libxdo.so.4")));
        }
        assert!(!TRUSTED_LIBXDO_PATHS.iter().any(|path| path == &"libxdo.so"));
        assert!(!TRUSTED_LIBXDO_PATHS
            .iter()
            .any(|path| path.starts_with("/usr/local/")));
    }

    #[test]
    fn root_owned_non_writable_rejects_user_or_group_writable_authority() {
        assert!(root_owned_non_writable(0o755, 0));
        assert!(root_owned_non_writable(0o644, 0));
        assert!(!root_owned_non_writable(0o775, 0));
        assert!(!root_owned_non_writable(0o777, 0));
        assert!(!root_owned_non_writable(0o755, 1000));
    }

    #[test]
    fn trusted_libxdo_path_rejects_relative_candidate() {
        assert!(trusted_libxdo_path(Path::new("libxdo.so.3")).is_none());
    }

    #[test]
    fn trusted_libxdo_path_rejects_world_writable_parent() {
        let path = PathBuf::from("/tmp").join(format!(
            "rustdesk-libxdo-world-writable-parent-{}",
            std::process::id()
        ));
        File::create(&path).expect("create temp libxdo test file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("chmod temp libxdo test file");
        assert!(trusted_libxdo_path(&path).is_none());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn trusted_libxdo_path_accepts_root_owned_protected_regular_file() {
        let Some(dir) = unique_root_test_dir("accept") else {
            return;
        };
        let path = dir.join("libxdo.so.3");
        File::create(&path).expect("create protected libxdo test file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("chmod protected libxdo test file");
        assert_eq!(trusted_libxdo_path(&path), fs::canonicalize(&path).ok());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn trusted_libxdo_path_rejects_group_writable_file() {
        let Some(dir) = unique_root_test_dir("group-writable") else {
            return;
        };
        let path = dir.join("libxdo.so.3");
        File::create(&path).expect("create writable libxdo test file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o664))
            .expect("chmod writable libxdo test file");
        assert!(trusted_libxdo_path(&path).is_none());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn trusted_libxdo_path_accepts_protected_symlink_to_protected_target() {
        let Some(dir) = unique_root_test_dir("symlink-accept") else {
            return;
        };
        let target = dir.join("libxdo.so.3.0.0");
        let link = dir.join("libxdo.so.3");
        File::create(&target).expect("create symlink target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644))
            .expect("chmod symlink target");
        symlink(&target, &link).expect("create symlink");
        assert_eq!(trusted_libxdo_path(&link), fs::canonicalize(&target).ok());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn trusted_libxdo_path_rejects_symlink_to_untrusted_target() {
        let Some(dir) = unique_root_test_dir("symlink-reject") else {
            return;
        };
        let target = PathBuf::from("/tmp").join(format!(
            "rustdesk-libxdo-untrusted-target-{}",
            std::process::id()
        ));
        let link = dir.join("libxdo.so.3");
        File::create(&target).expect("create untrusted symlink target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644))
            .expect("chmod untrusted symlink target");
        symlink(&target, &link).expect("create symlink");
        assert!(trusted_libxdo_path(&link).is_none());
        let _ = fs::remove_file(target);
        let _ = fs::remove_dir_all(dir);
    }
}

pub unsafe extern "C" fn xdo_new(display: *const c_char) -> *mut xdo_t {
    get_lib().map_or(std::ptr::null_mut(), |lib| (lib.xdo_new)(display))
}

pub unsafe extern "C" fn xdo_new_with_opened_display(
    xdpy: *mut Display,
    display: *const c_char,
    close_display_when_freed: c_int,
) -> *mut xdo_t {
    get_lib().map_or(std::ptr::null_mut(), |lib| {
        (lib.xdo_new_with_opened_display)(xdpy, display, close_display_when_freed)
    })
}

pub unsafe extern "C" fn xdo_free(xdo: *mut xdo_t) {
    if xdo.is_null() {
        return;
    }
    if let Some(lib) = get_lib() {
        (lib.xdo_free)(xdo);
    }
}

pub unsafe fn xdo_send_key_window(
    xdo: *const xdo_t,
    window: Window,
    key: XdoKey,
    action: XdoKeyAction,
    delay: useconds_t,
) -> c_int {
    let (kind, value) = match key {
        XdoKey::Keysym(value) => (1, value),
        XdoKey::Keycode(value) => (2, value as c_ulong),
    };
    get_lib().map_or(1, |lib| {
        (lib.xdo_send_key_window)(xdo, window, kind, value, action as c_uint, delay)
    })
}

pub unsafe extern "C" fn xdo_click_window(
    xdo: *const xdo_t,
    window: Window,
    button: c_int,
) -> c_int {
    get_lib().map_or(1, |lib| (lib.xdo_click_window)(xdo, window, button))
}

pub unsafe extern "C" fn xdo_mouse_down(xdo: *const xdo_t, window: Window, button: c_int) -> c_int {
    get_lib().map_or(1, |lib| (lib.xdo_mouse_down)(xdo, window, button))
}

pub unsafe extern "C" fn xdo_mouse_up(xdo: *const xdo_t, window: Window, button: c_int) -> c_int {
    get_lib().map_or(1, |lib| (lib.xdo_mouse_up)(xdo, window, button))
}

pub unsafe extern "C" fn xdo_move_mouse(
    xdo: *const xdo_t,
    x: c_int,
    y: c_int,
    screen: c_int,
) -> c_int {
    get_lib().map_or(1, |lib| (lib.xdo_move_mouse)(xdo, x, y, screen))
}

pub unsafe extern "C" fn xdo_move_mouse_relative(xdo: *const xdo_t, x: c_int, y: c_int) -> c_int {
    get_lib().map_or(1, |lib| (lib.xdo_move_mouse_relative)(xdo, x, y))
}

pub unsafe extern "C" fn xdo_move_mouse_relative_to_window(
    xdo: *const xdo_t,
    window: Window,
    x: c_int,
    y: c_int,
) -> c_int {
    get_lib().map_or(1, |lib| (lib.xdo_move_mouse_relative_to_window)(xdo, window, x, y))
}

pub unsafe extern "C" fn xdo_get_mouse_location(
    xdo: *const xdo_t,
    x: *mut c_int,
    y: *mut c_int,
    screen_num: *mut c_int,
) -> c_int {
    get_lib().map_or(1, |lib| (lib.xdo_get_mouse_location)(xdo, x, y, screen_num))
}

pub unsafe extern "C" fn xdo_get_mouse_location2(
    xdo: *const xdo_t,
    x: *mut c_int,
    y: *mut c_int,
    screen_num: *mut c_int,
    window: *mut Window,
) -> c_int {
    get_lib().map_or(1, |lib| (lib.xdo_get_mouse_location2)(xdo, x, y, screen_num, window))
}

pub unsafe extern "C" fn xdo_get_active_window(
    xdo: *const xdo_t,
    window_ret: *mut Window,
) -> c_int {
    get_lib().map_or(1, |lib| (lib.xdo_get_active_window)(xdo, window_ret))
}

pub unsafe extern "C" fn xdo_get_focused_window(
    xdo: *const xdo_t,
    window_ret: *mut Window,
) -> c_int {
    get_lib().map_or(1, |lib| (lib.xdo_get_focused_window)(xdo, window_ret))
}

pub unsafe extern "C" fn xdo_get_focused_window_sane(
    xdo: *const xdo_t,
    window_ret: *mut Window,
) -> c_int {
    get_lib().map_or(1, |lib| (lib.xdo_get_focused_window_sane)(xdo, window_ret))
}

pub unsafe extern "C" fn xdo_get_window_location(
    xdo: *const xdo_t,
    window: Window,
    x: *mut c_int,
    y: *mut c_int,
    screen_ret: *mut *mut Screen,
) -> c_int {
    get_lib().map_or(1, |lib| (lib.xdo_get_window_location)(xdo, window, x, y, screen_ret))
}

pub unsafe extern "C" fn xdo_get_window_size(
    xdo: *const xdo_t,
    window: Window,
    width: *mut c_uint,
    height: *mut c_uint,
) -> c_int {
    get_lib().map_or(1, |lib| (lib.xdo_get_window_size)(xdo, window, width, height))
}

pub unsafe extern "C" fn xdo_get_input_state(xdo: *const xdo_t) -> c_uint {
    get_lib().map_or(0, |lib| (lib.xdo_get_input_state)(xdo))
}

pub unsafe extern "C" fn xdo_activate_window(xdo: *const xdo_t, wid: Window) -> c_int {
    get_lib().map_or(1, |lib| (lib.xdo_activate_window)(xdo, wid))
}

pub unsafe extern "C" fn xdo_wait_for_mouse_move_from(
    xdo: *const xdo_t,
    origin_x: c_int,
    origin_y: c_int,
) -> c_int {
    get_lib().map_or(1, |lib| (lib.xdo_wait_for_mouse_move_from)(xdo, origin_x, origin_y))
}

pub unsafe extern "C" fn xdo_wait_for_mouse_move_to(
    xdo: *const xdo_t,
    dest_x: c_int,
    dest_y: c_int,
) -> c_int {
    get_lib().map_or(1, |lib| (lib.xdo_wait_for_mouse_move_to)(xdo, dest_x, dest_y))
}

pub unsafe extern "C" fn xdo_search_windows(
    xdo: *const xdo_t,
    search: *const xdo_search_t,
    windowlist_ret: *mut *mut Window,
    nwindows_ret: *mut c_uint,
) -> c_int {
    get_lib().map_or(1, |lib| (lib.xdo_search_windows)(xdo, search, windowlist_ret, nwindows_ret))
}
