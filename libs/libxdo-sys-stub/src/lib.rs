//! Dynamic loading wrapper for libxdo.
//!
//! Provides the same API as libxdo-sys but loads libxdo at runtime,
//! allowing the program to run on systems without libxdo installed
//! (e.g., Wayland-only environments).

use hbb_common::{
    libc::{c_char, c_int, c_uint},
    libloading::os::unix::{Library, Symbol, RTLD_LOCAL, RTLD_NOW},
    log,
};
use std::{
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
pub struct charcodemap_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct xdo_search_t {
    _private: [u8; 0],
}

pub type useconds_t = c_uint;

pub const CURRENTWINDOW: Window = 0;

const TRUSTED_LIBXDO_PATHS: &[&str] = &[
    "/usr/lib/x86_64-linux-gnu/libxdo.so.4",
    "/usr/lib/x86_64-linux-gnu/libxdo.so.3",
    "/usr/lib/aarch64-linux-gnu/libxdo.so.4",
    "/usr/lib/aarch64-linux-gnu/libxdo.so.3",
    "/usr/lib/arm-linux-gnueabihf/libxdo.so.4",
    "/usr/lib/arm-linux-gnueabihf/libxdo.so.3",
    "/usr/lib/i386-linux-gnu/libxdo.so.4",
    "/usr/lib/i386-linux-gnu/libxdo.so.3",
    "/usr/lib/libxdo.so.4",
    "/usr/lib/libxdo.so.3",
    "/usr/lib64/libxdo.so.4",
    "/usr/lib64/libxdo.so.3",
    "/lib/x86_64-linux-gnu/libxdo.so.4",
    "/lib/x86_64-linux-gnu/libxdo.so.3",
    "/lib/aarch64-linux-gnu/libxdo.so.4",
    "/lib/aarch64-linux-gnu/libxdo.so.3",
    "/lib/arm-linux-gnueabihf/libxdo.so.4",
    "/lib/arm-linux-gnueabihf/libxdo.so.3",
    "/lib/i386-linux-gnu/libxdo.so.4",
    "/lib/i386-linux-gnu/libxdo.so.3",
    "/lib/libxdo.so.4",
    "/lib/libxdo.so.3",
    "/lib64/libxdo.so.4",
    "/lib64/libxdo.so.3",
];

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
type FnXdoNewWithOpenedDisplay =
    unsafe extern "C" fn(*mut Display, *const c_char, c_int) -> *mut xdo_t;
type FnXdoFree = unsafe extern "C" fn(*mut xdo_t);
type FnXdoSendKeysequenceWindow =
    unsafe extern "C" fn(*const xdo_t, Window, *const c_char, useconds_t) -> c_int;
type FnXdoSendKeysequenceWindowDown =
    unsafe extern "C" fn(*const xdo_t, Window, *const c_char, useconds_t) -> c_int;
type FnXdoSendKeysequenceWindowUp =
    unsafe extern "C" fn(*const xdo_t, Window, *const c_char, useconds_t) -> c_int;
type FnXdoEnterTextWindow =
    unsafe extern "C" fn(*const xdo_t, Window, *const c_char, useconds_t) -> c_int;
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
type FnXdoSetWindowClass =
    unsafe extern "C" fn(*const xdo_t, Window, *const c_char, *const c_char) -> c_int;
type FnXdoSearchWindows =
    unsafe extern "C" fn(*const xdo_t, *const xdo_search_t, *mut *mut Window, *mut c_uint) -> c_int;

struct XdoLib {
    _lib: Library,
    xdo_new: FnXdoNew,
    xdo_new_with_opened_display: Option<FnXdoNewWithOpenedDisplay>,
    xdo_free: FnXdoFree,
    xdo_send_keysequence_window: FnXdoSendKeysequenceWindow,
    xdo_send_keysequence_window_down: Option<FnXdoSendKeysequenceWindowDown>,
    xdo_send_keysequence_window_up: Option<FnXdoSendKeysequenceWindowUp>,
    xdo_enter_text_window: Option<FnXdoEnterTextWindow>,
    xdo_click_window: Option<FnXdoClickWindow>,
    xdo_mouse_down: Option<FnXdoMouseDown>,
    xdo_mouse_up: Option<FnXdoMouseUp>,
    xdo_move_mouse: Option<FnXdoMoveMouse>,
    xdo_move_mouse_relative: Option<FnXdoMoveMouseRelative>,
    xdo_move_mouse_relative_to_window: Option<FnXdoMoveMouseRelativeToWindow>,
    xdo_get_mouse_location: Option<FnXdoGetMouseLocation>,
    xdo_get_mouse_location2: Option<FnXdoGetMouseLocation2>,
    xdo_get_active_window: Option<FnXdoGetActiveWindow>,
    xdo_get_focused_window: Option<FnXdoGetFocusedWindow>,
    xdo_get_focused_window_sane: Option<FnXdoGetFocusedWindowSane>,
    xdo_get_window_location: Option<FnXdoGetWindowLocation>,
    xdo_get_window_size: Option<FnXdoGetWindowSize>,
    xdo_get_input_state: Option<FnXdoGetInputState>,
    xdo_activate_window: Option<FnXdoActivateWindow>,
    xdo_wait_for_mouse_move_from: Option<FnXdoWaitForMouseMoveFrom>,
    xdo_wait_for_mouse_move_to: Option<FnXdoWaitForMouseMoveTo>,
    xdo_set_window_class: Option<FnXdoSetWindowClass>,
    xdo_search_windows: Option<FnXdoSearchWindows>,
}

impl XdoLib {
    fn load() -> Option<Self> {
        unsafe {
            let (lib, lib_path) = trusted_libxdo_paths().find_map(|path| {
                Library::open(Some(path.as_path()), RTLD_NOW | RTLD_LOCAL)
                    .ok()
                    .map(|lib| (lib, path))
            })?;

            log::info!("libxdo-sys Loaded {}", lib_path.display());

            let xdo_new: FnXdoNew = *lib.get(b"xdo_new").ok()?;
            let xdo_free: FnXdoFree = *lib.get(b"xdo_free").ok()?;
            let xdo_send_keysequence_window: FnXdoSendKeysequenceWindow =
                *lib.get(b"xdo_send_keysequence_window").ok()?;

            let xdo_new_with_opened_display = lib
                .get(b"xdo_new_with_opened_display")
                .ok()
                .map(|s: Symbol<FnXdoNewWithOpenedDisplay>| *s);
            let xdo_send_keysequence_window_down = lib
                .get(b"xdo_send_keysequence_window_down")
                .ok()
                .map(|s: Symbol<FnXdoSendKeysequenceWindowDown>| *s);
            let xdo_send_keysequence_window_up = lib
                .get(b"xdo_send_keysequence_window_up")
                .ok()
                .map(|s: Symbol<FnXdoSendKeysequenceWindowUp>| *s);
            let xdo_enter_text_window = lib
                .get(b"xdo_enter_text_window")
                .ok()
                .map(|s: Symbol<FnXdoEnterTextWindow>| *s);
            let xdo_click_window = lib
                .get(b"xdo_click_window")
                .ok()
                .map(|s: Symbol<FnXdoClickWindow>| *s);
            let xdo_mouse_down = lib
                .get(b"xdo_mouse_down")
                .ok()
                .map(|s: Symbol<FnXdoMouseDown>| *s);
            let xdo_mouse_up = lib
                .get(b"xdo_mouse_up")
                .ok()
                .map(|s: Symbol<FnXdoMouseUp>| *s);
            let xdo_move_mouse = lib
                .get(b"xdo_move_mouse")
                .ok()
                .map(|s: Symbol<FnXdoMoveMouse>| *s);
            let xdo_move_mouse_relative = lib
                .get(b"xdo_move_mouse_relative")
                .ok()
                .map(|s: Symbol<FnXdoMoveMouseRelative>| *s);
            let xdo_move_mouse_relative_to_window = lib
                .get(b"xdo_move_mouse_relative_to_window")
                .ok()
                .map(|s: Symbol<FnXdoMoveMouseRelativeToWindow>| *s);
            let xdo_get_mouse_location = lib
                .get(b"xdo_get_mouse_location")
                .ok()
                .map(|s: Symbol<FnXdoGetMouseLocation>| *s);
            let xdo_get_mouse_location2 = lib
                .get(b"xdo_get_mouse_location2")
                .ok()
                .map(|s: Symbol<FnXdoGetMouseLocation2>| *s);
            let xdo_get_active_window = lib
                .get(b"xdo_get_active_window")
                .ok()
                .map(|s: Symbol<FnXdoGetActiveWindow>| *s);
            let xdo_get_focused_window = lib
                .get(b"xdo_get_focused_window")
                .ok()
                .map(|s: Symbol<FnXdoGetFocusedWindow>| *s);
            let xdo_get_focused_window_sane = lib
                .get(b"xdo_get_focused_window_sane")
                .ok()
                .map(|s: Symbol<FnXdoGetFocusedWindowSane>| *s);
            let xdo_get_window_location = lib
                .get(b"xdo_get_window_location")
                .ok()
                .map(|s: Symbol<FnXdoGetWindowLocation>| *s);
            let xdo_get_window_size = lib
                .get(b"xdo_get_window_size")
                .ok()
                .map(|s: Symbol<FnXdoGetWindowSize>| *s);
            let xdo_get_input_state = lib
                .get(b"xdo_get_input_state")
                .ok()
                .map(|s: Symbol<FnXdoGetInputState>| *s);
            let xdo_activate_window = lib
                .get(b"xdo_activate_window")
                .ok()
                .map(|s: Symbol<FnXdoActivateWindow>| *s);
            let xdo_wait_for_mouse_move_from = lib
                .get(b"xdo_wait_for_mouse_move_from")
                .ok()
                .map(|s: Symbol<FnXdoWaitForMouseMoveFrom>| *s);
            let xdo_wait_for_mouse_move_to = lib
                .get(b"xdo_wait_for_mouse_move_to")
                .ok()
                .map(|s: Symbol<FnXdoWaitForMouseMoveTo>| *s);
            let xdo_set_window_class = lib
                .get(b"xdo_set_window_class")
                .ok()
                .map(|s: Symbol<FnXdoSetWindowClass>| *s);
            let xdo_search_windows = lib
                .get(b"xdo_search_windows")
                .ok()
                .map(|s: Symbol<FnXdoSearchWindows>| *s);

            Some(Self {
                _lib: lib,
                xdo_new,
                xdo_new_with_opened_display,
                xdo_free,
                xdo_send_keysequence_window,
                xdo_send_keysequence_window_down,
                xdo_send_keysequence_window_up,
                xdo_enter_text_window,
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
                xdo_set_window_class,
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
        assert!(!TRUSTED_LIBXDO_PATHS.is_empty());
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
    get_lib()
        .and_then(|lib| lib.xdo_new_with_opened_display)
        .map_or(std::ptr::null_mut(), |f| {
            f(xdpy, display, close_display_when_freed)
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

pub unsafe extern "C" fn xdo_send_keysequence_window(
    xdo: *const xdo_t,
    window: Window,
    keysequence: *const c_char,
    delay: useconds_t,
) -> c_int {
    get_lib().map_or(1, |lib| {
        (lib.xdo_send_keysequence_window)(xdo, window, keysequence, delay)
    })
}

pub unsafe extern "C" fn xdo_send_keysequence_window_down(
    xdo: *const xdo_t,
    window: Window,
    keysequence: *const c_char,
    delay: useconds_t,
) -> c_int {
    get_lib()
        .and_then(|lib| lib.xdo_send_keysequence_window_down)
        .map_or(1, |f| f(xdo, window, keysequence, delay))
}

pub unsafe extern "C" fn xdo_send_keysequence_window_up(
    xdo: *const xdo_t,
    window: Window,
    keysequence: *const c_char,
    delay: useconds_t,
) -> c_int {
    get_lib()
        .and_then(|lib| lib.xdo_send_keysequence_window_up)
        .map_or(1, |f| f(xdo, window, keysequence, delay))
}

pub unsafe extern "C" fn xdo_enter_text_window(
    xdo: *const xdo_t,
    window: Window,
    string: *const c_char,
    delay: useconds_t,
) -> c_int {
    get_lib()
        .and_then(|lib| lib.xdo_enter_text_window)
        .map_or(1, |f| f(xdo, window, string, delay))
}

pub unsafe extern "C" fn xdo_click_window(
    xdo: *const xdo_t,
    window: Window,
    button: c_int,
) -> c_int {
    get_lib()
        .and_then(|lib| lib.xdo_click_window)
        .map_or(1, |f| f(xdo, window, button))
}

pub unsafe extern "C" fn xdo_mouse_down(xdo: *const xdo_t, window: Window, button: c_int) -> c_int {
    get_lib()
        .and_then(|lib| lib.xdo_mouse_down)
        .map_or(1, |f| f(xdo, window, button))
}

pub unsafe extern "C" fn xdo_mouse_up(xdo: *const xdo_t, window: Window, button: c_int) -> c_int {
    get_lib()
        .and_then(|lib| lib.xdo_mouse_up)
        .map_or(1, |f| f(xdo, window, button))
}

pub unsafe extern "C" fn xdo_move_mouse(
    xdo: *const xdo_t,
    x: c_int,
    y: c_int,
    screen: c_int,
) -> c_int {
    get_lib()
        .and_then(|lib| lib.xdo_move_mouse)
        .map_or(1, |f| f(xdo, x, y, screen))
}

pub unsafe extern "C" fn xdo_move_mouse_relative(xdo: *const xdo_t, x: c_int, y: c_int) -> c_int {
    get_lib()
        .and_then(|lib| lib.xdo_move_mouse_relative)
        .map_or(1, |f| f(xdo, x, y))
}

pub unsafe extern "C" fn xdo_move_mouse_relative_to_window(
    xdo: *const xdo_t,
    window: Window,
    x: c_int,
    y: c_int,
) -> c_int {
    get_lib()
        .and_then(|lib| lib.xdo_move_mouse_relative_to_window)
        .map_or(1, |f| f(xdo, window, x, y))
}

pub unsafe extern "C" fn xdo_get_mouse_location(
    xdo: *const xdo_t,
    x: *mut c_int,
    y: *mut c_int,
    screen_num: *mut c_int,
) -> c_int {
    get_lib()
        .and_then(|lib| lib.xdo_get_mouse_location)
        .map_or(1, |f| f(xdo, x, y, screen_num))
}

pub unsafe extern "C" fn xdo_get_mouse_location2(
    xdo: *const xdo_t,
    x: *mut c_int,
    y: *mut c_int,
    screen_num: *mut c_int,
    window: *mut Window,
) -> c_int {
    get_lib()
        .and_then(|lib| lib.xdo_get_mouse_location2)
        .map_or(1, |f| f(xdo, x, y, screen_num, window))
}

pub unsafe extern "C" fn xdo_get_active_window(
    xdo: *const xdo_t,
    window_ret: *mut Window,
) -> c_int {
    get_lib()
        .and_then(|lib| lib.xdo_get_active_window)
        .map_or(1, |f| f(xdo, window_ret))
}

pub unsafe extern "C" fn xdo_get_focused_window(
    xdo: *const xdo_t,
    window_ret: *mut Window,
) -> c_int {
    get_lib()
        .and_then(|lib| lib.xdo_get_focused_window)
        .map_or(1, |f| f(xdo, window_ret))
}

pub unsafe extern "C" fn xdo_get_focused_window_sane(
    xdo: *const xdo_t,
    window_ret: *mut Window,
) -> c_int {
    get_lib()
        .and_then(|lib| lib.xdo_get_focused_window_sane)
        .map_or(1, |f| f(xdo, window_ret))
}

pub unsafe extern "C" fn xdo_get_window_location(
    xdo: *const xdo_t,
    window: Window,
    x: *mut c_int,
    y: *mut c_int,
    screen_ret: *mut *mut Screen,
) -> c_int {
    get_lib()
        .and_then(|lib| lib.xdo_get_window_location)
        .map_or(1, |f| f(xdo, window, x, y, screen_ret))
}

pub unsafe extern "C" fn xdo_get_window_size(
    xdo: *const xdo_t,
    window: Window,
    width: *mut c_uint,
    height: *mut c_uint,
) -> c_int {
    get_lib()
        .and_then(|lib| lib.xdo_get_window_size)
        .map_or(1, |f| f(xdo, window, width, height))
}

pub unsafe extern "C" fn xdo_get_input_state(xdo: *const xdo_t) -> c_uint {
    get_lib()
        .and_then(|lib| lib.xdo_get_input_state)
        .map_or(0, |f| f(xdo))
}

pub unsafe extern "C" fn xdo_activate_window(xdo: *const xdo_t, wid: Window) -> c_int {
    get_lib()
        .and_then(|lib| lib.xdo_activate_window)
        .map_or(1, |f| f(xdo, wid))
}

pub unsafe extern "C" fn xdo_wait_for_mouse_move_from(
    xdo: *const xdo_t,
    origin_x: c_int,
    origin_y: c_int,
) -> c_int {
    get_lib()
        .and_then(|lib| lib.xdo_wait_for_mouse_move_from)
        .map_or(1, |f| f(xdo, origin_x, origin_y))
}

pub unsafe extern "C" fn xdo_wait_for_mouse_move_to(
    xdo: *const xdo_t,
    dest_x: c_int,
    dest_y: c_int,
) -> c_int {
    get_lib()
        .and_then(|lib| lib.xdo_wait_for_mouse_move_to)
        .map_or(1, |f| f(xdo, dest_x, dest_y))
}

pub unsafe extern "C" fn xdo_set_window_class(
    xdo: *const xdo_t,
    wid: Window,
    name: *const c_char,
    class: *const c_char,
) -> c_int {
    get_lib()
        .and_then(|lib| lib.xdo_set_window_class)
        .map_or(1, |f| f(xdo, wid, name, class))
}

pub unsafe extern "C" fn xdo_search_windows(
    xdo: *const xdo_t,
    search: *const xdo_search_t,
    windowlist_ret: *mut *mut Window,
    nwindows_ret: *mut c_uint,
) -> c_int {
    get_lib()
        .and_then(|lib| lib.xdo_search_windows)
        .map_or(1, |f| f(xdo, search, windowlist_ret, nwindows_ret))
}
