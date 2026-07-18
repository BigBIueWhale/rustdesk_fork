#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(target_os = "macos")]
pub use macos::*;
#[cfg(windows)]
pub use windows::*;

#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
pub mod win_device;

#[cfg(target_os = "macos")]
pub mod macos;

// R-B6/R-R2: `mod delegate` (the macOS Sciter NSApplication menubar/dock app-handler over
// `sciter::Host`) is DELETED with the Sciter UI — its only callers were in the deleted src/ui.rs,
// and it linked the `sciter-rs` fork. The Flutter macOS build uses its own app-lifecycle handling.

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "linux")]
pub mod linux_desktop_manager;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
use hbb_common::sysinfo::System;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use hbb_common::{message_proto::CursorData, sysinfo::Pid, ResultType};
use std::sync::{Arc, Mutex};
#[cfg(not(any(target_os = "macos", target_os = "android", target_os = "ios")))]
pub const SERVICE_INTERVAL: u64 = 300;

lazy_static::lazy_static! {
    static ref INSTALLING_SERVICE: Arc<Mutex<bool>>= Default::default();
}

pub fn installing_service() -> bool {
    INSTALLING_SERVICE.lock().unwrap().clone()
}

pub fn is_xfce() -> bool {
    #[cfg(target_os = "linux")]
    {
        return std::env::var_os("XDG_CURRENT_DESKTOP") == Some(std::ffi::OsString::from("XFCE"));
    }
    #[cfg(not(target_os = "linux"))]
    {
        return false;
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn change_resolution(name: &str, width: usize, height: usize) -> ResultType<()> {
    let cur_resolution = current_resolution(name)?;
    // For MacOS
    // to-do: Make sure the following comparison works.
    // For Linux
    // Just run "xrandr", dpi may not be taken into consideration.
    // For Windows
    // dmPelsWidth and dmPelsHeight is the same to width and height
    // Because this process is running in dpi awareness mode.
    if cur_resolution.width as usize == width && cur_resolution.height as usize == height {
        return Ok(());
    }
    hbb_common::log::warn!("Change resolution of '{}' to ({},{})", name, width, height);
    change_resolution_directly(name, width, height)
}

// Android
#[cfg(target_os = "android")]
pub fn get_active_username() -> String {
    // TODO
    "android".into()
}

#[cfg(target_os = "android")]
pub const PA_SAMPLE_RATE: u32 = 48000;

#[cfg(target_os = "android")]
#[derive(Default)]
pub struct WakeLock(Option<android_wakelock::WakeLock>);

#[cfg(target_os = "android")]
impl WakeLock {
    pub fn new(tag: &str) -> Self {
        let tag = format!("{}:{tag}", crate::get_app_name());
        match android_wakelock::partial(tag) {
            Ok(lock) => Self(Some(lock)),
            Err(e) => {
                hbb_common::log::error!("Failed to get wakelock: {e:?}");
                Self::default()
            }
        }
    }
}

#[cfg(not(target_os = "ios"))]
pub fn get_wakelock(_display: bool) -> WakeLock {
    hbb_common::log::info!("new wakelock, require display on: {_display}");
    #[cfg(target_os = "android")]
    return crate::platform::WakeLock::new("server");
    // display: keep screen on
    // idle: keep cpu on
    // sleep: prevent system from sleeping, even manually
    #[cfg(not(target_os = "android"))]
    return crate::platform::WakeLock::new(_display, true, false);
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub(crate) struct InstallingService; // please use new

#[cfg(any(target_os = "windows", target_os = "linux"))]
impl InstallingService {
    pub fn new() -> Self {
        *INSTALLING_SERVICE.lock().unwrap() = true;
        Self
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
impl Drop for InstallingService {
    fn drop(&mut self) {
        *INSTALLING_SERVICE.lock().unwrap() = false;
    }
}

#[cfg(any(target_os = "android", target_os = "ios"))]
#[inline]
pub fn is_prelogin() -> bool {
    false
}

// True on a headless direct-`--server` box that has no console/seat0 user at all — and where none
// will ever arrive — so the connection-manager (`--cm`) and whiteboard subprocesses MUST run as the
// `--server` process owner (the service user) instead of blocking forever on `is_prelogin()` waiting
// for a login that never comes. This is the same "run at the service privilege for the already-CPace-
// authenticated owner" context the terminal (`SelfUser`, R-F1) and screen-capture already use, and it
// keeps file transfer a single full-filesystem mode at that privilege (R-S8).
//
// `is_prelogin()` alone CANNOT drive the wait-vs-proceed decision: it is ALSO true for a desktop
// display-manager greeter, where a real console login is imminent and the existing wait is correct.
// The signal on Linux is an EMPTY active username — logind exposes no usable seat0 session that
// `get_values_of_seat0` reports: either a headless/logind-less host (no console user, and none is
// coming), or a greeter that variant skips (e.g. gdm-Wayland). Proceeding as the service user is the
// correct fail-safe in BOTH cases: strictly better than the old infinite hang, downstream of CPace
// (only the root-entitled authenticated owner ever reaches it), and the `--service` still swaps to the
// per-user server on a real interactive login. An X11 greeter that DOES report a non-empty (`nologin`)
// username still waits via `is_prelogin()`, so an imminent console login is not preempted. This is the
// same signal the headless PeerInfo owner-fallback keys on (`connection.rs`, R-F1); a present console
// user (empty→false) preserves today's run-in-that-user's-session desktop path unchanged.
//
// Windows: always false — the pre-logon SYSTEM session MUST keep waiting; its "No active console
// user" refusal is intended (a file-transfer login there is deliberately not served). macOS: always
// false — a headless Mac and a login-window desktop both report a root-owned `/dev/console`, so they
// are not cheaply distinguishable; preserve the existing wait (macOS headless stays as today rather
// than risk regressing the desktop login-window path).
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn is_headless_no_console_user() -> bool {
    #[cfg(target_os = "linux")]
    {
        get_active_username().is_empty()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

// Note: This method is inefficient on Windows. It will get all the processes.
// It should only be called when performance is not critical.
// If we wanted to get the command line ourselves, there would be a lot of new code.
#[allow(dead_code)]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) fn get_pids_of_process_with_args<S1: AsRef<str>, S2: AsRef<str>>(
    name: S1,
    args: &[S2],
) -> Vec<Pid> {
    let name = name.as_ref().to_lowercase();
    let system = System::new_all();
    system
        .processes()
        .iter()
        .filter(|(_, process)| {
            process.name().to_lowercase() == name
                && process.cmd().len() == args.len() + 1
                && args.iter().enumerate().all(|(i, arg)| {
                    process.cmd()[i + 1].to_lowercase() == arg.as_ref().to_lowercase()
                })
        })
        .map(|(&pid, _)| pid)
        .collect()
}

// Note: This method is inefficient on Windows. It will get all the processes.
// It should only be called when performance is not critical.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn get_pids_of_process_with_first_arg<S1: AsRef<str>, S2: AsRef<str>>(
    name: S1,
    arg: S2,
) -> Vec<Pid> {
    let name = name.as_ref().to_lowercase();
    let system = System::new_all();
    system
        .processes()
        .iter()
        .filter(|(_, process)| {
            process.name().to_lowercase() == name
                && process.cmd().len() >= 2
                && process.cmd()[1].to_lowercase() == arg.as_ref().to_lowercase()
        })
        .map(|(&pid, _)| pid)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_cursor_data() {
        for _ in 0..30 {
            if let Some(hc) = get_cursor().unwrap() {
                let cd = get_cursor_data(hc).unwrap();
                repng::encode(
                    std::fs::File::create("cursor.png").unwrap(),
                    cd.width as _,
                    cd.height as _,
                    &cd.colors[..],
                )
                .unwrap();
            }
            #[cfg(target_os = "macos")]
            macos::is_process_trusted(false);
        }
    }
    #[test]
    fn test_get_cursor_pos() {
        for _ in 0..30 {
            assert!(!get_cursor_pos().is_none());
        }
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn test_resolution() {
        let name = r"\\.\DISPLAY1";
        println!("current:{:?}", current_resolution(name));
        println!("change:{:?}", change_resolution(name, 2880, 1800));
        println!("resolutions:{:?}", resolutions(name));
    }
}
