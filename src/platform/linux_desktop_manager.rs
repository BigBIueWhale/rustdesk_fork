use super::linux::*;
use crate::client::{
    LOGIN_MSG_DESKTOP_NO_DESKTOP, LOGIN_MSG_DESKTOP_SESSION_NOT_READY,
    LOGIN_MSG_DESKTOP_XORG_NOT_FOUND,
};
use hbb_common::{log, tokio::time};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

// R-X14 / R-S18 (Appendix C #17): the os_login -> PAM desktop-session-start is EXCISED. Upstream let a
// network peer's LoginRequest.os_login{username,password} drive a real PAM credential check + session
// setup and a root window-manager-launch script, spawning an X session as an arbitrary OS account — on
// the plaintext direct path this ran BEFORE the password check, making it a remote, rate-limited,
// root-context PAM oracle on an internet-exposed box (a second OS credential the PAKE does not subsume).
// The fork is one always-hardened build (R-R2b), so the ENTIRE X-session-spawn + PAM subsystem is
// removed from the tree, not merely gated: the per-user session starter, the Xorg and window-manager
// launchers, the xauth-cookie writer, the fixed /tmp/.Xauthority fallback, the PAM client, and the
// child-process tracking are all gone. What remains is existing-session DISCOVERY only — the seat0
// capture-session lookup the controlled side needs (R-S14) — which never checks a peer credential and
// never spawns anything. The peer's os_login is ignored.

lazy_static::lazy_static! {
    static ref DESKTOP_RUNNING: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    static ref DESKTOP_MANAGER: Arc<Mutex<Option<DesktopManager>>> = Arc::new(Mutex::new(None));
}

#[derive(Debug)]
struct DesktopManager {
    seat0_username: String,
    seat0_display_server: String,
}

pub fn start_xdesktop() {
    debug_assert!(crate::is_server());
    std::thread::spawn(|| {
        *DESKTOP_MANAGER.lock().unwrap() = Some(DesktopManager::new());

        let interval = time::Duration::from_millis(super::SERVICE_INTERVAL);
        DESKTOP_RUNNING.store(true, Ordering::SeqCst);
        // R-X14: no child X session is ever spawned, so this thread only holds the seat0-discovery
        // manager alive until stop_xdesktop() clears it (no child to monitor).
        while DESKTOP_RUNNING.load(Ordering::SeqCst) {
            std::thread::sleep(interval);
        }
        log::info!("xdesktop discovery thread exit");
    });
}

pub fn stop_xdesktop() {
    DESKTOP_RUNNING.store(false, Ordering::SeqCst);
    *DESKTOP_MANAGER.lock().unwrap() = None;
}

fn detect_headless() -> Option<&'static str> {
    match run_cmds(&format!("which {}", DesktopManager::get_xorg())) {
        Ok(output) => {
            if output.trim().is_empty() {
                return Some(LOGIN_MSG_DESKTOP_XORG_NOT_FOUND);
            }
        }
        _ => {
            return Some(LOGIN_MSG_DESKTOP_XORG_NOT_FOUND);
        }
    }

    match run_cmds("ls /usr/share/xsessions/") {
        Ok(output) => {
            if output.trim().is_empty() {
                return Some(LOGIN_MSG_DESKTOP_NO_DESKTOP);
            }
        }
        _ => {
            return Some(LOGIN_MSG_DESKTOP_NO_DESKTOP);
        }
    }

    None
}

// R-X14: collapsed to existing-session-DISCOVERY only. The peer-supplied os_login is ignored (never
// checked, never used to spawn a session); this only reports whether a usable seat0 desktop session
// exists for the controlled side to capture.
pub fn try_start_desktop(_username: &str, _passsword: &str) -> String {
    debug_assert!(crate::is_server());
    let username = get_username();
    if username.is_empty() {
        if let Some(msg) = detect_headless() {
            msg
        } else {
            LOGIN_MSG_DESKTOP_SESSION_NOT_READY
        }
    } else {
        ""
    }
    .to_owned()
}

#[inline]
pub fn is_headless() -> bool {
    DESKTOP_MANAGER
        .lock()
        .unwrap()
        .as_ref()
        .map_or(false, |manager| {
            manager.get_supported_display_seat0_username().is_none()
        })
}

pub fn get_username() -> String {
    match &*DESKTOP_MANAGER.lock().unwrap() {
        Some(manager) => manager
            .get_supported_display_seat0_username()
            .unwrap_or_default(),
        None => "".to_owned(),
    }
}

impl DesktopManager {
    pub fn new() -> Self {
        let mut seat0_username = "".to_owned();
        let mut seat0_display_server = "".to_owned();
        let seat0_values = get_values_of_seat0(&[0, 2]);
        if !seat0_values[0].is_empty() {
            seat0_username = seat0_values[1].clone();
            seat0_display_server = get_display_server_of_session(&seat0_values[0]);
        }
        Self {
            seat0_username,
            seat0_display_server,
        }
    }

    fn get_supported_display_seat0_username(&self) -> Option<String> {
        if is_gdm_user(&self.seat0_username) && self.seat0_display_server == DISPLAY_SERVER_WAYLAND
        {
            None
        } else if self.seat0_username.is_empty() {
            None
        } else {
            Some(self.seat0_username.clone())
        }
    }

    // Kept for the headless/no-desktop detection above (detect_headless `which Xorg`); never used to
    // spawn an X server (that path is excised, R-X14).
    fn get_xorg() -> &'static str {
        // Fedora 26 or later
        let xorg = "/usr/libexec/Xorg";
        if Path::new(xorg).is_file() {
            return xorg;
        }
        // Debian 9 or later
        let xorg = "/usr/lib/xorg/Xorg";
        if Path::new(xorg).is_file() {
            return xorg;
        }
        // Arch Linux
        let xorg = "/usr/lib/xorg-server/Xorg";
        if Path::new(xorg).is_file() {
            return xorg;
        }
        // Arch Linux
        let xorg = "/usr/lib/Xorg";
        if Path::new(xorg).is_file() {
            return xorg;
        }

        log::warn!("Failed to find xorg, use default Xorg.\n Please add \"allowed_users=anybody\" to \"/etc/X11/Xwrapper.config\".");
        "Xorg"
    }
}
