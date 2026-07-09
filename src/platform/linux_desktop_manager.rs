use super::linux::*;
use crate::client::{
    LOGIN_MSG_DESKTOP_NO_DESKTOP, LOGIN_MSG_DESKTOP_SESSION_NOT_READY,
    LOGIN_MSG_DESKTOP_XORG_NOT_FOUND,
};
use hbb_common::{log, tokio::time};
use std::{
    ffi::OsStr,
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

const XORG_CANDIDATE_PATHS: [&str; 5] = [
    "/usr/libexec/Xorg",
    "/usr/lib/xorg/Xorg",
    "/usr/lib/xorg-server/Xorg",
    "/usr/lib/Xorg",
    "/usr/bin/Xorg",
];
const XSESSIONS_DIR: &str = "/usr/share/xsessions";

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
    if find_xorg_path().is_none() {
        return Some(LOGIN_MSG_DESKTOP_XORG_NOT_FOUND);
    }

    if !has_xsession_desktop_entry() {
        return Some(LOGIN_MSG_DESKTOP_NO_DESKTOP);
    }

    None
}

fn find_xorg_path() -> Option<&'static str> {
    XORG_CANDIDATE_PATHS
        .iter()
        .copied()
        .find(|path| Path::new(path).is_file())
}

fn has_xsession_desktop_entry() -> bool {
    has_xsession_desktop_entry_in(Path::new(XSESSIONS_DIR))
}

fn has_xsession_desktop_entry_in(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_file()
            && entry.path().extension() == Some(OsStr::new("desktop"))
        {
            return true;
        }
    }
    false
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r_s11c10_desktop_manager_xorg_candidates_are_absolute() {
        assert!(XORG_CANDIDATE_PATHS
            .iter()
            .all(|path| Path::new(path).is_absolute()));
        assert!(!XORG_CANDIDATE_PATHS.iter().any(|path| *path == "Xorg"));
    }

    #[test]
    fn r_s11c10_desktop_manager_xsession_entries_are_desktop_files() {
        let dir = std::env::temp_dir().join(format!(
            "rustdesk_xsessions_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();

        std::fs::write(dir.join("README"), "").unwrap();
        assert!(!has_xsession_desktop_entry_in(&dir));

        std::fs::write(dir.join("test.desktop"), "[Desktop Entry]\n").unwrap();
        assert!(has_xsession_desktop_entry_in(&dir));

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
