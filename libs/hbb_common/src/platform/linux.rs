use crate::ResultType;
use std::{
    io,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    process::Command,
};
use users::{get_current_uid, get_effective_uid, get_user_by_uid, os::unix::UserExt};

use sctk::{
    output::OutputData,
    output::{OutputHandler, OutputState},
    reexports::client::protocol::wl_output::WlOutput,
    reexports::client::{globals, Proxy},
    reexports::client::{Connection, QueueHandle},
    registry::{ProvidesRegistryState, RegistryState},
};

lazy_static::lazy_static! {
    pub static ref DISTRO: Distro = Distro::new();
}

const LOGINCTL_PATHS: [&str; 2] = ["/usr/bin/loginctl", "/bin/loginctl"];
const NOTIFY_SEND_PATHS: [&str; 2] = ["/usr/bin/notify-send", "/bin/notify-send"];
const ZENITY_PATHS: [&str; 2] = ["/usr/bin/zenity", "/bin/zenity"];
const KDIALOG_PATHS: [&str; 2] = ["/usr/bin/kdialog", "/bin/kdialog"];
const XMESSAGE_PATHS: [&str; 2] = ["/usr/bin/xmessage", "/bin/xmessage"];

pub const DISPLAY_SERVER_WAYLAND: &str = "wayland";
pub const DISPLAY_SERVER_X11: &str = "x11";
pub const DISPLAY_DESKTOP_KDE: &str = "KDE";

pub const XDG_CURRENT_DESKTOP: &str = "XDG_CURRENT_DESKTOP";

pub struct Distro {
    pub name: String,
    pub version_id: String,
}

impl Distro {
    fn new() -> Self {
        let os_release = std::fs::read_to_string("/etc/os-release")
            .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
            .unwrap_or_default();
        let name = parse_os_release_field(&os_release, "NAME").unwrap_or_default();
        let version_id = parse_os_release_field(&os_release, "VERSION_ID").unwrap_or_default();
        Self { name, version_id }
    }
}

fn parse_os_release_field(contents: &str, key: &str) -> Option<String> {
    let mut value = None;
    for line in contents.lines() {
        if let Some(parsed) = parse_os_release_line(line, key) {
            value = Some(parsed);
        }
    }
    value
}

fn parse_os_release_line(line: &str, key: &str) -> Option<String> {
    let line = line.trim_start();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (line_key, raw_value) = line.split_once('=')?;
    if line_key != key {
        return None;
    }
    Some(unquote_os_release_value(raw_value.trim()))
}

fn unquote_os_release_value(raw: &str) -> String {
    let Some(quote) = raw.chars().next() else {
        return String::new();
    };
    if !matches!(quote, '"' | '\'') || !raw.ends_with(quote) || raw.len() < 2 {
        return raw.to_string();
    }
    unescape_os_release_quoted_value(&raw[1..raw.len() - 1])
}

fn unescape_os_release_quoted_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some(next @ ('$' | '"' | '\'' | '\\' | '`')) => out.push(next),
                Some(next) => {
                    out.push(ch);
                    out.push(next);
                }
                None => out.push(ch),
            }
        } else {
            out.push(ch);
        }
    }
    out
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

fn trusted_command_file(metadata: &std::fs::Metadata) -> bool {
    trusted_command_file_metadata(metadata.is_file(), metadata.uid(), metadata.mode())
}

fn trusted_command_parent(metadata: &std::fs::Metadata) -> bool {
    trusted_command_parent_metadata(metadata.is_dir(), metadata.uid(), metadata.mode())
}

fn trusted_fixed_executable_path(path: &Path) -> Option<PathBuf> {
    if !linux_helper_path_is_clean_absolute(path) {
        return None;
    }
    let candidate_parent = path.parent()?;
    if !trusted_command_parent(&std::fs::metadata(candidate_parent).ok()?) {
        return None;
    }
    let canonical = std::fs::canonicalize(path).ok()?;
    if !linux_helper_path_is_clean_absolute(&canonical) {
        return None;
    }
    let canonical_parent = canonical.parent()?;
    if !trusted_command_parent(&std::fs::metadata(canonical_parent).ok()?) {
        return None;
    }
    if !trusted_command_file(&std::fs::metadata(&canonical).ok()?) {
        return None;
    }
    Some(canonical)
}

fn trusted_command_path(paths: &'static [&'static str]) -> Option<PathBuf> {
    paths
        .iter()
        .find_map(|path| trusted_fixed_executable_path(Path::new(path)))
}

// Deprecated. Use `hbb_common::platform::linux::is_kde_session()` instead for now.
// Or we need to set the correct environment variable in the server process.
#[inline]
pub fn is_kde() -> bool {
    if let Ok(env) = std::env::var(XDG_CURRENT_DESKTOP) {
        env == DISPLAY_DESKTOP_KDE
    } else {
        false
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

fn process_basename(args: &[String]) -> Option<&str> {
    args.first()
        .and_then(|arg0| Path::new(arg0).file_name())
        .and_then(|name| name.to_str())
}

fn process_basename_is_kded(args: &[String]) -> bool {
    let Some(name) = process_basename(args) else {
        return false;
    };
    let Some(suffix) = name.strip_prefix("kded") else {
        return false;
    };
    !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit())
}

// Don't use `hbb_common::platform::linux::is_kde()` here.
// It's not correct in the server process.
pub fn is_kde_session() -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        if proc_entry_pid(&entry).is_none() {
            continue;
        }
        let Some(args) = read_proc_cmdline_args(&entry.path()) else {
            continue;
        };
        if process_basename_is_kded(&args) {
            return true;
        }
    }
    false
}

#[inline]
pub fn is_gdm_user(username: &str) -> bool {
    username == "gdm" || username == "sddm"
    // || username == "lightgdm"
}

#[inline]
pub fn is_desktop_wayland() -> bool {
    get_display_server() == DISPLAY_SERVER_WAYLAND
}

#[inline]
pub fn is_x11_or_headless() -> bool {
    !is_desktop_wayland()
}

pub fn get_display_server() -> String {
    // R-X12 (§8): the display server is COMPILE-PINNED to X11 — a constant, not a
    // runtime probe. This fork is X11-only (the Wayland/pipewire capture path is
    // compiled out and is_x11() is a pinned `true`), so "what display server is
    // this?" has exactly one answer on every shipped binary. The earlier R-X12
    // change removed the forced-display-server env override but left THIS function
    // still probing (loginctl, with a stray session-type fallback) — a half-measure
    // that did NOT deliver R-X12's stated promise, because the session-admission
    // gate (server::connection, "Unsupported display server type") and
    // ui_interface::get_error() consult THIS function, not is_x11(). A
    // seatless/container session whose environment leaked a non-x11 type could
    // therefore still refuse an incoming connection outright — the exact failure
    // R-X12 says the x11 pin eliminates ("determinism a property of the binary, so
    // no operator ever needs the env override"). Pinning the *answer* (mirroring the
    // is_x11() pin) closes it for every caller. Per-session queries that legitimately
    // concern OTHER seats keep their own runtime path, which is unaffected.
    DISPLAY_SERVER_X11.to_owned()
}

pub fn get_display_server_of_session(session: &str) -> String {
    let mut display_server = if let Ok(output) =
        run_loginctl(Some(vec!["show-session", "-p", "Type", session]))
    // Check session type of the session
    {
        String::from_utf8_lossy(&output.stdout)
            .replace("Type=", "")
            .trim_end()
            .into()
    } else {
        "".to_owned()
    };
    if display_server.is_empty() || display_server == "tty" || display_server == "unspecified" {
        if let Ok(sestype) = std::env::var("XDG_SESSION_TYPE") {
            if !sestype.is_empty() {
                return sestype.to_lowercase();
            }
        }
        display_server = "x11".to_owned();
    }
    display_server.to_lowercase()
}

#[inline]
fn line_values(indices: &[usize], line: &str) -> Vec<String> {
    indices
        .into_iter()
        .map(|idx| line.split_whitespace().nth(*idx).unwrap_or("").to_owned())
        .collect::<Vec<String>>()
}

#[inline]
pub fn get_values_of_seat0(indices: &[usize]) -> Vec<String> {
    _get_values_of_seat0(indices, true)
}

#[inline]
pub fn get_values_of_seat0_with_gdm_wayland(indices: &[usize]) -> Vec<String> {
    _get_values_of_seat0(indices, false)
}

// Ignore "3 sessions listed."
fn ignore_loginctl_line(line: &str) -> bool {
    line.contains("sessions") || line.split(" ").count() < 4
}

fn _get_values_of_seat0(indices: &[usize], ignore_gdm_wayland: bool) -> Vec<String> {
    if let Ok(output) = run_loginctl(None) {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if ignore_loginctl_line(line) {
                continue;
            }
            if line.contains("seat0") {
                if let Some(sid) = line.split_whitespace().next() {
                    if is_active(sid) {
                        if ignore_gdm_wayland {
                            if is_gdm_user(line.split_whitespace().nth(2).unwrap_or(""))
                                && get_display_server_of_session(sid) == DISPLAY_SERVER_WAYLAND
                            {
                                continue;
                            }
                        }
                        return line_values(indices, line);
                    }
                }
            }
        }

        // some case, there is no seat0 https://github.com/rustdesk/rustdesk/issues/73
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if ignore_loginctl_line(line) {
                continue;
            }
            if let Some(sid) = line.split_whitespace().next() {
                if is_active(sid) {
                    let d = get_display_server_of_session(sid);
                    if ignore_gdm_wayland {
                        if is_gdm_user(line.split_whitespace().nth(2).unwrap_or(""))
                            && d == DISPLAY_SERVER_WAYLAND
                        {
                            continue;
                        }
                    }
                    if d == "tty" || d == "unspecified" {
                        continue;
                    }
                    return line_values(indices, line);
                }
            }
        }
    }

    line_values(indices, "")
}

pub fn is_active(sid: &str) -> bool {
    if let Ok(output) = run_loginctl(Some(vec!["show-session", "-p", "State", sid])) {
        String::from_utf8_lossy(&output.stdout).contains("active")
    } else {
        false
    }
}

pub fn is_active_and_seat0(sid: &str) -> bool {
    if let Ok(output) = run_loginctl(Some(vec!["show-session", sid])) {
        String::from_utf8_lossy(&output.stdout).contains("State=active")
            && String::from_utf8_lossy(&output.stdout).contains("Seat=seat0")
    } else {
        false
    }
}

// Check both "Lock" and "Switch user"
pub fn is_session_locked(sid: &str) -> bool {
    if let Ok(output) = run_loginctl(Some(vec!["show-session", sid, "--property=LockedHint"])) {
        String::from_utf8_lossy(&output.stdout).contains("LockedHint=yes")
    } else {
        false
    }
}

fn run_loginctl(args: Option<Vec<&str>>) -> std::io::Result<std::process::Output> {
    let Some(loginctl) = trusted_command_path(&LOGINCTL_PATHS) else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "loginctl was not found at a trusted fixed path",
        ));
    };
    let mut cmd = std::process::Command::new(loginctl);
    if let Some(a) = args {
        return cmd.args(a).output();
    }
    cmd.output()
}

fn spawn_message_command(paths: &'static [&'static str], args: &[&str]) -> bool {
    let Some(command) = trusted_command_path(paths) else {
        return false;
    };
    Command::new(command).args(args).spawn().is_ok()
}

/// forever: may not work
#[cfg(target_os = "linux")]
pub fn system_message(title: &str, msg: &str, forever: bool) -> ResultType<()> {
    let timeout = if forever { "0" } else { "3" };
    if spawn_message_command(&NOTIFY_SEND_PATHS, &[title, msg])
        || spawn_message_command(
            &ZENITY_PATHS,
            &[
                "--info",
                "--timeout",
                timeout,
                "--title",
                title,
                "--text",
                msg,
            ],
        )
        || spawn_message_command(&KDIALOG_PATHS, &["--title", title, "--msgbox", msg])
        || spawn_message_command(
            &XMESSAGE_PATHS,
            &["-center", "-timeout", timeout, title, msg],
        )
    {
        return Ok(());
    }
    crate::bail!("failed to post system message");
}

#[derive(Debug, Clone)]
pub struct WaylandDisplayInfo {
    pub name: String,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub logical_size: Option<(i32, i32)>,
    pub refresh_rate: i32,
}

// Retrieves information about all connected displays via the Wayland protocol.
pub fn get_wayland_displays() -> ResultType<Vec<WaylandDisplayInfo>> {
    struct WaylandEnv {
        registry_state: RegistryState,
        output_state: OutputState,
    }

    impl OutputHandler for WaylandEnv {
        fn output_state(&mut self) -> &mut OutputState {
            &mut self.output_state
        }

        fn new_output(&mut self, _: &Connection, _: &QueueHandle<Self>, _: WlOutput) {}
        fn update_output(&mut self, _: &Connection, _: &QueueHandle<Self>, _: WlOutput) {}
        fn output_destroyed(&mut self, _: &Connection, _: &QueueHandle<Self>, _: WlOutput) {}
    }

    impl ProvidesRegistryState for WaylandEnv {
        fn registry(&mut self) -> &mut RegistryState {
            &mut self.registry_state
        }

        sctk::registry_handlers!();
    }

    sctk::delegate_output!(WaylandEnv);
    sctk::delegate_registry!(WaylandEnv);

    let conn = Connection::connect_to_env()?;
    let (globals, mut event_queue) = globals::registry_queue_init(&conn)?;
    let queue_handle = event_queue.handle();

    let registry_state = RegistryState::new(&globals);
    let output_state = OutputState::new(&globals, &queue_handle);

    let mut environment = WaylandEnv {
        registry_state,
        output_state,
    };

    event_queue.roundtrip(&mut environment)?;

    let outputs: Vec<_> = environment.output_state.outputs().collect();
    let mut display_infos = Vec::new();

    for output in outputs {
        if let Some(output_data) = output.data::<OutputData>() {
            output_data.with_output_info(|info| {
                if let Some(mode) = info.modes.iter().find(|m| m.current) {
                    let (x, y) = info.location;
                    let (width, height) = mode.dimensions;
                    let refresh_rate = mode.refresh_rate;
                    let name = info.name.clone().unwrap_or_default();
                    let logical_size = info.logical_size;
                    display_infos.push(WaylandDisplayInfo {
                        name,
                        x,
                        y,
                        width,
                        height,
                        logical_size,
                        refresh_rate,
                    });
                }
            });
        }
    }

    Ok(display_infos)
}

/// Get the current user's home directory via getpwuid (trusted source).
///
/// This function uses the system's password database (via `getpwuid`) to retrieve
/// the home directory, avoiding the security risk of relying on the `HOME`
/// environment variable which can be manipulated by untrusted input.
///
/// # Returns
/// - `Some(PathBuf)` if the home directory was found and exists
/// - `None` if the user lookup failed or the directory doesn't exist
///
/// # Security
/// This function is designed to be safe against confused-deputy attacks where
/// an attacker might manipulate environment variables to influence privileged
/// operations.
fn get_home_dir_for_uid_trusted(uid: libc::uid_t) -> Option<PathBuf> {
    match get_user_by_uid(uid) {
        Some(user) => {
            let home = user.home_dir();
            if Path::is_dir(home) {
                Some(PathBuf::from(home))
            } else {
                log::warn!(
                    "Home directory for uid {} does not exist or is not a directory: {:?}",
                    uid,
                    home
                );
                None
            }
        }
        None => {
            log::warn!("Failed to get user info for uid {}", uid);
            None
        }
    }
}

pub fn get_home_dir_trusted() -> Option<PathBuf> {
    get_home_dir_for_uid_trusted(get_current_uid())
}

/// Get the effective user's existing home directory from the password database.
///
/// Service-owned roles use effective authority, so their configuration namespace
/// must follow `geteuid` rather than the invoking process's real uid.
pub fn get_effective_home_dir_trusted() -> Option<PathBuf> {
    get_home_dir_for_uid_trusted(get_effective_uid())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r_s11c10m_command_candidates_are_fixed_absolute_paths() {
        for path in LOGINCTL_PATHS
            .iter()
            .chain(NOTIFY_SEND_PATHS.iter())
            .chain(ZENITY_PATHS.iter())
            .chain(KDIALOG_PATHS.iter())
            .chain(XMESSAGE_PATHS.iter())
        {
            assert!(Path::new(path).is_absolute(), "{} is not absolute", path);
            assert!(!path.contains(".."), "{} contains parent traversal", path);
        }
    }

    #[test]
    fn r_s11c10m_command_resolver_rejects_relative_and_missing_paths() {
        assert_eq!(trusted_command_path(&["loginctl"]), None);
        assert_eq!(trusted_command_path(&["/usr/bin/../bin/loginctl"]), None);
        assert_eq!(
            trusted_command_path(&["/definitely/not/rustdesk/loginctl"]),
            None
        );
    }

    #[test]
    fn r_s11c10m_command_metadata_requires_root_unwritable_executable() {
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
    fn r_s11c10_kde_session_matcher_is_process_basename_only() {
        let kded5 = vec!["/usr/bin/kded5".to_owned()];
        let kded6 = vec!["kded6".to_owned(), "--replace".to_owned()];
        assert!(process_basename_is_kded(&kded5));
        assert!(process_basename_is_kded(&kded6));

        let bare = vec!["/usr/bin/kded".to_owned()];
        let non_numeric = vec!["/usr/bin/kdedx".to_owned()];
        let helper = vec!["/usr/bin/kded5-helper".to_owned()];
        let grep = vec!["/usr/bin/grep".to_owned(), "kded5".to_owned()];
        assert!(!process_basename_is_kded(&bare));
        assert!(!process_basename_is_kded(&non_numeric));
        assert!(!process_basename_is_kded(&helper));
        assert!(!process_basename_is_kded(&grep));
    }

    #[test]
    fn r_s11c10_os_release_parser_handles_shell_compatible_assignments() {
        let contents = r#"
# ignored
NAME="Ubuntu"
VERSION_ID='24.04'
PRETTY_NAME="Ubuntu 24.04 LTS"
NAME="Debian GNU/Linux"
ESCAPED="quote \" dollar \$ slash \\ tick \`"
"#;

        assert_eq!(
            parse_os_release_field(contents, "NAME").as_deref(),
            Some("Debian GNU/Linux")
        );
        assert_eq!(
            parse_os_release_field(contents, "VERSION_ID").as_deref(),
            Some("24.04")
        );
        assert_eq!(
            parse_os_release_field(contents, "PRETTY_NAME").as_deref(),
            Some("Ubuntu 24.04 LTS")
        );
        assert_eq!(
            parse_os_release_field(contents, "ESCAPED").as_deref(),
            Some("quote \" dollar $ slash \\ tick `")
        );
        assert_eq!(parse_os_release_field(contents, "ID"), None);
    }

    #[test]
    fn r_s11c10_os_release_parser_leaves_unquoted_values_as_data() {
        let contents = "ID=ubuntu\nVERSION_ID=24.04\nBAD LINE\nHASH=value#not-comment\n";

        assert_eq!(
            parse_os_release_field(contents, "ID").as_deref(),
            Some("ubuntu")
        );
        assert_eq!(
            parse_os_release_field(contents, "VERSION_ID").as_deref(),
            Some("24.04")
        );
        assert_eq!(
            parse_os_release_field(contents, "HASH").as_deref(),
            Some("value#not-comment")
        );
    }

    /// Test get_home_dir_trusted: returns valid path and ignores HOME env var
    #[test]
    fn test_get_home_dir_trusted() {
        let original_home = std::env::var("HOME").ok();

        // Set HOME to a fake/malicious path
        std::env::set_var("HOME", "/tmp/fake_malicious_home");
        let result = get_home_dir_trusted();

        // Restore original HOME
        match original_home {
            Some(home) => std::env::set_var("HOME", home),
            None => std::env::remove_var("HOME"),
        }

        // Verify: returns valid path that is NOT the fake HOME
        if let Some(path) = result {
            assert!(path.is_absolute(), "Path should be absolute: {:?}", path);
            assert!(path.is_dir(), "Path should be a directory: {:?}", path);
            assert_ne!(
                path.to_string_lossy(),
                "/tmp/fake_malicious_home",
                "Should not use HOME env var"
            );
        }
    }

    #[test]
    fn linux_service_owned_config_root_effective_home_uses_euid() {
        let expected = get_user_by_uid(get_effective_uid()).and_then(|user| {
            let home = PathBuf::from(user.home_dir());
            home.is_dir().then_some(home)
        });

        assert_eq!(get_effective_home_dir_trusted(), expected);
    }
}
