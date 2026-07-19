use crate::ResultType;
use std::{
    io,
    os::{
        fd::RawFd,
        unix::{fs::MetadataExt, process::CommandExt},
    },
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

fn linux_descriptor_upper_bound() -> io::Result<RawFd> {
    let raw = std::fs::read_to_string("/proc/sys/fs/nr_open")?;
    let value = raw.trim_end_matches('\n');
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Linux descriptor-table bound is not canonical decimal",
        ));
    }
    let descriptor_limit = value.parse::<RawFd>().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Linux descriptor-table bound is invalid: {err}"),
        )
    })?;
    let last_fd = descriptor_limit.checked_sub(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Linux descriptor-table bound has no valid descriptor",
        )
    })?;
    if last_fd <= libc::STDERR_FILENO {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Linux descriptor-table bound does not cover non-stdio descriptors",
        ));
    }
    Ok(last_fd)
}

fn validated_nonstdio_descriptor_allowlist(
    descriptors: &[RawFd],
    last_fd: RawFd,
) -> io::Result<Vec<RawFd>> {
    let mut validated = Vec::with_capacity(descriptors.len());
    for &fd in descriptors {
        if fd <= libc::STDERR_FILENO || fd > last_fd {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("allowed child descriptor {fd} is outside the non-stdio descriptor range"),
            ));
        }
        if validated.contains(&fd) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("allowed child descriptor {fd} is duplicated"),
            ));
        }
        validated.push(fd);
    }
    Ok(validated)
}

fn set_descriptor_close_on_exec(fd: RawFd, enabled: bool) -> io::Result<()> {
    let descriptor_flags = unsafe { libc::syscall(libc::SYS_fcntl, fd, libc::F_GETFD) };
    if descriptor_flags == -1 {
        return Err(io::Error::last_os_error());
    }
    let close_on_exec = libc::c_long::from(libc::FD_CLOEXEC);
    let new_flags = if enabled {
        descriptor_flags | close_on_exec
    } else {
        descriptor_flags & !close_on_exec
    };
    if new_flags != descriptor_flags
        && unsafe { libc::syscall(libc::SYS_fcntl, fd, libc::F_SETFD, new_flags) } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn mark_nonstdio_descriptors_close_on_exec(last_fd: RawFd) -> io::Result<()> {
    if unsafe {
        libc::syscall(
            libc::SYS_close_range,
            (libc::STDERR_FILENO + 1) as libc::c_uint,
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    } == 0
    {
        return Ok(());
    }

    for fd in (libc::STDERR_FILENO + 1)..=last_fd {
        match set_descriptor_close_on_exec(fd, true) {
            Ok(()) => {}
            Err(err) if err.raw_os_error() == Some(libc::EBADF) => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// Constrain a Linux child image to stdio plus an explicit non-stdio descriptor allowlist.
///
/// All allocation and `/proc` parsing happens in the parent. The pre-exec hook uses only raw
/// descriptor syscalls, first marking every non-stdio descriptor close-on-exec and then clearing
/// that flag only for the descriptors named by the caller.
pub fn configure_command_descriptor_allowlist_on_exec(
    command: &mut Command,
    allowed_nonstdio_descriptors: &[RawFd],
) -> io::Result<()> {
    let last_fd = linux_descriptor_upper_bound()?;
    let allowed_nonstdio_descriptors =
        validated_nonstdio_descriptor_allowlist(allowed_nonstdio_descriptors, last_fd)?;
    unsafe {
        command.pre_exec(move || {
            mark_nonstdio_descriptors_close_on_exec(last_fd)?;
            for &fd in &allowed_nonstdio_descriptors {
                set_descriptor_close_on_exec(fd, false)?;
            }
            Ok(())
        });
    }
    Ok(())
}

/// Constrain a Linux child image to argv, environment, and stdio only.
pub fn configure_command_close_nonstdio_on_exec(command: &mut Command) -> io::Result<()> {
    configure_command_descriptor_allowlist_on_exec(command, &[])
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
    let display_server = loginctl_session_properties(session, &[LoginctlProperty::Type])
        .ok()
        .and_then(|mut values| values.pop());
    normalize_session_display_server(display_server.as_deref())
}

fn parse_local_x_display_name(display: &str) -> Option<(u32, Option<u32>)> {
    let rest = display.strip_prefix(':')?;
    let mut components = rest.split('.');
    let display_number = components.next()?.parse::<u32>().ok()?;
    let screen_number = match (components.next(), components.next()) {
        (None, None) => None,
        (Some(screen), None) => Some(screen.parse::<u32>().ok()?),
        _ => return None,
    };
    if rest.is_empty()
        || rest.starts_with('.')
        || rest
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && byte != b'.')
    {
        return None;
    }
    Some((display_number, screen_number))
}

pub fn normalize_local_x_display_name(display: &str) -> Option<String> {
    let (display_number, screen_number) = parse_local_x_display_name(display)?;
    Some(match screen_number {
        Some(screen_number) => format!(":{display_number}.{screen_number}"),
        None => format!(":{display_number}"),
    })
}

pub fn local_x_display_names_share_server(left: &str, right: &str) -> bool {
    matches!(
        (
            parse_local_x_display_name(left),
            parse_local_x_display_name(right)
        ),
        (Some((left, _)), Some((right, _))) if left == right
    )
}

pub fn get_x11_display_of_session(session: &str) -> Option<String> {
    loginctl_session_properties(session, &[LoginctlProperty::Display])
        .ok()
        .and_then(|mut values| values.pop())
        .and_then(|display| normalize_local_x_display_name(&display))
}

#[inline]
fn session_values(indices: &[usize], session: Option<&LoginctlSession>) -> Vec<String> {
    indices
        .into_iter()
        .map(|idx| {
            let Some(session) = session else {
                return String::new();
            };
            match idx {
                0 => session.id.clone(),
                1 => session.uid.clone(),
                2 => session.username.clone(),
                3 => session.seat.clone(),
                _ => String::new(),
            }
        })
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

fn _get_values_of_seat0(indices: &[usize], ignore_gdm_wayland: bool) -> Vec<String> {
    if let Ok(sessions) = loginctl_sessions() {
        for session in &sessions {
            if session.seat == "seat0" && is_active(&session.id) {
                if ignore_gdm_wayland
                    && is_gdm_user(&session.username)
                    && get_display_server_of_session(&session.id) == DISPLAY_SERVER_WAYLAND
                {
                    continue;
                }
                return session_values(indices, Some(session));
            }
        }

        // some case, there is no seat0 https://github.com/rustdesk/rustdesk/issues/73
        for session in &sessions {
            if is_active(&session.id) {
                let display_server = get_display_server_of_session(&session.id);
                if ignore_gdm_wayland
                    && is_gdm_user(&session.username)
                    && display_server == DISPLAY_SERVER_WAYLAND
                {
                    continue;
                }
                if display_server == "tty" || display_server == "unspecified" {
                    continue;
                }
                return session_values(indices, Some(session));
            }
        }
    }

    session_values(indices, None)
}

pub fn is_active(sid: &str) -> bool {
    matches!(
        loginctl_session_properties(sid, &[LoginctlProperty::State]).as_deref(),
        Ok([state]) if state == "active"
    )
}

pub fn is_active_and_seat0(sid: &str) -> bool {
    matches!(
        loginctl_session_properties(
            sid,
            &[LoginctlProperty::State, LoginctlProperty::Seat],
        )
        .as_deref(),
        Ok([state, seat]) if state == "active" && seat == "seat0"
    )
}

// Check both "Lock" and "Switch user"
pub fn is_session_locked(sid: &str) -> bool {
    matches!(
        loginctl_session_properties(sid, &[LoginctlProperty::LockedHint]).as_deref(),
        Ok([locked]) if locked == "yes"
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoginctlProperty {
    Display,
    LockedHint,
    Seat,
    State,
    Type,
}

impl LoginctlProperty {
    fn name(self) -> &'static str {
        match self {
            Self::Display => "Display",
            Self::LockedHint => "LockedHint",
            Self::Seat => "Seat",
            Self::State => "State",
            Self::Type => "Type",
        }
    }

    fn argument(self) -> &'static str {
        match self {
            Self::Display => "--property=Display",
            Self::LockedHint => "--property=LockedHint",
            Self::Seat => "--property=Seat",
            Self::State => "--property=State",
            Self::Type => "--property=Type",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct LoginctlSession {
    id: String,
    uid: String,
    username: String,
    seat: String,
}

enum LoginctlQuery<'a> {
    ListSessions,
    SessionProperties {
        session: &'a str,
        properties: &'a [LoginctlProperty],
    },
}

impl LoginctlQuery<'_> {
    fn arguments(&self) -> Vec<&str> {
        match self {
            Self::ListSessions => vec!["--no-pager", "--no-legend", "list-sessions"],
            Self::SessionProperties {
                session,
                properties,
            } => {
                let mut arguments = Vec::with_capacity(properties.len() + 4);
                arguments.push("--no-pager");
                arguments.extend(properties.iter().map(|property| property.argument()));
                arguments.push("show-session");
                arguments.push("--");
                arguments.push(session);
                arguments
            }
        }
    }
}

fn normalize_session_display_server(display_server: Option<&str>) -> String {
    let display_server = display_server.map(str::to_ascii_lowercase);
    match display_server.as_deref() {
        Some(display_server)
            if !display_server.is_empty()
                && display_server != "tty"
                && display_server != "unspecified" =>
        {
            display_server.to_owned()
        }
        _ => DISPLAY_SERVER_X11.to_owned(),
    }
}

fn invalid_loginctl_output(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn parse_loginctl_sessions(stdout: &[u8]) -> io::Result<Vec<LoginctlSession>> {
    let stdout = std::str::from_utf8(stdout)
        .map_err(|_| invalid_loginctl_output("loginctl session list is not UTF-8"))?;
    let mut sessions = Vec::new();
    for line in stdout.lines() {
        if line.is_empty() {
            return Err(invalid_loginctl_output(
                "loginctl session list contains an empty row",
            ));
        }
        // The first four fields are the session authority consumed here. systemd 252
        // appends TTY, while newer versions append further presentation fields.
        let mut fields = line.split_ascii_whitespace();
        let Some(id) = fields.next() else {
            return Err(invalid_loginctl_output(
                "loginctl session row has no identifier",
            ));
        };
        let Some(uid) = fields.next() else {
            return Err(invalid_loginctl_output("loginctl session row has no uid"));
        };
        let Some(username) = fields.next() else {
            return Err(invalid_loginctl_output(
                "loginctl session row has no username",
            ));
        };
        let Some(seat) = fields.next() else {
            return Err(invalid_loginctl_output("loginctl session row has no seat"));
        };
        let parsed_uid = uid
            .parse::<u32>()
            .map_err(|_| invalid_loginctl_output("loginctl session uid is not decimal"))?;
        if parsed_uid.to_string() != uid {
            return Err(invalid_loginctl_output(
                "loginctl session uid is not canonical decimal",
            ));
        }
        sessions.push(LoginctlSession {
            id: id.to_owned(),
            uid: uid.to_owned(),
            username: username.to_owned(),
            seat: seat.to_owned(),
        });
    }
    Ok(sessions)
}

fn parse_loginctl_session_properties(
    stdout: &[u8],
    properties: &[LoginctlProperty],
) -> io::Result<Vec<String>> {
    if properties.is_empty() {
        return Err(invalid_loginctl_output(
            "loginctl property query has no properties",
        ));
    }
    let stdout = std::str::from_utf8(stdout)
        .map_err(|_| invalid_loginctl_output("loginctl property output is not UTF-8"))?;
    let mut values = vec![None; properties.len()];
    for line in stdout.lines() {
        let Some((name, value)) = line.split_once('=') else {
            return Err(invalid_loginctl_output(
                "loginctl property row has no separator",
            ));
        };
        if value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(invalid_loginctl_output(
                "loginctl property value contains control bytes",
            ));
        }
        let Some(index) = properties
            .iter()
            .position(|property| property.name() == name)
        else {
            return Err(invalid_loginctl_output(
                "loginctl returned an unrequested property",
            ));
        };
        if values[index].replace(value.to_owned()).is_some() {
            return Err(invalid_loginctl_output(
                "loginctl returned a duplicate property",
            ));
        }
    }
    let mut parsed = Vec::with_capacity(values.len());
    for value in values {
        let Some(value) = value else {
            return Err(invalid_loginctl_output(
                "loginctl omitted a requested property",
            ));
        };
        parsed.push(value);
    }
    Ok(parsed)
}

fn loginctl_sessions() -> io::Result<Vec<LoginctlSession>> {
    let output = run_loginctl(LoginctlQuery::ListSessions)?;
    parse_loginctl_sessions(&output.stdout)
}

fn loginctl_session_properties(
    session: &str,
    properties: &[LoginctlProperty],
) -> io::Result<Vec<String>> {
    if session.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "loginctl session identifier is empty",
        ));
    }
    let output = run_loginctl(LoginctlQuery::SessionProperties {
        session,
        properties,
    })?;
    parse_loginctl_session_properties(&output.stdout, properties)
}

fn configure_loginctl_environment(command: &mut Command) {
    command.env_clear();
}

fn run_loginctl(query: LoginctlQuery<'_>) -> std::io::Result<std::process::Output> {
    let Some(loginctl) = trusted_command_path(&LOGINCTL_PATHS) else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "loginctl was not found at a trusted fixed path",
        ));
    };
    let mut cmd = std::process::Command::new(loginctl);
    configure_loginctl_environment(&mut cmd);
    cmd.args(query.arguments());
    configure_command_close_nonstdio_on_exec(&mut cmd)?;
    let output = cmd.output()?;
    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("loginctl query failed with {}", output.status),
        ));
    }
    Ok(output)
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
    fn r_s11e40_loginctl_queries_are_typed_and_noninteractive() {
        assert_eq!(
            LoginctlQuery::ListSessions.arguments(),
            ["--no-pager", "--no-legend", "list-sessions"]
        );
        assert_eq!(
            LoginctlQuery::SessionProperties {
                session: "c7",
                properties: &[LoginctlProperty::Display],
            }
            .arguments(),
            [
                "--no-pager",
                "--property=Display",
                "show-session",
                "--",
                "c7",
            ]
        );
        assert_eq!(
            LoginctlQuery::SessionProperties {
                session: "c7",
                properties: &[LoginctlProperty::State, LoginctlProperty::Seat],
            }
            .arguments(),
            [
                "--no-pager",
                "--property=State",
                "--property=Seat",
                "show-session",
                "--",
                "c7",
            ]
        );
    }

    #[test]
    fn r_s11e40_loginctl_session_list_parser_validates_stable_leading_fields() {
        assert_eq!(
            parse_loginctl_sessions(b"1 1000 owner seat0 tty2\nc4 1001 other - -\n").unwrap(),
            vec![
                LoginctlSession {
                    id: "1".to_owned(),
                    uid: "1000".to_owned(),
                    username: "owner".to_owned(),
                    seat: "seat0".to_owned(),
                },
                LoginctlSession {
                    id: "c4".to_owned(),
                    uid: "1001".to_owned(),
                    username: "other".to_owned(),
                    seat: "-".to_owned(),
                },
            ]
        );
        assert!(
            parse_loginctl_sessions(b"SESSION UID USER SEAT TTY\n1 1000 owner seat0 tty2\n")
                .is_err()
        );
        assert!(parse_loginctl_sessions(b"1 01000 owner seat0 tty2\n").is_err());
        let current = parse_loginctl_sessions(b"7 1000 owner seat0 1234 user tty2 no -\n").unwrap();
        assert_eq!(current[0].id, "7");
        assert_eq!(current[0].seat, "seat0");
        let ambiguous = parse_loginctl_sessions(b"1 1000 seat0-owner - tty2\n").unwrap();
        assert_eq!(ambiguous[0].username, "seat0-owner");
        assert_eq!(ambiguous[0].seat, "-");
    }

    #[test]
    fn r_s11e40_loginctl_property_parser_requires_exact_requested_rows() {
        let properties = [LoginctlProperty::State, LoginctlProperty::Seat];
        assert_eq!(
            parse_loginctl_session_properties(b"Seat=seat0\nState=active\n", &properties).unwrap(),
            ["active", "seat0"]
        );
        let inactive =
            parse_loginctl_session_properties(b"State=inactive\n", &[LoginctlProperty::State])
                .unwrap();
        assert_ne!(inactive.as_slice(), ["active"]);
        assert!(parse_loginctl_session_properties(b"State=active\n", &properties).is_err());
        assert!(parse_loginctl_session_properties(
            b"State=active\nState=closing\n",
            &[LoginctlProperty::State],
        )
        .is_err());
        assert!(parse_loginctl_session_properties(
            b"State=active\nType=x11\n",
            &[LoginctlProperty::State],
        )
        .is_err());
    }

    #[test]
    fn r_s11e42_x11_display_names_are_local_and_canonical() {
        assert_eq!(normalize_local_x_display_name(":0").as_deref(), Some(":0"));
        assert_eq!(
            normalize_local_x_display_name(":0007.02").as_deref(),
            Some(":7.2")
        );
        assert!(local_x_display_names_share_server(":7", ":0007.02"));
        assert!(!local_x_display_names_share_server(":7", ":8"));
        for invalid in [
            "",
            ":",
            ":.0",
            ":0.",
            ":0.1.2",
            ":-1",
            ":+1",
            ":one",
            "localhost:0",
            "host:0",
            "unix/:0",
            " :0",
            ":0 ",
        ] {
            assert_eq!(
                normalize_local_x_display_name(invalid),
                None,
                "accepted {invalid:?}"
            );
        }
        assert_eq!(
            parse_loginctl_session_properties(b"Display=:17.0\n", &[LoginctlProperty::Display])
                .unwrap(),
            [":17.0"]
        );
    }

    #[test]
    fn r_s11e40_session_display_fallback_is_binary_owned() {
        assert_eq!(normalize_session_display_server(None), DISPLAY_SERVER_X11);
        assert_eq!(
            normalize_session_display_server(Some("")),
            DISPLAY_SERVER_X11
        );
        assert_eq!(
            normalize_session_display_server(Some("tty")),
            DISPLAY_SERVER_X11
        );
        assert_eq!(
            normalize_session_display_server(Some("unspecified")),
            DISPLAY_SERVER_X11
        );
        assert_eq!(
            normalize_session_display_server(Some("WAYLAND")),
            DISPLAY_SERVER_WAYLAND
        );
    }

    #[test]
    fn r_s11e40_loginctl_child_excludes_inherited_environment() {
        const ROLE: &str = "RUSTDESK_TEST_LOGINCTL_ENVIRONMENT_ROLE";
        const HOSTILE_BUS: &str = "unix:path=/tmp/rustdesk-hostile-loginctl-system-bus";
        const TEST_NAME: &str =
            "platform::linux::tests::r_s11e40_loginctl_child_excludes_inherited_environment";

        match std::env::var(ROLE).as_deref() {
            Ok("launcher") => {
                assert_eq!(
                    std::env::var("DBUS_SYSTEM_BUS_ADDRESS").as_deref(),
                    Ok(HOSTILE_BUS)
                );
                assert_eq!(std::env::var("SYSTEMD_PAGER").as_deref(), Ok("/bin/sh"));
                assert_eq!(std::env::var("XDG_SESSION_TYPE").as_deref(), Ok("wayland"));
                let mut worker = Command::new(std::env::current_exe().unwrap());
                configure_loginctl_environment(&mut worker);
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
                    "SYSTEMD_PAGER",
                    "XDG_SESSION_TYPE",
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
                    .env("SYSTEMD_PAGER", "/bin/sh")
                    .env("XDG_SESSION_TYPE", "wayland")
                    .args(["--exact", TEST_NAME, "--nocapture"])
                    .status()
                    .unwrap();
                assert!(status.success());
            }
        }
    }

    #[test]
    fn r_s11c10m_command_candidates_are_fixed_absolute_paths() {
        for path in LOGINCTL_PATHS.iter() {
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

    #[test]
    fn r_s11e32_linux_command_descriptor_allowlist_is_exact() {
        use std::{
            fs::{self, OpenOptions},
            os::unix::fs::MetadataExt,
        };

        const ROLE_ENV: &str = "RUSTDESK_COMMAND_DESCRIPTOR_TEST_ROLE";
        const TARGET_ENV: &str = "RUSTDESK_COMMAND_DESCRIPTOR_TEST_TARGET";
        const TEST_NAME: &str =
            "platform::linux::tests::r_s11e32_linux_command_descriptor_allowlist_is_exact";

        let descriptor_for_target = || {
            let target_path = std::env::var_os(TARGET_ENV)
                .map(PathBuf::from)
                .expect("target path must be supplied by the parent test");
            let target = fs::metadata(&target_path).expect("target metadata must be readable");
            for entry in
                fs::read_dir("/proc/self/fd").expect("descriptor test proc directory must exist")
            {
                let entry = entry.expect("descriptor test proc entry must be readable");
                let Ok(metadata) = fs::metadata(entry.path()) else {
                    continue;
                };
                if metadata.dev() == target.dev() && metadata.ino() == target.ino() {
                    return Some(entry.file_name());
                }
            }
            None
        };

        match std::env::var(ROLE_ENV).as_deref() {
            Ok("allowed") => {
                assert_eq!(
                    descriptor_for_target().as_deref(),
                    Some(std::ffi::OsStr::new("9")),
                    "explicitly allowed descriptor must survive as the exact kernel object"
                );
                return;
            }
            Ok("closed") => {
                let inherited = descriptor_for_target();
                assert!(
                    inherited.is_none(),
                    "default helper contract retained the launcher's descriptor as {:?}",
                    inherited
                );
                return;
            }
            Ok("launcher") => {
                assert_eq!(
                    descriptor_for_target().as_deref(),
                    Some(std::ffi::OsStr::new("9")),
                    "shell launcher must inject descriptor 9 before testing the policy"
                );
                let target_path =
                    std::env::var_os(TARGET_ENV).expect("launcher target path must be present");
                let current_exe =
                    std::env::current_exe().expect("test executable path must be available");

                let mut allowed = Command::new(&current_exe);
                allowed
                    .args(["--exact", TEST_NAME, "--nocapture"])
                    .env(ROLE_ENV, "allowed")
                    .env(TARGET_ENV, &target_path);
                configure_command_descriptor_allowlist_on_exec(&mut allowed, &[9])
                    .expect("explicit descriptor allowlist must configure");
                let allowed_status = allowed
                    .status()
                    .expect("allowlisted descriptor child must execute");
                assert!(
                    allowed_status.success(),
                    "allowlisted descriptor child failed: {}",
                    allowed_status
                );

                let mut closed = Command::new(current_exe);
                closed
                    .args(["--exact", TEST_NAME, "--nocapture"])
                    .env(ROLE_ENV, "closed")
                    .env(TARGET_ENV, target_path);
                configure_command_close_nonstdio_on_exec(&mut closed)
                    .expect("default descriptor contract must configure");
                let closed_status = closed
                    .status()
                    .expect("default descriptor child must execute");
                assert!(
                    closed_status.success(),
                    "default descriptor child failed: {}",
                    closed_status
                );
                return;
            }
            Ok(role) => panic!("unexpected descriptor-test role: {}", role),
            Err(std::env::VarError::NotUnicode(_)) => {
                panic!("descriptor-test role must be Unicode")
            }
            Err(std::env::VarError::NotPresent) => {}
        }

        let test_root = std::env::temp_dir().join(format!(
            "rustdesk-command-descriptor-{}-{}",
            std::process::id(),
            std::time::SystemTime::UNIX_EPOCH
                .elapsed()
                .expect("test clock must follow the Unix epoch")
                .as_nanos()
        ));
        fs::create_dir(&test_root).expect("descriptor test directory must be creatable");
        let target_path = test_root.join("parent-authority");
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&target_path)
            .expect("descriptor test target must be creatable");

        let current_exe = std::env::current_exe().expect("test executable path must be available");
        let status = Command::new("/bin/sh")
            .args([
                std::ffi::OsStr::new("-c"),
                std::ffi::OsStr::new("exec 9<>\"$1\"; exec \"$2\" --exact \"$3\" --nocapture"),
                std::ffi::OsStr::new("rustdesk-command-descriptor-test"),
                target_path.as_os_str(),
                current_exe.as_os_str(),
                std::ffi::OsStr::new(TEST_NAME),
            ])
            .env(ROLE_ENV, "launcher")
            .env(TARGET_ENV, &target_path)
            .status()
            .expect("descriptor-injecting shell must execute");

        fs::remove_file(&target_path).expect("descriptor test target must be removable");
        fs::remove_dir(&test_root).expect("descriptor test directory must be removable");
        assert!(
            status.success(),
            "descriptor-test launcher failed: {}",
            status
        );
    }

    #[test]
    fn r_s11e32_linux_command_descriptor_allowlist_rejects_invalid_entries() {
        let mut command = Command::new("/bin/true");
        assert!(configure_command_descriptor_allowlist_on_exec(
            &mut command,
            &[libc::STDERR_FILENO]
        )
        .is_err());

        let mut command = Command::new("/bin/true");
        assert!(configure_command_descriptor_allowlist_on_exec(&mut command, &[9, 9]).is_err());

        let mut command = Command::new("/bin/true");
        let outside_bound = linux_descriptor_upper_bound()
            .expect("descriptor-table bound must be readable")
            .checked_add(1)
            .expect("descriptor-table bound must fit a larger RawFd");
        assert!(
            configure_command_descriptor_allowlist_on_exec(&mut command, &[outside_bound]).is_err()
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
