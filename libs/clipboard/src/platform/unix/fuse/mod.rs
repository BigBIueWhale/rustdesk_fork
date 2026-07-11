mod cs;

use super::filetype::FileDescription;
use crate::{ClipboardFile, CliprdrError};
use cs::{FuseFileContentResponse, FuseFileContentResponseRouter, FuseServer};
use fuser::MountOption;
use hbb_common::{config::APP_NAME, log};
use parking_lot::Mutex;
use std::{
    ffi::{CString, OsStr},
    fs, io,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
        io::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    thread::{self, JoinHandle},
    time::Duration,
};

lazy_static::lazy_static! {
    static ref FUSE_MOUNT_POINT_CLIENT: Arc<String> = {
        let mnt_path = format!("/tmp/{}/{}", APP_NAME.read().unwrap(), "cliprdr-client");
        // No need to run `canonicalize()` here.
        Arc::new(mnt_path)
    };

    static ref FUSE_MOUNT_POINT_SERVER: Arc<String> = {
        let mnt_path = format!("/tmp/{}/{}", APP_NAME.read().unwrap(), "cliprdr-server");
        // No need to run `canonicalize()` here.
        Arc::new(mnt_path)
    };

    static ref FUSE_CONTEXT_CLIENT: Arc<Mutex<Option<FuseContext>>> = Arc::new(Mutex::new(None));
    static ref FUSE_CONTEXT_SERVER: Arc<Mutex<Option<FuseContext>>> = Arc::new(Mutex::new(None));
}

static FUSE_TIMEOUT: Duration = Duration::from_secs(3);
const FUSE_COMMFD_ENV: &str = "_FUSE_COMMFD";
const FUSERMOUNT_HELPERS: &[&str] = &[
    "/usr/bin/fusermount3",
    "/bin/fusermount3",
    "/usr/bin/fusermount",
    "/bin/fusermount",
];

pub fn get_exclude_paths(is_client: bool) -> Arc<String> {
    if is_client {
        FUSE_MOUNT_POINT_CLIENT.clone()
    } else {
        FUSE_MOUNT_POINT_SERVER.clone()
    }
}

pub fn is_fuse_context_inited(is_client: bool) -> bool {
    if is_client {
        FUSE_CONTEXT_CLIENT.lock().is_some()
    } else {
        FUSE_CONTEXT_SERVER.lock().is_some()
    }
}

pub fn init_fuse_context(is_client: bool) -> Result<(), CliprdrError> {
    let mut fuse_context_lock = if is_client {
        FUSE_CONTEXT_CLIENT.lock()
    } else {
        FUSE_CONTEXT_SERVER.lock()
    };
    if fuse_context_lock.is_some() {
        return Ok(());
    }
    require_unprivileged_linux_fuse()?;
    let mount_point = if is_client {
        FUSE_MOUNT_POINT_CLIENT.clone()
    } else {
        FUSE_MOUNT_POINT_SERVER.clone()
    };

    let mount_point = std::path::PathBuf::from(&*mount_point);
    let (server, response_router) = FuseServer::new(FUSE_TIMEOUT);
    let server = Arc::new(Mutex::new(server));

    prepare_fuse_mount_point(&mount_point)?;
    let mnt_opts = [
        MountOption::FSName("rustdesk-cliprdr-fs".to_string()),
        MountOption::NoAtime,
        MountOption::RO,
    ];
    let session = mount_clipboard_fuse(server.clone(), &mount_point, &mnt_opts)?;
    let session = Mutex::new(Some(session));

    let ctx = FuseContext {
        server,
        response_router,
        mount_point,
        session,
        conn_id: 0,
    };
    *fuse_context_lock = Some(ctx);
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_unprivileged_linux_fuse() -> Result<(), CliprdrError> {
    let euid = unsafe { libc::geteuid() };
    if linux_clipboard_fuse_euid_allowed(euid) {
        return Ok(());
    }
    log::warn!("refusing Linux clipboard FUSE initialization in euid-0 process");
    Err(CliprdrError::CliprdrInit)
}

#[cfg(not(target_os = "linux"))]
fn require_unprivileged_linux_fuse() -> Result<(), CliprdrError> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_clipboard_fuse_euid_allowed(euid: libc::uid_t) -> bool {
    euid != 0
}

pub fn uninit_fuse_context(is_client: bool) {
    uninit_fuse_context_(is_client)
}

pub fn format_data_response_to_urls(
    is_client: bool,
    format_data: Vec<u8>,
    conn_id: i32,
) -> Result<Vec<String>, CliprdrError> {
    let mut ctx = if is_client {
        FUSE_CONTEXT_CLIENT.lock()
    } else {
        FUSE_CONTEXT_SERVER.lock()
    };
    ctx.as_mut()
        .ok_or(CliprdrError::CliprdrInit)?
        .format_data_response_to_urls(format_data, conn_id)
}

pub fn handle_file_content_response(
    is_client: bool,
    conn_id: i32,
    clip: ClipboardFile,
) -> Result<(), CliprdrError> {
    // we don't know its corresponding request, no resend can be performed
    let ctx = if is_client {
        FUSE_CONTEXT_CLIENT.lock()
    } else {
        FUSE_CONTEXT_SERVER.lock()
    };
    ctx.as_ref()
        .ok_or(CliprdrError::CliprdrInit)?
        .response_router
        .dispatch(FuseFileContentResponse { conn_id, clip })?;
    Ok(())
}

pub fn empty_local_files(is_client: bool, conn_id: i32) -> bool {
    let ctx = if is_client {
        FUSE_CONTEXT_CLIENT.lock()
    } else {
        FUSE_CONTEXT_SERVER.lock()
    };
    ctx.as_ref()
        .map(|c| c.empty_local_files(conn_id))
        .unwrap_or(false)
}

struct FuseContext {
    server: Arc<Mutex<FuseServer>>,
    response_router: FuseFileContentResponseRouter,
    mount_point: PathBuf,
    session: Mutex<Option<ClipboardFuseSession>>,
    // Indicates the connection ID of that set the clipboard content
    conn_id: i32,
}

struct FdGuard(RawFd);

impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

struct ClipboardFuseSession {
    mount: ClipboardFuseMountGuard,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl Drop for ClipboardFuseSession {
    fn drop(&mut self) {
        self.mount.unmount();
        let Some(thread) = self.thread.take() else {
            return;
        };
        match thread.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                log::debug!("clipboard FUSE session stopped with error: {err}");
            }
            Err(_) => {
                log::error!("clipboard FUSE session thread panicked");
            }
        }
    }
}

struct ClipboardFuseMountGuard {
    mount_point: PathBuf,
    fuse_fd: OwnedFd,
    unmounted: bool,
}

impl ClipboardFuseMountGuard {
    fn new(mount_point: PathBuf, fuse_fd: OwnedFd) -> Self {
        Self {
            mount_point,
            fuse_fd,
            unmounted: false,
        }
    }

    fn unmount(&mut self) {
        if self.unmounted {
            return;
        }
        self.unmounted = true;
        if !fuse_device_still_mounted(&self.fuse_fd) {
            return;
        }
        unmount_clipboard_fuse_mount(&self.mount_point);
    }
}

impl Drop for ClipboardFuseMountGuard {
    fn drop(&mut self) {
        self.unmount();
    }
}

fn fuse_common_error(description: impl Into<String>) -> CliprdrError {
    CliprdrError::CommonError {
        description: description.into(),
    }
}

fn mount_clipboard_fuse(
    server: Arc<Mutex<FuseServer>>,
    mount_point: &Path,
    options: &[MountOption],
) -> Result<ClipboardFuseSession, CliprdrError> {
    log::info!("mounting clipboard FUSE to {}", mount_point.display());
    let (fuse_fd, mount) = mount_with_fixed_fusermount(mount_point, options)?;
    let session = fuser::Session::from_fd(
        FuseServer::client(server),
        fuse_fd,
        fuser::SessionACL::Owner,
    );
    let thread = thread::Builder::new()
        .name("rustdesk-cliprdr-fuse".to_string())
        .spawn(move || {
            let mut session = session;
            session.run()
        })
        .map_err(|e| {
            log::error!("failed to spawn clipboard FUSE session thread: {e}");
            CliprdrError::CliprdrInit
        })?;
    Ok(ClipboardFuseSession {
        mount,
        thread: Some(thread),
    })
}

fn mount_with_fixed_fusermount(
    mount_point: &Path,
    options: &[MountOption],
) -> Result<(OwnedFd, ClipboardFuseMountGuard), CliprdrError> {
    let helper = trusted_fusermount_helper()?;
    let mount_options = clipboard_fuse_mount_options_arg(options)?;
    let (child_socket, receive_socket) = UnixStream::pair().map_err(|e| {
        fuse_common_error(format!("failed to create fusermount fd socket pair: {e}"))
    })?;
    set_fd_cloexec(child_socket.as_raw_fd(), false)?;

    let child = Command::new(&helper)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .arg("-o")
        .arg(mount_options)
        .arg("--")
        .arg(mount_point)
        .env(FUSE_COMMFD_ENV, child_socket.as_raw_fd().to_string())
        .spawn()
        .map_err(|e| {
            fuse_common_error(format!(
                "failed to start trusted fusermount helper {}: {e}",
                helper.display()
            ))
        })?;
    drop(child_socket);

    let fuse_fd = match receive_fusermount_fd(&receive_socket) {
        Ok(fuse_fd) => fuse_fd,
        Err(err) => {
            drop(receive_socket);
            let output = child.wait_with_output().map_err(|wait_err| {
                fuse_common_error(format!(
                    "failed to wait for trusted fusermount helper after fd receive error ({err}): {wait_err}"
                ))
            })?;
            log_fusermount_output("mount", &output);
            return Err(fuse_common_error(format!(
                "trusted fusermount helper did not return a FUSE fd: {err}"
            )));
        }
    };
    drop(receive_socket);
    if let Err(err) = set_fd_cloexec(fuse_fd.as_raw_fd(), true) {
        unmount_clipboard_fuse_mount(mount_point);
        return Err(err);
    }
    let mount_guard = match duplicate_owned_fd(fuse_fd.as_raw_fd()) {
        Ok(fd) => ClipboardFuseMountGuard::new(mount_point.to_path_buf(), fd),
        Err(err) => {
            unmount_clipboard_fuse_mount(mount_point);
            return Err(err);
        }
    };

    let output = child.wait_with_output().map_err(|e| {
        fuse_common_error(format!(
            "failed to wait for trusted fusermount helper {}: {e}",
            helper.display()
        ))
    })?;
    log_fusermount_output("mount", &output);
    if !output.status.success() {
        drop(mount_guard);
        return Err(fuse_common_error(format!(
            "trusted fusermount helper {} failed: {}",
            helper.display(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok((fuse_fd, mount_guard))
}

fn receive_fusermount_fd(socket: &UnixStream) -> Result<OwnedFd, CliprdrError> {
    let mut io_vec_buf = [0u8];
    let mut io_vec = libc::iovec {
        iov_base: io_vec_buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: io_vec_buf.len(),
    };
    let cmsg_buffer_len = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as libc::c_uint) };
    let mut cmsg_buffer = vec![0u8; cmsg_buffer_len as usize];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut io_vec;
    message.msg_iovlen = 1;
    message.msg_control = cmsg_buffer.as_mut_ptr() as *mut libc::c_void;
    message.msg_controllen = cmsg_buffer.len();

    let result = loop {
        let result = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, 0) };
        if result >= 0 {
            break result;
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(fuse_common_error(format!(
                "failed to receive FUSE fd from fusermount: {err}"
            )));
        }
    };
    if result == 0 {
        return Err(fuse_common_error(
            "fusermount closed fd socket without a FUSE fd",
        ));
    }
    if (message.msg_flags & libc::MSG_CTRUNC) != 0 {
        return Err(fuse_common_error(
            "fusermount control message was truncated",
        ));
    }

    let control_msg = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if control_msg.is_null() {
        return Err(fuse_common_error("fusermount returned no control message"));
    }
    let expected_len = unsafe { libc::CMSG_LEN(std::mem::size_of::<RawFd>() as libc::c_uint) };
    let valid_rights = unsafe {
        (*control_msg).cmsg_level == libc::SOL_SOCKET
            && (*control_msg).cmsg_type == libc::SCM_RIGHTS
            && (*control_msg).cmsg_len >= expected_len as _
    };
    if !valid_rights {
        return Err(fuse_common_error(
            "fusermount returned an invalid control message",
        ));
    }

    let mut fd: RawFd = -1;
    unsafe {
        std::ptr::copy_nonoverlapping(libc::CMSG_DATA(control_msg) as *const RawFd, &mut fd, 1);
    }
    if fd < 0 {
        return Err(fuse_common_error("fusermount returned an invalid FUSE fd"));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn set_fd_cloexec(fd: RawFd, enabled: bool) -> Result<(), CliprdrError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(fuse_common_error(format!(
            "failed to read fd flags: {}",
            io::Error::last_os_error()
        )));
    }
    let new_flags = if enabled {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, new_flags) } < 0 {
        return Err(fuse_common_error(format!(
            "failed to update fd close-on-exec flag: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn duplicate_owned_fd(fd: RawFd) -> Result<OwnedFd, CliprdrError> {
    let duplicated = unsafe { libc::dup(fd) };
    if duplicated < 0 {
        return Err(fuse_common_error(format!(
            "failed to duplicate FUSE fd: {}",
            io::Error::last_os_error()
        )));
    }
    let owned = unsafe { OwnedFd::from_raw_fd(duplicated) };
    set_fd_cloexec(owned.as_raw_fd(), true)?;
    Ok(owned)
}

fn fuse_device_still_mounted(fuse_fd: &OwnedFd) -> bool {
    let mut poll_result = libc::pollfd {
        fd: fuse_fd.as_raw_fd(),
        events: 0,
        revents: 0,
    };
    loop {
        let res = unsafe { libc::poll(&mut poll_result, 1, 0) };
        match res {
            0 => return true,
            1 => return (poll_result.revents & libc::POLLERR) != 0,
            -1 => {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                log::warn!("failed to poll clipboard FUSE fd before unmount: {err}");
                return true;
            }
            _ => return true,
        }
    }
}

fn clipboard_fuse_mount_options_arg(options: &[MountOption]) -> Result<String, CliprdrError> {
    let mut rendered = Vec::with_capacity(options.len());
    for option in options {
        rendered.push(clipboard_fuse_mount_option_arg(option)?);
    }
    Ok(rendered.join(","))
}

fn clipboard_fuse_mount_option_arg(option: &MountOption) -> Result<String, CliprdrError> {
    match option {
        MountOption::FSName(name) if safe_fuse_option_value(name) => Ok(format!("fsname={name}")),
        MountOption::NoAtime => Ok("noatime".to_string()),
        MountOption::RO => Ok("ro".to_string()),
        _ => Err(fuse_common_error(format!(
            "unsupported clipboard FUSE mount option: {option:?}"
        ))),
    }
}

fn safe_fuse_option_value(value: &str) -> bool {
    !value.is_empty() && !value.as_bytes().iter().any(|b| *b == b',' || *b == 0)
}

fn trusted_fusermount_helper() -> Result<PathBuf, CliprdrError> {
    for candidate in FUSERMOUNT_HELPERS {
        let path = Path::new(candidate);
        if let Some(helper) = trusted_fusermount_path(path) {
            return Ok(helper);
        }
    }
    Err(fuse_common_error(
        "no trusted fixed-path fusermount helper is available",
    ))
}

fn trusted_fusermount_path(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute()
        || !path
            .parent()
            .map(trusted_root_owned_not_writable_dir)
            .unwrap_or(false)
    {
        return None;
    }
    let canonical = fs::canonicalize(path).ok()?;
    if !canonical.is_absolute()
        || !canonical
            .parent()
            .map(trusted_root_owned_not_writable_dir)
            .unwrap_or(false)
    {
        return None;
    }
    fs::metadata(&canonical).ok().and_then(|metadata| {
        trusted_fusermount_metadata(
            metadata.is_file(),
            metadata.uid(),
            metadata.permissions().mode(),
        )
        .then_some(canonical)
    })
}

fn trusted_root_owned_not_writable_dir(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| {
            trusted_fusermount_parent_metadata(
                metadata.is_dir(),
                metadata.uid(),
                metadata.permissions().mode(),
            )
        })
        .unwrap_or(false)
}

fn trusted_fusermount_metadata(is_file: bool, uid: u32, mode: u32) -> bool {
    is_file && uid == 0 && mode & 0o022 == 0 && mode & 0o111 != 0
}

fn trusted_fusermount_parent_metadata(is_dir: bool, uid: u32, mode: u32) -> bool {
    is_dir && uid == 0 && mode & 0o022 == 0
}

fn log_fusermount_output(action: &str, output: &std::process::Output) {
    if !output.stdout.is_empty() {
        log::debug!(
            "fusermount {action} stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    if !output.stderr.is_empty() {
        log::debug!(
            "fusermount {action} stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

fn fuse_component_cstring(component: &OsStr, label: &str) -> Result<CString, CliprdrError> {
    let bytes = component.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(fuse_common_error(format!(
            "unsafe FUSE mount {label} component: {:?}",
            component
        )));
    }
    CString::new(bytes).map_err(|e| {
        fuse_common_error(format!(
            "unsafe FUSE mount {label} component contains NUL: {e}"
        ))
    })
}

fn open_tmp_dir_no_follow() -> Result<FdGuard, CliprdrError> {
    let tmp = CString::new("/tmp").map_err(|e| fuse_common_error(e.to_string()))?;
    let fd = unsafe {
        libc::open(
            tmp.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(fuse_common_error(format!(
            "failed to open /tmp for FUSE mount setup: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(FdGuard(fd))
}

fn ensure_trusted_child_dir(
    parent_fd: RawFd,
    name: &CString,
    display: &Path,
) -> Result<FdGuard, CliprdrError> {
    let rc = unsafe { libc::mkdirat(parent_fd, name.as_ptr(), 0o755 as libc::mode_t) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EEXIST) {
            return Err(fuse_common_error(format!(
                "failed to create FUSE mount directory {}: {err}",
                display.display()
            )));
        }
    }

    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(fuse_common_error(format!(
            "failed to open FUSE mount directory no-follow {}: {}",
            display.display(),
            std::io::Error::last_os_error()
        )));
    }
    let guard = FdGuard(fd);
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(guard.0, &mut stat) } != 0 {
        return Err(fuse_common_error(format!(
            "failed to stat FUSE mount directory {}: {}",
            display.display(),
            std::io::Error::last_os_error()
        )));
    }
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(fuse_common_error(format!(
            "FUSE mount path is not a directory: {}",
            display.display()
        )));
    }
    let current_euid = unsafe { libc::geteuid() };
    if stat.st_uid != current_euid {
        return Err(fuse_common_error(format!(
            "refusing foreign-owned FUSE mount directory {}: uid={} euid={}",
            display.display(),
            stat.st_uid,
            current_euid
        )));
    }
    if unsafe { libc::fchmod(guard.0, 0o755 as libc::mode_t) } != 0 {
        return Err(fuse_common_error(format!(
            "failed to set FUSE mount directory mode 0755 on {}: {}",
            display.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(guard)
}

fn fuse_mount_path_cstring(mount_point: &Path) -> Result<CString, CliprdrError> {
    CString::new(mount_point.as_os_str().as_bytes()).map_err(|e| {
        fuse_common_error(format!(
            "unsafe FUSE mount path contains NUL {}: {e}",
            mount_point.display()
        ))
    })
}

fn unmount_clipboard_fuse_mount(mount_point: &Path) {
    let mount_c = match fuse_mount_path_cstring(mount_point) {
        Ok(mount_c) => mount_c,
        Err(e) => {
            log::warn!("refusing to unmount clipboard FUSE mount: {e}");
            return;
        }
    };
    if unsafe { libc::umount2(mount_c.as_ptr(), libc::UMOUNT_NOFOLLOW) } == 0 {
        return;
    }

    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::EINVAL) | Some(libc::ENOENT) => {
            log::debug!(
                "no clipboard FUSE mount at {}: {}",
                mount_point.display(),
                err
            );
        }
        _ => {
            if let Err(helper_err) = fixed_fusermount_unmount(mount_point) {
                log::warn!(
                    "failed to unmount clipboard FUSE mount at {}: {}; helper failed: {}",
                    mount_point.display(),
                    err,
                    helper_err
                );
            }
        }
    }
}

fn fixed_fusermount_unmount(mount_point: &Path) -> Result<(), CliprdrError> {
    let helper = trusted_fusermount_helper()?;
    let output = Command::new(&helper)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .arg("-u")
        .arg("-q")
        .arg("-z")
        .arg("--")
        .arg(mount_point)
        .output()
        .map_err(|e| {
            fuse_common_error(format!(
                "failed to start trusted fusermount unmount helper {}: {e}",
                helper.display()
            ))
        })?;
    log_fusermount_output("unmount", &output);
    if output.status.success() {
        Ok(())
    } else {
        Err(fuse_common_error(format!(
            "trusted fusermount unmount helper {} failed: {}",
            helper.display(),
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

fn unmount_stale_fuse_mount(mount_point: &Path) {
    unmount_clipboard_fuse_mount(mount_point);
}

// this function must be called after the main IPC is up
fn prepare_fuse_mount_point(mount_point: &Path) -> Result<(), CliprdrError> {
    let parent = mount_point.parent().ok_or_else(|| {
        fuse_common_error(format!(
            "FUSE mount point has no parent: {}",
            mount_point.display()
        ))
    })?;
    let grandparent = parent.parent().ok_or_else(|| {
        fuse_common_error(format!(
            "FUSE mount parent has no grandparent: {}",
            parent.display()
        ))
    })?;
    if grandparent != Path::new("/tmp") {
        return Err(fuse_common_error(format!(
            "FUSE mount point must stay under /tmp/<app>: {}",
            mount_point.display()
        )));
    }

    let app_component = parent.file_name().ok_or_else(|| {
        fuse_common_error(format!(
            "FUSE mount parent has no basename: {}",
            parent.display()
        ))
    })?;
    let mount_component = mount_point.file_name().ok_or_else(|| {
        fuse_common_error(format!(
            "FUSE mount point has no basename: {}",
            mount_point.display()
        ))
    })?;
    let app_c = fuse_component_cstring(app_component, "app")?;
    let mount_c = fuse_component_cstring(mount_component, "mount")?;

    let tmp = open_tmp_dir_no_follow()?;
    let app_dir = ensure_trusted_child_dir(tmp.0, &app_c, parent)?;
    let mount_dir = ensure_trusted_child_dir(app_dir.0, &mount_c, mount_point)?;
    drop(mount_dir);

    unmount_stale_fuse_mount(mount_point);
    Ok(())
}

fn uninit_fuse_context_(is_client: bool) {
    if is_client {
        let _ = FUSE_CONTEXT_CLIENT.lock().take();
    } else {
        let _ = FUSE_CONTEXT_SERVER.lock().take();
    }
}

impl Drop for FuseContext {
    fn drop(&mut self) {
        self.session.lock().take();
        log::info!(
            "unmounting clipboard FUSE from {}",
            self.mount_point.display()
        );
    }
}

impl FuseContext {
    pub fn empty_local_files(&self, conn_id: i32) -> bool {
        if conn_id != 0 && self.conn_id != conn_id {
            return false;
        }
        let mut fuse_guard = self.server.lock();
        let _ = fuse_guard.load_file_list(vec![]);
        true
    }

    pub fn format_data_response_to_urls(
        &mut self,
        format_data: Vec<u8>,
        conn_id: i32,
    ) -> Result<Vec<String>, CliprdrError> {
        let files = FileDescription::parse_file_descriptors(format_data, conn_id)?;

        let paths = {
            let mut fuse_guard = self.server.lock();
            fuse_guard.load_file_list(files)?;
            self.conn_id = conn_id;

            fuse_guard.list_root()
        };

        let prefix = self.mount_point.clone();
        Ok(paths
            .into_iter()
            .map(|p| prefix.join(p).to_string_lossy().to_string())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn fuse_mount_component_rejects_empty_dot_dotdot_slash_and_nul() {
        for component in [
            OsString::from(""),
            OsString::from("."),
            OsString::from(".."),
            OsString::from("bad/name"),
            OsString::from_vec(b"bad\0name".to_vec()),
        ] {
            assert!(fuse_component_cstring(&component, "test").is_err());
        }
    }

    #[test]
    fn fuse_mount_component_accepts_expected_mount_name() {
        let component = OsString::from("cliprdr-client");
        let c_string = fuse_component_cstring(&component, "test").unwrap();
        assert_eq!(c_string.as_bytes(), b"cliprdr-client");
    }

    #[test]
    fn fuse_mount_path_cstring_rejects_nul() {
        let path = PathBuf::from(OsString::from_vec(b"/tmp/rustdesk/bad\0name".to_vec()));
        assert!(fuse_mount_path_cstring(&path).is_err());
    }

    #[test]
    fn clipboard_fuse_mount_options_are_owner_only() {
        let options = [
            MountOption::FSName("rustdesk-cliprdr-fs".to_string()),
            MountOption::NoAtime,
            MountOption::RO,
        ];
        assert_eq!(
            clipboard_fuse_mount_options_arg(&options).unwrap(),
            "fsname=rustdesk-cliprdr-fs,noatime,ro"
        );
        assert!(clipboard_fuse_mount_options_arg(&[MountOption::AllowOther]).is_err());
        assert!(clipboard_fuse_mount_options_arg(&[MountOption::AutoUnmount]).is_err());
        assert!(
            clipboard_fuse_mount_options_arg(&[MountOption::FSName("bad,name".to_string())])
                .is_err()
        );
    }

    #[test]
    fn trusted_fusermount_metadata_requires_root_regular_unwritable_file() {
        assert!(trusted_fusermount_metadata(true, 0, 0o4755));
        assert!(!trusted_fusermount_metadata(false, 0, 0o4755));
        assert!(!trusted_fusermount_metadata(true, 1000, 0o4755));
        assert!(!trusted_fusermount_metadata(true, 0, 0o4775));
        assert!(!trusted_fusermount_metadata(true, 0, 0o4777));
        assert!(!trusted_fusermount_metadata(true, 0, 0o644));
    }

    #[test]
    fn trusted_fusermount_parent_requires_root_unwritable_directory() {
        assert!(trusted_fusermount_parent_metadata(true, 0, 0o755));
        assert!(!trusted_fusermount_parent_metadata(false, 0, 0o755));
        assert!(!trusted_fusermount_parent_metadata(true, 1000, 0o755));
        assert!(!trusted_fusermount_parent_metadata(true, 0, 0o775));
        assert!(!trusted_fusermount_parent_metadata(true, 0, 0o777));
    }

    #[test]
    fn trusted_fusermount_path_rejects_relative_path() {
        assert!(trusted_fusermount_path(Path::new("fusermount3")).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_clipboard_fuse_rejects_euid_zero() {
        assert!(!linux_clipboard_fuse_euid_allowed(0));
        assert!(linux_clipboard_fuse_euid_allowed(1));
    }
}
