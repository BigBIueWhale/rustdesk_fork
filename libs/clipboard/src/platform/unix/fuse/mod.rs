mod cs;

use super::filetype::FileDescription;
use crate::{ClipboardFile, CliprdrError};
use cs::FuseServer;
use fuser::MountOption;
use hbb_common::{config::APP_NAME, log};
use parking_lot::Mutex;
use std::{
    ffi::{CString, OsStr},
    os::unix::{ffi::OsStrExt, io::RawFd},
    path::{Path, PathBuf},
    sync::{mpsc::Sender, Arc},
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
    let mount_point = if is_client {
        FUSE_MOUNT_POINT_CLIENT.clone()
    } else {
        FUSE_MOUNT_POINT_SERVER.clone()
    };

    let mount_point = std::path::PathBuf::from(&*mount_point);
    let (server, tx) = FuseServer::new(FUSE_TIMEOUT);
    let server = Arc::new(Mutex::new(server));

    prepare_fuse_mount_point(&mount_point)?;
    let mnt_opts = [
        MountOption::FSName("rustdesk-cliprdr-fs".to_string()),
        MountOption::NoAtime,
        MountOption::RO,
    ];
    log::info!("mounting clipboard FUSE to {}", mount_point.display());
    // to-do: ignore the error if the mount point is already mounted
    // Because the sciter version uses separate processes as the controlling side.
    let session = fuser::spawn_mount2(
        FuseServer::client(server.clone()),
        mount_point.clone(),
        &mnt_opts,
    )
    .map_err(|e| {
        log::error!("failed to mount cliprdr fuse: {:?}", e);
        CliprdrError::CliprdrInit
    })?;
    let session = Mutex::new(Some(session));

    let ctx = FuseContext {
        server,
        tx,
        mount_point,
        session,
        conn_id: 0,
    };
    *fuse_context_lock = Some(ctx);
    Ok(())
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
        .tx
        .send(clip)
        .map_err(|e| {
            log::error!("failed to send file contents response to fuse: {:?}", e);
            CliprdrError::ClipboardInternalError
        })?;
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
    tx: Sender<ClipboardFile>,
    mount_point: PathBuf,
    // stores fuse background session handle
    session: Mutex<Option<fuser::BackgroundSession>>,
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

fn fuse_common_error(description: impl Into<String>) -> CliprdrError {
    CliprdrError::CommonError {
        description: description.into(),
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

    if let Err(e) = std::process::Command::new("umount")
        .arg(mount_point)
        .status()
    {
        log::warn!("umount {:?} may fail: {:?}", mount_point, e);
    }
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
        self.session.lock().take().map(|s| s.join());
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
        let files = FileDescription::parse_file_descriptors_isolated(format_data, conn_id)?;

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
}
