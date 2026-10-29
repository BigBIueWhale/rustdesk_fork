#[cfg(target_os = "linux")]
use super::ipc_auth::{
    active_uid, authenticate_cm_endpoint, current_linux_process_identity,
    ensure_linux_process_identity_matches, peer_executable_is_current_by_pid,
};
#[cfg(target_os = "macos")]
use crate::ipc::connect;
#[cfg(target_os = "linux")]
use crate::ipc::{ConnClient, ConnectionTmpl, Endpoint, CM_IPC_MAX_FRAME_BYTES};
use crate::ipc::{ServiceIpcRequest, ServiceIpcResponse};
use hbb_common::{config, log, ResultType};
use std::{
    ffi::CString,
    io::{Error, ErrorKind},
    os::unix::ffi::OsStrExt,
    path::Path,
};

struct FdGuard(i32);
impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe {
            hbb_common::libc::close(self.0);
        }
    }
}

#[cfg(target_os = "linux")]
#[inline]
pub(crate) fn terminal_count_candidate_uids(effective_uid: u32) -> Vec<u32> {
    if effective_uid != 0 {
        return vec![effective_uid];
    }
    let mut candidates = Vec::with_capacity(2);
    if let Some(uid) = active_uid().filter(|uid| *uid != 0) {
        candidates.push(uid);
    }
    candidates.push(0);
    candidates
}

#[inline]
fn expected_ipc_parent_mode(postfix: &str) -> u32 {
    if config::is_service_ipc_postfix(postfix) {
        0o0711
    } else {
        0o0700
    }
}

fn open_ipc_parent_dir_fd(parent_c: &CString) -> std::io::Result<i32> {
    #[cfg(target_os = "linux")]
    let access = hbb_common::libc::O_PATH;
    #[cfg(not(target_os = "linux"))]
    let access = hbb_common::libc::O_RDONLY;
    let fd = unsafe {
        hbb_common::libc::open(
            parent_c.as_ptr(),
            access
                | hbb_common::libc::O_DIRECTORY
                | hbb_common::libc::O_CLOEXEC
                | hbb_common::libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

#[cfg(target_os = "linux")]
fn ipc_descriptor_directory() -> ResultType<FdGuard> {
    use hbb_common::libc;

    let directory = FdGuard(open_ipc_parent_dir_fd(&CString::new("/proc/thread-self/fd")?)?);
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(directory.0, &mut filesystem) } != 0 {
        return Err(Error::last_os_error().into());
    }
    if filesystem.f_type as u64 != libc::PROC_SUPER_MAGIC as u64 {
        return Err(Error::new(
            ErrorKind::PermissionDenied, "ipc descriptor directory is not procfs",
        ).into());
    }
    Ok(directory)
}

// Remove one preexisting IPC artifact via an already-opened parent directory FD.
//
// Security intent:
// - Bind cleanup to the exact parent inode that passed O_NOFOLLOW + fstat checks.
// - Avoid path-based TOCTOU during scrub (e.g., parent path rename/swap race).
//
// Flow:
// 1) fstatat(..., AT_SYMLINK_NOFOLLOW) to inspect the target entry under parent_fd.
// 2) Decide file vs directory from st_mode.
// 3) unlinkat relative to parent_fd (AT_REMOVEDIR for directories).
//
// Error policy:
// - NotFound is treated as benign (already removed / raced away).
// - Other errors are surfaced explicitly.
fn remove_parent_entry_via_fd(
    parent_fd: i32,
    parent_dir: &Path,
    entry_name: &str,
) -> ResultType<()> {
    if entry_name.contains('/') {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "invalid ipc parent entry name (contains '/'): parent={}, entry={}",
                parent_dir.display(),
                entry_name
            ),
        )
        .into());
    }
    let entry_c = CString::new(entry_name.as_bytes().to_vec()).map_err(|err| {
        Error::new(
            ErrorKind::InvalidInput,
            format!(
                "invalid ipc parent entry name: parent={}, entry={}, err={}",
                parent_dir.display(),
                entry_name,
                err
            ),
        )
    })?;
    let mut stat: hbb_common::libc::stat = unsafe { std::mem::zeroed() };
    let stat_rc = unsafe {
        hbb_common::libc::fstatat(
            parent_fd,
            entry_c.as_ptr(),
            &mut stat,
            hbb_common::libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if stat_rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == ErrorKind::NotFound {
            return Ok(());
        }
        return Err(Error::new(
            err.kind(),
            format!(
                "failed to stat preexisting ipc parent dir entry by fd: parent={}, entry={}, err={}",
                parent_dir.display(),
                entry_name,
                err
            ),
        )
        .into());
    }

    let is_dir = (stat.st_mode & (hbb_common::libc::S_IFMT as hbb_common::libc::mode_t))
        == hbb_common::libc::S_IFDIR;
    let unlink_flags = if is_dir {
        hbb_common::libc::AT_REMOVEDIR
    } else {
        0
    };
    let unlink_rc =
        unsafe { hbb_common::libc::unlinkat(parent_fd, entry_c.as_ptr(), unlink_flags) };
    if unlink_rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == ErrorKind::NotFound {
            return Ok(());
        }
        return Err(Error::new(
            err.kind(),
            format!(
                "failed to remove preexisting ipc parent dir entry by fd: parent={}, entry={}, err={}",
                parent_dir.display(),
                entry_name,
                err
            ),
        )
        .into());
    }
    Ok(())
}

fn scrub_preexisting_ipc_parent_entries(
    parent_fd: i32,
    parent_dir: &Path,
    postfix: &str,
) -> ResultType<()> {
    let ipc_basename = format!("ipc{}", postfix);
    remove_parent_entry_via_fd(parent_fd, parent_dir, &ipc_basename)?;
    remove_parent_entry_via_fd(parent_fd, parent_dir, &format!("{}.pid", ipc_basename))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn remove_ipc_socket_via_secure_parent_fd(postfix: &str) -> ResultType<()> {
    let path = config::Config::ipc_path(postfix);
    let parent_dir = Path::new(&path)
        .parent()
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, format!("invalid ipc path: {path}")))?;
    let parent_c = CString::new(parent_dir.as_os_str().as_bytes().to_vec())?;
    let fd = match open_ipc_parent_dir_fd(&parent_c) {
        Ok(fd) => fd,
        Err(open_err) => {
            if open_err.kind() == ErrorKind::NotFound {
                return Ok(());
            }
            return Err(Error::new(
                open_err.kind(),
                format!(
                    "failed to open ipc parent dir for stale socket cleanup (no-follow): postfix={}, parent={}, err={}",
                    postfix,
                    parent_dir.display(),
                    open_err
                ),
            )
            .into());
        }
    };
    let _fd_guard = FdGuard(fd);
    remove_parent_entry_via_fd(fd, parent_dir, &format!("ipc{}", postfix))
}

// R-S11a(b): replace the foreign-created inode rather than relabel its ownership.
// This also discards its access/default ACLs and other inode metadata. Linux chmod(0711)
// masks named-user write access, but does not remove the ACL entries or the default ACL.
// Remove only known IPC artifacts and recreate relative to the opened grandparent;
// leftover entries or failed recreation refuse startup. The caller verifies the returned fd.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn recreate_foreign_service_ipc_parent_dir(parent_dir: &Path, postfix: &str) -> ResultType<i32> {
    let grandparent = parent_dir.parent().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            format!(
                "R-S11a(b): ipc parent has no grandparent to recreate under: {}",
                parent_dir.display()
            ),
        )
    })?;
    let basename = parent_dir
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "R-S11a(b): ipc parent has no basename: {}",
                    parent_dir.display()
                ),
            )
        })?;
    let gp_c = CString::new(grandparent.as_os_str().as_bytes().to_vec())?;
    let gp_fd = open_ipc_parent_dir_fd(&gp_c).map_err(|e| {
        Error::new(
            e.kind(),
            format!(
                "R-S11a(b): failed to open ipc grandparent (no-follow) to recreate: gp={}, err={}",
                grandparent.display(),
                e
            ),
        )
    })?;
    let _gp_guard = FdGuard(gp_fd);

    // Scrub only known IPC artifacts through the no-follow directory fd. A failed
    // open or scrub refuses replacement; unrelated entries keep it nonempty.
    let base_c = CString::new(basename.as_bytes().to_vec())?;
    let foreign_fd = unsafe {
        hbb_common::libc::openat(
            gp_fd,
            base_c.as_ptr(),
            hbb_common::libc::O_RDONLY
                | hbb_common::libc::O_DIRECTORY
                | hbb_common::libc::O_CLOEXEC
                | hbb_common::libc::O_NOFOLLOW,
        )
    };
    if foreign_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(Error::new(
            err.kind(),
            format!(
                "failed to open foreign ipc parent for replacement: parent={}, err={}",
                parent_dir.display(),
                err
            ),
        )
        .into());
    }
    let _f_guard = FdGuard(foreign_fd);
    scrub_preexisting_ipc_parent_entries(foreign_fd, parent_dir, postfix)?;

    // The parent must still be a directory. Never select file/symlink unlink
    // semantics from a replacement entry's type, or continue after disappearance.
    if unsafe { hbb_common::libc::unlinkat(gp_fd, base_c.as_ptr(), hbb_common::libc::AT_REMOVEDIR) }
        != 0
    {
        let err = std::io::Error::last_os_error();
        return Err(Error::new(
            err.kind(),
            format!(
                "failed to remove foreign ipc parent directory: parent={}, err={}",
                parent_dir.display(),
                err
            ),
        )
        .into());
    }

    // Recreate fresh, root-owned, at the expected mode. EEXIST ⇒ an attacker raced our rmdir ⇒
    // fail-closed (do NOT adopt the raced inode).
    let expected_mode = expected_ipc_parent_mode(postfix);
    if unsafe {
        hbb_common::libc::mkdirat(
            gp_fd,
            base_c.as_ptr(),
            expected_mode as hbb_common::libc::mode_t,
        )
    } != 0
    {
        let err = std::io::Error::last_os_error();
        return Err(Error::new(
            err.kind(),
            format!(
                "R-S11a(b): failed to recreate ipc parent dir (refusing to adopt foreign): parent={}, err={}",
                parent_dir.display(),
                err
            ),
        )
        .into());
    }

    let new_fd = unsafe {
        hbb_common::libc::openat(
            gp_fd,
            base_c.as_ptr(),
            hbb_common::libc::O_RDONLY
                | hbb_common::libc::O_DIRECTORY
                | hbb_common::libc::O_CLOEXEC
                | hbb_common::libc::O_NOFOLLOW,
        )
    };
    if new_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(Error::new(
            err.kind(),
            format!(
                "R-S11a(b): failed to open recreated ipc parent dir (no-follow): parent={}, err={}",
                parent_dir.display(),
                err
            ),
        )
        .into());
    }
    Ok(new_fd)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[inline]
fn should_recreate_foreign_service_ipc_parent(
    owner_uid: u32,
    expected_uid: u32,
    postfix: &str,
) -> bool {
    cfg!(target_os = "macos")
        && owner_uid != expected_uid
        && expected_uid == 0
        && config::is_service_ipc_postfix(postfix)
}

#[cfg(target_os = "linux")]
fn verify_linux_service_ipc_namespace(parent_dir: &Path) -> ResultType<()> {
    if unsafe { hbb_common::libc::geteuid() } != 0
        || parent_dir.parent() != Some(Path::new("/run"))
    {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "service IPC requires root and a direct child of /run",
        )
        .into());
    }
    let runtime = CString::new("/run")?;
    let fd = open_ipc_parent_dir_fd(&runtime)?;
    let _guard = FdGuard(fd);
    let mut st: hbb_common::libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { hbb_common::libc::fstat(fd, &mut st) } != 0 {
        return Err(Error::last_os_error().into());
    }
    if st.st_uid != 0 || st.st_mode & 0o022 != 0 {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "service IPC runtime directory must be root-owned and not group/other writable",
        )
        .into());
    }
    Ok(())
}

// Purpose:
// - Harden the IPC parent directory before creating/listening socket files.
// - Prevent symlink/path-race abuse and reject unsafe owner/mode.
//
// Approach:
// - Open parent dir with O_NOFOLLOW/O_DIRECTORY and operate on that fd.
// - Validate inode type/owner/mode via fstat.
// - Linux service parents live beneath root-controlled /run and refuse foreign ownership.
// - macOS replaces a foreign service parent; stale artifacts are scrubbed after liveness checks.
//
// Main steps:
// 1) Resolve parent path and open/create directory securely.
// 2) Verify directory inode type and owner uid.
// 3) Enforce expected mode on the retained inode.
// 4) Report parent repair for the macOS caller's separate artifact cleanup.
//
// References:
// - open(2): O_NOFOLLOW/O_DIRECTORY/O_CLOEXEC
//   https://man7.org/linux/man-pages/man2/open.2.html
// - fstat(2): verify file type/metadata on opened fd
//   https://man7.org/linux/man-pages/man2/fstat.2.html
// - unlinkat(2)/mkdirat(2): replace a foreign directory relative to its opened grandparent
//   https://man7.org/linux/man-pages/man2/unlinkat.2.html
//   https://man7.org/linux/man-pages/man2/mkdir.2.html
// - fchmod(2): enforce exact mode on opened fd
//   https://man7.org/linux/man-pages/man2/fchmod.2.html
pub(crate) fn ensure_secure_ipc_parent_dir(path: &str, postfix: &str) -> ResultType<bool> {
    let parent_dir = Path::new(path)
        .parent()
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, format!("invalid ipc path: {path}")))?;
    #[cfg(target_os = "linux")]
    if config::is_service_ipc_postfix(postfix) {
        verify_linux_service_ipc_namespace(parent_dir)?;
    }
    // Harden against common TOCTOU by opening the parent directory with O_NOFOLLOW (so the parent
    // itself cannot be a symlink) and then operating on its retained inode. This ensures
    // we mutate the inode we opened, though it does not protect against symlinks in ancestor path
    // components.
    let parent_c = CString::new(parent_dir.as_os_str().as_bytes().to_vec())?;
    let mut fd = match open_ipc_parent_dir_fd(&parent_c) {
        Ok(fd) => fd,
        Err(open_err) => {
            // IPC parents are single-level children of their selected runtime directory.
            // The opened inode is validated before repairing permissions removed by umask.
            if open_err.raw_os_error() == Some(hbb_common::libc::ENOENT) {
                let expected_mode = expected_ipc_parent_mode(postfix);
                let rc = unsafe {
                    hbb_common::libc::mkdir(
                        parent_c.as_ptr(),
                        expected_mode as hbb_common::libc::mode_t,
                    )
                };
                if rc != 0 {
                    let mkdir_err = std::io::Error::last_os_error();
                    // Handle a race where another process created the directory first.
                    if mkdir_err.raw_os_error() != Some(hbb_common::libc::EEXIST) {
                        return Err(Error::new(
                            mkdir_err.kind(),
                            format!(
                                "failed to mkdir ipc parent dir: postfix={}, parent={}, err={}",
                                postfix,
                                parent_dir.display(),
                                mkdir_err
                            ),
                        )
                        .into());
                    }
                }
                match open_ipc_parent_dir_fd(&parent_c) {
                    Ok(fd) => fd,
                    Err(err) => {
                        return Err(Error::new(
                            err.kind(),
                            format!(
                                "failed to open ipc parent dir (no-follow): postfix={}, parent={}, err={}",
                                postfix,
                                parent_dir.display(),
                                err
                            ),
                        )
                        .into());
                    }
                }
            } else {
                return Err(Error::new(
                    open_err.kind(),
                    format!(
                        "failed to open ipc parent dir (no-follow): postfix={}, parent={}, err={}",
                        postfix,
                        parent_dir.display(),
                        open_err
                    ),
                )
                .into());
            }
        }
    };
    let mut fd_guard = FdGuard(fd);

    let mut st: hbb_common::libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { hbb_common::libc::fstat(fd, &mut st as *mut _) } != 0 {
        let os_err = std::io::Error::last_os_error();
        return Err(Error::new(
            os_err.kind(),
            format!(
                "failed to stat ipc parent dir: postfix={}, parent={}, err={}",
                postfix,
                parent_dir.display(),
                os_err
            ),
        )
        .into());
    }
    let mode = st.st_mode as u32;
    let is_dir = (mode & (hbb_common::libc::S_IFMT as u32)) == (hbb_common::libc::S_IFDIR as u32);
    if !is_dir {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "ipc parent is not directory: postfix={}, parent={}",
                postfix,
                parent_dir.display()
            ),
        )
        .into());
    }

    let expected_uid = unsafe { hbb_common::libc::geteuid() as u32 };
    let mut owner_uid = st.st_uid as u32;
    let mut recreated_foreign_service_parent = false;
    // macOS may replace a foreign service parent. Linux rejects every foreign owner.
    if should_recreate_foreign_service_ipc_parent(owner_uid, expected_uid, postfix) {
        // Close the foreign parent fd before its directory is removed, then re-open the fresh one.
        drop(fd_guard);
        fd = recreate_foreign_service_ipc_parent_dir(parent_dir, postfix)?;
        fd_guard = FdGuard(fd);
        let mut st2: hbb_common::libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { hbb_common::libc::fstat(fd, &mut st2 as *mut _) } != 0 {
            let os_err = std::io::Error::last_os_error();
            return Err(Error::new(
                os_err.kind(),
                format!(
                    "R-S11a(b): failed to stat recreated ipc parent dir: postfix={}, parent={}, err={}",
                    postfix,
                    parent_dir.display(),
                    os_err
                ),
            )
            .into());
        }
        owner_uid = st2.st_uid as u32;
        st = st2;
        recreated_foreign_service_parent = true;
    }
    if owner_uid != expected_uid {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "unsafe ipc parent owner, postfix={}, expected uid {expected_uid}, got {owner_uid}: {}",
                postfix,
                parent_dir.display()
            ),
        )
        .into());
    }

    let expected_mode = expected_ipc_parent_mode(postfix);
    // Include special bits (setuid/setgid/sticky) to ensure the directory is hardened to the exact
    // expected mode.
    let current_mode = (st.st_mode as u32) & 0o7777;
    let repaired_parent_mode = current_mode != expected_mode;
    let had_untrusted_parent_mode = (current_mode & 0o022) != 0;
    if repaired_parent_mode {
        #[cfg(target_os = "linux")]
        let chmod_result = {
            // O_PATH permits ownership validation even when owner read/search is absent.
            // Change only its verified procfs alias, never reopen the mutable parent path.
            let descriptors = ipc_descriptor_directory()?;
            let descriptor = CString::new(fd.to_string())?;
            let mut target: hbb_common::libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { hbb_common::libc::fstatat(descriptors.0, descriptor.as_ptr(), &mut target, 0) } != 0 {
                return Err(Error::last_os_error().into());
            }
            if (target.st_dev, target.st_ino) != (st.st_dev, st.st_ino) {
                return Err(Error::new(ErrorKind::PermissionDenied, "ipc parent descriptor changed").into());
            }
            let rc = unsafe { hbb_common::libc::fchmodat(
                descriptors.0, descriptor.as_ptr(), expected_mode as hbb_common::libc::mode_t, 0,
            ) };
            if rc != 0 { Err(Error::last_os_error()) } else { Ok(()) }
        };
        #[cfg(not(target_os = "linux"))]
        let chmod_result = {
            let rc = unsafe { hbb_common::libc::fchmod(fd, expected_mode as hbb_common::libc::mode_t) };
            if rc != 0 { Err(Error::last_os_error()) } else { Ok(()) }
        };
        if let Err(os_err) = chmod_result {
            return Err(Error::new(
                os_err.kind(),
                format!(
                    "failed to chmod ipc parent dir: postfix={}, parent={}, err={}",
                    postfix,
                    parent_dir.display(),
                    os_err
                ),
            )
            .into());
        }
    }
    #[cfg(target_os = "linux")]
    {
        if unsafe { hbb_common::libc::fstat(fd, &mut st) } != 0 {
            return Err(Error::last_os_error().into());
        }
        if st.st_uid as u32 != expected_uid || st.st_mode as u32 & 0o7777 != expected_mode {
            return Err(Error::new(ErrorKind::PermissionDenied, "ipc parent mode or owner changed").into());
        }
    }
    let should_scrub =
        repaired_parent_mode || recreated_foreign_service_parent || had_untrusted_parent_mode;
    // Close the (possibly-recreated) parent-dir fd now that hardening is complete; the caller re-opens
    // by path to bind. The explicit drop also marks fd_guard read after the recreate-branch rebind.
    drop(fd_guard);
    Ok(should_scrub)
}

#[cfg(target_os = "macos")]
pub(crate) fn scrub_secure_ipc_parent_dir(path: &str, postfix: &str) -> ResultType<()> {
    let parent_dir = Path::new(path)
        .parent()
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, format!("invalid ipc path: {path}")))?;
    let parent_c = CString::new(parent_dir.as_os_str().as_bytes().to_vec())?;
    let fd = open_ipc_parent_dir_fd(&parent_c).map_err(|err| {
        Error::new(
            err.kind(),
            format!(
                "failed to open ipc parent dir for scrub (no-follow): postfix={}, parent={}, err={}",
                postfix,
                parent_dir.display(),
                err
            ),
        )
    })?;
    let _fd_guard = FdGuard(fd);
    scrub_preexisting_ipc_parent_entries(fd, parent_dir, postfix)
}

#[cfg(target_os = "linux")]
fn restore_ipc_socket_owner_access(path: &str, postfix: &str) -> ResultType<()> {
    let path = Path::new(path);
    let parent = path.parent().ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid ipc parent"))?;
    let name = CString::new(format!("ipc{postfix}"))?;
    if path.file_name() != Some(std::ffi::OsStr::new(name.to_str()?)) {
        return Err(Error::new(ErrorKind::InvalidInput, "invalid ipc basename").into());
    }
    if config::is_service_ipc_postfix(postfix) {
        verify_linux_service_ipc_namespace(parent)?;
    }
    let parent = FdGuard(open_ipc_parent_dir_fd(&CString::new(parent.as_os_str().as_bytes())?)?);
    set_ipc_socket_permissions_at(parent.0, postfix, true)
}

#[cfg(target_os = "linux")]
fn set_ipc_socket_permissions_at(
    parent_fd: i32,
    postfix: &str,
    restore_owner_write: bool,
) -> ResultType<()> {
    use hbb_common::libc;

    let name = CString::new(format!("ipc{postfix}"))?;
    let metadata = |fd| -> std::io::Result<libc::stat> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return Err(Error::last_os_error());
        }
        Ok(st)
    };
    let uid = unsafe { libc::geteuid() };
    let directory = metadata(parent_fd)?;
    if directory.st_uid != uid || directory.st_mode & 0o7777 != expected_ipc_parent_mode(postfix) {
        return Err(Error::new(ErrorKind::PermissionDenied, "unsafe ipc socket parent").into());
    }
    let fd = unsafe { libc::openat(parent_fd, name.as_ptr(), libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(Error::last_os_error().into());
    }
    let socket = FdGuard(fd);
    let original = metadata(fd)?;
    if original.st_mode & libc::S_IFMT != libc::S_IFSOCK || original.st_uid != uid
        || original.st_nlink != 1 || original.st_mode & 0o7000 != 0
        || (restore_owner_write && original.st_mode & 0o200 != 0)
    {
        return Err(Error::new(ErrorKind::PermissionDenied, "unsafe ipc socket permission target").into());
    }
    let require_identity = |directory, entry: &std::ffi::CStr, flags| -> ResultType<()> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(directory, entry.as_ptr(), &mut st, flags) } != 0 {
            return Err(Error::last_os_error().into());
        }
        if (st.st_dev, st.st_ino) != (original.st_dev, original.st_ino) {
            return Err(Error::new(ErrorKind::PermissionDenied, "ipc socket identity changed").into());
        }
        Ok(())
    };
    require_identity(parent_fd, &name, libc::AT_SYMLINK_NOFOLLOW)?;
    let descriptors = ipc_descriptor_directory()?;
    let descriptor = CString::new(fd.to_string())?;
    require_identity(descriptors.0, &descriptor, 0)?;
    let mode = if config::is_service_ipc_postfix(postfix) { 0o666 } else { 0o600 };
    // Both initial mode establishment and interrupted-startup recovery mutate
    // only this retained socket; permission failure never authorizes unlinking.
    if unsafe { libc::fchmodat(descriptors.0, descriptor.as_ptr(), mode, 0) } != 0 {
        return Err(Error::last_os_error().into());
    }
    let repaired = metadata(socket.0)?;
    if repaired.st_uid != uid || repaired.st_nlink != 1 || repaired.st_mode & 0o7777 != mode {
        return Err(Error::new(ErrorKind::PermissionDenied, "ipc socket metadata changed").into());
    }
    require_identity(parent_fd, &name, libc::AT_SYMLINK_NOFOLLOW)
}

#[cfg(target_os = "linux")]
async fn connect_existing_listener(postfix: &str) -> ResultType<Option<ConnectionTmpl<ConnClient>>> {
    let path = config::Config::ipc_path(postfix);
    let client: ResultType<Option<ConnClient>> = hbb_common::timeout(1000, async {
        let result = match Endpoint::connect(&path).await {
            Err(err) if err.raw_os_error() == Some(hbb_common::libc::EACCES) => {
                restore_ipc_socket_owner_access(&path, postfix)?;
                Endpoint::connect(&path).await
            }
            result => result,
        };
        match result {
            Ok(client) => Ok(Some(client)),
            Err(err) if matches!(err.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }).await?;
    let Some(client) = client? else { return Ok(None); };
    // Startup probes transport presence before authenticating the incumbent. The
    // application client API intentionally refuses raw credential endpoints.
    let mut connection = if config::is_service_ipc_postfix(postfix) {
        ConnectionTmpl::new_protected_service(client)
    } else {
        ConnectionTmpl::new(client)
    };
    if postfix == "_cm" {
        connection.set_max_packet_length(CM_IPC_MAX_FRAME_BYTES);
    }
    Ok(Some(connection))
}

#[inline]
pub(crate) async fn probe_existing_listener(postfix: &str) -> ResultType<bool> {
    #[cfg(target_os = "linux")]
    let Some(mut stream) = connect_existing_listener(postfix).await? else {
        return Ok(false);
    };
    #[cfg(target_os = "macos")]
    let Ok(mut stream) = connect(1000, postfix).await else {
        return Ok(false);
    };
    #[cfg(target_os = "linux")]
    {
        if postfix == "_cm" {
            let expected_arg = std::env::args().nth(1).unwrap_or_default();
            if expected_arg != "--cm" && expected_arg != "--cm-no-ui" {
                return Ok(false);
            }
            let expected_launch_token =
                std::env::var(crate::common::CM_LAUNCH_TOKEN_ENV).unwrap_or_default();
            let expected_launch_parent = std::env::var(crate::common::CM_LAUNCH_PARENT_ENV)
                .ok()
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or(0);
            if authenticate_cm_endpoint(&stream, current_euid(), expected_launch_parent).is_err() {
                return Ok(false);
            }
            return Ok(super::authenticate_cm_endpoint_launch_proof(
                &mut stream,
                &expected_launch_token,
                &expected_arg,
            )
            .await
            .is_ok());
        }
        if postfix == "_pa" {
            let Ok(expected) = current_linux_process_identity() else {
                return Ok(false);
            };
            return Ok(ensure_linux_process_identity_matches(&stream, &expected, "_pa").is_ok());
        }
    }

    let current_uid = unsafe { hbb_common::libc::geteuid() as u32 };
    let peer_uid = stream.peer_uid().ok_or_else(|| {
        Error::new(
            ErrorKind::PermissionDenied,
            format!("incumbent ipc listener peer uid is unavailable: postfix={postfix}"),
        )
    })?;
    if peer_uid != current_uid {
        return Ok(false);
    }
    let peer_pid = stream.peer_pid().ok_or_else(|| {
        Error::new(
            ErrorKind::PermissionDenied,
            format!("incumbent ipc listener peer pid is unavailable: postfix={postfix}"),
        )
    })?;
    let executable_matches = peer_executable_is_current_by_pid(peer_pid)?;
    if !executable_matches {
        log::debug!(
            "Refusing foreign incumbent ipc listener: postfix={}, peer_uid={}, current_uid={}, peer_pid={}, executable_matches={}",
            postfix,
            peer_uid,
            current_uid,
            peer_pid,
            executable_matches,
        );
        return Ok(false);
    }
    if postfix != crate::POSTFIX_SERVICE {
        return Ok(true);
    }
    stream
        .send_service_request_timeout(&ServiceIpcRequest::LivenessProbe {}, 1000)
        .await
        .map_err(|err| {
            Error::new(
                ErrorKind::TimedOut,
                format!("incumbent protected ipc listener liveness write failed: {err}"),
            )
        })?;
    match stream.next_service_response_timeout(1000).await {
        Ok(Some(ServiceIpcResponse::Liveness {})) => Ok(true),
        Ok(response) => Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "incumbent protected ipc listener returned an invalid liveness response: {response:?}"
            ),
        )
        .into()),
        Err(err) => Err(Error::new(
            ErrorKind::TimedOut,
            format!("incumbent protected ipc listener liveness read failed: {err}"),
        )
        .into()),
    }
}

#[cfg(target_os = "linux")]
fn current_euid() -> u32 {
    unsafe { hbb_common::libc::geteuid() as u32 }
}

#[cfg(target_os = "macos")]
pub(crate) async fn check_existing_listener(postfix: &str) -> ResultType<bool> {
    if probe_existing_listener(postfix).await? {
        return Ok(true);
    }
    // A failed cleanup must reach the caller before it attempts to bind.
    remove_ipc_socket_via_secure_parent_fd(postfix)?;
    Ok(false)
}

#[cfg(target_os = "linux")]
fn open_ipc_startup_lock(parent_fd: i32, name: &std::ffi::CStr, uid: u32) -> ResultType<FdGuard> {
    use hbb_common::libc;

    let metadata_flags = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let read_flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY;
    let mut fresh = false;
    let mut fd = unsafe { libc::openat(parent_fd, name.as_ptr(), metadata_flags) };
    if fd < 0 {
        let err = Error::last_os_error();
        if err.kind() != ErrorKind::NotFound {
            return Err(err.into());
        }
        fd = unsafe {
            libc::openat(
                parent_fd,
                name.as_ptr(),
                read_flags | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                0o600 as libc::mode_t,
            )
        };
        if fd < 0 {
            let err = Error::last_os_error();
            if err.kind() != ErrorKind::AlreadyExists {
                return Err(err.into());
            }
            fd = unsafe { libc::openat(parent_fd, name.as_ptr(), metadata_flags) };
            if fd < 0 {
                return Err(Error::last_os_error().into());
            }
        } else {
            fresh = true;
        }
    }
    let mut guard = FdGuard(fd);
    let metadata = |fd| -> std::io::Result<libc::stat> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return Err(Error::last_os_error());
        }
        Ok(st)
    };
    let original = metadata(fd)?;
    if original.st_mode & libc::S_IFMT != libc::S_IFREG
        || original.st_uid != uid
        || original.st_nlink != 1
        || original.st_mode & 0o7777 & !0o600 != 0
    {
        return Err(Error::new(ErrorKind::PermissionDenied, "unsafe ipc startup lock").into());
    }
    let require_identity = |directory, entry: &std::ffi::CStr, flags| -> ResultType<()> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(directory, entry.as_ptr(), &mut st, flags) } != 0 {
            return Err(Error::last_os_error().into());
        }
        if (st.st_dev, st.st_ino) != (original.st_dev, original.st_ino) {
            return Err(Error::new(ErrorKind::PermissionDenied, "ipc startup lock changed").into());
        }
        Ok(())
    };
    require_identity(parent_fd, name, libc::AT_SYMLINK_NOFOLLOW)?;
    if fresh {
        if unsafe { libc::fchmod(fd, 0o600) } != 0 {
            return Err(Error::last_os_error().into());
        }
    } else {
        // O_PATH admits the inode before any read open or permission repair.
        // A creator may have exited before restoring owner bits removed by umask.
        let descriptors = ipc_descriptor_directory()?;
        let descriptor = CString::new(fd.to_string())?;
        require_identity(descriptors.0, &descriptor, 0)?;
        if original.st_mode & 0o7777 != 0o600
            && unsafe { libc::fchmodat(descriptors.0, descriptor.as_ptr(), 0o600, 0) } != 0
        {
            return Err(Error::last_os_error().into());
        }
        let readable = unsafe { libc::openat(descriptors.0, descriptor.as_ptr(), read_flags) };
        if readable < 0 {
            return Err(Error::last_os_error().into());
        }
        let readable = FdGuard(readable);
        let reopened = metadata(readable.0)?;
        if (reopened.st_dev, reopened.st_ino) != (original.st_dev, original.st_ino) {
            return Err(Error::new(ErrorKind::PermissionDenied, "ipc lock descriptor changed").into());
        }
        guard = readable;
    }
    let st = metadata(guard.0)?;
    if st.st_mode & libc::S_IFMT != libc::S_IFREG
        || st.st_uid != uid
        || st.st_nlink != 1
        || st.st_mode & 0o7777 != 0o600
    {
        return Err(Error::new(ErrorKind::PermissionDenied, "unsafe ipc startup lock").into());
    }
    if unsafe { libc::flock(guard.0, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(Error::last_os_error().into());
    }
    require_identity(parent_fd, name, libc::AT_SYMLINK_NOFOLLOW)?;
    Ok(guard)
}

#[cfg(target_os = "linux")]
pub(crate) struct IpcListenerBind {
    parent: FdGuard,
    _lock: FdGuard,
    parent_path: CString,
    path: String,
    postfix: String,
}

#[cfg(target_os = "linux")]
impl IpcListenerBind {
    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    fn validate_parent(&self) -> ResultType<()> {
        use hbb_common::libc;

        let mut retained: libc::stat = unsafe { std::mem::zeroed() };
        let mut named: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(self.parent.0, &mut retained) } != 0
            || unsafe { libc::fstatat(libc::AT_FDCWD, self.parent_path.as_ptr(), &mut named, libc::AT_SYMLINK_NOFOLLOW) } != 0
        {
            return Err(Error::last_os_error().into());
        }
        let uid = unsafe { libc::geteuid() };
        let mode = expected_ipc_parent_mode(&self.postfix);
        if (retained.st_dev, retained.st_ino) != (named.st_dev, named.st_ino)
            || retained.st_uid != uid || named.st_uid != uid
            || retained.st_mode & 0o7777 != mode || named.st_mode & 0o7777 != mode
            || named.st_mode & libc::S_IFMT != libc::S_IFDIR
        {
            return Err(Error::new(ErrorKind::PermissionDenied, "ipc listener parent identity or metadata changed").into());
        }
        Ok(())
    }

    pub(crate) fn finish(&self) -> ResultType<()> {
        self.validate_parent()?;
        set_ipc_socket_permissions_at(self.parent.0, &self.postfix, false)?;
        self.validate_parent()
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn prepare_ipc_listener_bind(
    path: &str,
    postfix: &str,
) -> ResultType<IpcListenerBind> {
    use hbb_common::libc;

    let path = Path::new(path);
    let basename = format!("ipc{postfix}");
    if path.file_name() != Some(std::ffi::OsStr::new(&basename)) {
        return Err(Error::new(ErrorKind::InvalidInput, "invalid ipc basename").into());
    }
    let parent = path
        .parent()
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid ipc parent"))?;
    if config::is_service_ipc_postfix(postfix) {
        verify_linux_service_ipc_namespace(parent)?;
    }
    let parent_c = CString::new(parent.as_os_str().as_bytes())?;
    let parent_fd = open_ipc_parent_dir_fd(&parent_c)?;
    let parent_guard = FdGuard(parent_fd);
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(parent_fd, &mut st) } != 0 {
        return Err(Error::last_os_error().into());
    }
    let uid = unsafe { libc::geteuid() };
    if st.st_uid != uid || st.st_mode & 0o7777 != expected_ipc_parent_mode(postfix) {
        return Err(Error::new(ErrorKind::PermissionDenied, "ipc parent changed before bind").into());
    }

    // Keep one stable lock inode per endpoint. Never unlink it: replacing a lock
    // pathname would allow overlapping owners. Other endpoints start independently.
    let lock_name = CString::new(format!("{basename}.lock"))?;
    let guard = open_ipc_startup_lock(parent_fd, &lock_name, uid)?;

    // Linux has no bindat. Its procfs descriptor alias keeps bind and the fresh
    // transport check in the retained directory even if the public name moves.
    let descriptors = ipc_descriptor_directory()?;
    let descriptor = CString::new(parent_fd.to_string())?;
    let mut alias: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatat(descriptors.0, descriptor.as_ptr(), &mut alias, 0) } != 0 {
        return Err(Error::last_os_error().into());
    }
    if (alias.st_dev, alias.st_ino) != (st.st_dev, st.st_ino) {
        return Err(Error::new(ErrorKind::PermissionDenied, "ipc parent descriptor changed").into());
    }
    let bind = IpcListenerBind {
        parent: parent_guard,
        _lock: guard,
        parent_path: parent_c,
        path: format!("/proc/thread-self/fd/{parent_fd}/{basename}"),
        postfix: postfix.to_owned(),
    };
    bind.validate_parent()?;

    // The asynchronous probe predates this reservation. Refuse any transport
    // that appeared meanwhile; this check grants no peer or request authority.
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
    socket.set_nonblocking(true)?;
    match socket.connect(&socket2::SockAddr::unix(bind.path())?) {
        Ok(()) => return Err(Error::new(ErrorKind::AddrInUse, "ipc listener is active").into()),
        Err(err) if matches!(err.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {}
        Err(err) => return Err(err.into()),
    }
    // A missing/refused transport does not make an arbitrary filesystem entry
    // a stale socket. Preserve collisions, including symlinks and directories.
    let name = CString::new(basename)?;
    if unsafe { libc::fstatat(parent_fd, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        let err = Error::last_os_error();
        if err.kind() != ErrorKind::NotFound {
            return Err(err.into());
        }
    } else {
        if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
            return Err(Error::new(ErrorKind::AlreadyExists, "ipc endpoint exists and is not a socket").into());
        }
        if unsafe { libc::unlinkat(parent_fd, name.as_ptr(), 0) } != 0 {
            let err = Error::last_os_error();
            if err.kind() != ErrorKind::NotFound {
                return Err(err.into());
            }
        }
    }
    bind.validate_parent()?;
    // The caller retains both directory and reservation through synchronous bind
    // and finalization. No descriptor alias or lock crosses an await.
    Ok(bind)
}

#[cfg(any(target_os = "macos", test))]
#[inline]
pub(crate) fn should_scrub_parent_entries_after_listener_check(
    should_scrub_parent_entries: bool,
    existing_listener_alive: bool,
) -> bool {
    should_scrub_parent_entries && !existing_listener_alive
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_ensure_secure_ipc_parent_dir_rejects_symlink_parent() {
        use std::os::unix::fs::symlink;

        let unique = format!(
            "rustdesk-ipc-secure-dir-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let base = std::env::temp_dir().join(unique);
        let real_dir = base.join("real");
        let link_dir = base.join("link");
        std::fs::create_dir_all(&real_dir).unwrap();
        symlink(&real_dir, &link_dir).unwrap();
        let ipc_path = link_dir.join("ipc");
        let res =
            super::ensure_secure_ipc_parent_dir(ipc_path.to_string_lossy().as_ref(), "");
        assert!(res.is_err());
        std::fs::remove_file(&link_dir).ok();
        std::fs::remove_dir_all(&real_dir).ok();
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn test_ensure_secure_ipc_parent_dir_creates_parent_with_expected_mode() {
        use std::os::unix::fs::PermissionsExt;

        let unique = format!(
            "rustdesk-ipc-secure-dir-create-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let base = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&base).unwrap();

        // Intentionally choose a parent that does not exist to exercise the ENOENT -> mkdir branch.
        let parent_dir = base.join("parent");
        assert!(!parent_dir.exists());
        let ipc_path = parent_dir.join("ipc");

        let res = super::ensure_secure_ipc_parent_dir(ipc_path.to_string_lossy().as_ref(), "");
        // Restrictive umask can make mkdir create a stricter initial mode. In that case
        // ensure_secure_ipc_parent_dir repairs it with fchmod and may request a scrub.
        res.unwrap();

        let md = std::fs::metadata(&parent_dir).unwrap();
        assert!(md.is_dir());
        let mode = md.permissions().mode() & 0o777;
        assert_eq!(mode, 0o0700);

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn test_foreign_service_parent_recreation_policy_is_macos_root_service_only() {
        assert_eq!(super::should_recreate_foreign_service_ipc_parent(
            1001, 0, "_service"
        ), cfg!(target_os = "macos"));
        assert!(!super::should_recreate_foreign_service_ipc_parent(
            0, 0, "_service"
        ));
        assert!(!super::should_recreate_foreign_service_ipc_parent(
            1001, 1000, "_service"
        ));
        assert!(!super::should_recreate_foreign_service_ipc_parent(
            1001, 0, ""
        ));
    }

    #[test]
    fn test_scrub_preexisting_ipc_parent_entries_only_removes_target_postfix_artifacts() {
        use std::os::unix::ffi::OsStrExt;

        let unique = format!(
            "rustdesk-ipc-scrub-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let base = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&base).unwrap();

        let ipc_file = base.join("ipc_service");
        let ipc_pid_file = base.join("ipc_service.pid");
        let ipc_other_postfix_file = base.join("ipc_uinput_1");
        let keep_file = base.join("keep.txt");
        let keep_dir = base.join("keep_dir");

        std::fs::write(&ipc_file, b"socket-placeholder").unwrap();
        std::fs::write(&ipc_pid_file, b"1234").unwrap();
        std::fs::write(&ipc_other_postfix_file, b"other-postfix").unwrap();
        std::fs::write(&keep_file, b"keep").unwrap();
        std::fs::create_dir_all(&keep_dir).unwrap();

        let base_c = std::ffi::CString::new(base.as_os_str().as_bytes().to_vec()).unwrap();
        let base_fd = super::open_ipc_parent_dir_fd(&base_c).unwrap();
        let _base_guard = super::FdGuard(base_fd);
        super::scrub_preexisting_ipc_parent_entries(base_fd, &base, "_service").unwrap();

        assert!(!ipc_file.exists());
        assert!(!ipc_pid_file.exists());
        assert!(ipc_other_postfix_file.exists());
        assert!(keep_file.exists());
        assert!(keep_dir.exists());

        std::fs::remove_file(&ipc_other_postfix_file).ok();
        std::fs::remove_file(&keep_file).ok();
        std::fs::remove_dir_all(&keep_dir).ok();
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn test_scrub_preexisting_ipc_parent_entries_should_bind_to_opened_inode_not_path() {
        use std::os::unix::ffi::OsStrExt;

        let unique = format!(
            "rustdesk-ipc-scrub-fd-bind-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let base = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&base).unwrap();

        let trusted_parent = base.join("trusted_parent");
        let trusted_parent_moved = base.join("trusted_parent_moved");
        let attacker_parent = base.join("attacker_parent");
        std::fs::create_dir_all(&trusted_parent).unwrap();
        std::fs::create_dir_all(&attacker_parent).unwrap();

        let trusted_ipc_file = trusted_parent.join("ipc_service");
        let attacker_ipc_file = attacker_parent.join("ipc_service");
        std::fs::write(&trusted_ipc_file, b"trusted").unwrap();
        std::fs::write(&attacker_ipc_file, b"attacker").unwrap();

        let trusted_parent_c =
            std::ffi::CString::new(trusted_parent.as_os_str().as_bytes().to_vec()).unwrap();
        let trusted_parent_fd = super::open_ipc_parent_dir_fd(&trusted_parent_c).unwrap();
        let _trusted_parent_guard = super::FdGuard(trusted_parent_fd);

        // Swap the path after the trusted inode has been opened.
        std::fs::rename(&trusted_parent, &trusted_parent_moved).unwrap();
        std::fs::rename(&attacker_parent, &trusted_parent).unwrap();

        super::scrub_preexisting_ipc_parent_entries(trusted_parent_fd, &trusted_parent, "_service")
            .unwrap();

        // Expected secure behavior: scrub should target the inode that was opened before path swap.
        assert!(
            !trusted_parent_moved.join("ipc_service").exists(),
            "trusted inode artifact should be removed even after path swap"
        );
        assert!(
            trusted_parent.join("ipc_service").exists(),
            "path-swapped attacker directory should not be scrubbed"
        );

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_ensure_secure_ipc_parent_dir_keeps_service_artifacts_before_liveness_probe() {
        use std::os::unix::fs::PermissionsExt;

        let unique = format!(
            "rustdesk-ipc-secure-dir-order-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let base = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&base).unwrap();

        let parent_dir = base.join("service_parent");
        std::fs::create_dir_all(&parent_dir).unwrap();
        // Trigger "had_untrusted_service_parent_mode".
        std::fs::set_permissions(&parent_dir, std::fs::Permissions::from_mode(0o777)).unwrap();

        let ipc_file = parent_dir.join("ipc_service");
        let ipc_pid_file = parent_dir.join("ipc_service.pid");
        std::fs::write(&ipc_file, b"socket-placeholder").unwrap();
        std::fs::write(&ipc_pid_file, b"1234").unwrap();

        let res =
            super::ensure_secure_ipc_parent_dir(ipc_file.to_string_lossy().as_ref(), "_service");
        assert_eq!(res.unwrap(), true);

        // Parent hardening should run first; artifacts should stay until liveness probe completes.
        assert!(ipc_file.exists(), "ipc socket marker should be preserved");
        assert!(ipc_pid_file.exists(), "pid marker should be preserved");

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn test_ensure_secure_ipc_parent_dir_marks_non_service_mode_repair_for_scrub() {
        use std::os::unix::fs::PermissionsExt;

        let unique = format!(
            "rustdesk-ipc-nonservice-mode-repair-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let base = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&base).unwrap();

        let parent_dir = base.join("non_service_parent");
        std::fs::create_dir_all(&parent_dir).unwrap();
        std::fs::set_permissions(&parent_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let ipc_file = parent_dir.join("ipc");
        std::fs::write(&ipc_file, b"socket-placeholder").unwrap();

        let res = super::ensure_secure_ipc_parent_dir(ipc_file.to_string_lossy().as_ref(), "");
        assert_eq!(res.unwrap(), true);

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn test_should_scrub_parent_entries_after_listener_check_only_when_requested_and_not_alive() {
        assert!(!super::should_scrub_parent_entries_after_listener_check(
            false, false
        ));
        assert!(!super::should_scrub_parent_entries_after_listener_check(
            false, true
        ));
        assert!(super::should_scrub_parent_entries_after_listener_check(
            true, false
        ));
        assert!(!super::should_scrub_parent_entries_after_listener_check(
            true, true
        ));
    }
}
