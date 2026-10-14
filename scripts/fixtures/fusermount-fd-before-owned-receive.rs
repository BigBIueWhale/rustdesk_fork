// Exact functions from 35f380ff's production FUSE module; error adaptation is in the driver.
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
