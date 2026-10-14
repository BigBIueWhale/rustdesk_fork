use std::{
    io,
    mem,
    os::unix::{
        io::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        net::UnixStream,
    },
};

pub(super) fn receive_fusermount_fd(socket: &UnixStream) -> io::Result<OwnedFd> {
    let mut payload = [0u8];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    // CMSG_SPACE for one fd may have room for a second fd in its padding.
    // cmsghdr storage supplies the alignment required by CMSG_FIRSTHDR/NXTHDR.
    let mut control: [libc::cmsghdr; 2] = unsafe { mem::zeroed() };
    let control_len = unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as _) } as usize;
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    let received_bytes = loop {
        message.msg_controllen = control_len;
        message.msg_flags = 0;
        let result = unsafe {
            libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC)
        };
        if result >= 0 {
            break result;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    };

    let header_len = unsafe { libc::CMSG_LEN(0) } as usize;
    let expected_len = unsafe { libc::CMSG_LEN(mem::size_of::<RawFd>() as _) } as usize;
    let mut received = None;
    let mut exact_one = true;
    let mut headers = 0;
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !cmsg.is_null() {
        headers += 1;
        // recvmsg's kernel-generated headers describe the descriptors installed
        // in this process, including the prefix of a truncated rights message.
        let header = unsafe { &*cmsg };
        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
            let data_len = header.cmsg_len.saturating_sub(header_len);
            let count = data_len / mem::size_of::<RawFd>();
            exact_one &= header.cmsg_len == expected_len;
            for index in 0..count {
                let fd = unsafe {
                    libc::CMSG_DATA(cmsg)
                        .add(index * mem::size_of::<RawFd>())
                        .cast::<RawFd>()
                        .read_unaligned()
                };
                if fd < 0 {
                    exact_one = false;
                    continue;
                }
                let owned = unsafe { OwnedFd::from_raw_fd(fd) };
                if received.is_none() {
                    received = Some(owned);
                } else {
                    exact_one = false;
                    drop(owned);
                }
            }
        } else {
            exact_one = false;
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&message, cmsg) };
    }
    // Ownership must precede every refusal: MSG_CTRUNC does not close the
    // descriptors that fit in the receive buffer.
    if received_bytes != 1
        || message.msg_flags & libc::MSG_CTRUNC != 0
        || headers != 1
        || !exact_one
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fusermount must return exactly one complete descriptor",
        ));
    }
    received.ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "fusermount returned no descriptor")
    })
}

pub(super) fn duplicate_owned_fd(fd: RawFd) -> io::Result<OwnedFd> {
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

#[cfg(test)]
#[path = "fusermount_fd_tests.rs"]
mod tests;
