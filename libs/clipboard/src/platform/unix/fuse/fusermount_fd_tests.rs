use super::*;
use std::{
    fs,
    io::{Read, Write},
    process::Command,
    time::Duration,
};

fn send_rights(socket: &UnixStream, rights: &[RawFd]) {
    let mut payload = [0u8];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let data_len = mem::size_of_val(rights);
    let control_len = unsafe { libc::CMSG_SPACE(data_len as _) } as usize;
    let words = (control_len + mem::size_of::<usize>() - 1) / mem::size_of::<usize>();
    let mut control = vec![0usize; words];
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control_len;
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&message) };
    assert!(!cmsg.is_null());
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(data_len as _) as _;
        std::ptr::copy_nonoverlapping(rights.as_ptr().cast::<u8>(), libc::CMSG_DATA(cmsg), data_len);
    }
    assert_eq!(unsafe { libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL) }, 1);
}

fn transfer_one() -> (UnixStream, OwnedFd) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let (witness, source) = UnixStream::pair().unwrap();
    witness.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    send_rights(&sender, &[source.as_raw_fd()]);
    drop(source);
    let received = receive_fusermount_fd(&receiver).unwrap();
    (witness, received)
}

fn assert_closed(witness: &mut UnixStream) {
    witness.set_read_timeout(Some(Duration::from_millis(250))).unwrap();
    let mut byte = [0u8];
    assert_eq!(witness.read(&mut byte).expect("a refused descriptor must have no surviving reference"), 0);
}

fn assert_cloexec(fd: RawFd) {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(flags >= 0);
    assert_ne!(flags & libc::FD_CLOEXEC, 0, "descriptor must already be close-on-exec");
}

#[test]
fn receives_exact_native_object_and_closes_on_drop() {
    let (mut witness, received) = transfer_one();
    witness.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut received = UnixStream::from(received);
    received.write_all(b"native descriptor").unwrap();
    let mut data = [0u8; 17];
    witness.read_exact(&mut data).unwrap();
    assert_eq!(&data, b"native descriptor");
    drop(received);
    assert_closed(&mut witness);
}

#[test]
fn received_descriptor_is_cloexec() {
    let (_, received) = transfer_one();
    assert_cloexec(received.as_raw_fd());
}

fn refused_rights_leave_no_references(count: usize) {
    let (sender, receiver) = UnixStream::pair().unwrap();
    let pairs: Vec<_> = (0..count).map(|_| UnixStream::pair().unwrap()).collect();
    let rights: Vec<_> = pairs.iter().map(|(_, source)| source.as_raw_fd()).collect();
    send_rights(&sender, &rights);
    let mut witnesses: Vec<_> = pairs.into_iter().map(|(witness, source)| {
        drop(source);
        witness
    }).collect();
    let result = receive_fusermount_fd(&receiver);
    let refused = result.is_err();
    drop(result);
    for witness in &mut witnesses {
        assert_closed(witness);
    }
    assert!(refused, "multiple descriptors must never be accepted");
}

#[test]
fn extra_descriptor_is_refused_and_all_handles_close() {
    refused_rights_leave_no_references(2);
}

#[test]
fn truncated_rights_close_every_delivered_handle() {
    for count in [3, 8, 32] {
        refused_rights_leave_no_references(count);
    }
}

#[test]
fn payload_without_rights_refuses() {
    let (mut sender, receiver) = UnixStream::pair().unwrap();
    sender.write_all(&[0]).unwrap();
    assert!(receive_fusermount_fd(&receiver).is_err());
}

#[test]
fn peer_eof_refuses() {
    let (sender, receiver) = UnixStream::pair().unwrap();
    drop(sender);
    assert!(receive_fusermount_fd(&receiver).is_err());
}

#[test]
fn duplicated_descriptor_is_cloexec_and_retains_object() {
    let (mut witness, received) = transfer_one();
    let duplicate = duplicate_owned_fd(received.as_raw_fd()).unwrap();
    assert_ne!(received.as_raw_fd(), duplicate.as_raw_fd());
    assert_cloexec(duplicate.as_raw_fd());
    drop(received);
    let mut duplicate = UnixStream::from(duplicate);
    duplicate.write_all(b"same object").unwrap();
    let mut data = [0u8; 11];
    witness.read_exact(&mut data).unwrap();
    assert_eq!(&data, b"same object");
    drop(duplicate);
    assert_closed(&mut witness);
}

#[test]
fn duplicate_bad_descriptor_refuses() {
    let error = duplicate_owned_fd(-1).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EBADF));
}

fn descriptor_identity(fd: RawFd) -> String {
    fs::read_link(format!("/proc/self/fd/{fd}")).unwrap().to_str().unwrap().to_owned()
}

fn object_matches(value: &str) -> bool {
    let (fd, object) = value.split_once('|').unwrap();
    fs::read_link(format!("/proc/self/fd/{fd}"))
        .map(|path| path.as_os_str() == std::ffi::OsStr::new(object))
        .unwrap_or(false)
}

#[test]
fn descriptors_do_not_survive_exec() {
    if let Ok(control) = std::env::var("RD_FUSE_FD_EXEC_CONTROL") {
        assert!(object_matches(&control), "positive inherited-object control is absent");
        for name in ["RD_FUSE_FD_EXEC_RECEIVED", "RD_FUSE_FD_EXEC_DUPLICATE"] {
            assert!(!object_matches(&std::env::var(name).unwrap()), "FUSE descriptor survived exec");
        }
        return;
    }
    let (_, received) = transfer_one();
    let duplicate = duplicate_owned_fd(received.as_raw_fd()).unwrap();
    let (control, _control_peer) = UnixStream::pair().unwrap();
    assert_eq!(unsafe { libc::fcntl(control.as_raw_fd(), libc::F_SETFD, 0) }, 0);
    let test_name = std::thread::current().name().unwrap().to_owned();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", &test_name, "--nocapture"]);
    for (name, fd) in [
        ("RD_FUSE_FD_EXEC_CONTROL", control.as_raw_fd()),
        ("RD_FUSE_FD_EXEC_RECEIVED", received.as_raw_fd()),
        ("RD_FUSE_FD_EXEC_DUPLICATE", duplicate.as_raw_fd()),
    ] {
        command.env(name, format!("{fd}|{}", descriptor_identity(fd)));
    }
    let output = command.output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
}
