use super::*;
use super::super::fusermount_fd::duplicate_owned_fd;
use std::{
    io::{Read, Write},
    os::unix::{io::{FromRawFd, RawFd}, process::CommandExt},
    process::Stdio,
    sync::{atomic::{AtomicBool, Ordering}, Arc},
};

const ENTRY: &str = "normal_completion_drains_output_and_retains_the_original";

fn send_fd(socket: &UnixStream, fd: RawFd, count: usize) {
    let mut data = [0u8];
    let mut iov = libc::iovec { iov_base: data.as_mut_ptr().cast(), iov_len: 1 };
    let size = count * std::mem::size_of::<RawFd>();
    let space = unsafe { libc::CMSG_SPACE(size as _) } as usize;
    let word = std::mem::size_of::<usize>();
    let mut control = vec![0usize; (space + word - 1) / word];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = space;
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&message) };
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size as _) as _;
        for index in 0..count {
            libc::CMSG_DATA(cmsg).add(index * std::mem::size_of::<RawFd>()).cast::<RawFd>().write_unaligned(fd);
        }
    }
    assert_eq!(unsafe { libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL) }, 1);
}

fn producer(mode: &str) -> ! {
    let descriptor = |name| std::env::var(name).unwrap().parse::<RawFd>().unwrap();
    let mut ready = unsafe { UnixStream::from_raw_fd(descriptor("RD_FUSE_HELPER_READY")) };
    ready.write_all(&std::process::id().to_be_bytes()).unwrap();
    let channel = unsafe { UnixStream::from_raw_fd(descriptor("RD_FUSE_HELPER_CHANNEL")) };
    let passed = unsafe { UnixStream::from_raw_fd(descriptor("RD_FUSE_HELPER_OBJECT")) };
    match mode {
        "silent" => std::thread::sleep(Duration::from_secs(60)),
        "overflow" => {
            std::io::stdout().write_all(&vec![b'o'; 2 * HELPER_OUTPUT_LIMIT]).unwrap();
        }
        "valid" | "exit7" => {
            let capacity = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_GETPIPE_SZ) };
            assert!(capacity > 0 && (capacity as usize) < HELPER_OUTPUT_LIMIT / 2);
            std::io::stdout().write_all(&vec![b'o'; capacity as usize + 8192]).unwrap();
            std::io::stderr().write_all(b"native stderr marker").unwrap();
            send_fd(&channel, passed.as_raw_fd(), 1);
        }
        "fd-hang" => {
            send_fd(&channel, passed.as_raw_fd(), 1);
            std::thread::sleep(Duration::from_secs(60));
        }
        "extra" => {
            send_fd(&channel, passed.as_raw_fd(), 2);
            std::thread::sleep(Duration::from_secs(60));
        }
        _ => panic!("unexpected child mode"),
    }
    std::process::exit(if mode == "exit7" { 7 } else { 0 });
}

struct Fixture {
    owner: OwnedAuthorizationChild,
    channel: UnixStream,
    witness: UnixStream,
    pid: libc::pid_t,
    pidfd: OwnedFd,
}

fn fixture(mode: &str, stdout_pipe: bool) -> Fixture {
    let (mut ready, child_ready) = UnixStream::pair().unwrap();
    let (channel, child_channel) = UnixStream::pair().unwrap();
    let (witness, child_object) = UnixStream::pair().unwrap();
    let current = std::thread::current();
    let prefix = current.name().unwrap().rsplit_once("::").unwrap().0;
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", &format!("{prefix}::{ENTRY}"), "--nocapture"])
        .stdin(Stdio::null()).stderr(Stdio::piped())
        .stdout(if stdout_pipe { Stdio::piped() } else { Stdio::null() })
        .env("RD_FUSE_HELPER_MODE", mode);
    for (name, fd) in [
        ("RD_FUSE_HELPER_READY", child_ready.as_raw_fd()),
        ("RD_FUSE_HELPER_CHANNEL", child_channel.as_raw_fd()),
        ("RD_FUSE_HELPER_OBJECT", child_object.as_raw_fd()),
    ] {
        command.env(name, fd.to_string());
    }
    let inherited = [child_ready.as_raw_fd(), child_channel.as_raw_fd(), child_object.as_raw_fd()];
    unsafe {
        command.pre_exec(move || {
            for fd in inherited {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let owner = OwnedAuthorizationChild::spawn(&mut command).unwrap();
    drop((child_ready, child_channel, child_object));
    ready.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut pid = [0u8; 4];
    ready.read_exact(&mut pid).unwrap();
    let pid = u32::from_be_bytes(pid) as libc::pid_t;
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(fd >= 0);
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
    Fixture { owner, channel, witness, pid, pidfd }
}

fn reaped(pid: libc::pid_t) -> bool {
    let mut status = 0;
    (unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) }) == -1
        && io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
}

fn assert_retired(pid: libc::pid_t, pidfd: &OwnedFd, witness: &mut UnixStream) {
    let mut event = libc::pollfd { fd: pidfd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    assert_eq!(unsafe { libc::poll(&mut event, 1, 0) }, 1);
    assert!(event.revents & libc::POLLIN != 0);
    assert!(reaped(pid), "the actual child must already have been reaped");
    witness.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    assert_eq!(witness.read(&mut [0u8; 1]).unwrap(), 0);
}

#[test]
fn normal_completion_drains_output_and_retains_the_original() {
    if let Ok(mode) = std::env::var("RD_FUSE_HELPER_MODE") {
        producer(&mode);
    }
    let Fixture { owner, channel, mut witness, pid, pidfd } = fixture("valid", true);
    let (output, original) = finish(owner, Some(channel), |fd| fd,
        Instant::now() + Duration::from_secs(3), HELPER_OUTPUT_LIMIT).unwrap();
    assert!(output.status.success());
    assert!(output.stdout.iter().filter(|byte| **byte == b'o').count() > 8192);
    assert!(output.stderr.ends_with(b"native stderr marker"));
    assert!(reaped(pid));
    let original = original.unwrap();
    let copied = duplicate_owned_fd(original.as_raw_fd()).unwrap();
    drop(original);
    let mut copied = UnixStream::from(copied);
    copied.write_all(b"after exact helper exit").unwrap();
    let mut bytes = [0u8; 23];
    witness.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"after exact helper exit");
    drop(copied);
    assert_retired(pid, &pidfd, &mut witness);
}

#[test]
fn failed_exit_is_preserved_after_reaping() {
    let Fixture { owner, channel, mut witness, pid, pidfd } = fixture("exit7", true);
    let (output, original) = finish(owner, Some(channel), |fd| fd,
        Instant::now() + Duration::from_secs(3), HELPER_OUTPUT_LIMIT).unwrap();
    assert_eq!(output.status.code(), Some(7));
    drop(original);
    assert_retired(pid, &pidfd, &mut witness);
}

#[test]
fn absent_descriptor_deadline_kills_and_reaps_the_actual_child() {
    let Fixture { owner, channel, mut witness, pid, pidfd } = fixture("silent", true);
    let result = finish(owner, Some(channel), |fd| fd,
        Instant::now() + Duration::from_millis(100), HELPER_OUTPUT_LIMIT);
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_retired(pid, &pidfd, &mut witness);
}

#[test]
fn output_exhaustion_closes_admission_and_reaps() {
    let Fixture { owner, channel, mut witness, pid, pidfd } = fixture("overflow", true);
    let result = finish(owner, Some(channel), |fd| fd,
        Instant::now() + Duration::from_secs(3), 16384);
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_retired(pid, &pidfd, &mut witness);
}

struct Cleanup {
    _fd: OwnedFd,
    pid: libc::pid_t,
    observed: Arc<AtomicBool>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        self.observed.store(reaped(self.pid), Ordering::Release);
    }
}

#[test]
fn admitted_mount_cleanup_follows_exact_child_retirement() {
    let Fixture { owner, channel, mut witness, pid, pidfd } = fixture("fd-hang", true);
    let observed = Arc::new(AtomicBool::new(false));
    let result = finish(owner, Some(channel), |fd| Cleanup { _fd: fd, pid, observed: observed.clone() },
        Instant::now() + Duration::from_millis(100), HELPER_OUTPUT_LIMIT);
    assert!(matches!(result, Err(ref error) if error.kind() == io::ErrorKind::TimedOut));
    assert!(observed.load(Ordering::Acquire));
    assert_retired(pid, &pidfd, &mut witness);
}

#[test]
fn malformed_rights_never_publish_a_mount_owner() {
    let Fixture { owner, channel, mut witness, pid, pidfd } = fixture("extra", true);
    let admitted = Arc::new(AtomicBool::new(false));
    let result = finish(owner, Some(channel), |fd| { admitted.store(true, Ordering::Release); fd },
        Instant::now() + Duration::from_secs(3), HELPER_OUTPUT_LIMIT);
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert!(!admitted.load(Ordering::Acquire));
    assert_retired(pid, &pidfd, &mut witness);
}

#[test]
fn guard_construction_unwind_retires_the_actual_child() {
    let Fixture { owner, channel, mut witness, pid, pidfd } = fixture("fd-hang", true);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        finish(owner, Some(channel), |_fd| -> OwnedFd { panic!("mount construction unwind") },
            Instant::now() + Duration::from_secs(3), HELPER_OUTPUT_LIMIT)
    }));
    assert!(result.is_err());
    assert_retired(pid, &pidfd, &mut witness);
}

#[test]
fn missing_pipe_refuses_and_reaps_before_return() {
    let Fixture { owner, channel, mut witness, pid, pidfd } = fixture("silent", false);
    let result = finish(owner, Some(channel), |fd| fd,
        Instant::now() + Duration::from_secs(3), HELPER_OUTPUT_LIMIT);
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Other);
    assert_retired(pid, &pidfd, &mut witness);
}

#[test]
fn unmount_uses_the_same_owned_output_boundary() {
    let mut command = Command::new("/usr/bin/printf");
    command.args(["unmount result"]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let output = unmount(&mut command).unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"unmount result");
    assert!(output.stderr.is_empty());
}
