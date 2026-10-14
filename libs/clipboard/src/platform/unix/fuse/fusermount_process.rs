use super::fusermount_fd::receive_fusermount_fd;
use hbb_common::{libc, platform::linux::OwnedAuthorizationChild};
use std::{
    io::{self, Read},
    os::unix::{io::{AsRawFd, OwnedFd, RawFd}, net::UnixStream},
    process::{Command, Output},
    time::{Duration, Instant},
};

const HELPER_TIMEOUT: Duration = Duration::from_secs(5);
const HELPER_OUTPUT_LIMIT: usize = 1024 * 1024;

struct HelperScope<G> {
    // Close the reply channel before retiring the child, then release the mount.
    receiver: Option<UnixStream>,
    owner: OwnedAuthorizationChild,
    mount: Option<G>,
}

pub(super) fn mount<G>(
    command: &mut Command,
    communication: UnixStream,
    receiver: UnixStream,
    retain_mount: impl FnOnce(OwnedFd) -> G,
) -> io::Result<(Output, G)> {
    let deadline = Instant::now() + HELPER_TIMEOUT;
    let owner = OwnedAuthorizationChild::spawn(command)?;
    drop(communication);
    finish(owner, Some(receiver), retain_mount, deadline, HELPER_OUTPUT_LIMIT)
        .and_then(|(output, mount)| {
            mount.map(|mount| (output, mount)).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "fusermount returned no descriptor")
            })
        })
}

pub(super) fn unmount(command: &mut Command) -> io::Result<Output> {
    let deadline = Instant::now() + HELPER_TIMEOUT;
    let owner = OwnedAuthorizationChild::spawn(command)?;
    finish(owner, None, |_| (), deadline, HELPER_OUTPUT_LIMIT).map(|(output, _)| output)
}

fn nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn drain(
    stream: &mut impl Read,
    bytes: &mut Vec<u8>,
    remaining: usize,
) -> io::Result<(bool, bool)> {
    let mut buffer = [0u8; 8192];
    match stream.read(&mut buffer) {
        Ok(0) => Ok((true, false)),
        Ok(count) if count > remaining => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fusermount diagnostics exceed their combined byte limit",
        )),
        Ok(count) => {
            bytes.extend_from_slice(&buffer[..count]);
            Ok((false, true))
        }
        Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {
            Ok((false, false))
        }
        Err(error) => Err(error),
    }
}

fn finish<G>(
    owner: OwnedAuthorizationChild,
    receiver: Option<UnixStream>,
    retain_mount: impl FnOnce(OwnedFd) -> G,
    deadline: Instant,
    output_limit: usize,
) -> io::Result<(Output, Option<G>)> {
    let mut scope = HelperScope { receiver, owner, mount: None };
    let mut stdout = scope.owner.take_stdout().ok_or_else(|| {
        io::Error::new(io::ErrorKind::Other, "fusermount stdout pipe is missing")
    })?;
    let mut stderr = scope.owner.take_stderr().ok_or_else(|| {
        io::Error::new(io::ErrorKind::Other, "fusermount stderr pipe is missing")
    })?;
    nonblocking(stdout.as_raw_fd())?;
    nonblocking(stderr.as_raw_fd())?;
    if let Some(receiver) = &scope.receiver {
        nonblocking(receiver.as_raw_fd())?;
    }
    let mut retain_mount = Some(retain_mount);
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    let mut status = None;
    let mut descriptor_error = None;
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "fusermount exceeded its initiating deadline"));
        }
        let mut progressed = false;
        if !stdout_eof {
            let remaining = output_limit.saturating_sub(out.len() + err.len());
            let (eof, read) = drain(&mut stdout, &mut out, remaining)?;
            stdout_eof = eof;
            progressed |= read;
        }
        if !stderr_eof {
            let remaining = output_limit.saturating_sub(out.len() + err.len());
            let (eof, read) = drain(&mut stderr, &mut err, remaining)?;
            stderr_eof = eof;
            progressed |= read;
        }
        if let Some(socket) = &scope.receiver {
            match receive_fusermount_fd(socket) {
                Ok(fd) => {
                    let retain = retain_mount.take().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "fusermount descriptor was already admitted")
                    })?;
                    scope.mount = Some(retain(fd));
                    scope.receiver = None;
                    progressed = true;
                }
                Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {}
                Err(error) => {
                    scope.receiver = None;
                    scope.owner.terminate_and_reap()?;
                    descriptor_error = Some(error);
                    progressed = true;
                }
            }
        }
        if status.is_none() {
            status = scope.owner.try_wait()?;
        }
        if let Some(status) = status {
            if stdout_eof && stderr_eof && scope.receiver.is_none() {
                if let Some(error) = descriptor_error {
                    return Err(io::Error::new(error.kind(), format!(
                        "fusermount descriptor reply failed: {error}; stderr: {}",
                        String::from_utf8_lossy(&err),
                    )));
                }
                return Ok((Output { status, stdout: out, stderr: err }, scope.mount.take()));
            }
        }
        if !progressed {
            let result = unsafe { libc::poll(std::ptr::null_mut(), 0, 5) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "fusermount_process_tests.rs"]
mod tests;
