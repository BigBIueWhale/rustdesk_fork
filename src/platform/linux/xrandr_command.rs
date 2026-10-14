use hbb_common::{libc, log};
use std::{
    io::{self, Read},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const OUTPUT_LIMIT: usize = 1024 * 1024;

struct CommandChild {
    child: Child,
    pidfd: Option<OwnedFd>,
    joined: bool,
}

impl CommandChild {
    fn exited(&self) -> io::Result<bool> {
        let Some(pidfd) = &self.pidfd else {
            return Ok(false);
        };
        let mut event = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut event, 1, 0) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if event.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "xrandr pidfd became invalid"));
        }
        Ok(event.revents & (libc::POLLIN | libc::POLLHUP) != 0)
    }

    fn retire(&mut self) -> io::Result<()> {
        if self.joined {
            return Ok(());
        }
        loop {
            if let Some(pidfd) = &self.pidfd {
                let result = unsafe {
                    libc::syscall(libc::SYS_pidfd_send_signal, pidfd.as_raw_fd(),
                        libc::SIGKILL, std::ptr::null::<libc::siginfo_t>(), 0)
                };
                if result < 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::ESRCH) {
                        log::error!("Could not terminate owned xrandr child: {error}");
                    }
                }
            }
            // Without an acquired pidfd, retain the unreaped Child and wait naturally.
            // A failed identity acquisition never selects numeric-PID signaling.
            match self.child.wait() {
                Ok(_) => {
                    self.joined = true;
                    return Ok(());
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    if error.raw_os_error() == Some(libc::ECHILD) {
                        match self.exited() {
                            Ok(true) => {
                                self.joined = true;
                                return Err(error);
                            }
                            Ok(false) => {}
                            Err(poll_error) => log::error!("Could not prove xrandr exit: {poll_error}"),
                        }
                    }
                    log::error!("Owned xrandr child has not been reaped: {error}");
                    // Keep ownership and bound retry CPU even if a wait syscall fails.
                    let result = unsafe { libc::poll(std::ptr::null_mut(), 0, 50) };
                    if result < 0 {
                        let error = io::Error::last_os_error();
                        if error.kind() != io::ErrorKind::Interrupted {
                            log::error!("xrandr retirement retry wait failed: {error}");
                        }
                    }
                }
            }
        }
    }
}

impl Drop for CommandChild {
    fn drop(&mut self) {
        if let Err(error) = self.retire() {
            log::error!("Owned xrandr child exit status was unavailable: {error}");
        }
    }
}

pub(super) fn run(command: Command) -> io::Result<Output> {
    run_with_limits(command, COMMAND_TIMEOUT, OUTPUT_LIMIT)
}

fn run_with_limits(mut command: Command, timeout: Duration, output_limit: usize) -> io::Result<Output> {
    let mut disposition: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut disposition) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if disposition.sa_sigaction == libc::SIG_IGN || disposition.sa_flags & libc::SA_NOCLDWAIT != 0 {
        return Err(io::Error::new(io::ErrorKind::Other, "xrandr requires retained child wait authority"));
    }
    let deadline = Instant::now() + timeout;
    let child = command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()?;
    let mut owned = CommandChild { child, pidfd: None, joined: false };
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, owned.child.id(), 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    owned.pidfd = Some(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) });
    let Some(mut stdout) = owned.child.stdout.take() else {
        return Err(io::Error::new(io::ErrorKind::Other, "xrandr stdout pipe is missing"));
    };
    let flags = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut eof = false;
    let mut status = None;
    loop {
        if let Some(status) = status {
            if eof {
                return Ok(Output { status, stdout: bytes, stderr: Vec::new() });
            }
        }
        if Instant::now() >= deadline {
            owned.retire()?;
            return Err(io::Error::new(io::ErrorKind::TimedOut, "xrandr command exceeded its deadline"));
        }
        let mut progressed = false;
        if !eof {
            match stdout.read(&mut buffer) {
                Ok(0) => eof = true,
                Ok(count) => {
                    if count > output_limit.saturating_sub(bytes.len()) {
                        owned.retire()?;
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "xrandr output exceeds its limit"));
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        if status.is_none() {
            status = owned.child.try_wait()?;
            if status.is_some() {
                owned.joined = true;
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
