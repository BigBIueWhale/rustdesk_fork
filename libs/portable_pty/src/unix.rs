//! Working with pseudo-terminals

use crate::{Child, CommandBuilder, MasterPty, PtyPair, PtySize, PtySystem, SlavePty};
use anyhow::{bail, Error};
use filedescriptor::FileDescriptor;
use libc::{self, winsize};
use std::cell::RefCell;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::{io, mem, mem::MaybeUninit, ptr};

pub use std::os::unix::io::RawFd;

#[derive(Default)]
pub struct UnixPtySystem {}

fn openpty(size: PtySize) -> anyhow::Result<(UnixMasterPty, UnixSlavePty)> {
    let mut master: RawFd = -1;
    let mut slave: RawFd = -1;

    let mut size = winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: size.pixel_width,
        ws_ypixel: size.pixel_height,
    };

    let result = unsafe {
        // BSDish systems may require mut pointers to some args
        #[cfg_attr(feature = "cargo-clippy", allow(clippy::unnecessary_mut_passed))]
        libc::openpty(
            &mut master,
            &mut slave,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut size,
        )
    };

    if result != 0 {
        bail!("failed to openpty: {:?}", io::Error::last_os_error());
    }

    let master = UnixMasterPty {
        fd: PtyFd(unsafe { FileDescriptor::from_raw_fd(master) }),
        took_writer: RefCell::new(false),
    };
    let slave = UnixSlavePty {
        fd: PtyFd(unsafe { FileDescriptor::from_raw_fd(slave) }),
    };

    // Ensure that these descriptors will get closed when we execute
    // the child process.  This is done after constructing the Pty
    // instances so that we ensure that the Ptys get drop()'d if
    // the cloexec() functions fail (unlikely!).
    cloexec(master.fd.as_raw_fd())?;
    cloexec(slave.fd.as_raw_fd())?;

    Ok((master, slave))
}

impl PtySystem for UnixPtySystem {
    fn openpty(&self, size: PtySize) -> anyhow::Result<PtyPair> {
        let (master, slave) = openpty(size)?;
        Ok(PtyPair {
            master: Box::new(master),
            slave: Box::new(slave),
        })
    }
}

struct PtyFd(pub FileDescriptor);
impl std::ops::Deref for PtyFd {
    type Target = FileDescriptor;
    fn deref(&self) -> &FileDescriptor {
        &self.0
    }
}
impl std::ops::DerefMut for PtyFd {
    fn deref_mut(&mut self) -> &mut FileDescriptor {
        &mut self.0
    }
}

impl Read for PtyFd {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        match self.0.read(buf) {
            Err(ref e) if e.raw_os_error() == Some(libc::EIO) => {
                // EIO indicates that the slave pty has been closed.
                // Treat this as EOF so that std::io::Read::read_to_string
                // and similar functions gracefully terminate when they
                // encounter this condition
                Ok(0)
            }
            x => x,
        }
    }
}

const MAX_UNIX_DESCRIPTOR_LIMIT: u64 = 1_048_576;

struct UnixChildDescriptorPolicy {
    last_fd: RawFd,
    observed_descriptors: Vec<RawFd>,
}

impl UnixChildDescriptorPolicy {
    fn prepare() -> io::Result<Self> {
        let mut limits = MaybeUninit::<libc::rlimit>::uninit();
        let limits = unsafe {
            if libc::getrlimit(libc::RLIMIT_NOFILE, limits.as_mut_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
            limits.assume_init()
        };
        let last_fd = validated_unix_descriptor_upper_bound(limits.rlim_cur as u64)?;

        let mut observed_descriptors = Vec::new();
        for entry in std::fs::read_dir("/dev/fd")? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "descriptor directory contains a non-UTF-8 entry",
                ));
            };
            let Ok(fd) = name.parse::<RawFd>() else {
                continue;
            };
            if fd > libc::STDERR_FILENO {
                observed_descriptors.push(fd);
            }
        }
        observed_descriptors.sort_unstable();
        observed_descriptors.dedup();
        Ok(Self {
            last_fd,
            observed_descriptors,
        })
    }

    fn mark_close_on_exec(&self) -> io::Result<()> {
        for fd in (libc::STDERR_FILENO + 1)..=self.last_fd {
            set_descriptor_close_on_exec_if_open(fd)?;
        }
        for &fd in &self.observed_descriptors {
            if fd <= self.last_fd {
                continue;
            }
            set_descriptor_close_on_exec_if_open(fd)?;
        }
        Ok(())
    }
}

fn validated_unix_descriptor_upper_bound(descriptor_limit: u64) -> io::Result<RawFd> {
    if descriptor_limit == 0
        || descriptor_limit == libc::RLIM_INFINITY as u64
        || descriptor_limit > MAX_UNIX_DESCRIPTOR_LIMIT
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported Unix descriptor limit: {descriptor_limit}"),
        ));
    }
    Ok((descriptor_limit - 1) as RawFd)
}

fn set_descriptor_close_on_exec_if_open(fd: RawFd) -> io::Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags == -1 {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::EBADF) {
                Ok(())
            } else {
                Err(error)
            };
        }
        if flags & libc::FD_CLOEXEC == 0
            && libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) == -1
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

impl PtyFd {
    fn resize(&self, size: PtySize) -> Result<(), Error> {
        let ws_size = winsize {
            ws_row: size.rows,
            ws_col: size.cols,
            ws_xpixel: size.pixel_width,
            ws_ypixel: size.pixel_height,
        };

        if unsafe {
            libc::ioctl(
                self.0.as_raw_fd(),
                libc::TIOCSWINSZ as _,
                &ws_size as *const _,
            )
        } != 0
        {
            bail!(
                "failed to ioctl(TIOCSWINSZ): {:?}",
                io::Error::last_os_error()
            );
        }

        Ok(())
    }

    fn get_size(&self) -> Result<PtySize, Error> {
        let mut size: winsize = unsafe { mem::zeroed() };
        if unsafe {
            libc::ioctl(
                self.0.as_raw_fd(),
                libc::TIOCGWINSZ as _,
                &mut size as *mut _,
            )
        } != 0
        {
            bail!(
                "failed to ioctl(TIOCGWINSZ): {:?}",
                io::Error::last_os_error()
            );
        }
        Ok(PtySize {
            rows: size.ws_row,
            cols: size.ws_col,
            pixel_width: size.ws_xpixel,
            pixel_height: size.ws_ypixel,
        })
    }

    fn spawn_command(&self, builder: CommandBuilder) -> anyhow::Result<std::process::Child> {
        let configured_umask = builder.umask;
        let descriptor_policy = UnixChildDescriptorPolicy::prepare()?;

        let mut cmd = builder.as_command()?;
        let controlling_tty = builder.get_controlling_tty();

        unsafe {
            cmd.stdin(self.as_stdio()?)
                .stdout(self.as_stdio()?)
                .stderr(self.as_stdio()?)
                .pre_exec(move || {
                    // Clean up a few things before we exec the program
                    // Clear out any potentially problematic signal
                    // dispositions that we might have inherited
                    for signo in &[
                        libc::SIGCHLD,
                        libc::SIGHUP,
                        libc::SIGINT,
                        libc::SIGQUIT,
                        libc::SIGTERM,
                        libc::SIGALRM,
                    ] {
                        libc::signal(*signo, libc::SIG_DFL);
                    }

                    // Establish ourselves as a session leader.
                    if libc::setsid() == -1 {
                        return Err(io::Error::last_os_error());
                    }

                    // Clippy wants us to explicitly cast TIOCSCTTY using
                    // type::from(), but the size and potentially signedness
                    // are system dependent, which is why we're using `as _`.
                    // Suppress this lint for this section of code.
                    #[cfg_attr(feature = "cargo-clippy", allow(clippy::cast_lossless))]
                    if controlling_tty {
                        // Set the pty as the controlling terminal.
                        // Failure to do this means that delivery of
                        // SIGWINCH won't happen when we resize the
                        // terminal, among other undesirable effects.
                        if libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                            return Err(io::Error::last_os_error());
                        }
                    }

                    descriptor_policy.mark_close_on_exec()?;

                    if let Some(mask) = configured_umask {
                        libc::umask(mask);
                    }

                    Ok(())
                })
        };

        let mut child = cmd.spawn()?;

        // Ensure that we close out the slave fds that Child retains;
        // they are not what we need (we need the master side to reference
        // them) and won't work in the usual way anyway.
        // In practice these are None, but it seems best to be move them
        // out in case the behavior of Command changes in the future.
        child.stdin.take();
        child.stdout.take();
        child.stderr.take();

        Ok(child)
    }
}

/// Represents the master end of a pty.
/// The file descriptor will be closed when the Pty is dropped.
struct UnixMasterPty {
    fd: PtyFd,
    took_writer: RefCell<bool>,
}

/// Represents the slave end of a pty.
/// The file descriptor will be closed when the Pty is dropped.
struct UnixSlavePty {
    fd: PtyFd,
}

/// Helper function to set the close-on-exec flag for a raw descriptor
fn cloexec(fd: RawFd) -> Result<(), Error> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        bail!(
            "fcntl to read flags failed: {:?}",
            io::Error::last_os_error()
        );
    }
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if result == -1 {
        bail!(
            "fcntl to set CLOEXEC failed: {:?}",
            io::Error::last_os_error()
        );
    }
    Ok(())
}

impl SlavePty for UnixSlavePty {
    fn spawn_command(
        &self,
        builder: CommandBuilder,
    ) -> Result<Box<dyn Child + Send + Sync>, Error> {
        Ok(Box::new(self.fd.spawn_command(builder)?))
    }
}

impl MasterPty for UnixMasterPty {
    fn resize(&self, size: PtySize) -> Result<(), Error> {
        self.fd.resize(size)
    }

    fn get_size(&self) -> Result<PtySize, Error> {
        self.fd.get_size()
    }

    fn try_clone_reader(&self) -> Result<Box<dyn Read + Send>, Error> {
        let fd = PtyFd(self.fd.try_clone()?);
        Ok(Box::new(fd))
    }

    fn take_writer(&self) -> Result<Box<dyn Write + Send>, Error> {
        if *self.took_writer.borrow() {
            anyhow::bail!("cannot take writer more than once");
        }
        *self.took_writer.borrow_mut() = true;
        let fd = PtyFd(self.fd.try_clone()?);
        Ok(Box::new(UnixMasterWriter { fd }))
    }

    fn as_raw_fd(&self) -> Option<RawFd> {
        Some(self.fd.0.as_raw_fd())
    }

    fn process_group_leader(&self) -> Option<libc::pid_t> {
        match unsafe { libc::tcgetpgrp(self.fd.0.as_raw_fd()) } {
            pid if pid > 0 => Some(pid),
            _ => None,
        }
    }

    fn get_termios(&self) -> Option<nix::sys::termios::Termios> {
        nix::sys::termios::tcgetattr(self.fd.0.as_raw_fd()).ok()
    }
}

/// Represents the master end of a pty.
/// EOT will be sent, and then the file descriptor will be closed when
/// the Pty is dropped.
struct UnixMasterWriter {
    fd: PtyFd,
}

impl Drop for UnixMasterWriter {
    fn drop(&mut self) {
        let mut t: libc::termios = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        if unsafe { libc::tcgetattr(self.fd.0.as_raw_fd(), &mut t) } == 0 {
            // EOF is only interpreted after a newline, so if it is set,
            // we send a newline followed by EOF.
            let eot = t.c_cc[libc::VEOF];
            if eot != 0 {
                let _ = self.fd.0.write_all(&[b'\n', eot]);
            }
        }
    }
}

impl Write for UnixMasterWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.fd.write(buf)
    }
    fn flush(&mut self) -> Result<(), io::Error> {
        self.fd.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::OpenOptions,
        os::unix::fs::MetadataExt,
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    };

    const DESCRIPTOR_TEST_ROLE_ENV: &str = "RUSTDESK_PTY_DESCRIPTOR_TEST_ROLE";
    const DESCRIPTOR_TEST_DEVICE_ENV: &str = "RUSTDESK_PTY_DESCRIPTOR_TEST_DEVICE";
    const DESCRIPTOR_TEST_INODE_ENV: &str = "RUSTDESK_PTY_DESCRIPTOR_TEST_INODE";
    const DESCRIPTOR_TEST_LAUNCHER_ROLE: &str = "launcher";
    const DESCRIPTOR_TEST_WORKER_ROLE: &str = "worker";
    const DESCRIPTOR_TEST_FILTER: &str = "pty_child_excludes_injected_nonstdio_descriptor";

    fn expected_descriptor_test_identity() -> (u64, u64) {
        let device = std::env::var(DESCRIPTOR_TEST_DEVICE_ENV)
            .unwrap()
            .parse()
            .unwrap();
        let inode = std::env::var(DESCRIPTOR_TEST_INODE_ENV)
            .unwrap()
            .parse()
            .unwrap();
        (device, inode)
    }

    fn descriptor_test_identity(path: &Path) -> Option<(u64, u64)> {
        let metadata = std::fs::metadata(path).ok()?;
        Some((metadata.dev(), metadata.ino()))
    }

    #[test]
    fn unix_child_descriptor_limit_is_bounded() {
        assert_eq!(validated_unix_descriptor_upper_bound(1).unwrap(), 0);
        assert_eq!(
            validated_unix_descriptor_upper_bound(MAX_UNIX_DESCRIPTOR_LIMIT).unwrap(),
            (MAX_UNIX_DESCRIPTOR_LIMIT - 1) as RawFd
        );
        assert!(validated_unix_descriptor_upper_bound(0).is_err());
        assert!(validated_unix_descriptor_upper_bound(libc::RLIM_INFINITY as u64).is_err());
        assert!(validated_unix_descriptor_upper_bound(MAX_UNIX_DESCRIPTOR_LIMIT + 1).is_err());
    }

    #[test]
    fn pty_child_exec_failure_is_reported() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let non_executable = std::env::temp_dir().join(format!(
            "rustdesk-pty-exec-error-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&non_executable).unwrap();

        let pty_system = UnixPtySystem::default();
        let pair = pty_system
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .unwrap();
        let command = CommandBuilder::new(&non_executable);
        let rejected = match pair.slave.spawn_command(command) {
            Err(_) => true,
            Ok(mut child) => {
                let _ = child.wait();
                false
            }
        };
        let cleanup = std::fs::remove_dir(&non_executable);
        assert!(cleanup.is_ok(), "failed to remove PTY exec-error target");
        assert!(
            rejected,
            "the PTY spawn hid its post-fork exec failure from the parent"
        );
    }

    #[test]
    fn pty_child_excludes_injected_nonstdio_descriptor() {
        match std::env::var(DESCRIPTOR_TEST_ROLE_ENV).as_deref() {
            Ok(DESCRIPTOR_TEST_LAUNCHER_ROLE) => {
                let expected = expected_descriptor_test_identity();
                assert_eq!(
                    descriptor_test_identity(Path::new("/dev/fd/9")),
                    Some(expected),
                    "the intermediate PTY test image must prove the injected descriptor object"
                );

                let pty_system = UnixPtySystem::default();
                let pair = pty_system
                    .openpty(PtySize {
                        rows: 24,
                        cols: 80,
                        pixel_width: 0,
                        pixel_height: 0,
                    })
                    .unwrap();
                let mut command = CommandBuilder::new(std::env::current_exe().unwrap());
                command.arg(DESCRIPTOR_TEST_FILTER);
                command.arg("--nocapture");
                command.env(DESCRIPTOR_TEST_ROLE_ENV, DESCRIPTOR_TEST_WORKER_ROLE);
                let mut child = pair.slave.spawn_command(command).unwrap();
                drop(pair.slave);
                assert!(
                    child.wait().unwrap().success(),
                    "the descriptor-policy PTY worker failed"
                );
                return;
            }
            Ok(DESCRIPTOR_TEST_WORKER_ROLE) => {
                let expected = expected_descriptor_test_identity();
                assert_ne!(
                    descriptor_test_identity(Path::new("/dev/fd/9")),
                    Some(expected),
                    "the final PTY test image inherited the injected descriptor object"
                );
                return;
            }
            _ => {}
        }

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let target = std::env::temp_dir().join(format!(
            "rustdesk-pty-descriptor-{}-{nonce}",
            std::process::id()
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&target)
            .unwrap();
        let metadata = file.metadata().unwrap();
        let expected = (metadata.dev(), metadata.ino());
        drop(file);

        let mut launcher = std::process::Command::new("/bin/sh");
        launcher
            .arg("-c")
            .arg("exec 9<\"$1\"; exec \"$2\" \"$3\" --nocapture")
            .arg("sh")
            .arg(&target)
            .arg(std::env::current_exe().unwrap())
            .arg(DESCRIPTOR_TEST_FILTER)
            .env(DESCRIPTOR_TEST_ROLE_ENV, DESCRIPTOR_TEST_LAUNCHER_ROLE)
            .env(DESCRIPTOR_TEST_DEVICE_ENV, expected.0.to_string())
            .env(DESCRIPTOR_TEST_INODE_ENV, expected.1.to_string());
        let status = launcher.status();
        let cleanup = std::fs::remove_file(&target);
        assert!(
            cleanup.is_ok(),
            "failed to remove PTY descriptor test target"
        );
        assert!(
            status.unwrap().success(),
            "the PTY descriptor-injection launcher failed"
        );
    }
}
