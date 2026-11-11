use std::{
    io,
    process::{Child, Command, ExitStatus},
    sync::{Arc, Mutex, MutexGuard},
};

/// Counts launches from before fork until the retained Child observes exit.
/// Dropping a Child without joining it deliberately does not establish absence.
#[derive(Default)]
pub(super) struct ServiceChildProcesses {
    outstanding: Arc<Mutex<usize>>,
}

pub(super) struct ServiceChildProcess {
    process: Child,
    outstanding: Option<Arc<Mutex<usize>>>,
}

fn lock_count(count: &Mutex<usize>) -> io::Result<MutexGuard<'_, usize>> {
    count.lock().map_err(|_| {
        io::Error::new(io::ErrorKind::Other, "Service child process ownership was poisoned")
    })
}

fn retire(count: &Mutex<usize>) -> io::Result<()> {
    let mut count = lock_count(count)?;
    *count = count.checked_sub(1).ok_or_else(|| {
        io::Error::new(io::ErrorKind::Other, "Service child process ownership was lost")
    })?;
    Ok(())
}

impl ServiceChildProcesses {
    pub(super) fn is_empty(&self) -> io::Result<bool> {
        Ok(*lock_count(&self.outstanding)? == 0)
    }

    pub(super) fn spawn(&self, command: &mut Command) -> io::Result<ServiceChildProcess> {
        {
            let mut count = lock_count(&self.outstanding)?;
            *count = count.checked_add(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::Other, "Service child process capacity exhausted")
            })?;
        }
        match command.spawn() {
            Ok(process) => Ok(ServiceChildProcess {
                process,
                outstanding: Some(Arc::clone(&self.outstanding)),
            }),
            Err(err) => {
                // Command::spawn reaps a failed Unix pre_exec/exec before returning Err.
                retire(&self.outstanding)?;
                Err(err)
            }
        }
    }
}

impl ServiceChildProcess {
    pub(super) fn id(&self) -> u32 {
        self.process.id()
    }

    pub(super) fn kill(&mut self) -> io::Result<()> {
        self.process.kill()
    }

    fn retire(&mut self) -> io::Result<()> {
        if let Some(count) = self.outstanding.as_ref() {
            retire(count)?;
            self.outstanding = None;
        }
        Ok(())
    }

    pub(super) fn wait(&mut self) -> io::Result<ExitStatus> {
        let status = self.process.wait()?;
        self.retire()?;
        Ok(status)
    }

    pub(super) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.process.try_wait()?;
        if status.is_some() {
            self.retire()?;
        }
        Ok(status)
    }

    #[cfg(test)]
    pub(super) fn for_test(process: Child) -> Self {
        Self { process, outstanding: Some(Arc::new(Mutex::new(1))) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    struct Owner(ServiceChildProcess);

    impl Drop for Owner {
        fn drop(&mut self) {
            let _ = self.0.kill();
            self.0.wait().unwrap();
        }
    }

    #[test]
    fn live_and_signalled_children_require_a_join() {
        let children = ServiceChildProcesses::default();
        assert!(children.is_empty().unwrap());
        let mut first = Owner(children.spawn(Command::new("/bin/sleep").arg("60")).unwrap());
        let mut second = Owner(children.spawn(Command::new("/bin/sleep").arg("60")).unwrap());
        assert!(!children.is_empty().unwrap());
        assert!(first.0.try_wait().unwrap().is_none());
        first.0.kill().unwrap();
        assert!(!children.is_empty().unwrap());
        first.0.wait().unwrap();
        assert!(!children.is_empty().unwrap());
        // Cached waits for the first child must not retire the second child.
        first.0.wait().unwrap();
        assert!(first.0.try_wait().unwrap().is_some());
        assert!(!children.is_empty().unwrap());
        second.0.kill().unwrap();
        second.0.wait().unwrap();
        assert!(children.is_empty().unwrap());
    }

    #[test]
    fn failed_exec_and_pre_exec_preserve_absence() {
        let children = ServiceChildProcesses::default();
        assert!(children.spawn(&mut Command::new("/no-such-rustdesk-service-child")).is_err());
        assert!(children.is_empty().unwrap());
        let mut command = Command::new("/bin/true");
        unsafe {
            command.pre_exec(|| Err(io::Error::from_raw_os_error(13)));
        }
        assert_eq!(children.spawn(&mut command).err().unwrap().raw_os_error(), Some(13));
        assert!(children.is_empty().unwrap());
    }

    #[test]
    fn launch_is_counted_before_the_child_can_exec() {
        use std::{io::{Read, Write}, os::fd::AsRawFd, os::unix::net::UnixStream};
        extern "C" {
            fn read(fd: i32, buffer: *mut std::ffi::c_void, count: usize) -> isize;
            fn write(fd: i32, buffer: *const std::ffi::c_void, count: usize) -> isize;
        }
        let children = Arc::new(ServiceChildProcesses::default());
        let (mut parent, child) = UnixStream::pair().unwrap();
        let timeout = Some(std::time::Duration::from_secs(3));
        parent.set_read_timeout(timeout).unwrap();
        parent.set_write_timeout(timeout).unwrap();
        child.set_read_timeout(timeout).unwrap();
        child.set_write_timeout(timeout).unwrap();
        let spawning = Arc::clone(&children);
        let worker = std::thread::spawn(move || {
            let mut command = Command::new("/bin/true");
            unsafe {
                command.pre_exec(move || {
                    // Only raw async-signal-safe I/O in the forked child.
                    let mut byte = [1u8];
                    if write(child.as_raw_fd(), byte.as_ptr().cast(), 1) != 1
                        || read(child.as_raw_fd(), byte.as_mut_ptr().cast(), 1) != 1
                    {
                        return Err(io::Error::from_raw_os_error(5));
                    }
                    Ok(())
                });
            }
            spawning.spawn(&mut command)
        });
        let observed = parent.read_exact(&mut [0u8]);
        let absent_during_spawn = children.is_empty();
        let released = parent.write_all(&[1]);
        drop(parent);
        let mut spawned = worker.join().unwrap().unwrap();
        let status = spawned.wait().unwrap();
        observed.unwrap();
        released.unwrap();
        assert!(!absent_during_spawn.unwrap());
        assert!(status.success());
        assert!(children.is_empty().unwrap());
    }

    #[test]
    fn lost_wait_ownership_cannot_establish_absence() {
        let children = ServiceChildProcesses::default();
        let tracked = children.spawn(Command::new("/bin/sleep").arg("60")).unwrap();
        // Retain the native Child only to clean up this deliberate owner-loss case.
        let ServiceChildProcess { mut process, outstanding } = tracked;
        drop(outstanding);
        process.kill().unwrap();
        process.wait().unwrap();
        assert!(!children.is_empty().unwrap());
    }
}
