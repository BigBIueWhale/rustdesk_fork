use std::{
    fs, io,
    mem::MaybeUninit,
    os::unix::{io::RawFd, process::CommandExt},
    process::Command,
};

const MAX_MACOS_DESCRIPTOR_LIMIT: u64 = 1_048_576;

fn validated_macos_descriptor_upper_bound(descriptor_limit: u64) -> io::Result<RawFd> {
    if descriptor_limit == 0
        || descriptor_limit == libc::RLIM_INFINITY
        || descriptor_limit > MAX_MACOS_DESCRIPTOR_LIMIT
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported macOS descriptor limit: {descriptor_limit}"),
        ));
    }
    let last_fd = descriptor_limit - 1;
    Ok(last_fd as RawFd)
}

fn macos_descriptor_upper_bound() -> io::Result<RawFd> {
    let mut limits = MaybeUninit::<libc::rlimit>::uninit();
    let limits = unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, limits.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        limits.assume_init()
    };
    validated_macos_descriptor_upper_bound(limits.rlim_cur)
}

fn observed_nonstdio_descriptors() -> io::Result<Vec<RawFd>> {
    let mut descriptors = Vec::new();
    for entry in fs::read_dir("/dev/fd")? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "macOS descriptor directory contains a non-UTF-8 entry",
            ));
        };
        let Ok(fd) = name.parse::<RawFd>() else {
            continue;
        };
        if fd > libc::STDERR_FILENO {
            descriptors.push(fd);
        }
    }
    descriptors.sort_unstable();
    descriptors.dedup();
    Ok(descriptors)
}

fn set_descriptor_close_on_exec(fd: RawFd) -> io::Result<()> {
    unsafe {
        let descriptor_flags = libc::fcntl(fd, libc::F_GETFD);
        if descriptor_flags == -1 {
            return Err(io::Error::last_os_error());
        }
        if descriptor_flags & libc::FD_CLOEXEC == 0
            && libc::fcntl(fd, libc::F_SETFD, descriptor_flags | libc::FD_CLOEXEC) == -1
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn set_descriptor_close_on_exec_if_open(fd: RawFd) -> io::Result<()> {
    match set_descriptor_close_on_exec(fd) {
        Ok(()) => Ok(()),
        Err(err) if err.raw_os_error() == Some(libc::EBADF) => Ok(()),
        Err(err) => Err(err),
    }
}

fn mark_nonstdio_descriptors_close_on_exec(
    last_fd: RawFd,
    observed_descriptors: &[RawFd],
) -> io::Result<()> {
    for fd in (libc::STDERR_FILENO + 1)..=last_fd {
        set_descriptor_close_on_exec_if_open(fd)?;
    }
    for &fd in observed_descriptors {
        if fd <= last_fd {
            continue;
        }
        set_descriptor_close_on_exec_if_open(fd)?;
    }
    Ok(())
}

/// Constrain a macOS child image to argv, environment, and stdio only.
///
/// Resource-limit and `/dev/fd` inspection happen in the parent. The post-fork hook uses only
/// async-signal-safe `fcntl` operations and leaves the parent's descriptor table unchanged.
pub fn configure_command_close_nonstdio_on_exec(command: &mut Command) -> io::Result<()> {
    let last_fd = macos_descriptor_upper_bound()?;
    let observed_descriptors = observed_nonstdio_descriptors()?;
    unsafe {
        command.pre_exec(move || {
            mark_nonstdio_descriptors_close_on_exec(last_fd, &observed_descriptors)
        });
    }
    Ok(())
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

    const DESCRIPTOR_TEST_ROLE_ENV: &str = "RUSTDESK_MACOS_DESCRIPTOR_TEST_ROLE";
    const DESCRIPTOR_TEST_DEVICE_ENV: &str = "RUSTDESK_MACOS_DESCRIPTOR_TEST_DEVICE";
    const DESCRIPTOR_TEST_INODE_ENV: &str = "RUSTDESK_MACOS_DESCRIPTOR_TEST_INODE";
    const DESCRIPTOR_TEST_LAUNCHER_ROLE: &str = "launcher";
    const DESCRIPTOR_TEST_WORKER_ROLE: &str = "worker";
    const DESCRIPTOR_TEST_FILTER: &str = "macos_command_excludes_injected_nonstdio_descriptor";

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
        let metadata = fs::metadata(path).ok()?;
        Some((metadata.dev(), metadata.ino()))
    }

    #[test]
    fn macos_command_descriptor_limit_is_bounded() {
        assert_eq!(validated_macos_descriptor_upper_bound(1).unwrap(), 0);
        assert_eq!(
            validated_macos_descriptor_upper_bound(MAX_MACOS_DESCRIPTOR_LIMIT).unwrap(),
            (MAX_MACOS_DESCRIPTOR_LIMIT - 1) as RawFd
        );
        assert!(validated_macos_descriptor_upper_bound(0).is_err());
        assert!(validated_macos_descriptor_upper_bound(libc::RLIM_INFINITY).is_err());
        assert!(validated_macos_descriptor_upper_bound(MAX_MACOS_DESCRIPTOR_LIMIT + 1).is_err());
    }

    #[test]
    fn macos_command_excludes_injected_nonstdio_descriptor() {
        match std::env::var(DESCRIPTOR_TEST_ROLE_ENV).as_deref() {
            Ok(DESCRIPTOR_TEST_LAUNCHER_ROLE) => {
                let expected = expected_descriptor_test_identity();
                assert_eq!(
                    descriptor_test_identity(Path::new("/dev/fd/9")),
                    Some(expected),
                    "the intermediate test image must prove the injected descriptor object"
                );

                let mut child = Command::new(std::env::current_exe().unwrap());
                child
                    .arg(DESCRIPTOR_TEST_FILTER)
                    .arg("--nocapture")
                    .env(DESCRIPTOR_TEST_ROLE_ENV, DESCRIPTOR_TEST_WORKER_ROLE);
                configure_command_close_nonstdio_on_exec(&mut child).unwrap();
                assert!(
                    child.status().unwrap().success(),
                    "the descriptor-policy worker failed"
                );
                return;
            }
            Ok(DESCRIPTOR_TEST_WORKER_ROLE) => {
                let expected = expected_descriptor_test_identity();
                assert_ne!(
                    descriptor_test_identity(Path::new("/dev/fd/9")),
                    Some(expected),
                    "the final test image inherited the injected descriptor object"
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
            "rustdesk-macos-descriptor-{}-{nonce}",
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

        let mut launcher = Command::new("/bin/sh");
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
        let cleanup = fs::remove_file(&target);
        assert!(cleanup.is_ok(), "failed to remove descriptor test target");
        assert!(
            status.unwrap().success(),
            "the descriptor-injection launcher failed"
        );
    }
}
