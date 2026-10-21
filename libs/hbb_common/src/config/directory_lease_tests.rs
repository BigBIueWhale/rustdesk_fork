use super::*;
use std::fs;
use std::os::unix::fs::{symlink, FileTypeExt, OpenOptionsExt, PermissionsExt};

fn held_lease_attempt(
    action: impl FnOnce() -> Result<()> + Send + 'static,
) -> (std::thread::JoinHandle<()>, std::sync::mpsc::Receiver<(bool, u128)>) {
    let (ready, started) = std::sync::mpsc::channel();
    let (finished, result) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        ready.send(()).unwrap();
        let start = std::time::Instant::now();
        let timed_out = action().err().and_then(|error| {
            error.downcast_ref::<io::Error>().map(|error| error.kind())
        }) == Some(io::ErrorKind::TimedOut);
        finished.send((timed_out, start.elapsed().as_millis())).unwrap();
    });
    started.recv_timeout(std::time::Duration::from_secs(3)).unwrap();
    (worker, result)
}

#[test]
fn directory_lease_held_owner_bounds_admission_and_allows_retry() {
    crate::config::option_tests::in_private_process(
        "config::linux_directory::lease_tests::directory_lease_held_owner_bounds_admission_and_allows_retry",
        |root| {
            let handles = || fs::read_dir("/proc/self/fd").unwrap().count();
            let before = handles();
            let mut correct = true;
            for create in [false, true] {
                let base = root.join(format!("held-lease-{create}"));
                fs::create_dir(&base).unwrap();
                let parent = File::open(&base).unwrap();
                let owner = Lease::open(&parent, b"next", true).unwrap().unwrap();
                let path = base.join(std::ffi::OsStr::from_bytes(owner.name.to_bytes()));
                let original = id(&owner.file).unwrap();
                let canary = File::options().read(true).write(true).open(&path).unwrap();
                assert_eq!(unsafe { libc::flock(canary.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, -1);
                assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
                drop(canary);
                let worker_base = base.clone();
                let (worker, result) = held_lease_attempt(move || {
                    let parent = File::open(worker_base)?;
                    Lease::open(&parent, b"next", create).map(|_| ())
                });
                let observed = result.recv_timeout(std::time::Duration::from_secs(3));
                let bounded = observed.as_ref().map(|value| value.0).unwrap_or(false);
                let preserved = id(&owner.file).unwrap() == original && fs::read(&path).unwrap().is_empty()
                    && fs::read_dir(&base).unwrap().count() == 1;
                drop(owner);
                worker.join().unwrap();
                let retried = Lease::open(&parent, b"next", create).unwrap().unwrap();
                let retry_same = id(&retried.file).unwrap() == original;
                println!("OPTION_COMMIT_LEASE_WAIT=observed kind=lease create={create} returned_while_held={} timed_out={bounded} elapsed_ms={} preserved={preserved} retry_same_inode={retry_same}", observed.is_ok(), observed.map(|value| value.1).unwrap_or(3000));
                correct &= bounded && preserved && retry_same;
            }
            let after = handles();
            println!("OPTION_COMMIT_LEASE_WAIT=handles kind=lease before={before} after={after}");
            assert!(correct);
            assert_eq!(before, after);
        },
    );
}

#[test]
fn directory_lease_busy_save_preserves_first_and_replacement_outcomes() {
    crate::config::option_tests::in_private_process(
        "config::linux_directory::lease_tests::directory_lease_busy_save_preserves_first_and_replacement_outcomes",
        |root| {
            let handles = || fs::read_dir("/proc/self/fd").unwrap().count();
            let before = handles();
            let mut correct = true;
            for existing in [false, true] {
                let base = root.join(format!("held-store-{existing}"));
                fs::create_dir(&base).unwrap();
                let path = base.join("next/settings.toml");
                if existing {
                    crate::config::store_config_bytes_transaction(&path, b"original", crate::config::ConfigStoreFault::None).unwrap();
                }
                let original = fs::metadata(&path).ok().map(|m| (m.dev(), m.ino()));
                let parent = File::open(&base).unwrap();
                let owner = Lease::open(&parent, b"next", true).unwrap().unwrap();
                let journal = base.join(std::ffi::OsStr::from_bytes(owner.name.to_bytes()));
                let original_lease = id(&owner.file).unwrap();
                let worker_path = path.clone();
                let (worker, result) = held_lease_attempt(move || {
                    crate::config::store_config_bytes_transaction(&worker_path, b"replacement", crate::config::ConfigStoreFault::None)
                });
                let observed = result.recv_timeout(std::time::Duration::from_secs(3));
                let bounded = observed.as_ref().map(|value| value.0).unwrap_or(false);
                let preserved = fs::metadata(&path).ok().map(|m| (m.dev(), m.ino())) == original
                    && if existing { fs::read(&path).unwrap() == b"original" } else { !path.parent().unwrap().exists() };
                let lease_preserved = id(&owner.file).unwrap() == original_lease && fs::read(&journal).unwrap().is_empty();
                drop(owner);
                worker.join().unwrap();
                crate::config::store_config_bytes_transaction(&path, b"replacement", crate::config::ConfigStoreFault::None).unwrap();
                let retry_saved = fs::read(&path).unwrap() == b"replacement";
                println!("OPTION_COMMIT_LEASE_WAIT=observed kind=store existing={existing} returned_while_held={} timed_out={bounded} elapsed_ms={} preserved={preserved} lease_preserved={lease_preserved} retry_saved={retry_saved}", observed.is_ok(), observed.map(|value| value.1).unwrap_or(3000));
                correct &= bounded && preserved && lease_preserved && retry_saved;
            }
            let after = handles();
            println!("OPTION_COMMIT_LEASE_WAIT=handles kind=store before={before} after={after}");
            assert!(correct);
            assert_eq!(before, after);
        },
    );
}

#[test]
fn directory_lease_metadata_admission_precedes_io() {
    crate::config::option_tests::in_private_process(
        "config::linux_directory::lease_tests::directory_lease_metadata_admission_precedes_io",
        |root| {
            let target: &[u8] = b"next";
            let mut hash = Sha256::new();
            hash.update(DOMAIN);
            hash.update(target);
            let name = format!(".config-dir-lease.{:x}", hash.finalize());
            let safe = root.join("lease-safe");
            fs::create_dir(&safe).unwrap();
            let safe_parent = File::open(&safe).unwrap();
            assert!(Lease::open(&safe_parent, target, false).unwrap().is_none());
            let lease = Lease::open(&safe_parent, target, true).unwrap().unwrap();
            assert_eq!(lease.file.metadata().unwrap().mode() & 0o7777, 0o600);
            drop(lease);
            drop(Lease::open(&safe_parent, target, false).unwrap().unwrap());

            let mut cases = Vec::new();
            let mut socket_owner = None;
            for kind in ["fifo", "directory", "socket", "symlink", "hardlink", "shared", "special", "oversized"] {
                let base = root.join(format!("lease-{kind}"));
                fs::create_dir(&base).unwrap();
                let path = base.join(&name);
                match kind {
                    "fifo" => {
                        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
                        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
                    }
                    "directory" => fs::create_dir(&path).unwrap(),
                    "socket" => {
                        let parent = File::open(&base).unwrap();
                        let alias = format!("/proc/self/fd/{}/{name}", parent.as_raw_fd());
                        assert!(alias.len() < 108);
                        socket_owner = Some(std::os::unix::net::UnixListener::bind(alias).unwrap());
                    }
                    "symlink" => symlink(safe.join(&name), &path).unwrap(),
                    _ => {
                        fs::write(&path, b"retained lease fixture").unwrap();
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                        match kind {
                            "hardlink" => fs::hard_link(&path, base.join("alias")).unwrap(),
                            "shared" => fs::set_permissions(&path, fs::Permissions::from_mode(0o620)).unwrap(),
                            "special" => fs::set_permissions(&path, fs::Permissions::from_mode(0o4600)).unwrap(),
                            "oversized" => File::options().write(true).open(&path).unwrap().set_len(MAX_JOURNAL as u64 + 1).unwrap(),
                            _ => unreachable!(),
                        }
                    }
                }
                cases.push((kind, File::open(&base).unwrap(), path));
            }
            let fresh = root.join("lease-fresh");
            fs::create_dir(&fresh).unwrap();
            let fresh_parent = File::open(&fresh).unwrap();
            let missing = root.join("lease-missing");
            fs::create_dir(&missing).unwrap();
            let missing_parent = File::open(&missing).unwrap();
            let identity = |path: &Path| {
                let m = fs::symlink_metadata(path).unwrap();
                (m.dev(), m.ino(), m.uid(), m.gid(), m.mode(), m.nlink(), m.len())
            };
            let original = cases.iter().map(|(_, _, path)| identity(path)).collect::<Vec<_>>();
            let fifo = &cases[0].2;
            let io_open = || File::options().read(true).write(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
                .open(fifo);
            drop(io_open().unwrap());
            assert!(fs::metadata(fifo).unwrap().file_type().is_fifo());
            let handles = || fs::read_dir("/proc/self/fd").unwrap().count();
            let before = handles();
            let statement = |code, k| libc::sock_filter { code: code as u16, jt: 0, jf: 0, k };
            let jump = |code, k, jt, jf| libc::sock_filter { code: code as u16, jt, jf, k };
            let load = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
            let equal = libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K;
            let bits = libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K;
            let ret = libc::BPF_RET | libc::BPF_K;
            let mut filter = [
                statement(load, 4),
                jump(equal, 0xc000003e, 1, 0),
                statement(ret, libc::SECCOMP_RET_KILL_PROCESS),
                statement(load, 0),
                jump(bits, 0x40000000, 0, 1),
                statement(ret, libc::SECCOMP_RET_KILL_PROCESS),
                jump(equal, libc::SYS_openat as u32, 3, 0),
                jump(equal, libc::SYS_open as u32, 4, 0),
                jump(equal, libc::SYS_openat2 as u32, 8, 0),
                statement(ret, libc::SECCOMP_RET_ALLOW),
                statement(load, 32),
                statement(libc::BPF_JMP | libc::BPF_JA, 1),
                statement(load, 24),
                jump(bits, libc::O_PATH as u32, 4, 0),
                statement(libc::BPF_ALU | libc::BPF_AND | libc::BPF_K, (libc::O_CREAT | libc::O_EXCL | libc::O_ACCMODE) as u32),
                jump(equal, (libc::O_CREAT | libc::O_EXCL | libc::O_RDWR) as u32, 2, 0),
                jump(bits, libc::O_RDWR as u32, 0, 1),
                statement(ret, libc::SECCOMP_RET_ERRNO | libc::EOWNERDEAD as u32),
                statement(ret, libc::SECCOMP_RET_ALLOW),
            ];
            let program = libc::sock_fprog { len: filter.len() as u16, filter: filter.as_mut_ptr() };
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }, 0);
            assert_eq!(unsafe { libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, libc::SECCOMP_FILTER_FLAG_TSYNC, &program) }, 0);
            assert_eq!(io_open().unwrap_err().raw_os_error(), Some(libc::EOWNERDEAD));
            let metadata = File::options().read(true).custom_flags(libc::O_PATH | libc::O_NOFOLLOW).open(fifo).unwrap();
            assert!(metadata.metadata().unwrap().file_type().is_fifo());
            drop(metadata);
            let io_denied = |error: &anyhow::Error| error.downcast_ref::<io::Error>()
                .and_then(io::Error::raw_os_error) == Some(libc::EOWNERDEAD);
            let mut all_refused = true;
            for ((kind, parent, path), original) in cases.iter().zip(&original) {
                for create in [false, true] {
                    let error = Lease::open(parent, target, create).err().expect("unsafe lease must refuse");
                    let before_io = !io_denied(&error);
                    let preserved = identity(path) == *original;
                    println!("OPTION_COMMIT_LEASE_PREOPEN=observed kind={kind} create={create} refused_before_io={before_io} preserved={preserved}");
                    all_refused &= before_io && preserved;
                }
            }
            let absent = matches!(Lease::open(&missing_parent, target, false), Ok(None));
            let fresh = Lease::open(&fresh_parent, target, true).map(|lease| lease.is_some()).unwrap_or(false);
            let refused = Lease::open(&safe_parent, target, false).err().map(|error| io_denied(&error)).unwrap_or(false);
            let after = handles();
            println!("OPTION_COMMIT_LEASE_PREOPEN=controls fifo_io_before=true fifo_io_denied=true metadata_allowed=true absent={absent} fresh_exclusive={fresh} regular_reopen_refused={refused} fds_before={before} fds_after={after}");
            assert!(all_refused && absent && fresh && refused);
            assert_eq!(before, after);
            drop(socket_owner);
        },
    );
}
