use super::*;
use std::fs;
use std::os::unix::fs::{symlink, FileTypeExt, OpenOptionsExt, PermissionsExt};

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
                    "socket" => socket_owner = Some(std::os::unix::net::UnixListener::bind(&path).unwrap()),
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
