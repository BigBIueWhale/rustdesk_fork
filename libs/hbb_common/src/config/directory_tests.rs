use super::*;
use std::{os::unix::fs::MetadataExt, sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering}};

#[path = "directory_crash_tests.rs"]
mod crash_tests;

std::arch::global_asm!(
    ".global rustdesk_config_test_fsync",
    ".type rustdesk_config_test_fsync,@function",
    "rustdesk_config_test_fsync:",
    "mov eax, 74",
    "syscall",
    ".global rustdesk_config_test_fsync_resume",
    "rustdesk_config_test_fsync_resume:",
    "ret",
);

extern "C" {
    fn rustdesk_config_test_fsync(fd: i32) -> i64;
    static rustdesk_config_test_fsync_resume: u8;
}

static SYNC_DEVICE: AtomicU64 = AtomicU64::new(0);
static SYNC_INODE: AtomicU64 = AtomicU64::new(0);
static SYNC_CALLS: AtomicUsize = AtomicUsize::new(0);
static SYNC_FAIL_AT: AtomicUsize = AtomicUsize::new(0);
static SYNC_HANDLER_ERROR: AtomicBool = AtomicBool::new(false);

extern "C" fn sync_signal(_signal: i32, _info: *mut crate::libc::siginfo_t,
    context: *mut crate::libc::c_void) {
    unsafe {
        let registers = &mut (*(context as *mut crate::libc::ucontext_t)).uc_mcontext.gregs;
        let fd = registers[crate::libc::REG_RDI as usize] as i32;
        let mut metadata = std::mem::MaybeUninit::<crate::libc::stat>::uninit();
        let result = if crate::libc::fstat(fd, metadata.as_mut_ptr()) != 0 {
            SYNC_HANDLER_ERROR.store(true, Ordering::Relaxed);
            -(crate::libc::EBADF as i64)
        } else {
            let metadata = metadata.assume_init();
            let selected = metadata.st_dev as u64 == SYNC_DEVICE.load(Ordering::Relaxed)
                && metadata.st_ino as u64 == SYNC_INODE.load(Ordering::Relaxed);
            let call = if selected { SYNC_CALLS.fetch_add(1, Ordering::Relaxed) + 1 } else { 0 };
            if selected && call == SYNC_FAIL_AT.load(Ordering::Relaxed) {
                -(crate::libc::EIO as i64)
            } else {
                rustdesk_config_test_fsync(fd)
            }
        };
        registers[crate::libc::REG_RAX as usize] = result;
    }
}

fn observe_directory_sync(directory: &fs::File, fail_at: usize) {
    assert_eq!(crate::libc::SYS_fsync, 74);
    let metadata = directory.metadata().unwrap();
    SYNC_DEVICE.store(metadata.dev(), Ordering::Relaxed);
    SYNC_INODE.store(metadata.ino(), Ordering::Relaxed);
    SYNC_CALLS.store(0, Ordering::Relaxed);
    SYNC_FAIL_AT.store(1, Ordering::Relaxed);
    unsafe {
        let mut action: crate::libc::sigaction = std::mem::zeroed();
        action.sa_flags = crate::libc::SA_SIGINFO;
        action.sa_sigaction = sync_signal as usize;
        assert_eq!(crate::libc::sigemptyset(&mut action.sa_mask), 0);
        assert_eq!(crate::libc::sigaction(crate::libc::SIGSYS, &action, std::ptr::null_mut()), 0);
        let address = std::ptr::addr_of!(rustdesk_config_test_fsync_resume) as u64;
        let statement = |code, k| crate::libc::sock_filter { code: code as u16, jt: 0, jf: 0, k };
        let jump = |code, k, jt, jf| crate::libc::sock_filter { code: code as u16, jt, jf, k };
        let load = crate::libc::BPF_LD | crate::libc::BPF_W | crate::libc::BPF_ABS;
        let equal = crate::libc::BPF_JMP | crate::libc::BPF_JEQ | crate::libc::BPF_K;
        let bits = crate::libc::BPF_JMP | crate::libc::BPF_JSET | crate::libc::BPF_K;
        let ret = crate::libc::BPF_RET | crate::libc::BPF_K;
        let mut filter = [
            statement(load, 4), jump(equal, 0xc000003e, 1, 0),
            statement(ret, crate::libc::SECCOMP_RET_KILL_PROCESS),
            statement(load, 0), jump(bits, 0x40000000, 0, 1),
            statement(ret, crate::libc::SECCOMP_RET_KILL_PROCESS),
            jump(equal, crate::libc::SYS_fsync as u32, 0, 5),
            statement(load, 12), jump(equal, (address >> 32) as u32, 0, 2),
            statement(load, 8), jump(equal, address as u32, 1, 0),
            statement(ret, crate::libc::SECCOMP_RET_TRAP),
            statement(ret, crate::libc::SECCOMP_RET_ALLOW),
        ];
        let program = crate::libc::sock_fprog { len: filter.len() as u16, filter: filter.as_mut_ptr() };
        assert_eq!(crate::libc::prctl(crate::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        assert_eq!(crate::libc::syscall(crate::libc::SYS_seccomp,
            crate::libc::SECCOMP_SET_MODE_FILTER, 0, &program), 0);
    }
    assert_eq!(directory.sync_all().unwrap_err().raw_os_error(), Some(crate::libc::EIO));
    assert_eq!(SYNC_CALLS.swap(0, Ordering::Relaxed), 1);
    SYNC_FAIL_AT.store(fail_at, Ordering::Relaxed);
}

fn publication_case(test: &str, fail_at: usize) {
    in_private_process(test, |root| {
        let base = root.join("directory-publication");
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let directory = fs::File::open(&base).unwrap();
        let path = base.join("first/second/config.toml");
        let fds = || fs::read_dir("/proc/self/fd").unwrap().count();
        let before_fds = fds();
        observe_directory_sync(&directory, fail_at);
        let result = store_config_bytes_transaction(&path, b"first save", ConfigStoreFault::None);
        let calls = SYNC_CALLS.load(Ordering::Relaxed);
        let refused = result.is_err();
        let file_absent = !path.exists();
        let first = base.join("first");
        let first_identity = fs::metadata(&first).ok().map(|m| (m.dev(), m.ino()));
        let private: Vec<_> = fs::read_dir(&base).unwrap().map(|e| e.unwrap().path())
            .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with(".config-dir-stage.")).collect();
        let staged_file = private.first().map(|p| fs::File::open(p).unwrap());
        let staged_identity = staged_file.as_ref().map(|f| { let m = f.metadata().unwrap(); (m.dev(), m.ino()) });
        let correct_phase = match fail_at {
            0 => !refused && !file_absent,
            1 => refused && file_absent && first_identity.is_none() && private.is_empty(),
            2 => refused && file_absent && first_identity.is_none() && private.len() == 1,
            3 => refused && file_absent && first_identity.is_some() && private.is_empty(),
            _ => panic!("unknown publication phase"),
        };
        println!("OPTION_COMMIT_DIRECTORY=observed fail_at={fail_at} calls={calls} refused={refused} file_absent={file_absent} public_root={} private_roots={} correct_phase={correct_phase}", first_identity.is_some(), private.len());
        SYNC_FAIL_AT.store(0, Ordering::Relaxed);
        store_config_bytes_transaction(&path, b"healthy retry", ConfigStoreFault::None).unwrap();
        let after = fs::metadata(&first).unwrap();
        let identity = (after.dev(), after.ino());
        let selected_preserved = fail_at != 3 || Some(identity) == first_identity;
        let unselected_retired = fail_at != 2 || staged_identity.map(|old| old != identity).unwrap_or(false)
            && staged_file.as_ref().unwrap().metadata().unwrap().nlink() == 0;
        let retry = fs::read(&path).unwrap() == b"healthy retry"
            && fs::metadata(&path).unwrap().mode() & 0o7777 == 0o600
            && private.iter().all(|p| !p.exists()) && selected_preserved && unselected_retired;
        drop(staged_file);
        let after_fds = fds();
        println!("OPTION_COMMIT_DIRECTORY=retry fail_at={fail_at} correct={retry} selected_preserved={selected_preserved} unselected_retired={unselected_retired}");
        println!("OPTION_COMMIT_DIRECTORY=handles fail_at={fail_at} before={before_fds} after={after_fds}");
        assert!(!SYNC_HANDLER_ERROR.load(Ordering::Relaxed));
        assert_eq!(before_fds, after_fds);
        assert!(correct_phase && retry);
    });
}

#[test]
fn directory_initial_sync_error_precedes_private_creation() {
    publication_case("config::option_tests::directory_tests::directory_initial_sync_error_precedes_private_creation", 1);
}

#[test]
fn directory_preselection_sync_error_retires_only_private_tree() {
    publication_case("config::option_tests::directory_tests::directory_preselection_sync_error_retires_only_private_tree", 2);
}

#[test]
fn directory_postrename_sync_error_recovers_selected_identity() {
    publication_case("config::option_tests::directory_tests::directory_postrename_sync_error_recovers_selected_identity", 3);
}

#[test]
fn directory_normal_publication_and_repeated_save_remain_functional() {
    publication_case("config::option_tests::directory_tests::directory_normal_publication_and_repeated_save_remain_functional", 0);
}
fn entries_with_prefix(base: &Path, prefix: &str) -> Vec<PathBuf> {
    fs::read_dir(base).unwrap().map(|entry| entry.unwrap().path())
        .filter(|path| path.file_name().unwrap().to_string_lossy().starts_with(prefix)).collect()
}

fn pending_directory(root: &Path, fail_at: usize) -> (PathBuf, fs::File, PathBuf) {
    let base = root.join("directory-publication");
    fs::create_dir(&base).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
    let directory = fs::File::open(&base).unwrap();
    observe_directory_sync(&directory, fail_at);
    let path = base.join("first/second/config.toml");
    assert!(store_config_bytes_transaction(&path, b"uncommitted", ConfigStoreFault::None).is_err());
    assert!(!path.exists());
    assert_eq!(SYNC_CALLS.load(Ordering::Relaxed), fail_at);
    SYNC_FAIL_AT.store(0, Ordering::Relaxed);
    (base, directory, path)
}

fn only_lease(base: &Path) -> PathBuf {
    let entries = entries_with_prefix(base, ".config-dir-lease.");
    assert_eq!(entries.len(), 1);
    entries[0].clone()
}

#[test]
fn directory_moved_unselected_tree_refuses_without_adoption() {
    in_private_process("config::option_tests::directory_tests::directory_moved_unselected_tree_refuses_without_adoption", |root| {
        let (base, _directory, path) = pending_directory(root, 2);
        let stages = entries_with_prefix(&base, ".config-dir-stage.");
        assert_eq!(stages.len(), 1);
        let retained = fs::File::open(&stages[0]).unwrap();
        let identity = retained.metadata().unwrap().ino();
        let lease = only_lease(&base);
        let journal = fs::read(&lease).unwrap();
        fs::rename(&stages[0], base.join("first")).unwrap();
        let sentinel = base.join("first/second/preserve");
        fs::write(&sentinel, b"preserve moved tree").unwrap();
        assert!(store_config_bytes_transaction(&path, b"refused", ConfigStoreFault::None).is_err());
        assert!(!path.exists());
        assert_eq!(fs::metadata(base.join("first")).unwrap().ino(), identity);
        assert_eq!(fs::read(&sentinel).unwrap(), b"preserve moved tree");
        assert_eq!(fs::read(&lease).unwrap(), journal);
        assert!(!stages[0].exists());
        assert!(!SYNC_HANDLER_ERROR.load(Ordering::Relaxed));
        println!("OPTION_COMMIT_DIRECTORY_JOURNAL=moved_unselected refused=true preserved=true");
    });
}

#[test]
fn directory_replaced_selected_tree_refuses_without_mutation() {
    in_private_process("config::option_tests::directory_tests::directory_replaced_selected_tree_refuses_without_mutation", |root| {
        let (base, _directory, path) = pending_directory(root, 3);
        let lease = only_lease(&base);
        let journal = fs::read(&lease).unwrap();
        let original = fs::metadata(base.join("first")).unwrap().ino();
        fs::rename(base.join("first"), base.join("selected-original")).unwrap();
        fs::create_dir_all(base.join("first/second")).unwrap();
        fs::set_permissions(base.join("first"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(base.join("first/second"), fs::Permissions::from_mode(0o700)).unwrap();
        let replacement = fs::metadata(base.join("first")).unwrap().ino();
        assert_ne!(replacement, original);
        let sentinel = base.join("first/second/preserve");
        fs::write(&sentinel, b"preserve replacement").unwrap();
        assert!(store_config_bytes_transaction(&path, b"refused", ConfigStoreFault::None).is_err());
        assert!(!path.exists());
        assert_eq!(fs::metadata(base.join("first")).unwrap().ino(), replacement);
        assert_eq!(fs::metadata(base.join("selected-original")).unwrap().ino(), original);
        assert_eq!(fs::read(&sentinel).unwrap(), b"preserve replacement");
        assert_eq!(fs::read(&lease).unwrap(), journal);
        assert!(!SYNC_HANDLER_ERROR.load(Ordering::Relaxed));
        println!("OPTION_COMMIT_DIRECTORY_JOURNAL=replaced_selected refused=true preserved=true");
    });
}

#[test]
fn directory_torn_selection_retires_private_identity_and_retries() {
    in_private_process("config::option_tests::directory_tests::directory_torn_selection_retires_private_identity_and_retries", |root| {
        let (base, _directory, path) = pending_directory(root, 2);
        let stages = entries_with_prefix(&base, ".config-dir-stage.");
        assert_eq!(stages.len(), 1);
        let retained = fs::File::open(&stages[0]).unwrap();
        let original = retained.metadata().unwrap().ino();
        let lease = only_lease(&base);
        let mut journal = fs::OpenOptions::new().append(true).open(&lease).unwrap();
        journal.write_all(&[0x40, 0]).unwrap();
        journal.sync_all().unwrap();
        drop(journal);
        store_config_bytes_transaction(&path, b"after torn append", ConfigStoreFault::None).unwrap();
        assert_eq!(retained.metadata().unwrap().nlink(), 0);
        assert_ne!(fs::metadata(base.join("first")).unwrap().ino(), original);
        assert!(!stages[0].exists());
        assert_eq!(fs::read(&path).unwrap(), b"after torn append");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
        assert_eq!(fs::metadata(&lease).unwrap().len(), 0);
        assert!(!SYNC_HANDLER_ERROR.load(Ordering::Relaxed));
        println!("OPTION_COMMIT_DIRECTORY_JOURNAL=torn_selection retired=true retry=true");
    });
}

#[test]
fn directory_concurrent_first_saves_all_complete() {
    in_private_process("config::option_tests::directory_tests::directory_concurrent_first_saves_all_complete", |root| {
        let base = root.join("directory-concurrent");
        fs::create_dir(&base).unwrap();
        let before = fs::read_dir("/proc/self/fd").unwrap().count();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let mut threads = Vec::new();
        for index in 0..8 {
            let barrier = barrier.clone();
            let path = base.join(format!("first/second/{index}.toml"));
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                store_config_bytes_transaction(&path, format!("writer {index}").as_bytes(), ConfigStoreFault::None)
            }));
        }
        for thread in threads { thread.join().unwrap().unwrap(); }
        for index in 0..8 {
            let path = base.join(format!("first/second/{index}.toml"));
            assert_eq!(fs::read(&path).unwrap(), format!("writer {index}").as_bytes());
            assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
        }
        assert_eq!(fs::metadata(only_lease(&base)).unwrap().len(), 0);
        assert!(entries_with_prefix(&base, ".config-dir-stage.").is_empty());
        let after = fs::read_dir("/proc/self/fd").unwrap().count();
        assert_eq!(before, after);
        println!("OPTION_COMMIT_DIRECTORY_JOURNAL=concurrent writers=8 joined=8 correct=true before={before} after={after}");
    });
}

#[test]
fn directory_unsafe_journals_refuse_without_creation_or_side_effects() {
    in_private_process("config::option_tests::directory_tests::directory_unsafe_journals_refuse_without_creation_or_side_effects", |root| {
        let before = fs::read_dir("/proc/self/fd").unwrap().count();
        for kind in ["symlink", "fifo", "hardlink", "mode", "oversized", "malformed"] {
            let base = root.join(kind);
            fs::create_dir(&base).unwrap();
            let path = base.join("first/second/config.toml");
            store_config_bytes_transaction(&path, b"initial", ConfigStoreFault::None).unwrap();
            let lease = only_lease(&base);
            fs::remove_dir_all(base.join("first")).unwrap();
            fs::remove_file(&lease).unwrap();
            let sentinel = base.join("sentinel");
            fs::write(&sentinel, b"unchanged sentinel").unwrap();
            match kind {
                "symlink" => std::os::unix::fs::symlink(&sentinel, &lease).unwrap(),
                "fifo" => {
                    use std::os::unix::ffi::OsStrExt;
                    let name = std::ffi::CString::new(lease.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { crate::libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                }
                "hardlink" => fs::hard_link(&sentinel, &lease).unwrap(),
                "mode" => {
                    fs::write(&lease, b"").unwrap();
                    fs::set_permissions(&lease, fs::Permissions::from_mode(0o644)).unwrap();
                }
                "oversized" => {
                    fs::write(&lease, vec![0u8; 512 * 1024]).unwrap();
                    fs::set_permissions(&lease, fs::Permissions::from_mode(0o600)).unwrap();
                }
                "malformed" => {
                    fs::write(&lease, [1, 0, 0, 0, b'x']).unwrap();
                    fs::set_permissions(&lease, fs::Permissions::from_mode(0o600)).unwrap();
                }
                _ => unreachable!(),
            }
            let old = fs::symlink_metadata(&lease).unwrap();
            let old_bytes = if old.is_file() { Some(fs::read(&lease).unwrap()) } else { None };
            assert!(store_config_bytes_transaction(&path, b"refused", ConfigStoreFault::None).is_err());
            assert!(!base.join("first").exists());
            let after = fs::symlink_metadata(&lease).unwrap();
            assert_eq!((old.dev(), old.ino(), old.mode(), old.nlink(), old.len()),
                (after.dev(), after.ino(), after.mode(), after.nlink(), after.len()));
            if let Some(bytes) = old_bytes { assert_eq!(fs::read(&lease).unwrap(), bytes); }
            if kind == "symlink" { assert_eq!(fs::read_link(&lease).unwrap(), sentinel); }
            assert_eq!(fs::read(&sentinel).unwrap(), b"unchanged sentinel");
            assert!(entries_with_prefix(&base, ".config-dir-stage.").is_empty());
            println!("OPTION_COMMIT_DIRECTORY_JOURNAL=unsafe kind={kind} refused=true preserved=true");
        }
        let after = fs::read_dir("/proc/self/fd").unwrap().count();
        assert_eq!(before, after);
        println!("OPTION_COMMIT_DIRECTORY_JOURNAL=unsafe_handles before={before} after={after}");
    });
}
