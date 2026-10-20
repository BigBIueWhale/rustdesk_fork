use super::*;
use std::{os::unix::fs::MetadataExt, sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering}};

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
        let staged_identity = private.first().map(|p| { let m = fs::metadata(p).unwrap(); (m.dev(), m.ino()) });
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
        let unselected_retired = fail_at != 2 || staged_identity.map(|old| old != identity).unwrap_or(false);
        let retry = fs::read(&path).unwrap() == b"healthy retry"
            && fs::metadata(&path).unwrap().mode() & 0o7777 == 0o600
            && private.iter().all(|p| !p.exists()) && selected_preserved && unselected_retired;
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
