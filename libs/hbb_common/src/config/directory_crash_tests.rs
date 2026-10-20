use super::*;
use std::{os::unix::fs::OpenOptionsExt, process::{Command, Output, Stdio}};

std::arch::global_asm!(
    ".global rustdesk_config_test_mkdirat",
    ".type rustdesk_config_test_mkdirat,@function",
    "rustdesk_config_test_mkdirat:",
    "mov eax, 258",
    "syscall",
    ".global rustdesk_config_test_mkdirat_resume",
    "rustdesk_config_test_mkdirat_resume:",
    "ret",
);

extern "C" {
    fn rustdesk_config_test_mkdirat(fd: i32, name: *const crate::libc::c_char, mode: u32) -> i64;
    static rustdesk_config_test_mkdirat_resume: u8;
}

static MKDIR_DEVICE: AtomicU64 = AtomicU64::new(0);
static MKDIR_INODE: AtomicU64 = AtomicU64::new(0);

extern "C" fn exit_after_mkdir(_signal: i32, _info: *mut crate::libc::siginfo_t,
    context: *mut crate::libc::c_void) {
    unsafe {
        let registers = &(*(context as *mut crate::libc::ucontext_t)).uc_mcontext.gregs;
        let fd = registers[crate::libc::REG_RDI as usize] as i32;
        let name = registers[crate::libc::REG_RSI as usize] as *const crate::libc::c_char;
        let mode = registers[crate::libc::REG_RDX as usize] as u32;
        let mut metadata = std::mem::MaybeUninit::<crate::libc::stat>::uninit();
        if mode != 0o700 || crate::libc::fstat(fd, metadata.as_mut_ptr()) != 0 {
            crate::libc::_exit(75);
        }
        let metadata = metadata.assume_init();
        if metadata.st_dev as u64 != MKDIR_DEVICE.load(Ordering::Relaxed)
            || metadata.st_ino as u64 != MKDIR_INODE.load(Ordering::Relaxed) {
            crate::libc::_exit(76);
        }
        for (index, expected) in b".config-dir-stage.".iter().enumerate() {
            if *name.add(index) as u8 != *expected { crate::libc::_exit(77); }
        }
        let result = rustdesk_config_test_mkdirat(fd, name, mode);
        crate::libc::_exit(if result == 0 { 74 } else { 78 });
    }
}

fn interrupt_mkdir(base: &Path) {
    assert_eq!(crate::libc::SYS_mkdirat, 258);
    let metadata = fs::metadata(base).unwrap();
    MKDIR_DEVICE.store(metadata.dev(), Ordering::Relaxed);
    MKDIR_INODE.store(metadata.ino(), Ordering::Relaxed);
    unsafe {
        let mut action: crate::libc::sigaction = std::mem::zeroed();
        action.sa_flags = crate::libc::SA_SIGINFO;
        action.sa_sigaction = exit_after_mkdir as usize;
        assert_eq!(crate::libc::sigemptyset(&mut action.sa_mask), 0);
        assert_eq!(crate::libc::sigaction(crate::libc::SIGSYS, &action, std::ptr::null_mut()), 0);
        let address = std::ptr::addr_of!(rustdesk_config_test_mkdirat_resume) as u64;
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
            jump(equal, crate::libc::SYS_mkdirat as u32, 0, 5),
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
}

fn worker(test: &str, root: &Path) -> bool {
    let step = match std::env::var("RUSTDESK_DIRECTORY_CRASH_STEP") {
        Ok(step) => step, Err(_) => return false,
    };
    assert_eq!(std::env::var("RUSTDESK_DIRECTORY_CRASH_TEST").unwrap(), test);
    let base = PathBuf::from(std::env::var_os("RUSTDESK_DIRECTORY_CRASH_BASE").unwrap());
    assert!(base.starts_with(root) && base != root);
    let path = base.join("first/second/config.toml");
    match step.as_str() {
        "mkdir" | "restrictive" => {
            if step == "restrictive" { unsafe { crate::libc::umask(0o777); } }
            interrupt_mkdir(&base);
            let result = store_config_bytes_transaction(&path, b"interrupted", ConfigStoreFault::None);
            panic!("writer returned before injected process exit: {result:?}");
        }
        "retry" => {
            if let Err(error) = store_config_bytes_transaction(&path, b"fresh process retry", ConfigStoreFault::None) {
                eprintln!("fresh process refused: {error}");
                std::process::exit(81);
            }
        }
        "sync-fail" => {
            let directory = fs::File::open(&base).unwrap();
            observe_directory_sync(&directory, 1);
            let result = store_config_bytes_transaction(&path, b"refused", ConfigStoreFault::None);
            let calls = SYNC_CALLS.load(Ordering::Relaxed);
            let retired = entries_with_prefix(&base, ".config-dir-stage.").is_empty();
            println!("OPTION_COMMIT_DIRECTORY_CRASH=sync_failure calls={calls} refused={} retired={retired} file_absent={}", result.is_err(), !path.exists());
            assert!(result.is_err() && calls == 1 && retired && !path.exists());
            assert!(!SYNC_HANDLER_ERROR.load(Ordering::Relaxed));
        }
        _ => panic!("unknown child step"),
    }
    true
}

fn run_worker(test: &str, base: &Path, step: &str) -> Output {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--color", "never", "--test-threads=1", "--nocapture"])
        .env("RUSTDESK_DIRECTORY_CRASH_TEST", test)
        .env("RUSTDESK_DIRECTORY_CRASH_BASE", base)
        .env("RUSTDESK_DIRECTORY_CRASH_STEP", step)
        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() { break; }
        if Instant::now() >= deadline {
            let killed = child.kill();
            let joined = child.wait();
            panic!("owned child deadline: kill={killed:?}, joined={joined:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.stdout.len() + output.stderr.len() <= 8192);
    output
}

fn interrupted_stage(test: &str, base: &Path, step: &str) -> (PathBuf, fs::File, PathBuf) {
    let output = run_worker(test, base, step);
    assert_eq!(output.status.code(), Some(74), "mkdir child: {}", String::from_utf8_lossy(&output.stderr));
    assert!(!base.join("first").exists());
    let stages = entries_with_prefix(base, ".config-dir-stage.");
    assert_eq!(stages.len(), 1);
    let lease = only_lease(base);
    let journal = fs::read(&lease).unwrap();
    assert!(journal.len() >= 36);
    let length = u32::from_le_bytes([journal[0], journal[1], journal[2], journal[3]]) as usize;
    assert_eq!(journal.len(), length + 36);
    let body = &journal[4..4 + length];
    let record: serde_json::Value = serde_json::from_slice(body).unwrap();
    assert_eq!(record["stage"].as_str().unwrap(), stages[0].file_name().unwrap().to_str().unwrap());
    assert!(record["root"].is_null() && record["selected"].is_null());
    let retained = fs::OpenOptions::new().read(true)
        .custom_flags(crate::libc::O_PATH | crate::libc::O_NOFOLLOW | crate::libc::O_DIRECTORY)
        .open(&stages[0]).unwrap();
    (stages[0].clone(), retained, lease)
}

#[test]
fn directory_created_before_identity_record_recovers_after_process_exit() {
    let test = "config::option_tests::directory_tests::crash_tests::directory_created_before_identity_record_recovers_after_process_exit";
    in_private_process(test, |root| {
        if worker(test, root) { return; }
        let fds = || fs::read_dir("/proc/self/fd").unwrap().count();
        let before = fds();
        let mut all_correct = true;
        for (kind, mode, step, stage_mode) in [
            ("private", 0o700, "mkdir", 0o700),
            ("readable", 0o755, "mkdir", 0o700),
            ("restrictive", 0o700, "restrictive", 0),
            ("setgid", 0o2700, "mkdir", 0o2700),
            ("sticky", 0o1777, "mkdir", 0o700),
        ] {
            let base = root.join(kind);
            fs::create_dir(&base).unwrap();
            fs::set_permissions(&base, fs::Permissions::from_mode(mode)).unwrap();
            let (stage, retained, lease) = interrupted_stage(test, &base, step);
            let old = retained.metadata().unwrap();
            assert_eq!(old.mode() & 0o7777, stage_mode);
            let lease_identity = fs::metadata(&lease).unwrap().ino();
            let output = run_worker(test, &base, "retry");
            let path = base.join("first/second/config.toml");
            let saved = output.status.success();
            let retired = retained.metadata().unwrap().nlink() == 0 && !stage.exists();
            let fresh = fs::metadata(base.join("first")).map(|m| (m.dev(), m.ino()) != (old.dev(), old.ino())).unwrap_or(false);
            let correct = saved && retired && fresh && fs::read(&path).unwrap() == b"fresh process retry"
                && fs::metadata(&path).unwrap().mode() & 0o7777 == 0o600
                && fs::metadata(&lease).unwrap().ino() == lease_identity
                && fs::metadata(&lease).unwrap().len() == 0;
            println!("OPTION_COMMIT_DIRECTORY_CRASH=restart kind={kind} writer_exit=74 retry_exit={} saved={saved} retired={retired} fresh={fresh} correct={correct}", output.status.code().unwrap());
            all_correct &= correct;
            drop(retained);
            // Fixture-only removal also permits the unchanged-product failing baseline to finish.
            if stage.exists() { fs::set_permissions(&stage, fs::Permissions::from_mode(0o700)).unwrap(); }
            fs::remove_dir_all(&base).unwrap();
        }
        let after = fds();
        println!("OPTION_COMMIT_DIRECTORY_CRASH=restart_handles before={before} after={after}");
        assert_eq!(before, after);
        assert!(all_correct);
    });
}

fn snapshot(base: &Path) -> Vec<(PathBuf, u64, u64, u32, u64, Option<Vec<u8>>, Option<PathBuf>)> {
    let mut pending = vec![base.to_path_buf()];
    let mut result = Vec::new();
    while let Some(path) = pending.pop() {
        assert!(result.len() < 32);
        let metadata = fs::symlink_metadata(&path).unwrap();
        let bytes = if metadata.is_file() { Some(fs::read(&path).unwrap()) } else { None };
        let link = if metadata.file_type().is_symlink() { Some(fs::read_link(&path).unwrap()) } else { None };
        if metadata.is_dir() {
            pending.extend(fs::read_dir(&path).unwrap().map(|entry| entry.unwrap().path()));
        }
        result.push((path, metadata.dev(), metadata.ino(), metadata.mode(), metadata.nlink(), bytes, link));
    }
    result.sort_by(|a, b| a.0.cmp(&b.0));
    result
}

#[test]
fn directory_unrecorded_stage_changes_refuse_and_preserve() {
    let test = "config::option_tests::directory_tests::crash_tests::directory_unrecorded_stage_changes_refuse_and_preserve";
    in_private_process(test, |root| {
        if worker(test, root) { return; }
        let before = fs::read_dir("/proc/self/fd").unwrap().count();
        for kind in ["nonempty", "expected_child", "symlink", "regular", "mode", "moved", "shared_group", "shared_other"] {
            let base = root.join(kind);
            fs::create_dir(&base).unwrap();
            let (stage, retained, _lease) = interrupted_stage(test, &base, "mkdir");
            match kind {
                "nonempty" => fs::write(stage.join("preserve"), b"preserve data").unwrap(),
                "expected_child" => fs::create_dir(stage.join("second")).unwrap(),
                "symlink" | "regular" => {
                    fs::rename(&stage, base.join("preserved-original")).unwrap();
                    if kind == "symlink" {
                        std::os::unix::fs::symlink(base.join("preserved-original"), &stage).unwrap();
                    } else { fs::write(&stage, b"preserve regular file").unwrap(); }
                }
                "mode" => fs::set_permissions(&stage, fs::Permissions::from_mode(0o770)).unwrap(),
                "moved" => fs::rename(&stage, base.join("first")).unwrap(),
                "shared_group" => fs::set_permissions(&base, fs::Permissions::from_mode(0o770)).unwrap(),
                "shared_other" => fs::set_permissions(&base, fs::Permissions::from_mode(0o707)).unwrap(),
                _ => unreachable!(),
            }
            let original = snapshot(&base);
            let output = run_worker(test, &base, "retry");
            let refused = output.status.code() == Some(81);
            let preserved = snapshot(&base) == original && retained.metadata().unwrap().nlink() != 0;
            println!("OPTION_COMMIT_DIRECTORY_CRASH=changed kind={kind} refused={refused} preserved={preserved}");
            assert!(refused && preserved, "retry: {}", String::from_utf8_lossy(&output.stderr));
            drop(retained);
        }
        let after = fs::read_dir("/proc/self/fd").unwrap().count();
        println!("OPTION_COMMIT_DIRECTORY_CRASH=changed_handles before={before} after={after}");
        assert_eq!(before, after);
    });
}

#[test]
fn directory_unrecorded_stage_recovery_sync_error_is_retryable() {
    let test = "config::option_tests::directory_tests::crash_tests::directory_unrecorded_stage_recovery_sync_error_is_retryable";
    in_private_process(test, |root| {
        if worker(test, root) { return; }
        let before = fs::read_dir("/proc/self/fd").unwrap().count();
        let base = root.join("sync-error");
        fs::create_dir(&base).unwrap();
        let (stage, retained, lease) = interrupted_stage(test, &base, "mkdir");
        let journal = fs::read(&lease).unwrap();
        let output = run_worker(test, &base, "sync-fail");
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if let Some(start) = line.find("OPTION_COMMIT_") { println!("{}", &line[start..]); }
        }
        let retired = retained.metadata().unwrap().nlink() == 0 && !stage.exists();
        let preserved = fs::read(&lease).unwrap() == journal;
        let no_file = !base.join("first").exists();
        let retry = run_worker(test, &base, "retry");
        let saved = retry.status.success();
        println!("OPTION_COMMIT_DIRECTORY_CRASH=sync_retry failed_worker_ok={} retired={retired} journal_preserved={preserved} file_absent={no_file} saved={saved}", output.status.success());
        drop(retained);
        let after = fs::read_dir("/proc/self/fd").unwrap().count();
        println!("OPTION_COMMIT_DIRECTORY_CRASH=sync_handles before={before} after={after}");
        assert_eq!(before, after);
        assert!(output.status.success() && retired && preserved && no_file && saved);
        assert_eq!(fs::read(base.join("first/second/config.toml")).unwrap(), b"fresh process retry");
    });
}
