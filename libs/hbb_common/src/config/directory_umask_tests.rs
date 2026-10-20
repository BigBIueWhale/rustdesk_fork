use super::*;
use std::os::unix::io::AsRawFd;

struct Umask(u32);

impl Umask {
    fn set(value: u32) -> Self { Self(unsafe { crate::libc::umask(value) }) }
}

impl Drop for Umask {
    fn drop(&mut self) { unsafe { crate::libc::umask(self.0); } }
}

#[test]
fn directory_first_saves_and_replacements_preserve_every_owner_umask() {
    in_private_process("config::option_tests::directory_tests::crash_tests::umask_tests::directory_first_saves_and_replacements_preserve_every_owner_umask", |root| {
        let before = fs::read_dir("/proc/self/fd").unwrap().count();
        let mut all_correct = true;
        for parent in ["plain", "setgid"] {
            for owner in 0..8 {
                let mask = (owner << 6) | 0o077;
                let base = root.join(format!("{parent}-{mask:04o}"));
                fs::create_dir(&base).unwrap();
                fs::set_permissions(&base, fs::Permissions::from_mode(if parent == "setgid" { 0o2700 } else { 0o700 })).unwrap();
                let original = fs::metadata(&base).unwrap();
                let path = base.join("first/second/config.toml");
                let guard = Umask::set(mask);
                let first = store_config_bytes_transaction(&path, b"first", ConfigStoreFault::None);
                let first_bytes = first.is_ok() && fs::read(&path).unwrap() == b"first";
                let first_mask = unsafe { crate::libc::umask(mask) };
                let second = store_config_bytes_transaction(&path, b"second", ConfigStoreFault::None);
                let second_mask = unsafe { crate::libc::umask(mask) };
                drop(guard);
                let final_bytes = second.is_ok() && fs::read(&path).unwrap() == b"second";
                let modes = second.is_ok()
                    && fs::metadata(base.join("first")).unwrap().mode() & 0o7777 == 0o700
                    && fs::metadata(base.join("first/second")).unwrap().mode() & 0o7777 == 0o700
                    && fs::metadata(&path).unwrap().mode() & 0o7777 == 0o600;
                let idle = fs::metadata(only_lease(&base)).unwrap().len() == 0
                    && entries_with_prefix(&base, ".config-dir-stage.").is_empty();
                let after = fs::metadata(&base).unwrap();
                let parent_preserved = (original.dev(), original.ino(), original.uid(), original.gid(), original.mode())
                    == (after.dev(), after.ino(), after.uid(), after.gid(), after.mode());
                let mask_unchanged = first_mask == mask && second_mask == mask;
                let correct = first_bytes && final_bytes && modes && idle && parent_preserved && mask_unchanged;
                println!("OPTION_COMMIT_CONFIG_UMASK=save parent={parent} mask={mask:04o} first={} second={} first_bytes={first_bytes} final_bytes={final_bytes} modes={modes} idle={idle} mask_unchanged={mask_unchanged} parent_preserved={parent_preserved}", first.is_ok(), second.is_ok());
                all_correct &= correct;
                // Fixture-only cleanup after observations permits the failing baseline to finish.
                for stage in entries_with_prefix(&base, ".config-dir-stage.") {
                    fs::set_permissions(stage, fs::Permissions::from_mode(0o700)).unwrap();
                }
                fs::remove_dir_all(&base).unwrap();
            }
        }
        let after = fs::read_dir("/proc/self/fd").unwrap().count();
        println!("OPTION_COMMIT_CONFIG_UMASK=save_handles before={before} after={after}");
        assert_eq!(before, after);
        assert!(all_correct);
    });
}

fn deny_descriptor_chmod() {
    assert_eq!(crate::libc::SYS_fchmodat, 268);
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
        jump(equal, crate::libc::SYS_fchmodat as u32, 0, 1),
        statement(ret, crate::libc::SECCOMP_RET_ERRNO | crate::libc::EIO as u32),
        statement(ret, crate::libc::SECCOMP_RET_ALLOW),
    ];
    let program = crate::libc::sock_fprog { len: filter.len() as u16, filter: filter.as_mut_ptr() };
    assert_eq!(unsafe { crate::libc::prctl(crate::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }, 0);
    assert_eq!(unsafe { crate::libc::syscall(crate::libc::SYS_seccomp,
        crate::libc::SECCOMP_SET_MODE_FILTER, 0, &program) }, 0);
}

fn permission_worker(test: &str, root: &Path) -> bool {
    let step = match std::env::var("RUSTDESK_DIRECTORY_CRASH_STEP") {
        Ok(step) => step, Err(_) => return false,
    };
    assert_eq!(std::env::var("RUSTDESK_DIRECTORY_CRASH_TEST").unwrap(), test);
    let base = PathBuf::from(std::env::var_os("RUSTDESK_DIRECTORY_CRASH_BASE").unwrap());
    assert!(base.starts_with(root) && base != root);
    let path = base.join("first/second/config.toml");
    if step == "fault" {
        let directory = fs::File::open(&base).unwrap();
        fs::write(base.join("probe"), b"probe preserved").unwrap();
        deny_descriptor_chmod();
        let probe = std::ffi::CString::new("probe").unwrap();
        assert_eq!(unsafe { crate::libc::fchmodat(directory.as_raw_fd(), probe.as_ptr(), 0o600, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(crate::libc::EIO));
        let guard = Umask::set(0o777);
        let result = store_config_bytes_transaction(&path, b"refused", ConfigStoreFault::None);
        let observed_mask = unsafe { crate::libc::umask(0o777) };
        drop(guard);
        let errno = result.as_ref().err().and_then(|e| e.downcast_ref::<io::Error>())
            .and_then(io::Error::raw_os_error).unwrap_or(0);
        let stages = entries_with_prefix(&base, ".config-dir-stage.");
        assert_eq!(stages.len(), 1);
        let mode = fs::metadata(&stages[0]).unwrap().mode() & 0o7777;
        let journal = fs::read(only_lease(&base)).unwrap();
        let length = u32::from_le_bytes([journal[0], journal[1], journal[2], journal[3]]) as usize;
        let record: serde_json::Value = serde_json::from_slice(&journal[4..4 + length]).unwrap();
        let reserved = journal.len() == length + 36 && record["root"].is_null() && record["selected"].is_null();
        println!("OPTION_COMMIT_CONFIG_UMASK=fault errno={errno} refused={} file_absent={} stage_mode={mode:04o} journal_reserved={reserved} mask_unchanged={}", result.is_err(), !base.join("first").exists(), observed_mask == 0o777);
        assert_eq!(fs::read(base.join("probe")).unwrap(), b"probe preserved");
        assert!(result.is_err() && errno == crate::libc::EIO && !base.join("first").exists()
            && mode == 0 && reserved && observed_mask == 0o777);
    } else {
        assert_eq!(step, "save");
        let guard = Umask::set(0o777);
        let result = store_config_bytes_transaction(&path, b"after chmod retry", ConfigStoreFault::None);
        let observed_mask = unsafe { crate::libc::umask(0o777) };
        drop(guard);
        assert_eq!(observed_mask, 0o777);
        if result.is_err() { std::process::exit(81); }
    }
    true
}

#[test]
fn directory_retained_chmod_failure_preserves_reservation_and_retries() {
    let test = "config::option_tests::directory_tests::crash_tests::umask_tests::directory_retained_chmod_failure_preserves_reservation_and_retries";
    in_private_process(test, |root| {
        if permission_worker(test, root) { return; }
        let before = fs::read_dir("/proc/self/fd").unwrap().count();
        let base = root.join("chmod-failure");
        fs::create_dir(&base).unwrap();
        let fault = run_worker(test, &base, "fault");
        for line in String::from_utf8_lossy(&fault.stdout).lines() {
            if let Some(start) = line.find("OPTION_COMMIT_") { println!("{}", &line[start..]); }
        }
        let stages = entries_with_prefix(&base, ".config-dir-stage.");
        assert_eq!(stages.len(), 1);
        let retained = fs::OpenOptions::new().read(true)
            .custom_flags(crate::libc::O_PATH | crate::libc::O_DIRECTORY | crate::libc::O_NOFOLLOW)
            .open(&stages[0]).unwrap();
        let original = retained.metadata().unwrap();
        let retry = run_worker(test, &base, "save");
        let saved = retry.status.success();
        let retired = retained.metadata().unwrap().nlink() == 0 && !stages[0].exists();
        let fresh = fs::metadata(base.join("first"))
            .map(|m| (m.dev(), m.ino()) != (original.dev(), original.ino())).unwrap_or(false);
        let path = base.join("first/second/config.toml");
        let correct = fault.status.success() && saved && retired && fresh
            && fs::read(&path).unwrap() == b"after chmod retry"
            && fs::metadata(&path).unwrap().mode() & 0o7777 == 0o600
            && fs::metadata(only_lease(&base)).unwrap().len() == 0;
        println!("OPTION_COMMIT_CONFIG_UMASK=retry fault_worker_ok={} saved={saved} retired={retired} fresh={fresh} correct={correct}", fault.status.success());
        drop(retained);
        // The old writer cannot read its mode0000 stage; repair only the test fixture for cleanup.
        for stage in entries_with_prefix(&base, ".config-dir-stage.") {
            fs::set_permissions(stage, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let after = fs::read_dir("/proc/self/fd").unwrap().count();
        println!("OPTION_COMMIT_CONFIG_UMASK=retry_handles before={before} after={after}");
        assert_eq!(before, after);
        assert!(correct);
    });
}
