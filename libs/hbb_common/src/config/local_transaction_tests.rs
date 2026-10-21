use super::*;
use std::{cell::Cell, os::unix::{ffi::OsStrExt, fs::{MetadataExt, OpenOptionsExt}, io::AsRawFd}};

const ROLE: &str = "RUSTDESK_LOCAL_TRANSACTION_ROLE";
const PREFIX: &str = "config::option_tests::local_transaction_tests::";

fn lease_path() -> PathBuf {
    use crate::sha2::{Digest, Sha256};
    let path = Config::file_("_local");
    let mut hash = Sha256::new();
    hash.update(b"rustdesk-local-preferences-v1\0");
    hash.update(path.file_name().unwrap().as_bytes());
    path.parent().unwrap().join(format!(".config-view-lease.{:x}", hash.finalize()))
}

fn fixture_lease() -> fs::File {
    let path = lease_path();
    match fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            fs::OpenOptions::new().read(true).write(true).open(path).unwrap()
        }
        Err(err) => panic!("lease fixture: {err}"),
    }
}

fn lock(file: &fs::File) {
    assert_eq!(unsafe { crate::libc::flock(file.as_raw_fd(), crate::libc::LOCK_EX | crate::libc::LOCK_NB) }, 0);
}

fn actor(test: &str, role: &str) -> serde_json::Value {
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([format!("{PREFIX}{test}"), "--exact".into(), "--nocapture".into(), "--test-threads=1".into()])
        .env(ROLE, role).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
        .spawn().unwrap();
    let pid = child.id();
    assert_ne!(pid, std::process::id());
    let output = child.wait_with_output().unwrap();
    assert!(output.stdout.len() + output.stderr.len() < 8192);
    assert!(output.status.success(), "actor failed: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let marker = "OPTION_COMMIT_LOCAL_ACTOR=";
    let start = stdout.find(marker).unwrap() + marker.len();
    let value: serde_json::Value = serde_json::from_str(stdout[start..].lines().next().unwrap()).unwrap();
    assert_eq!(value["pid"], pid);
    value
}

fn run_actor() -> bool {
    let role = match std::env::var(ROLE) { Ok(role) => role, Err(_) => return false };
    assert_ne!(unsafe { crate::libc::geteuid() }, 0);
    let root = PathBuf::from(std::env::var_os("RUSTDESK_OPTION_COMMIT_TEST_ROOT").unwrap());
    assert!(Config::file_("_local").starts_with(root));
    if role == "exit-locked" {
        let file = fixture_lease();
        lock(&file);
        println!("OPTION_COMMIT_LOCAL_ACTOR={}", serde_json::json!({"pid":std::process::id(),"locked":true}));
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        std::process::exit(0);
    }
    let original_cache = LocalConfig::get_option("selected");
    let result = if role == "favorite" {
        LocalConfig::set_favorites(vec!["child-peer".into()], true)
    } else {
        assert_eq!(role, "write");
        LocalConfig::set_option("selected".into(), "desired".into())
    };
    let timeout = result.as_ref().err().and_then(|err| err.downcast_ref::<io::Error>())
        .map(|err| err.kind() == io::ErrorKind::TimedOut).unwrap_or(false);
    println!("OPTION_COMMIT_LOCAL_ACTOR={}", serde_json::json!({
        "pid":std::process::id(),"saved":result.is_ok(),"timeout":timeout,
        "cache":LocalConfig::get_option("selected"),"original_cache":original_cache
    }));
    true
}

#[test]
fn local_updates_preserve_another_process_completed_change() {
    if run_actor() { return; }
    let test = "local_updates_preserve_another_process_completed_change";
    in_private_process(&format!("{PREFIX}{test}"), |_| {
        LocalConfig::set_option("selected".into(), "original".into()).unwrap();
        let first = Cell::new(true);
        let result = LocalConfig::update(|candidate| {
            if first.replace(false) { assert_eq!(actor(test, "favorite")["saved"], true); }
            candidate.options.insert("selected".into(), "desired".into());
        });
        let stored: LocalConfig = read_config_view(&Config::file_("_local")).unwrap();
        let preserved = stored.fav == ["child-peer"] && LocalConfig::get_fav() == stored.fav;
        println!("OPTION_COMMIT_LOCAL_TRANSACTION=interleaved saved={} preserved={preserved}", result.is_ok());
        assert!(result.is_ok() && preserved);
        assert_eq!(stored.options.get("selected").unwrap(), "desired");
        assert_eq!(LocalConfig::get_option("selected"), "desired");
    });
}

#[test]
fn local_update_refuses_a_held_cross_process_lease_and_retries() {
    if run_actor() { return; }
    let test = "local_update_refuses_a_held_cross_process_lease_and_retries";
    in_private_process(&format!("{PREFIX}{test}"), |_| {
        LocalConfig::set_option("selected".into(), "original".into()).unwrap();
        let path = Config::file_("_local");
        let original = fs::read(&path).unwrap();
        let identity = |path: &Path| { let m = fs::metadata(path).unwrap(); (m.dev(), m.ino(), m.mode(), m.len()) };
        let before = identity(&path);
        let fds = || fs::read_dir("/proc/self/fd").unwrap().count();
        let before_fds = fds();
        let lease = fixture_lease();
        let lease_before = identity(&lease_path());
        lock(&lease);
        let start = std::time::Instant::now();
        let observed = actor(test, "write");
        let elapsed = start.elapsed().as_millis();
        let refused = observed["saved"] == false && observed["timeout"] == true;
        let preserved = fs::read(&path).unwrap() == original && identity(&path) == before
            && observed["cache"] == "original" && observed["original_cache"] == "original";
        let lease_preserved = identity(&lease_path()) == lease_before && fs::read(lease_path()).unwrap().is_empty();
        drop(lease);
        LocalConfig::set_option("selected".into(), "desired".into()).unwrap();
        let stored: LocalConfig = read_config_view(&path).unwrap();
        let retry = stored.options.get("selected").unwrap() == "desired" && LocalConfig::get_option("selected") == "desired";
        let after_fds = fds();
        println!("OPTION_COMMIT_LOCAL_TRANSACTION=held refused={refused} elapsed_ms={elapsed} preserved={preserved} lease_preserved={lease_preserved} retry={retry} fds={before_fds}:{after_fds}");
        assert!(refused && preserved && lease_preserved && retry);
        assert!((900..3000).contains(&elapsed));
        assert_eq!(before_fds, after_fds);
    });
}

#[test]
fn local_update_lease_survives_owner_process_exit() {
    if run_actor() { return; }
    let test = "local_update_lease_survives_owner_process_exit";
    in_private_process(&format!("{PREFIX}{test}"), |_| {
        LocalConfig::set_option("selected".into(), "original".into()).unwrap();
        let lease = fixture_lease();
        let before = lease.metadata().unwrap();
        drop(lease);
        assert_eq!(actor(test, "exit-locked")["locked"], true);
        let canary = fixture_lease();
        lock(&canary);
        let after = canary.metadata().unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert_eq!(after.len(), 0);
        drop(canary);
        LocalConfig::set_option("selected".into(), "desired".into()).unwrap();
        let stored: LocalConfig = read_config_view(&Config::file_("_local")).unwrap();
        assert_eq!(stored.options.get("selected").unwrap(), "desired");
        println!("OPTION_COMMIT_LOCAL_TRANSACTION=owner_exit retained_inode=true lock_released=true retry=true");
    });
}
