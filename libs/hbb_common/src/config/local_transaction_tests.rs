use super::*;
use std::{cell::Cell, os::unix::{ffi::OsStrExt, fs::{MetadataExt, OpenOptionsExt}, io::AsRawFd}};

const ROLE: &str = "RUSTDESK_LOCAL_TRANSACTION_ROLE";
const PREFIX: &str = "config::option_tests::local_transaction_tests::";

#[derive(Clone, Copy, Debug)]
enum Store { Local, Defaults }

impl Store {
    fn name(self) -> &'static str { match self { Self::Local => "local", Self::Defaults => "defaults" } }
    fn path(self) -> PathBuf { Config::file_(match self { Self::Local => "_local", Self::Defaults => "_default" }) }
    fn set(self, value: &str) -> crate::ResultType<()> {
        match self {
            Self::Local => LocalConfig::set_option("selected".into(), value.into()),
            Self::Defaults => UserDefaultConfig::set_option("selected".into(), value.into()).map(|_| ()),
        }
    }
    fn cached(self) -> String {
        match self {
            Self::Local => LOCAL_CONFIG.read().unwrap().options.get("selected").cloned().unwrap_or_default(),
            Self::Defaults => USER_DEFAULT_CONFIG.read().unwrap().0.get("selected"),
        }
    }
    fn stored(self) -> String {
        match self {
            Self::Local => read_config_view::<LocalConfig>(&self.path()).unwrap().options.get("selected").cloned().unwrap_or_default(),
            Self::Defaults => read_config_view::<UserDefaultConfig>(&self.path()).unwrap().get("selected"),
        }
    }
    fn update(self, mutate: impl Fn(&mut HashMap<String, String>)) -> crate::ResultType<()> {
        match self {
            Self::Local => LocalConfig::update(|candidate| mutate(&mut candidate.options)),
            Self::Defaults => UserDefaultConfig::update(|candidate| mutate(&mut candidate.options)),
        }
    }
    fn child_change(self) -> crate::ResultType<()> {
        match self {
            Self::Local => LocalConfig::set_favorites(vec!["child-peer".into()], true),
            Self::Defaults => UserDefaultConfig::set_option("child-key".into(), "child-value".into()).map(|_| ()),
        }
    }
    fn child_preserved(self) -> bool {
        match self {
            Self::Local => read_config_view::<LocalConfig>(&self.path()).unwrap().fav == ["child-peer"]
                && LocalConfig::get_fav() == ["child-peer"],
            Self::Defaults => read_config_view::<UserDefaultConfig>(&self.path()).unwrap().get("child-key") == "child-value"
                && USER_DEFAULT_CONFIG.read().unwrap().0.get("child-key") == "child-value",
        }
    }
}

fn lease_path(store: Store) -> PathBuf {
    use crate::sha2::{Digest, Sha256};
    let path = store.path();
    let mut hash = Sha256::new();
    hash.update(b"rustdesk-local-preferences-v1\0");
    hash.update(path.file_name().unwrap().as_bytes());
    path.parent().unwrap().join(format!(".config-view-lease.{:x}", hash.finalize()))
}

fn fixture_lease(store: Store) -> fs::File {
    let path = lease_path(store);
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

fn actor(test: &str, role: &str, store: Store) -> serde_json::Value {
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([format!("{PREFIX}{test}"), "--exact".into(), "--nocapture".into(), "--test-threads=1".into()])
        .env(ROLE, role).env("RUSTDESK_PREFERENCE_TEST_STORE", store.name())
        .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
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
    let store = match std::env::var("RUSTDESK_PREFERENCE_TEST_STORE").unwrap().as_str() {
        "local" => Store::Local, "defaults" => Store::Defaults, _ => panic!("invalid actor store"),
    };
    let root = PathBuf::from(std::env::var_os("RUSTDESK_OPTION_COMMIT_TEST_ROOT").unwrap());
    assert!(store.path().starts_with(root));
    if role == "exit-locked" {
        let file = fixture_lease(store);
        lock(&file);
        println!("OPTION_COMMIT_LOCAL_ACTOR={}", serde_json::json!({"pid":std::process::id(),"locked":true}));
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        std::process::exit(0);
    }
    // Initialize the real process cache before observing refusal/publication.
    match store {
        Store::Local => { LocalConfig::get_option("selected"); }
        Store::Defaults => { UserDefaultConfig::get_option("selected"); }
    }
    let original_cache = store.cached();
    let result = if role == "child-change" {
        store.child_change()
    } else {
        assert_eq!(role, "write");
        store.set("desired")
    };
    let timeout = result.as_ref().err().and_then(|err| err.downcast_ref::<io::Error>())
        .map(|err| err.kind() == io::ErrorKind::TimedOut).unwrap_or(false);
    println!("OPTION_COMMIT_LOCAL_ACTOR={}", serde_json::json!({
        "pid":std::process::id(),"saved":result.is_ok(),"timeout":timeout,
        "cache":store.cached(),"original_cache":original_cache
    }));
    true
}

fn in_stores(test: &str, run: impl Fn(Store)) {
    in_private_process(&format!("{PREFIX}{test}"), |_| {
        for store in [Store::Local, Store::Defaults] { run(store); }
    });
}

#[test]
fn preference_updates_preserve_another_process_completed_change() {
    if run_actor() { return; }
    let test = "preference_updates_preserve_another_process_completed_change";
    in_stores(test, |store| {
        store.set("original").unwrap();
        let first = Cell::new(true);
        let result = store.update(|options| {
            if first.replace(false) { assert_eq!(actor(test, "child-change", store)["saved"], true); }
            options.insert("selected".into(), "desired".into());
        });
        let preserved = store.child_preserved();
        println!("OPTION_COMMIT_PREFERENCE_TRANSACTION=interleaved store={} saved={} preserved={preserved}", store.name(), result.is_ok());
        assert!(result.is_ok() && preserved);
        assert_eq!(store.stored(), "desired");
        assert_eq!(store.cached(), "desired");
    });
}

#[test]
fn preference_update_refuses_a_held_cross_process_lease_and_retries() {
    if run_actor() { return; }
    let test = "preference_update_refuses_a_held_cross_process_lease_and_retries";
    in_stores(test, |store| {
        store.set("original").unwrap();
        let path = store.path();
        let original = fs::read(&path).unwrap();
        let identity = |path: &Path| { let m = fs::metadata(path).unwrap(); (m.dev(), m.ino(), m.mode(), m.len()) };
        let before = identity(&path);
        let fds = || fs::read_dir("/proc/self/fd").unwrap().count();
        let before_fds = fds();
        let lease = fixture_lease(store);
        let lease_before = identity(&lease_path(store));
        lock(&lease);
        let start = std::time::Instant::now();
        let observed = actor(test, "write", store);
        let elapsed = start.elapsed().as_millis();
        let refused = observed["saved"] == false && observed["timeout"] == true;
        let preserved = fs::read(&path).unwrap() == original && identity(&path) == before
            && observed["cache"] == "original" && observed["original_cache"] == "original";
        let lease_preserved = identity(&lease_path(store)) == lease_before && fs::read(lease_path(store)).unwrap().is_empty();
        drop(lease);
        store.set("desired").unwrap();
        let retry = store.stored() == "desired" && store.cached() == "desired";
        let after_fds = fds();
        println!("OPTION_COMMIT_PREFERENCE_TRANSACTION=held store={} refused={refused} elapsed_ms={elapsed} preserved={preserved} lease_preserved={lease_preserved} retry={retry} fds={before_fds}:{after_fds}", store.name());
        assert!(refused && preserved && lease_preserved && retry);
        assert!((900..3000).contains(&elapsed));
        assert_eq!(before_fds, after_fds);
    });
}

#[test]
fn preference_update_lease_survives_owner_process_exit() {
    if run_actor() { return; }
    let test = "preference_update_lease_survives_owner_process_exit";
    in_stores(test, |store| {
        store.set("original").unwrap();
        let lease = fixture_lease(store);
        let before = lease.metadata().unwrap();
        drop(lease);
        assert_eq!(actor(test, "exit-locked", store)["locked"], true);
        let canary = fixture_lease(store);
        lock(&canary);
        let after = canary.metadata().unwrap();
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert_eq!(after.len(), 0);
        drop(canary);
        store.set("desired").unwrap();
        assert_eq!(store.stored(), "desired");
        println!("OPTION_COMMIT_PREFERENCE_TRANSACTION=owner_exit store={} retained_inode=true lock_released=true retry=true", store.name());
    });
}
