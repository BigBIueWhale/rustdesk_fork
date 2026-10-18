use super::*;
use std::os::unix::fs::PermissionsExt;

mod before {
    use super::*;

    // The complete set_fav body at bd03deb4, before persistence and membership ownership.
    pub fn set_fav(fav: Vec<String>) {
        let mut lock = LOCAL_CONFIG.write().unwrap();
        if lock.fav == fav {
            return;
        }
        lock.fav = fav;
        lock.store();
    }
}

fn in_private_process(test: &str, run: impl FnOnce(&Path)) {
    const ROOT_ENV: &str = "RUSTDESK_OPTION_COMMIT_TEST_ROOT";
    if let Some(root) = std::env::var_os(ROOT_ENV) {
        let root = PathBuf::from(root);
        assert_ne!(unsafe { crate::libc::geteuid() }, 0);
        assert!(Config2::file().starts_with(&root));
        run(&root);
        return;
    }
    let root = std::env::temp_dir().join(format!("option-commit-{}", crate::uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--color", "never", "--test-threads=1", "--nocapture"])
        .env(ROOT_ENV, &root)
        .env("XDG_CONFIG_HOME", &root)
        .output().unwrap();
    fs::remove_dir_all(&root).unwrap();
    assert!(output.stdout.len() + output.stderr.len() <= 16384);
    for line in String::from_utf8(output.stdout).unwrap().lines() {
        if let Some(start) = line.find("OPTION_COMMIT_") {
            println!("{}", &line[start..]);
        }
    }
    assert!(output.status.success(), "option worker failed: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn failed_write_preserves_memory_and_allows_the_same_retry() {
    in_private_process("config::option_tests::failed_write_preserves_memory_and_allows_the_same_retry", |_| {
        let mut outcomes = Vec::new();
        for requested in ["replacement-source", ""] {
            let _ = Config::set_option("audio-input".into(), "original-source".into());
            let _ = Config::set_option("enable-abr".into(), "N".into());
            let file = Config2::file();
            let parent = file.parent().unwrap();
            let before = fs::read(&file).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let _ = Config::set_option("audio-input".into(), requested.into());
            let memory_preserved = Config::get_option("audio-input") == "original-source";
            let file_preserved = fs::read(&file).unwrap() == before;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            let _ = Config::set_option("audio-input".into(), requested.into());
            let stored: Config2 = load_path(file);
            let retry_persisted = stored.options.get("audio-input").map(String::as_str).unwrap_or("") == requested;
            let unrelated_preserved = Config::get_option("enable-abr") == "N"
                && stored.options.get("enable-abr").map(String::as_str) == Some("N");
            println!("OPTION_COMMIT_WRITE=observed removal={} memory_preserved={memory_preserved} file_preserved={file_preserved} retry_persisted={retry_persisted} unrelated_preserved={unrelated_preserved}", requested.is_empty());
            outcomes.push(memory_preserved && file_preserved && retry_persisted && unrelated_preserved);
        }
        assert!(outcomes.into_iter().all(|passed| passed));
    });
}

#[test]
fn failed_pinned_entry_purge_remains_retryable() {
    in_private_process("config::option_tests::failed_pinned_entry_purge_remains_retryable", |_| {
        let _ = Config::set_option("audio-input".into(), "original-source".into());
        CONFIG2.write().unwrap().options.insert("enable-keyboard".into(), "N".into());
        let file = Config2::file();
        store_path(file.clone(), &*CONFIG2.read().unwrap()).unwrap();
        let before = fs::read(&file).unwrap();
        let parent = file.parent().unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        let _ = Config::set_option("enable-keyboard".into(), "N".into());
        let memory_preserved = CONFIG2.read().unwrap().options.get("enable-keyboard").map(String::as_str) == Some("N");
        let file_preserved = fs::read(&file).unwrap() == before;
        let policy_preserved = Config::get_option("enable-keyboard") == "Y";
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        let _ = Config::set_option("enable-keyboard".into(), "N".into());
        let stored: Config2 = load_path(file);
        let retry_purged = !stored.options.contains_key("enable-keyboard")
            && !CONFIG2.read().unwrap().options.contains_key("enable-keyboard");
        let unrelated_preserved = stored.options.get("audio-input").map(String::as_str) == Some("original-source");
        println!("OPTION_COMMIT_PURGE=observed memory_preserved={memory_preserved} file_preserved={file_preserved} policy_preserved={policy_preserved} retry_purged={retry_purged} unrelated_preserved={unrelated_preserved}");
        assert!(memory_preserved && file_preserved && policy_preserved && retry_purged && unrelated_preserved);
    });
}

#[test]
fn results_distinguish_failed_saves_from_durable_and_idempotent_success() {
    in_private_process("config::option_tests::results_distinguish_failed_saves_from_durable_and_idempotent_success", |_| {
        Config::set_option("audio-input".into(), "original-source".into()).unwrap();
        let file = Config2::file();
        let parent = file.parent().unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        let failure_returned = Config::set_option("audio-input".into(), "replacement-source".into()).is_err();
        let unchanged_accepted = Config::set_option("audio-input".into(), "original-source".into()).is_ok();
        let pinned_accepted = Config::set_option("enable-keyboard".into(), "N".into()).is_ok()
            && Config::get_option("enable-keyboard") == "Y";
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        let retry_accepted = Config::set_option("audio-input".into(), "replacement-source".into()).is_ok();
        let stored: Config2 = load_path(file);
        let retry_persisted = stored.options.get("audio-input").map(String::as_str) == Some("replacement-source");
        println!("OPTION_COMMIT_RESULT=observed failure_returned={failure_returned} unchanged_accepted={unchanged_accepted} pinned_accepted={pinned_accepted} retry_accepted={retry_accepted} retry_persisted={retry_persisted}");
        assert!(failure_returned && unchanged_accepted && pinned_accepted && retry_accepted && retry_persisted);
    });
}

#[test]
fn favorite_failure_preserves_state_and_retries_the_exact_membership_change() {
    in_private_process("config::option_tests::favorite_failure_preserves_state_and_retries_the_exact_membership_change", |_| {
        LocalConfig::set_flutter_option("favorite-test".into(), "preserved".into());
        before::set_fav(vec!["original".into()]);
        let file = Config::file_("_local");
        let parent = file.parent().unwrap();
        let original = fs::read(&file).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        before::set_fav(vec!["original".into(), "second".into()]);
        let old_published = LocalConfig::get_fav() == ["original", "second"];
        let old_file_preserved = fs::read(&file).unwrap() == original;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        before::set_fav(vec!["original".into(), "second".into()]);
        let old_retry_skipped = fs::read(&file).unwrap() == original;
        println!("OPTION_COMMIT_FAVORITES_BEFORE=observed published_without_commit={old_published} file_preserved={old_file_preserved} retry_skipped={old_retry_skipped}");
        assert!(old_published && old_file_preserved && old_retry_skipped);
        before::set_fav(vec!["original".into()]);

        for favorite in [true, false] {
            let memory = LocalConfig::get_fav();
            let durable = fs::read(&file).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let failed = LocalConfig::set_favorites(vec!["second".into()], favorite).is_err();
            let memory_preserved = LocalConfig::get_fav() == memory;
            let file_preserved = fs::read(&file).unwrap() == durable;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            LocalConfig::set_favorites(vec!["second".into()], favorite).unwrap();
            let stored: LocalConfig = load_path(file.clone());
            let retry_persisted = stored.fav == LocalConfig::get_fav()
                && stored.fav.contains(&"second".to_owned()) == favorite;
            let unrelated_preserved = stored.ui_flutter.get("favorite-test").map(String::as_str) == Some("preserved")
                && stored.fav.contains(&"original".to_owned());
            println!("OPTION_COMMIT_FAVORITES_NATIVE=observed favorite={favorite} failure_reported={failed} memory_preserved={memory_preserved} file_preserved={file_preserved} retry_persisted={retry_persisted} unrelated_preserved={unrelated_preserved}");
            assert!(failed && memory_preserved && file_preserved && retry_persisted && unrelated_preserved);
        }
    });
}

#[test]
fn favorite_membership_preserves_order_and_avoids_idempotent_writes() {
    in_private_process("config::option_tests::favorite_membership_preserves_order_and_avoids_idempotent_writes", |_| {
        LocalConfig::set_favorites(vec!["one".into(), "two".into(), "one".into(), "three".into()], true).unwrap();
        assert_eq!(LocalConfig::get_fav(), ["one", "two", "three"]);
        LocalConfig::set_favorites(vec!["two".into(), "missing".into()], false).unwrap();
        LocalConfig::set_favorites(vec!["one".into(), "four".into()], true).unwrap();
        assert_eq!(LocalConfig::get_fav(), ["one", "three", "four"]);
        let file = Config::file_("_local");
        let parent = file.parent().unwrap();
        let durable = fs::read(&file).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        LocalConfig::set_favorites(vec!["one".into(), "three".into()], true).unwrap();
        LocalConfig::set_favorites(vec!["missing".into()], false).unwrap();
        assert_eq!(fs::read(&file).unwrap(), durable);
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        println!("OPTION_COMMIT_FAVORITES_MEMBERSHIP=observed order=preserved duplicates=absent idempotent=without-write");
    });
}

#[test]
fn concurrent_favorite_membership_changes_preserve_every_admitted_id() {
    in_private_process("config::option_tests::concurrent_favorite_membership_changes_preserve_every_admitted_id", |_| {
        let start = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            for index in 0..8 {
                let start = &start;
                scope.spawn(move || {
                    start.wait();
                    LocalConfig::set_favorites(vec![format!("peer-{index}")], true).unwrap();
                });
            }
        });
        let current = LocalConfig::get_fav();
        assert_eq!(current.len(), 8);
        for index in 0..8 {
            assert!(current.contains(&format!("peer-{index}")));
        }
        let stored: LocalConfig = load_path(Config::file_("_local"));
        assert_eq!(stored.fav, current);
        println!("OPTION_COMMIT_FAVORITES_CONCURRENT=observed writers=8 ids=8 durable=equal cleanup=joined");
    });
}
