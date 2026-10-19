use super::*;
use std::os::unix::fs::PermissionsExt;

#[path = "../../../../scripts/fixtures/default-options-before-transaction.rs"]
mod before_defaults;

#[path = "../../../../scripts/fixtures/peer-store-before-errors.rs"]
mod before_peer;

mod before {
    use super::*;

    trait HistoricalLocalStore {
        fn store(&self);
    }

    impl HistoricalLocalStore for LocalConfig {
        fn store(&self) {
            Config::store_(self, "_local");
        }
    }

    pub fn set_remote_id(remote_id: &str) {
        let mut config = LOCAL_CONFIG.write().unwrap();
        if remote_id == config.remote_id {
            return;
        }
        config.remote_id = remote_id.into();
        config.store();
    }

    pub fn set_flutter_option(k: String, v: String) {
        let mut config = LOCAL_CONFIG.write().unwrap();
        let v2 = if v.is_empty() { None } else { Some(&v) };
        if v2 != config.ui_flutter.get(&k) {
            if v2.is_none() {
                config.ui_flutter.remove(&k);
            } else {
                config.ui_flutter.insert(k, v);
            }
            config.store();
        }
    }

    pub fn set_option(k: String, v: String) {
        if !is_option_can_save(&OVERWRITE_LOCAL_SETTINGS, &k, &DEFAULT_LOCAL_SETTINGS, &v) {
            let mut config = LOCAL_CONFIG.write().unwrap();
            if config.options.remove(&k).is_some() {
                config.store();
            }
            return;
        }
        let mut config = LOCAL_CONFIG.write().unwrap();
        // The custom client will explictly set "default" as the default language.
        let is_custom_client_default_lang = k == keys::OPTION_LANGUAGE && v == "default";
        if is_custom_client_default_lang {
            config.options.insert(k, "".to_owned());
            config.store();
            return;
        }
        let v2 = if v.is_empty() { None } else { Some(&v) };
        if v2 != config.options.get(&k) {
            if v2.is_none() {
                config.options.remove(&k);
            } else {
                config.options.insert(k, v);
            }
            config.store();
        }
    }

    // The complete set_fav body at bd03deb4, before persistence and membership ownership.
    pub fn set_fav(fav: Vec<String>) {
        let mut lock = LOCAL_CONFIG.write().unwrap();
        if lock.fav == fav {
            return;
        }
        lock.fav = fav;
        lock.store();
    }

    pub fn set_kb_layout_type(kb_layout_type: String) {
        let mut config = LOCAL_CONFIG.write().unwrap();
        config.kb_layout_type = kb_layout_type;
        config.store();
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
fn peer_store_reports_failure_without_publishing_a_change_and_refuses_unreadable_source() {
    in_private_process("config::option_tests::peer_store_reports_failure_without_publishing_a_change_and_refuses_unreadable_source", |_| {
        let id = "peer-commit-fixture";
        let mut candidate = PeerConfig::default();
        candidate.password_prs = b"fixture-peer-prs".to_vec();
        candidate.options.insert("unrelated".into(), "preserved".into());
        candidate.store(id).unwrap();
        let file = PeerConfig::path(id);
        let parent = file.parent().unwrap();
        let original = fs::read(&file).unwrap();
        candidate.options.insert("selected".into(), "replacement".into());
        NEW_STORED_PEER_CONFIG.lock().unwrap().remove(id);
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        before_peer::store_before(&candidate, id);
        let old_marked = NEW_STORED_PEER_CONFIG.lock().unwrap().remove(id);
        let old_file_preserved = fs::read(&file).unwrap() == original;
        println!("OPTION_COMMIT_PEER_BEFORE=observed normal_return=true false_change_mark={old_marked} file_preserved={old_file_preserved}");
        assert!(old_marked && old_file_preserved);
        let failed = candidate.store(id).is_err();
        let no_change_mark = !NEW_STORED_PEER_CONFIG.lock().unwrap().contains(id);
        let file_preserved = fs::read(&file).unwrap() == original;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        candidate.store(id).unwrap();
        let durable_retry = PeerConfig::load_for_write(id).unwrap() == candidate;
        let committed_mark = NEW_STORED_PEER_CONFIG.lock().unwrap().remove(id);
        let committed = fs::read(&file).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
        let unreadable_refused = PeerConfig::load_for_write(id).is_err();
        let unreadable_not_marked = !NEW_STORED_PEER_CONFIG.lock().unwrap().contains(id);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let read_failure_preserved = fs::read(&file).unwrap() == committed;
        println!("OPTION_COMMIT_PEER_NATIVE=observed failure_reported={failed} no_false_change_mark={no_change_mark} file_preserved={file_preserved} retry_durable={durable_retry} committed_mark={committed_mark} unreadable_refused={unreadable_refused} unreadable_not_marked={unreadable_not_marked} read_failure_preserved={read_failure_preserved}");
        assert!(failed && no_change_mark && file_preserved && durable_retry && committed_mark && unreadable_refused && unreadable_not_marked && read_failure_preserved);
    });
}

#[test]
fn default_single_key_writes_preserve_other_keys_and_concurrent_writers() {
    in_private_process("config::option_tests::default_single_key_writes_preserve_other_keys_and_concurrent_writers", |_| {
        let mut left = UserDefaultConfig::load();
        let mut right = UserDefaultConfig::load();
        left.set("left".into(), "one".into());
        right.set("right".into(), "two".into());
        let old = UserDefaultConfig::load();
        let old_lost_update = old.get("left").is_empty() && old.get("right") == "two";
        println!("OPTION_COMMIT_DEFAULT_BEFORE=observed stale_snapshot_erased_other_key={old_lost_update}");
        assert!(old_lost_update);
        assert_eq!(UserDefaultConfig::set_option("left".into(), "one".into()).unwrap(), "one");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let writers: Vec<_> = (0..8).map(|i| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let key = format!("default-worker-{i}");
                assert_eq!(UserDefaultConfig::set_option(key, i.to_string()).unwrap(), i.to_string());
            })
        }).collect();
        for writer in writers { writer.join().unwrap(); }
        let stored = UserDefaultConfig::load();
        let all_preserved = stored.get("left") == "one" && stored.get("right") == "two"
            && (0..8).all(|i| stored.get(&format!("default-worker-{i}")) == i.to_string());
        let cache_current = USER_DEFAULT_CONFIG.read().unwrap().0.options == stored.options;
        println!("OPTION_COMMIT_DEFAULT_CONCURRENT=observed writers=8 keys_preserved={all_preserved} cache_current={cache_current} cleanup=joined");
        assert!(all_preserved && cache_current);
    });
}

#[test]
fn default_write_failure_preserves_cache_file_and_identical_retry() {
    in_private_process("config::option_tests::default_write_failure_preserves_cache_file_and_identical_retry", |_| {
        UserDefaultConfig::set_option("default-unrelated".into(), "preserved".into()).unwrap();
        let file = Config::file_("_default");
        let parent = file.parent().unwrap();
        UserDefaultConfig::set_option(keys::OPTION_VIEW_STYLE.into(), "adaptive".into()).unwrap();
        let mut historical = UserDefaultConfig::load();
        let original = fs::read(&file).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        historical.set(keys::OPTION_VIEW_STYLE.into(), "original".into());
        let old_snapshot_changed = historical.options.get(keys::OPTION_VIEW_STYLE).map(String::as_str) == Some("original");
        let old_file_preserved = fs::read(&file).unwrap() == original;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        println!("OPTION_COMMIT_DEFAULT_WRITE_BEFORE=observed returned_without_error=true snapshot_changed={old_snapshot_changed} file_preserved={old_file_preserved}");
        assert!(old_snapshot_changed && old_file_preserved);
        for requested in ["original", ""] {
            UserDefaultConfig::set_option(keys::OPTION_VIEW_STYLE.into(), "adaptive".into()).unwrap();
            let original = fs::read(&file).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let failed = UserDefaultConfig::set_option(keys::OPTION_VIEW_STYLE.into(), requested.into()).is_err();
            let cache_preserved = USER_DEFAULT_CONFIG.read().unwrap().0.get(keys::OPTION_VIEW_STYLE) == "adaptive";
            let file_preserved = fs::read(&file).unwrap() == original;
            let unchanged = UserDefaultConfig::set_option(keys::OPTION_VIEW_STYLE.into(), "adaptive".into()).unwrap() == "adaptive";
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            let effective = UserDefaultConfig::set_option(keys::OPTION_VIEW_STYLE.into(), requested.into()).unwrap();
            let stored = UserDefaultConfig::load();
            let retry_persisted = effective == "original" && stored.get(keys::OPTION_VIEW_STYLE) == effective;
            let cache_current = UserDefaultConfig::read(keys::OPTION_VIEW_STYLE) == effective;
            let unrelated_preserved = stored.get("default-unrelated") == "preserved";
            println!("OPTION_COMMIT_DEFAULT_NATIVE=observed removal={} failure_reported={failed} cache_preserved={cache_preserved} file_preserved={file_preserved} unchanged_without_write={unchanged} retry_persisted={retry_persisted} cache_current={cache_current} unrelated_preserved={unrelated_preserved}", requested.is_empty());
            assert!(failed && cache_preserved && file_preserved && unchanged && retry_persisted && cache_current && unrelated_preserved);
        }
    });
}

#[test]
fn default_purge_is_retryable_and_returns_effective_normalized_values() {
    in_private_process("config::option_tests::default_purge_is_retryable_and_returns_effective_normalized_values", |_| {
        let file = Config::file_("_default");
        for overwritten in [false, true] {
            UserDefaultConfig::set_option("default-purge".into(), "stored".into()).unwrap();
            let policy = if overwritten { &*OVERWRITE_DISPLAY_SETTINGS } else { &*DEFAULT_DISPLAY_SETTINGS };
            policy.write().unwrap().insert("default-purge".into(), "policy".into());
            let original = fs::read(&file).unwrap();
            let parent = file.parent().unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let failed = UserDefaultConfig::set_option("default-purge".into(), "policy".into()).is_err();
            let file_preserved = fs::read(&file).unwrap() == original;
            let cache_preserved = USER_DEFAULT_CONFIG.read().unwrap().0.options.get("default-purge").map(String::as_str) == Some("stored");
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            let effective = UserDefaultConfig::set_option("default-purge".into(), "policy".into()).unwrap();
            let retry_purged = effective == "policy" && !UserDefaultConfig::load().options.contains_key("default-purge");
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let idempotent = UserDefaultConfig::set_option("default-purge".into(), "policy".into()).unwrap() == "policy";
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            policy.write().unwrap().clear();
            println!("OPTION_COMMIT_DEFAULT_PURGE=observed overwritten={overwritten} failure_reported={failed} cache_preserved={cache_preserved} file_preserved={file_preserved} retry_purged={retry_purged} idempotent_without_write={idempotent}");
            assert!(failed && cache_preserved && file_preserved && retry_purged && idempotent);
        }
        let normalized = UserDefaultConfig::set_option(keys::OPTION_CUSTOM_FPS.into(), "25.0".into()).unwrap() == "25"
            && UserDefaultConfig::read(keys::OPTION_CUSTOM_FPS) == "25";
        let fallback = UserDefaultConfig::set_option(keys::OPTION_CUSTOM_FPS.into(), "9999".into()).unwrap() == "30"
            && UserDefaultConfig::read(keys::OPTION_CUSTOM_FPS) == "30";
        println!("OPTION_COMMIT_DEFAULT_EFFECTIVE=observed normalized={normalized} existing_fallback_reported={fallback}");
        assert!(normalized && fallback);
        let disabled = UserDefaultConfig::set_option(keys::OPTION_ENABLE_FILE_COPY_PASTE.into(), "N".into()).unwrap() == "N"
            && UserDefaultConfig::get_option(keys::OPTION_ENABLE_FILE_COPY_PASTE) == "N";
        let restored = UserDefaultConfig::set_option(keys::OPTION_ENABLE_FILE_COPY_PASTE.into(), String::new()).unwrap() == "Y"
            && UserDefaultConfig::get_option(keys::OPTION_ENABLE_FILE_COPY_PASTE) == "Y";
        println!("OPTION_COMMIT_DEFAULT_BOOL=observed explicit_disabled={disabled} empty_restores_enabled_default={restored}");
        assert!(disabled && restored);
    });
}

#[test]
fn default_unreadable_source_refuses_mutation_without_losing_existing_values() {
    in_private_process("config::option_tests::default_unreadable_source_refuses_mutation_without_losing_existing_values", |_| {
        UserDefaultConfig::set_option("default-read-test".into(), "original".into()).unwrap();
        let file = Config::file_("_default");
        let original = fs::read(&file).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
        USER_DEFAULT_CONFIG.write().unwrap().1 = Instant::now() - Duration::from_secs(2);
        let read_preserved = UserDefaultConfig::get_option("default-read-test") == "original";
        let failed = UserDefaultConfig::set_option("default-read-test".into(), "replacement".into()).is_err();
        let cache_preserved = USER_DEFAULT_CONFIG.read().unwrap().0.get("default-read-test") == "original";
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let file_preserved = fs::read(&file).unwrap() == original;
        let retried = UserDefaultConfig::set_option("default-read-test".into(), "replacement".into()).unwrap() == "replacement"
            && UserDefaultConfig::load().get("default-read-test") == "replacement";
        println!("OPTION_COMMIT_DEFAULT_READ=observed last_confirmed_read_preserved={read_preserved} failure_reported={failed} cache_preserved={cache_preserved} file_preserved={file_preserved} retry_persisted={retried}");
        assert!(read_preserved && failed && cache_preserved && file_preserved && retried);
    });
}

#[test]
fn last_peer_failure_preserves_state_and_retries_the_identical_value() {
    in_private_process("config::option_tests::last_peer_failure_preserves_state_and_retries_the_identical_value", |_| {
        LocalConfig::set_option("last-peer-test".into(), "preserved".into()).unwrap();
        LocalConfig::set_favorites(vec!["favorite-peer".into()], true).unwrap();
        before::set_remote_id("127.0.0.1:24001");
        let file = Config::file_("_local");
        let parent = file.parent().unwrap();
        let original = fs::read(&file).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        before::set_remote_id("127.0.0.1:24002");
        let old_published = LocalConfig::get_remote_id() == "127.0.0.1:24002";
        let old_file_preserved = fs::read(&file).unwrap() == original;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        before::set_remote_id("127.0.0.1:24002");
        let old_retry_skipped = fs::read(&file).unwrap() == original;
        println!("OPTION_COMMIT_LAST_PEER_BEFORE=observed published_without_commit={old_published} file_preserved={old_file_preserved} retry_skipped={old_retry_skipped}");
        assert!(old_published && old_file_preserved && old_retry_skipped);

        for requested in ["127.0.0.1:24002", ""] {
            before::set_remote_id("127.0.0.1:24001");
            let original = fs::read(&file).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let failed = LocalConfig::set_remote_id(requested).is_err();
            let memory_preserved = LocalConfig::get_remote_id() == "127.0.0.1:24001";
            let file_preserved = fs::read(&file).unwrap() == original;
            let unchanged_accepted = LocalConfig::set_remote_id("127.0.0.1:24001").is_ok();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            LocalConfig::set_remote_id(requested).unwrap();
            let stored: LocalConfig = load_path(file.clone());
            let retry_persisted = stored.remote_id == requested
                && LocalConfig::get_remote_id() == requested;
            let unrelated_preserved = stored.options.get("last-peer-test").map(String::as_str) == Some("preserved")
                && stored.fav == ["favorite-peer"];
            println!("OPTION_COMMIT_LAST_PEER_NATIVE=observed empty={} failure_reported={failed} memory_preserved={memory_preserved} file_preserved={file_preserved} unchanged_accepted={unchanged_accepted} retry_persisted={retry_persisted} unrelated_preserved={unrelated_preserved}", requested.is_empty());
            assert!(failed && memory_preserved && file_preserved && unchanged_accepted && retry_persisted && unrelated_preserved);
        }
    });
}

#[test]
fn retired_local_geometry_is_ignored_without_losing_live_preferences() {
    in_private_process("config::option_tests::retired_local_geometry_is_ignored_without_losing_live_preferences", |_| {
        let legacy = r#"
remote_id = "127.0.0.1:24001"
kb_layout_type = "iso"
size = [10, 20, 800, 600]
fav = ["favorite-peer"]
[options]
last-peer-test = "preserved"
[ui_flutter]
peer-view = "grid"
"#;
        let loaded: LocalConfig = toml::from_str(legacy).unwrap();
        let file = Config::file_("_local");
        store_path(file.clone(), &loaded).unwrap();
        *LOCAL_CONFIG.write().unwrap() = loaded;
        LocalConfig::set_remote_id("127.0.0.1:24002").unwrap();
        let stored: LocalConfig = load_path(file.clone());
        let serialized: toml::Value = toml::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
        let geometry_absent = serialized.get("size").is_none();
        let preferences_preserved = stored.kb_layout_type == "iso"
            && stored.fav == ["favorite-peer"]
            && stored.options.get("last-peer-test").map(String::as_str) == Some("preserved")
            && stored.ui_flutter.get("peer-view").map(String::as_str) == Some("grid");
        let history_persisted = stored.remote_id == "127.0.0.1:24002";
        println!("OPTION_COMMIT_LAST_PEER_LEGACY=observed retired_geometry_absent={geometry_absent} preferences_preserved={preferences_preserved} history_persisted={history_persisted}");
        assert!(geometry_absent && preferences_preserved && history_persisted);
    });
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
        LocalConfig::set_flutter_option("favorite-test".into(), "preserved".into()).unwrap();
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

#[test]
fn keyboard_layout_failure_preserves_mapping_and_allows_retry() {
    in_private_process("config::option_tests::keyboard_layout_failure_preserves_mapping_and_allows_retry", |_| {
        before::set_kb_layout_type("ISO".into());
        let file = Config::file_("_local");
        let parent = file.parent().unwrap();
        let original = fs::read(&file).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        before::set_kb_layout_type("Not ISO".into());
        let old_published = LocalConfig::get_kb_layout_type() == "Not ISO";
        let old_file_preserved = fs::read(&file).unwrap() == original;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        println!("OPTION_COMMIT_KEYBOARD_BEFORE=observed published_without_commit={old_published} file_preserved={old_file_preserved}");
        assert!(old_published && old_file_preserved);

        LocalConfig::set_kb_layout_type("ISO".into()).unwrap();
        LocalConfig::set_favorites(vec!["original".into()], true).unwrap();
        let original = fs::read(&file).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        let failed = LocalConfig::set_kb_layout_type("Not ISO".into()).is_err();
        let memory_preserved = LocalConfig::get_kb_layout_type() == "ISO";
        let file_preserved = fs::read(&file).unwrap() == original;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        LocalConfig::set_kb_layout_type("Not ISO".into()).unwrap();
        let stored: LocalConfig = load_path(file.clone());
        let retry_persisted = stored.kb_layout_type == "Not ISO"
            && LocalConfig::get_kb_layout_type() == stored.kb_layout_type;
        let unrelated_preserved = stored.fav == ["original"];
        let durable = fs::read(&file).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        LocalConfig::set_kb_layout_type("Not ISO".into()).unwrap();
        let idempotent = fs::read(&file).unwrap() == durable;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        println!("OPTION_COMMIT_KEYBOARD_NATIVE=observed failure_reported={failed} memory_preserved={memory_preserved} file_preserved={file_preserved} retry_persisted={retry_persisted} unrelated_preserved={unrelated_preserved} idempotent_without_write={idempotent}");
        assert!(failed && memory_preserved && file_preserved && retry_persisted && unrelated_preserved && idempotent);
    });
}

#[test]
fn flutter_option_failure_preserves_state_and_retries_without_crossing_namespaces() {
    in_private_process("config::option_tests::flutter_option_failure_preserves_state_and_retries_without_crossing_namespaces", |_| {
        let key = "flutter-option-commit-test";
        LocalConfig::set_option(key.into(), "general-preserved".into()).unwrap();
        LocalConfig::set_favorites(vec!["preserved".into()], true).unwrap();
        LocalConfig::set_kb_layout_type("ISO".into()).unwrap();
        before::set_flutter_option(key.into(), "ui-original".into());
        let file = Config::file_("_local");
        let parent = file.parent().unwrap();
        let original = fs::read(&file).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        before::set_flutter_option(key.into(), "ui-replacement".into());
        let published = LocalConfig::get_flutter_option(key) == "ui-replacement";
        let file_preserved = fs::read(&file).unwrap() == original;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        before::set_flutter_option(key.into(), "ui-replacement".into());
        let retry_skipped = fs::read(&file).unwrap() == original;
        println!("OPTION_COMMIT_UI_STATE_BEFORE=observed published_without_commit={published} file_preserved={file_preserved} retry_skipped={retry_skipped}");
        assert!(published && file_preserved && retry_skipped);

        for value in ["ui-replacement", ""] {
            LocalConfig::set_flutter_option(key.into(), "ui-original".into()).unwrap();
            let original = fs::read(&file).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let failed = LocalConfig::set_flutter_option(key.into(), value.into()).is_err();
            let memory_preserved = LocalConfig::get_flutter_option(key) == "ui-original";
            let file_preserved = fs::read(&file).unwrap() == original;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            LocalConfig::set_flutter_option(key.into(), value.into()).unwrap();
            let stored: LocalConfig = load_path(file.clone());
            let retry_persisted = stored.ui_flutter.get(key).map(String::as_str).unwrap_or("") == value
                && LocalConfig::get_flutter_option(key) == value;
            let unrelated_preserved = LocalConfig::get_option(key) == "general-preserved"
                && stored.options.get(key).map(String::as_str) == Some("general-preserved")
                && stored.fav == ["preserved"] && stored.kb_layout_type == "ISO";
            let durable = fs::read(&file).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            LocalConfig::set_flutter_option(key.into(), value.into()).unwrap();
            let idempotent = fs::read(&file).unwrap() == durable;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            println!("OPTION_COMMIT_UI_STATE_NATIVE=observed removal={} failure_reported={failed} memory_preserved={memory_preserved} file_preserved={file_preserved} retry_persisted={retry_persisted} unrelated_preserved={unrelated_preserved} idempotent_without_write={idempotent}", value.is_empty());
            assert!(failed && memory_preserved && file_preserved && retry_persisted && unrelated_preserved && idempotent);
        }
    });
}

#[test]
fn local_option_failure_preserves_state_and_retries_replacement_and_removal() {
    in_private_process("config::option_tests::local_option_failure_preserves_state_and_retries_replacement_and_removal", |_| {
        let key = "local-option-commit-test";
        before::set_option(key.into(), "original".into());
        let file = Config::file_("_local");
        let parent = file.parent().unwrap();
        let original = fs::read(&file).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        before::set_option(key.into(), "replacement".into());
        let published = LocalConfig::get_option(key) == "replacement";
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        before::set_option(key.into(), "replacement".into());
        let retry_skipped = fs::read(&file).unwrap() == original;
        println!("OPTION_COMMIT_LOCAL_BEFORE=observed published_without_commit={published} retry_skipped={retry_skipped}");
        assert!(published && retry_skipped);
        LocalConfig::set_favorites(vec!["preserved".into()], true).unwrap();
        for value in ["replacement", ""] {
            LocalConfig::set_option(key.into(), "original".into()).unwrap();
            let original = fs::read(&file).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let failed = LocalConfig::set_option(key.into(), value.into()).is_err();
            let memory = LocalConfig::get_option(key) == "original";
            let durable = fs::read(&file).unwrap() == original;
            LocalConfig::set_option(key.into(), "original".into()).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            LocalConfig::set_option(key.into(), value.into()).unwrap();
            let stored: LocalConfig = load_path(file.clone());
            let retry = stored.options.get(key).map(String::as_str).unwrap_or("") == value
                && LocalConfig::get_option(key) == value;
            let unrelated = stored.fav == ["preserved"];
            println!("OPTION_COMMIT_LOCAL_NATIVE=observed removal={} failure_reported={failed} memory_preserved={memory} file_preserved={durable} retry_persisted={retry} unrelated_preserved={unrelated}", value.is_empty());
            assert!(failed && memory && durable && retry && unrelated);
        }
    });
}

#[test]
fn local_option_purge_failure_preserves_overrides_and_defaults() {
    in_private_process("config::option_tests::local_option_purge_failure_preserves_overrides_and_defaults", |_| {
        for overwritten in [true, false] {
            let key = if overwritten { "local-override-test" } else { "local-default-test" };
            if overwritten {
                OVERWRITE_LOCAL_SETTINGS.write().unwrap().insert(key.into(), "fixed".into());
            } else {
                DEFAULT_LOCAL_SETTINGS.write().unwrap().insert(key.into(), "fixed".into());
            }
            LOCAL_CONFIG.write().unwrap().options.insert(key.into(), "stale".into());
            let file = Config::file_("_local");
            store_path(file.clone(), &*LOCAL_CONFIG.read().unwrap()).unwrap();
            let original = fs::read(&file).unwrap();
            let parent = file.parent().unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let failed = LocalConfig::set_option(key.into(), "fixed".into()).is_err();
            let memory = LOCAL_CONFIG.read().unwrap().options.get(key).map(String::as_str) == Some("stale");
            let durable = fs::read(&file).unwrap() == original;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            LocalConfig::set_option(key.into(), "fixed".into()).unwrap();
            let stored: LocalConfig = load_path(file.clone());
            let purged = !stored.options.contains_key(key) && LocalConfig::get_option(key) == "fixed";
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            LocalConfig::set_option(key.into(), "fixed".into()).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            println!("OPTION_COMMIT_LOCAL_PURGE=observed overwritten={overwritten} failure_reported={failed} memory_preserved={memory} file_preserved={durable} retry_purged={purged} idempotent_without_write=true");
            assert!(failed && memory && durable && purged);
        }
    });
}

#[test]
fn local_system_language_is_explicit_durable_and_retryable() {
    in_private_process("config::option_tests::local_system_language_is_explicit_durable_and_retryable", |_| {
        DEFAULT_LOCAL_SETTINGS.write().unwrap().insert(keys::OPTION_LANGUAGE.into(), "de".into());
        LocalConfig::set_option(keys::OPTION_LANGUAGE.into(), "fr".into()).unwrap();
        let file = Config::file_("_local");
        let parent = file.parent().unwrap();
        let original = fs::read(&file).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        let failed = LocalConfig::set_option(keys::OPTION_LANGUAGE.into(), "default".into()).is_err();
        let memory = LocalConfig::get_option(keys::OPTION_LANGUAGE) == "fr";
        let durable = fs::read(&file).unwrap() == original;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        LocalConfig::set_option(keys::OPTION_LANGUAGE.into(), "default".into()).unwrap();
        let stored: LocalConfig = load_path(file.clone());
        let explicit = stored.options.get(keys::OPTION_LANGUAGE).map(String::as_str) == Some("")
            && LocalConfig::get_option(keys::OPTION_LANGUAGE).is_empty();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        LocalConfig::set_option(keys::OPTION_LANGUAGE.into(), "default".into()).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        LocalConfig::set_option(keys::OPTION_LANGUAGE.into(), "".into()).unwrap();
        let stored: LocalConfig = load_path(file);
        let default_restored = !stored.options.contains_key(keys::OPTION_LANGUAGE)
            && LocalConfig::get_option(keys::OPTION_LANGUAGE) == "de";
        println!("OPTION_COMMIT_LOCAL_LANGUAGE=observed failure_reported={failed} memory_preserved={memory} file_preserved={durable} retry_explicit={explicit} default_restored={default_restored} idempotent_without_write=true");
        assert!(failed && memory && durable && explicit && default_restored);
    });
}
