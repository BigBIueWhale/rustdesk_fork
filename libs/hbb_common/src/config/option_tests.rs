use super::*;
use std::os::unix::fs::PermissionsExt;

mod before {
    use super::*;

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
