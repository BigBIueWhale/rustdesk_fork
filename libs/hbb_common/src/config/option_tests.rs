use super::*;
use std::os::unix::fs::PermissionsExt;

#[path = "../../../../scripts/fixtures/default-options-before-transaction.rs"]
mod before_defaults;

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

fn insert_retired_peer_password(id: &str) {
    let path = PeerConfig::path(id);
    let source = fs::read_to_string(&path).unwrap();
    let document: toml::Value = toml::from_str(&source).unwrap();
    let source = if let Some(value) = document.get("password") {
        assert_eq!(value, &toml::Value::Array(vec![]));
        let mut removed = 0;
        let lines: Vec<_> = source.lines().filter(|line| {
            if *line == "password = []" { removed += 1; false } else { true }
        }).collect();
        assert_eq!(removed, 1);
        lines.join("\n")
    } else {
        source
    };
    let value = b"fixture-retired-peer-hash".iter().map(u8::to_string).collect::<Vec<_>>().join(", ");
    fs::write(path, format!("password = [{value}]\n{source}\n")).unwrap();
}

#[test]
fn peer_port_forward_write_failure_reports_error_and_retries_add_remove() {
    in_private_process("config::option_tests::peer_port_forward_write_failure_reports_error_and_retries_add_remove", |_| {
        let id = "peer-port-forward-write";
        let mapping = (8000, "localhost".into(), 80);
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-port-forward-prs".to_vec();
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        for removing in [false, true] {
            let original = fs::read(&path).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let result = if removing {
                PeerConfig::remove_port_forward(id, mapping.0).map(|_| ())
            } else {
                PeerConfig::add_port_forward(id, &mapping).map(|_| ())
            };
            let preserved = fs::read(&path).unwrap() == original;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            println!("OPTION_COMMIT_PEER_PORT_FORWARD=observed kind=write removing={removing} reported={} file_preserved={preserved}", result.is_err());
            assert!(result.is_err() && preserved);
            if removing {
                assert!(PeerConfig::remove_port_forward(id, mapping.0).unwrap().is_empty());
            } else {
                assert_eq!(PeerConfig::add_port_forward(id, &mapping).unwrap(), (vec![mapping.clone()], true));
            }
            let stored = PeerConfig::load_for_write(id).unwrap();
            assert_eq!(stored.port_forwards.is_empty(), removing);
            assert_eq!(stored.password_prs, peer.password_prs);
            assert_eq!(stored.options, peer.options);
        }
    });
}

#[test]
fn peer_port_forward_unreadable_source_refuses_add_remove() {
    in_private_process("config::option_tests::peer_port_forward_unreadable_source_refuses_add_remove", |_| {
        let id = "peer-port-forward-read";
        let mapping = (8000, "localhost".into(), 80);
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-port-forward-prs".to_vec();
        peer.port_forwards.push(mapping.clone());
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        for removing in [false, true] {
            let original = fs::read(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
            let native = fs::read(&path).unwrap_err();
            let result = if removing {
                PeerConfig::remove_port_forward(id, mapping.0).map(|_| ())
            } else {
                PeerConfig::add_port_forward(id, &(9000, "other".into(), 443)).map(|_| ())
            };
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let preserved = fs::read(&path).unwrap() == original;
            println!("OPTION_COMMIT_PEER_PORT_FORWARD=observed kind=read removing={removing} errno={} reported={} file_preserved={preserved}", native.raw_os_error().unwrap(), result.is_err());
            assert_eq!(native.kind(), std::io::ErrorKind::PermissionDenied);
            assert!(result.is_err() && preserved);
        }
        assert_eq!(PeerConfig::load_for_write(id).unwrap(), peer);
    });
}

#[test]
fn peer_port_forward_edits_preserve_other_fields_siblings_and_capacity() {
    in_private_process("config::option_tests::peer_port_forward_edits_preserve_other_fields_siblings_and_capacity", |_| {
        let id = "peer-port-forward-fields";
        let sibling = "peer-port-forward-sibling";
        let mut expected = PeerConfig::default();
        expected.password_prs = b"fixture-port-forward-prs".to_vec();
        expected.info.hostname = "preserved-host".into();
        expected.options.insert("alias".into(), "preserved".into());
        expected.ui_flutter.insert("canvas".into(), "preserved".into());
        expected.transfer.read_jobs.push("preserved-job".into());
        expected.store(id).unwrap();
        expected.store(sibling).unwrap();
        let sibling_bytes = fs::read(PeerConfig::path(sibling)).unwrap();
        for i in 0..MAX_OWNED_PORT_FORWARD_MAPPINGS as i32 {
            let mapping = (8000 + i, "localhost".into(), 80 + i);
            let (saved, added) = PeerConfig::add_port_forward(id, &mapping).unwrap();
            expected.port_forwards.push(mapping);
            assert!(added);
            assert_eq!(saved, expected.port_forwards);
            assert_eq!(PeerConfig::load_for_write(id).unwrap(), expected);
        }
        let path = PeerConfig::path(id);
        let full = fs::read(&path).unwrap();
        let duplicate = PeerConfig::add_port_forward(id, &(8000, "different".into(), 443)).unwrap();
        assert_eq!(duplicate, (expected.port_forwards.clone(), false));
        assert!(PeerConfig::add_port_forward(id, &(9000, "localhost".into(), 80)).is_err());
        assert_eq!(fs::read(&path).unwrap(), full);
        expected.port_forwards.retain(|entry| entry.0 != 8000);
        assert_eq!(PeerConfig::remove_port_forward(id, 8000).unwrap(), expected.port_forwards);
        assert_eq!(PeerConfig::load_for_write(id).unwrap(), expected);
        assert!(PeerConfig::add_port_forward(id, &(9000, "localhost".into(), 80)).unwrap().1);
        assert_eq!(fs::read(PeerConfig::path(sibling)).unwrap(), sibling_bytes);
    });
}

#[test]
fn peer_port_forward_idempotent_edits_avoid_writes() {
    in_private_process("config::option_tests::peer_port_forward_idempotent_edits_avoid_writes", |_| {
        use std::os::unix::fs::MetadataExt;
        let id = "peer-port-forward-unchanged";
        let mapping = (8000, "localhost".into(), 80);
        PeerConfig::add_port_forward(id, &mapping).unwrap();
        let path = PeerConfig::path(id);
        let before = fs::metadata(&path).unwrap();
        let original = fs::read(&path).unwrap();
        assert!(!PeerConfig::add_port_forward(id, &mapping).unwrap().1);
        assert_eq!(PeerConfig::remove_port_forward(id, 9000).unwrap(), vec![mapping]);
        let after = fs::metadata(&path).unwrap();
        let unchanged = (before.dev(), before.ino()) == (after.dev(), after.ino());
        println!("OPTION_COMMIT_PEER_PORT_FORWARD=observed kind=idempotent unchanged_inode={unchanged}");
        assert!(unchanged);
        assert_eq!(fs::read(path).unwrap(), original);
    });
}

#[test]
fn peer_port_forward_missing_removal_does_not_create_record() {
    in_private_process("config::option_tests::peer_port_forward_missing_removal_does_not_create_record", |_| {
        let id = "peer-port-forward-missing";
        assert!(PeerConfig::remove_port_forward(id, 8000).unwrap().is_empty());
        let absent = !PeerConfig::path(id).exists();
        println!("OPTION_COMMIT_PEER_PORT_FORWARD=observed kind=missing absent={absent}");
        assert!(absent);
    });
}

#[test]
fn peer_ui_info_does_not_load_controlled_credentials() {
    in_private_process("config::option_tests::peer_ui_info_does_not_load_controlled_credentials", |_| {
        let global_path = Config::file_("");
        fs::create_dir_all(global_path.parent().unwrap()).unwrap();
        let source = b"password = [private-display-source\n";
        fs::write(&global_path, source).unwrap();
        let info: serde_json::Value = serde_json::from_str(&PeerConfig::ui_info_json("peer-ui-no-global-load").unwrap()).unwrap();
        let preserved = fs::read(&global_path).map(|bytes| bytes == source).unwrap_or(false);
        println!("OPTION_COMMIT_PEER_UI_READONLY=observed kind=global_config file_preserved={preserved}");
        assert!(preserved);
        assert_eq!(info, serde_json::json!({"info": {"hostname": ""}, "port_forwards": []}));
    });
}

#[test]
fn peer_ui_info_corrupt_record_stays_in_place() {
    in_private_process("config::option_tests::peer_ui_info_corrupt_record_stays_in_place", |_| {
        let source = b"password_prs = [private-display-source\n";
        assert!(toml::from_str::<toml::Value>(std::str::from_utf8(source).unwrap()).is_err());
        assert_display_read_refusal_preserves_file("peer-ui-corrupt", source, "syntax");
    });
}

#[test]
fn peer_ui_info_wrong_display_shape_stays_in_place() {
    in_private_process("config::option_tests::peer_ui_info_wrong_display_shape_stays_in_place", |_| {
        let source = b"password_prs = [1, 2, 3]\ninfo = 42\n";
        assert!(toml::from_str::<toml::Value>(std::str::from_utf8(source).unwrap()).is_ok());
        assert!(toml::from_str::<PeerUiInfo>(std::str::from_utf8(source).unwrap()).is_err());
        assert_display_read_refusal_preserves_file("peer-ui-wrong-shape", source, "shape");
    });
}

#[test]
fn peer_ui_info_invalid_utf8_and_directory_refuse_without_mutation() {
    in_private_process("config::option_tests::peer_ui_info_invalid_utf8_and_directory_refuse_without_mutation", |_| {
        let id = "peer-ui-invalid-input";
        assert_display_read_refusal_preserves_file(id, b"\xffprivate-display-source", "utf8");
        let path = PeerConfig::path(id);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let child = path.join("preserved");
        fs::write(&child, b"private-display-source").unwrap();
        assert!(PeerConfig::ui_info_json(id).is_err());
        let preserved = path.is_dir() && fs::read(child).unwrap() == b"private-display-source";
        println!("OPTION_COMMIT_PEER_UI_READONLY=observed kind=directory children_preserved={preserved}");
        assert!(preserved);
    });
}

fn assert_display_read_refusal_preserves_file(id: &str, source: &[u8], kind: &str) {
    use std::os::unix::fs::MetadataExt;
    let path = PeerConfig::path(id);
    let parent = path.parent().unwrap();
    fs::create_dir_all(parent).unwrap();
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&path, source).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let before = fs::metadata(&path).unwrap();
    let names = || {
        let mut names = fs::read_dir(parent).unwrap().map(|entry| entry.unwrap().file_name()).collect::<Vec<_>>();
        names.sort();
        names
    };
    let original_names = names();
    let error = PeerConfig::ui_info_json(id).unwrap_err();
    let preserved = fs::read(&path).map(|bytes| bytes == source).unwrap_or(false);
    let same_file = fs::metadata(&path).map(|after| (before.dev(), before.ino()) == (after.dev(), after.ino())).unwrap_or(false);
    let directory_unchanged = names() == original_names;
    println!("OPTION_COMMIT_PEER_UI_READONLY=observed kind={kind} file_preserved={preserved} same_file={same_file} directory_unchanged={directory_unchanged}");
    assert!(!format!("{error:?}").contains("private-display-source"));
    assert!(preserved && same_file && directory_unchanged);
}

#[test]
fn peer_ui_info_excludes_credentials_and_unrelated_state() {
    in_private_process("config::option_tests::peer_ui_info_excludes_credentials_and_unrelated_state", |_| {
        let id = "peer-ui-fields";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-private-ui-prs".to_vec();
        peer.info.hostname = "public-host".into();
        peer.info.username = "private-username".into();
        peer.info.platform = "Linux".into();
        peer.port_forwards = vec![(8000, "destination".into(), 80), (9000, "other".into(), 443)];
        peer.options.insert("private-option".into(), "private-value".into());
        peer.ui_flutter.insert("canvas".into(), "private-canvas".into());
        peer.transfer.read_jobs.push("private-transfer".into());
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let original = fs::read(&path).unwrap();
        let info: serde_json::Value = serde_json::from_str(&PeerConfig::ui_info_json(id).unwrap()).unwrap();
        let fields = info.as_object().unwrap();
        let exposed = fields.contains_key("password_prs");
        println!("OPTION_COMMIT_PEER_UI=observed kind=fields credential_returned={exposed} fields={}", fields.len());
        assert!(!exposed && fields.len() == 2);
        assert_eq!(info["info"], serde_json::json!({"hostname": "public-host"}));
        assert_eq!(info["port_forwards"], serde_json::json!([[8000, "destination", 80], [9000, "other", 443]]));
        assert_eq!(fs::read(path).unwrap(), original);
    });
}

#[test]
fn peer_ui_info_read_denial_reports_error_and_preserves_the_record() {
    in_private_process("config::option_tests::peer_ui_info_read_denial_reports_error_and_preserves_the_record", |_| {
        let id = "peer-ui-read";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-private-ui-prs".to_vec();
        peer.info.hostname = "public-host".into();
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let original = fs::read(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        let native = fs::read(&path).unwrap_err();
        let result = PeerConfig::ui_info_json(id);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let preserved = fs::read(&path).unwrap() == original;
        println!("OPTION_COMMIT_PEER_UI=observed kind=read errno={} reported={} file_preserved={preserved}", native.raw_os_error().unwrap(), result.is_err());
        assert_eq!(native.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(result.is_err() && preserved);
        let info: serde_json::Value = serde_json::from_str(&PeerConfig::ui_info_json(id).unwrap()).unwrap();
        assert_eq!(info["info"]["hostname"], "public-host");
    });
}

#[test]
fn peer_ui_info_does_not_migrate_credentials_for_a_display_read() {
    in_private_process("config::option_tests::peer_ui_info_does_not_migrate_credentials_for_a_display_read", |_| {
        let id = "peer-ui-no-credential-work";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-unwrapped-ui-prs".to_vec();
        peer.info.hostname = "public-host".into();
        peer.port_forwards = vec![(8000, "destination".into(), 80)];
        let path = PeerConfig::path(id);
        store_path(path.clone(), &peer).unwrap();
        let original = fs::read(&path).unwrap();
        let info: serde_json::Value = serde_json::from_str(&PeerConfig::ui_info_json(id).unwrap()).unwrap();
        let untouched = fs::read(&path).unwrap() == original;
        println!("OPTION_COMMIT_PEER_UI=observed kind=credential_work file_unchanged={untouched}");
        assert!(untouched);
        assert_eq!(info["info"]["hostname"], "public-host");
        assert_eq!(info["port_forwards"], serde_json::json!([[8000, "destination", 80]]));
        assert_eq!(PeerConfig::load_for_write(id).unwrap().password_prs, peer.password_prs);
        assert_ne!(fs::read(path).unwrap(), original);
    });
}

#[test]
fn peer_ui_info_missing_record_has_empty_display_fields_without_creation() {
    in_private_process("config::option_tests::peer_ui_info_missing_record_has_empty_display_fields_without_creation", |_| {
        let id = "peer-ui-missing";
        let path = PeerConfig::path(id);
        assert!(!path.exists());
        let info: serde_json::Value = serde_json::from_str(&PeerConfig::ui_info_json(id).unwrap()).unwrap();
        assert_eq!(info["info"]["hostname"], "");
        assert_eq!(info["port_forwards"], serde_json::json!([]));
        assert!(!path.exists());
    });
}

#[test]
fn peer_retired_password_read_does_not_rewrite_or_publish_the_value() {
    in_private_process("config::option_tests::peer_retired_password_read_does_not_rewrite_or_publish_the_value", |_| {
        let id = "peer-retired-read";
        let mut peer = PeerConfig::default();
        peer.info.platform = "Linux".into();
        peer.options.insert("alias".into(), "preserved".into());
        peer.store(id).unwrap();
        insert_retired_peer_password(id);
        let path = PeerConfig::path(id);
        let original = fs::read(&path).unwrap();
        let loaded = PeerConfig::load_for_write(id).unwrap();
        let public = serde_json::to_value(&loaded).unwrap();
        let untouched = fs::read(&path).unwrap() == original;
        let excluded = public.get("password").is_none();
        println!("OPTION_COMMIT_PEER_RETIRED=observed kind=read file_unchanged={untouched} value_excluded={excluded}");
        assert!(untouched && excluded);
        assert!(loaded.password_prs.is_empty());
        assert_eq!(loaded.info.platform, "Linux");
        assert_eq!(loaded.options.get("alias").map(String::as_str), Some("preserved"));
    });
}

#[test]
fn peer_retired_password_normal_save_omits_the_field_and_preserves_prs() {
    in_private_process("config::option_tests::peer_retired_password_normal_save_omits_the_field_and_preserves_prs", |_| {
        let id = "peer-retired-save";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-current-peer-prs".to_vec();
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.store(id).unwrap();
        insert_retired_peer_password(id);
        assert_eq!(PeerConfig::load_for_write(id).unwrap().password_prs, peer.password_prs);
        PeerConfig::set_option(id, "alias", "selected".into()).unwrap();
        let document: toml::Value = toml::from_str(&fs::read_to_string(PeerConfig::path(id)).unwrap()).unwrap();
        let excluded = document.get("password").is_none();
        println!("OPTION_COMMIT_PEER_RETIRED=observed kind=save field_omitted={excluded}");
        assert!(excluded);
        let loaded = PeerConfig::load_for_write(id).unwrap();
        assert_eq!(loaded.password_prs, b"fixture-current-peer-prs");
        assert_eq!(loaded.options.get("unrelated").map(String::as_str), Some("preserved"));
        assert_eq!(loaded.options.get("alias").map(String::as_str), Some("selected"));
    });
}

#[test]
fn peer_retired_password_forget_purges_old_only_files_and_retries_failure() {
    in_private_process("config::option_tests::peer_retired_password_forget_purges_old_only_files_and_retries_failure", |_| {
        let id = "peer-retired-forget";
        let mut peer = PeerConfig::default();
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.store(id).unwrap();
        insert_retired_peer_password(id);
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        let original = fs::read(&path).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        let failed = PeerConfig::forget_password(id).is_err();
        let preserved = fs::read(&path).unwrap() == original;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(failed && preserved);
        PeerConfig::forget_password(id).unwrap();
        let document: toml::Value = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let excluded = document.get("password").is_none();
        println!("OPTION_COMMIT_PEER_RETIRED=observed kind=forget failure_reported={failed} failed_file_preserved={preserved} field_omitted={excluded}");
        assert!(excluded);
        let loaded = PeerConfig::load_for_write(id).unwrap();
        assert!(loaded.password_prs.is_empty());
        assert_eq!(loaded.options.get("unrelated").map(String::as_str), Some("preserved"));
        let bytes = fs::read(&path).unwrap();
        let before = std::os::unix::fs::MetadataExt::ino(&fs::metadata(&path).unwrap());
        PeerConfig::forget_password(id).unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(std::os::unix::fs::MetadataExt::ino(&fs::metadata(path).unwrap()), before);
    });
}

#[test]
fn peer_credential_status_read_does_not_migrate_the_record() {
    in_private_process("config::option_tests::peer_credential_status_read_does_not_migrate_the_record", |_| {
        let id = "peer-credential-status-readonly";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-status-unwrapped-prs".to_vec();
        let path = PeerConfig::path(id);
        store_path(path.clone(), &peer).unwrap();
        let original = fs::read(&path).unwrap();
        let status = PeerConfig::credential_status(id).unwrap();
        let preserved = fs::read(&path).unwrap() == original;
        println!("OPTION_COMMIT_PEER_CREDENTIAL_STATUS=observed kind=migration file_preserved={preserved}");
        assert!(preserved && status.has_saved_prs && status.can_forget);
        assert_eq!(serde_json::to_value(status).unwrap(), serde_json::json!({"has_saved_prs": true, "can_forget": true}));
        assert_eq!(PeerConfig::load_for_write(id).unwrap().password_prs, peer.password_prs);
        assert_ne!(fs::read(path).unwrap(), original);
    });
}

#[test]
fn peer_credential_status_corruption_refuses_without_recovery() {
    in_private_process("config::option_tests::peer_credential_status_corruption_refuses_without_recovery", |_| {
        use std::os::unix::fs::MetadataExt;
        let id = "peer-credential-status-corrupt";
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        for source in [b"password_prs = [private-status-source\n".as_slice(), b"\xff\n".as_slice()] {
            fs::write(&path, source).unwrap();
            let before = fs::metadata(&path).unwrap();
            let names = || {
                let mut names = fs::read_dir(parent).unwrap().map(|entry| entry.unwrap().file_name()).collect::<Vec<_>>();
                names.sort();
                names
            };
            let original_names = names();
            let status = PeerConfig::credential_status(id);
            let preserved = fs::read(&path).map(|bytes| bytes == source).unwrap_or(false);
            let same_file = fs::metadata(&path).map(|after| (before.dev(), before.ino()) == (after.dev(), after.ino())).unwrap_or(false);
            let directory_unchanged = names() == original_names;
            println!("OPTION_COMMIT_PEER_CREDENTIAL_STATUS=observed kind=corrupt error_reported={} file_preserved={preserved} same_file={same_file} directory_unchanged={directory_unchanged}", status.is_err());
            assert!(status.is_err() && preserved && same_file && directory_unchanged);
            let error = status.unwrap_err().to_string();
            assert!(!error.contains("private-status-source"));
        }
    });
}

#[test]
fn peer_credential_status_read_denial_is_reported_and_retryable() {
    in_private_process("config::option_tests::peer_credential_status_read_denial_is_reported_and_retryable", |_| {
        let id = "peer-credential-status-denied";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-status-prs".to_vec();
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let original = fs::read(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(fs::read(&path).unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        let status = PeerConfig::credential_status(id);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let preserved = fs::read(&path).unwrap() == original;
        println!("OPTION_COMMIT_PEER_CREDENTIAL_STATUS=observed kind=read_denial error_reported={} file_preserved={preserved}", status.is_err());
        assert!(status.is_err() && preserved);
        assert_eq!(PeerConfig::credential_status(id).unwrap(), PeerCredentialStatus { has_saved_prs: true, can_forget: true });
    });
}

#[test]
fn peer_credential_status_does_not_initialize_controlled_config() {
    in_private_process("config::option_tests::peer_credential_status_does_not_initialize_controlled_config", |_| {
        let id = "peer-credential-status-no-global";
        let path = PeerConfig::path(id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let peer = b"password_prs = []\n";
        fs::write(&path, peer).unwrap();
        let global_path = Config::file_("");
        let global = b"password = [private-status-source\n";
        fs::write(&global_path, global).unwrap();
        let status = PeerConfig::credential_status(id).unwrap();
        let preserved = fs::read(global_path).map(|bytes| bytes == global).unwrap_or(false);
        println!("OPTION_COMMIT_PEER_CREDENTIAL_STATUS=observed kind=global_config file_preserved={preserved}");
        assert!(preserved && status == PeerCredentialStatus::default());
        assert_eq!(fs::read(path).unwrap(), peer);
    });
}

#[test]
fn peer_credential_status_distinguishes_saved_prs_and_retired_data() {
    in_private_process("config::option_tests::peer_credential_status_distinguishes_saved_prs_and_retired_data", |_| {
        let id = "peer-credential-status-presence";
        assert_eq!(PeerConfig::credential_status(id).unwrap(), PeerCredentialStatus::default());
        assert!(!PeerConfig::path(id).exists());
        for has_prs in [false, true] {
            for retired in ["", "password = 'private-status-source'\n", "password = [111,108,100]\n", "password = {unexpected = 'private-status-source'}\n"] {
                let mut peer = PeerConfig::default();
                if has_prs { peer.password_prs = b"fixture-status-presence-prs".to_vec(); }
                peer.store(id).unwrap();
                let path = PeerConfig::path(id);
                let mut original = retired.as_bytes().to_vec();
                original.extend(fs::read(&path).unwrap());
                fs::write(&path, &original).unwrap();
                let status = PeerConfig::credential_status(id).unwrap();
                println!("OPTION_COMMIT_PEER_CREDENTIAL_STATUS=observed kind=presence prs={has_prs} retired={} can_forget={}", !retired.is_empty(), status.can_forget);
                assert_eq!(status, PeerCredentialStatus { has_saved_prs: has_prs, can_forget: has_prs || !retired.is_empty() });
                assert_eq!(fs::read(&path).unwrap(), original);
                PeerConfig::forget_password(id).unwrap();
                assert_eq!(PeerConfig::credential_status(id).unwrap(), PeerCredentialStatus::default());
            }
        }
    });
}

#[test]
fn peer_credential_status_rejects_malformed_prs_shape() {
    in_private_process("config::option_tests::peer_credential_status_rejects_malformed_prs_shape", |_| {
        let id = "peer-credential-status-shape";
        let path = PeerConfig::path(id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        for source in ["password_prs = 42\n", "password_prs = 'private-status-source'\n", "password_prs = ['private-status-source']\n"] {
            fs::write(&path, source).unwrap();
            let status = PeerConfig::credential_status(id);
            println!("OPTION_COMMIT_PEER_CREDENTIAL_STATUS=observed kind=prs_shape error_reported={} file_preserved={}", status.is_err(), fs::read(&path).unwrap() == source.as_bytes());
            assert!(status.is_err());
            assert!(!status.unwrap_err().to_string().contains("private-status-source"));
            assert_eq!(fs::read(&path).unwrap(), source.as_bytes());
        }
    });
}

#[test]
fn peer_listing_does_not_migrate_credentials() {
    in_private_process("config::option_tests::peer_listing_does_not_migrate_credentials", |_| {
        let id = "peer-listing-no-migration";
        let mut peer = PeerConfig::default();
        peer.info.platform = "Linux".into();
        peer.info.hostname = "visible-host".into();
        peer.options.insert("alias".into(), "visible-alias".into());
        peer.password_prs = b"fixture-unwrapped-list-prs".to_vec();
        let path = PeerConfig::path(id);
        store_path(path.clone(), &peer).unwrap();
        let original = fs::read(&path).unwrap();
        let (peers, next) = PeerConfig::batch_peers(&vec![(id.into(), SystemTime::UNIX_EPOCH, path.clone())], 0, None);
        let preserved = fs::read(&path).unwrap() == original;
        println!("OPTION_COMMIT_PEER_LIST_VIEW=observed kind=credential_work file_preserved={preserved}");
        assert!(preserved && peers.len() == 1 && next == 1);
        assert_eq!(peers[0].2.info, peer.info);
        assert_eq!(peers[0].2.alias, "visible-alias");
        assert_eq!(PeerConfig::load_for_write(id).unwrap().password_prs, peer.password_prs);
        assert_ne!(fs::read(path).unwrap(), original);
    });
}

#[test]
fn peer_listing_corrupt_records_stay_in_place() {
    in_private_process("config::option_tests::peer_listing_corrupt_records_stay_in_place", |_| {
        use std::os::unix::fs::MetadataExt;
        let id = "peer-listing-corrupt";
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        for source in [b"password_prs = [private-list-source\n".as_slice(), b"info = 42\n".as_slice()] {
            fs::write(&path, source).unwrap();
            let before = fs::metadata(&path).unwrap();
            let names = || {
                let mut names = fs::read_dir(parent).unwrap().map(|entry| entry.unwrap().file_name()).collect::<Vec<_>>();
                names.sort();
                names
            };
            let original_names = names();
            let (peers, next) = PeerConfig::batch_peers(&vec![(id.into(), SystemTime::UNIX_EPOCH, path.clone())], 0, None);
            let preserved = fs::read(&path).map(|bytes| bytes == source).unwrap_or(false);
            let same_file = fs::metadata(&path).map(|after| (before.dev(), before.ino()) == (after.dev(), after.ino())).unwrap_or(false);
            let directory_unchanged = names() == original_names;
            println!("OPTION_COMMIT_PEER_LIST_VIEW=observed kind=corrupt file_preserved={preserved} same_file={same_file} directory_unchanged={directory_unchanged}");
            assert!(peers.is_empty() && next == 1 && preserved && same_file && directory_unchanged);
        }
    });
}

#[test]
fn peer_listing_does_not_load_controlled_credentials() {
    in_private_process("config::option_tests::peer_listing_does_not_load_controlled_credentials", |_| {
        let id = "peer-listing-no-global";
        let path = PeerConfig::path(id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let peer = b"[info]\nusername = 'user'\nhostname = 'host'\nplatform = 'Linux'\n[options]\nalias = 'alias'\n";
        fs::write(&path, peer).unwrap();
        let global_path = Config::file_("");
        let global = b"password = [private-list-source\n";
        fs::write(&global_path, global).unwrap();
        let (peers, next) = PeerConfig::batch_peers(&vec![(id.into(), SystemTime::UNIX_EPOCH, path.clone())], 0, None);
        let preserved = fs::read(global_path).map(|bytes| bytes == global).unwrap_or(false);
        println!("OPTION_COMMIT_PEER_LIST_VIEW=observed kind=global_config file_preserved={preserved}");
        assert!(preserved && peers.len() == 1 && next == 1);
        assert_eq!(peers[0].2.alias, "alias");
        assert_eq!(fs::read(path).unwrap(), peer);
    });
}

#[test]
fn peer_listing_returns_only_metadata_and_alias() {
    in_private_process("config::option_tests::peer_listing_returns_only_metadata_and_alias", |_| {
        let id = "peer-listing-closed-view";
        let mut peer = PeerConfig::default();
        peer.info = PeerInfoSerde { username: "user".into(), hostname: "host".into(), platform: "Linux".into() };
        peer.options.insert("alias".into(), "alias".into());
        peer.options.insert("private".into(), "private-list-source".into());
        peer.password_prs = b"fixture-private-list-prs".to_vec();
        peer.ui_flutter.insert("canvas".into(), "private-list-source".into());
        peer.transfer.read_jobs.push("private-list-source".into());
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let original = fs::read(&path).unwrap();
        let (peers, next) = PeerConfig::batch_peers(&vec![(id.into(), SystemTime::UNIX_EPOCH, path.clone())], 0, None);
        assert_eq!(next, 1);
        assert_eq!(peers.len(), 1);
        let info = serde_json::to_value(&peers[0].2).unwrap();
        assert_eq!(info, serde_json::json!({"info": {"username": "user", "hostname": "host", "platform": "Linux"}, "alias": "alias"}));
        assert_eq!(fs::read(path).unwrap(), original);
    });
}

#[test]
fn peer_listing_omits_empty_records_without_deleting_them() {
    in_private_process("config::option_tests::peer_listing_omits_empty_records_without_deleting_them", |_| {
        let id = "peer-listing-empty";
        PeerConfig::default().store(id).unwrap();
        let path = PeerConfig::path(id);
        let original = fs::read(&path).unwrap();
        let all = vec![(id.into(), SystemTime::UNIX_EPOCH, path.clone())];
        let (peers, next) = PeerConfig::batch_peers(&all, 0, None);
        let preserved = fs::read(&path).ok().as_deref() == Some(original.as_slice());
        println!("OPTION_COMMIT_PEER_LISTING=observed kind=empty omitted={} next={next} file_preserved={preserved}", peers.is_empty());
        assert!(peers.is_empty() && next == 1 && preserved);
    });
}

#[test]
fn peer_listing_empty_snapshot_cannot_delete_a_replacement_record() {
    in_private_process("config::option_tests::peer_listing_empty_snapshot_cannot_delete_a_replacement_record", |_| {
        let id = "peer-listing-replacement";
        PeerConfig::default().store(id).unwrap();
        let path = PeerConfig::path(id);
        let all = vec![(id.into(), SystemTime::UNIX_EPOCH, path.clone())];
        let mut replacement = PeerConfig::default();
        replacement.password_prs = b"fixture-replacement-prs".to_vec();
        replacement.info.platform = "Linux".into();
        replacement.options.insert("alias".into(), "replacement".into());
        let mut written = Vec::new();
        let mut reads = 0;
        let (peers, next) = PeerConfig::batch_peers_with_loader(&all, 0, None, |actual| {
            assert_eq!(actual, path);
            let loaded = PeerConfig::load_list_info(actual).unwrap();
            assert_eq!(loaded, PeerListInfo::default());
            replacement.store(id).unwrap();
            written = fs::read(&path).unwrap();
            reads += 1;
            Ok(loaded)
        });
        let preserved = fs::read(&path).ok().as_deref() == Some(written.as_slice());
        println!("OPTION_COMMIT_PEER_LISTING=observed kind=replacement real_reads={reads} replacement_committed={} snapshot_omitted={} next={next} replacement_preserved={preserved}", !written.is_empty(), peers.is_empty());
        assert!(reads == 1 && !written.is_empty() && peers.is_empty() && next == 1 && preserved);
        let stored = PeerConfig::load_for_write(id).unwrap();
        assert_eq!(stored.password_prs, b"fixture-replacement-prs");
        assert_eq!(stored.options.get("alias").map(String::as_str), Some("replacement"));
        assert_eq!(stored.info.platform, "Linux");
    });
}

#[test]
fn peer_listing_preserves_visible_and_incomplete_records_and_batch_boundaries() {
    in_private_process("config::option_tests::peer_listing_preserves_visible_and_incomplete_records_and_batch_boundaries", |_| {
        let visible_id = "peer-listing-visible";
        let incomplete_id = "peer-listing-incomplete";
        let mut visible = PeerConfig::default();
        visible.info.platform = "Linux".into();
        visible.options.insert("alias".into(), "visible".into());
        visible.store(visible_id).unwrap();
        let mut incomplete = PeerConfig::default();
        incomplete.password_prs = b"fixture-incomplete-prs".to_vec();
        incomplete.store(incomplete_id).unwrap();
        let visible_path = PeerConfig::path(visible_id);
        let incomplete_path = PeerConfig::path(incomplete_id);
        let visible_bytes = fs::read(&visible_path).unwrap();
        let incomplete_bytes = fs::read(&incomplete_path).unwrap();
        let all = vec![
            (visible_id.into(), SystemTime::UNIX_EPOCH, visible_path.clone()),
            (incomplete_id.into(), SystemTime::UNIX_EPOCH, incomplete_path.clone()),
        ];
        let (peers, next) = PeerConfig::batch_peers(&all, 0, Some(1));
        assert_eq!(next, 1);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].0, visible_id);
        assert_eq!(peers[0].1, SystemTime::UNIX_EPOCH);
        assert_eq!(peers[0].2.info.platform, "Linux");
        assert_eq!(peers[0].2.alias, "visible");
        let (peers, next) = PeerConfig::batch_peers(&all, 1, None);
        assert!(peers.is_empty() && next == 2);
        let (peers, next) = PeerConfig::batch_peers(&all, 2, None);
        assert!(peers.is_empty() && next == 0);
        let (peers, next) = PeerConfig::batch_peers(&all, 1, Some(0));
        assert!(peers.is_empty() && next == 1);
        assert_eq!(fs::read(visible_path).unwrap(), visible_bytes);
        assert_eq!(fs::read(incomplete_path).unwrap(), incomplete_bytes);
    });
}

#[test]
fn peer_listing_reads_the_enumerated_alias_and_preserves_read_denial() {
    in_private_process("config::option_tests::peer_listing_reads_the_enumerated_alias_and_preserves_read_denial", |root| {
        let id = "peer-listing-alias";
        PeerConfig::default().store(id).unwrap();
        let canonical = PeerConfig::path(id);
        let canonical_bytes = fs::read(&canonical).unwrap();
        let alias = root.join("alternate").join("alias.toml");
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-alias-prs".to_vec();
        peer.info.platform = "Linux".into();
        peer.options.insert("alias".into(), "enumerated".into());
        PeerConfig::store_path(&alias, &peer).unwrap();
        let alias_bytes = fs::read(&alias).unwrap();
        let all = vec![(id.into(), SystemTime::UNIX_EPOCH, alias.clone())];
        let (peers, next) = PeerConfig::batch_peers(&all, 0, None);
        assert_eq!(next, 1);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].2.info, peer.info);
        assert_eq!(peers[0].2.alias, "enumerated");
        fs::set_permissions(&alias, fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(fs::read(&alias).unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        let (peers, next) = PeerConfig::batch_peers(&all, 0, None);
        fs::set_permissions(&alias, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(peers.is_empty() && next == 1);
        assert_eq!(fs::read(&alias).unwrap(), alias_bytes);
        assert_eq!(PeerConfig::load_path_with_status(alias).value.password_prs, peer.password_prs);
        assert_eq!(fs::read(canonical).unwrap(), canonical_bytes);
    });
}

#[test]
fn peer_transfer_write_failure_is_reported_and_retryable() {
    in_private_process("config::option_tests::peer_transfer_write_failure_is_reported_and_retryable", |_| {
        let id = "peer-transfer-write";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-transfer-prs".to_vec();
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.transfer.read_jobs.push("old-read".into());
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        for transfer in [TransferSerde { read_jobs: vec!["new-read".into()], write_jobs: vec!["new-write".into()] }, TransferSerde::default()] {
            let original = fs::read(&path).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let result = PeerConfig::set_transfer(id, &transfer);
            let preserved = fs::read(&path).unwrap() == original;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            println!("OPTION_COMMIT_PEER_TRANSFER=observed kind=write clearing={} reported={} file_preserved={preserved}", transfer == TransferSerde::default(), result.is_err());
            assert!(result.is_err() && preserved);
            PeerConfig::set_transfer(id, &transfer).unwrap();
            let stored = PeerConfig::load_for_write(id).unwrap();
            assert_eq!(stored.transfer, transfer);
            assert_eq!(stored.password_prs, b"fixture-transfer-prs");
            assert_eq!(stored.options.get("unrelated").map(String::as_str), Some("preserved"));
        }
    });
}

#[test]
fn peer_transfer_unreadable_source_refuses_without_replacing_credentials() {
    in_private_process("config::option_tests::peer_transfer_unreadable_source_refuses_without_replacing_credentials", |_| {
        let id = "peer-transfer-read";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-transfer-prs".to_vec();
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.transfer.read_jobs.push("old-read".into());
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let original = fs::read(&path).unwrap();
        let transfer = TransferSerde { read_jobs: vec!["new-read".into()], write_jobs: vec!["new-write".into()] };
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        let native = fs::read(&path).unwrap_err();
        let result = PeerConfig::set_transfer(id, &transfer);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let preserved = fs::read(&path).unwrap() == original;
        println!("OPTION_COMMIT_PEER_TRANSFER=observed kind=read errno={} reported={} file_preserved={preserved}", native.raw_os_error().unwrap(), result.is_err());
        assert_eq!(native.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(result.is_err() && preserved);
        PeerConfig::set_transfer(id, &transfer).unwrap();
        let stored = PeerConfig::load_for_write(id).unwrap();
        assert_eq!(stored.transfer, transfer);
        assert_eq!(stored.password_prs, b"fixture-transfer-prs");
        assert_eq!(stored.options.get("unrelated").map(String::as_str), Some("preserved"));
    });
}

#[test]
fn peer_transfer_changes_only_the_checkpoint_and_preserves_siblings() {
    in_private_process("config::option_tests::peer_transfer_changes_only_the_checkpoint_and_preserves_siblings", |_| {
        let id = "peer-transfer-selected";
        let sibling = "peer-transfer-sibling";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-transfer-prs".to_vec();
        peer.options.insert("alias".into(), "preserved".into());
        peer.ui_flutter.insert("canvas".into(), "preserved".into());
        peer.info.platform = "Linux".into();
        peer.store(id).unwrap();
        peer.store(sibling).unwrap();
        let sibling_bytes = fs::read(PeerConfig::path(sibling)).unwrap();
        let mut expected = PeerConfig::load_for_write(id).unwrap();
        for transfer in [TransferSerde { read_jobs: vec!["read-1".into(), "read-2".into()], write_jobs: vec!["write-1".into()] }, TransferSerde::default()] {
            PeerConfig::set_transfer(id, &transfer).unwrap();
            expected.transfer = transfer;
            assert_eq!(PeerConfig::load_for_write(id).unwrap(), expected);
            assert_eq!(fs::read(PeerConfig::path(sibling)).unwrap(), sibling_bytes);
        }
    });
}

#[test]
fn peer_transfer_unchanged_and_missing_empty_checkpoints_avoid_writes() {
    in_private_process("config::option_tests::peer_transfer_unchanged_and_missing_empty_checkpoints_avoid_writes", |_| {
        use std::os::unix::fs::MetadataExt;
        let id = "peer-transfer-unchanged";
        let missing = "peer-transfer-missing";
        PeerConfig::set_transfer(missing, &TransferSerde::default()).unwrap();
        assert!(!PeerConfig::path(missing).exists());
        let transfer = TransferSerde { read_jobs: vec!["read".into()], write_jobs: vec!["write".into()] };
        PeerConfig::set_transfer(id, &transfer).unwrap();
        let path = PeerConfig::path(id);
        let bytes = fs::read(&path).unwrap();
        let before = fs::metadata(&path).unwrap();
        let parent = path.parent().unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        let unchanged = PeerConfig::set_transfer(id, &transfer);
        let missing_empty = PeerConfig::set_transfer(missing, &TransferSerde::default());
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        let after = fs::metadata(&path).unwrap();
        assert!(unchanged.is_ok() && missing_empty.is_ok());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert!(!PeerConfig::path(missing).exists());
    });
}

#[test]
fn peer_load_corruption_preserves_source_and_repeated_actions_refuse() {
    in_private_process("config::option_tests::peer_load_corruption_preserves_source_and_repeated_actions_refuse", |_| {
        use std::os::unix::fs::MetadataExt;
        let id = "peer-load-preserve-source";
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        let actions: [(&str, fn(&str) -> crate::ResultType<()>); 6] = [
            ("read", |id| PeerConfig::load_for_write(id).map(|_| ())),
            ("option", |id| PeerConfig::set_option(id, "alias", "requested".into())),
            ("forget", PeerConfig::forget_password),
            ("transfer", |id| PeerConfig::set_transfer(id, &TransferSerde::default())),
            ("add_forward", |id| PeerConfig::add_port_forward(id, &(8001, "destination".into(), 80)).map(|_| ())),
            ("remove_forward", |id| PeerConfig::remove_port_forward(id, 8001).map(|_| ())),
        ];
        let mut all_preserved = true;
        for (kind, source) in [("syntax", b"password_prs = [private-peer-source\n".as_slice()), ("utf8", b"\xffprivate-peer-source".as_slice())] {
            for (name, action) in actions {
                fs::write(&path, source).unwrap();
                let before = fs::metadata(&path).unwrap();
                let names = || {
                    let mut names = fs::read_dir(parent).unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>();
                    names.sort(); names
                };
                let original_names = names();
                let first = action(id);
                let second = action(id);
                let preserved = fs::read(&path).map(|bytes| bytes == source).unwrap_or(false);
                let same_file = fs::metadata(&path).map(|m| (m.dev(), m.ino()) == (before.dev(), before.ino())).unwrap_or(false);
                let directory_unchanged = names() == original_names;
                println!("OPTION_COMMIT_PEER_LOAD=observed kind={kind} action={name} first_refused={} repeated_refused={} file_preserved={preserved} same_file={same_file} directory_unchanged={directory_unchanged}", first.is_err(), second.is_err());
                if let Err(err) = first.as_ref() { assert!(!err.to_string().contains("private-peer-source")); }
                all_preserved &= first.is_err() && second.is_err() && preserved && same_file && directory_unchanged;
            }
        }
        assert!(all_preserved);
    });
}

#[test]
fn peer_load_missing_does_not_initialize_controlled_config() {
    in_private_process("config::option_tests::peer_load_missing_does_not_initialize_controlled_config", |_| {
        let global = Config::file_("");
        fs::create_dir_all(global.parent().unwrap()).unwrap();
        let source = b"password = [private-peer-global\n";
        fs::write(&global, source).unwrap();
        let id = "peer-load-missing-no-global";
        let path = PeerConfig::path(id);
        assert!(!path.exists());
        let loaded = PeerConfig::load_with_status(id);
        let preserved = fs::read(&global).map(|bytes| bytes == source).unwrap_or(false);
        println!("OPTION_COMMIT_PEER_LOAD=observed kind=missing_global global_preserved={preserved} peer_absent={}", !path.exists());
        assert_eq!(loaded.status, ConfigLoadStatus::NotFound);
        assert!(preserved && !path.exists() && loaded.value.password_prs.is_empty());
    });
}

#[test]
fn peer_load_corrupt_does_not_initialize_controlled_config() {
    in_private_process("config::option_tests::peer_load_corrupt_does_not_initialize_controlled_config", |_| {
        let id = "peer-load-corrupt-no-global";
        let path = PeerConfig::path(id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let peer = b"password_prs = [private-peer-source\n";
        fs::write(&path, peer).unwrap();
        let global = Config::file_("");
        let source = b"password = [private-peer-global\n";
        fs::write(&global, source).unwrap();
        let loaded = PeerConfig::load_with_status(id);
        let preserved = fs::read(global).map(|bytes| bytes == source).unwrap_or(false);
        let peer_preserved = fs::read(path).map(|bytes| bytes == peer).unwrap_or(false);
        println!("OPTION_COMMIT_PEER_LOAD=observed kind=corrupt_global global_preserved={preserved} peer_preserved={peer_preserved}");
        assert_eq!(loaded.status, ConfigLoadStatus::Corrupt);
        assert!(preserved && peer_preserved && loaded.value.password_prs.is_empty());
    });
}

#[test]
fn peer_load_utf8_is_corrupt_without_recovery() {
    in_private_process("config::option_tests::peer_load_utf8_is_corrupt_without_recovery", |_| {
        let id = "peer-load-bad-utf8";
        let path = PeerConfig::path(id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let source = b"\xffprivate-peer-source";
        fs::write(&path, source).unwrap();
        let loaded = PeerConfig::load_with_status(id);
        let preserved = fs::read(path).unwrap() == source;
        println!("OPTION_COMMIT_PEER_LOAD=observed kind=utf8_classification corrupt={} file_preserved={preserved}", loaded.status == ConfigLoadStatus::Corrupt);
        assert_eq!(loaded.status, ConfigLoadStatus::Corrupt);
        assert!(preserved && loaded.value.password_prs.is_empty());
    });
}

#[test]
fn peer_load_malformed_prs_refuses_without_defaulting_or_mutation() {
    in_private_process("config::option_tests::peer_load_malformed_prs_refuses_without_defaulting_or_mutation", |_| {
        use std::os::unix::fs::MetadataExt;
        let id = "peer-load-malformed-prs";
        let path = PeerConfig::path(id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut all_refused = true;
        for (index, value) in ["'private-invalid-prs'", "42", "{private = 'invalid-prs'}", "[256]", "[-1]", "['invalid-prs']"].iter().enumerate() {
            let source = format!("password_prs = {value}\n[options]\nalias = 'preserved'\n");
            fs::write(&path, &source).unwrap();
            let before = fs::metadata(&path).unwrap();
            let loaded = PeerConfig::load_with_status(id);
            let checked = PeerConfig::load_for_write(id);
            let first = PeerConfig::set_option(id, "alias", "requested".into());
            let repeated = PeerConfig::set_option(id, "alias", "requested".into());
            let corrupt = loaded.status == ConfigLoadStatus::Corrupt;
            let preserved = fs::read(&path).unwrap() == source.as_bytes();
            let same_file = fs::metadata(&path).unwrap().ino() == before.ino();
            println!("OPTION_COMMIT_PEER_LOAD=observed kind=prs_shape case={index} corrupt={corrupt} checked_refused={} write_refused={} repeated_refused={} file_preserved={preserved} same_file={same_file}", checked.is_err(), first.is_err(), repeated.is_err());
            all_refused &= corrupt && checked.is_err() && first.is_err() && repeated.is_err() && preserved && same_file;
            assert!(loaded.value.password_prs.is_empty());
        }
        assert!(all_refused);
    });
}

#[test]
fn peer_load_status_controls_preserve_missing_denied_and_directory() {
    in_private_process("config::option_tests::peer_load_status_controls_preserve_missing_denied_and_directory", |_| {
        let id = "peer-load-status-controls";
        let path = PeerConfig::path(id);
        assert_eq!(PeerConfig::load_with_status(id).status, ConfigLoadStatus::NotFound);
        assert!(PeerConfig::load_for_write(id).is_ok() && !path.exists());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let source = b"password_prs = []\n[options]\nalias = 'preserved'\n";
        fs::write(&path, source).unwrap();
        let loaded = PeerConfig::load_with_status(id);
        assert_eq!(loaded.status, ConfigLoadStatus::Loaded);
        assert_eq!(loaded.value.options.get("alias").map(String::as_str), Some("preserved"));
        assert_eq!(fs::read(&path).unwrap(), source);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        let native = fs::read(&path).unwrap_err();
        let denied = PeerConfig::load_with_status(id);
        let refused = PeerConfig::load_for_write(id).is_err();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(native.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(denied.status, ConfigLoadStatus::TransientError);
        assert!(refused && fs::read(&path).unwrap() == source);
        assert_eq!(PeerConfig::load_with_status(id).status, ConfigLoadStatus::Loaded);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let child = path.join("preserved");
        fs::write(&child, source).unwrap();
        assert_eq!(PeerConfig::load_with_status(id).status, ConfigLoadStatus::TransientError);
        assert!(PeerConfig::load_for_write(id).is_err());
        assert_eq!(fs::read(child).unwrap(), source);
        println!("OPTION_COMMIT_PEER_LOAD=observed kind=controls missing_absent=true loaded_preserved=true denied_errno={} transient=true retry_loaded=true directory_preserved=true", native.raw_os_error().unwrap());
    });
}

#[test]
fn peer_option_read_preserves_credentials_and_file_identity() {
    in_private_process("config::option_tests::peer_option_read_preserves_credentials_and_file_identity", |_| {
        use std::os::unix::fs::MetadataExt;
        let id = "peer-option-display-migration";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-unwrapped-option-prs".to_vec();
        peer.options.insert("alias".into(), "visible alias".into());
        peer.options.insert("rdp_password".into(), "fixture-retired-secret".into());
        let path = PeerConfig::path(id);
        store_path(path.clone(), &peer).unwrap();
        let original = fs::read(&path).unwrap();
        let before = fs::metadata(&path).unwrap();
        let value = PeerConfig::read_option(id, "alias").unwrap();
        let after = fs::metadata(&path).unwrap();
        let preserved = fs::read(&path).unwrap() == original;
        let same_file = (before.dev(), before.ino()) == (after.dev(), after.ino());
        println!("OPTION_COMMIT_PEER_OPTION_READ=observed kind=migration file_preserved={preserved} same_file={same_file}");
        assert_eq!(value, "visible alias");
        assert!(preserved && same_file);
        assert_eq!(PeerConfig::read_option(id, "rdp_password").unwrap(), "");
        assert_eq!(fs::read(&path).unwrap(), original);
        let loaded = PeerConfig::load_for_write(id).unwrap();
        assert_eq!(loaded.password_prs, peer.password_prs);
        assert!(!loaded.options.contains_key("rdp_password"));
        assert_ne!(fs::read(path).unwrap(), original);
    });
}

#[test]
fn peer_option_read_corrupt_records_refuse_without_recovery() {
    in_private_process("config::option_tests::peer_option_read_corrupt_records_refuse_without_recovery", |_| {
        use std::os::unix::fs::MetadataExt;
        let path = PeerConfig::path("peer-option-display-corrupt");
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        for (kind, source) in [("syntax", b"password = [private-option-source\n".as_slice()), ("utf8", b"\xffprivate-option-source".as_slice())] {
            fs::write(&path, source).unwrap();
            let before = fs::metadata(&path).unwrap();
            let names = || {
                let mut names = fs::read_dir(parent).unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>();
                names.sort(); names
            };
            let original_names = names();
            let result = PeerConfig::read_option("peer-option-display-corrupt", "alias");
            let preserved = fs::read(&path).map(|bytes| bytes == source).unwrap_or(false);
            let same_file = fs::metadata(&path).map(|m| (m.dev(), m.ino()) == (before.dev(), before.ino())).unwrap_or(false);
            println!("OPTION_COMMIT_PEER_OPTION_READ=observed kind={kind} refused={} file_preserved={preserved} same_file={same_file}", result.is_err());
            assert!(result.is_err() && preserved && same_file && names() == original_names);
            assert!(!result.unwrap_err().to_string().contains("private-option-source"));
        }
    });
}

#[test]
fn peer_option_read_denial_is_reported_and_retryable() {
    in_private_process("config::option_tests::peer_option_read_denial_is_reported_and_retryable", |_| {
        let id = "peer-option-display-denied";
        let path = PeerConfig::path(id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let source = b"[options]\nalias = 'visible alias'\n";
        fs::write(&path, source).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        let native = fs::read(&path).unwrap_err();
        let result = PeerConfig::read_option(id, "alias");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let preserved = fs::read(&path).unwrap() == source;
        println!("OPTION_COMMIT_PEER_OPTION_READ=observed kind=denial errno={} refused={} file_preserved={preserved}", native.raw_os_error().unwrap(), result.is_err());
        assert_eq!(native.kind(), io::ErrorKind::PermissionDenied);
        assert!(result.is_err() && preserved);
        assert_eq!(PeerConfig::read_option(id, "alias").unwrap(), "visible alias");
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let child = path.join("preserved");
        fs::write(&child, source).unwrap();
        assert!(PeerConfig::read_option(id, "alias").is_err());
        assert_eq!(fs::read(child).unwrap(), source);
    });
}

#[test]
fn peer_option_read_does_not_initialize_controlled_credentials() {
    in_private_process("config::option_tests::peer_option_read_does_not_initialize_controlled_credentials", |_| {
        let id = "peer-option-display-no-global";
        let path = PeerConfig::path(id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let source = b"[options]\nalias = 'visible alias'\n";
        fs::write(&path, source).unwrap();
        let global_path = Config::file_("");
        let global = b"password = [private-option-global\n";
        fs::write(&global_path, global).unwrap();
        let result = PeerConfig::read_option(id, "alias").unwrap();
        let preserved = fs::read(global_path).map(|bytes| bytes == global).unwrap_or(false);
        println!("OPTION_COMMIT_PEER_OPTION_READ=observed kind=global_config file_preserved={preserved}");
        assert!(preserved);
        assert_eq!(result, "visible alias");
        assert_eq!(fs::read(path).unwrap(), source);
    });
}

#[test]
fn peer_option_read_ignores_unrelated_record_shapes() {
    in_private_process("config::option_tests::peer_option_read_ignores_unrelated_record_shapes", |_| {
        let id = "peer-option-display-projection";
        let path = PeerConfig::path(id);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let source = b"password_prs = {private = 'ignored'}\npassword = ['ignored']\ninfo = 42\ntransfer = 42\nui_flutter = 42\n[options]\nalias = 'visible alias'\nrdp_port = '3390'\n";
        fs::write(&path, source).unwrap();
        let value = PeerConfig::read_option(id, "alias").unwrap();
        let preserved = fs::read(&path).map(|bytes| bytes == source).unwrap_or(false);
        println!("OPTION_COMMIT_PEER_OPTION_READ=observed kind=projection value_preserved={} file_preserved={preserved}", value == "visible alias");
        assert!(preserved && value == "visible alias");
        assert_eq!(PeerConfig::read_option(id, "rdp_port").unwrap(), "3390");
    });
}

#[test]
fn peer_option_read_preserves_values_defaults_and_retired_key_masking() {
    in_private_process("config::option_tests::peer_option_read_preserves_values_defaults_and_retired_key_masking", |_| {
        let id = "peer-option-display-values";
        let path = PeerConfig::path(id);
        let key = keys::OPTION_CUSTOM_FPS;
        UserDefaultConfig::set_option(key.into(), "25".into()).unwrap();
        assert_eq!(PeerConfig::read_option(id, key).unwrap(), "25");
        assert_eq!(PeerConfig::read_option(id, "alias").unwrap(), "");
        assert!(!path.exists());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        for source in ["password_prs = []\n", "options = 42\n", "[options]\n", "[options]\nalias = 'visible alias'\nrdp_port = '3390'\nrdp_username = 'retired-user'\nrdp_password = 'retired-secret'\n"] {
            fs::write(&path, source).unwrap();
            assert_eq!(PeerConfig::read_option(id, key).unwrap(), "");
            assert_eq!(PeerConfig::read_option(id, "alias").unwrap(), if source.contains("visible alias") { "visible alias" } else { "" });
            for name in RETIRED_RDP_CREDENTIAL_OPTIONS {
                assert_eq!(PeerConfig::read_option(id, name).unwrap(), "");
            }
        }
        println!("OPTION_COMMIT_PEER_OPTION_READ=observed kind=controls inherited_missing_default=true existing_empty_distinct=true retired_keys_masked=true");
    });
}

#[test]
fn peer_option_write_failure_preserves_settings_and_retries_set_and_remove() {
    in_private_process("config::option_tests::peer_option_write_failure_preserves_settings_and_retries_set_and_remove", |_| {
        let id = "peer-option-write";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-option-prs".to_vec();
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        for value in ["selected", ""] {
            let original = fs::read(&path).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let result = PeerConfig::set_option(id, "alias", value.into());
            let preserved = fs::read(&path).unwrap() == original;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            println!("OPTION_COMMIT_PEER_OPTION=observed kind=write remove={} reported={} file_preserved={preserved}", value.is_empty(), result.is_err());
            assert!(preserved && result.is_err());
            PeerConfig::set_option(id, "alias", value.into()).unwrap();
            let stored = PeerConfig::load_for_write(id).unwrap();
            assert_eq!(stored.options.get("alias").map(String::as_str), if value.is_empty() { None } else { Some(value) });
            assert_eq!(stored.options.get("unrelated").map(String::as_str), Some("preserved"));
            assert_eq!(stored.password_prs, b"fixture-option-prs");
        }
    });
}

#[test]
fn peer_option_unreadable_source_refuses_without_losing_credentials() {
    in_private_process("config::option_tests::peer_option_unreadable_source_refuses_without_losing_credentials", |_| {
        let id = "peer-option-read";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-option-prs".to_vec();
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let original = fs::read(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        let native = fs::read(&path).unwrap_err();
        let result = PeerConfig::set_option(id, "alias", "selected".into());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let preserved = fs::read(&path).unwrap() == original;
        println!("OPTION_COMMIT_PEER_OPTION=observed kind=read errno={} reported={} file_preserved={preserved}", native.raw_os_error().unwrap(), result.is_err());
        assert_eq!(native.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(preserved && result.is_err());
        PeerConfig::set_option(id, "alias", "selected".into()).unwrap();
        let stored = PeerConfig::load_for_write(id).unwrap();
        assert_eq!(stored.options.get("alias").map(String::as_str), Some("selected"));
        assert_eq!(stored.options.get("unrelated").map(String::as_str), Some("preserved"));
        assert_eq!(stored.password_prs, b"fixture-option-prs");
    });
}

#[test]
fn peer_option_preserves_other_state_and_avoids_idempotent_or_missing_removal_writes() {
    in_private_process("config::option_tests::peer_option_preserves_other_state_and_avoids_idempotent_or_missing_removal_writes", |_| {
        let id = "peer-option-selected";
        let sibling = "peer-option-sibling";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-option-prs".to_vec();
        peer.ui_flutter.insert("canvas".into(), "preserved".into());
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.store(id).unwrap();
        peer.store(sibling).unwrap();
        let sibling_bytes = fs::read(PeerConfig::path(sibling)).unwrap();
        let mut expected = PeerConfig::load_for_write(id).unwrap();
        expected.options.insert("alias".into(), "selected".into());
        PeerConfig::set_option(id, "alias", "selected".into()).unwrap();
        assert_eq!(PeerConfig::load_for_write(id).unwrap(), expected);
        assert_eq!(fs::read(PeerConfig::path(sibling)).unwrap(), sibling_bytes);
        let path = PeerConfig::path(id);
        let original = fs::read(&path).unwrap();
        let before = fs::metadata(&path).unwrap();
        PeerConfig::set_option(id, "alias", "selected".into()).unwrap();
        let unchanged_inode = std::os::unix::fs::MetadataExt::ino(&before)
            == std::os::unix::fs::MetadataExt::ino(&fs::metadata(&path).unwrap());
        let missing = "peer-option-missing";
        PeerConfig::set_option(missing, "alias", String::new()).unwrap();
        let absent = !PeerConfig::path(missing).exists();
        println!("OPTION_COMMIT_PEER_OPTION=observed kind=idempotent unchanged_inode={unchanged_inode} missing_removal_absent={absent} credential_and_unrelated_preserved=true sibling_preserved=true");
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(unchanged_inode && absent);
    });
}

#[test]
fn peer_option_explicit_inherited_default_persists_and_missing_removal_is_absent() {
    in_private_process("config::option_tests::peer_option_explicit_inherited_default_persists_and_missing_removal_is_absent", |_| {
        let key = keys::OPTION_CUSTOM_FPS;
        assert_eq!(UserDefaultConfig::set_option(key.into(), "25".into()).unwrap(), "25");
        let id = "peer-option-explicit-default";
        assert!(!PeerConfig::path(id).exists());
        assert_eq!(PeerConfig::load_for_write(id).unwrap().options.get(key).map(String::as_str), Some("25"));
        PeerConfig::set_option(id, key, "25".into()).unwrap();
        let explicit_file = PeerConfig::path(id).exists();
        assert_eq!(UserDefaultConfig::set_option(key.into(), "26".into()).unwrap(), "26");
        let retained = PeerConfig::load_for_write(id).unwrap().options.get(key).map(String::as_str) == Some("25");
        let missing = "peer-option-default-removal";
        PeerConfig::set_option(missing, key, String::new()).unwrap();
        let removal_absent = !PeerConfig::path(missing).exists();
        println!("OPTION_COMMIT_PEER_OPTION=observed kind=inherited_default explicit_file={explicit_file} retained_after_default_change={retained} missing_removal_absent={removal_absent}");
        assert!(explicit_file && retained && removal_absent);
    });
}

#[test]
fn peer_forget_write_failure_is_reported_and_retryable() {
    in_private_process("config::option_tests::peer_forget_write_failure_is_reported_and_retryable", |_| {
        let id = "peer-forget-write";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-forget-prs".to_vec();
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        let original = fs::read(&path).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        let result = PeerConfig::forget_password(id);
        let preserved = fs::read(&path).unwrap() == original;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        println!("OPTION_COMMIT_PEER_FORGET=observed kind=write reported={} file_preserved={preserved}", result.is_err());
        assert!(preserved && result.is_err());
        PeerConfig::forget_password(id).unwrap();
        let stored = PeerConfig::load_for_write(id).unwrap();
        assert!(stored.password_prs.is_empty());
        assert_eq!(stored.options.get("unrelated").map(String::as_str), Some("preserved"));
    });
}

#[test]
fn peer_forget_unreadable_source_refuses_without_replacing_settings() {
    in_private_process("config::option_tests::peer_forget_unreadable_source_refuses_without_replacing_settings", |_| {
        let id = "peer-forget-read";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-forget-prs".to_vec();
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let original = fs::read(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        let native = fs::read(&path).unwrap_err();
        let result = PeerConfig::forget_password(id);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let preserved = fs::read(&path).unwrap() == original;
        println!("OPTION_COMMIT_PEER_FORGET=observed kind=read errno={} reported={} file_preserved={preserved}", native.raw_os_error().unwrap(), result.is_err());
        assert_eq!(native.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(preserved && result.is_err());
        PeerConfig::forget_password(id).unwrap();
        let stored = PeerConfig::load_for_write(id).unwrap();
        assert!(stored.password_prs.is_empty());
        assert_eq!(stored.options.get("unrelated").map(String::as_str), Some("preserved"));
    });
}

#[test]
fn peer_forget_clears_both_credentials_preserves_settings_and_is_idempotent() {
    in_private_process("config::option_tests::peer_forget_clears_both_credentials_preserves_settings_and_is_idempotent", |_| {
        let id = "peer-forget-selected";
        let sibling = "peer-forget-sibling";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-forget-prs".to_vec();
        peer.options.insert("unrelated".into(), "preserved".into());
        peer.ui_flutter.insert("selected".into(), "preserved".into());
        peer.store(id).unwrap();
        peer.store(sibling).unwrap();
        let sibling_bytes = fs::read(PeerConfig::path(sibling)).unwrap();
        let mut expected = PeerConfig::load_for_write(id).unwrap();
        expected.password_prs.clear();
        insert_retired_peer_password(id);
        PeerConfig::forget_password(id).unwrap();
        assert_eq!(PeerConfig::load_for_write(id).unwrap(), expected);
        assert_eq!(fs::read(PeerConfig::path(sibling)).unwrap(), sibling_bytes);
        let path = PeerConfig::path(id);
        let original = fs::read(&path).unwrap();
        let before = fs::metadata(&path).unwrap();
        PeerConfig::forget_password(id).unwrap();
        let unchanged_inode = std::os::unix::fs::MetadataExt::ino(&before)
            == std::os::unix::fs::MetadataExt::ino(&fs::metadata(&path).unwrap());
        println!("OPTION_COMMIT_PEER_FORGET=observed kind=repeat both_cleared=true settings_preserved=true sibling_preserved=true unchanged_inode={unchanged_inode}");
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(unchanged_inode);
    });
}

#[test]
fn peer_forget_missing_record_does_not_create_a_peer() {
    in_private_process("config::option_tests::peer_forget_missing_record_does_not_create_a_peer", |_| {
        let id = "peer-forget-missing";
        let path = PeerConfig::path(id);
        assert!(!path.exists());
        PeerConfig::forget_password(id).unwrap();
        let absent = !path.exists();
        println!("OPTION_COMMIT_PEER_FORGET=observed kind=missing absent={absent}");
        assert!(absent);
    });
}

#[test]
fn peer_removal_permission_failure_is_reported_and_retryable() {
    in_private_process("config::option_tests::peer_removal_permission_failure_is_reported_and_retryable", |_| {
        let id = "peer-removal-permission";
        let mut peer = PeerConfig::default();
        peer.password_prs = b"fixture-removal-prs".to_vec();
        peer.store(id).unwrap();
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        let original = fs::read(&path).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        let native = fs::remove_file(&path).unwrap_err();
        let result = PeerConfig::remove(id);
        let preserved = fs::read(&path).unwrap() == original;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        println!("OPTION_COMMIT_PEER_REMOVE=observed kind=permission errno={} reported={} file_preserved={preserved}",
            native.raw_os_error().unwrap(), result.is_err());
        assert_eq!(native.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(preserved);
        assert!(result.is_err());
        PeerConfig::remove(id).unwrap();
        assert!(!path.exists());
    });
}

#[test]
fn peer_removal_directory_failure_preserves_its_contents() {
    in_private_process("config::option_tests::peer_removal_directory_failure_preserves_its_contents", |_| {
        let id = "peer-removal-directory";
        PeerConfig::default().store(id).unwrap();
        let path = PeerConfig::path(id);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let sentinel = path.join("sentinel");
        fs::write(&sentinel, b"unchanged").unwrap();
        let native = fs::remove_file(&path).unwrap_err();
        let result = PeerConfig::remove(id);
        println!("OPTION_COMMIT_PEER_REMOVE=observed kind=directory errno={} reported={}",
            native.raw_os_error().unwrap(), result.is_err());
        assert!(path.is_dir());
        assert_eq!(fs::read(&sentinel).unwrap(), b"unchanged");
        assert!(result.is_err());
    });
}

#[test]
fn peer_removal_missing_file_is_idempotent() {
    in_private_process("config::option_tests::peer_removal_missing_file_is_idempotent", |_| {
        let id = "peer-removal-missing";
        let path = PeerConfig::path(id);
        assert!(!path.exists());
        PeerConfig::remove(id).unwrap();
        assert!(!path.exists());
    });
}

#[test]
fn peer_removal_deletes_only_the_selected_file_and_allows_repeat() {
    in_private_process("config::option_tests::peer_removal_deletes_only_the_selected_file_and_allows_repeat", |_| {
        let id = "peer-removal-selected";
        let other = "peer-removal-sibling";
        PeerConfig::default().store(id).unwrap();
        PeerConfig::default().store(other).unwrap();
        let sibling = PeerConfig::path(other);
        let original = fs::read(&sibling).unwrap();
        PeerConfig::remove(id).unwrap();
        PeerConfig::remove(id).unwrap();
        assert!(!PeerConfig::path(id).exists());
        assert_eq!(fs::read(&sibling).unwrap(), original);
    });
}

#[test]
fn peer_removal_unlinks_a_symlink_without_removing_its_target() {
    in_private_process("config::option_tests::peer_removal_unlinks_a_symlink_without_removing_its_target", |_| {
        let id = "peer-removal-link";
        PeerConfig::default().store(id).unwrap();
        let path = PeerConfig::path(id);
        let target = path.with_file_name("unrelated-target");
        fs::write(&target, b"unchanged target").unwrap();
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        PeerConfig::remove(id).unwrap();
        assert!(fs::symlink_metadata(&path).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"unchanged target");
    });
}

#[test]
#[cfg(target_os = "linux")]
fn peer_removal_refuses_a_symlinked_peer_parent() {
    in_private_process("config::option_tests::peer_removal_refuses_a_symlinked_peer_parent", |root| {
        let id = "peer-removal-linked-parent";
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent.parent().unwrap()).unwrap();
        let outside = root.join("outside-peers");
        fs::create_dir(&outside).unwrap();
        let target = outside.join(path.file_name().unwrap());
        fs::write(&target, b"outside peer bytes").unwrap();
        std::os::unix::fs::symlink(&outside, parent).unwrap();
        let result = PeerConfig::remove(id);
        let preserved = fs::read(&target).ok().as_deref() == Some(b"outside peer bytes".as_slice());
        println!("OPTION_COMMIT_PEER_REMOVE_PARENT=observed kind=parent_link refused={} outside_preserved={preserved}", result.is_err());
        assert!(result.is_err() && preserved);
        assert!(fs::symlink_metadata(parent).unwrap().file_type().is_symlink());
    });
}

#[test]
#[cfg(target_os = "linux")]
fn peer_removal_refuses_a_symlinked_config_ancestor() {
    in_private_process("config::option_tests::peer_removal_refuses_a_symlinked_config_ancestor", |root| {
        let id = "peer-removal-linked-ancestor";
        let path = PeerConfig::path(id);
        let config_root = path.parent().unwrap().parent().unwrap();
        fs::create_dir_all(config_root.parent().unwrap()).unwrap();
        let outside = root.join("outside-config");
        let outside_peers = outside.join(PEERS);
        fs::create_dir_all(&outside_peers).unwrap();
        let target = outside_peers.join(path.file_name().unwrap());
        fs::write(&target, b"outside ancestor bytes").unwrap();
        std::os::unix::fs::symlink(&outside, config_root).unwrap();
        let result = PeerConfig::remove(id);
        let preserved = fs::read(&target).ok().as_deref() == Some(b"outside ancestor bytes".as_slice());
        println!("OPTION_COMMIT_PEER_REMOVE_PARENT=observed kind=ancestor_link refused={} outside_preserved={preserved}", result.is_err());
        assert!(result.is_err() && preserved);
        assert!(fs::symlink_metadata(config_root).unwrap().file_type().is_symlink());
    });
}

#[test]
#[cfg(target_os = "linux")]
fn peer_removal_retains_its_parent_across_path_replacement() {
    in_private_process("config::option_tests::peer_removal_retains_its_parent_across_path_replacement", |root| {
        let id = "peer-removal-parent-replaced";
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&path, b"selected original bytes").unwrap();
        let sibling = parent.join("sibling.toml");
        fs::write(&sibling, b"retained sibling bytes").unwrap();
        let outside = root.join("replacement-target");
        fs::create_dir(&outside).unwrap();
        let target = outside.join(path.file_name().unwrap());
        fs::write(&target, b"outside replacement bytes").unwrap();
        let moved = parent.with_file_name("retained-original-peers");
        let mut hooks = 0;
        let result = PeerConfig::remove_with_unlink_hook(id, || {
            fs::rename(parent, &moved).unwrap();
            std::os::unix::fs::symlink(&outside, parent).unwrap();
            hooks += 1;
        });
        let outside_preserved = fs::read(&target).ok().as_deref() == Some(b"outside replacement bytes".as_slice());
        let selected_removed = !moved.join(path.file_name().unwrap()).exists();
        println!("OPTION_COMMIT_PEER_REMOVE_PARENT=observed kind=replacement hooks={hooks} success={} selected_removed={selected_removed} outside_preserved={outside_preserved}", result.is_ok());
        assert!(result.is_ok() && hooks == 1 && selected_removed && outside_preserved);
        assert_eq!(fs::read(moved.join("sibling.toml")).unwrap(), b"retained sibling bytes");
        assert!(fs::symlink_metadata(parent).unwrap().file_type().is_symlink());
    });
}

#[test]
#[cfg(target_os = "linux")]
fn peer_removal_refuses_shared_writable_parents_without_repair() {
    in_private_process("config::option_tests::peer_removal_refuses_shared_writable_parents_without_repair", |_| {
        let id = "peer-removal-shared-parent";
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        for mode in [0o720, 0o702] {
            fs::write(&path, b"selected private bytes").unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(mode)).unwrap();
            let result = PeerConfig::remove(id);
            let preserved = fs::read(&path).ok().as_deref() == Some(b"selected private bytes".as_slice());
            let unchanged_mode = fs::metadata(parent).unwrap().permissions().mode() & 0o777 == mode;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            println!("OPTION_COMMIT_PEER_REMOVE_PARENT=observed kind=shared_parent mode={mode:o} refused={} file_preserved={preserved} mode_unchanged={unchanged_mode}", result.is_err());
            assert!(result.is_err() && preserved && unchanged_mode);
        }
        PeerConfig::remove(id).unwrap();
        assert!(!path.exists());
    });
}

#[test]
#[cfg(target_os = "linux")]
fn peer_removal_missing_parents_and_repeats_release_descriptors() {
    in_private_process("config::option_tests::peer_removal_missing_parents_and_repeats_release_descriptors", |_| {
        let id = "peer-removal-fd-control";
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        assert!(!parent.exists());
        PeerConfig::remove(id).unwrap();
        PeerConfig::remove(id).unwrap();
        assert!(!parent.exists());
        fs::create_dir_all(parent).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        let fds = || fs::read_dir("/proc/self/fd").unwrap().count();
        let before = fds();
        for _ in 0..100 {
            fs::write(&path, b"selected bytes").unwrap();
            PeerConfig::remove(id).unwrap();
            PeerConfig::remove(id).unwrap();
        }
        let after = fds();
        println!("OPTION_COMMIT_PEER_REMOVE_PARENT=observed kind=repeat iterations=100 missing_parents_not_created=true fds_before={before} fds_after={after}");
        assert_eq!(after, before);
        assert!(!path.exists());
    });
}

#[test]
#[cfg(target_os = "linux")]
fn peer_removal_supports_write_search_only_parents() {
    in_private_process("config::option_tests::peer_removal_supports_write_search_only_parents", |_| {
        let id = "peer-removal-search-only";
        let path = PeerConfig::path(id);
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        fs::write(&path, b"selected bytes").unwrap();
        let sibling = parent.join("sibling.toml");
        fs::write(&sibling, b"preserved bytes").unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o300)).unwrap();
        assert_eq!(fs::read_dir(parent).err().unwrap().kind(), std::io::ErrorKind::PermissionDenied);
        let result = PeerConfig::remove(id);
        let unchanged_mode = fs::metadata(parent).unwrap().permissions().mode() & 0o777 == 0o300;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        println!("OPTION_COMMIT_PEER_REMOVE_PARENT=observed kind=search_only success={} mode_unchanged={unchanged_mode}", result.is_ok());
        assert!(result.is_ok() && unchanged_mode && !path.exists());
        assert_eq!(fs::read(sibling).unwrap(), b"preserved bytes");
    });
}

#[test]
fn peer_store_reports_failure_preserves_the_file_and_refuses_unreadable_source() {
    in_private_process("config::option_tests::peer_store_reports_failure_preserves_the_file_and_refuses_unreadable_source", |_| {
        let id = "peer-commit-fixture";
        let mut candidate = PeerConfig::default();
        candidate.password_prs = b"fixture-peer-prs".to_vec();
        candidate.options.insert("unrelated".into(), "preserved".into());
        candidate.store(id).unwrap();
        // Mutations start from a loaded config, including its normalised defaults.
        candidate = PeerConfig::load_for_write(id).unwrap();
        assert_eq!(candidate.password_prs, b"fixture-peer-prs");
        let file = PeerConfig::path(id);
        let parent = file.parent().unwrap();
        let original = fs::read(&file).unwrap();
        candidate.options.insert("selected".into(), "replacement".into());
        fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
        let failed = candidate.store(id).is_err();
        let file_preserved = fs::read(&file).unwrap() == original;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        candidate.store(id).unwrap();
        let durable_retry = PeerConfig::load_for_write(id).unwrap() == candidate;
        let committed = fs::read(&file).unwrap();
        let mut oversized = candidate.clone();
        oversized.password_prs = vec![b'x'; ENCRYPT_MAX_LEN + 1];
        assert!(oversized.store(id).is_err());
        assert_eq!(fs::read(&file).unwrap(), committed);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
        let unreadable_refused = PeerConfig::load_for_write(id).is_err();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let read_failure_preserved = fs::read(&file).unwrap() == committed;
        println!("OPTION_COMMIT_PEER_NATIVE=observed failure_reported={failed} file_preserved={file_preserved} retry_durable={durable_retry} unreadable_refused={unreadable_refused} read_failure_preserved={read_failure_preserved}");
        assert!(failed && file_preserved && durable_retry && unreadable_refused && read_failure_preserved);
    });
}

#[test]
fn default_initial_read_preserves_corrupt_files() {
    in_private_process("config::option_tests::default_initial_read_preserves_corrupt_files", |_| {
        use std::os::unix::fs::MetadataExt;
        let file = Config::file_("_default");
        let parent = file.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        for (kind, source) in [("syntax", b"[options]\nprivate-default-source = [\n".as_slice()), ("utf8", b"\xffprivate-default-source".as_slice())] {
            fs::write(&file, source).unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
            let before = fs::metadata(&file).unwrap();
            let names = || {
                let mut names = fs::read_dir(parent).unwrap().map(|e| e.unwrap().file_name()).collect::<Vec<_>>();
                names.sort(); names
            };
            let original_names = names();
            let loaded = UserDefaultConfig::load();
            let preserved = fs::read(&file).map(|bytes| bytes == source).unwrap_or(false);
            let same_file = fs::metadata(&file).map(|s| (s.dev(), s.ino(), s.mode()) == (before.dev(), before.ino(), before.mode())).unwrap_or(false);
            println!("OPTION_COMMIT_DEFAULT_READONLY=observed kind=initial_{kind} file_preserved={preserved} same_file={same_file}");
            assert!(preserved && same_file && names() == original_names);
            assert_eq!(loaded.get(keys::OPTION_CUSTOM_FPS), "30");
        }
    });
}

#[test]
fn default_refresh_preserves_corrupt_source_and_confirmed_values() {
    in_private_process("config::option_tests::default_refresh_preserves_corrupt_source_and_confirmed_values", |_| {
        UserDefaultConfig::set_option("confirmed".into(), "original".into()).unwrap();
        let file = Config::file_("_default");
        for (kind, source) in [("syntax", b"[options]\nprivate-default-source = [\n".as_slice()), ("utf8", b"\xffprivate-default-source".as_slice())] {
            fs::write(&file, source).unwrap();
            for round in 0..2 {
                USER_DEFAULT_CONFIG.write().unwrap().1 = Instant::now() - Duration::from_secs(2);
                let value = UserDefaultConfig::get_option("confirmed");
                let preserved = fs::read(&file).map(|bytes| bytes == source).unwrap_or(false);
                println!("OPTION_COMMIT_DEFAULT_READONLY=observed kind=refresh_{kind} round={round} file_preserved={preserved} confirmed_retained={}", value == "original");
                assert!(preserved && value == "original");
            }
        }
        let healthy = b"[options]\nconfirmed = 'external'\nunrelated = 'preserved'\n";
        fs::write(&file, healthy).unwrap();
        USER_DEFAULT_CONFIG.write().unwrap().1 = Instant::now() - Duration::from_secs(2);
        assert_eq!(UserDefaultConfig::get_option("confirmed"), "external");
        assert_eq!(UserDefaultConfig::get_option("unrelated"), "preserved");
        assert_eq!(fs::read(file).unwrap(), healthy);
    });
}

#[test]
fn default_corrupt_source_refuses_repeated_writes_without_recovery() {
    in_private_process("config::option_tests::default_corrupt_source_refuses_repeated_writes_without_recovery", |_| {
        UserDefaultConfig::set_option("confirmed".into(), "original".into()).unwrap();
        UserDefaultConfig::set_option("unrelated".into(), "preserved".into()).unwrap();
        let file = Config::file_("_default");
        let healthy = fs::read(&file).unwrap();
        let corrupt = b"[options]\nprivate-default-source = [\n";
        fs::write(&file, corrupt).unwrap();
        let first = UserDefaultConfig::set_option("confirmed".into(), "requested".into());
        let second = UserDefaultConfig::set_option("confirmed".into(), "requested".into());
        let preserved = fs::read(&file).map(|bytes| bytes == corrupt).unwrap_or(false);
        let cache_preserved = USER_DEFAULT_CONFIG.read().unwrap().0.get("confirmed") == "original";
        println!("OPTION_COMMIT_DEFAULT_READONLY=observed kind=write first_refused={} repeated_refused={} file_preserved={preserved} cache_preserved={cache_preserved}", first.is_err(), second.is_err());
        assert!(first.is_err() && second.is_err() && preserved && cache_preserved);
        assert!(!first.unwrap_err().to_string().contains("private-default-source"));
        fs::write(&file, healthy).unwrap();
        assert_eq!(UserDefaultConfig::set_option("confirmed".into(), "requested".into()).unwrap(), "requested");
        let stored = UserDefaultConfig::load();
        assert_eq!(stored.get("confirmed"), "requested");
        assert_eq!(stored.get("unrelated"), "preserved");
    });
}

#[test]
fn default_missing_peer_inheritance_does_not_recover_defaults() {
    in_private_process("config::option_tests::default_missing_peer_inheritance_does_not_recover_defaults", |_| {
        let file = Config::file_("_default");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        let source = b"[options]\nprivate-default-source = [\n";
        fs::write(&file, source).unwrap();
        let id = "peer-defaults-display-only";
        let path = PeerConfig::path(id);
        assert!(!path.exists());
        let value = PeerConfig::read_option(id, keys::OPTION_CUSTOM_FPS).unwrap();
        let preserved = fs::read(&file).map(|bytes| bytes == source).unwrap_or(false);
        println!("OPTION_COMMIT_DEFAULT_READONLY=observed kind=missing_peer inherited={} defaults_preserved={preserved} peer_absent={}", value == "30", !path.exists());
        assert!(preserved && value == "30" && !path.exists());
    });
}

#[test]
fn default_initial_denial_directory_and_missing_reads_preserve_sources() {
    in_private_process("config::option_tests::default_initial_denial_directory_and_missing_reads_preserve_sources", |_| {
        let file = Config::file_("_default");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        let source = b"[options]\ncustom-fps = '25'\n";
        fs::write(&file, source).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
        let native = fs::read(&file).unwrap_err();
        let initial = UserDefaultConfig::get_option(keys::OPTION_CUSTOM_FPS);
        let unchanged_mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777 == 0;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(native.kind(), io::ErrorKind::PermissionDenied);
        assert!(initial == "30" && unchanged_mode && fs::read(&file).unwrap() == source);
        USER_DEFAULT_CONFIG.write().unwrap().1 = Instant::now() - Duration::from_secs(2);
        assert_eq!(UserDefaultConfig::get_option(keys::OPTION_CUSTOM_FPS), "25");
        fs::remove_file(&file).unwrap();
        fs::create_dir(&file).unwrap();
        let child = file.join("preserved");
        fs::write(&child, source).unwrap();
        for _ in 0..2 {
            USER_DEFAULT_CONFIG.write().unwrap().1 = Instant::now() - Duration::from_secs(2);
            assert_eq!(UserDefaultConfig::get_option(keys::OPTION_CUSTOM_FPS), "25");
            assert_eq!(fs::read(&child).unwrap(), source);
        }
        fs::remove_file(child).unwrap();
        fs::remove_dir(&file).unwrap();
        USER_DEFAULT_CONFIG.write().unwrap().1 = Instant::now() - Duration::from_secs(2);
        assert_eq!(UserDefaultConfig::get_option(keys::OPTION_CUSTOM_FPS), "30");
        assert!(!file.exists());
        println!("OPTION_COMMIT_DEFAULT_READONLY=observed kind=controls denied_errno={} mode_unchanged={unchanged_mode} retry=true directory_preserved=true missing_not_created=true", native.raw_os_error().unwrap());
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

fn local_source_seed(tag: &str) -> LocalConfig {
    LocalConfig {
        remote_id: format!("host-{tag}"),
        kb_layout_type: format!("layout-{tag}"),
        fav: vec![format!("peer-{tag}")],
        options: [("selected".into(), tag.into()), ("unrelated".into(), format!("keep-{tag}"))].into(),
        ui_flutter: [("selected".into(), tag.into()), ("unrelated".into(), format!("keep-{tag}"))].into(),
    }
}

fn local_source_actions() -> [(&'static str, fn() -> crate::ResultType<()>); 5] {
    [
        ("history", || LocalConfig::set_remote_id("requested-host")),
        ("keyboard", || LocalConfig::set_kb_layout_type("Not ISO".into())),
        ("favorites", || LocalConfig::set_favorites(vec!["requested-peer".into()], true)),
        ("option", || LocalConfig::set_option("selected".into(), "requested".into())),
        ("flutter", || LocalConfig::set_flutter_option("selected".into(), "requested".into())),
    ]
}

fn local_source_expected(mut source: LocalConfig, action: &str) -> serde_json::Value {
    match action {
        "history" => source.remote_id = "requested-host".into(),
        "keyboard" => source.kb_layout_type = "Not ISO".into(),
        "favorites" => source.fav.push("requested-peer".into()),
        "option" => { source.options.insert("selected".into(), "requested".into()); }
        "flutter" => { source.ui_flutter.insert("selected".into(), "requested".into()); }
        _ => panic!("unknown local action"),
    }
    serde_json::to_value(source).unwrap()
}

#[test]
fn local_source_initial_and_direct_reads_preserve_corruption() {
    in_private_process("config::option_tests::local_source_initial_and_direct_reads_preserve_corruption", |_| {
        use std::os::unix::fs::MetadataExt;
        let file = Config::file_("_local");
        let parent = file.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        let readers: [(&str, fn()); 2] = [("initial", || { let _ = LocalConfig::load(); }), ("direct", || { let _ = LocalConfig::get_option_from_file("selected"); })];
        let mut all_preserved = true;
        for (kind, bytes) in [("syntax", b"[options]\nprivate-local-source = [\n".as_slice()), ("utf8", b"\xffprivate-local-source".as_slice())] {
            for (reader, read) in readers {
                fs::write(&file, bytes).unwrap();
                let before = fs::metadata(&file).unwrap();
                read();
                let preserved = fs::read(&file).map(|b| b == bytes).unwrap_or(false);
                let same_file = fs::metadata(&file).map(|s| (s.dev(), s.ino()) == (before.dev(), before.ino())).unwrap_or(false);
                println!("OPTION_COMMIT_LOCAL_SOURCE=observed kind={kind} reader={reader} file_preserved={preserved} same_file={same_file}");
                all_preserved &= preserved && same_file;
            }
        }
        assert!(all_preserved);
    });
}

#[test]
fn local_source_denial_refuses_every_mutation_and_allows_retry() {
    in_private_process("config::option_tests::local_source_denial_refuses_every_mutation_and_allows_retry", |_| {
        let source = local_source_seed("confirmed");
        let file = Config::file_("_local");
        let mut all_preserved = true;
        for (name, action) in local_source_actions() {
            store_path(file.clone(), &source).unwrap();
            *LOCAL_CONFIG.write().unwrap() = source.clone();
            let bytes = fs::read(&file).unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
            let native = fs::read(&file).unwrap_err();
            let result = action();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
            let preserved = fs::read(&file).unwrap() == bytes;
            let cache_preserved = serde_json::to_value(&*LOCAL_CONFIG.read().unwrap()).unwrap() == serde_json::to_value(&source).unwrap();
            assert_eq!(native.kind(), io::ErrorKind::PermissionDenied);
            println!("OPTION_COMMIT_LOCAL_SOURCE=observed kind=denial action={name} errno={} refused={} file_preserved={preserved} cache_preserved={cache_preserved}", native.raw_os_error().unwrap(), result.is_err());
            all_preserved &= result.is_err() && preserved && cache_preserved;
            store_path(file.clone(), &source).unwrap();
            *LOCAL_CONFIG.write().unwrap() = source.clone();
            action().unwrap();
            let stored: LocalConfig = toml::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
            assert_eq!(serde_json::to_value(stored).unwrap(), local_source_expected(source.clone(), name));
        }
        assert!(all_preserved);
    });
}

#[test]
fn local_source_corruption_refuses_repeated_mutations_without_recovery() {
    in_private_process("config::option_tests::local_source_corruption_refuses_repeated_mutations_without_recovery", |_| {
        let source = local_source_seed("confirmed");
        let file = Config::file_("_local");
        store_path(file.clone(), &source).unwrap();
        let mut all_preserved = true;
        for (kind, bytes) in [("syntax", b"[options]\nprivate-local-source = [\n".as_slice()), ("utf8", b"\xffprivate-local-source".as_slice())] {
            for (name, action) in local_source_actions() {
                *LOCAL_CONFIG.write().unwrap() = source.clone();
                fs::write(&file, bytes).unwrap();
                let first = action();
                let second = action();
                let preserved = fs::read(&file).map(|b| b == bytes).unwrap_or(false);
                let cache_preserved = serde_json::to_value(&*LOCAL_CONFIG.read().unwrap()).unwrap() == serde_json::to_value(&source).unwrap();
                println!("OPTION_COMMIT_LOCAL_SOURCE=observed kind={kind} action={name} first_refused={} repeated_refused={} file_preserved={preserved} cache_preserved={cache_preserved}", first.is_err(), second.is_err());
                if let Err(error) = first.as_ref() { assert!(!error.to_string().contains("private-local-source")); }
                all_preserved &= first.is_err() && second.is_err() && preserved && cache_preserved;
            }
        }
        assert!(all_preserved);
    });
}

#[test]
fn local_source_mutations_preserve_completed_external_changes() {
    in_private_process("config::option_tests::local_source_mutations_preserve_completed_external_changes", |_| {
        let cached = local_source_seed("cached");
        let external = local_source_seed("external");
        let file = Config::file_("_local");
        let mut all_preserved = true;
        for (name, action) in local_source_actions() {
            store_path(file.clone(), &external).unwrap();
            *LOCAL_CONFIG.write().unwrap() = cached.clone();
            action().unwrap();
            let stored: LocalConfig = toml::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
            let expected = local_source_expected(external.clone(), name);
            let file_current = serde_json::to_value(stored).unwrap() == expected;
            let cache_current = serde_json::to_value(&*LOCAL_CONFIG.read().unwrap()).unwrap() == expected;
            println!("OPTION_COMMIT_LOCAL_SOURCE=observed kind=external action={name} file_current={file_current} cache_current={cache_current}");
            all_preserved &= file_current && cache_current;
        }
        assert!(all_preserved);
    });
}

#[test]
fn local_source_idempotence_uses_durable_values_and_refreshes_cache() {
    in_private_process("config::option_tests::local_source_idempotence_uses_durable_values_and_refreshes_cache", |_| {
        use std::os::unix::fs::MetadataExt;
        let cached = local_source_seed("cached");
        let external = local_source_seed("external");
        let file = Config::file_("_local");
        let parent = file.parent().unwrap();
        let mut all_preserved = true;
        for (name, action) in local_source_actions() {
            let expected = local_source_expected(external.clone(), name);
            let durable: LocalConfig = serde_json::from_value(expected.clone()).unwrap();
            store_path(file.clone(), &durable).unwrap();
            *LOCAL_CONFIG.write().unwrap() = cached.clone();
            let before = fs::metadata(&file).unwrap();
            let bytes = fs::read(&file).unwrap();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o500)).unwrap();
            let result = action();
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            let same_file = fs::metadata(&file).unwrap().ino() == before.ino() && fs::read(&file).unwrap() == bytes;
            let cache_current = serde_json::to_value(&*LOCAL_CONFIG.read().unwrap()).unwrap() == expected;
            println!("OPTION_COMMIT_LOCAL_SOURCE=observed kind=idempotent action={name} success={} same_file={same_file} cache_current={cache_current}", result.is_ok());
            all_preserved &= result.is_ok() && same_file && cache_current;
        }
        assert!(all_preserved);
    });
}

#[test]
fn local_source_missing_noops_do_not_create_and_first_saves_work() {
    in_private_process("config::option_tests::local_source_missing_noops_do_not_create_and_first_saves_work", |_| {
        let file = Config::file_("_local");
        LocalConfig::set_remote_id("").unwrap();
        LocalConfig::set_kb_layout_type(String::new()).unwrap();
        LocalConfig::set_favorites(vec!["missing".into()], false).unwrap();
        LocalConfig::set_option("selected".into(), String::new()).unwrap();
        LocalConfig::set_flutter_option("selected".into(), String::new()).unwrap();
        assert!(!file.exists());
        for (name, action) in local_source_actions() {
            if file.exists() { fs::remove_file(&file).unwrap(); }
            *LOCAL_CONFIG.write().unwrap() = LocalConfig::default();
            action().unwrap();
            let stored: LocalConfig = toml::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
            assert_eq!(serde_json::to_value(stored).unwrap(), local_source_expected(LocalConfig::default(), name));
        }
        println!("OPTION_COMMIT_LOCAL_SOURCE=observed kind=controls missing_noops_absent=true first_saves=5");
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

#[test]
fn peer_retired_password_shapes_preserve_live_state_and_allow_explicit_cleanup() {
    in_private_process("config::option_tests::peer_retired_password_shapes_preserve_live_state_and_allow_explicit_cleanup", |_| {
        for (index, retired) in ["[]", "\"discard-me\"", "\"\"", "true", "42", "{ obsolete = [1, 2] }"].iter().enumerate() {
            for remembered in [false, true] {
                let id = format!("peer-retired-shape-{index}-{remembered}");
                let mut peer = PeerConfig::default();
                peer.info.platform = "Linux".into();
                peer.options.insert("alias".into(), "preserved".into());
                if remembered { peer.password_prs = b"fixture-current-peer-prs".to_vec(); }
                peer.store(&id).unwrap();
                let mut expected = PeerConfig::load_for_write(&id).unwrap();
                let path = PeerConfig::path(&id);
                let original = fs::read_to_string(&path).unwrap();
                let document: toml::Value = toml::from_str(&original).unwrap();
                assert!(document.get("password").is_none());
                fs::write(&path, format!("password = {retired}\n{original}")).unwrap();
                let old_bytes = fs::read(&path).unwrap();
                assert_eq!(PeerConfig::load_for_write(&id).unwrap(), expected);
                assert_eq!(fs::read(&path).unwrap(), old_bytes);
                PeerConfig::forget_password(&id).unwrap();
                expected.password_prs.clear();
                assert_eq!(PeerConfig::load_for_write(&id).unwrap(), expected);
                let document: toml::Value = toml::from_str(&fs::read_to_string(path).unwrap()).unwrap();
                assert!(document.get("password").is_none());
            }
        }
        println!("OPTION_COMMIT_PEER_RETIRED=observed kind=shapes formats=6 prs_states=2 live_state_preserved=true old_field_purged=true");
    });
}
