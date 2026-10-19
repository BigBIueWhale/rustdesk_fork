use super::*;
use crate::client::Interface;
use hbb_common::ResultType;

#[path = "../../scripts/fixtures/option-export-before-errors.rs"]
mod before;

#[path = "../../scripts/fixtures/voice-input-before-errors.rs"]
mod before_voice;

#[allow(unused_must_use)]
#[path = "../../scripts/fixtures/peer-preference-export-before-errors.rs"]
mod before_peer;

#[path = "../../scripts/fixtures/trackpad-store-before-errors.rs"]
mod before_trackpad;

// FRB treats a unit-returning export as a successful completion. This adapter
// lets the same behavioral probe execute the pre-fix and fallible exports.
trait ExportOutcome {
    fn result(self) -> ResultType<String>;
}

impl ExportOutcome for () {
    fn result(self) -> ResultType<String> {
        Ok(String::new())
    }
}

impl ExportOutcome for ResultType<()> {
    fn result(self) -> ResultType<String> {
        self.map(|()| String::new())
    }
}

#[test]
fn native_option_export_preserves_refusal_and_missing_receiver() {
    const ROOT_ENV: &str = "RUSTDESK_OPTION_EXPORT_TEST_ROOT";
    let Some(root) = std::env::var_os(ROOT_ENV) else {
        let root = std::env::temp_dir().join(format!("option-export-{}", hbb_common::uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["ui_interface::option_tests::native_option_export_preserves_refusal_and_missing_receiver", "--exact", "--color", "never", "--test-threads=1", "--nocapture"])
            .env(ROOT_ENV, &root)
            .env("XDG_CONFIG_HOME", &root)
            .output().unwrap();
        std::fs::remove_dir_all(&root).unwrap();
        assert!(output.stdout.len() + output.stderr.len() <= 16384);
        for line in String::from_utf8(output.stdout).unwrap().lines() {
            if let Some(start) = line.find("OPTION_EXPORT_")
                .or_else(|| line.find("VOICE_INPUT_EXPORT_"))
                .or_else(|| line.find("LAST_PEER_EXPORT_"))
                .or_else(|| line.find("PEER_PREF_EXPORT_"))
                .or_else(|| line.find("TRACKPAD_EXPORT_"))
            {
                println!("{}", &line[start..]);
            }
        }
        assert!(output.status.success(), "native option export worker failed: {}", String::from_utf8_lossy(&output.stderr));
        return;
    };
    let root = std::path::PathBuf::from(root);
    assert_ne!(unsafe { hbb_common::libc::geteuid() }, 0);
    let file = config::Config2::file();
    assert!(file.starts_with(&root));
    Config::set_option("enable-abr".into(), "N".into()).unwrap();
    OPTIONS.lock().unwrap().insert("enable-abr".into(), "N".into());
    let original = std::fs::read(&file).unwrap();

    let before_refused = before::main_set_option("not-an-option".into(), "fixture-value".into()).result().is_err();
    let before_missing_receiver = before::main_set_option("enable-abr".into(), "Y".into()).result().is_err();
    let before_preserved = OPTIONS.lock().unwrap().get("enable-abr").map(String::as_str) == Some("N")
        && Config::get_option("enable-abr") == "N"
        && std::fs::read(&file).unwrap() == original;
    println!("OPTION_EXPORT_BEFORE=observed refused={before_refused} missing_receiver={before_missing_receiver} state_preserved={before_preserved}");
    assert!(!before_refused && !before_missing_receiver && before_preserved);

    let refused = crate::flutter_ffi::main_set_option("not-an-option".into(), "fixture-value".into()).result().is_err();
    let missing_receiver = crate::flutter_ffi::main_set_option("enable-abr".into(), "Y".into()).result().is_err();
    let cache_preserved = OPTIONS.lock().unwrap().get("enable-abr").map(String::as_str) == Some("N");
    let memory_preserved = Config::get_option("enable-abr") == "N";
    let file_preserved = std::fs::read(&file).unwrap() == original;
    println!("OPTION_EXPORT_NATIVE=observed refused={refused} missing_receiver={missing_receiver} cache_preserved={cache_preserved} memory_preserved={memory_preserved} file_preserved={file_preserved}");
    assert!(refused && missing_receiver && cache_preserved && memory_preserved && file_preserved);

    crate::flutter_ffi::set_voice_call_input_device(false, "viewer-microphone".into()).result().unwrap();
    let viewer_selected = crate::audio_service::get_voice_call_input_device().as_deref() == Some("viewer-microphone");
    let before_voice_failure = before_voice::set_voice_call_input_device(true, "cm-microphone".into()).result().is_err();
    let before_read_default = before_voice::get_voice_call_input_device(true).is_empty();
    let before_viewer_preserved = crate::audio_service::get_voice_call_input_device().as_deref() == Some("viewer-microphone");
    println!("VOICE_INPUT_EXPORT_BEFORE=observed failure_reported={before_voice_failure} failed_read_default={before_read_default} viewer_preserved={before_viewer_preserved}");
    assert!(!before_voice_failure && before_read_default && before_viewer_preserved);
    let voice_failure = crate::flutter_ffi::set_voice_call_input_device(true, "cm-microphone".into()).result().is_err();
    let read_failure = crate::flutter_ffi::get_voice_call_input_device(true).is_err();
    let viewer_preserved = crate::audio_service::get_voice_call_input_device().as_deref() == Some("viewer-microphone");
    let config_preserved = std::fs::read(&file).unwrap() == original;
    println!("VOICE_INPUT_EXPORT_NATIVE=observed failure_reported={voice_failure} read_failure_reported={read_failure} viewer_selected={viewer_selected} viewer_preserved={viewer_preserved} config_preserved={config_preserved}");
    assert!(voice_failure && read_failure && viewer_selected && viewer_preserved && config_preserved);

    use std::os::unix::fs::PermissionsExt;
    LocalConfig::set_remote_id("127.0.0.1:24001").unwrap();
    let config_file = Config::file();
    let mut history_name = config_file.file_stem().unwrap().to_os_string();
    history_name.push("_local.toml");
    let history_file = config_file.with_file_name(history_name);
    assert!(history_file.starts_with(&root));
    let history_parent = history_file.parent().unwrap();
    let original_history = std::fs::read(&history_file).unwrap();
    let peer = "127.0.0.1:24002";
    let owner = crate::flutter_ffi::SessionID::new_v4();
    let session_id = crate::flutter_ffi::SessionID::new_v4();
    std::fs::set_permissions(history_parent, std::fs::Permissions::from_mode(0o500)).unwrap();
    let added = crate::flutter_ffi::session_add_sync(
        session_id, owner, peer.into(), false, false, false, false, false,
        "explicit-password".into(), None,
    );
    let history_preserved = crate::flutter_ffi::main_get_last_remote_id() == "127.0.0.1:24001"
        && std::fs::read(&history_file).unwrap() == original_history;
    std::fs::set_permissions(history_parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let session = crate::flutter::sessions::get_session_by_session_id(&session_id).unwrap();
    let session_admitted = added.0.is_empty()
        && crate::flutter::sessions::session_has_client_owner(&session_id, &owner)
        && session.get_connect_password() == "explicit-password";
    let no_peer_started = session.sender.read().unwrap().is_none();
    let duplicate = crate::flutter_ffi::session_add_sync(
        session_id, owner, peer.into(), false, false, false, false, false,
        "other-password".into(), None,
    );
    let duplicate_refused = !duplicate.0.is_empty()
        && session.get_connect_password() == "explicit-password";
    let duplicate_history_preserved = crate::flutter_ffi::main_get_last_remote_id() == "127.0.0.1:24001"
        && std::fs::read(&history_file).unwrap() == original_history;
    let retired = crate::flutter::sessions::remove_session_by_exact_ui_owner(&session_id, &owner).unwrap();
    assert!(std::sync::Arc::ptr_eq(&retired, &session));
    drop(retired);
    drop(session);
    let retry_id = crate::flutter_ffi::SessionID::new_v4();
    let retried = crate::flutter_ffi::session_add_sync(
        retry_id, owner, peer.into(), false, false, false, false, false,
        "explicit-password".into(), None,
    );
    let durable: hbb_common::toml::Value =
        hbb_common::toml::from_str(&std::fs::read_to_string(&history_file).unwrap()).unwrap();
    let retry_persisted = retried.0.is_empty()
        && crate::flutter_ffi::main_get_last_remote_id() == peer
        && durable.get("remote_id").and_then(hbb_common::toml::Value::as_str) == Some(peer);
    let retired = crate::flutter::sessions::remove_session_by_exact_ui_owner(&retry_id, &owner).unwrap();
    assert!(retired.sender.read().unwrap().is_none());
    drop(retired);
    println!("LAST_PEER_EXPORT_NATIVE=observed history_preserved={history_preserved} session_admitted={session_admitted} no_peer_started={no_peer_started} duplicate_refused={duplicate_refused} duplicate_history_preserved={duplicate_history_preserved} retry_persisted={retry_persisted}");
    assert!(history_preserved && session_admitted && no_peer_started && duplicate_refused && duplicate_history_preserved && retry_persisted);
    peer_preferences_commit_before_cache_and_command(&root);
    trackpad_preference_commits_before_publication(&root);
}

fn trackpad_preference_commits_before_publication(root: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let peer = "127.0.0.1:24004";
    let peers = Config::file().parent().unwrap().join("peers");
    assert!(peers.starts_with(root));
    let old_files: Vec<_> = std::fs::read_dir(&peers).unwrap().map(|e| e.unwrap().path()).collect();
    let mut config = PeerConfig::default();
    config.trackpad_speed = 120;
    config.password_prs = b"preserved-trackpad-prs".to_vec();
    config.info.username = "session-user".into();
    config.options.insert("unrelated".into(), "preserved".into());
    config.store(peer).unwrap();
    let files: Vec<_> = std::fs::read_dir(&peers).unwrap().map(|e| e.unwrap().path())
        .filter(|p| !old_files.contains(p)).collect();
    assert_eq!(files.len(), 1);
    let file = &files[0];
    let old_peer = "127.0.0.1:24005";
    config.store(old_peer).unwrap();
    let old_peer_files: Vec<_> = std::fs::read_dir(&peers).unwrap().map(|e| e.unwrap().path())
        .filter(|p| !old_files.contains(p) && p != file).collect();
    assert_eq!(old_peer_files.len(), 1);
    let old_peer_file = &old_peer_files[0];
    let old_original = std::fs::read(old_peer_file).unwrap();
    let owner = crate::flutter_ffi::SessionID::new_v4();
    let old_owner = crate::flutter_ffi::SessionID::new_v4();
    let old_id = crate::flutter_ffi::SessionID::new_v4();
    let id = crate::flutter_ffi::SessionID::new_v4();
    for (session_id, client_owner, target) in [(old_id, old_owner, old_peer), (id, owner, peer)] {
        assert!(crate::flutter_ffi::session_add_sync(
            session_id, client_owner, target.into(), false, false, false, false, false,
            "explicit-password".into(), None,
        ).0.is_empty());
    }
    let session = crate::flutter::sessions::get_session_by_session_id(&id).unwrap();
    for value in [10, 1000, 120] {
        assert_eq!(crate::flutter_ffi::session_set_trackpad_speed(id, value).unwrap(), value);
        assert_eq!(PeerConfig::load_for_write(peer).unwrap().trackpad_speed, value);
        assert_eq!(session.get_trackpad_speed(), value);
    }
    let mut config = PeerConfig::load_for_write(peer).unwrap();
    config.info.username = "file-user".into();
    config.store(peer).unwrap();
    let original = std::fs::read(file).unwrap();
    std::fs::set_permissions(&peers, std::fs::Permissions::from_mode(0o500)).unwrap();
    before_trackpad::session_set_trackpad_speed(old_id, 235);
    let old_published = crate::flutter_ffi::session_get_trackpad_speed(old_id) == Some(235);
    let old_file_preserved = std::fs::read(old_peer_file).unwrap() == old_original;
    println!("TRACKPAD_EXPORT_BEFORE=observed normal_return=true cache_without_commit={old_published} file_preserved={old_file_preserved}");
    assert!(old_published && old_file_preserved);
    let failed = crate::flutter_ffi::session_set_trackpad_speed(id, 235).is_err();
    let cache_preserved = session.get_trackpad_speed() == 120;
    let file_preserved = std::fs::read(file).unwrap() == original;
    std::fs::set_permissions(&peers, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(crate::flutter_ffi::session_set_trackpad_speed(id, 235).unwrap(), 235);
    let stored = PeerConfig::load_for_write(peer).unwrap();
    let retry_durable = stored.trackpad_speed == 235 && session.get_trackpad_speed() == 235;
    let unrelated_preserved = stored.info.username == "file-user"
        && session.lc.read().unwrap().info.username == "session-user"
        && stored.password_prs == b"preserved-trackpad-prs"
        && stored.options.get("unrelated").map(String::as_str) == Some("preserved");
    let original = std::fs::read(file).unwrap();
    std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o000)).unwrap();
    let unreadable_refused = crate::flutter_ffi::session_set_trackpad_speed(id, 240).is_err();
    assert_eq!(session.get_trackpad_speed(), 235);
    std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(std::fs::read(file).unwrap(), original);
    assert_eq!(crate::flutter_ffi::session_set_trackpad_speed(id, 240).unwrap(), 240);
    assert_eq!(PeerConfig::load_for_write(peer).unwrap().trackpad_speed, 240);
    let original = std::fs::read(file).unwrap();
    let bounds_refused = [9, 1001].into_iter().all(|value| crate::flutter_ffi::session_set_trackpad_speed(id, value).is_err());
    let missing_refused = crate::flutter_ffi::session_set_trackpad_speed(crate::flutter_ffi::SessionID::new_v4(), 240).is_err();
    assert_eq!(std::fs::read(file).unwrap(), original);
    assert_eq!(session.get_trackpad_speed(), 240);
    for (session_id, client_owner) in [(old_id, old_owner), (id, owner)] {
        let retired = crate::flutter::sessions::remove_session_by_exact_ui_owner(&session_id, &client_owner).unwrap();
        assert!(retired.sender.read().unwrap().is_none());
        drop(retired);
    }
    drop(session);
    println!("TRACKPAD_EXPORT_NATIVE=observed failure_reported={failed} cache_preserved={cache_preserved} file_preserved={file_preserved} retry_durable={retry_durable} unrelated_preserved={unrelated_preserved} unreadable_refused={unreadable_refused} bounds_refused={bounds_refused} missing_session_refused={missing_refused} no_peer_started=true cleanup=joined");
    assert!(failed && cache_preserved && file_preserved && retry_durable && unrelated_preserved && unreadable_refused && bounds_refused && missing_refused);
}

fn peer_preferences_commit_before_cache_and_command(root: &std::path::Path) {
    use hbb_common::{config::PeerConfig, futures::FutureExt, message_proto::{message, misc}};
    use std::os::unix::fs::PermissionsExt;
    let peer = "127.0.0.1:24003";
    let owner = crate::flutter_ffi::SessionID::new_v4();
    let id = crate::flutter_ffi::SessionID::new_v4();
    let mut config = PeerConfig::default();
    config.password_prs = b"preserved-prs".to_vec();
    config.info.username = "session-user".into();
    config.options.insert("unrelated".into(), "preserved".into());
    config.store(peer).unwrap();
    let added = crate::flutter_ffi::session_add_sync(
        id, owner, peer.into(), false, false, false, false, false,
        "explicit-password".into(), None,
    );
    assert!(added.0.is_empty());
    assert!(crate::flutter::sessions::session_has_client_owner(&id, &owner));
    let session = crate::flutter::sessions::get_session_by_session_id(&id).unwrap();
    assert!(session.sender.read().unwrap().is_none());
    let (sender, mut receiver) = crate::client::viewer_command_channel();
    *session.sender.write().unwrap() = Some(sender);
    let mut command = |quality, fps| {
        let data = receiver.recv().now_or_never().unwrap().unwrap().unwrap();
        let crate::client::Data::Message(message) = data else { panic!("unexpected command") };
        let Some(message::Union::Misc(misc)) = message.union else { panic!("missing misc") };
        let Some(misc::Union::Option(option)) = misc.union else { panic!("missing option") };
        assert_eq!((option.custom_image_quality, option.custom_fps), (quality << 8, fps));
    };
    assert_eq!(crate::flutter_ffi::session_set_custom_image_quality(id, 80).unwrap(), 80);
    assert_eq!(crate::flutter_ffi::session_set_custom_fps(id, 45).unwrap(), 45);
    command(80, 0);
    command(0, 45);
    drop(command);
    // The file can contain newer metadata than this live session. A preference
    // commit must preserve both, rather than publish the entire disk snapshot.
    let mut config = PeerConfig::load_for_write(peer).unwrap();
    config.info.username = "file-user".into();
    config.store(peer).unwrap();
    let peers = Config::file().parent().unwrap().join("peers");
    assert!(peers.starts_with(root));
    let files: Vec<_> = std::fs::read_dir(&peers).unwrap().map(|entry| entry.unwrap().path()).collect();
    assert_eq!(files.len(), 1);
    let file = &files[0];
    let original = std::fs::read(file).unwrap();
    std::fs::set_permissions(&peers, std::fs::Permissions::from_mode(0o500)).unwrap();
    before_peer::session_set_custom_image_quality(id, 90);
    before_peer::session_set_custom_fps(id, 50);
    println!("PEER_PREF_EXPORT_BEFORE=observed normal_quality_return=true normal_fps_return=true");
    let failure_reported = crate::flutter_ffi::session_set_custom_image_quality(id, 90).is_err()
        && crate::flutter_ffi::session_set_custom_fps(id, 50).is_err();
    let cache_preserved = session.get_custom_image_quality() == [80]
        && session.get_option("custom-fps".into()) == "45";
    let volatile_fps_preserved = *session.lc.read().unwrap().custom_fps.lock().unwrap() == Some(45);
    let file_preserved = std::fs::read(file).unwrap() == original;
    let no_failed_command = receiver.recv().now_or_never().is_none();
    std::fs::set_permissions(&peers, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(crate::flutter_ffi::session_set_custom_image_quality(id, 90).unwrap(), 90);
    assert_eq!(crate::flutter_ffi::session_set_custom_fps(id, 50).unwrap(), 50);
    for (quality, fps) in [(90 << 8, 0), (0, 50)] {
        let crate::client::Data::Message(message) = receiver.recv().now_or_never().unwrap().unwrap().unwrap()
            else { panic!("unexpected retry command") };
        let Some(message::Union::Misc(misc)) = message.union else { panic!("missing misc") };
        let Some(misc::Union::Option(option)) = misc.union else { panic!("missing option") };
        assert_eq!((option.custom_image_quality, option.custom_fps), (quality, fps));
    }
    let stored = PeerConfig::load_for_write(peer).unwrap();
    let retry_durable = stored.image_quality == "custom" && stored.custom_image_quality == [90]
        && stored.options.get("custom-fps").map(String::as_str) == Some("50")
        && session.get_custom_image_quality() == [90]
        && session.get_option("custom-fps".into()) == "50";
    let runtime_metadata_preserved = session.lc.read().unwrap().info.username == "session-user"
        && stored.info.username == "file-user" && stored.password_prs == b"preserved-prs"
        && stored.options.get("unrelated").map(String::as_str) == Some("preserved");
    let original = std::fs::read(file).unwrap();
    std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o000)).unwrap();
    let unreadable_refused = crate::flutter_ffi::session_set_custom_image_quality(id, 95).is_err()
        && crate::flutter_ffi::session_set_custom_fps(id, 55).is_err();
    std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(std::fs::read(file).unwrap(), original);
    assert_eq!(session.get_custom_image_quality(), [90]);
    assert_eq!(*session.lc.read().unwrap().custom_fps.lock().unwrap(), Some(50));
    assert!(receiver.recv().now_or_never().is_none());
    let bounds_refused = [9, 4096].into_iter().all(|value| crate::flutter_ffi::session_set_custom_image_quality(id, value).is_err())
        && [4, 121].into_iter().all(|fps| crate::flutter_ffi::session_set_custom_fps(id, fps).is_err());
    let missing = crate::flutter_ffi::SessionID::new_v4();
    let missing_session_refused = crate::flutter_ffi::session_set_custom_image_quality(missing, 95).is_err()
        && crate::flutter_ffi::session_set_custom_fps(missing, 55).is_err();
    assert_eq!(std::fs::read(file).unwrap(), original);
    assert!(receiver.recv().now_or_never().is_none());
    session.sender.write().unwrap().take();
    drop(receiver);
    let retired = crate::flutter::sessions::remove_session_by_exact_ui_owner(&id, &owner).unwrap();
    assert!(std::sync::Arc::ptr_eq(&retired, &session));
    drop(retired);
    drop(session);
    println!("PEER_PREF_EXPORT_NATIVE=observed failure_reported={failure_reported} cache_preserved={cache_preserved} volatile_fps_preserved={volatile_fps_preserved} file_preserved={file_preserved} no_failed_command={no_failed_command} retry_durable={retry_durable} runtime_metadata_preserved={runtime_metadata_preserved} unreadable_refused={unreadable_refused} bounds_refused={bounds_refused} missing_session_refused={missing_session_refused} cleanup=joined");
    assert!(failure_reported && cache_preserved && volatile_fps_preserved && file_preserved
        && no_failed_command && retry_durable && runtime_metadata_preserved && unreadable_refused
        && bounds_refused && missing_session_refused);
}
