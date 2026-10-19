use super::*;
use crate::client::Interface;
use hbb_common::ResultType;

#[path = "../../scripts/fixtures/option-export-before-errors.rs"]
mod before;

#[path = "../../scripts/fixtures/voice-input-before-errors.rs"]
mod before_voice;

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
    let history_file = Config::file_("_local");
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
}
