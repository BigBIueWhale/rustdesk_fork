use super::*;
use hbb_common::ResultType;

#[path = "../../scripts/fixtures/option-export-before-errors.rs"]
mod before;

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
            if let Some(start) = line.find("OPTION_EXPORT_") {
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
    let file_preserved = std::fs::read(file).unwrap() == original;
    println!("OPTION_EXPORT_NATIVE=observed refused={refused} missing_receiver={missing_receiver} cache_preserved={cache_preserved} memory_preserved={memory_preserved} file_preserved={file_preserved}");
    assert!(refused && missing_receiver && cache_preserved && memory_preserved && file_preserved);
}
