use super::{
    session_read_local_dir_sync, session_read_local_empty_dirs_recursive_sync, SessionID,
};
use hbb_common::fs;
use serde_json::Value;
use std::{
    collections::BTreeSet,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
};

#[path = "../../scripts/fixtures/local-file-listing-before-errors.rs"]
mod before;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir()
            .join(format!("local-file-listing-{}-{nonce}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> String {
        self.0.to_str().unwrap().to_owned()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn compare_failure(path: String, expected_fragment: Option<&str>) {
    let id = SessionID::new_v4();
    let native = [
        fs::read_dir(&fs::get_path(&path), false).err().expect("native flat listing must fail").to_string(),
        fs::get_empty_dirs_recursive(&path, false).err().expect("native empty-directory listing must fail").to_string(),
    ];
    let old = [
        before::session_read_local_dir_sync(id, path.clone(), false),
        before::session_read_local_empty_dirs_recursive_sync(id, path.clone(), false),
    ];
    let current = [
        session_read_local_dir_sync(id, path.clone(), false).err().expect("flat export must retain the error").to_string(),
        session_read_local_empty_dirs_recursive_sync(id, path, false).err().expect("empty-directory export must retain the error").to_string(),
    ];
    assert_eq!(old, ["", ""], "the earlier exports erase actual native failures");
    assert_eq!(current, native, "both exports must retain the original native cause");
    if let Some(fragment) = expected_fragment {
        assert!(current.iter().all(|error| error.contains(fragment)));
    }
}

#[test]
fn listing_exports_preserve_filesystem_errors() {
    let fixture = Fixture::new();
    compare_failure(fixture.0.join("missing").to_str().unwrap().to_owned(), None);
    let source = fixture.0.join("source");
    std::fs::write(&source, b"retained").unwrap();
    compare_failure(source.join("child").to_str().unwrap().to_owned(), None);
    assert_eq!(std::fs::read(source).unwrap(), b"retained");
    let blocked = Fixture::new();
    std::fs::set_permissions(&blocked.0, std::fs::Permissions::from_mode(0)).unwrap();
    compare_failure(blocked.path(), Some("Permission denied"));
    println!("LOCAL_FILE_LISTING_COMPARISON=pass scenarios=missing,non-directory,permission exports=2 old=empty-success current=native-error");
}

#[test]
fn listing_exports_report_entry_budget_and_recover_at_exact_boundary() {
    let fixture = Fixture::new();
    for index in 0..fs::DEFAULT_FILE_TRANSFER_MAX_FILES {
        std::fs::File::create(fixture.0.join(format!("entry-{index}"))).unwrap();
    }
    let extra = fixture.0.join(".excluded-entry");
    std::fs::write(&extra, b"retained hidden bytes").unwrap();
    compare_failure(fixture.path(), Some("file enumeration budget exceeded"));
    assert_eq!(std::fs::read(&extra).unwrap(), b"retained hidden bytes");

    std::fs::remove_file(extra).unwrap();
    let id = SessionID::new_v4();
    let flat: Value = serde_json::from_str(
        &session_read_local_dir_sync(id, fixture.path(), false).unwrap(),
    ).unwrap();
    assert_eq!(flat["path"], fixture.path());
    assert_eq!(flat["entries"].as_array().unwrap().len(), fs::DEFAULT_FILE_TRANSFER_MAX_FILES);
    let empty: Value = serde_json::from_str(
        &session_read_local_empty_dirs_recursive_sync(id, fixture.path(), false).unwrap(),
    ).unwrap();
    assert_eq!(empty, serde_json::json!([]));
    assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), fs::DEFAULT_FILE_TRANSFER_MAX_FILES);
    println!("LOCAL_FILE_LISTING_COMPARISON=pass scenarios=entry-budget exports=2 old=empty-success current=native-error recovery=exact-boundary");
}

fn entry_names(directory: &Value) -> BTreeSet<&str> {
    directory["entries"].as_array().unwrap().iter()
        .map(|entry| entry["name"].as_str().unwrap()).collect()
}

fn directory_paths(directories: &Value) -> BTreeSet<&str> {
    directories.as_array().unwrap().iter()
        .map(|directory| {
            assert!(directory["entries"].as_array().unwrap().is_empty());
            directory["path"].as_str().unwrap()
        }).collect()
}

#[test]
fn listing_exports_preserve_empty_and_hidden_success_json() {
    let fixture = Fixture::new();
    let id = SessionID::new_v4();
    let fixture_path = fixture.path();
    let flat: Value = serde_json::from_str(
        &session_read_local_dir_sync(id, fixture.path(), false).unwrap(),
    ).unwrap();
    assert_eq!(flat["id"], 0);
    assert_eq!(flat["path"], fixture.path());
    assert!(entry_names(&flat).is_empty());
    let empty: Value = serde_json::from_str(
        &session_read_local_empty_dirs_recursive_sync(id, fixture.path(), false).unwrap(),
    ).unwrap();
    assert_eq!(directory_paths(&empty), BTreeSet::from([fixture_path.as_str()]));

    std::fs::create_dir(fixture.0.join("visible")).unwrap();
    std::fs::create_dir(fixture.0.join(".hidden")).unwrap();
    std::fs::write(fixture.0.join("payload"), b"retained").unwrap();
    for include_hidden in [false, true] {
        let flat: Value = serde_json::from_str(
            &session_read_local_dir_sync(id, fixture.path(), include_hidden).unwrap(),
        ).unwrap();
        let old_flat: Value = serde_json::from_str(
            &before::session_read_local_dir_sync(id, fixture.path(), include_hidden),
        ).unwrap();
        assert_eq!(entry_names(&flat), entry_names(&old_flat));
        assert_eq!(entry_names(&flat).len(), if include_hidden { 3 } else { 2 });
        assert_eq!(flat["path"], fixture.path());
        let empty: Value = serde_json::from_str(
            &session_read_local_empty_dirs_recursive_sync(id, fixture.path(), include_hidden).unwrap(),
        ).unwrap();
        let old_empty: Value = serde_json::from_str(
            &before::session_read_local_empty_dirs_recursive_sync(id, fixture.path(), include_hidden),
        ).unwrap();
        assert_eq!(directory_paths(&empty), directory_paths(&old_empty));
        assert_eq!(directory_paths(&empty).len(), if include_hidden { 2 } else { 1 });
    }
    assert_eq!(std::fs::read(fixture.0.join("payload")).unwrap(), b"retained");
    println!("LOCAL_FILE_LISTING_SUCCESS=pass empty=valid-json hidden=preserved entries=preserved payload=unchanged");
}
