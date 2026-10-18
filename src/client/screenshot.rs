#[cfg(not(any(target_os = "android", target_os = "ios")))]
use crate::clipboard::copy_screenshot_to_clipboard;
use hbb_common::ResultType;
use std::convert::TryFrom;

pub enum ScreenshotAction {
    SaveAs(String),
    CopyToClipboard,
    Discard,
}

impl TryFrom<&str> for ScreenshotAction {
    type Error = hbb_common::anyhow::Error;

    fn try_from(value: &str) -> ResultType<Self> {
        if let Some(path) = value.strip_prefix("0:").filter(|path| !path.is_empty()) {
            return Ok(Self::SaveAs(path.to_owned()));
        }
        match value {
            "1" => Ok(Self::CopyToClipboard),
            "2" => Ok(Self::Discard),
            _ => hbb_common::bail!("Invalid screenshot action"),
        }
    }
}

impl Into<String> for ScreenshotAction {
    fn into(self) -> String {
        match self {
            Self::SaveAs(p) => format!("0:{p}"),
            Self::CopyToClipboard => "1".to_owned(),
            Self::Discard => "2".to_owned(),
        }
    }
}

fn handle_screenshot_(data: bytes::Bytes, action: String) -> ResultType<()> {
    match ScreenshotAction::try_from(action.as_str())? {
        ScreenshotAction::SaveAs(p) => {
            hbb_common::fs::write_user_file_atomically(std::path::Path::new(&p), data.as_ref())?;
        }
        ScreenshotAction::CopyToClipboard => {
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            {
                copy_screenshot_to_clipboard(data)?;
            }
        }
        ScreenshotAction::Discard => {}
    }
    Ok(())
}

pub fn handle_screenshot(data: bytes::Bytes, action: String) -> String {
    match handle_screenshot_(data, action) {
        Ok(()) => "".to_owned(),
        Err(e) => e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{convert::TryFrom, path::PathBuf};

    fn output_directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "rustdesk-screenshot-action-{}", hbb_common::uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn malformed_actions_are_rejected() {
        let mut outcomes = Vec::new();
        for action in ["", "0", "0:", "1trailing", "2trailing", "3", " ", " 1", "1 "] {
            let refused = ScreenshotAction::try_from(action).is_err();
            println!("SCREENSHOT_ACTION_PARSE=observed action={action:?} refused={refused}");
            outcomes.push(refused);
        }
        assert!(outcomes.into_iter().all(|refused| refused));
    }

    #[test]
    fn malformed_save_selectors_preserve_the_destination() {
        let root = output_directory();
        let path = root.join("screen-שלום.png");
        let mut outcomes = Vec::new();
        for (kind, separator) in [("ascii", "x"), ("unicode", "💥")] {
            std::fs::write(&path, b"original").unwrap();
            let error = handle_screenshot(
                bytes::Bytes::from_static(b"new image"),
                format!("0{separator}{}", path.to_str().unwrap()),
            );
            let refused = !error.is_empty();
            let unchanged = std::fs::read(&path).unwrap() == b"original";
            println!("SCREENSHOT_ACTION_SAVE=observed separator={kind} refused={refused} unchanged={unchanged}");
            outcomes.push(refused && unchanged);
        }
        std::fs::remove_dir_all(&root).unwrap();
        assert!(outcomes.into_iter().all(|passed| passed));
    }

    #[test]
    fn canonical_actions_round_trip_without_altering_paths() {
        for action in ["0:/tmp/נוף:a.png", "0:C:\\Screens\\image.png", "1", "2"] {
            let decoded = ScreenshotAction::try_from(action).unwrap();
            let encoded: String = decoded.into();
            assert_eq!(encoded, action);
        }
    }

    #[test]
    fn valid_save_discard_and_io_error_preserve_file_behavior() {
        let root = output_directory();
        let path = root.join("screen-שלום.png");
        let save = format!("0:{}", path.to_str().unwrap());
        assert!(handle_screenshot(bytes::Bytes::from_static(b"first"), save.clone()).is_empty());
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        assert!(handle_screenshot(bytes::Bytes::from_static(b"replacement"), save).is_empty());
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        assert!(handle_screenshot(bytes::Bytes::from_static(b"discarded"), "2".to_owned()).is_empty());
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        let missing = root.join("absent/screen.png");
        let error = handle_screenshot(
            bytes::Bytes::from_static(b"must not appear"),
            format!("0:{}", missing.to_str().unwrap()),
        );
        assert!(!error.is_empty());
        assert!(!missing.exists());
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn save_replaces_symlink_without_changing_its_target() {
        let root = output_directory();
        let target = root.join("target.png");
        let selected = root.join("selected.png");
        std::fs::write(&target, b"original").unwrap();
        std::os::unix::fs::symlink(&target, &selected).unwrap();
        let error = handle_screenshot(
            bytes::Bytes::from_static(b"replacement image"),
            format!("0:{}", selected.to_str().unwrap()),
        );
        let target_preserved = std::fs::read(&target).unwrap() == b"original";
        let selected_regular = std::fs::symlink_metadata(&selected).unwrap().is_file();
        let selected_exact = std::fs::read(&selected).unwrap() == b"replacement image";
        println!("SCREENSHOT_SAVE_SYMLINK=observed success={} target_preserved={target_preserved} selected_regular={selected_regular} selected_exact={selected_exact}", error.is_empty());
        std::fs::remove_dir_all(&root).unwrap();
        assert!(error.is_empty());
        assert!(target_preserved && selected_regular && selected_exact);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn save_replaces_hard_link_without_changing_alias_or_open_reader() {
        use std::io::Read;
        let root = output_directory();
        let alias = root.join("alias.png");
        let selected = root.join("selected.png");
        std::fs::write(&alias, b"original").unwrap();
        std::fs::hard_link(&alias, &selected).unwrap();
        let mut reader = std::fs::File::open(&selected).unwrap();
        let error = handle_screenshot(
            bytes::Bytes::from_static(b"replacement image"),
            format!("0:{}", selected.to_str().unwrap()),
        );
        let alias_preserved = std::fs::read(&alias).unwrap() == b"original";
        let mut retained = Vec::new();
        reader.read_to_end(&mut retained).unwrap();
        let reader_preserved = retained == b"original";
        let selected_exact = std::fs::read(&selected).unwrap() == b"replacement image";
        println!("SCREENSHOT_SAVE_HARDLINK=observed success={} alias_preserved={alias_preserved} reader_preserved={reader_preserved} selected_exact={selected_exact}", error.is_empty());
        drop(reader);
        std::fs::remove_dir_all(&root).unwrap();
        assert!(error.is_empty());
        assert!(alias_preserved && reader_preserved && selected_exact);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn save_write_failure_preserves_existing_destination() {
        use hbb_common::libc;
        if std::env::var("RUSTDESK_SCREENSHOT_FILE_LIMIT_CHILD").as_deref() != Ok("1") {
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "client::screenshot::tests::save_write_failure_preserves_existing_destination",
                    "--exact", "--color", "never", "--test-threads=1", "--show-output",
                ])
                .env("RUSTDESK_SCREENSHOT_FILE_LIMIT_CHILD", "1")
                .output().unwrap();
            assert!(child.stdout.len() + child.stderr.len() <= 16384);
            for line in std::str::from_utf8(&child.stdout).unwrap().lines() {
                if line.starts_with("SCREENSHOT_SAVE_") {
                    println!("{line}");
                }
            }
            assert!(child.status.success(), "file-limit child failed: {}", String::from_utf8_lossy(&child.stderr));
            return;
        }
        let root = output_directory();
        let selected = root.join("selected.png");
        std::fs::write(&selected, b"original").unwrap();
        let mut old_limit = unsafe { std::mem::zeroed::<libc::rlimit>() };
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut old_limit) }, 0);
        let old_signal = unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) };
        assert_ne!(old_signal, libc::SIG_ERR);
        let limited = libc::rlimit { rlim_cur: 2, rlim_max: old_limit.rlim_max };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &limited) }, 0);
        let error = handle_screenshot(
            bytes::Bytes::from_static(b"replacement image"),
            format!("0:{}", selected.to_str().unwrap()),
        );
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &old_limit) }, 0);
        assert_ne!(unsafe { libc::signal(libc::SIGXFSZ, old_signal) }, libc::SIG_ERR);
        let native_limit_error = error.contains(&format!("os error {}", libc::EFBIG));
        let destination_preserved = std::fs::read(&selected).unwrap() == b"original";
        let no_temporary_entries = std::fs::read_dir(&root).unwrap().count() == 1;
        println!("SCREENSHOT_SAVE_LIMIT=observed error_returned={} native_efbig={native_limit_error} destination_preserved={destination_preserved} no_temporary_entries={no_temporary_entries}", !error.is_empty());
        std::fs::remove_dir_all(&root).unwrap();
        assert!(native_limit_error && destination_preserved && no_temporary_entries);
    }
}
