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
            std::fs::write(p, data)?;
        }
        ScreenshotAction::CopyToClipboard => {
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            {
                copy_screenshot_to_clipboard(data);
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
}
