use super::{PrivacyMode, PrivacyModeConnectionOwner, PrivacyModeState};
use hbb_common::{anyhow::anyhow, ResultType};

extern "C" {
    fn MacSetPrivacyMode(on: bool) -> bool;
}

pub const PRIVACY_MODE_IMPL: &str = "privacy_mode_impl_macos";

pub struct PrivacyModeImpl {
    impl_key: String,
    owner: Option<PrivacyModeConnectionOwner>,
}

impl PrivacyModeImpl {
    pub fn new(impl_key: &str) -> Self {
        Self {
            impl_key: impl_key.to_owned(),
            owner: None,
        }
    }
}

impl PrivacyMode for PrivacyModeImpl {
    fn init(&self) -> ResultType<()> {
        Ok(())
    }

    fn clear(&mut self) -> ResultType<()> {
        self.turn_off_privacy(None)
    }

    fn turn_on_privacy(&mut self, mut owner: PrivacyModeConnectionOwner) -> ResultType<bool> {
        if self.check_on_owner(&owner)? {
            return Ok(true);
        }
        owner.ensure_activation_current()?;
        let success = unsafe { MacSetPrivacyMode(true) };
        if !success {
            return Err(anyhow!("Failed to turn on privacy mode"));
        }
        if let Err(activation_error) = owner.commit_activation() {
            if !unsafe { MacSetPrivacyMode(false) } {
                self.owner = Some(owner);
                return Err(anyhow!(
                    "{activation_error}; failed to roll back cancelled macOS privacy activation"
                ));
            }
            return Err(activation_error);
        }
        self.owner = Some(owner);
        Ok(true)
    }

    fn turn_off_privacy(&mut self, _state: Option<PrivacyModeState>) -> ResultType<()> {
        // Note: The `_state` parameter is intentionally ignored on macOS.
        // On Windows, it's used to notify the connection manager about privacy mode state changes
        // (see win_topmost_window.rs). macOS currently has a simpler single-mode implementation
        // without the need for such cross-component state synchronization.
        let success = unsafe { MacSetPrivacyMode(false) };
        if !success {
            return Err(anyhow!("Failed to turn off privacy mode"));
        }
        self.owner = None;
        Ok(())
    }

    fn connection_owner(&self) -> Option<&PrivacyModeConnectionOwner> {
        self.owner.as_ref()
    }

    fn get_impl_key(&self) -> &str {
        &self.impl_key
    }
}

impl Drop for PrivacyModeImpl {
    fn drop(&mut self) {
        // Use the same cleanup logic as other code paths to keep owner state consistent
        // and ensure all cleanup is centralized in one place.
        if let Err(error) = self.clear() {
            hbb_common::log::error!("Failed to clear macOS privacy mode during drop: {error}");
        }
    }
}
