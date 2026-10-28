// MainConfigKey from src/ipc.rs at 431a3e77838f4274f80fa1086bcc0fca708a3b7a.
use serde_derive::{Deserialize, Serialize};

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(tag = "t")]
pub enum MainConfigKey {
    Id,
    PermanentPasswordSet,
    UserOwnedPermanentPasswordWritable,
    HideConnectionManager,
    VoiceCallInput,
    DirectListenerBound,
}
