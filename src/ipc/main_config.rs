use serde_derive::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(tag = "t", deny_unknown_fields)]
pub enum MainConfigKey {
    PermanentPasswordSet {},
    UserOwnedPermanentPasswordWritable {},
    HideConnectionManager {},
    VoiceCallInput {},
    DirectListenerBound {},
}

#[cfg(test)]
mod tests {
    use super::MainConfigKey;

    #[test]
    fn remaining_keys_round_trip() {
        for (key, tag) in [
            (MainConfigKey::PermanentPasswordSet {}, "PermanentPasswordSet"),
            (MainConfigKey::UserOwnedPermanentPasswordWritable {}, "UserOwnedPermanentPasswordWritable"),
            (MainConfigKey::HideConnectionManager {}, "HideConnectionManager"),
            (MainConfigKey::VoiceCallInput {}, "VoiceCallInput"),
            (MainConfigKey::DirectListenerBound {}, "DirectListenerBound"),
        ] {
            let wire = format!(r#"{{"t":"{tag}"}}"#);
            assert_eq!(serde_json::to_string(&key).unwrap(), wire);
            assert_eq!(serde_json::from_str::<MainConfigKey>(&wire).unwrap(), key);
        }
    }

    #[test]
    fn retired_and_unknown_keys_are_rejected() {
        for tag in ["Id", "id", "PermanentPassword", "Salt", "Config", "Unknown", ""] {
            let wire = format!(r#"{{"t":"{tag}"}}"#);
            assert!(serde_json::from_str::<MainConfigKey>(&wire).is_err(), "{tag}");
        }
    }

    #[test]
    fn missing_or_wrong_tag_shape_is_rejected() {
        let mut invalid = [r#"{}"#, r#"{"t":null}"#, r#"{"t":0}"#, r#""Id""#]
            .map(str::to_owned)
            .to_vec();
        for tag in [
            "PermanentPasswordSet",
            "UserOwnedPermanentPasswordWritable",
            "HideConnectionManager",
            "VoiceCallInput",
            "DirectListenerBound",
        ] {
            invalid.extend([
                format!(r#"{{"t":"{tag}","future":true}}"#),
                format!(r#"{{"future":true,"t":"{tag}"}}"#),
                format!(r#"{{"t":"{tag}","c":null}}"#),
                format!(r#"{{"t":"{tag}","future":{{"nested":[1,2]}}}}"#),
                format!(r#"{{"t":"{tag}","t":"{tag}"}}"#),
                format!(r#"{{"t":"{tag}","t":"Id"}}"#),
            ]);
        }
        let accepted: Vec<_> = invalid
            .iter()
            .filter(|wire| serde_json::from_str::<MainConfigKey>(wire).is_ok())
            .collect();
        assert!(accepted.is_empty(), "accepted malformed keys: {accepted:?}");
    }
}
