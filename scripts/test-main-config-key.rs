#[path = "../src/ipc/main_config.rs"]
mod main_config;
#[path = "fixtures/main-config-key-before-id-removal.rs"]
mod before;

#[test]
fn historical_schema_accepts_the_retired_id_query() {
    use before::MainConfigKey;
    assert_eq!(serde_json::from_str::<MainConfigKey>(r#"{"t":"Id"}"#).unwrap(), MainConfigKey::Id);
    for tag in ["PermanentPasswordSet", "UserOwnedPermanentPasswordWritable",
        "HideConnectionManager", "VoiceCallInput", "DirectListenerBound"] {
        let wire = format!(r#"{{"t":"{tag}"}}"#);
        let key = serde_json::from_str::<MainConfigKey>(&wire).unwrap();
        assert_eq!(serde_json::to_string(&key).unwrap(), wire);
    }
}
