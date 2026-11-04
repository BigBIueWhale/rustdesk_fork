//! Compare the production password derivation with the VM's independent libargon2.
//! Run through scripts/smoke-verifier-vm-authority.sh --prs-derivation-tests.

use hbb_common::config::derive_cpace_prs;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[test]
fn password_derivation_matches_independent_argon2_reference() {
    let fixture = include_bytes!("fixtures/prs_derivation.json");
    let inputs: Value = serde_json::from_slice(fixture).unwrap();
    let path = std::env::var("PRS_DERIVATION_REFERENCE").expect("isolated Argon2 reference fixture");
    let bytes = std::fs::read(path).expect("read-only reference fixture");
    assert!(bytes.len() < 8192);
    let reference: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(reference["schema"], 1);
    assert_eq!(reference["fixture_sha256"], format!("{:x}", Sha256::digest(fixture)));
    assert_eq!(reference["reference"]["rfc9106_5_3"],
        "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
    let inputs = inputs.as_array().unwrap();
    let expected = reference["cases"].as_array().unwrap();
    assert_eq!(inputs.len(), 17);
    assert_eq!(expected.len(), inputs.len());
    for (input, result) in inputs.iter().zip(expected) {
        assert_eq!(input["name"], result["name"]);
        let name = input["name"].as_str().unwrap();
        let password = input["password"].as_str().unwrap();
        let actual = derive_cpace_prs(password);
        if name == "empty" {
            assert!(result["expected"].is_null());
            assert_eq!(actual, None);
        } else {
            let expected = result["expected"].as_str().unwrap();
            assert_eq!(expected.len(), 44);
            assert!(expected.ends_with('='));
            assert_eq!(actual.as_deref(), Some(expected), "{name}");
        }
    }
    println!("PRS_DERIVATION_CASES=pass cases=17 derived=16 empty=refused oracle=libargon2-rfc9106");
}
