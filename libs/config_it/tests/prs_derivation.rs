//! R-P1: the memory-hard CPace PRS derivation (Argon2id) — both ends MUST compute
//! IDENTICAL bytes, so these pin the formula's invariants DIRECTLY (independent of
//! the at-rest storage wrapper exercised by lockdown.rs):
//!   PRS = base64( Argon2id( NFC(password), SHA256("rustdesk-cpace-prs-salt-v1" ++ host_pubkey)[..16] ) )

use hbb_common::config::derive_cpace_prs;
use hbb_common::sodiumoxide::base64;

// A fixed, non-empty stand-in for the box's Ed25519 host public key. derive_cpace_prs
// only HASHES these bytes into the Argon2id salt, so any non-empty slice is a valid
// "pubkey" for exercising the derivation.
const PK_A: &[u8] = &[7u8; 32];
const PK_B: &[u8] = &[9u8; 32];

#[test]
fn prs_is_deterministic_and_base64_of_32_bytes() {
    let a = derive_cpace_prs("correct horse", PK_A).expect("derive");
    let b = derive_cpace_prs("correct horse", PK_A).expect("derive");
    assert_eq!(a, b, "same password + key => identical PRS (no per-call randomness)");
    // base64_Original of the 32-byte Argon2id output decodes back to exactly 32 bytes.
    let raw = base64::decode(a.as_bytes(), base64::Variant::Original).expect("PRS is valid base64");
    assert_eq!(raw.len(), 32, "the PRS is base64 of the 32-byte Argon2id output");
}

#[test]
fn prs_is_salted_by_the_host_key() {
    // SAME password, DIFFERENT host key => DIFFERENT PRS. The salt is bound to the key,
    // so a substitute box with a different key cannot key even knowing the password — the
    // host identity is woven into the PAKE secret (R-S17/R-P1).
    let a = derive_cpace_prs("same-password", PK_A).expect("derive");
    let b = derive_cpace_prs("same-password", PK_B).expect("derive");
    assert_ne!(a, b, "the PRS salt MUST be bound to the host public key");
}

#[test]
fn different_passwords_differ() {
    let a = derive_cpace_prs("password-one", PK_A).expect("derive");
    let b = derive_cpace_prs("password-two", PK_A).expect("derive");
    assert_ne!(a, b);
}

#[test]
fn nfc_normalizes_composed_and_decomposed_alike() {
    // U+00E9 (é, composed) vs U+0065 U+0301 (e + combining acute, decomposed) NFC to the
    // SAME bytes, so they MUST yield the SAME PRS — the IDENTICAL NFC the CPace path uses
    // (a viewer that types one spelling must match a box provisioned with the other).
    let composed = "caf\u{00e9}";
    let decomposed = "caf\u{0065}\u{0301}";
    assert_ne!(composed, decomposed, "distinct code points before normalization");
    assert_eq!(
        derive_cpace_prs(composed, PK_A).expect("derive"),
        derive_cpace_prs(decomposed, PK_A).expect("derive"),
        "NFC makes a composed and a decomposed password agree (R-P1)"
    );
}

#[test]
fn empty_password_or_pubkey_is_none() {
    assert!(derive_cpace_prs("", PK_A).is_none(), "empty password => None (R-S9)");
    assert!(derive_cpace_prs("pw", &[]).is_none(), "empty host key => None (R-S9)");
}
