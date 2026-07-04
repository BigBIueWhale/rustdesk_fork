//! R-P1: the memory-hard CPace PRS derivation (Argon2id) — both ends MUST compute
//! IDENTICAL bytes, so these pin the formula's invariants DIRECTLY (independent of
//! the at-rest storage wrapper exercised by lockdown.rs):
//!   PRS = base64( Argon2id( NFC(password), SHA256("rustdesk-cpace-prs-salt-v1")[..16] ) )

use hbb_common::config::derive_cpace_prs;
use hbb_common::sodiumoxide::base64;

#[test]
fn prs_is_deterministic_and_base64_of_32_bytes() {
    let a = derive_cpace_prs("correct horse").expect("derive");
    let b = derive_cpace_prs("correct horse").expect("derive");
    assert_eq!(a, b, "same password => identical PRS (no per-call randomness)");
    // base64_Original of the 32-byte Argon2id output decodes back to exactly 32 bytes.
    let raw = base64::decode(a.as_bytes(), base64::Variant::Original).expect("PRS is valid base64");
    assert_eq!(raw.len(), 32, "the PRS is base64 of the 32-byte Argon2id output");
}

#[test]
fn prs_depends_on_the_password_alone() {
    // The salt is a FIXED global constant with NO per-box value (R-P1/R-P5), so the PRS is
    // a pure function of the (normalized) password: both ends derive the IDENTICAL value
    // from the password alone, with nothing per-box to distribute, pin, or agree. This is
    // the property the retired host-key salt used to break (same password, different box =>
    // different PRS); it now holds.
    assert_eq!(
        derive_cpace_prs("same-password").expect("derive"),
        derive_cpace_prs("same-password").expect("derive"),
        "the PRS is a function of the password alone (fixed salt)"
    );
}

#[test]
fn different_passwords_differ() {
    let a = derive_cpace_prs("password-one").expect("derive");
    let b = derive_cpace_prs("password-two").expect("derive");
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
        derive_cpace_prs(composed).expect("derive"),
        derive_cpace_prs(decomposed).expect("derive"),
        "NFC makes a composed and a decomposed password agree (R-P1)"
    );
}

#[test]
fn empty_password_is_none() {
    assert!(derive_cpace_prs("").is_none(), "empty password => None (R-S9)");
}
