//! R-S17/R-SV5 address-normalization KAT (hbb_common::address::normalize_address).
//!
//! The host-key pin store (R-S17) and the direct-IP peer list (R-SV5) key on the
//! SAME normalized address; a mismatch silently re-seeds a fresh host — a
//! substitution blind spot. So this KAT freezes the function's exact behavior:
//! the spec's two equivalences plus port-fill, case-fold, IPv4 canonicalization,
//! and rejection of non-addresses.

use hbb_common::address::normalize_address;
use hbb_common::config::DIRECT_PORT;

#[test]
fn r_f4_direct_port_is_the_pinned_fill() {
    // The absent-port fill IS the pinned direct port; if DIRECT_PORT ever moves,
    // the hardcoded ":21118" expectations below must move with it (and so must
    // the §10.4 CPace CI KAT).
    assert_eq!(DIRECT_PORT, 21118);
}

#[test]
fn spec_equivalence_ipv4_default_port() {
    // 1.2.3.4 ≡ 1.2.3.4:21118 (the spec's first named equivalence).
    assert_eq!(normalize_address("1.2.3.4").as_deref(), Some("1.2.3.4:21118"));
    assert_eq!(
        normalize_address("1.2.3.4:21118").as_deref(),
        Some("1.2.3.4:21118")
    );
    assert_eq!(normalize_address("1.2.3.4"), normalize_address("1.2.3.4:21118"));
}

#[test]
fn spec_equivalence_domain_case_fold() {
    // EXAMPLE.com:21118 ≡ example.com:21118 (the spec's second named equivalence).
    assert_eq!(
        normalize_address("EXAMPLE.com:21118").as_deref(),
        Some("example.com:21118")
    );
    assert_eq!(
        normalize_address("example.com:21118").as_deref(),
        Some("example.com:21118")
    );
    assert_eq!(
        normalize_address("EXAMPLE.com:21118"),
        normalize_address("example.com:21118")
    );
}

#[test]
fn domain_port_fill_and_full_case_fold() {
    assert_eq!(
        normalize_address("example.com").as_deref(),
        Some("example.com:21118")
    );
    assert_eq!(
        normalize_address("EXAMPLE.COM").as_deref(),
        Some("example.com:21118")
    );
    // The absent-port domain and its :21118 spelling key the same pin.
    assert_eq!(normalize_address("EXAMPLE.COM"), normalize_address("example.com:21118"));
}

#[test]
fn non_default_port_is_preserved() {
    assert_eq!(normalize_address("1.2.3.4:22").as_deref(), Some("1.2.3.4:22"));
    assert_eq!(
        normalize_address("box.local:8000").as_deref(),
        Some("box.local:8000")
    );
}

#[test]
fn whitespace_is_trimmed() {
    assert_eq!(
        normalize_address("  1.2.3.4 ").as_deref(),
        Some("1.2.3.4:21118")
    );
}

#[test]
fn non_addresses_are_rejected() {
    assert_eq!(normalize_address(""), None);
    assert_eq!(normalize_address("   "), None);
    // Out-of-range / overlong port.
    assert_eq!(normalize_address("1.2.3.4:99999"), None);
    assert_eq!(normalize_address("1.2.3.4:0x10"), None); // non-digit ⇒ not a port split ⇒ idna rejects the colon-bearing label
    // Empty host with a port.
    assert_eq!(normalize_address(":21118"), None);
}

#[test]
fn ipv4_is_canonicalized_not_treated_as_a_domain() {
    // A canonical IPv4 stays a v4 literal (no idna mangling), with the port fill.
    assert_eq!(normalize_address("10.0.0.1").as_deref(), Some("10.0.0.1:21118"));
    assert_eq!(
        normalize_address("255.255.255.255:1").as_deref(),
        Some("255.255.255.255:1")
    );
}
