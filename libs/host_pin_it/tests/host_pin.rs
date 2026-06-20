//! R-S17 host-key pin store KAT (`hbb_common::host_pin`).
//!
//! The pin store MUST key on the SAME `address::normalize_address` the R-SV5 direct-IP
//! peer list uses: a normalization mismatch would silently re-seed a fresh host — a
//! substitution blind spot — so these are normative, not cosmetic. Exercises the
//! path-explicit `*_at` API against a temp file (the default-path wrappers just bind
//! `Config::path("host_pins.toml")`).

use hbb_common::host_pin::{get_at, remove_at, set_at};
use std::path::PathBuf;

fn tmp(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("rd_host_pins_it_{tag}_{}.toml", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

#[test]
fn pin_roundtrip_and_normalization() {
    let p = tmp("rt");
    let pk = vec![7u8; 32];
    assert_eq!(get_at(&p, "1.2.3.4"), None);
    set_at(&p, "1.2.3.4", &pk).unwrap();
    // R-S17: the port-less and the explicit pinned-port (21118, R-F4) spelling key the
    // SAME pin — so a viewer connecting to either form compares against one identity.
    assert_eq!(get_at(&p, "1.2.3.4"), Some(pk.clone()));
    assert_eq!(get_at(&p, "1.2.3.4:21118"), Some(pk.clone()));
    // a different host is a miss (never a false pin)
    assert_eq!(get_at(&p, "5.6.7.8"), None);
    // a domain case-folds (EXAMPLE.com == example.com), shared with R-SV5.
    set_at(&p, "EXAMPLE.com:21118", &pk).unwrap();
    assert_eq!(get_at(&p, "example.com"), Some(pk.clone()));
    // re-pin overwrites in place (the deliberate mismatch re-pin)
    let pk2 = vec![9u8; 32];
    set_at(&p, "1.2.3.4", &pk2).unwrap();
    assert_eq!(get_at(&p, "1.2.3.4"), Some(pk2));
    // forget one host, leaving the other intact
    remove_at(&p, "1.2.3.4").unwrap();
    assert_eq!(get_at(&p, "1.2.3.4"), None);
    assert_eq!(get_at(&p, "example.com"), Some(pk));
    let _ = std::fs::remove_file(&p);
}

#[test]
fn unusable_address_rejected() {
    let p = tmp("bad");
    // an empty / malformed address cannot be pinned or looked up (normalize → None),
    // so a pin can never be seeded under a key the connect path can't reproduce.
    assert!(set_at(&p, "", &[1, 2, 3]).is_err());
    assert_eq!(get_at(&p, ""), None);
    assert_eq!(get_at(&p, "1.2.3.4:notaport"), None);
    let _ = std::fs::remove_file(&p);
}
