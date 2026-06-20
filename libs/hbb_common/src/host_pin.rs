//! R-S17 host-key pin store — the fork viewer's SSH `known_hosts`.
//!
//! CPace (§10) proves the responder knows the password, not that it is the SPECIFIC box
//! the operator onboarded (R-P5 deliberately leaves no long-term identities). This store
//! closes that residual: the viewer pins each box's self-generated Ed25519 public key
//! (`Config::get_key_pair().1`) per address and, on every later connect, compares the
//! box's channel-bound `HostIdentity` proof (R-S17, emitted by the responder — server.rs
//! 5fb04fc) against the pin — catching a substitute that knows the password but lacks the
//! box's private key.
//!
//! Design invariants (R-S17 / R-S15 / R-A6):
//!   - a SEPARATE local file, NOT `PeerConfig` — a keyed hostile peer must not be able to
//!     seed or overwrite a pin (R-S15), so this is never written from a peer-message arm;
//!   - keyed by the SAME `address::normalize_address` the R-SV5 direct-IP peer list uses,
//!     so a domain/IP spelling (`1.2.3.4` vs `1.2.3.4:21118`, `EXAMPLE.com` vs the
//!     punycode) can never silently re-seed a fresh host (a substitution blind spot);
//!   - stored `0o600` (via `store_path`), since the pins are an integrity anchor.
//!
//! The pk is held as the raw Ed25519 bytes, hex-encoded in the file (the same lowercase
//! hex the fingerprint uses). A list of `[[pin]]` array-of-tables avoids TOML interpreting
//! the dots/colons in an address key as nested-table paths.

use crate::{address::normalize_address, config::Config, ResultType};
use serde_derive::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PinEntry {
    address: String, // already normalize_address-canonical
    pk: String,      // lowercase hex of the Ed25519 public key
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct HostPins {
    #[serde(default)]
    pin: Vec<PinEntry>,
}

fn default_path() -> PathBuf {
    Config::path("host_pins.toml")
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

// The `*_at(path, …)` functions are the path-explicit implementation; the default-path
// public wrappers below call them with `Config::path("host_pins.toml")`. They are `pub`
// so the isolated `host_pin_it` KAT crate can exercise them against a temp file without
// touching the real config dir (the inline-test path pulls hbb_common's `sdp` dev-dep,
// which does not build on the pinned rust 1.75 — the same reason `address_it` is isolated).
pub fn get_at(path: &PathBuf, address: &str) -> Option<Vec<u8>> {
    let key = normalize_address(address)?;
    let pins: HostPins = crate::config::load_path(path.clone());
    let entry = pins.pin.iter().find(|e| e.address == key)?;
    hex_decode(&entry.pk)
}

pub fn set_at(path: &PathBuf, address: &str, pk: &[u8]) -> ResultType<()> {
    let key = normalize_address(address)
        .ok_or_else(|| crate::anyhow::anyhow!("R-S17: unusable pin address: {address}"))?;
    let mut pins: HostPins = crate::config::load_path(path.clone());
    let hex = hex_encode(pk);
    if let Some(e) = pins.pin.iter_mut().find(|e| e.address == key) {
        e.pk = hex;
    } else {
        pins.pin.push(PinEntry { address: key, pk: hex });
    }
    crate::config::store_path(path.clone(), pins)
}

pub fn remove_at(path: &PathBuf, address: &str) -> ResultType<()> {
    let Some(key) = normalize_address(address) else {
        return Ok(());
    };
    let mut pins: HostPins = crate::config::load_path(path.clone());
    let before = pins.pin.len();
    pins.pin.retain(|e| e.address != key);
    if pins.pin.len() != before {
        crate::config::store_path(path.clone(), pins)?;
    }
    Ok(())
}

/// The pinned Ed25519 public key for `address`, or `None` if not yet pinned (or the
/// address is unusable). Read on every connect to compare against the box's HostIdentity.
pub fn get_pinned_pk(address: &str) -> Option<Vec<u8>> {
    get_at(&default_path(), address)
}

/// Pin (seed or re-pin) `address` to `pk` — ONLY on an explicit operator decision (the
/// first-connect accept dialog or a deliberate mismatch re-pin), NEVER from a peer message.
pub fn set_pinned_pk(address: &str, pk: &[u8]) -> ResultType<()> {
    set_at(&default_path(), address, pk)
}

/// Forget a pinned host (the manage / forget-host view, R-S17 / §19).
pub fn remove_pinned(address: &str) -> ResultType<()> {
    remove_at(&default_path(), address)
}

/// All pinned `(normalized-address, hex-pk)` entries — for the manage view.
pub fn list_pinned() -> Vec<(String, String)> {
    let pins: HostPins = crate::config::load_path(default_path());
    let mut v: Vec<(String, String)> = pins.pin.into_iter().map(|e| (e.address, e.pk)).collect();
    v.sort();
    v
}

// Tests live in the isolated `libs/host_pin_it` crate (no hbb_common dev-deps ⇒ no
// sdp/webrtc, so they build + run on the pinned rust 1.75), exercising the `*_at`
// functions against a temp file. Mirrors `address_it`.
