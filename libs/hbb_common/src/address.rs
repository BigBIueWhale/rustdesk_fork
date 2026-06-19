//! R-S17 / R-SV5 address normalization — the single pinned, KAT-frozen function
//! that maps a connect target to its canonical `<ip|domain>:port` identity.
//!
//! The R-S17 host-key pin store and the R-SV5 direct-IP peer list MUST key on the
//! SAME normalized address: a normalization mismatch silently re-seeds a fresh
//! host (a substitution blind spot), so this function is pinned here and its
//! behavior frozen by the KAT in `libs/address_it` (R-A6). Rules: lowercase;
//! IDNA `to_ascii` for domains; the port filled to the pinned direct port (21118,
//! R-F4) when absent; IPv4 canonicalized. So `1.2.3.4` ≡ `1.2.3.4:21118` and
//! `EXAMPLE.com:21118` ≡ `example.com:21118`.

use crate::config::DIRECT_PORT;
use std::net::Ipv4Addr;

/// Normalize a connect target to its canonical `<host>:<port>` identity, or
/// `None` if it is not a usable IPv4/domain address. Pure + deterministic — the
/// frozen KAT (R-SV5/R-S17) depends on this exact behavior, so a refactor that
/// changes it is a substitution blind spot, not a cosmetic edit.
pub fn normalize_address(input: &str) -> Option<String> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }
    // Split a trailing `:port` only when the suffix is all-digits — an IPv4 or
    // domain host never contains a colon, so this is unambiguous. IPv6 (which
    // would) is out of scope: the fork binds v4-only (R-D5) and connects by a
    // reachable v4/domain address (R-SV5).
    let (host, port) = match input.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => (h, Some(p)),
        _ => (input, None),
    };
    if host.is_empty() || host.contains(':') {
        // A normalized v4/domain host carries no colon; a residual colon means a
        // malformed port (e.g. `1.2.3.4:0x10`) or an IPv6 literal — out of scope
        // (R-D5 v4-only) — so reject rather than mangle it through IDNA.
        return None;
    }
    let port: u16 = match port {
        Some(p) => p.parse().ok()?, // rejects an out-of-range / overlong port
        None => DIRECT_PORT as u16,  // R-F4: the pinned direct port
    };
    // Canonicalize the host: an IPv4 literal via `Ipv4Addr` (normalizes the
    // dotted-decimal form and rejects a malformed one); otherwise a domain via
    // IDNA `to_ascii` (lowercases + punycode-encodes, rejecting an invalid
    // label) so a unicode and its punycode spelling key the same pin.
    let host_norm = if let Ok(ip) = host.parse::<Ipv4Addr>() {
        ip.to_string()
    } else {
        let ascii = idna::domain_to_ascii(host).ok()?;
        if ascii.is_empty() {
            return None;
        }
        ascii
    };
    Some(format!("{host_norm}:{port}"))
}
