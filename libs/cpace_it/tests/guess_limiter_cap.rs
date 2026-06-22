//! R-S10(b): the per-source online-guess limiter MUST carry a HARD entry-count ceiling
//! (MAX_TRACKED_SOURCES = 8192) on top of its time-eviction, so a flood of DISTINCT source IPs within
//! one window cannot grow the tracking map without bound (each record is one completed-PAKE R-P3
//! failure, and v4-only per R-D5 bounds the keyspace — but the spec still mandates the literal cap).
//! This floods the limiter with > the cap of distinct v4 sources and asserts the map never exceeds
//! the ceiling, so the eviction path is genuinely exercised (not a vacuous pass).
//!
//! Isolated in its own test file → its own process → a fresh GUESS_FAILURES static, so it cannot race
//! the shared-static `guess_limiter_blocks_after_threshold` test.

use hbb_common::cpace::{guess_limiter_tracked_count, record_guess_failure};
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn guess_limiter_caps_tracked_sources() {
    const CAP: usize = 8192;
    const FLOOD: u32 = 9000; // comfortably past the cap with distinct v4 sources
    for i in 0..FLOOD {
        // Ipv4Addr::from(u32) yields FLOOD distinct addresses (0.0.0.0 .. 0.0.35.39).
        record_guess_failure(IpAddr::V4(Ipv4Addr::from(i)));
    }
    let tracked = guess_limiter_tracked_count();
    assert!(
        tracked <= CAP,
        "R-S10(b): the limiter map must be capped at MAX_TRACKED_SOURCES ({CAP}); tracked={tracked}"
    );
    // The flood exceeded the cap, so the eviction must have engaged — a near-empty map would mean the
    // ceiling never triggered (the test would be vacuous).
    assert!(
        tracked > CAP - 64,
        "the cap should hold AT the ceiling after a {FLOOD}-source flood; tracked={tracked}"
    );
}
