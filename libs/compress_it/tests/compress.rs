//! R-S7 post-key decompression bound (hbb_common::compress::decompress).
//!
//! The inherited `zstd::decode_all` reads to EOF with no output limit, so a small
//! compressed payload from a *keyed* peer can amplify to an unbounded allocation
//! (a zstd bomb). `decompress` now streams through a 64 MiB-capped reader and
//! rejects (empty) anything larger. These tests pin: a normal payload round-trips,
//! a within-cap payload survives, and a bomb is refused rather than allocated.

use hbb_common::compress::{compress, decompress};

#[test]
fn roundtrip_small_payload() {
    let data = b"the quick brown fox jumps over the lazy dog".repeat(50);
    let c = compress(&data);
    assert!(!c.is_empty());
    assert_eq!(decompress(&c), data);
}

#[test]
fn within_cap_payload_survives() {
    // ~10 MiB decompresses fine — comfortably under the 64 MiB ceiling.
    let src = vec![7u8; 10 * 1024 * 1024];
    let c = compress(&src);
    let out = decompress(&c);
    assert_eq!(out.len(), src.len());
    assert_eq!(out, src);
}

#[test]
fn r_s7_rejects_a_decompression_bomb() {
    // 80 MiB of zeros compresses to a tiny payload but would decompress ABOVE the
    // 64 MiB cap → decompress must reject it (empty), never allocate 80 MiB.
    let bomb_src = vec![0u8; 80 * 1024 * 1024];
    let c = compress(&bomb_src);
    assert!(
        c.len() < 1024 * 1024,
        "zstd should shrink 80 MiB of zeros to well under 1 MiB (got {})",
        c.len()
    );
    assert!(
        decompress(&c).is_empty(),
        "an over-cap (>64 MiB) decompression must be rejected, not returned"
    );
}

#[test]
fn garbage_input_is_empty_not_a_panic() {
    // A non-zstd blob must fail safe (empty), matching the prior unwrap_or_default.
    assert!(decompress(b"not a zstd stream at all").is_empty());
}
