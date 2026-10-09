//! Real zstd decoding: bounded output and explicit failure, distinct from valid emptiness.

use hbb_common::compress::{compress, try_decompress, try_decompress_with_limit};

#[test]
fn roundtrip_small_payload() {
    let data = b"the quick brown fox jumps over the lazy dog".repeat(50);
    let c = compress(&data);
    assert!(!c.is_empty());
    assert_eq!(try_decompress(&c).unwrap(), data);
}

#[test]
fn within_cap_payload_survives() {
    // ~10 MiB decompresses fine — comfortably under the 64 MiB ceiling.
    let src = vec![7u8; 10 * 1024 * 1024];
    let c = compress(&src);
    let out = try_decompress(&c).unwrap();
    assert_eq!(out.len(), src.len());
    assert_eq!(out, src);
}

#[test]
fn r_s7_rejects_a_decompression_bomb() {
    // 80 MiB of zeros compresses to a tiny payload but would decompress ABOVE the
    // 64 MiB cap: decoding must return an error rather than the output.
    let bomb_src = vec![0u8; 80 * 1024 * 1024];
    let c = compress(&bomb_src);
    assert!(
        c.len() < 1024 * 1024,
        "zstd should shrink 80 MiB of zeros to well under 1 MiB (got {})",
        c.len()
    );
    assert!(
        try_decompress(&c).is_err(),
        "an over-cap (>64 MiB) decompression must be rejected, not returned"
    );
}

#[test]
fn garbage_input_is_an_explicit_error() {
    assert!(try_decompress(b"not a zstd stream at all").is_err());
}

#[test]
fn caller_specific_limit_rejects_before_the_global_ceiling() {
    let src = vec![9u8; 4096];
    let compressed = compress(&src);
    assert_eq!(try_decompress_with_limit(&compressed, src.len()).unwrap(), src);
    assert!(try_decompress_with_limit(&compressed, src.len() - 1).is_err());
}

#[test]
fn valid_empty_frame_is_successful_even_at_zero_limit() {
    let compressed = compress(&[]);
    assert!(!compressed.is_empty());
    assert_eq!(try_decompress_with_limit(&compressed, 0).unwrap(), Vec::<u8>::new());
}

#[test]
fn truncated_frame_is_an_explicit_error() {
    let mut compressed = compress(b"complete frame");
    assert!(compressed.pop().is_some());
    assert!(try_decompress(&compressed).is_err());
}
