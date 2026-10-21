use std::{cell::RefCell, convert::TryFrom, io};
use zstd::bulk::Compressor;

// The library supports regular compression levels from 1 up to ZSTD_maxCLevel(),
// which is currently 22. Levels >= 20
// Default level is ZSTD_CLEVEL_DEFAULT==3.
// value 0 means default, which is controlled by ZSTD_CLEVEL_DEFAULT
thread_local! {
    static COMPRESSOR: RefCell<io::Result<Compressor<'static>>> = RefCell::new(Compressor::new(crate::config::COMPRESS_LEVEL));
}

pub fn compress(data: &[u8]) -> io::Result<Vec<u8>> {
    COMPRESSOR.with(|compressor| {
        let mut state = compressor.try_borrow_mut().map_err(|err| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("compression context is unavailable: {err}"),
            )
        })?;
        let compressor = state.as_mut().map_err(|err| {
            io::Error::new(
                err.kind(),
                format!("compression context initialization failed: {err}"),
            )
        })?;
        compressor.compress(data)
    })
}

#[cfg(test)]
pub(crate) fn with_busy_compressor_for_test<T>(action: impl FnOnce() -> T) -> T {
    COMPRESSOR.with(|compressor| {
        let _borrow = compressor.borrow_mut();
        action()
    })
}

/// The post-key decompressed-output ceiling (R-S7, the twin of the pre-auth
/// frame cap). zstd's ratio is unbounded, so a small compressed file-block,
/// clipboard, or cursor payload from a *keyed* peer can amplify to an unbounded
/// allocation/disk-write (a zstd bomb) on either role. This cap (64 MiB) sits
/// well above any realistic single decompressed payload — the 128 KiB file
/// block (`fs.rs`), a clipboard image, a cursor — yet bounds the amplification.
const MAX_DECOMPRESSED: usize = 64 * 1024 * 1024;

/// Decompress, bounding the output to [`MAX_DECOMPRESSED`] (R-S7 post-key twin).
/// The inherited `zstd::decode_all` reads to EOF with NO output limit; this
/// streams through a capped reader instead. Decode and limit failures remain
/// explicit so a receive path cannot mistake malformed or over-limit input for
/// a successfully transferred empty block.
pub fn try_decompress_with_limit(data: &[u8], max_decompressed: usize) -> io::Result<Vec<u8>> {
    use io::Read;
    let decoder = zstd::stream::read::Decoder::new(data)?;
    let max_decompressed = u64::try_from(max_decompressed)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "decompression limit overflow"))?;
    let read_limit = max_decompressed.checked_add(1).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "decompression limit overflow")
    })?;
    // take(MAX+1) so an over-cap stream is *detected* (len > MAX) and rejected
    // rather than truncated; at most MAX+1 decoded bytes are appended.
    let mut limited = decoder.take(read_limit);
    let mut out = Vec::new();
    limited.read_to_end(&mut out)?;
    let length = u64::try_from(out.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "decompressed output length overflow",
        )
    })?;
    if length > max_decompressed {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "decompressed output exceeds limit",
        ));
    }
    Ok(out)
}

pub fn try_decompress(data: &[u8]) -> io::Result<Vec<u8>> {
    try_decompress_with_limit(data, MAX_DECOMPRESSED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompression_history_window_is_independent_of_output_limit() {
        // RFC 8878: an explicit 64 MiB window and one final raw block of three bytes.
        let mut frame = vec![
            0x28, 0xb5, 0x2f, 0xfd, 0, 0x80, 25, 0, 0, b'a', b'b', b'c',
        ];
        assert_eq!(try_decompress_with_limit(&frame, 3).unwrap(), b"abc");
        for size in [0, 1, 128 * 1024] {
            let input = vec![0x5a; size];
            let encoded = compress(&input).unwrap();
            assert_eq!(try_decompress_with_limit(&encoded, size).unwrap(), input);
        }

        let mut concatenated = frame.clone();
        frame[5] = 0x88; // The same three output bytes, with a 128 MiB history window.
        concatenated.extend_from_slice(&frame);
        let mut admitted = 0;
        for (case, result) in [
            ("default", try_decompress(&frame)),
            ("tight", try_decompress_with_limit(&frame, 3)),
            ("concatenated", try_decompress_with_limit(&concatenated, 6)),
        ] {
            println!(
                "DECOMPRESSION_WINDOW_CASE=observed case={case} admitted={} output_bytes={:?} error={:?}",
                result.is_ok(),
                result.as_ref().map(Vec::len),
                result.as_ref().err()
            );
            if result.is_ok() {
                admitted += 1;
            }
        }
        println!("DECOMPRESSION_WINDOW=observed cases=3 admitted={admitted} controls=4 max_window_bytes=67108864");
        assert_eq!(
            admitted, 0,
            "output bounds cannot authorize excessive decoder history"
        );
    }

    #[test]
    fn decompression_is_fallible_and_output_bounded() {
        let encoded = zstd::stream::encode_all(&b"bounded payload"[..], 1)
            .expect("encode decompression fixture");
        assert_eq!(
            try_decompress_with_limit(&encoded, 15).expect("decode within the exact limit"),
            b"bounded payload"
        );
        assert!(
            try_decompress_with_limit(&encoded, 14).is_err(),
            "over-limit output must not masquerade as an empty block"
        );
        assert!(
            try_decompress_with_limit(b"not a zstd frame", 64).is_err(),
            "malformed input must remain an explicit receive failure"
        );
    }
}
