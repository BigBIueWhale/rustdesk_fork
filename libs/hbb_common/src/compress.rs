use std::{cell::RefCell, convert::TryFrom, io};
use zstd::bulk::Compressor;

// The library supports regular compression levels from 1 up to ZSTD_maxCLevel(),
// which is currently 22. Levels >= 20
// Default level is ZSTD_CLEVEL_DEFAULT==3.
// value 0 means default, which is controlled by ZSTD_CLEVEL_DEFAULT
thread_local! {
    static COMPRESSOR: RefCell<io::Result<Compressor<'static>>> = RefCell::new(Compressor::new(crate::config::COMPRESS_LEVEL));
}

pub fn compress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    COMPRESSOR.with(|c| {
        if let Ok(mut c) = c.try_borrow_mut() {
            match &mut *c {
                Ok(c) => match c.compress(data) {
                    Ok(res) => out = res,
                    Err(err) => {
                        crate::log::debug!("Failed to compress: {}", err);
                    }
                },
                Err(err) => {
                    crate::log::debug!("Failed to get compressor: {}", err);
                }
            }
        }
    });
    out
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
    // rather than truncated; allocation is bounded to MAX+1.
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

pub fn decompress_with_limit(data: &[u8], max_decompressed: usize) -> Vec<u8> {
    try_decompress_with_limit(data, max_decompressed).unwrap_or_default()
}

pub fn try_decompress(data: &[u8]) -> io::Result<Vec<u8>> {
    try_decompress_with_limit(data, MAX_DECOMPRESSED)
}

pub fn decompress(data: &[u8]) -> Vec<u8> {
    try_decompress(data).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

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
