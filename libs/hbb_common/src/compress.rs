use std::{cell::RefCell, io};
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
/// streams through a capped reader instead. An over-cap stream is *rejected*
/// (empty — the same fail-safe the previous `unwrap_or_default` already returned
/// on a decode error, which every caller handles), never silently truncated
/// (truncation would corrupt a legitimately-large payload).
pub fn decompress(data: &[u8]) -> Vec<u8> {
    use io::Read;
    let Ok(decoder) = zstd::stream::read::Decoder::new(data) else {
        return Vec::new();
    };
    // take(MAX+1) so an over-cap stream is *detected* (len > MAX) and rejected
    // rather than truncated; allocation is bounded to MAX+1.
    let mut limited = decoder.take(MAX_DECOMPRESSED as u64 + 1);
    let mut out = Vec::new();
    if limited.read_to_end(&mut out).is_err() || out.len() > MAX_DECOMPRESSED {
        return Vec::new();
    }
    out
}
