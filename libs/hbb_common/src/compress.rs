use std::{cell::RefCell, convert::TryFrom, io};
use zstd::zstd_safe::{self, CCtx, CParameter};

thread_local! {
    static COMPRESSOR: RefCell<Option<CCtx<'static>>> = const { RefCell::new(None) };
}

pub fn compress(data: &[u8]) -> io::Result<Vec<u8>> {
    COMPRESSOR.with(|compressor| {
        let mut state = compressor.try_borrow_mut().map_err(|err| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("compression context is unavailable: {err}"),
            )
        })?;
        let compressor = match &mut *state {
            Some(context) => context,
            slot @ None => {
                let mut context = CCtx::try_create()
                    .ok_or_else(|| io::Error::from(io::ErrorKind::OutOfMemory))?;
                context.set_parameter(CParameter::CompressionLevel(crate::config::COMPRESS_LEVEL))
                    .map_err(zstd_error)?;
                context.load_dictionary(&[]).map_err(zstd_error)?;
                slot.insert(context)
            }
        };
        let mut output = Vec::new();
        output.try_reserve_exact(zstd::zstd_safe::compress_bound(data.len()))
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        compressor.compress2(&mut output, data).map_err(zstd_error)?;
        // Queued compressed payloads must not retain the worst-case workspace.
        if output.capacity() != output.len() {
            let mut packed = Vec::new();
            packed.try_reserve_exact(output.len())
                .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
            packed.extend_from_slice(&output);
            output = packed;
        }
        Ok(output)
    })
}

#[cfg(test)]
pub(crate) fn with_busy_compressor_for_test<T>(action: impl FnOnce() -> T) -> T {
    COMPRESSOR.with(|compressor| {
        let _borrow = compressor.borrow_mut();
        action()
    })
}

fn zstd_error(code: usize) -> io::Error {
    io::Error::new(io::ErrorKind::Other, zstd_safe::get_error_name(code))
}

struct DecoderOperation(zstd_safe::DCtx<'static>);

impl zstd::stream::raw::Operation for DecoderOperation {
    fn run<C: zstd_safe::WriteBuf + ?Sized>(
        &mut self,
        input: &mut zstd_safe::InBuffer<'_>,
        output: &mut zstd_safe::OutBuffer<'_, C>,
    ) -> io::Result<usize> {
        self.0.decompress_stream(output, input).map_err(zstd_error)
    }

    fn reinit(&mut self) -> io::Result<()> {
        self.0.reset(zstd_safe::ResetDirective::SessionOnly)
            .map(|_| ()).map_err(zstd_error)
    }

    fn finish<C: zstd_safe::WriteBuf + ?Sized>(
        &mut self,
        _output: &mut zstd_safe::OutBuffer<'_, C>,
        finished_frame: bool,
    ) -> io::Result<usize> {
        if finished_frame {
            Ok(0)
        } else {
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete frame"))
        }
    }
}

/// Own a fallibly allocated decoder with borrowed input and bounded history.
pub(crate) fn decoder_with_window_limit(
    data: &[u8],
    max_window_log: u32,
) -> io::Result<impl io::Read + '_> {
    let mut context = zstd_safe::DCtx::try_create()
        .ok_or_else(|| io::Error::from(io::ErrorKind::OutOfMemory))?;
    context.init().map_err(zstd_error)?;
    context.load_dictionary(&[]).map_err(zstd_error)?;
    context.set_parameter(zstd_safe::DParameter::WindowLogMax(max_window_log))
        .map_err(zstd_error)?;
    Ok(zstd::stream::zio::Reader::new(data, DecoderOperation(context)))
}

/// The default decoded-output ceiling and the shared decoder's independent
/// history-window ceiling (R-S7). File blocks use their own stricter decoder.
const MAX_DECOMPRESSED: usize = 64 * 1024 * 1024;

/// Decompress with the caller's output limit and a [`MAX_DECOMPRESSED`] history
/// limit. Decode and limit failures remain explicit receive errors.
pub fn try_decompress_with_limit(data: &[u8], max_decompressed: usize) -> io::Result<Vec<u8>> {
    use io::Read;
    let decoder = decoder_with_window_limit(data, MAX_DECOMPRESSED.ilog2())?;
    let read_limit = u64::try_from(max_decompressed)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "decompression limit overflow"))?;
    let read_limit = read_limit.checked_add(1).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "decompression limit overflow")
    })?;
    // Read one extra byte to detect excess before reserving or appending output.
    let mut limited = decoder.take(read_limit);
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let count = match limited.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => count,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        let length = out.len().checked_add(count)
            .filter(|length| *length <= max_decompressed)
            .ok_or_else(|| io::Error::new(
                io::ErrorKind::InvalidData,
                "decompressed output exceeds limit",
            ))?;
        if length > out.capacity() {
            let capacity = length.max(out.capacity().saturating_mul(2)).min(max_decompressed);
            out.try_reserve_exact(capacity - out.len())
                .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        }
        out.extend_from_slice(&chunk[..count]);
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
