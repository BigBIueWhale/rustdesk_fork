use std::{borrow::Cow, io, io::Read};

pub(super) const SIZE: usize = 128 * 1024;

pub(super) fn decode(data: &[u8], compressed: bool) -> io::Result<Cow<'_, [u8]>> {
    if data.len() > SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file block exceeds the 128 KiB limit"));
    }
    if !compressed {
        return Ok(Cow::Borrowed(data));
    }
    let mut decoder = zstd::stream::read::Decoder::new(data)?;
    decoder.window_log_max(SIZE.ilog2())?;
    // One extra byte distinguishes a complete block from excessive decoded output.
    // A fixed buffer also avoids read_to_end's capacity growth on hostile input.
    let mut output = vec![0; SIZE + 1];
    let mut length = 0;
    loop {
        let count = decoder.read(&mut output[length..])?;
        if count == 0 {
            output.truncate(length);
            return Ok(Cow::Owned(output));
        }
        length += count;
        if length > SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "decompressed output exceeds limit"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compress::{compress, try_decompress_with_limit};

    #[test]
    fn raw_blocks_borrow_exact_input_and_refuse_excess() {
        for size in [0, 1, 128 * 1024] {
            let input = vec![0x5a; size];
            let decoded = decode(&input, false).expect("admit exact raw input");
            assert!(matches!(decoded, Cow::Borrowed(_)));
            assert_eq!(decoded.as_ptr(), input.as_ptr());
            assert_eq!(decoded.as_ref(), input);
        }
        let oversized = vec![0x5a; 128 * 1024 + 1];
        for compressed in [false, true] {
            let error = decode(&oversized, compressed).expect_err("refuse input before decoding");
            assert!(error.to_string().contains("file block exceeds"));
        }
    }

    #[test]
    fn production_compressor_roundtrips_exact_block_boundaries() {
        for size in [0, 1, 1023, 1024, 128 * 1024 - 1, 128 * 1024] {
            let input = vec![0x5a; size];
            let encoded = compress(&input).expect("use actual production compressor");
            assert!(encoded.len() <= SIZE);
            assert_eq!(decode(&encoded, true).expect("decode actual emitted content").as_ref(), input);
        }
    }

    #[test]
    fn concatenated_frames_obey_one_total_output_limit() {
        let input = vec![0x5a; 128 * 1024];
        let mut encoded = compress(&input).expect("encode exact boundary");
        encoded.extend(compress(b"Z").expect("encode extra decoded byte"));
        let error = decode(&encoded, true).expect_err("refuse excess across frames");
        assert!(error.to_string().contains("decompressed output exceeds limit"));
        assert_eq!(try_decompress_with_limit(&encoded, SIZE + 1).expect("positive codec control").len(), SIZE + 1);
    }

    fn raw_frame(window_log: u8) -> Vec<u8> {
        // RFC 8878: no content-size field, explicit window, one final raw block of three bytes.
        let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0, (window_log - 10) << 3, 25, 0, 0];
        frame.extend_from_slice(b"abc");
        frame
    }

    #[test]
    fn small_output_cannot_authorize_a_larger_history_window() {
        let allowed = raw_frame(17);
        assert_eq!(decode(&allowed, true).expect("exact window boundary").as_ref(), b"abc");
        for window_log in [18, 23, 27] {
            let refused = raw_frame(window_log);
            assert_eq!(try_decompress_with_limit(&refused, SIZE).expect("previous decoder control"), b"abc");
            assert!(decode(&refused, true).is_err(), "refuse excessive window {window_log}");
            let mut concatenated = allowed.clone();
            concatenated.extend(refused);
            assert!(decode(&concatenated, true).is_err(), "window bound must survive a frame boundary");
        }
    }

    #[test]
    fn malformed_and_truncated_frames_refuse() {
        assert!(decode(b"not a zstd frame", true).is_err());
        let mut encoded = compress(b"complete payload").expect("encode real content");
        assert!(encoded.pop().is_some());
        assert!(decode(&encoded, true).is_err());
    }
}
