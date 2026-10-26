use std::{cell::Cell, io, panic::catch_unwind, ptr, thread};
use zstd::zstd_safe::{self, zstd_sys::{ZSTD_CCtx, ZSTD_DCtx}};

thread_local! {
    static CREATION: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    static DECODER_CREATION: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    static DECODER_FREES: Cell<usize> = const { Cell::new(0) };
}

extern "C" {
    fn __real_ZSTD_createCCtx() -> *mut ZSTD_CCtx;
    fn __real_ZSTD_createDCtx() -> *mut ZSTD_DCtx;
    fn __real_ZSTD_freeDCtx(context: *mut ZSTD_DCtx) -> usize;
}

#[no_mangle]
unsafe extern "C" fn __wrap_ZSTD_createDCtx() -> *mut ZSTD_DCtx {
    let refuse = DECODER_CREATION.with(|state| {
        let (remaining, calls) = state.get();
        state.set((remaining.saturating_sub(1), calls + 1));
        remaining > 0
    });
    if refuse { ptr::null_mut() } else { __real_ZSTD_createDCtx() }
}

#[no_mangle]
unsafe extern "C" fn __wrap_ZSTD_freeDCtx(context: *mut ZSTD_DCtx) -> usize {
    let result = __real_ZSTD_freeDCtx(context);
    if !context.is_null() && result == 0 {
        DECODER_FREES.with(|count| count.set(count.get() + 1));
    }
    result
}

// Linked only into the isolated component test. Healthy calls use the actual
// pinned native library; refusal reproduces its documented null return.
#[no_mangle]
unsafe extern "C" fn __wrap_ZSTD_createCCtx() -> *mut ZSTD_CCtx {
    let refuse = CREATION.with(|state| {
        let (remaining, calls) = state.get();
        state.set((remaining.saturating_sub(1), calls + 1));
        remaining > 0
    });
    if refuse { ptr::null_mut() } else { __real_ZSTD_createCCtx() }
}

#[test]
fn context_allocation_refusal_is_retryable() {
    let mut all_ok = true;
    for size in [0, 1, 128 * 1024] {
        let correct = thread::spawn(move || {
            let input = vec![0x5a; size];
            let reference = zstd::bulk::compress(&input, crate::config::COMPRESS_LEVEL).unwrap();
            CREATION.with(|state| state.set((1, 0)));
            assert!(zstd_safe::CCtx::try_create().is_none());
            assert_eq!(CREATION.with(Cell::get), (0, 1), "native fault must be reached");

            CREATION.with(|state| state.set((2, 0)));
            let mut panics = 0;
            let mut refused = 0;
            for _ in 0..2 {
                match catch_unwind(|| crate::compress::compress(&input)) {
                    Err(_) => panics += 1,
                    Ok(Err(error)) if error.kind() == io::ErrorKind::OutOfMemory => refused += 1,
                    _ => {}
                }
            }
            let retry = crate::compress::compress(&input).unwrap();
            let reused = crate::compress::compress(&input).unwrap();
            let (remaining, attempts) = CREATION.with(Cell::get);
            let exact = retry == reference && reused == reference
                && retry.capacity() == retry.len() && reused.capacity() == reused.len()
                && crate::compress::try_decompress(&retry).unwrap() == input;
            let correct = panics == 0 && refused == 2 && remaining == 0 && attempts == 3 && exact;
            println!("COMPRESS_CONTEXT_CASE=observed bytes={size} panics={panics} refused={refused} attempts={attempts} exact={exact} correct={correct}");
            correct
        }).join().unwrap();
        all_ok &= correct;
    }
    assert!(all_ok, "native context refusal must be fallible, retryable and preserve reuse");
    println!("COMPRESS_CONTEXT=pass cases=3 refusals=6 probes=3 retries=exact context=reused threads=joined");
}

fn decode(path: &str, data: &[u8], limit: usize) -> io::Result<Vec<u8>> {
    match path {
        "default" => crate::compress::try_decompress(data),
        "limited" => crate::compress::try_decompress_with_limit(data, limit),
        "file" => crate::file_block::decode(data, true).map(|bytes| bytes.into_owned()),
        _ => panic!("unknown decoder path"),
    }
}

#[test]
fn decoder_context_refusal_is_retryable() {
    let mut all_ok = true;
    for path in ["default", "limited", "file"] {
        for size in [0, 1, 128 * 1024] {
            let input = vec![0x5a; size];
            let encoded = crate::compress::compress(&input).unwrap();
            let original = encoded.clone();
            DECODER_CREATION.with(|state| state.set((1, 0)));
            assert!(zstd_safe::DCtx::try_create().is_none());
            assert_eq!(DECODER_CREATION.with(Cell::get), (0, 1));

            DECODER_CREATION.with(|state| state.set((2, 0)));
            DECODER_FREES.with(|count| count.set(0));
            let raw = crate::file_block::decode(&input, false).unwrap();
            assert!(matches!(raw, std::borrow::Cow::Borrowed(_)));
            assert_eq!(raw.as_ptr(), input.as_ptr());
            assert_eq!(DECODER_CREATION.with(Cell::get), (2, 0));
            let mut panics = 0;
            let mut refused = 0;
            for _ in 0..2 {
                match catch_unwind(|| decode(path, &encoded, size)) {
                    Err(_) => panics += 1,
                    Ok(Err(error)) if error.kind() == io::ErrorKind::OutOfMemory => refused += 1,
                    _ => {}
                }
            }
            let exact = decode(path, &encoded, size).unwrap() == input
                && decode(path, &encoded, size).unwrap() == input && encoded == original;
            let (remaining, attempts) = DECODER_CREATION.with(Cell::get);
            let freed = DECODER_FREES.with(Cell::get);
            let correct = panics == 0 && refused == 2 && remaining == 0
                && attempts == 4 && freed == 2 && exact;
            println!("DECODE_CONTEXT_CASE=observed path={path} bytes={size} panics={panics} refused={refused} attempts={attempts} freed={freed} exact={exact} correct={correct}");
            all_ok &= correct;
        }
    }
    assert!(all_ok, "decoder context refusal must return errors and retire successful contexts");
    println!("DECODE_CONTEXT=pass paths=3 sizes=3 refusals=18 probes=9 raw=borrowed retries=exact contexts=freed");
}

#[test]
fn decoders_require_complete_frames() {
    for size in [0, 1, 8193] {
        let input = vec![0x5a; size];
        let encoded = crate::compress::compress(&input).unwrap();
        let mut concatenated = encoded.clone();
        concatenated.extend_from_slice(&encoded);
        for path in ["default", "limited", "file"] {
            assert_eq!(decode(path, &encoded, size).unwrap(), input);
            assert_eq!(decode(path, &concatenated, size * 2).unwrap(), input.repeat(2));
            for end in 0..encoded.len() {
                assert!(decode(path, &encoded[..end], size).is_err(), "{path} truncated at {end}");
                if end > 0 {
                    assert!(decode(path, &concatenated[..encoded.len() + end], size * 2).is_err(),
                        "{path} truncated second frame at {end}");
                }
            }
            let mut trailing = encoded.clone();
            trailing.push(0xff);
            assert!(decode(path, &trailing, size).is_err(), "{path} accepted trailing garbage");
        }
    }
}
