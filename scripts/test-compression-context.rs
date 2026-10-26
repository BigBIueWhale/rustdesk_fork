use std::{cell::Cell, io, panic::catch_unwind, ptr, thread};
use zstd::zstd_safe::{self, zstd_sys::ZSTD_CCtx};

thread_local! {
    static CREATION: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
}

extern "C" {
    fn __real_ZSTD_createCCtx() -> *mut ZSTD_CCtx;
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
