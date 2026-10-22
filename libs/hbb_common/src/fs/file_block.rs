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
    let mut output = Vec::new();
    output.try_reserve_exact(SIZE + 1)
        .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    output.resize(SIZE + 1, 0);
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
pub(super) mod tests {
    use super::*;
    use crate::compress::{compress, try_decompress_with_limit};
    use std::{alloc::{GlobalAlloc, Layout, System}, cell::Cell, process::Command};

    thread_local! {
        static OUTPUT_ALLOCATION: Cell<(bool, usize)> = const { Cell::new((false, 0)) };
        static EXACT_ALLOCATION: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
        static REFUSE_ALL_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
        static DECODER_INPUT_ALLOCATION: Cell<(usize, usize, bool)> = const { Cell::new((0, 0, false)) };
    }

    struct OutputAllocator;

    pub(crate) fn fail_next_exact_allocation(size: usize) {
        assert!(size > 0);
        EXACT_ALLOCATION.with(|state| state.set((size, 0)));
    }

    pub(crate) fn exact_allocation_failure_state() -> (usize, usize) {
        EXACT_ALLOCATION.with(Cell::get)
    }

    pub(crate) fn with_allocations_refused<T>(action: impl FnOnce() -> T) -> T {
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                REFUSE_ALL_ALLOCATIONS.with(|state| state.set(false));
            }
        }
        assert!(!REFUSE_ALL_ALLOCATIONS.with(|state| state.replace(true)));
        let restore = Restore;
        let result = action();
        drop(restore);
        result
    }

    fn refuse_allocation(size: usize) -> bool {
        if DECODER_INPUT_ALLOCATION.try_with(|state| {
            let (target, count, refuse) = state.get();
            if target != 0 && target == size {
                state.set((target, count + 1, refuse));
                refuse
            } else {
                false
            }
        }).unwrap_or(false) {
            return true;
        }
        if REFUSE_ALL_ALLOCATIONS.try_with(Cell::get).unwrap_or(false) {
            return true;
        }
        size == SIZE + 1 && OUTPUT_ALLOCATION.try_with(|state| {
            let (armed, refusals) = state.get();
            if armed {
                state.set((false, refusals + 1));
            }
            armed
        }).unwrap_or(false) || EXACT_ALLOCATION.try_with(|state| {
            let (target, refusals) = state.get();
            if target != 0 && target == size {
                state.set((0, refusals + 1));
                true
            } else {
                false
            }
        }).unwrap_or(false)
    }

    unsafe impl GlobalAlloc for OutputAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if refuse_allocation(layout.size()) {
                std::ptr::null_mut()
            } else {
                System.alloc(layout)
            }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            if refuse_allocation(layout.size()) {
                std::ptr::null_mut()
            } else {
                System.alloc_zeroed(layout)
            }
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            if refuse_allocation(size) {
                std::ptr::null_mut()
            } else {
                System.realloc(pointer, layout, size)
            }
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            System.dealloc(pointer, layout)
        }
    }

    #[global_allocator]
    static OUTPUT_ALLOCATOR: OutputAllocator = OutputAllocator;

    #[cfg(target_os = "linux")]
    #[test]
    fn slice_decoding_uses_existing_input_storage() {
        use std::os::unix::process::ExitStatusExt;

        fn observe<T>(refuse: bool, action: impl FnOnce() -> T) -> (T, usize) {
            struct Reset;
            impl Drop for Reset {
                fn drop(&mut self) {
                    DECODER_INPUT_ALLOCATION.with(|state| state.set((0, 0, false)));
                }
            }
            let target = zstd::zstd_safe::DCtx::in_size();
            assert!(target > SIZE + 1);
            DECODER_INPUT_ALLOCATION.with(|state| {
                assert_eq!(state.get(), (0, 0, false));
                state.set((target, 0, refuse));
            });
            let reset = Reset;
            let result = action();
            let count = DECODER_INPUT_ALLOCATION.with(|state| state.get().1);
            drop(reset);
            (result, count)
        }

        if let Ok(case) = std::env::var("RD_FILE_BLOCK_ALLOC_INPUT_CASE") {
            if case == "probe" {
                observe(true, || std::hint::black_box(
                    Vec::<u8>::with_capacity(zstd::zstd_safe::DCtx::in_size())
                ));
                panic!("positive allocation-refusal probe did not abort");
            }
            let mut fields = case.split(':');
            let mode = fields.next().unwrap();
            let path = fields.next().unwrap();
            let size: usize = fields.next().unwrap().parse().unwrap();
            assert!(fields.next().is_none());
            assert!(matches!(mode, "count" | "refuse"));
            assert!(matches!(path, "shared" | "file"));
            assert!([0, 1, SIZE].contains(&size));
            let input = vec![0x5a; size];
            let encoded = compress(&input).unwrap();
            let original = encoded.clone();
            let (results, allocations) = observe(mode == "refuse", || {
                let decode_once = || match path {
                    "shared" => try_decompress_with_limit(&encoded, size),
                    _ => decode(&encoded, true).map(Cow::into_owned),
                };
                (decode_once(), decode_once())
            });
            assert_eq!(results.0.unwrap(), input);
            assert_eq!(results.1.unwrap(), input);
            assert_eq!(encoded, original);
            println!("DECOMPRESSION_INPUT_CASE=observed mode={mode} path={path} bytes={size} reads=2 input_allocations={allocations} exact=true");
            return;
        }

        let thread = std::thread::current();
        let name = thread.name().unwrap();
        let run = |case: &str| Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env("RD_FILE_BLOCK_ALLOC_INPUT_CASE", case)
            .output().unwrap();
        let probe = run("probe");
        let probe_ok = probe.status.signal() == Some(6)
            && String::from_utf8_lossy(&probe.stderr).contains("memory allocation of");
        println!("DECOMPRESSION_INPUT_PROBE=observed bytes={} signal={:?} passed={probe_ok}",
            zstd::zstd_safe::DCtx::in_size(), probe.status.signal());
        let mut all_ok = probe_ok;
        for mode in ["count", "refuse"] {
            for path in ["shared", "file"] {
                for size in [0, 1, SIZE] {
                    let output = run(&format!("{mode}:{path}:{size}"));
                    let mut records = 0;
                    for line in String::from_utf8_lossy(&output.stdout).lines() {
                        if let Some((_, observation)) = line.split_once("DECOMPRESSION_INPUT_CASE=") {
                            println!("DECOMPRESSION_INPUT_CASE={observation}");
                            records += 1;
                            all_ok &= observation.contains(" input_allocations=0 exact=true");
                        }
                    }
                    print!("{}", String::from_utf8_lossy(&output.stderr));
                    println!("DECOMPRESSION_INPUT_CHILD=observed mode={mode} path={path} bytes={size} success={} signal={:?}",
                        output.status.success(), output.status.signal());
                    all_ok &= output.status.success() && records == 1;
                }
            }
        }
        assert!(all_ok, "slice decoding must use its existing input storage");
        println!("DECOMPRESSION_INPUT=pass paths=2 sizes=3 healthy=6 refused=6 probe=SIGABRT children=joined");
    }

    #[test]
    fn allocation_refusal_returns_error_and_preserves_retry() {
        if !matches!(std::env::var("RD_FILE_BLOCK_ALLOC_CHILD").as_deref(), Ok("1")) {
            let thread = std::thread::current();
            let name = thread.name().expect("native test name");
            let output = Command::new(std::env::current_exe().expect("native test artifact"))
                .args(["--exact", name, "--nocapture", "--test-threads=1"])
                .env("RD_FILE_BLOCK_ALLOC_CHILD", "1")
                .output().expect("join allocation child");
            assert!(output.status.success(), "allocation child {:?}: {}{}",
                output.status, String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr));
            assert!(String::from_utf8_lossy(&output.stdout).contains(
                "FILE_BLOCK_ALLOCATION=pass cases=3 refusals=3 raw=borrowed retries=exact"));
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains(
                "FILE_COMPRESSION_ALLOCATION=pass cases=3 refusals=3 retries=exact wire=unchanged"));
            for line in stdout.lines() {
                if let Some((_, message)) = line.split_once("FILE_COMPRESSION_") {
                    println!("FILE_COMPRESSION_{message}");
                }
            }
            return;
        }

        for size in [0, 1, SIZE] {
            let input = vec![0x5a; size];
            let encoded = compress(&input).expect("production compression before fault");
            let reference = zstd::bulk::compress(&input, crate::config::COMPRESS_LEVEL)
                .expect("unchanged upstream compression control");
            assert_eq!(encoded, reference);
            let bound = zstd::zstd_safe::compress_bound(size);
            assert!(bound > 0);
            fail_next_exact_allocation(bound);
            let error = compress(&input).expect_err("refused compressed output is fallible");
            assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
            assert_eq!(exact_allocation_failure_state(), (0, 1));
            assert_eq!(compress(&input).expect("same-context compression retry"), reference);
            println!("FILE_COMPRESSION_CASE=pass bytes={size} allocation={bound} error=OutOfMemory retry=exact wire=unchanged");
            assert_eq!(decode(&encoded, true).unwrap().as_ref(), input);
            OUTPUT_ALLOCATION.with(|state| state.set((true, 0)));
            let raw = decode(&input, false).expect("raw input needs no output allocation");
            assert!(matches!(raw, Cow::Borrowed(_)));
            assert_eq!(raw.as_ptr(), input.as_ptr());
            assert_eq!(raw.as_ref(), input);
            OUTPUT_ALLOCATION.with(|state| assert_eq!(state.get(), (true, 0)));
            let error = decode(&encoded, true).expect_err("refused output allocation is fallible");
            assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
            OUTPUT_ALLOCATION.with(|state| assert_eq!(state.get(), (false, 1)));
            assert_eq!(decode(&encoded, true).expect("retry after one refusal").as_ref(), input);
        }
        println!("FILE_BLOCK_ALLOCATION=pass cases=3 refusals=3 raw=borrowed retries=exact");
        println!("FILE_COMPRESSION_ALLOCATION=pass cases=3 refusals=3 retries=exact wire=unchanged");
    }

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
            if window_log <= 26 {
                assert_eq!(try_decompress_with_limit(&refused, SIZE).expect("shared decoder control"), b"abc");
            } else {
                assert!(try_decompress_with_limit(&refused, SIZE).is_err());
            }
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
