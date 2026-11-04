//! Allocator observation is compiled only by the isolated allocation profile.
//! It counts calls and exposes owned retirement barriers to an external observer.
//! Rust never reads freed or deinitialized allocation contents.
use super::{compute_isk, compute_tag, derive_generator, derive_mac_key, lv_cat, verify_tag,
    HmacSha512, Mac, AD_INITIATOR, AD_RESPONDER};
use std::{alloc::{GlobalAlloc, Layout, System}, cell::Cell, hint::black_box};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Counts { allocations: usize, reallocations: usize }

thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static COUNTS: Cell<Counts> = const { Cell::new(Counts { allocations: 0, reallocations: 0 }) };
    static RETIREMENT: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
}

fn record(reallocation: bool) {
    if ACTIVE.try_with(Cell::get).unwrap_or(false) {
        let _ = COUNTS.try_with(|slot| {
            let mut count = slot.get();
            if reallocation { count.reallocations = count.reallocations.wrapping_add(1); }
            else { count.allocations = count.allocations.wrapping_add(1); }
            slot.set(count);
        });
    }
}

struct Observer;
unsafe impl GlobalAlloc for Observer {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(false);
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(false);
        System.alloc_zeroed(layout)
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record(true);
        if RETIREMENT.try_with(|slot| slot.get().map(|value| value.0) == Some(pointer as usize))
            .unwrap_or(false) { std::process::abort(); }
        System.realloc(pointer, layout, size)
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let watched = RETIREMENT.try_with(|slot| {
            if slot.get() == Some((pointer as usize, layout.size())) {
                slot.set(None);
                true
            } else { false }
        }).unwrap_or(false);
        if watched { observer_barrier(b"RELEASE\n"); }
        System.dealloc(pointer, layout)
    }
}

// Only the isolated observer invokes this ignored test. The allocator hook
// pauses before System.dealloc, without allocating, panicking or reading bytes.
// The parent observes its own child's physical memory through the kernel.
fn observer_barrier(message: &[u8]) {
    extern "C" {
        fn write(fd: i32, data: *const u8, length: usize) -> isize;
        fn read(fd: i32, data: *mut u8, length: usize) -> isize;
    }
    let mut acknowledgement = 0u8;
    // SAFETY: fixed live buffers and the fixture's stdin/stderr pipes; no Rust
    // allocation contents are read here. Any short/failed exchange aborts.
    unsafe {
        if write(2, message.as_ptr(), message.len()) != message.len() as isize
            || read(0, &mut acknowledgement, 1) != 1 || acknowledgement != b'+'
        { std::process::abort(); }
    }
}

struct RetirementWatch;
impl RetirementWatch {
    fn new(bytes: &Vec<u8>) -> Self {
        assert!(!bytes.is_empty() && bytes.len() <= 128 && bytes.capacity() <= 256);
        assert!(RETIREMENT.with(|slot| slot.get().is_none()));
        eprintln!("WATCH address={:x} length={} capacity={}",
            bytes.as_ptr() as usize, bytes.len(), bytes.capacity());
        observer_barrier(b"LIVE\n");
        RETIREMENT.with(|slot| slot.set(Some((bytes.as_ptr() as usize, bytes.capacity()))));
        Self
    }
    fn finish(self, released: bool) {
        assert_eq!(RETIREMENT.with(|slot| slot.get().is_none()), released);
    }
}
impl Drop for RetirementWatch {
    fn drop(&mut self) { RETIREMENT.with(|slot| slot.set(None)); }
}

#[test]
#[ignore = "requires the isolated owned-child memory observer"]
fn credential_retirement_probe() {
    use super::{Initiator, Responder, PakeError, CI_PORT};
    const FIXTURE: &str = "public-pake-erasure-fixture-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    assert!(!cfg!(debug_assertions));
    let case = std::env::var("PAKE_ERASURE_CASE").unwrap();
    match case.as_str() {
        "control-plain" | "control-tail" | "control-unreleased" => {
            let bytes = if case == "control-tail" {
                let mut bytes = vec![0; 64];
                bytes[63] = 0x5a;
                bytes
            } else { FIXTURE.as_bytes().to_vec() };
            let watch = RetirementWatch::new(&bytes);
            if case == "control-unreleased" {
                watch.finish(false);
                drop(bytes);
            } else {
                drop(bytes);
                watch.finish(true);
            }
        }
        "drop-initiator" | "refuse-initiator" | "advance-initiator" | "unwind-initiator" => {
            let (state, step1) = Initiator::new(FIXTURE, CI_PORT).unwrap();
            let (responder, mut step2) = Responder::new(FIXTURE, CI_PORT).unwrap()
                .recv_step1(&step1).unwrap();
            let watch = RetirementWatch::new(&state.prs);
            match case.as_str() {
                "drop-initiator" => drop(state),
                "refuse-initiator" => {
                    step2.adb = AD_INITIATOR.to_vec();
                    assert!(matches!(state.recv_step2(&step2), Err(PakeError::AdMismatch)));
                }
                "advance-initiator" => {
                    let (pending, step3) = state.recv_step2(&step2).unwrap();
                    let (keys, step4) = responder.recv_step3(&step3).unwrap();
                    let peer_keys = pending.recv_step4(&step4).unwrap();
                    assert!(keys.send == peer_keys.recv && keys.recv == peer_keys.send);
                }
                "unwind-initiator" => {
                    assert!(std::panic::catch_unwind(move || {
                        let _state = state;
                        std::panic::resume_unwind(Box::new(()));
                    }).is_err());
                }
                _ => unreachable!(),
            }
            watch.finish(true);
        }
        "drop-responder" | "refuse-responder" | "advance-responder" | "unwind-responder" => {
            let state = Responder::new(FIXTURE, CI_PORT).unwrap();
            let (initiator, mut step1) = Initiator::new(FIXTURE, CI_PORT).unwrap();
            let watch = RetirementWatch::new(&state.prs);
            match case.as_str() {
                "drop-responder" => drop(state),
                "refuse-responder" => {
                    step1.ada = AD_RESPONDER.to_vec();
                    assert!(matches!(state.recv_step1(&step1), Err(PakeError::AdMismatch)));
                }
                "advance-responder" => {
                    let (pending, step2) = state.recv_step1(&step1).unwrap();
                    let (peer, step3) = initiator.recv_step2(&step2).unwrap();
                    let (keys, step4) = pending.recv_step3(&step3).unwrap();
                    let peer_keys = peer.recv_step4(&step4).unwrap();
                    assert!(keys.send == peer_keys.recv && keys.recv == peer_keys.send);
                }
                "unwind-responder" => {
                    assert!(std::panic::catch_unwind(move || {
                        let _state = state;
                        std::panic::resume_unwind(Box::new(()));
                    }).is_err());
                }
                _ => unreachable!(),
            }
            watch.finish(true);
        }
        _ => panic!("unknown retirement case"),
    }
    eprintln!("DONE");
}

#[global_allocator]
static ALLOCATOR: Observer = Observer;

fn observe(action: impl FnOnce()) -> Counts {
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) { ACTIVE.with(|active| active.set(false)); }
    }
    COUNTS.with(|count| count.set(Counts::default()));
    ACTIVE.with(|active| assert!(!active.replace(true)));
    let guard = Guard;
    action();
    drop(guard);
    COUNTS.with(Cell::get)
}

#[test]
fn no_transient_secret_heap_copies() {
    assert!(!cfg!(debug_assertions));
    let control = observe(|| { black_box(vec![black_box(0x5au8); black_box(128)]); });
    let prs = [0x93u8; 64];
    let sid = [0x62u8; 32];
    let ci = b"allocation-observation";
    let generator = observe(|| { black_box(derive_generator(black_box(&prs), ci, &sid)); });
    let ya = [0x27u8; 32];
    let yb = [0xe1u8; 32];
    let k = [0xb4u8; 32];
    let isk = observe(|| { black_box(compute_isk(&ya, AD_INITIATOR, &yb, AD_RESPONDER, &sid, black_box(&k))); });
    let isk_bytes = [0x47u8; 64];
    let mac_key = observe(|| { black_box(derive_mac_key(&sid, black_box(&isk_bytes))); });
    println!("PAKE_ALLOCATION_CASE=control allocations={} reallocations={}", control.allocations, control.reallocations);
    println!("PAKE_ALLOCATION_CASE=generator allocations={} reallocations={}", generator.allocations, generator.reallocations);
    println!("PAKE_ALLOCATION_CASE=isk allocations={} reallocations={}", isk.allocations, isk.reallocations);
    println!("PAKE_ALLOCATION_CASE=mac-key allocations={} reallocations={}", mac_key.allocations, mac_key.reallocations);
    assert!(control.allocations > 0, "allocator observer did not detect its control");
    assert_eq!((generator, isk, mac_key), (Counts::default(), Counts::default(), Counts::default()));

    let key = [0x39u8; 64];
    let mut allocating_confirmations = 0;
    for (case, (y_len, ad_len)) in [(32, 6), (0, 0), (127, 128), (128, 127), (255, 256)]
        .into_iter().enumerate()
    {
        let y = vec![0x27; y_len];
        let ad = vec![0x61; ad_len];
        // Materialized reference outside observation; production must retain
        // these exact bytes without allocating its own temporary encoding.
        let mut reference = HmacSha512::new_from_slice(&key).unwrap();
        reference.update(&lv_cat(&[&y, &ad]));
        let expected: [u8; 64] = reference.finalize().into_bytes().into();
        let mut actual = [0; 64];
        let generated = observe(|| { actual = black_box(compute_tag(black_box(&key), &y, &ad)); });
        assert_eq!(actual, expected);
        println!("PAKE_ALLOCATION_CASE=tag-{case}-generate allocations={} reallocations={}",
            generated.allocations, generated.reallocations);
        allocating_confirmations += usize::from(generated != Counts::default());
        for flipped in [None, Some(0), Some(63)] {
            let mut tag = expected;
            if let Some(index) = flipped { tag[index] ^= 1; }
            let mut accepted = false;
            let verified = observe(|| {
                accepted = black_box(verify_tag(black_box(&key), &y, &ad, black_box(&tag)));
            });
            assert_eq!(accepted, flipped.is_none());
            println!("PAKE_ALLOCATION_CASE=tag-{case}-verify-{flipped:?} accepted={accepted} allocations={} reallocations={}",
                verified.allocations, verified.reallocations);
            allocating_confirmations += usize::from(verified != Counts::default());
        }
    }
    assert_eq!(allocating_confirmations, 0, "confirmation must not allocate temporary encodings");
}
