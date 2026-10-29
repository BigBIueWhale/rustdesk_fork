//! Allocator observation is compiled only by the isolated allocation profile.
//! It counts calls, without inspecting freed or uninitialized memory.
use super::{compute_isk, derive_generator, AD_INITIATOR, AD_RESPONDER};
use std::{alloc::{GlobalAlloc, Layout, System}, cell::Cell, hint::black_box};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Counts { allocations: usize, reallocations: usize }

thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static COUNTS: Cell<Counts> = const { Cell::new(Counts { allocations: 0, reallocations: 0 }) };
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
        System.realloc(pointer, layout, size)
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        System.dealloc(pointer, layout)
    }
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
    println!("PAKE_ALLOCATION_CASE=control allocations={} reallocations={}", control.allocations, control.reallocations);
    println!("PAKE_ALLOCATION_CASE=generator allocations={} reallocations={}", generator.allocations, generator.reallocations);
    println!("PAKE_ALLOCATION_CASE=isk allocations={} reallocations={}", isk.allocations, isk.reallocations);
    assert!(control.allocations > 0, "allocator observer did not detect its control");
    assert_eq!((generator, isk), (Counts::default(), Counts::default()));
}
