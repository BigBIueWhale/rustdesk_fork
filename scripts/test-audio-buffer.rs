extern crate self as hbb_common;
pub use log;

#[path = "../src/client/audio_buffer.rs"]
mod audio_buffer;

use dasp_sample::{FromSample, Sample};
use ringbuf::{ring_buffer::RbBase, Rb};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    sync::Mutex,
};

struct AllocationCounter;

thread_local! {
    static TRACKING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

fn record_allocation() {
    // Other test threads and thread teardown are outside the measured interval.
    if TRACKING.try_with(Cell::get).unwrap_or(false) {
        let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
    }
}

unsafe impl GlobalAlloc for AllocationCounter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        System.alloc_zeroed(layout)
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record_allocation();
        System.realloc(pointer, layout, size)
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        System.dealloc(pointer, layout)
    }
}

#[global_allocator]
static ALLOCATOR: AllocationCounter = AllocationCounter;

fn allocations_during(action: impl FnOnce()) -> usize {
    struct TrackingGuard;
    impl Drop for TrackingGuard {
        fn drop(&mut self) {
            TRACKING.with(|tracking| tracking.set(false));
        }
    }
    ALLOCATIONS.with(|count| count.set(0));
    TRACKING.with(|tracking| {
        assert!(!tracking.replace(true), "nested allocation measurement");
    });
    let guard = TrackingGuard;
    action();
    drop(guard);
    ALLOCATIONS.with(Cell::get)
}

fn convert<T: Sample + FromSample<f32>>(value: f32) -> T {
    T::from_sample(value)
}

#[test]
fn fill_converts_all_cpal_sample_types_with_correct_silence() {
    fn check<T: Sample + FromSample<f32> + std::fmt::Debug>() {
        let mut ring = ringbuf::HeapRb::new(4);
        ring.push_slice_overwrite(&[-0.5, 0.25]);
        let ring = Mutex::new(ring);
        let mut output = [T::EQUILIBRIUM; 4];
        audio_buffer::fill_output(&ring, &mut output, T::from_sample);
        assert_eq!(
            output,
            [
                T::from_sample(-0.5f32),
                T::from_sample(0.25f32),
                T::EQUILIBRIUM,
                T::EQUILIBRIUM,
            ]
        );
        assert_eq!(ring.lock().unwrap().occupied_len(), 0);
    }
    check::<i8>();
    check::<i16>();
    check::<i32>();
    check::<i64>();
    check::<u8>();
    check::<u16>();
    check::<u32>();
    check::<u64>();
    check::<f32>();
    check::<f64>();
}

#[test]
fn fill_has_no_allocations_in_the_warmed_normal_path() {
    let ring = Mutex::new(ringbuf::HeapRb::new(64));
    let mut output = [0.; 64];
    audio_buffer::fill_output(&ring, &mut output, convert::<f32>);
    assert!(allocations_during(|| {
        std::hint::black_box(vec![0u8; 32]);
    }) > 0, "allocation counter must observe its positive control");
    let mut observed = 0;
    for _ in 0..1000 {
        ring.lock().unwrap().push_slice_overwrite(&[0.5; 64]);
        observed += allocations_during(|| {
            audio_buffer::fill_output(&ring, &mut output, convert::<f32>);
        });
        assert_eq!(output, [0.5; 64]);
    }
    assert_eq!(observed, 0);
    let _producer = ring.lock().unwrap();
    assert_eq!(allocations_during(|| {
        audio_buffer::fill_output(&ring, &mut output, convert::<f32>);
    }), 0);
    assert_eq!(output, [0.; 64]);
}
