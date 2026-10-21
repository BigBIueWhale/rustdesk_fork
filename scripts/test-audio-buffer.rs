extern crate self as hbb_common;
pub use log;

#[path = "../src/client/audio_buffer.rs"]
mod audio_buffer;

#[cfg(feature = "capture-pcm-before")]
#[path = "../libs/hbb_common/src/mem.rs"]
mod before_capture_pcm;
#[cfg(not(feature = "capture-pcm-before"))]
#[path = "../src/server/audio_service/pcm.rs"]
mod capture_pcm;

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
    static LAYOUT_TRACKING: Cell<bool> = const { Cell::new(false) };
    static TRACKED_LAYOUT: Cell<Option<(*mut u8, Layout)>> = const { Cell::new(None) };
    static LAYOUT_MISMATCHES: Cell<usize> = const { Cell::new(0) };
}

fn record_layout(pointer: *mut u8, layout: Layout) {
    if !pointer.is_null() && LAYOUT_TRACKING.try_with(Cell::get).unwrap_or(false) {
        let _ = TRACKED_LAYOUT.try_with(|tracked| {
            if tracked.get().is_none() {
                tracked.set(Some((pointer, layout)));
            }
        });
    }
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
        let pointer = System.alloc(layout);
        record_layout(pointer, layout);
        pointer
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
        let original = TRACKED_LAYOUT.try_with(|tracked| {
            if let Some((target, original)) = tracked.get() {
                if target == pointer {
                    tracked.set(None);
                    if original != layout {
                        LAYOUT_MISMATCHES.with(|count| count.set(count.get() + 1));
                    }
                    return Some(original);
                }
            }
            None
        }).ok().flatten();
        // Observe the requested layout without forwarding a mismatch to System.
        let layout = original.unwrap_or(layout);
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

fn decode_capture<'a>(input: &[u8], output: &'a mut Vec<f32>) -> std::io::Result<&'a [f32]> {
    #[cfg(feature = "capture-pcm-before")]
    {
        // Directly exercise the existing aligned-allocation fallback and native-float cast.
        // This forces that component; it does not claim the ordinary allocator returns
        // a misaligned Vec or that a complete capture service executed.
        output.clear();
        if !input.is_empty() {
            let mut aligned = unsafe { before_capture_pcm::aligned_u8_vec(input.len(), 4) };
            aligned.extend_from_slice(input);
            let samples = unsafe {
                std::slice::from_raw_parts(aligned.as_ptr().cast::<f32>(), aligned.len() / 4)
            };
            output.extend_from_slice(samples);
        }
        Ok(output)
    }
    #[cfg(not(feature = "capture-pcm-before"))]
    capture_pcm::decode(input, output)
}

#[test]
fn capture_pcm_allocation_layout_matches_its_owner() {
    let input = [0.25f32, -0.5, 0., 1.].map(f32::to_ne_bytes).concat();
    let mut output = Vec::new();
    LAYOUT_MISMATCHES.with(|count| count.set(0));
    LAYOUT_TRACKING.with(|tracking| tracking.set(true));
    decode_capture(&input, &mut output).unwrap();
    LAYOUT_TRACKING.with(|tracking| tracking.set(false));
    assert_eq!(output, [0.25, -0.5, 0., 1.]);
    drop(output);
    assert!(TRACKED_LAYOUT.with(Cell::get).is_none());
    let mismatches = LAYOUT_MISMATCHES.with(Cell::get);
    println!("CAPTURE_PCM_LAYOUT=observed mismatches={mismatches}");
    assert_eq!(mismatches, 0, "allocation and deallocation layouts must match");
}

#[test]
fn capture_pcm_preserves_bits_at_every_byte_alignment() {
    let bits = [0u32, 0x8000_0000, 0x3e80_0000, 0xbf00_0000, 1, 0x7f80_0000, 0xff80_0000, 0x7fc1_2345];
    let bytes = bits.map(u32::to_ne_bytes).concat();
    let mut output = vec![123.];
    for offset in 0..4 {
        let mut storage = vec![0; offset];
        storage.extend_from_slice(&bytes);
        let samples = decode_capture(&storage[offset..], &mut output).unwrap();
        assert_eq!(samples.iter().map(|sample| sample.to_bits()).collect::<Vec<_>>(), bits);
    }
    assert!(decode_capture(&[], &mut output).unwrap().is_empty());
    assert_eq!(decode_capture(&0.5f32.to_ne_bytes(), &mut output).unwrap(), [0.5]);
}

#[test]
fn capture_pcm_refuses_partial_samples_before_output_changes() {
    let mut admitted = 0;
    for remainder in 1..4 {
        let mut bytes = 0.25f32.to_ne_bytes().to_vec();
        bytes.extend(vec![0; remainder]);
        let mut output = vec![0.5, -0.5];
        let pointer = output.as_ptr();
        let capacity = output.capacity();
        let result = decode_capture(&bytes, &mut output);
        if result.is_ok() {
            admitted += 1;
        } else {
            assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
            assert_eq!(output, [0.5, -0.5]);
            assert_eq!(output.as_ptr(), pointer);
            assert_eq!(output.capacity(), capacity);
        }
    }
    println!("CAPTURE_PCM_PARTIAL=observed cases=3 admitted={admitted}");
    assert_eq!(admitted, 0);
}

#[test]
fn capture_pcm_reuses_warmed_storage_without_allocating() {
    let input = vec![0.25f32; 960].into_iter().flat_map(f32::to_ne_bytes).collect::<Vec<_>>();
    let mut output = Vec::new();
    decode_capture(&input, &mut output).unwrap();
    let pointer = output.as_ptr();
    let mut allocations = 0;
    for _ in 0..1000 {
        allocations += allocations_during(|| {
            decode_capture(&input, &mut output).unwrap();
        });
        assert_eq!(output.as_ptr(), pointer);
        assert_eq!(output.len(), 960);
        assert!(output.iter().all(|sample| *sample == 0.25));
    }
    println!("CAPTURE_PCM_REUSE=observed frames=1000 samples_per_frame=960 allocations={allocations}");
    assert_eq!(allocations, 0);
}
