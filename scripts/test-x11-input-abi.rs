//! Measure the exact TFC declarations against native client headers and real XKB writes.
//! A larger byte allocation contains every native write; no out-of-allocation write is used.
#![allow(dead_code)]

use std::{ffi::c_void, mem::{align_of, size_of, MaybeUninit}, ptr::NonNull};

mod ffi {
    mod xlib;
    pub use xlib::*;
    mod xkb;
    pub use xkb::*;
}

extern "C" {
    fn input_state_layout(index: u32) -> usize;
    fn input_native_state(display: *mut c_void, device: u32, buffer: *mut c_void) -> i32;
    fn input_bad_device_error(display: *mut c_void) -> i32;
    fn input_install_error_handler();
    fn input_error_count() -> u32;
    fn input_last_error() -> u32;
    fn input_bad_device_errors() -> u32;
    fn input_restore_error_handler();
}

struct DisplayOwner(NonNull<ffi::Display>);
impl Drop for DisplayOwner {
    fn drop(&mut self) {
        assert_eq!(unsafe { ffi::XCloseDisplay(self.0.as_ptr()) }, 0);
    }
}
struct ErrorHandlerOwner;
impl Drop for ErrorHandlerOwner {
    fn drop(&mut self) { unsafe { input_restore_error_handler() }; }
}

const SENTINEL: u8 = 0xa5;
const PREFIX: usize = 16;
#[repr(C, align(8))]
struct GuardedBuffer([u8; 96]);
impl GuardedBuffer {
    fn new() -> Self { Self([SENTINEL; 96]) }
    fn pointer(&mut self) -> *mut ffi::XkbStateRec {
        unsafe { self.0.as_mut_ptr().add(PREFIX).cast() }
    }
    fn assert_native_bounds(&self, native_size: usize) {
        assert!(self.0[..PREFIX].iter().all(|b| *b == SENTINEL));
        assert!(self.0[PREFIX + native_size..].iter().all(|b| *b == SENTINEL));
    }
}

fn rust_layout() -> [usize; 16] {
    let state = MaybeUninit::<ffi::XkbStateRec>::uninit();
    let p = state.as_ptr();
    macro_rules! offset {
        ($field:ident) => { unsafe { std::ptr::addr_of!((*p).$field) as usize - p as usize } };
    }
    [size_of::<ffi::XkbStateRec>(), align_of::<ffi::XkbStateRec>(),
     offset!(group), offset!(base_group), offset!(latched_group), offset!(locked_group),
     offset!(mods), offset!(base_mods), offset!(latched_mods), offset!(locked_mods),
     offset!(compat_state), offset!(grab_mods), offset!(compat_grab_mods),
     offset!(lookup_mods), offset!(compat_lookup_mods), offset!(ptr_buttons)]
}

fn fd_count() -> usize { std::fs::read_dir("/proc/self/fd").unwrap().count() }

fn main() {
    let rust = rust_layout();
    let native: [usize; 16] = std::array::from_fn(|i| unsafe { input_state_layout(i as u32) });
    // Exact diagnostic, not product acceptance: an unexpected target layout must fail visibly.
    assert_eq!(rust, [16, 2, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14]);
    assert_eq!(native, [18, 2, 0, 2, 4, 1, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16]);
    assert_eq!(rust[2..].iter().zip(&native[2..]).filter(|(a, b)| a != b).count(), 13);
    println!("X11_INPUT_ABI_OFFSETS rust={rust:?} native={native:?}");
    println!("X11_INPUT_ABI_FINDING=confirmed supplier=tfc rust_size=16 native_size=18 align=2 fields=14 offset_mismatches=13 oracle=client-header product_acceptance=false");

    let before = fd_count();
    {
        let display = DisplayOwner(NonNull::new(unsafe { ffi::XOpenDisplay(std::ptr::null()) })
                                   .expect("owned Xvfb display unavailable"));
        let libraries: std::collections::BTreeSet<_> = std::fs::read_to_string("/proc/self/maps")
            .unwrap().lines().filter_map(|line| line.split_whitespace().last())
            .filter(|path| path.contains("/libX11.so.")).map(str::to_owned).collect();
        assert_eq!(libraries.len(), 1);
        println!("X11_INPUT_ABI_LOADED library={}", libraries.iter().next().unwrap());
        let raw_display = display.0.as_ptr().cast::<c_void>();
        let expected_error = unsafe { input_bad_device_error(raw_display) };
        assert!(expected_error > 0);
        unsafe { input_install_error_handler() };
        let _handler = ErrorHandlerOwner;
        for iteration in 0..16 {
            for _ in 0..2 {
                let mut rust_buffer = GuardedBuffer::new();
                // The actual production declaration calls the real library. Its typed state
                // size is wrong, but the raw storage remains large/aligned enough for C.
                let status = unsafe { ffi::XkbGetState(display.0.as_ptr(), ffi::XkbUseCoreKbd,
                                                       rust_buffer.pointer()) };
                assert_eq!(status, ffi::False); // XkbGetState returns Status: Success == 0.
                rust_buffer.assert_native_bounds(native[0]);
                assert_eq!(&rust_buffer.0[PREFIX + rust[0]..PREFIX + native[0]], &[0, 0]);
                let mut control = GuardedBuffer::new();
                assert_eq!(unsafe { input_native_state(raw_display, ffi::XkbUseCoreKbd,
                                                       control.pointer().cast()) }, 0);
                control.assert_native_bounds(native[0]);
                assert_eq!(rust_buffer.0, control.0);
            }
            let mut rejected = GuardedBuffer::new();
            let status = unsafe { ffi::XkbGetState(display.0.as_ptr(), 255, rejected.pointer()) };
            assert_ne!(status, ffi::False);
            assert!(rejected.0.iter().all(|b| *b == SENTINEL));
            assert_eq!(unsafe { input_error_count() }, iteration + 1);
            assert_eq!(unsafe { input_last_error() }, expected_error as u32);
            assert_eq!(unsafe { input_bad_device_errors() }, iteration + 1);
        }
        // One final valid request proves recovery after the last real server rejection.
        let mut final_state = GuardedBuffer::new();
        assert_eq!(unsafe { input_native_state(raw_display, ffi::XkbUseCoreKbd,
                                               final_state.pointer().cast()) }, 0);
        final_state.assert_native_bounds(native[0]);
    }
    assert_eq!(fd_count(), before);
    println!("X11_INPUT_ABI_NATIVE=confirmed supplier=tfc queries=32 controls=33 rejected=16 rejection=XI-BadDevice:XKB-BadDevice recovery=same-connection write_beyond_rust_type=2 allocation_overrun=false guards=intact descriptors=retired product_acceptance=false");
}
