//! Exercise the entire repository-owned Linux TFC crate against real, private Xvfb.
#![allow(dead_code)]
use std::{mem::{align_of, size_of, MaybeUninit}, ptr};
use tfc::{Context, GenericError, UnicodeKeyboardContext};

// The exact production declaration is also compiled for native layout measurement.
mod ffi {
    #[path = "/work/libs/tfc/src/linux_x11/ffi/xlib.rs"] mod xlib;
    pub use xlib::*;
    #[path = "/work/libs/tfc/src/linux_x11/ffi/xkb.rs"] mod xkb;
    pub use xkb::*;
}
extern "C" {
    fn input_state_layout(index: u32) -> usize;
    fn input_install_error_handler();
    fn input_error_count() -> u32;
    fn input_last_error() -> u32;
    fn input_bad_device_errors() -> u32;
    fn input_restore_error_handler();
    fn input_reset(fault: u32);
    fn input_count(index: u32) -> u32;
    fn input_rejected_status() -> i32;
    fn input_expected_error() -> i32;
    fn input_reject_next_state();
    fn input_observer_open();
    fn input_observe(character: u32, presses: u32, releases: u32);
    fn input_observer_close();
}
fn fd_count() -> usize { std::fs::read_dir("/proc/self/fd").unwrap().count() }
fn counts() -> [u32; 11] { std::array::from_fn(|i| unsafe { input_count(i as u32) }) }
fn rust_layout() -> [usize; 16] {
    let state = MaybeUninit::<ffi::XkbStateRec>::uninit();
    let p = state.as_ptr();
    macro_rules! offset { ($field:ident) => { unsafe { ptr::addr_of!((*p).$field) as usize - p as usize } }; }
    [size_of::<ffi::XkbStateRec>(), align_of::<ffi::XkbStateRec>(),
     offset!(group), offset!(base_group), offset!(latched_group), offset!(locked_group),
     offset!(mods), offset!(base_mods), offset!(latched_mods), offset!(locked_mods),
     offset!(compat_state), offset!(grab_mods), offset!(compat_grab_mods),
     offset!(lookup_mods), offset!(compat_lookup_mods), offset!(ptr_buttons)]
}
fn main() {
    let native: [usize; 16] = std::array::from_fn(|i| unsafe { input_state_layout(i as u32) });
    assert_eq!(native, [18, 2, 0, 2, 4, 1, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16]);
    assert_eq!(rust_layout(), native);
    println!("X11_INPUT_LAYOUT=pass source=production fields=14 size=18 align=2 oracle=client-header");
    let initial = fd_count();
    unsafe { input_observer_open(); }
    let observer_fds = fd_count();
    assert_eq!(observer_fds, initial + 1);
    let expected_error = unsafe { input_expected_error() };
    assert!(expected_error > 0);
    for iteration in 0..16 {
        unsafe { input_reset(0); }
        let mut context = Context::new().expect("actual TFC context");
        assert_eq!(fd_count(), observer_fds + 1);
        assert_eq!(counts(), [1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0]);
        if iteration == 0 {
            let libraries: std::collections::BTreeSet<_> = std::fs::read_to_string("/proc/self/maps")
                .unwrap().lines().filter_map(|line| line.split_whitespace().last())
                .filter(|path| path.contains("/libX11.so.")).map(str::to_owned).collect();
            assert_eq!(libraries.len(), 1);
            println!("X11_INPUT_LOADED library={}", libraries.iter().next().unwrap());
        }
        context.unicode_char('a').unwrap();
        unsafe { input_observe('a' as u32, 1, 1); }
        context.unicode_char_down('b').unwrap();
        unsafe { input_observe('b' as u32, 1, 0); }
        context.unicode_char_up('b').unwrap();
        unsafe { input_observe('b' as u32, 0, 1); }
        // Send one invalid-device query through the actual production character path.
        unsafe { input_install_error_handler(); input_reject_next_state(); }
        let error = context.unicode_char('c').expect_err("native invalid device must reject");
        let status = unsafe { input_rejected_status() };
        assert_ne!(status, 0);
        match error {
            GenericError::Platform(error) => assert_eq!(error.to_string(), format!("Failed to get keyboard state: {status}")),
            error => panic!("wrong failure: {error}"),
        }
        assert_eq!(unsafe { input_error_count() }, 1);
        assert_eq!(unsafe { input_bad_device_errors() }, 1);
        assert_eq!(unsafe { input_last_error() }, expected_error as u32);
        unsafe { input_restore_error_handler(); input_observe('c' as u32, 0, 0); }
        assert_eq!(counts()[10], 4); // no key emission on the rejected query
        context.unicode_char('c').unwrap();
        unsafe { input_observe('c' as u32, 1, 1); }
        drop(context);
        assert_eq!(counts(), [1, 1, 1, 1, 1, 1, 1, 1, 5, 1, 6]);
        assert_eq!(fd_count(), observer_fds);
    }
    println!("X11_INPUT_EVENTS=pass source=whole-production-tfc repeats=16 characters=a,b,c events=96 observer=real-window query_rejections=16 rejected_emissions=0 recovery=same-context");
    for fault in [1, 2, 3, 5] {
        for _ in 0..16 {
            unsafe { input_reset(fault); }
            let error = match Context::new() {
                Ok(_) => panic!("injected constructor failure {fault} was accepted"),
                Err(error) => error,
            };
            let expected = match fault {
                1 => "Failed to get keyboard mapping",
                2 => "Failed to get keyboard information",
                3 => "Failed to get modifier key mapping",
                5 => "Invalid keyboard mapping",
                _ => unreachable!(),
            };
            match error {
                GenericError::Platform(error) => assert_eq!(error.to_string(), expected),
                error => panic!("wrong constructor failure: {error}"),
            }
            let c = counts();
            assert_eq!(c[0], 1);
            assert_eq!(c[0], c[1]);
            assert_eq!(c[2], c[3]);
            assert_eq!(c[4], c[5]);
            assert_eq!(c[6], c[7]);
            assert_eq!(&c[8..], &[0, 0, 0]);
            assert_eq!(fd_count(), observer_fds);
        }
    }
    unsafe { input_observer_close(); }
    assert_eq!(fd_count(), initial);
    println!("X11_INPUT_LIFETIME=pass source=whole-production-tfc successful_contexts=16 connection=one failures=64 cause=injected-null,invalid-count symbols=paired keyboard=full-free modifiers=paired descriptors=retired scope=direct-owned-calls");
}
