//! Complete production Enigo Linux crate through the production private loader.
use enigo::{Enigo, Key, KeyboardControllable, MouseButton, MouseControllable};
use hbb_common::{libc, x11::xlib::*};
use std::{ptr, thread, time::{Duration, Instant}};

struct DisplayOwner(*mut Display);
impl Drop for DisplayOwner {
    fn drop(&mut self) { assert_eq!(unsafe { XCloseDisplay(self.0) }, 0); }
}
fn descriptors() -> usize { std::fs::read_dir("/proc/self/fd").unwrap().count() }
unsafe fn pointer(display: *mut Display) -> (i32, i32, u32) {
    let (mut root, mut child, mut x, mut y, mut wx, mut wy, mut mask) = (0, 0, 0, 0, 0, 0, 0);
    assert_ne!(XQueryPointer(display, XDefaultRootWindow(display), &mut root, &mut child,
                           &mut x, &mut y, &mut wx, &mut wy, &mut mask), 0);
    (x, y, mask)
}
unsafe fn observe(display: *mut Display, check: impl Fn((i32, i32, u32)) -> bool) {
    let until = Instant::now() + Duration::from_millis(250);
    loop {
        XSync(display, 0);
        if check(pointer(display)) { return; }
        assert!(Instant::now() < until, "real input effect was not observed");
        thread::sleep(Duration::from_millis(1));
    }
}
fn main() {
    assert_eq!(unsafe { libc::geteuid() }, 4000);
    assert_eq!(hbb_common::platform::linux::get_display_server(), "x11");
    let scenario = std::env::args().nth(1).unwrap();
    let baseline = descriptors();
    let display = DisplayOwner(unsafe { XOpenDisplay(ptr::null()) });
    assert!(!display.0.is_null());
    let connected = descriptors();
    if scenario != "complete" && scenario != "reject-key-down" {
        for _ in 0..8 {
            let mut enigo = Enigo::new();
            let refused = enigo.key_down(Key::Shift).is_err();
            assert!(enigo.mouse_down(MouseButton::Left).is_err());
            drop(enigo);
            assert_eq!(descriptors(), connected);
            if !refused {
                drop(display);
                assert_eq!(descriptors(), baseline);
                panic!("unavailable Enigo key-down was reported as successful");
            }
        }
        drop(display);
        assert_eq!(descriptors(), baseline);
        println!("XDO_ENIGO_COMPONENT=pass scenario={scenario} attempts=8 key_down=unavailable mouse=unavailable descriptors=retired");
        return;
    }
    unsafe {
        let root = XDefaultRootWindow(display.0);
        let window = XCreateSimpleWindow(display.0, root, 0, 0, 320, 240, 0, 0, 0);
        XSelectInput(display.0, window, KeyPressMask | KeyReleaseMask);
        XMapWindow(display.0, window);
        XSetInputFocus(display.0, window, RevertToParent, CurrentTime);
        XSync(display.0, 0);
        for index in 0..8 {
            let mut enigo = Enigo::new();
            enigo.set_delay(0);
            assert_eq!(descriptors(), connected + 1, "one Enigo-owned display must exist");
            enigo.mouse_move_to(71 + index, 93).unwrap();
            observe(display.0, |(x, y, _)| (x, y) == (71 + index, 93));
            for key in [Key::Sleep, Key::Layout('\0'), Key::Raw(0), Key::Raw(256), Key::Raw(u16::MAX)] {
                assert!(enigo.key_down(key).is_err(), "unsupported key was admitted");
            }
            let result = enigo.key_down(Key::Shift);
            if scenario == "reject-key-down" {
                let rejected = result.as_ref().err().map(|error| error.to_string());
                assert_eq!(pointer(display.0).2 & ShiftMask, 0);
                drop(enigo);
                assert_eq!(descriptors(), connected);
                if rejected.as_deref() != Some("libxdo key down failed with status 7") {
                    drop(display);
                    assert_eq!(descriptors(), baseline);
                    panic!("Enigo discarded the native key-down refusal: {rejected:?}");
                }
                continue;
            }
            result.unwrap();
            observe(display.0, |(_, _, mask)| mask & ShiftMask != 0);
            enigo.key_up(Key::Shift);
            observe(display.0, |(_, _, mask)| mask & ShiftMask == 0);
            let raw = XKeysymToKeycode(display.0, b'a' as libc::c_ulong);
            assert!(raw >= 8);
            enigo.key_down(Key::Raw(raw.into())).unwrap();
            enigo.key_up(Key::Raw(raw.into()));
            enigo.key_sequence_result("a").unwrap();
            let until = Instant::now() + Duration::from_millis(250);
            let mut events = Vec::new();
            while events.len() < 4 {
                XSync(display.0, 0);
                while XPending(display.0) > 0 {
                    let mut event: XEvent = std::mem::zeroed();
                    XNextEvent(display.0, &mut event);
                    if matches!(event.get_type(), KeyPress | KeyRelease)
                        && XLookupKeysym(&mut event.key, 0) == b'a' as libc::c_ulong {
                        events.push(event.get_type());
                    }
                }
                assert!(Instant::now() < until, "Enigo text event receipt expired");
                if events.len() < 4 { thread::sleep(Duration::from_millis(1)); }
            }
            assert_eq!(events, [KeyPress, KeyRelease, KeyPress, KeyRelease]);
            drop(enigo);
            assert_eq!(descriptors(), connected);
        }
        XDestroyWindow(display.0, window);
        XSync(display.0, 0);
    }
    drop(display);
    assert_eq!(descriptors(), baseline);
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    println!("XDO_ENIGO_COMPONENT=pass scenario={scenario} attempts=8 key_down={} pointer=actual descriptors=retired",
             if scenario == "complete" { "delivered" } else { "native-error" });
}
