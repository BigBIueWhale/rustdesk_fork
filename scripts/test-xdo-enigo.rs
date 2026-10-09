//! Complete production Enigo Linux crate through the production private loader.
use enigo::{Enigo, ModifierKey, NumLockState, KeyboardControllable, MouseButton, MouseControllable};
use hbb_common::{libc, x11::xlib::*};
use std::{ptr, thread, time::{Duration, Instant}};

#[link(name = "Xtst")]
extern "C" {
    fn XTestFakeKeyEvent(display: *mut Display, keycode: u32, down: i32, delay: libc::c_ulong) -> i32;
}

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
    let scenario = std::env::args().nth(1).unwrap();
    let baseline = descriptors();
    let display = DisplayOwner(unsafe { XOpenDisplay(ptr::null()) });
    assert!(!display.0.is_null());
    let connected = descriptors();
    if scenario != "complete" && scenario != "reject-text" {
        for _ in 0..8 {
            let mut enigo = Enigo::new();
            let refused = enigo.key_sequence_result("A").is_err();
            assert!(enigo.mouse_down(MouseButton::Left).is_err());
            assert!(enigo.keyboard_state().is_err());
            drop(enigo);
            assert_eq!(descriptors(), connected);
            if !refused {
                drop(display);
                assert_eq!(descriptors(), baseline);
                panic!("unavailable Enigo text input was reported as successful");
            }
        }
        drop(display);
        assert_eq!(descriptors(), baseline);
        println!("XDO_ENIGO_COMPONENT=pass scenario={scenario} attempts=8 text=unavailable mouse=unavailable descriptors=retired");
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
            if scenario == "complete" {
                for key in ModifierKey::ALL {
                    let code = rdev::linux_keycode_from_key(key.rdev_key()).unwrap();
                    assert!(code >= 8);
                    assert!(!enigo.keyboard_state().unwrap().modifier_down(key));
                    assert_ne!(XTestFakeKeyEvent(display.0, code.into(), 1, 0), 0);
                    XSync(display.0, 0);
                    let mut observed = [0i8; 32];
                    assert_ne!(XQueryKeymap(display.0, observed.as_mut_ptr()), 0);
                    assert_ne!(observed[code as usize / 8] & (1 << (code % 8)), 0);
                    let state = enigo.keyboard_state().unwrap();
                    for other in ModifierKey::ALL {
                        assert_eq!(state.modifier_down(other), other == key, "exact identity {key:?}/{other:?}");
                        assert_eq!(state.modifier_family_down(other), (other as u8 & 3) == (key as u8 & 3));
                    }
                    assert_ne!(XTestFakeKeyEvent(display.0, code.into(), 0, 0), 0);
                    XSync(display.0, 0);
                    assert!(!enigo.keyboard_state().unwrap().modifier_down(key));
                }
                for (symbol, caps) in [(0xffe5, true), (0xff7f, false)] {
                    let code = XKeysymToKeycode(display.0, symbol);
                    assert!(code >= 8);
                    let state = enigo.keyboard_state().unwrap();
                    assert!(!if caps { state.caps_lock_enabled() } else { state.num_lock() == NumLockState::On });
                    for expected in [true, false] {
                        assert_ne!(XTestFakeKeyEvent(display.0, code.into(), 1, 0), 0);
                        assert_ne!(XTestFakeKeyEvent(display.0, code.into(), 0, 0), 0);
                        XSync(display.0, 0);
                        let state = enigo.keyboard_state().unwrap();
                        assert_eq!(if caps { state.caps_lock_enabled() } else { state.num_lock() == NumLockState::On }, expected);
                    }
                }
                while XPending(display.0) > 0 {
                    let mut event: XEvent = std::mem::zeroed();
                    XNextEvent(display.0, &mut event);
                }
            }
            for text in ["a\0a", "a\u{1}a"] {
                assert!(enigo.key_sequence_result(text).is_err(), "unsupported control was admitted");
            }
            XSync(display.0, 0);
            let mut event: XEvent = std::mem::zeroed();
            assert_eq!(XCheckWindowEvent(display.0, window, KeyPressMask | KeyReleaseMask, &mut event), 0,
                       "text preflight emitted a prefix before refusal");
            let result = enigo.key_sequence_result("A");
            if scenario == "reject-text" {
                assert!(enigo.keyboard_state().is_err(), "failed native state query was published as all-up");
                let rejected = result.as_ref().err().map(|error| error.to_string());
                assert_eq!(pointer(display.0).2 & ShiftMask, 0);
                XSync(display.0, 0);
                let mut event: XEvent = std::mem::zeroed();
                assert_eq!(XCheckWindowEvent(display.0, window, KeyPressMask | KeyReleaseMask, &mut event), 0,
                           "failed modifier-map query emitted input");
                drop(enigo);
                assert_eq!(descriptors(), connected);
                if rejected.as_deref() != Some("libxdo text entry failed with status 1") {
                    drop(display);
                    assert_eq!(descriptors(), baseline);
                    panic!("Enigo discarded the native text refusal: {rejected:?}");
                }
                continue;
            }
            result.unwrap();
            observe(display.0, |(_, _, mask)| mask & ShiftMask == 0);
            enigo.key_sequence_result("a\n\t").unwrap();
            let until = Instant::now() + Duration::from_millis(250);
            let mut events = Vec::new();
            while events.len() < 8 {
                XSync(display.0, 0);
                while XPending(display.0) > 0 {
                    let mut event: XEvent = std::mem::zeroed();
                    XNextEvent(display.0, &mut event);
                    if matches!(event.get_type(), KeyPress | KeyRelease) {
                        let symbol = XLookupKeysym(&mut event.key, 0);
                        if [b'a' as libc::c_ulong, 0xff0d, 0xff09].contains(&symbol) {
                            events.push((event.get_type(), symbol, event.key.state & ShiftMask));
                        }
                    }
                }
                assert!(Instant::now() < until, "Enigo text event receipt expired");
                if events.len() < 8 { thread::sleep(Duration::from_millis(1)); }
            }
            assert_eq!(events, [
                (KeyPress, b'a' as libc::c_ulong, ShiftMask),
                (KeyRelease, b'a' as libc::c_ulong, ShiftMask),
                (KeyPress, b'a' as libc::c_ulong, 0),
                (KeyRelease, b'a' as libc::c_ulong, 0),
                (KeyPress, 0xff0d, 0), (KeyRelease, 0xff0d, 0),
                (KeyPress, 0xff09, 0), (KeyRelease, 0xff09, 0),
            ]);
            drop(enigo);
            assert_eq!(descriptors(), connected);
        }
        XDestroyWindow(display.0, window);
        XSync(display.0, 0);
    }
    drop(display);
    assert_eq!(descriptors(), baseline);
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    if scenario == "complete" {
        println!("XDO_ENIGO_STATE=pass contexts=8 modifiers=8 locks=2 exact_sides=distinct family=union state=server-observed source=complete-linux-crate");
    }
    println!("XDO_ENIGO_COMPONENT=pass scenario={scenario} attempts=8 text={} pointer=actual descriptors=retired",
             if scenario == "complete" { "delivered" } else { "native-modifier-error" });
}
