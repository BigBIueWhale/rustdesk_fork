use super::*;
use hbb_common::x11::xlib;
use rdev::{EventType, Key as RdevKey};

struct Observer {
    display: *mut xlib::Display,
    window: xlib::Window,
    previous_focus: xlib::Window,
    previous_revert: i32,
}

impl Observer {
    fn new() -> Self {
        unsafe {
            let display = xlib::XOpenDisplay(std::ptr::null());
            assert!(!display.is_null());
            let mut previous_focus = 0;
            let mut previous_revert = 0;
            xlib::XGetInputFocus(display, &mut previous_focus, &mut previous_revert);
            let window = xlib::XCreateSimpleWindow(
                display, xlib::XDefaultRootWindow(display), 0, 0, 100, 100, 0, 0, 0,
            );
            assert_ne!(window, 0);
            xlib::XSelectInput(display, window, xlib::KeyPressMask | xlib::KeyReleaseMask);
            xlib::XMapWindow(display, window);
            xlib::XSetInputFocus(display, window, xlib::RevertToPointerRoot, xlib::CurrentTime);
            xlib::XSync(display, 0);
            Self { display, window, previous_focus, previous_revert }
        }
    }

    fn keys(&self, expected: &[u32]) -> bool {
        let mut actual = [0i8; 32];
        let mut wanted = [0i8; 32];
        for code in expected {
            wanted[*code as usize / 8] |= (1u8 << (*code % 8)) as i8;
        }
        unsafe { xlib::XQueryKeymap(self.display, actual.as_mut_ptr()) != 0 && actual == wanted }
    }

    fn events(&self) -> Vec<(i32, u32)> {
        let mut events = Vec::new();
        unsafe {
            xlib::XSync(self.display, 0);
            let mut event: xlib::XEvent = std::mem::zeroed();
            while xlib::XCheckWindowEvent(
                self.display, self.window, xlib::KeyPressMask | xlib::KeyReleaseMask, &mut event,
            ) != 0 {
                assert_eq!(event.key.window, self.window);
                assert_eq!(event.key.send_event, 0);
                events.push((event.get_type(), event.key.keycode));
            }
        }
        events
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        unsafe {
            xlib::XSetInputFocus(
                self.display, self.previous_focus, self.previous_revert, xlib::CurrentTime,
            );
            xlib::XDestroyWindow(self.display, self.window);
            xlib::XSync(self.display, 0);
            xlib::XCloseDisplay(self.display);
        }
    }
}

fn descriptors() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

#[test]
#[ignore = "requires the owned isolated X11 input-release profile"]
fn physical_lease_retirement_survives_unavailable_keyboard_state() {
    assert_eq!(std::env::var("DISPLAY").unwrap(), ":98");
    assert!(!std::path::Path::new("/usr/lib/rustdesk-fork/libxdo.so.3").exists());
    let baseline = descriptors();
    let observer = Observer::new();
    assert!(observer.keys(&[]));
    let foreign = RdevKey::KeyA;
    let foreign_code = rdev::linux_keycode_from_key(foreign).unwrap();
    let controls = [
        ControlKey::Control, ControlKey::RControl, ControlKey::Shift, ControlKey::RShift,
        ControlKey::Alt, ControlKey::RAlt, ControlKey::Meta, ControlKey::RWin,
    ];
    for map_mode in [false, true] {
        for control in controls {
            let mut event = KeyEvent::new();
            event.set_control_key(control);
            event.down = true;
            let OwnedPhysicalKey::Key(physical) = owned_physical_key(&event).unwrap();
            let code = match physical {
                RdevKey::RawKey(rdev::RawKey::LinuxXorgKeycode(code)) => code,
                _ => rdev::linux_keycode_from_key(physical).unwrap(),
            };
            if map_mode {
                event.mode = KeyboardMode::Map.into();
                event.set_chr(code);
            }
            // The unavailable state collector closes ordinary dispatch. The fixture
            // supplies a real accepted physical press to the production lease registry.
            let refusal = handle_owned_key(&event, &[]).unwrap_err();
            assert!(refusal.to_string().contains("libxdo is unavailable"));
            assert!(observer.keys(&[]) && observer.events().is_empty());
            rdev::simulate(&EventType::KeyPress(foreign)).unwrap();
            assert_eq!(observer.events(), vec![(xlib::KeyPress, foreign_code)]);
            let registry = Arc::new(InputKeyOwnerRegistry::default());
            let mut first = InputKeyOwnership::new(Arc::clone(&registry));
            let mut second = InputKeyOwnership::new(Arc::clone(&registry));
            assert!(first.dispatch(&event, |_, _| {
                rdev::simulate(&EventType::KeyPress(physical)).unwrap();
                Ok(())
            }).unwrap());
            assert!(!second.dispatch(&event, |_, _| panic!("duplicate owner emitted input")).unwrap());
            assert_eq!(observer.events(), vec![(xlib::KeyPress, code)]);
            assert!(observer.keys(&[foreign_code, code]));
            assert!(first.release_remaining().is_ok());
            assert!(first.held.is_empty());
            assert!(observer.keys(&[foreign_code, code]) && observer.events().is_empty());
            assert!(!first.finish_worker(|| panic!("nonfinal worker retired global input")));
            let released = second.release_remaining();
            let observed = observer.events();
            let finality = released.is_ok() && observed == [(xlib::KeyRelease, code)]
                && observer.keys(&[foreign_code]) && second.held.is_empty()
                && registry.lock().is_empty();
            // Retire only fixture-introduced keys before reporting a product failure.
            rdev::simulate(&EventType::KeyRelease(physical)).unwrap();
            rdev::simulate(&EventType::KeyRelease(foreign)).unwrap();
            observer.events();
            assert!(observer.keys(&[]));
            assert!(finality, "physical lease retirement failed: result={released:?}, events={observed:?}");
            assert!(second.finish_worker(|| {}));
            assert_eq!(descriptors(), baseline + 1);
        }
    }
    drop(observer);
    assert_eq!(descriptors(), baseline);
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut receipt = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open("/tmp/input-release-native.receipt").unwrap();
    receipt.write_all(b"INPUT_RELEASE_NATIVE=pass cases=16 shared_owners=2 prior_owner_retirement=no-events final_owner_release=exact-key foreign_key=preserved keyboard_state=unavailable ordinary_admission=refused registry=retired descriptors=retired whole_app=false\n").unwrap();
}
