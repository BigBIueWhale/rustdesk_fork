//! Native test of the complete production loader through its public API.
use hbb_common::{libc, libloading::os::unix::{Library, RTLD_LOCAL, RTLD_NOW}, x11::{keysym::*, xlib::*}};
use libxdo_sys::*;
use std::{collections::HashSet, ffi::CString, ptr};

struct DisplayOwner(*mut Display);
impl Drop for DisplayOwner {
    fn drop(&mut self) {
        assert_eq!(unsafe { XCloseDisplay(self.0) }, 0);
    }
}
struct Context(*mut xdo_t);
impl Drop for Context {
    fn drop(&mut self) { unsafe { xdo_free(self.0) }; }
}
fn descriptors() -> usize { std::fs::read_dir("/proc/self/fd").unwrap().count() }

fn main() {
    assert_eq!(unsafe { libc::geteuid() }, 4000);
    assert_eq!(unsafe { libc::getegid() }, 4000);
    let scenario = std::env::args().nth(1).unwrap();
    let baseline = descriptors();
    let name = CString::new(":98").unwrap();
    let display = DisplayOwner(unsafe { XOpenDisplay(name.as_ptr()) });
    assert!(!display.0.is_null(), "real X display must be ready in every case");
    let context = Context(unsafe { xdo_new_with_opened_display(display.0, name.as_ptr(), 0) });
    let owned = Context(unsafe { xdo_new(name.as_ptr()) });
    if scenario != "complete" {
        if scenario == "no-xtest" {
            unsafe {
                let extension = CString::new("XTEST").unwrap();
                let (mut opcode, mut event, mut error) = (0, 0, 0);
                assert_eq!(XQueryExtension(display.0, extension.as_ptr(), &mut opcode, &mut event, &mut error), 0,
                           "the real X server still exposes XTEST");
                let transferring = Context(xdo_new_with_opened_display(display.0, name.as_ptr(), 1));
                assert!(transferring.0.is_null());
                drop(transferring);
                let (mut focus, mut revert) = (0, 0);
                assert_ne!(XGetInputFocus(display.0, &mut focus, &mut revert), 0,
                           "refusal lost the caller-owned display");
            }
        }
        let admitted = !context.0.is_null() || !owned.0.is_null();
        drop(owned);
        drop(context);
        drop(display);
        assert_eq!(descriptors(), baseline);
        assert!(!admitted, "incomplete or unavailable provider admitted a native context");
        let capability = if scenario == "no-xtest" { " extension=absent paths=3 borrowed_display=usable" } else { "" };
        println!("XDO_LOADER_COMPONENT=pass scenario={scenario} constructors=refused{capability} descriptors=retired");
        return;
    }
    assert!(!context.0.is_null() && !owned.0.is_null());
    drop(owned);
    unsafe {
        let before_lookup = descriptors();
        let library = Library::open(Some("/usr/lib/rustdesk-fork/libxdo.so.3"), RTLD_NOW | RTLD_LOCAL).unwrap();
        let retired: Vec<_> = include_str!("fixtures/xdo-retired-apis.txt").lines().collect();
        assert_eq!(retired.len(), 61);
        assert_eq!(retired.iter().collect::<HashSet<_>>().len(), 61);
        for name in retired {
            let symbol = CString::new(name).unwrap();
            assert!(library.get::<unsafe extern "C" fn()>(symbol.as_bytes_with_nul()).is_err(),
                    "retired XDO API {name} is available");
        }
        drop(library);
        assert_eq!(descriptors(), before_lookup);
        let root = XDefaultRootWindow(display.0);
        let window = XCreateSimpleWindow(display.0, root, 0, 0, 320, 240, 0, 0, 0);
        assert_ne!(window, 0);
        XSelectInput(display.0, window, KeyPressMask | KeyReleaseMask);
        XMapWindow(display.0, window);
        XSetInputFocus(display.0, window, RevertToParent, CurrentTime);
        XSync(display.0, 0);
        assert_eq!(xdo_move_mouse(context.0, 73, 91, 0), 0);
        XSync(display.0, 0);
        let (mut x, mut y, mut screen) = (0, 0, -1);
        assert_eq!(xdo_get_mouse_location(context.0, &mut x, &mut y, &mut screen), 0);
        assert_eq!((x, y, screen), (73, 91, 0));
        assert_eq!(xdo_move_mouse_relative(context.0, 5, -3), 0);
        XSync(display.0, 0);
        assert_eq!(xdo_get_mouse_location(context.0, &mut x, &mut y, &mut screen), 0);
        assert_eq!((x, y), (78, 88));
        assert_eq!(xdo_mouse_down(context.0, 1), 0);
        XSync(display.0, 0);
        assert_ne!(xdo_get_input_state(context.0) & Button1Mask, 0);
        assert_eq!(xdo_mouse_up(context.0, 1), 0);
        XSync(display.0, 0);
        assert_eq!(xdo_get_input_state(context.0) & Button1Mask, 0);
        assert_eq!(xdo_send_key(context.0, XdoKey::Keysym(XK_Shift_L.into()), XdoKeyAction::Down, 0), 0);
        XSync(display.0, 0);
        assert_ne!(xdo_get_input_state(context.0) & ShiftMask, 0);
        assert_eq!(xdo_send_key(context.0, XdoKey::Keysym(XK_Shift_L.into()), XdoKeyAction::Up, 0), 0);
        XSync(display.0, 0);
        assert_eq!(xdo_get_input_state(context.0) & ShiftMask, 0);
        assert_eq!(xdo_send_key(context.0, XdoKey::Keysym(XK_a.into()), XdoKeyAction::Click, 0), 0);
        XSync(display.0, 0);
        let mut events = Vec::new();
        while XPending(display.0) > 0 {
            let mut event: XEvent = std::mem::zeroed();
            XNextEvent(display.0, &mut event);
            if matches!(event.get_type(), KeyPress | KeyRelease) {
                assert_eq!(event.key.send_event, 0);
                assert_eq!(event.key.window, window);
                let symbol = XLookupKeysym(&mut event.key, 0);
                if symbol == b'a' as libc::c_ulong {
                    events.push(event.get_type());
                }
            }
        }
        assert_eq!(events, [KeyPress, KeyRelease], "observe actual native key delivery");
        XDestroyWindow(display.0, window);
        XSync(display.0, 0);
    }
    drop(context);
    drop(display);
    unsafe { xdo_free(ptr::null_mut()) };
    assert_eq!(descriptors(), baseline);
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    println!("XDO_LOADER_COMPONENT=pass scenario=complete pointer=absolute,relative button=pressed,released shift=pressed,released key=a,a input=xtest retired_lookups=61 retired_symbols=absent descriptors=retired");
}
