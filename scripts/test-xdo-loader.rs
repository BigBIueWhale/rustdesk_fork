//! Native test of the complete production loader through its public API.
use hbb_common::{libc, libloading::os::unix::{Library, RTLD_LOCAL, RTLD_NOW}, x11::{keysym::*, xlib::*}};
use libxdo_sys::*;
use std::{collections::HashSet, ffi::CString, io::Read, os::unix::fs::MetadataExt, ptr};

#[link(name = "Xtst")]
extern "C" {
    fn XTestFakeKeyEvent(display: *mut Display, code: libc::c_uint, pressed: libc::c_int,
                        delay: libc::c_ulong) -> libc::c_int;
}

struct DisplayOwner(*mut Display);
impl Drop for DisplayOwner {
    fn drop(&mut self) {
        assert_eq!(unsafe { XCloseDisplay(self.0) }, 0);
    }
}
struct Context(*mut xdo_t);
impl Drop for Context {
    fn drop(&mut self) { assert_eq!(unsafe { xdo_free(self.0) }, 0); }
}
fn descriptors() -> usize { std::fs::read_dir("/proc/self/fd").unwrap().count() }
unsafe fn state(context: *const xdo_t) -> XdoInputState {
    let mut value = XdoInputState::default();
    assert_eq!(xdo_query_input_state(context, &mut value), 0);
    value
}

fn assert_provider_mappings(loaded: bool) {
    let path = "/usr/lib/rustdesk-fork/libxdo.so.3";
    let before = loaded.then(|| std::fs::metadata(path).unwrap());
    let mut maps = String::new();
    std::fs::File::open("/proc/self/maps").unwrap().take(1024 * 1024 + 1)
        .read_to_string(&mut maps).unwrap();
    assert!(maps.len() <= 1024 * 1024, "process mapping inventory exceeded its bound");
    let mappings: Vec<_> = maps.lines().map(|line| line.split_whitespace().collect::<Vec<_>>())
        .filter(|fields| fields.get(5).is_some_and(|name| {
            name.rsplit('/').next().is_some_and(|name| name.starts_with("libxdo.so"))
        })).collect();
    if !loaded {
        assert!(mappings.is_empty(), "refused or unrequested XDO provider remains mapped");
        return;
    }
    let before = before.unwrap();
    assert!(before.is_file());
    assert_eq!((before.uid(), before.gid(), before.mode() & 0o7777), (0, 0, 0o644));
    assert!(!mappings.is_empty(), "accepted provider has no kernel mapping");
    assert!(mappings.iter().any(|fields| fields[1].contains('x')),
            "accepted provider has no executable mapping");
    for fields in mappings {
        assert_eq!(fields.len(), 6, "provider mapping is deleted or has an unexpected pathname");
        assert_eq!(fields[5], path, "another XDO provider is mapped");
        let (major, minor) = fields[3].split_once(':').unwrap();
        assert_eq!(u32::from_str_radix(major, 16).unwrap(), libc::major(before.dev()));
        assert_eq!(u32::from_str_radix(minor, 16).unwrap(), libc::minor(before.dev()));
        assert_eq!(fields[4].parse::<u64>().unwrap(), before.ino(),
                   "mapped provider differs from the staged executable object");
    }
    let after = std::fs::metadata(path).unwrap();
    assert_eq!((before.dev(), before.ino(), before.mode(), before.uid(), before.gid(),
                before.len(), before.mtime(), before.mtime_nsec(), before.ctime(), before.ctime_nsec()),
               (after.dev(), after.ino(), after.mode(), after.uid(), after.gid(),
                after.len(), after.mtime(), after.mtime_nsec(), after.ctime(), after.ctime_nsec()),
               "staged provider identity changed during mapping observation");
}

fn main() {
    assert_eq!(unsafe { libc::geteuid() }, 4000);
    assert_eq!(unsafe { libc::getegid() }, 4000);
    let scenario = std::env::args().nth(1).unwrap();
    assert_provider_mappings(false);
    let baseline = descriptors();
    let name = CString::new(":98").unwrap();
    let display = DisplayOwner(unsafe { XOpenDisplay(name.as_ptr()) });
    assert!(!display.0.is_null(), "real X display must be ready in every case");
    let context = Context(unsafe { xdo_new_with_opened_display(display.0, name.as_ptr(), 0) });
    let owned = Context(unsafe { xdo_new(name.as_ptr()) });
    let mut unpublished = XdoInputState { pointer_mask: 0xa5a5a5a5, ..Default::default() };
    assert_ne!(unsafe { xdo_query_input_state(ptr::null(), &mut unpublished) }, 0);
    assert_eq!(unpublished.pointer_mask, 0xa5a5a5a5);
    assert_provider_mappings(scenario == "complete" || scenario == "no-xtest");
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
        assert_provider_mappings(scenario == "no-xtest");
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
        assert_eq!(retired.len(), 63);
        assert_eq!(retired.iter().collect::<HashSet<_>>().len(), 63);
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
        assert_ne!(xdo_move_mouse(ptr::null(), 73, 91), 0);
        assert_eq!(xdo_move_mouse(context.0, 73, 91), 0);
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
        assert_ne!(state(context.0).pointer_mask & Button1Mask, 0);
        assert_eq!(xdo_mouse_up(context.0, 1), 0);
        XSync(display.0, 0);
        assert_eq!(state(context.0).pointer_mask & Button1Mask, 0);
        let shift = XKeysymToKeycode(display.0, XK_Shift_L.into());
        assert_ne!(shift, 0);
        assert_ne!(XTestFakeKeyEvent(display.0, shift.into(), 1, CurrentTime), 0);
        XSync(display.0, 0);
        let down = state(context.0);
        assert_ne!(down.pointer_mask & ShiftMask, 0);
        assert_ne!(down.keys[shift as usize / 8] & (1 << (shift % 8)), 0);
        assert_ne!(XTestFakeKeyEvent(display.0, shift.into(), 0, CurrentTime), 0);
        XSync(display.0, 0);
        assert_eq!(state(context.0).pointer_mask & ShiftMask, 0);
        assert_eq!(xdo_enter_text_scalar(context.0, 'a', 0), 0);
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
    assert_eq!(unsafe { xdo_free(ptr::null_mut()) }, 0);
    assert_eq!(descriptors(), baseline);
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    assert_provider_mappings(true);
    println!("XDO_LOADER_COMPONENT=pass scenario=complete pointer=absolute,relative button=pressed,released shift=pressed,released key=a,a input=xtest retired_lookups=63 retired_symbols=absent descriptors=retired");
}
