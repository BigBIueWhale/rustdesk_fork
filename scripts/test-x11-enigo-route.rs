//! Complete production XDO backend with source-extracted production API declarations.
//! ABI bindings call the real libraries; this does not exercise the protected loader or parent Enigo.
extern crate self as hbb_common;
extern crate self as libxdo_sys;
include!("/build/enigo-api.rs");
include!("/build/xdo-key-types.rs");
mod platform {
    #[path = "/work/libs/hbb_common/src/platform/x11_display.rs"]
    pub mod x11_display;
}
pub mod libc { pub use std::ffi::c_int; }
pub mod x11 {
    #[allow(non_upper_case_globals)]
    #[path = "/work/xdo-vendor/x11-2.21.0/src/keysym.rs"]
    pub mod keysym;
    pub mod xlib {
        use std::ffi::{c_char, c_int};
        #[repr(C)]
        pub struct Display { _private: [u8; 0] }
        #[link(name = "X11")]
        extern "C" {
            pub fn XOpenDisplay(name: *const c_char) -> *mut Display;
            pub fn XCloseDisplay(display: *mut Display) -> c_int;
            pub fn XDefaultScreen(display: *mut Display) -> c_int;
            pub fn XGetPointerMapping(display: *mut Display, map: *mut u8, size: c_int) -> c_int;
        }
    }
}
use std::{ffi::{c_char, c_int, c_uint, c_ulong, CStr, CString},
          sync::{Mutex, atomic::{AtomicBool, AtomicUsize, Ordering}}};
use x11::xlib::{Display, XDefaultScreen};
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct xdo_t { _private: [u8; 0] }
#[allow(non_camel_case_types)]
pub type useconds_t = c_uint;
#[link(name = "xdo")]
extern "C" {
    pub fn xdo_new_with_opened_display(display: *mut Display, name: *const c_char, close: c_int) -> *mut xdo_t;
    pub fn xdo_free(context: *mut xdo_t);
    pub fn xdo_move_mouse(context: *const xdo_t, x: c_int, y: c_int, screen: c_int) -> c_int;
    pub fn xdo_move_mouse_relative(context: *const xdo_t, x: c_int, y: c_int) -> c_int;
    pub fn xdo_mouse_down(context: *const xdo_t, button: c_int) -> c_int;
    pub fn xdo_mouse_up(context: *const xdo_t, button: c_int) -> c_int;
    pub fn xdo_get_input_state(context: *const xdo_t) -> c_uint;
    #[link_name = "xdo_send_key"]
    fn native_send_key(context: *const xdo_t, kind: c_uint, value: c_ulong, action: c_uint, delay: useconds_t) -> c_int;
    fn __real_xdo_new_with_opened_display(display: *mut Display, name: *const c_char, close: c_int) -> *mut xdo_t;
    fn __real_xdo_free(context: *mut xdo_t);
}
pub unsafe fn xdo_send_key(context: *const xdo_t, key: XdoKey,
                                  action: XdoKeyAction, delay: useconds_t) -> c_int {
    let (kind, value) = match key {
        XdoKey::Keysym(value) => (1, value),
        XdoKey::Keycode(value) => (2, value as c_ulong),
    };
    native_send_key(context, kind, value, action as c_uint, delay)
}
#[link(name = "X11")]
extern "C" {
    fn XInitThreads() -> c_int;
    fn __real_XOpenDisplay(name: *const c_char) -> *mut Display;
    fn __real_XCloseDisplay(display: *mut Display) -> c_int;
    fn XDisplayWidth(display: *mut Display, screen: c_int) -> c_int;
    fn XDisplayHeight(display: *mut Display, screen: c_int) -> c_int;
    fn XDefaultRootWindow(display: *mut Display) -> c_ulong;
    fn XQueryPointer(display: *mut Display, window: c_ulong, root: *mut c_ulong, child: *mut c_ulong,
                     root_x: *mut c_int, root_y: *mut c_int, x: *mut c_int, y: *mut c_int, mask: *mut c_uint) -> c_int;
}
#[path = "/work/libs/enigo/src/linux/xdo.rs"]
mod backend;

static NAMES: Mutex<Vec<(bool, Option<String>)>> = Mutex::new(Vec::new());
static RETIREMENTS: AtomicUsize = AtomicUsize::new(0);
static DISPLAY_RETIREMENTS: AtomicUsize = AtomicUsize::new(0);
static RETAINED_DISPLAY: AtomicUsize = AtomicUsize::new(0);
static TEXT_BORROWS: AtomicUsize = AtomicUsize::new(0);
static SHIFT_AFTER_OPEN: AtomicBool = AtomicBool::new(false);
static REFUSE_NEXT_CONSTRUCT: AtomicBool = AtomicBool::new(false);
static PANIC_AFTER_CONSTRUCT: AtomicBool = AtomicBool::new(false);
static PANIC_NEXT_LOG: AtomicBool = AtomicBool::new(false);

struct NativeLogger;
impl log::Log for NativeLogger {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool { PANIC_NEXT_LOG.load(Ordering::SeqCst) }
    fn log(&self, _: &log::Record<'_>) {
        if PANIC_NEXT_LOG.swap(false, Ordering::SeqCst) {
            panic!("injected constructor log unwind after native context creation");
        }
    }
    fn flush(&self) {}
}
unsafe fn record(xdo: bool, name: *const c_char) {
    NAMES.lock().unwrap().push((xdo, if name.is_null() { None }
                              else { Some(CStr::from_ptr(name).to_str().unwrap().to_owned()) }));
}
#[no_mangle]
unsafe extern "C" fn __wrap_xdo_new_with_opened_display(display: *mut Display, name: *const c_char,
                                                       close: c_int) -> *mut xdo_t {
    record(true, name);
    assert!(!display.is_null());
    assert!(matches!(close, 0 | 1));
    assert_eq!(display as usize, RETAINED_DISPLAY.load(Ordering::SeqCst));
    if close == 0 {
        let names = NAMES.lock().unwrap();
        assert_eq!(names.iter().filter(|(native, _)| !native).count(), 1);
        assert_eq!(names.first().unwrap().1, names.last().unwrap().1);
        TEXT_BORROWS.fetch_add(1, Ordering::SeqCst);
    }
    if REFUSE_NEXT_CONSTRUCT.swap(false, Ordering::SeqCst) { return std::ptr::null_mut(); }
    let context = __real_xdo_new_with_opened_display(display, name, close);
    assert!(!context.is_null());
    if SHIFT_AFTER_OPEN.swap(false, Ordering::SeqCst) { std::env::set_var("DISPLAY", ":95"); }
    if PANIC_AFTER_CONSTRUCT.swap(false, Ordering::SeqCst) { PANIC_NEXT_LOG.store(true, Ordering::SeqCst); }
    context
}
#[no_mangle]
unsafe extern "C" fn __wrap_xdo_free(context: *mut xdo_t) {
    __real_xdo_free(context);
    RETIREMENTS.fetch_add(1, Ordering::SeqCst);
}
#[no_mangle]
unsafe extern "C" fn __wrap_XOpenDisplay(name: *const c_char) -> *mut Display {
    record(false, name);
    let display = __real_XOpenDisplay(name);
    if !display.is_null() { RETAINED_DISPLAY.store(display as usize, Ordering::SeqCst); }
    if !display.is_null() && !name.is_null() {
        let screen = if CStr::from_ptr(name).to_bytes().ends_with(b".1") { 1 } else { 0 };
        assert_eq!(XDefaultScreen(display), screen);
        assert_eq!((XDisplayWidth(display, screen), XDisplayHeight(display, screen)),
                   if screen == 0 { (640, 480) } else { (800, 600) });
    }
    display
}
#[no_mangle]
unsafe extern "C" fn __wrap_XCloseDisplay(display: *mut Display) -> c_int {
    let status = __real_XCloseDisplay(display);
    assert_eq!(status, 0);
    DISPLAY_RETIREMENTS.fetch_add(1, Ordering::SeqCst);
    status
}
fn descriptors() -> usize { std::fs::read_dir("/proc/self/fd").unwrap().count() }
fn tasks() -> usize { std::fs::read_dir("/proc/self/task").unwrap().count() }
fn retired(baseline: usize) { assert_eq!(descriptors(), baseline); assert_eq!(tasks(), 1); }
fn main() {
    assert_ne!(unsafe { XInitThreads() }, 0);
    log::set_logger(&NativeLogger).unwrap();
    log::set_max_level(log::LevelFilter::Info);
    let baseline = descriptors();
    if let Some(scenario) = std::env::args().nth(1) {
        if matches!(scenario.as_str(), "layout" | "layout-repeat") {
            use std::io::{Read, Write};
            std::env::set_var("DISPLAY", ":98");
            let mut injector = backend::EnigoXdo::default();
            println!("X11_ENIGO_LAYOUT_CHILD=ready");
            std::io::stdout().flush().unwrap();
            let mut command = [0];
            std::io::stdin().read_exact(&mut command).unwrap();
            assert_eq!(command, [b'D']);
            std::env::set_var("DISPLAY", ":95");
            REFUSE_NEXT_CONSTRUCT.store(true, Ordering::SeqCst);
            assert!(injector.key_sequence_result("a").is_err());
            assert!(!REFUSE_NEXT_CONSTRUCT.load(Ordering::SeqCst));
            let repeats = if scenario == "layout-repeat" { 32 } else { 1 };
            for _ in 0..repeats {
                injector.key_sequence_result("a").unwrap();
                assert_eq!(descriptors(), baseline + 1);
                assert_eq!(tasks(), 1);
            }
            drop(injector);
            retired(baseline);
            assert_eq!(RETIREMENTS.load(Ordering::SeqCst), repeats + 1);
            assert_eq!(TEXT_BORROWS.load(Ordering::SeqCst), repeats + 1);
            println!("X11_ENIGO_LAYOUT_CHILD=pass pairs={repeats} mapping_refusal=explicit descriptors=retired threads=retired");
            return;
        }
        if scenario == "text" {
            std::env::set_var("DISPLAY", ":98");
            let mut injector = backend::EnigoXdo::default();
            injector.key_sequence_result("aéא🙂+\n\t").unwrap();
            assert!(injector.key_sequence_result("a\0a").is_err());
            assert!(injector.key_sequence_result("a\u{1}a").is_err());
            drop(injector);
            retired(baseline);
            assert_eq!(RETIREMENTS.load(Ordering::SeqCst), 2);
            println!("X11_ENIGO_TEXT_CHILD=pass scalar_pairs=7 controls=preadmission-refused descriptors=retired threads=retired");
            return;
        }
        assert!(matches!(scenario.as_str(), "route" | "diagnostic"));
        let diagnostic = scenario == "diagnostic";
        std::env::set_var("DISPLAY", if diagnostic { ":98" } else { ":95" });
        SHIFT_AFTER_OPEN.store(diagnostic, Ordering::SeqCst);
        let mut injector = backend::EnigoXdo::default();
        if diagnostic {
            injector.mouse_move_to(131, 79).unwrap();
        } else {
            assert!(injector.mouse_move_to(131, 79).is_err());
            assert!(injector.key_sequence_result("a").is_err());
        }
        drop(injector);
        assert_eq!(RETIREMENTS.load(Ordering::SeqCst), usize::from(diagnostic));
        let names = NAMES.lock().unwrap();
        assert_eq!(*names, if diagnostic {
            vec![(false, Some("unix/:98.0".into())), (true, Some("unix/:98.0".into()))]
        } else { vec![(false, Some("unix/:95.0".into()))] });
        assert_eq!(DISPLAY_RETIREMENTS.load(Ordering::SeqCst), 0);
        retired(baseline);
        println!("X11_ENIGO_{}_CHILD variant=corrected result={} descriptors=retired threads=retired",
                 if diagnostic { "DIAGNOSTIC" } else { "ROUTE" },
                 if diagnostic { "selected-once" } else { "refused" });
        return;
    }
    let refuse = || {
        let mut injector = backend::EnigoXdo::default();
        assert!(injector.mouse_move_to(131, 79).is_err());
        assert!(injector.key_sequence_result("a").is_err());
        drop(injector);
        assert!(NAMES.lock().unwrap().is_empty());
        retired(baseline);
    };
    for name in ["", ":", ":1.", ":.0", ":1.0.0", ":+1", ":-1", ":1.-1",
                 "localhost:98", "unix/:98", "/tmp/.X11-unix/X98", "tcp/:98",
                 ":2147483648", ":98.2147483648", ":98\n", " :98"] {
        std::env::set_var("DISPLAY", name);
        refuse();
    }
    std::env::remove_var("DISPLAY"); refuse();
    use std::os::unix::ffi::OsStringExt;
    std::env::set_var("DISPLAY", std::ffi::OsString::from_vec(vec![0xff])); refuse();
    std::env::set_var("DISPLAY", ":98.1");
    for _ in 0..32 {
        REFUSE_NEXT_CONSTRUCT.store(true, Ordering::SeqCst);
        let mut injector = backend::EnigoXdo::default();
        assert!(!REFUSE_NEXT_CONSTRUCT.load(Ordering::SeqCst));
        assert!(injector.mouse_move_to(131, 79).is_err());
        assert!(injector.key_sequence_result("a").is_err());
        drop(injector);
        assert_eq!(*NAMES.lock().unwrap(), vec![(false, Some("unix/:98.1".into())),
                                             (true, Some("unix/:98.1".into()))]);
        NAMES.lock().unwrap().clear();
        retired(baseline);
    }
    for _ in 0..16 {
        PANIC_AFTER_CONSTRUCT.store(true, Ordering::SeqCst);
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = std::panic::catch_unwind(backend::EnigoXdo::default);
        std::panic::set_hook(hook);
        assert!(result.is_err());
        assert!(!PANIC_AFTER_CONSTRUCT.load(Ordering::SeqCst));
        assert!(!PANIC_NEXT_LOG.load(Ordering::SeqCst));
        assert_eq!(*NAMES.lock().unwrap(), vec![(false, Some("unix/:98.1".into())),
                                             (true, Some("unix/:98.1".into()))]);
        NAMES.lock().unwrap().clear();
        retired(baseline);
    }
    for (selector, canonical) in [(":00098", "unix/:98.0"), (":00098.0000", "unix/:98.0"),
                                  (":00098.0001", "unix/:98.1")] {
        for iteration in 0..8 {
            std::env::set_var("DISPLAY", selector);
            let mut injector = backend::EnigoXdo::default();
            assert_eq!(descriptors(), baseline + 1);
            assert_eq!(*NAMES.lock().unwrap(), vec![(false, Some(canonical.into())), (true, Some(canonical.into()))]);
            injector.mouse_move_to(131 + iteration, 79 + iteration).unwrap();
            // Observe native pointer coordinates using an independent real X11 connection.
            unsafe {
                let selected = CString::new(canonical).unwrap();
                let observer = __real_XOpenDisplay(selected.as_ptr());
                assert!(!observer.is_null());
                assert_eq!(XDefaultScreen(observer), if canonical.ends_with(".1") { 1 } else { 0 });
                let (mut root, mut child, mut x, mut y, mut wx, mut wy, mut mask) = (0, 0, 0, 0, 0, 0, 0);
                let deadline = std::time::Instant::now() + std::time::Duration::from_millis(100);
                loop {
                    let same_screen = XQueryPointer(observer, XDefaultRootWindow(observer), &mut root, &mut child,
                                                    &mut x, &mut y, &mut wx, &mut wy, &mut mask);
                    if same_screen != 0 && (x, y) == (131 + iteration, 79 + iteration) { break; }
                    assert!(std::time::Instant::now() < deadline,
                            "native pointer did not arrive on selected screen {canonical}");
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                assert_eq!(root, XDefaultRootWindow(observer));
                assert_eq!(__real_XCloseDisplay(observer), 0);
            }
            drop(injector);
            NAMES.lock().unwrap().clear();
            retired(baseline);
        }
    }
    assert_eq!(RETIREMENTS.load(Ordering::SeqCst), 40);
    assert_eq!(DISPLAY_RETIREMENTS.load(Ordering::SeqCst), 32);
    println!("X11_ENIGO_NATIVE=pass source=complete-backend api=production-declarations selectors_refused=18 canonical_screens=3 contexts=24 context_refusals=32 constructor_unwinds=16 display_connections=one pointer=selected-root callbacks=paired descriptors=retired threads=retired scope=xdo-backend");
}
