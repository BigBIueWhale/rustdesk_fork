//! Exercise the complete production owner with real X11 and XDO contexts.
extern crate self as hbb_common;
extern crate self as libxdo_sys;
mod platform {
    #[path = "/work/libs/hbb_common/src/platform/x11_display.rs"]
    pub mod x11_display;
    include!("/build/x11-cursor-bounds.rs");
}
use std::{cell::RefCell, collections::BTreeSet, ffi::{c_char, c_int, c_ulong, c_void}, io::Read, ptr,
          sync::{Arc, Barrier, Mutex, atomic::{AtomicUsize, Ordering}}, thread, time::{Duration, Instant}};

#[path = "/work/src/platform/linux/native_context.rs"]
mod native_context;
use native_context::NativeContext;
#[path = "/work/src/platform/linux/x11_context.rs"]
mod x11_context;
#[path = "/work/src/platform/linux/x11_cursor.rs"]
mod x11_cursor;

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct xdo_t { _private: [u8; 0] }
type Xdo = xdo_t;
#[link(name = "X11")]
extern "C" {
    // Observe the pinned library's initialization, without initializing it for
    // the test. These private ABI symbols are not production dependencies.
    static _Xglobal_lock: *const c_void;
    static _XInitDisplayLock_fn: Option<unsafe extern "C" fn(*mut c_void) -> c_int>;
    fn XOpenDisplay(name: *const c_char) -> *mut c_void;
    fn __real_XOpenDisplay(name: *const c_char) -> *mut c_void;
    fn XCloseDisplay(display: *mut c_void) -> c_int;
    fn __real_XCloseDisplay(display: *mut c_void) -> c_int;
    fn XDefaultScreen(display: *mut c_void) -> c_int;
    fn XDisplayWidth(display: *mut c_void, screen: c_int) -> c_int;
    fn XDisplayHeight(display: *mut c_void, screen: c_int) -> c_int;
    fn XGetInputFocus(display: *mut c_void, focus: *mut c_ulong, revert: *mut c_int) -> c_int;
}
#[link(name = "xdo")]
extern "C" {
    pub fn xdo_new(name: *const c_char) -> *mut Xdo;
    fn __real_xdo_new(name: *const c_char) -> *mut Xdo;
    pub fn xdo_free(context: *mut Xdo);
    fn __real_xdo_free(context: *mut Xdo);
    pub fn xdo_get_mouse_location(context: *const Xdo, x: *mut c_int, y: *mut c_int,
                                  screen: *mut c_int) -> c_int;
    pub fn xdo_move_mouse(context: *const Xdo, x: c_int, y: c_int, screen: c_int) -> c_int;
}

mod cursor {
    use super::{x11_context, x11_cursor};
    use std::ffi::c_int;
    include!("/build/x11-cursor-position.rs");
    include!("/build/x11-cursor-reset.rs");
}

static DISPLAY_OPENS: AtomicUsize = AtomicUsize::new(0);
static XDO_OPENS: AtomicUsize = AtomicUsize::new(0);
static DISPLAY_RETIREMENTS: AtomicUsize = AtomicUsize::new(0);
static XDO_RETIREMENTS: AtomicUsize = AtomicUsize::new(0);
#[no_mangle]
unsafe extern "C" fn __wrap_XOpenDisplay(name: *const c_char) -> *mut c_void {
    DISPLAY_OPENS.fetch_add(1, Ordering::SeqCst);
    __real_XOpenDisplay(name)
}
#[no_mangle]
unsafe extern "C" fn __wrap_xdo_new(name: *const c_char) -> *mut Xdo {
    XDO_OPENS.fetch_add(1, Ordering::SeqCst);
    __real_xdo_new(name)
}
#[no_mangle]
unsafe extern "C" fn __wrap_XCloseDisplay(display: *mut c_void) -> c_int {
    let status = __real_XCloseDisplay(display);
    assert_eq!(status, 0);
    DISPLAY_RETIREMENTS.fetch_add(1, Ordering::SeqCst);
    status
}
#[no_mangle]
unsafe extern "C" fn __wrap_xdo_free(context: *mut Xdo) {
    __real_xdo_free(context);
    XDO_RETIREMENTS.fetch_add(1, Ordering::SeqCst);
}

thread_local! {
    // Historical ownership shape: a RefCell containing a raw pointer has no native destructor.
    static OLD_DISPLAY: RefCell<*mut c_void> = RefCell::new(unsafe { XOpenDisplay(ptr::null()) });
    static OLD_XDO: RefCell<*mut Xdo> = RefCell::new(unsafe { xdo_new(ptr::null()) });
}

mod before_retry {
    use super::{c_void, xdo_t, NativeContext, RefCell, x11_context};
    include!("/work/scripts/fixtures/x11-thread-context-before-retry.rs");

    pub fn pointer(xdo: bool) -> Option<usize> {
        if xdo { XDO.with(|context| context.borrow().as_ref().map(|context| context.as_ptr() as usize)) }
        else { DISPLAY.with(|context| context.borrow().as_ref().map(|context| context.as_ptr() as usize)) }
    }
}

fn pointer(xdo: bool) -> std::io::Result<Option<usize>> {
    if xdo { x11_context::with_xdo(|context| context.as_ptr() as usize) }
    else { x11_context::with_display(|context| context.as_ptr() as usize) }
}

fn retry(scenario: &str) {
    let historical = scenario.ends_with("historical");
    let xdo = scenario.contains("-xdo-");
    let baseline = descriptors();
    let tasks = std::fs::read_dir("/proc/self/task").unwrap().count();
    std::env::set_var("DISPLAY", ":97");
    let counts = || (DISPLAY_OPENS.load(Ordering::SeqCst), XDO_OPENS.load(Ordering::SeqCst));
    let expected = if xdo { (0, 1) } else { (1, 0) };
    let worker = thread::spawn(move || {
        let failed = Instant::now();
        if historical { assert_eq!(before_retry::pointer(xdo), None); }
        else {
            assert_eq!(pointer(xdo).unwrap_err().kind(), std::io::ErrorKind::ConnectionRefused);
            if xdo {
                assert_eq!(cursor::get_cursor_pos(), None);
                assert!(!cursor::set_cursor_pos(91, 71));
            }
        }
        for _ in 0..32 {
            if historical { assert_eq!(before_retry::pointer(xdo), None); }
            else { assert_eq!(pointer(xdo).unwrap(), None); }
        }
        assert!(failed.elapsed() < Duration::from_millis(900), "initial cooldown was not observed");
        assert_eq!(counts(), expected, "polling repeated a native constructor inside cooldown");
        assert_eq!(descriptors(), baseline);
        println!("X11_STARTUP_READY variant={} component={} failed=1 cooldown_calls=32 native_opens=1",
                 if historical { "historical" } else { "corrected" }, if xdo { "xdo" } else { "xlib" });
        let mut token = [0];
        std::io::stdin().read_exact(&mut token).unwrap();
        assert_eq!(token, [b'S']);
        if historical {
            thread::sleep(Duration::from_millis(1100));
            assert_eq!(before_retry::pointer(xdo), None, "historical TLS unexpectedly retried");
            assert_eq!(counts(), expected);
        } else {
            let until = Instant::now() + Duration::from_secs(3);
            let context = loop {
                if let Some(context) = pointer(xdo).unwrap() { break context; }
                assert!(Instant::now() < until, "same-thread startup retry did not recover");
                thread::sleep(Duration::from_millis(10));
            };
            assert!(failed.elapsed() >= Duration::from_secs(1));
            assert_eq!(counts(), if xdo { (0, 2) } else { (2, 0) });
            assert_eq!(descriptors(), baseline + 1);
            for _ in 0..32 { assert_eq!(pointer(xdo).unwrap(), Some(context)); }
            if xdo {
                assert!(cursor::set_cursor_pos(91, 71));
                assert_eq!(cursor::get_cursor_pos(), Some((91, 71)));
                x11_context::with_xdo(|context| {
                    let (mut x, mut y, mut screen) = (0, 0, -1);
                    assert_eq!(unsafe { xdo_get_mouse_location(context.as_ptr(), &mut x, &mut y, &mut screen) }, 0);
                    assert_eq!(screen, 0);
                    assert_eq!((x, y), (91, 71));
                    assert_eq!(pointer(true).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
                }).unwrap().unwrap();
            } else {
                x11_context::with_display(|context| unsafe {
                    let display = context.as_ptr();
                    assert_eq!(XDefaultScreen(display), 0);
                    assert_eq!((XDisplayWidth(display, 0), XDisplayHeight(display, 0)), (640, 480));
                    assert_eq!(pointer(false).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
                }).unwrap().unwrap();
            }
            assert_eq!(counts(), if xdo { (0, 2) } else { (2, 0) });
        }
    });
    worker.join().unwrap();
    assert_eq!(descriptors(), baseline);
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), tasks);
    assert_eq!(retirements(), if historical { (0, 0) } else if xdo { (0, 1) } else { (1, 0) });
    println!("X11_STARTUP_CHILD variant={} component={} result={} native_opens={} worker=same callbacks=paired descriptors=retired threads=retired",
             if historical { "historical" } else { "corrected" }, if xdo { "xdo" } else { "xlib" },
             if historical { "cached-failure" } else { "recovered" }, if historical { 1 } else { 2 });
}

fn descriptors() -> usize { std::fs::read_dir("/proc/self/fd").unwrap().count() }
fn retirements() -> (usize, usize) {
    (DISPLAY_RETIREMENTS.load(Ordering::SeqCst), XDO_RETIREMENTS.load(Ordering::SeqCst))
}

fn authentication(credential: &str) {
    assert!(matches!(credential, "valid" | "wrong" | "missing"));
    assert_eq!(std::env::var("DISPLAY").unwrap(), ":93");
    let admitted = credential == "valid";
    let baseline = descriptors();
    let tasks = std::fs::read_dir("/proc/self/task").unwrap().count();
    thread::spawn(move || {
        if admitted {
            let display = pointer(false).unwrap().unwrap();
            let xdo = pointer(true).unwrap().unwrap();
            assert_eq!(descriptors(), baseline + 2);
            x11_context::with_display(|context| unsafe {
                assert_eq!(XDefaultScreen(context.as_ptr()), 0);
                assert_eq!((XDisplayWidth(context.as_ptr(), 0),
                            XDisplayHeight(context.as_ptr(), 0)), (640, 480));
            }).unwrap().unwrap();
            assert!(cursor::set_cursor_pos(123, 87));
            for _ in 0..32 {
                assert_eq!(pointer(false).unwrap(), Some(display));
                assert_eq!(pointer(true).unwrap(), Some(xdo));
                assert_eq!(cursor::get_cursor_pos(), Some((123, 87)));
            }
        } else {
            let start = Instant::now();
            assert_eq!(pointer(false).unwrap_err().kind(), std::io::ErrorKind::ConnectionRefused);
            assert_eq!(pointer(true).unwrap_err().kind(), std::io::ErrorKind::ConnectionRefused);
            for _ in 0..32 {
                assert_eq!(pointer(false).unwrap(), None);
                assert_eq!(pointer(true).unwrap(), None);
            }
            assert_eq!(cursor::get_cursor_pos(), None);
            assert!(!cursor::set_cursor_pos(123, 87));
            assert!(start.elapsed() < Duration::from_millis(900), "authentication cooldown observation expired");
            assert_eq!(descriptors(), baseline);
        }
        assert_eq!((DISPLAY_OPENS.load(Ordering::SeqCst), XDO_OPENS.load(Ordering::SeqCst)), (1, 1));
    }).join().unwrap();
    assert_eq!(descriptors(), baseline);
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), tasks);
    assert_eq!(retirements(), if admitted { (1, 1) } else { (0, 0) });
    println!("X11_AUTH_CHILD credential={credential} result={} components=xlib,xdo native_opens=2 contexts={} queries={} callbacks=paired descriptors=retired threads=retired",
             if admitted { "admitted" } else { "refused" }, if admitted { 2 } else { 0 },
             if admitted { "server-real" } else { "unavailable" });
}

fn concurrent_contexts() {
    const WORKERS: usize = 8;
    assert_eq!(std::env::var("DISPLAY").unwrap(), ":98");
    let baseline = descriptors();
    let tasks = std::fs::read_dir("/proc/self/task").unwrap().count();
    let phase = Arc::new(Barrier::new(WORKERS + 1));
    let workers: Vec<_> = (0..WORKERS).map(|_| {
        let phase = Arc::clone(&phase);
        thread::spawn(move || {
            phase.wait(); // Begin native construction together.
            let display = pointer(false).unwrap().unwrap();
            let xdo = pointer(true).unwrap().unwrap();
            phase.wait(); // All owners exist before the parent snapshots them.
            phase.wait(); // Keep owners live until that snapshot completes.
            for _ in 0..64 {
                x11_context::with_display(|context| unsafe {
                    assert_eq!(context.as_ptr() as usize, display);
                    assert_eq!(XDefaultScreen(context.as_ptr()), 0);
                    assert_eq!((XDisplayWidth(context.as_ptr(), 0),
                                XDisplayHeight(context.as_ptr(), 0)), (640, 480));
                    let (mut focus, mut revert) = (0, -1);
                    assert_eq!(XGetInputFocus(context.as_ptr(), &mut focus, &mut revert), 1);
                    assert_eq!((focus, revert), (1, 0)); // Fresh Xvfb: PointerRoot, RevertToNone.
                }).unwrap().unwrap();
                x11_context::with_xdo(|context| unsafe {
                    assert_eq!(context.as_ptr() as usize, xdo);
                    let (mut x, mut y, mut screen) = (-1, -1, -1);
                    assert_eq!(xdo_get_mouse_location(context.as_ptr(), &mut x, &mut y, &mut screen), 0);
                    assert_eq!(screen, 0);
                    assert!((0..640).contains(&x) && (0..480).contains(&y));
                }).unwrap().unwrap();
            }
            phase.wait(); // All real server requests have completed.
            phase.wait(); // Parent observes resources before TLS retirement.
            (display, xdo)
        })
    }).collect();
    phase.wait();
    phase.wait();
    let live = || {
        assert_eq!((DISPLAY_OPENS.load(Ordering::SeqCst), XDO_OPENS.load(Ordering::SeqCst)),
                   (WORKERS, WORKERS));
        assert_eq!(retirements(), (0, 0));
        assert_eq!(descriptors(), baseline + 2 * WORKERS);
        assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), tasks + WORKERS);
    };
    live();
    phase.wait();
    phase.wait();
    live();
    phase.wait();
    let mut pointers = BTreeSet::new();
    for worker in workers {
        let (display, xdo) = worker.join().unwrap();
        assert!(pointers.insert(display) && pointers.insert(xdo), "simultaneous owners alias");
    }
    assert_eq!(retirements(), (WORKERS, WORKERS));
    assert_eq!(descriptors(), baseline);
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), tasks);
    println!("X11_CONCURRENT_CONTEXTS_NATIVE=pass source=complete-context-module native_init=ready-at-main fixture_init=none workers=8 simultaneous_contexts=16 unique_owners=16 reuses_per_owner=64 queries=1024 server=real callbacks=paired live_resources=observed descriptors=retired threads=joined scope=pinned-native-runtime");
}

#[repr(C)]
struct XColor { pixel: c_ulong, red: u16, green: u16, blue: u16, flags: c_char, pad: c_char }
#[repr(C)]
struct CursorImagePrefix { position: [i16; 2], size: [u16; 2], hotspot: [u16; 2], serial: c_ulong }
#[link(name = "X11")]
extern "C" {
    fn XDefaultRootWindow(display: *mut c_void) -> c_ulong;
    fn XCreateBitmapFromData(display: *mut c_void, drawable: c_ulong, data: *const c_char,
                             width: u32, height: u32) -> c_ulong;
    fn XCreatePixmapCursor(display: *mut c_void, source: c_ulong, mask: c_ulong,
                          foreground: *mut XColor, background: *mut XColor, x: u32, y: u32) -> c_ulong;
    fn XDefineCursor(display: *mut c_void, window: c_ulong, cursor: c_ulong) -> c_int;
    fn XUndefineCursor(display: *mut c_void, window: c_ulong) -> c_int;
    fn XFreePixmap(display: *mut c_void, pixmap: c_ulong) -> c_int;
    fn XFreeCursor(display: *mut c_void, cursor: c_ulong) -> c_int;
    fn XWarpPointer(display: *mut c_void, source: c_ulong, destination: c_ulong,
                    source_x: c_int, source_y: c_int, width: u32, height: u32, x: c_int, y: c_int) -> c_int;
    fn XSync(display: *mut c_void, discard: c_int) -> c_int;
    fn XFree(pointer: *mut c_void) -> c_int;
    fn __real_XFree(pointer: *mut c_void) -> c_int;
}
#[link(name = "Xfixes")]
extern "C" {
    fn XFixesGetCursorImage(display: *mut c_void) -> *mut c_void;
    fn __real_XFixesGetCursorImage(display: *mut c_void) -> *mut c_void;
}
static CURSOR_QUERIES: AtomicUsize = AtomicUsize::new(0);
static CURSOR_FREES: AtomicUsize = AtomicUsize::new(0);
static CURSOR_IMAGES: Mutex<BTreeSet<usize>> = Mutex::new(BTreeSet::new());
#[no_mangle]
unsafe extern "C" fn __wrap_XFixesGetCursorImage(display: *mut c_void) -> *mut c_void {
    CURSOR_QUERIES.fetch_add(1, Ordering::SeqCst);
    let image = __real_XFixesGetCursorImage(display);
    assert!(!image.is_null());
    let mut live = CURSOR_IMAGES.lock().unwrap();
    assert!(live.is_empty(), "more than one native image retained by the fixture worker");
    assert!(live.insert(image as usize));
    image
}
#[no_mangle]
unsafe extern "C" fn __wrap_XFree(pointer: *mut c_void) -> c_int {
    assert!(CURSOR_IMAGES.lock().unwrap().remove(&(pointer as usize)), "image retired twice or unowned");
    let status = __real_XFree(pointer);
    CURSOR_FREES.fetch_add(1, Ordering::SeqCst);
    status
}

struct FixtureCursors { display: *mut c_void, root: c_ulong, cursors: [c_ulong; 2] }
impl FixtureCursors {
    fn new() -> Self {
        x11_context::with_display(|context| unsafe {
            let display = context.as_ptr();
            let root = XDefaultRootWindow(display);
            let source = XCreateBitmapFromData(display, root, [1_u8, 2].as_ptr().cast(), 2, 2);
            let mask = XCreateBitmapFromData(display, root, [3_u8, 3].as_ptr().cast(), 2, 2);
            assert!(source != 0 && mask != 0);
            let color = |red, green, blue| XColor { pixel: 0, red, green, blue, flags: 0, pad: 0 };
            let a = XCreatePixmapCursor(display, source, mask, &mut color(65535, 0, 0),
                                        &mut color(0, 0, 65535), 0, 0);
            let b = XCreatePixmapCursor(display, source, mask, &mut color(0, 65535, 0),
                                        &mut color(65535, 65535, 65535), 1, 1);
            assert!(a != 0 && b != 0 && a != b);
            XFreePixmap(display, source);
            XFreePixmap(display, mask);
            XWarpPointer(display, 0, root, 0, 0, 0, 0, 10, 10);
            XSync(display, 0);
            Self { display, root, cursors: [a, b] }
        }).unwrap().unwrap()
    }
    fn select(&self, index: usize) {
        unsafe { XDefineCursor(self.display, self.root, self.cursors[index]); XSync(self.display, 0); }
    }
    // Observe the historical two-query native call shape, not a full old app.
    fn queried_serial(&self) -> u64 {
        unsafe {
            let image = XFixesGetCursorImage(self.display);
            let serial = (*(image.cast::<CursorImagePrefix>())).serial as u64;
            XFree(image);
            serial
        }
    }
}
impl Drop for FixtureCursors {
    fn drop(&mut self) {
        unsafe {
            XUndefineCursor(self.display, self.root);
            for cursor in self.cursors { XFreeCursor(self.display, cursor); }
            XSync(self.display, 0);
        }
    }
}

fn cursor_snapshots() {
    let baseline = descriptors();
    let tasks = std::fs::read_dir("/proc/self/task").unwrap().count();
    thread::spawn(move || {
        let cursors = FixtureCursors::new();
        let check = |data: x11_cursor::CursorSnapshot, index| {
            assert_eq!((data.width, data.height), (2, 2));
            assert_eq!((data.hotx, data.hoty), if index == 0 { (0, 0) } else { (1, 1) });
            let foreground = if index == 0 { [255, 0, 0, 255] } else { [0, 255, 0, 255] };
            let background = if index == 0 { [0, 0, 255, 255] } else { [255, 255, 255, 255] };
            assert_eq!(data.colors, [foreground, background, background, foreground].concat());
        };
        for _ in 0..32 {
            cursors.select(0);
            let old = cursors.queried_serial();
            cursors.select(1);
            assert_ne!(cursors.queried_serial(), old, "two real queries did not observe a changed serial");
            cursors.select(0);
            let serial = x11_cursor::capture_serial().unwrap().unwrap();
            assert_eq!(CURSOR_IMAGES.lock().unwrap().len(), 1);
            let queries = CURSOR_QUERIES.load(Ordering::SeqCst);
            cursors.select(1);
            let image = x11_cursor::take_data(serial).unwrap();
            assert_eq!(image.id, serial);
            check(image, 0); // Pixels belong to the captured old serial, not the new cursor.
            assert_eq!(CURSOR_QUERIES.load(Ordering::SeqCst), queries, "pixel read made a second native query");
            let next = x11_cursor::capture_serial().unwrap().unwrap();
            assert_ne!(next, serial);
            check(x11_cursor::take_data(next).unwrap(), 1);
            assert_eq!(x11_cursor::take_data(next).err().unwrap().kind(), std::io::ErrorKind::NotFound);
            assert!(CURSOR_IMAGES.lock().unwrap().is_empty());
            assert_eq!(descriptors(), baseline + 1);
        }
        for _ in 0..16 {
            let first = x11_cursor::capture_serial().unwrap().unwrap();
            let next = x11_cursor::capture_serial().unwrap().unwrap();
            assert_eq!(first, next);
            assert_eq!(CURSOR_IMAGES.lock().unwrap().len(), 1);
            check(x11_cursor::take_data(next).unwrap(), 1);
        }
        let serial = x11_cursor::capture_serial().unwrap().unwrap();
        assert_eq!(x11_cursor::take_data(serial.checked_add(1).unwrap()).err().unwrap().kind(),
                   std::io::ErrorKind::InvalidInput);
        assert!(CURSOR_IMAGES.lock().unwrap().is_empty());
        let serial = x11_cursor::capture_serial().unwrap().unwrap();
        assert_eq!(CURSOR_IMAGES.lock().unwrap().len(), 1);
        cursor::reset_input_cache();
        assert!(CURSOR_IMAGES.lock().unwrap().is_empty());
        assert_eq!(x11_cursor::take_data(serial).err().unwrap().kind(), std::io::ErrorKind::NotFound);
        cursor::reset_input_cache(); // Idempotent, without another native query.
    }).join().unwrap();
    assert_eq!(descriptors(), baseline);
    for _ in 0..8 {
        thread::spawn(|| {
            let cursors = FixtureCursors::new();
            cursors.select(0);
            assert!(x11_cursor::capture_serial().unwrap().is_some());
            assert_eq!(CURSOR_IMAGES.lock().unwrap().len(), 1);
            // Leave this captured image unconsumed until exact TLS retirement.
        }).join().unwrap();
        assert!(CURSOR_IMAGES.lock().unwrap().is_empty());
        assert_eq!(descriptors(), baseline);
    }
    assert_eq!(CURSOR_QUERIES.load(Ordering::SeqCst), 170);
    assert_eq!(CURSOR_FREES.load(Ordering::SeqCst), 170);
    assert_eq!((DISPLAY_OPENS.load(Ordering::SeqCst), XDO_OPENS.load(Ordering::SeqCst)), (9, 0));
    assert_eq!(retirements(), (9, 0));
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), tasks);
    let libraries: BTreeSet<_> = std::fs::read_to_string("/proc/self/maps").unwrap().lines()
        .filter_map(|line| line.split_whitespace().last()).filter(|name| name.contains("/libXfixes.so."))
        .map(str::to_owned).collect();
    assert_eq!(libraries.len(), 1);
    println!("X11_CURSOR_LOADED library={}", libraries.iter().next().unwrap());
    println!("X11_CURSOR_SNAPSHOT_NATIVE=pass source=complete-module old=two-query-call-shape serial_mismatches=32 current_snapshots=64 changes_between_phases=32 pixels=server-real second_query=absent query_calls=170 images=170 frees=170 live_image_peak=1 replacements=16 wrong_serial=refused repeated_consume=refused reset=discarded-and-idempotent retained_thread_exits=8 display_owners=9 descriptors=retired threads=joined scope=native-cursor-snapshot");
}

fn main() {
    // libX11 1.8+ normally initializes threading in its ELF constructor.
    // Fail instead of hiding a missing initialization behind a fixture call.
    assert!(unsafe { !_Xglobal_lock.is_null() && _XInitDisplayLock_fn.is_some() },
            "pinned Xlib threading is not initialized at fixture main entry");
    if let Some(scenario) = std::env::args().nth(1) {
        if scenario == "cursor-snapshots" {
            cursor_snapshots();
            return;
        }
        if scenario == "concurrent-contexts" {
            concurrent_contexts();
            return;
        }
        if let Some(credential) = scenario.strip_prefix("auth-") {
            authentication(credential);
            return;
        }
        if matches!(scenario.as_str(), "retry-xlib-historical" | "retry-xlib-corrected"
                   | "retry-xdo-historical" | "retry-xdo-corrected") {
            retry(&scenario);
            return;
        }
        assert!(matches!(scenario.as_str(), "route-xlib-historical" | "route-xlib-corrected"
                        | "route-xdo-historical" | "route-xdo-corrected"));
        let baseline = descriptors();
        let threads = std::fs::read_dir("/proc/self/task").unwrap().count();
        std::env::set_var("DISPLAY", ":95");
        let historical = scenario.ends_with("historical");
        let xdo = scenario.contains("-xdo-");
        if historical {
            let refused = if xdo { unsafe { xdo_new(ptr::null()).is_null() } }
                          else { unsafe { XOpenDisplay(ptr::null()).is_null() } };
            assert!(refused);
        } else {
            let error = if xdo { x11_context::open_xdo().err() } else { x11_context::open_display().err() };
            assert_eq!(error.expect("constructor unexpectedly opened").kind(), std::io::ErrorKind::ConnectionRefused);
        }
        assert_eq!(descriptors(), baseline);
        assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), threads);
        println!("X11_{}_ROUTE_CHILD variant={} result=refused descriptors=retired threads=retired",
                 if xdo { "XDO" } else { "XLIB" }, if historical { "historical" } else { "corrected" });
        return;
    }
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if info.payload().downcast_ref::<&str>() != Some(&"native owner unwind case") {
            original_hook(info);
        }
    }));
    let baseline = descriptors();

    // The isolated parent retains these exact pointers solely to bound historical-test residue.
    for _ in 0..8 {
        let pointers = thread::spawn(move || {
            let display = OLD_DISPLAY.with(|p| *p.borrow());
            let xdo = OLD_XDO.with(|p| *p.borrow());
            assert!(!display.is_null() && !xdo.is_null());
            assert_eq!(descriptors(), baseline + 2);
            (display as usize, xdo as usize)
        }).join().unwrap();
        assert_eq!(descriptors(), baseline + 2, "raw TLS contexts survive joined thread exit");
        assert_eq!(retirements(), (0, 0));
        unsafe {
            xdo_free(pointers.1 as *mut Xdo);
            assert_eq!(XCloseDisplay(pointers.0 as *mut c_void), 0);
        }
        assert_eq!(descriptors(), baseline);
        DISPLAY_RETIREMENTS.store(0, Ordering::SeqCst);
        XDO_RETIREMENTS.store(0, Ordering::SeqCst);
    }

    for iteration in 0..32 {
        let result = thread::spawn(move || {
            let display = pointer(false).unwrap().unwrap();
            let xdo = pointer(true).unwrap().unwrap();
            assert_eq!(descriptors(), baseline + 2);
            for _ in 0..16 {
                assert_eq!(pointer(false).unwrap(), Some(display));
                assert_eq!(pointer(true).unwrap(), Some(xdo));
            }
            if iteration == 0 {
                let libraries: BTreeSet<_> = std::fs::read_to_string("/proc/self/maps").unwrap()
                    .lines().filter_map(|line| line.split_whitespace().last())
                    .filter(|name| name.contains("/libX11.so.") || name.contains("/libxdo.so."))
                    .map(str::to_owned).collect();
                assert_eq!(libraries.len(), 2);
                for library in libraries { println!("X11_THREAD_CONTEXT_LOADED library={library}"); }
            }
            if iteration >= 16 { panic!("native owner unwind case"); }
        }).join();
        match result {
            Ok(()) => assert!(iteration < 16),
            Err(payload) => {
                assert!(iteration >= 16);
                assert_eq!(payload.downcast_ref::<&str>(), Some(&"native owner unwind case"));
            }
        }
        assert_eq!(descriptors(), baseline, "owned TLS contexts retire before thread join completes");
        assert_eq!(retirements(), (iteration + 1, iteration + 1));
    }

    let refuse = || {
        assert_eq!(x11_context::open_display().err().expect("invalid selector accepted").kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(x11_context::open_xdo().err().expect("invalid selector accepted").kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(descriptors(), baseline);
        assert_eq!(retirements(), (32, 32));
    };
    for display in ["", ":", ":1.", ":.0", ":1.0.0", ":+1", ":-1", ":1.-1",
                    "localhost:98", "unix/:98", "/tmp/.X11-unix/X98", "tcp/:98",
                    ":2147483648", ":98.2147483648", ":98\n", " :98"] {
        std::env::set_var("DISPLAY", display);
        refuse();
    }
    std::env::remove_var("DISPLAY");
    refuse();
    use std::os::unix::ffi::OsStringExt;
    std::env::set_var("DISPLAY", std::ffi::OsString::from_vec(vec![0xff]));
    refuse();
    for (display, screen, width, height) in [(":00098", 0, 640, 480),
            (":00098.0000", 0, 640, 480), (":00098.0001", 1, 800, 600)] {
        std::env::set_var("DISPLAY", display);
        {
            let display = x11_context::open_display().unwrap();
            let _xdo = x11_context::open_xdo().unwrap();
            assert_eq!(descriptors(), baseline + 2);
            unsafe {
                assert_eq!(XDefaultScreen(display.as_ptr()), screen);
                assert_eq!((XDisplayWidth(display.as_ptr(), screen), XDisplayHeight(display.as_ptr(), screen)), (width, height));
            }
        }
        assert_eq!(descriptors(), baseline);
    }
    for _ in 0..16 {
        std::env::set_var("DISPLAY", ":97");
        assert_eq!(x11_context::open_display().err().expect("absent display opened").kind(), std::io::ErrorKind::ConnectionRefused);
        assert_eq!(x11_context::open_xdo().err().expect("absent display opened").kind(), std::io::ErrorKind::ConnectionRefused);
        assert_eq!(retirements(), (35, 35), "failed constructors have no native retirement");
        assert_eq!(descriptors(), baseline);
    }
    println!("X11_THREAD_CONTEXT_NATIVE=pass source=production-owner-and-constructors old=retained-after-thread-exit old_threads=8 corrected_threads=32 unwind_threads=16 contexts=70 constructor_refusals=32 selectors_refused=18 canonical_screens=3 callbacks=paired descriptors=retired scope=native-owner");
}
