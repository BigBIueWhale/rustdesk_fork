//! Exercise the complete production owner with real X11 and XDO contexts.
extern crate self as hbb_common;
extern crate self as libxdo_sys;
mod platform {
    #[path = "/work/libs/hbb_common/src/platform/x11_display.rs"]
    pub mod x11_display;
}
use std::{cell::RefCell, collections::BTreeSet, ffi::{c_char, c_int, c_void}, ptr,
          sync::atomic::{AtomicUsize, Ordering}, thread};

#[path = "/work/src/platform/linux/native_context.rs"]
mod native_context;
use native_context::NativeContext;
#[path = "/work/src/platform/linux/x11_context.rs"]
mod x11_context;

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct xdo_t { _private: [u8; 0] }
type Xdo = xdo_t;
#[link(name = "X11")]
extern "C" {
    fn XInitThreads() -> c_int;
    fn XOpenDisplay(name: *const c_char) -> *mut c_void;
    fn XCloseDisplay(display: *mut c_void) -> c_int;
    fn __real_XCloseDisplay(display: *mut c_void) -> c_int;
    fn XDefaultScreen(display: *mut c_void) -> c_int;
    fn XDisplayWidth(display: *mut c_void, screen: c_int) -> c_int;
    fn XDisplayHeight(display: *mut c_void, screen: c_int) -> c_int;
}
#[link(name = "xdo")]
extern "C" {
    pub fn xdo_new(name: *const c_char) -> *mut Xdo;
    pub fn xdo_free(context: *mut Xdo);
    fn __real_xdo_free(context: *mut Xdo);
}

static DISPLAY_RETIREMENTS: AtomicUsize = AtomicUsize::new(0);
static XDO_RETIREMENTS: AtomicUsize = AtomicUsize::new(0);
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
    static DISPLAY: RefCell<Option<NativeContext<c_void>>> = RefCell::new(x11_context::open_display().ok());
    static XDO: RefCell<Option<NativeContext<Xdo>>> = RefCell::new(x11_context::open_xdo().ok());
}

fn descriptors() -> usize { std::fs::read_dir("/proc/self/fd").unwrap().count() }
fn retirements() -> (usize, usize) {
    (DISPLAY_RETIREMENTS.load(Ordering::SeqCst), XDO_RETIREMENTS.load(Ordering::SeqCst))
}

fn main() {
    assert_ne!(unsafe { XInitThreads() }, 0);
    if let Some(scenario) = std::env::args().nth(1) {
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
            let display = DISPLAY.with(|p| p.borrow().as_ref().unwrap().as_ptr());
            let xdo = XDO.with(|p| p.borrow().as_ref().unwrap().as_ptr());
            assert_eq!(descriptors(), baseline + 2);
            for _ in 0..16 {
                DISPLAY.with(|p| assert_eq!(p.borrow().as_ref().unwrap().as_ptr(), display));
                XDO.with(|p| assert_eq!(p.borrow().as_ref().unwrap().as_ptr(), xdo));
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
