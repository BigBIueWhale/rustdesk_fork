//! Exercise the complete production owner with real X11 and XDO contexts.
use std::{cell::RefCell, collections::BTreeSet, ffi::{c_char, c_int, c_void}, ptr,
          sync::atomic::{AtomicUsize, Ordering}, thread};

#[path = "/work/src/platform/linux/native_context.rs"]
mod native_context;
use native_context::NativeContext;

#[repr(C)]
struct Xdo { _private: [u8; 0] }
#[link(name = "X11")]
extern "C" {
    fn XInitThreads() -> c_int;
    fn XOpenDisplay(name: *const c_char) -> *mut c_void;
    fn XCloseDisplay(display: *mut c_void) -> c_int;
}
#[link(name = "xdo")]
extern "C" {
    fn xdo_new(name: *const c_char) -> *mut Xdo;
    fn xdo_free(context: *mut Xdo);
}

static DISPLAY_RETIREMENTS: AtomicUsize = AtomicUsize::new(0);
static XDO_RETIREMENTS: AtomicUsize = AtomicUsize::new(0);
unsafe fn retire_display(display: *mut c_void) {
    assert_eq!(XCloseDisplay(display), 0);
    DISPLAY_RETIREMENTS.fetch_add(1, Ordering::SeqCst);
}
unsafe fn retire_xdo(context: *mut Xdo) {
    xdo_free(context);
    XDO_RETIREMENTS.fetch_add(1, Ordering::SeqCst);
}

thread_local! {
    // Historical ownership shape: a RefCell containing a raw pointer has no native destructor.
    static OLD_DISPLAY: RefCell<*mut c_void> = RefCell::new(unsafe { XOpenDisplay(ptr::null()) });
    static OLD_XDO: RefCell<*mut Xdo> = RefCell::new(unsafe { xdo_new(ptr::null()) });
    static DISPLAY: RefCell<Option<NativeContext<c_void>>> = RefCell::new(unsafe {
        NativeContext::from_raw(XOpenDisplay(ptr::null()), |display| retire_display(display))
    });
    static XDO: RefCell<Option<NativeContext<Xdo>>> = RefCell::new(unsafe {
        NativeContext::from_raw(xdo_new(ptr::null()), |context| retire_xdo(context))
    });
}

fn descriptors() -> usize { std::fs::read_dir("/proc/self/fd").unwrap().count() }
fn retirements() -> (usize, usize) {
    (DISPLAY_RETIREMENTS.load(Ordering::SeqCst), XDO_RETIREMENTS.load(Ordering::SeqCst))
}

fn main() {
    assert_ne!(unsafe { XInitThreads() }, 0);
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

    for _ in 0..16 {
        let unavailable = b":97\0";
        let display = unsafe { XOpenDisplay(unavailable.as_ptr().cast()) };
        let xdo = unsafe { xdo_new(unavailable.as_ptr().cast()) };
        assert!(display.is_null() && xdo.is_null());
        assert!(unsafe { NativeContext::from_raw(display, retire_display) }.is_none());
        assert!(unsafe { NativeContext::from_raw(xdo, retire_xdo) }.is_none());
        assert_eq!(retirements(), (32, 32), "failed constructors have no native retirement");
        assert_eq!(descriptors(), baseline);
    }
    println!("X11_THREAD_CONTEXT_NATIVE=pass source=production-owner old=retained-after-thread-exit old_threads=8 corrected_threads=32 unwind_threads=16 contexts=64 constructor_refusals=32 callbacks=paired descriptors=retired scope=native-owner");
}
