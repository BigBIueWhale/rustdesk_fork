use super::native_context::NativeContext;
use hbb_common::platform::x11_display::unix_display_name;
use libxdo_sys::xdo_t;
use std::{cell::RefCell, ffi::{c_char, c_int, c_void}, io, time::{Duration, Instant}};

const RETRY_DELAY: Duration = Duration::from_secs(1);

struct ThreadContext<T> {
    context: Option<NativeContext<T>>,
    failed_at: Option<Instant>,
}

impl<T> ThreadContext<T> {
    const fn new() -> Self {
        Self { context: None, failed_at: None }
    }

    fn with<R>(&mut self, open: fn() -> io::Result<NativeContext<T>>,
               operation: impl FnOnce(&NativeContext<T>) -> R) -> io::Result<Option<R>> {
        if self.context.is_none() {
            if self.failed_at.is_some_and(|failed| failed.elapsed() < RETRY_DELAY) {
                return Ok(None);
            }
            match open() {
                Ok(context) => {
                    self.context = Some(context);
                    self.failed_at = None;
                }
                Err(error) => {
                    self.failed_at = Some(Instant::now());
                    return Err(error);
                }
            }
        }
        Ok(self.context.as_ref().map(operation))
    }
}

thread_local! {
    static DISPLAY: RefCell<ThreadContext<c_void>> = RefCell::new(ThreadContext::new());
    static XDO: RefCell<ThreadContext<xdo_t>> = RefCell::new(ThreadContext::new());
}

pub(super) fn with_display<R>(operation: impl FnOnce(&NativeContext<c_void>) -> R)
    -> io::Result<Option<R>>
{
    DISPLAY.with(|context| {
        context.try_borrow_mut()
            .map_err(|error| io::Error::new(io::ErrorKind::WouldBlock, error))?
            .with(open_display, operation)
    })
}

pub(super) fn with_xdo<R>(operation: impl FnOnce(&NativeContext<xdo_t>) -> R)
    -> io::Result<Option<R>>
{
    XDO.with(|context| {
        context.try_borrow_mut()
            .map_err(|error| io::Error::new(io::ErrorKind::WouldBlock, error))?
            .with(open_xdo, operation)
    })
}

#[link(name = "X11")]
extern "C" {
    fn XOpenDisplay(name: *const c_char) -> *mut c_void;
    fn XCloseDisplay(display: *mut c_void) -> c_int;
}

pub(super) fn open_display() -> io::Result<NativeContext<c_void>> {
    let name = unix_display_name()?;
    unsafe {
        NativeContext::from_raw(XOpenDisplay(name.as_ptr()), |display| {
            // Zero is the native destructor's return value, not an operation status.
            XCloseDisplay(display);
        }).ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionRefused,
                                       "local X11 display could not be opened"))
    }
}

pub(super) fn open_xdo() -> io::Result<NativeContext<xdo_t>> {
    let name = unix_display_name()?;
    unsafe {
        NativeContext::from_raw(libxdo_sys::xdo_new(name.as_ptr()), |context| {
            if libxdo_sys::xdo_free(context) != 0 && libxdo_sys::xdo_free(context) != 0 {
                std::process::abort();
            }
        }).ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionRefused,
                                       "local XDO context could not be opened"))
    }
}
