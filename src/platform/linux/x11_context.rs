use super::native_context::NativeContext;
use hbb_common::platform::x11_display::unix_display_name;
use libxdo_sys::xdo_t;
use std::{ffi::{c_char, c_int, c_void}, io};

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
            libxdo_sys::xdo_free(context);
        }).ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionRefused,
                                       "local XDO context could not be opened"))
    }
}
