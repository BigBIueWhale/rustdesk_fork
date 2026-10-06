//! Native component fixture: production enumeration, MIT-SHM capture and public callers, real XCB.
//! The historical iterator has a capture stand-in; the corrected case uses production capture.
#![allow(dead_code)]

extern crate self as hbb_common;

use std::{cell::RefCell, io};
#[cfg(corrected)]
use std::rc::Rc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pixfmt {
    BGRA,
    RGBA,
    RGB565LE,
}

pub fn would_block_if_equal(old: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
    STATE.with(|state| state.borrow_mut().frame_comparisons += 1);
    if old.as_slice() == data { return Err(io::ErrorKind::WouldBlock.into()); }
    old.clear();
    old.extend_from_slice(data);
    Ok(())
}

impl Pixfmt {
    pub fn bpp(&self) -> usize {
        match self { Self::RGB565LE => 16, Self::BGRA | Self::RGBA => 32 }
    }
    pub fn bytes_per_pixel(&self) -> usize { self.bpp() / 8 }
}

mod x11 {
    #[path = "ffi.rs"]
    pub mod production_ffi;
    pub mod ffi {
        pub use super::production_ffi::*;
        #[repr(C)]
        pub struct xcb_screen_iterator_t {
            pub data: *mut xcb_screen_t,
            pub rem: i32,
            pub index: i32,
        }
        #[repr(C)]
        pub struct xcb_randr_monitor_info_iterator_t {
            pub data: *mut xcb_randr_monitor_info_t,
            pub rem: i32,
            pub index: i32,
        }
        extern "C" {
            pub fn xcb_setup_roots_iterator(r: *const xcb_setup_t) -> xcb_screen_iterator_t;
            pub fn xcb_screen_next(i: *mut xcb_screen_iterator_t);
            pub fn xcb_get_geometry_unchecked(c: *mut xcb_connection_t, drawable: xcb_drawable_t)
                -> xcb_get_geometry_cookie_t;
            pub fn xcb_get_geometry_reply(c: *mut xcb_connection_t, cookie: xcb_get_geometry_cookie_t,
                                          e: *mut *mut xcb_generic_error_t) -> *mut xcb_get_geometry_reply_t;
            pub fn xcb_randr_get_monitors_unchecked(
                c: *mut xcb_connection_t,
                window: xcb_window_t,
                active: u8,
            ) -> xcb_randr_get_monitors_cookie_t;
            pub fn xcb_randr_get_monitors_monitors_iterator(
                reply: *const xcb_randr_get_monitors_reply_t,
            ) -> xcb_randr_monitor_info_iterator_t;
            pub fn xcb_randr_monitor_info_next(cursor: *mut xcb_randr_monitor_info_iterator_t);
            pub fn xcb_get_atom_name_name(reply: *const xcb_get_atom_name_reply_t) -> *const u8;
            pub fn xcb_get_atom_name_name_length(reply: *const xcb_get_atom_name_reply_t) -> i32;
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub struct xcb_get_geometry_cookie_t { pub sequence: u32 }
        #[repr(C)]
        pub struct xcb_get_geometry_reply_t {
            pub response_type: u8, pub depth: u8, pub sequence: u16, pub length: u32,
            pub root: xcb_window_t, pub x: i16, pub y: i16,
            pub width: u16, pub height: u16, pub border_width: u16, pub pad0: [u8; 2],
        }
    }
    mod display;
    #[cfg(not(corrected))]
    mod iter;
    #[cfg(corrected)]
    mod iter {
        include!("x11/iter.rs");

        pub fn query_atom_name(c: *mut super::ffi::xcb_connection_t, atom: u32)
            -> std::io::Result<String> {
            get_atom_name(c, atom)
        }

        pub fn reject_unsupported_layouts() {
            assert_eq!(classify_format(0, 24, 24, 0x00ff0000, 0x0000ff00, 0x000000ff), None);
            assert_eq!(classify_format(0, 16, 16, 0x7c00, 0x03e0, 0x001f), None);
            assert_eq!(classify_format(1, 24, 32, 0x00ff0000, 0x0000ff00, 0x000000ff), None);
            assert_eq!(classify_format(0, 24, 32, 0x00ff0000, 0x0000ff00, 0x0000ff00), None);
            assert_eq!(classify_format(2, 24, 32, 0x00ff0000, 0x0000ff00, 0x000000ff), None);
        }
    }
    mod server;
    pub use display::*;
    pub use iter::*;
    pub use server::*;

    #[cfg(corrected)]
    mod capturer;
    #[cfg(corrected)]
    pub use capturer::Capturer;
    #[cfg(not(corrected))]
    pub struct Capturer;
    #[cfg(not(corrected))]
    impl Capturer {
        pub fn new(_: Display) -> std::io::Result<Self> {
            Err(std::io::ErrorKind::Unsupported.into())
        }
        pub fn display(&self) -> &Display {
            unreachable!("capture is outside this component fixture")
        }
        pub fn frame(&mut self) -> std::io::Result<&[u8]> {
            Err(std::io::ErrorKind::Unsupported.into())
        }
    }
}

#[cfg(corrected)]
mod common {
    pub trait TraitCapturer {
        fn frame(&mut self, timeout: std::time::Duration) -> std::io::Result<crate::Frame<'_>>;
    }
    #[path = "x11.rs"]
    mod implementation;
    pub use implementation::*;
}
#[cfg(corrected)]
pub enum Frame<'a> {
    PixelBuffer(common::PixelBuffer<'a>),
}
#[cfg(corrected)]
pub trait TraitPixelBuffer {
    fn data(&self) -> &[u8];
    fn width(&self) -> usize;
    fn height(&self) -> usize;
    fn stride(&self) -> Vec<usize>;
    fn pixfmt(&self) -> Pixfmt;
}

use x11::ffi::*;

#[repr(C)]
struct InternAtomCookie {
    sequence: u32,
}

#[repr(C)]
struct InternAtomReply {
    response_type: u8,
    pad0: u8,
    sequence: u16,
    length: u32,
    atom: u32,
}

#[repr(C)]
struct AtomNameHeader {
    response_type: u8,
    pad0: u8,
    sequence: u16,
    length: u32,
    name_len: u16,
    pad1: [u8; 22],
}

struct Allocation {
    pointer: *mut libc::c_void,
    bytes: usize,
    monitor: bool,
    retired: bool,
}

#[derive(Default)]
struct State {
    allocations: Vec<Allocation>,
    queries: usize,
    reject_query: usize,
    atom_queries: usize,
    reject_atom_query: usize,
    inject_atom_nul: bool,
    malformed_atom: u8,
    malformed_monitors: u8,
    malformed_query: usize,
    bad_atom_reply: usize,
    bad_monitor_reply: usize,
    malformed_setup: u8,
    capture_queries: usize,
    reject_capture_query: usize,
    capture_replies: usize,
    capture_errors: usize,
    capture_error: Option<(u8, u8, u16, u32)>,
    attach_queries: usize,
    reject_attach_query: usize,
    rejected_attach_cookie: Option<(*mut xcb_connection_t, u32)>,
    attach_errors: usize,
    attach_error: Option<(u8, u8, u16, u32)>,
    frame_comparisons: usize,
    segments: Vec<i32>,
}
thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

pub mod libc {
    pub use std::ffi::c_void;
    pub type c_int = i32;
    pub const IPC_PRIVATE: c_int = 0;
    pub const IPC_CREAT: c_int = 0o1000;
    pub const IPC_RMID: c_int = 0;
    pub const SHM_RDONLY: c_int = 0o10000;
    extern "C" {
        #[link_name = "free"]
        pub fn system_free(pointer: *mut c_void);
        #[link_name = "shmget"]
        fn system_shmget(key: c_int, size: usize, flags: c_int) -> c_int;
        pub fn shmat(id: c_int, addr: *const c_void, flags: c_int) -> *mut c_void;
        pub fn shmdt(addr: *const c_void) -> c_int;
        pub fn shmctl(id: c_int, cmd: c_int, status: *mut c_void) -> c_int;
    }
    pub unsafe fn shmget(key: c_int, size: usize, flags: c_int) -> c_int {
        let id = system_shmget(key, size, flags);
        if id >= 0 {
            super::STATE.with(|state| state.borrow_mut().segments.push(id));
        }
        id
    }
    pub unsafe fn free(pointer: *mut c_void) {
        let deferred = super::STATE.with(|state| {
            let mut state = state.borrow_mut();
            // Observe acquisitions as well as frees: an address can name a newer allocation.
            if let Some(entry) = state.allocations.iter_mut().rev().find(|e| e.pointer == pointer) {
                assert!(!entry.retired, "reply/error freed twice");
                entry.retired = true;
                entry.monitor
            } else {
                false
            }
        });
        // Deferral makes the historical invalid ordering deterministic without executing
        // an uncontrolled dangling read. Retirement is still observed at the real free call.
        if !deferred {
            system_free(pointer);
        }
    }
}

#[macro_export]
macro_rules! warn { ($($arg:tt)*) => { eprintln!($($arg)*); } }
pub mod log { pub use crate::warn; }

extern "C" {
    #[link_name = "__real_xcb_get_setup"]
    fn real_setup(c: *mut xcb_connection_t) -> *const xcb_setup_t;
    fn xcb_intern_atom(c: *mut xcb_connection_t, only_if_exists: u8,
                       name_len: u16, name: *const u8) -> InternAtomCookie;
    fn xcb_intern_atom_reply(c: *mut xcb_connection_t, cookie: InternAtomCookie,
                             error: *mut *mut xcb_generic_error_t) -> *mut InternAtomReply;
    fn xcb_create_gc_checked(c: *mut xcb_connection_t, gc: u32, drawable: u32,
                             value_mask: u32, value_list: *const u32) -> xcb_void_cookie_t;
    fn xcb_poly_fill_rectangle_checked(c: *mut xcb_connection_t, drawable: u32, gc: u32,
                                       rectangles_len: u32, rectangles: *const XcbRectangle) -> xcb_void_cookie_t;
    fn xcb_free_gc_checked(c: *mut xcb_connection_t, gc: u32) -> xcb_void_cookie_t;
    #[link_name = "__real_xcb_get_atom_name_name"]
    fn real_atom_bytes(reply: *const xcb_get_atom_name_reply_t) -> *const u8;
    #[link_name = "__real_xcb_get_geometry_reply"]
    fn real_geometry_reply(c: *mut xcb_connection_t, cookie: xcb_get_geometry_cookie_t,
                           error: *mut *mut xcb_generic_error_t) -> *mut xcb_get_geometry_reply_t;
    #[link_name = "__real_xcb_get_atom_name"]
    fn real_atom_request(c: *mut xcb_connection_t, atom: u32) -> xcb_get_atom_name_cookie_t;
    #[link_name = "__real_xcb_get_atom_name_reply"]
    fn real_atom_reply(c: *mut xcb_connection_t, cookie: xcb_get_atom_name_cookie_t,
                       error: *mut *mut xcb_generic_error_t) -> *const xcb_get_atom_name_reply_t;
    #[link_name = "__real_xcb_randr_get_monitors"]
    fn real_request(c: *mut xcb_connection_t, root: u32, active: u8) -> xcb_randr_get_monitors_cookie_t;
    #[link_name = "__real_xcb_randr_get_monitors_unchecked"]
    fn real_unchecked(c: *mut xcb_connection_t, root: u32, active: u8) -> xcb_randr_get_monitors_cookie_t;
    #[link_name = "__real_xcb_randr_get_monitors_reply"]
    fn real_reply(c: *mut xcb_connection_t, cookie: xcb_randr_get_monitors_cookie_t,
                  error: *mut *mut xcb_generic_error_t) -> *mut xcb_randr_get_monitors_reply_t;
    #[link_name = "__real_xcb_randr_get_monitors_monitors_iterator"]
    fn real_iterator(reply: *const xcb_randr_get_monitors_reply_t) -> xcb_randr_monitor_info_iterator_t;
    #[link_name = "__real_xcb_randr_monitor_info_next"]
    fn real_next(cursor: *mut xcb_randr_monitor_info_iterator_t);
    #[cfg(corrected)]
    #[link_name = "__real_xcb_shm_get_image"]
    fn real_capture_request(c: *mut xcb_connection_t, drawable: xcb_drawable_t,
        x: i16, y: i16, width: u16, height: u16, plane_mask: u32, format: u8,
        shmseg: xcb_shm_seg_t, offset: u32) -> xcb_shm_get_image_cookie_t;
    #[cfg(corrected)]
    #[link_name = "__real_xcb_shm_get_image_reply"]
    fn real_capture_reply(c: *mut xcb_connection_t, cookie: xcb_shm_get_image_cookie_t,
        error: *mut *mut xcb_generic_error_t) -> *mut xcb_shm_get_image_reply_t;
    #[cfg(corrected)]
    #[link_name = "__real_xcb_shm_attach_checked"]
    fn real_attach(c: *mut xcb_connection_t, shmseg: xcb_shm_seg_t,
        shmid: u32, read_only: u8) -> xcb_void_cookie_t;
    #[cfg(corrected)]
    #[link_name = "__real_xcb_request_check"]
    fn real_request_check(c: *mut xcb_connection_t, cookie: xcb_void_cookie_t)
        -> *mut xcb_generic_error_t;
}

#[cfg(corrected)]
#[no_mangle]
unsafe extern "C" fn __wrap_xcb_shm_attach_checked(c: *mut xcb_connection_t,
    shmseg: xcb_shm_seg_t, shmid: u32, read_only: u8) -> xcb_void_cookie_t {
    let reject = STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.attach_queries += 1;
        state.attach_queries == state.reject_attach_query
    });
    // Alter only the selected request's ID; XCB and Xvfb produce the actual error.
    let cookie = real_attach(c, shmseg, if reject { u32::MAX } else { shmid }, read_only);
    if reject {
        STATE.with(|state| {
            assert!(state.borrow_mut().rejected_attach_cookie.replace((c, cookie.sequence)).is_none());
        });
    }
    cookie
}

#[cfg(corrected)]
#[no_mangle]
unsafe extern "C" fn __wrap_xcb_request_check(c: *mut xcb_connection_t,
    cookie: xcb_void_cookie_t) -> *mut xcb_generic_error_t {
    let error = real_request_check(c, cookie);
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if state.rejected_attach_cookie == Some((c, cookie.sequence)) {
            state.rejected_attach_cookie = None;
            assert!(!error.is_null(), "invalid attach ID did not receive a server error");
            let actual = &*error;
            state.attach_errors += 1;
            state.attach_error = Some((actual.error_code, actual.major_code,
                                      actual.minor_code, actual.resource_id));
            state.allocations.push(Allocation { pointer: error.cast(),
                bytes: 36, monitor: false, retired: false });
        }
    });
    error
}

#[cfg(corrected)]
#[no_mangle]
unsafe extern "C" fn __wrap_xcb_shm_get_image(c: *mut xcb_connection_t,
    drawable: xcb_drawable_t, x: i16, y: i16, width: u16, height: u16,
    plane_mask: u32, format: u8, shmseg: xcb_shm_seg_t, offset: u32)
    -> xcb_shm_get_image_cookie_t {
    let drawable = STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.capture_queries += 1;
        if state.capture_queries == state.reject_capture_query { 0 } else { drawable }
    });
    // Only the selected request's drawable changes. XCB and the real server
    // generate the reply/error; no response or shared-memory bytes are fabricated.
    real_capture_request(c, drawable, x, y, width, height, plane_mask, format, shmseg, offset)
}

#[cfg(corrected)]
#[no_mangle]
unsafe extern "C" fn __wrap_xcb_shm_get_image_reply(c: *mut xcb_connection_t,
    cookie: xcb_shm_get_image_cookie_t, error: *mut *mut xcb_generic_error_t)
    -> *mut xcb_shm_get_image_reply_t {
    assert!(!error.is_null(), "capture omitted its protocol-error result pointer");
    let reply = real_capture_reply(c, cookie, error);
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if !reply.is_null() {
            state.capture_replies += 1;
            state.allocations.push(Allocation { pointer: reply.cast(),
                bytes: 0, monitor: false, retired: false });
        }
        if !(*error).is_null() {
            assert!(reply.is_null(), "rejected GetImage unexpectedly returned pixels");
            let actual = &**error;
            state.capture_errors += 1;
            state.capture_error = Some((actual.error_code, actual.major_code,
                                        actual.minor_code, actual.resource_id));
            state.allocations.push(Allocation { pointer: (*error).cast(),
                bytes: 36, monitor: false, retired: false });
        }
    });
    reply
}

#[no_mangle]
unsafe extern "C" fn __wrap_xcb_get_setup(c: *mut xcb_connection_t) -> *const xcb_setup_t {
    let setup = real_setup(c);
    let fault = STATE.with(|state| state.borrow().malformed_setup);
    if setup.is_null() || fault == 0 {
        return setup;
    }
    let header = &mut *setup.cast_mut();
    assert_eq!(header.status, 1);
    assert_eq!(header.roots_len, 2);
    let vendor = (usize::from(header.vendor_len) + 3) & !3;
    let screen = setup.cast::<u8>().add(40 + vendor + usize::from(header.pixmap_formats_len) * 8)
        .cast::<xcb_screen_t>().cast_mut();
    match fault {
        1 => header.length = 7,
        2 => header.vendor_len = u16::MAX,
        3 => header.pixmap_formats_len = u8::MAX,
        4 => header.roots_len = u8::MAX,
        5 => (*screen).allowed_depths_len = u8::MAX,
        6 => {
            assert!((*screen).allowed_depths_len > 0);
            let depth = screen.cast::<u8>().add(40).cast::<xcb_depth_t>();
            (*depth).visuals_len = u16::MAX;
        }
        7 => header.roots_len = 0,
        _ => unreachable!("unknown X setup fault"),
    }
    setup
}

#[repr(C)]
struct XcbRectangle { x: i16, y: i16, width: u16, height: u16 }

#[cfg(corrected)]
fn draw_red(server: &x11::Server, root: u32, pixel: u32) -> io::Result<()> {
    unsafe fn checked(server: *mut xcb_connection_t, cookie: xcb_void_cookie_t) -> io::Result<()> {
        let error = xcb_request_check(server, cookie);
        if error.is_null() { return Ok(()); }
        let code = (*error).error_code;
        libc::system_free(error.cast());
        Err(io::Error::new(io::ErrorKind::Other, format!("X11 draw error {code}")))
    }
    unsafe {
        let gc = xcb_generate_id(server.raw());
        checked(server.raw(), xcb_create_gc_checked(server.raw(), gc, root, 4, &pixel))?;
        let rectangle = XcbRectangle { x: 0, y: 0, width: 3, height: 1 };
        let draw = checked(server.raw(), xcb_poly_fill_rectangle_checked(server.raw(), root, gc, 1, &rectangle));
        let retire = checked(server.raw(), xcb_free_gc_checked(server.raw(), gc));
        draw?;
        retire
    }
}

#[cfg(corrected)]
fn intern_atom(c: *mut xcb_connection_t, name: &[u8]) -> io::Result<u32> {
    use std::convert::TryFrom;
    let length = u16::try_from(name.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
    unsafe {
        let mut error = std::ptr::null_mut();
        let reply = xcb_intern_atom_reply(c, xcb_intern_atom(c, 0, length, name.as_ptr()), &mut error);
        let result = if !error.is_null() {
            Err(io::Error::new(io::ErrorKind::Other,
                              format!("InternAtom server error {}", (*error).error_code)))
        } else if reply.is_null() {
            Err(io::ErrorKind::ConnectionAborted.into())
        } else {
            Ok((*reply).atom)
        };
        // Setup allocations are not product allocations; free them without the observer.
        if !error.is_null() { libc::system_free(error.cast()); }
        if !reply.is_null() { libc::system_free(reply.cast()); }
        result
    }
}

#[no_mangle]
unsafe extern "C" fn __wrap_xcb_get_atom_name(c: *mut xcb_connection_t, atom: u32)
    -> xcb_get_atom_name_cookie_t {
    let atom = STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.atom_queries += 1;
        if state.atom_queries == state.reject_atom_query { u32::MAX } else { atom }
    });
    real_atom_request(c, atom)
}

#[no_mangle]
unsafe extern "C" fn __wrap_xcb_get_atom_name_reply(c: *mut xcb_connection_t,
    cookie: xcb_get_atom_name_cookie_t, error: *mut *mut xcb_generic_error_t)
    -> *const xcb_get_atom_name_reply_t {
    let reply = real_atom_reply(c, cookie, error);
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if !reply.is_null() {
            state.allocations.push(Allocation { pointer: reply.cast_mut().cast(),
                bytes: 0, monitor: false, retired: false });
            if state.inject_atom_nul {
                // Xorg truncates interned NUL names. Exercise the protocol-valid byte
                // separately by modifying one byte of an actual 12-byte XCB reply.
                assert_eq!(xcb_get_atom_name_name_length(reply), 12);
                *real_atom_bytes(reply).cast_mut().add(7) = 0;
            }
            if state.malformed_atom != 0 && state.atom_queries == state.malformed_query {
                let header = &mut *reply.cast::<AtomNameHeader>().cast_mut();
                assert!(header.length > 0 && header.length < 16383);
                match state.malformed_atom {
                    1 => header.name_len = (header.length * 4 + 1) as u16,
                    2 => header.name_len = 0,
                    _ => unreachable!("unknown atom fault"),
                }
                state.bad_atom_reply = reply as usize;
            }
        }
        if !error.is_null() && !(*error).is_null() {
            assert_eq!((**error).error_code, 5, "not an actual server BadAtom response");
            state.allocations.push(Allocation { pointer: (*error).cast(),
                bytes: 36, monitor: false, retired: false });
        }
    });
    reply
}

#[no_mangle]
unsafe extern "C" fn __wrap_xcb_get_atom_name_name(reply: *const xcb_get_atom_name_reply_t)
    -> *const u8 {
    let bad = STATE.with(|state| state.borrow().bad_atom_reply == reply as usize);
    if bad {
        eprintln!("X11_BOUNDS_OLD_FAILURE=unchecked-atom-span");
        std::process::exit(44);
    }
    real_atom_bytes(reply)
}

#[no_mangle]
unsafe extern "C" fn __wrap_xcb_get_geometry_reply(c: *mut xcb_connection_t,
    cookie: xcb_get_geometry_cookie_t, error: *mut *mut xcb_generic_error_t)
    -> *mut xcb_get_geometry_reply_t {
    let reply = real_geometry_reply(c, cookie, error);
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if !reply.is_null() {
            state.allocations.push(Allocation { pointer: reply.cast(),
                bytes: 0, monitor: false, retired: false });
        }
        if !error.is_null() && !(*error).is_null() {
            state.allocations.push(Allocation { pointer: (*error).cast(),
                bytes: 36, monitor: false, retired: false });
        }
    });
    reply
}

fn request_root(root: u32) -> u32 {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.queries += 1;
        if state.queries == state.reject_query { 0 } else { root }
    })
}

#[no_mangle]
unsafe extern "C" fn __wrap_xcb_randr_get_monitors(c: *mut xcb_connection_t, root: u32, active: u8)
    -> xcb_randr_get_monitors_cookie_t {
    real_request(c, request_root(root), active)
}
#[no_mangle]
unsafe extern "C" fn __wrap_xcb_randr_get_monitors_unchecked(c: *mut xcb_connection_t, root: u32, active: u8)
    -> xcb_randr_get_monitors_cookie_t {
    real_unchecked(c, request_root(root), active)
}
#[no_mangle]
unsafe extern "C" fn __wrap_xcb_randr_get_monitors_reply(c: *mut xcb_connection_t,
    cookie: xcb_randr_get_monitors_cookie_t, error: *mut *mut xcb_generic_error_t)
    -> *mut xcb_randr_get_monitors_reply_t {
    let reply = real_reply(c, cookie, error);
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if !reply.is_null() {
            state.allocations.push(Allocation { pointer: reply.cast(),
                bytes: 32 + (*reply).length as usize * 4, monitor: true, retired: false });
            if state.malformed_monitors != 0
                && (state.malformed_query == 0 || state.queries == state.malformed_query) {
                assert_eq!((*reply).n_monitors, 1);
                match state.malformed_monitors {
                    1 => (*reply).n_monitors = u32::MAX,
                    2 => (*reply).length = 0,
                    3 => (*reply).n_outputs += 1,
                    4 | 5 => {
                        let info = &mut *reply.add(1).cast::<xcb_randr_monitor_info_t>();
                        assert!(info.n_output > 0);
                        info.n_output = if state.malformed_monitors == 4 { u16::MAX } else { 0 };
                    }
                    6 => {
                        // One actual one-output XCB reply becomes a valid declared
                        // one-monitor/zero-output reply, without a SetMonitor request.
                        assert_eq!((*reply).length, 7);
                        assert_eq!((*reply).n_outputs, 1);
                        let info = &mut *reply.add(1).cast::<xcb_randr_monitor_info_t>();
                        assert_eq!(info.n_output, 1);
                        (*reply).length = 6;
                        (*reply).n_outputs = 0;
                        info.n_output = 0;
                    }
                    _ => unreachable!("unknown monitor fault"),
                }
                if state.malformed_monitors != 6 {
                    state.bad_monitor_reply = reply as usize;
                }
            }
        }
        if !error.is_null() && !(*error).is_null() {
            state.allocations.push(Allocation { pointer: (*error).cast(),
                bytes: 36, monitor: false, retired: false });
        }
    });
    reply
}
#[no_mangle]
unsafe extern "C" fn __wrap_xcb_randr_get_monitors_monitors_iterator(reply: *const xcb_randr_get_monitors_reply_t)
    -> xcb_randr_monitor_info_iterator_t {
    if reply.is_null() {
        eprintln!("X11_DISPLAY_OLD_FAILURE=null-reply-passed-to-iterator");
        std::process::exit(43);
    }
    let bad = STATE.with(|state| state.borrow().bad_monitor_reply == reply as usize);
    if bad {
        eprintln!("X11_BOUNDS_OLD_FAILURE=unchecked-monitor-span");
        std::process::exit(45);
    }
    real_iterator(reply)
}
#[no_mangle]
unsafe extern "C" fn __wrap_xcb_randr_monitor_info_next(cursor: *mut xcb_randr_monitor_info_iterator_t) {
    let retired = STATE.with(|state| {
        let state = state.borrow();
        let data = (*cursor).data as usize;
        let entry = state.allocations.iter().find(|e| e.monitor
            && data >= e.pointer as usize + 32 && data < e.pointer as usize + e.bytes)
            .expect("cursor not backed by the actual reply allocation");
        entry.retired
    });
    if retired {
        eprintln!("X11_DISPLAY_OLD_FAILURE=monitor-used-after-reply-retirement");
        std::process::exit(42);
    }
    real_next(cursor);
}

fn finish_case(reject: usize) {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        assert!(state.allocations.iter().all(|e| e.retired), "reply/error leaked");
        for entry in state.allocations.drain(..).filter(|e| e.monitor) {
            unsafe { libc::system_free(entry.pointer) };
        }
        state.queries = 0;
        state.reject_query = reject;
        state.atom_queries = 0;
        state.reject_atom_query = 0;
        state.inject_atom_nul = false;
        state.malformed_atom = 0;
        state.malformed_monitors = 0;
        state.malformed_query = 0;
        state.bad_atom_reply = 0;
        state.bad_monitor_reply = 0;
        state.malformed_setup = 0;
        state.capture_queries = 0;
        state.reject_capture_query = 0;
        state.capture_replies = 0;
        state.capture_errors = 0;
        state.capture_error = None;
        state.attach_queries = 0;
        state.reject_attach_query = 0;
        assert!(state.rejected_attach_cookie.is_none(), "rejected attach was never checked");
        state.attach_errors = 0;
        state.attach_error = None;
        state.frame_comparisons = 0;
        state.segments.clear();
    });
}

#[cfg(corrected)]
fn configure_bounds(atom: u8, monitor: u8, query: usize) {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.malformed_atom = atom;
        state.malformed_monitors = monitor;
        state.malformed_query = query;
    });
}

#[cfg(corrected)]
fn probe_segment(id: i32) -> io::Result<()> {
    let mapping = unsafe { libc::shmat(id, std::ptr::null(), libc::SHM_RDONLY) };
    if mapping as isize == -1 { return Err(io::Error::last_os_error()); }
    if unsafe { libc::shmdt(mapping) } == -1 { return Err(io::Error::last_os_error()); }
    Ok(())
}

#[cfg(corrected)]
fn exercise_capture_rejection(
    server: &x11::Server, root: u32,
    mut pixel: impl FnMut() -> io::Result<[u8; 3]>,
) -> io::Result<i32> {
    let segment = STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.segments.len(), 1, "capture did not own exactly one segment");
        state.segments[0]
    });
    probe_segment(segment)?;
    assert_eq!(pixel()?, [0x00, 0x00, 0xff], "initial real red pixel differs");
    STATE.with(|state| state.borrow_mut().reject_capture_query = 2);
    let error = pixel().expect_err("server rejection returned a frame");
    assert_eq!(error.kind(), io::ErrorKind::Other, "rejection became unchanged-frame behavior");
    STATE.with(|state| {
        let state = state.borrow();
        let (code, major, minor, resource) = state.capture_error.expect("actual XCB error absent");
        assert_eq!((code, minor, resource), (9, 4, 0), "not the real BadDrawable GetImage response");
        assert_eq!(error.to_string(), format!(
            "X server rejected MIT-SHM GetImage with error {code} (major {major}, minor {minor}, resource {resource})"));
        assert_eq!(state.frame_comparisons, 1, "failed capture compared shared bytes");
        assert!(state.allocations.iter().all(|entry| entry.retired), "capture reply/error leaked");
    });
    // The same capture and connection remain usable; rejection must not replace
    // the prior-frame state or turn later fresh pixels into an unchanged frame.
    assert_eq!(pixel().expect_err("unchanged real pixels unexpectedly changed").kind(),
               io::ErrorKind::WouldBlock);
    draw_red(server, root, 0x000000ff)?;
    assert_eq!(pixel()?, [0xff, 0x00, 0x00], "fresh real blue pixel did not recover");
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!((state.capture_queries, state.capture_replies, state.capture_errors,
                    state.frame_comparisons), (4, 3, 1, 3));
        assert!(state.allocations.iter().all(|entry| entry.retired), "capture reply/error leaked");
    });
    Ok(segment)
}

#[cfg(corrected)]
fn exercise_capture_connection_loss(server: &Rc<x11::Server>) -> io::Result<()> {
    use crate::common::TraitCapturer;
    use std::io::{Read, Write};

    let display = x11::Server::displays(Rc::clone(server))
        .next().expect("first real X screen")?;
    assert_eq!(display.pixfmt(), Pixfmt::BGRA);
    let root = display.root();
    let public_display = common::Display::primary()?;
    finish_case(0);
    draw_red(server, root, 0x00ff0000)?;
    let mut direct = x11::Capturer::new(display)?;
    let mut public = common::Capturer::new(public_display)?;
    let segments = STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.segments.len(), 2, "live captures did not own two segments");
        [state.segments[0], state.segments[1]]
    });
    assert_ne!(segments[0], segments[1]);
    for segment in segments { probe_segment(segment)?; }
    assert_eq!(&direct.frame()?[..3], &[0x00, 0x00, 0xff]);
    let Frame::PixelBuffer(buffer) = public.frame(std::time::Duration::from_millis(100))?;
    assert_eq!(&buffer.data()[..3], &[0x00, 0x00, 0xff]);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!((state.capture_queries, state.capture_replies, state.capture_errors,
                    state.frame_comparisons), (2, 2, 0, 2));
        assert!(state.allocations.iter().all(|entry| entry.retired), "initial capture reply leaked");
    });

    // The driver joins the exact real Xvfb process before granting this token.
    // Both captures and their last valid frame state remain alive across server exit.
    println!("X11_CAPTURE_CONNECTION_READY callers=direct,public segments=2 pixels=red");
    io::stdout().flush()?;
    let mut token = [0];
    io::stdin().read_exact(&mut token)?;
    assert_eq!(token, *b"X", "server retirement token differs");

    let mut connection_error = 0;
    for _ in 0..3 {
        let error = direct.frame().expect_err("dead X connection returned cached pixels");
        connection_error = unsafe { xcb_connection_has_error(server.raw()) };
        assert!(connection_error > 0, "real XCB connection remained healthy");
        let expected = format!("X connection failed during MIT-SHM GetImage: {connection_error}");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted,
                   "connection loss became unchanged-frame behavior");
        assert_eq!(error.to_string(), expected);
        let error = match public.frame(std::time::Duration::from_millis(100)) {
            Err(error) => error,
            Ok(_) => panic!("public capture returned cached pixels after server exit"),
        };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(error.to_string(), expected);
    }
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!((state.capture_queries, state.capture_replies, state.capture_errors,
                    state.frame_comparisons), (8, 2, 0, 2));
        assert!(state.allocations.iter().all(|entry| entry.retired), "capture reply/error leaked");
    });
    drop(direct);
    let absent = probe_segment(segments[0]).expect_err("direct capture segment survived drop");
    assert!(matches!(absent.raw_os_error(), Some(22) | Some(43)), "retirement error: {}", absent);
    probe_segment(segments[1])?;
    drop(public);
    let absent = probe_segment(segments[1]).expect_err("public capture segment survived drop");
    assert!(matches!(absent.raw_os_error(), Some(22) | Some(43)), "retirement error: {}", absent);
    finish_case(0);
    println!("X11_CAPTURE_CONNECTION_NATIVE=pass callers=direct,public repeats=3 connection_error={connection_error} requests=8 replies=2 errors=0 comparisons=2 segments=retired");
    Ok(())
}

#[cfg(corrected)]
fn exercise_attach_rejection(server: &Rc<x11::Server>,
    mut construct: impl FnMut() -> io::Result<()>) -> io::Result<u8> {
    let display = x11::Server::displays(Rc::clone(server))
        .next().expect("first real X screen")?;
    let root = display.root();
    finish_case(0);
    draw_red(server, root, 0x00ff0000)?;
    let mut survivor = x11::Capturer::new(display)?;
    assert_eq!(&survivor.frame()?[..3], &[0x00, 0x00, 0xff]);
    STATE.with(|state| state.borrow_mut().reject_attach_query = 2);
    let error = construct().expect_err("rejected constructor became success");
    assert_eq!(error.kind(), io::ErrorKind::Other);
    let (segments, error_code) = STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.segments.len(), 2, "failed constructor did not create a local segment");
        let (code, major, minor, _) = state.attach_error.expect("actual attach error absent");
        assert!(code > 0 && major > 0);
        assert_eq!(minor, 1, "not an actual MIT-SHM Attach rejection");
        assert_eq!(error.to_string(), format!("X server rejected MIT-SHM attach with error {code}"));
        assert_eq!((state.attach_queries, state.attach_errors, state.capture_queries,
                    state.capture_replies, state.frame_comparisons), (2, 1, 1, 1, 1));
        assert!(state.allocations.iter().all(|entry| entry.retired), "attach error allocation leaked");
        ([state.segments[0], state.segments[1]], code)
    });
    let absent = probe_segment(segments[1]).expect_err("failed constructor segment is still live");
    assert!(matches!(absent.raw_os_error(), Some(22) | Some(43)), "retirement error: {}", absent);
    probe_segment(segments[0])?;
    draw_red(server, root, 0x000000ff)?;
    assert_eq!(&survivor.frame()?[..3], &[0xff, 0x00, 0x00], "live capture lost fresh pixels");
    construct()?;
    let retry_segment = STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.segments.len(), 3);
        assert_eq!((state.attach_queries, state.attach_errors, state.capture_queries,
                    state.capture_replies, state.capture_errors, state.frame_comparisons), (3, 1, 3, 3, 0, 3));
        assert!(state.allocations.iter().all(|entry| entry.retired), "reply/error leaked after retry");
        state.segments[2]
    });
    let absent = probe_segment(retry_segment).expect_err("retry capture segment survived drop");
    assert!(matches!(absent.raw_os_error(), Some(22) | Some(43)), "retirement error: {}", absent);
    probe_segment(segments[0])?;
    drop(survivor);
    let absent = probe_segment(segments[0]).expect_err("surviving capture segment survived drop");
    assert!(matches!(absent.raw_os_error(), Some(22) | Some(43)), "retirement error: {}", absent);
    finish_case(0);
    Ok(error_code)
}

fn main() -> io::Result<()> {
    let scenario = std::env::args().nth(1).expect("scenario");
    finish_case(if scenario == "reject" { 1 } else { 0 });
    #[cfg(corrected)]
    if let Some(fault) = match scenario.as_str() {
        "setup-short" => Some(1),
        "setup-vendor" => Some(2),
        "setup-formats" => Some(3),
        "setup-roots" => Some(4),
        "setup-depths" => Some(5),
        "setup-visuals" => Some(6),
        "setup-trailing" => Some(7),
        _ => None,
    } {
        for _ in 0..16 {
            STATE.with(|state| state.borrow_mut().malformed_setup = fault);
            let server = x11::Server::default().map_err(|_| io::ErrorKind::ConnectionRefused)?;
            if fault == 1 {
                // The former generated cursor ignores the setup length. The actual
                // allocation is still intact, so this comparison does not read past it.
                let old = unsafe { xcb_setup_roots_iterator(server.setup()) };
                assert_eq!(old.rem, 2, "old XCB cursor unexpectedly checked setup length");
                assert!(!old.data.is_null());
            }
            let mut displays = x11::Server::displays(server);
            let error = displays.next().expect("malformed setup result")
                .expect_err("malformed setup accepted");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(displays.next().is_none());
            STATE.with(|state| assert_eq!(state.borrow().queries, 0,
                "malformed setup reached a monitor request"));
            finish_case(0);
        }
        let old_cursor = if fault == 1 { " old_cursor=admitted" } else { "" };
        println!("X11_SETUP_NATIVE=pass scenario={scenario} repeats=16 monitor_queries=0 enumeration=fused{old_cursor}");
        return Ok(());
    }
    let server = x11::Server::default().map_err(|_| io::ErrorKind::ConnectionRefused)?;
    #[cfg(not(corrected))]
    {
        let _ = x11::Server::displays(server).next();
        panic!("historical defect was not observed");
    }
    #[cfg(corrected)]
    {
        let fault = match scenario.as_str() {
            "bounds-atom-length" => Some((1, 0)),
            "bounds-atom-padding" => Some((2, 0)),
            "bounds-mon-count" => Some((0, 1)),
            "bounds-mon-length" => Some((0, 2)),
            "bounds-mon-total" => Some((0, 3)),
            "bounds-mon-span" => Some((0, 4)),
            "bounds-mon-sum" => Some((0, 5)),
            _ => None,
        };
        if scenario == "capture-attach-reject" {
            use crate::common::TraitCapturer;
            let mut error_code = None;
            for public in [false, true] {
                for _ in 0..16 {
                    let code = exercise_attach_rejection(&server, || {
                        if public {
                            let mut capture = common::Capturer::new(common::Display::primary()?)?;
                            let Frame::PixelBuffer(buffer) = capture.frame(std::time::Duration::from_millis(100))?;
                            assert_eq!(&buffer.data()[..3], &[0xff, 0x00, 0x00]);
                            drop(capture);
                        } else {
                            let display = x11::Server::displays(Rc::clone(&server))
                                .next().expect("constructor X screen")?;
                            let mut capture = x11::Capturer::new(display)?;
                            assert_eq!(&capture.frame()?[..3], &[0xff, 0x00, 0x00]);
                            drop(capture);
                        }
                        Ok(())
                    })?;
                    if let Some(previous) = error_code { assert_eq!(code, previous); }
                    error_code = Some(code);
                }
            }
            println!("X11_CAPTURE_ATTACH_NATIVE=pass callers=direct,public repeats=16 server_error={} attach_requests=3 capture_requests=3 capture_replies=3 attach_errors=1 survivor=fresh retry=valid segments=retired", error_code.expect("attach error observed"));
        } else if scenario == "capture-connection-loss" {
            exercise_capture_connection_loss(&server)?;
        } else if scenario == "capture-reject" {
            use crate::{TraitPixelBuffer, common::TraitCapturer};
            for public in [false, true] {
                for _ in 0..16 {
                    let display = x11::Server::displays(Rc::clone(&server))
                        .next().expect("first real X screen")?;
                    assert_eq!(display.pixfmt(), Pixfmt::BGRA);
                    let root = display.root();
                    finish_case(0);
                    draw_red(&server, root, 0x00ff0000)?;
                    let segment = if public {
                        let display = common::Display::primary()?;
                        finish_case(0);
                        let mut capture = common::Capturer::new(display)?;
                        let id = exercise_capture_rejection(&server, root, || {
                            let Frame::PixelBuffer(buffer) = capture.frame(
                                std::time::Duration::from_millis(100))?;
                            Ok([buffer.data()[0], buffer.data()[1], buffer.data()[2]])
                        })?;
                        drop(capture);
                        id
                    } else {
                        let mut capture = x11::Capturer::new(display)?;
                        let id = exercise_capture_rejection(&server, root, || {
                            let bytes = capture.frame()?;
                            Ok([bytes[0], bytes[1], bytes[2]])
                        })?;
                        drop(capture);
                        id
                    };
                    let absent = probe_segment(segment).expect_err("dropped capture segment is still live");
                    assert!(matches!(absent.raw_os_error(), Some(22) | Some(43)),
                            "unexpected exact-segment retirement error: {}", absent);
                    finish_case(0);
                }
            }
            println!("X11_CAPTURE_REJECTION_NATIVE=pass server_error=BadDrawable repeats=16 callers=direct,public requests=4 replies=3 errors=1 comparison_on_error=none same_capture=recovered pixels=red,blue segment=retired");
        } else if scenario == "capture-24" || scenario == "capture-16" {
            use crate::{TraitPixelBuffer, common::TraitCapturer};
            x11::reject_unsupported_layouts();
            let depth = if scenario == "capture-16" { 16 } else { 24 };
            let display = x11::Server::displays(Rc::clone(&server))
                .next().expect("first X screen")?;
            let expected = if depth == 16 { Pixfmt::RGB565LE } else { Pixfmt::BGRA };
            assert_eq!(display.depth(), depth);
            assert_eq!(display.pixfmt(), expected);
            let stride = display.row_stride()?;
            let width = display.w();
            let height = display.h();
            let root = display.root();
            finish_case(0);
            draw_red(&server, root, if depth == 16 { 0xf800 } else { 0x00ff0000 })?;
            let mut capture = x11::Capturer::new(display)?;
            assert_eq!(capture.row_stride()?, stride);
            let data = capture.frame()?;
            assert_eq!(data.len(), stride * height);
            if depth == 16 {
                assert_eq!(width, 641);
                assert_eq!(stride, 1284, "16bpp odd-width row must be padded to 32 bits");
                assert_eq!(&data[..2], &[0x00, 0xf8], "red pixel bytes differ");
            } else {
                assert_eq!(width, 640);
                assert_eq!(stride, 2560);
                assert_eq!(&data[..3], &[0x00, 0x00, 0xff], "red pixel bytes differ");
            }
            drop(capture);
            let public = common::Display::primary()?;
            let mut public_capture = common::Capturer::new(public)?;
            let frame = public_capture.frame(std::time::Duration::from_millis(100))?;
            let Frame::PixelBuffer(buffer) = frame;
            assert_eq!(buffer.pixfmt(), expected);
            assert_eq!(buffer.stride(), vec![stride]);
            assert_eq!(buffer.data().len(), stride * height);
            finish_case(0);
            println!("X11_LAYOUT_NATIVE=pass depth={depth} width={width} height={height} stride={stride} pixel=red capture=production-shm public=production-buffer");
        } else if let Some((atom, monitor)) = fault {
            for _ in 0..32 {
                configure_bounds(atom, monitor, 1);
                let mut iter = x11::Server::displays(Rc::clone(&server));
                let error = iter.next().expect("explicit malformed reply result").expect_err("malformed reply accepted");
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert!(iter.next().is_none() && iter.next().is_none());
                drop(iter);
                finish_case(0);
            }
            configure_bounds(atom, monitor, 2);
            assert!(common::Display::all().is_err(), "second-root malformed reply became partial success");
            finish_case(0);
            configure_bounds(atom, monitor, 1);
            assert!(common::Display::primary().is_err(), "primary hid malformed reply");
            finish_case(0);
            println!("X11_BOUNDS_CASE=pass scenario={scenario} repeats=32 replies=exact enumeration=fused public_callers=explicit");
        } else if scenario == "bounds-valid" {
            configure_bounds(0, 6, 1);
            let displays = x11::Server::displays(Rc::clone(&server)).collect::<io::Result<Vec<_>>>()?;
            assert_eq!(displays.len(), 2, "the valid outputless reply lost a display");
            STATE.with(|state| assert_eq!(state.borrow().queries, 2));
            finish_case(0);
            println!("X11_BOUNDS_VALID=pass outputless=received-header-injected screens=server-real replies=exact");
        } else if scenario == "atom-name" {
            for _ in 0..32 {
                assert_eq!(x11::query_atom_name(server.raw(), 0)?, "");
                STATE.with(|state| assert_eq!(state.borrow().atom_queries, 0,
                                              "unnamed monitor queried the invalid atom0"));
                finish_case(0);
            }
            for (bytes, expected) in [
                (&b"monitor\0name"[..], "monitor"),
                (&b"monitor-\xc3\xa9"[..], "monitor-é"),
                (&b"monitor-\xff"[..], "monitor-\u{fffd}"),
            ].iter().copied() {
                let atom = intern_atom(server.raw(), bytes)?;
                assert_ne!(atom, 0, "server did not intern the actual byte string");
                for _ in 0..32 {
                    assert_eq!(x11::query_atom_name(server.raw(), atom)?, expected,
                               "atom name conversion changed its content");
                    STATE.with(|state| {
                        let state = state.borrow();
                        assert_eq!(state.atom_queries, 1);
                        assert_eq!(state.allocations.len(), 1);
                    });
                    finish_case(0);
                }
            }
            let atom = intern_atom(server.raw(), b"monitor-name")?;
            for _ in 0..32 {
                STATE.with(|state| state.borrow_mut().inject_atom_nul = true);
                let result = x11::query_atom_name(server.raw(), atom);
                if result.is_err() {
                    eprintln!("X11_ATOM_NAME_OLD_FAILURE=rejected-injected-length-delimited-name");
                }
                assert_eq!(result?, "monitor\0name", "received NUL byte was not preserved");
                finish_case(0);
            }
            println!("X11_ATOM_NAME_NATIVE=pass server=real unnamed=no-query server_nul=truncated received_nul=injected-preserved utf8=preserved non_utf8=lossy iterations=32 replies=exact edition=2018");
        } else if scenario == "atom-reject" {
            for _ in 0..32 {
                STATE.with(|state| state.borrow_mut().reject_atom_query = 1);
                let mut iter = x11::Server::displays(Rc::clone(&server));
                let result = iter.next().expect("explicit atom result");
                if result.is_ok() {
                    let leaked = STATE.with(|state| state.borrow().allocations.iter()
                        .filter(|entry| !entry.monitor && !entry.retired).count());
                    eprintln!("X11_ATOM_OLD_FAILURE=accepted-query-rejection leaked_errors={leaked}");
                    return Err(io::Error::new(io::ErrorKind::Other, "BadAtom became a successful Display"));
                }
                assert!(iter.next().is_none() && iter.next().is_none());
                STATE.with(|state| assert!(state.borrow().allocations.iter().all(|e| e.retired),
                                          "atom failure did not retire every reply/error"));
                drop(iter);
                finish_case(0);
            }
            STATE.with(|state| state.borrow_mut().reject_atom_query = 2);
            assert!(common::Display::all().is_err(), "second-root BadAtom became partial success");
            finish_case(0);
            STATE.with(|state| state.borrow_mut().reject_atom_query = 1);
            assert!(common::Display::primary().is_err(), "primary hid BadAtom");
            finish_case(0);
            println!("X11_ATOM_NATIVE=pass server_error=BadAtom iterations=32 replies=exact errors=exact enumeration=fused public_callers=explicit");
        } else if scenario == "reject" {
            let mut iter = x11::Server::displays(server);
            assert!(iter.next().expect("explicit query result").is_err());
            assert!(iter.next().is_none() && iter.next().is_none());
            finish_case(2);
            assert!(common::Display::all().is_err(), "partial enumeration hid a second-screen error");
            finish_case(1);
            assert!(common::Display::primary().is_err(), "primary hid a query error");
            finish_case(0);
        } else {
            drop(x11::Server::displays(Rc::clone(&server)));
            STATE.with(|s| assert_eq!(s.borrow().queries, 0, "unconsumed iterator performed a query"));
            let mut iter = x11::Server::displays(Rc::clone(&server));
            let display = iter.next().expect("first monitor")?;
            assert_eq!((display.w(), display.h()), (640, 480));
            assert!(!display.name().is_empty());
            STATE.with(|s| assert_eq!(s.borrow().allocations.iter().filter(|e| e.monitor).count(), 1));
            drop(iter);
            finish_case(0);
            // The copied Display and its retained server outlive the monitor reply.
            assert_eq!(display.rect().w, 640);
            for _ in 0..32 {
                let displays = x11::Server::displays(Rc::clone(&server)).collect::<io::Result<Vec<_>>>()?;
                assert_eq!(displays.len(), 2);
                assert_eq!((displays[1].w(), displays[1].h()), (800, 600));
                assert_ne!(displays[0].root(), displays[1].root());
                STATE.with(|s| assert_eq!(s.borrow().allocations.iter().filter(|e| e.monitor).count(), 2));
                finish_case(0);
            }
            assert_eq!(common::Display::all()?.len(), 2);
            finish_case(0);
            let primary = common::Display::primary()?;
            assert!(primary.width() > 0 && primary.height() > 0);
            finish_case(0);
        }
        println!("X11_DISPLAY_COMPONENT=pass scenario={scenario} replies=exact errors=explicit cleanup=joined");
        Ok(())
    }
}
