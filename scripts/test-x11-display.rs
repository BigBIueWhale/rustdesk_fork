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

#[path = "common/frame_compare.rs"]
mod frame_compare;

pub fn would_block_if_equal(old: &mut Vec<u8>, data: &[u8]) -> io::Result<()> {
    STATE.with(|state| state.borrow_mut().frame_comparisons += 1);
    frame_compare::would_block_if_equal(old, data)
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

#[cfg(corrected)]
#[repr(C)]
struct GetInputFocusCookie {
    sequence: u32,
}

#[cfg(corrected)]
#[repr(C)]
struct XcbExtension { name: *const i8, global_id: i32 }
#[cfg(corrected)]
#[repr(C)]
struct XcbProtocolRequest { count: usize, ext: *mut XcbExtension, opcode: u8, isvoid: u8 }
#[cfg(corrected)]
#[repr(C)]
#[derive(Clone, Copy)]
struct Iovec { base: *mut libc::c_void, len: usize }
#[cfg(corrected)]
#[repr(C)]
struct OversizedShmQuery { major: u8, minor: u8, length: u16, extra: u32 }

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

#[derive(Clone, Copy)]
enum CaptureReplyFault { Size, Depth, Visual, Missing }

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConstructionFault { ServerAttach, LocalAttach, RemovalPending }

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
    shm_queries: usize,
    reject_shm_query: usize,
    shm_replies: usize,
    shm_errors: usize,
    shm_error: Option<(u8, u8, u16, u32)>,
    capture_queries: usize,
    reject_capture_query: usize,
    capture_replies: usize,
    capture_errors: usize,
    capture_error: Option<(u8, u8, u16, u32)>,
    capture_reply_fault: Option<CaptureReplyFault>,
    fault_capture_reply: usize,
    capture_reply_injections: usize,
    capture_reply_original: Option<(u32, u8, xcb_visualid_t)>,
    attach_queries: usize,
    attach_checks: usize,
    attach_connection_errors: usize,
    last_attach_connection_error: i32,
    reject_attach_query: usize,
    attach_cookie: Option<(*mut xcb_connection_t, u32, bool)>,
    attach_errors: usize,
    attach_error: Option<(u8, u8, u16, u32)>,
    construction_fault: Option<ConstructionFault>,
    construction_segment: Option<i32>,
    construction_errno: Option<i32>,
    detach_queries: usize,
    detach_checks: usize,
    detach_errors: usize,
    detach_cookie: Option<(*mut xcb_connection_t, u32)>,
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
        #[link_name = "shmat"]
        fn system_shmat(id: c_int, addr: *const c_void, flags: c_int) -> *mut c_void;
        pub fn shmdt(addr: *const c_void) -> c_int;
        #[link_name = "shmctl"]
        fn system_shmctl(id: c_int, cmd: c_int, status: *mut c_void) -> c_int;
        fn __errno_location() -> *mut c_int;
    }
    pub unsafe fn shmget(key: c_int, size: usize, flags: c_int) -> c_int {
        let id = system_shmget(key, size, flags);
        if id >= 0 {
            super::STATE.with(|state| {
                let mut state = state.borrow_mut();
                state.segments.push(id);
                if state.construction_fault.is_some() {
                    assert!(state.construction_segment.replace(id).is_none());
                }
            });
        }
        id
    }
    fn take_construction_fault(id: c_int, fault: super::ConstructionFault) -> bool {
        super::STATE.with(|state| {
            let mut state = state.borrow_mut();
            if state.construction_segment == Some(id) && state.construction_fault == Some(fault) {
                state.construction_fault = None;
                true
            } else {
                false
            }
        })
    }
    fn record_kernel_refusal() {
        let errno = std::io::Error::last_os_error().raw_os_error();
        assert_eq!(errno, Some(22), "selected invalid syscall did not receive EINVAL");
        super::STATE.with(|state| {
            assert!(state.borrow_mut().construction_errno.replace(22).is_none());
        });
        // The observer must not alter the syscall error consumed by production.
        unsafe { *__errno_location() = 22; }
    }
    pub unsafe fn shmat(id: c_int, addr: *const c_void, flags: c_int) -> *mut c_void {
        let reject = take_construction_fault(id, super::ConstructionFault::LocalAttach);
        // Only the selected real segment's address changes. Without SHM_RND,
        // address 1 is unaligned; the kernel supplies the actual failure/errno.
        let result = system_shmat(id, if reject { 1usize as *const c_void } else { addr }, flags);
        if reject {
            assert_eq!(result as isize, -1, "unaligned local attachment succeeded");
            record_kernel_refusal();
        }
        result
    }
    pub unsafe fn shmctl(id: c_int, cmd: c_int, status: *mut c_void) -> c_int {
        let reject = cmd == IPC_RMID
            && take_construction_fault(id, super::ConstructionFault::RemovalPending);
        // Refuse one transition using an invalid ID, without removing the actual
        // segment. The owner's subsequent Drop must retire its real ID normally.
        let result = system_shmctl(if reject { -1 } else { id }, cmd, status);
        if reject {
            assert_eq!(result, -1, "invalid removal ID succeeded");
            record_kernel_refusal();
        }
        result
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
    #[cfg(corrected)]
    #[link_name = "__real_xcb_shm_query_version"]
    fn real_shm_query(c: *mut xcb_connection_t) -> xcb_shm_query_version_cookie_t;
    #[cfg(corrected)]
    #[link_name = "__real_xcb_shm_query_version_reply"]
    fn real_shm_reply(c: *mut xcb_connection_t, cookie: xcb_shm_query_version_cookie_t,
        error: *mut *mut xcb_generic_error_t) -> *const xcb_shm_query_version_reply_t;
    #[cfg(corrected)]
    static mut xcb_shm_id: XcbExtension;
    #[cfg(corrected)]
    fn xcb_send_request(c: *mut xcb_connection_t, flags: i32, vector: *mut Iovec,
        request: *const XcbProtocolRequest) -> u32;
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
    fn xcb_discard_reply(c: *mut xcb_connection_t, sequence: u32);
    #[cfg(corrected)]
    fn xcb_get_input_focus(c: *mut xcb_connection_t) -> GetInputFocusCookie;
    #[cfg(corrected)]
    fn xcb_get_input_focus_reply(c: *mut xcb_connection_t, cookie: GetInputFocusCookie,
        error: *mut *mut xcb_generic_error_t) -> *mut libc::c_void;
    #[cfg(corrected)]
    #[link_name = "__real_xcb_shm_attach_checked"]
    fn real_attach(c: *mut xcb_connection_t, shmseg: xcb_shm_seg_t,
        shmid: u32, read_only: u8) -> xcb_void_cookie_t;
    #[cfg(corrected)]
    #[link_name = "__real_xcb_shm_detach_checked"]
    fn real_detach(c: *mut xcb_connection_t, shmseg: xcb_shm_seg_t) -> xcb_void_cookie_t;
    #[cfg(corrected)]
    #[link_name = "__real_xcb_request_check"]
    fn real_request_check(c: *mut xcb_connection_t, cookie: xcb_void_cookie_t)
        -> *mut xcb_generic_error_t;
}

#[cfg(corrected)]
#[no_mangle]
unsafe extern "C" fn __wrap_xcb_shm_query_version(c: *mut xcb_connection_t)
    -> xcb_shm_query_version_cookie_t {
    let reject = STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.shm_queries += 1;
        state.shm_queries == state.reject_shm_query
    });
    if !reject { return real_shm_query(c); }
    // Real QueryVersion, with one extra word. Xvfb's request-size check emits
    // BadLength; the normal reply API must deliver its actual error allocation.
    let mut bytes = OversizedShmQuery { major: 0, minor: 0, length: 0, extra: 0 };
    let request = XcbProtocolRequest {
        count: 2, ext: std::ptr::addr_of_mut!(xcb_shm_id), opcode: 0, isvoid: 0,
    };
    let mut parts = [Iovec { base: std::ptr::null_mut(), len: 0 }; 4];
    // xcb_send_request requires two valid preceding iovecs for its own use.
    parts[2] = Iovec { base: (&mut bytes as *mut OversizedShmQuery).cast(),
                       len: std::mem::size_of::<OversizedShmQuery>() };
    let sequence = xcb_send_request(c, 1, parts.as_mut_ptr().add(2), &request);
    assert_ne!(sequence, 0, "malformed version query was not sent");
    xcb_shm_query_version_cookie_t { sequence }
}

#[cfg(corrected)]
#[no_mangle]
unsafe extern "C" fn __wrap_xcb_shm_query_version_reply(c: *mut xcb_connection_t,
    cookie: xcb_shm_query_version_cookie_t, error: *mut *mut xcb_generic_error_t)
    -> *const xcb_shm_query_version_reply_t {
    assert!(!error.is_null(), "availability probe omitted its error output");
    let reply = real_shm_reply(c, cookie, error);
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if !reply.is_null() {
            state.shm_replies += 1;
            state.allocations.push(Allocation { pointer: reply.cast_mut().cast(),
                bytes: 0, monitor: false, retired: false });
        }
        if !(*error).is_null() {
            assert!(reply.is_null(), "failed probe returned a reply");
            let actual = &**error;
            state.shm_errors += 1;
            state.shm_error = Some((actual.error_code, actual.major_code,
                                   actual.minor_code, actual.resource_id));
            state.allocations.push(Allocation { pointer: (*error).cast(),
                bytes: 36, monitor: false, retired: false });
        }
    });
    reply
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
    STATE.with(|state| {
        assert!(state.borrow_mut().attach_cookie.replace((c, cookie.sequence, reject)).is_none(),
                "previous capture attach was not checked");
    });
    cookie
}

#[cfg(corrected)]
#[no_mangle]
unsafe extern "C" fn __wrap_xcb_shm_detach_checked(c: *mut xcb_connection_t,
    shmseg: xcb_shm_seg_t) -> xcb_void_cookie_t {
    let cookie = real_detach(c, shmseg);
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.detach_queries += 1;
        assert!(state.detach_cookie.replace((c, cookie.sequence)).is_none(),
                "previous capture detach was not checked");
    });
    cookie
}

#[cfg(corrected)]
#[no_mangle]
unsafe extern "C" fn __wrap_xcb_request_check(c: *mut xcb_connection_t,
    cookie: xcb_void_cookie_t) -> *mut xcb_generic_error_t {
    let error = real_request_check(c, cookie);
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if state.detach_cookie == Some((c, cookie.sequence)) {
            state.detach_cookie = None;
            state.detach_checks += 1;
            if !error.is_null() || xcb_connection_has_error(c) != 0 {
                state.detach_errors += 1;
            }
        }
        if let Some((connection, sequence, reject)) = state.attach_cookie {
            if (connection, sequence) == (c, cookie.sequence) {
                state.attach_cookie = None;
                state.attach_checks += 1;
                state.last_attach_connection_error = xcb_connection_has_error(c);
                if state.last_attach_connection_error != 0 { state.attach_connection_errors += 1; }
                if reject {
                    assert!(!error.is_null(), "invalid attach ID did not receive a server error");
                    let actual = &*error;
                    state.attach_errors += 1;
                    state.attach_error = Some((actual.error_code, actual.major_code,
                                              actual.minor_code, actual.resource_id));
                    state.allocations.push(Allocation { pointer: error.cast(),
                        bytes: 36, monitor: false, retired: false });
                } else {
                    assert!(error.is_null(), "unmodified attach received a protocol error");
                }
            }
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
    let discard = STATE.with(|state| {
        let state = state.borrow();
        matches!(state.capture_reply_fault, Some(CaptureReplyFault::Missing))
            && state.capture_queries == state.fault_capture_reply
    });
    if discard {
        assert_ne!(cookie.sequence, 0, "cannot discard a failed request");
        assert_eq!(xcb_connection_has_error(c), 0, "discard used a failed connection");
        // Exercise XCB's own missing-reply result, not a fabricated null return.
        // Request arguments and server-written shared pixels remain unchanged.
        xcb_discard_reply(c, cookie.sequence);
        // Discard is nonblocking. A later real reply must advance XCB's completed
        // sequence before waiting for the discarded cookie can return no reply.
        let completion = xcb_get_input_focus(c);
        assert!(completion.sequence != 0 && completion.sequence != cookie.sequence,
                "discard completion request did not receive a distinct cookie");
        let mut completion_error = std::ptr::null_mut();
        let completion_reply = xcb_get_input_focus_reply(c, completion, &mut completion_error);
        let completed = !completion_reply.is_null() && completion_error.is_null()
            && xcb_connection_has_error(c) == 0;
        libc::system_free(completion_reply);
        libc::system_free(completion_error.cast());
        assert!(completed, "real discard completion round trip failed");
        STATE.with(|state| state.borrow_mut().capture_reply_injections += 1);
    }
    let reply = real_capture_reply(c, cookie, error);
    if discard {
        assert!(reply.is_null() && (*error).is_null(), "discard did not remove the real reply");
        assert_eq!(xcb_connection_has_error(c), 0, "discard failed the X connection");
    }
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if !reply.is_null() {
            state.capture_replies += 1;
            state.allocations.push(Allocation { pointer: reply.cast(),
                bytes: 0, monitor: false, retired: false });
            if state.capture_queries == state.fault_capture_reply {
                let fault = state.capture_reply_fault.expect("capture reply fault absent");
                assert!((*error).is_null(), "valid capture received a protocol error");
                assert_eq!(xcb_connection_has_error(c), 0, "reply fault used a failed connection");
                assert!(state.capture_reply_original.replace(
                    ((*reply).size, (*reply).depth, (*reply).visual)).is_none());
                // Inject one field in the actual reply allocation. Request arguments,
                // server completion and captured shared-memory pixels remain real.
                match fault {
                    CaptureReplyFault::Size => (*reply).size = (*reply).size.checked_add(1)
                        .expect("real capture size cannot be incremented"),
                    CaptureReplyFault::Depth => (*reply).depth ^= 1,
                    CaptureReplyFault::Visual => (*reply).visual ^= 1,
                    CaptureReplyFault::Missing => unreachable!("discarded reply returned metadata"),
                }
                state.capture_reply_injections += 1;
            }
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
        state.shm_queries = 0;
        state.reject_shm_query = 0;
        state.shm_replies = 0;
        state.shm_errors = 0;
        state.shm_error = None;
        state.capture_queries = 0;
        state.reject_capture_query = 0;
        state.capture_replies = 0;
        state.capture_errors = 0;
        state.capture_error = None;
        state.capture_reply_fault = None;
        state.fault_capture_reply = 0;
        state.capture_reply_injections = 0;
        state.capture_reply_original = None;
        state.attach_queries = 0;
        state.attach_checks = 0;
        state.attach_connection_errors = 0;
        state.last_attach_connection_error = 0;
        state.reject_attach_query = 0;
        assert!(state.attach_cookie.is_none(), "capture attach was never checked");
        state.attach_errors = 0;
        state.attach_error = None;
        assert!(state.construction_fault.is_none(), "construction fault was not exercised");
        state.construction_segment = None;
        state.construction_errno = None;
        state.detach_queries = 0;
        state.detach_checks = 0;
        state.detach_errors = 0;
        assert!(state.detach_cookie.is_none(), "capture detach was never checked");
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
fn exercise_shm_probe(server: &Rc<x11::Server>,
    mut probe: impl FnMut() -> Result<(), x11::Error>) -> io::Result<()> {
    let display = x11::Server::displays(Rc::clone(server))
        .next().expect("first real X screen")?;
    let root = display.root();
    finish_case(0);
    draw_red(server, root, 0x00ff0000)?;
    let mut capture = x11::Capturer::new(display)?;
    assert_eq!(&capture.frame()?[..3], &[0x00, 0x00, 0xff]);
    probe().expect("real MIT-SHM extension available");
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!((state.shm_queries, state.shm_replies, state.shm_errors), (1, 1, 0));
        assert!(state.allocations.iter().all(|entry| entry.retired), "successful probe reply leaked");
    });
    STATE.with(|state| state.borrow_mut().reject_shm_query = 2);
    let result = probe();
    let leaked = STATE.with(|state| {
        let state = state.borrow();
        let (code, major, minor, _) = state.shm_error.expect("real probe error absent");
        assert_eq!((code, minor), (16, 0), "not a real QueryVersion BadLength response");
        assert!(major > 0);
        assert_eq!((state.shm_queries, state.shm_replies, state.shm_errors), (2, 1, 1));
        state.allocations.iter().filter(|entry| !entry.retired).count()
    });
    if leaked != 0 || !matches!(result, Err(x11::Error::Generic)) {
        eprintln!("X11_SHM_PROBE_OLD_FAILURE leaked_errors={leaked} result={result:?}");
        return Err(io::Error::new(io::ErrorKind::Other, "MIT-SHM probe error finality differs"));
    }
    probe().expect("same connection probe did not recover");
    draw_red(server, root, 0x000000ff)?;
    assert_eq!(&capture.frame()?[..3], &[0xff, 0x00, 0x00]);
    let segment = STATE.with(|state| {
        let state = state.borrow();
        assert_eq!((state.shm_queries, state.shm_replies, state.shm_errors), (3, 2, 1));
        assert_eq!((state.capture_queries, state.capture_replies, state.frame_comparisons), (2, 2, 2));
        assert!(state.allocations.iter().all(|entry| entry.retired), "probe/capture allocation leaked");
        assert_eq!(state.segments.len(), 1);
        state.segments[0]
    });
    drop(capture);
    let absent = probe_segment(segment).expect_err("capture segment survived probe/drop");
    assert!(matches!(absent.raw_os_error(), Some(22) | Some(43)), "retirement error: {}", absent);
    finish_case(0);
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
fn exercise_capture_reply_fault(
    server: &x11::Server, root: u32, fault: CaptureReplyFault,
    mut pixel: impl FnMut() -> io::Result<[u8; 3]>,
) -> io::Result<i32> {
    let segment = STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.segments.len(), 1, "capture did not own exactly one segment");
        state.segments[0]
    });
    probe_segment(segment)?;
    assert_eq!(pixel()?, [0x00, 0x00, 0xff], "initial real red pixel differs");
    draw_red(server, root, 0x000000ff)?;
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.capture_reply_fault = Some(fault);
        state.fault_capture_reply = 2;
    });
    let error = pixel().expect_err("invalid received reply returned a frame");
    let missing = matches!(fault, CaptureReplyFault::Missing);
    assert_eq!(error.kind(), if missing { io::ErrorKind::Other } else { io::ErrorKind::InvalidData },
               "failed received reply became unchanged-frame behavior");
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.capture_reply_original.is_none(), missing,
                   "received-metadata ownership differs from the selected fault");
        let expected = match fault {
            CaptureReplyFault::Size => {
                let (size, _, _) = state.capture_reply_original.expect("actual reply metadata absent");
                format!("X server MIT-SHM GetImage size {} does not match capture buffer size {}", size + 1, size)
            }
            CaptureReplyFault::Depth | CaptureReplyFault::Visual =>
                "X server MIT-SHM GetImage layout differs from root setup".to_owned(),
            CaptureReplyFault::Missing => "X server returned no MIT-SHM GetImage reply".to_owned(),
        };
        assert_eq!(error.to_string(), expected);
        assert_eq!(state.capture_reply_injections, 1);
        assert_eq!((state.capture_queries, state.capture_replies, state.capture_errors,
                    state.frame_comparisons), (2, if missing { 1 } else { 2 }, 0, 1));
        assert!(state.allocations.iter().all(|entry| entry.retired), "rejected reply leaked");
    });
    probe_segment(segment)?;
    // Blue was already written by the real server during the rejected request.
    // It must remain fresh relative to the last published red frame, rather than
    // being lost because rejection compared or committed those shared bytes.
    assert_eq!(pixel()?, [0xff, 0x00, 0x00], "valid blue frame did not recover");
    assert_eq!(pixel().expect_err("unchanged blue pixels unexpectedly changed").kind(),
               io::ErrorKind::WouldBlock);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!((state.capture_queries, state.capture_replies, state.capture_errors,
                    state.frame_comparisons, state.capture_reply_injections),
                   (4, if missing { 3 } else { 4 }, 0, 3, 1));
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
    // Enumerate while healthy so later failure reaches capture construction,
    // not a fresh connection or display lookup after the server has disappeared.
    let mut pending_displays = Vec::new();
    for _ in 0..3 {
        let direct = x11::Server::displays(Rc::clone(server))
            .next().expect("pending constructor X screen")?;
        let public = common::Display::primary()?;
        pending_displays.push((direct, public));
    }
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
    let probe_error = server.get_shm_status().expect_err("dead connection probe succeeded");
    assert!(matches!(probe_error, x11::Error::Generic), "dead connection became extension absence");
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!((state.shm_queries, state.shm_replies, state.shm_errors), (1, 0, 0));
        assert_eq!((state.capture_queries, state.capture_replies, state.capture_errors,
                    state.frame_comparisons), (8, 2, 0, 2));
        assert!(state.allocations.iter().all(|entry| entry.retired), "capture reply/error leaked");
    });
    let mut rejected = 0;
    let mut construction_errors = Vec::new();
    let mut check_constructor = |result: io::Result<()>| -> io::Result<()> {
        let error = result.expect_err("constructor accepted a dead X connection");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        rejected += 1;
        let (segment, actual_error) = STATE.with(|state| {
            let state = state.borrow();
            assert_eq!(state.segments.len(), 2 + rejected,
                       "failed constructor did not allocate exactly one local segment");
            assert_eq!((state.attach_queries, state.attach_checks, state.attach_connection_errors,
                        state.attach_errors), (2 + rejected, 2 + rejected, rejected, 0));
            assert!(state.attach_cookie.is_none(), "failed constructor did not check its attach");
            assert_eq!((state.detach_queries, state.detach_checks, state.detach_errors), (0, 0, 0),
                       "failed constructor attempted detach of an unaccepted XCB segment");
            assert_eq!((state.capture_queries, state.capture_replies, state.capture_errors,
                        state.frame_comparisons), (8, 2, 0, 2),
                       "failed constructor captured or compared pixels");
            assert!(state.allocations.iter().all(|entry| entry.retired), "constructor allocation leaked");
            assert!(state.last_attach_connection_error > 0, "constructor connection remained healthy");
            (state.segments[1 + rejected], state.last_attach_connection_error)
        });
        assert_eq!(error.to_string(),
                   format!("X connection failed during MIT-SHM attach: {actual_error}"));
        construction_errors.push(actual_error);
        let absent = probe_segment(segment).expect_err("dead-connection constructor leaked its segment");
        assert!(matches!(absent.raw_os_error(), Some(22) | Some(43)), "retirement error: {}", absent);
        for segment in segments { probe_segment(segment)?; }
        Ok(())
    };
    for (direct_display, public_display) in pending_displays {
        check_constructor(x11::Capturer::new(direct_display).map(drop))?;
        check_constructor(common::Capturer::new(public_display).map(drop))?;
    }
    assert_eq!(rejected, 6);
    assert!(construction_errors.iter().step_by(2).all(|&error| error == connection_error),
            "constructor on the retained direct connection reported a different status");
    let construction_errors = construction_errors.iter().map(i32::to_string)
        .collect::<Vec<_>>().join(",");
    drop(direct);
    let absent = probe_segment(segments[0]).expect_err("direct capture segment survived drop");
    assert!(matches!(absent.raw_os_error(), Some(22) | Some(43)), "retirement error: {}", absent);
    probe_segment(segments[1])?;
    drop(public);
    let absent = probe_segment(segments[1]).expect_err("public capture segment survived drop");
    assert!(matches!(absent.raw_os_error(), Some(22) | Some(43)), "retirement error: {}", absent);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!((state.detach_queries, state.detach_checks, state.detach_errors), (2, 2, 2));
    });
    finish_case(0);
    println!("X11_CAPTURE_CONNECTION_NATIVE=pass callers=direct,public repeats=3 connection_error={connection_error} requests=8 replies=2 errors=0 comparisons=2 segments=retired");
    println!("X11_SHM_STATUS_CONNECTION_NATIVE=pass connection_error={connection_error} queries=1 replies=0 protocol_errors=0 allocations=retired");
    println!("X11_CONSTRUCTOR_CONNECTION_NATIVE=pass callers=direct,public repeats=3 cases=6 connection_errors={construction_errors} attach_requests=8 attach_checks=8 connection_failures=6 rejected_segments=retired survivor_retirement=independent comparison_on_error=none");
    Ok(())
}

#[cfg(corrected)]
fn exercise_constructor_failure(server: &Rc<x11::Server>, fault: ConstructionFault,
    mut construct: impl FnMut() -> io::Result<()>) -> io::Result<u8> {
    let display = x11::Server::displays(Rc::clone(server))
        .next().expect("first real X screen")?;
    let root = display.root();
    finish_case(0);
    draw_red(server, root, 0x00ff0000)?;
    let mut survivor = x11::Capturer::new(display)?;
    assert_eq!(&survivor.frame()?[..3], &[0x00, 0x00, 0xff]);
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if fault == ConstructionFault::ServerAttach {
            state.reject_attach_query = 2;
        } else {
            state.construction_fault = Some(fault);
        }
    });
    let error = construct().expect_err("rejected constructor became success");
    let (segments, error_code) = STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.segments.len(), 2, "failed constructor did not create a local segment");
        let code = if fault == ConstructionFault::ServerAttach {
            assert_eq!(error.kind(), io::ErrorKind::Other);
            let (code, major, minor, _) = state.attach_error.expect("actual attach error absent");
            assert!(code > 0 && major > 0);
            assert_eq!(minor, 1, "not an actual MIT-SHM Attach rejection");
            assert_eq!(error.to_string(), format!("X server rejected MIT-SHM attach with error {code}"));
            code
        } else {
            assert!(state.construction_fault.is_none(), "fault did not run");
            assert_eq!(state.construction_segment, Some(state.segments[1]));
            assert_eq!(state.construction_errno, Some(22));
            let kernel_error = io::Error::from_raw_os_error(22);
            assert_eq!(error.kind(), kernel_error.kind());
            let expected = if fault == ConstructionFault::LocalAttach {
                kernel_error.to_string()
            } else {
                format!("failed to make X11 capture shared memory deletion-pending: {kernel_error}")
            };
            assert_eq!(error.to_string(), expected);
            0
        };
        let attach_count = if fault == ConstructionFault::LocalAttach { 1 } else { 2 };
        let protocol_errors = usize::from(fault == ConstructionFault::ServerAttach);
        assert_eq!((state.attach_queries, state.attach_errors, state.capture_queries,
                    state.capture_replies, state.frame_comparisons), (attach_count, protocol_errors, 1, 1, 1));
        let cleanup_detach = usize::from(fault == ConstructionFault::RemovalPending);
        assert_eq!((state.detach_queries, state.detach_checks, state.detach_errors),
                   (cleanup_detach, cleanup_detach, 0), "failed constructor's XCB detach differs");
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
        let attach_count = if fault == ConstructionFault::LocalAttach { 2 } else { 3 };
        let protocol_errors = usize::from(fault == ConstructionFault::ServerAttach);
        assert_eq!((state.attach_queries, state.attach_errors, state.capture_queries,
                    state.capture_replies, state.capture_errors, state.frame_comparisons),
                   (attach_count, protocol_errors, 3, 3, 0, 3));
        assert!(state.allocations.iter().all(|entry| entry.retired), "reply/error leaked after retry");
        state.segments[2]
    });
    let absent = probe_segment(retry_segment).expect_err("retry capture segment survived drop");
    assert!(matches!(absent.raw_os_error(), Some(22) | Some(43)), "retirement error: {}", absent);
    probe_segment(segments[0])?;
    drop(survivor);
    let absent = probe_segment(segments[0]).expect_err("surviving capture segment survived drop");
    assert!(matches!(absent.raw_os_error(), Some(22) | Some(43)), "retirement error: {}", absent);
    STATE.with(|state| {
        let state = state.borrow();
        let detaches = if fault == ConstructionFault::RemovalPending { 3 } else { 2 };
        assert_eq!((state.detach_queries, state.detach_checks, state.detach_errors),
                   (detaches, detaches, 0), "capture destruction did not finish exact XCB detach");
    });
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
        if scenario == "shm-status" {
            for public in [false, true] {
                for _ in 0..16 {
                    if public {
                        let display = common::Display::primary()?;
                        exercise_shm_probe(&server, || display.get_shm_status())?;
                    } else {
                        exercise_shm_probe(&server, || server.get_shm_status())?;
                    }
                }
            }
            println!("X11_SHM_STATUS_NATIVE=pass request_fault=oversized-query-version server_error=BadLength callers=direct,public repeats=16 cases=32 queries=3 replies=2 protocol_errors=1 recovery=same-connection capture=fresh allocations=retired segments=retired");
        } else if scenario == "capture-attach-reject" || scenario == "capture-construction-failure" {
            use crate::common::TraitCapturer;
            let mut error_code = None;
            let faults: &[ConstructionFault] = if scenario == "capture-attach-reject" {
                &[ConstructionFault::ServerAttach]
            } else {
                &[ConstructionFault::LocalAttach, ConstructionFault::RemovalPending]
            };
            for &fault in faults {
                for public in [false, true] {
                    for _ in 0..16 {
                        let code = exercise_constructor_failure(&server, fault, || {
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
            }
            if scenario == "capture-attach-reject" {
                println!("X11_CAPTURE_ATTACH_NATIVE=pass callers=direct,public repeats=16 server_error={} attach_requests=3 capture_requests=3 capture_replies=3 attach_errors=1 survivor=fresh retry=valid segments=retired", error_code.expect("attach error observed"));
            } else {
                println!("X11_CAPTURE_CONSTRUCTION_NATIVE=pass faults=local-attach,removal-pending cause=kernel-invalid-argument callers=direct,public repeats=16 cases=64 rejected_segments=retired xcb_detach=checked survivor=fresh retry=valid pixels=red,blue allocations=retired");
            }
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
        } else if scenario == "capture-reply-layout" || scenario == "capture-missing-reply" {
            use crate::common::TraitCapturer;
            let faults: &[CaptureReplyFault] = if scenario == "capture-missing-reply" {
                &[CaptureReplyFault::Missing]
            } else {
                &[CaptureReplyFault::Size, CaptureReplyFault::Depth, CaptureReplyFault::Visual]
            };
            for &fault in faults {
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
                            let id = exercise_capture_reply_fault(&server, root, fault, || {
                                let Frame::PixelBuffer(buffer) = capture.frame(
                                    std::time::Duration::from_millis(100))?;
                                Ok([buffer.data()[0], buffer.data()[1], buffer.data()[2]])
                            })?;
                            drop(capture);
                            id
                        } else {
                            let mut capture = x11::Capturer::new(display)?;
                            let id = exercise_capture_reply_fault(&server, root, fault, || {
                                let bytes = capture.frame()?;
                                Ok([bytes[0], bytes[1], bytes[2]])
                            })?;
                            drop(capture);
                            id
                        };
                        let absent = probe_segment(segment).expect_err("capture segment survived drop");
                        assert!(matches!(absent.raw_os_error(), Some(22) | Some(43)),
                                "unexpected exact-segment retirement error: {}", absent);
                        finish_case(0);
                    }
                }
            }
            if scenario == "capture-missing-reply" {
                println!("X11_CAPTURE_MISSING_NATIVE=pass cause=xcb-discard connection=healthy callers=direct,public repeats=16 cases=32 requests=4 replies=3 missing=1 completion=get-input-focus protocol_errors=0 comparison_on_rejection=none same_capture=recovered pixels=red,blue allocations=retired segments=retired");
            } else {
                println!("X11_CAPTURE_REPLY_NATIVE=pass received_header=injected fields=size,depth,visual callers=direct,public repeats=16 cases=96 requests=4 replies=4 protocol_errors=0 comparison_on_rejection=none same_capture=recovered pixels=red,blue allocations=retired segments=retired");
            }
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
