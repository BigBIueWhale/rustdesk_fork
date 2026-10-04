//! Native component fixture: production enumeration and public callers, real XCB.
//! Capture is not exercised; its unrelated interface is a compile-only stand-in.
#![allow(dead_code)]

extern crate self as hbb_common;

use std::{cell::RefCell, io};
#[cfg(corrected)]
use std::rc::Rc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pixfmt {
    BGRA,
    RGB565LE,
}

mod x11 {
    #[path = "ffi.rs"]
    pub mod production_ffi;
    pub mod ffi {
        pub use super::production_ffi::*;
        #[repr(C)]
        pub struct xcb_randr_monitor_info_iterator_t {
            pub data: *mut xcb_randr_monitor_info_t,
            pub rem: i32,
            pub index: i32,
        }
        extern "C" {
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
    }
    mod server;
    pub use display::*;
    pub use iter::*;
    pub use server::*;

    pub struct Capturer;
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
}
thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

pub mod libc {
    pub use std::ffi::c_void;
    extern "C" {
        #[link_name = "free"]
        pub fn system_free(pointer: *mut c_void);
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

extern "C" {
    fn xcb_intern_atom(c: *mut xcb_connection_t, only_if_exists: u8,
                       name_len: u16, name: *const u8) -> InternAtomCookie;
    fn xcb_intern_atom_reply(c: *mut xcb_connection_t, cookie: InternAtomCookie,
                             error: *mut *mut xcb_generic_error_t) -> *mut InternAtomReply;
    fn xcb_randr_set_monitor_checked(c: *mut xcb_connection_t, root: u32,
                                    info: *mut xcb_randr_monitor_info_t) -> xcb_void_cookie_t;
    fn xcb_randr_delete_monitor_checked(c: *mut xcb_connection_t, root: u32,
                                       name: u32) -> xcb_void_cookie_t;
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
                    _ => unreachable!("unknown monitor fault"),
                }
                state.bad_monitor_reply = reply as usize;
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
fn checked_fixture_request(c: *mut xcb_connection_t, cookie: xcb_void_cookie_t) -> io::Result<()> {
    unsafe {
        let error = xcb_request_check(c, cookie);
        if error.is_null() { return Ok(()); }
        let code = (*error).error_code;
        libc::system_free(error.cast());
        Err(io::Error::new(io::ErrorKind::Other, format!("fixture request server error {code}")))
    }
}

fn main() -> io::Result<()> {
    let scenario = std::env::args().nth(1).expect("scenario");
    finish_case(if scenario == "reject" { 1 } else { 0 });
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
        if let Some((atom, monitor)) = fault {
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
            let root = unsafe { (*xcb_setup_roots_iterator(server.setup()).data).root };
            let atom = intern_atom(server.raw(), b"bounds-native")?;
            let mut info = xcb_randr_monitor_info_t {
                name: atom, primary: 0, automatic: 0, n_output: 0,
                x: 0, y: 0, width: 320, height: 480, width_mm: 100, height_mm: 100,
            };
            checked_fixture_request(server.raw(), unsafe { xcb_randr_set_monitor_checked(server.raw(), root, &mut info) })?;
            let displays = x11::Server::displays(Rc::clone(&server)).collect::<io::Result<Vec<_>>>();
            // Retire the actual server-side fixture even if enumeration returned an error.
            checked_fixture_request(server.raw(), unsafe { xcb_randr_delete_monitor_checked(server.raw(), root, atom) })?;
            let displays = displays?;
            assert_eq!(displays.len(), 3, "real outputless monitor did not join the default screens");
            assert!(displays.iter().any(|d| d.name() == "bounds-native" && d.w() == 320 && d.h() == 480));
            finish_case(0);
            println!("X11_BOUNDS_VALID=pass multiple_monitors=server-real outputless=server-real replies=exact");
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
