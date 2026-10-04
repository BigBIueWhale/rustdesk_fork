//! Native component fixture: production enumeration and public callers, real XCB.
//! Capture is not exercised; its unrelated interface is a compile-only stand-in.
#![allow(dead_code)]

extern crate self as hbb_common;

use std::{cell::RefCell, io, ptr, rc::Rc};

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
        extern "C" {
            pub fn xcb_randr_get_monitors_unchecked(
                c: *mut xcb_connection_t,
                window: xcb_window_t,
                active: u8,
            ) -> xcb_randr_get_monitors_cookie_t;
        }
    }
    mod display;
    mod iter;
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
            if let Some(entry) = state.allocations.iter_mut().find(|e| e.pointer == pointer) {
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
    });
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
        if scenario == "reject" {
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
            STATE.with(|s| assert_eq!(s.borrow().allocations.iter().filter(|e| e.monitor && !e.retired).count(), 1));
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
