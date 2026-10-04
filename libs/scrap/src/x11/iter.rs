use std::convert::TryFrom;
use std::io;
use std::ptr;
use std::ptr::NonNull;
use std::rc::Rc;

use crate::Pixfmt;
use hbb_common::libc;

use super::ffi::*;
use super::{Display, Rect, Server};

pub struct DisplayIter {
    outer: xcb_screen_iterator_t,
    inner: Option<ScreenMonitors>,
    server: Rc<Server>,
    failed: bool,
}

struct ScreenMonitors {
    _reply: XcbReply<xcb_randr_get_monitors_reply_t>,
    cursor: xcb_randr_monitor_info_iterator_t,
    root: xcb_window_t,
}

struct XcbReply<T>(NonNull<T>);

impl<T> Drop for XcbReply<T> {
    fn drop(&mut self) {
        unsafe { libc::free(self.0.as_ptr().cast()) };
    }
}

unsafe fn checked_reply<T>(
    response: *mut T,
    error: *mut xcb_generic_error_t,
    operation: &str,
) -> io::Result<XcbReply<T>> {
    let reply = NonNull::new(response).map(XcbReply);
    if let Some(error) = NonNull::new(error).map(XcbReply) {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "X server rejected {operation} with error {}",
                (*error.0.as_ptr()).error_code
            ),
        ));
    }
    reply.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::ConnectionAborted,
            format!("X server returned no {operation} reply"),
        )
    })
}

impl DisplayIter {
    pub unsafe fn new(server: Rc<Server>) -> DisplayIter {
        DisplayIter {
            outer: xcb_setup_roots_iterator(server.setup()),
            inner: None,
            server,
            failed: false,
        }
    }

    fn next_screen(
        outer: &mut xcb_screen_iterator_t,
        server: &Server,
    ) -> io::Result<Option<ScreenMonitors>> {
        if outer.rem == 0 {
            return Ok(None);
        }

        unsafe {
            let root = (*outer.data).root;

            let cookie = xcb_randr_get_monitors(server.raw(), root, 1);
            let mut error = ptr::null_mut();
            let response = xcb_randr_get_monitors_reply(server.raw(), cookie, &mut error);
            let reply = checked_reply(response, error, "RandR GetMonitors")?;
            let cursor = xcb_randr_get_monitors_monitors_iterator(reply.0.as_ptr());
            xcb_screen_next(outer);
            Ok(Some(ScreenMonitors {
                _reply: reply,
                cursor,
                root,
            }))
        }
    }
}

impl Iterator for DisplayIter {
    type Item = io::Result<Display>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        loop {
            if let Some(ref mut screen) = self.inner {
                let inner = &mut screen.cursor;
                // If there is something in the current screen, return that.
                if inner.rem != 0 {
                    unsafe {
                        let data = &*inner.data;
                        let name = match get_atom_name(self.server.raw(), data.name) {
                            Ok(name) => name,
                            Err(error) => {
                                self.failed = true;
                                self.inner = None;
                                return Some(Err(error));
                            }
                        };
                        let pixfmt =
                            get_pixfmt(self.server.raw(), screen.root).unwrap_or(Pixfmt::BGRA);
                        let display = Display::new(
                            self.server.clone(),
                            data.primary != 0,
                            Rect {
                                x: data.x,
                                y: data.y,
                                w: data.width,
                                h: data.height,
                            },
                            screen.root,
                            name,
                            pixfmt,
                        );

                        xcb_randr_monitor_info_next(inner);
                        return Some(Ok(display));
                    }
                }
            }

            // Retire the current reply before acquiring the next screen's reply.
            self.inner = None;
            match Self::next_screen(&mut self.outer, &self.server) {
                Ok(Some(screen)) => self.inner = Some(screen),
                Ok(None) => return None,
                Err(error) => {
                    self.failed = true;
                    return Some(Err(error));
                }
            }
        }
    }
}

impl std::iter::FusedIterator for DisplayIter {}

fn get_atom_name(conn: *mut xcb_connection_t, atom: xcb_atom_t) -> io::Result<String> {
    if atom == 0 {
        return Ok(String::new());
    }
    unsafe {
        let mut error = ptr::null_mut();
        let response = xcb_get_atom_name_reply(conn, xcb_get_atom_name(conn, atom), &mut error);
        let reply = checked_reply(response.cast_mut(), error, "GetAtomName")?;
        let length = usize::try_from(xcb_get_atom_name_name_length(reply.0.as_ptr())).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "X atom name has a negative length")
        })?;
        let bytes = std::slice::from_raw_parts(xcb_get_atom_name_name(reply.0.as_ptr()), length);
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }
}

unsafe fn get_pixfmt(conn: *mut xcb_connection_t, root: xcb_window_t) -> Option<Pixfmt> {
    let geo_cookie = xcb_get_geometry_unchecked(conn, root);
    let geo = xcb_get_geometry_reply(conn, geo_cookie, ptr::null_mut());
    if geo.is_null() {
        return None;
    }
    let depth = (*geo).depth;
    libc::free(geo as _);
    // now only support little endian
    // https://github.com/FFmpeg/FFmpeg/blob/a9c05eb657d0d05f3ac79fe9973581a41b265a5e/libavdevice/xcbgrab.c#L519
    match depth {
        16 => Some(Pixfmt::RGB565LE),
        32 => Some(Pixfmt::BGRA),
        _ => None,
    }
}
