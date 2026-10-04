use std::convert::TryFrom;
use std::io;
use std::mem::size_of;
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
    reply: XcbReply<xcb_randr_get_monitors_reply_t>,
    next_offset: usize,
    remaining: usize,
    root: xcb_window_t,
    format: RootFormat,
}

#[derive(Clone, Copy)]
struct RootFormat {
    pixfmt: Pixfmt,
    scanline_pad: u8,
    depth: u8,
    visual: xcb_visualid_t,
}

impl ScreenMonitors {
    fn new(
        reply: XcbReply<xcb_randr_get_monitors_reply_t>,
        root: xcb_window_t,
        format: RootFormat,
    ) -> io::Result<Self> {
        let header = unsafe { reply.0.as_ref() };
        let payload_len = usize::try_from(header.length)
            .ok()
            .and_then(|length| length.checked_mul(4))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid RandR reply length"))?;
        let monitor_count = usize::try_from(header.n_monitors)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid RandR monitor count"))?;
        let output_count = usize::try_from(header.n_outputs)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid RandR output count"))?;
        let expected = monitor_count
            .checked_mul(size_of::<xcb_randr_monitor_info_t>())
            .and_then(|bytes| {
                output_count
                    .checked_mul(size_of::<u32>())
                    .and_then(|outputs| bytes.checked_add(outputs))
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RandR counts overflow"))?;
        if expected != payload_len {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "RandR counts differ from reply length"));
        }

        let payload = unsafe { reply.0.as_ptr().add(1).cast::<u8>() };
        let mut offset = 0usize;
        let mut outputs_seen = 0usize;
        for _ in 0..monitor_count {
            let header_end = offset
                .checked_add(size_of::<xcb_randr_monitor_info_t>())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RandR monitor offset overflow"))?;
            if header_end > payload_len {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "RandR monitor exceeds reply"));
            }
            let monitor = unsafe { ptr::read_unaligned(payload.add(offset).cast::<xcb_randr_monitor_info_t>()) };
            let output_len = usize::from(monitor.n_output) * size_of::<u32>();
            offset = header_end
                .checked_add(output_len)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RandR output offset overflow"))?;
            if offset > payload_len {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "RandR outputs exceed reply"));
            }
            outputs_seen = outputs_seen
                .checked_add(usize::from(monitor.n_output))
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RandR output count overflow"))?;
        }
        if offset != payload_len || outputs_seen != output_count {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "RandR monitor layout differs from reply"));
        }

        Ok(Self { reply, next_offset: 0, remaining: monitor_count, root, format })
    }

    fn next_monitor(&mut self) -> Option<xcb_randr_monitor_info_t> {
        if self.remaining == 0 {
            return None;
        }
        // The complete immutable reply layout was checked before this cursor was created.
        let payload = unsafe { self.reply.0.as_ptr().add(1).cast::<u8>() };
        let monitor = unsafe {
            ptr::read_unaligned(payload.add(self.next_offset).cast::<xcb_randr_monitor_info_t>())
        };
        self.next_offset += size_of::<xcb_randr_monitor_info_t>()
            + usize::from(monitor.n_output) * size_of::<u32>();
        self.remaining -= 1;
        Some(monitor)
    }
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
            if outer.data.is_null() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "X screen is missing"));
            }
            let root = (*outer.data).root;
            let format = root_format(server.setup(), outer.data)?;

            let cookie = xcb_randr_get_monitors(server.raw(), root, 1);
            let mut error = ptr::null_mut();
            let response = xcb_randr_get_monitors_reply(server.raw(), cookie, &mut error);
            let reply = checked_reply(response, error, "RandR GetMonitors")?;
            let monitors = ScreenMonitors::new(reply, root, format)?;
            xcb_screen_next(outer);
            Ok(Some(monitors))
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
                // If there is something in the current screen, return that.
                if let Some(data) = screen.next_monitor() {
                    unsafe {
                        let name = match get_atom_name(self.server.raw(), data.name) {
                            Ok(name) => name,
                            Err(error) => {
                                self.failed = true;
                                self.inner = None;
                                return Some(Err(error));
                            }
                        };
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
                            screen.format.pixfmt,
                            screen.format.scanline_pad,
                            screen.format.depth,
                            screen.format.visual,
                        );
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
        let header = reply.0.as_ref();
        let payload_len = usize::try_from(header.length)
            .ok()
            .and_then(|length| length.checked_mul(4))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid X atom reply length"))?;
        let name_len = usize::from(header.name_len);
        let padded_name_len = name_len
            .checked_add(3)
            .map(|length| length & !3)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "X atom name length overflow"))?;
        if payload_len != padded_name_len {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "X atom name length differs from reply"));
        }
        let bytes = std::slice::from_raw_parts(reply.0.as_ptr().add(1).cast::<u8>(), name_len);
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }
}

fn classify_format(
    order: u8,
    depth: u8,
    bits_per_pixel: u8,
    red: u32,
    green: u32,
    blue: u32,
) -> Option<Pixfmt> {
    match (order, depth, bits_per_pixel, red, green, blue) {
        (XCB_IMAGE_ORDER_LSB_FIRST, 16, 16, 0xf800, 0x07e0, 0x001f) =>
            Some(Pixfmt::RGB565LE),
        (XCB_IMAGE_ORDER_LSB_FIRST, 24 | 32, 32, 0x00ff0000, 0x0000ff00, 0x000000ff) =>
            Some(Pixfmt::BGRA),
        (XCB_IMAGE_ORDER_LSB_FIRST, 24 | 32, 32, 0x000000ff, 0x0000ff00, 0x00ff0000) =>
            Some(Pixfmt::RGBA),
        (XCB_IMAGE_ORDER_MSB_FIRST, 32, 32, 0x0000ff00, 0x00ff0000, 0xff000000) =>
            Some(Pixfmt::BGRA),
        (XCB_IMAGE_ORDER_MSB_FIRST, 32, 32, 0xff000000, 0x00ff0000, 0x0000ff00) =>
            Some(Pixfmt::RGBA),
        _ => None,
    }
}

unsafe fn root_format(setup: *const xcb_setup_t, screen: *const xcb_screen_t) -> io::Result<RootFormat> {
    if setup.is_null() || screen.is_null() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "X setup is missing"));
    }
    let screen = &*screen;
    let mut selected = None;
    let mut formats = xcb_setup_pixmap_formats_iterator(setup);
    while formats.rem > 0 {
        if formats.data.is_null() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "X pixmap format is missing"));
        }
        let format = &*formats.data;
        if format.depth == screen.root_depth {
            if selected.replace((format.bits_per_pixel, format.scanline_pad)).is_some() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "duplicate X root pixmap format"));
            }
        }
        xcb_format_next(&mut formats);
    }
    let (bits_per_pixel, scanline_pad) = selected
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "X root pixmap format is missing"))?;
    if !matches!(scanline_pad, 8 | 16 | 32) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid X scanline padding"));
    }

    let mut visual = None;
    let mut depths = xcb_screen_allowed_depths_iterator(screen);
    while depths.rem > 0 {
        if depths.data.is_null() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "X depth is missing"));
        }
        let depth = &*depths.data;
        if depth.depth == screen.root_depth {
            let mut visuals = xcb_depth_visuals_iterator(depth);
            while visuals.rem > 0 {
                if visuals.data.is_null() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "X visual is missing"));
                }
                let candidate = &*visuals.data;
                if candidate.visual_id == screen.root_visual {
                    if visual.replace((candidate.class, candidate.red_mask, candidate.green_mask, candidate.blue_mask)).is_some() {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "duplicate X root visual"));
                    }
                }
                xcb_visualtype_next(&mut visuals);
            }
        }
        xcb_depth_next(&mut depths);
    }
    let (class, red, green, blue) = visual
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "X root visual is missing"))?;
    if class != XCB_VISUAL_CLASS_TRUE_COLOR {
        return Err(io::Error::new(io::ErrorKind::Unsupported, "X root visual is not TrueColor"));
    }
    let pixfmt = classify_format((*setup).image_byte_order, screen.root_depth, bits_per_pixel, red, green, blue)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "unsupported X root pixel layout"))?;
    Ok(RootFormat { pixfmt, scanline_pad, depth: screen.root_depth, visual: screen.root_visual })
}
