use super::{native_context::NativeContext, x11_context};
use std::{cell::RefCell, ffi::{c_char, c_int, c_ulong, c_void}, io};

// X11/extensions/Xfixes.h, version 2+ native client ABI (not the wire reply).
#[repr(C)]
struct XFixesCursorImage {
    x: i16,
    y: i16,
    width: u16,
    height: u16,
    xhot: u16,
    yhot: u16,
    cursor_serial: c_ulong,
    pixels: *const c_ulong,
    atom: c_ulong,
    name: *const c_char,
}

#[link(name = "Xfixes")]
extern "C" {
    fn XFixesGetCursorImage(display: *mut c_void) -> *mut XFixesCursorImage;
}
#[link(name = "X11")]
extern "C" {
    fn XFree(data: *mut c_void) -> c_int;
}

struct OwnedImage {
    image: NativeContext<XFixesCursorImage>,
    rgba_len: usize,
}

thread_local! {
    // One polling worker owns at most one image until its data is consumed,
    // the next poll replaces it, or the thread exits.
    static SNAPSHOT: RefCell<Option<OwnedImage>> = RefCell::new(None);
}

pub(super) struct CursorSnapshot {
    pub id: u64,
    pub hotx: i32,
    pub hoty: i32,
    pub width: i32,
    pub height: i32,
    pub colors: Vec<u8>,
}

pub(super) fn discard() -> io::Result<()> {
    SNAPSHOT.with(|snapshot| {
        let mut snapshot = snapshot.try_borrow_mut()
            .map_err(|error| io::Error::new(io::ErrorKind::WouldBlock, error))?;
        *snapshot = None;
        Ok(())
    })
}

pub(super) fn capture_serial() -> io::Result<Option<u64>> {
    SNAPSHOT.with(|snapshot| {
        let mut snapshot = snapshot.try_borrow_mut()
            .map_err(|error| io::Error::new(io::ErrorKind::WouldBlock, error))?;
        *snapshot = None;
        let image = x11_context::with_display(|display| unsafe {
            NativeContext::from_raw(XFixesGetCursorImage(display.as_ptr()), |image| {
                XFree(image.cast());
            }).ok_or_else(|| io::Error::new(io::ErrorKind::Other, "XFixes cursor image unavailable"))
        })?.transpose()?;
        let Some(image) = image else { return Ok(None); };
        let native = unsafe { &*image.as_ptr() };
        let rgba_len = crate::platform::cursor_rgba_len(i32::from(native.width), i32::from(native.height))
            .filter(|_| native.xhot < native.width && native.yhot < native.height && !native.pixels.is_null())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid XFixes cursor image geometry"))?;
        let serial = native.cursor_serial as u64;
        *snapshot = Some(OwnedImage { image, rgba_len });
        Ok(Some(serial))
    })
}

pub(super) fn take_data(serial: u64) -> io::Result<CursorSnapshot> {
    let image = SNAPSHOT.with(|snapshot| {
        snapshot.try_borrow_mut()
            .map_err(|error| io::Error::new(io::ErrorKind::WouldBlock, error))?
            .take().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "cursor snapshot was not captured"))
    })?;
    let native = unsafe { &*image.image.as_ptr() };
    if serial != native.cursor_serial as u64 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "cursor snapshot serial differs"));
    }
    // The native library owns one allocation containing this header and all
    // width*height pixels. Geometry was checked before publishing its serial.
    let pixels = unsafe { std::slice::from_raw_parts(native.pixels, image.rgba_len / 4) };
    let mut colors = vec![0_u8; image.rgba_len];
    for (rgba, pixel) in colors.chunks_exact_mut(4).zip(pixels) {
        let alpha = (pixel >> 24) as u8;
        if alpha != 0 {
            rgba.copy_from_slice(&[(pixel >> 16) as u8, (pixel >> 8) as u8, *pixel as u8, alpha]);
        }
    }
    Ok(CursorSnapshot {
        id: serial,
        hotx: i32::from(native.xhot),
        hoty: i32::from(native.yhot),
        width: i32::from(native.width),
        height: i32::from(native.height),
        colors,
    })
}
