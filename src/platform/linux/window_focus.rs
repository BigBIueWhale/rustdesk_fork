use super::native_context::NativeContext;
use std::{ffi::{c_char, c_int, c_void, CString}, io, os::fd::BorrowedFd,
          ptr::{self, NonNull}, time::Duration};
#[path = "window_focus_deadline.rs"]
mod deadline;
use deadline::SocketDeadline;

const REPLY_BUDGET: Duration = Duration::from_millis(100);

#[derive(Debug)]
pub(super) enum FocusError {
    Connection(c_int),
    Deadline,
    Transport(io::Error),
    MissingReply,
    Protocol(u8),
    InvalidReply,
    InvalidDisplay,
    InvalidScreen,
}

#[derive(Default)]
pub(super) struct WindowFocus {
    connection: Option<FocusConnection>,
}

impl WindowFocus {
    pub(super) fn center(&mut self) -> Result<Option<(i32, i32)>, FocusError> {
        if self.connection.is_none() {
            self.connection = Some(FocusConnection::connect()?);
        }
        let result = match self.connection.as_ref() {
            Some(connection) => connection.center(),
            None => return Err(FocusError::InvalidReply),
        };
        if matches!(result, Err(FocusError::Connection(_) | FocusError::Deadline
                               | FocusError::Transport(_) | FocusError::MissingReply)) {
            // Retire pending requests with the connection. A retry cannot consume
            // a late reply or reuse a previous server's setup/window/atom state.
            self.connection = None;
        }
        result
    }
}

struct FocusConnection {
    // Join the deadline owner before disconnecting the native connection.
    deadline: SocketDeadline,
    connection: NativeContext<c_void>,
    root: u32,
}

impl FocusConnection {
    fn connect() -> Result<Self, FocusError> {
        let display = unix_display_name()?;
        unsafe {
            let mut screen = 0;
            let connection = NativeContext::from_raw(xcb_connect(display.as_ptr(), &mut screen),
                                                    |connection| xcb_disconnect(connection))
                .ok_or(FocusError::InvalidReply)?;
            let error = xcb_connection_has_error(connection.as_ptr());
            if error != 0 {
                return Err(FocusError::Connection(error));
            }
            let root = setup_root(xcb_get_setup(connection.as_ptr()), screen)?;
            let descriptor = xcb_get_file_descriptor(connection.as_ptr());
            if descriptor < 0 {
                return Err(FocusError::Transport(io::Error::new(io::ErrorKind::InvalidInput,
                    "X11 focus connection has no socket")));
            }
            let deadline = SocketDeadline::new(BorrowedFd::borrow_raw(descriptor))
                .map_err(FocusError::Transport)?;
            Ok(Self { deadline, connection, root })
        }
    }

    fn atom(&self, name: &[u8]) -> Result<Option<u32>, FocusError> {
        unsafe {
            let cookie = xcb_intern_atom(self.connection.as_ptr(), 1, name.len() as u16,
                                         name.as_ptr().cast());
            let reply = self.reply::<Atom>(cookie)?;
            let atom = reply.get();
            if atom.response_type != 1 || atom.length != 0 {
                return Err(FocusError::InvalidReply);
            }
            Ok((atom.atom != 0).then_some(atom.atom))
        }
    }

    fn property(&self, atom: u32, expected_type: u32, limit: u32)
        -> Result<Option<Reply<Property>>, FocusError>
    {
        unsafe {
            let cookie = xcb_get_property(self.connection.as_ptr(), 0, self.root, atom, 0, 0, limit);
            let reply = self.reply::<Property>(cookie)?;
            let property = reply.get();
            if property.response_type != 1 || property.bytes_after != 0 {
                return Err(FocusError::InvalidReply);
            }
            if property.type_ == 0 && property.format == 0 && property.value_len == 0 && property.length == 0 {
                return Ok(None);
            }
            if property.type_ != expected_type || property.format != 32
                || property.value_len > limit || property.length != property.value_len
            {
                return Err(FocusError::InvalidReply);
            }
            Ok(Some(reply))
        }
    }

    fn center(&self) -> Result<Option<(i32, i32)>, FocusError> {
        // One owned cancellation budget covers all established-connection I/O.
        // Native construction is separate; no worker is detached on expiration.
        let observation = self.deadline.start(REPLY_BUDGET)?;
        let result = self.query();
        observation.finish()?;
        result
    }

    fn query(&self) -> Result<Option<(i32, i32)>, FocusError> {
        let Some(active) = self.atom(b"_NET_ACTIVE_WINDOW")? else { return Ok(None); };
        let Some(supported) = self.atom(b"_NET_SUPPORTED")? else { return Ok(None); };
        let Some(supported) = self.property(supported, 4, 1024)? else { return Ok(None); };
        if !supported.values().contains(&active) {
            return Ok(None);
        }
        drop(supported);
        let Some(window) = self.property(active, 33, 1)? else { return Ok(None); };
        let Some(&window_id) = window.values().first() else { return Ok(None); };
        if window_id == 0 {
            return Ok(None);
        }
        drop(window);
        // Checked replies keep errors with their own request. A window may disappear
        // at either step; that is no result, not a change to another Xlib client's handler.
        unsafe {
            let cookie = xcb_get_geometry(self.connection.as_ptr(), window_id);
            let geometry = match self.reply::<Geometry>(cookie) {
                Err(FocusError::Protocol(3 | 9)) => return Ok(None), // BadWindow/BadDrawable
                result => result?,
            };
            let geometry = geometry.get();
            if geometry.response_type != 1 || geometry.length != 0 {
                return Err(FocusError::InvalidReply);
            }
            if geometry.root != self.root {
                return Ok(None);
            }
            let cookie = xcb_translate_coordinates(self.connection.as_ptr(), window_id, self.root, 0, 0);
            let coordinates = match self.reply::<Coordinates>(cookie) {
                Err(FocusError::Protocol(3)) => return Ok(None),
                result => result?,
            };
            let coordinates = coordinates.get();
            if coordinates.response_type != 1 || coordinates.length != 0 {
                return Err(FocusError::InvalidReply);
            }
            if coordinates.same_screen != 1 {
                return Ok(None);
            }
            Ok(Some((i32::from(coordinates.dst_x) + i32::from(geometry.width / 2),
                     i32::from(coordinates.dst_y) + i32::from(geometry.height / 2))))
        }
    }

    unsafe fn reply<T>(&self, cookie: Cookie) -> Result<Reply<T>, FocusError> {
        let connection = self.connection.as_ptr();
        let mut error = ptr::null_mut();
        let pointer = xcb_wait_for_reply(connection, cookie.sequence, &mut error);
        let reply = NonNull::new(pointer.cast::<T>()).map(Reply);
        let error = NonNull::new(error).map(Reply);
        let connection_error = xcb_connection_has_error(connection);
        if connection_error != 0 {
            return Err(FocusError::Connection(connection_error));
        }
        if let Some(error) = error {
            // xcb_generic_error_t's second byte is its protocol error code.
            return Err(FocusError::Protocol(error.0.as_ptr().cast::<u8>().add(1).read()));
        }
        reply.ok_or(FocusError::MissingReply)
    }
}

fn unix_display_name() -> Result<CString, FocusError> {
    fn number(field: &str) -> Result<c_int, FocusError> {
        if field.is_empty() || !field.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(FocusError::InvalidDisplay);
        }
        field.parse().map_err(|_| FocusError::InvalidDisplay)
    }
    let value = std::env::var("DISPLAY").map_err(|_| FocusError::InvalidDisplay)?;
    let value = value.strip_prefix(':').ok_or(FocusError::InvalidDisplay)?;
    let mut fields = value.split('.');
    let display = number(fields.next().ok_or(FocusError::InvalidDisplay)?)?;
    let screen = match (fields.next(), fields.next()) {
        (None, None) => 0,
        (Some(screen), None) => number(screen)?,
        _ => return Err(FocusError::InvalidDisplay),
    };
    // Explicit Unix transport prevents libxcb's implicit localhost TCP retry
    // after a missing/refused local socket. Native Xauthority handling is retained.
    CString::new(format!("unix/:{display}.{screen}"))
        .map_err(|_| FocusError::InvalidDisplay)
}

struct Reply<T>(NonNull<T>);
impl<T> Reply<T> {
    fn get(&self) -> &T { unsafe { self.0.as_ref() } }
}
impl Reply<Property> {
    fn values(&self) -> &[u32] {
        // Only exposed after property() validates the bounded 32-bit payload/header.
        unsafe { std::slice::from_raw_parts(self.0.as_ptr().add(1).cast(), self.get().value_len as usize) }
    }
}
impl<T> Drop for Reply<T> {
    fn drop(&mut self) { unsafe { free(self.0.as_ptr().cast()) }; }
}

unsafe fn setup_root(setup: *const c_void, selected: c_int) -> Result<u32, FocusError> {
    if setup.is_null() || selected < 0 {
        return Err(FocusError::InvalidScreen);
    }
    // As in capture's setup reader, check the native eight-byte response prefix
    // before touching the success header or walking variable-sized screen records.
    let prefix = std::slice::from_raw_parts(setup.cast::<u8>(), 8);
    let total = 8 + usize::from(u16::from_ne_bytes([prefix[6], prefix[7]])) * 4;
    if prefix[0] != 1 || total < 40 {
        return Err(FocusError::InvalidReply);
    }
    let mut reader = SetupReader { bytes: std::slice::from_raw_parts(setup.cast(), total), offset: 0 };
    let header = reader.take(40)?;
    let vendor = usize::from(u16::from_ne_bytes([header[24], header[25]]));
    let screens = header[28];
    let formats = header[29];
    if selected >= c_int::from(screens) {
        return Err(FocusError::InvalidScreen);
    }
    reader.take((vendor + 3) & !3)?;
    reader.take(usize::from(formats) * 8)?;
    let mut root = None;
    for index in 0..screens {
        let screen = reader.take(40)?;
        if c_int::from(index) == selected {
            root = Some(u32::from_ne_bytes([screen[0], screen[1], screen[2], screen[3]]));
        }
        let depths = screen[39];
        for _ in 0..depths {
            let depth = reader.take(8)?;
            let visuals = usize::from(u16::from_ne_bytes([depth[2], depth[3]]));
            reader.take(visuals * 24)?;
        }
    }
    if reader.offset != total {
        return Err(FocusError::InvalidReply);
    }
    root.filter(|root| *root != 0).ok_or(FocusError::InvalidScreen)
}

struct SetupReader<'a> { bytes: &'a [u8], offset: usize }
impl<'a> SetupReader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], FocusError> {
        let end = self.offset.checked_add(length).ok_or(FocusError::InvalidReply)?;
        let bytes = self.bytes.get(self.offset..end).ok_or(FocusError::InvalidReply)?;
        self.offset = end;
        Ok(bytes)
    }
}

// libxcb core protocol ABI; the native fixture checks sizes/offsets against xproto.h.
#[repr(C)]
struct Cookie { sequence: u32 }
#[repr(C)]
struct Atom { response_type: u8, pad: u8, sequence: u16, length: u32, atom: u32 }
#[repr(C)]
struct Property {
    response_type: u8, format: u8, sequence: u16, length: u32,
    type_: u32, bytes_after: u32, value_len: u32, pad: [u8; 12],
}
#[repr(C)]
struct Geometry {
    response_type: u8, depth: u8, sequence: u16, length: u32, root: u32,
    x: i16, y: i16, width: u16, height: u16, border: u16, pad: [u8; 2],
}
#[repr(C)]
struct Coordinates {
    response_type: u8, same_screen: u8, sequence: u16, length: u32,
    child: u32, dst_x: i16, dst_y: i16,
}
const _: [(); 12] = [(); std::mem::size_of::<Atom>()];
const _: [(); 32] = [(); std::mem::size_of::<Property>()];
const _: [(); 24] = [(); std::mem::size_of::<Geometry>()];
const _: [(); 16] = [(); std::mem::size_of::<Coordinates>()];
const _: [(); 4] = [(); std::mem::size_of::<Cookie>()];

#[link(name = "xcb")]
extern "C" {
    fn xcb_connect(name: *const c_char, screen: *mut c_int) -> *mut c_void;
    fn xcb_disconnect(connection: *mut c_void);
    fn xcb_connection_has_error(connection: *mut c_void) -> c_int;
    fn xcb_get_setup(connection: *mut c_void) -> *const c_void;
    fn xcb_intern_atom(connection: *mut c_void, exists: u8, length: u16, name: *const c_char) -> Cookie;
    fn xcb_get_property(connection: *mut c_void, delete: u8, window: u32, property: u32,
                        type_: u32, offset: u32, length: u32) -> Cookie;
    fn xcb_get_geometry(connection: *mut c_void, drawable: u32) -> Cookie;
    fn xcb_translate_coordinates(connection: *mut c_void, source: u32, target: u32, x: i16, y: i16) -> Cookie;
    fn xcb_get_file_descriptor(connection: *mut c_void) -> c_int;
    fn xcb_wait_for_reply(connection: *mut c_void, sequence: u32, error: *mut *mut c_void) -> *mut c_void;
    fn free(pointer: *mut c_void);
}
