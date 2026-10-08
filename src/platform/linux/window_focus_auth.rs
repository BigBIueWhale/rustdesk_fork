use super::{FocusError, NativeContext};
use std::{ffi::{c_char, c_int}, io, time::{SystemTime, UNIX_EPOCH}};

const COOKIE: &[u8] = b"MIT-MAGIC-COOKIE-1";
const XDM: &[u8] = b"XDM-AUTHORIZATION-1";

// These are the public Xau and XCB ABIs, checked against the native headers.
#[repr(C)]
struct Xauth {
    family: u16, address_length: u16, address: *mut c_char,
    number_length: u16, number: *mut c_char,
    name_length: u16, name: *mut c_char,
    data_length: u16, data: *mut c_char,
}
#[repr(C)]
pub(super) struct AuthInfo {
    namelen: c_int, name: *mut c_char,
    datalen: c_int, data: *mut c_char,
}

/// Retains the native-selected record until XCB has consumed the setup data.
pub(super) struct Authentication {
    record: Option<NativeContext<Xauth>>,
    xdm: Option<[u8; 24]>,
}

impl Authentication {
    pub(super) fn local(display: c_int) -> Result<Self, FocusError> {
        let mut hostname = [0 as c_char; 256];
        if unsafe { hbb_common::libc::gethostname(hostname.as_mut_ptr(), hostname.len()) } != 0 {
            return Err(FocusError::Transport(std::io::Error::last_os_error()));
        }
        let length = hostname.iter().position(|byte| *byte == 0)
            .ok_or(FocusError::InvalidAuthentication)?;
        let number = display.to_string();
        // Match libxcb's native protocol preference, including XDM, rather than
        // replacing its auth selection with a cookie-only implementation.
        let mut names = [XDM.as_ptr() as *mut c_char, COOKIE.as_ptr() as *mut c_char];
        let lengths = [XDM.len() as c_int, COOKIE.len() as c_int];
        let record = unsafe { NativeContext::from_raw(XauGetBestAuthByAddr(
            256, length as u16, hostname.as_ptr(), number.len() as u16,
            number.as_ptr().cast(), 2, names.as_mut_ptr(), lengths.as_ptr()),
            |record| XauDisposeAuth(record)) };
        let mut owner = Self { record, xdm: None };
        let Some(record) = owner.record.as_ref() else {
            // As in the native connector, only absence of a matching record
            // selects empty auth; a selected but invalid record is an error.
            return Ok(owner);
        };
        let record = unsafe { &*record.as_ptr() };
        if record.name.is_null() || record.data.is_null() || record.data_length == 0 {
            return Err(FocusError::InvalidAuthentication);
        }
        let name = unsafe { std::slice::from_raw_parts(record.name.cast::<u8>(), record.name_length as usize) };
        if name == COOKIE {
            return Ok(owner);
        }
        if name != XDM || record.data_length != 16 {
            return Err(FocusError::InvalidAuthentication);
        }
        let data = unsafe { std::slice::from_raw_parts(record.data.cast::<u8>(), 16) };
        // The server compares the six Unix client bytes for replay, not a socket
        // address. A private copy of libxcb's counter would collide with Xlib's
        // independent use of that library in this same process.
        let mut plain = [0u8; 24];
        plain[..8].copy_from_slice(&data[..8]);
        let mut remaining = &mut plain[8..14];
        while !remaining.is_empty() {
            let count = unsafe { hbb_common::libc::getrandom(remaining.as_mut_ptr().cast(),
                remaining.len(), hbb_common::libc::GRND_NONBLOCK) };
            if count < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted { continue; }
                return Err(FocusError::Transport(error));
            }
            if count == 0 {
                return Err(FocusError::Transport(io::Error::new(io::ErrorKind::UnexpectedEof,
                    "X11 authentication randomness unavailable")));
            }
            remaining = &mut remaining[count as usize..];
        }
        let seconds = u32::try_from(SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_| FocusError::InvalidAuthentication)?.as_secs())
            .map_err(|_| FocusError::InvalidAuthentication)?;
        plain[14..18].copy_from_slice(&seconds.to_be_bytes());
        let mut wrapped = [0u8; 24];
        unsafe { XdmcpWrap(plain.as_ptr(), data[8..].as_ptr(), wrapped.as_mut_ptr(), 24); }
        owner.xdm = Some(wrapped);
        Ok(owner)
    }

    pub(super) fn info(&mut self) -> Option<AuthInfo> {
        let record = unsafe { &*self.record.as_ref()?.as_ptr() };
        let (data, length) = match self.xdm.as_mut() {
            Some(data) => (data.as_mut_ptr().cast(), data.len() as c_int),
            None => (record.data, c_int::from(record.data_length)),
        };
        Some(AuthInfo { namelen: c_int::from(record.name_length), name: record.name,
                        datalen: length, data })
    }
}

#[link(name = "Xau")]
extern "C" {
    fn XauGetBestAuthByAddr(family: u16, address_length: u16, address: *const c_char,
                           number_length: u16, number: *const c_char, types_length: c_int,
                           names: *mut *mut c_char, lengths: *const c_int) -> *mut Xauth;
    fn XauDisposeAuth(auth: *mut Xauth);
}
#[link(name = "Xdmcp")]
extern "C" {
    fn XdmcpWrap(input: *const u8, key: *const u8, output: *mut u8, length: c_int);
}
