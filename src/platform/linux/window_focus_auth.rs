use super::FocusError;
use std::{ffi::{c_char, c_int}, fs::OpenOptions, io::{self, Read},
          os::unix::fs::OpenOptionsExt, time::{SystemTime, UNIX_EPOCH}};

const COOKIE: &[u8] = b"MIT-MAGIC-COOKIE-1";
const XDM: &[u8] = b"XDM-AUTHORIZATION-1";
const MAX_AUTH_BYTES: u64 = 1024 * 1024;

// Public XCB ABI, checked against the native headers.
#[repr(C)]
pub(super) struct AuthInfo {
    namelen: c_int, name: *mut c_char,
    datalen: c_int, data: *mut c_char,
}

/// Retains the selected protocol and bytes until synchronous XCB setup drains.
pub(super) struct Authentication {
    name: Option<&'static [u8]>,
    data: AuthBytes,
}

struct AuthBytes(Vec<u8>);
impl Drop for AuthBytes {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe { std::ptr::write_volatile(byte, 0); }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl Authentication {
    pub(super) fn local(display: c_int) -> Result<Self, FocusError> {
        let mut hostname = [0u8; 256];
        if unsafe { hbb_common::libc::gethostname(hostname.as_mut_ptr().cast(), hostname.len()) } != 0 {
            return Err(FocusError::Transport(std::io::Error::last_os_error()));
        }
        let length = hostname.iter().position(|byte| *byte == 0)
            .ok_or(FocusError::InvalidAuthentication)?;
        let number = display.to_string();
        let hostname = &hostname[..length];
        let mut owner = Self::read(hostname, number.as_bytes())?;
        let Some(name) = owner.name else { return Ok(owner); };
        if owner.data.0.is_empty() {
            return Err(FocusError::InvalidAuthentication);
        }
        if name == COOKIE {
            return Ok(owner);
        }
        if name != XDM || owner.data.0.len() != 16 {
            return Err(FocusError::InvalidAuthentication);
        }
        let data = &owner.data.0;
        // The server compares the six Unix client bytes for replay, not a socket
        // address. A private copy of libxcb's counter would collide with Xlib's
        // independent use of that library in this same process.
        let mut plain = AuthBytes(vec![0; 24]);
        plain.0[..8].copy_from_slice(&data[..8]);
        let mut remaining = &mut plain.0[8..14];
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
        plain.0[14..18].copy_from_slice(&seconds.to_be_bytes());
        let mut wrapped = AuthBytes(vec![0; 24]);
        unsafe { XdmcpWrap(plain.0.as_ptr(), data[8..].as_ptr(), wrapped.0.as_mut_ptr(), 24); }
        owner.data = wrapped;
        Ok(owner)
    }

    fn read(hostname: &[u8], number: &[u8]) -> Result<Self, FocusError> {
        let empty = Self { name: None, data: AuthBytes(Vec::new()) };
        // Do not acquire file authority from a set-ID effective principal.
        if unsafe { hbb_common::libc::getuid() != hbb_common::libc::geteuid()
            || hbb_common::libc::getgid() != hbb_common::libc::getegid() }
        {
            return Err(FocusError::InvalidAuthentication);
        }
        let path = match std::env::var_os("XAUTHORITY") {
            Some(path) => path,
            None => match std::env::var_os("HOME") {
                Some(mut home) => { home.push("/.Xauthority"); home }
                None => return Ok(empty),
            },
        };
        // A FIFO must not wait for a writer, and a device must not become the
        // controlling terminal. Validate the exact opened object before reading.
        let mut file = match OpenOptions::new().read(true)
            .custom_flags(hbb_common::libc::O_NONBLOCK | hbb_common::libc::O_NOCTTY).open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(empty),
            Err(error) => return Err(FocusError::Transport(error)),
        };
        let metadata = file.metadata().map_err(FocusError::Transport)?;
        if !metadata.is_file() || metadata.len() > MAX_AUTH_BYTES {
            return Err(FocusError::InvalidAuthentication);
        }
        // Fixed capacity avoids freeing un-wiped credential bytes on growth.
        let mut bytes = AuthBytes(vec![0; (MAX_AUTH_BYTES + 1) as usize]);
        let mut length = 0;
        while length < bytes.0.len() {
            match file.read(&mut bytes.0[length..]) {
                Ok(0) => break,
                Ok(count) => length += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(FocusError::Transport(error)),
            }
        }
        if length as u64 > MAX_AUTH_BYTES {
            return Err(FocusError::InvalidAuthentication);
        }
        let mut remaining = &bytes.0[..length];
        let mut best: Option<(u8, &'static [u8], &[u8])> = None;
        while !remaining.is_empty() {
            let family = word(&mut remaining)?;
            let address = field(&mut remaining)?;
            let display = field(&mut remaining)?;
            let name = field(&mut remaining)?;
            let data = field(&mut remaining)?;
            if !(family == 65535 || (family == 256 && address == hostname))
                || !(display.is_empty() || display == number)
            {
                continue;
            }
            // Xau's first matching record at the best protocol rank wins.
            let (rank, name) = if name == XDM { (0, XDM) }
                else if name == COOKIE { (1, COOKIE) } else { continue; };
            if best.as_ref().map_or(true, |(prior, _, _)| rank < *prior) {
                best = Some((rank, name, data));
            }
        }
        match best {
            Some((_, name, data)) => Ok(Self { name: Some(name), data: AuthBytes(data.to_vec()) }),
            None => Ok(empty),
        }
    }

    pub(super) fn info(&mut self) -> Option<AuthInfo> {
        let name = self.name?;
        Some(AuthInfo { namelen: name.len() as c_int, name: name.as_ptr() as *mut c_char,
                        datalen: self.data.0.len() as c_int, data: self.data.0.as_mut_ptr().cast() })
    }
}

fn word(input: &mut &[u8]) -> Result<u16, FocusError> {
    let bytes = input.get(..2).ok_or(FocusError::InvalidAuthentication)?;
    let value = u16::from_be_bytes([bytes[0], bytes[1]]);
    *input = &input[2..];
    Ok(value)
}

fn field<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], FocusError> {
    let length = usize::from(word(input)?);
    let value = input.get(..length).ok_or(FocusError::InvalidAuthentication)?;
    *input = &input[length..];
    Ok(value)
}
#[link(name = "Xdmcp")]
extern "C" {
    fn XdmcpWrap(input: *const u8, key: *const u8, output: *mut u8, length: c_int);
}
