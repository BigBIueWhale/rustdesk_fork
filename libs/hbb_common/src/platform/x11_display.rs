use std::{ffi::{c_int, CString}, io};

/// Native display selection is local-only; authentication remains library-owned.
pub fn unix_display_name() -> io::Result<CString> {
    let (display, screen) = local_display()?;
    // An explicit protocol prevents implicit localhost TCP after Unix refusal.
    CString::new(format!("unix/:{display}.{screen}"))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid local X11 display selector"))
}

pub fn local_display() -> io::Result<(c_int, c_int)> {
    fn invalid() -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, "invalid local X11 display selector")
    }
    fn number(field: &str) -> io::Result<c_int> {
        if field.is_empty() || !field.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        field.parse().map_err(|_| invalid())
    }
    let value = std::env::var("DISPLAY").map_err(|_| invalid())?;
    let value = value.strip_prefix(':').ok_or_else(invalid)?;
    let mut fields = value.split('.');
    let display = number(fields.next().ok_or_else(invalid)?)?;
    let screen = match (fields.next(), fields.next()) {
        (None, None) => 0,
        (Some(screen), None) => number(screen)?,
        _ => return Err(invalid()),
    };
    Ok((display, screen))
}
