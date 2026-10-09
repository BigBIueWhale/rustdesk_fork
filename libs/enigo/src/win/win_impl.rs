use self::winapi::ctypes::c_int;
use self::winapi::shared::{basetsd::ULONG_PTR, minwindef::*, windef::*};
use self::winapi::um::winuser::*;
use winapi;

use crate::win::keycodes::*;
use crate::{Key, KeyboardControllable, MouseButton, MouseControllable};
use std::mem::*;

/// The main struct for handling the event emitting
#[derive(Default)]
pub struct Enigo;

/// The dwExtraInfo value in keyboard and mouse structure that used in SendInput()
pub const ENIGO_INPUT_EXTRA_VALUE: ULONG_PTR = 100;
const MAX_SCROLL_LENGTH: i32 = 64 * WHEEL_DELTA as i32;

enum MouseInsertOutcome {
    Complete,
    None(std::io::Error),
    Partial {
        inserted: UINT,
        requested: UINT,
        error: std::io::Error,
    },
}

fn mouse_events(events: &[(u32, u32, i32, i32)]) -> MouseInsertOutcome {
    let mut inputs = Vec::with_capacity(events.len());
    for (flags, data, dx, dy) in events {
        let mut u = INPUT_u::default();
        unsafe {
            *u.mi_mut() = MOUSEINPUT {
                dx: *dx,
                dy: *dy,
                mouseData: *data,
                dwFlags: *flags,
                time: 0,
                dwExtraInfo: ENIGO_INPUT_EXTRA_VALUE,
            };
        }
        inputs.push(INPUT {
            type_: INPUT_MOUSE,
            u,
        });
    }
    let requested = inputs.len() as UINT;
    let inserted =
        unsafe { SendInput(requested, inputs.as_mut_ptr(), size_of::<INPUT>() as c_int) };
    if inserted == requested {
        return MouseInsertOutcome::Complete;
    }
    // The insertion count determines acceptance; the error code cannot diagnose UIPI.
    let error = std::io::Error::last_os_error();
    if inserted == 0 {
        MouseInsertOutcome::None(error)
    } else {
        MouseInsertOutcome::Partial {
            inserted,
            requested,
            error,
        }
    }
}

fn mouse_event(flags: u32, data: u32, dx: i32, dy: i32) -> crate::ResultType {
    match mouse_events(&[(flags, data, dx, dy)]) {
        MouseInsertOutcome::Complete => Ok(()),
        MouseInsertOutcome::None(error) => {
            Err(format!("SendInput inserted no mouse event: {error}").into())
        }
        MouseInsertOutcome::Partial {
            inserted,
            requested,
            error,
        } => Err(format!(
            "SendInput reported {inserted} of {requested} for one mouse event: {error}"
        )
        .into()),
    }
}

fn mouse_button_event(button: MouseButton, down: bool) -> Result<(u32, u32), String> {
    let flags = match (button, down) {
        (MouseButton::Left, true) => MOUSEEVENTF_LEFTDOWN,
        (MouseButton::Left, false) => MOUSEEVENTF_LEFTUP,
        (MouseButton::Middle, true) => MOUSEEVENTF_MIDDLEDOWN,
        (MouseButton::Middle, false) => MOUSEEVENTF_MIDDLEUP,
        (MouseButton::Right, true) => MOUSEEVENTF_RIGHTDOWN,
        (MouseButton::Right, false) => MOUSEEVENTF_RIGHTUP,
        (MouseButton::Back | MouseButton::Forward, true) => MOUSEEVENTF_XDOWN,
        (MouseButton::Back | MouseButton::Forward, false) => MOUSEEVENTF_XUP,
        _ => return Err(format!("unsupported mouse button {button:?}")),
    };
    let data = match button {
        MouseButton::Back => XBUTTON1 as u32,
        MouseButton::Forward => XBUTTON2 as u32,
        _ => 0,
    };
    Ok((flags, data))
}

impl MouseControllable for Enigo {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn mouse_move_to(&mut self, x: i32, y: i32) -> crate::ResultType {
        mouse_event(
            MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
            0,
            (x - unsafe { GetSystemMetrics(SM_XVIRTUALSCREEN) }) * 65535
                / unsafe { GetSystemMetrics(SM_CXVIRTUALSCREEN) },
            (y - unsafe { GetSystemMetrics(SM_YVIRTUALSCREEN) }) * 65535
                / unsafe { GetSystemMetrics(SM_CYVIRTUALSCREEN) },
        )
    }

    fn mouse_move_relative(&mut self, x: i32, y: i32) -> crate::ResultType {
        mouse_event(MOUSEEVENTF_MOVE, 0, x, y)
    }

    fn mouse_down(&mut self, button: MouseButton) -> crate::ResultType {
        let (flags, data) = mouse_button_event(button, true)?;
        mouse_event(flags, data, 0, 0)
    }

    fn mouse_up(&mut self, button: MouseButton) -> crate::ResultType {
        let (flags, data) = mouse_button_event(button, false)?;
        mouse_event(flags, data, 0, 0)
    }

    fn mouse_click(&mut self, button: MouseButton) -> crate::ResultType {
        let (down_flags, data) = mouse_button_event(button, true)?;
        let (up_flags, _) = mouse_button_event(button, false)?;
        match mouse_events(&[(down_flags, data, 0, 0), (up_flags, data, 0, 0)]) {
            MouseInsertOutcome::Complete => Ok(()),
            MouseInsertOutcome::None(error) => {
                Err(format!("SendInput inserted no mouse-click events: {error}").into())
            }
            MouseInsertOutcome::Partial {
                inserted,
                requested,
                error,
            } => {
                log::error!(
                    "SendInput inserted {inserted} of {requested} mouse-click events: {error}"
                );
                std::process::abort();
            }
        }
    }

    fn mouse_scroll_x(&mut self, length: i32) -> crate::ResultType {
        crate::checked_scroll_magnitude(length, MAX_SCROLL_LENGTH)?;
        mouse_event(MOUSEEVENTF_HWHEEL, length as _, 0, 0)
    }

    fn mouse_scroll_y(&mut self, length: i32) -> crate::ResultType {
        crate::checked_scroll_magnitude(length, MAX_SCROLL_LENGTH)?;
        mouse_event(MOUSEEVENTF_WHEEL, length as _, 0, 0)
    }
}

impl KeyboardControllable for Enigo {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn get_key_state(&mut self, key: Key) -> bool {
        let keycode = self.key_to_keycode(key);
        let x = unsafe { GetKeyState(keycode as _) };
        if key == Key::CapsLock || key == Key::NumLock || key == Key::Scroll {
            return (x & 0x1) == 0x1;
        }
        return (x as u16 & 0x8000) == 0x8000;
    }
}

impl Enigo {
    /// Gets the (width, height) of the main display in screen coordinates
    /// (pixels).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use enigo::*;
    /// let mut size = Enigo::main_display_size();
    /// ```
    pub fn main_display_size() -> (usize, usize) {
        let w = unsafe { GetSystemMetrics(SM_CXSCREEN) as usize };
        let h = unsafe { GetSystemMetrics(SM_CYSCREEN) as usize };
        (w, h)
    }

    /// Gets the location of mouse in screen coordinates (pixels).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use enigo::*;
    /// let mut location = Enigo::mouse_location();
    /// ```
    pub fn mouse_location() -> (i32, i32) {
        let mut point = POINT { x: 0, y: 0 };
        let result = unsafe { GetCursorPos(&mut point) };
        if result != 0 {
            (point.x, point.y)
        } else {
            (0, 0)
        }
    }

    fn key_to_keycode(&self, key: Key) -> u16 {
        // do not use the codes from crate winapi they're
        // wrongly typed with i32 instead of i16 use the
        // ones provided by win/keycodes.rs that are prefixed
        // with an 'E' infront of the original name
        #[allow(deprecated)]
        // I mean duh, we still need to support deprecated keys until they're removed
        match key {
            Key::Alt => EVK_MENU,
            Key::Backspace => EVK_BACK,
            Key::CapsLock => EVK_CAPITAL,
            Key::Control => EVK_LCONTROL,
            Key::Delete => EVK_DELETE,
            Key::DownArrow => EVK_DOWN,
            Key::End => EVK_END,
            Key::Escape => EVK_ESCAPE,
            Key::F1 => EVK_F1,
            Key::F10 => EVK_F10,
            Key::F11 => EVK_F11,
            Key::F12 => EVK_F12,
            Key::F2 => EVK_F2,
            Key::F3 => EVK_F3,
            Key::F4 => EVK_F4,
            Key::F5 => EVK_F5,
            Key::F6 => EVK_F6,
            Key::F7 => EVK_F7,
            Key::F8 => EVK_F8,
            Key::F9 => EVK_F9,
            Key::Home => EVK_HOME,
            Key::LeftArrow => EVK_LEFT,
            Key::Option => EVK_MENU,
            Key::PageDown => EVK_NEXT,
            Key::PageUp => EVK_PRIOR,
            Key::Return => EVK_RETURN,
            Key::RightArrow => EVK_RIGHT,
            Key::Shift => EVK_SHIFT,
            Key::Space => EVK_SPACE,
            Key::Tab => EVK_TAB,
            Key::UpArrow => EVK_UP,
            Key::Numpad0 => EVK_NUMPAD0,
            Key::Numpad1 => EVK_NUMPAD1,
            Key::Numpad2 => EVK_NUMPAD2,
            Key::Numpad3 => EVK_NUMPAD3,
            Key::Numpad4 => EVK_NUMPAD4,
            Key::Numpad5 => EVK_NUMPAD5,
            Key::Numpad6 => EVK_NUMPAD6,
            Key::Numpad7 => EVK_NUMPAD7,
            Key::Numpad8 => EVK_NUMPAD8,
            Key::Numpad9 => EVK_NUMPAD9,
            Key::Cancel => EVK_CANCEL,
            Key::Clear => EVK_CLEAR,
            Key::Pause => EVK_PAUSE,
            Key::Kana => EVK_KANA,
            Key::Hangul => EVK_HANGUL,
            Key::Junja => EVK_JUNJA,
            Key::Final => EVK_FINAL,
            Key::Hanja => EVK_HANJA,
            Key::Kanji => EVK_KANJI,
            Key::Convert => EVK_CONVERT,
            Key::Select => EVK_SELECT,
            Key::Print => EVK_PRINT,
            Key::Execute => EVK_EXECUTE,
            Key::Snapshot => EVK_SNAPSHOT,
            Key::Insert => EVK_INSERT,
            Key::Help => EVK_HELP,
            Key::Sleep => EVK_SLEEP,
            Key::Separator => EVK_SEPARATOR,
            Key::Mute => EVK_VOLUME_MUTE,
            Key::VolumeDown => EVK_VOLUME_DOWN,
            Key::VolumeUp => EVK_VOLUME_UP,
            Key::Scroll => EVK_SCROLL,
            Key::NumLock => EVK_NUMLOCK,
            Key::RWin => EVK_RWIN,
            Key::Apps => EVK_APPS,
            Key::Add => EVK_ADD,
            Key::Multiply => EVK_MULTIPLY,
            Key::Decimal => EVK_DECIMAL,
            Key::Subtract => EVK_SUBTRACT,
            Key::Divide => EVK_DIVIDE,
            Key::NumpadEnter => EVK_RETURN,
            Key::Equals => '=' as _,
            Key::RightShift => EVK_RSHIFT,
            Key::RightControl => EVK_RCONTROL,
            Key::RightAlt => EVK_RMENU,

            Key::Raw(raw_keycode) => raw_keycode,
            Key::Super | Key::Command | Key::Windows | Key::Meta => EVK_LWIN,
            Key::Layout(..) => {
                // unreachable
                0
            }
        }
    }
}
