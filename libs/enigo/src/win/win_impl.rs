use self::winapi::ctypes::c_int;
use self::winapi::shared::{basetsd::ULONG_PTR, minwindef::*, windef::*};
use self::winapi::um::winuser::*;
use winapi;

use crate::{
    KeyboardControllable, KeyboardState, ModifierKey, MouseButton, MouseControllable, NumLockState,
};
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

    fn keyboard_state(&mut self) -> Result<KeyboardState, Box<dyn std::error::Error>> {
        let mut state = [0u8; 256];
        if unsafe { GetKeyboardState(state.as_mut_ptr()) } == 0 {
            let error = std::io::Error::last_os_error();
            return Err(format!("GetKeyboardState failed: {error}").into());
        }
        let modifiers = ModifierKey::ALL.map(|key| {
            let vk = match key {
                ModifierKey::Shift => VK_LSHIFT,
                ModifierKey::Control => VK_LCONTROL,
                ModifierKey::Alt => VK_LMENU,
                ModifierKey::Meta => VK_LWIN,
                ModifierKey::RightShift => VK_RSHIFT,
                ModifierKey::RightControl => VK_RCONTROL,
                ModifierKey::RightAlt => VK_RMENU,
                ModifierKey::RightMeta => VK_RWIN,
            };
            state[vk as usize] & 0x80 != 0
        });
        Ok(KeyboardState::from_parts(
            modifiers,
            state[VK_CAPITAL as usize] & 1 != 0,
            if state[VK_NUMLOCK as usize] & 1 != 0 {
                NumLockState::On
            } else {
                NumLockState::Off
            },
        ))
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
}
