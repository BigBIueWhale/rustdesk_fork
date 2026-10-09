//! XDO-based input emulation for Linux.
//!
//! This module uses libxdo-sys (patched to use dynamic loading stub) for input emulation.
//! The stub handles dynamic loading of libxdo, so we just call the functions directly.
//!
//! If libxdo is not available at runtime, operations return errors.

use crate::{
    checked_scroll_magnitude, KeyboardControllable, KeyboardState, ModifierKey, MouseButton,
    MouseControllable, NumLockState,
};

use hbb_common::libc::c_int;
use hbb_common::platform::x11_display::unix_display_name;
use hbb_common::x11::xlib::{Display, XCloseDisplay, XGetPointerMapping, XOpenDisplay};
use libxdo_sys::{self, xdo_t};
use std::ffi::CString;

/// Default delay per keypress in microseconds.
/// This value is passed to libxdo functions and must fit in `useconds_t` (u32).
const DEFAULT_DELAY: u64 = 12000;

/// Maximum allowed delay value (u32::MAX as u64).
const MAX_DELAY: u64 = u32::MAX as u64;
const MAX_SCROLL_LENGTH: i32 = 64;

fn mousebutton(button: MouseButton) -> c_int {
    match button {
        MouseButton::Left => 1,
        MouseButton::Middle => 2,
        MouseButton::Right => 3,
        MouseButton::ScrollUp => 4,
        MouseButton::ScrollDown => 5,
        MouseButton::ScrollLeft => 6,
        MouseButton::ScrollRight => 7,
        MouseButton::Back => 8,
        MouseButton::Forward => 9,
    }
}

fn xdo_result(operation: &str, status: c_int) -> crate::ResultType {
    // libxdo's status reports request submission/flush acceptance, not eventual X server delivery;
    // asynchronous X protocol errors remain outside this synchronous API contract.
    if status == 0 {
        Ok(())
    } else {
        Err(format!("libxdo {operation} failed with status {status}").into())
    }
}

/// Minimum number of buttons the X11 core pointer must support.
/// Buttons 8 (Back) and 9 (Forward) are needed for mouse side buttons.
const MIN_POINTER_BUTTONS: usize = 9;

/// Check that the X11 core pointer's button map includes at least 9 buttons
/// so that `XTestFakeButtonEvent` can simulate Back (8) and Forward (9).
///
/// `XSetPointerMapping` cannot extend the button count, so this only diagnoses
/// configurations where side-button injection cannot work.
fn check_x11_button_map(display: *mut Display) {
    let mut current_map = [0u8; 32];
    let nbuttons =
        unsafe { XGetPointerMapping(display, current_map.as_mut_ptr(), current_map.len() as i32) };

    if nbuttons < 0 {
        log::warn!("XGetPointerMapping failed (returned {nbuttons})");
        return;
    }

    let nbuttons = nbuttons as usize;
    if nbuttons >= MIN_POINTER_BUTTONS {
        log::info!("X11 pointer has {nbuttons} buttons, side buttons supported");
    } else {
        log::warn!(
            "X11 pointer has only {nbuttons} buttons (need {MIN_POINTER_BUTTONS}); \
             back/forward side buttons may not work until a device with more buttons is added"
        );
    }
}

struct OpenedDisplay(*mut Display);

impl Drop for OpenedDisplay {
    fn drop(&mut self) {
        unsafe { XCloseDisplay(self.0) };
    }
}

struct TextContext(*mut xdo_t);

impl Drop for TextContext {
    fn drop(&mut self) {
        unsafe { libxdo_sys::xdo_free(self.0) };
    }
}

/// The main struct for handling the event emitting
pub(super) struct EnigoXdo {
    xdo: *mut xdo_t,
    display: *mut Display,
    display_name: Option<CString>,
    delay: u64,
    pending_text_cleanup: Option<TextContext>,
}
// This is safe, we have a unique pointer.
// TODO: use Unique<c_char> once stable.
unsafe impl Send for EnigoXdo {}

impl Default for EnigoXdo {
    /// Create a new EnigoXdo instance.
    ///
    /// If libxdo is unavailable, input operations return errors.
    fn default() -> Self {
        let mut owner = Self {
            xdo: std::ptr::null_mut(),
            display: std::ptr::null_mut(),
            display_name: None,
            delay: DEFAULT_DELAY,
            pending_text_cleanup: None,
        };
        let display_name = match unix_display_name() {
            Ok(display_name) => display_name,
            Err(err) => {
                log::warn!("Cannot select a local X11 display for xdo: {err}");
                return owner;
            }
        };
        let display = unsafe { XOpenDisplay(display_name.as_ptr()) };
        if display.is_null() {
            log::warn!("Failed to open the selected X11 display, xdo functions will be disabled");
            return owner;
        }
        let opened = OpenedDisplay(display);
        let xdo = unsafe { libxdo_sys::xdo_new_with_opened_display(display, display_name.as_ptr(), 1) };
        if xdo.is_null() {
            log::warn!("Failed to create xdo context, xdo functions will be disabled");
            return owner;
        }
        // Transfer the sole display to the native context, then retain that
        // context before diagnostics or logging can unwind.
        owner.xdo = xdo;
        owner.display = display;
        owner.display_name = Some(display_name);
        std::mem::forget(opened);
        log::info!("xdo context created successfully");
        check_x11_button_map(display);
        owner
    }
}

impl EnigoXdo {
    /// Get the delay per keypress in microseconds.
    ///
    /// Default value is 12000 (12ms). This is Linux-specific.
    pub fn delay(&self) -> u64 {
        self.delay
    }

    /// Set the delay per keypress in microseconds.
    ///
    /// This is Linux-specific. The value is clamped to `u32::MAX` (approximately
    /// 4295 seconds) because libxdo uses `useconds_t` which is typically `u32`.
    ///
    /// # Arguments
    /// * `delay` - Delay in microseconds. Values exceeding `u32::MAX` will be clamped.
    pub fn set_delay(&mut self, delay: u64) {
        self.delay = delay.min(MAX_DELAY);
        if delay > MAX_DELAY {
            log::warn!(
                "delay value {} exceeds maximum {}, clamped",
                delay,
                MAX_DELAY
            );
        }
    }
}

impl Drop for EnigoXdo {
    fn drop(&mut self) {
        // The text context borrows the main Display for key and map retirement.
        drop(self.pending_text_cleanup.take());
        if !self.xdo.is_null() {
            unsafe {
                libxdo_sys::xdo_free(self.xdo);
            }
        }
    }
}

impl EnigoXdo {
    pub(crate) fn key_sequence_result(&mut self, sequence: &str) -> crate::ResultType {
        if self.xdo.is_null() {
            return Err("libxdo is unavailable".into());
        }
        if self.pending_text_cleanup.is_some() {
            return Err("libxdo text cleanup is unconfirmed".into());
        }
        // Validate the complete text before emitting any prefix.
        if let Some(character) = sequence
            .chars()
            .find(|c| c.is_control() && !matches!(*c, '\n' | '\r' | '\t'))
        {
            return Err(format!("unsupported text control U+{:04X}", character as u32).into());
        }
        if sequence.is_empty() {
            return Ok(());
        }
        // libxdo caches its keyboard map at construction. Give each text request
        // a fresh map on the retained display; the temporary context borrows that
        // display and retires before its owning EnigoXdo can close it.
        let display_name = self.display_name.as_ref().ok_or("libxdo display is unavailable")?;
        let context = unsafe {
            libxdo_sys::xdo_new_with_opened_display(self.display, display_name.as_ptr(), 0)
        };
        if context.is_null() {
            return Err("libxdo text mapping is unavailable".into());
        }
        let context = TextContext(context);
        for character in sequence.chars() {
            let status = unsafe {
                libxdo_sys::xdo_enter_text_scalar(
                    context.0,
                    character,
                    (self.delay / 2) as libxdo_sys::useconds_t,
                )
            };
            if status == libxdo_sys::XDO_CLEANUP_ERROR {
                self.pending_text_cleanup = Some(context);
                return xdo_result("text entry", status);
            }
            xdo_result("text entry", status)?;
        }
        Ok(())
    }
}

impl MouseControllable for EnigoXdo {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn mouse_move_to(&mut self, x: i32, y: i32) -> crate::ResultType {
        if self.xdo.is_null() {
            return Err("libxdo is unavailable".into());
        }
        let status = unsafe { libxdo_sys::xdo_move_mouse(self.xdo as *const _, x, y) };
        xdo_result("mouse move", status)
    }

    fn mouse_move_relative(&mut self, x: i32, y: i32) -> crate::ResultType {
        if self.xdo.is_null() {
            return Err("libxdo is unavailable".into());
        }
        let status = unsafe { libxdo_sys::xdo_move_mouse_relative(self.xdo as *const _, x, y) };
        xdo_result("relative mouse move", status)
    }

    fn mouse_down(&mut self, button: MouseButton) -> crate::ResultType {
        if self.xdo.is_null() {
            return Err("libxdo is unavailable".into());
        }
        let status = unsafe {
            libxdo_sys::xdo_mouse_down(self.xdo as *const _, mousebutton(button))
        };
        xdo_result("mouse down", status)
    }

    fn mouse_up(&mut self, button: MouseButton) -> crate::ResultType {
        if self.xdo.is_null() {
            return Err("libxdo is unavailable".into());
        }
        let status = unsafe {
            libxdo_sys::xdo_mouse_up(self.xdo as *const _, mousebutton(button))
        };
        xdo_result("mouse up", status)
    }

    fn mouse_click(&mut self, button: MouseButton) -> crate::ResultType {
        self.mouse_down(button)?;
        if let Err(first_err) = self.mouse_up(button) {
            if let Err(retry_err) = self.mouse_up(button) {
                log::error!(
                    "X11 mouse-click release submission failed twice: first={first_err}, retry={retry_err}"
                );
                std::process::abort();
            }
            log::warn!("X11 mouse-click release submission required a retry: {first_err}");
        }
        Ok(())
    }

    fn mouse_scroll_x(&mut self, length: i32) -> crate::ResultType {
        let button = if length < 0 {
            MouseButton::ScrollLeft
        } else {
            MouseButton::ScrollRight
        };
        let length = checked_scroll_magnitude(length, MAX_SCROLL_LENGTH)?;

        for _ in 0..length {
            self.mouse_click(button)?;
        }
        Ok(())
    }

    fn mouse_scroll_y(&mut self, length: i32) -> crate::ResultType {
        let button = if length < 0 {
            MouseButton::ScrollUp
        } else {
            MouseButton::ScrollDown
        };
        let length = checked_scroll_magnitude(length, MAX_SCROLL_LENGTH)?;

        for _ in 0..length {
            self.mouse_click(button)?;
        }
        Ok(())
    }
}

impl KeyboardControllable for EnigoXdo {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn keyboard_state(&mut self) -> Result<KeyboardState, Box<dyn std::error::Error>> {
        if self.xdo.is_null() {
            return Err("X11 keyboard state is unavailable".into());
        }
        let mut state = libxdo_sys::XdoInputState::default();
        let status = unsafe { libxdo_sys::xdo_query_input_state(self.xdo, &mut state) };
        xdo_result("keyboard state", status)?;
        if state.keycode_min < 8
            || state.keycode_min > state.keycode_max
            || state.caps_lock > 1
            || state.num_lock > 1
        {
            return Err("X11 keyboard state has invalid bounds or lock values".into());
        }
        let mut modifiers = [false; 8];
        for (index, key) in ModifierKey::ALL.iter().enumerate() {
            let code = rdev::linux_keycode_from_key(key.rdev_key())
                .ok_or("X11 modifier has no physical injector identity")?;
            if code < u32::from(state.keycode_min) || code > u32::from(state.keycode_max) {
                return Err("X11 modifier is outside the native keycode range".into());
            }
            modifiers[index] = state.keys[code as usize / 8] & (1 << (code % 8)) != 0;
        }
        Ok(KeyboardState::from_parts(
            modifiers,
            state.caps_lock != 0,
            if state.num_lock != 0 {
                NumLockState::On
            } else {
                NumLockState::Off
            },
        ))
    }
}
