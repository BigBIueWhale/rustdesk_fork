//! XDO-based input emulation for Linux.
//!
//! This module uses libxdo-sys (patched to use dynamic loading stub) for input emulation.
//! The stub handles dynamic loading of libxdo, so we just call the functions directly.
//!
//! If libxdo is not available at runtime, operations return errors.

use crate::{checked_scroll_magnitude, Key, KeyboardControllable, MouseButton, MouseControllable};

use hbb_common::libc::c_int;
use hbb_common::platform::x11_display::unix_display_name;
use hbb_common::x11::keysym::*;
use hbb_common::x11::xlib::{Display, XCloseDisplay, XDefaultScreen, XGetPointerMapping, XOpenDisplay};
use libxdo_sys::{self, xdo_t, XdoKey, XdoKeyAction, CURRENTWINDOW};
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
    screen: c_int,
    delay: u64,
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
            screen: 0,
            delay: DEFAULT_DELAY,
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
        let screen = unsafe { XDefaultScreen(display) };
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
        owner.screen = screen;
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
        // Validate the complete text before emitting any prefix. Text scalars use
        // numeric keysyms without locale-dependent native multibyte conversion.
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
            let key = match character {
                '\n' | '\r' => Key::Return,
                '\t' => Key::Tab,
                _ => Key::Layout(character),
            };
            let key = xdo_key(key)?;
            let status = unsafe {
                libxdo_sys::xdo_send_key_window(
                    context.0 as *const _,
                    CURRENTWINDOW,
                    key,
                    XdoKeyAction::Click,
                    (self.delay / 2) as libxdo_sys::useconds_t,
                )
            };
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
        let status = unsafe { libxdo_sys::xdo_move_mouse(self.xdo as *const _, x, y, self.screen) };
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
            libxdo_sys::xdo_mouse_down(self.xdo as *const _, CURRENTWINDOW, mousebutton(button))
        };
        xdo_result("mouse down", status)
    }

    fn mouse_up(&mut self, button: MouseButton) -> crate::ResultType {
        if self.xdo.is_null() {
            return Err("libxdo is unavailable".into());
        }
        let status = unsafe {
            libxdo_sys::xdo_mouse_up(self.xdo as *const _, CURRENTWINDOW, mousebutton(button))
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

fn xdo_key(key: Key) -> Result<XdoKey, Box<dyn std::error::Error>> {
    let symbol = match key {
        Key::Layout(character) => {
            if character.is_control() {
                return Err("unsupported X11 layout control".into());
            }
            let scalar = character as u32;
            if scalar <= 0xff { scalar } else { 0x01000000 | scalar }
        }
        Key::Raw(code) => return Ok(XdoKey::Keycode(code.into())),
        Key::Alt => XK_Alt_L,
        Key::Backspace => XK_BackSpace,
        Key::CapsLock => XK_Caps_Lock,
        Key::Control => XK_Control_L,
        Key::Delete => XK_Delete,
        Key::DownArrow => XK_Down,
        Key::End => XK_End,
        Key::Escape => XK_Escape,
        Key::F1 => XK_F1,
        Key::F10 => XK_F10,
        Key::F11 => XK_F11,
        Key::F12 => XK_F12,
        Key::F2 => XK_F2,
        Key::F3 => XK_F3,
        Key::F4 => XK_F4,
        Key::F5 => XK_F5,
        Key::F6 => XK_F6,
        Key::F7 => XK_F7,
        Key::F8 => XK_F8,
        Key::F9 => XK_F9,
        Key::Home => XK_Home,
        Key::LeftArrow => XK_Left,
        Key::PageDown => XK_Page_Down,
        Key::PageUp => XK_Page_Up,
        Key::Return => XK_Return,
        Key::RightArrow => XK_Right,
        Key::Shift => XK_Shift_L,
        Key::Space => XK_space,
        Key::Tab => XK_Tab,
        Key::UpArrow => XK_Up,
        Key::Numpad0 => XK_0,
        Key::Numpad1 => XK_1,
        Key::Numpad2 => XK_2,
        Key::Numpad3 => XK_3,
        Key::Numpad4 => XK_4,
        Key::Numpad5 => XK_5,
        Key::Numpad6 => XK_6,
        Key::Numpad7 => XK_7,
        Key::Numpad8 => XK_8,
        Key::Numpad9 => XK_9,
        Key::Decimal => XK_period,
        Key::Cancel => XK_Cancel,
        Key::Clear => XK_Clear,
        Key::Pause => XK_Pause,
        Key::Kana => XK_Kana_Lock,
        Key::Hangul => 0xff31, // Hangul
        Key::Hanja => 0xff34, // Hangul_Hanja
        Key::Kanji => XK_Kanji,
        Key::Select => XK_Select,
        Key::Print => XK_Print,
        Key::Execute => XK_Execute,
        Key::Snapshot => 0xfd1d, // 3270_PrintScreen
        Key::Insert => XK_Insert,
        Key::Help => XK_Help,
        Key::Separator => XK_KP_Separator,
        Key::Scroll => XK_Scroll_Lock,
        Key::NumLock => XK_Num_Lock,
        Key::RWin => XK_Super_R,
        Key::Apps => XK_Menu,
        Key::Multiply => XK_KP_Multiply,
        Key::Add => XK_KP_Add,
        Key::Subtract => XK_KP_Subtract,
        Key::Divide => XK_KP_Divide,
        Key::Equals => XK_KP_Equal,
        Key::NumpadEnter => XK_KP_Enter,
        Key::RightShift => XK_Shift_R,
        Key::RightControl => XK_Control_R,
        Key::RightAlt => XK_Alt_R,
        Key::Command | Key::Super | Key::Windows | Key::Meta => XK_Super_L,
        _ => return Err("unsupported X11 key".into()),
    };
    Ok(XdoKey::Keysym(symbol.into()))
}

impl KeyboardControllable for EnigoXdo {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn get_key_state(&mut self, key: Key) -> bool {
        if self.xdo.is_null() {
            return false;
        }
        /*
        // modifier keys mask
        pub const ShiftMask: c_uint = 0x01;
        pub const LockMask: c_uint = 0x02;
        pub const ControlMask: c_uint = 0x04;
        pub const Mod1Mask: c_uint = 0x08;
        pub const Mod2Mask: c_uint = 0x10;
        pub const Mod3Mask: c_uint = 0x20;
        pub const Mod4Mask: c_uint = 0x40;
        pub const Mod5Mask: c_uint = 0x80;
        */
        let mod_shift = 1 << 0;
        let mod_lock = 1 << 1;
        let mod_control = 1 << 2;
        let mod_alt = 1 << 3;
        let mod_numlock = 1 << 4;
        let mod_meta = 1 << 6;
        let mask = unsafe { libxdo_sys::xdo_get_input_state(self.xdo as *const _) };
        match key {
            Key::Shift => mask & mod_shift != 0,
            Key::CapsLock => mask & mod_lock != 0,
            Key::Control => mask & mod_control != 0,
            Key::Alt => mask & mod_alt != 0,
            Key::NumLock => mask & mod_numlock != 0,
            Key::Meta => mask & mod_meta != 0,
            _ => false,
        }
    }

    fn key_sequence(&mut self, sequence: &str) {
        if let Err(err) = self.key_sequence_result(sequence) {
            log::warn!("EnigoXdo::key_sequence failed: {err}");
        }
    }

    fn key_down(&mut self, key: Key) -> crate::ResultType {
        if self.xdo.is_null() {
            return Err("libxdo is unavailable".into());
        }
        let key = xdo_key(key)?;
        let status = unsafe {
            libxdo_sys::xdo_send_key_window(
                self.xdo as *const _,
                CURRENTWINDOW,
                key,
                XdoKeyAction::Down,
                self.delay as libxdo_sys::useconds_t,
            )
        };
        xdo_result("key down", status)
    }

    fn key_up(&mut self, key: Key) {
        if self.xdo.is_null() {
            log::warn!("EnigoXdo::key_up failed: libxdo is unavailable");
            return;
        }
        let result = xdo_key(key).and_then(|key| {
            let status = unsafe {
                libxdo_sys::xdo_send_key_window(
                    self.xdo as *const _,
                    CURRENTWINDOW,
                    key,
                    XdoKeyAction::Up,
                    self.delay as libxdo_sys::useconds_t,
                )
            };
            xdo_result("key up", status)
        });
        if let Err(err) = result {
            log::warn!("EnigoXdo::key_up failed: {err}");
        }
    }

    fn key_click(&mut self, key: Key) {
        if self.xdo.is_null() {
            log::warn!("EnigoXdo::key_click failed: libxdo is unavailable");
            return;
        }
        let result = xdo_key(key).and_then(|key| {
            let status = unsafe {
                libxdo_sys::xdo_send_key_window(
                    self.xdo as *const _,
                    CURRENTWINDOW,
                    key,
                    XdoKeyAction::Click,
                    self.delay as libxdo_sys::useconds_t,
                )
            };
            xdo_result("key click", status)
        });
        if let Err(err) = result {
            log::warn!("EnigoXdo::key_click failed: {err}");
        }
    }
}
