use core_graphics;
// TODO(dustin): use only the things i need

use self::core_graphics::display::*;
use self::core_graphics::event::*;
use self::core_graphics::event_source::*;

use crate::macos::keycodes::*;
use crate::{checked_scroll_magnitude, Key, KeyboardState, ModifierKey, NumLockState,
            KeyboardControllable, MouseButton, MouseControllable};
use objc::runtime::Class;

struct MyCGEvent;
const MAX_SCROLL_LENGTH: i32 = 64;

const MOUSE_EVENT_BUTTON_NUMBER_BACK: i64 = 3;
const MOUSE_EVENT_BUTTON_NUMBER_FORWARD: i64 = 4;

/// The event source user data value of cgevent.
pub const ENIGO_INPUT_EXTRA_VALUE: i64 = 100;

#[allow(improper_ctypes)]
#[allow(non_snake_case)]
#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    fn CGEventPost(tapLocation: CGEventTapLocation, event: *mut MyCGEvent);
    // not present in servo/core-graphics
    fn CGEventCreateScrollWheelEvent(
        source: &CGEventSourceRef,
        units: ScrollUnit,
        wheelCount: u32,
        wheel1: i32,
        ...
    ) -> *mut MyCGEvent;
    fn CGEventSourceKeyState(stateID: i32, key: u16) -> bool;
    fn CGEventSourceFlagsState(stateID: i32) -> u64;
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NSPoint {
    x: f64,
    y: f64,
}

// not present in servo/core-graphics
#[allow(dead_code)]
#[derive(Debug)]
enum ScrollUnit {
    Pixel = 0,
    Line = 1,
}
// hack

/// The main struct for handling the event emitting
pub struct Enigo {
    event_source: Option<CGEventSource>,
    double_click_interval: u32,
    last_click_time: Option<std::time::Instant>,
    multiple_click: i64,
    ignore_flags: bool,
    flags: CGEventFlags,
}

impl Enigo {
    /// Set if ignore flags when posting events.
    pub fn set_ignore_flags(&mut self, ignore: bool) {
        self.ignore_flags = ignore;
    }

    ///
    pub fn reset_flag(&mut self) {
        self.flags = CGEventFlags::CGEventFlagNull;
    }

    ///
    pub fn add_flag(&mut self, key: &Key) {
        let flag = match key {
            &Key::CapsLock => CGEventFlags::CGEventFlagAlphaShift,
            &Key::Shift => CGEventFlags::CGEventFlagShift,
            &Key::Control => CGEventFlags::CGEventFlagControl,
            &Key::Alt => CGEventFlags::CGEventFlagAlternate,
            &Key::Meta => CGEventFlags::CGEventFlagCommand,
            &Key::NumLock => CGEventFlags::CGEventFlagNumericPad,
            _ => CGEventFlags::CGEventFlagNull,
        };
        self.flags |= flag;
    }

    fn post(&self, event: CGEvent) {
        if !self.ignore_flags {
            event.set_flags(self.flags);
        }
        event.set_integer_value_field(EventField::EVENT_SOURCE_USER_DATA, ENIGO_INPUT_EXTRA_VALUE);
        // CGEventPost has no synchronous delivery acknowledgement. Successful event
        // construction followed by this call is the strongest native acceptance contract.
        event.post(CGEventTapLocation::HID);
    }
}

impl Default for Enigo {
    fn default() -> Self {
        let mut double_click_interval = 500;
        if let Some(ns_event) = Class::get("NSEvent") {
            let tm: f64 = unsafe { msg_send![ns_event, doubleClickInterval] };
            if tm > 0. {
                double_click_interval = (tm * 1000.) as u32;
                log::info!("double click interval: {}ms", double_click_interval);
            }
        }
        Self {
            // TODO(dustin): return error rather than panic here
            event_source: if let Ok(src) =
                CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
            {
                Some(src)
            } else {
                None
            },
            double_click_interval,
            multiple_click: 1,
            last_click_time: None,
            ignore_flags: false,
            flags: CGEventFlags::CGEventFlagNull,
        }
    }
}

impl MouseControllable for Enigo {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn mouse_move_to(&mut self, x: i32, y: i32) -> crate::ResultType {
        // For absolute movement, we don't set delta values
        // This maintains backward compatibility
        self.mouse_move_to_impl(x, y, None)
    }

    fn mouse_move_relative(&mut self, x: i32, y: i32) -> crate::ResultType {
        let (display_width, display_height) = Self::main_display_size();
        let (current_x, y_inv) = Self::mouse_location_raw_coords();
        let current_y = (display_height as i32) - y_inv;
        // Use saturating arithmetic to prevent overflow/wraparound
        let mut new_x = current_x.saturating_add(x);
        let mut new_y = current_y.saturating_add(y);

        // Define screen center and edge margins for cursor reset
        let center_x = (display_width / 2) as i32;
        let center_y = (display_height / 2) as i32;
        // Margin calculation: 5% of the smaller screen dimension with a minimum of 50px.
        // This provides a comfortable buffer zone to detect when the cursor is approaching
        // screen edges, allowing us to reset it to center before it hits the boundary.
        // This ensures continuous relative mouse movement without getting stuck at edges.
        let margin = (display_width.min(display_height) / 20).max(50) as i32;

        // Check if cursor is approaching screen boundaries
        // Use saturating_sub to prevent negative thresholds on very small displays
        let right = (display_width as i32).saturating_sub(margin);
        let bottom = (display_height as i32).saturating_sub(margin);
        let near_edge = new_x < margin || new_x > right || new_y < margin || new_y > bottom;

        if near_edge {
            // Reset cursor to screen center to allow continuous movement
            // The delta values are still passed correctly for games/apps
            new_x = center_x;
            new_y = center_y;
        }

        // Clamp to screen bounds as a safety measure.
        // Use saturating_sub(1) to ensure coordinates don't exceed the last valid pixel.
        let max_x = (display_width as i32).saturating_sub(1).max(0);
        let max_y = (display_height as i32).saturating_sub(1).max(0);
        new_x = new_x.clamp(0, max_x);
        new_y = new_y.clamp(0, max_y);

        // Pass delta values for relative movement
        // This is critical for browser Pointer Lock API support
        // The delta fields (MOUSE_EVENT_DELTA_X/Y) are used by browsers
        // to calculate movementX/Y in Pointer Lock mode
        self.mouse_move_to_impl(new_x, new_y, Some((x, y)))
    }

    fn mouse_down(&mut self, button: MouseButton) -> crate::ResultType {
        let now = std::time::Instant::now();
        if let Some(t) = self.last_click_time {
            if t.elapsed().as_millis() as u32 <= self.double_click_interval {
                self.multiple_click += 1;
            } else {
                self.multiple_click = 1;
            }
        }
        self.last_click_time = Some(now);
        let (current_x, current_y) = Self::mouse_location();
        let (button, event_type, btn_value) = match button {
            MouseButton::Left => (CGMouseButton::Left, CGEventType::LeftMouseDown, None),
            MouseButton::Middle => (CGMouseButton::Center, CGEventType::OtherMouseDown, None),
            MouseButton::Right => (CGMouseButton::Right, CGEventType::RightMouseDown, None),
            MouseButton::Back => (
                CGMouseButton::Left,
                CGEventType::OtherMouseDown,
                Some(MOUSE_EVENT_BUTTON_NUMBER_BACK),
            ),
            MouseButton::Forward => (
                CGMouseButton::Left,
                CGEventType::OtherMouseDown,
                Some(MOUSE_EVENT_BUTTON_NUMBER_FORWARD),
            ),
            _ => {
                return Err(format!("unsupported mouse button {button:?}").into());
            }
        };
        let dest = CGPoint::new(current_x as f64, current_y as f64);
        let Some(src) = self.event_source.as_ref() else {
            return Err("macOS event source is unavailable".into());
        };
        let event = CGEvent::new_mouse_event(src.clone(), event_type, dest, button)
            .map_err(|err| format!("could not construct macOS mouse-down event: {err:?}"))?;
        if self.multiple_click > 1 {
            event.set_integer_value_field(EventField::MOUSE_EVENT_CLICK_STATE, self.multiple_click);
        }
        if let Some(v) = btn_value {
            event.set_integer_value_field(EventField::MOUSE_EVENT_BUTTON_NUMBER, v);
        }
        self.post(event);
        Ok(())
    }

    fn mouse_up(&mut self, button: MouseButton) -> crate::ResultType {
        let (current_x, current_y) = Self::mouse_location();
        let (button, event_type, btn_value) = match button {
            MouseButton::Left => (CGMouseButton::Left, CGEventType::LeftMouseUp, None),
            MouseButton::Middle => (CGMouseButton::Center, CGEventType::OtherMouseUp, None),
            MouseButton::Right => (CGMouseButton::Right, CGEventType::RightMouseUp, None),
            MouseButton::Back => (
                CGMouseButton::Left,
                CGEventType::OtherMouseUp,
                Some(MOUSE_EVENT_BUTTON_NUMBER_BACK),
            ),
            MouseButton::Forward => (
                CGMouseButton::Left,
                CGEventType::OtherMouseUp,
                Some(MOUSE_EVENT_BUTTON_NUMBER_FORWARD),
            ),
            _ => {
                return Err(format!("unsupported mouse button {button:?}").into());
            }
        };
        let dest = CGPoint::new(current_x as f64, current_y as f64);
        let Some(src) = self.event_source.as_ref() else {
            return Err("macOS event source is unavailable".into());
        };
        let event = CGEvent::new_mouse_event(src.clone(), event_type, dest, button)
            .map_err(|err| format!("could not construct macOS mouse-up event: {err:?}"))?;
        if self.multiple_click > 1 {
            event.set_integer_value_field(EventField::MOUSE_EVENT_CLICK_STATE, self.multiple_click);
        }
        if let Some(v) = btn_value {
            event.set_integer_value_field(EventField::MOUSE_EVENT_BUTTON_NUMBER, v);
        }
        self.post(event);
        Ok(())
    }

    fn mouse_click(&mut self, button: MouseButton) -> crate::ResultType {
        self.mouse_down(button)?;
        if let Err(err) = self.mouse_up(button) {
            log::error!("macOS mouse click could not submit its release: {err}");
            std::process::abort();
        }
        Ok(())
    }

    fn mouse_scroll_x(&mut self, length: i32) -> crate::ResultType {
        let scroll_direction = if length < 0 { 1 } else { -1 };
        let length = checked_scroll_magnitude(length, MAX_SCROLL_LENGTH)?;

        let Some(src) = self.event_source.as_ref() else {
            return Err("macOS event source is unavailable".into());
        };
        for _ in 0..length {
            unsafe {
                let mouse_ev = CGEventCreateScrollWheelEvent(
                    &src,
                    ScrollUnit::Line,
                    2, // CGWheelCount 1 = y 2 = xy 3 = xyz
                    0,
                    scroll_direction,
                );
                if mouse_ev.is_null() {
                    return Err("could not construct macOS horizontal scroll event".into());
                }
                CGEventPost(CGEventTapLocation::HID, mouse_ev);
                CFRelease(mouse_ev as *const std::ffi::c_void);
            }
        }
        Ok(())
    }

    fn mouse_scroll_y(&mut self, length: i32) -> crate::ResultType {
        let scroll_direction = if length < 0 { 1 } else { -1 };
        let length = checked_scroll_magnitude(length, MAX_SCROLL_LENGTH)?;

        let Some(src) = self.event_source.as_ref() else {
            return Err("macOS event source is unavailable".into());
        };
        for _ in 0..length {
            unsafe {
                let mouse_ev = CGEventCreateScrollWheelEvent(
                    &src,
                    ScrollUnit::Line,
                    1, // CGWheelCount 1 = y 2 = xy 3 = xyz
                    scroll_direction,
                );
                if mouse_ev.is_null() {
                    return Err("could not construct macOS vertical scroll event".into());
                }
                CGEventPost(CGEventTapLocation::HID, mouse_ev);
                CFRelease(mouse_ev as *const std::ffi::c_void);
            }
        }
        Ok(())
    }
}

// https://stackoverflow.
// com/questions/1918841/how-to-convert-ascii-character-to-cgkeycode

impl KeyboardControllable for Enigo {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn keyboard_state(&mut self) -> Result<KeyboardState, Box<dyn std::error::Error>> {
        if self.event_source.is_none() {
            return Err("macOS event source is unavailable".into());
        }
        let state_id = CGEventSourceStateID::HIDSystemState as i32;
        let modifiers = ModifierKey::ALL.map(|key| {
            let code = match key {
                ModifierKey::Shift => kVK_Shift,
                ModifierKey::Control => kVK_Control,
                ModifierKey::Alt => kVK_Option,
                ModifierKey::Meta => kVK_Command,
                ModifierKey::RightShift => kVK_RightShift,
                ModifierKey::RightControl => kVK_RightControl,
                ModifierKey::RightAlt => kVK_RightOption,
                ModifierKey::RightMeta => kVK_RIGHT_COMMAND,
            };
            unsafe { CGEventSourceKeyState(state_id, code) }
        });
        let flags = unsafe { CGEventSourceFlagsState(state_id) };
        Ok(KeyboardState::from_parts(modifiers,
            flags & CGEventFlags::CGEventFlagAlphaShift.bits() != 0, NumLockState::NotPresent))
    }
}

impl Enigo {
    fn pressed_buttons() -> usize {
        if let Some(ns_event) = Class::get("NSEvent") {
            unsafe { msg_send![ns_event, pressedMouseButtons] }
        } else {
            0
        }
    }

    /// Internal implementation for mouse movement with optional delta values.
    ///
    /// The `delta` parameter is crucial for browser Pointer Lock API support.
    /// When a browser enters Pointer Lock mode, it reads mouse delta values
    /// (MOUSE_EVENT_DELTA_X/Y) directly from CGEvent to calculate movementX/Y.
    /// Without setting these fields, the browser sees zero movement.
    fn mouse_move_to_impl(
        &mut self,
        x: i32,
        y: i32,
        delta: Option<(i32, i32)>,
    ) -> crate::ResultType {
        let pressed = Self::pressed_buttons();

        // Determine event type and corresponding mouse button based on pressed buttons.
        // The CGMouseButton must match the event type for drag events.
        let (event_type, button) = if pressed & 1 > 0 {
            (CGEventType::LeftMouseDragged, CGMouseButton::Left)
        } else if pressed & 2 > 0 {
            (CGEventType::RightMouseDragged, CGMouseButton::Right)
        } else if pressed & 4 > 0 {
            (CGEventType::OtherMouseDragged, CGMouseButton::Center)
        } else {
            (CGEventType::MouseMoved, CGMouseButton::Left) // Button doesn't matter for MouseMoved
        };

        let dest = CGPoint::new(x as f64, y as f64);
        let Some(src) = self.event_source.as_ref() else {
            return Err("macOS event source is unavailable".into());
        };
        let event = CGEvent::new_mouse_event(src.clone(), event_type, dest, button)
            .map_err(|err| format!("could not construct macOS mouse-move event: {err:?}"))?;
        if let Some((dx, dy)) = delta {
            event.set_integer_value_field(EventField::MOUSE_EVENT_DELTA_X, dx as i64);
            event.set_integer_value_field(EventField::MOUSE_EVENT_DELTA_Y, dy as i64);
        }
        self.post(event);
        Ok(())
    }

    /// Fetches the `(width, height)` in pixels of the main display
    pub fn main_display_size() -> (usize, usize) {
        let display_id = unsafe { CGMainDisplayID() };
        let width = unsafe { CGDisplayPixelsWide(display_id) };
        let height = unsafe { CGDisplayPixelsHigh(display_id) };
        (width, height)
    }

    /// Returns the current mouse location in Cocoa coordinates which have Y
    /// inverted from the Carbon coordinates used in the rest of the API.
    /// This function exists so that mouse_move_relative only has to fetch
    /// the screen size once.
    fn mouse_location_raw_coords() -> (i32, i32) {
        if let Some(ns_event) = Class::get("NSEvent") {
            let pt: NSPoint = unsafe { msg_send![ns_event, mouseLocation] };
            (pt.x as i32, pt.y as i32)
        } else {
            (0, 0)
        }
    }

    /// The mouse coordinates in points, only works on the main display
    pub fn mouse_location() -> (i32, i32) {
        let (x, y_inv) = Self::mouse_location_raw_coords();
        let (_, display_height) = Self::main_display_size();
        (x, (display_height as i32) - y_inv)
    }

    #[inline]
    fn mouse_scroll_impl(
        &mut self,
        length: i32,
        is_track_pad: bool,
        is_horizontal: bool,
    ) -> crate::ResultType {
        let scroll_direction = if length < 0 { 1 } else { -1 };
        let length = checked_scroll_magnitude(length, MAX_SCROLL_LENGTH)?;

        let Some(src) = self.event_source.as_ref() else {
            return Err("macOS event source is unavailable".into());
        };
        for _ in 0..length {
            unsafe {
                let units = if is_track_pad {
                    ScrollUnit::Pixel
                } else {
                    ScrollUnit::Line
                };
                let mouse_ev = if is_horizontal {
                    CGEventCreateScrollWheelEvent(
                        &src,
                        units,
                        2, // CGWheelCount 1 = y 2 = xy 3 = xyz
                        0,
                        scroll_direction,
                    )
                } else {
                    CGEventCreateScrollWheelEvent(
                        &src,
                        units,
                        1, // CGWheelCount 1 = y 2 = xy 3 = xyz
                        scroll_direction,
                    )
                };
                if mouse_ev.is_null() {
                    return Err("could not construct macOS scroll event".into());
                }
                CGEventPost(CGEventTapLocation::HID, mouse_ev);
                CFRelease(mouse_ev as *const std::ffi::c_void);
            }
        }
        Ok(())
    }

    /// handle scroll vertically
    pub fn mouse_scroll_y(&mut self, length: i32, is_track_pad: bool) -> crate::ResultType {
        self.mouse_scroll_impl(length, is_track_pad, false)
    }

    /// handle scroll horizontally
    pub fn mouse_scroll_x(&mut self, length: i32, is_track_pad: bool) -> crate::ResultType {
        self.mouse_scroll_impl(length, is_track_pad, true)
    }

    /// Submits text as matched key-down/key-up pairs after constructing both events.
    pub fn key_sequence_complete(&mut self, sequence: &str) -> crate::ResultType {
        use unicode_segmentation::UnicodeSegmentation;

        let Some(src) = self.event_source.as_ref() else {
            return Err("macOS event source is unavailable".into());
        };
        for cluster in UnicodeSegmentation::graphemes(sequence, true) {
            let down = CGEvent::new_keyboard_event(src.clone(), 0, true)
                .map_err(|err| format!("could not construct macOS text key-down: {err:?}"))?;
            let up = CGEvent::new_keyboard_event(src.clone(), 0, false)
                .map_err(|err| format!("could not construct macOS text key-up: {err:?}"))?;
            down.set_string(cluster);
            self.post(down);
            self.post(up);
        }
        Ok(())
    }
}

unsafe impl Send for Enigo {}
