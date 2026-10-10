use super::xdo::EnigoXdo;
use crate::{KeyboardState, KeyboardControllable, MouseButton, MouseControllable};

/// Linux input through the owned XDO backend.
#[derive(Default)]
pub struct Enigo {
    xdo: EnigoXdo,
}

impl Enigo {
    /// Checks ordinary input admission without submitting native requests.
    /// Pending text cleanup refuses admission; release-only mouse cleanup remains available.
    pub fn ensure_input_ready(&self) -> crate::ResultType {
        self.xdo.ensure_input_ready()
    }

    /// Get delay of xdo implementation.
    pub fn delay(&self) -> u64 {
        self.xdo.delay()
    }
    /// Set delay of xdo implementation.
    pub fn set_delay(&mut self, delay: u64) {
        self.xdo.set_delay(delay)
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
        self.xdo.mouse_move_to(x, y)
    }
    fn mouse_move_relative(&mut self, x: i32, y: i32) -> crate::ResultType {
        self.xdo.mouse_move_relative(x, y)
    }
    fn mouse_down(&mut self, button: MouseButton) -> crate::ResultType {
        self.xdo.mouse_down(button)
    }
    fn mouse_up(&mut self, button: MouseButton) -> crate::ResultType {
        self.xdo.mouse_up(button)
    }
    fn mouse_click(&mut self, button: MouseButton) -> crate::ResultType {
        self.xdo.mouse_click(button)
    }
    fn mouse_scroll_x(&mut self, length: i32) -> crate::ResultType {
        self.xdo.mouse_scroll_x(length)
    }
    fn mouse_scroll_y(&mut self, length: i32) -> crate::ResultType {
        self.xdo.mouse_scroll_y(length)
    }
}

impl Enigo {
    /// Types text and returns the X11 injector's synchronous submission status.
    pub fn key_sequence_result(&mut self, sequence: &str) -> crate::ResultType {
        self.xdo.key_sequence_result(sequence)
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
        self.xdo.keyboard_state()
    }
}
