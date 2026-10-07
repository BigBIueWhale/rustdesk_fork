use super::xdo::EnigoXdo;
use crate::{
    checked_scroll_magnitude, Key, KeyboardControllable, MouseButton, MouseControllable, ResultType,
};
use std::io::Read;

pub type CustomKeyboard = Box<dyn KeyboardControllable + Send>;
pub type CustomMouce = Box<dyn MouseControllable + Send>;
const MAX_SCROLL_LENGTH: i32 = 64;

/// The main struct for handling the event emitting
// #[derive(Default)]
pub struct Enigo {
    xdo: EnigoXdo,
    is_x11: bool,
    custom_keyboard: Option<CustomKeyboard>,
    custom_mouse: Option<CustomMouce>,
}

impl Enigo {
    /// Get delay of xdo implementation.
    pub fn delay(&self) -> u64 {
        self.xdo.delay()
    }
    /// Set delay of xdo implementation.
    pub fn set_delay(&mut self, delay: u64) {
        self.xdo.set_delay(delay)
    }
    /// Set custom keyboard.
    pub fn set_custom_keyboard(&mut self, custom_keyboard: CustomKeyboard) {
        self.custom_keyboard = Some(custom_keyboard)
    }
    /// Set custom mouse.
    pub fn set_custom_mouse(&mut self, custom_mouse: CustomMouce) {
        self.custom_mouse = Some(custom_mouse)
    }
    /// Get custom keyboard.
    pub fn get_custom_keyboard(&mut self) -> &mut Option<CustomKeyboard> {
        &mut self.custom_keyboard
    }
    /// Get custom mouse.
    pub fn get_custom_mouse(&mut self) -> &mut Option<CustomMouce> {
        &mut self.custom_mouse
    }
}

impl Default for Enigo {
    fn default() -> Self {
        let is_x11 = hbb_common::platform::linux::is_x11_or_headless();
        Self {
            is_x11,
            custom_keyboard: None,
            custom_mouse: None,
            xdo: EnigoXdo::default(),
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
        if self.is_x11 {
            self.xdo.mouse_move_to(x, y)
        } else {
            if let Some(mouse) = &mut self.custom_mouse {
                mouse.mouse_move_to(x, y)
            } else {
                Err("no mouse injector is available".into())
            }
        }
    }
    fn mouse_move_relative(&mut self, x: i32, y: i32) -> crate::ResultType {
        if self.is_x11 {
            self.xdo.mouse_move_relative(x, y)
        } else {
            if let Some(mouse) = &mut self.custom_mouse {
                mouse.mouse_move_relative(x, y)
            } else {
                Err("no mouse injector is available".into())
            }
        }
    }
    fn mouse_down(&mut self, button: MouseButton) -> crate::ResultType {
        if self.is_x11 {
            self.xdo.mouse_down(button)
        } else {
            if let Some(mouse) = &mut self.custom_mouse {
                mouse.mouse_down(button)
            } else {
                Err("no mouse injector is available".into())
            }
        }
    }
    fn mouse_up(&mut self, button: MouseButton) -> crate::ResultType {
        if self.is_x11 {
            self.xdo.mouse_up(button)
        } else {
            if let Some(mouse) = &mut self.custom_mouse {
                mouse.mouse_up(button)
            } else {
                Err("no mouse injector is available".into())
            }
        }
    }
    fn mouse_click(&mut self, button: MouseButton) -> crate::ResultType {
        if self.is_x11 {
            self.xdo.mouse_click(button)
        } else {
            if let Some(mouse) = &mut self.custom_mouse {
                mouse.mouse_click(button)
            } else {
                Err("no mouse injector is available".into())
            }
        }
    }
    fn mouse_scroll_x(&mut self, length: i32) -> crate::ResultType {
        checked_scroll_magnitude(length, MAX_SCROLL_LENGTH)?;
        if self.is_x11 {
            self.xdo.mouse_scroll_x(length)
        } else {
            if let Some(mouse) = &mut self.custom_mouse {
                mouse.mouse_scroll_x(length)
            } else {
                Err("no mouse injector is available".into())
            }
        }
    }
    fn mouse_scroll_y(&mut self, length: i32) -> crate::ResultType {
        checked_scroll_magnitude(length, MAX_SCROLL_LENGTH)?;
        if self.is_x11 {
            self.xdo.mouse_scroll_y(length)
        } else {
            if let Some(mouse) = &mut self.custom_mouse {
                mouse.mouse_scroll_y(length)
            } else {
                Err("no mouse injector is available".into())
            }
        }
    }
}

impl Enigo {
    /// Types text and returns the X11 injector's synchronous submission status.
    pub fn key_sequence_result(&mut self, sequence: &str) -> crate::ResultType {
        if self.is_x11 {
            self.xdo.key_sequence_result(sequence)
        } else {
            Err("result-bearing text input is unavailable outside X11".into())
        }
    }
}

fn get_led_state(key: Key) -> bool {
    let led_file = match key {
        // FIXME: the file may be /sys/class/leds/input2 or input5 ...
        Key::CapsLock => "/sys/class/leds/input1::capslock/brightness",
        Key::NumLock => "/sys/class/leds/input1::numlock/brightness",
        _ => {
            return false;
        }
    };

    let status = if let Ok(mut file) = std::fs::File::open(&led_file) {
        let mut content = String::new();
        if let Err(err) = file.read_to_string(&mut content) {
            log::warn!("Could not read keyboard LED state from {led_file}: {err}");
            return false;
        }
        let status = content.trim_end().to_string().parse::<i32>().unwrap_or(0);
        status
    } else {
        0
    };
    status == 1
}

impl KeyboardControllable for Enigo {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn get_key_state(&mut self, key: Key) -> bool {
        if self.is_x11 {
            self.xdo.get_key_state(key)
        } else {
            if let Some(keyboard) = &mut self.custom_keyboard {
                keyboard.get_key_state(key)
            } else {
                get_led_state(key)
            }
        }
    }

    /// Warning: Get 6^ in French.
    fn key_sequence(&mut self, sequence: &str) {
        if self.is_x11 {
            self.xdo.key_sequence(sequence)
        } else {
            if let Some(keyboard) = &mut self.custom_keyboard {
                keyboard.key_sequence(sequence)
            } else {
                log::warn!("Enigo::key_sequence: no custom_keyboard set for Wayland!");
            }
        }
    }

    fn key_down(&mut self, key: Key) -> crate::ResultType {
        if self.is_x11 {
            self.xdo.key_down(key)
        } else {
            if let Some(keyboard) = &mut self.custom_keyboard {
                keyboard.key_down(key)
            } else {
                log::warn!("Enigo::key_down: no custom_keyboard set for Wayland!");
                Ok(())
            }
        }
    }
    fn key_up(&mut self, key: Key) {
        if self.is_x11 {
            self.xdo.key_up(key)
        } else {
            if let Some(keyboard) = &mut self.custom_keyboard {
                keyboard.key_up(key)
            } else {
                log::warn!("Enigo::key_up: no custom_keyboard set for Wayland!");
            }
        }
    }
    fn key_click(&mut self, key: Key) {
        if self.is_x11 {
            self.xdo.key_click(key);
        } else {
            if let Some(keyboard) = &mut self.custom_keyboard {
                keyboard.key_click(key);
            } else {
                log::warn!("Enigo::key_click: no custom_keyboard set for Wayland!");
            }
        }
    }
}

#[test]
fn test_key_seq() {
    // Get 6^ in French.
    let mut en = Enigo::new();
    en.key_sequence("^^");
}
