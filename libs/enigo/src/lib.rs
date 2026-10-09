//! RustDesk's platform input backend provides mouse operations and keyboard-state queries.
//! Linux and macOS expose result-bearing text submission through their concrete backends.
//! Physical keyboard input belongs to the application's owned rdev input path.
#![deny(missing_docs)]

#[cfg(target_os = "macos")]
#[macro_use]
extern crate objc;

// TODO(dustin) use interior mutability not &mut self

#[cfg(target_os = "windows")]
mod win;
#[cfg(target_os = "windows")]
pub use win::Enigo;
#[cfg(target_os = "windows")]
pub use win::ENIGO_INPUT_EXTRA_VALUE;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::Enigo;
#[cfg(target_os = "macos")]
pub use macos::ENIGO_INPUT_EXTRA_VALUE;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use crate::linux::Enigo;

#[cfg(feature = "with_serde")]
#[macro_use]
extern crate serde_derive;

#[cfg(feature = "with_serde")]
extern crate serde;

///
pub type ResultType = std::result::Result<(), Box<dyn std::error::Error>>;

mod keyboard_state;
pub use keyboard_state::{KeyboardState, ModifierKey, NumLockState};

pub(crate) fn checked_scroll_magnitude(
    length: i32,
    maximum: i32,
) -> std::result::Result<i32, Box<dyn std::error::Error>> {
    let magnitude = length
        .checked_abs()
        .ok_or_else(|| "scroll length is not representable".to_owned())?;
    if magnitude > maximum {
        return Err(format!("scroll length exceeds backend maximum {maximum}").into());
    }
    Ok(magnitude)
}

#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
/// MouseButton represents a mouse button,
/// and is used in for example
/// [mouse_click](trait.MouseControllable.html#tymethod.mouse_click).
/// WARNING: Types with the prefix Scroll
/// IS NOT intended to be used, and may not work on
/// all operating systems.
pub enum MouseButton {
    /// Left mouse button
    Left,
    /// Middle mouse button
    Middle,
    /// Right mouse button
    Right,
    /// Back mouse button
    Back,
    /// Forward mouse button
    Forward,

    /// Scroll up button
    ScrollUp,
    /// Left right button
    ScrollDown,
    /// Left right button
    ScrollLeft,
    /// Left right button
    ScrollRight,
}

/// Representing an interface and a set of mouse functions every
/// operating system implementation _should_ implement.
pub trait MouseControllable {
    // https://stackoverflow.com/a/33687996
    /// Offer the ability to confer concrete type.
    fn as_any(&self) -> &dyn std::any::Any;

    /// Offer the ability to confer concrete type.
    fn as_mut_any(&mut self) -> &mut dyn std::any::Any;

    /// Lets the mouse cursor move to the specified x and y coordinates.
    ///
    /// The topleft corner of your monitor screen is x=0 y=0. Move
    /// the cursor down the screen by increasing the y and to the right
    /// by increasing x coordinate.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use enigo::*;
    /// let mut enigo = Enigo::new();
    /// enigo.mouse_move_to(500, 200).unwrap();
    /// ```
    fn mouse_move_to(&mut self, x: i32, y: i32) -> ResultType;

    /// Lets the mouse cursor move the specified amount in the x and y
    /// direction.
    ///
    /// The amount specified in the x and y parameters are added to the
    /// current location of the mouse cursor. A positive x values lets
    /// the mouse cursor move an amount of `x` pixels to the right. A negative
    /// value for `x` lets the mouse cursor go to the left. A positive value
    /// of y
    /// lets the mouse cursor go down, a negative one lets the mouse cursor go
    /// up.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use enigo::*;
    /// let mut enigo = Enigo::new();
    /// enigo.mouse_move_relative(100, 100).unwrap();
    /// ```
    fn mouse_move_relative(&mut self, x: i32, y: i32) -> ResultType;

    /// Push down one of the mouse buttons
    ///
    /// Push down the mouse button specified by the parameter `button` of
    /// type [MouseButton](enum.MouseButton.html)
    /// and holds it until it is released by
    /// [mouse_up](trait.MouseControllable.html#tymethod.mouse_up).
    /// Calls to [mouse_move_to](trait.MouseControllable.html#tymethod.
    /// mouse_move_to) or
    /// [mouse_move_relative](trait.MouseControllable.html#tymethod.
    /// mouse_move_relative)
    /// will work like expected and will e.g. drag widgets or highlight text.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use enigo::*;
    /// let mut enigo = Enigo::new();
    /// enigo.mouse_down(MouseButton::Left).unwrap();
    /// ```
    fn mouse_down(&mut self, button: MouseButton) -> ResultType;

    /// Lift up a pushed down mouse button
    ///
    /// Lift up a previously pushed down button (by invoking
    /// [mouse_down](trait.MouseControllable.html#tymethod.mouse_down)).
    /// If the button was not pushed down or consecutive calls without
    /// invoking [mouse_down](trait.MouseControllable.html#tymethod.mouse_down)
    /// will emit lift up events. It depends on the
    /// operating system whats actually happening – my guess is it will just
    /// get ignored.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use enigo::*;
    /// let mut enigo = Enigo::new();
    /// enigo.mouse_up(MouseButton::Right).unwrap();
    /// ```
    fn mouse_up(&mut self, button: MouseButton) -> ResultType;

    /// Click a mouse button
    ///
    /// it's essentially just a consecutive invocation of
    /// [mouse_down](trait.MouseControllable.html#tymethod.mouse_down) followed
    /// by a [mouse_up](trait.MouseControllable.html#tymethod.mouse_up). Just
    /// for
    /// convenience.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use enigo::*;
    /// let mut enigo = Enigo::new();
    /// enigo.mouse_click(MouseButton::Right).unwrap();
    /// ```
    fn mouse_click(&mut self, button: MouseButton) -> ResultType;

    /// Scroll the mouse (wheel) left or right
    ///
    /// Positive numbers for length lets the mouse wheel scroll to the right
    /// and negative ones to the left. The value that is specified translates
    /// to `lines` defined by the operating system and is essentially one 15°
    /// (click)rotation on the mouse wheel. How many lines it moves depends
    /// on the current setting in the operating system.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use enigo::*;
    /// let mut enigo = Enigo::new();
    /// enigo.mouse_scroll_x(2).unwrap();
    /// ```
    fn mouse_scroll_x(&mut self, length: i32) -> ResultType;

    /// Scroll the mouse (wheel) up or down
    ///
    /// Positive numbers for length lets the mouse wheel scroll down
    /// and negative ones up. The value that is specified translates
    /// to `lines` defined by the operating system and is essentially one 15°
    /// (click)rotation on the mouse wheel. How many lines it moves depends
    /// on the current setting in the operating system.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use enigo::*;
    /// let mut enigo = Enigo::new();
    /// enigo.mouse_scroll_y(2).unwrap();
    /// ```
    fn mouse_scroll_y(&mut self, length: i32) -> ResultType;
}

/// A key on the keyboard.
/// For alphabetical keys, use Key::Layout for a system independent key.
/// If a key is missing, you can use the raw keycode with Key::Raw.
#[cfg_attr(feature = "with_serde", derive(Serialize, Deserialize))]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Key {
    /// alt key on Linux and Windows (option key on macOS)
    Alt,
    /// backspace key
    Backspace,
    /// caps lock key
    CapsLock,
    // #[deprecated(since = "0.0.12", note = "now renamed to Meta")]
    /// command key on macOS (super key on Linux, windows key on Windows)
    Command,
    /// control key
    Control,
    /// delete key
    Delete,
    /// down arrow key
    DownArrow,
    /// end key
    End,
    /// escape key (esc)
    Escape,
    /// F1 key
    F1,
    /// F10 key
    F10,
    /// F11 key
    F11,
    /// F12 key
    F12,
    /// F2 key
    F2,
    /// F3 key
    F3,
    /// F4 key
    F4,
    /// F5 key
    F5,
    /// F6 key
    F6,
    /// F7 key
    F7,
    /// F8 key
    F8,
    /// F9 key
    F9,
    /// home key
    Home,
    /// left arrow key
    LeftArrow,
    /// meta key (also known as "windows", "super", and "command")
    Meta,
    /// option key on macOS (alt key on Linux and Windows)
    Option, // deprecated, use Alt instead
    /// page down key
    PageDown,
    /// page up key
    PageUp,
    /// return key
    Return,
    /// right arrow key
    RightArrow,
    /// shift key
    Shift,
    /// space key
    Space,
    // #[deprecated(since = "0.0.12", note = "now renamed to Meta")]
    /// super key on linux (command key on macOS, windows key on Windows)
    Super,
    /// tab key (tabulator)
    Tab,
    /// up arrow key
    UpArrow,
    // #[deprecated(since = "0.0.12", note = "now renamed to Meta")]
    /// windows key on Windows (super key on Linux, command key on macOS)
    Windows,
    ///
    Numpad0,
    ///
    Numpad1,
    ///
    Numpad2,
    ///
    Numpad3,
    ///
    Numpad4,
    ///
    Numpad5,
    ///
    Numpad6,
    ///
    Numpad7,
    ///
    Numpad8,
    ///
    Numpad9,
    ///
    Cancel,
    ///
    Clear,
    ///
    Pause,
    ///
    Kana,
    ///
    Hangul,
    ///
    Junja,
    ///
    Final,
    ///
    Hanja,
    ///
    Kanji,
    ///
    Convert,
    ///
    Select,
    ///
    Print,
    ///
    Execute,
    ///
    Snapshot,
    ///
    Insert,
    ///
    Help,
    ///
    Sleep,
    ///
    Separator,
    ///
    VolumeUp,
    ///
    VolumeDown,
    ///
    Mute,
    ///
    Scroll,
    /// scroll lock
    NumLock,
    ///
    RWin,
    ///
    Apps,
    ///
    Multiply,
    ///
    Add,
    ///
    Subtract,
    ///
    Decimal,
    ///
    Divide,
    ///
    Equals,
    ///
    NumpadEnter,
    ///
    RightShift,
    ///
    RightControl,
    ///
    RightAlt,
    ///
    /// Function, /// mac
    /// keyboard layout dependent key
    Layout(char),
    /// raw keycode eg 0x38
    Raw(u16),
}

/// Cross-platform keyboard-state access.
pub trait KeyboardControllable {
    // https://stackoverflow.com/a/33687996
    /// Offer the ability to confer concrete type.
    fn as_any(&self) -> &dyn std::any::Any;

    /// Offer the ability to confer concrete type.
    fn as_mut_any(&mut self) -> &mut dyn std::any::Any;

    /// Collect all supported keyboard state before an operation starts.
    /// Unavailable native state returns an error; no partial state is published.
    fn keyboard_state(&mut self) -> std::result::Result<KeyboardState, Box<dyn std::error::Error>>;
}

#[cfg(any(target_os = "android", target_os = "ios"))]
struct Enigo;

impl Enigo {
    /// Constructs a new `Enigo` instance.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use enigo::*;
    /// let mut enigo = Enigo::new();
    /// ```
    pub fn new() -> Self {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        return Enigo {};
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        Self::default()
    }
}

use std::fmt;

impl fmt::Debug for Enigo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Enigo")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scroll_magnitude_rejects_overflow_and_backend_excess() {
        assert_eq!(checked_scroll_magnitude(64, 64).unwrap(), 64);
        assert_eq!(checked_scroll_magnitude(-64, 64).unwrap(), 64);
        assert!(checked_scroll_magnitude(65, 64).is_err());
        assert!(checked_scroll_magnitude(-65, 64).is_err());
        assert!(checked_scroll_magnitude(i32::MIN, 64).is_err());
    }
}
