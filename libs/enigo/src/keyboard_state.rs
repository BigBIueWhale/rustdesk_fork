//! Operation-local keyboard observations. Native collection must succeed before input starts.

/// An exact modifier identity, kept separate from its left/right family.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum ModifierKey {
    /// Left Shift.
    Shift,
    /// Left Control.
    Control,
    /// Left Alt/Option.
    Alt,
    /// Left Meta/Command/Windows.
    Meta,
    /// Right Shift.
    RightShift,
    /// Right Control.
    RightControl,
    /// Right Alt/Option (AltGr).
    RightAlt,
    /// Right Meta/Command/Windows.
    RightMeta,
}

impl ModifierKey {
    /// All exact identities, in the order used by native collection.
    pub const ALL: [Self; 8] = [
        Self::Shift,
        Self::Control,
        Self::Alt,
        Self::Meta,
        Self::RightShift,
        Self::RightControl,
        Self::RightAlt,
        Self::RightMeta,
    ];

    /// The physical injector identity for this modifier.
    pub fn rdev_key(self) -> rdev::Key {
        match self {
            Self::Shift => rdev::Key::ShiftLeft,
            Self::Control => rdev::Key::ControlLeft,
            Self::Alt => rdev::Key::Alt,
            Self::Meta => rdev::Key::MetaLeft,
            Self::RightShift => rdev::Key::ShiftRight,
            Self::RightControl => rdev::Key::ControlRight,
            Self::RightAlt => rdev::Key::AltGr,
            Self::RightMeta => rdev::Key::MetaRight,
        }
    }
}

/// NumLock availability and its reported toggle state.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum NumLockState {
    /// NumLock is disabled.
    Off,
    /// NumLock is enabled.
    On,
    /// The platform has no NumLock mode; its keypad remains numeric.
    NotPresent,
}

/// Successfully collected native modifier identities and lock modes.
///
/// X11 reports server logical key state; Windows reports this thread's input-queue
/// state; macOS reports the HID source table. Separate native reads are not atomic
/// against concurrent input. This value belongs to one operation, not a state cache.
#[derive(Debug, Clone, Copy)]
pub struct KeyboardState {
    modifiers: u8,
    caps_lock: bool,
    num_lock: NumLockState,
}

impl KeyboardState {
    pub(crate) fn from_parts(modifiers: [bool; 8], caps_lock: bool, num_lock: NumLockState) -> Self {
        let mut bits = 0;
        for (index, down) in modifiers.iter().enumerate() {
            if *down {
                bits |= 1 << index;
            }
        }
        Self {
            modifiers: bits,
            caps_lock,
            num_lock,
        }
    }

    /// Whether this exact modifier identity was reported down.
    pub fn modifier_down(&self, key: ModifierKey) -> bool {
        self.modifiers & (1 << key as u8) != 0
    }

    /// Whether either side of this modifier's family was reported down.
    pub fn modifier_family_down(&self, key: ModifierKey) -> bool {
        let index = key as u8 & 3;
        self.modifiers & ((1 << index) | (1 << (index + 4))) != 0
    }

    /// The native CapsLock toggle/indicator state.
    pub fn caps_lock_enabled(&self) -> bool {
        self.caps_lock
    }

    /// The native NumLock toggle/indicator state or its explicit platform absence.
    pub fn num_lock(&self) -> NumLockState {
        self.num_lock
    }

    /// Record an accepted input effect for subsequent planning in this operation.
    /// This updates the local plan; it does not query or confirm eventual delivery.
    pub fn record_modifier(&mut self, key: ModifierKey, down: bool) {
        if down {
            self.modifiers |= 1 << key as u8;
        } else {
            self.modifiers &= !(1 << key as u8);
        }
    }
}
