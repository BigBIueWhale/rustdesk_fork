use super::*;
use crate::input::*;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use crate::whiteboard;
#[cfg(target_os = "macos")]
use dispatch::Queue;
use enigo::{Enigo, Key, KeyboardControllable, MouseButton, MouseControllable};
use hbb_common::{
    get_time,
    message_proto::{pointer_device_event::Union::TouchEvent, touch_event::Union::ScaleUpdate},
    protobuf::EnumOrUnknown,
};
use rdev::{self, EventType, Key as RdevKey, KeyCode, RawKey};
#[cfg(target_os = "macos")]
use rdev::{CGEventSourceStateID, CGEventTapLocation, VirtualInput};
#[cfg(target_os = "linux")]
use std::sync::mpsc;
use std::{
    convert::TryFrom,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{self, Duration, Instant},
};

#[cfg(windows)]
use winapi::um::winuser::{
    GetForegroundWindow, GetKeyboardLayout, GetWindowThreadProcessId, MapVirtualKeyExW,
    VkKeyScanExW, MAPVK_VK_TO_VSC_EX, WHEEL_DELTA,
};

const INVALID_CURSOR_POS: i32 = i32::MIN;
const INVALID_DISPLAY_IDX: i32 = -1;
const INPUT_SCROLL_MAX_DELTA: i32 = 64;

fn validate_scroll_delta(delta: i32) -> ResultType<()> {
    let magnitude = delta
        .checked_abs()
        .ok_or_else(|| hbb_common::anyhow::anyhow!("scroll delta is not representable"))?;
    if magnitude > INPUT_SCROLL_MAX_DELTA {
        bail!("scroll delta exceeds the injector limit");
    }
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
type OwnedInputTask = Box<dyn FnOnce() + Send + 'static>;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) struct OwnedInputExecutor {
    requests: std::sync::mpsc::SyncSender<OwnedInputTask>,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl OwnedInputExecutor {
    pub(crate) fn spawn(name: &str) -> Result<Self, String> {
        Self::spawn_with_initializer(name, || {})
    }

    pub(crate) fn spawn_with_initializer(
        name: &str,
        initializer: impl FnOnce() + Send + 'static,
    ) -> Result<Self, String> {
        let (requests, receiver) = std::sync::mpsc::sync_channel::<OwnedInputTask>(1);
        let (ready, initialized) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                initializer();
                if ready.send(()).is_err() {
                    return;
                }
                while let Ok(action) = receiver.recv() {
                    action();
                }
            })
            .map_err(|err| format!("could not start owned-input executor: {err}"))?;
        initialized
            .recv()
            .map_err(|_| "owned-input executor initializer failed".to_owned())?;
        Ok(Self { requests })
    }

    pub(crate) fn dispatch<T: Send + 'static>(
        &self,
        action: impl FnOnce() -> ResultType<T> + Send + 'static,
    ) -> ResultType<T> {
        enum DispatchResult<T> {
            Complete(ResultType<T>),
            Panicked(Box<dyn std::any::Any + Send>),
        }

        let (response, receiver) = std::sync::mpsc::sync_channel(1);
        let task = Box::new(move || {
            let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
                Ok(result) => DispatchResult::Complete(result),
                Err(payload) => DispatchResult::Panicked(payload),
            };
            if response.send(result).is_err() {
                log::error!("owned-input executor caller ended before receiving its result");
            }
        });
        self.requests
            .send(task)
            .map_err(|_| hbb_common::anyhow::anyhow!("owned-input executor is unavailable"))?;
        match receiver.recv() {
            Ok(DispatchResult::Complete(result)) => result,
            Ok(DispatchResult::Panicked(payload)) => std::panic::resume_unwind(payload),
            Err(_) => bail!("owned-input executor ended without a result"),
        }
    }
}

#[cfg(target_os = "windows")]
lazy_static::lazy_static! {
    static ref WINDOWS_OWNED_INPUT_EXECUTOR: Result<OwnedInputExecutor, String> =
        OwnedInputExecutor::spawn_with_initializer("windows-owned-input", || {
            rdev::set_mouse_extra_info(enigo::ENIGO_INPUT_EXTRA_VALUE);
            rdev::set_keyboard_extra_info(enigo::ENIGO_INPUT_EXTRA_VALUE);
        });
}

#[cfg(target_os = "windows")]
pub(crate) fn dispatch_windows_owned_input<T: Send + 'static>(
    action: impl FnOnce() -> ResultType<T> + Send + 'static,
) -> ResultType<T> {
    WINDOWS_OWNED_INPUT_EXECUTOR
        .as_ref()
        .map_err(|err| hbb_common::anyhow::anyhow!(err.clone()))?
        .dispatch(action)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum OwnedPhysicalKey {
    Key(RdevKey),
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OwnedMouseButton {
    Left,
    Middle,
    Right,
    Back,
    Forward,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn owned_mouse_button(event: &MouseEvent) -> Option<(OwnedMouseButton, bool)> {
    let down = match event.mask & MOUSE_TYPE_MASK {
        MOUSE_TYPE_DOWN => true,
        MOUSE_TYPE_UP => false,
        _ => return None,
    };
    let button = match event.mask >> 3 {
        MOUSE_BUTTON_LEFT => OwnedMouseButton::Left,
        MOUSE_BUTTON_WHEEL => OwnedMouseButton::Middle,
        MOUSE_BUTTON_RIGHT => OwnedMouseButton::Right,
        MOUSE_BUTTON_BACK => OwnedMouseButton::Back,
        MOUSE_BUTTON_FORWARD => OwnedMouseButton::Forward,
        _ => return None,
    };
    Some((button, down))
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn enigo_mouse_button(button: OwnedMouseButton) -> MouseButton {
    match button {
        OwnedMouseButton::Left => MouseButton::Left,
        OwnedMouseButton::Middle => MouseButton::Middle,
        OwnedMouseButton::Right => MouseButton::Right,
        OwnedMouseButton::Back => MouseButton::Back,
        OwnedMouseButton::Forward => MouseButton::Forward,
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn owned_physical_key(event: &KeyEvent) -> Option<OwnedPhysicalKey> {
    match event.mode.enum_value_or(KeyboardMode::Legacy) {
        KeyboardMode::Map => match &event.union {
            Some(key_event::Union::Chr(code)) => Some(OwnedPhysicalKey::Key(
                crate::keyboard::keycode_to_rdev_key(*code),
            )),
            _ => None,
        },
        KeyboardMode::Translate => match &event.union {
            Some(key_event::Union::Chr(code)) => {
                #[cfg(target_os = "windows")]
                let key = if code >> 16 == 0 {
                    crate::keyboard::keycode_to_rdev_key(*code)
                } else {
                    rdev::win_key_from_scancode(rdev::vk_to_scancode(code >> 16))
                };
                #[cfg(not(target_os = "windows"))]
                let key = crate::keyboard::keycode_to_rdev_key(*code);
                Some(OwnedPhysicalKey::Key(key))
            }
            Some(key_event::Union::ControlKey(key)) => {
                control_key_to_rdev_key(key.value()).map(OwnedPhysicalKey::Key)
            }
            #[cfg(target_os = "windows")]
            Some(key_event::Union::Win2winHotkey(_)) => None,
            _ => None,
        },
        _ => match &event.union {
            Some(key_event::Union::ControlKey(key)) => {
                control_key_to_rdev_key(key.value()).map(OwnedPhysicalKey::Key)
            }
            _ => None,
        },
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn owned_physical_modifier(key: &OwnedPhysicalKey) -> Option<ControlKey> {
    match key {
        OwnedPhysicalKey::Key(RdevKey::Alt) => Some(ControlKey::Alt),
        OwnedPhysicalKey::Key(RdevKey::AltGr) => Some(ControlKey::RAlt),
        OwnedPhysicalKey::Key(RdevKey::ControlLeft) => Some(ControlKey::Control),
        OwnedPhysicalKey::Key(RdevKey::ControlRight) => Some(ControlKey::RControl),
        OwnedPhysicalKey::Key(RdevKey::MetaLeft) => Some(ControlKey::Meta),
        OwnedPhysicalKey::Key(RdevKey::MetaRight) => Some(ControlKey::RWin),
        OwnedPhysicalKey::Key(RdevKey::ShiftLeft) => Some(ControlKey::Shift),
        OwnedPhysicalKey::Key(RdevKey::ShiftRight) => Some(ControlKey::RShift),
        _ => None,
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn control_key_to_rdev_key(value: i32) -> Option<RdevKey> {
    let key = KEY_MAP.get(&value)?;
    match key {
        Key::Alt | Key::Option => Some(RdevKey::Alt),
        Key::Backspace => Some(RdevKey::Backspace),
        Key::CapsLock => Some(RdevKey::CapsLock),
        Key::Command | Key::Meta | Key::Super | Key::Windows => Some(RdevKey::MetaLeft),
        Key::Control => Some(RdevKey::ControlLeft),
        Key::Delete => Some(RdevKey::Delete),
        Key::DownArrow => Some(RdevKey::DownArrow),
        Key::End => Some(RdevKey::End),
        Key::Escape => Some(RdevKey::Escape),
        Key::F1 => Some(RdevKey::F1),
        Key::F2 => Some(RdevKey::F2),
        Key::F3 => Some(RdevKey::F3),
        Key::F4 => Some(RdevKey::F4),
        Key::F5 => Some(RdevKey::F5),
        Key::F6 => Some(RdevKey::F6),
        Key::F7 => Some(RdevKey::F7),
        Key::F8 => Some(RdevKey::F8),
        Key::F9 => Some(RdevKey::F9),
        Key::F10 => Some(RdevKey::F10),
        Key::F11 => Some(RdevKey::F11),
        Key::F12 => Some(RdevKey::F12),
        Key::Home => Some(RdevKey::Home),
        Key::LeftArrow => Some(RdevKey::LeftArrow),
        Key::PageDown => Some(RdevKey::PageDown),
        Key::PageUp => Some(RdevKey::PageUp),
        Key::Return => Some(RdevKey::Return),
        Key::RightArrow => Some(RdevKey::RightArrow),
        Key::Shift => Some(RdevKey::ShiftLeft),
        Key::Space => Some(RdevKey::Space),
        Key::Tab => Some(RdevKey::Tab),
        Key::UpArrow => Some(RdevKey::UpArrow),
        Key::Numpad0 => Some(RdevKey::Kp0),
        Key::Numpad1 => Some(RdevKey::Kp1),
        Key::Numpad2 => Some(RdevKey::Kp2),
        Key::Numpad3 => Some(RdevKey::Kp3),
        Key::Numpad4 => Some(RdevKey::Kp4),
        Key::Numpad5 => Some(RdevKey::Kp5),
        Key::Numpad6 => Some(RdevKey::Kp6),
        Key::Numpad7 => Some(RdevKey::Kp7),
        Key::Numpad8 => Some(RdevKey::Kp8),
        Key::Numpad9 => Some(RdevKey::Kp9),
        Key::Cancel => Some(RdevKey::Cancel),
        Key::Clear => Some(RdevKey::Clear),
        Key::Pause => Some(RdevKey::Pause),
        Key::Kana => Some(RdevKey::Kana),
        Key::Hangul => Some(RdevKey::Hangul),
        Key::Junja => Some(RdevKey::Junja),
        Key::Final => Some(RdevKey::Final),
        Key::Hanja | Key::Kanji => Some(RdevKey::Hanja),
        Key::Convert => Some(RdevKey::Lang2),
        Key::Select => Some(RdevKey::Select),
        Key::Print => Some(RdevKey::Print),
        Key::Execute => Some(RdevKey::Execute),
        Key::Snapshot => Some(RdevKey::PrintScreen),
        Key::Insert => Some(RdevKey::Insert),
        Key::Help => Some(RdevKey::Help),
        Key::Sleep => Some(RdevKey::Sleep),
        Key::Separator => Some(RdevKey::Separator),
        Key::VolumeUp => Some(RdevKey::VolumeUp),
        Key::VolumeDown => Some(RdevKey::VolumeDown),
        Key::Mute => Some(RdevKey::VolumeMute),
        Key::Scroll => Some(RdevKey::ScrollLock),
        Key::NumLock => Some(RdevKey::NumLock),
        Key::RWin => Some(RdevKey::MetaRight),
        Key::Apps => Some(RdevKey::Apps),
        Key::Multiply => Some(RdevKey::KpMultiply),
        Key::Add => Some(RdevKey::KpPlus),
        Key::Subtract => Some(RdevKey::KpMinus),
        Key::Decimal => Some(RdevKey::KpDecimal),
        Key::Divide => Some(RdevKey::KpDivide),
        Key::Equals => Some(RdevKey::KpEqual),
        Key::NumpadEnter => Some(RdevKey::KpReturn),
        Key::RightShift => Some(RdevKey::ShiftRight),
        Key::RightControl => Some(RdevKey::ControlRight),
        Key::RightAlt => Some(RdevKey::AltGr),
        Key::Layout(_) | Key::Raw(_) => None,
    }
}

#[derive(Default)]
struct StateCursor {
    hcursor: u64,
    cursor_data: Arc<Message>,
    cached_cursor_data: HashMap<u64, Arc<Message>>,
}

impl super::service::Reset for StateCursor {
    fn reset(&mut self) {
        *self = Default::default();
        crate::platform::reset_input_cache();
    }
}

struct StatePos {
    cursor_pos: (i32, i32),
}

impl Default for StatePos {
    fn default() -> Self {
        Self {
            cursor_pos: (INVALID_CURSOR_POS, INVALID_CURSOR_POS),
        }
    }
}

impl super::service::Reset for StatePos {
    fn reset(&mut self) {
        self.cursor_pos = (INVALID_CURSOR_POS, INVALID_CURSOR_POS);
    }
}

impl StatePos {
    #[inline]
    fn is_valid(&self) -> bool {
        self.cursor_pos.0 != INVALID_CURSOR_POS
    }

    #[inline]
    fn is_moved(&self, x: i32, y: i32) -> bool {
        self.is_valid() && (self.cursor_pos.0 != x || self.cursor_pos.1 != y)
    }
}

#[derive(Default)]
struct StateWindowFocus {
    display_idx: i32,
}

impl super::service::Reset for StateWindowFocus {
    fn reset(&mut self) {
        self.display_idx = INVALID_DISPLAY_IDX;
    }
}

impl StateWindowFocus {
    #[inline]
    fn is_valid(&self) -> bool {
        self.display_idx != INVALID_DISPLAY_IDX
    }

    #[inline]
    fn is_changed(&self, disp_idx: i32) -> bool {
        self.is_valid() && self.display_idx != disp_idx
    }
}

#[derive(Default, Clone, Copy)]
struct Input {
    conn: i32,
    time: i64,
    x: i32,
    y: i32,
}

#[derive(Clone, Default)]
pub struct MouseCursorSub {
    inner: ConnInner,
    cached: HashMap<u64, Arc<Message>>,
}

impl From<ConnInner> for MouseCursorSub {
    fn from(inner: ConnInner) -> Self {
        Self {
            inner,
            cached: HashMap::new(),
        }
    }
}

impl Subscriber for MouseCursorSub {
    #[inline]
    fn id(&self) -> i32 {
        self.inner.id()
    }

    #[inline]
    fn send(&mut self, msg: Arc<Message>) {
        if let Some(message::Union::CursorData(cd)) = &msg.union {
            if let Some(msg) = self.cached.get(&cd.id) {
                self.inner.send(msg.clone());
            } else {
                self.inner.send(msg.clone());
                let mut tmp = Message::new();
                // only send id out, require client side cache also
                tmp.set_cursor_id(cd.id);
                self.cached.insert(cd.id, Arc::new(tmp));
            }
        } else {
            self.inner.send(msg);
        }
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
struct LockModesHandler {
    caps_lock_changed: bool,
    num_lock_changed: bool,
}

#[cfg(target_os = "macos")]
struct LockModesHandler;

impl LockModesHandler {
    #[inline]
    fn is_modifier_enabled(key_event: &KeyEvent, modifier: ControlKey) -> bool {
        key_event.modifiers.contains(&modifier.into())
    }

    #[inline]
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    fn new_handler(key_event: &KeyEvent, _is_numpad_key: bool) -> ResultType<Self> {
        #[cfg(any(target_os = "windows", target_os = "linux"))]
        {
            Self::new(key_event, _is_numpad_key)
        }
        #[cfg(target_os = "macos")]
        {
            Self::new(key_event)
        }
    }

    #[cfg(any(target_os = "windows", target_os = "linux"))]
    fn new(key_event: &KeyEvent, is_numpad_key: bool) -> ResultType<Self> {
        let mut en = lock_input_state(&ENIGO, "Enigo state while synchronizing lock modes");
        let event_caps_enabled = Self::is_modifier_enabled(key_event, ControlKey::CapsLock);
        let local_caps_enabled = en.get_key_state(enigo::Key::CapsLock);
        let caps_lock_changed = event_caps_enabled != local_caps_enabled;
        if caps_lock_changed {
            complete_lock_key_click(RdevKey::CapsLock)?;
        }

        let mut num_lock_changed = false;
        #[allow(unused)]
        let mut event_num_enabled = false;
        if is_numpad_key {
            let local_num_enabled = en.get_key_state(enigo::Key::NumLock);
            event_num_enabled = Self::is_modifier_enabled(key_event, ControlKey::NumLock);
            num_lock_changed = event_num_enabled != local_num_enabled;
        } else if is_legacy_mode(key_event) {
            #[cfg(target_os = "windows")]
            {
                num_lock_changed =
                    should_disable_numlock(key_event) && en.get_key_state(enigo::Key::NumLock);
            }
        }
        if num_lock_changed {
            if let Err(err) = complete_lock_key_click(RdevKey::NumLock) {
                if caps_lock_changed {
                    retry_lock_key_click(RdevKey::CapsLock);
                }
                return Err(err);
            }
        }

        Ok(Self {
            caps_lock_changed,
            num_lock_changed,
        })
    }

    #[cfg(target_os = "macos")]
    fn new(key_event: &KeyEvent) -> ResultType<Self> {
        let event_caps_enabled = Self::is_modifier_enabled(key_event, ControlKey::CapsLock);
        // Do not use the following code to detect `local_caps_enabled`.
        // Because the state of get_key_state will not affect simulation of `VIRTUAL_INPUT_STATE` in this file.
        //
        // let local_caps_enabled = VirtualInput::get_key_state(
        //     CGEventSourceStateID::CombinedSessionState,
        //     rdev::kVK_CapsLock,
        // );
        let local_caps_enabled = unsafe {
            let _lock = VIRTUAL_INPUT_MTX.lock();
            VIRTUAL_INPUT_STATE
                .as_ref()
                .map_or(false, |input| input.capslock_down)
        };
        if event_caps_enabled && !local_caps_enabled {
            press_capslock()?;
        } else if !event_caps_enabled && local_caps_enabled {
            release_capslock()?;
        }

        Ok(Self {})
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
impl Drop for LockModesHandler {
    fn drop(&mut self) {
        if self.caps_lock_changed {
            retry_lock_key_click(RdevKey::CapsLock);
        }
        if self.num_lock_changed {
            retry_lock_key_click(RdevKey::NumLock);
        }
    }
}

#[inline]
#[cfg(target_os = "windows")]
fn should_disable_numlock(evt: &KeyEvent) -> bool {
    // disable numlock if press home etc when numlock is on,
    // because we will get numpad value (7,8,9 etc) if not
    match (&evt.union, evt.mode.enum_value_or(KeyboardMode::Legacy)) {
        (Some(key_event::Union::ControlKey(ck)), KeyboardMode::Legacy) => {
            return NUMPAD_KEY_MAP.contains_key(&ck.value());
        }
        _ => {}
    }
    false
}

pub const NAME_CURSOR: &'static str = "mouse_cursor";
pub const NAME_POS: &'static str = "mouse_pos";
pub const NAME_WINDOW_FOCUS: &'static str = "window_focus";
#[derive(Clone)]
pub struct MouseCursorService {
    pub sp: ServiceTmpl<MouseCursorSub>,
}

impl Deref for MouseCursorService {
    type Target = ServiceTmpl<MouseCursorSub>;

    fn deref(&self) -> &Self::Target {
        &self.sp
    }
}

impl DerefMut for MouseCursorService {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.sp
    }
}

impl MouseCursorService {
    pub fn new(name: String, need_snapshot: bool) -> Self {
        Self {
            sp: ServiceTmpl::<MouseCursorSub>::new(name, need_snapshot),
        }
    }
}

pub fn new_cursor() -> ServiceTmpl<MouseCursorSub> {
    let svc = MouseCursorService::new(NAME_CURSOR.to_owned(), true);
    ServiceTmpl::<MouseCursorSub>::repeat::<StateCursor, _, _>(&svc.clone(), 33, run_cursor);
    svc.sp
}

pub fn new_pos() -> GenericService {
    let svc = EmptyExtraFieldService::new(NAME_POS.to_owned(), false);
    GenericService::repeat::<StatePos, _, _>(&svc.clone(), 33, run_pos);
    svc.sp
}

pub fn new_window_focus() -> GenericService {
    let svc = EmptyExtraFieldService::new(NAME_WINDOW_FOCUS.to_owned(), false);
    GenericService::repeat::<StateWindowFocus, _, _>(&svc.clone(), 33, run_window_focus);
    svc.sp
}

#[inline]
fn update_last_cursor_pos(x: i32, y: i32) {
    let mut lock = LATEST_SYS_CURSOR_POS.lock().unwrap();
    if lock.1 .0 != x || lock.1 .1 != y {
        (lock.0, lock.1) = (Some(Instant::now()), (x, y))
    }
}

fn run_pos(sp: EmptyExtraFieldService, state: &mut StatePos) -> ResultType<()> {
    let (_, (x, y)) = *LATEST_SYS_CURSOR_POS.lock().unwrap();
    if x == INVALID_CURSOR_POS || y == INVALID_CURSOR_POS {
        return Ok(());
    }

    if state.is_moved(x, y) {
        let mut msg_out = Message::new();
        msg_out.set_cursor_position(CursorPosition {
            x,
            y,
            ..Default::default()
        });
        let exclude = {
            let now = get_time();
            let lock = LATEST_PEER_INPUT_CURSOR.lock().unwrap();
            if now - lock.time < 300 {
                lock.conn
            } else {
                0
            }
        };
        sp.send_without(msg_out, exclude);
    }
    state.cursor_pos = (x, y);

    sp.snapshot(|sps| {
        let mut msg_out = Message::new();
        msg_out.set_cursor_position(CursorPosition {
            x: state.cursor_pos.0,
            y: state.cursor_pos.1,
            ..Default::default()
        });
        sps.send(msg_out);
        Ok(())
    })?;
    Ok(())
}

fn run_cursor(sp: MouseCursorService, state: &mut StateCursor) -> ResultType<()> {
    if let Some(hcursor) = crate::get_cursor()? {
        if hcursor != state.hcursor {
            let msg;
            if let Some(cached) = state.cached_cursor_data.get(&hcursor) {
                super::log::trace!("Cursor data cached, hcursor: {}", hcursor);
                msg = cached.clone();
            } else {
                let mut data = crate::get_cursor_data(hcursor)?;
                data.colors = hbb_common::compress::compress(&data.colors[..]).into();
                let mut tmp = Message::new();
                tmp.set_cursor_data(data);
                msg = Arc::new(tmp);
                state.cached_cursor_data.insert(hcursor, msg.clone());
                super::log::trace!("Cursor data updated, hcursor: {}", hcursor);
            }
            state.hcursor = hcursor;
            sp.send_shared(msg.clone());
            state.cursor_data = msg;
        }
    }
    sp.snapshot(|sps| {
        sps.send_shared(state.cursor_data.clone());
        Ok(())
    })?;
    Ok(())
}

fn run_window_focus(sp: EmptyExtraFieldService, state: &mut StateWindowFocus) -> ResultType<()> {
    let displays = super::display_service::get_sync_displays();
    if displays.len() <= 1 {
        return Ok(());
    }
    let disp_idx = crate::get_focused_display(displays);
    if let Some(disp_idx) = disp_idx.map(|id| id as i32) {
        if state.is_changed(disp_idx) {
            let mut misc = Misc::new();
            misc.set_follow_current_display(disp_idx as i32);
            let mut msg_out = Message::new();
            msg_out.set_misc(misc);
            sp.send(msg_out);
        }
        state.display_idx = disp_idx;
    }
    Ok(())
}

lazy_static::lazy_static! {
    static ref ENIGO: Arc<Mutex<Enigo>> = {
        Arc::new(Mutex::new(Enigo::new()))
    };
    static ref LATEST_PEER_INPUT_CURSOR: Arc<Mutex<Input>> = Default::default();
    static ref LATEST_SYS_CURSOR_POS: Arc<Mutex<(Option<Instant>, (i32, i32))>> = Arc::new(Mutex::new((None, (INVALID_CURSOR_POS, INVALID_CURSOR_POS))));
    // Track connections that are currently using relative mouse movement.
    // Used to disable whiteboard/cursor display for all events while in relative mode.
    static ref RELATIVE_MOUSE_CONNS: Arc<Mutex<std::collections::HashSet<i32>>> = Default::default();
}

#[inline]
fn set_relative_mouse_active(conn: i32, active: bool) {
    let mut lock = RELATIVE_MOUSE_CONNS.lock().unwrap();
    if active {
        lock.insert(conn);
    } else {
        lock.remove(&conn);
    }
}

#[inline]
fn is_relative_mouse_active(conn: i32) -> bool {
    RELATIVE_MOUSE_CONNS.lock().unwrap().contains(&conn)
}

/// Clears the relative mouse mode state for a connection.
///
/// This must be called when an authenticated connection is dropped (during connection teardown)
/// to avoid leaking the connection id in `RELATIVE_MOUSE_CONNS` (a `Mutex<HashSet<i32>>`).
/// Callers are responsible for invoking this on disconnect.
#[inline]
pub(crate) fn clear_relative_mouse_active(conn: i32) {
    set_relative_mouse_active(conn, false);
}

static EXITING: AtomicBool = AtomicBool::new(false);

const MOUSE_MOVE_PROTECTION_TIMEOUT: Duration = Duration::from_millis(1_000);
// Actual diff of (x,y) is (1,1) here. But 5 may be tolerant.
const MOUSE_ACTIVE_DISTANCE: i32 = 5;

static RECORD_CURSOR_POS_RUNNING: AtomicBool = AtomicBool::new(false);

// https://github.com/rustdesk/rustdesk/issues/9729
// We need to do some special handling for macOS when using the legacy mode.
#[cfg(target_os = "macos")]
static LAST_KEY_LEGACY_MODE: AtomicBool = AtomicBool::new(true);
// We use enigo to
// 1. Simulate mouse events
// 2. Simulate the legacy mode key events
// 3. Simulate the functioin key events, like LockScreen
#[inline]
#[cfg(target_os = "macos")]
fn enigo_ignore_flags() -> bool {
    !LAST_KEY_LEGACY_MODE.load(Ordering::SeqCst)
}
#[inline]
#[cfg(target_os = "macos")]
fn set_last_legacy_mode(v: bool) {
    LAST_KEY_LEGACY_MODE.store(v, Ordering::SeqCst);
    lock_input_state(&ENIGO, "Enigo state while updating macOS input flags").set_ignore_flags(!v);
}

pub fn try_start_record_cursor_pos() -> Option<thread::JoinHandle<()>> {
    if RECORD_CURSOR_POS_RUNNING.load(Ordering::SeqCst) {
        return None;
    }

    RECORD_CURSOR_POS_RUNNING.store(true, Ordering::SeqCst);
    let handle = thread::spawn(|| {
        let interval = time::Duration::from_millis(33);
        loop {
            if !RECORD_CURSOR_POS_RUNNING.load(Ordering::SeqCst) {
                break;
            }

            let now = time::Instant::now();
            if let Some((x, y)) = crate::get_cursor_pos() {
                update_last_cursor_pos(x, y);
            }
            let elapsed = now.elapsed();
            if elapsed < interval {
                thread::sleep(interval - elapsed);
            }
        }
        update_last_cursor_pos(INVALID_CURSOR_POS, INVALID_CURSOR_POS);
    });
    Some(handle)
}

pub fn try_stop_record_cursor_pos() {
    let remote_count = AUTHED_CONNS
        .lock()
        .unwrap()
        .iter()
        .filter(|c| c.conn_type == AuthConnType::Remote)
        .count();
    if remote_count > 0 {
        return;
    }
    RECORD_CURSOR_POS_RUNNING.store(false, Ordering::SeqCst);
}

// mac key input must be run in main thread, otherwise crash on >= osx 10.15
#[cfg(target_os = "macos")]
lazy_static::lazy_static! {
    static ref QUEUE: Queue = Queue::main();
}

#[cfg(target_os = "macos")]
static MACOS_RDEV_METADATA: std::sync::Once = std::sync::Once::new();

#[cfg(target_os = "macos")]
fn initialize_macos_rdev_metadata() {
    MACOS_RDEV_METADATA.call_once(|| {
        rdev::set_mouse_extra_info(enigo::ENIGO_INPUT_EXTRA_VALUE);
        rdev::set_keyboard_extra_info(enigo::ENIGO_INPUT_EXTRA_VALUE);
    });
}

#[cfg(target_os = "macos")]
struct VirtualInputState {
    virtual_input: VirtualInput,
    capslock_down: bool,
}

#[cfg(target_os = "macos")]
impl VirtualInputState {
    fn new() -> ResultType<Self> {
        VirtualInput::new(
            CGEventSourceStateID::CombinedSessionState,
            // Note: `CGEventTapLocation::Session` will be affected by the mouse events.
            // When we're simulating key events, then move the physical mouse, the key events will be affected.
            // It looks like https://github.com/rustdesk/rustdesk/issues/9729#issuecomment-2432306822
            // 1. Press "Command" key in RustDesk
            // 2. Move the physical mouse
            // 3. Press "V" key in RustDesk
            // Then the controlled side just prints "v" instead of pasting.
            //
            // Changing `CGEventTapLocation::Session` to `CGEventTapLocation::HID` fixes it.
            // But we do not consider this as a bug, because it's not a common case,
            // we consider only RustDesk operates the controlled side.
            //
            // https://developer.apple.com/documentation/coregraphics/cgeventtaplocation/
            CGEventTapLocation::Session,
        )
        .map(|virtual_input| Self {
            virtual_input,
            capslock_down: false,
        })
        .map_err(|err| hbb_common::anyhow::anyhow!("could not create macOS virtual input: {err:?}"))
    }

    #[inline]
    fn simulate(&self, event_type: &EventType) -> ResultType<()> {
        Ok(self.virtual_input.simulate(&event_type)?)
    }
}

#[cfg(target_os = "macos")]
static mut VIRTUAL_INPUT_MTX: Mutex<()> = Mutex::new(());
#[cfg(target_os = "macos")]
static mut VIRTUAL_INPUT_STATE: Option<VirtualInputState> = None;

pub fn is_left_up(evt: &MouseEvent) -> bool {
    let buttons = evt.mask >> 3;
    let evt_type = evt.mask & MOUSE_TYPE_MASK;
    buttons == MOUSE_BUTTON_LEFT && evt_type == MOUSE_TYPE_UP
}

#[cfg(windows)]
pub fn mouse_move_relative(x: i32, y: i32) {
    if let Err(err) = dispatch_windows_owned_input(move || {
        crate::platform::windows::try_change_desktop();
        lock_input_state(&ENIGO, "Enigo state while moving the mouse")
            .mouse_move_relative(x, y)
            .map_err(|err| hbb_common::anyhow::anyhow!(err.to_string()))
    }) {
        log::error!("Could not move the Windows mouse through the owned-input executor: {err}");
    }
}

#[cfg(windows)]
fn modifier_sleep() {
    // sleep for a while, this is only for keying in rdp in peer so far
    std::thread::sleep(std::time::Duration::from_nanos(1));
}

#[inline]
#[cfg(not(target_os = "macos"))]
fn is_pressed(key: &Key, en: &mut Enigo) -> bool {
    get_exact_key_state(key.clone(), en)
}

// Sleep for 8ms is enough in my tests, but we sleep 12ms to be safe.
// sleep 12ms In my test, the characters are already output in real time.
#[inline]
#[cfg(target_os = "macos")]
fn key_sleep() {
    // https://www.reddit.com/r/rustdesk/comments/1kn1w5x/typing_lags_when_connecting_to_macos_clients/
    //
    // There's a strange bug when running by `launchctl load -w /Library/LaunchAgents/abc.plist`
    // `std::thread::sleep(Duration::from_millis(20));` may sleep 90ms or more.
    // Though `/Applications/RustDesk.app/Contents/MacOS/rustdesk --server` in terminal is ok.
    let now = Instant::now();
    while now.elapsed() < Duration::from_millis(12) {
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[inline]
fn get_exact_key_state(key: Key, en: &mut Enigo) -> bool {
    en.get_key_state(key)
}

#[inline]
fn get_modifier_family_state(key: Key, en: &mut Enigo) -> bool {
    // https://github.com/rustdesk/rustdesk/issues/332
    // on Linux, if RightAlt is down, RightAlt status is false, Alt status is true
    // but on Windows, both are true
    let x = en.get_key_state(key.clone());
    match key {
        Key::Shift => x || en.get_key_state(Key::RightShift),
        Key::Control => x || en.get_key_state(Key::RightControl),
        Key::Alt => x || en.get_key_state(Key::RightAlt),
        Key::Meta => x || en.get_key_state(Key::RWin),
        Key::RightShift => x || en.get_key_state(Key::Shift),
        Key::RightControl => x || en.get_key_state(Key::Control),
        Key::RightAlt => x || en.get_key_state(Key::Alt),
        Key::RWin => x || en.get_key_state(Key::Meta),
        _ => x,
    }
}

#[allow(unreachable_code)]
pub fn handle_mouse(
    evt: &MouseEvent,
    conn: i32,
    username: String,
    argb: u32,
    simulate: bool,
    show_cursor: bool,
) {
    #[cfg(target_os = "macos")]
    {
        // having GUI (--server has tray, it is GUI too), run main GUI thread, otherwise crash
        let evt = evt.clone();
        QUEUE.exec_async(move || {
            initialize_macos_rdev_metadata();
            if let Err(err) = handle_mouse_(&evt, conn, username, argb, simulate, show_cursor, &[])
            {
                log::error!("Could not dispatch mouse input: {err}");
            }
        });
        return;
    }
    #[cfg(target_os = "windows")]
    {
        let evt = evt.clone();
        if let Err(err) = dispatch_windows_owned_input(move || {
            handle_mouse_(&evt, conn, username, argb, simulate, show_cursor, &[])
        }) {
            log::error!("Could not dispatch Windows mouse input: {err}");
        }
        return;
    }
    if let Err(err) = handle_mouse_(evt, conn, username, argb, simulate, show_cursor, &[]) {
        log::error!("Could not dispatch mouse input: {err}");
    }
}

// to-do: merge handle_mouse and handle_pointer
#[allow(unreachable_code)]
pub fn handle_pointer(evt: &PointerDeviceEvent, conn: i32) {
    #[cfg(target_os = "macos")]
    {
        // having GUI, run main GUI thread, otherwise crash
        let evt = evt.clone();
        QUEUE.exec_async(move || {
            initialize_macos_rdev_metadata();
            if let Err(err) = handle_pointer_(&evt, conn) {
                log::error!("Could not dispatch pointer input: {err}");
            }
        });
        return;
    }
    #[cfg(target_os = "windows")]
    {
        let evt = evt.clone();
        if let Err(err) = dispatch_windows_owned_input(move || handle_pointer_(&evt, conn)) {
            log::error!("Could not dispatch Windows pointer input: {err}");
        }
        return;
    }
    if let Err(err) = handle_pointer_(evt, conn) {
        log::error!("Could not dispatch pointer input: {err}");
    }
}

pub fn fix_key_down_timeout_at_exit() {
    if EXITING.load(Ordering::SeqCst) {
        return;
    }
    EXITING.store(true, Ordering::SeqCst);
    release_device_modifiers();
    log::info!("fix_key_down_timeout_at_exit");
}

fn lock_input_state<'a, T>(state: &'a Mutex<T>, context: &str) -> std::sync::MutexGuard<'a, T> {
    match state.lock() {
        Ok(state) => state,
        Err(poisoned) => {
            log::error!("{context} was poisoned");
            poisoned.into_inner()
        }
    }
}

#[inline]
#[cfg(target_os = "linux")]
pub fn clear_remapped_keycode() {
    lock_input_state(&ENIGO, "Enigo state while clearing remapped keycodes").tfc_clear_remapped();
}

fn release_device_modifiers_inner() -> ResultType<()> {
    let mut en = lock_input_state(&ENIGO, "Enigo state while releasing device modifiers");
    for (modifier, physical) in [
        (Key::Shift, RdevKey::ShiftLeft),
        (Key::Control, RdevKey::ControlLeft),
        (Key::Alt, RdevKey::Alt),
        (Key::Meta, RdevKey::MetaLeft),
        (Key::RightShift, RdevKey::ShiftRight),
        (Key::RightControl, RdevKey::ControlRight),
        (Key::RightAlt, RdevKey::AltGr),
        (Key::RWin, RdevKey::MetaRight),
    ] {
        if get_exact_key_state(modifier, &mut en) {
            simulate_(&EventType::KeyRelease(physical))?;
        }
    }
    Ok(())
}

pub fn release_device_modifiers() {
    #[cfg(target_os = "windows")]
    let result = dispatch_windows_owned_input(release_device_modifiers_inner);
    #[cfg(not(target_os = "windows"))]
    let result = release_device_modifiers_inner();
    if let Err(err) = result {
        log::error!("Could not release device modifiers: {err}");
    }
}

#[cfg(test)]
mod input_state_tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn owned_executor_initializes_once_before_actions_on_the_same_thread() {
        let calls = Arc::new(AtomicUsize::new(0));
        let threads = Arc::new(Mutex::new(Vec::new()));
        let init_calls = Arc::clone(&calls);
        let init_threads = Arc::clone(&threads);
        let executor = OwnedInputExecutor::spawn_with_initializer("input-init-test", move || {
            init_calls.fetch_add(1, Ordering::AcqRel);
            init_threads
                .lock()
                .unwrap()
                .push(std::thread::current().id());
        })
        .unwrap();
        for _ in 0..2 {
            let action_threads = Arc::clone(&threads);
            executor
                .dispatch(move || {
                    action_threads
                        .lock()
                        .unwrap()
                        .push(std::thread::current().id());
                    Ok(())
                })
                .unwrap();
        }
        assert_eq!(calls.load(Ordering::Acquire), 1);
        let threads = threads.lock().unwrap();
        assert_eq!(threads.len(), 3);
        assert!(threads.iter().all(|thread| *thread == threads[0]));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn temporary_modifier_setup_failure_releases_prior_downs() {
        let operations = Arc::new(Mutex::new(Vec::new()));
        let attempts = Arc::new(AtomicUsize::new(0));
        let press_operations = Arc::clone(&operations);
        let press_attempts = Arc::clone(&attempts);
        let release_operations = Arc::clone(&operations);
        let result = press_temporary_keys_with(
            &[RdevKey::ShiftLeft, RdevKey::ControlLeft],
            "test modifier",
            move |key| {
                press_operations.lock().unwrap().push((true, key));
                if press_attempts.fetch_add(1, Ordering::AcqRel) == 1 {
                    bail!("injected second-modifier failure");
                }
                Ok(())
            },
            move |key| {
                release_operations.lock().unwrap().push((false, key));
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(
            *operations.lock().unwrap(),
            vec![
                (true, RdevKey::ShiftLeft),
                (true, RdevKey::ControlLeft),
                (false, RdevKey::ShiftLeft),
            ]
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn temporary_modifier_action_failure_releases_every_down_in_reverse() {
        let operations = Arc::new(Mutex::new(Vec::new()));
        let press_operations = Arc::clone(&operations);
        let release_operations = Arc::clone(&operations);
        let result: ResultType<()> = with_temporary_keys_with(
            &[RdevKey::ShiftLeft, RdevKey::ControlLeft],
            "test modifier",
            move |key| {
                press_operations.lock().unwrap().push((true, key));
                Ok(())
            },
            || bail!("injected semantic action failure"),
            move |key| {
                release_operations.lock().unwrap().push((false, key));
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(
            *operations.lock().unwrap(),
            vec![
                (true, RdevKey::ShiftLeft),
                (true, RdevKey::ControlLeft),
                (false, RdevKey::ControlLeft),
                (false, RdevKey::ShiftLeft),
            ]
        );
    }

    #[test]
    fn poisoned_input_state_is_recovered_without_a_second_panic() {
        let state = Arc::new(Mutex::new(0usize));
        let poison = Arc::clone(&state);
        let _ = std::thread::spawn(move || {
            let _guard = poison.lock().unwrap();
            panic!("poison input state");
        })
        .join();

        *lock_input_state(&state, "test input state") = 1;
        assert_eq!(*lock_input_state(&state, "test input state"), 1);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_first_worker_reset_restores_legacy_input_mode() {
        LAST_KEY_LEGACY_MODE.store(false, Ordering::SeqCst);
        lock_input_state(&ENIGO, "test macOS input mode").set_ignore_flags(true);
        reset_input();
        assert!(LAST_KEY_LEGACY_MODE.load(Ordering::SeqCst));
        assert!(!enigo_ignore_flags());
    }
}

// e.g. current state of ctrl is down, but ctrl not in modifier, we should change ctrl to up, to make modifier state sync between remote and local
#[inline]
fn fix_modifier(
    modifiers: &[EnumOrUnknown<ControlKey>],
    key0: ControlKey,
    key1: Key,
    physical_key: RdevKey,
    en: &mut Enigo,
    preserve_modifiers: &[ControlKey],
) -> ResultType<()> {
    if get_exact_key_state(key1, en)
        && !modifiers.contains(&EnumOrUnknown::new(key0))
        && !preserve_modifiers.contains(&key0)
    {
        #[cfg(windows)]
        if key0 == ControlKey::Control && get_modifier_family_state(Key::Alt, en) {
            // AltGr case
            return Ok(());
        }
        simulate_(&EventType::KeyRelease(physical_key))?;
        log::debug!("Fixed {:?}", key1);
    }
    Ok(())
}

fn fix_modifiers(
    modifiers: &[EnumOrUnknown<ControlKey>],
    en: &mut Enigo,
    ck: i32,
    preserve_modifiers: &[ControlKey],
) -> ResultType<()> {
    if ck != ControlKey::Shift.value() {
        fix_modifier(
            modifiers,
            ControlKey::Shift,
            Key::Shift,
            RdevKey::ShiftLeft,
            en,
            preserve_modifiers,
        )?;
    }
    if ck != ControlKey::RShift.value() {
        fix_modifier(
            modifiers,
            ControlKey::RShift,
            Key::RightShift,
            RdevKey::ShiftRight,
            en,
            preserve_modifiers,
        )?;
    }
    if ck != ControlKey::Alt.value() {
        fix_modifier(
            modifiers,
            ControlKey::Alt,
            Key::Alt,
            RdevKey::Alt,
            en,
            preserve_modifiers,
        )?;
    }
    if ck != ControlKey::RAlt.value() {
        fix_modifier(
            modifiers,
            ControlKey::RAlt,
            Key::RightAlt,
            RdevKey::AltGr,
            en,
            preserve_modifiers,
        )?;
    }
    if ck != ControlKey::Control.value() {
        fix_modifier(
            modifiers,
            ControlKey::Control,
            Key::Control,
            RdevKey::ControlLeft,
            en,
            preserve_modifiers,
        )?;
    }
    if ck != ControlKey::RControl.value() {
        fix_modifier(
            modifiers,
            ControlKey::RControl,
            Key::RightControl,
            RdevKey::ControlRight,
            en,
            preserve_modifiers,
        )?;
    }
    if ck != ControlKey::Meta.value() {
        fix_modifier(
            modifiers,
            ControlKey::Meta,
            Key::Meta,
            RdevKey::MetaLeft,
            en,
            preserve_modifiers,
        )?;
    }
    if ck != ControlKey::RWin.value() {
        fix_modifier(
            modifiers,
            ControlKey::RWin,
            Key::RWin,
            RdevKey::MetaRight,
            en,
            preserve_modifiers,
        )?;
    }
    Ok(())
}

// Update time to avoid send cursor position event to the peer.
// See `run_pos` --> `set_cursor_position` --> `exclude`
#[inline]
pub fn update_latest_input_cursor_time(conn: i32) {
    let mut lock = LATEST_PEER_INPUT_CURSOR.lock().unwrap();
    lock.conn = conn;
    lock.time = get_time();
}

#[inline]
fn get_last_input_cursor_pos() -> (i32, i32) {
    let lock = LATEST_PEER_INPUT_CURSOR.lock().unwrap();
    (lock.x, lock.y)
}

// check if mouse is moved by the controlled side user to make controlled side has higher mouse priority than remote.
fn active_mouse_(_conn: i32) -> bool {
    true
    /* this method is buggy (not working on macOS, making fast moving mouse event discarded here) and added latency (this is blocking way, must do in async way), so we disable it for now
    // out of time protection
    if LATEST_SYS_CURSOR_POS
        .lock()
        .unwrap()
        .0
        .map(|t| t.elapsed() > MOUSE_MOVE_PROTECTION_TIMEOUT)
        .unwrap_or(true)
    {
        return true;
    }

    // last conn input may be protected
    if LATEST_PEER_INPUT_CURSOR.lock().unwrap().conn != conn {
        return false;
    }

    let in_active_dist = |a: i32, b: i32| -> bool { (a - b).abs() < MOUSE_ACTIVE_DISTANCE };

    // Check if input is in valid range
    match crate::get_cursor_pos() {
        Some((x, y)) => {
            let (last_in_x, last_in_y) = get_last_input_cursor_pos();
            let mut can_active = in_active_dist(last_in_x, x) && in_active_dist(last_in_y, y);
            // The cursor may not have been moved to last input position if system is busy now.
            // While this is not a common case, we check it again after some time later.
            if !can_active {
                // 100 micros may be enough for system to move cursor.
                // Mouse inputs on macOS are asynchronous. 1. Put in a queue to process in main thread. 2. Send event async.
                // More reties are needed on macOS.
                #[cfg(not(target_os = "macos"))]
                let retries = 10;
                #[cfg(target_os = "macos")]
                let retries = 100;
                #[cfg(not(target_os = "macos"))]
                let sleep_interval: u64 = 10;
                #[cfg(target_os = "macos")]
                let sleep_interval: u64 = 30;
                for _retry in 0..retries {
                    std::thread::sleep(std::time::Duration::from_micros(sleep_interval));
                    // Sleep here can also somehow suppress delay accumulation.
                    if let Some((x2, y2)) = crate::get_cursor_pos() {
                        let (last_in_x, last_in_y) = get_last_input_cursor_pos();
                        can_active = in_active_dist(last_in_x, x2) && in_active_dist(last_in_y, y2);
                        if can_active {
                            break;
                        }
                    }
                }
            }
            if !can_active {
                let mut lock = LATEST_PEER_INPUT_CURSOR.lock().unwrap();
                lock.x = INVALID_CURSOR_POS / 2;
                lock.y = INVALID_CURSOR_POS / 2;
            }
            can_active
        }
        None => true,
    }
    */
}

fn handle_pointer_(evt: &PointerDeviceEvent, conn: i32) -> ResultType<()> {
    if !active_mouse_(conn) {
        return Ok(());
    }

    if EXITING.load(Ordering::SeqCst) {
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    let preserve_control = evt.modifiers.iter().any(|modifier| {
        modifier.value() == ControlKey::Control.value()
            || modifier.value() == ControlKey::RControl.value()
    });
    match &evt.union {
        Some(TouchEvent(evt)) => match &evt.union {
            Some(ScaleUpdate(_scale_evt)) => {
                #[cfg(target_os = "windows")]
                handle_scale(_scale_evt.scale, preserve_control)?;
            }
            _ => {}
        },
        _ => {}
    }
    Ok(())
}

fn handle_mouse_(
    evt: &MouseEvent,
    conn: i32,
    _username: String,
    _argb: u32,
    simulate: bool,
    _show_cursor: bool,
    preserve_modifiers: &[ControlKey],
) -> ResultType<()> {
    if simulate {
        handle_mouse_simulation_(evt, conn, preserve_modifiers)?;
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let evt_type = evt.mask & MOUSE_TYPE_MASK;
        // Relative (delta) mouse events do not include absolute coordinates, so
        // whiteboard/cursor rendering must be disabled during relative mode to prevent
        // incorrect cursor/whiteboard updates. We check both is_relative_mouse_active(conn)
        // (connection already in relative mode from prior events) and evt_type (current
        // event is relative) to guard against the first relative event before the flag is set.
        if _show_cursor && !is_relative_mouse_active(conn) && evt_type != MOUSE_TYPE_MOVE_RELATIVE {
            handle_mouse_show_cursor_(evt, conn, _username, _argb);
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn simulate_mouse_button(button: OwnedMouseButton, down: bool) -> ResultType<()> {
    let mut en = lock_input_state(&ENIGO, "Enigo state while handling a mouse button");
    let result = if down {
        en.mouse_down(enigo_mouse_button(button))
    } else {
        en.mouse_up(enigo_mouse_button(button))
    };
    result.map_err(|err| hbb_common::anyhow::anyhow!(err.to_string()))
}

fn handle_mouse_simulation_(
    evt: &MouseEvent,
    conn: i32,
    preserve_modifiers: &[ControlKey],
) -> ResultType<()> {
    if !active_mouse_(conn) {
        return Ok(());
    }

    if EXITING.load(Ordering::SeqCst) {
        return Ok(());
    }

    #[cfg(windows)]
    crate::platform::windows::try_change_desktop();
    let evt_type = evt.mask & MOUSE_TYPE_MASK;
    let mut en = lock_input_state(&ENIGO, "Enigo state while handling mouse input");
    #[cfg(target_os = "macos")]
    en.set_ignore_flags(enigo_ignore_flags());
    #[cfg(not(target_os = "macos"))]
    let mut to_press = Vec::new();
    if evt_type == MOUSE_TYPE_DOWN {
        fix_modifiers(&evt.modifiers[..], &mut en, 0, preserve_modifiers)?;
        #[cfg(target_os = "macos")]
        en.reset_flag();
        for ref ck in evt.modifiers.iter() {
            if let Some(key) = KEY_MAP.get(&ck.value()) {
                #[cfg(target_os = "macos")]
                en.add_flag(key);
                #[cfg(not(target_os = "macos"))]
                if key != &Key::CapsLock && key != &Key::NumLock {
                    let modifier = ck.enum_value_or(ControlKey::Unknown);
                    if !preserve_modifiers.contains(&modifier)
                        && !get_exact_key_state(key.clone(), &mut en)
                    {
                        let physical_key =
                            control_key_to_rdev_key(ck.value()).ok_or_else(|| {
                                hbb_common::anyhow::anyhow!(
                                    "mouse modifier has no physical injector identity"
                                )
                            })?;
                        to_press.push(physical_key);
                    }
                }
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    let to_release = press_temporary_keys(&to_press, "mouse modifier")?;
    let action_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut action_result = Ok(());
        match evt_type {
            MOUSE_TYPE_MOVE => {
                // Switching back to absolute movement implicitly disables relative mouse mode.
                set_relative_mouse_active(conn, false);
                en.mouse_move_to(evt.x, evt.y)
                    .map_err(|err| hbb_common::anyhow::anyhow!(err.to_string()))?;
                *LATEST_PEER_INPUT_CURSOR.lock().unwrap() = Input {
                    conn,
                    time: get_time(),
                    x: evt.x,
                    y: evt.y,
                };
            }
            // MOUSE_TYPE_MOVE_RELATIVE: Relative mouse movement for gaming/3D applications.
            // Each client independently decides whether to use relative mode.
            // Multiple clients can mix absolute and relative movements without conflict,
            // as the server simply applies the delta to the current cursor position.
            MOUSE_TYPE_MOVE_RELATIVE => {
                set_relative_mouse_active(conn, true);
                // Clamp delta to prevent extreme/malicious values from reaching OS APIs.
                // This matches the Flutter client's kMaxRelativeMouseDelta constant.
                const MAX_RELATIVE_MOUSE_DELTA: i32 = 10000;
                let dx = evt
                    .x
                    .clamp(-MAX_RELATIVE_MOUSE_DELTA, MAX_RELATIVE_MOUSE_DELTA);
                let dy = evt
                    .y
                    .clamp(-MAX_RELATIVE_MOUSE_DELTA, MAX_RELATIVE_MOUSE_DELTA);
                en.mouse_move_relative(dx, dy)
                    .map_err(|err| hbb_common::anyhow::anyhow!(err.to_string()))?;
                // Get actual cursor position after relative movement for tracking
                if let Some((x, y)) = crate::get_cursor_pos() {
                    *LATEST_PEER_INPUT_CURSOR.lock().unwrap() = Input {
                        conn,
                        time: get_time(),
                        x,
                        y,
                    };
                }
            }
            MOUSE_TYPE_DOWN | MOUSE_TYPE_UP => {
                if let Some((button, down)) = owned_mouse_button(evt) {
                    let result = if down {
                        en.mouse_down(enigo_mouse_button(button))
                    } else {
                        en.mouse_up(enigo_mouse_button(button))
                    };
                    action_result =
                        result.map_err(|err| hbb_common::anyhow::anyhow!(err.to_string()));
                }
            }
            MOUSE_TYPE_WHEEL | MOUSE_TYPE_TRACKPAD => {
                validate_scroll_delta(evt.x)?;
                validate_scroll_delta(evt.y)?;
                #[allow(unused_mut)]
                let mut x = evt
                    .x
                    .checked_neg()
                    .ok_or_else(|| hbb_common::anyhow::anyhow!("horizontal scroll overflow"))?;
                #[allow(unused_mut)]
                let mut y = evt.y;
                #[cfg(not(windows))]
                {
                    y = y
                        .checked_neg()
                        .ok_or_else(|| hbb_common::anyhow::anyhow!("vertical scroll overflow"))?;
                }

                #[cfg(any(target_os = "macos", target_os = "windows"))]
                let is_track_pad = evt_type == MOUSE_TYPE_TRACKPAD;

                #[cfg(target_os = "macos")]
                {
                    // TODO: support track pad on win.

                    // fix shift + scroll(down/up)
                    if !is_track_pad
                        && evt
                            .modifiers
                            .contains(&EnumOrUnknown::new(ControlKey::Shift))
                    {
                        x = y;
                        y = 0;
                    }

                    if x != 0 {
                        en.mouse_scroll_x(x, is_track_pad)
                            .map_err(|err| hbb_common::anyhow::anyhow!(err.to_string()))?;
                    }
                    if y != 0 {
                        en.mouse_scroll_y(y, is_track_pad)
                            .map_err(|err| hbb_common::anyhow::anyhow!(err.to_string()))?;
                    }
                }

                #[cfg(windows)]
                if !is_track_pad {
                    x = x.checked_mul(WHEEL_DELTA as i32).ok_or_else(|| {
                        hbb_common::anyhow::anyhow!("horizontal wheel scaling overflow")
                    })?;
                    y = y.checked_mul(WHEEL_DELTA as i32).ok_or_else(|| {
                        hbb_common::anyhow::anyhow!("vertical wheel scaling overflow")
                    })?;
                }

                #[cfg(not(target_os = "macos"))]
                {
                    if y != 0 {
                        en.mouse_scroll_y(y)
                            .map_err(|err| hbb_common::anyhow::anyhow!(err.to_string()))?;
                    }
                    if x != 0 {
                        en.mouse_scroll_x(x)
                            .map_err(|err| hbb_common::anyhow::anyhow!(err.to_string()))?;
                    }
                }
            }
            _ => {}
        }
        action_result
    }));
    #[cfg(not(target_os = "macos"))]
    drop(en);
    #[cfg(not(target_os = "macos"))]
    release_temporary_keys(&to_release, "mouse modifier")?;
    match action_result {
        Ok(result) => result,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn handle_mouse_show_cursor_(evt: &MouseEvent, conn: i32, username: String, argb: u32) {
    let buttons = evt.mask >> 3;
    let evt_type = evt.mask & MOUSE_TYPE_MASK;
    match evt_type {
        MOUSE_TYPE_MOVE => {
            whiteboard::update_whiteboard(
                conn,
                whiteboard::CustomEvent::Cursor(whiteboard::Cursor {
                    x: evt.x as _,
                    y: evt.y as _,
                    argb,
                    btns: 0,
                    text: username,
                }),
            );
        }
        MOUSE_TYPE_UP => {
            if buttons == MOUSE_BUTTON_LEFT {
                // Some clients intentionally send button events without coordinates.
                // Fall back to the last known cursor position to avoid jumping to (0, 0).
                // TODO(protocol): (0, 0) is a valid screen coordinate. Consider using a dedicated
                // sentinel value (e.g. INVALID_CURSOR_POS) or a protocol-level flag to distinguish
                // "coordinates not provided" from "coordinates are (0, 0)". Impact is minor since
                // this only affects whiteboard rendering and clicking exactly at (0, 0) is rare.
                let (x, y) = if evt.x == 0 && evt.y == 0 {
                    get_last_input_cursor_pos()
                } else {
                    (evt.x, evt.y)
                };
                whiteboard::update_whiteboard(
                    conn,
                    whiteboard::CustomEvent::Cursor(whiteboard::Cursor {
                        x: x as _,
                        y: y as _,
                        argb,
                        btns: buttons,
                        text: username,
                    }),
                );
            }
        }
        _ => {}
    }
}

#[cfg(target_os = "windows")]
fn handle_scale(scale: i32, preserve_control: bool) -> ResultType<()> {
    let mut en = lock_input_state(&ENIGO, "Enigo state while handling mouse scale input");
    if scale == 0 {
        return Ok(());
    }
    if preserve_control {
        return en
            .mouse_scroll_y(scale)
            .map_err(|err| hbb_common::anyhow::anyhow!(err.to_string()));
    }
    simulate_(&EventType::KeyPress(RdevKey::ControlLeft))?;
    let scroll_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        en.mouse_scroll_y(scale)
            .map_err(|err| hbb_common::anyhow::anyhow!(err.to_string()))
    }));
    if let Err(first_err) = simulate_(&EventType::KeyRelease(RdevKey::ControlLeft)) {
        if let Err(retry_err) = simulate_(&EventType::KeyRelease(RdevKey::ControlLeft)) {
            log::error!(
                "Could not prove gesture Control release: first={first_err}, retry={retry_err}"
            );
            std::process::abort();
        }
        log::warn!("gesture Control release required a retry: {first_err}");
    }
    match scroll_result {
        Ok(result) => result,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

pub fn is_enter(evt: &KeyEvent) -> bool {
    if let Some(key_event::Union::ControlKey(ck)) = evt.union {
        if ck.value() == ControlKey::Return.value() || ck.value() == ControlKey::NumpadEnter.value()
        {
            return true;
        }
    }
    return false;
}

fn lock_screen_with_key_handler(
    mut key_handler: impl FnMut(&KeyEvent) -> ResultType<()>,
) -> ResultType<()> {
    cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {
        let code = rdev::linux_keycode_from_key(RdevKey::KeyL)
            .ok_or_else(|| hbb_common::anyhow::anyhow!("Linux lock key has no keycode"))?;
        dispatch_physical_lock_chord(&mut key_handler, &[ControlKey::Meta], code as u32)?;
    } else if #[cfg(target_os = "macos")] {
        let code = rdev::macos_keycode_from_key(RdevKey::KeyQ)
            .ok_or_else(|| hbb_common::anyhow::anyhow!("macOS lock key has no keycode"))?;
        dispatch_physical_lock_chord(
            &mut key_handler,
            &[ControlKey::Meta, ControlKey::Control],
            code as u32,
        )?;
    } else {
        crate::platform::lock_screen();
    }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn dispatch_physical_lock_chord(
    key_handler: &mut impl FnMut(&KeyEvent) -> ResultType<()>,
    modifiers: &[ControlKey],
    keycode: u32,
) -> ResultType<()> {
    for modifier in modifiers {
        let mut event = KeyEvent::new();
        event.set_control_key(*modifier);
        event.down = true;
        key_handler(&event)?;
    }
    let mut key = KeyEvent::new();
    key.mode = KeyboardMode::Map.into();
    key.set_chr(keycode);
    key.down = true;
    key_handler(&key)?;
    key.down = false;
    key_handler(&key)?;
    for modifier in modifiers.iter().rev() {
        let mut event = KeyEvent::new();
        event.set_control_key(*modifier);
        event.down = false;
        key_handler(&event)?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn handle_owned_mouse(
    evt: &MouseEvent,
    conn: i32,
    username: String,
    argb: u32,
    simulate: bool,
    show_cursor: bool,
    preserve_modifiers: &[ControlKey],
) -> ResultType<()> {
    handle_mouse_(
        evt,
        conn,
        username,
        argb,
        simulate,
        show_cursor,
        preserve_modifiers,
    )
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn release_owned_mouse_button(button: OwnedMouseButton) -> ResultType<()> {
    simulate_mouse_button(button, false)
}

#[cfg(target_os = "windows")]
pub fn release_owned_mouse_button(button: OwnedMouseButton) -> ResultType<()> {
    dispatch_windows_owned_input(move || simulate_mouse_button(button, false))
}

#[cfg(target_os = "macos")]
pub fn release_owned_mouse_button(button: OwnedMouseButton) -> ResultType<()> {
    QUEUE.exec_sync(move || {
        initialize_macos_rdev_metadata();
        simulate_mouse_button(button, false)
    })
}

#[cfg(target_os = "windows")]
pub fn handle_owned_mouse(
    evt: &MouseEvent,
    conn: i32,
    username: String,
    argb: u32,
    simulate: bool,
    show_cursor: bool,
    preserve_modifiers: &[ControlKey],
) -> ResultType<()> {
    let evt = evt.clone();
    let preserve_modifiers = preserve_modifiers.to_vec();
    dispatch_windows_owned_input(move || {
        handle_mouse_(
            &evt,
            conn,
            username,
            argb,
            simulate,
            show_cursor,
            &preserve_modifiers,
        )
    })
}

#[cfg(target_os = "macos")]
pub fn handle_owned_mouse(
    evt: &MouseEvent,
    conn: i32,
    username: String,
    argb: u32,
    simulate: bool,
    show_cursor: bool,
    preserve_modifiers: &[ControlKey],
) -> ResultType<()> {
    let evt = evt.clone();
    let preserve_modifiers = preserve_modifiers.to_vec();
    QUEUE.exec_sync(move || {
        initialize_macos_rdev_metadata();
        handle_mouse_(
            &evt,
            conn,
            username,
            argb,
            simulate,
            show_cursor,
            &preserve_modifiers,
        )
    })
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn handle_owned_pointer(evt: &PointerDeviceEvent, conn: i32) -> ResultType<()> {
    handle_pointer_(evt, conn)
}

#[cfg(target_os = "windows")]
pub fn handle_owned_pointer(evt: &PointerDeviceEvent, conn: i32) -> ResultType<()> {
    let evt = evt.clone();
    dispatch_windows_owned_input(move || handle_pointer_(&evt, conn))
}

#[cfg(target_os = "macos")]
pub fn handle_owned_pointer(evt: &PointerDeviceEvent, conn: i32) -> ResultType<()> {
    let evt = evt.clone();
    QUEUE.exec_sync(move || {
        initialize_macos_rdev_metadata();
        handle_pointer_(&evt, conn)
    })
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn handle_owned_key(evt: &KeyEvent, preserve_modifiers: &[ControlKey]) -> ResultType<()> {
    handle_key_with_preserved_modifiers(evt, preserve_modifiers)
}

#[cfg(target_os = "windows")]
pub fn handle_owned_key(evt: &KeyEvent, preserve_modifiers: &[ControlKey]) -> ResultType<()> {
    let evt = evt.clone();
    let preserve_modifiers = preserve_modifiers.to_vec();
    dispatch_windows_owned_input(move || {
        handle_key_with_preserved_modifiers(&evt, &preserve_modifiers)
    })
}

#[cfg(target_os = "macos")]
pub fn handle_owned_key(evt: &KeyEvent, preserve_modifiers: &[ControlKey]) -> ResultType<()> {
    let evt = evt.clone();
    let preserve_modifiers = preserve_modifiers.to_vec();
    let result = QUEUE.exec_sync(move || {
        initialize_macos_rdev_metadata();
        handle_key_with_preserved_modifiers(&evt, &preserve_modifiers)
    });
    key_sleep();
    result
}

pub fn handle_owned_lock_screen(
    key_handler: impl FnMut(&KeyEvent) -> ResultType<()>,
) -> ResultType<()> {
    lock_screen_with_key_handler(key_handler)
}

#[cfg(target_os = "macos")]
pub fn finish_owned_input_dispatch() {
    QUEUE.exec_sync(|| {});
}

#[cfg(target_os = "macos")]
#[inline]
fn reset_input() {
    LAST_KEY_LEGACY_MODE.store(true, Ordering::SeqCst);
    lock_input_state(&ENIGO, "Enigo state while initializing macOS owned input")
        .set_ignore_flags(false);
    unsafe {
        let _lock = VIRTUAL_INPUT_MTX.lock();
        VIRTUAL_INPUT_STATE = match VirtualInputState::new() {
            Ok(input) => Some(input),
            Err(err) => {
                log::error!("Could not initialize macOS owned input: {err}");
                None
            }
        };
    }
}

#[cfg(target_os = "macos")]
pub fn initialize_owned_input_dispatch() {
    QUEUE.exec_sync(|| {
        initialize_macos_rdev_metadata();
        reset_input();
    });
}

#[cfg(not(target_os = "macos"))]
#[inline]
pub fn initialize_owned_input_dispatch() {}

fn sim_rdev_rawkey_position(code: KeyCode, keydown: bool) -> ResultType<()> {
    #[cfg(target_os = "windows")]
    let rawkey = RawKey::ScanCode(code);
    #[cfg(target_os = "linux")]
    let rawkey = RawKey::LinuxXorgKeycode(code);
    // // to-do: test android
    // #[cfg(target_os = "android")]
    // let rawkey = RawKey::LinuxConsoleKeycode(code);
    #[cfg(target_os = "macos")]
    let rawkey = RawKey::MacVirtualKeycode(code);

    let event_type = if keydown {
        EventType::KeyPress(RdevKey::RawKey(rawkey))
    } else {
        EventType::KeyRelease(RdevKey::RawKey(rawkey))
    };
    simulate_(&event_type)
}

#[cfg(target_os = "windows")]
fn sim_rdev_rawkey_virtual(code: u32, keydown: bool) -> ResultType<()> {
    let rawkey = RawKey::WinVirtualKeycode(code);
    let event_type = if keydown {
        EventType::KeyPress(RdevKey::RawKey(rawkey))
    } else {
        EventType::KeyRelease(RdevKey::RawKey(rawkey))
    };
    simulate_(&event_type)
}

#[inline]
#[cfg(target_os = "macos")]
fn simulate_(event_type: &EventType) -> ResultType<()> {
    unsafe {
        let _lock = VIRTUAL_INPUT_MTX.lock();
        let Some(input) = VIRTUAL_INPUT_STATE.as_ref() else {
            bail!("macOS virtual input is unavailable");
        };
        input
            .simulate(event_type)
            .map_err(|err| hbb_common::anyhow::anyhow!("macOS input dispatch failed: {err:?}"))
    }
}

#[inline]
#[cfg(target_os = "macos")]
fn press_capslock() -> ResultType<()> {
    let caps_key = RdevKey::RawKey(rdev::RawKey::MacVirtualKeycode(rdev::kVK_CapsLock));
    unsafe {
        let _lock = VIRTUAL_INPUT_MTX.lock();
        let Some(input) = VIRTUAL_INPUT_STATE.as_mut() else {
            bail!("macOS virtual input is unavailable for CapsLock press");
        };
        input.simulate(&EventType::KeyPress(caps_key))?;
        input.capslock_down = true;
        key_sleep();
    }
    Ok(())
}

#[cfg(target_os = "macos")]
#[inline]
fn release_capslock() -> ResultType<()> {
    let caps_key = RdevKey::RawKey(rdev::RawKey::MacVirtualKeycode(rdev::kVK_CapsLock));
    unsafe {
        let _lock = VIRTUAL_INPUT_MTX.lock();
        let Some(input) = VIRTUAL_INPUT_STATE.as_mut() else {
            bail!("macOS virtual input is unavailable for CapsLock release");
        };
        input.simulate(&EventType::KeyRelease(caps_key))?;
        input.capslock_down = false;
        key_sleep();
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
#[inline]
fn simulate_(event_type: &EventType) -> ResultType<()> {
    rdev::simulate(event_type)
        .map_err(|err| hbb_common::anyhow::anyhow!("input dispatch failed: {err:?}"))
}

#[cfg(target_os = "windows")]
fn complete_lock_key_click(key: RdevKey) -> ResultType<()> {
    let scan = rdev::win_scancode_from_key(key)
        .ok_or_else(|| hbb_common::anyhow::anyhow!("lock key has no Windows scan code"))?;
    windows_complete_scan_click(scan as u32)
}

#[cfg(target_os = "linux")]
fn complete_lock_key_click(key: RdevKey) -> ResultType<()> {
    simulate_(&EventType::KeyPress(key))?;
    if let Err(first_err) = simulate_(&EventType::KeyRelease(key)) {
        if let Err(retry_err) = simulate_(&EventType::KeyRelease(key)) {
            log::error!("Could not prove lock-key release: first={first_err}, retry={retry_err}");
            std::process::abort();
        }
        log::warn!("lock-key release required a retry: {first_err}");
    }
    Ok(())
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
fn retry_lock_key_click(key: RdevKey) {
    if let Err(first_err) = complete_lock_key_click(key) {
        if let Err(retry_err) = complete_lock_key_click(key) {
            log::error!("Could not restore lock-key state: first={first_err}, retry={retry_err}");
            std::process::abort();
        }
        log::warn!("lock-key restoration required a retry: {first_err}");
    }
}

#[inline]
fn control_key_value_to_key(value: i32) -> Option<Key> {
    KEY_MAP.get(&value).and_then(|k| Some(*k))
}

#[inline]
fn char_value_to_key(value: u32) -> Key {
    Key::Layout(std::char::from_u32(value).unwrap_or('\0'))
}

fn map_keyboard_mode(evt: &KeyEvent) -> ResultType<()> {
    #[cfg(windows)]
    crate::platform::windows::try_change_desktop();

    // Wayland
    #[cfg(target_os = "linux")]
    if !crate::platform::linux::is_x11() {
        return wayland_send_raw_key(evt.chr() as u16, evt.down);
    }

    sim_rdev_rawkey_position(evt.chr() as _, evt.down)
}

/// Send raw keycode on Wayland via the active backend (uinput or RemoteDesktop portal).
/// The keycode is expected to be a Linux keycode (evdev code + 8 for X11 compatibility).
#[cfg(target_os = "linux")]
#[inline]
fn wayland_send_raw_key(_code: u16, _down: bool) -> ResultType<()> {
    bail!("owned physical input is unavailable outside the pinned X11 backend")
}

#[cfg(target_os = "macos")]
fn add_flags_to_enigo(en: &mut Enigo, key_event: &KeyEvent) {
    // When long-pressed the command key, then press and release
    // the Tab key, there should be CGEventFlagCommand in the flag.
    en.reset_flag();
    for ck in key_event.modifiers.iter() {
        if let Some(key) = KEY_MAP.get(&ck.value()) {
            en.add_flag(key);
        }
    }
}

fn get_control_key_value(key_event: &KeyEvent) -> i32 {
    if let Some(key_event::Union::ControlKey(ck)) = key_event.union {
        ck.value()
    } else {
        -1
    }
}

#[inline]
fn has_hotkey_modifiers(key_event: &KeyEvent) -> bool {
    key_event.modifiers.iter().any(|ck| {
        let v = ck.value();
        v == ControlKey::Control.value()
            || v == ControlKey::RControl.value()
            || v == ControlKey::Meta.value()
            || v == ControlKey::RWin.value()
            || {
                #[cfg(any(target_os = "windows", target_os = "linux"))]
                {
                    v == ControlKey::Alt.value() || v == ControlKey::RAlt.value()
                }
                #[cfg(target_os = "macos")]
                {
                    false
                }
            }
    })
}

fn release_unpressed_modifiers(
    en: &mut Enigo,
    key_event: &KeyEvent,
    preserve_modifiers: &[ControlKey],
) -> ResultType<()> {
    let ck_value = get_control_key_value(key_event);
    fix_modifiers(&key_event.modifiers[..], en, ck_value, preserve_modifiers)
}

#[cfg(target_os = "linux")]
fn is_altgr_pressed(en: &mut Enigo) -> bool {
    get_modifier_family_state(Key::RightAlt, en)
}

#[cfg(not(target_os = "macos"))]
fn temporary_modifiers_to_press(
    en: &mut Enigo,
    key_event: &KeyEvent,
    preserve_modifiers: &[ControlKey],
) -> Vec<RdevKey> {
    let mut to_press = Vec::new();
    for ref ck in key_event.modifiers.iter() {
        let modifier = ck.enum_value_or(ControlKey::Unknown);
        if preserve_modifiers.contains(&modifier) {
            continue;
        }
        if let (Some(key), Some(physical_key)) = (
            control_key_value_to_key(ck.value()),
            control_key_to_rdev_key(ck.value()),
        ) {
            if !is_pressed(&key, en) {
                #[cfg(target_os = "linux")]
                if key == Key::Alt && is_altgr_pressed(en) {
                    continue;
                }
                to_press.push(physical_key);
            }
        }
    }
    to_press
}

fn sync_modifiers(
    en: &mut Enigo,
    key_event: &KeyEvent,
    preserve_modifiers: &[ControlKey],
    _to_release: &mut Vec<RdevKey>,
) -> ResultType<()> {
    #[cfg(target_os = "macos")]
    add_flags_to_enigo(en, key_event);

    if key_event.down {
        release_unpressed_modifiers(en, key_event, preserve_modifiers)?;
        #[cfg(not(target_os = "macos"))]
        {
            let to_press = temporary_modifiers_to_press(en, key_event, preserve_modifiers);
            _to_release.extend(press_temporary_keys(&to_press, "key modifier")?);
        }
    }
    Ok(())
}

fn process_control_key(ck: &EnumOrUnknown<ControlKey>, down: bool) -> ResultType<()> {
    if let Some(key) = control_key_to_rdev_key(ck.value()) {
        let event = if down {
            EventType::KeyPress(key)
        } else {
            EventType::KeyRelease(key)
        };
        simulate_(&event)?;
    }
    Ok(())
}

fn process_unicode(en: &mut Enigo, chr: u32) -> ResultType<()> {
    let chr = char::try_from(chr)
        .map_err(|_| hbb_common::anyhow::anyhow!("invalid Unicode scalar value"))?;
    #[cfg(target_os = "windows")]
    crate::platform::windows::send_input_unicode_text(&chr.to_string())?;
    #[cfg(target_os = "linux")]
    en.key_sequence_result(&chr.to_string())
        .map_err(|err| hbb_common::anyhow::anyhow!(err.to_string()))?;
    #[cfg(target_os = "macos")]
    en.key_sequence_complete(&chr.to_string())
        .map_err(|err| hbb_common::anyhow::anyhow!(err.to_string()))?;
    Ok(())
}

fn process_seq(en: &mut Enigo, sequence: &str) -> ResultType<()> {
    #[cfg(target_os = "windows")]
    crate::platform::windows::send_input_unicode_text(sequence)?;
    #[cfg(target_os = "linux")]
    en.key_sequence_result(sequence)
        .map_err(|err| hbb_common::anyhow::anyhow!(err.to_string()))?;
    #[cfg(target_os = "macos")]
    en.key_sequence_complete(sequence)
        .map_err(|err| hbb_common::anyhow::anyhow!(err.to_string()))?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn release_keys(to_release: &[RdevKey]) -> ResultType<()> {
    release_temporary_keys(to_release, "key modifier")
}

#[cfg(not(target_os = "macos"))]
fn release_temporary_keys(to_release: &[RdevKey], context: &str) -> ResultType<()> {
    release_temporary_keys_with(to_release, context, |key| {
        simulate_(&EventType::KeyRelease(key))
    })
}

#[cfg(not(target_os = "macos"))]
fn release_temporary_keys_with(
    to_release: &[RdevKey],
    context: &str,
    mut release: impl FnMut(RdevKey) -> ResultType<()>,
) -> ResultType<()> {
    let mut panic_to_resume = None;
    for key in to_release.iter().rev() {
        let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| release(*key)));
        match first {
            Ok(Ok(())) => continue,
            Ok(Err(first_err)) => {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| release(*key))) {
                    Ok(Ok(())) => {
                        log::warn!(
                            "temporary {context} release for {key:?} required a retry: {first_err}"
                        );
                    }
                    Ok(Err(retry_err)) => {
                        log::error!(
                            "Could not prove temporary {context} release for {key:?}: first={first_err}, retry={retry_err}"
                        );
                        std::process::abort();
                    }
                    Err(_) => {
                        log::error!(
                            "Temporary {context} release retry panicked for {key:?} after: {first_err}"
                        );
                        std::process::abort();
                    }
                }
            }
            Err(payload) => {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| release(*key))) {
                    Ok(Ok(())) => {
                        if panic_to_resume.is_none() {
                            panic_to_resume = Some(payload);
                        }
                    }
                    Ok(Err(retry_err)) => {
                        log::error!(
                            "Temporary {context} release panicked and retry failed for {key:?}: {retry_err}"
                        );
                        std::process::abort();
                    }
                    Err(_) => {
                        log::error!(
                            "Temporary {context} release and retry both panicked for {key:?}"
                        );
                        std::process::abort();
                    }
                }
            }
        }
    }
    if let Some(payload) = panic_to_resume {
        std::panic::resume_unwind(payload);
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn press_temporary_keys(keys: &[RdevKey], context: &str) -> ResultType<Vec<RdevKey>> {
    press_temporary_keys_with(
        keys,
        context,
        |key| {
            simulate_(&EventType::KeyPress(key))?;
            #[cfg(windows)]
            modifier_sleep();
            Ok(())
        },
        |key| simulate_(&EventType::KeyRelease(key)),
    )
}

#[cfg(not(target_os = "macos"))]
fn press_temporary_keys_with(
    keys: &[RdevKey],
    context: &str,
    mut press: impl FnMut(RdevKey) -> ResultType<()>,
    mut release: impl FnMut(RdevKey) -> ResultType<()>,
) -> ResultType<Vec<RdevKey>> {
    let mut pressed = Vec::with_capacity(keys.len());
    for key in keys {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| press(*key))) {
            Ok(Ok(())) => pressed.push(*key),
            Ok(Err(err)) => {
                release_temporary_keys_with(&pressed, context, &mut release)?;
                return Err(err);
            }
            Err(payload) => {
                if release_temporary_keys_with(&pressed, context, &mut release).is_err() {
                    std::process::abort();
                }
                std::panic::resume_unwind(payload);
            }
        }
    }
    Ok(pressed)
}

#[cfg(not(target_os = "macos"))]
fn with_temporary_keys<T>(
    keys: &[RdevKey],
    context: &str,
    action: impl FnOnce() -> ResultType<T>,
) -> ResultType<T> {
    with_temporary_keys_with(
        keys,
        context,
        |key| {
            simulate_(&EventType::KeyPress(key))?;
            #[cfg(windows)]
            modifier_sleep();
            Ok(())
        },
        action,
        |key| simulate_(&EventType::KeyRelease(key)),
    )
}

#[cfg(not(target_os = "macos"))]
fn with_temporary_keys_with<T>(
    keys: &[RdevKey],
    context: &str,
    press: impl FnMut(RdevKey) -> ResultType<()>,
    action: impl FnOnce() -> ResultType<T>,
    mut release: impl FnMut(RdevKey) -> ResultType<()>,
) -> ResultType<T> {
    let pressed = press_temporary_keys_with(keys, context, press, &mut release)?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action));
    release_temporary_keys_with(&pressed, context, release)?;
    match result {
        Ok(result) => result,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

/// Check if any hotkey modifier (Ctrl/Alt/Meta) is currently pressed.
/// Used to detect hotkey combinations like Ctrl+C, Alt+Tab, etc.
///
/// Note: Shift is intentionally NOT checked here. Shift+character produces a different
/// character (e.g., Shift+a → 'A'), which is normal text input, not a hotkey.
/// Shift is only relevant as a hotkey modifier when combined with Ctrl/Alt/Meta
/// (e.g., Ctrl+Shift+Z), in which case this function already returns true via Ctrl.
#[cfg(target_os = "linux")]
#[inline]
fn is_hotkey_modifier_pressed(en: &mut Enigo) -> bool {
    get_modifier_family_state(Key::Control, en)
        || get_modifier_family_state(Key::Alt, en)
        || get_modifier_family_state(Key::Meta, en)
}

/// Release Shift keys before character input in Legacy/Translate mode.
/// In these modes, the character has already been converted by the client,
/// so we should input it directly without Shift modifier affecting the result.
///
/// Note: Does NOT release Shift if hotkey modifiers (Ctrl/Alt/Meta) are pressed,
/// to preserve combinations like Ctrl+Shift+Z.
#[cfg(target_os = "linux")]
fn release_shift_for_char_input(
    en: &mut Enigo,
    preserve_modifiers: &[ControlKey],
) -> ResultType<()> {
    // Don't release Shift if hotkey modifiers (Ctrl/Alt/Meta) are pressed.
    // This preserves combinations like Ctrl+Shift+Z.
    if is_hotkey_modifier_pressed(en) {
        return Ok(());
    }

    // In translate mode, the client has already converted the keystroke to a character
    // (e.g., Shift+a → 'A'). We release Shift here so the server inputs the character
    // directly without Shift affecting the result.
    //
    // Shift is intentionally NOT restored after input — the client will send an explicit
    // Shift key_up event when the user physically releases Shift. Restoring it here would
    // cause a brief Shift re-press that could interfere with the next input event.

    let is_x11 = crate::platform::linux::is_x11();

    if !preserve_modifiers.contains(&ControlKey::Shift) && get_exact_key_state(Key::Shift, en) {
        if !is_x11 {
            bail!("owned modifier synchronization is unavailable outside X11");
        }
        simulate_(&EventType::KeyRelease(RdevKey::ShiftLeft))?;
    }
    if !preserve_modifiers.contains(&ControlKey::RShift) && get_exact_key_state(Key::RightShift, en)
    {
        if !is_x11 {
            bail!("owned modifier synchronization is unavailable outside X11");
        }
        simulate_(&EventType::KeyRelease(RdevKey::ShiftRight))?;
    }
    Ok(())
}

fn legacy_keyboard_mode(evt: &KeyEvent, preserve_modifiers: &[ControlKey]) -> ResultType<()> {
    #[cfg(windows)]
    crate::platform::windows::try_change_desktop();
    let mut to_release: Vec<RdevKey> = Vec::new();

    let mut en = lock_input_state(&ENIGO, "Enigo state while handling a legacy key");
    sync_modifiers(&mut en, evt, preserve_modifiers, &mut to_release)?;

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match evt.union {
        Some(key_event::Union::ControlKey(ck)) => process_control_key(&ck, evt.down),
        Some(key_event::Union::Chr(chr)) => {
            if !evt.down {
                Ok(())
            } else if has_hotkey_modifiers(evt) {
                #[cfg(target_os = "windows")]
                {
                    windows_semantic_key_click(chr, &mut en, preserve_modifiers)
                }
                #[cfg(not(target_os = "windows"))]
                {
                    bail!("Legacy character hotkeys require a physical keyboard mode")
                }
            } else {
                #[cfg(target_os = "linux")]
                release_shift_for_char_input(&mut en, preserve_modifiers)?;
                let chr = char::try_from(chr)
                    .map_err(|_| hbb_common::anyhow::anyhow!("invalid Legacy character"))?;
                process_seq(&mut en, &chr.to_string())
            }
        }
        Some(key_event::Union::Unicode(chr)) => {
            if evt.down {
                if has_hotkey_modifiers(evt) {
                    bail!("Legacy Unicode hotkeys require a physical keyboard mode");
                }
                process_unicode(&mut en, chr)?;
            }
            Ok(())
        }
        Some(key_event::Union::Seq(ref seq)) => {
            if evt.down {
                if has_hotkey_modifiers(evt) {
                    bail!("Legacy sequence hotkeys require a physical keyboard mode");
                }
                process_seq(&mut en, seq)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }));

    #[cfg(not(target_os = "macos"))]
    {
        drop(en);
        release_keys(&to_release)?;
    }
    match result {
        Ok(result) => result,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

#[cfg(target_os = "windows")]
fn windows_complete_scan_click(scan: u32) -> ResultType<()> {
    crate::platform::windows::send_input_scan_click(scan)
}

#[cfg(target_os = "windows")]
fn windows_semantic_key_click(
    chr: u32,
    en: &mut Enigo,
    preserve_modifiers: &[ControlKey],
) -> ResultType<()> {
    let unicode = u16::try_from(chr)
        .map_err(|_| hbb_common::anyhow::anyhow!("Windows semantic character exceeds UTF-16"))?;
    let foreground_thread =
        unsafe { GetWindowThreadProcessId(GetForegroundWindow(), std::ptr::null_mut()) };
    let layout = unsafe { GetKeyboardLayout(foreground_thread) };
    let mapped = unsafe { VkKeyScanExW(unicode, layout) as u16 };
    if mapped == 0xFFFF {
        bail!("character is not representable in the target Windows layout");
    }
    let vk = u32::from(mapped & 0x00FF);
    let scan = unsafe { MapVirtualKeyExW(vk, MAPVK_VK_TO_VSC_EX, layout) };
    if scan == 0 {
        bail!("target Windows layout produced no scan code");
    }

    let flags = mapped >> 8;
    if flags & !0x07 != 0 {
        bail!("target Windows layout requires unsupported semantic modifiers");
    }
    let required = [
        (
            0x01,
            ControlKey::Shift,
            ControlKey::RShift,
            Key::Shift,
            Key::RightShift,
            RdevKey::ShiftLeft,
        ),
        (
            0x02,
            ControlKey::Control,
            ControlKey::RControl,
            Key::Control,
            Key::RightControl,
            RdevKey::ControlLeft,
        ),
        (
            0x04,
            ControlKey::Alt,
            ControlKey::RAlt,
            Key::Alt,
            Key::RightAlt,
            RdevKey::Alt,
        ),
    ];
    let mut to_press = Vec::new();
    for (flag, left, right, left_key, right_key, physical) in required {
        if flags & flag == 0
            || get_exact_key_state(left_key, en)
            || get_exact_key_state(right_key, en)
            || preserve_modifiers.contains(&left)
            || preserve_modifiers.contains(&right)
        {
            continue;
        }
        to_press.push(physical);
    }
    with_temporary_keys(&to_press, "Windows semantic modifier", || {
        windows_complete_scan_click(scan)
    })
}

#[cfg(target_os = "windows")]
fn translate_process_code(code: u32, down: bool) -> ResultType<()> {
    crate::platform::windows::try_change_desktop();
    match code >> 16 {
        0 => sim_rdev_rawkey_position(code as _, down),
        vk_code => sim_rdev_rawkey_virtual(vk_code, down),
    }
}

fn translate_keyboard_mode(evt: &KeyEvent, preserve_modifiers: &[ControlKey]) -> ResultType<()> {
    match &evt.union {
        Some(key_event::Union::Seq(seq)) => {
            if !evt.down {
                return Ok(());
            }
            let mut en = lock_input_state(&ENIGO, "Enigo state while translating a key sequence");

            #[cfg(target_os = "macos")]
            {
                if has_hotkey_modifiers(evt) {
                    bail!("Translate sequence hotkeys require a physical keyboard mode");
                }
                process_seq(&mut en, seq)?;
            }
            #[cfg(target_os = "linux")]
            {
                if has_hotkey_modifiers(evt) {
                    bail!("Translate sequence hotkeys require a physical keyboard mode");
                }
                process_seq(&mut en, seq)?;
            }
            #[cfg(target_os = "windows")]
            {
                if has_hotkey_modifiers(evt) {
                    for chr in seq.chars() {
                        windows_semantic_key_click(chr as u32, &mut en, preserve_modifiers)?;
                    }
                } else {
                    process_seq(&mut en, seq)?;
                }
            }
        }
        Some(key_event::Union::Chr(..)) => {
            #[cfg(target_os = "windows")]
            translate_process_code(evt.chr(), evt.down)?;
            #[cfg(target_os = "linux")]
            {
                if !crate::platform::linux::is_x11() {
                    wayland_send_raw_key(evt.chr() as u16, evt.down)?;
                } else {
                    sim_rdev_rawkey_position(evt.chr() as _, evt.down)?;
                }
            }
            #[cfg(target_os = "macos")]
            sim_rdev_rawkey_position(evt.chr() as _, evt.down)?;
        }
        Some(key_event::Union::ControlKey(key)) => {
            #[cfg(target_os = "windows")]
            crate::platform::windows::try_change_desktop();
            process_control_key(key, evt.down)?;
        }
        #[cfg(target_os = "windows")]
        Some(key_event::Union::Win2winHotkey(code)) => {
            let mut en = lock_input_state(&ENIGO, "Enigo state while handling Win2win input");
            simulate_win2win_hotkey(*code, evt.down, &mut en, preserve_modifiers)?;
        }
        _ => {
            log::debug!(
                "Unreachable. Unexpected key event (mode={:?}, down={:?})",
                &evt.mode,
                &evt.down
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn simulate_win2win_hotkey(
    code: u32,
    down: bool,
    en: &mut Enigo,
    preserve_modifiers: &[ControlKey],
) -> ResultType<()> {
    if !down {
        return Ok(());
    }
    let unicode = code & 0x0000FFFF;
    windows_semantic_key_click(unicode, en, preserve_modifiers)
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn skip_led_sync_control_key(_key: &ControlKey) -> bool {
    false
}

// LockModesHandler should not be created when single meta is pressing and releasing.
// Because the drop function may insert "CapsLock Click" and "NumLock Click", which breaks single meta click.
// https://github.com/rustdesk/rustdesk/issues/3928#issuecomment-1496936687
// https://github.com/rustdesk/rustdesk/issues/3928#issuecomment-1500415822
// https://github.com/rustdesk/rustdesk/issues/3928#issuecomment-1500773473
#[cfg(any(target_os = "windows", target_os = "linux"))]
fn skip_led_sync_control_key(key: &ControlKey) -> bool {
    matches!(
        key,
        ControlKey::Control
            | ControlKey::RControl
            | ControlKey::Meta
            | ControlKey::Shift
            | ControlKey::RShift
            | ControlKey::Alt
            | ControlKey::RAlt
            | ControlKey::Tab
            | ControlKey::Return
    )
}

#[inline]
#[cfg(any(target_os = "windows", target_os = "linux"))]
fn is_numpad_control_key(key: &ControlKey) -> bool {
    matches!(
        key,
        ControlKey::Numpad0
            | ControlKey::Numpad1
            | ControlKey::Numpad2
            | ControlKey::Numpad3
            | ControlKey::Numpad4
            | ControlKey::Numpad5
            | ControlKey::Numpad6
            | ControlKey::Numpad7
            | ControlKey::Numpad8
            | ControlKey::Numpad9
            | ControlKey::NumpadEnter
    )
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn skip_led_sync_rdev_key(_key: &RdevKey) -> bool {
    false
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
fn skip_led_sync_rdev_key(key: &RdevKey) -> bool {
    matches!(
        key,
        RdevKey::ControlLeft
            | RdevKey::ControlRight
            | RdevKey::MetaLeft
            | RdevKey::MetaRight
            | RdevKey::ShiftLeft
            | RdevKey::ShiftRight
            | RdevKey::Alt
            | RdevKey::AltGr
            | RdevKey::Tab
            | RdevKey::Return
    )
}

#[inline]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn is_legacy_mode(evt: &KeyEvent) -> bool {
    evt.mode.enum_value_or(KeyboardMode::Legacy) == KeyboardMode::Legacy
}

fn handle_key_with_preserved_modifiers(
    evt: &KeyEvent,
    preserve_modifiers: &[ControlKey],
) -> ResultType<()> {
    if EXITING.load(Ordering::SeqCst) {
        return Ok(());
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let mut _lock_mode_handler = None;
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    match &evt.union {
        Some(key_event::Union::Unicode(..)) | Some(key_event::Union::Seq(..)) => {
            _lock_mode_handler = Some(LockModesHandler::new_handler(&evt, false)?);
        }
        Some(key_event::Union::ControlKey(ck)) => {
            let key = ck.enum_value_or(ControlKey::Unknown);
            if !skip_led_sync_control_key(&key) {
                #[cfg(target_os = "macos")]
                let is_numpad_key = false;
                #[cfg(any(target_os = "windows", target_os = "linux"))]
                let is_numpad_key = is_numpad_control_key(&key);
                _lock_mode_handler = Some(LockModesHandler::new_handler(&evt, is_numpad_key)?);
            }
        }
        Some(key_event::Union::Chr(code)) => {
            if is_legacy_mode(&evt) {
                _lock_mode_handler = Some(LockModesHandler::new_handler(evt, false)?);
            } else {
                let key = crate::keyboard::keycode_to_rdev_key(*code);
                if !skip_led_sync_rdev_key(&key) {
                    #[cfg(target_os = "macos")]
                    let is_numpad_key = false;
                    #[cfg(any(target_os = "windows", target_os = "linux"))]
                    let is_numpad_key = crate::keyboard::is_numpad_rdev_key(&key);
                    _lock_mode_handler = Some(LockModesHandler::new_handler(evt, is_numpad_key)?);
                }
            }
        }
        _ => {}
    }

    match evt.mode.enum_value() {
        Ok(KeyboardMode::Map) => {
            #[cfg(target_os = "macos")]
            set_last_legacy_mode(false);
            map_keyboard_mode(evt)
        }
        Ok(KeyboardMode::Translate) => {
            #[cfg(target_os = "macos")]
            set_last_legacy_mode(false);
            translate_keyboard_mode(evt, preserve_modifiers)
        }
        _ => {
            // All key down events are started from here,
            // so we can reset the flag of last legacy mode here.
            #[cfg(target_os = "macos")]
            set_last_legacy_mode(true);
            legacy_keyboard_mode(evt, preserve_modifiers)
        }
    }
}

#[cfg(target_os = "linux")]
pub struct TemporaryMouseMoveHandle {
    thread_handle: Option<std::thread::JoinHandle<()>>,
    tx: Option<mpsc::Sender<(i32, i32)>>,
}

#[cfg(target_os = "linux")]
impl TemporaryMouseMoveHandle {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel::<(i32, i32)>();
        let thread_handle = std::thread::spawn(move || {
            log::debug!("TemporaryMouseMoveHandle thread started");
            for (x, y) in rx {
                if let Err(err) =
                    lock_input_state(&ENIGO, "Enigo state while restoring the mouse position")
                        .mouse_move_to(x, y)
                {
                    log::error!("Could not restore the temporary mouse position: {err}");
                }
            }
            log::debug!("TemporaryMouseMoveHandle thread exiting");
        });
        TemporaryMouseMoveHandle {
            thread_handle: Some(thread_handle),
            tx: Some(tx),
        }
    }

    pub fn move_mouse_to(&self, x: i32, y: i32) {
        if let Some(tx) = &self.tx {
            let _ = tx.send((x, y));
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for TemporaryMouseMoveHandle {
    fn drop(&mut self) {
        log::debug!("Dropping TemporaryMouseMoveHandle");
        // Close the channel to signal the thread to exit.
        self.tx.take();
        // Wait for the thread to finish.
        if let Some(thread_handle) = self.thread_handle.take() {
            if let Err(e) = thread_handle.join() {
                log::error!("Error joining TemporaryMouseMoveHandle thread: {:?}", e);
            }
        }
    }
}

lazy_static::lazy_static! {
    static ref MODIFIER_MAP: HashMap<i32, Key> = [
        (ControlKey::Alt, Key::Alt),
        (ControlKey::RAlt, Key::RightAlt),
        (ControlKey::Control, Key::Control),
        (ControlKey::RControl, Key::RightControl),
        (ControlKey::Shift, Key::Shift),
        (ControlKey::RShift, Key::RightShift),
        (ControlKey::Meta, Key::Meta),
        (ControlKey::RWin, Key::RWin),
    ].iter().map(|(a, b)| (a.value(), b.clone())).collect();
    static ref KEY_MAP: HashMap<i32, Key> =
    [
        (ControlKey::Alt, Key::Alt),
        (ControlKey::Backspace, Key::Backspace),
        (ControlKey::CapsLock, Key::CapsLock),
        (ControlKey::Control, Key::Control),
        (ControlKey::Delete, Key::Delete),
        (ControlKey::DownArrow, Key::DownArrow),
        (ControlKey::End, Key::End),
        (ControlKey::Escape, Key::Escape),
        (ControlKey::F1, Key::F1),
        (ControlKey::F10, Key::F10),
        (ControlKey::F11, Key::F11),
        (ControlKey::F12, Key::F12),
        (ControlKey::F2, Key::F2),
        (ControlKey::F3, Key::F3),
        (ControlKey::F4, Key::F4),
        (ControlKey::F5, Key::F5),
        (ControlKey::F6, Key::F6),
        (ControlKey::F7, Key::F7),
        (ControlKey::F8, Key::F8),
        (ControlKey::F9, Key::F9),
        (ControlKey::Home, Key::Home),
        (ControlKey::LeftArrow, Key::LeftArrow),
        (ControlKey::Meta, Key::Meta),
        (ControlKey::Option, Key::Option),
        (ControlKey::PageDown, Key::PageDown),
        (ControlKey::PageUp, Key::PageUp),
        (ControlKey::Return, Key::Return),
        (ControlKey::RightArrow, Key::RightArrow),
        (ControlKey::Shift, Key::Shift),
        (ControlKey::Space, Key::Space),
        (ControlKey::Tab, Key::Tab),
        (ControlKey::UpArrow, Key::UpArrow),
        (ControlKey::Numpad0, Key::Numpad0),
        (ControlKey::Numpad1, Key::Numpad1),
        (ControlKey::Numpad2, Key::Numpad2),
        (ControlKey::Numpad3, Key::Numpad3),
        (ControlKey::Numpad4, Key::Numpad4),
        (ControlKey::Numpad5, Key::Numpad5),
        (ControlKey::Numpad6, Key::Numpad6),
        (ControlKey::Numpad7, Key::Numpad7),
        (ControlKey::Numpad8, Key::Numpad8),
        (ControlKey::Numpad9, Key::Numpad9),
        (ControlKey::Cancel, Key::Cancel),
        (ControlKey::Clear, Key::Clear),
        (ControlKey::Menu, Key::Alt),
        (ControlKey::Pause, Key::Pause),
        (ControlKey::Kana, Key::Kana),
        (ControlKey::Hangul, Key::Hangul),
        (ControlKey::Junja, Key::Junja),
        (ControlKey::Final, Key::Final),
        (ControlKey::Hanja, Key::Hanja),
        (ControlKey::Kanji, Key::Kanji),
        (ControlKey::Convert, Key::Convert),
        (ControlKey::Select, Key::Select),
        (ControlKey::Print, Key::Print),
        (ControlKey::Execute, Key::Execute),
        (ControlKey::Snapshot, Key::Snapshot),
        (ControlKey::Insert, Key::Insert),
        (ControlKey::Help, Key::Help),
        (ControlKey::Sleep, Key::Sleep),
        (ControlKey::Separator, Key::Separator),
        (ControlKey::Scroll, Key::Scroll),
        (ControlKey::NumLock, Key::NumLock),
        (ControlKey::RWin, Key::RWin),
        (ControlKey::Apps, Key::Apps),
        (ControlKey::Multiply, Key::Multiply),
        (ControlKey::Add, Key::Add),
        (ControlKey::Subtract, Key::Subtract),
        (ControlKey::Decimal, Key::Decimal),
        (ControlKey::Divide, Key::Divide),
        (ControlKey::Equals, Key::Equals),
        (ControlKey::NumpadEnter, Key::NumpadEnter),
        (ControlKey::RAlt, Key::RightAlt),
        (ControlKey::RControl, Key::RightControl),
        (ControlKey::RShift, Key::RightShift),
    ].iter().map(|(a, b)| (a.value(), b.clone())).collect();
    static ref NUMPAD_KEY_MAP: HashMap<i32, bool> =
    [
        (ControlKey::Home, true),
        (ControlKey::UpArrow, true),
        (ControlKey::PageUp, true),
        (ControlKey::LeftArrow, true),
        (ControlKey::RightArrow, true),
        (ControlKey::End, true),
        (ControlKey::DownArrow, true),
        (ControlKey::PageDown, true),
        (ControlKey::Insert, true),
        (ControlKey::Delete, true),
    ].iter().map(|(a, b)| (a.value(), b.clone())).collect();
}
