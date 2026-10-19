use crate::{
    client::{KeyboardInputCommand, ViewerCommandSender},
    flutter::FlutterSession,
    ui_session_interface::PreparedKeyboardInput,
};
use hbb_common::{anyhow::anyhow, bail, log, message_proto::*, ResultType};
use std::sync::{
    atomic::{AtomicBool, AtomicI64, Ordering},
    Arc, OnceLock, Weak,
};

pub(crate) const MAX_INPUT_EPOCH: i64 = (1i64 << 53) - 1;

#[derive(Default)]
pub(crate) struct FlutterKeyboardRegistration(Arc<FlutterKeyboardOwner>);

impl std::ops::Deref for FlutterKeyboardRegistration {
    type Target = Arc<FlutterKeyboardOwner>;
    fn deref(&self) -> &Self::Target { &self.0 }
}

impl Drop for FlutterKeyboardRegistration {
    fn drop(&mut self) { self.0.retire(); }
}

#[derive(Default)]
pub(crate) struct FlutterKeyboardOwner {
    retired: AtomicBool,
    retired_through: AtomicI64,
    released_through: [AtomicI64; 9],
    session: OnceLock<Weak<crate::ui_session_interface::Session<crate::flutter::FlutterHandler>>>,
}

impl FlutterKeyboardOwner {
    pub(crate) fn attach(&self, session: &FlutterSession) {
        self.session.get_or_init(|| Arc::downgrade(session));
    }

    pub(crate) fn mark_retired(&self) {
        self.retired.store(true, Ordering::Release);
    }

    pub(crate) fn retire(self: &Arc<Self>) {
        self.mark_retired();
        if let Some(session) = self.session.get().and_then(Weak::upgrade) {
            let mut state = session.flutter_keyboard.lock().unwrap();
            if let Err(error) = state.release(self, MAX_INPUT_EPOCH, None, 0) {
                log::error!("Could not retire owned Flutter modifiers: {error}");
                state.discard_closed_round();
            }
        }
    }

    fn fence(&self, epoch: i64) {
        self.retired_through.fetch_max(epoch, Ordering::AcqRel);
    }
}

struct HeldModifier {
    physical: Option<rdev::Key>,
    releases: Vec<KeyEvent>,
}

struct ActiveInput {
    owner: Arc<FlutterKeyboardOwner>,
    epoch: i64,
    sender: ViewerCommandSender,
    held: [Option<Arc<HeldModifier>>; 9],
    pressed_at: [i64; 9],
}

impl ActiveInput {
    fn releases(&self, slot: Option<usize>) -> Vec<KeyEvent> {
        let mut selected: Vec<&Arc<HeldModifier>> = Vec::new();
        for (index, key) in self.held.iter().enumerate() {
            let Some(key) = key else { continue };
            if slot.is_some_and(|slot| index != slot) { continue; }
            if slot.is_some() && self.held.iter().enumerate().any(|(other, held)|
                other != index && held.as_ref().is_some_and(|held| Arc::ptr_eq(held, key))) {
                continue;
            }
            if !selected.iter().any(|selected| Arc::ptr_eq(selected, key)) {
                selected.push(key);
            }
        }
        selected.into_iter().flat_map(|key| key.releases.iter().cloned()).collect()
    }

    fn clear(&mut self, slot: Option<usize>) {
        for index in 0..self.held.len() {
            if slot.is_some_and(|slot| index != slot) { continue; }
            self.held[index] = None;
        }
    }
}

impl Drop for ActiveInput {
    fn drop(&mut self) { self.clear(None); }
}

#[derive(Default)]
pub(crate) struct FlutterKeyboardState {
    active: Option<ActiveInput>,
}

impl FlutterKeyboardState {
    fn discard_closed_round(&mut self) {
        if self.active.as_ref().is_some_and(|active| !active.sender.is_open()) {
            if let Some(active) = self.active.take() { active.owner.fence(active.epoch); }
        }
    }

    fn release(&mut self, owner: &Arc<FlutterKeyboardOwner>, epoch: i64, slot: Option<usize>, sequence: i64) -> ResultType<()> {
        if slot.is_none() { owner.fence(epoch); }
        if let Some(slot) = slot { owner.released_through[slot].fetch_max(sequence, Ordering::AcqRel); }
        self.discard_closed_round();
        let Some(active) = self.active.as_mut() else { return Ok(()) };
        if !Arc::ptr_eq(&active.owner, owner) || active.epoch > epoch { return Ok(()) }
        if slot.is_some_and(|slot| active.pressed_at[slot] > sequence) { return Ok(()) }
        let releases = active.releases(slot);
        if releases.is_empty() {
            active.clear(slot);
        } else {
            let sender = active.sender.clone();
            sender.send_keyboard_with_commit(KeyboardInputCommand::new(releases)?, || active.clear(slot))
                .map_err(|error| anyhow!(error.to_string()))?;
        }
        if slot.is_none() { self.active = None; }
        Ok(())
    }

    fn submit(
        &mut self, sender: ViewerCommandSender, owner: &Arc<FlutterKeyboardOwner>, epoch: i64,
        slot: Option<usize>, sequence: i64, prepared: PreparedKeyboardInput,
    ) -> ResultType<()> {
        self.discard_closed_round();
        if owner.retired.load(Ordering::Acquire) || epoch <= owner.retired_through.load(Ordering::Acquire) {
            bail!("Flutter keyboard input owner or epoch was retired");
        }
        if slot.is_some_and(|slot| sequence <= owner.released_through[slot].load(Ordering::Acquire)) {
            return Ok(());
        }
        if self.active.as_ref().is_some_and(|active| !active.sender.same_round(&sender)) {
            bail!("Previous keyboard connection round is still active");
        }
        if self.active.as_ref().is_some_and(|active|
            Arc::ptr_eq(&active.owner, owner) && epoch < active.epoch) {
            bail!("Flutter keyboard input epoch was superseded");
        }
        let same_owner = self.active.as_ref().is_some_and(|active|
            Arc::ptr_eq(&active.owner, owner) && active.epoch == epoch);
        if same_owner && slot.is_some_and(|slot| self.active.as_ref().is_some_and(|a|
            a.held[slot].is_some() && a.pressed_at[slot] >= sequence)) {
            return Ok(());
        }
        if same_owner && slot.is_some_and(|slot| self.active.as_ref().is_some_and(|a| a.held[slot].is_some()))
            && prepared.events.iter().all(|event| event.press) {
            return Ok(());
        }
        if prepared.events.is_empty() { return Ok(()) }
        if prepared.events.len() > 32 { bail!("Keyboard input representation is oversized"); }
        let captured = if slot.is_some() {
            let releases = prepared.events.iter().filter(|event| {
                event.down && !event.press && match (&event.union, event.mode.enum_value_or(KeyboardMode::Legacy)) {
                    (Some(key_event::Union::ControlKey(_)), _) => true,
                    (Some(key_event::Union::Chr(_)), KeyboardMode::Map | KeyboardMode::Translate) => true,
                    _ => false,
                }
            }).map(|event| {
                let mut release = event.clone();
                release.down = false;
                release.press = false;
                release.modifiers.clear();
                release
            }).collect::<Vec<_>>();
            if releases.len() > 8 { bail!("Modifier release representation is oversized"); }
            if releases.is_empty() { None } else {
                let alias = if same_owner {
                    self.active.as_ref().and_then(|active| active.held.iter().enumerate()
                        .filter(|(index, _)| Some(*index) != slot)
                        .filter_map(|(_, held)| held.as_ref()).find(|held|
                        prepared.physical.is_some() && prepared.physical == held.physical
                        || held.releases == releases)).cloned()
                } else { None };
                if let Some(alias) = alias {
                    if let (Some(slot), Some(active)) = (slot, self.active.as_mut()) {
                        active.held[slot] = Some(alias);
                        active.pressed_at[slot] = sequence;
                    }
                    return Ok(());
                }
                Some(Arc::new(HeldModifier {
                    physical: prepared.physical,
                    releases,
                }))
            }
        } else { None };
        let mut events = if same_owner {
            slot.and_then(|slot| self.active.as_ref().map(|active| active.releases(Some(slot))))
                .unwrap_or_default()
        } else {
            self.active.as_ref().map(|active| active.releases(None)).unwrap_or_default()
        };
        events.extend(prepared.events);
        let command = KeyboardInputCommand::new(events)?;
        sender.send_keyboard_with_commit(command, || {
            if !same_owner {
                if let Some(active) = self.active.take() { active.owner.fence(active.epoch); }
                self.active = Some(ActiveInput {
                    owner: owner.clone(), epoch, sender: sender.clone(),
                    held: std::array::from_fn(|_| None),
                    pressed_at: [0; 9],
                });
            }
            if let (Some(active), Some(slot)) = (self.active.as_mut(), slot) {
                active.clear(Some(slot));
                active.held[slot] = captured;
                active.pressed_at[slot] = sequence;
            }
        }).map_err(|error| anyhow!(error.to_string()))
    }
}

pub(crate) enum FlutterKeyboardRequest<'a> {
    Key { character: &'a str, usb_hid: i32, lock_modes: i32, down: bool },
    Raw { name: &'a str, platform_code: i32, position_code: i32, lock_modes: i32, down: bool },
    Legacy { name: &'a str, down: bool, press: bool, alt: bool, ctrl: bool, shift: bool, command: bool },
}

fn modifier_slot(key: Option<rdev::Key>) -> Option<usize> {
    use rdev::Key;
    match key {
        Some(Key::ShiftLeft) => Some(0), Some(Key::ShiftRight) => Some(1),
        Some(Key::ControlLeft) => Some(2), Some(Key::ControlRight) => Some(3),
        Some(Key::Alt) => Some(4), Some(Key::AltGr) => Some(5),
        Some(Key::MetaLeft) => Some(6), Some(Key::MetaRight) => Some(7),
        _ => None,
    }
}

fn validate_epoch_slot(epoch: i64, slot: Option<i32>) -> ResultType<Option<usize>> {
    if !(1..=MAX_INPUT_EPOCH).contains(&epoch) { bail!("Invalid Flutter keyboard input epoch"); }
    slot.map(|slot| usize::try_from(slot).ok().filter(|slot| *slot < 9)
        .ok_or_else(|| anyhow!("Invalid Flutter modifier slot"))).transpose()
}

pub(crate) fn dispatch(
    session: &FlutterSession, owner: &Arc<FlutterKeyboardOwner>, epoch: i64,
    round: &str, sequence: i64, slot: Option<i32>, request: FlutterKeyboardRequest<'_>,
) -> ResultType<()> {
    let slot = validate_epoch_slot(epoch, slot)?;
    if !(1..=MAX_INPUT_EPOCH).contains(&sequence) { bail!("Invalid Flutter key press sequence"); }
    let round = uuid::Uuid::parse_str(round)?;
    if !session.is_default() { bail!("Keyboard input requires a Remote session"); }
    let release = match &request {
        FlutterKeyboardRequest::Key { down, .. } | FlutterKeyboardRequest::Raw { down, .. } => !down,
        FlutterKeyboardRequest::Legacy { down, press, .. } => !down && !press,
    };
    if release && slot.is_some() {
        return session.flutter_keyboard.lock().unwrap().release(owner, epoch, slot, sequence);
    }
    let mut prepared = match request {
        FlutterKeyboardRequest::Key { character, usb_hid, lock_modes, down } => {
            if character.len() > 4096 || !(0..=65535).contains(&usb_hid) { bail!("Invalid Flutter key event"); }
            session.prepare_flutter_key_event(&session.get_keyboard_mode(), character, usb_hid, lock_modes, down)?
        }
        FlutterKeyboardRequest::Raw { name, platform_code, position_code, lock_modes, down } => {
            if name.len() > 4096 { bail!("Invalid raw Flutter key event"); }
            session.prepare_flutter_raw_key_event(&session.get_keyboard_mode(), name, platform_code, position_code, lock_modes, down)?
        }
        FlutterKeyboardRequest::Legacy { name, down, press, alt, ctrl, shift, command } => {
            if name.len() > 4096 { bail!("Invalid legacy Flutter key event"); }
            session.prepare_legacy_key(name, down, press, alt, ctrl, shift, command)
        }
    };
    for event in &mut prepared.events { session.swap_modifier_key(event); }
    let slot = slot.or_else(|| modifier_slot(prepared.physical));
    session.connection_round_owner.with_connected(|| {
        let sender = session.sender.read().unwrap().clone()
            .ok_or_else(|| anyhow!("Keyboard connection round is unavailable"))?;
        if sender.keyboard_round() != round { bail!("Flutter keyboard connection round was replaced"); }
        let mut state = session.flutter_keyboard.lock().unwrap();
        if release {
            if let Some(slot) = slot { return state.release(owner, epoch, Some(slot), sequence); }
            if !state.active.as_ref().is_some_and(|active|
                Arc::ptr_eq(&active.owner, owner) && active.epoch == epoch) { return Ok(()) }
        }
        state.submit(sender, owner, epoch, slot, sequence, prepared)
    }).ok_or_else(|| anyhow!("Flutter keyboard connection is not ready"))?
}

pub(crate) fn input_round(session: &FlutterSession) -> ResultType<String> {
    if !session.is_default() { bail!("Keyboard input requires a Remote session"); }
    session.connection_round_owner.with_connected(|| {
        let sender = session.sender.read().unwrap();
        let sender = sender.as_ref().filter(|sender| sender.is_open())
            .ok_or_else(|| anyhow!("Keyboard connection round is unavailable"))?;
        Ok(sender.keyboard_round().to_string())
    }).ok_or_else(|| anyhow!("Flutter keyboard connection is not ready"))?
}

pub(crate) fn release(
    session: &FlutterSession, owner: &Arc<FlutterKeyboardOwner>, epoch: i64, slot: Option<i32>, sequence: i64,
) -> ResultType<()> {
    let slot = validate_epoch_slot(epoch, slot)?;
    if slot.is_some() && !(1..=MAX_INPUT_EPOCH).contains(&sequence) { bail!("Invalid Flutter key release sequence"); }
    session.flutter_keyboard.lock().unwrap().release(owner, epoch, slot, sequence)
}
