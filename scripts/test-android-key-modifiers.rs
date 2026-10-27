use super::*;

fn physical(code: u32, down: bool) -> KeyEvent {
    let mut event = KeyEvent::new();
    event.mode = KeyboardMode::Map.into();
    event.set_chr(code);
    event.down = down;
    event
}

fn apply(owner: &mut Connection, event: KeyEvent) -> KeyEvent {
    // Exercise the real protobuf on both sides of the production rewrite.
    let inbound = KeyEvent::parse_from_bytes(&event.write_to_bytes().unwrap()).unwrap();
    let outbound = owner.rewrite(inbound);
    KeyEvent::parse_from_bytes(&outbound.write_to_bytes().unwrap()).unwrap()
}

fn modifiers(event: &KeyEvent) -> HashSet<ControlKey> {
    event.modifiers.iter().map(|m| m.enum_value().unwrap()).collect()
}

#[test]
fn physical_modifiers_survive_until_their_release() {
    for (code, modifier) in [(57, ControlKey::Alt), (58, ControlKey::RAlt),
        (59, ControlKey::Shift), (60, ControlKey::RShift),
        (113, ControlKey::Control), (114, ControlKey::RControl),
        (117, ControlKey::Meta), (118, ControlKey::RWin)] {
        let mut owner = Connection::default();
        assert_eq!(modifiers(&apply(&mut owner, physical(code, true))), HashSet::from([modifier]));
        for down in [true, false] {
            assert_eq!(modifiers(&apply(&mut owner, physical(29, down))), HashSet::from([modifier]));
        }
        assert!(apply(&mut owner, physical(code, false)).modifiers.is_empty());
        assert!(apply(&mut owner, physical(29, true)).modifiers.is_empty());
    }
}

#[test]
fn modifier_sides_release_independently() {
    let mut owner = Connection::default();
    apply(&mut owner, physical(59, true));
    apply(&mut owner, physical(60, true));
    let left_up = apply(&mut owner, physical(59, false));
    assert_eq!(modifiers(&left_up), HashSet::from([ControlKey::RShift]));
    assert_eq!(modifiers(&apply(&mut owner, physical(29, true))), HashSet::from([ControlKey::RShift]));
    assert!(apply(&mut owner, physical(60, false)).modifiers.is_empty());
}

#[test]
fn repeat_and_tap_do_not_corrupt_held_state() {
    let mut owner = Connection::default();
    for _ in 0..3 { apply(&mut owner, physical(113, true)); }
    let mut tap = physical(113, true);
    tap.press = true;
    assert_eq!(modifiers(&apply(&mut owner, tap)), HashSet::from([ControlKey::Control]));
    let held = apply(&mut owner, physical(29, true));
    assert_eq!(held.modifiers, vec![ControlKey::Control.into()]);
    apply(&mut owner, physical(113, false));
    let mut tap = physical(59, false);
    tap.press = true;
    assert_eq!(modifiers(&apply(&mut owner, tap)), HashSet::from([ControlKey::Shift]));
    assert!(apply(&mut owner, physical(29, true)).modifiers.is_empty());
}

#[test]
fn legacy_modifiers_and_locks_survive_rewriting() {
    let mut owner = Connection::default();
    apply(&mut owner, physical(113, true));
    let mut event = KeyEvent::new();
    event.mode = KeyboardMode::Legacy.into();
    event.set_chr('A' as u32);
    event.press = true;
    event.modifiers = vec![ControlKey::Control.into(), ControlKey::Shift.into(),
        ControlKey::CapsLock.into(), ControlKey::NumLock.into()];
    let result = apply(&mut owner, event.clone());
    assert_eq!(result, event, "supplied modifiers must survive without duplicates");
}

#[test]
fn legacy_release_clears_a_physical_hold() {
    let mut owner = Connection::default();
    apply(&mut owner, physical(113, true));
    let mut release = KeyEvent::new();
    release.mode = KeyboardMode::Legacy.into();
    release.set_control_key(ControlKey::Control);
    apply(&mut owner, release);
    assert!(apply(&mut owner, physical(29, true)).modifiers.is_empty());
    let mut down = KeyEvent::new();
    down.mode = KeyboardMode::Legacy.into();
    down.set_control_key(ControlKey::RControl);
    down.down = true;
    apply(&mut owner, down);
    assert_eq!(modifiers(&apply(&mut owner, physical(29, true))), HashSet::from([ControlKey::RControl]));
    apply(&mut owner, physical(114, false));
    assert!(apply(&mut owner, physical(29, true)).modifiers.is_empty());
}

#[test]
fn translate_modifiers_follow_physical_transitions() {
    let mut owner = Connection::default();
    for down in [true, false] {
        let mut event = physical(113, down);
        event.mode = KeyboardMode::Translate.into();
        apply(&mut owner, event);
        let result = apply(&mut owner, physical(29, true));
        assert_eq!(modifiers(&result), if down { HashSet::from([ControlKey::Control]) } else { HashSet::new() });
    }
}

#[test]
fn connection_modifiers_are_isolated() {
    let mut first = Connection::default();
    let mut second = Connection::default();
    apply(&mut first, physical(113, true));
    assert!(apply(&mut second, physical(29, true)).modifiers.is_empty());
    assert_eq!(modifiers(&apply(&mut first, physical(29, true))), HashSet::from([ControlKey::Control]));
    drop(first);
    let mut replacement = Connection::default();
    assert!(apply(&mut replacement, physical(29, true)).modifiers.is_empty());
}

#[test]
fn nonmodifiers_never_become_held_modifiers() {
    let mut owner = Connection::default();
    for code in [0, 29, 115, 143, u32::MAX] {
        for down in [true, false] {
            assert!(apply(&mut owner, physical(code, down)).modifiers.is_empty());
        }
    }
    assert!(owner.pressed_modifiers.is_empty());
}
