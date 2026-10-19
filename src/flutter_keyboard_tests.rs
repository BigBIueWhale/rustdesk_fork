use super::*;
use crate::{client::{viewer_command_channel, Data, ViewerCommandReceiver}, flutter_ffi as api};
use hbb_common::{message_proto::*, tokio};
use std::time::Duration;

struct Fixture {
    session: FlutterSession,
    id: SessionID,
    client: SessionID,
    round: String,
    receiver: ViewerCommandReceiver,
}

impl Fixture {
    fn new() -> Self {
        sessions::clear_for_test();
        let id = SessionID::new_v4();
        let client = SessionID::new_v4();
        let session = sessions::insert_test_session_for_owner(id, client, "keyboard-fixture", ConnType::DEFAULT_CONN);
        session.lc.write().unwrap().set_keyboard_fixture("map", false);
        *session.server_keyboard_enabled.write().unwrap() = true;
        let (sender, receiver) = viewer_command_channel();
        *session.sender.write().unwrap() = Some(sender);
        session.connection_round_owner.admit_connected(0, || ()).unwrap();
        let round = api::session_keyboard_input_round(id, client).unwrap();
        Self { session, id, client, round, receiver }
    }

    fn legacy(&self, epoch: i64, sequence: i64, slot: i32, name: &str) -> hbb_common::ResultType<()> {
        api::session_input_key(self.id, self.client, epoch, self.round.clone(), sequence, Some(slot),
            name.to_owned(), true, false, true, true, true, true)
    }

    fn release(&self, epoch: i64, sequence: i64, slot: Option<i32>) -> hbb_common::ResultType<()> {
        api::session_release_flutter_modifiers(self.id, self.client, epoch, sequence, slot)
    }

    async fn batch(&mut self) -> Vec<KeyEvent> {
        let command = tokio::time::timeout(Duration::from_secs(1), self.receiver.recv()).await.unwrap().unwrap().unwrap();
        match command {
            Data::KeyboardInput(command) => command.into_events(),
            _ => panic!("expected the typed keyboard batch"),
        }
    }

    async fn empty(&mut self) {
        assert!(tokio::time::timeout(Duration::from_millis(1), self.receiver.recv()).await.is_err());
    }
}

impl Drop for Fixture {
    fn drop(&mut self) { sessions::clear_for_test(); }
}

fn expected_release(mut down: KeyEvent) -> KeyEvent {
    down.down = false;
    down.press = false;
    down.modifiers.clear();
    down
}

#[tokio::test(flavor = "current_thread")]
async fn cleanup_keeps_the_accepted_swap_and_mode() {
    let _guard = super::mobile_session_lifecycle_tests::TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new();
    fixture.session.lc.write().unwrap().set_keyboard_fixture("legacy", true);
    fixture.legacy(1, 1, 2, "Control_L").unwrap();
    let down = fixture.batch().await.remove(0);
    assert_eq!(down.control_key(), ControlKey::Meta);
    fixture.session.lc.write().unwrap().set_keyboard_fixture("translate", false);
    fixture.release(1, 0, None).unwrap();
    assert_eq!(fixture.batch().await, [expected_release(down)]);
}

#[tokio::test(flavor = "current_thread")]
async fn modern_and_raw_releases_reuse_the_encoded_press() {
    let _guard = super::mobile_session_lifecycle_tests::TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new();
    api::session_handle_flutter_key_event(fixture.id, fixture.client, 1, fixture.round.clone(), 1, Some(0),
        String::new(), 0xe1, 0, true).unwrap();
    let down = fixture.batch().await.remove(0);
    assert!(down.down);
    assert_eq!(down.mode.enum_value().unwrap(), KeyboardMode::Map);
    fixture.release(1, 1, Some(0)).unwrap();
    assert_eq!(fixture.batch().await, [expected_release(down)]);
    api::session_handle_flutter_raw_key_event(fixture.id, fixture.client, 1, fixture.round.clone(), 2, Some(1),
        String::new(), 0xffe2, 62, 0, true).unwrap();
    let down = fixture.batch().await.remove(0);
    fixture.session.lc.write().unwrap().set_keyboard_fixture("legacy", true);
    fixture.release(1, 2, Some(1)).unwrap();
    assert_eq!(fixture.batch().await, [expected_release(down)]);
}

#[tokio::test(flavor = "current_thread")]
async fn a_key_up_fences_a_worker_delayed_down() {
    let _guard = super::mobile_session_lifecycle_tests::TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new();
    fixture.release(1, 8, Some(4)).unwrap();
    fixture.legacy(1, 8, 4, "Alt_L").unwrap();
    fixture.empty().await;
    fixture.legacy(1, 9, 4, "Alt_L").unwrap();
    assert!(fixture.batch().await[0].down);
}

#[tokio::test(flavor = "current_thread")]
async fn focus_retirement_fences_queued_input_but_admits_the_next_epoch() {
    let _guard = super::mobile_session_lifecycle_tests::TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new();
    fixture.release(1, 0, None).unwrap();
    assert!(fixture.legacy(1, 1, 0, "Shift_L").is_err());
    fixture.empty().await;
    fixture.legacy(2, 2, 0, "Shift_L").unwrap();
    assert!(fixture.batch().await[0].down);
}

#[tokio::test(flavor = "current_thread")]
async fn an_old_key_up_cannot_release_a_later_press() {
    let _guard = super::mobile_session_lifecycle_tests::TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new();
    fixture.legacy(1, 1, 2, "Control_L").unwrap();
    let down = fixture.batch().await.remove(0);
    fixture.legacy(1, 2, 2, "Control_L").unwrap();
    fixture.release(1, 1, Some(2)).unwrap();
    fixture.empty().await;
    fixture.release(1, 2, Some(2)).unwrap();
    assert_eq!(fixture.batch().await, [expected_release(down)]);
}

#[tokio::test(flavor = "current_thread")]
async fn aliases_and_repeats_own_one_physical_release() {
    let _guard = super::mobile_session_lifecycle_tests::TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new();
    fixture.legacy(1, 1, 6, "Meta_L").unwrap();
    let down = fixture.batch().await.remove(0);
    fixture.legacy(1, 1, 6, "Meta_L").unwrap();
    fixture.legacy(1, 2, 8, "Meta_L").unwrap();
    fixture.release(1, 1, Some(6)).unwrap();
    fixture.empty().await;
    fixture.release(1, 2, Some(8)).unwrap();
    assert_eq!(fixture.batch().await, [expected_release(down)]);
}

#[tokio::test(flavor = "current_thread")]
async fn owner_handoff_batches_old_release_before_new_input() {
    let _guard = super::mobile_session_lifecycle_tests::TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new();
    fixture.legacy(1, 1, 0, "Shift_L").unwrap();
    let down = fixture.batch().await.remove(0);
    let id = SessionID::new_v4();
    let client = SessionID::new_v4();
    fixture.session.session_handlers.write().unwrap().insert(id, SessionHandler {
        client_owner_id: Some(client), ..Default::default()
    });
    api::session_input_key(id, client, 1, fixture.round.clone(), 1, Some(4), "Alt_L".to_owned(),
        true, false, false, false, false, false).unwrap();
    let batch = fixture.batch().await;
    assert_eq!(batch.len(), 2);
    assert_eq!(batch[0], expected_release(down));
    assert!(batch[1].down);
    fixture.release(1, 0, None).unwrap();
    fixture.empty().await;
    api::session_release_flutter_modifiers(id, client, 1, 0, None).unwrap();
    assert_eq!(fixture.batch().await, [expected_release(batch[1].clone())]);
}

#[tokio::test(flavor = "current_thread")]
async fn exact_handler_retirement_releases_after_capture_admission() {
    let _guard = super::mobile_session_lifecycle_tests::TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new();
    fixture.legacy(1, 1, 4, "Alt_L").unwrap();
    let down = fixture.batch().await.remove(0);
    fixture.session.session_handlers.write().unwrap().insert(SessionID::new_v4(), SessionHandler {
        client_owner_id: Some(SessionID::new_v4()), displays: vec![0], ..Default::default()
    });
    assert!(sessions::remove_session_by_exact_ui_owner(&fixture.id, &fixture.client).is_none());
    let capture = fixture.receiver.recv().await.unwrap().unwrap();
    assert!(matches!(capture, Data::DisplaySelection(_)));
    assert_eq!(fixture.batch().await, [expected_release(down)]);
}

#[tokio::test(flavor = "current_thread")]
async fn a_retained_retired_owner_cannot_submit_input() {
    let _guard = super::mobile_session_lifecycle_tests::TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new();
    let (_, owner) = sessions::get_keyboard_input_owner(&fixture.id, &fixture.client).unwrap();
    let retired = sessions::remove_session_by_exact_ui_owner(&fixture.id, &fixture.client).unwrap();
    assert!(crate::flutter_keyboard::dispatch(&retired, &owner, 2, &fixture.round, 1, Some(0),
        crate::flutter_keyboard::FlutterKeyboardRequest::Legacy {
            name: "Shift_L", down: true, press: false, alt: false, ctrl: false, shift: false, command: false,
        }).is_err());
    fixture.empty().await;
}

#[tokio::test(flavor = "current_thread")]
async fn missing_wrong_invalid_and_non_remote_owners_are_refused() {
    let _guard = super::mobile_session_lifecycle_tests::TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new();
    assert!(api::session_keyboard_input_round(fixture.id, SessionID::new_v4()).is_err());
    assert!(api::session_keyboard_input_round(SessionID::new_v4(), fixture.client).is_err());
    assert!(fixture.legacy(0, 1, 0, "Shift_L").is_err());
    assert!(fixture.legacy(1, 0, 0, "Shift_L").is_err());
    assert!(fixture.legacy(1, 1, 9, "Shift_L").is_err());
    assert!(fixture.release(1, 0, Some(0)).is_err());
    fixture.session.lc.write().unwrap().conn_type = ConnType::FILE_TRANSFER;
    assert!(fixture.legacy(1, 1, 0, "Shift_L").is_err());
    assert!(api::session_keyboard_input_round(fixture.id, fixture.client).is_err());
    fixture.empty().await;
}

#[tokio::test(flavor = "current_thread")]
async fn replaced_connection_rejects_stale_jobs_and_keeps_cleanup_on_the_old_round() {
    let _guard = super::mobile_session_lifecycle_tests::TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new();
    fixture.legacy(1, 1, 0, "Shift_L").unwrap();
    let down = fixture.batch().await.remove(0);
    let old_sender = fixture.session.sender.read().unwrap().clone().unwrap();
    let (replacement, mut receiver) = viewer_command_channel();
    *fixture.session.sender.write().unwrap() = Some(replacement);
    assert!(fixture.legacy(1, 2, 4, "Alt_L").is_err());
    fixture.release(1, 0, None).unwrap();
    assert_eq!(fixture.batch().await, [expected_release(down)]);
    assert!(tokio::time::timeout(Duration::from_millis(1), receiver.recv()).await.is_err());
    old_sender.close().unwrap();
    fixture.round = api::session_keyboard_input_round(fixture.id, fixture.client).unwrap();
    fixture.legacy(2, 3, 4, "Alt_L").unwrap();
    assert!(matches!(receiver.recv().await.unwrap().unwrap(), Data::KeyboardInput(_)));
}

#[tokio::test(flavor = "current_thread")]
async fn bounded_command_refusal_is_terminal_without_a_cleanup_retry() {
    let _guard = super::mobile_session_lifecycle_tests::TEST_LOCK.lock().unwrap();
    let fixture = Fixture::new();
    let sender = fixture.session.sender.read().unwrap().clone().unwrap();
    let mut admitted = 0;
    while sender.send(Data::CloseVoiceCall).is_ok() {
        admitted += 1;
        assert!(admitted <= 1024);
    }
    assert!(admitted > 0);
    assert!(!sender.is_open());
    assert!(fixture.legacy(1, 1, 0, "Shift_L").is_err());
    fixture.release(1, 0, None).unwrap();
    assert!(api::session_keyboard_input_round(fixture.id, fixture.client).is_err());
    assert!(crate::client::KeyboardInputCommand::new(vec![]).is_err());
    assert!(crate::client::KeyboardInputCommand::new(vec![KeyEvent::new(); 129]).is_err());
}
