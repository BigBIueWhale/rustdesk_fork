use super::*;
use crate::{client::{viewer_command_channel, Data, ViewerCommandReceiver}, flutter_ffi as api};
use hbb_common::{message_proto::*, protobuf::Message as _, tokio, Stream};
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

    async fn wire_batch(&mut self, viewer: &mut Stream, peer: &mut Stream) -> Vec<KeyEvent> {
        let command = self.receiver.recv().await.unwrap().unwrap();
        let Data::KeyboardInput(command) = command else { panic!("expected keyboard command") };
        let expected = command.clone().into_events();
        command.send_to_peer(viewer).await.unwrap();
        viewer.flush_writer().await.unwrap();
        let mut received = Vec::new();
        for _ in &expected {
            let bytes = peer.next_timeout(2000).await.unwrap().unwrap();
            let message = Message::parse_from_bytes(&bytes).unwrap();
            let Some(message::Union::KeyEvent(event)) = message.union else { panic!("expected wire key event") };
            received.push(event);
        }
        assert_eq!(received, expected);
        received
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
    assert!(fixture.session.prepare_legacy_key("Control_L", false, false, false, false, false, false).events.is_empty());
    fixture.legacy(1, 1, 2, "VK_CONTROL").unwrap();
    let down = fixture.batch().await.remove(0);
    assert_eq!(down.control_key(), ControlKey::Meta);
    fixture.session.lc.write().unwrap().set_keyboard_fixture("translate", false);
    let rebuilt = fixture.session.prepare_legacy_key("VK_CONTROL", false, false, false, false, false, false);
    assert_ne!(rebuilt.events, [expected_release(down.clone())]);
    fixture.release(1, 0, None).unwrap();
    assert_eq!(fixture.batch().await, [expected_release(down)]);
}

#[tokio::test(flavor = "current_thread")]
async fn modern_and_raw_releases_reuse_the_encoded_press() {
    let _guard = super::mobile_session_lifecycle_tests::TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (connected, accepted) = tokio::join!(tokio::net::TcpStream::connect(address), listener.accept());
    let mut viewer = Stream::from(connected.unwrap(), address);
    let mut peer = Stream::from(accepted.unwrap().0, address);
    drop(listener);
    let (initiator, responder) = tokio::join!(
        hbb_common::cpace::run_initiator(viewer.as_framed_tcp_mut().unwrap(), "keyboard-wire-fixture"),
        hbb_common::cpace::run_responder(peer.as_framed_tcp_mut().unwrap(), "keyboard-wire-fixture")
    );
    viewer.set_session_keys(initiator.unwrap());
    peer.set_session_keys(responder.unwrap());
    api::session_handle_flutter_key_event(fixture.id, fixture.client, 1, fixture.round.clone(), 1, Some(0),
        String::new(), 0xe1, 0, true).unwrap();
    let down = fixture.wire_batch(&mut viewer, &mut peer).await.remove(0);
    assert!(down.down);
    assert_eq!(down.mode.enum_value().unwrap(), KeyboardMode::Map);
    fixture.release(1, 1, Some(0)).unwrap();
    assert_eq!(fixture.wire_batch(&mut viewer, &mut peer).await, [expected_release(down)]);
    api::session_handle_flutter_raw_key_event(fixture.id, fixture.client, 1, fixture.round.clone(), 2, Some(1),
        String::new(), 0xffe2, 62, 0, true).unwrap();
    let down = fixture.wire_batch(&mut viewer, &mut peer).await.remove(0);
    fixture.session.lc.write().unwrap().set_keyboard_fixture("legacy", true);
    fixture.release(1, 2, Some(1)).unwrap();
    assert_eq!(fixture.wire_batch(&mut viewer, &mut peer).await, [expected_release(down)]);
    assert_eq!(peer.as_framed_tcp_mut().unwrap().recv_counter(), 4);
    // A refused oversize send closes admission and joins the exact stream writer before return.
    let oversized = hbb_common::bytes::Bytes::from(vec![0; hbb_common::cpace::MAX_SESSION_PACKET + 1]);
    assert!(viewer.send_bytes(oversized.clone()).await.is_err());
    assert!(peer.send_bytes(oversized).await.is_err());
    println!("FLUTTER_KEYBOARD_WIRE=observed commands=4 events=4 transport=cpace-keyed-tcp writers=joined");
}

#[tokio::test(flavor = "current_thread")]
async fn a_key_up_fences_a_worker_delayed_down() {
    let _guard = super::mobile_session_lifecycle_tests::TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new();
    fixture.release(1, 8, Some(4)).unwrap();
    fixture.legacy(1, 8, 4, "VK_MENU").unwrap();
    fixture.empty().await;
    fixture.legacy(1, 9, 4, "VK_MENU").unwrap();
    assert!(fixture.batch().await[0].down);
}

#[tokio::test(flavor = "current_thread")]
async fn focus_retirement_fences_queued_input_but_admits_the_next_epoch() {
    let _guard = super::mobile_session_lifecycle_tests::TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new();
    fixture.release(1, 0, None).unwrap();
    assert!(fixture.legacy(1, 1, 0, "VK_SHIFT").is_err());
    fixture.empty().await;
    fixture.legacy(10, 2, 0, "VK_SHIFT").unwrap();
    assert!(fixture.batch().await[0].down);
    assert!(fixture.legacy(3, 3, 4, "VK_MENU").is_err());
    fixture.empty().await;
}

#[tokio::test(flavor = "current_thread")]
async fn an_old_key_up_cannot_release_a_later_press() {
    let _guard = super::mobile_session_lifecycle_tests::TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new();
    fixture.legacy(1, 1, 2, "VK_CONTROL").unwrap();
    let down = fixture.batch().await.remove(0);
    fixture.legacy(1, 2, 2, "VK_CONTROL").unwrap();
    fixture.release(1, 1, Some(2)).unwrap();
    fixture.empty().await;
    fixture.release(1, 2, Some(2)).unwrap();
    assert_eq!(fixture.batch().await, [expected_release(down)]);
}

#[tokio::test(flavor = "current_thread")]
async fn aliases_and_repeats_own_one_physical_release() {
    let _guard = super::mobile_session_lifecycle_tests::TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new();
    fixture.legacy(1, 1, 6, "Meta").unwrap();
    let down = fixture.batch().await.remove(0);
    fixture.legacy(1, 1, 6, "Meta").unwrap();
    fixture.legacy(1, 2, 8, "Meta").unwrap();
    api::session_input_key(fixture.id, fixture.client, 1, fixture.round.clone(), 3, Some(6),
        "Meta".to_owned(), false, true, false, false, false, false).unwrap();
    fixture.release(1, 1, Some(6)).unwrap();
    fixture.empty().await;
    fixture.release(1, 2, Some(8)).unwrap();
    assert_eq!(fixture.batch().await, [expected_release(down)]);
}

#[tokio::test(flavor = "current_thread")]
async fn owner_handoff_batches_old_release_before_new_input() {
    let _guard = super::mobile_session_lifecycle_tests::TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new();
    fixture.legacy(1, 1, 0, "VK_SHIFT").unwrap();
    let down = fixture.batch().await.remove(0);
    let id = SessionID::new_v4();
    let client = SessionID::new_v4();
    fixture.session.session_handlers.write().unwrap().insert(id, SessionHandler {
        client_owner_id: Some(client), ..Default::default()
    });
    api::session_input_key(id, client, 1, fixture.round.clone(), 1, Some(4), "VK_MENU".to_owned(),
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
    fixture.legacy(1, 1, 4, "VK_MENU").unwrap();
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
            name: "VK_SHIFT", down: true, press: false, alt: false, ctrl: false, shift: false, command: false,
        }).is_err());
    fixture.empty().await;
}

#[tokio::test(flavor = "current_thread")]
async fn missing_wrong_invalid_and_non_remote_owners_are_refused() {
    let _guard = super::mobile_session_lifecycle_tests::TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new();
    assert!(api::session_keyboard_input_round(fixture.id, SessionID::new_v4()).is_err());
    assert!(api::session_keyboard_input_round(SessionID::new_v4(), fixture.client).is_err());
    assert!(fixture.legacy(0, 1, 0, "VK_SHIFT").is_err());
    assert!(fixture.legacy(1, 0, 0, "VK_SHIFT").is_err());
    assert!(fixture.legacy(1, 1, 9, "VK_SHIFT").is_err());
    assert!(fixture.release(1, 0, Some(0)).is_err());
    fixture.session.lc.write().unwrap().conn_type = ConnType::FILE_TRANSFER;
    assert!(fixture.legacy(1, 1, 0, "VK_SHIFT").is_err());
    assert!(api::session_keyboard_input_round(fixture.id, fixture.client).is_err());
    fixture.empty().await;
}

#[tokio::test(flavor = "current_thread")]
async fn replaced_connection_rejects_stale_jobs_and_keeps_cleanup_on_the_old_round() {
    let _guard = super::mobile_session_lifecycle_tests::TEST_LOCK.lock().unwrap();
    let mut fixture = Fixture::new();
    fixture.legacy(1, 1, 0, "VK_SHIFT").unwrap();
    let down = fixture.batch().await.remove(0);
    let old_sender = fixture.session.sender.read().unwrap().clone().unwrap();
    let (replacement, mut receiver) = viewer_command_channel();
    *fixture.session.sender.write().unwrap() = Some(replacement);
    assert!(fixture.legacy(1, 2, 4, "VK_MENU").is_err());
    fixture.release(1, 0, None).unwrap();
    assert_eq!(fixture.batch().await, [expected_release(down)]);
    assert!(tokio::time::timeout(Duration::from_millis(1), receiver.recv()).await.is_err());
    old_sender.close().unwrap();
    fixture.round = api::session_keyboard_input_round(fixture.id, fixture.client).unwrap();
    fixture.legacy(2, 3, 4, "VK_MENU").unwrap();
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
    assert!(fixture.legacy(1, 1, 0, "VK_SHIFT").is_err());
    fixture.release(1, 0, None).unwrap();
    assert!(api::session_keyboard_input_round(fixture.id, fixture.client).is_err());
    assert!(crate::client::KeyboardInputCommand::new(vec![]).is_err());
    assert!(crate::client::KeyboardInputCommand::new(vec![KeyEvent::new(); 129]).is_err());
}
