use super::*;
use crate::client::{viewer_command_channel, Data};
use hbb_common::{message_proto::{message, misc, Message}, tokio};
use std::time::Duration;

fn session() -> Session<FlutterHandler> {
    Session::default()
}

#[test]
fn absent_round_preserves_restart_state() {
    let session = session();
    let _ = session.restart_remote_device();
    assert!(!session.is_restarting_remote_device());
}

#[test]
fn closed_round_preserves_restart_state() {
    let session = session();
    let (sender, _receiver) = viewer_command_channel();
    sender.close().unwrap();
    *session.sender.write().unwrap() = Some(sender);
    let _ = session.restart_remote_device();
    assert!(!session.is_restarting_remote_device());
}

#[test]
fn retired_receiver_preserves_restart_state() {
    let session = session();
    let (sender, receiver) = viewer_command_channel();
    drop(receiver);
    *session.sender.write().unwrap() = Some(sender);
    let _ = session.restart_remote_device();
    assert!(!session.is_restarting_remote_device());
}

#[test]
fn full_round_preserves_restart_state() {
    let session = session();
    let (sender, _receiver) = viewer_command_channel();
    for _ in 0..256 {
        sender.send(Data::Message(Message::new())).unwrap();
    }
    *session.sender.write().unwrap() = Some(sender);
    let _ = session.restart_remote_device();
    assert!(!session.is_restarting_remote_device());
}

#[tokio::test(flavor = "current_thread")]
async fn accepted_restart_publishes_one_command_and_state() {
    let session = session();
    let (sender, mut receiver) = viewer_command_channel();
    *session.sender.write().unwrap() = Some(sender);
    let _ = session.restart_remote_device();
    let command = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await.unwrap().unwrap().unwrap();
    let Data::Message(message) = command else { panic!("expected restart message") };
    let Some(message::Union::Misc(misc)) = message.union else { panic!("expected misc message") };
    assert!(matches!(misc.union, Some(misc::Union::RestartRemoteDevice(true))));
    assert!(session.is_restarting_remote_device());
    assert!(tokio::time::timeout(Duration::from_millis(10), receiver.recv()).await.is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn admission_failure_is_returned_and_new_round_can_retry() {
    let session = session();
    assert!(session.restart_remote_device().is_err());
    let (closed, _closed_receiver) = viewer_command_channel();
    closed.close().unwrap();
    *session.sender.write().unwrap() = Some(closed);
    assert!(session.restart_remote_device().is_err());
    let (gone, receiver) = viewer_command_channel();
    drop(receiver);
    *session.sender.write().unwrap() = Some(gone);
    assert!(session.restart_remote_device().is_err());
    let (full, _full_receiver) = viewer_command_channel();
    for _ in 0..256 { full.send(Data::Message(Message::new())).unwrap(); }
    *session.sender.write().unwrap() = Some(full);
    assert!(session.restart_remote_device().is_err());
    assert!(!session.is_restarting_remote_device());
    let (sender, mut receiver) = viewer_command_channel();
    *session.sender.write().unwrap() = Some(sender);
    session.restart_remote_device().unwrap();
    assert!(session.is_restarting_remote_device());
    assert!(matches!(receiver.recv().await.unwrap().unwrap(), Data::Message(_)));
}

#[test]
fn replacement_round_does_not_inherit_restart_state() {
    let session = session();
    let (old, _old_receiver) = viewer_command_channel();
    *session.sender.write().unwrap() = Some(old.clone());
    session.restart_remote_device().unwrap();
    assert!(session.is_restarting_remote_device());
    let (replacement, _replacement_receiver) = viewer_command_channel();
    *session.sender.write().unwrap() = Some(replacement);
    assert!(!session.is_restarting_remote_device());
    assert!(old.restart_requested());
    session.restart_remote_device().unwrap();
    assert!(session.is_restarting_remote_device());
}

#[tokio::test(flavor = "current_thread")]
async fn non_remote_session_cannot_submit_restart() {
    let session = session();
    let (sender, mut receiver) = viewer_command_channel();
    *session.sender.write().unwrap() = Some(sender);
    for conn_type in [ConnType::FILE_TRANSFER, ConnType::PORT_FORWARD, ConnType::VIEW_CAMERA, ConnType::TERMINAL, ConnType::RDP] {
        session.lc.write().unwrap().conn_type = conn_type;
        assert!(session.restart_remote_device().is_err());
        assert!(!session.is_restarting_remote_device());
        assert!(tokio::time::timeout(Duration::from_millis(10), receiver.recv()).await.is_err());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn export_requires_the_registered_ui_owner_through_admission() {
    let _guard = super::mobile_session_lifecycle_tests::TEST_LOCK.lock().unwrap();
    sessions::clear_for_test();
    let id = SessionID::new_v4();
    let owner = SessionID::new_v4();
    let session = sessions::insert_test_session_for_owner(id, owner, "restart-fixture", ConnType::DEFAULT_CONN);
    let request = crate::flutter_ffi::session_restart_remote_device;
    let (sender, mut receiver) = viewer_command_channel();
    *session.sender.write().unwrap() = Some(sender);
    assert!(request(id, SessionID::new_v4()).is_err());
    assert!(request(SessionID::new_v4(), owner).is_err());
    assert!(!session.is_restarting_remote_device());
    assert!(tokio::time::timeout(Duration::from_millis(10), receiver.recv()).await.is_err());
    request(id, owner).unwrap();
    assert!(matches!(receiver.recv().await.unwrap().unwrap(), Data::Message(_)));
    let replacement = SessionID::new_v4();
    session.session_handlers.write().unwrap().get_mut(&id).unwrap().client_owner_id = Some(replacement);
    assert!(request(id, owner).is_err());
    assert!(tokio::time::timeout(Duration::from_millis(10), receiver.recv()).await.is_err());
    request(id, replacement).unwrap();
    assert!(matches!(receiver.recv().await.unwrap().unwrap(), Data::Message(_)));
    sessions::clear_for_test();
    assert!(request(id, replacement).is_err());
}
