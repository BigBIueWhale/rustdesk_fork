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
