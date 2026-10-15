use super::*;
use super::write_native_tests::{native_text, wait_for_native_lock};
use crate::client::LoginConfigHandler;
use hbb_common::rendezvous_proto::ConnType;

fn text(value: &str) -> Vec<Clipboard> {
    vec![Clipboard {
        format: hbb_common::message_proto::ClipboardFormat::Text.into(),
        content: value.as_bytes().to_vec().into(),
        ..Default::default()
    }]
}

fn change_permission(reenable: bool) {
    assert_eq!(std::env::var("RUSTDESK_CLIPBOARD_WRITE_NATIVE").as_deref(), Ok("1"));
    assert_eq!(std::env::var("HOME").as_deref(), Ok("/tmp/home"));
    let mut login = LoginConfigHandler::default();
    let peer = if reenable { "127.0.0.1:21112" } else { "127.0.0.1:21111" };
    login.initialize(peer.to_owned(), ConnType::DEFAULT_CONN, None, None);
    let mut config = login.load_config();
    config.disable_clipboard.v = false;
    login.save_config(config);
    set_native_clipboard_data(
        vec![ClipboardData::Text("clipboard-before-permission-change".to_owned())],
        ClipboardSide::Client,
    ).unwrap();

    let owner = ClipboardWriteOwner::new();
    let writer = owner.writer();
    let native_lock = ARBOARD_MTX.lock().unwrap();
    login.queue_peer_clipboard(&writer, text("clipboard-from-old-permission"));
    let completion = wait_for_native_lock();
    assert!(login.toggle_option("disable-clipboard".to_owned()).is_some());
    assert!(login.disable_clipboard.v);
    if reenable {
        assert!(login.toggle_option("disable-clipboard".to_owned()).is_some());
        assert!(!login.disable_clipboard.v);
    }
    drop(native_lock);
    completion.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(native_text(), "clipboard-before-permission-change");

    if reenable {
        let native_lock = ARBOARD_MTX.lock().unwrap();
        login.queue_peer_clipboard(&writer, text("clipboard-from-fresh-permission"));
        let completion = wait_for_native_lock();
        drop(native_lock);
        completion.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(native_text(), "clipboard-from-fresh-permission");
    }
}

#[test]
#[ignore = "requires the owned private X11 clipboard VM"]
fn disabling_viewer_clipboard_retires_a_write_waiting_for_native_admission() {
    change_permission(false);
}

#[test]
#[ignore = "requires the owned private X11 clipboard VM"]
fn reenabling_viewer_clipboard_does_not_resurrect_an_old_queued_write() {
    change_permission(true);
}
