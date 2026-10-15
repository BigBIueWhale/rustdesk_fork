use super::*;
use std::{sync::mpsc, time::Instant};

fn queued_write(retire: bool) {
    assert_eq!(std::env::var("RUSTDESK_CLIPBOARD_WRITE_NATIVE").as_deref(), Ok("1"));
    set_native_clipboard_data(
        vec![ClipboardData::Text("clipboard-before-peer-write".to_owned())],
        ClipboardSide::Client,
    ).unwrap();

    let owner = ClipboardWriteOwner::new();
    let writer = owner.writer();
    let native_lock = ARBOARD_MTX.lock().unwrap();
    writer.update(vec![Clipboard {
        format: hbb_common::message_proto::ClipboardFormat::Text.into(),
        content: b"clipboard-from-peer".to_vec().into(),
        ..Default::default()
    }], ClipboardSide::Client);

    // A barrier fits only after the worker removes the SET from its one-slot
    // queue. Native SET cannot begin while this test owns ARBOARD_MTX.
    let sender = CLIPBOARD_UPDATE_TX.get().unwrap().as_ref().unwrap();
    let (completion, receiver) = mpsc::sync_channel(1);
    let mut barrier = ClipboardUpdateRequest::Barrier(completion);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match sender.try_send(barrier) {
            Ok(()) => break,
            Err(TrySendError::Full(request)) => {
                barrier = request;
                assert!(Instant::now() < deadline, "clipboard worker did not dequeue SET");
                std::thread::yield_now();
            }
            Err(TrySendError::Disconnected(_)) => panic!("clipboard worker stopped"),
        }
    }
    if retire {
        owner.close();
    }
    drop(native_lock);
    receiver.recv_timeout(Duration::from_secs(2)).unwrap();

    let mut observer = arboard::Clipboard::new().unwrap();
    let data = observer.get_formats(&[arboard::ClipboardFormat::Text]).unwrap();
    let actual = data.into_iter().find_map(|data| match data {
        ClipboardData::Text(text) => Some(text),
        _ => None,
    }).expect("actual X11 clipboard text");
    assert_eq!(actual, if retire {
        "clipboard-before-peer-write"
    } else {
        "clipboard-from-peer"
    });
    drop(owner);
    assert!(!writer.is_live());
}

#[test]
#[ignore = "requires the owned private X11 clipboard VM"]
fn live_owner_publishes_a_queued_peer_write_to_x11() {
    queued_write(false);
}

#[test]
#[ignore = "requires the owned private X11 clipboard VM"]
fn retired_owner_cannot_publish_a_dequeued_write_after_the_native_lock() {
    queued_write(true);
}
