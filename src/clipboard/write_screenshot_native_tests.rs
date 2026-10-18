use super::*;
use super::write_native_tests::{native_text, wait_for_native_lock};

fn screenshot(png: bytes::Bytes) -> String {
    crate::client::screenshot::handle_screenshot(png, "1".to_owned())
}

fn png() -> Vec<u8> {
    let mut bytes = Vec::new();
    repng::encode(&mut bytes, 1, 1, &[19, 83, 147, 255]).unwrap();
    bytes
}

fn seed() {
    assert_eq!(std::env::var("RUSTDESK_CLIPBOARD_WRITE_NATIVE").as_deref(), Ok("1"));
    set_native_clipboard_data(
        vec![ClipboardData::Text("before-screenshot-copy".to_owned())],
        ClipboardSide::Client,
    ).unwrap();
}

#[test]
#[ignore = "requires the owned private X11 clipboard VM"]
fn screenshot_copy_waits_for_native_publication() {
    seed();
    let expected = png();
    let content = bytes::Bytes::from(expected.clone());
    let native_lock = ARBOARD_MTX.lock().unwrap();
    let (done, completion) = mpsc::sync_channel(1);
    let caller = std::thread::spawn(move || done.send(screenshot(content)).unwrap());
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match CLIPBOARD_CTX.try_lock() {
            Err(std::sync::TryLockError::WouldBlock) => break,
            Err(std::sync::TryLockError::Poisoned(_)) => panic!("clipboard context poisoned"),
            Ok(context) => drop(context),
        }
        assert!(std::time::Instant::now() < deadline, "screenshot did not reach native admission");
        std::thread::yield_now();
    }
    let barrier = wait_for_native_lock();
    let premature = completion.recv_timeout(Duration::from_millis(150)).ok();
    let returned_early = premature.is_some();
    drop(native_lock);
    barrier.recv_timeout(Duration::from_secs(2)).unwrap();
    let result = premature.unwrap_or_else(|| completion.recv_timeout(Duration::from_secs(2)).unwrap());
    caller.join().unwrap();
    let mut observer = arboard::Clipboard::new().unwrap();
    let data = observer.get_formats(&[ClipboardFormat::ImagePng]).unwrap();
    let published = data.into_iter().find_map(|data| match data {
        ClipboardData::Image(arboard::ImageData::Png(bytes)) => Some(bytes.into_owned()),
        _ => None,
    }).unwrap();
    println!("SCREENSHOT_COPY_COMPLETION=observed returned_before_native_write={returned_early} result_empty={} png_exact={}", result.is_empty(), published == expected);
    assert!(result.is_empty());
    assert_eq!(published, expected);
    assert!(!returned_early, "screenshot copy reported success while the native write was blocked");
}

#[test]
#[ignore = "requires the owned private X11 clipboard VM"]
fn screenshot_copy_refuses_a_full_dispatcher() {
    seed();
    let owner = ClipboardWriteOwner::controlled();
    let native_lock = ARBOARD_MTX.lock().unwrap();
    owner.writer().update_controlled(vec![Clipboard {
        format: hbb_common::message_proto::ClipboardFormat::Text.into(),
        content: b"admitted-before-screenshot".to_vec().into(),
        ..Default::default()
    }]);
    let barrier = wait_for_native_lock();
    let error = screenshot(bytes::Bytes::from(png()));
    drop(native_lock);
    barrier.recv_timeout(Duration::from_secs(2)).unwrap();
    let unchanged = native_text() == "admitted-before-screenshot";
    println!("SCREENSHOT_COPY_BUSY=observed refused={} admitted_write_preserved={unchanged}", !error.is_empty());
    assert!(unchanged);
    assert!(!error.is_empty(), "full dispatcher was reported as screenshot copy success");
}

#[test]
#[ignore = "requires the owned private X11 clipboard VM"]
fn screenshot_copy_returns_payload_refusal_without_changing_clipboard() {
    seed();
    let error = screenshot(bytes::Bytes::from(vec![0; MAX_NATIVE_CLIPBOARD_PAYLOAD_BYTES + 1]));
    if let Some(Ok(sender)) = CLIPBOARD_UPDATE_TX.get() {
        let (done, completion) = mpsc::sync_channel(1);
        sender.send(ClipboardUpdateRequest::Barrier(done)).unwrap();
        completion.recv_timeout(Duration::from_secs(2)).unwrap();
    }
    let unchanged = native_text() == "before-screenshot-copy";
    println!("SCREENSHOT_COPY_LIMIT=observed refused={} clipboard_unchanged={unchanged}", !error.is_empty());
    assert!(unchanged);
    assert!(!error.is_empty(), "oversized screenshot refusal was reported as copy success");
}

#[test]
#[ignore = "requires a fresh process with an absent private X11 display"]
fn screenshot_copy_reports_native_backend_error() {
    assert_eq!(std::env::var("RUSTDESK_SCREENSHOT_NO_DISPLAY").as_deref(), Ok("1"));
    let error = screenshot(bytes::Bytes::from(png()));
    println!("SCREENSHOT_COPY_BACKEND=observed error_returned={}", !error.is_empty());
    assert!(!error.is_empty(), "unavailable native clipboard was reported as screenshot copy success");
}
