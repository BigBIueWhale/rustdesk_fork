use super::*;
use crate::viewer_pipeline_smoke_tests::ViewerPipelineUi;
use hbb_common::{
    cpace::{run_initiator, run_responder},
    tokio::net::{TcpListener, TcpStream},
};
use std::panic::{resume_unwind, AssertUnwindSafe};

struct Fixture {
    root: PathBuf,
    previous_options: Vec<(&'static str, Option<String>)>,
}

impl Fixture {
    fn new(fail_output: bool) -> Self {
        let root = std::env::temp_dir().join(format!(
            "viewer-recording-status-{}", uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&root).expect("private recording fixture");
        let blocker = root.join("not-a-directory");
        std::fs::write(&blocker, b"retained").expect("recording path canary");
        let directory = if fail_output {
            blocker.join("recordings")
        } else {
            root.join("recordings")
        };
        let mut options = config::OVERWRITE_LOCAL_SETTINGS.write().unwrap();
        let previous_options = [
            (config::keys::OPTION_VIDEO_SAVE_DIRECTORY,
                directory.to_str().expect("UTF-8 fixture path").to_owned()),
            (config::keys::OPTION_ALLOW_AUTO_RECORD_OUTGOING, "N".to_owned()),
        ].into_iter().map(|(key, value)| (key, options.insert(key.to_owned(), value)))
            .collect();
        Self { root, previous_options }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let mut options = config::OVERWRITE_LOCAL_SETTINGS.write().unwrap();
        for (key, previous) in self.previous_options.drain(..) {
            match previous {
                Some(value) => { options.insert(key.to_owned(), value); }
                None => { options.remove(key); }
            }
        }
        drop(options);
        std::fs::remove_dir_all(&self.root).expect("remove owned recording fixture");
    }
}

async fn keyed_pair() -> (Stream, Stream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("guest-only listener");
    let address = listener.local_addr().unwrap();
    let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
    let mut viewer = Stream::from(client.unwrap(), address);
    let mut peer = Stream::from(accepted.unwrap().0, address);
    let (initiator, responder) = tokio::join!(
        run_initiator(viewer.as_framed_tcp_mut().unwrap(), "recording-status-fixture"),
        run_responder(peer.as_framed_tcp_mut().unwrap(), "recording-status-fixture")
    );
    viewer.set_session_keys(initiator.expect("viewer PAKE"));
    peer.set_session_keys(responder.expect("peer PAKE"));
    (viewer, peer)
}

async fn recording_status_case(fail_output: bool) {
    let fixture = Fixture::new(fail_output);
    let handler = Session::<ViewerPipelineUi>::default();
    {
        let mut config = handler.lc.write().unwrap();
        config.id = "127.0.0.1".to_owned();
        config.record_permission = true;
        config.peer_info = Some(PeerInfo {
            displays: vec![DisplayInfo { width: 640, height: 480, ..Default::default() }],
            ..Default::default()
        });
    }
    let ui = handler.ui_handler.clone();
    let (sender, receiver) = client::viewer_command_channel();
    *handler.sender.write().unwrap() = Some(sender.clone());
    let (refresh_sender, refresh) = viewer_video_refresh_channel();
    *handler.video_refresh_sender.write().unwrap() = Some(refresh_sender);
    let mut remote = Remote::new(handler, receiver, sender, refresh);

    let result = AssertUnwindSafe(async {
        let (mut viewer, _peer) = keyed_pair().await;
        assert!(remote.handle_msg_from_ui(Data::RecordScreen(true), &mut viewer).await);
        assert_eq!(remote.recording_status, RecordingStatus::Starting,
            "recording requested before the first frame must remain cancellable");
        assert_eq!(remote.handler.recording_status(), RecordingStatus::Starting,
            "a newly attached UI must observe the pending recording request");
        assert!(remote.handle_msg_from_ui(Data::RecordScreen(false), &mut viewer).await);
        assert_eq!(remote.recording_status, RecordingStatus::Stopped);
        assert!(remote.new_video_thread(0, &mut viewer).await, "real decoder worker admitted");
        if !fail_output {
            assert!(remote.handle_msg_from_ui(Data::RecordScreen(true), &mut viewer).await);
            assert_eq!(remote.recording_status, RecordingStatus::Starting);
            let first = remote.recording.as_ref().unwrap().clone();
            let pending = first.writer(0).expect("owned pending recording writer");
            assert!(remote.handle_msg_from_ui(Data::RecordScreen(false), &mut viewer).await);
            assert!(remote.handle_msg_from_ui(Data::RecordScreen(true), &mut viewer).await);
            assert_eq!(remote.recording_status, RecordingStatus::Stopping);
            assert_eq!(remote.handler.recording_status(), RecordingStatus::Stopping,
                "a newly attached UI must observe the draining recording attempt");
            assert!(Arc::ptr_eq(remote.recording.as_ref().unwrap(), &first),
                "retry replaced an undrained recording attempt");
            drop(pending);
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                assert!(remote.update_record_state(&mut viewer).await);
                if remote.recording.as_ref().map_or(false, |next| !Arc::ptr_eq(next, &first)) {
                    break;
                }
                assert!(Instant::now() < deadline, "pending recording retry failed to drain");
                let _ = time::timeout(Duration::from_millis(10), remote.recording_changed.notified()).await;
            }
            assert_eq!(first.snapshot().writers, 0);
            assert!(!fixture.root.join("recordings").exists(), "unwritten stop created output");
        }
        assert!(remote.handle_msg_from_ui(Data::RecordScreen(true), &mut viewer).await);
        let (mut frame, _) = client::video_handler_tests::visible_and_hidden_frames();
        let Some(video_frame::Union::Vp8s(encoded)) = &frame.union else {
            panic!("native VP8 fixture frame");
        };
        let encoded = encoded.frames[0].data.to_vec();
        frame.generation = 1;
        assert_eq!(remote.video_threads[&0].media_thread.admit_received_frame(
            frame.clone(), true, std::time::Instant::now()
        ), VideoFrameAdmission::Queued);

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut second_frame_sent = false;
        loop {
            let (status, frames, first_callback_drained) = ui.recording_observation();
            if first_callback_drained && !second_frame_sent {
                frame.generation = 2;
                // Keep this healthy control in one source-clock epoch.
                let Some(video_frame::Union::Vp8s(encoded)) = &mut frame.union else { panic!("VP8 fixture"); };
                encoded.frames[0].pts = 2000;
                assert_eq!(remote.video_threads[&0].media_thread.admit_received_frame(
                    frame.clone(), true, std::time::Instant::now()
                ), VideoFrameAdmission::Queued);
                second_frame_sent = true;
            }
            let expected = if fail_output { RecordingStatus::Stopped } else { RecordingStatus::Active };
            if frames >= 2 && status == Some(!fail_output) && remote.recording_status == expected { break; }
            if Instant::now() >= deadline { break; }
            tokio::select! {
                _ = remote.recording_changed.notified() => {
                    assert!(remote.update_record_state(&mut viewer).await,
                        "recording completion must not close the connection");
                }
                command = time::timeout(Duration::from_millis(10), remote.receiver.recv()) => {
                    if let Ok(command) = command {
                        let command = command.expect("recording command receiver alive")
                            .expect("recording command admitted");
                        assert!(remote.handle_msg_from_ui(command, &mut viewer).await,
                            "recording failure must not close the connection");
                    }
                }
            }
        }
        let observation = ui.recording_observation();
        let recording = remote.handler.recording_status();
        let errors = ui.take_errors();
        if fail_output {
            assert_eq!(remote.recording_status, RecordingStatus::Stopped);
            assert!(!fixture.root.join("recordings").exists());
            config::OVERWRITE_LOCAL_SETTINGS.write().unwrap().insert(
                config::keys::OPTION_VIDEO_SAVE_DIRECTORY.to_owned(),
                fixture.root.join("recordings").to_str().unwrap().to_owned(),
            );
            assert!(remote.handle_msg_from_ui(Data::RecordScreen(true), &mut viewer).await);
            let deadline = Instant::now() + Duration::from_secs(3);
            for generation in [3, 4] {
                frame.generation = generation;
                let Some(video_frame::Union::Vp8s(encoded)) = &mut frame.union else { panic!("VP8 fixture"); };
                encoded.frames[0].pts = ((generation - 3) * 2000) as i64;
                assert_eq!(remote.video_threads[&0].media_thread.admit_received_frame(
                    frame.clone(), true, std::time::Instant::now()
                ), VideoFrameAdmission::Queued);
                while remote.recording_status != RecordingStatus::Active
                    || ui.recording_observation().1 < generation as usize
                {
                    assert!(Instant::now() < deadline,
                        "same-viewer recording retry failed: status={:?} observation={:?}",
                        remote.recording_status, ui.recording_observation());
                    let _ = time::timeout(Duration::from_millis(10), remote.recording_changed.notified()).await;
                    assert!(remote.update_record_state(&mut viewer).await);
                }
            }
            assert_eq!(remote.handler.recording_status(), RecordingStatus::Active);
            assert!(ui.take_errors().is_empty(), "retry reported an old failure");
        }
        assert!(remote.handle_msg_from_ui(Data::RecordScreen(false), &mut viewer).await);
        (observation, recording, errors, encoded)
    }).catch_unwind().await;
    remote.shutdown_workers().await;
    let ((status, frames, _), recording, errors, encoded) =
        result.unwrap_or_else(|panic| resume_unwind(panic));

    assert_eq!(frames, 2, "native decoding must continue after recording outcome");
    assert_eq!(std::fs::read(fixture.root.join("not-a-directory")).unwrap(), b"retained");
    if fail_output {
        assert_eq!(status, Some(false), "failed recording still advertises active status");
        assert_eq!(recording, RecordingStatus::Stopped,
            "failed recording remains selected in the session");
        assert!(!errors.is_empty(), "recording failure was not reported to the UI callback");
    } else {
        assert_eq!(status, Some(true), "working recording must remain active");
        assert_eq!(recording, RecordingStatus::Active);
        assert!(errors.is_empty(), "healthy recording errors: {errors:?}");
    }
    let files: Vec<_> = std::fs::read_dir(fixture.root.join("recordings")).unwrap()
        .map(|entry| entry.unwrap().path()).collect();
    assert_eq!(files.len(), 1, "one native recording output");
    let bytes = std::fs::read(&files[0]).unwrap();
    assert!(bytes.starts_with(&[0x1a, 0x45, 0xdf, 0xa3]), "native WebM header");
    assert_eq!(bytes.windows(encoded.len()).filter(|window| *window == encoded.as_slice()).count(),
        2, "both actual encoded frame payloads must reach the recording output");
}

#[tokio::test]
async fn recording_output_failure_stops_status_without_stopping_video() {
    recording_status_case(true).await;
}

#[tokio::test]
async fn writable_recording_keeps_status_and_produces_output() {
    recording_status_case(false).await;
}

struct FileLimit {
    original: hbb_common::libc::rlimit,
    signal: hbb_common::libc::sighandler_t,
}

impl FileLimit {
    fn zero() -> Self {
        use hbb_common::libc;
        let mut original = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut original) }, 0);
        assert!(original.rlim_cur >= 1024 * 1024);
        let signal = unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) };
        assert_ne!(signal, libc::SIG_ERR);
        let guard = Self { original, signal };
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: original.rlim_max };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &zero) }, 0);
        let mut actual = original;
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut actual) }, 0);
        assert_eq!((actual.rlim_cur, actual.rlim_max), (0, original.rlim_max));
        guard
    }
}

impl Drop for FileLimit {
    fn drop(&mut self) {
        use hbb_common::libc;
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &self.original) }, 0);
        assert_ne!(unsafe { libc::signal(libc::SIGXFSZ, self.signal) }, libc::SIG_ERR);
    }
}

async fn wait_recording(
    remote: &mut Remote<ViewerPipelineUi>, peer: &mut Stream,
    ready: impl Fn(&Remote<ViewerPipelineUi>) -> bool,
) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        assert!(remote.update_record_state(peer).await, "recording closed the connection");
        if ready(remote) { return; }
        assert!(Instant::now() < deadline, "recording did not converge: {:?}", remote.recording_status);
        tokio::select! {
            _ = remote.recording_changed.notified() => {}
            command = time::timeout(Duration::from_millis(10), remote.receiver.recv()) => {
                if let Ok(command) = command {
                    assert!(remote.handle_msg_from_ui(command.unwrap().unwrap(), peer).await);
                }
            }
        }
    }
}

#[tokio::test]
async fn multi_writer_finalization_failure_preserves_pending_retry() {
    use std::{collections::BTreeMap, io::Write};
    const CHILD: &str = "RUSTDESK_RECORDING_LATE_FAILURE_CHILD";
    const TEST: &str = "client::io_loop::recording_status_tests::multi_writer_finalization_failure_preserves_pending_retry";
    if std::env::var_os(CHILD).is_none() {
        // Resource limits and signal disposition are process-wide. Keep them
        // outside the parent test process, even when its tests run concurrently.
        let output = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(CHILD, "1").stdin(std::process::Stdio::null()).output().await.unwrap();
        assert!(output.stdout.len() + output.stderr.len() <= 64 * 1024);
        assert!(output.status.success(), "late recording failure child: {}\n{}\n{}",
            output.status, String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        assert!(String::from_utf8_lossy(&output.stdout)
            .contains("RECORDING_LATE_FAILURE=pass decoders=2 held_owners=2 retry=preserved children=joined"));
        return;
    }

    let fixture = Fixture::new(false);
    let mut handler = Session::<ViewerPipelineUi>::default();
    handler.ui_handler = ViewerPipelineUi::with_display_count(2);
    {
        let mut config = handler.lc.write().unwrap();
        config.id = "127.0.0.1".to_owned();
        config.record_permission = true;
        config.peer_info = Some(PeerInfo {
            displays: vec![DisplayInfo { width: 640, height: 480, ..Default::default() }; 2],
            ..Default::default()
        });
    }
    let ui = handler.ui_handler.clone();
    let (sender, receiver) = client::viewer_command_channel();
    *handler.sender.write().unwrap() = Some(sender.clone());
    let (refresh_sender, refresh) = viewer_video_refresh_channel();
    *handler.video_refresh_sender.write().unwrap() = Some(refresh_sender);
    let mut remote = Remote::new(handler, receiver, sender, refresh);
    let files = || -> BTreeMap<PathBuf, Vec<u8>> {
        std::fs::read_dir(fixture.root.join("recordings")).unwrap()
            .map(|entry| { let path = entry.unwrap().path();
                let bytes = std::fs::read(&path).unwrap(); (path, bytes) }).collect()
    };
    let result = AssertUnwindSafe(async {
        let (mut viewer, _peer) = keyed_pair().await;
        for display in 0..2 { assert!(remote.new_video_thread(display, &mut viewer).await); }
        assert!(remote.handle_msg_from_ui(Data::RecordScreen(true), &mut viewer).await);
        let first = remote.recording.as_ref().unwrap().clone();
        assert_eq!(first.snapshot().writers, 2);
        let (frame, _) = client::video_handler_tests::visible_and_hidden_frames();
        for display in 0..2 {
            let mut frame = frame.clone(); frame.display = display as i32; frame.generation = 1;
            assert_eq!(remote.video_threads[&display].media_thread.admit_received_frame(
                frame, true, std::time::Instant::now()), VideoFrameAdmission::Queued);
        }
        wait_recording(&mut remote, &mut viewer, |remote| {
            remote.recording_status == RecordingStatus::Active
                && remote.video_threads.values().all(|video| *video.frame_count.read().unwrap() == 1)
                && ui.recording_observation().1 == 2 && ui.recording_observation().2
        }).await;
        assert_eq!(files().len(), 2, "both actual decoder writers produced output");
        assert!(ui.take_errors().is_empty());

        // Retain one written owner and one queued reservation. Stop/retry must
        // wait for both, including a finalization error from the written owner.
        let mut late = first.writer(0).unwrap();
        let pending = first.writer(1).unwrap();
        assert!(late.write(frame.union.as_ref().unwrap(), 640, 480));
        assert!(remote.handle_msg_from_ui(Data::RecordScreen(false), &mut viewer).await);
        assert!(remote.handle_msg_from_ui(Data::RecordScreen(true), &mut viewer).await);
        wait_recording(&mut remote, &mut viewer, |_| first.snapshot().writers == 2).await;
        assert_eq!(remote.recording_status, RecordingStatus::Stopping);
        assert!(Arc::ptr_eq(remote.recording.as_ref().unwrap(), &first));
        let retained = files(); assert_eq!(retained.len(), 3);
        let mut canary = std::fs::File::create(fixture.root.join("limit-canary")).unwrap();
        let limit = FileLimit::zero();
        assert_eq!(canary.write_all(b"refused").unwrap_err().raw_os_error(), Some(hbb_common::libc::EFBIG));
        drop(late);
        drop(limit);
        assert!(remote.update_record_state(&mut viewer).await);
        assert_eq!(first.snapshot().writers, 1);
        assert_eq!(remote.recording_status, RecordingStatus::Stopping);
        assert!(remote.recording_requested, "late failure cancelled an already requested retry");
        assert!(Arc::ptr_eq(remote.recording.as_ref().unwrap(), &first));
        assert!(first.writer(0).is_none(), "retiring attempt admitted a new writer");
        assert_eq!(ui.take_errors(), vec!["custom-error: Recording: Failed: Failed to finalize WebM recording"]);
        assert!(remote.update_record_state(&mut viewer).await);
        assert!(ui.take_errors().is_empty(), "late failure was reported twice");
        assert_eq!(files(), retained, "failed finalization changed existing bytes");

        drop(pending);
        assert!(remote.update_record_state(&mut viewer).await);
        let retry = remote.recording.as_ref().unwrap().clone();
        assert!(!Arc::ptr_eq(&retry, &first));
        assert_eq!(first.snapshot().writers, 0);
        assert_eq!(retry.snapshot().writers, 2);
        assert_eq!(remote.recording_status, RecordingStatus::Starting);
        assert_eq!(files(), retained, "retry wrote before receiving a frame");
        for display in 0..2 {
            let mut frame = frame.clone(); frame.display = display as i32; frame.generation = 2;
            assert_eq!(remote.video_threads[&display].media_thread.admit_received_frame(
                frame, true, std::time::Instant::now()), VideoFrameAdmission::Queued);
        }
        wait_recording(&mut remote, &mut viewer, |remote| {
            remote.recording_status == RecordingStatus::Active
                && remote.video_threads.values().all(|video| *video.frame_count.read().unwrap() == 2)
                && ui.recording_observation().1 == 4
        }).await;
        assert!(remote.handle_msg_from_ui(Data::RecordScreen(false), &mut viewer).await);
        wait_recording(&mut remote, &mut viewer, |remote| remote.recording.is_none()).await;
        assert_eq!(remote.recording_status, RecordingStatus::Stopped);
        assert_eq!(retry.snapshot().writers, 0);
        assert!(ui.take_errors().is_empty());
        let complete = files(); assert_eq!(complete.len(), 5);
        let Some(video_frame::Union::Vp8s(encoded)) = &frame.union else { panic!("native VP8 frame"); };
        let encoded = &encoded.frames[0].data;
        for (path, bytes) in &complete {
            if !retained.contains_key(path) {
                assert!(bytes.starts_with(&[0x1a, 0x45, 0xdf, 0xa3]));
                assert_eq!(bytes.windows(encoded.len()).filter(|data| *data == encoded.as_ref()).count(), 1,
                    "retry output must contain its actual encoded frame");
            }
        }
        for (path, bytes) in retained { assert_eq!(complete[&path], bytes); }
        complete
    }).catch_unwind().await;
    remote.shutdown_workers().await;
    let complete = result.unwrap_or_else(|panic| resume_unwind(panic));
    assert!(remote.video_threads.is_empty());
    assert_eq!(files(), complete, "shutdown changed finalized output");
    println!("RECORDING_LATE_FAILURE=pass decoders=2 held_owners=2 retry=preserved children=joined");
}
