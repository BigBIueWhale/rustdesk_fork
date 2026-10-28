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
        assert!(remote.new_video_thread(0), "real decoder worker admitted");
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
                assert_eq!(remote.video_threads[&0].media_thread.admit_received_frame(
                    frame.clone(), true, std::time::Instant::now()
                ), VideoFrameAdmission::Queued);
                second_frame_sent = true;
            }
            if frames >= 2 && status == Some(!fail_output) { break; }
            if Instant::now() >= deadline { break; }
            if let Ok(command) = time::timeout(Duration::from_millis(10), remote.receiver.recv()).await {
                let command = command.expect("recording command receiver alive")
                    .expect("recording command admitted");
                assert!(remote.handle_msg_from_ui(command, &mut viewer).await,
                    "recording failure must not close the connection");
            }
        }
        let observation = ui.recording_observation();
        let recording = remote.handler.is_recording();
        let errors = ui.take_errors();
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
        assert!(!recording, "failed recording remains selected in the session");
        assert!(!errors.is_empty(), "recording failure was not reported to the UI callback");
        assert!(!fixture.root.join("recordings").exists());
    } else {
        assert_eq!(status, Some(true), "working recording must remain active");
        assert!(recording);
        assert!(errors.is_empty(), "healthy recording errors: {errors:?}");
        let files: Vec<_> = std::fs::read_dir(fixture.root.join("recordings")).unwrap()
            .map(|entry| entry.unwrap().path()).collect();
        assert_eq!(files.len(), 1, "one native recording output");
        let bytes = std::fs::read(&files[0]).unwrap();
        assert!(bytes.starts_with(&[0x1a, 0x45, 0xdf, 0xa3]), "native WebM header");
        assert_eq!(bytes.windows(encoded.len()).filter(|window| *window == encoded.as_slice()).count(),
            2, "both actual encoded frame payloads must reach the recording output");
    }
}

#[tokio::test]
async fn recording_output_failure_stops_status_without_stopping_video() {
    recording_status_case(true).await;
}

#[tokio::test]
async fn writable_recording_keeps_status_and_produces_output() {
    recording_status_case(false).await;
}
