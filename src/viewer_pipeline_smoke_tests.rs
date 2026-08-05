//! Container-gated integration evidence for the production outgoing-viewer video path.
//!
//! This module is compiled only into the Linux library test artifact, and its sole test is ignored
//! by default. The test refuses to dial unless the exact smoke runtime contract is present. It is
//! intentionally not a Flutter, compositor, focus, Android-lifecycle, Windows, or installed-service
//! test.

use crate::{
    client::QualityStatus,
    ui_session_interface::{InvokeUiSession, Session},
};
use hbb_common::{message_proto::*, rendezvous_proto::ConnType, VIDEO_FRAME_RECEIPT_VERSION};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    path::Path,
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant},
};

const EXACT_TEST_EXECUTABLE: &str = "/smoke-target/production-viewer-pipeline-tests";
const EXACT_WORKING_DIRECTORY: &str = "/work";
const EXACT_HOME: &str = "/tmp/rd-video-pipeline";
const EXACT_PEER: &str = "127.0.0.1:21118";
const FIXTURE_PASSWORD: &str = "Str0ng-Test-Pw-123";
const EXPECTED_WIDTH: usize = 640;
const EXPECTED_HEIGHT: usize = 480;
const PUBLICATION_STALL: Duration = Duration::from_millis(1_500);
const MIN_PUBLICATION_STALL: Duration = Duration::from_millis(1_400);
const MAX_POST_STALL_RECOVERY: Duration = Duration::from_millis(2_500);
const PIPELINE_DEADLINE: Duration = Duration::from_secs(25);
const MIN_PUBLISHED_FRAMES: usize = 20;
const MIN_DISTINCT_FRAMES: usize = 10;

#[derive(Clone, Debug, Default)]
struct ViewerPipelineState {
    connected: bool,
    peer_info: bool,
    connection_type: Option<String>,
    advertised_dimensions: Option<(usize, usize)>,
    published_dimensions: Option<(usize, usize)>,
    published_frames: usize,
    distinct_frames: HashSet<[u8; 32]>,
    close_successes: usize,
    stall_started: Option<Instant>,
    stall_released: Option<Instant>,
    first_post_stall_frame: Option<Instant>,
    stall_timed_out: bool,
    errors: Vec<String>,
}

impl ViewerPipelineState {
    fn record_error(&mut self, error: String) {
        if self.errors.len() < 8 && !self.errors.contains(&error) {
            self.errors.push(error);
        }
    }

    fn complete(&self) -> bool {
        self.connected
            && self.peer_info
            && self.connection_type.as_deref() == Some("TCP")
            && self.advertised_dimensions == Some((EXPECTED_WIDTH, EXPECTED_HEIGHT))
            && self.published_dimensions == Some((EXPECTED_WIDTH, EXPECTED_HEIGHT))
            && self.published_frames >= MIN_PUBLISHED_FRAMES
            && self.distinct_frames.len() >= MIN_DISTINCT_FRAMES
            && self.close_successes > 0
            && self.stall_released.is_some()
            && self.first_post_stall_frame.is_some()
            && self.stall_timed_out
            && self.errors.is_empty()
    }

    fn stall_duration(&self) -> Option<Duration> {
        self.stall_released?
            .checked_duration_since(self.stall_started?)
    }

    fn recovery_duration(&self) -> Option<Duration> {
        self.first_post_stall_frame?
            .checked_duration_since(self.stall_released?)
    }
}

#[derive(Clone, Default)]
struct ViewerPipelineUi {
    state: Arc<(Mutex<ViewerPipelineState>, Condvar)>,
}

impl ViewerPipelineUi {
    fn update(&self, update: impl FnOnce(&mut ViewerPipelineState)) {
        let (state, ready) = &*self.state;
        let mut state = state.lock().unwrap();
        update(&mut state);
        drop(state);
        ready.notify_all();
    }

    fn wait_for_completion(&self, timeout: Duration) -> ViewerPipelineState {
        let deadline = Instant::now() + timeout;
        let (state, ready) = &*self.state;
        let mut state = state.lock().unwrap();
        loop {
            if state.complete() || !state.errors.is_empty() {
                return state.clone();
            }
            let now = Instant::now();
            if now >= deadline {
                return state.clone();
            }
            let (next, wait) = ready.wait_timeout(state, deadline - now).unwrap();
            state = next;
            if wait.timed_out() {
                return state.clone();
            }
        }
    }
}

impl InvokeUiSession for ViewerPipelineUi {
    fn set_cursor_data(&self, _cd: CursorData) {}
    fn set_cursor_id(&self, _id: String) {}
    fn set_cursor_position(&self, _cp: CursorPosition) {}

    fn set_display(&self, _x: i32, _y: i32, w: i32, h: i32, _cursor_embedded: bool, _scale: f64) {
        self.update(|state| match (usize::try_from(w), usize::try_from(h)) {
            (Ok(w), Ok(h)) => state.advertised_dimensions = Some((w, h)),
            _ => state.record_error(format!("peer advertised invalid dimensions {w}x{h}")),
        });
    }

    fn switch_display(&self, _display: &SwitchDisplay) {}

    fn set_peer_info(&self, peer_info: &PeerInfo) {
        self.update(|state| {
            if peer_info.video_frame_receipt_version != VIDEO_FRAME_RECEIPT_VERSION {
                state.record_error(format!(
                    "peer receipt version {} != {}",
                    peer_info.video_frame_receipt_version, VIDEO_FRAME_RECEIPT_VERSION
                ));
            }
            state.peer_info = true;
        });
    }

    fn set_displays(&self, _displays: &Vec<DisplayInfo>) {}
    fn set_platform_additions(&self, _data: &str) {}

    fn on_connected(&self, conn_type: ConnType) {
        self.update(|state| {
            if conn_type != ConnType::DEFAULT_CONN {
                state.record_error(format!("unexpected connection type {conn_type:?}"));
            }
            state.connected = true;
        });
    }

    fn update_privacy_mode(&self) {}
    fn set_permission(&self, _name: &str, _value: bool) {}

    fn close_success(&self) {
        self.update(|state| state.close_successes += 1);
    }

    fn update_quality_status(&self, _qs: QualityStatus) {}

    fn set_connection_type(&self, stream_type: &str) {
        self.update(|state| state.connection_type = Some(stream_type.to_owned()));
    }

    fn job_error(&self, id: i32, error: String, file_num: i32) {
        self.update(|state| {
            state.record_error(format!(
                "unexpected file job error {id}/{file_num}: {error}"
            ))
        });
    }

    fn job_done(&self, _id: i32, _file_num: i32) {}
    fn clear_all_jobs(&self) {}
    fn new_message(&self, _msg: String) {}
    fn update_transfer_list(&self) {}
    fn load_last_job(&self, _cnt: i32, _job_json: &str, _auto_start: bool) {}

    fn update_folder_files(
        &self,
        _id: i32,
        _entries: &Vec<FileEntry>,
        _path: String,
        _is_local: bool,
        _only_count: bool,
    ) {
    }

    fn confirm_delete_files(&self, _id: i32, _file_num: i32, _name: String) {}

    fn override_file_confirm(
        &self,
        _id: i32,
        _file_num: i32,
        _to: String,
        _is_upload: bool,
        _is_identical: bool,
    ) {
    }

    fn update_block_input_state(&self, _on: bool) {}

    fn job_progress(&self, _id: i32, _file_num: i32, _speed: f64, _finished_size: f64) {}

    fn adapt_size(&self) {}

    fn on_rgba(&self, display: usize, rgba: &mut scrap::ImageRgb) {
        let digest: [u8; 32] = Sha256::digest(&rgba.raw).into();
        let now = Instant::now();
        let should_stall = {
            let (state, ready) = &*self.state;
            let mut state = state.lock().unwrap();
            if display != 0 {
                state.record_error(format!("unexpected published display {display}"));
            }
            let dimensions = (rgba.w, rgba.h);
            match state.published_dimensions {
                Some(previous) if previous != dimensions => state.record_error(format!(
                    "published dimensions changed from {}x{} to {}x{}",
                    previous.0, previous.1, rgba.w, rgba.h
                )),
                None => state.published_dimensions = Some(dimensions),
                _ => {}
            }
            if rgba.raw.is_empty() {
                state.record_error("production RGBA publication was empty".to_owned());
            }
            state.published_frames += 1;
            state.distinct_frames.insert(digest);
            let should_stall = state.stall_started.is_none();
            if should_stall {
                state.stall_started = Some(now);
            } else if state.stall_released.is_some() && state.first_post_stall_frame.is_none() {
                state.first_post_stall_frame = Some(now);
            }
            drop(state);
            ready.notify_all();
            should_stall
        };

        if should_stall {
            let gate = Mutex::new(());
            let release = Condvar::new();
            let guard = gate.lock().unwrap();
            let (_guard, wait) = release.wait_timeout(guard, PUBLICATION_STALL).unwrap();
            let released_at = Instant::now();
            self.update(|state| {
                state.stall_timed_out = wait.timed_out();
                state.stall_released = Some(released_at);
            });
        }
    }

    fn msgbox(&self, msgtype: &str, title: &str, text: &str, _link: &str, _retry: bool) {
        if msgtype == "error" || msgtype == "connect-password-prompt" {
            self.update(|state| state.record_error(format!("{msgtype}: {title}: {text}")));
        }
    }

    fn cancel_msgbox(&self, _tag: &str) {}
    fn on_voice_call_started(&self) {}
    fn on_voice_call_closed(&self, _reason: &str) {}
    fn on_voice_call_waiting(&self) {}
    fn on_voice_call_incoming(&self) {}
    fn set_multiple_windows_session(&self, _sessions: Vec<WindowsSession>) {}
    fn set_current_display(&self, _display: i32) {}

    #[cfg(feature = "flutter")]
    fn is_multi_ui_session(&self) -> bool {
        false
    }

    fn update_record_status(&self, _start: bool) {}

    fn handle_screenshot_resp(
        &self,
        _sid: String,
        _request_id: String,
        _data: Option<bytes::Bytes>,
        _msg: String,
    ) {
    }

    fn handle_terminal_response(&self, _response: TerminalResponse) {}
}

#[test]
#[ignore = "runs only in the exact rootless video-pipeline smoke container"]
fn production_viewer_pipeline_recovers_after_stalled_publication_without_reconnect() {
    assert_eq!(
        std::env::var("RUSTDESK_PRODUCTION_VIEWER_PIPELINE_SMOKE").as_deref(),
        Ok("1"),
        "the production viewer smoke requires its explicit runtime marker"
    );
    let current_executable =
        std::env::current_exe().expect("the production viewer smoke must resolve its executable");
    assert_eq!(
        current_executable.as_path(),
        Path::new(EXACT_TEST_EXECUTABLE),
        "the production viewer smoke refuses any other test artifact path"
    );
    let current_directory = std::env::current_dir()
        .expect("the production viewer smoke must resolve its working directory");
    assert_eq!(
        current_directory.as_path(),
        Path::new(EXACT_WORKING_DIRECTORY),
        "the production viewer smoke refuses any other working directory"
    );
    assert_eq!(
        std::env::var("HOME").as_deref(),
        Ok(EXACT_HOME),
        "the production viewer smoke refuses any other configuration home"
    );

    let ui = ViewerPipelineUi::default();
    let session = Session {
        password: FIXTURE_PASSWORD.to_owned(),
        ui_handler: ui.clone(),
        ..Default::default()
    };
    {
        let mut login = session.lc.write().unwrap();
        login.initialize(EXACT_PEER.to_owned(), ConnType::DEFAULT_CONN, None, None);
        login.disable_audio.v = true;
        login.disable_clipboard.v = true;
    }

    let panic_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed_panics = Arc::clone(&panic_count);
    let previous_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        observed_panics.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        eprintln!("PRODUCTION_VIEWER_PIPELINE_PANIC {info}");
    }));

    let start = session.start_io_thread();
    let started = matches!(start, Ok(true));
    let snapshot = if started {
        ui.wait_for_completion(PIPELINE_DEADLINE)
    } else {
        ViewerPipelineState::default()
    };
    let joined = started && session.close_and_join();
    let retained_panic_hook = std::panic::take_hook();
    drop(retained_panic_hook);
    std::panic::set_hook(previous_panic_hook);

    assert!(
        started,
        "production viewer I/O worker did not start: {start:?}"
    );
    assert!(
        joined,
        "production viewer I/O worker had no exact join owner"
    );
    assert_eq!(
        panic_count.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a production viewer or owned media worker panicked"
    );
    assert!(
        snapshot.errors.is_empty(),
        "production viewer reported errors: {:?}",
        snapshot.errors
    );
    assert!(
        snapshot.connected,
        "production viewer never published connection readiness"
    );
    assert!(
        snapshot.peer_info,
        "production viewer never admitted exact peer metadata"
    );
    assert_eq!(snapshot.connection_type.as_deref(), Some("TCP"));
    assert_eq!(
        snapshot.advertised_dimensions,
        Some((EXPECTED_WIDTH, EXPECTED_HEIGHT))
    );
    assert_eq!(
        snapshot.published_dimensions,
        Some((EXPECTED_WIDTH, EXPECTED_HEIGHT))
    );
    assert!(
        snapshot.stall_timed_out,
        "the deliberate publication stall ended early"
    );
    let stall = snapshot
        .stall_duration()
        .expect("the deliberate publication stall must start and end");
    assert!(
        stall >= MIN_PUBLICATION_STALL,
        "publication stall was shorter than its lower bound: {stall:?}"
    );
    let recovery = snapshot
        .recovery_duration()
        .expect("a frame must be published after the deliberate stall");
    assert!(
        recovery <= MAX_POST_STALL_RECOVERY,
        "production publication failed its post-stall recovery budget: {recovery:?}"
    );
    assert!(
        snapshot.published_frames >= MIN_PUBLISHED_FRAMES,
        "too few frames reached production publication: {}",
        snapshot.published_frames
    );
    assert!(
        snapshot.distinct_frames.len() >= MIN_DISTINCT_FRAMES,
        "too few distinct frames reached production publication: {}",
        snapshot.distinct_frames.len()
    );
    assert!(
        snapshot.close_successes > 0,
        "production viewer never published first-frame completion"
    );

    println!(
        "\nPRODUCTION_VIEWER_PIPELINE_OK dimensions={}x{} frames={} distinct={} stall_ms={} recovery_ms={} connected=true peer_info=true close_successes={} teardown=io-and-media-joined",
        EXPECTED_WIDTH,
        EXPECTED_HEIGHT,
        snapshot.published_frames,
        snapshot.distinct_frames.len(),
        stall.as_millis(),
        recovery.as_millis(),
        snapshot.close_successes,
    );
}
