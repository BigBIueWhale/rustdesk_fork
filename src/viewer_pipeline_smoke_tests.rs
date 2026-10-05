//! Container-gated integration evidence for production outgoing-viewer video and file paths.
//!
//! This module is compiled only into the Linux library test artifact. Its tests are ignored by
//! default and refuse to dial outside their exact smoke runtime contracts. They are not Flutter,
//! compositor, focus, Android-lifecycle, Windows, or installed-service tests.

use crate::{
    client::{FileManager, QualityStatus},
    ui_session_interface::{InvokeUiSession, Session},
};
use hbb_common::{
    fs::JobType, message_proto::*, rendezvous_proto::ConnType, ResultType,
    VIDEO_FRAME_RECEIPT_VERSION,
};
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
const EXACT_FILE_TEST_EXECUTABLE: &str = "/smoke-target/production-viewer-file-tests";
const EXACT_FILE_HOME: &str = "/tmp/rd-cm-file-replay";
const FILE_SOURCE: &str = "/tmp/rd-cm-file-replay/viewer-source.bin";
const FILE_DESTINATION: &str = "/tmp/rd-cm-file-replay/viewer-downloads/viewer-source.bin";
const FILE_REFUSED_DESTINATION: &str = "/tmp/rd-cm-file-replay/viewer-downloads/viewer-refused.bin";
const FILE_REFUSAL_SENTINEL: &str = "/tmp/rd-cm-file-replay/viewer-downloads/refusal-sentinel.bin";
const FILE_REFUSAL_SENTINEL_BYTES: &[u8] = b"viewer-symlink-sentinel-unchanged";
const FILE_JOB_ID: i32 = 18001;
const FILE_LENGTH: usize = 150_001;
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

fn assert_file_absent(path: &str) {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        other => panic!("expected absent viewer artifact {path}: {other:?}"),
    }
}

#[derive(Clone, Debug, Default)]
struct ViewerPipelineState {
    connected: bool,
    peer_info: bool,
    initial_display_owner: Option<usize>,
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
    file_listing_seen: bool,
    file_done_count: usize,
    file_refusal_errors: usize,
    file_refusal_job_errors: usize,
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
            && self.initial_display_owner == Some(0)
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
    file_transfer: bool,
    expect_file_inspection_refusal: bool,
}

impl ViewerPipelineUi {
    fn update(&self, update: impl FnOnce(&mut ViewerPipelineState)) {
        let (state, ready) = &*self.state;
        let mut state = state.lock().unwrap();
        update(&mut state);
        drop(state);
        ready.notify_all();
    }

    fn wait_until(
        &self,
        timeout: Duration,
        complete: impl Fn(&ViewerPipelineState) -> bool,
    ) -> ViewerPipelineState {
        let deadline = Instant::now() + timeout;
        let (state, ready) = &*self.state;
        let mut state = state.lock().unwrap();
        loop {
            if complete(&state) || !state.errors.is_empty() {
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

    fn wait_for_completion(&self, timeout: Duration) -> ViewerPipelineState {
        self.wait_until(timeout, ViewerPipelineState::complete)
    }

    fn wait_for_file_ready(&self, timeout: Duration) -> ViewerPipelineState {
        self.wait_until(timeout, |state| state.connected && state.peer_info)
    }

    fn wait_for_file_done(&self, timeout: Duration) -> ViewerPipelineState {
        self.wait_until(timeout, |state| state.file_done_count > 0)
    }

    fn wait_for_file_refusal(&self, timeout: Duration) -> ViewerPipelineState {
        self.wait_until(timeout, |state| {
            state.file_refusal_errors == 1 && state.file_refusal_job_errors == 1
        })
    }

    fn snapshot(&self) -> ViewerPipelineState {
        self.state.0.lock().unwrap().clone()
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

    fn bind_initial_display_owner(
        &self,
        current_display: i32,
        display_count: usize,
    ) -> ResultType<()> {
        let display = usize::try_from(current_display)
            .map_err(|_| hbb_common::anyhow::anyhow!("negative initial display"))?;
        if display >= display_count {
            return Err(hbb_common::anyhow::anyhow!(
                "initial display is outside the peer inventory"
            ));
        }
        let (state, ready) = &*self.state;
        let mut state = state.lock().unwrap();
        if state.initial_display_owner.is_none() {
            if state.peer_info {
                return Err(hbb_common::anyhow::anyhow!(
                    "initial display ownership was admitted after peer publication"
                ));
            }
            state.initial_display_owner = Some(display);
        } else if !state.peer_info {
            return Err(hbb_common::anyhow::anyhow!(
                "initial display ownership was rebound before peer publication"
            ));
        }
        drop(state);
        ready.notify_all();
        Ok(())
    }

    fn set_peer_info(&self, peer_info: &PeerInfo) {
        self.update(|state| {
            if self.file_transfer {
                if hbb_common::get_version_number(&peer_info.version)
                    < hbb_common::get_version_number("1.1.10")
                {
                    state.record_error("file peer does not support digest confirmation".to_owned());
                }
                state.peer_info = true;
                return;
            }
            if state.initial_display_owner.is_none()
                || (!state.peer_info
                    && state.initial_display_owner
                        != usize::try_from(peer_info.current_display).ok())
            {
                state.record_error(
                    "peer information preceded exact initial display ownership".to_owned(),
                );
            }
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
            let expected = if self.file_transfer {
                ConnType::FILE_TRANSFER
            } else {
                ConnType::DEFAULT_CONN
            };
            if conn_type != expected {
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
            if self.expect_file_inspection_refusal
                && id == FILE_JOB_ID
                && file_num == 0
                && error.starts_with("inspect download digest failed before peer operation completion: local download digest check failed:")
            {
                state.file_refusal_job_errors += 1;
            } else {
                state.record_error(format!("unexpected file job error {id}/{file_num}: {error}"));
            }
        });
    }

    fn job_done(&self, id: i32, file_num: i32) {
        self.update(|state| {
            if self.file_transfer && id == FILE_JOB_ID && file_num == 1 {
                state.file_done_count += 1;
            } else {
                state.record_error(format!("unexpected file job completion {id}/{file_num}"));
            }
        });
    }
    fn clear_all_jobs(&self) {}
    fn new_message(&self, _msg: String) {}
    fn update_transfer_list(&self) {}
    fn load_last_job(&self, _cnt: i32, _job_json: &str, _auto_start: bool) {}

    fn update_folder_files(
        &self,
        id: i32,
        entries: &Vec<FileEntry>,
        _path: String,
        is_local: bool,
        only_count: bool,
    ) {
        if self.file_transfer && id == FILE_JOB_ID && !is_local && !only_count {
            self.update(|state| {
                if entries.len() != 1 || entries[0].size != FILE_LENGTH as u64 {
                    state.record_error("remote file listing did not match the fixture".to_owned());
                } else {
                    state.file_listing_seen = true;
                }
            });
        }
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
        if self.expect_file_inspection_refusal
            && msgtype == "error"
            && text.starts_with("inspect download digest failed before peer operation completion: local download digest check failed:")
        {
            self.update(|state| state.file_refusal_errors += 1);
        } else if msgtype == "error" || msgtype == "connect-password-prompt" {
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
        let config = login.get_config();
        config.disable_audio.v = true;
        config.disable_clipboard.v = true;
    }

    let panic_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed_panics = Arc::clone(&panic_count);
    let previous_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        observed_panics.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        eprintln!("PRODUCTION_VIEWER_PIPELINE_PANIC {info}");
    }));

    let start = session.start_io_thread();
    let started = matches!(&start, Ok(true));
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

#[test]
#[ignore = "runs only in the exact no-NIC CM file replay container"]
fn production_viewer_download_commits_the_exact_file_after_digest_confirmation() {
    assert_eq!(
        std::env::var("RUSTDESK_PRODUCTION_VIEWER_FILE_SMOKE").as_deref(),
        Ok("1"),
        "the file viewer smoke requires its explicit runtime marker"
    );
    assert_eq!(
        std::env::current_exe()
            .expect("resolve exact viewer test executable")
            .as_path(),
        Path::new(EXACT_FILE_TEST_EXECUTABLE)
    );
    assert_eq!(
        std::env::current_dir()
            .expect("resolve viewer test working directory")
            .as_path(),
        Path::new(EXACT_WORKING_DIRECTORY)
    );
    assert_eq!(std::env::var("HOME").as_deref(), Ok(EXACT_FILE_HOME));

    let expected: Vec<u8> = (0..FILE_LENGTH)
        .map(|index| ((index * 37 + 11) % 251) as u8)
        .collect();
    assert_eq!(
        std::fs::read(FILE_SOURCE).expect("read independent server-side file fixture"),
        expected
    );
    for suffix in ["", ".download", ".digest", ".download.lock"] {
        assert_file_absent(&format!("{FILE_DESTINATION}{suffix}"));
    }

    let ui = ViewerPipelineUi {
        file_transfer: true,
        ..Default::default()
    };
    let session = Session {
        password: FIXTURE_PASSWORD.to_owned(),
        ui_handler: ui.clone(),
        ..Default::default()
    };
    session
        .lc
        .write()
        .unwrap()
        .initialize(EXACT_PEER.to_owned(), ConnType::FILE_TRANSFER, None, None);

    let panic_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed_panics = Arc::clone(&panic_count);
    let previous_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        observed_panics.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        eprintln!("PRODUCTION_VIEWER_FILE_PANIC {info}");
    }));

    let start = session.start_io_thread();
    let started = matches!(&start, Ok(true));
    let ready = if started {
        ui.wait_for_file_ready(Duration::from_secs(20))
    } else {
        ViewerPipelineState::default()
    };
    let request = if ready.connected && ready.peer_info && ready.errors.is_empty() {
        Some(session.send_files(
            FILE_JOB_ID,
            JobType::Generic.into(),
            FILE_SOURCE.to_owned(),
            FILE_DESTINATION.to_owned(),
            0,
            false,
            true,
        ))
    } else {
        None
    };
    let snapshot = if matches!(&request, Some(Ok(()))) {
        ui.wait_for_file_done(Duration::from_secs(30))
    } else {
        ready
    };
    let joined = started && session.close_and_join();
    let final_state = ui.snapshot();
    let retained_panic_hook = std::panic::take_hook();
    drop(retained_panic_hook);
    std::panic::set_hook(previous_panic_hook);

    assert!(started, "production file viewer I/O worker did not start: {start:?}");
    assert!(joined, "production file viewer I/O worker was not joined");
    assert_eq!(
        panic_count.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a production file viewer worker panicked"
    );
    assert!(snapshot.errors.is_empty(), "viewer errors: {:?}", snapshot.errors);
    assert!(snapshot.connected && snapshot.peer_info, "file viewer did not connect");
    assert!(matches!(&request, Some(Ok(()))), "file request was not admitted: {request:?}");
    assert!(snapshot.file_listing_seen, "viewer did not admit the listed file size");
    assert_eq!(snapshot.file_done_count, 1, "viewer must report one exact Done");
    assert!(final_state.errors.is_empty(), "viewer teardown errors: {:?}", final_state.errors);
    assert_eq!(final_state.file_done_count, 1, "viewer reported a later duplicate Done");
    assert_eq!(
        std::fs::read(FILE_DESTINATION).expect("read committed viewer destination"),
        expected
    );
    for suffix in [".download", ".digest", ".download.lock"] {
        assert_file_absent(&format!("{FILE_DESTINATION}{suffix}"));
    }
    println!(
        "\nPRODUCTION_VIEWER_FILE_OK bytes={FILE_LENGTH} listing=exact digest=confirmed done=once destination=exact-bytes sidecars=absent teardown=joined"
    );
}

#[test]
#[ignore = "runs only in the exact no-NIC CM file replay container"]
fn production_viewer_download_refuses_a_symlink_destination_at_digest_inspection() {
    assert_eq!(
        std::env::var("RUSTDESK_PRODUCTION_VIEWER_FILE_SMOKE").as_deref(),
        Ok("1")
    );
    assert_eq!(
        std::env::current_exe()
            .expect("resolve exact viewer test executable")
            .as_path(),
        Path::new(EXACT_FILE_TEST_EXECUTABLE)
    );
    assert_eq!(
        std::env::current_dir()
            .expect("resolve viewer test working directory")
            .as_path(),
        Path::new(EXACT_WORKING_DIRECTORY)
    );
    assert_eq!(std::env::var("HOME").as_deref(), Ok(EXACT_FILE_HOME));

    let expected: Vec<u8> = (0..FILE_LENGTH)
        .map(|index| ((index * 37 + 11) % 251) as u8)
        .collect();
    assert_eq!(std::fs::read(FILE_SOURCE).expect("read server fixture"), expected);
    assert!(
        std::fs::symlink_metadata(FILE_REFUSED_DESTINATION)
            .expect("inspect refusal destination")
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        std::fs::read_link(FILE_REFUSED_DESTINATION).expect("read refusal symlink"),
        Path::new("refusal-sentinel.bin").to_path_buf()
    );
    assert_eq!(
        std::fs::read(FILE_REFUSAL_SENTINEL)
            .expect("read refusal sentinel")
            .as_slice(),
        FILE_REFUSAL_SENTINEL_BYTES
    );
    for suffix in [".download", ".digest", ".download.lock"] {
        assert_file_absent(&format!("{FILE_REFUSED_DESTINATION}{suffix}"));
    }

    let ui = ViewerPipelineUi {
        file_transfer: true,
        expect_file_inspection_refusal: true,
        ..Default::default()
    };
    let session = Session {
        password: FIXTURE_PASSWORD.to_owned(),
        ui_handler: ui.clone(),
        ..Default::default()
    };
    session
        .lc
        .write()
        .unwrap()
        .initialize(EXACT_PEER.to_owned(), ConnType::FILE_TRANSFER, None, None);

    let panic_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed_panics = Arc::clone(&panic_count);
    let previous_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        observed_panics.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        eprintln!("PRODUCTION_VIEWER_FILE_REFUSAL_PANIC {info}");
    }));

    let start = session.start_io_thread();
    let started = matches!(&start, Ok(true));
    let ready = if started {
        ui.wait_for_file_ready(Duration::from_secs(20))
    } else {
        ViewerPipelineState::default()
    };
    let request = if ready.connected && ready.peer_info && ready.errors.is_empty() {
        Some(session.send_files(
            FILE_JOB_ID,
            JobType::Generic.into(),
            FILE_SOURCE.to_owned(),
            FILE_REFUSED_DESTINATION.to_owned(),
            0,
            false,
            true,
        ))
    } else {
        None
    };
    let snapshot = if matches!(&request, Some(Ok(()))) {
        ui.wait_for_file_refusal(Duration::from_secs(30))
    } else {
        ready
    };
    let joined = started && session.close_and_join();
    let final_state = ui.snapshot();

    assert!(started, "production file viewer I/O worker did not start: {start:?}");
    assert!(joined, "production file viewer I/O worker was not joined");
    assert_eq!(
        panic_count.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a production file viewer worker panicked"
    );
    assert!(snapshot.errors.is_empty(), "viewer errors: {:?}", snapshot.errors);
    assert!(snapshot.connected && snapshot.peer_info, "file viewer did not connect");
    assert!(matches!(&request, Some(Ok(()))), "file request was not admitted: {request:?}");
    assert!(snapshot.file_listing_seen, "viewer did not admit the listed file size");
    assert_eq!(snapshot.file_refusal_errors, 1, "round error was not visible once");
    assert_eq!(snapshot.file_refusal_job_errors, 1, "job error was not visible once");
    assert_eq!(snapshot.file_done_count, 0, "unsafe destination completed a file job");
    assert!(final_state.errors.is_empty(), "viewer teardown errors: {:?}", final_state.errors);
    assert_eq!(final_state.file_refusal_errors, 1, "later round error appeared");
    assert_eq!(final_state.file_refusal_job_errors, 1, "later job error appeared");
    assert_eq!(final_state.file_done_count, 0, "later file completion appeared");
    assert_eq!(
        std::fs::read_link(FILE_REFUSED_DESTINATION).expect("read retained refusal symlink"),
        Path::new("refusal-sentinel.bin").to_path_buf()
    );
    assert_eq!(
        std::fs::read(FILE_REFUSAL_SENTINEL)
            .expect("read retained refusal sentinel")
            .as_slice(),
        FILE_REFUSAL_SENTINEL_BYTES
    );
    for suffix in [".download", ".digest", ".download.lock"] {
        assert_file_absent(&format!("{FILE_REFUSED_DESTINATION}{suffix}"));
    }
    println!(
        "\nPRODUCTION_VIEWER_FILE_REFUSAL_OK listing=exact digest=symlink-refused round-error=once job-error=once done=absent symlink=preserved sidecars=absent teardown=joined"
    );

    // The failed round is terminal, but it must not poison a fresh connection to the same peer
    // or turn its visible error into an implicit retry. Reuse the same job ID and destination to
    // catch stale round/job state after the unsafe link is removed by the local owner.
    drop(session);
    std::fs::remove_file(FILE_REFUSED_DESTINATION).expect("remove the exact refused symlink");
    assert_file_absent(FILE_REFUSED_DESTINATION);
    let recovered_ui = ViewerPipelineUi {
        file_transfer: true,
        ..Default::default()
    };
    let recovered_session = Session {
        password: FIXTURE_PASSWORD.to_owned(),
        ui_handler: recovered_ui.clone(),
        ..Default::default()
    };
    recovered_session
        .lc
        .write()
        .unwrap()
        .initialize(EXACT_PEER.to_owned(), ConnType::FILE_TRANSFER, None, None);
    let recovered_start = recovered_session.start_io_thread();
    let recovered_started = matches!(&recovered_start, Ok(true));
    let recovered_ready = if recovered_started {
        recovered_ui.wait_for_file_ready(Duration::from_secs(20))
    } else {
        ViewerPipelineState::default()
    };
    let recovered_request = if recovered_ready.connected
        && recovered_ready.peer_info
        && recovered_ready.errors.is_empty()
    {
        Some(recovered_session.send_files(
            FILE_JOB_ID,
            JobType::Generic.into(),
            FILE_SOURCE.to_owned(),
            FILE_REFUSED_DESTINATION.to_owned(),
            0,
            false,
            true,
        ))
    } else {
        None
    };
    let recovered_snapshot = if matches!(&recovered_request, Some(Ok(()))) {
        recovered_ui.wait_for_file_done(Duration::from_secs(30))
    } else {
        recovered_ready
    };
    let recovered_joined = recovered_started && recovered_session.close_and_join();
    let recovered_final = recovered_ui.snapshot();
    let old_final = ui.snapshot();
    let retained_panic_hook = std::panic::take_hook();
    drop(retained_panic_hook);
    std::panic::set_hook(previous_panic_hook);

    assert!(
        recovered_started,
        "replacement file viewer I/O worker did not start: {recovered_start:?}"
    );
    assert!(recovered_joined, "replacement file viewer I/O worker was not joined");
    assert_eq!(
        panic_count.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a production file viewer worker panicked"
    );
    assert!(
        recovered_snapshot.connected && recovered_snapshot.peer_info,
        "replacement file viewer did not connect"
    );
    assert!(
        matches!(&recovered_request, Some(Ok(()))),
        "replacement file request was not admitted: {recovered_request:?}"
    );
    assert!(
        recovered_snapshot.errors.is_empty(),
        "replacement viewer errors: {:?}",
        recovered_snapshot.errors
    );
    assert!(
        recovered_snapshot.file_listing_seen,
        "replacement viewer did not admit the listing"
    );
    assert_eq!(
        recovered_snapshot.file_done_count, 1,
        "replacement viewer must report one Done"
    );
    assert!(
        recovered_final.errors.is_empty(),
        "replacement teardown errors: {:?}",
        recovered_final.errors
    );
    assert_eq!(
        recovered_final.file_done_count, 1,
        "replacement viewer reported a duplicate Done"
    );
    assert!(
        old_final.errors.is_empty(),
        "old round emitted a later error: {:?}",
        old_final.errors
    );
    assert_eq!(old_final.file_refusal_errors, 1, "old round emitted a later error");
    assert_eq!(old_final.file_refusal_job_errors, 1, "old job emitted a later error");
    assert_eq!(old_final.file_done_count, 0, "old round acquired the replacement completion");
    assert_eq!(
        std::fs::read(FILE_REFUSED_DESTINATION).expect("read replacement viewer destination"),
        expected
    );
    assert_eq!(
        std::fs::read(FILE_REFUSAL_SENTINEL)
            .expect("read preserved refusal sentinel")
            .as_slice(),
        FILE_REFUSAL_SENTINEL_BYTES
    );
    for suffix in [".download", ".digest", ".download.lock"] {
        assert_file_absent(&format!("{FILE_REFUSED_DESTINATION}{suffix}"));
    }
    println!(
        "\nPRODUCTION_VIEWER_FILE_RECOVERY_OK new-connection=same-peer same-job-id=true digest=confirmed done=once destination=exact-bytes old-round=terminal sentinel=preserved sidecars=absent teardown=joined"
    );
}
