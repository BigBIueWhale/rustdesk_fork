use hbb_common::{log, message_proto::video_frame, tokio::sync::Notify};
use scrap::record::{Recorder, RecorderContext};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RecordingStatus {
    #[default]
    Stopped,
    Starting,
    Active,
    Stopping,
}

impl RecordingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Starting => "starting",
            Self::Active => "active",
            Self::Stopping => "stopping",
        }
    }
}

#[derive(Default)]
struct State {
    writers: usize,
    started: bool,
    stopping: bool,
    failed: bool,
    failure: Option<String>,
}

pub(super) struct RecordingAttempt {
    context: RecorderContext,
    state: Mutex<State>,
    changed: Arc<Notify>,
}

pub(super) struct RecordingSnapshot {
    pub writers: usize,
    pub started: bool,
    pub stopping: bool,
    pub failure: Option<String>,
}

impl RecordingAttempt {
    pub fn new(context: RecorderContext, changed: Arc<Notify>) -> Arc<Self> {
        Arc::new(Self { context, state: Mutex::new(State::default()), changed })
    }

    pub fn stop(&self) {
        self.state.lock().unwrap().stopping = true;
        self.changed.notify_one();
    }

    pub fn snapshot(&self) -> RecordingSnapshot {
        let mut state = self.state.lock().unwrap();
        RecordingSnapshot {
            writers: state.writers,
            started: state.started,
            stopping: state.stopping,
            failure: state.failure.take(),
        }
    }

    fn fail(&self, error: impl std::fmt::Display) {
        log::error!("Recording failed: {error}");
        let mut state = self.state.lock().unwrap();
        // One retained failure per attempt survives notification coalescing.
        if !state.failed {
            state.failure = Some(error.to_string());
            state.failed = true;
        }
        state.stopping = true;
        drop(state);
        self.changed.notify_one();
    }

    pub fn writer(self: &Arc<Self>, display: usize) -> Option<RecordingWriter> {
        let mut state = self.state.lock().unwrap();
        if state.stopping {
            return None;
        }
        let mut context = self.context.clone();
        context.display_idx = display;
        let recorder = match Recorder::new(context) {
            Ok(recorder) => recorder,
            Err(error) => {
                drop(state);
                self.fail(error);
                return None;
            }
        };
        state.writers += 1;
        Some(RecordingWriter { recorder: Some(recorder), attempt: self.clone() })
    }
}

// This owner moves from the bounded control mailbox into exactly one decoder
// worker. Dropping a coalesced start, closing the mailbox, and joining the worker
// all release the same reservation; a retry waits for every reservation to drain.
pub(crate) struct RecordingWriter {
    recorder: Option<Recorder>,
    attempt: Arc<RecordingAttempt>,
}

impl RecordingWriter {
    pub fn write(&mut self, frame: &video_frame::Union, width: usize, height: usize) -> bool {
        if self.attempt.state.lock().unwrap().stopping {
            return false;
        }
        let Some(recorder) = self.recorder.as_mut() else {
            return false;
        };
        match recorder.write_frame(frame, width, height) {
            Ok(()) => {
                if recorder.has_frames() {
                    let mut state = self.attempt.state.lock().unwrap();
                    if !state.started {
                        state.started = true;
                        drop(state);
                        self.attempt.changed.notify_one();
                    }
                }
                true
            }
            Err(error) => {
                self.attempt.fail(error);
                false
            }
        }
    }
}

impl Drop for RecordingWriter {
    fn drop(&mut self) {
        if let Some(recorder) = self.recorder.take() {
            if let Err(error) = recorder.finish() {
                self.attempt.fail(error);
            }
        }
        let mut state = self.attempt.state.lock().unwrap();
        if !state.stopping {
            state.stopping = true;
            state.failed = true;
            state.failure = Some("Recording video worker stopped".to_owned());
        }
        state.writers -= 1;
        drop(state);
        self.attempt.changed.notify_one();
    }
}
