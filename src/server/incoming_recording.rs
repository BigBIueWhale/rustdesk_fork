use hbb_common::{bail, log, message_proto::video_frame, ResultType};
use scrap::record::{Recorder, RecorderContext};
use std::sync::{Mutex, OnceLock};
use crate::incoming_recording_status::{
    FailureStage, IncomingRecordingStatus, RecordingFailure, MAX_RECORDERS,
};

fn state() -> &'static Mutex<IncomingRecordingStatus> {
    static STATE: OnceLock<Mutex<IncomingRecordingStatus>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(IncomingRecordingStatus::default()))
}

pub fn snapshot() -> IncomingRecordingStatus {
    *state().lock().unwrap()
}

pub(super) struct IncomingRecording {
    recorder: Option<Recorder>,
    display: usize,
    camera: bool,
    active: bool,
    failed: bool,
}

impl IncomingRecording {
    pub fn new(context: RecorderContext) -> ResultType<Self> {
        let failure = RecordingFailure {
            display: context.display_idx, camera: context.camera, stage: FailureStage::Start,
        };
        let recorder = match Recorder::new(context) {
            Ok(recorder) => recorder,
            Err(error) => {
                state().lock().unwrap().last_failure = Some(failure);
                return Err(error);
            }
        };
        let mut state = state().lock().unwrap();
        if state.writers() >= MAX_RECORDERS {
            state.last_failure = Some(failure);
            bail!("Incoming recording writer limit reached");
        }
        state.starting += 1;
        Ok(Self {
            recorder: Some(recorder), display: failure.display, camera: failure.camera,
            active: false, failed: false,
        })
    }

    fn fail(&mut self, stage: FailureStage) {
        if !self.failed {
            state().lock().unwrap().last_failure = Some(RecordingFailure {
                display: self.display, camera: self.camera, stage,
            });
            self.failed = true;
        }
    }

    pub fn write_frame(&mut self, frame: &video_frame::Union, w: usize, h: usize) -> ResultType<()> {
        let Some(recorder) = self.recorder.as_mut() else {
            bail!("Incoming recording is already complete");
        };
        if let Err(error) = recorder.write_frame(frame, w, h) {
            self.fail(FailureStage::Write);
            return Err(error);
        }
        if !self.active && recorder.has_frames() {
            let mut state = state().lock().unwrap();
            state.starting -= 1;
            state.active += 1;
            self.active = true;
        }
        Ok(())
    }
}

impl Drop for IncomingRecording {
    fn drop(&mut self) {
        let Some(recorder) = self.recorder.take() else {
            return;
        };
        {
            let mut state = state().lock().unwrap();
            if self.active {
                state.active -= 1;
            } else {
                state.starting -= 1;
            }
            state.finishing += 1;
        }
        // File completion can block or fail. Publish neither completion nor
        // released ownership until the exact recorder has returned.
        if let Err(error) = recorder.finish() {
            if !self.failed {
                log::error!("Failed to finalize incoming recording: {error:#}");
                self.fail(FailureStage::Finish);
            }
        }
        state().lock().unwrap().finishing -= 1;
    }
}
