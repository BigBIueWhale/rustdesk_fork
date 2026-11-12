use crate::incoming_recording_status::{
    FailureStage, IncomingRecordingStatus, RecordingFailure, MAX_RECORDERS,
};
use hbb_common::{bail, log, message_proto::video_frame, ResultType};
use scrap::{codec::{validate_native_video_frames, MAX_NATIVE_VIDEO_BATCH_BYTES},
    record::{Recorder, RecorderContext}};
use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex, OnceLock},
    thread::{self, JoinHandle},
};

// Eight queued native batches plus one in flight per worker. The process-wide
// byte budget includes in-flight I/O and permits two maximum native batches.
const MAX_QUEUED_BATCHES: usize = 8;
const MAX_BUFFERED_BYTES: usize = 2 * MAX_NATIVE_VIDEO_BATCH_BYTES;

#[derive(Default)]
struct State {
    status: IncomingRecordingStatus,
    workers: u32,
    bytes: usize,
}

fn state() -> &'static Mutex<State> {
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(State::default()))
}

pub fn snapshot() -> IncomingRecordingStatus {
    state().lock().unwrap().status
}

#[cfg(test)]
pub(super) fn retained_resources() -> (u32, usize) {
    let state = state().lock().unwrap();
    (state.workers, state.bytes)
}

struct ByteCharge(usize);

impl Drop for ByteCharge {
    fn drop(&mut self) {
        state().lock().unwrap().bytes -= self.0;
    }
}

struct Frame {
    video: video_frame::Union,
    width: usize,
    height: usize,
    // Fields drop in declaration order: release bytes after the frame itself.
    _charge: ByteCharge,
}

#[derive(Clone, Copy, PartialEq)]
enum Phase { Starting, Active, Finishing, Done }

impl Phase {
    fn count(self, status: &mut IncomingRecordingStatus) -> Option<&mut u16> {
        match self {
            Self::Starting => Some(&mut status.starting),
            Self::Active => Some(&mut status.active),
            Self::Finishing => Some(&mut status.finishing),
            Self::Done => None,
        }
    }
}

struct Queue {
    frames: VecDeque<Frame>,
    phase: Phase,
    failed: bool,
}

impl Queue {
    fn transition(&mut self, next: Phase) {
        let mut state = state().lock().unwrap();
        if let Some(count) = self.phase.count(&mut state.status) { *count -= 1; }
        if let Some(count) = next.count(&mut state.status) { *count += 1; }
        self.phase = next;
    }

    fn fail(&mut self, shared: &Shared, stage: FailureStage) {
        if !self.failed {
            state().lock().unwrap().status.last_failure = Some(RecordingFailure {
                display: shared.display, camera: shared.camera, stage,
            });
            self.failed = true;
        }
    }

    fn close(&mut self) {
        if matches!(self.phase, Phase::Starting | Phase::Active) {
            self.transition(Phase::Finishing);
        }
    }
}

struct Shared {
    queue: Mutex<Queue>,
    ready: Condvar,
    display: usize,
    camera: bool,
}

impl Shared {
    fn close(&self, failure: Option<FailureStage>) {
        let mut queue = self.queue.lock().unwrap();
        if let Some(stage) = failure { queue.fail(self, stage); }
        queue.close();
        self.ready.notify_one();
    }
}

struct Completion {
    shared: Arc<Shared>,
    checked: bool,
}

impl Drop for Completion {
    fn drop(&mut self) {
        let mut queue = self.shared.queue.lock().unwrap();
        if !self.checked { queue.fail(&self.shared, FailureStage::Finish); }
        queue.frames.clear();
        queue.transition(Phase::Done);
        self.shared.ready.notify_all();
    }
}

fn record(context: RecorderContext, shared: Arc<Shared>) {
    // Declare completion first so recorder destruction (including unwinding)
    // finishes before status can report that no writer remains.
    let mut completion = Completion { shared: Arc::clone(&shared), checked: false };
    let mut recorder = match Recorder::new(context) {
        Ok(recorder) => recorder,
        Err(error) => {
            shared.close(Some(FailureStage::Start));
            log::error!("Failed to initialize incoming recording: {error:#}");
            completion.checked = true;
            return;
        }
    };
    loop {
        let frame = {
            let mut queue = shared.queue.lock().unwrap();
            loop {
                if let Some(frame) = queue.frames.pop_front() { break Some(frame); }
                if queue.phase == Phase::Finishing { break None; }
                queue = shared.ready.wait(queue).unwrap();
            }
        };
        let Some(frame) = frame else { break; };
        if let Err(error) = recorder.write_frame(&frame.video, frame.width, frame.height) {
            shared.close(Some(FailureStage::Write));
            shared.queue.lock().unwrap().frames.clear();
            log::error!("Failed to write incoming recording: {error:#}");
            break;
        }
        if recorder.has_frames() {
            let mut queue = shared.queue.lock().unwrap();
            if queue.phase == Phase::Starting { queue.transition(Phase::Active); }
        }
    }
    shared.close(None);
    if let Err(error) = recorder.finish() {
        shared.close(Some(FailureStage::Finish));
        log::error!("Failed to finalize incoming recording: {error:#}");
    }
    completion.checked = true;
}

struct Worker {
    handle: Option<JoinHandle<()>>,
    shared: Arc<Shared>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.shared.close(None);
        if let Some(handle) = self.handle.take() {
            if let Err(error) = handle.join() {
                log::error!("Incoming recording worker failed: {error:?}");
            }
        }
        // Retain the worker slot until exact join, including native finalization.
        state().lock().unwrap().workers -= 1;
    }
}

/// Owned by the video service's outer callback, across capture/encoder restarts.
#[derive(Default)]
pub(super) struct RecordingWorkers {
    workers: Vec<Worker>,
}

impl RecordingWorkers {
    pub fn start(&mut self, context: RecorderContext) -> ResultType<IncomingRecording> {
        let mut index = 0;
        while index < self.workers.len() {
            if self.workers[index].handle.as_ref().map_or(false, JoinHandle::is_finished) {
                self.workers.swap_remove(index);
            } else {
                index += 1;
            }
        }
        {
            let mut state = state().lock().unwrap();
            if state.workers >= MAX_RECORDERS {
                state.status.last_failure = Some(RecordingFailure {
                    display: context.display_idx, camera: context.camera, stage: FailureStage::Start,
                });
                bail!("Incoming recording worker limit reached");
            }
            state.workers += 1;
            state.status.starting += 1;
        }
        let shared = Arc::new(Shared {
            queue: Mutex::new(Queue { frames: VecDeque::new(), phase: Phase::Starting, failed: false }),
            ready: Condvar::new(), display: context.display_idx, camera: context.camera,
        });
        let mut worker = Worker { handle: None, shared: Arc::clone(&shared) };
        let target = Arc::clone(&shared);
        match thread::Builder::new().name("incoming-recording".into())
            .spawn(move || record(context, target))
        {
            Ok(handle) => worker.handle = Some(handle),
            Err(error) => {
                let mut queue = shared.queue.lock().unwrap();
                queue.fail(&shared, FailureStage::Start);
                queue.transition(Phase::Done);
                return Err(error.into());
            }
        }
        self.workers.push(worker);
        Ok(IncomingRecording { shared })
    }
}

impl Drop for RecordingWorkers {
    fn drop(&mut self) {
        // Close every admission before waiting for any slow worker. Vec then
        // drops and joins each exact handle; no deadline detaches a writer.
        for worker in &self.workers { worker.shared.close(None); }
    }
}

pub(super) struct IncomingRecording {
    shared: Arc<Shared>,
}

impl IncomingRecording {
    pub fn enqueue_frame(&mut self, frame: &video_frame::Union, width: usize, height: usize) -> ResultType<()> {
        let result = self.enqueue(frame, width, height);
        if result.is_err() { self.shared.close(Some(FailureStage::Write)); }
        result
    }

    fn enqueue(&self, frame: &video_frame::Union, width: usize, height: usize) -> ResultType<()> {
        let frames = match frame {
            video_frame::Union::Vp8s(frames) | video_frame::Union::Vp9s(frames) => frames,
            #[cfg(feature = "hwcodec")]
            video_frame::Union::H264s(frames) | video_frame::Union::H265s(frames) => frames,
            _ => bail!("Unsupported incoming recording frame type"),
        };
        validate_native_video_frames("recording", frames)?;
        let bytes = frames.frames.iter().map(|frame| frame.data.len()).sum::<usize>();
        let mut queue = self.shared.queue.lock().unwrap();
        if queue.failed || !matches!(queue.phase, Phase::Starting | Phase::Active) {
            bail!("Incoming recording admission is closed");
        }
        if queue.frames.len() >= MAX_QUEUED_BATCHES {
            bail!("Incoming recording storage cannot keep up with capture");
        }
        let charge = {
            let mut state = state().lock().unwrap();
            if bytes > MAX_BUFFERED_BYTES - state.bytes {
                bail!("Incoming recording byte budget exhausted");
            }
            state.bytes += bytes;
            ByteCharge(bytes)
        };
        queue.frames.push_back(Frame { video: frame.clone(), width, height, _charge: charge });
        self.shared.ready.notify_one();
        Ok(())
    }
}

impl Drop for IncomingRecording {
    fn drop(&mut self) {
        self.shared.close(None);
    }
}
