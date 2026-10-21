use hbb_common::{
    bytes::Bytes,
    message_proto::{AudioFormat, AudioFrame},
};
use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};
#[cfg(any(test, not(target_os = "linux")))]
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Weak,
};

pub const AUDIO_FRAME_QUEUE_CAPACITY: usize = 8;
pub const MAX_AUDIO_FRAME_QUEUE_AGE: Duration = Duration::from_secs(1);

/// Maximum compressed Opus packet bytes handed to libopus for one AudioFrame.
/// Opus packets are small; this is deliberately generous while still making the
/// native decoder handoff length-bounded.
pub(crate) const MAX_NATIVE_OPUS_PACKET_BYTES: usize = 4096;

#[inline]
pub(crate) fn native_opus_packet_within_limit(len: usize) -> bool {
    len <= MAX_NATIVE_OPUS_PACKET_BYTES
}

#[inline]
pub(crate) fn native_opus_format_within_limit(sample_rate: u32, channels: u32) -> bool {
    matches!(sample_rate, 8000 | 12000 | 16000 | 24000 | 48000) && matches!(channels, 1 | 2)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NativeOpusFormatAdmission {
    AcceptFirst,
    Duplicate,
    Changed,
}

#[inline]
pub(crate) fn native_opus_format_key(sample_rate: u32, channels: u32) -> (u32, u32) {
    (sample_rate, channels)
}

#[inline]
pub(crate) fn native_opus_format_admission(
    current: Option<(u32, u32)>,
    sample_rate: u32,
    channels: u32,
) -> NativeOpusFormatAdmission {
    match current {
        None => NativeOpusFormatAdmission::AcceptFirst,
        Some(current) if current == native_opus_format_key(sample_rate, channels) => {
            NativeOpusFormatAdmission::Duplicate
        }
        Some(_) => NativeOpusFormatAdmission::Changed,
    }
}

struct QueuedAudioFrame {
    queued_at: std::time::Instant,
    frame: AudioFrame,
}

#[derive(Default)]
struct AudioMailboxState {
    format: Option<AudioFormat>,
    format_key: Option<(u32, u32)>,
    frames: VecDeque<QueuedAudioFrame>,
    closed: bool,
}

struct AudioMailboxShared {
    state: Mutex<AudioMailboxState>,
    ready: Condvar,
}

impl AudioMailboxShared {
    fn close(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        state.format = None;
        state.frames.clear();
        drop(state);
        self.ready.notify_all();
    }
}

pub(crate) struct AudioMailboxSender {
    shared: Arc<AudioMailboxShared>,
}

pub(super) struct AudioMailboxReceiver {
    shared: Arc<AudioMailboxShared>,
}

// Each native output attempt owns independent callbacks, including failed setup attempts.
#[cfg(any(test, not(target_os = "linux")))]
pub(super) struct AudioOutputFactory(Weak<AudioMailboxShared>);

#[cfg(any(test, not(target_os = "linux")))]
#[derive(PartialEq)]
enum AudioOutputPhase {
    Pending,
    Active,
    Terminal,
}

#[cfg(any(test, not(target_os = "linux")))]
struct AudioOutputState {
    phase: Mutex<AudioOutputPhase>,
    live: AtomicBool,
    ready: AtomicBool,
    mailbox: Weak<AudioMailboxShared>,
}

#[cfg(any(test, not(target_os = "linux")))]
pub(super) struct AudioOutputOwner(Arc<AudioOutputState>);

#[cfg(any(test, not(target_os = "linux")))]
#[derive(Clone)]
pub(super) struct AudioOutputCallback(Arc<AudioOutputState>);

#[cfg(any(test, not(target_os = "linux")))]
impl AudioOutputFactory {
    pub(super) fn begin(&mut self) -> std::io::Result<AudioOutputOwner> {
        let mailbox = self.0.upgrade().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "audio receiver retired")
        })?;
        let state = mailbox.state.lock().unwrap();
        if state.closed || state.format_key.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe, "audio output requires a live admitted format",
            ));
        }
        Ok(AudioOutputOwner(Arc::new(AudioOutputState {
            phase: Mutex::new(AudioOutputPhase::Pending),
            live: AtomicBool::new(true),
            ready: AtomicBool::new(false),
            mailbox: self.0.clone(),
        })))
    }
}

#[cfg(any(test, not(target_os = "linux")))]
impl AudioOutputOwner {
    pub(super) fn callback(&self) -> AudioOutputCallback {
        AudioOutputCallback(Arc::clone(&self.0))
    }

    pub(super) fn activate(&mut self) -> std::io::Result<()> {
        let mut phase = self.0.phase.lock().unwrap();
        let mailbox = self.0.mailbox.upgrade().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "audio receiver retired")
        })?;
        if *phase != AudioOutputPhase::Pending || mailbox.state.lock().unwrap().closed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe, "audio output failed before activation",
            ));
        }
        *phase = AudioOutputPhase::Active;
        Ok(())
    }

    pub(super) fn is_ready(&self) -> bool {
        self.0.live.load(Ordering::Acquire) && self.0.ready.load(Ordering::Acquire)
    }
}

#[cfg(any(test, not(target_os = "linux")))]
impl Drop for AudioOutputOwner {
    fn drop(&mut self) {
        let mut phase = self.0.phase.lock().unwrap();
        self.0.live.store(false, Ordering::Release);
        *phase = AudioOutputPhase::Terminal;
    }
}

#[cfg(any(test, not(target_os = "linux")))]
impl AudioOutputCallback {
    pub(super) fn mark_ready(&self) -> bool {
        self.0.ready.store(true, Ordering::Release);
        self.0.live.load(Ordering::Acquire)
    }

    pub(super) fn fail(&self) {
        let mut phase = self.0.phase.lock().unwrap();
        self.0.live.store(false, Ordering::Release);
        if *phase == AudioOutputPhase::Active {
            // Wake the owning decoder even without another packet. It drops the stream.
            if let Some(mailbox) = self.0.mailbox.upgrade() {
                mailbox.close();
            }
        }
        *phase = AudioOutputPhase::Terminal;
    }
}

pub(super) enum AudioMailboxItem {
    Frame(AudioFrame),
    Format(AudioFormat),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AudioFormatAdmission {
    Queued,
    Duplicate,
    Changed,
    Unsupported,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AudioFrameAdmission {
    Queued,
    ReplacedOldest,
    AwaitingFormat,
    Oversized,
    Closed,
}

fn audio_frame_is_fresh(queued_at: std::time::Instant, now: std::time::Instant) -> bool {
    now.checked_duration_since(queued_at).unwrap_or_default() <= MAX_AUDIO_FRAME_QUEUE_AGE
}

pub(super) fn audio_mailbox() -> (AudioMailboxSender, AudioMailboxReceiver) {
    let shared = Arc::new(AudioMailboxShared {
        state: Mutex::new(AudioMailboxState::default()),
        ready: Condvar::new(),
    });
    (
        AudioMailboxSender {
            shared: Arc::clone(&shared),
        },
        AudioMailboxReceiver { shared },
    )
}

impl AudioMailboxSender {
    pub(crate) fn admit_format(&self, format: AudioFormat) -> AudioFormatAdmission {
        let mut state = self.shared.state.lock().unwrap();
        if state.closed {
            return AudioFormatAdmission::Closed;
        }
        if !native_opus_format_within_limit(format.sample_rate, format.channels) {
            return AudioFormatAdmission::Unsupported;
        }
        match native_opus_format_admission(
            state.format_key,
            format.sample_rate,
            format.channels,
        ) {
            NativeOpusFormatAdmission::AcceptFirst => {
                state.format_key = Some(native_opus_format_key(
                    format.sample_rate,
                    format.channels,
                ));
                let mut admitted = AudioFormat::new();
                admitted.sample_rate = format.sample_rate;
                admitted.channels = format.channels;
                state.format = Some(admitted);
                state.frames.clear();
                drop(state);
                self.shared.ready.notify_one();
                AudioFormatAdmission::Queued
            }
            NativeOpusFormatAdmission::Duplicate => AudioFormatAdmission::Duplicate,
            NativeOpusFormatAdmission::Changed => AudioFormatAdmission::Changed,
        }
    }

    fn admit_frame_queued_at(
        &self,
        frame: AudioFrame,
        queued_at: std::time::Instant,
    ) -> AudioFrameAdmission {
        let mut state = self.shared.state.lock().unwrap();
        if state.closed {
            return AudioFrameAdmission::Closed;
        }
        if state.format_key.is_none() {
            return AudioFrameAdmission::AwaitingFormat;
        }
        if !native_opus_packet_within_limit(frame.data.len()) {
            return AudioFrameAdmission::Oversized;
        }
        let mut admitted = AudioFrame::new();
        // Own only packet bytes, without unknown fields or a larger shared allocation.
        admitted.data = Bytes::copy_from_slice(&frame.data);
        let admission = if state.frames.len() >= AUDIO_FRAME_QUEUE_CAPACITY {
            state.frames.pop_front();
            AudioFrameAdmission::ReplacedOldest
        } else {
            AudioFrameAdmission::Queued
        };
        state.frames.push_back(QueuedAudioFrame {
            queued_at,
            frame: admitted,
        });
        drop(state);
        self.shared.ready.notify_one();
        admission
    }

    pub(crate) fn admit_frame(&self, frame: AudioFrame) -> AudioFrameAdmission {
        self.admit_frame_queued_at(frame, std::time::Instant::now())
    }
}

impl Drop for AudioMailboxSender {
    fn drop(&mut self) {
        self.shared.close();
    }
}

impl AudioMailboxReceiver {
    #[cfg(any(test, not(target_os = "linux")))]
    pub(super) fn output_factory(&self) -> AudioOutputFactory {
        AudioOutputFactory(Arc::downgrade(&self.shared))
    }

    pub(super) fn recv(&self) -> Option<AudioMailboxItem> {
        loop {
            let mut state = self.shared.state.lock().unwrap();
            while state.format.is_none() && state.frames.is_empty() && !state.closed {
                state = self.shared.ready.wait(state).unwrap();
            }
            if state.closed {
                return None;
            }
            if let Some(format) = state.format.take() {
                return Some(AudioMailboxItem::Format(format));
            }
            let Some(frame) = state.frames.pop_front() else {
                continue;
            };
            if audio_frame_is_fresh(frame.queued_at, std::time::Instant::now()) {
                return Some(AudioMailboxItem::Frame(frame.frame));
            }
        }
    }
}

impl Drop for AudioMailboxReceiver {
    fn drop(&mut self) {
        self.shared.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audio_format(sample_rate: u32, channels: u32) -> AudioFormat {
        let mut format = AudioFormat::new();
        format.sample_rate = sample_rate;
        format.channels = channels;
        format
    }

    fn audio_frame(marker: u8) -> AudioFrame {
        let mut frame = AudioFrame::new();
        frame.data = vec![marker].into();
        frame
    }

    fn admitted_audio_frame(item: AudioMailboxItem) -> AudioFrame {
        match item {
            AudioMailboxItem::Frame(frame) => frame,
            AudioMailboxItem::Format(_) => panic!("expected queued audio frame, got format"),
        }
    }

    #[test]
    fn r_s11hi_audio_mailbox_requires_and_prioritizes_the_first_format() {
        let (sender, receiver) = audio_mailbox();

        assert_eq!(
            sender.admit_frame(audio_frame(0)),
            AudioFrameAdmission::AwaitingFormat
        );
        assert_eq!(
            sender.admit_format(audio_format(48000, 2)),
            AudioFormatAdmission::Queued
        );
        assert_eq!(
            sender.admit_frame(audio_frame(1)),
            AudioFrameAdmission::Queued
        );
        assert!(matches!(receiver.recv(), Some(AudioMailboxItem::Format(_))));
        assert_eq!(
            admitted_audio_frame(receiver.recv().expect("queued audio frame")).data,
            vec![1]
        );
    }

    #[test]
    fn r_s11hi_audio_mailbox_pins_one_format_without_replay_work() {
        let (sender, receiver) = audio_mailbox();

        assert_eq!(
            sender.admit_format(audio_format(48000, 2)),
            AudioFormatAdmission::Queued
        );
        assert_eq!(
            sender.admit_format(audio_format(48000, 2)),
            AudioFormatAdmission::Duplicate
        );
        assert_eq!(
            sender.admit_format(audio_format(24000, 1)),
            AudioFormatAdmission::Changed
        );
        let Some(AudioMailboxItem::Format(format)) = receiver.recv() else {
            panic!("the first format must remain pending");
        };
        assert_eq!((format.sample_rate, format.channels), (48000, 2));
    }

    #[test]
    fn r_s11hi_audio_mailbox_retires_oldest_frame_at_its_exact_bound() {
        let (sender, receiver) = audio_mailbox();
        assert_eq!(
            sender.admit_format(audio_format(48000, 2)),
            AudioFormatAdmission::Queued
        );
        for marker in 0..AUDIO_FRAME_QUEUE_CAPACITY {
            assert_eq!(
                sender.admit_frame(audio_frame(marker as u8)),
                AudioFrameAdmission::Queued
            );
        }
        assert_eq!(
            sender.admit_frame(audio_frame(AUDIO_FRAME_QUEUE_CAPACITY as u8)),
            AudioFrameAdmission::ReplacedOldest
        );

        assert!(matches!(receiver.recv(), Some(AudioMailboxItem::Format(_))));
        for marker in 1..=AUDIO_FRAME_QUEUE_CAPACITY {
            assert_eq!(
                admitted_audio_frame(receiver.recv().expect("bounded audio frame")).data,
                vec![marker as u8]
            );
        }
    }

    #[test]
    fn r_s11hi_audio_mailbox_discards_stale_frames_before_delivery() {
        let (sender, receiver) = audio_mailbox();
        assert_eq!(
            sender.admit_format(audio_format(48000, 2)),
            AudioFormatAdmission::Queued
        );
        assert!(matches!(receiver.recv(), Some(AudioMailboxItem::Format(_))));
        let stale_at = std::time::Instant::now()
            .checked_sub(MAX_AUDIO_FRAME_QUEUE_AGE + std::time::Duration::from_millis(1))
            .expect("test instant supports the stale interval");
        assert_eq!(
            sender.admit_frame_queued_at(audio_frame(1), stale_at),
            AudioFrameAdmission::Queued
        );
        assert_eq!(
            sender.admit_frame(audio_frame(2)),
            AudioFrameAdmission::Queued
        );
        assert_eq!(
            admitted_audio_frame(receiver.recv().expect("fresh audio frame")).data,
            vec![2]
        );
    }


    #[test]
    fn r_s11hi_unsupported_format_does_not_claim_codec_identity() {
        let (sender, receiver) = audio_mailbox();
        for (rate, channels) in [(96000, 2), (48000, 0), (48000, 3)] {
            assert_eq!(
                sender.admit_format(audio_format(rate, channels)),
                AudioFormatAdmission::Unsupported
            );
        }
        assert_eq!(sender.admit_frame(audio_frame(1)), AudioFrameAdmission::AwaitingFormat);
        assert_eq!(sender.admit_format(audio_format(48000, 2)), AudioFormatAdmission::Queued);
        assert!(matches!(receiver.recv(), Some(AudioMailboxItem::Format(_))));
    }

    #[test]
    fn r_s11hi_oversized_packet_preserves_pending_format_and_full_queue() {
        let (sender, receiver) = audio_mailbox();
        assert_eq!(sender.admit_format(audio_format(48000, 2)), AudioFormatAdmission::Queued);
        for marker in 0..AUDIO_FRAME_QUEUE_CAPACITY {
            assert_eq!(sender.admit_frame(audio_frame(marker as u8)), AudioFrameAdmission::Queued);
        }
        let mut oversized = AudioFrame::new();
        oversized.data = vec![255; MAX_NATIVE_OPUS_PACKET_BYTES + 1].into();
        assert_eq!(sender.admit_frame(oversized), AudioFrameAdmission::Oversized);
        assert!(matches!(receiver.recv(), Some(AudioMailboxItem::Format(_))));
        for marker in 0..AUDIO_FRAME_QUEUE_CAPACITY {
            assert_eq!(admitted_audio_frame(receiver.recv().unwrap()).data, vec![marker as u8]);
        }
    }

    #[test]
    fn r_s11hi_exact_packet_bound_is_admitted() {
        let (sender, receiver) = audio_mailbox();
        assert_eq!(sender.admit_format(audio_format(48000, 2)), AudioFormatAdmission::Queued);
        let mut frame = AudioFrame::new();
        frame.data = vec![7; MAX_NATIVE_OPUS_PACKET_BYTES].into();
        assert_eq!(sender.admit_frame(frame), AudioFrameAdmission::Queued);
        assert!(matches!(receiver.recv(), Some(AudioMailboxItem::Format(_))));
        assert_eq!(admitted_audio_frame(receiver.recv().unwrap()).data, vec![7; MAX_NATIVE_OPUS_PACKET_BYTES]);
    }

    #[test]
    fn r_s11hi_packet_unknown_wire_fields_are_not_retained() {
        use hbb_common::protobuf::Message;
        let (sender, receiver) = audio_mailbox();
        assert_eq!(sender.admit_format(audio_format(48000, 2)), AudioFormatAdmission::Queued);
        let mut frame = audio_frame(3);
        frame.special_fields.mut_unknown_fields().add_length_delimited(100, vec![9; 65536]);
        let encoded = frame.write_to_bytes().unwrap();
        let decoded = AudioFrame::parse_from_bytes(&encoded).unwrap();
        assert!(decoded.special_fields.unknown_fields().iter().next().is_some());
        assert_eq!(sender.admit_frame(decoded), AudioFrameAdmission::Queued);
        assert!(matches!(receiver.recv(), Some(AudioMailboxItem::Format(_))));
        let admitted = admitted_audio_frame(receiver.recv().unwrap());
        assert_eq!(admitted.data, vec![3]);
        assert!(admitted.special_fields.unknown_fields().iter().next().is_none());
    }

    #[test]
    fn r_s11hi_format_unknown_wire_fields_are_not_retained() {
        use hbb_common::protobuf::Message;
        let (sender, receiver) = audio_mailbox();
        let mut format = audio_format(48000, 2);
        format.special_fields.mut_unknown_fields().add_length_delimited(100, vec![9; 65536]);
        let encoded = format.write_to_bytes().unwrap();
        let decoded = AudioFormat::parse_from_bytes(&encoded).unwrap();
        assert!(decoded.special_fields.unknown_fields().iter().next().is_some());
        assert_eq!(sender.admit_format(decoded), AudioFormatAdmission::Queued);
        let Some(AudioMailboxItem::Format(admitted)) = receiver.recv() else {
            panic!("expected admitted format");
        };
        assert_eq!((admitted.sample_rate, admitted.channels), (48000, 2));
        assert!(admitted.special_fields.unknown_fields().iter().next().is_none());
    }

    #[test]
    fn r_s11hi_small_packet_releases_large_backing_owner_at_admission() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Backing {
            bytes: Vec<u8>,
            dropped: Arc<AtomicBool>,
        }
        impl AsRef<[u8]> for Backing {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }
        impl Drop for Backing {
            fn drop(&mut self) {
                self.dropped.store(true, Ordering::Release);
            }
        }
        let (sender, receiver) = audio_mailbox();
        assert_eq!(sender.admit_format(audio_format(48000, 2)), AudioFormatAdmission::Queued);
        let dropped = Arc::new(AtomicBool::new(false));
        let mut frame = AudioFrame::new();
        frame.data = Bytes::from_owner(Backing {
            bytes: vec![5; 8 * 1024 * 1024],
            dropped: Arc::clone(&dropped),
        })
        .slice(..MAX_NATIVE_OPUS_PACKET_BYTES);
        assert!(!dropped.load(Ordering::Acquire));
        assert_eq!(sender.admit_frame(frame), AudioFrameAdmission::Queued);
        assert!(dropped.load(Ordering::Acquire), "queue must own a bounded copy");
        assert!(matches!(receiver.recv(), Some(AudioMailboxItem::Format(_))));
        assert_eq!(admitted_audio_frame(receiver.recv().unwrap()).data, vec![5; MAX_NATIVE_OPUS_PACKET_BYTES]);
    }

    #[test]
    fn r_s11hi_sender_drop_wakes_and_joins_the_native_receiver() {
        let (sender, receiver) = audio_mailbox();
        let (finished, result) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            finished.send(receiver.recv().is_none()).unwrap();
        });
        drop(sender);
        let outcome = result.recv_timeout(Duration::from_secs(2));
        worker.join().unwrap();
        assert!(outcome.unwrap());
    }

    #[test]
    fn r_s11hi_receiver_drop_refuses_further_admission() {
        let (sender, receiver) = audio_mailbox();
        assert_eq!(sender.admit_format(audio_format(48000, 2)), AudioFormatAdmission::Queued);
        assert_eq!(sender.admit_frame(audio_frame(1)), AudioFrameAdmission::Queued);
        drop(receiver);
        assert_eq!(sender.admit_format(audio_format(48000, 2)), AudioFormatAdmission::Closed);
        assert_eq!(sender.admit_frame(audio_frame(2)), AudioFrameAdmission::Closed);
        let state = sender.shared.state.lock().unwrap();
        assert!(state.format.is_none() && state.frames.is_empty());
    }

    #[test]
    fn output_pending_failure_allows_a_fresh_setup_attempt() {
        let (sender, receiver) = audio_mailbox();
        let mut factory = receiver.output_factory();
        assert!(factory.begin().is_err());
        assert_eq!(sender.admit_format(audio_format(48000, 2)), AudioFormatAdmission::Queued);
        let mut failed = factory.begin().unwrap();
        let old = failed.callback();
        assert!(old.mark_ready());
        old.fail();
        assert!(!failed.is_ready());
        assert!(failed.activate().is_err());
        drop(failed);
        let mut selected = factory.begin().unwrap();
        selected.activate().unwrap();
        assert!(!selected.is_ready());
        assert!(!old.mark_ready());
        old.fail();
        assert!(selected.callback().mark_ready());
        assert!(selected.is_ready());
        assert_eq!(sender.admit_format(audio_format(48000, 2)), AudioFormatAdmission::Duplicate);
        assert!(matches!(receiver.recv(), Some(AudioMailboxItem::Format(_))));
    }

    #[test]
    fn output_retired_callbacks_preserve_the_selected_owner() {
        let (sender, receiver) = audio_mailbox();
        sender.admit_format(audio_format(48000, 2));
        let mut factory = receiver.output_factory();
        let mut retired = factory.begin().unwrap();
        retired.activate().unwrap();
        let old = retired.callback();
        drop(retired);
        let mut selected = factory.begin().unwrap();
        selected.activate().unwrap();
        let callback = selected.callback();
        let late = std::thread::spawn(move || {
            for _ in 0..64 {
                old.fail();
                assert!(!old.mark_ready());
            }
        });
        assert!(callback.mark_ready());
        late.join().unwrap();
        assert!(selected.is_ready());
        assert_eq!(sender.admit_frame(audio_frame(1)), AudioFrameAdmission::Queued);
    }

    #[test]
    fn output_active_failure_releases_payloads_and_closes_admission() {
        let (sender, receiver) = audio_mailbox();
        sender.admit_format(audio_format(48000, 2));
        for i in 0..AUDIO_FRAME_QUEUE_CAPACITY {
            sender.admit_frame(audio_frame(i as u8));
        }
        let mut factory = receiver.output_factory();
        let mut owner = factory.begin().unwrap();
        owner.activate().unwrap();
        let callback = owner.callback();
        assert!(callback.mark_ready());
        callback.fail();
        callback.fail();
        assert!(!callback.mark_ready());
        assert!(!owner.is_ready());
        assert!(receiver.recv().is_none());
        assert_eq!(sender.admit_frame(audio_frame(42)), AudioFrameAdmission::Closed);
        assert_eq!(sender.admit_format(audio_format(48000, 2)), AudioFormatAdmission::Closed);
        assert!(factory.begin().is_err());
        let state = sender.shared.state.lock().unwrap();
        assert!(state.format.is_none() && state.frames.is_empty());
    }

    #[test]
    fn output_activation_refuses_a_retired_receiver() {
        let (sender, receiver) = audio_mailbox();
        sender.admit_format(audio_format(48000, 2));
        let mut factory = receiver.output_factory();
        let mut pending = factory.begin().unwrap();
        drop(receiver);
        assert!(pending.activate().is_err());
        assert!(factory.begin().is_err());
        drop(sender);
        assert!(factory.begin().is_err());
        pending.callback().fail();
    }

    #[test]
    fn output_failure_and_readiness_converge_across_native_threads() {
        for _ in 0..64 {
            let (sender, receiver) = audio_mailbox();
            sender.admit_format(audio_format(48000, 2));
            let mut owner = receiver.output_factory().begin().unwrap();
            let ready = owner.callback();
            let failure = owner.callback();
            let gate = Arc::new(std::sync::Barrier::new(3));
            let ready_gate = Arc::clone(&gate);
            let ready_worker = std::thread::spawn(move || {
                ready_gate.wait();
                for _ in 0..64 { ready.mark_ready(); }
            });
            let failure_gate = Arc::clone(&gate);
            let failure_worker = std::thread::spawn(move || {
                failure_gate.wait();
                failure.fail();
            });
            gate.wait();
            let activated = owner.activate().is_ok();
            ready_worker.join().unwrap();
            failure_worker.join().unwrap();
            assert!(!owner.is_ready());
            assert!(!owner.callback().mark_ready());
            if activated {
                assert!(receiver.recv().is_none());
            } else {
                assert!(matches!(receiver.recv(), Some(AudioMailboxItem::Format(_))));
            }
        }
    }
}
