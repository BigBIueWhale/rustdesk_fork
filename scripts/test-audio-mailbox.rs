extern crate self as hbb_common;

pub use bytes;
pub use protobuf;
pub use log;
pub mod protos {
    include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
}
pub use protos::message as message_proto;

#[path = "../src/client/audio_mailbox.rs"]
mod audio_mailbox;

#[path = "../src/client/audio_buffer.rs"]
mod audio_buffer;

use audio_buffer::AudioBuffer;
use audio_mailbox::{AudioOutputFactory, AudioOutputOwner};
use cpal::{traits::{DeviceTrait, StreamTrait}, Device, StreamConfig};
use std::sync::Arc;
type ResultType<T> = anyhow::Result<T>;
use anyhow::anyhow;

// Only the fields used by the exact extracted production method. No device is opened here.
#[derive(Default)]
struct AudioHandler {
    output_factory: Option<AudioOutputFactory>,
    output_owner: Option<AudioOutputOwner>,
    audio_buffer: AudioBuffer,
    audio_stream: Option<Box<dyn StreamTrait>>,
    device_channel: u16,
}

include!(env!("AUDIO_OUTPUT_METHOD"));

#[test]
fn output_error_callback_wakes_the_idle_owner_and_joins_off_callback() {
    use std::{sync::mpsc, thread, time::Duration};

    struct DropWitness(mpsc::Sender<thread::ThreadId>);
    impl Drop for DropWitness {
        fn drop(&mut self) { self.0.send(thread::current().id()).unwrap(); }
    }

    for current in [false, true] {
        let (sender, receiver) = audio_mailbox::audio_mailbox();
        let mut format = message_proto::AudioFormat::new();
        format.sample_rate = 48000;
        format.channels = 2;
        assert_eq!(sender.admit_format(format), audio_mailbox::AudioFormatAdmission::Queued);
        let (callback_tx, callback_rx) = mpsc::channel();
        let (exit_tx, exit_rx) = mpsc::channel();
        let (drop_tx, drop_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let witness = DropWitness(drop_tx);
            assert!(matches!(receiver.recv(), Some(audio_mailbox::AudioMailboxItem::Format(_))));
            let mut owner = receiver.output_factory().begin().unwrap();
            owner.activate().unwrap();
            callback_tx.send(owner.callback()).unwrap();
            assert!(receiver.recv().is_none());
            drop(owner);
            drop(witness);
            exit_tx.send(thread::current().id()).unwrap();
        });
        let failure = callback_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(failure.mark_ready());
        let callback_thread = thread::spawn(move || {
            if current {
                candidate_error_callback(failure)(cpal::StreamError::DeviceNotAvailable);
            } else {
                // Exact error closure at e1936d0df1e2419d7d65d45d00a6470808b5dc13.
                let err_fn = move |err| {
                    // too many errors, will improve later
                    log::trace!("an error occurred on stream: {}", err);
                };
                err_fn(cpal::StreamError::DeviceNotAvailable);
            }
            thread::current().id()
        });
        let callback_id = callback_thread.join().unwrap();
        let observed = exit_rx.recv_timeout(Duration::from_millis(250));
        // Always close and join before asserting, including the historical negative control.
        drop(sender);
        let owner_id = observed.as_ref().copied().unwrap_or_else(|_| {
            exit_rx.recv_timeout(Duration::from_secs(2)).unwrap()
        });
        worker.join().unwrap();
        assert_eq!(drop_rx.recv_timeout(Duration::from_secs(2)).unwrap(), owner_id);
        assert_ne!(owner_id, callback_id);
        assert_eq!(observed.is_ok(), current);
        println!("AUDIO_OUTPUT_ERROR=pass version={} idle_owner_woke={} retirement=owner-thread native_device=unexecuted",
                 if current { "current" } else { "e1936d0d" }, observed.is_ok());
    }
}
