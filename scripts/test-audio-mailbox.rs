extern crate self as hbb_common;

pub use bytes;
pub use protobuf;
pub use log;
pub mod protos {
    include!(concat!(env!("OUT_DIR"), "/protos/mod.rs"));
}
pub use protos::message as message_proto;

#[path = "../libs/scrap/src/android/frame_raw_generation.rs"]
mod frame_raw_generation;
#[path = "../libs/scrap/src/common/frame_compare.rs"]
mod frame_compare;
pub use frame_compare::would_block_if_equal;

mod android_raw {
    include!("../libs/scrap/src/android/frame_raw.rs");

    #[test]
    fn take_moves_owned_storage_without_allocation() {
        use std::{os::unix::process::ExitStatusExt, process::Command};
        if let Ok(case) = std::env::var("ANDROID_RAW_TRANSFER_CASE") {
            if case == "probe" {
                crate::with_allocation_budget(0, || std::hint::black_box(Vec::<u8>::with_capacity(31)));
                panic!("allocation-refusal probe returned");
            }
            let mut dst = Vec::with_capacity(match case.as_str() {
                "empty" => 0, "short" => 1, "spare" => 131072, "reused" => 65536,
                _ => panic!("unknown raw-buffer case"),
            });
            let mut last = Vec::new();
            let mut raw = FrameRaw::new("test", Duration::from_secs(60));
            raw.set_enable(true);
            for round in 1..=3 {
                let mut payload = vec![round as u8; 65536];
                raw.update_from_jni_buffer(payload.as_mut_ptr(), payload.len(), payload.len());
                let source = raw.data.as_ptr();
                let reusable = dst.as_ptr();
                let reusable_capacity = dst.capacity();
                let (result, refusals) = crate::with_allocation_budget(0, || raw.take(&mut dst, &mut last));
                let transferred = dst.as_ptr() == source;
                let reused = raw.data.as_ptr() == reusable && raw.data.capacity() == reusable_capacity;
                let exact = dst == payload && raw.data.is_empty();
                println!("ANDROID_RAW_TRANSFER_CASE=observed case={case} round={round} admitted={} refusals={refusals} transferred={transferred} reused={reused} exact={exact}", result.is_some());
                assert!(result.is_some() && refusals == 0 && transferred && reused && exact);
            }
            return;
        }
        let executable = std::env::current_exe().unwrap();
        let run = |case: &str| Command::new(&executable)
            .args(["--exact", "android_raw::take_moves_owned_storage_without_allocation", "--nocapture"])
            .env("ANDROID_RAW_TRANSFER_CASE", case).output().unwrap();
        let probe = run("probe");
        assert_eq!(probe.status.signal(), Some(6));
        assert!(String::from_utf8_lossy(&probe.stderr).contains("memory allocation of 31 bytes failed"));
        println!("ANDROID_RAW_TRANSFER_PROBE=observed bytes=31 signal=Some(6)");
        let mut passed = 0;
        for case in ["empty", "short", "spare", "reused"] {
            let output = run(case);
            assert!(output.stdout.len() + output.stderr.len() <= 65536);
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                if line.starts_with("ANDROID_RAW_TRANSFER_CASE=") { println!("{line}"); }
            }
            print!("{}", String::from_utf8_lossy(&output.stderr));
            println!("ANDROID_RAW_TRANSFER_CHILD=observed case={case} success={} signal={:?}", output.status.success(), output.status.signal());
            passed += usize::from(output.status.success());
        }
        assert_eq!(passed, 4, "raw handoff must transfer storage without allocating or copying");
        println!("ANDROID_RAW_TRANSFER=pass cases=4 rounds=3 copy_allocations=0 pointer=transferred producer_storage=reused payload=exact probe=SIGABRT children=joined scope=portable-linux");
    }

    #[test]
    fn take_preserves_terminal_and_generation_semantics() {
        let mut raw = FrameRaw::new("test", Duration::from_secs(60));
        let mut payload = [1, 2, 3, 4];
        let mut dst = vec![9; 3];
        let mut last = Vec::new();
        raw.update_from_jni_buffer(payload.as_mut_ptr(), payload.len(), payload.len());
        assert!(raw.take(&mut dst, &mut last).is_none());
        assert_eq!(dst, [9; 3]);
        raw.set_enable(true);
        assert!(raw.take(&mut dst, &mut last).is_none());
        raw.update_from_jni_buffer(payload.as_mut_ptr(), payload.len(), payload.len());
        assert!(raw.take(&mut dst, &mut last).is_some());
        assert_eq!(dst, payload);
        assert!(raw.take(&mut dst, &mut last).is_none());
        last = payload.to_vec();
        raw.update_from_jni_buffer(payload.as_mut_ptr(), payload.len(), payload.len());
        assert!(raw.take(&mut dst, &mut last).is_none());
        assert_eq!(dst, payload);
        assert!(raw.data.is_empty());
        payload[0] = 5;
        raw.update_from_jni_buffer(payload.as_mut_ptr(), payload.len(), payload.len());
        assert!(raw.take(&mut dst, &mut last).is_some());
        assert_eq!(dst, payload);
        assert_eq!(last, payload);
        raw.update_from_jni_buffer(payload.as_mut_ptr(), payload.len(), payload.len());
        raw.last_update = Instant::now().checked_sub(raw.timeout + Duration::from_secs(1)).unwrap();
        assert!(raw.take(&mut dst, &mut last).is_none());
        assert!(raw.data.is_empty());
        assert_eq!(dst, payload);

        let mut owned = GenerationOwnedFrameRaw::new("test", Duration::from_secs(60));
        assert!(owned.begin_generation(1) && owned.set_enable(1, true));
        owned.update_from_jni_buffer(1, payload.as_mut_ptr(), payload.len(), payload.len());
        assert!(owned.take(2, &mut dst, &mut Vec::new()).is_none());
        assert!(owned.take(1, &mut dst, &mut Vec::new()).is_some());
        assert_eq!(dst, payload);
        owned.update_from_jni_buffer(1, payload.as_mut_ptr(), payload.len(), payload.len());
        assert!(owned.retire_generation(1));
        assert!(owned.take(1, &mut dst, &mut Vec::new()).is_none());
        assert!(owned.begin_generation(2) && owned.set_enable(2, true));
        owned.update_from_jni_buffer(1, payload.as_mut_ptr(), payload.len(), payload.len());
        assert!(owned.take(2, &mut dst, &mut Vec::new()).is_none());
        payload[0] = 6;
        owned.update_from_jni_buffer(2, payload.as_mut_ptr(), payload.len(), payload.len());
        assert!(owned.take(2, &mut dst, &mut Vec::new()).is_some());
        assert_eq!(dst, payload);
        println!("ANDROID_RAW_SEMANTICS=pass cases=8 disabled=refused empty=refused single_use=true equal=refused changed=exact expired=retired stale=refused successor=usable scope=portable-linux");
    }
}

#[path = "../src/client/audio_mailbox.rs"]
mod audio_mailbox;

#[path = "../src/client/audio_buffer.rs"]
mod audio_buffer;

use audio_buffer::AudioBuffer;
use audio_mailbox::{
    audio_mailbox, native_opus_format_admission, native_opus_format_key,
    native_opus_format_within_limit, native_opus_packet_within_limit,
    AudioFormatAdmission, AudioFrameAdmission, AudioMailboxItem, AudioMailboxSender,
    AudioOutputFactory, AudioOutputOwner, NativeOpusFormatAdmission, MAX_NATIVE_OPUS_PACKET_BYTES,
};
use message_proto::{AudioFormat, AudioFrame};
use magnum_opus::{Application, Channels::{Mono, Stereo}, Decoder as AudioDecoder, Encoder};
use cpal::{traits::{DeviceTrait, StreamTrait}, Device, StreamConfig};
use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};
type ResultType<T> = anyhow::Result<T>;
use anyhow::anyhow;

// Production codec/worker methods use a controlled PCM sink; no physical device is opened.
#[derive(Default)]
struct AudioHandler {
    audio_decoder: Option<(AudioDecoder, Vec<f32>)>,
    audio_format: Option<(u32, u32)>,
    audio_failed: bool,
    channels: u16,
    simple: Option<ControlledPlayback>,
    output_factory: Option<AudioOutputFactory>,
    output_owner: Option<AudioOutputOwner>,
    audio_buffer: Option<AudioBuffer>,
    audio_stream: Option<Box<dyn StreamTrait>>,
    device_channel: u16,
}

include!(env!("AUDIO_OUTPUT_METHOD"));

static PCM_TARGET_BYTES: AtomicUsize = AtomicUsize::new(0);
static PCM_REFUSE: AtomicBool = AtomicBool::new(false);
static PCM_REFUSALS: AtomicUsize = AtomicUsize::new(0);
static PLAYBACK_STARTS: AtomicUsize = AtomicUsize::new(0);
static PCM_WRITES: AtomicUsize = AtomicUsize::new(0);
static PCM_SCALARS: AtomicUsize = AtomicUsize::new(0);
static PCM_NONZERO: AtomicUsize = AtomicUsize::new(0);
static PCM_NONFINITE: AtomicUsize = AtomicUsize::new(0);

struct ControlledPlayback;
impl ControlledPlayback {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        assert_eq!(bytes.len() % 4, 0);
        for sample in bytes.chunks_exact(4) {
            let value = f32::from_ne_bytes(sample.try_into().unwrap());
            PCM_NONFINITE.fetch_add(usize::from(!value.is_finite()), Ordering::SeqCst);
            PCM_NONZERO.fetch_add(usize::from(value.abs() > 0.000001), Ordering::SeqCst);
        }
        PCM_SCALARS.fetch_add(bytes.len() / 4, Ordering::SeqCst);
        PCM_WRITES.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl AudioHandler {
    fn start_audio(&mut self, format: AudioFormat) -> ResultType<()> {
        let (_, pcm) = self.audio_decoder.as_ref().expect("native decoder must precede playback");
        assert_eq!(pcm.len(), format.sample_rate as usize * format.channels as usize);
        assert!(pcm.iter().all(|sample| *sample == 0.0));
        self.simple = Some(ControlledPlayback);
        PLAYBACK_STARTS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn refuse_pcm(layout: std::alloc::Layout, bytes: usize) -> bool {
    if bytes != 0 && bytes == PCM_TARGET_BYTES.load(Ordering::SeqCst)
        && layout.align() == std::mem::align_of::<f32>() && PCM_REFUSE.load(Ordering::SeqCst)
    {
        PCM_REFUSALS.fetch_add(1, Ordering::SeqCst);
        true
    } else { false }
}

struct AdmissionAllocator;
thread_local! {
    static ALLOCATION_BUDGET: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static ALLOCATION_REFUSALS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn refuse_allocation() -> bool {
    ALLOCATION_BUDGET.try_with(|budget| match budget.get() {
        None => false,
        Some(0) => {
            ALLOCATION_REFUSALS.with(|count| count.set(count.get() + 1));
            true
        }
        Some(remaining) => { budget.set(Some(remaining - 1)); false }
    }).unwrap_or(false)
}

unsafe impl std::alloc::GlobalAlloc for AdmissionAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        if refuse_pcm(layout, layout.size()) || refuse_allocation() { std::ptr::null_mut() }
        else { std::alloc::GlobalAlloc::alloc(&std::alloc::System, layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        if refuse_pcm(layout, layout.size()) || refuse_allocation() { std::ptr::null_mut() }
        else { std::alloc::GlobalAlloc::alloc_zeroed(&std::alloc::System, layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        if refuse_pcm(layout, size) || refuse_allocation() { std::ptr::null_mut() }
        else { std::alloc::GlobalAlloc::realloc(&std::alloc::System, pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        std::alloc::GlobalAlloc::dealloc(&std::alloc::System, pointer, layout);
    }
}

#[global_allocator]
static ADMISSION_ALLOCATOR: AdmissionAllocator = AdmissionAllocator;

fn wait_for(mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while !predicate() {
        if std::time::Instant::now() >= deadline { return false; }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    true
}

fn decoder_format(rate: u32, channels: u32) -> AudioFormat {
    let mut format = AudioFormat::new();
    format.sample_rate = rate;
    format.channels = channels;
    format
}

fn encoded_frame(rate: u32, channels: u32) -> AudioFrame {
    let mut encoder = Encoder::new(rate, if channels == 1 { Mono } else { Stereo }, Application::LowDelay).unwrap();
    let pcm: Vec<f32> = (0..rate / 50).flat_map(|i| {
        let sample = (i as f32 * std::f32::consts::TAU * 440.0 / rate as f32).sin() * 0.25;
        std::iter::repeat(sample).take(channels as usize)
    }).collect();
    let mut packet = [0u8; MAX_NATIVE_OPUS_PACKET_BYTES];
    let bytes = encoder.encode_float(&pcm, &mut packet).unwrap();
    let mut frame = AudioFrame::new();
    frame.data = packet[..bytes].to_vec().into();
    frame
}

fn start_decoder(rate: u32, channels: u32) -> (AudioMailboxSender, std::thread::JoinHandle<()>) {
    let (sender, worker) = new_audio_thread();
    assert_eq!(sender.admit_format(decoder_format(rate, channels)), AudioFormatAdmission::Queued);
    (sender, worker)
}

fn decoder_storage_case(case: &str) {
    if case == "probe" {
        PCM_TARGET_BYTES.store(384000, Ordering::SeqCst);
        PCM_REFUSE.store(true, Ordering::SeqCst);
        std::hint::black_box(Vec::<f32>::with_capacity(96000));
        panic!("PCM allocation-refusal probe returned");
    }
    let parts: Vec<_> = case.split(':').collect();
    assert_eq!(parts.len(), 3);
    let rate: u32 = parts[1].parse().unwrap();
    let channels: u32 = parts[2].parse().unwrap();
    let (sender, worker) = start_decoder(rate, channels);
    let started = wait_for(|| PLAYBACK_STARTS.load(Ordering::SeqCst) == 1);
    if !started { drop(sender); worker.join().unwrap(); panic!("healthy decoder never started"); }
    if parts[0] == "refusal" {
        PCM_TARGET_BYTES.store(rate as usize * channels as usize * 4, Ordering::SeqCst);
        PCM_REFUSE.store(true, Ordering::SeqCst);
        let (failed_sender, failed_worker) = start_decoder(rate, channels);
        let terminal = wait_for(|| failed_worker.is_finished());
        PCM_REFUSE.store(false, Ordering::SeqCst);
        let closed = failed_sender.state_for_test() == (true, false, 0);
        let starts = PLAYBACK_STARTS.load(Ordering::SeqCst);
        drop(failed_sender);
        failed_worker.join().unwrap();
        // Existing playback must survive, and a fresh worker must decode with the same format.
        assert_eq!(sender.admit_frame(encoded_frame(rate, channels)), AudioFrameAdmission::Queued);
        let survivor = wait_for(|| PCM_WRITES.load(Ordering::SeqCst) == 1);
        drop(sender);
        worker.join().unwrap();
        let (fresh, fresh_worker) = start_decoder(rate, channels);
        let restarted = wait_for(|| PLAYBACK_STARTS.load(Ordering::SeqCst) == 2);
        assert_eq!(fresh.admit_frame(encoded_frame(rate, channels)), AudioFrameAdmission::Queued);
        let recovered = wait_for(|| PCM_WRITES.load(Ordering::SeqCst) == 2);
        drop(fresh);
        fresh_worker.join().unwrap();
        assert!(terminal && closed && survivor && restarted && recovered);
        assert_eq!(starts, 1, "storage refusal must precede backend setup");
        assert_eq!(PCM_REFUSALS.load(Ordering::SeqCst), 1);
        assert_eq!(PCM_SCALARS.load(Ordering::SeqCst), rate as usize / 50 * channels as usize * 2);
        println!("AUDIO_DECODE_CASE=pass case={case} refusals=1 terminal=natural mailbox=closed survivor=decoded fresh=decoded");
    } else if parts[0] == "decode-error" {
        let mut decoder = AudioDecoder::new(rate, if channels == 1 { Mono } else { Stereo }).unwrap();
        assert!(decoder.decode_float(&[0xff], &mut vec![0.0; rate as usize * channels as usize], false).is_err());
        let mut frame = AudioFrame::new();
        frame.data = vec![0xff].into();
        assert_eq!(sender.admit_frame(frame), AudioFrameAdmission::Queued);
        let terminal = wait_for(|| worker.is_finished());
        let closed = sender.state_for_test() == (true, false, 0);
        // A failed old worker is still joined; sender loss is cleanup, not accepted finality.
        drop(sender);
        worker.join().unwrap();
        println!("AUDIO_DECODE_FAILURE=observed terminal={terminal} mailbox_closed={closed} forced_cleanup={}", !terminal);
        assert!(terminal && closed, "native decode failure left worker admission open");
        assert_eq!(PCM_WRITES.load(Ordering::SeqCst), 0);
    } else {
        assert_eq!(parts[0], "healthy");
        for count in 1..=3 {
            assert_eq!(sender.admit_frame(encoded_frame(rate, channels)), AudioFrameAdmission::Queued);
            if !wait_for(|| PCM_WRITES.load(Ordering::SeqCst) == count) {
                drop(sender); worker.join().unwrap(); panic!("native PCM write timed out");
            }
        }
        drop(sender);
        worker.join().unwrap();
        let scalars = PCM_SCALARS.load(Ordering::SeqCst);
        assert_eq!(scalars, rate as usize / 50 * channels as usize * 3);
        assert_eq!(PCM_REFUSALS.load(Ordering::SeqCst), 0);
        println!("AUDIO_DECODE_CASE=pass case={case} writes=3 scalars={scalars} worker=joined");
    }
    if parts[0] != "decode-error" {
        assert!(PCM_NONZERO.load(Ordering::SeqCst) > 0);
        assert_eq!(PCM_NONFINITE.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn decoder_storage_failure_closes_worker_and_preserves_native_opus() {
    use std::{os::unix::process::ExitStatusExt, process::Command};
    if let Ok(case) = std::env::var("AUDIO_DECODE_CASE") {
        decoder_storage_case(&case);
        return;
    }
    let executable = std::env::current_exe().unwrap();
    let run = |case: &str| Command::new(&executable)
        .args(["--exact", "decoder_storage_failure_closes_worker_and_preserves_native_opus", "--nocapture"])
        .env("AUDIO_DECODE_CASE", case).output().unwrap();
    let probe = run("probe");
    assert_eq!(probe.status.signal(), Some(6));
    assert!(String::from_utf8_lossy(&probe.stderr).contains("memory allocation of 384000 bytes failed"));
    println!("AUDIO_DECODE_PROBE=observed bytes=384000 signal=Some(6)");
    let mut cases = Vec::new();
    for rate in [8000, 12000, 16000, 24000, 48000] {
        for channels in [1, 2] {
            for kind in ["healthy", "refusal"] { cases.push(format!("{kind}:{rate}:{channels}")); }
        }
    }
    cases.push("decode-error:48000:2".to_owned());
    let mut passed = 0;
    for case in cases {
        let output = run(&case);
        assert!(output.stdout.len() + output.stderr.len() <= 65536);
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if line.starts_with("AUDIO_DECODE_") { println!("{line}"); }
        }
        print!("{}", String::from_utf8_lossy(&output.stderr));
        println!("AUDIO_DECODE_CHILD=observed case={case} success={} signal={:?}", output.status.success(), output.status.signal());
        passed += usize::from(output.status.success());
    }
    assert_eq!(passed, 21, "PCM storage refusal and native decode errors must retire only their worker");
    println!("AUDIO_DECODE_STORAGE=pass refusals=10 healthy=10 decode_failure=1 probe=SIGABRT children=22");
}

fn with_allocation_budget<T>(budget: usize, action: impl FnOnce() -> T) -> (T, usize) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) { ALLOCATION_BUDGET.with(|budget| budget.set(None)); }
    }
    ALLOCATION_REFUSALS.with(|count| count.set(0));
    ALLOCATION_BUDGET.with(|current| { assert!(current.get().is_none()); current.set(Some(budget)); });
    let reset = Reset;
    let result = action();
    drop(reset);
    (result, ALLOCATION_REFUSALS.with(std::cell::Cell::get))
}

fn allocation_admission_case(case: &str) {
    use audio_mailbox::{AudioFormatAdmission, AudioFrameAdmission, AudioMailboxItem};
    fn format() -> message_proto::AudioFormat {
        let mut format = message_proto::AudioFormat::new();
        format.sample_rate = 48000; format.channels = 2; format
    }
    fn frame(marker: u8, bytes: usize) -> message_proto::AudioFrame {
        let mut frame = message_proto::AudioFrame::new();
        frame.data = vec![marker; bytes].into(); frame
    }
    if case == "probe" {
        with_allocation_budget(0, || std::hint::black_box(Vec::<u8>::with_capacity(31)));
        panic!("the allocation-refusal probe unexpectedly returned");
    }
    let parts: Vec<_> = case.split(':').collect();
    assert_eq!(parts.len(), 4);
    let healthy = parts[0] == "healthy";
    let bytes: usize = parts[1].parse().unwrap();
    let queued: usize = parts[2].parse().unwrap();
    let budget: usize = parts[3].parse().unwrap();
    let (sender, receiver) = audio_mailbox::audio_mailbox();
    assert_eq!(sender.admit_format(format()), AudioFormatAdmission::Queued);
    assert!(matches!(receiver.recv(), Some(AudioMailboxItem::Format(_))));
    for marker in 0..queued {
        assert_eq!(sender.admit_frame(frame(marker as u8, bytes)), AudioFrameAdmission::Queued);
    }
    let packet = frame(255, bytes);
    let (result, refusals) = with_allocation_budget(budget, || sender.admit_frame(packet));
    if healthy {
        assert_eq!(refusals, 0);
        assert_eq!(result, if queued == 8 { AudioFrameAdmission::ReplacedOldest } else { AudioFrameAdmission::Queued });
        assert_eq!(sender.state_for_test(), (false, false, (queued + 1).min(8)));
        for marker in usize::from(queued == 8)..queued {
            let Some(AudioMailboxItem::Frame(packet)) = receiver.recv() else { panic!("queued packet lost"); };
            assert_eq!(packet.data, vec![marker as u8; bytes]);
        }
        let Some(AudioMailboxItem::Frame(packet)) = receiver.recv() else { panic!("new packet lost"); };
        assert_eq!(packet.data, vec![255; bytes]);
    } else {
        assert!(refusals > 0);
        assert_eq!(result, AudioFrameAdmission::ResourceUnavailable);
        assert_eq!(sender.state_for_test(), (true, false, 0));
        assert!(receiver.recv().is_none());
        assert_eq!(sender.admit_format(format()), AudioFormatAdmission::Closed);
        assert_eq!(sender.admit_frame(frame(1, bytes)), AudioFrameAdmission::Closed);
        let (fresh, fresh_receiver) = audio_mailbox::audio_mailbox();
        assert_eq!(fresh.admit_format(format()), AudioFormatAdmission::Queued);
        assert_eq!(fresh.admit_frame(frame(9, bytes)), AudioFrameAdmission::Queued);
        assert!(matches!(fresh_receiver.recv(), Some(AudioMailboxItem::Format(_))));
        let Some(AudioMailboxItem::Frame(packet)) = fresh_receiver.recv() else { panic!("fresh owner failed"); };
        assert_eq!(packet.data, vec![9; bytes]);
    }
    println!("AUDIO_MAILBOX_ALLOC_CASE=pass kind={} bytes={bytes} queued={queued} budget={budget} refusals={refusals} terminal={} state=checked",
        if healthy { "healthy" } else { "refusal" }, !healthy);
}

#[test]
fn frame_admission_allocation_failure_is_terminal_and_recoverable() {
    use std::{os::unix::process::ExitStatusExt, process::Command};
    if let Ok(case) = std::env::var("AUDIO_MAILBOX_ALLOC_CASE") {
        allocation_admission_case(&case);
        return;
    }
    let executable = std::env::current_exe().unwrap();
    let run = |case: &str| Command::new(&executable)
        .args(["--exact", "frame_admission_allocation_failure_is_terminal_and_recoverable", "--nocapture"])
        .env("AUDIO_MAILBOX_ALLOC_CASE", case).output().unwrap();
    let probe = run("probe");
    assert_eq!(probe.status.signal(), Some(6));
    assert!(String::from_utf8_lossy(&probe.stderr).contains("memory allocation of 31 bytes failed"));
    println!("AUDIO_MAILBOX_ALLOC_PROBE=observed bytes=31 signal={:?}", probe.status.signal());
    let mut passed = 0;
    for bytes in [1, 4096] {
        for queued in [0, 4, 8] {
            let allocations = if queued == 8 { 1 } else { 2 };
            for budget in 0..=allocations {
                let kind = if budget == allocations { "healthy" } else { "refusal" };
                let case = format!("{kind}:{bytes}:{queued}:{budget}");
                let output = run(&case);
                assert!(output.stdout.len() + output.stderr.len() <= 65536);
                for line in String::from_utf8_lossy(&output.stdout).lines() {
                    if line.starts_with("AUDIO_MAILBOX_ALLOC_CASE=") { println!("{line}"); }
                }
                print!("{}", String::from_utf8_lossy(&output.stderr));
                println!("AUDIO_MAILBOX_ALLOC_CHILD=observed case={case} success={} signal={:?}", output.status.success(), output.status.signal());
                passed += usize::from(output.status.success());
            }
        }
    }
    assert_eq!(passed, 16, "every allocation refusal must return a terminal result and healthy admission must preserve packets");
    println!("AUDIO_MAILBOX_ALLOC=pass refusals=10 healthy=6 probe=SIGABRT children=joined");
}
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
