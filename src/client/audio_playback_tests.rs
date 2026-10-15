use super::AudioHandler;
use hbb_common::message_proto::{AudioFormat, AudioFrame};
use magnum_opus::{Application::LowDelay, Channels::Stereo, Encoder};
use std::{collections::BTreeSet, process::Command, time::{Duration, Instant}};

fn require_private_server() -> String {
    assert_eq!(std::env::var("RUSTDESK_PA_NATIVE_TEST").unwrap(), "1");
    assert_eq!(std::env::var("PULSE_SERVER").unwrap(),
               "unix:/tmp/pa-runtime/runtime/pulse/native");
    std::env::var("RUSTDESK_PA_NATIVE_PACTL").unwrap()
}

fn pactl(arguments: &[&str]) -> String {
    let result = Command::new(require_private_server()).args(arguments).output().unwrap();
    assert!(result.status.success(), "pactl {arguments:?}: {result:?}");
    String::from_utf8(result.stdout).unwrap()
}

fn sink_inputs() -> BTreeSet<String> {
    pactl(&["list", "short", "sink-inputs"]).lines()
        .map(|line| line.split_whitespace().next().unwrap().to_owned()).collect()
}

fn tasks() -> BTreeSet<String> {
    std::fs::read_dir("/proc/self/task").unwrap().map(|entry|
        entry.unwrap().file_name().into_string().unwrap()).collect()
}

fn assert_tasks_retired(before: &BTreeSet<String>) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let current = tasks();
        if &current == before { return; }
        assert!(Instant::now() < deadline, "native audio threads remain: {current:?}, before: {before:?}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn format() -> AudioFormat {
    let mut format = AudioFormat::new();
    format.sample_rate = 48000;
    format.channels = 2;
    format
}

fn frame() -> AudioFrame {
    let mut encoder = Encoder::new(48000, Stereo, LowDelay).unwrap();
    let pcm: Vec<f32> = (0..960).flat_map(|i| {
        let sample = (i as f32 * 440.0 * std::f32::consts::TAU / 48000.0).sin() * 0.25;
        [sample, sample]
    }).collect();
    let mut encoded = vec![0; 4096];
    let length = encoder.encode_float(&pcm, &mut encoded).unwrap();
    encoded.truncate(length);
    let mut frame = AudioFrame::new();
    frame.data = encoded.into();
    frame
}

fn assert_retired(handler: &AudioHandler) {
    assert!(handler.simple.is_none(), "failed playback must release its native connection");
    assert!(handler.audio_decoder.is_none(), "failed playback must release its decoder");
    assert_eq!(handler.audio_format, Some((48000, 2)), "failure must preserve the first format pin");
}

fn assert_no_recreation(handler: &mut AudioHandler) {
    handler.handle_format(format());
    let mut changed = format();
    changed.channels = 1;
    handler.handle_format(changed);
    handler.handle_frame(frame());
    assert_retired(handler);
}

#[test]
#[ignore = "requires the disposable VM's private native PulseAudio daemon"]
fn real_write_and_decode_failures_retire_audio_resources() {
    require_private_server();
    let before_inputs = sink_inputs();
    let before_tasks = tasks();
    let mut handler = AudioHandler::default();
    handler.handle_format(format());
    assert!(handler.simple.is_some() && handler.audio_decoder.is_some());
    let inputs = sink_inputs();
    let added: Vec<_> = inputs.difference(&before_inputs).cloned().collect();
    assert_eq!(added.len(), 1, "one exact playback stream must be created");
    assert!(before_inputs.is_subset(&inputs));
    assert!(tasks().difference(&before_tasks).count() >= 1, "native Simple must own a live thread");
    handler.handle_frame(frame());
    handler.simple.as_ref().unwrap().drain().unwrap();

    // Kill only the exact stream created by this handler; the private daemon stays live.
    pactl(&["kill-sink-input", &added[0]]);
    let deadline = Instant::now() + Duration::from_secs(2);
    while handler.simple.as_ref().unwrap().get_latency().is_ok() {
        assert!(Instant::now() < deadline, "native stream did not observe removal");
        std::thread::sleep(Duration::from_millis(5));
    }
    handler.handle_frame(frame());
    assert_retired(&handler);
    assert_no_recreation(&mut handler);
    assert_eq!(sink_inputs(), before_inputs);
    assert_tasks_retired(&before_tasks);

    let mut fresh = AudioHandler::default();
    fresh.handle_format(format());
    assert!(fresh.simple.is_some() && fresh.audio_decoder.is_some());
    fresh.handle_frame(frame());
    fresh.simple.as_ref().unwrap().drain().unwrap();
    let mut malformed = AudioFrame::new();
    malformed.data = vec![0xff].into();
    fresh.handle_frame(malformed);
    assert_retired(&fresh);
    assert_no_recreation(&mut fresh);
    assert_eq!(sink_inputs(), before_inputs);
    assert_tasks_retired(&before_tasks);

    let mut recovered = AudioHandler::default();
    recovered.handle_format(format());
    assert!(recovered.simple.is_some() && recovered.audio_decoder.is_some());
    recovered.handle_frame(frame());
    recovered.simple.as_ref().unwrap().drain().unwrap();
    drop(recovered);
    assert_eq!(sink_inputs(), before_inputs);
    assert_tasks_retired(&before_tasks);
    println!("PA_PLAYBACK_FINALITY=pass native_write=failed decoder=retired output=retired replay=refused decode_failure=retired fresh_owner=recovered threads=retired");
}

#[test]
#[ignore = "requires the disposable VM's private native PulseAudio daemon"]
fn real_setup_failure_is_terminal_and_a_fresh_owner_recovers() {
    let server = {
        require_private_server();
        std::env::var_os("PULSE_SERVER").unwrap()
    };
    let before_inputs = sink_inputs();
    let before_tasks = tasks();
    struct RestoreServer(std::ffi::OsString);
    impl Drop for RestoreServer {
        fn drop(&mut self) { std::env::set_var("PULSE_SERVER", &self.0); }
    }
    let restore = RestoreServer(server);
    std::env::set_var("PULSE_SERVER", "unix:/tmp/pa-runtime/runtime/pulse/absent");
    let mut handler = AudioHandler::default();
    handler.handle_format(format());
    drop(restore);
    assert_retired(&handler);
    assert_no_recreation(&mut handler);
    assert_eq!(sink_inputs(), before_inputs);
    assert_tasks_retired(&before_tasks);

    let mut fresh = AudioHandler::default();
    fresh.handle_format(format());
    assert!(fresh.simple.is_some() && fresh.audio_decoder.is_some());
    fresh.handle_frame(frame());
    fresh.simple.as_ref().unwrap().drain().unwrap();
    drop(fresh);
    assert_eq!(sink_inputs(), before_inputs);
    assert_tasks_retired(&before_tasks);
    println!("PA_PLAYBACK_SETUP_FINALITY=pass native_open=failed decoder=retired replay=refused fresh_owner=recovered threads=retired");
}

