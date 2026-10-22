use super::{video_qos::VideoQoS, Enum, ImageQuality};
use hbb_common::{anyhow::anyhow, lazy_static::lazy_static, ResultType};
use std::{cell::{Cell, RefCell}, sync::{mpsc, Mutex}, time::{Duration, Instant}};

struct EncoderGate {
    stage: &'static str,
    entered: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
}

// Only the encoder boundary is controlled; QoS selection and application are production code.
struct Encoder {
    supports_quality: bool,
    failures: usize,
    requests: Vec<f32>,
    bitrate: u32,
    bitrate_reads: Cell<usize>,
    gate: RefCell<Option<EncoderGate>>,
}

impl Encoder {
    fn new(supports_quality: bool, failures: usize) -> Self {
        Self { supports_quality, failures, requests: Vec::new(), bitrate: 2000,
            bitrate_reads: Cell::new(0), gate: RefCell::new(None) }
    }

    fn wait_at(&self, stage: &str) {
        let gate = {
            let mut gate = self.gate.borrow_mut();
            if gate.as_ref().map(|gate| gate.stage) == Some(stage) { gate.take() } else { None }
        };
        if let Some(gate) = gate {
            gate.entered.send(()).unwrap();
            gate.release.recv_timeout(Duration::from_secs(2)).unwrap();
        }
    }

    fn support_changing_quality(&self) -> bool { self.supports_quality }

    fn set_quality(&mut self, ratio: f32) -> ResultType<()> {
        self.requests.push(ratio);
        self.wait_at("set");
        if self.failures > 0 {
            self.failures -= 1;
            return Err(anyhow!("controlled encoder quality failure"));
        }
        self.bitrate += 500;
        Ok(())
    }

    fn bitrate(&self) -> u32 {
        self.bitrate_reads.set(self.bitrate_reads.get() + 1);
        self.wait_at("bitrate");
        self.bitrate
    }
}

lazy_static! {
    static ref VIDEO_QOS: Mutex<VideoQoS> = Mutex::new(VideoQoS::default());
}

#[path = "../../../src/server/video_qos_apply.rs"]
mod qos_apply;

fn reset(supports_quality: bool) -> f32 {
    let mut qos = VIDEO_QOS.lock().unwrap();
    *qos = VideoQoS::default();
    qos.on_connection_open(7);
    qos.new_display("monitor".into());
    qos.set_support_changing_quality("monitor", supports_quality);
    qos.store_bitrate(2000);
    qos.ratio()
}

fn apply(encoder: &mut Encoder, ratio: &mut f32) -> ResultType<()> {
    qos_apply::check_qos(encoder, ratio, &mut Duration::ZERO, false,
        &mut 0, &mut Instant::now(), "monitor")
}

#[test]
fn failed_quality_change_preserves_confirmation_and_retries() {
    let original = reset(true);
    let mut ratio = original;
    let mut encoder = Encoder::new(true, 2);
    VIDEO_QOS.lock().unwrap().user_image_quality(7, ImageQuality::Best.value());
    let target = VIDEO_QOS.lock().unwrap().ratio();
    let mut observations = Vec::new();
    for attempt in 1..=2 {
        let result = apply(&mut encoder, &mut ratio);
        let error = result.as_ref().err().map(ToString::to_string);
        let unchanged = ratio == original && VIDEO_QOS.lock().unwrap().bitrate() == 2000;
        let retried = encoder.requests.len() == attempt;
        println!("VIDEO_QOS_APPLY=error attempt={attempt} result={error:?} ratio={ratio} unchanged={unchanged} requests={} bitrate_reads={}", encoder.requests.len(), encoder.bitrate_reads.get());
        observations.push(error.as_deref() == Some("controlled encoder quality failure")
            && unchanged && retried && encoder.bitrate_reads.get() == 0);
    }
    let retried = apply(&mut encoder, &mut ratio).is_ok();
    let confirmed = ratio == target && VIDEO_QOS.lock().unwrap().bitrate() == 2500;
    println!("VIDEO_QOS_APPLY=retry success={retried} confirmed={confirmed} requests={} bitrate_reads={}", encoder.requests.len(), encoder.bitrate_reads.get());
    assert!(observations.into_iter().all(|ok| ok) && retried && confirmed
        && encoder.requests == [target, target, target] && encoder.bitrate_reads.get() == 1);
}

#[test]
fn unsupported_quality_changes_require_recreation() {
    let mut observations = Vec::new();
    for registered in [false, true] {
        for quality in [ImageQuality::Best.value(), 150 << 8] {
            let original = reset(false);
            if !registered { VIDEO_QOS.lock().unwrap().remove_display("monitor"); }
            VIDEO_QOS.lock().unwrap().user_image_quality(7, quality);
            let mut ratio = original;
            let mut encoder = Encoder::new(false, 0);
            let result = apply(&mut encoder, &mut ratio);
            let error = result.as_ref().err().map(ToString::to_string);
            let unchanged = ratio == original && VIDEO_QOS.lock().unwrap().bitrate() == 2000;
            println!("VIDEO_QOS_APPLY=unsupported registered={registered} quality={quality} result={error:?} unchanged={unchanged} requests={}", encoder.requests.len());
            observations.push(error.as_deref() == Some("SWITCH") && unchanged
                && encoder.requests.is_empty() && encoder.bitrate_reads.get() == 0);
        }
    }
    assert!(observations.into_iter().all(|ok| ok));
}

#[test]
fn successful_quality_changes_publish_once_per_target() {
    let mut ratio = reset(true);
    let mut encoder = Encoder::new(true, 0);
    let mut targets = Vec::new();
    for quality in [ImageQuality::Best.value(), 150 << 8] {
        VIDEO_QOS.lock().unwrap().user_image_quality(7, quality);
        let target = VIDEO_QOS.lock().unwrap().ratio();
        targets.push(target);
        apply(&mut encoder, &mut ratio).unwrap();
        assert_eq!(ratio, target);
        assert_eq!(VIDEO_QOS.lock().unwrap().bitrate(), encoder.bitrate);
        apply(&mut encoder, &mut ratio).unwrap();
        assert_eq!(encoder.requests, targets);
        assert_eq!(encoder.bitrate_reads.get(), targets.len());
    }
    println!("VIDEO_QOS_APPLY=success targets={targets:?} requests={} bitrate_reads={}", encoder.requests.len(), encoder.bitrate_reads.get());
}

#[test]
fn recording_switch_and_periodic_accounting_remain_active() {
    let mut ratio = reset(true);
    let mut encoder = Encoder::new(true, 0);
    let mut spf = Duration::ZERO;
    let mut count = 7;
    let mut second = Instant::now() - Duration::from_secs(2);
    qos_apply::check_qos(&mut encoder, &mut ratio, &mut spf, false,
        &mut count, &mut second, "monitor").unwrap();
    assert_eq!(count, 0);
    assert!(spf > Duration::ZERO && second.elapsed() < Duration::from_secs(1));
    VIDEO_QOS.lock().unwrap().user_record(7, true);
    let result = qos_apply::check_qos(&mut encoder, &mut ratio, &mut spf, false,
        &mut count, &mut second, "monitor");
    assert_eq!(result.unwrap_err().to_string(), "SWITCH");
    assert!(encoder.requests.is_empty() && encoder.bitrate_reads.get() == 0);
    println!("VIDEO_QOS_APPLY=controls accounting=true pacing=true record_switch=true unchanged_target_no_apply=true");
}

#[test]
fn encoder_calls_allow_feedback_and_revalidate_the_display_owner() {
    let mut passed = 0;
    let mut available = 0;
    let mut joined = 0;
    for (stage, event, failures) in [
        ("set", "feedback", 0), ("bitrate", "feedback", 0),
        ("set", "replace", 0), ("bitrate", "replace", 0),
        ("set", "reset", 0), ("bitrate", "reset", 0),
        ("set", "record", 0), ("bitrate", "record", 0),
        ("set", "failure", 1),
    ] {
        let original = reset(true);
        VIDEO_QOS.lock().unwrap().user_image_quality(7, ImageQuality::Best.value());
        let requested = VIDEO_QOS.lock().unwrap().ratio();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let mut encoder = Encoder::new(true, failures);
        *encoder.gate.get_mut() = Some(EncoderGate { stage, entered: entered_tx, release: release_rx });
        let worker = std::thread::spawn(move || {
            let mut ratio = original;
            let mut spf = Duration::ZERO;
            let result = qos_apply::check_qos(&mut encoder, &mut ratio, &mut spf, false,
                &mut 0, &mut Instant::now(), "monitor");
            (encoder, ratio, spf, result.err().map(|error| error.to_string()))
        });
        let entered = entered_rx.recv_timeout(Duration::from_secs(2)).is_ok();
        let applied = if let Ok(mut qos) = VIDEO_QOS.try_lock() {
            match event {
                "feedback" | "failure" => {
                    qos.user_custom_fps(7, 5);
                    qos.user_delay_response_elapsed(7, 4000);
                    qos.user_image_quality(7, ImageQuality::Low.value());
                }
                "replace" => {
                    qos.remove_display("monitor");
                    qos.new_display("monitor".into());
                    qos.store_bitrate(7777);
                }
                "reset" => {
                    qos.on_connection_close(7);
                    qos.on_connection_open(7);
                    qos.new_display("monitor".into());
                    qos.store_bitrate(7777);
                }
                "record" => qos.user_record(7, true),
                _ => unreachable!(),
            }
            true
        } else { false };
        let released = release_tx.send(()).is_ok();
        let (mut encoder, mut ratio, spf, error) = worker.join().unwrap();
        joined += 1;
        available += usize::from(applied);
        let mut correct = entered && released && applied && encoder.requests == [requested];
        match event {
            "feedback" => {
                let mut qos = VIDEO_QOS.lock().unwrap();
                let latest = qos.ratio();
                correct &= error.is_none() && ratio == requested && qos.bitrate() == 2500
                    && qos.fps() == 2 && spf == Duration::from_millis(500) && latest != requested;
                drop(qos);
                let retry = apply(&mut encoder, &mut ratio);
                correct &= retry.is_ok() && ratio == latest && encoder.requests == [requested, latest]
                    && VIDEO_QOS.lock().unwrap().bitrate() == 3000;
            }
            "replace" | "reset" => {
                let mut qos = VIDEO_QOS.lock().unwrap();
                correct &= error.as_deref() == Some("SWITCH") && ratio == original && qos.bitrate() == 7777;
                qos.remove_display("monitor");
                correct &= !qos.in_vbr_state();
            }
            "record" => {
                let qos = VIDEO_QOS.lock().unwrap();
                correct &= error.as_deref() == Some("SWITCH") && ratio == original
                    && qos.bitrate() == 2000 && qos.record();
            }
            "failure" => {
                let mut qos = VIDEO_QOS.lock().unwrap();
                correct &= error.as_deref() == Some("controlled encoder quality failure")
                    && ratio == original && qos.bitrate() == 2000
                    && qos.ratio() != requested && qos.fps() == 2 && encoder.bitrate_reads.get() == 0;
            }
            _ => unreachable!(),
        }
        passed += usize::from(correct);
        println!("VIDEO_QOS_ENCODER_OWNER=observed stage={stage} event={event} available={applied} entered={entered} released={released} joined=true correct={correct} error={error:?}");
    }
    println!("VIDEO_QOS_ENCODER_OWNER=observed cases=9 available={available} passed={passed} joined={joined}");
    assert_eq!(passed, 9);
    assert_eq!(available, 9);
    assert_eq!(joined, 9);
    println!("VIDEO_QOS_ENCODER_OWNER=pass cases=9 available=9 passed=9 joined=9 stale=refused feedback=preserved retries=pass");
}
