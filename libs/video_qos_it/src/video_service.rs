use super::{video_qos::VideoQoS, Enum, ImageQuality};
use hbb_common::{anyhow::anyhow, lazy_static::lazy_static, ResultType};
use std::{cell::Cell, sync::Mutex, time::{Duration, Instant}};

// Only the encoder boundary is controlled; QoS selection and application are production code.
struct Encoder {
    supports_quality: bool,
    failures: usize,
    requests: Vec<f32>,
    bitrate: u32,
    bitrate_reads: Cell<usize>,
}

impl Encoder {
    fn new(supports_quality: bool, failures: usize) -> Self {
        Self { supports_quality, failures, requests: Vec::new(), bitrate: 2000,
            bitrate_reads: Cell::new(0) }
    }

    fn support_changing_quality(&self) -> bool { self.supports_quality }

    fn set_quality(&mut self, ratio: f32) -> ResultType<()> {
        self.requests.push(ratio);
        if self.failures > 0 {
            self.failures -= 1;
            return Err(anyhow!("controlled encoder quality failure"));
        }
        self.bitrate += 500;
        Ok(())
    }

    fn bitrate(&self) -> u32 {
        self.bitrate_reads.set(self.bitrate_reads.get() + 1);
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
