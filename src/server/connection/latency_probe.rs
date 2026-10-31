use hbb_common::tokio::time::{Duration, Instant};

const PERIOD: Duration = Duration::from_secs(1);
const STALLED: Duration = Duration::from_secs(2);
const RECOVERY_SPACING: Duration = Duration::from_millis(100);

/// One connection's outstanding latency measurement and next sampling deadline.
pub(super) struct LatencyProbe {
    next_due: Instant,
    sequence: i64,
    pending: Option<(i64, Instant)>,
    recovery_probes: u8,
}

impl LatencyProbe {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            next_due: now,
            sequence: 0,
            pending: None,
            recovery_probes: 0,
        }
    }

    pub(super) fn deadline(&self) -> Instant {
        self.next_due
    }

    pub(super) fn on_timer(&mut self, now: Instant) -> Result<Option<i64>, &'static str> {
        if now < self.next_due {
            return Ok(None);
        }
        self.next_due = now + PERIOD;
        if self.pending.is_some() {
            return Ok(None);
        }
        self.sequence = self.sequence.checked_add(1).ok_or("Latency probe sequence exhausted")?;
        self.pending = Some((self.sequence, now));
        self.recovery_probes = self.recovery_probes.saturating_sub(1);
        Ok(Some(self.sequence))
    }

    pub(super) fn pending_age(&self, now: Instant) -> Option<Duration> {
        self.pending.map(|(_, started)| now.saturating_duration_since(started))
    }

    pub(super) fn complete(&mut self, sequence: i64, now: Instant, video: bool) -> Option<Duration> {
        let (expected, started) = self.pending?;
        if sequence != expected || now < started {
            return None;
        }
        let elapsed = now.duration_since(started);
        self.pending = None;
        if !video {
            self.recovery_probes = 0;
        } else if elapsed > STALLED {
            // Two new round trips retire the completed outage sample in VideoQoS.
            self.recovery_probes = 2;
        }
        let earliest = now + RECOVERY_SPACING;
        self.next_due = if self.recovery_probes > 0 {
            earliest
        } else {
            self.next_due.max(earliest)
        };
        Some(elapsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stalled_probe_recovers_with_two_serial_samples_and_no_catchup() {
        let start = Instant::now();
        let mut probe = LatencyProbe::new(start);
        let first = probe.on_timer(start).unwrap().unwrap();
        for seconds in [1, 3, 6] {
            let now = start + Duration::from_secs(seconds);
            assert_eq!(probe.on_timer(now).unwrap(), None);
            assert_eq!(probe.pending_age(now), Some(Duration::from_secs(seconds)));
        }
        let mut now = start + Duration::from_millis(6630);
        assert_eq!(probe.complete(first, now, true), Some(Duration::from_millis(6630)));
        for _ in 0..2 {
            assert_eq!(probe.deadline(), now + RECOVERY_SPACING);
            assert_eq!(probe.on_timer(now + Duration::from_millis(99)).unwrap(), None);
            now += RECOVERY_SPACING;
            let sequence = probe.on_timer(now).unwrap().unwrap();
            assert_eq!(probe.on_timer(now).unwrap(), None);
            now += Duration::from_millis(20);
            assert_eq!(probe.complete(sequence, now, true), Some(Duration::from_millis(20)));
        }
        assert_eq!(probe.deadline(), now + Duration::from_millis(980));
        assert_eq!(probe.on_timer(now + RECOVERY_SPACING).unwrap(), None);
        // A delayed task sends one measurement, never a burst of missed ticks.
        now += Duration::from_secs(10);
        assert!(probe.on_timer(now).unwrap().is_some());
        assert_eq!(probe.on_timer(now).unwrap(), None);
        println!("LATENCY_PROBE_SCHEDULE=pass outstanding=1 fresh_samples=2 spacing_ms=100 catchup=none");
    }

    #[test]
    fn only_current_probe_replies_complete_and_nonvideo_keeps_normal_cadence() {
        let start = Instant::now();
        let mut probe = LatencyProbe::new(start);
        assert_eq!(probe.complete(1, start, true), None);
        let first = probe.on_timer(start).unwrap().unwrap();
        let now = start + Duration::from_secs(3);
        assert_eq!(probe.on_timer(now).unwrap(), None);
        let deadline = probe.deadline();
        for (sequence, at) in [(0, now), (first + 1, now), (first, start - PERIOD)] {
            assert_eq!(probe.complete(sequence, at, true), None);
            assert_eq!(probe.deadline(), deadline);
            assert_eq!(probe.pending_age(now), Some(Duration::from_secs(3)));
        }
        assert_eq!(probe.complete(first, now, false), Some(Duration::from_secs(3)));
        assert_eq!(probe.deadline(), deadline);
        assert_eq!(probe.complete(first, now, true), None);
        let second = probe.on_timer(deadline).unwrap().unwrap();
        assert_ne!(first, second);
        assert_eq!(probe.complete(first, deadline + RECOVERY_SPACING, true), None);
        assert_eq!(probe.pending_age(deadline + RECOVERY_SPACING), Some(RECOVERY_SPACING));
        assert_eq!(probe.complete(second, deadline + RECOVERY_SPACING, false), Some(RECOVERY_SPACING));
        probe.sequence = i64::MAX;
        assert!(probe.on_timer(probe.deadline()).is_err());
        assert!(probe.pending.is_none());
        println!("LATENCY_PROBE_REPLY=pass absent=refused wrong=refused stale=refused duplicate=refused nonvideo=normal exhaustion=refused");
    }

    #[hbb_common::tokio::test]
    async fn cancelled_waits_preserve_the_recovery_deadline() {
        let mut probe = LatencyProbe::new(Instant::now());
        let first = probe.on_timer(Instant::now()).unwrap().unwrap();
        let started = Instant::now();
        probe.pending = Some((first, started - Duration::from_secs(3)));
        probe.complete(first, started, true).unwrap();
        let deadline = probe.deadline();
        for _ in 0..3 {
            hbb_common::tokio::select! {
                biased;
                _ = hbb_common::tokio::time::sleep_until(probe.deadline()) => {
                    panic!("recovery timer completed before cancellation controls");
                }
                _ = hbb_common::tokio::time::sleep(Duration::from_millis(10)) => {}
            }
            assert_eq!(probe.deadline(), deadline);
        }
        hbb_common::tokio::time::sleep_until(probe.deadline()).await;
        let elapsed = started.elapsed();
        assert!(elapsed >= RECOVERY_SPACING && elapsed < Duration::from_millis(500));
        assert!(probe.on_timer(Instant::now()).unwrap().is_some());
        assert!(probe.on_timer(Instant::now()).unwrap().is_none());
        println!("LATENCY_PROBE_TIMER=pass elapsed_ms={} cancellations=3 outstanding=1", elapsed.as_millis());
    }
}
