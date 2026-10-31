use hbb_common::{config::Config, message_proto::ImageQuality, protobuf::Enum};
use std::collections::HashMap;

#[path = "../../../src/server/video_qos.rs"]
mod video_qos;

#[path = "video_service.rs"]
mod video_service;

#[path = "../../../src/server/connection/latency_probe.rs"]
mod latency_probe;

mod latency_feedback {
    use super::{latency_probe::LatencyProbe, video_qos::VideoQoS};
    use hbb_common::tokio::time::{Duration, Instant};

    #[test]
    fn recovery_samples_preserve_congestion_and_other_viewers() {
        for case in ["healthy", "continued-congestion", "other-pending", "other-limit"] {
            let mut qos = VideoQoS::default();
            qos.on_connection_open(7);
            qos.on_connection_open(8);
            for _ in 0..60 {
                qos.user_network_delay(7, 20);
                qos.user_network_delay(8, 20);
            }
            assert!(qos.fps() >= 10);
            let start = Instant::now();
            let mut probe = LatencyProbe::new(start);
            let sequence = probe.on_timer(start).unwrap().unwrap();
            let restored = start + Duration::from_millis(6630);
            assert!(probe.on_timer(restored).unwrap().is_none());
            qos.user_delay_response_elapsed(7, probe.pending_age(restored).unwrap().as_millis());
            assert!(qos.fps() <= 2);
            let elapsed = probe.complete(sequence, restored, true).unwrap();
            qos.user_network_delay(7, elapsed.as_millis() as u32);
            assert_eq!(qos.fps(), 1);
            if case == "other-pending" {
                qos.user_delay_response_elapsed(8, 4000);
            } else if case == "other-limit" {
                qos.user_custom_fps(8, 5);
            }
            let delay = if case == "continued-congestion" { 420 } else { 20 };
            let mut completed_at = restored;
            for index in 0..2 {
                let due = probe.deadline();
                let sequence = probe.on_timer(due).unwrap().unwrap();
                completed_at = due + Duration::from_millis(delay);
                let elapsed = probe.complete(sequence, completed_at, true).unwrap();
                qos.user_network_delay(7, elapsed.as_millis() as u32);
                if index == 0 || case == "continued-congestion" {
                    assert_eq!(qos.fps(), 1, "one fresh sample or continued congestion cannot restore rate");
                }
            }
            match case {
                "healthy" => {
                    assert!(qos.fps() >= 10);
                    assert!(completed_at.duration_since(restored) < Duration::from_millis(500));
                }
                "continued-congestion" => assert_eq!(qos.fps(), 1),
                "other-pending" => assert_eq!(qos.fps(), 2),
                "other-limit" => assert_eq!(qos.fps(), 5),
                _ => unreachable!(),
            }
            let rate = qos.fps();
            qos.on_connection_close(8);
            if case != "continued-congestion" {
                assert!(qos.fps() >= 10, "the recovered viewer keeps its own estimate");
            }
            println!("LATENCY_PROBE_QOS=pass case={case} measured_ms={delay} shared_fps={rate} remaining_fps={}", qos.fps());
        }
    }
}
