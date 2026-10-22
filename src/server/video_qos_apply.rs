use super::{Duration, Encoder, Instant, VIDEO_QOS};
use hbb_common::{anyhow::bail, log, ResultType};

pub(super) fn check_qos(
    encoder: &mut Encoder,
    ratio: &mut f32,
    spf: &mut Duration,
    client_record: bool,
    send_counter: &mut usize,
    second_instant: &mut Instant,
    name: &str,
) -> ResultType<()> {
    let mut video_qos = VIDEO_QOS.lock().unwrap();
    *spf = video_qos.spf();
    let requested_ratio = video_qos.ratio();
    if *ratio != requested_ratio {
        if !encoder.support_changing_quality() {
            log::info!("switch to change quality");
            bail!("SWITCH");
        }
        encoder.set_quality(requested_ratio)?;
        *ratio = requested_ratio;
        video_qos.store_bitrate(encoder.bitrate());
    }
    if client_record != video_qos.record() {
        log::info!("switch due to record changed");
        bail!("SWITCH");
    }
    if second_instant.elapsed() > Duration::from_secs(1) {
        *second_instant = Instant::now();
        video_qos.update_display_data(&name, *send_counter);
        *send_counter = 0;
    }
    drop(video_qos);
    Ok(())
}
