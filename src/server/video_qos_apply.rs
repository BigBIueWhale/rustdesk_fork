use super::{Duration, Encoder, VIDEO_QOS};
use crate::server::video_qos::{DisplayActivity, DisplayGeneration};
use hbb_common::{anyhow::bail, log, ResultType};

pub(super) fn check_qos(
    encoder: &mut Encoder,
    ratio: &mut f32,
    spf: &mut Duration,
    client_record: bool,
    activity: &mut DisplayActivity,
    name: &str,
    generation: &DisplayGeneration,
) -> ResultType<()> {
    let requested_ratio = {
        let mut video_qos = VIDEO_QOS.lock().unwrap();
        if client_record != video_qos.record()
            || !video_qos.sync_display_activity(name, generation, activity)
        {
            bail!("SWITCH");
        }
        *spf = video_qos.spf();
        video_qos.ratio()
    };
    let bitrate = if *ratio != requested_ratio {
        if !encoder.support_changing_quality() {
            log::info!("switch to change quality");
            bail!("SWITCH");
        }
        encoder.set_quality(requested_ratio)?;
        Some(encoder.bitrate())
    } else {
        None
    };
    let mut video_qos = VIDEO_QOS.lock().unwrap();
    if client_record != video_qos.record()
        || !video_qos.sync_display_activity(name, generation, activity)
    {
        bail!("SWITCH");
    }
    if let Some(bitrate) = bitrate {
        if !video_qos.set_display_bitrate(name, generation, bitrate) {
            bail!("SWITCH");
        }
        *ratio = requested_ratio;
    }
    *spf = video_qos.spf();
    if !video_qos.update_display_data(name, generation, activity) {
        bail!("SWITCH");
    }
    drop(video_qos);
    Ok(())
}
