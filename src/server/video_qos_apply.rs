use super::{Duration, Encoder, VIDEO_QOS};
use crate::server::video_qos::{DisplayActivity, DisplayGeneration};
use hbb_common::{log, ResultType};
use std::ops::ControlFlow;

pub(super) fn check_qos(
    encoder: &mut Encoder,
    ratio: &mut f32,
    spf: &mut Duration,
    client_record: bool,
    activity: &mut DisplayActivity,
    name: &str,
    generation: &DisplayGeneration,
) -> ResultType<ControlFlow<()>> {
    let requested_ratio = {
        let mut video_qos = VIDEO_QOS.lock().unwrap();
        if client_record != video_qos.record()
            || !video_qos.sync_display_activity(name, generation, activity)
        {
            return Ok(ControlFlow::Break(()));
        }
        *spf = video_qos.spf();
        video_qos.ratio()
    };
    let bitrate = if *ratio != requested_ratio {
        if !encoder.support_changing_quality() {
            log::info!("switch to change quality");
            return Ok(ControlFlow::Break(()));
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
        return Ok(ControlFlow::Break(()));
    }
    if let Some(bitrate) = bitrate {
        if !video_qos.set_display_bitrate(name, generation, bitrate) {
            return Ok(ControlFlow::Break(()));
        }
        *ratio = requested_ratio;
    }
    *spf = video_qos.spf();
    if !video_qos.update_display_data(name, generation, activity) {
        return Ok(ControlFlow::Break(()));
    }
    drop(video_qos);
    Ok(ControlFlow::Continue(()))
}
