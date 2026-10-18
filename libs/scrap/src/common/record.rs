use crate::CodecFormat;
#[cfg(feature = "hwcodec")]
use hbb_common::anyhow::anyhow;
use hbb_common::{
    bail, chrono, log,
    message_proto::{message, video_frame, EncodedVideoFrame, Message},
    uuid::Uuid,
    ResultType,
};
#[cfg(feature = "hwcodec")]
use hwcodec::mux::{MuxContext, Muxer};
use std::{
    convert::TryFrom,
    fs::{File, OpenOptions},
    path::PathBuf,
};
use self::webm_mux::WebmMux;

mod webm_mux;

#[cfg(all(test, target_os = "linux"))]
mod tests;

#[derive(Debug, Clone)]
pub struct RecorderContext {
    pub server: bool,
    pub id: String,
    pub dir: String,
    pub display_idx: usize,
    pub camera: bool,
}

#[derive(Debug, Clone)]
struct RecorderContext2 {
    filename: String,
    width: usize,
    height: usize,
    format: CodecFormat,
}

impl RecorderContext2 {
    fn set_filename(&mut self, ctx: &RecorderContext) -> ResultType<()> {
        if !PathBuf::from(&ctx.dir).exists() {
            std::fs::create_dir_all(&ctx.dir)?;
        }
        let file = if ctx.server { "incoming" } else { "outgoing" }.to_string()
            + "_"
            + &ctx.id
            + &chrono::Local::now().format("_%Y%m%d%H%M%S%3f_").to_string()
            + &format!(
                "{}{}_{}_",
                if ctx.camera { "camera" } else { "display" },
                ctx.display_idx,
                Uuid::new_v4().simple()
            )
            + &self.format.to_string().to_lowercase()
            + if self.format == CodecFormat::VP9 || self.format == CodecFormat::VP8 {
                ".webm"
            } else {
                ".mp4"
            };
        self.filename = PathBuf::from(&ctx.dir)
            .join(file)
            .to_string_lossy()
            .to_string();
        Ok(())
    }
}

unsafe impl Send for Recorder {}
unsafe impl Sync for Recorder {}

trait RecorderApi {
    fn new(ctx: &RecorderContext2) -> ResultType<Self>
    where
        Self: Sized;
    fn write_video(&mut self, frame: &EncodedVideoFrame) -> bool;
    fn finish(&mut self) -> ResultType<()>;
}

pub struct Recorder {
    inner: Option<Box<dyn RecorderApi>>,
    ctx: RecorderContext,
    ctx2: Option<RecorderContext2>,
    pts: Option<i64>,
    failed: bool,
}

impl Recorder {
    pub fn new(ctx: RecorderContext) -> ResultType<Self> {
        Ok(Self {
            inner: None,
            ctx,
            ctx2: None,
            pts: None,
            failed: false,
        })
    }

    fn start(&mut self, w: usize, h: usize, format: CodecFormat) -> ResultType<()> {
        if self.inner.is_some() {
            return Ok(());
        }
        let mut ctx2 = RecorderContext2 {
            width: w,
            height: h,
            format,
            filename: Default::default(),
        };
        ctx2.set_filename(&self.ctx)?;
        let inner: Box<dyn RecorderApi> = match format {
            CodecFormat::VP8 | CodecFormat::VP9 => {
                Box::new(WebmRecorder::new(&ctx2)?)
            }
            #[cfg(feature = "hwcodec")]
            _ => Box::new(HwRecorder::new(&ctx2)?),
            #[cfg(not(feature = "hwcodec"))]
            _ => bail!("unsupported codec type"),
        };
        self.inner = Some(inner);
        self.ctx2 = Some(ctx2);
        Ok(())
    }

    fn close_epoch(&mut self) -> ResultType<()> {
        let inner = self.inner.take();
        self.ctx2 = None;
        self.pts = None;
        if let Some(mut inner) = inner {
            inner.finish()?;
        }
        Ok(())
    }

    pub fn write_message(&mut self, msg: &Message, w: usize, h: usize) {
        if let Some(message::Union::VideoFrame(vf)) = &msg.union {
            if let Some(frame) = &vf.union {
                self.write_frame(frame, w, h).ok();
            }
        }
    }

    pub fn write_frame(
        &mut self,
        frame: &video_frame::Union,
        w: usize,
        h: usize,
    ) -> ResultType<()> {
        if self.failed {
            bail!("recording failed");
        }
        let format = CodecFormat::from(frame);
        let frames = match frame {
            video_frame::Union::Vp8s(frames) | video_frame::Union::Vp9s(frames) => &frames.frames,
            #[cfg(feature = "hwcodec")]
            video_frame::Union::H264s(frames) | video_frame::Union::H265s(frames) => &frames.frames,
            _ => bail!("unsupported frame type"),
        };
        for frame in frames {
            let changed = self.ctx2.as_ref().map_or(false, |ctx| {
                ctx.width != w || ctx.height != h || ctx.format != format
            });
            if changed || self.pts.map_or(false, |pts| frame.pts < pts) {
                if let Err(error) = self.close_epoch() {
                    self.failed = true;
                    log::error!("Failed to close recording epoch: {error:?}");
                    return Err(error);
                }
            }
            if self.pts.is_none() && !frame.key {
                continue;
            }
            if let Err(error) = self.start(w, h, format) {
                self.failed = true;
                log::error!("Failed to start recording: {error:?}");
                return Err(error);
            }
            let written = match self.inner.as_mut() {
                Some(recorder) => recorder.write_video(frame),
                None => false,
            };
            if !written {
                self.failed = true;
                self.inner = None;
                log::error!("Failed to write recording frame");
                bail!("Failed to write recording frame");
            }
            self.pts = Some(frame.pts);
        }
        Ok(())
    }
}

struct WebmRecorder {
    webm: Option<WebmMux<File>>,
    origin: Option<i64>,
}

impl RecorderApi for WebmRecorder {
    fn new(ctx2: &RecorderContext2) -> ResultType<Self> {
        let out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&ctx2.filename)?;
        let webm = WebmMux::new(out, ctx2)?;
        Ok(WebmRecorder {
            webm: Some(webm),
            origin: None,
        })
    }

    fn write_video(&mut self, frame: &EncodedVideoFrame) -> bool {
        let origin = match self.origin {
            Some(origin) => origin,
            None if frame.key => frame.pts,
            None => return false,
        };
        let timestamp = frame
            .pts
            .checked_sub(origin)
            .and_then(|delta| u64::try_from(delta).ok())
            .and_then(|delta| delta.checked_mul(1_000_000));
        let Some(timestamp) = timestamp else {
            return false;
        };
        let accepted = self.webm.as_mut().map_or(false, |webm| {
            webm.add_frame(&frame.data, timestamp, frame.key)
        });
        if accepted {
            self.origin = Some(origin);
        }
        accepted
    }

    fn finish(&mut self) -> ResultType<()> {
        if let Some(webm) = self.webm.take() {
            if !webm.finalize() {
                bail!("Failed to finalize WebM recording");
            }
        }
        Ok(())
    }
}

impl Drop for WebmRecorder {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            log::error!("{error:?}");
        }
    }
}

#[cfg(feature = "hwcodec")]
struct HwRecorder {
    muxer: Option<Muxer>,
    key: bool,
}

#[cfg(feature = "hwcodec")]
impl RecorderApi for HwRecorder {
    fn new(ctx2: &RecorderContext2) -> ResultType<Self> {
        let muxer = Muxer::new(MuxContext {
            filename: ctx2.filename.clone(),
            width: ctx2.width,
            height: ctx2.height,
            is265: ctx2.format == CodecFormat::H265,
            framerate: crate::hwcodec::DEFAULT_FPS as _,
        })
        .map_err(|_| anyhow!("Failed to create hardware muxer"))?;
        Ok(HwRecorder {
            muxer: Some(muxer),
            key: false,
        })
    }

    fn write_video(&mut self, frame: &EncodedVideoFrame) -> bool {
        if frame.key {
            self.key = true;
        }
        if self.key {
            self.muxer
                .as_mut()
                .map(|m| m.write_video(&frame.data, frame.key).is_ok())
                .unwrap_or_default()
        } else {
            false
        }
    }

    fn finish(&mut self) -> ResultType<()> {
        if let Some(mut muxer) = self.muxer.take() {
            muxer
                .write_tail()
                .map_err(|error| anyhow!("Failed to finalize hardware recording: {error}"))?;
        }
        Ok(())
    }
}

#[cfg(feature = "hwcodec")]
impl Drop for HwRecorder {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            log::error!("{error:?}");
        }
    }
}
