use super::{CodecFormat, RecorderContext2};
use hbb_common::{bail, log, ResultType};
use std::io::{Seek, Write};
use webm::mux::{self, Segment, Track, VideoTrack, Writer};

pub(super) struct WebmMux<T: Write + Seek> {
    track: VideoTrack,
    segment: Option<Segment<Writer<T>>>,
}

impl<T: Write + Seek> WebmMux<T> {
    pub(super) fn new(dest: T, ctx: &RecorderContext2) -> ResultType<Self> {
        let mut segment = match Segment::new(Writer::new(dest)) {
            Some(segment) => segment,
            None => bail!("Failed to create webm mux"),
        };
        let codec = match ctx.format {
            CodecFormat::VP8 => mux::VideoCodecId::VP8,
            CodecFormat::VP9 => mux::VideoCodecId::VP9,
            _ => mux::VideoCodecId::AV1,
        };
        let track = segment.add_video_track(ctx.width as _, ctx.height as _, None, codec);
        if ctx.format == CodecFormat::AV1 && !segment.set_codec_private(track.track_number(), &[0; 4]) {
            bail!("Failed to set codec private");
        }
        Ok(Self { track, segment: Some(segment) })
    }

    pub(super) fn add_frame(&mut self, data: &[u8], pts: u64, key: bool) -> bool {
        self.track.add_frame(data, pts, key)
    }

    fn finish(&mut self) -> bool {
        let Some(segment) = self.segment.take() else { return true; };
        let (writer, finalized) = match segment.try_finalize(None) {
            Ok(writer) => (writer, true),
            Err(writer) => (writer, false),
        };
        // This consuming API releases the native writer and returns its destination.
        drop(mux::Writer::unwrap(writer));
        finalized
    }

    pub(super) fn finalize(mut self) -> bool {
        self.finish()
    }
}

impl<T: Write + Seek> Drop for WebmMux<T> {
    fn drop(&mut self) {
        if self.segment.is_some() && !self.finish() {
            log::error!("Failed to finalize WebM recording");
        }
    }
}
