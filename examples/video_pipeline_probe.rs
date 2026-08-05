//! TEST-ONLY loopback video-pipeline probe. NOT shipped.
//!
//! This is deliberately narrower than a UI or device test. It proves that a real keyed Remote
//! session can receive frames produced by the controlled side's capture + software encode path,
//! acknowledge each exact `{display, generation}` before decoding (the production viewer order),
//! and decode those frames with `scrap::codec::Decoder`. It does not exercise Flutter/compositor
//! presentation, application focus, Android lifecycle, native Windows behavior, or an installed
//! service.
//!
//! The only admitted endpoint is exactly `127.0.0.1:21118`. The password is read from bounded
//! standard input so it never appears in the probe's process arguments.

use hbb_common::{
    anyhow::{anyhow, bail, Context},
    cpace::run_initiator,
    message_proto::{
        login_response, message, supported_decoding, video_frame, Chroma, LoginRequest, Message,
        OptionMessage, PeerInfo, VideoFrame, VideoFrameReceipt,
    },
    protobuf::Message as _,
    tcp::FramedStream,
    ResultType, VIDEO_FRAME_RECEIPT_VERSION,
};
use scrap::{
    codec::Decoder, CodecFormat, ImageFormat, ImageRgb, ImageTexture,
    MAX_NATIVE_VIDEO_DECODED_BYTES,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

const LOOPBACK_ENDPOINT: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 21_118);
const MAX_PASSWORD_BYTES: usize = 1_024;
const MAX_PEER_VIDEO_DISPLAYS: usize = 16;
const MAX_PEER_DISPLAY_DIMENSION: usize = 32_768;
const EXPECTED_WIDTH: usize = 640;
const EXPECTED_HEIGHT: usize = 480;
const MIN_DECODED_FRAMES: usize = 30;
const MIN_DISTINCT_FRAMES: usize = 10;
const MIN_PTS_SPAN_MS: i64 = 4_000;
const SESSION_DEADLINE: Duration = Duration::from_secs(25);
const NEXT_FRAME_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_FIRST_DECODE_LATENCY: Duration = Duration::from_secs(15);
const MAX_SINGLE_DECODE_LATENCY: Duration = Duration::from_secs(2);
const MAX_RECEIVE_BACKLOG_DRIFT_MS: i64 = 2_000;
const MAX_SESSION_MESSAGES: usize = 1_024;

struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        hbb_common::sodiumoxide::utils::memzero(&mut self.0);
    }
}

struct SensitiveString(String);

impl SensitiveString {
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for SensitiveString {
    fn drop(&mut self) {
        // Replacing every byte with zero preserves String's UTF-8 invariant. `as_mut_vec` is the
        // only unsafe operation and the buffer is neither resized nor exposed beyond this Drop.
        hbb_common::sodiumoxide::utils::memzero(unsafe { self.0.as_mut_vec() });
    }
}

#[derive(Default)]
struct ReceiptTracker {
    last_generation: HashMap<usize, u64>,
}

impl ReceiptTracker {
    fn admit(&mut self, frame: &VideoFrame) -> ResultType<VideoFrameReceipt> {
        let display = usize::try_from(frame.display)
            .map_err(|_| anyhow!("video frame display is negative"))?;
        if display >= MAX_PEER_VIDEO_DISPLAYS {
            bail!("video frame display is outside the bounded peer display set");
        }
        if frame.generation == 0 {
            bail!("video frame generation is zero");
        }
        if self
            .last_generation
            .get(&display)
            .map_or(false, |last| frame.generation <= *last)
        {
            bail!("video frame generation is not strictly monotonic");
        }
        self.last_generation.insert(display, frame.generation);
        Ok(VideoFrameReceipt {
            display: frame.display,
            generation: frame.generation,
            ..Default::default()
        })
    }
}

#[derive(Debug)]
struct PipelineMetrics {
    codec: CodecFormat,
    decoded_frames: usize,
    distinct_frames: usize,
    receipts: usize,
    first_decode_ms: u128,
    pts_span_ms: i64,
    max_decode_us: u128,
    mean_decode_us: u128,
    max_receive_backlog_drift_ms: i64,
}

fn validate_endpoint(raw: &str) -> ResultType<SocketAddr> {
    let endpoint = raw
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid socket address: {raw:?}"))?;
    if endpoint != LOOPBACK_ENDPOINT {
        bail!("probe refuses every endpoint except {LOOPBACK_ENDPOINT}");
    }
    Ok(endpoint)
}

fn read_password() -> ResultType<SensitiveBytes> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_PASSWORD_BYTES + 2) as u64)
        .read_to_end(&mut bytes)
        .context("failed to read the password from standard input")?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    if bytes.is_empty() {
        bail!("password input is empty");
    }
    if bytes.len() > MAX_PASSWORD_BYTES {
        bail!("password input exceeds the bounded length");
    }
    if bytes.iter().any(|byte| matches!(byte, b'\0' | b'\r' | b'\n')) {
        bail!("password input contains an embedded terminator");
    }
    std::str::from_utf8(&bytes).context("password input is not valid UTF-8")?;
    Ok(SensitiveBytes(bytes))
}

fn validate_peer_info(peer: &PeerInfo) -> ResultType<()> {
    if peer.video_frame_receipt_version != VIDEO_FRAME_RECEIPT_VERSION {
        bail!(
            "controlled peer selected video receipt version {}, expected {}",
            peer.video_frame_receipt_version,
            VIDEO_FRAME_RECEIPT_VERSION
        );
    }
    if peer.displays.is_empty() || peer.displays.len() > MAX_PEER_VIDEO_DISPLAYS {
        bail!("controlled peer reported an invalid display count");
    }
    let current_display = usize::try_from(peer.current_display)
        .map_err(|_| anyhow!("controlled peer reported a negative current display"))?;
    let display = peer
        .displays
        .get(current_display)
        .ok_or_else(|| anyhow!("controlled peer current display is outside its display list"))?;
    let width = usize::try_from(display.width)
        .map_err(|_| anyhow!("controlled peer reported a negative display width"))?;
    let height = usize::try_from(display.height)
        .map_err(|_| anyhow!("controlled peer reported a negative display height"))?;
    if width == 0
        || height == 0
        || width > MAX_PEER_DISPLAY_DIMENSION
        || height > MAX_PEER_DISPLAY_DIMENSION
    {
        bail!("controlled peer reported out-of-bounds display dimensions");
    }
    if current_display != 0 || (width, height) != (EXPECTED_WIDTH, EXPECTED_HEIGHT) {
        bail!(
            "controlled peer reported display #{current_display} at {width}x{height}, expected #0 at {EXPECTED_WIDTH}x{EXPECTED_HEIGHT}"
        );
    }
    Ok(())
}

fn encoded_frame_pts(frame: &VideoFrame) -> ResultType<(CodecFormat, i64, bool)> {
    let (format, frames) = match frame.union.as_ref() {
        Some(video_frame::Union::Vp8s(frames)) => (CodecFormat::VP8, frames),
        Some(video_frame::Union::Vp9s(frames)) => (CodecFormat::VP9, frames),
        Some(_) => bail!("controlled peer selected a codec outside the software VP8/VP9 policy"),
        None => bail!("controlled peer sent a video frame without an encoded payload"),
    };
    let mut previous_pts = None;
    let mut contains_keyframe = false;
    for encoded in &frames.frames {
        if encoded.data.is_empty() {
            bail!("controlled peer sent an empty encoded frame");
        }
        if encoded.pts < 0 || previous_pts.map_or(false, |pts| encoded.pts < pts) {
            bail!("controlled peer sent invalid or decreasing frame PTS values");
        }
        previous_pts = Some(encoded.pts);
        contains_keyframe |= encoded.key;
    }
    let pts = previous_pts.ok_or_else(|| anyhow!("controlled peer sent an empty encoded batch"))?;
    Ok((format, pts, contains_keyframe))
}

fn decoded_image_bytes(rgb: &ImageRgb) -> ResultType<usize> {
    if rgb.w == 0
        || rgb.h == 0
        || rgb.w > MAX_PEER_DISPLAY_DIMENSION
        || rgb.h > MAX_PEER_DISPLAY_DIMENSION
    {
        bail!("decoder produced out-of-bounds dimensions");
    }
    if (rgb.w, rgb.h) != (EXPECTED_WIDTH, EXPECTED_HEIGHT) {
        bail!(
            "decoder produced {}x{}, expected {}x{}",
            rgb.w,
            rgb.h,
            EXPECTED_WIDTH,
            EXPECTED_HEIGHT
        );
    }
    let expected = rgb
        .w
        .checked_mul(rgb.h)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or_else(|| anyhow!("decoded image byte length overflowed"))?;
    if expected > MAX_NATIVE_VIDEO_DECODED_BYTES || rgb.raw.len() != expected {
        bail!(
            "decoder produced an invalid RGB buffer length: got {}, expected {expected}",
            rgb.raw.len()
        );
    }
    Ok(expected)
}

fn make_login(endpoint: SocketAddr) -> ResultType<Message> {
    let mut supported = Decoder::supported_decodings(None, false, None, &Vec::new());
    if supported.ability_vp8 != 1
        || supported.ability_vp9 != 1
        || supported.ability_av1 != 0
        || supported.ability_h264 != 0
        || supported.ability_h265 != 0
    {
        bail!("probe build does not expose the exact software VP8/VP9 decoding policy");
    }
    supported.prefer = supported_decoding::PreferCodec::VP9.into();
    let option = OptionMessage {
        custom_fps: 30,
        supported_decoding: Some(supported).into(),
        ..Default::default()
    };
    let login = LoginRequest {
        username: endpoint.to_string(),
        my_id: "video-pipeline-probe".to_owned(),
        my_name: "video-pipeline-probe".to_owned(),
        option: Some(option).into(),
        version: librustdesk::VERSION.to_owned(),
        my_platform: "Linux".to_owned(),
        video_frame_receipt_version: VIDEO_FRAME_RECEIPT_VERSION,
        ..Default::default()
    };
    let mut message = Message::new();
    message.set_login_request(login);
    Ok(message)
}

async fn run_pipeline(endpoint: SocketAddr, prs: &str) -> ResultType<PipelineMetrics> {
    let started = Instant::now();
    let mut stream = FramedStream::new(&endpoint.to_string(), None, 5_000)
        .await
        .context("failed to connect to the loopback RustDesk server")?;
    let keys = run_initiator(&mut stream, prs)
        .await
        .map_err(|error| anyhow!("CPace key confirmation failed: {error:?}"))?;
    stream.set_session_keys(keys);
    stream
        .send(&make_login(endpoint)?)
        .await
        .context("failed to send the keyed Remote login")?;

    let deadline = started + SESSION_DEADLINE;
    let mut peer_admitted = false;
    let mut decoder: Option<Decoder> = None;
    let mut decoder_format = CodecFormat::Unknown;
    let mut rgb = ImageRgb::new(ImageFormat::ABGR, 1);
    let mut texture = ImageTexture::default();
    let mut pixelbuffer = true;
    let mut chroma: Option<Chroma> = None;
    let mut receipts = ReceiptTracker::default();
    let mut receipt_count = 0usize;
    let mut decoded_frames = 0usize;
    let mut distinct_frames = HashSet::new();
    let mut first_received_at: Option<Instant> = None;
    let mut first_pts: Option<i64> = None;
    let mut last_pts: Option<i64> = None;
    let mut first_decode_ms = None;
    let mut total_decode_us = 0u128;
    let mut max_decode_us = 0u128;
    let mut max_receive_backlog_drift_ms = 0i64;
    let mut first_batch_had_keyframe = false;

    for message_index in 0..MAX_SESSION_MESSAGES {
        let now = Instant::now();
        if now >= deadline {
            bail!("video pipeline exceeded its finite session deadline");
        }
        let timeout = NEXT_FRAME_TIMEOUT.min(deadline.saturating_duration_since(now));
        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX).max(1);
        let bytes = match stream.next_timeout(timeout_ms).await {
            Some(Ok(bytes)) => bytes,
            Some(Err(error)) => return Err(error).context("keyed video stream failed"),
            None => bail!("video pipeline made no progress before its receive timeout"),
        };
        let message = Message::parse_from_bytes(&bytes)
            .with_context(|| format!("malformed keyed message at index {message_index}"))?;
        match message.union {
            Some(message::Union::TestDelay(_)) => {
                // The production direct-login path does not need a latency-probe response to
                // authorize. Never inject a response outside the real viewer protocol flow.
            }
            Some(message::Union::LoginResponse(response)) => match response.union {
                Some(login_response::Union::PeerInfo(peer)) => {
                    if peer_admitted {
                        bail!("controlled peer sent duplicate Remote admission");
                    }
                    validate_peer_info(&peer)?;
                    peer_admitted = true;
                }
                Some(login_response::Union::Error(error)) => {
                    bail!("controlled peer rejected the graphical Remote login: {error}");
                }
                Some(_) => bail!("controlled peer sent an unsupported login response variant"),
                None => bail!("controlled peer sent an empty login response"),
            },
            Some(message::Union::VideoFrame(frame)) => {
                if !peer_admitted {
                    bail!("controlled peer sent video before exact Remote admission");
                }
                if frame.display != 0 {
                    bail!("controlled peer sent the single-display fixture as display {}", frame.display);
                }
                let receipt = receipts.admit(&frame)?;
                let mut receipt_message = Message::new();
                receipt_message.set_video_frame_receipt(receipt);
                stream
                    .send(&receipt_message)
                    .await
                    .context("failed to acknowledge the exact video generation")?;
                receipt_count += 1;

                let received_at = Instant::now();
                let (format, pts, contains_keyframe) = encoded_frame_pts(&frame)?;
                if let Some(last) = last_pts {
                    if pts < last {
                        bail!("controlled peer regressed video PTS across batches");
                    }
                }
                last_pts = Some(pts);
                if first_pts.is_none() {
                    first_pts = Some(pts);
                    first_received_at = Some(received_at);
                    first_batch_had_keyframe = contains_keyframe;
                }
                if decoder.is_none() {
                    let candidate = Decoder::new(format, None);
                    if !candidate.valid() {
                        bail!("real software decoder failed to initialize for {format:?}");
                    }
                    decoder_format = format;
                    decoder = Some(candidate);
                } else if format != decoder_format {
                    bail!("controlled peer changed codec from {decoder_format:?} to {format:?}");
                }

                let decode_started = Instant::now();
                let decoded = decoder
                    .as_mut()
                    .ok_or_else(|| anyhow!("decoder ownership disappeared"))?
                    .handle_video_frame(
                        frame
                            .union
                            .as_ref()
                            .ok_or_else(|| anyhow!("video payload disappeared before decode"))?,
                        &mut rgb,
                        &mut texture,
                        &mut pixelbuffer,
                        &mut chroma,
                    )
                    .context("real software decoder rejected the encoded frame")?;
                let decode_elapsed = decode_started.elapsed();
                if decode_elapsed > MAX_SINGLE_DECODE_LATENCY {
                    bail!("one software decode exceeded the finite latency budget");
                }
                if decoded {
                    if !pixelbuffer {
                        bail!("software-only probe unexpectedly selected texture decode output");
                    }
                    decoded_image_bytes(&rgb)?;
                    let digest: [u8; 32] = Sha256::digest(&rgb.raw).into();
                    distinct_frames.insert(digest);
                    decoded_frames += 1;
                    let decode_us = decode_elapsed.as_micros();
                    total_decode_us = total_decode_us.saturating_add(decode_us);
                    max_decode_us = max_decode_us.max(decode_us);
                    first_decode_ms.get_or_insert_with(|| started.elapsed().as_millis());

                    let base_pts = first_pts.ok_or_else(|| anyhow!("first PTS ownership disappeared"))?;
                    let base_received = first_received_at
                        .ok_or_else(|| anyhow!("first receive timestamp ownership disappeared"))?;
                    let pts_span = pts
                        .checked_sub(base_pts)
                        .ok_or_else(|| anyhow!("video PTS span underflowed"))?;
                    let receive_span = i64::try_from(received_at.duration_since(base_received).as_millis())
                        .map_err(|_| anyhow!("video receive duration is not representable"))?;
                    max_receive_backlog_drift_ms =
                        max_receive_backlog_drift_ms.max(receive_span.saturating_sub(pts_span));

                    if decoded_frames >= MIN_DECODED_FRAMES
                        && distinct_frames.len() >= MIN_DISTINCT_FRAMES
                        && pts_span >= MIN_PTS_SPAN_MS
                    {
                        break;
                    }
                }
            }
            Some(_) => {}
            None => bail!("controlled peer sent an empty keyed message"),
        }
    }

    let first_decode_ms = first_decode_ms.ok_or_else(|| anyhow!("no frame decoded"))?;
    let first_pts = first_pts.ok_or_else(|| anyhow!("no encoded PTS observed"))?;
    let last_pts = last_pts.ok_or_else(|| anyhow!("no final encoded PTS observed"))?;
    let pts_span_ms = last_pts
        .checked_sub(first_pts)
        .ok_or_else(|| anyhow!("final video PTS span underflowed"))?;
    if !peer_admitted {
        bail!("no exact Remote PeerInfo admission was observed");
    }
    if !first_batch_had_keyframe {
        bail!("first encoded video batch did not establish a keyframe");
    }
    if decoded_frames < MIN_DECODED_FRAMES {
        bail!("decoded only {decoded_frames} frames, expected at least {MIN_DECODED_FRAMES}");
    }
    if distinct_frames.len() < MIN_DISTINCT_FRAMES {
        bail!(
            "decoded only {} visibly distinct frames, expected at least {MIN_DISTINCT_FRAMES}",
            distinct_frames.len()
        );
    }
    if pts_span_ms < MIN_PTS_SPAN_MS {
        bail!("decoded PTS span was only {pts_span_ms}ms, expected at least {MIN_PTS_SPAN_MS}ms");
    }
    if receipt_count == 0 {
        bail!("no exact video receipt was sent");
    }
    if receipt_count < decoded_frames {
        bail!("fewer exact receipts were sent than frames were decoded");
    }
    if Duration::from_millis(u64::try_from(first_decode_ms).unwrap_or(u64::MAX))
        > MAX_FIRST_DECODE_LATENCY
    {
        bail!("first decoded frame exceeded the finite startup latency budget");
    }
    if max_receive_backlog_drift_ms > MAX_RECEIVE_BACKLOG_DRIFT_MS {
        bail!(
            "receive backlog drift reached {max_receive_backlog_drift_ms}ms, exceeding {MAX_RECEIVE_BACKLOG_DRIFT_MS}ms"
        );
    }

    Ok(PipelineMetrics {
        codec: decoder_format,
        decoded_frames,
        distinct_frames: distinct_frames.len(),
        receipts: receipt_count,
        first_decode_ms,
        pts_span_ms,
        max_decode_us,
        mean_decode_us: total_decode_us / decoded_frames as u128,
        max_receive_backlog_drift_ms,
    })
}

fn run() -> ResultType<PipelineMetrics> {
    let mut args = std::env::args();
    let _program = args.next();
    let raw_endpoint = args
        .next()
        .ok_or_else(|| anyhow!("usage: video_pipeline_probe 127.0.0.1:21118 < password"))?;
    if args.next().is_some() {
        bail!("video pipeline probe accepts exactly one endpoint argument");
    }
    let endpoint = validate_endpoint(&raw_endpoint)?;
    let password = read_password()?;
    let password_text = std::str::from_utf8(password.as_slice())
        .context("validated password unexpectedly became invalid UTF-8")?;
    let prs = SensitiveString(
        hbb_common::config::derive_cpace_prs(password_text)
            .context("failed to derive the CPace password-related string")?,
    );
    drop(password);

    let runtime = hbb_common::tokio::runtime::Runtime::new()
        .context("failed to create the test-only Tokio runtime")?;
    runtime.block_on(run_pipeline(endpoint, prs.as_str()))
}

fn main() {
    match run() {
        Ok(metrics) => println!(
            "VIDEO_PIPELINE_OK codec={:?} dimensions={}x{} frames={} distinct={} receipts={} first_decode_ms={} pts_span_ms={} max_decode_us={} mean_decode_us={} max_receive_backlog_drift_ms={}",
            metrics.codec,
            EXPECTED_WIDTH,
            EXPECTED_HEIGHT,
            metrics.decoded_frames,
            metrics.distinct_frames,
            metrics.receipts,
            metrics.first_decode_ms,
            metrics.pts_span_ms,
            metrics.max_decode_us,
            metrics.mean_decode_us,
            metrics.max_receive_backlog_drift_ms,
        ),
        Err(error) => {
            eprintln!("VIDEO_PIPELINE_FAIL: {error:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::message_proto::{EncodedVideoFrame, EncodedVideoFrames};

    fn video_frame(display: i32, generation: u64, pts: i64) -> VideoFrame {
        let mut frame = VideoFrame {
            display,
            generation,
            ..Default::default()
        };
        frame.set_vp9s(EncodedVideoFrames {
            frames: vec![EncodedVideoFrame {
                data: vec![1, 2, 3].into(),
                key: true,
                pts,
                ..Default::default()
            }],
            ..Default::default()
        });
        frame
    }

    #[test]
    fn endpoint_is_exact_ipv4_loopback_and_port() {
        assert_eq!(
            validate_endpoint("127.0.0.1:21118").ok(),
            Some(LOOPBACK_ENDPOINT)
        );
        for rejected in [
            "0.0.0.0:21118",
            "127.0.0.2:21118",
            "[::1]:21118",
            "127.0.0.1:21119",
            "example.com:21118",
        ] {
            assert!(validate_endpoint(rejected).is_err(), "accepted {rejected}");
        }
    }

    #[test]
    fn receipt_tracker_requires_bounded_strict_generation_identity() {
        let mut tracker = ReceiptTracker::default();
        let first = video_frame(0, 7, 0);
        let receipt = tracker.admit(&first).expect("first identity is valid");
        assert_eq!((receipt.display, receipt.generation), (0, 7));
        assert!(tracker.admit(&first).is_err());
        assert!(tracker.admit(&video_frame(0, 6, 1)).is_err());
        assert!(tracker.admit(&video_frame(-1, 8, 1)).is_err());
        assert!(tracker
            .admit(&video_frame(MAX_PEER_VIDEO_DISPLAYS as i32, 8, 1))
            .is_err());
        assert!(tracker.admit(&video_frame(1, 0, 1)).is_err());
        assert!(tracker.admit(&video_frame(1, 1, 1)).is_ok());
    }

    #[test]
    fn encoded_metadata_rejects_empty_and_decreasing_batches() {
        assert_eq!(
            encoded_frame_pts(&video_frame(0, 1, 9)).ok(),
            Some((CodecFormat::VP9, 9, true))
        );

        let mut empty = video_frame(0, 1, 9);
        empty.mut_vp9s().frames.clear();
        assert!(encoded_frame_pts(&empty).is_err());

        let mut decreasing = video_frame(0, 1, 9);
        decreasing.mut_vp9s().frames.push(EncodedVideoFrame {
            data: vec![4].into(),
            pts: 8,
            ..Default::default()
        });
        assert!(encoded_frame_pts(&decreasing).is_err());
    }

    #[test]
    fn decoded_rgb_contract_is_exact_and_bounded() {
        let mut rgb = ImageRgb::new(ImageFormat::ABGR, 1);
        rgb.w = EXPECTED_WIDTH;
        rgb.h = EXPECTED_HEIGHT;
        rgb.raw = vec![0; EXPECTED_WIDTH * EXPECTED_HEIGHT * 4];
        assert_eq!(decoded_image_bytes(&rgb).ok(), Some(rgb.raw.len()));
        rgb.raw.pop();
        assert!(decoded_image_bytes(&rgb).is_err());
    }
}
