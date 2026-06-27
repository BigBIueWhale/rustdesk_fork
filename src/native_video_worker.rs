use hbb_common::{
    anyhow::{anyhow, bail},
    log,
    message_proto::{video_frame, Chroma, SupportedDecoding, VideoFrame},
    protobuf::Message as _,
    ResultType,
};
use scrap::{CodecFormat, ImageFormat, ImageRgb, ImageTexture};
use std::{
    io::{Read, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::mpsc::{self, RecvTimeoutError, SyncSender},
    time::Duration,
};

const WORKER_ARG: &str = "--native-video-worker";
const PROTOCOL_VERSION: u8 = 1;
const REQUEST_MAGIC: [u8; 4] = *b"RDVW";
const RESPONSE_MAGIC: [u8; 4] = *b"RDVR";
const OP_DECODE: u8 = 1;
const STATUS_DECODED: u8 = 0;
const STATUS_NO_FRAME: u8 = 1;
const STATUS_ERROR: u8 = 2;
const MAX_WORKER_FRAME_PROTO_BYTES: usize = 32 * 1024 * 1024;
const WORKER_DECODE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct NativeVideoDecoder {
    format: CodecFormat,
    backend: NativeVideoDecoderBackend,
}

enum NativeVideoDecoderBackend {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    Worker(WorkerVideoDecoder),
    Unavailable,
}

impl NativeVideoDecoder {
    pub fn new(format: CodecFormat, _luid: Option<i64>) -> Self {
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            match WorkerVideoDecoder::spawn(format) {
                Ok(worker) => {
                    return Self {
                        format,
                        backend: NativeVideoDecoderBackend::Worker(worker),
                    };
                }
                Err(err) => {
                    log::error!(
                        "native video worker unavailable for {format:?}; refusing in-process desktop decode: {err}"
                    );
                    return Self {
                        format,
                        backend: NativeVideoDecoderBackend::Unavailable,
                    };
                }
            }
        }

        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            log::warn!(
                "refusing in-process mobile video decode until a platform worker/service boundary exists"
            );
            Self {
                format,
                backend: NativeVideoDecoderBackend::Unavailable,
            }
        }
    }

    pub fn format(&self) -> CodecFormat {
        self.format
    }

    pub fn valid(&self) -> bool {
        match &self.backend {
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            NativeVideoDecoderBackend::Worker(worker) => worker.valid,
            NativeVideoDecoderBackend::Unavailable => false,
        }
    }

    pub fn supported_decodings(
        id_for_prefer: Option<&str>,
        use_texture_render: bool,
        luid: Option<i64>,
        mark_unsupported: &Vec<CodecFormat>,
    ) -> SupportedDecoding {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            let _ = (id_for_prefer, use_texture_render, luid, mark_unsupported);
            log::warn!(
                "refusing to advertise mobile video decoding until a platform worker/service boundary exists"
            );
            return SupportedDecoding::default();
        }

        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            let mut decoding = scrap::codec::Decoder::supported_decodings(
                id_for_prefer,
                use_texture_render,
                luid,
                mark_unsupported,
            );
            // The desktop worker boundary returns raw RGB over stdio. Process-local
            // hardware/VRAM decoder outputs are not transferable, so do not advertise
            // H.264/H.265 decode from the main process while this slice is active.
            decoding.ability_h264 = 0;
            decoding.ability_h265 = 0;
            decoding
        }
    }

    pub fn handle_video_frame(
        &mut self,
        frame: &video_frame::Union,
        rgb: &mut ImageRgb,
        texture: &mut ImageTexture,
        pixelbuffer: &mut bool,
        chroma: &mut Option<Chroma>,
    ) -> ResultType<bool> {
        match &mut self.backend {
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            NativeVideoDecoderBackend::Worker(worker) => {
                worker.decode(frame, rgb, pixelbuffer, chroma)
            }
            NativeVideoDecoderBackend::Unavailable => {
                let _ = texture;
                bail!(
                    "native video worker/platform worker unavailable; in-process decode is refused"
                )
            }
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn run_worker() -> ResultType<()> {
    hbb_common::native_worker_sandbox::enter_worker_process()?;
    worker_loop(std::io::stdin(), std::io::stdout())
}

pub fn worker_arg() -> &'static str {
    WORKER_ARG
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct WorkerVideoDecoder {
    child: Child,
    _process_guard: hbb_common::native_worker_sandbox::WorkerProcessGuard,
    io_tx: SyncSender<VideoWorkerIoRequest>,
    format: CodecFormat,
    valid: bool,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct VideoWorkerIoRequest {
    image_format: ImageFormat,
    align: usize,
    payload: Vec<u8>,
    reply: mpsc::Sender<ResultType<WorkerResponse>>,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl Drop for WorkerVideoDecoder {
    fn drop(&mut self) {
        self.kill_child();
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl WorkerVideoDecoder {
    fn kill_child(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn spawn(format: CodecFormat) -> ResultType<Self> {
        let exe = std::env::current_exe()
            .map_err(|e| anyhow!("failed to resolve current executable for video worker: {e}"))?;
        let mut command = Command::new(exe);
        command
            .arg(WORKER_ARG)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        hbb_common::native_worker_sandbox::apply_to_command(&mut command);
        let mut child = command
            .spawn()
            .map_err(|e| anyhow!("failed to spawn native video worker: {e}"))?;
        let process_guard =
            match hbb_common::native_worker_sandbox::apply_to_spawned_child(&mut child) {
                Ok(process_guard) => process_guard,
                Err(err) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(anyhow!("failed to constrain native video worker: {err}"));
                }
            };
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("native video worker stdin unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("native video worker stdout unavailable"))?;
        let io_tx = match spawn_worker_io_thread(stdin, stdout, format) {
            Ok(io_tx) => io_tx,
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(err);
            }
        };
        Ok(Self {
            child,
            _process_guard: process_guard,
            io_tx,
            format,
            valid: true,
        })
    }

    fn decode(
        &mut self,
        frame: &video_frame::Union,
        rgb: &mut ImageRgb,
        pixelbuffer: &mut bool,
        chroma: &mut Option<Chroma>,
    ) -> ResultType<bool> {
        if !self.valid {
            bail!("native video worker is no longer valid");
        }
        let mut vf = VideoFrame::new();
        vf.union = Some(frame.clone());
        let payload = vf
            .write_to_bytes()
            .map_err(|e| anyhow!("failed to serialize video frame for worker: {e}"))?;
        if payload.len() > MAX_WORKER_FRAME_PROTO_BYTES {
            bail!(
                "native video worker request too large: {} > {}",
                payload.len(),
                MAX_WORKER_FRAME_PROTO_BYTES
            );
        }

        let response = self.decode_with_timeout(rgb.fmt(), rgb.align(), payload)?;
        match response.status {
            STATUS_DECODED => {
                rgb.w = response.width;
                rgb.h = response.height;
                rgb.raw = response.raw;
                *pixelbuffer = true;
                *chroma = response.chroma;
                Ok(true)
            }
            STATUS_NO_FRAME => Ok(false),
            STATUS_ERROR => {
                self.valid = false;
                bail!("native video worker decode failed: {}", response.message)
            }
            status => {
                self.valid = false;
                bail!("native video worker returned unknown status {status}")
            }
        }
    }

    fn decode_with_timeout(
        &mut self,
        image_format: ImageFormat,
        align: usize,
        payload: Vec<u8>,
    ) -> ResultType<WorkerResponse> {
        let (tx, rx) = mpsc::channel();
        self.io_tx
            .send(VideoWorkerIoRequest {
                image_format,
                align,
                payload,
                reply: tx,
            })
            .map_err(|_| anyhow!("native video worker I/O thread unavailable"))?;

        match rx.recv_timeout(WORKER_DECODE_TIMEOUT) {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(err)) => {
                self.valid = false;
                self.kill_child();
                bail!("native video worker transport failed: {err}")
            }
            Err(RecvTimeoutError::Timeout) => {
                self.valid = false;
                self.kill_child();
                bail!(
                    "native video worker decode timed out after {:?}; killed child",
                    WORKER_DECODE_TIMEOUT
                )
            }
            Err(RecvTimeoutError::Disconnected) => {
                self.valid = false;
                self.kill_child();
                bail!("native video worker I/O thread exited without a response")
            }
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn spawn_worker_io_thread(
    mut stdin: ChildStdin,
    mut stdout: ChildStdout,
    format: CodecFormat,
) -> ResultType<SyncSender<VideoWorkerIoRequest>> {
    let (tx, rx) = mpsc::sync_channel::<VideoWorkerIoRequest>(1);
    std::thread::Builder::new()
        .name("rd-native-video-io".to_owned())
        .spawn(move || {
            while let Ok(request) = rx.recv() {
                let result = worker_round_trip(
                    &mut stdin,
                    &mut stdout,
                    format,
                    request.image_format,
                    request.align,
                    &request.payload,
                );
                let _ = request.reply.send(result);
            }
        })
        .map_err(|e| anyhow!("failed to spawn native video worker I/O thread: {e}"))?;
    Ok(tx)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct WorkerResponse {
    status: u8,
    width: usize,
    height: usize,
    chroma: Option<Chroma>,
    raw: Vec<u8>,
    message: String,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn worker_loop<R, W>(mut input: R, mut output: W) -> ResultType<()>
where
    R: Read,
    W: Write,
{
    let mut decoder = None;
    let mut decoder_format = CodecFormat::Unknown;
    loop {
        let request = match read_request(&mut input) {
            Ok(request) => request,
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => bail!("failed to read native video worker request: {err}"),
        };
        if request.version != PROTOCOL_VERSION {
            write_error(
                &mut output,
                "unsupported native video worker protocol version",
            )?;
            continue;
        }
        if request.op != OP_DECODE {
            write_error(&mut output, "unsupported native video worker operation")?;
            continue;
        }
        let result = decode_worker_request(
            &request,
            &mut decoder,
            &mut decoder_format,
            request.image_format,
            request.align,
        );
        match result {
            Ok(Some((rgb, chroma))) => write_decoded(&mut output, &rgb, chroma)?,
            Ok(None) => write_no_frame(&mut output)?,
            Err(err) => write_error(&mut output, &err.to_string())?,
        }
        output
            .flush()
            .map_err(|e| anyhow!("failed to flush native video worker response: {e}"))?;
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn decode_worker_request(
    request: &WorkerRequest,
    decoder: &mut Option<scrap::codec::Decoder>,
    decoder_format: &mut CodecFormat,
    image_format: ImageFormat,
    align: usize,
) -> ResultType<Option<(ImageRgb, Option<Chroma>)>> {
    let vf = VideoFrame::parse_from_bytes(&request.payload)
        .map_err(|e| anyhow!("failed to parse worker video frame protobuf: {e}"))?;
    let frame_format = CodecFormat::from(&vf);
    if frame_format == CodecFormat::Unknown {
        bail!("worker received unsupported video frame");
    }
    if !matches!(
        frame_format,
        CodecFormat::VP8 | CodecFormat::VP9 | CodecFormat::AV1
    ) {
        bail!("worker accepts only software VP8/VP9/AV1 video frames");
    }
    if request.format != frame_format {
        bail!(
            "worker request codec {:?} does not match frame codec {:?}",
            request.format,
            frame_format
        );
    }
    if decoder.is_none() || *decoder_format != frame_format {
        *decoder = Some(scrap::codec::Decoder::new(frame_format, None));
        *decoder_format = frame_format;
    }
    let Some(decoder) = decoder.as_mut() else {
        bail!("worker decoder unavailable");
    };
    let Some(frame) = vf.union.as_ref() else {
        bail!("worker video frame has no union");
    };
    let mut rgb = ImageRgb::new(image_format, align);
    let mut texture = ImageTexture::default();
    let mut pixelbuffer = true;
    let mut chroma = None;
    let decoded =
        decoder.handle_video_frame(frame, &mut rgb, &mut texture, &mut pixelbuffer, &mut chroma)?;
    if !pixelbuffer {
        bail!("worker video decode unexpectedly produced a process-local texture");
    }
    if decoded {
        Ok(Some((rgb, chroma)))
    } else {
        Ok(None)
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct WorkerRequest {
    version: u8,
    op: u8,
    format: CodecFormat,
    image_format: ImageFormat,
    align: usize,
    payload: Vec<u8>,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn read_request<R: Read>(reader: &mut R) -> std::io::Result<WorkerRequest> {
    let magic = read_array::<4, _>(reader)?;
    if magic != REQUEST_MAGIC {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad native video worker request magic",
        ));
    }
    let version = read_u8(reader)?;
    let op = read_u8(reader)?;
    let format = codec_from_u8(read_u8(reader)?)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad worker codec"))?;
    let image_format = image_format_from_u8(read_u8(reader)?).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "bad worker image format")
    })?;
    let align = read_u32(reader)? as usize;
    let len = read_u32(reader)? as usize;
    if len > MAX_WORKER_FRAME_PROTO_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "oversized native video worker request",
        ));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(WorkerRequest {
        version,
        op,
        format,
        image_format,
        align,
        payload,
    })
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn write_request<W: Write>(
    writer: &mut W,
    format: CodecFormat,
    image_format: ImageFormat,
    align: usize,
    payload: &[u8],
) -> ResultType<()> {
    writer.write_all(&REQUEST_MAGIC)?;
    writer.write_all(&[
        PROTOCOL_VERSION,
        OP_DECODE,
        codec_to_u8(format),
        image_format_to_u8(image_format),
    ])?;
    write_u32(
        writer,
        u32::try_from(align).map_err(|_| anyhow!("video worker align too large"))?,
    )?;
    write_u32(
        writer,
        u32::try_from(payload.len()).map_err(|_| anyhow!("video worker payload too large"))?,
    )?;
    writer.write_all(payload)?;
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn worker_round_trip<W: Write, R: Read>(
    writer: &mut W,
    reader: &mut R,
    format: CodecFormat,
    image_format: ImageFormat,
    align: usize,
    payload: &[u8],
) -> ResultType<WorkerResponse> {
    write_request(writer, format, image_format, align, payload)?;
    writer
        .flush()
        .map_err(|e| anyhow!("failed to flush native video worker request: {e}"))?;
    read_response(reader)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn read_response<R: Read>(reader: &mut R) -> ResultType<WorkerResponse> {
    let magic = read_array::<4, _>(reader)
        .map_err(|e| anyhow!("failed to read native video worker response magic: {e}"))?;
    if magic != RESPONSE_MAGIC {
        bail!("bad native video worker response magic");
    }
    let version = read_u8(reader)
        .map_err(|e| anyhow!("failed to read native video worker response version: {e}"))?;
    if version != PROTOCOL_VERSION {
        bail!("unsupported native video worker response version {version}");
    }
    let status = read_u8(reader)
        .map_err(|e| anyhow!("failed to read native video worker response status: {e}"))?;
    let chroma = chroma_from_u8(
        read_u8(reader).map_err(|e| anyhow!("failed to read native video worker chroma: {e}"))?,
    )?;
    let _reserved = read_u8(reader)
        .map_err(|e| anyhow!("failed to read native video worker reserved field: {e}"))?;
    let width = read_u32(reader)
        .map_err(|e| anyhow!("failed to read native video worker width: {e}"))?
        as usize;
    let height = read_u32(reader)
        .map_err(|e| anyhow!("failed to read native video worker height: {e}"))?
        as usize;
    let raw_len = read_u32(reader)
        .map_err(|e| anyhow!("failed to read native video worker raw length: {e}"))?
        as usize;
    let msg_len = read_u32(reader)
        .map_err(|e| anyhow!("failed to read native video worker message length: {e}"))?
        as usize;
    if raw_len > scrap::MAX_NATIVE_VIDEO_DECODED_BYTES {
        bail!(
            "native video worker response too large: {raw_len} > {}",
            scrap::MAX_NATIVE_VIDEO_DECODED_BYTES
        );
    }
    if msg_len > 64 * 1024 {
        bail!("native video worker error message too large");
    }
    let mut raw = vec![0u8; raw_len];
    reader
        .read_exact(&mut raw)
        .map_err(|e| anyhow!("failed to read native video worker raw frame: {e}"))?;
    let mut msg = vec![0u8; msg_len];
    reader
        .read_exact(&mut msg)
        .map_err(|e| anyhow!("failed to read native video worker message: {e}"))?;
    let message = String::from_utf8_lossy(&msg).into_owned();
    Ok(WorkerResponse {
        status,
        width,
        height,
        chroma,
        raw,
        message,
    })
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn write_decoded<W: Write>(
    writer: &mut W,
    rgb: &ImageRgb,
    chroma: Option<Chroma>,
) -> ResultType<()> {
    write_response_header(
        writer,
        STATUS_DECODED,
        chroma_to_u8(chroma),
        rgb.w,
        rgb.h,
        rgb.raw.len(),
        0,
    )?;
    writer.write_all(&rgb.raw)?;
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn write_no_frame<W: Write>(writer: &mut W) -> ResultType<()> {
    write_response_header(writer, STATUS_NO_FRAME, chroma_to_u8(None), 0, 0, 0, 0)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn write_error<W: Write>(writer: &mut W, message: &str) -> ResultType<()> {
    let bytes = message.as_bytes();
    let len = bytes.len().min(64 * 1024);
    write_response_header(writer, STATUS_ERROR, chroma_to_u8(None), 0, 0, 0, len)?;
    writer.write_all(&bytes[..len])?;
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn write_response_header<W: Write>(
    writer: &mut W,
    status: u8,
    chroma: u8,
    width: usize,
    height: usize,
    raw_len: usize,
    msg_len: usize,
) -> ResultType<()> {
    writer.write_all(&RESPONSE_MAGIC)?;
    writer.write_all(&[PROTOCOL_VERSION, status, chroma, 0])?;
    write_u32(
        writer,
        u32::try_from(width).map_err(|_| anyhow!("worker width too large"))?,
    )?;
    write_u32(
        writer,
        u32::try_from(height).map_err(|_| anyhow!("worker height too large"))?,
    )?;
    write_u32(
        writer,
        u32::try_from(raw_len).map_err(|_| anyhow!("worker raw response too large"))?,
    )?;
    write_u32(
        writer,
        u32::try_from(msg_len).map_err(|_| anyhow!("worker message response too large"))?,
    )?;
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn read_array<const N: usize, R: Read>(reader: &mut R) -> std::io::Result<[u8; N]> {
    let mut out = [0u8; N];
    reader.read_exact(&mut out)?;
    Ok(out)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn read_u8<R: Read>(reader: &mut R) -> std::io::Result<u8> {
    Ok(read_array::<1, _>(reader)?[0])
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn read_u32<R: Read>(reader: &mut R) -> std::io::Result<u32> {
    Ok(u32::from_le_bytes(read_array::<4, _>(reader)?))
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn write_u32<W: Write>(writer: &mut W, value: u32) -> std::io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn codec_to_u8(format: CodecFormat) -> u8 {
    match format {
        CodecFormat::VP8 => 1,
        CodecFormat::VP9 => 2,
        CodecFormat::AV1 => 3,
        CodecFormat::H264 => 4,
        CodecFormat::H265 => 5,
        CodecFormat::Unknown => 0,
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn codec_from_u8(value: u8) -> Option<CodecFormat> {
    Some(match value {
        0 => CodecFormat::Unknown,
        1 => CodecFormat::VP8,
        2 => CodecFormat::VP9,
        3 => CodecFormat::AV1,
        4 => CodecFormat::H264,
        5 => CodecFormat::H265,
        _ => return None,
    })
}

fn image_format_to_u8(format: ImageFormat) -> u8 {
    match format {
        ImageFormat::Raw => 0,
        ImageFormat::ABGR => 1,
        ImageFormat::ARGB => 2,
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn image_format_from_u8(value: u8) -> Option<ImageFormat> {
    Some(match value {
        0 => ImageFormat::Raw,
        1 => ImageFormat::ABGR,
        2 => ImageFormat::ARGB,
        _ => return None,
    })
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn chroma_to_u8(chroma: Option<Chroma>) -> u8 {
    match chroma {
        Some(Chroma::I420) => 1,
        Some(Chroma::I444) => 2,
        _ => 0,
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn chroma_from_u8(value: u8) -> ResultType<Option<Chroma>> {
    Ok(match value {
        0 => None,
        1 => Some(Chroma::I420),
        2 => Some(Chroma::I444),
        _ => bail!("bad native video worker chroma value {value}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_round_trip_is_stable() {
        for format in [
            CodecFormat::Unknown,
            CodecFormat::VP8,
            CodecFormat::VP9,
            CodecFormat::AV1,
            CodecFormat::H264,
            CodecFormat::H265,
        ] {
            assert_eq!(codec_from_u8(codec_to_u8(format)), Some(format));
        }
    }

    #[test]
    fn image_format_round_trip_is_stable() {
        for format in [ImageFormat::Raw, ImageFormat::ABGR, ImageFormat::ARGB] {
            let decoded = image_format_from_u8(image_format_to_u8(format)).unwrap();
            assert_eq!(image_format_to_u8(decoded), image_format_to_u8(format));
        }
    }

    #[test]
    fn chroma_round_trip_is_stable() {
        for chroma in [None, Some(Chroma::I420), Some(Chroma::I444)] {
            assert_eq!(chroma_from_u8(chroma_to_u8(chroma)).unwrap(), chroma);
        }
    }
}
