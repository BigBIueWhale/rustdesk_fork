use hbb_common::{
    anyhow::{anyhow, bail},
    ResultType,
};
use magnum_opus::{Channels, Decoder as OpusDecoder};
use std::{
    io::{Read, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::mpsc::{self, RecvTimeoutError, SyncSender},
    time::Duration,
};

const WORKER_ARG: &str = "--native-opus-worker";
const PROTOCOL_VERSION: u8 = 1;
const REQUEST_MAGIC: [u8; 4] = *b"RDAW";
const RESPONSE_MAGIC: [u8; 4] = *b"RDAR";
const OP_DECODE: u8 = 1;
const STATUS_DECODED: u8 = 0;
const STATUS_ERROR: u8 = 1;
pub(crate) const MAX_OPUS_PACKET_BYTES: usize = 4096;
const MAX_OPUS_ERROR_BYTES: usize = 64 * 1024;
const WORKER_DECODE_TIMEOUT: Duration = Duration::from_secs(3);

pub struct NativeOpusDecoder {
    backend: NativeOpusDecoderBackend,
}

enum NativeOpusDecoderBackend {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    Worker(WorkerOpusDecoder),
    Unavailable,
}

impl NativeOpusDecoder {
    pub fn new(sample_rate: u32, channels: u32) -> ResultType<Self> {
        validate_format(sample_rate, channels)?;
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            match WorkerOpusDecoder::spawn(sample_rate, channels) {
                Ok(worker) => {
                    return Ok(Self {
                        backend: NativeOpusDecoderBackend::Worker(worker),
                    });
                }
                Err(err) => {
                    bail!(
                        "native Opus worker unavailable; refusing in-process desktop decode: {err}"
                    );
                }
            }
        }

        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            bail!(
                "refusing in-process mobile Opus decode until a platform worker/service boundary exists"
            );
        }
    }

    pub fn decode_float(
        &mut self,
        data: &[u8],
        output: &mut [f32],
        decode_fec: bool,
    ) -> ResultType<usize> {
        if data.len() > MAX_OPUS_PACKET_BYTES {
            bail!(
                "native Opus worker request too large: {} > {}",
                data.len(),
                MAX_OPUS_PACKET_BYTES
            );
        }
        match &mut self.backend {
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            NativeOpusDecoderBackend::Worker(worker) => {
                worker.decode_float(data, output, decode_fec)
            }
            NativeOpusDecoderBackend::Unavailable => {
                bail!(
                    "native Opus worker/platform worker unavailable; in-process decode is refused"
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
struct WorkerOpusDecoder {
    child: Child,
    _process_guard: hbb_common::native_worker_sandbox::WorkerProcessGuard,
    io_tx: SyncSender<OpusWorkerIoRequest>,
    sample_rate: u32,
    channels: u32,
    valid: bool,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct OpusWorkerIoRequest {
    payload: Vec<u8>,
    decode_fec: bool,
    reply: mpsc::Sender<ResultType<WorkerResponse>>,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl Drop for WorkerOpusDecoder {
    fn drop(&mut self) {
        self.kill_child();
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl WorkerOpusDecoder {
    fn kill_child(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn invalidate_and_kill(&mut self) {
        self.valid = false;
        self.kill_child();
    }

    fn spawn(sample_rate: u32, channels: u32) -> ResultType<Self> {
        let exe = std::env::current_exe()
            .map_err(|e| anyhow!("failed to resolve current executable for Opus worker: {e}"))?;
        let mut command = Command::new(exe);
        command
            .arg(WORKER_ARG)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        hbb_common::native_worker_sandbox::apply_to_command(&mut command);
        let mut child = command
            .spawn()
            .map_err(|e| anyhow!("failed to spawn native Opus worker: {e}"))?;
        let process_guard =
            match hbb_common::native_worker_sandbox::apply_to_spawned_child(&mut child) {
                Ok(process_guard) => process_guard,
                Err(err) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(anyhow!("failed to constrain native Opus worker: {err}"));
                }
            };
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("native Opus worker stdin unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("native Opus worker stdout unavailable"))?;
        let io_tx = match spawn_worker_io_thread(stdin, stdout, sample_rate, channels) {
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
            sample_rate,
            channels,
            valid: true,
        })
    }

    fn decode_float(
        &mut self,
        data: &[u8],
        output: &mut [f32],
        decode_fec: bool,
    ) -> ResultType<usize> {
        if !self.valid {
            bail!("native Opus worker is no longer valid");
        }
        let response = self.decode_with_timeout(data.to_vec(), decode_fec)?;
        match response.status {
            STATUS_DECODED => {
                if response.pcm.len() > output.len() {
                    self.invalidate_and_kill();
                    bail!(
                        "native Opus worker response does not fit output buffer; killed child: {} > {}",
                        response.pcm.len(),
                        output.len()
                    );
                }
                output[..response.pcm.len()].copy_from_slice(&response.pcm);
                Ok(response.samples_per_channel)
            }
            STATUS_ERROR => {
                self.invalidate_and_kill();
                bail!(
                    "native Opus worker decode failed; killed child: {}",
                    response.message
                )
            }
            status => {
                self.invalidate_and_kill();
                bail!("native Opus worker returned unknown status {status}; killed child")
            }
        }
    }

    fn decode_with_timeout(
        &mut self,
        payload: Vec<u8>,
        decode_fec: bool,
    ) -> ResultType<WorkerResponse> {
        let (tx, rx) = mpsc::channel();
        self.io_tx
            .send(OpusWorkerIoRequest {
                payload,
                decode_fec,
                reply: tx,
            })
            .map_err(|_| anyhow!("native Opus worker I/O thread unavailable"))?;

        match rx.recv_timeout(WORKER_DECODE_TIMEOUT) {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(err)) => {
                self.invalidate_and_kill();
                bail!("native Opus worker transport failed: {err}")
            }
            Err(RecvTimeoutError::Timeout) => {
                self.invalidate_and_kill();
                bail!(
                    "native Opus worker decode timed out after {:?}; killed child",
                    WORKER_DECODE_TIMEOUT
                )
            }
            Err(RecvTimeoutError::Disconnected) => {
                self.invalidate_and_kill();
                bail!("native Opus worker I/O thread exited without a response")
            }
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn spawn_worker_io_thread(
    mut stdin: ChildStdin,
    mut stdout: ChildStdout,
    sample_rate: u32,
    channels: u32,
) -> ResultType<SyncSender<OpusWorkerIoRequest>> {
    let (tx, rx) = mpsc::sync_channel::<OpusWorkerIoRequest>(1);
    std::thread::Builder::new()
        .name("rd-native-opus-io".to_owned())
        .spawn(move || {
            while let Ok(request) = rx.recv() {
                let result = worker_round_trip(
                    &mut stdin,
                    &mut stdout,
                    sample_rate,
                    channels,
                    request.decode_fec,
                    &request.payload,
                );
                let _ = request.reply.send(result);
            }
        })
        .map_err(|e| anyhow!("failed to spawn native Opus worker I/O thread: {e}"))?;
    Ok(tx)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct WorkerRequest {
    sample_rate: u32,
    channels: u32,
    decode_fec: bool,
    payload: Vec<u8>,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct WorkerResponse {
    status: u8,
    sample_rate: u32,
    channels: u32,
    samples_per_channel: usize,
    pcm: Vec<f32>,
    message: String,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn worker_loop<R, W>(mut input: R, mut output: W) -> ResultType<()>
where
    R: Read,
    W: Write,
{
    let mut decoder = None;
    let mut decoder_format = (0, 0);
    loop {
        let request = match read_request(&mut input) {
            Ok(request) => request,
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => bail!("failed to read native Opus worker request: {err}"),
        };
        let result = decode_worker_request(&request, &mut decoder, &mut decoder_format);
        match result {
            Ok(response) => write_decoded(&mut output, &response)?,
            Err(err) => write_error(
                &mut output,
                request.sample_rate,
                request.channels,
                &err.to_string(),
            )?,
        }
        output
            .flush()
            .map_err(|e| anyhow!("failed to flush native Opus worker response: {e}"))?;
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn decode_worker_request(
    request: &WorkerRequest,
    decoder: &mut Option<OpusDecoder>,
    decoder_format: &mut (u32, u32),
) -> ResultType<WorkerResponse> {
    validate_format(request.sample_rate, request.channels)?;
    if request.payload.len() > MAX_OPUS_PACKET_BYTES {
        bail!("oversized native Opus worker request");
    }
    if decoder.is_none() || *decoder_format != (request.sample_rate, request.channels) {
        *decoder = Some(OpusDecoder::new(
            request.sample_rate,
            channels_to_opus(request.channels)?,
        )?);
        *decoder_format = (request.sample_rate, request.channels);
    }
    let Some(decoder) = decoder.as_mut() else {
        bail!("native Opus decoder unavailable");
    };
    let channels = request.channels as usize;
    let mut buffer = vec![0.0; max_pcm_float_count(request.sample_rate, request.channels)?];
    let samples_per_channel = decoder
        .decode_float(&request.payload, &mut buffer, request.decode_fec)
        .map_err(|e| anyhow!("Opus decode failed in worker: {e}"))?;
    let float_count = samples_per_channel
        .checked_mul(channels)
        .ok_or_else(|| anyhow!("native Opus sample count overflow"))?;
    if float_count > buffer.len() {
        bail!(
            "native Opus decoder produced too many samples: {} > {}",
            float_count,
            buffer.len()
        );
    }
    buffer.truncate(float_count);
    Ok(WorkerResponse {
        status: STATUS_DECODED,
        sample_rate: request.sample_rate,
        channels: request.channels,
        samples_per_channel,
        pcm: buffer,
        message: String::new(),
    })
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn read_request<R: Read>(reader: &mut R) -> std::io::Result<WorkerRequest> {
    let magic = read_array::<4, _>(reader)?;
    if magic != REQUEST_MAGIC {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad native Opus worker request magic",
        ));
    }
    let version = read_u8(reader)?;
    if version != PROTOCOL_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported native Opus worker protocol version",
        ));
    }
    let op = read_u8(reader)?;
    if op != OP_DECODE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported native Opus worker operation",
        ));
    }
    let decode_fec = read_u8(reader)? != 0;
    let channels = read_u8(reader)? as u32;
    let sample_rate = read_u32(reader)?;
    let len = read_u32(reader)? as usize;
    if len > MAX_OPUS_PACKET_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "oversized native Opus worker request",
        ));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(WorkerRequest {
        sample_rate,
        channels,
        decode_fec,
        payload,
    })
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn write_request<W: Write>(
    writer: &mut W,
    sample_rate: u32,
    channels: u32,
    decode_fec: bool,
    payload: &[u8],
) -> ResultType<()> {
    if payload.len() > MAX_OPUS_PACKET_BYTES {
        bail!(
            "native Opus worker request too large: {} > {}",
            payload.len(),
            MAX_OPUS_PACKET_BYTES
        );
    }
    writer.write_all(&REQUEST_MAGIC)?;
    writer.write_all(&[
        PROTOCOL_VERSION,
        OP_DECODE,
        u8::from(decode_fec),
        u8::try_from(channels).map_err(|_| anyhow!("native Opus channel count too large"))?,
    ])?;
    write_u32(writer, sample_rate)?;
    write_u32(
        writer,
        u32::try_from(payload.len()).map_err(|_| anyhow!("native Opus payload too large"))?,
    )?;
    writer.write_all(payload)?;
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn worker_round_trip<W: Write, R: Read>(
    writer: &mut W,
    reader: &mut R,
    sample_rate: u32,
    channels: u32,
    decode_fec: bool,
    payload: &[u8],
) -> ResultType<WorkerResponse> {
    write_request(writer, sample_rate, channels, decode_fec, payload)?;
    writer
        .flush()
        .map_err(|e| anyhow!("failed to flush native Opus worker request: {e}"))?;
    read_response(reader, sample_rate, channels)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn read_response<R: Read>(
    reader: &mut R,
    sample_rate: u32,
    channels: u32,
) -> ResultType<WorkerResponse> {
    let magic = read_array::<4, _>(reader)
        .map_err(|e| anyhow!("failed to read native Opus worker response magic: {e}"))?;
    if magic != RESPONSE_MAGIC {
        bail!("bad native Opus worker response magic");
    }
    let version = read_u8(reader)
        .map_err(|e| anyhow!("failed to read native Opus worker response version: {e}"))?;
    if version != PROTOCOL_VERSION {
        bail!("unsupported native Opus worker response version {version}");
    }
    let status = read_u8(reader)
        .map_err(|e| anyhow!("failed to read native Opus worker response status: {e}"))?;
    let response_channels = read_u8(reader)
        .map_err(|e| anyhow!("failed to read native Opus worker response channel count: {e}"))?
        as u32;
    let _reserved = read_u8(reader)
        .map_err(|e| anyhow!("failed to read native Opus worker reserved field: {e}"))?;
    let response_sample_rate = read_u32(reader)
        .map_err(|e| anyhow!("failed to read native Opus worker response sample rate: {e}"))?;
    let samples_per_channel = read_u32(reader)
        .map_err(|e| anyhow!("failed to read native Opus worker sample count: {e}"))?
        as usize;
    let float_count = read_u32(reader)
        .map_err(|e| anyhow!("failed to read native Opus worker float count: {e}"))?
        as usize;
    let msg_len = read_u32(reader)
        .map_err(|e| anyhow!("failed to read native Opus worker message length: {e}"))?
        as usize;
    if response_sample_rate != sample_rate || response_channels != channels {
        bail!("native Opus worker response format mismatch");
    }
    let max_floats = max_pcm_float_count(sample_rate, channels)?;
    if float_count > max_floats {
        bail!("native Opus worker response too large: {float_count} > {max_floats}");
    }
    if samples_per_channel.checked_mul(channels as usize) != Some(float_count) {
        bail!("native Opus worker sample count does not match float count");
    }
    if msg_len > MAX_OPUS_ERROR_BYTES {
        bail!("native Opus worker error message too large");
    }
    validate_worker_response_shape(status, samples_per_channel, float_count, msg_len)?;
    let mut pcm_bytes = vec![0u8; float_count * std::mem::size_of::<f32>()];
    reader
        .read_exact(&mut pcm_bytes)
        .map_err(|e| anyhow!("failed to read native Opus worker PCM data: {e}"))?;
    let mut msg = vec![0u8; msg_len];
    reader
        .read_exact(&mut msg)
        .map_err(|e| anyhow!("failed to read native Opus worker message: {e}"))?;
    let pcm = decode_f32_le(&pcm_bytes)?;
    let message = String::from_utf8_lossy(&msg).into_owned();
    Ok(WorkerResponse {
        status,
        sample_rate: response_sample_rate,
        channels: response_channels,
        samples_per_channel,
        pcm,
        message,
    })
}

fn validate_worker_response_shape(
    status: u8,
    samples_per_channel: usize,
    float_count: usize,
    msg_len: usize,
) -> ResultType<()> {
    match status {
        STATUS_DECODED => {
            if msg_len != 0 {
                bail!("native Opus worker decoded response carried an error message");
            }
        }
        STATUS_ERROR => {
            if samples_per_channel != 0 || float_count != 0 {
                bail!("native Opus worker error response carried PCM data");
            }
        }
        _ => bail!("native Opus worker returned unknown status {status}"),
    }
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn write_decoded<W: Write>(writer: &mut W, response: &WorkerResponse) -> ResultType<()> {
    write_response_header(
        writer,
        STATUS_DECODED,
        response.samples_per_channel,
        response.pcm.len(),
        response.sample_rate,
        response.channels as usize,
        0,
    )?;
    write_f32_le(writer, &response.pcm)?;
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn write_error<W: Write>(
    writer: &mut W,
    sample_rate: u32,
    channels: u32,
    message: &str,
) -> ResultType<()> {
    let bytes = message.as_bytes();
    let len = bytes.len().min(MAX_OPUS_ERROR_BYTES);
    write_response_header(
        writer,
        STATUS_ERROR,
        0,
        0,
        sample_rate,
        channels as usize,
        len,
    )?;
    writer.write_all(&bytes[..len])?;
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn write_response_header<W: Write>(
    writer: &mut W,
    status: u8,
    samples_per_channel: usize,
    float_count: usize,
    sample_rate: u32,
    channels: usize,
    msg_len: usize,
) -> ResultType<()> {
    writer.write_all(&RESPONSE_MAGIC)?;
    writer.write_all(&[
        PROTOCOL_VERSION,
        status,
        u8::try_from(channels).map_err(|_| anyhow!("worker Opus channel count too large"))?,
        0,
    ])?;
    write_u32(writer, sample_rate)?;
    write_u32(
        writer,
        u32::try_from(samples_per_channel)
            .map_err(|_| anyhow!("worker Opus sample count too large"))?,
    )?;
    write_u32(
        writer,
        u32::try_from(float_count).map_err(|_| anyhow!("worker Opus response too large"))?,
    )?;
    write_u32(
        writer,
        u32::try_from(msg_len).map_err(|_| anyhow!("worker Opus message response too large"))?,
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

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn write_f32_le<W: Write>(writer: &mut W, values: &[f32]) -> std::io::Result<()> {
    for value in values {
        writer.write_all(&value.to_le_bytes())?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn decode_f32_le(bytes: &[u8]) -> ResultType<Vec<f32>> {
    if bytes.len() % std::mem::size_of::<f32>() != 0 {
        bail!("native Opus worker returned a partial f32");
    }
    let mut out = Vec::with_capacity(bytes.len() / std::mem::size_of::<f32>());
    for chunk in bytes.chunks_exact(std::mem::size_of::<f32>()) {
        out.push(f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    Ok(out)
}

fn validate_format(sample_rate: u32, channels: u32) -> ResultType<()> {
    if !matches!(sample_rate, 8000 | 12000 | 16000 | 24000 | 48000) {
        bail!("unsupported native Opus sample rate {sample_rate}");
    }
    if !matches!(channels, 1 | 2) {
        bail!("unsupported native Opus channel count {channels}");
    }
    Ok(())
}

fn channels_to_opus(channels: u32) -> ResultType<Channels> {
    match channels {
        1 => Ok(Channels::Mono),
        2 => Ok(Channels::Stereo),
        _ => bail!("unsupported native Opus channel count {channels}"),
    }
}

fn max_pcm_float_count(sample_rate: u32, channels: u32) -> ResultType<usize> {
    validate_format(sample_rate, channels)?;
    (sample_rate as usize)
        .checked_mul(channels as usize)
        .ok_or_else(|| anyhow!("native Opus PCM buffer size overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_limit_accepts_only_opus_rates_and_mono_stereo() {
        assert!(validate_format(48000, 2).is_ok());
        assert!(validate_format(8000, 1).is_ok());
        assert!(validate_format(96000, 2).is_err());
        assert!(validate_format(48000, 0).is_err());
        assert!(validate_format(48000, 3).is_err());
    }

    #[test]
    fn pcm_bound_is_one_second_of_valid_format() {
        assert_eq!(max_pcm_float_count(48000, 2).unwrap(), 96000);
        assert_eq!(max_pcm_float_count(8000, 1).unwrap(), 8000);
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn f32_le_round_trip_is_stable() {
        let values = [0.0_f32, 1.0, -1.5, 1234.25];
        let mut bytes = Vec::new();
        write_f32_le(&mut bytes, &values).unwrap();
        assert_eq!(decode_f32_le(&bytes).unwrap(), values);
    }

    #[test]
    fn opus_worker_response_shape_rejects_success_message() {
        assert!(validate_worker_response_shape(STATUS_DECODED, 1, 2, 1).is_err());
    }

    #[test]
    fn opus_worker_response_shape_rejects_error_pcm() {
        assert!(validate_worker_response_shape(STATUS_ERROR, 1, 2, 4).is_err());
    }

    #[test]
    fn opus_worker_response_shape_rejects_unknown_status() {
        assert!(validate_worker_response_shape(99, 0, 0, 0).is_err());
    }
}
