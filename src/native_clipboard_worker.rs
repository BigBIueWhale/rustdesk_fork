use crate::clipboard::ClipboardSide;
use hbb_common::{
    anyhow::{anyhow, bail},
    message_proto::MultiClipboards,
    protobuf::Message as _,
    ResultType,
};
use std::{
    convert::TryFrom,
    io::{self, Read, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{
        mpsc::{self, SyncSender},
        Mutex, OnceLock, TryLockError,
    },
    time::Duration,
};

const WORKER_ARG: &str = "--native-clipboard-worker";
const PROTOCOL_VERSION: u8 = 1;
const REQUEST_MAGIC: [u8; 4] = *b"RDCW";
const RESPONSE_MAGIC: [u8; 4] = *b"RDCR";
const OP_SET_CLIPBOARD: u8 = 1;
const STATUS_OK: u8 = 0;
const STATUS_ERROR: u8 = 1;
const MAX_WORKER_REQUEST_BYTES: usize =
    crate::clipboard::MAX_NATIVE_CLIPBOARD_TOTAL_BYTES + 64 * 1024;
const MAX_WORKER_ERROR_BYTES: usize = 64 * 1024;
const WORKER_SET_TIMEOUT: Duration = Duration::from_secs(3);

pub fn worker_arg() -> &'static str {
    WORKER_ARG
}

pub fn update_clipboard(multi_clipboards: MultiClipboards, side: ClipboardSide) -> ResultType<()> {
    let payload = multi_clipboards
        .write_to_bytes()
        .map_err(|e| anyhow!("failed to serialize native clipboard worker request: {e}"))?;
    if payload.len() > MAX_WORKER_REQUEST_BYTES {
        bail!(
            "native clipboard worker request too large: {} > {}",
            payload.len(),
            MAX_WORKER_REQUEST_BYTES
        );
    }

    static WORKER: OnceLock<Mutex<Option<ClipboardWorker>>> = OnceLock::new();
    let worker = WORKER.get_or_init(|| Mutex::new(None));
    let mut guard = match worker.try_lock() {
        Ok(guard) => guard,
        Err(TryLockError::WouldBlock) => {
            bail!("native clipboard worker busy; refusing to queue peer clipboard SET");
        }
        Err(TryLockError::Poisoned(_)) => {
            bail!("native clipboard worker lock poisoned");
        }
    };
    if guard.is_none() {
        *guard = Some(ClipboardWorker::spawn()?);
    }
    let Some(worker) = guard.as_mut() else {
        bail!("native clipboard worker unavailable");
    };
    match worker.set_clipboard(side, payload) {
        Ok(()) => Ok(()),
        Err(err) => {
            *guard = None;
            Err(err)
        }
    }
}

pub fn run_worker() -> ResultType<()> {
    hbb_common::native_worker_sandbox::enter_worker_process()?;
    worker_loop(std::io::stdin(), std::io::stdout())
}

struct ClipboardWorker {
    child: Child,
    _process_guard: hbb_common::native_worker_sandbox::WorkerProcessGuard,
    io_tx: SyncSender<ClipboardWorkerIoRequest>,
}

struct ClipboardWorkerIoRequest {
    side: ClipboardSide,
    payload: Vec<u8>,
    reply: mpsc::Sender<ResultType<()>>,
}

impl Drop for ClipboardWorker {
    fn drop(&mut self) {
        self.kill_child();
    }
}

impl ClipboardWorker {
    fn spawn() -> ResultType<Self> {
        let exe = std::env::current_exe().map_err(|e| {
            anyhow!("failed to resolve current executable for clipboard worker: {e}")
        })?;
        let mut command = Command::new(exe);
        command
            .arg(WORKER_ARG)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        hbb_common::native_worker_sandbox::apply_to_command(&mut command);
        let mut child = command
            .spawn()
            .map_err(|e| anyhow!("failed to spawn native clipboard worker: {e}"))?;
        let process_guard =
            match hbb_common::native_worker_sandbox::apply_to_spawned_child(&mut child) {
                Ok(process_guard) => process_guard,
                Err(err) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(anyhow!(
                        "failed to constrain native clipboard worker: {err}"
                    ));
                }
            };
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("native clipboard worker stdin unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("native clipboard worker stdout unavailable"))?;
        let io_tx = match spawn_worker_io_thread(stdin, stdout) {
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
        })
    }

    fn kill_child(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn set_clipboard(&mut self, side: ClipboardSide, payload: Vec<u8>) -> ResultType<()> {
        let (tx, rx) = mpsc::channel();
        self.io_tx
            .send(ClipboardWorkerIoRequest {
                side,
                payload,
                reply: tx,
            })
            .map_err(|_| anyhow!("native clipboard worker I/O thread unavailable"))?;

        match rx.recv_timeout(WORKER_SET_TIMEOUT) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => {
                self.kill_child();
                Err(err)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.kill_child();
                Err(anyhow!(
                    "native clipboard worker set timed out after {:?}; killed child",
                    WORKER_SET_TIMEOUT
                ))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.kill_child();
                Err(anyhow!(
                    "native clipboard worker I/O thread exited without a response"
                ))
            }
        }
    }
}

fn spawn_worker_io_thread(
    mut stdin: ChildStdin,
    mut stdout: ChildStdout,
) -> ResultType<SyncSender<ClipboardWorkerIoRequest>> {
    let (tx, rx) = mpsc::sync_channel::<ClipboardWorkerIoRequest>(1);
    std::thread::Builder::new()
        .name("rd-native-clipboard-io".to_owned())
        .spawn(move || {
            while let Ok(request) = rx.recv() {
                let result =
                    worker_round_trip(&mut stdin, &mut stdout, request.side, &request.payload);
                let _ = request.reply.send(result);
            }
        })
        .map_err(|e| anyhow!("failed to spawn native clipboard worker I/O thread: {e}"))?;
    Ok(tx)
}

struct WorkerRequest {
    side: ClipboardSide,
    payload: Vec<u8>,
}

fn worker_loop<R, W>(mut input: R, mut output: W) -> ResultType<()>
where
    R: Read,
    W: Write,
{
    loop {
        let request = match read_request(&mut input) {
            Ok(request) => request,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => bail!("failed to read native clipboard worker request: {err}"),
        };
        match set_clipboard_in_worker(request.payload, request.side) {
            Ok(()) => write_ok(&mut output)?,
            Err(err) => write_error(&mut output, &err.to_string())?,
        }
        output
            .flush()
            .map_err(|e| anyhow!("failed to flush native clipboard worker response: {e}"))?;
    }
}

fn set_clipboard_in_worker(payload: Vec<u8>, side: ClipboardSide) -> ResultType<()> {
    let multi_clipboards = MultiClipboards::parse_from_bytes(&payload)
        .map_err(|e| anyhow!("failed to parse native clipboard worker protobuf: {e}"))?;
    let native =
        crate::clipboard::native_clipboard_data_from_multi_clipboards(multi_clipboards.clipboards);
    if native.is_empty() {
        bail!("native clipboard worker received no supported clipboard items");
    }
    crate::clipboard::set_native_clipboard_data(native, side)
}

fn read_request<R: Read>(reader: &mut R) -> std::io::Result<WorkerRequest> {
    let magic = read_array::<4, _>(reader)?;
    if magic != REQUEST_MAGIC {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad native clipboard worker request magic",
        ));
    }
    let version = read_u8(reader)?;
    if version != PROTOCOL_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported native clipboard worker protocol version",
        ));
    }
    let op = read_u8(reader)?;
    if op != OP_SET_CLIPBOARD {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported native clipboard worker operation",
        ));
    }
    let side = side_from_u8(read_u8(reader)?).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad native clipboard worker side",
        )
    })?;
    let _reserved = read_u8(reader)?;
    let len = read_u32(reader)? as usize;
    if len > MAX_WORKER_REQUEST_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "oversized native clipboard worker request",
        ));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(WorkerRequest { side, payload })
}

fn write_request<W: Write>(writer: &mut W, side: ClipboardSide, payload: &[u8]) -> ResultType<()> {
    if payload.len() > MAX_WORKER_REQUEST_BYTES {
        bail!(
            "native clipboard worker request too large: {} > {}",
            payload.len(),
            MAX_WORKER_REQUEST_BYTES
        );
    }
    writer.write_all(&REQUEST_MAGIC)?;
    writer.write_all(&[PROTOCOL_VERSION, OP_SET_CLIPBOARD, side_to_u8(side), 0])?;
    write_u32(
        writer,
        u32::try_from(payload.len()).map_err(|_| anyhow!("native clipboard payload too large"))?,
    )?;
    writer.write_all(payload)?;
    Ok(())
}

fn worker_round_trip<W: Write, R: Read>(
    writer: &mut W,
    reader: &mut R,
    side: ClipboardSide,
    payload: &[u8],
) -> ResultType<()> {
    write_request(writer, side, payload)?;
    writer
        .flush()
        .map_err(|e| anyhow!("failed to flush native clipboard worker request: {e}"))?;
    read_response(reader)
}

fn read_response<R: Read>(reader: &mut R) -> ResultType<()> {
    let magic = read_array::<4, _>(reader)
        .map_err(|e| anyhow!("failed to read native clipboard worker response magic: {e}"))?;
    if magic != RESPONSE_MAGIC {
        bail!("bad native clipboard worker response magic");
    }
    let version = read_u8(reader)
        .map_err(|e| anyhow!("failed to read native clipboard worker response version: {e}"))?;
    if version != PROTOCOL_VERSION {
        bail!("unsupported native clipboard worker response version {version}");
    }
    let status = read_u8(reader)
        .map_err(|e| anyhow!("failed to read native clipboard worker response status: {e}"))?;
    let _reserved = read_u8(reader)
        .map_err(|e| anyhow!("failed to read native clipboard worker reserved field: {e}"))?;
    let msg_len = read_u32(reader)
        .map_err(|e| anyhow!("failed to read native clipboard worker message length: {e}"))?
        as usize;
    if msg_len > MAX_WORKER_ERROR_BYTES {
        bail!("native clipboard worker error message too large");
    }
    validate_worker_response_shape(status, msg_len)?;
    match status {
        STATUS_OK => Ok(()),
        STATUS_ERROR => {
            let mut msg = vec![0u8; msg_len];
            reader
                .read_exact(&mut msg)
                .map_err(|e| anyhow!("failed to read native clipboard worker message: {e}"))?;
            let message = String::from_utf8_lossy(&msg).into_owned();
            bail!("native clipboard worker failed: {}", message)
        }
        status => bail!("native clipboard worker returned unknown status {status}"),
    }
}

fn validate_worker_response_shape(status: u8, msg_len: usize) -> ResultType<()> {
    match status {
        STATUS_OK => {
            if msg_len != 0 {
                bail!("native clipboard worker success response carried an error message");
            }
        }
        STATUS_ERROR => {}
        _ => bail!("native clipboard worker returned unknown status {status}"),
    }
    Ok(())
}

fn write_ok<W: Write>(writer: &mut W) -> ResultType<()> {
    write_response_header(writer, STATUS_OK, 0)
}

fn write_error<W: Write>(writer: &mut W, message: &str) -> ResultType<()> {
    let bytes = message.as_bytes();
    let len = bytes.len().min(MAX_WORKER_ERROR_BYTES);
    write_response_header(writer, STATUS_ERROR, len)?;
    writer.write_all(&bytes[..len])?;
    Ok(())
}

fn write_response_header<W: Write>(writer: &mut W, status: u8, msg_len: usize) -> ResultType<()> {
    writer.write_all(&RESPONSE_MAGIC)?;
    writer.write_all(&[PROTOCOL_VERSION, status, 0])?;
    write_u32(
        writer,
        u32::try_from(msg_len)
            .map_err(|_| anyhow!("native clipboard worker message response too large"))?,
    )?;
    Ok(())
}

fn read_array<const N: usize, R: Read>(reader: &mut R) -> std::io::Result<[u8; N]> {
    let mut out = [0u8; N];
    reader.read_exact(&mut out)?;
    Ok(out)
}

fn read_u8<R: Read>(reader: &mut R) -> std::io::Result<u8> {
    Ok(read_array::<1, _>(reader)?[0])
}

fn read_u32<R: Read>(reader: &mut R) -> std::io::Result<u32> {
    Ok(u32::from_le_bytes(read_array::<4, _>(reader)?))
}

fn write_u32<W: Write>(writer: &mut W, value: u32) -> std::io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn side_to_u8(side: ClipboardSide) -> u8 {
    match side {
        ClipboardSide::Host => 1,
        ClipboardSide::Client => 2,
    }
}

fn side_from_u8(value: u8) -> Option<ClipboardSide> {
    Some(match value {
        1 => ClipboardSide::Host,
        2 => ClipboardSide::Client,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn side_wire_encoding_is_stable() {
        assert!(matches!(
            side_from_u8(side_to_u8(ClipboardSide::Host)),
            Some(ClipboardSide::Host)
        ));
        assert!(matches!(
            side_from_u8(side_to_u8(ClipboardSide::Client)),
            Some(ClipboardSide::Client)
        ));
        assert!(side_from_u8(0).is_none());
        assert!(side_from_u8(3).is_none());
    }

    #[test]
    fn clipboard_worker_response_rejects_success_message() {
        assert!(validate_worker_response_shape(STATUS_OK, 1).is_err());
    }

    #[test]
    fn clipboard_worker_response_rejects_unknown_status() {
        assert!(validate_worker_response_shape(99, 0).is_err());
    }
}
