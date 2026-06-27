use crate::ResultType;
use std::{
    cell::RefCell,
    convert::TryFrom,
    io::{self, Read, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{
        mpsc::{self, SyncSender},
        Mutex, OnceLock, TryLockError,
    },
    time::Duration,
};
use zstd::bulk::Compressor;

const WORKER_ARG: &str = "--native-zstd-worker";
const PROTOCOL_VERSION: u8 = 1;
const REQUEST_MAGIC: [u8; 4] = *b"RDZW";
const RESPONSE_MAGIC: [u8; 4] = *b"RDZR";
const OP_DECOMPRESS: u8 = 1;
const STATUS_DECOMPRESSED: u8 = 0;
const STATUS_ERROR: u8 = 1;
const MAX_COMPRESSED_INPUT: usize = 32 * 1024 * 1024;
const MAX_WORKER_ERROR_BYTES: usize = 64 * 1024;
const WORKER_DECOMPRESS_TIMEOUT: Duration = Duration::from_secs(5);

// The library supports regular compression levels from 1 up to ZSTD_maxCLevel(),
// which is currently 22. Levels >= 20
// Default level is ZSTD_CLEVEL_DEFAULT==3.
// value 0 means default, which is controlled by ZSTD_CLEVEL_DEFAULT
thread_local! {
    static COMPRESSOR: RefCell<io::Result<Compressor<'static>>> = RefCell::new(Compressor::new(crate::config::COMPRESS_LEVEL));
}

pub fn compress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    COMPRESSOR.with(|c| {
        if let Ok(mut c) = c.try_borrow_mut() {
            match &mut *c {
                Ok(c) => match c.compress(data) {
                    Ok(res) => out = res,
                    Err(err) => {
                        crate::log::debug!("Failed to compress: {}", err);
                    }
                },
                Err(err) => {
                    crate::log::debug!("Failed to get compressor: {}", err);
                }
            }
        }
    });
    out
}

/// The post-key decompressed-output ceiling (R-S7, the twin of the pre-auth
/// frame cap). zstd's ratio is unbounded, so a small compressed file-block,
/// clipboard, or cursor payload from a *keyed* peer can amplify to an unbounded
/// allocation/disk-write (a zstd bomb) on either role. This cap (64 MiB) sits
/// well above any realistic single decompressed payload — the 128 KiB file
/// block (`fs.rs`), a clipboard image, a cursor — yet bounds the amplification.
const MAX_DECOMPRESSED: usize = 64 * 1024 * 1024;

/// Decompress, bounding the output to [`MAX_DECOMPRESSED`] (R-S7 post-key twin).
/// The inherited `zstd::decode_all` reads to EOF with NO output limit; this
/// streams through a capped reader instead. An over-cap stream is *rejected*
/// (empty — the same fail-safe the previous `unwrap_or_default` already returned
/// on a decode error, which every caller handles), never silently truncated
/// (truncation would corrupt a legitimately-large payload).
pub fn decompress(data: &[u8]) -> Vec<u8> {
    decompress_checked(data).unwrap_or_default()
}

fn decompress_checked(data: &[u8]) -> ResultType<Vec<u8>> {
    let Ok(decoder) = zstd::stream::read::Decoder::new(data) else {
        return Err(crate::anyhow::anyhow!("invalid zstd stream"));
    };
    // take(MAX+1) so an over-cap stream is *detected* (len > MAX) and rejected
    // rather than truncated; allocation is bounded to MAX+1.
    let mut limited = decoder.take(MAX_DECOMPRESSED as u64 + 1);
    let mut out = Vec::new();
    if let Err(err) = limited.read_to_end(&mut out) {
        return Err(crate::anyhow::anyhow!("zstd decompression failed: {err}"));
    }
    if out.len() > MAX_DECOMPRESSED {
        return Err(crate::anyhow::anyhow!(
            "zstd decompressed output too large: {} > {}",
            out.len(),
            MAX_DECOMPRESSED
        ));
    }
    Ok(out)
}

/// Decompress peer-controlled zstd payloads. Desktop builds route hostile-peer
/// compressed bytes through a same-artifact child process; local persisted
/// config data intentionally continues to use [`decompress`] directly.
pub fn peer_decompress(data: &[u8]) -> Vec<u8> {
    if data.len() > MAX_COMPRESSED_INPUT {
        crate::log::warn!(
            "dropping oversized peer zstd payload before native worker: {} > {}",
            data.len(),
            MAX_COMPRESSED_INPUT
        );
        return Vec::new();
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        match peer_decompress_worker(data) {
            Ok(out) => out,
            Err(err) => {
                crate::log::warn!(
                    "native zstd worker failed; refusing in-process desktop peer decompress: {}",
                    err
                );
                Vec::new()
            }
        }
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        crate::log::warn!(
            "refusing in-process mobile peer zstd decompress until a platform worker/service boundary exists"
        );
        Vec::new()
    }
}

pub fn worker_arg() -> &'static str {
    WORKER_ARG
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn run_worker() -> ResultType<()> {
    crate::native_worker_sandbox::enter_worker_process()?;
    worker_loop(std::io::stdin(), std::io::stdout())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn peer_decompress_worker(data: &[u8]) -> ResultType<Vec<u8>> {
    static WORKER: OnceLock<Mutex<Option<ZstdWorker>>> = OnceLock::new();
    let worker = WORKER.get_or_init(|| Mutex::new(None));
    let mut guard = match worker.try_lock() {
        Ok(guard) => guard,
        Err(TryLockError::WouldBlock) => {
            return Err(crate::anyhow::anyhow!(
                "native zstd worker busy; refusing to queue peer decompress"
            ));
        }
        Err(TryLockError::Poisoned(_)) => {
            return Err(crate::anyhow::anyhow!("native zstd worker lock poisoned"));
        }
    };
    if guard.is_none() {
        *guard = Some(ZstdWorker::spawn()?);
    }
    let Some(worker) = guard.as_mut() else {
        return Err(crate::anyhow::anyhow!("native zstd worker unavailable"));
    };
    match worker.decompress(data) {
        Ok(out) => Ok(out),
        Err(err) => {
            *guard = None;
            Err(err)
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct ZstdWorker {
    child: Child,
    _process_guard: crate::native_worker_sandbox::WorkerProcessGuard,
    io_tx: SyncSender<ZstdWorkerIoRequest>,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct ZstdWorkerIoRequest {
    payload: Vec<u8>,
    reply: mpsc::Sender<ResultType<Vec<u8>>>,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl Drop for ZstdWorker {
    fn drop(&mut self) {
        self.kill_child();
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl ZstdWorker {
    fn spawn() -> ResultType<Self> {
        let exe = std::env::current_exe().map_err(|e| {
            crate::anyhow::anyhow!("failed to resolve current executable for zstd worker: {e}")
        })?;
        let mut command = Command::new(exe);
        command
            .arg(WORKER_ARG)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        crate::native_worker_sandbox::apply_to_command(&mut command);
        let mut child = command
            .spawn()
            .map_err(|e| crate::anyhow::anyhow!("failed to spawn native zstd worker: {e}"))?;
        let process_guard = match crate::native_worker_sandbox::apply_to_spawned_child(&mut child) {
            Ok(process_guard) => process_guard,
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(crate::anyhow::anyhow!(
                    "failed to constrain native zstd worker: {err}"
                ));
            }
        };
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| crate::anyhow::anyhow!("native zstd worker stdin unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| crate::anyhow::anyhow!("native zstd worker stdout unavailable"))?;
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

    fn decompress(&mut self, data: &[u8]) -> ResultType<Vec<u8>> {
        let payload = data.to_vec();
        let (tx, rx) = mpsc::channel();
        self.io_tx
            .send(ZstdWorkerIoRequest { payload, reply: tx })
            .map_err(|_| crate::anyhow::anyhow!("native zstd worker I/O thread unavailable"))?;

        match rx.recv_timeout(WORKER_DECOMPRESS_TIMEOUT) {
            Ok(Ok(out)) => Ok(out),
            Ok(Err(err)) => {
                self.kill_child();
                Err(err)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.kill_child();
                Err(crate::anyhow::anyhow!(
                    "native zstd worker decompress timed out after {:?}; killed child",
                    WORKER_DECOMPRESS_TIMEOUT
                ))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.kill_child();
                Err(crate::anyhow::anyhow!(
                    "native zstd worker I/O thread exited without a response"
                ))
            }
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn spawn_worker_io_thread(
    mut stdin: ChildStdin,
    mut stdout: ChildStdout,
) -> ResultType<SyncSender<ZstdWorkerIoRequest>> {
    let (tx, rx) = mpsc::sync_channel::<ZstdWorkerIoRequest>(1);
    std::thread::Builder::new()
        .name("rd-native-zstd-io".to_owned())
        .spawn(move || {
            while let Ok(request) = rx.recv() {
                let result = worker_round_trip(&mut stdin, &mut stdout, &request.payload);
                let _ = request.reply.send(result);
            }
        })
        .map_err(|e| {
            crate::anyhow::anyhow!("failed to spawn native zstd worker I/O thread: {e}")
        })?;
    Ok(tx)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn worker_loop<R, W>(mut input: R, mut output: W) -> ResultType<()>
where
    R: Read,
    W: Write,
{
    loop {
        let payload = match read_request(&mut input) {
            Ok(payload) => payload,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => {
                return Err(crate::anyhow::anyhow!(
                    "failed to read native zstd worker request: {err}"
                ));
            }
        };
        match decompress_checked(&payload) {
            Ok(out) => write_response(&mut output, STATUS_DECOMPRESSED, &out, "")?,
            Err(err) => write_response(&mut output, STATUS_ERROR, &[], &err.to_string())?,
        }
        output.flush().map_err(|e| {
            crate::anyhow::anyhow!("failed to flush native zstd worker response: {e}")
        })?;
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn read_request<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let magic = read_array::<4, _>(reader)?;
    if magic != REQUEST_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad native zstd worker request magic",
        ));
    }
    let version = read_u8(reader)?;
    if version != PROTOCOL_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported native zstd worker protocol version",
        ));
    }
    let op = read_u8(reader)?;
    if op != OP_DECOMPRESS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported native zstd worker operation",
        ));
    }
    let _reserved = read_u8(reader)?;
    let len = read_u32(reader)? as usize;
    if len > MAX_COMPRESSED_INPUT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized native zstd worker request",
        ));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn write_request<W: Write>(writer: &mut W, data: &[u8]) -> ResultType<()> {
    if data.len() > MAX_COMPRESSED_INPUT {
        return Err(crate::anyhow::anyhow!(
            "native zstd worker request too large: {} > {}",
            data.len(),
            MAX_COMPRESSED_INPUT
        ));
    }
    writer.write_all(&REQUEST_MAGIC)?;
    writer.write_all(&[PROTOCOL_VERSION, OP_DECOMPRESS, 0])?;
    write_u32(
        writer,
        u32::try_from(data.len())
            .map_err(|_| crate::anyhow::anyhow!("native zstd payload too large"))?,
    )?;
    writer.write_all(data)?;
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn worker_round_trip<W: Write, R: Read>(
    writer: &mut W,
    reader: &mut R,
    data: &[u8],
) -> ResultType<Vec<u8>> {
    write_request(writer, data)?;
    writer
        .flush()
        .map_err(|e| crate::anyhow::anyhow!("failed to flush native zstd worker request: {e}"))?;
    read_response(reader)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn read_response<R: Read>(reader: &mut R) -> ResultType<Vec<u8>> {
    let magic = read_array::<4, _>(reader)
        .map_err(|e| crate::anyhow::anyhow!("failed to read native zstd response magic: {e}"))?;
    if magic != RESPONSE_MAGIC {
        return Err(crate::anyhow::anyhow!(
            "bad native zstd worker response magic"
        ));
    }
    let version = read_u8(reader)
        .map_err(|e| crate::anyhow::anyhow!("failed to read native zstd response version: {e}"))?;
    if version != PROTOCOL_VERSION {
        return Err(crate::anyhow::anyhow!(
            "unsupported native zstd response version {version}"
        ));
    }
    let status = read_u8(reader)
        .map_err(|e| crate::anyhow::anyhow!("failed to read native zstd response status: {e}"))?;
    let _reserved = read_u8(reader)
        .map_err(|e| crate::anyhow::anyhow!("failed to read native zstd response reserved: {e}"))?;
    let out_len = read_u32(reader)
        .map_err(|e| crate::anyhow::anyhow!("failed to read native zstd output length: {e}"))?
        as usize;
    let msg_len = read_u32(reader)
        .map_err(|e| crate::anyhow::anyhow!("failed to read native zstd message length: {e}"))?
        as usize;
    if out_len > MAX_DECOMPRESSED {
        return Err(crate::anyhow::anyhow!(
            "native zstd worker response too large: {out_len} > {MAX_DECOMPRESSED}"
        ));
    }
    if msg_len > MAX_WORKER_ERROR_BYTES {
        return Err(crate::anyhow::anyhow!(
            "native zstd worker error message too large"
        ));
    }
    let mut out = vec![0u8; out_len];
    reader
        .read_exact(&mut out)
        .map_err(|e| crate::anyhow::anyhow!("failed to read native zstd worker output: {e}"))?;
    let mut msg = vec![0u8; msg_len];
    reader
        .read_exact(&mut msg)
        .map_err(|e| crate::anyhow::anyhow!("failed to read native zstd worker message: {e}"))?;
    if status == STATUS_DECOMPRESSED {
        Ok(out)
    } else if status == STATUS_ERROR {
        Err(crate::anyhow::anyhow!(
            "native zstd worker failed: {}",
            String::from_utf8_lossy(&msg)
        ))
    } else {
        Err(crate::anyhow::anyhow!(
            "native zstd worker returned unknown status {status}"
        ))
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn write_response<W: Write>(
    writer: &mut W,
    status: u8,
    output: &[u8],
    message: &str,
) -> ResultType<()> {
    let msg = message.as_bytes();
    let msg_len = msg.len().min(MAX_WORKER_ERROR_BYTES);
    writer.write_all(&RESPONSE_MAGIC)?;
    writer.write_all(&[PROTOCOL_VERSION, status, 0])?;
    write_u32(
        writer,
        u32::try_from(output.len())
            .map_err(|_| crate::anyhow::anyhow!("native zstd output too large"))?,
    )?;
    write_u32(
        writer,
        u32::try_from(msg_len)
            .map_err(|_| crate::anyhow::anyhow!("native zstd message too large"))?,
    )?;
    writer.write_all(output)?;
    writer.write_all(&msg[..msg_len])?;
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn read_array<const N: usize, R: Read>(reader: &mut R) -> io::Result<[u8; N]> {
    let mut out = [0u8; N];
    reader.read_exact(&mut out)?;
    Ok(out)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn read_u8<R: Read>(reader: &mut R) -> io::Result<u8> {
    Ok(read_array::<1, _>(reader)?[0])
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn read_u32<R: Read>(reader: &mut R) -> io::Result<u32> {
    Ok(u32::from_le_bytes(read_array::<4, _>(reader)?))
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn write_u32<W: Write>(writer: &mut W, value: u32) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}
