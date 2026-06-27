use hbb_common::{
    anyhow::{anyhow, bail},
    ResultType,
};
use std::{
    io::{self, Read, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{
        mpsc::{self, SyncSender},
        Mutex, OnceLock, TryLockError,
    },
    time::Duration,
};

const WORKER_ARG: &str = "--native-printer-worker";
const PROTOCOL_VERSION: u8 = 1;
const REQUEST_MAGIC: [u8; 4] = *b"RDPW";
const RESPONSE_MAGIC: [u8; 4] = *b"RDPR";
const OP_PRINT_XPS: u8 = 1;
const STATUS_OK: u8 = 0;
const STATUS_ERROR: u8 = 1;
const MAX_PRINTER_NAME_BYTES: usize = 1024;
const MAX_PRINTER_DATA_BYTES: usize = 128 * 1024 * 1024;
const MAX_WORKER_ERROR_BYTES: usize = 64 * 1024;
const WORKER_PRINT_TIMEOUT: Duration = Duration::from_secs(120);

pub fn worker_arg() -> &'static str {
    WORKER_ARG
}

pub fn send_raw_data_to_printer(printer_name: Option<String>, data: Vec<u8>) -> ResultType<()> {
    validate_request(printer_name.as_deref(), data.len())?;

    static WORKER: OnceLock<Mutex<Option<PrinterWorker>>> = OnceLock::new();
    let worker = WORKER.get_or_init(|| Mutex::new(None));
    let mut guard = match worker.try_lock() {
        Ok(guard) => guard,
        Err(TryLockError::WouldBlock) => {
            bail!("native printer worker busy; refusing to queue remote print job");
        }
        Err(TryLockError::Poisoned(_)) => {
            bail!("native printer worker lock poisoned");
        }
    };
    if guard.is_none() {
        *guard = Some(PrinterWorker::spawn()?);
    }
    let Some(worker) = guard.as_mut() else {
        bail!("native printer worker unavailable");
    };
    match worker.print(printer_name, data) {
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

struct PrinterWorker {
    child: Child,
    _process_guard: hbb_common::native_worker_sandbox::WorkerProcessGuard,
    io_tx: SyncSender<PrinterWorkerIoRequest>,
}

struct PrinterWorkerIoRequest {
    printer_name: Option<String>,
    data: Vec<u8>,
    reply: mpsc::Sender<ResultType<()>>,
}

impl Drop for PrinterWorker {
    fn drop(&mut self) {
        self.kill_child();
    }
}

impl PrinterWorker {
    fn spawn() -> ResultType<Self> {
        let exe = std::env::current_exe()
            .map_err(|e| anyhow!("failed to resolve current executable for printer worker: {e}"))?;
        let mut command = Command::new(exe);
        command
            .arg(WORKER_ARG)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        hbb_common::native_worker_sandbox::apply_to_command(&mut command);
        let mut child = command
            .spawn()
            .map_err(|e| anyhow!("failed to spawn native printer worker: {e}"))?;
        let process_guard =
            match hbb_common::native_worker_sandbox::apply_to_spawned_child(&mut child) {
                Ok(process_guard) => process_guard,
                Err(err) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(anyhow!("failed to constrain native printer worker: {err}"));
                }
            };
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("native printer worker stdin unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("native printer worker stdout unavailable"))?;
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

    fn print(&mut self, printer_name: Option<String>, data: Vec<u8>) -> ResultType<()> {
        let (tx, rx) = mpsc::channel();
        self.io_tx
            .send(PrinterWorkerIoRequest {
                printer_name,
                data,
                reply: tx,
            })
            .map_err(|_| anyhow!("native printer worker I/O thread unavailable"))?;

        match rx.recv_timeout(WORKER_PRINT_TIMEOUT) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => {
                self.kill_child();
                Err(err)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.kill_child();
                Err(anyhow!(
                    "native printer worker timed out after {:?}; killed child",
                    WORKER_PRINT_TIMEOUT
                ))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.kill_child();
                Err(anyhow!(
                    "native printer worker I/O thread exited without a response"
                ))
            }
        }
    }
}

fn spawn_worker_io_thread(
    mut stdin: ChildStdin,
    mut stdout: ChildStdout,
) -> ResultType<SyncSender<PrinterWorkerIoRequest>> {
    let (tx, rx) = mpsc::sync_channel::<PrinterWorkerIoRequest>(1);
    std::thread::Builder::new()
        .name("rd-native-printer-io".to_owned())
        .spawn(move || {
            while let Ok(request) = rx.recv() {
                let result = worker_round_trip(&mut stdin, &mut stdout, &request);
                let _ = request.reply.send(result);
            }
        })
        .map_err(|e| anyhow!("failed to spawn native printer worker I/O thread: {e}"))?;
    Ok(tx)
}

fn worker_round_trip<R, W>(
    writer: &mut W,
    reader: &mut R,
    request: &PrinterWorkerIoRequest,
) -> ResultType<()>
where
    R: Read,
    W: Write,
{
    write_request(writer, request.printer_name.as_deref(), &request.data)?;
    read_response(reader)
}

struct WorkerRequest {
    printer_name: Option<String>,
    data: Vec<u8>,
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
            Err(err) => bail!("failed to read native printer worker request: {err}"),
        };
        match crate::platform::windows::send_raw_data_to_printer(request.printer_name, request.data)
        {
            Ok(()) => write_response(&mut output, STATUS_OK, "")?,
            Err(err) => write_response(&mut output, STATUS_ERROR, &err.to_string())?,
        }
        output
            .flush()
            .map_err(|e| anyhow!("failed to flush native printer worker response: {e}"))?;
    }
}

fn validate_request(printer_name: Option<&str>, data_len: usize) -> ResultType<()> {
    if data_len == 0 {
        bail!("native printer worker refuses empty print job");
    }
    if data_len > MAX_PRINTER_DATA_BYTES {
        bail!(
            "native printer worker request too large: {} > {}",
            data_len,
            MAX_PRINTER_DATA_BYTES
        );
    }
    if let Some(printer_name) = printer_name {
        if printer_name.as_bytes().len() > MAX_PRINTER_NAME_BYTES {
            bail!(
                "native printer worker printer name too large: {} > {}",
                printer_name.as_bytes().len(),
                MAX_PRINTER_NAME_BYTES
            );
        }
        if printer_name.as_bytes().contains(&0) {
            bail!("native printer worker refuses NUL in printer name");
        }
    }
    Ok(())
}

fn write_request<W: Write>(
    writer: &mut W,
    printer_name: Option<&str>,
    data: &[u8],
) -> ResultType<()> {
    validate_request(printer_name, data.len())?;
    let printer_name = printer_name.unwrap_or("");
    let name_len = u32::try_from(printer_name.as_bytes().len())
        .map_err(|_| anyhow!("native printer worker printer name length overflow"))?;
    let data_len = u64::try_from(data.len())
        .map_err(|_| anyhow!("native printer worker data length overflow"))?;
    writer.write_all(&REQUEST_MAGIC)?;
    write_u8(writer, PROTOCOL_VERSION)?;
    write_u8(writer, OP_PRINT_XPS)?;
    write_u32(writer, name_len)?;
    write_u64(writer, data_len)?;
    writer.write_all(printer_name.as_bytes())?;
    writer.write_all(data)?;
    writer.flush()?;
    Ok(())
}

fn read_request<R: Read>(reader: &mut R) -> io::Result<WorkerRequest> {
    let magic = read_array::<4, _>(reader)?;
    if magic != REQUEST_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad native printer worker request magic",
        ));
    }
    let version = read_u8(reader)?;
    if version != PROTOCOL_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported native printer worker protocol version",
        ));
    }
    let op = read_u8(reader)?;
    if op != OP_PRINT_XPS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported native printer worker operation",
        ));
    }
    let name_len = read_u32(reader)? as usize;
    if name_len > MAX_PRINTER_NAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized native printer worker printer name",
        ));
    }
    let data_len = read_u64(reader)?;
    if data_len > MAX_PRINTER_DATA_BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized native printer worker data",
        ));
    }
    let data_len = usize::try_from(data_len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "native printer worker data length overflows usize",
        )
    })?;
    let name = read_exact_vec(reader, name_len)?;
    if name.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native printer worker printer name contains NUL",
        ));
    }
    let printer_name = if name.is_empty() {
        None
    } else {
        Some(String::from_utf8(name).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "native printer worker printer name is not UTF-8",
            )
        })?)
    };
    let data = read_exact_vec(reader, data_len)?;
    if data.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native printer worker refuses empty print job",
        ));
    }
    Ok(WorkerRequest { printer_name, data })
}

fn write_response<W: Write>(writer: &mut W, status: u8, message: &str) -> ResultType<()> {
    let message = message.as_bytes();
    let message_len = message.len().min(MAX_WORKER_ERROR_BYTES);
    writer.write_all(&RESPONSE_MAGIC)?;
    write_u8(writer, PROTOCOL_VERSION)?;
    write_u8(writer, status)?;
    write_u8(writer, 0)?;
    write_u32(
        writer,
        u32::try_from(message_len)
            .map_err(|_| anyhow!("native printer worker error length overflow"))?,
    )?;
    writer.write_all(&message[..message_len])?;
    Ok(())
}

fn read_response<R: Read>(reader: &mut R) -> ResultType<()> {
    let magic = read_array::<4, _>(reader)
        .map_err(|e| anyhow!("failed to read native printer worker response magic: {e}"))?;
    if magic != RESPONSE_MAGIC {
        bail!("bad native printer worker response magic");
    }
    let version = read_u8(reader)
        .map_err(|e| anyhow!("failed to read native printer worker response version: {e}"))?;
    if version != PROTOCOL_VERSION {
        bail!("unsupported native printer worker response version {version}");
    }
    let status = read_u8(reader)
        .map_err(|e| anyhow!("failed to read native printer worker response status: {e}"))?;
    let reserved = read_u8(reader)
        .map_err(|e| anyhow!("failed to read native printer worker reserved field: {e}"))?;
    if reserved != 0 {
        bail!("native printer worker response reserved field was nonzero");
    }
    let message_len = read_u32(reader)
        .map_err(|e| anyhow!("failed to read native printer worker response message length: {e}"))?
        as usize;
    if message_len > MAX_WORKER_ERROR_BYTES {
        bail!("native printer worker response message too large");
    }
    validate_worker_response_shape(status, message_len)?;
    match status {
        STATUS_OK => Ok(()),
        STATUS_ERROR => {
            let message = read_exact_vec(reader, message_len).map_err(|e| {
                anyhow!("failed to read native printer worker response message: {e}")
            })?;
            bail!(
                "native printer worker failed: {}",
                String::from_utf8_lossy(&message)
            )
        }
        status => bail!("native printer worker returned unknown status {status}"),
    }
}

fn validate_worker_response_shape(status: u8, message_len: usize) -> ResultType<()> {
    match status {
        STATUS_OK => {
            if message_len != 0 {
                bail!("native printer worker success response carried an error message");
            }
        }
        STATUS_ERROR => {}
        _ => bail!("native printer worker returned unknown status {status}"),
    }
    Ok(())
}

fn read_exact_vec<R: Read>(reader: &mut R, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_array<const N: usize, R: Read>(reader: &mut R) -> io::Result<[u8; N]> {
    let mut buf = [0u8; N];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_u8<R: Read>(reader: &mut R) -> io::Result<u8> {
    Ok(read_array::<1, _>(reader)?[0])
}

fn write_u8<W: Write>(writer: &mut W, value: u8) -> io::Result<()> {
    writer.write_all(&[value])
}

fn read_u32<R: Read>(reader: &mut R) -> io::Result<u32> {
    Ok(u32::from_be_bytes(read_array::<4, _>(reader)?))
}

fn write_u32<W: Write>(writer: &mut W, value: u32) -> io::Result<()> {
    writer.write_all(&value.to_be_bytes())
}

fn read_u64<R: Read>(reader: &mut R) -> io::Result<u64> {
    Ok(u64::from_be_bytes(read_array::<8, _>(reader)?))
}

fn write_u64<W: Write>(writer: &mut W, value: u64) -> io::Result<()> {
    writer.write_all(&value.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn printer_response(version: u8, status: u8, message: &[u8]) -> Vec<u8> {
        let mut response = Vec::new();
        response.extend_from_slice(&RESPONSE_MAGIC);
        write_u8(&mut response, version).unwrap();
        write_u8(&mut response, status).unwrap();
        write_u8(&mut response, 0).unwrap();
        write_u32(&mut response, message.len() as u32).unwrap();
        response.extend_from_slice(message);
        response
    }

    #[test]
    fn printer_worker_response_rejects_bad_version() {
        let response = printer_response(PROTOCOL_VERSION.wrapping_add(1), STATUS_OK, &[]);

        assert!(read_response(&mut &response[..]).is_err());
    }

    #[test]
    fn printer_worker_response_rejects_success_message() {
        let response = printer_response(PROTOCOL_VERSION, STATUS_OK, b"unexpected");

        assert!(read_response(&mut &response[..]).is_err());
    }

    #[test]
    fn printer_worker_response_rejects_nonzero_reserved() {
        let mut response = printer_response(PROTOCOL_VERSION, STATUS_OK, &[]);
        response[RESPONSE_MAGIC.len() + 2] = 1;

        assert!(read_response(&mut &response[..]).is_err());
    }
}
