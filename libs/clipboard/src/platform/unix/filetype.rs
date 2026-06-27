use super::{FLAGS_FD_ATTRIBUTES, FLAGS_FD_LAST_WRITE, FLAGS_FD_UNIX_MODE, LDAP_EPOCH_DELTA};
use crate::CliprdrError;
use hbb_common::{
    bytes::{Buf, Bytes},
    log,
};
use serde_derive::{Deserialize, Serialize};
use std::{
    io::{self, Read, Write},
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{
        mpsc::{self, RecvTimeoutError, SyncSender},
        OnceLock,
    },
    time::{Duration, SystemTime},
};
use utf16string::WStr;

#[cfg(target_os = "linux")]
pub type Inode = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileType {
    File,
    Directory,
    // todo: support symlink
    Symlink,
}

/// read only permission
pub const PERM_READ: u16 = 0o444;
/// read and write permission
pub const PERM_RW: u16 = 0o644;
/// only self can read and readonly
pub const PERM_SELF_RO: u16 = 0o400;
/// rwx
pub const PERM_RWX: u16 = 0o755;
#[allow(dead_code)]
/// max length of file name
pub const MAX_NAME_LEN: usize = 255;
pub const MAX_FILE_DESCRIPTORS: usize = 4096;
const FILE_DESCRIPTOR_SIZE: usize = 592;
const MAX_FILE_DESCRIPTOR_PDU_BYTES: usize = 4 + FILE_DESCRIPTOR_SIZE * MAX_FILE_DESCRIPTORS;
const WORKER_ARG: &str = "--native-filedesc-worker";
const WORKER_PARSE_TIMEOUT: Duration = Duration::from_secs(3);
const PROTOCOL_VERSION: u8 = 1;
const REQUEST_MAGIC: [u8; 4] = *b"RDFW";
const RESPONSE_MAGIC: [u8; 4] = *b"RDFR";
const OP_PARSE_FILE_DESCRIPTORS: u8 = 1;
const STATUS_PARSED: u8 = 0;
const STATUS_ERROR: u8 = 1;
const MAX_WORKER_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_WORKER_ERROR_BYTES: usize = 64 * 1024;

pub fn file_descriptor_worker_arg() -> &'static str {
    WORKER_ARG
}

pub fn run_file_descriptor_worker() -> Result<(), CliprdrError> {
    hbb_common::native_worker_sandbox::enter_worker_process().map_err(|e| {
        common_error(format!(
            "failed to enter file descriptor worker sandbox: {e}"
        ))
    })?;
    worker_loop(std::io::stdin(), std::io::stdout())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDescription {
    pub conn_id: i32,
    pub name: PathBuf,
    pub kind: FileType,
    pub atime: SystemTime,
    pub last_modified: SystemTime,
    pub last_metadata_changed: SystemTime,
    pub creation_time: SystemTime,
    pub size: u64,
    pub perm: u16,
}

impl FileDescription {
    pub fn parse_file_descriptors_isolated(
        file_descriptor_pdu: Vec<u8>,
        conn_id: i32,
    ) -> Result<Vec<Self>, CliprdrError> {
        if file_descriptor_pdu.len() > MAX_FILE_DESCRIPTOR_PDU_BYTES {
            return Err(CliprdrError::InvalidRequest {
                description: format!(
                    "file descriptor request too large for worker: {} > {}",
                    file_descriptor_pdu.len(),
                    MAX_FILE_DESCRIPTOR_PDU_BYTES
                ),
            });
        }

        static WORKER: OnceLock<parking_lot::Mutex<Option<FileDescriptorWorker>>> = OnceLock::new();
        let worker = WORKER.get_or_init(|| parking_lot::Mutex::new(None));
        let Some(mut guard) = worker.try_lock() else {
            return Err(common_error(
                "file descriptor worker busy; refusing to queue peer descriptor parse".to_string(),
            ));
        };
        if guard.is_none() {
            *guard = Some(FileDescriptorWorker::spawn()?);
        }
        let Some(worker) = guard.as_mut() else {
            return Err(common_error(
                "native file descriptor worker unavailable".to_string(),
            ));
        };
        match worker.parse(conn_id, file_descriptor_pdu) {
            Ok(files) => Ok(files),
            Err(err) => {
                *guard = None;
                Err(err)
            }
        }
    }

    fn parse_file_descriptor(
        bytes: &mut Bytes,
        conn_id: i32,
    ) -> Result<FileDescription, CliprdrError> {
        let flags = bytes.get_u32_le();
        // skip reserved 32 bytes
        bytes.advance(32);
        let attributes = bytes.get_u32_le();

        // in original specification, this is 16 bytes reserved
        // we use the last 4 bytes to store the file mode
        // skip reserved 12 bytes
        bytes.advance(12);
        let perm = bytes.get_u32_le() as u16;

        // last write time from 1601-01-01 00:00:00, in 100ns
        let last_write_time = bytes.get_u64_le();
        // file size
        let file_size_high = bytes.get_u32_le();
        let file_size_low = bytes.get_u32_le();
        // utf16 file name, double \0 terminated, in 520 bytes block
        // read with another pointer, and advance the main pointer
        let block = bytes.clone();
        bytes.advance(520);

        let block = &block[..520];
        let wstr = WStr::from_utf16le(block).map_err(|e| {
            log::error!("cannot convert file descriptor path: {:?}", e);
            CliprdrError::ConversionFailure
        })?;

        let from_unix = flags & FLAGS_FD_UNIX_MODE != 0;

        let valid_attributes = flags & FLAGS_FD_ATTRIBUTES != 0;
        if !valid_attributes {
            return Err(CliprdrError::InvalidRequest {
                description: "file description must have valid attributes".to_string(),
            });
        }

        // todo: check normal, hidden, system, readonly, archive...
        let directory = attributes & 0x10 != 0;
        let normal = attributes == 0x80;
        let hidden = attributes & 0x02 != 0;
        let readonly = attributes & 0x01 != 0;

        let perm = if from_unix {
            // as is
            perm
            // cannot set as is...
        } else if normal {
            PERM_RWX
        } else if readonly {
            PERM_READ
        } else if hidden {
            PERM_SELF_RO
        } else if directory {
            PERM_RWX
        } else {
            PERM_RW
        };

        let kind = if directory {
            FileType::Directory
        } else {
            FileType::File
        };

        // to-do: use `let valid_size = flags & FLAGS_FD_SIZE != 0;`
        // We use `true` to for compatibility with Windows.
        // let valid_size = flags & FLAGS_FD_SIZE != 0;
        let valid_size = true;
        let size = if valid_size {
            ((file_size_high as u64) << 32) + file_size_low as u64
        } else {
            0
        };

        let valid_write_time = flags & FLAGS_FD_LAST_WRITE != 0;
        let last_modified = if valid_write_time && last_write_time >= LDAP_EPOCH_DELTA {
            let last_write_time = (last_write_time - LDAP_EPOCH_DELTA) * 100;
            let last_write_time = Duration::from_nanos(last_write_time);
            SystemTime::UNIX_EPOCH + last_write_time
        } else {
            SystemTime::UNIX_EPOCH
        };

        let name = wstr.to_utf8().replace('\\', "/");
        let name = PathBuf::from(name.trim_end_matches('\0'));

        let desc = FileDescription {
            conn_id,
            name,
            kind,
            atime: last_modified,
            last_modified,
            last_metadata_changed: last_modified,
            creation_time: last_modified,
            size,
            perm,
        };

        Ok(desc)
    }

    /// parse file descriptions from a format data response PDU
    /// which containing a CSPTR_FILEDESCRIPTORW indicated format data
    pub fn parse_file_descriptors(
        file_descriptor_pdu: Vec<u8>,
        conn_id: i32,
    ) -> Result<Vec<Self>, CliprdrError> {
        let mut data = Bytes::from(file_descriptor_pdu);
        if data.remaining() < 4 {
            return Err(CliprdrError::InvalidRequest {
                description: "file descriptor request with infficient length".to_string(),
            });
        }

        let count = data.get_u32_le() as usize;
        if data.remaining() == 0 && count == 0 {
            return Ok(Vec::new());
        }

        if count > MAX_FILE_DESCRIPTORS {
            return Err(CliprdrError::InvalidRequest {
                description: format!(
                    "file descriptor request with too many descriptors: {} > {}",
                    count, MAX_FILE_DESCRIPTORS
                ),
            });
        }

        let Some(expected_len) = FILE_DESCRIPTOR_SIZE.checked_mul(count) else {
            return Err(CliprdrError::InvalidRequest {
                description: "file descriptor request with overflowing length".to_string(),
            });
        };
        if data.remaining() != expected_len {
            return Err(CliprdrError::InvalidRequest {
                description: "file descriptor request with invalid length".to_string(),
            });
        }

        let mut files = Vec::with_capacity(count);
        for _ in 0..count {
            let desc = Self::parse_file_descriptor(&mut data, conn_id)?;
            files.push(desc);
        }

        Ok(files)
    }
}

struct FileDescriptorWorker {
    child: Child,
    _process_guard: hbb_common::native_worker_sandbox::WorkerProcessGuard,
    io_tx: SyncSender<FileDescriptorWorkerIoRequest>,
}

struct FileDescriptorWorkerIoRequest {
    conn_id: i32,
    payload: Vec<u8>,
    reply: mpsc::Sender<Result<Vec<FileDescription>, CliprdrError>>,
}

impl Drop for FileDescriptorWorker {
    fn drop(&mut self) {
        self.kill_child();
    }
}

impl FileDescriptorWorker {
    fn spawn() -> Result<Self, CliprdrError> {
        let exe = std::env::current_exe().map_err(|e| {
            common_error(format!(
                "failed to resolve current executable for file descriptor worker: {e}"
            ))
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
            .map_err(|e| common_error(format!("failed to spawn file descriptor worker: {e}")))?;
        let process_guard =
            match hbb_common::native_worker_sandbox::apply_to_spawned_child(&mut child) {
                Ok(process_guard) => process_guard,
                Err(err) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(common_error(format!(
                        "failed to constrain file descriptor worker: {err}"
                    )));
                }
            };
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| common_error("file descriptor worker stdin unavailable".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| common_error("file descriptor worker stdout unavailable".to_string()))?;
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

    fn parse(
        &mut self,
        conn_id: i32,
        payload: Vec<u8>,
    ) -> Result<Vec<FileDescription>, CliprdrError> {
        let (tx, rx) = mpsc::channel();
        self.io_tx
            .send(FileDescriptorWorkerIoRequest {
                conn_id,
                payload,
                reply: tx,
            })
            .map_err(|_| {
                common_error("file descriptor worker I/O thread unavailable".to_string())
            })?;

        match rx.recv_timeout(WORKER_PARSE_TIMEOUT) {
            Ok(Ok(files)) => Ok(files),
            Ok(Err(err)) => {
                self.kill_child();
                Err(err)
            }
            Err(RecvTimeoutError::Timeout) => {
                self.kill_child();
                Err(common_error(format!(
                    "file descriptor worker parse timed out after {:?}; killed child",
                    WORKER_PARSE_TIMEOUT
                )))
            }
            Err(RecvTimeoutError::Disconnected) => {
                self.kill_child();
                Err(common_error(
                    "file descriptor worker I/O thread exited without a response".to_string(),
                ))
            }
        }
    }
}

fn spawn_worker_io_thread(
    mut stdin: ChildStdin,
    mut stdout: ChildStdout,
) -> Result<SyncSender<FileDescriptorWorkerIoRequest>, CliprdrError> {
    let (tx, rx) = mpsc::sync_channel::<FileDescriptorWorkerIoRequest>(1);
    std::thread::Builder::new()
        .name("rd-native-filedesc-io".to_owned())
        .spawn(move || {
            while let Ok(request) = rx.recv() {
                let result =
                    worker_round_trip(&mut stdin, &mut stdout, request.conn_id, &request.payload);
                let _ = request.reply.send(result);
            }
        })
        .map_err(|e| {
            common_error(format!(
                "failed to spawn file descriptor worker I/O thread: {e}"
            ))
        })?;
    Ok(tx)
}

fn worker_loop<R, W>(mut input: R, mut output: W) -> Result<(), CliprdrError>
where
    R: Read,
    W: Write,
{
    loop {
        let request = match read_worker_request(&mut input) {
            Ok(request) => request,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => {
                return Err(common_error(format!(
                    "failed to read file descriptor worker request: {err}"
                )));
            }
        };
        match FileDescription::parse_file_descriptors(request.payload, request.conn_id) {
            Ok(files) => write_worker_response(&mut output, STATUS_PARSED, &files, "")?,
            Err(err) => write_worker_response(
                &mut output,
                STATUS_ERROR,
                &Vec::<FileDescription>::new(),
                &err.to_string(),
            )?,
        }
        output.flush().map_err(|e| {
            common_error(format!(
                "failed to flush file descriptor worker response: {e}"
            ))
        })?;
    }
}

struct WorkerRequest {
    conn_id: i32,
    payload: Vec<u8>,
}

fn read_worker_request<R: Read>(reader: &mut R) -> io::Result<WorkerRequest> {
    let magic = read_array::<4, _>(reader)?;
    if magic != REQUEST_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad file descriptor worker request magic",
        ));
    }
    let version = read_u8(reader)?;
    if version != PROTOCOL_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported file descriptor worker protocol version",
        ));
    }
    let op = read_u8(reader)?;
    if op != OP_PARSE_FILE_DESCRIPTORS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported file descriptor worker operation",
        ));
    }
    let _reserved = read_u8(reader)?;
    let conn_id = read_i32(reader)?;
    let len = read_u32(reader)? as usize;
    if len > MAX_FILE_DESCRIPTOR_PDU_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized file descriptor worker request",
        ));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(WorkerRequest { conn_id, payload })
}

fn write_worker_request<W: Write>(
    writer: &mut W,
    conn_id: i32,
    data: &[u8],
) -> Result<(), CliprdrError> {
    if data.len() > MAX_FILE_DESCRIPTOR_PDU_BYTES {
        return Err(CliprdrError::InvalidRequest {
            description: format!(
                "file descriptor worker request too large: {} > {}",
                data.len(),
                MAX_FILE_DESCRIPTOR_PDU_BYTES
            ),
        });
    }
    writer.write_all(&REQUEST_MAGIC).map_err(io_error)?;
    writer
        .write_all(&[PROTOCOL_VERSION, OP_PARSE_FILE_DESCRIPTORS, 0])
        .map_err(io_error)?;
    write_i32(writer, conn_id).map_err(io_error)?;
    write_u32(writer, data.len() as u32).map_err(io_error)?;
    writer.write_all(data).map_err(io_error)?;
    writer.flush().map_err(io_error)
}

fn worker_round_trip<R, W>(
    writer: &mut W,
    reader: &mut R,
    conn_id: i32,
    data: &[u8],
) -> Result<Vec<FileDescription>, CliprdrError>
where
    R: Read,
    W: Write,
{
    write_worker_request(writer, conn_id, data)?;
    read_worker_response(reader)
}

fn write_worker_response<W: Write>(
    writer: &mut W,
    status: u8,
    files: &[FileDescription],
    message: &str,
) -> Result<(), CliprdrError> {
    let payload = if status == STATUS_PARSED {
        hbb_common::serde_json::to_vec(files).map_err(|e| {
            common_error(format!("failed to serialize file descriptor response: {e}"))
        })?
    } else {
        let message = message.as_bytes();
        if message.len() > MAX_WORKER_ERROR_BYTES {
            return Err(common_error(
                "file descriptor worker error message too large".to_string(),
            ));
        }
        message.to_vec()
    };
    if payload.len() > MAX_WORKER_RESPONSE_BYTES {
        return Err(common_error(format!(
            "file descriptor worker response too large: {} > {}",
            payload.len(),
            MAX_WORKER_RESPONSE_BYTES
        )));
    }
    writer.write_all(&RESPONSE_MAGIC).map_err(io_error)?;
    writer
        .write_all(&[PROTOCOL_VERSION, status, 0, 0])
        .map_err(io_error)?;
    write_u32(writer, payload.len() as u32).map_err(io_error)?;
    writer.write_all(&payload).map_err(io_error)
}

fn read_worker_response<R: Read>(reader: &mut R) -> Result<Vec<FileDescription>, CliprdrError> {
    let magic = read_array::<4, _>(reader).map_err(io_error)?;
    if magic != RESPONSE_MAGIC {
        return Err(common_error(
            "bad file descriptor worker response magic".to_string(),
        ));
    }
    let version = read_u8(reader).map_err(io_error)?;
    if version != PROTOCOL_VERSION {
        return Err(common_error(format!(
            "unsupported file descriptor worker response version {version}"
        )));
    }
    let status = read_u8(reader).map_err(io_error)?;
    let _reserved0 = read_u8(reader).map_err(io_error)?;
    let _reserved1 = read_u8(reader).map_err(io_error)?;
    let len = read_u32(reader).map_err(io_error)? as usize;
    if len > MAX_WORKER_RESPONSE_BYTES {
        return Err(common_error(format!(
            "file descriptor worker response too large: {len} > {MAX_WORKER_RESPONSE_BYTES}"
        )));
    }
    if status == STATUS_ERROR && len > MAX_WORKER_ERROR_BYTES {
        return Err(common_error(
            "file descriptor worker error message too large".to_string(),
        ));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).map_err(io_error)?;
    match status {
        STATUS_PARSED => hbb_common::serde_json::from_slice::<Vec<FileDescription>>(&payload)
            .map_err(|e| common_error(format!("failed to parse file descriptor worker JSON: {e}"))),
        STATUS_ERROR => Err(CliprdrError::InvalidRequest {
            description: String::from_utf8_lossy(&payload).to_string(),
        }),
        status => Err(common_error(format!(
            "file descriptor worker returned unknown status {status}"
        ))),
    }
}

fn read_array<const N: usize, R: Read>(reader: &mut R) -> io::Result<[u8; N]> {
    let mut value = [0u8; N];
    reader.read_exact(&mut value)?;
    Ok(value)
}

fn read_u8<R: Read>(reader: &mut R) -> io::Result<u8> {
    Ok(read_array::<1, _>(reader)?[0])
}

fn read_u32<R: Read>(reader: &mut R) -> io::Result<u32> {
    Ok(u32::from_le_bytes(read_array::<4, _>(reader)?))
}

fn read_i32<R: Read>(reader: &mut R) -> io::Result<i32> {
    Ok(i32::from_le_bytes(read_array::<4, _>(reader)?))
}

fn write_u32<W: Write>(writer: &mut W, value: u32) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn write_i32<W: Write>(writer: &mut W, value: i32) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn io_error(err: io::Error) -> CliprdrError {
    common_error(format!("file descriptor worker I/O failed: {err}"))
}

fn common_error(description: String) -> CliprdrError {
    CliprdrError::CommonError { description }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::bytes::{BufMut, BytesMut};

    fn descriptor_pdu(name: &str) -> Vec<u8> {
        let mut out = BytesMut::with_capacity(4 + FILE_DESCRIPTOR_SIZE);
        out.put_u32_le(1);
        out.put_u32_le(FLAGS_FD_ATTRIBUTES | FLAGS_FD_LAST_WRITE | FLAGS_FD_UNIX_MODE);
        out.put(&[0u8; 32][..]);
        out.put_u32_le(0x80);
        out.put(&[0u8; 12][..]);
        out.put_u32_le(0o644);
        out.put_u64_le(LDAP_EPOCH_DELTA);
        out.put_u32_le(0);
        out.put_u32_le(7);
        let mut name_bytes = Vec::new();
        for unit in name.encode_utf16() {
            name_bytes.extend_from_slice(&unit.to_le_bytes());
        }
        assert!(name_bytes.len() <= 520);
        out.put(&name_bytes[..]);
        out.put(&vec![0u8; 520 - name_bytes.len()][..]);
        out.to_vec()
    }

    #[test]
    fn file_descriptor_worker_loop_parses_valid_pdu() {
        let pdu = descriptor_pdu("a.txt");
        let mut request = Vec::new();
        write_worker_request(&mut request, 42, &pdu).expect("write descriptor worker request");

        let mut response = Vec::new();
        worker_loop(&request[..], &mut response).expect("run descriptor worker loop");
        let parsed = read_worker_response(&mut &response[..]).expect("read descriptor response");

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].conn_id, 42);
        assert_eq!(parsed[0].name, PathBuf::from("a.txt"));
        assert_eq!(parsed[0].size, 7);
        assert_eq!(parsed[0].perm, 0o644);
    }

    #[test]
    fn file_descriptor_worker_loop_reports_parse_error() {
        let mut request = Vec::new();
        write_worker_request(&mut request, 42, &[0, 0, 0]).expect("write bad request");

        let mut response = Vec::new();
        worker_loop(&request[..], &mut response).expect("run descriptor worker loop");

        assert!(read_worker_response(&mut &response[..]).is_err());
    }
}
