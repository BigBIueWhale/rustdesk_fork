use super::local_file::LocalFile;
use crate::{platform::unix::local_file::construct_file_list, ClipboardFile, CliprdrError};
use hbb_common::{
    bytes::{BufMut, BytesMut},
    log,
};
use serde_derive::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    io::{self, Read, Write},
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{
        mpsc::{self, RecvTimeoutError, SyncSender},
        OnceLock,
    },
    time::{Duration, Instant},
    usize,
};

const FILE_CONTENT_REQUEST_WINDOW: Duration = Duration::from_secs(10);
const MAX_FILE_CONTENT_REQUESTS_PER_CONN_WINDOW: usize = 512;
const MAX_FILE_CONTENT_BYTES_PER_CONN_WINDOW: u64 = 1024 * 1024 * 1024;
const MAX_FILE_CONTENT_RESPONSE_BYTES: u64 = super::BLOCK_SIZE as u64;
const WORKER_ARG: &str = "--native-filecontents-worker";
const WORKER_ROUND_TRIP_TIMEOUT: Duration = Duration::from_secs(30);
const PROTOCOL_VERSION: u8 = 1;
const REQUEST_MAGIC: [u8; 4] = *b"RCFW";
const RESPONSE_MAGIC: [u8; 4] = *b"RCFR";
const RESPONSE_STATUS_OK: u8 = 0;
const RESPONSE_STATUS_ERROR: u8 = 1;
const RESPONSE_STATUS_FILE_LIST_PDU: u8 = 2;
const RESPONSE_STATUS_FILE_CONTENTS: u8 = 3;
const FILE_CONTENT_RESULT_RESPONSE: u8 = 0;
const FILE_CONTENT_RESULT_FILES: u8 = 1;
const FILE_CONTENT_RESULT_ERROR: u8 = 2;
const MAX_WORKER_REQUEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_WORKER_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const MAX_WORKER_ERROR_BYTES: usize = 64 * 1024;

pub fn file_contents_worker_arg() -> &'static str {
    WORKER_ARG
}

pub fn run_file_contents_worker() -> Result<(), CliprdrError> {
    hbb_common::native_worker_sandbox::enter_worker_process()
        .map_err(|e| common_error(format!("failed to enter file-content worker sandbox: {e}")))?;
    worker_loop(std::io::stdin(), std::io::stdout())
}

#[derive(Debug)]
enum FileContentsRequest {
    Size {
        stream_id: i32,
        file_idx: usize,
    },

    Range {
        stream_id: i32,
        file_idx: usize,
        offset: u64,
        length: u64,
    },
}

impl FileContentsRequest {
    fn accounting_cost(&self) -> u64 {
        match self {
            FileContentsRequest::Size { .. } => 8,
            FileContentsRequest::Range { length, .. } => *length,
        }
    }
}

#[derive(Default)]
struct FileRequestAccounting {
    requests: VecDeque<(Instant, u64)>,
}

impl FileRequestAccounting {
    fn prune(&mut self, now: Instant) {
        while let Some((created, _)) = self.requests.front() {
            if now.duration_since(*created) <= FILE_CONTENT_REQUEST_WINDOW {
                break;
            }
            self.requests.pop_front();
        }
    }

    fn total_bytes(&self) -> u64 {
        self.requests
            .iter()
            .fold(0u64, |total, (_, bytes)| total.saturating_add(*bytes))
    }
}

#[derive(Default)]
struct ClipFiles {
    files: Vec<String>,
    file_list: Vec<LocalFile>,
    first_file_index: usize,
    files_pdu: Vec<u8>,
    request_accounting: HashMap<i32, FileRequestAccounting>,
}

impl ClipFiles {
    fn clear(&mut self) {
        self.files.clear();
        self.file_list.clear();
        self.first_file_index = usize::MAX;
        self.files_pdu.clear();
        self.request_accounting.clear();
    }

    fn sync_files(&mut self, clipboard_files: &[String]) -> Result<(), CliprdrError> {
        let clipboard_paths = clipboard_files
            .iter()
            .map(|s| PathBuf::from(s))
            .collect::<Vec<_>>();
        self.file_list = construct_file_list(&clipboard_paths)?;
        self.first_file_index = self
            .file_list
            .iter()
            .position(|f| !f.path.is_dir())
            .unwrap_or(usize::MAX);
        self.files = clipboard_files.to_vec();
        self.request_accounting.clear();
        Ok(())
    }

    fn build_file_list_pdu(&mut self) {
        let mut data = BytesMut::with_capacity(4 + 592 * self.file_list.len());
        data.put_u32_le(self.file_list.len() as u32);
        for file in self.file_list.iter() {
            data.put(file.as_bin().as_slice());
        }
        self.files_pdu = data.to_vec()
    }

    fn get_files_for_audit(&self, request: &FileContentsRequest) -> Option<ClipboardFile> {
        if let FileContentsRequest::Range {
            file_idx, offset, ..
        } = request
        {
            if *file_idx == self.first_file_index && *offset == 0 {
                let files: Vec<(String, u64)> = self
                    .file_list
                    .iter()
                    .filter_map(|f| {
                        if f.path.is_file() {
                            Some((f.path.to_string_lossy().to_string(), f.size))
                        } else {
                            None
                        }
                    })
                    .collect::<_>();
                if files.is_empty() {
                    return None;
                } else {
                    return Some(ClipboardFile::Files { files });
                }
            }
        }
        None
    }

    fn serve_file_contents(
        &mut self,
        conn_id: i32,
        request: FileContentsRequest,
    ) -> Result<ClipboardFile, CliprdrError> {
        let (file_idx, file_contents_resp) = match request {
            FileContentsRequest::Size {
                stream_id,
                file_idx,
            } => {
                log::debug!("file contents (size) requested from conn: {}", conn_id);
                let Some(file) = self.file_list.get(file_idx) else {
                    log::error!(
                        "invalid file index {} requested from conn: {}",
                        file_idx,
                        conn_id
                    );
                    return Err(CliprdrError::InvalidRequest {
                        description: format!(
                            "invalid file index {} requested from conn: {}",
                            file_idx, conn_id
                        ),
                    });
                };

                log::debug!(
                    "conn {} requested file-{}: {}",
                    conn_id,
                    file_idx,
                    file.name
                );

                let size = file.size;
                (
                    file_idx,
                    ClipboardFile::FileContentsResponse {
                        msg_flags: 0x1,
                        stream_id,
                        requested_data: size.to_le_bytes().to_vec(),
                    },
                )
            }
            FileContentsRequest::Range {
                stream_id,
                file_idx,
                offset,
                length,
            } => {
                log::debug!(
                    "file contents (range from {} length {}) request from conn: {}",
                    offset,
                    length,
                    conn_id
                );
                let Some(file) = self.file_list.get_mut(file_idx) else {
                    log::error!(
                        "invalid file index {} requested from conn: {}",
                        file_idx,
                        conn_id
                    );
                    return Err(CliprdrError::InvalidRequest {
                        description: format!(
                            "invalid file index {} requested from conn: {}",
                            file_idx, conn_id
                        ),
                    });
                };
                log::debug!(
                    "conn {} requested file-{}: {}",
                    conn_id,
                    file_idx,
                    file.name
                );

                if offset > file.size {
                    log::error!("invalid reading offset requested from conn: {}", conn_id);
                    return Err(CliprdrError::InvalidRequest {
                        description: format!(
                            "invalid reading offset requested from conn: {}",
                            conn_id
                        ),
                    });
                }
                let Some(end) = offset.checked_add(length) else {
                    log::error!("overflowing reading range requested from conn: {}", conn_id);
                    return Err(CliprdrError::InvalidRequest {
                        description: format!(
                            "overflowing reading range requested from conn: {}",
                            conn_id
                        ),
                    });
                };
                let read_size = if end > file.size {
                    file.size - offset
                } else {
                    length
                };

                let mut buf = vec![0u8; read_size as usize];

                file.read_exact_at(&mut buf, offset)?;

                (
                    file_idx,
                    ClipboardFile::FileContentsResponse {
                        msg_flags: 0x1,
                        stream_id,
                        requested_data: buf,
                    },
                )
            }
        };

        log::debug!("file contents sent to conn: {}", conn_id);
        // hot reload next file
        for next_file in self.file_list.iter_mut().skip(file_idx + 1) {
            if !next_file.is_dir {
                next_file.load_handle()?;
                break;
            }
        }
        Ok(file_contents_resp)
    }

    fn admit_file_content_request(
        &mut self,
        conn_id: i32,
        requested_bytes: u64,
    ) -> Result<(), CliprdrError> {
        let now = Instant::now();
        let accounting = self.request_accounting.entry(conn_id).or_default();
        accounting.prune(now);
        if accounting.requests.len() >= MAX_FILE_CONTENT_REQUESTS_PER_CONN_WINDOW {
            return Err(CliprdrError::InvalidRequest {
                description: format!(
                    "too many file-content requests from conn {} in the accounting window",
                    conn_id
                ),
            });
        }
        let next_total = accounting.total_bytes().saturating_add(requested_bytes);
        if next_total > MAX_FILE_CONTENT_BYTES_PER_CONN_WINDOW {
            return Err(CliprdrError::InvalidRequest {
                description: format!(
                    "too many file-content bytes requested from conn {} in the accounting window",
                    conn_id
                ),
            });
        }
        accounting.requests.push_back((now, requested_bytes));
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", content = "c")]
enum WorkerRequest {
    Clear,
    SyncFiles {
        files: Vec<String>,
    },
    GetFileListPdu,
    ReadFileContents {
        conn_id: i32,
        stream_id: i32,
        list_index: i32,
        dw_flags: i32,
        n_position_low: i32,
        n_position_high: i32,
        cb_requested: i32,
    },
}

#[derive(Debug, Clone)]
enum WorkerResponse {
    Ok,
    Error {
        description: String,
    },
    FileListPdu {
        pdu: Vec<u8>,
    },
    FileContents {
        results: Vec<WorkerFileContentResult>,
    },
}

#[derive(Debug, Clone)]
enum WorkerFileContentResult {
    Success { value: ClipboardFile },
    Failure { description: String },
}

impl WorkerFileContentResult {
    fn from_result(result: Result<ClipboardFile, CliprdrError>) -> Self {
        match result {
            Ok(value) => Self::Success { value },
            Err(err) => Self::Failure {
                description: err.to_string(),
            },
        }
    }

    fn into_result(self) -> Result<ClipboardFile, CliprdrError> {
        match self {
            Self::Success { value } => Ok(value),
            Self::Failure { description } => Err(invalid_request(description)),
        }
    }
}

fn parse_file_content_request(
    stream_id: i32,
    list_index: i32,
    dw_flags: i32,
    n_position_low: i32,
    n_position_high: i32,
    cb_requested: i32,
) -> Result<FileContentsRequest, CliprdrError> {
    if list_index < 0 {
        return Err(invalid_request(format!(
            "got invalid FileContentsRequest with negative list_index: {list_index}"
        )));
    }

    if dw_flags == 0x1 {
        Ok(FileContentsRequest::Size {
            stream_id,
            file_idx: list_index as usize,
        })
    } else if dw_flags == 0x2 {
        if cb_requested < 0 {
            return Err(invalid_request(format!(
                "got invalid FileContentsRequest with negative cb_requested: {cb_requested}"
            )));
        }
        let offset = ((n_position_high as u32 as u64) << 32) | n_position_low as u32 as u64;
        let length = cb_requested as u64;
        if length > MAX_FILE_CONTENT_RESPONSE_BYTES {
            return Err(invalid_request(format!(
                "got oversized FileContentsRequest: {length} > {MAX_FILE_CONTENT_RESPONSE_BYTES}"
            )));
        }
        if offset.checked_add(length).is_none() {
            return Err(invalid_request(
                "got overflowing FileContentsRequest range".to_string(),
            ));
        }

        Ok(FileContentsRequest::Range {
            stream_id,
            file_idx: list_index as usize,
            offset,
            length,
        })
    } else {
        Err(invalid_request(format!(
            "got invalid FileContentsRequest, dw_flags: {dw_flags}"
        )))
    }
}

struct FileContentsWorker {
    child: Child,
    _process_guard: hbb_common::native_worker_sandbox::WorkerProcessGuard,
    io_tx: SyncSender<FileContentWorkerIoRequest>,
}

struct FileContentWorkerIoRequest {
    request: WorkerRequest,
    reply: mpsc::Sender<Result<WorkerResponse, CliprdrError>>,
}

impl Drop for FileContentsWorker {
    fn drop(&mut self) {
        self.kill_child();
    }
}

impl FileContentsWorker {
    fn spawn() -> Result<Self, CliprdrError> {
        let exe = std::env::current_exe().map_err(|e| {
            common_error(format!(
                "failed to resolve current executable for file-content worker: {e}"
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
            .map_err(|e| common_error(format!("failed to spawn file-content worker: {e}")))?;
        let process_guard =
            match hbb_common::native_worker_sandbox::apply_to_spawned_child(&mut child) {
                Ok(process_guard) => process_guard,
                Err(err) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(common_error(format!(
                        "failed to constrain file-content worker: {err}"
                    )));
                }
            };
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| common_error("file-content worker stdin unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| common_error("file-content worker stdout unavailable"))?;
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

    fn request(&mut self, request: WorkerRequest) -> Result<WorkerResponse, CliprdrError> {
        let (tx, rx) = mpsc::channel();
        self.io_tx
            .send(FileContentWorkerIoRequest { request, reply: tx })
            .map_err(|_| common_error("file-content worker I/O thread unavailable"))?;

        match rx.recv_timeout(WORKER_ROUND_TRIP_TIMEOUT) {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(err)) => {
                self.kill_child();
                Err(err)
            }
            Err(RecvTimeoutError::Timeout) => {
                self.kill_child();
                Err(common_error(format!(
                    "file-content worker round-trip timed out after {:?}; killed child",
                    WORKER_ROUND_TRIP_TIMEOUT
                )))
            }
            Err(RecvTimeoutError::Disconnected) => {
                self.kill_child();
                Err(common_error(
                    "file-content worker I/O thread exited without a response",
                ))
            }
        }
    }
}

fn worker_request(request: WorkerRequest) -> Result<WorkerResponse, CliprdrError> {
    static WORKER: OnceLock<parking_lot::Mutex<Option<FileContentsWorker>>> = OnceLock::new();
    let worker = WORKER.get_or_init(|| parking_lot::Mutex::new(None));
    let Some(mut guard) = worker.try_lock() else {
        return Err(common_error(
            "file-content worker busy; refusing to queue peer file-content request",
        ));
    };
    if guard.is_none() {
        *guard = Some(FileContentsWorker::spawn()?);
    }
    let Some(worker) = guard.as_mut() else {
        return Err(common_error("native file-content worker unavailable"));
    };
    match worker.request(request) {
        Ok(response) => Ok(response),
        Err(err) => {
            *guard = None;
            Err(err)
        }
    }
}

fn spawn_worker_io_thread(
    mut stdin: ChildStdin,
    mut stdout: ChildStdout,
) -> Result<SyncSender<FileContentWorkerIoRequest>, CliprdrError> {
    let (tx, rx) = mpsc::sync_channel::<FileContentWorkerIoRequest>(1);
    std::thread::Builder::new()
        .name("rd-native-filecontent-io".to_owned())
        .spawn(move || {
            while let Ok(request) = rx.recv() {
                let result = worker_round_trip(&mut stdin, &mut stdout, &request.request);
                let _ = request.reply.send(result);
            }
        })
        .map_err(|e| {
            common_error(format!(
                "failed to spawn file-content worker I/O thread: {e}"
            ))
        })?;
    Ok(tx)
}

fn worker_loop<R, W>(mut input: R, mut output: W) -> Result<(), CliprdrError>
where
    R: Read,
    W: Write,
{
    let mut clip_files = ClipFiles::default();
    loop {
        let request = match read_worker_request(&mut input) {
            Ok(request) => request,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => {
                return Err(common_error(format!(
                    "failed to read file-content worker request: {err}"
                )));
            }
        };
        let response = handle_worker_request(&mut clip_files, request);
        write_worker_response(&mut output, &response)?;
        output.flush().map_err(|e| {
            common_error(format!("failed to flush file-content worker response: {e}"))
        })?;
    }
}

fn handle_worker_request(clip_files: &mut ClipFiles, request: WorkerRequest) -> WorkerResponse {
    match request {
        WorkerRequest::Clear => {
            clip_files.clear();
            WorkerResponse::Ok
        }
        WorkerRequest::SyncFiles { files } => {
            if clip_files.files != files {
                if let Err(err) = clip_files.sync_files(&files) {
                    return WorkerResponse::Error {
                        description: err.to_string(),
                    };
                }
                clip_files.build_file_list_pdu();
            }
            WorkerResponse::Ok
        }
        WorkerRequest::GetFileListPdu => WorkerResponse::FileListPdu {
            pdu: clip_files.files_pdu.clone(),
        },
        WorkerRequest::ReadFileContents {
            conn_id,
            stream_id,
            list_index,
            dw_flags,
            n_position_low,
            n_position_high,
            cb_requested,
        } => {
            let fcr = match parse_file_content_request(
                stream_id,
                list_index,
                dw_flags,
                n_position_low,
                n_position_high,
                cb_requested,
            ) {
                Ok(request) => request,
                Err(err) => {
                    return WorkerResponse::FileContents {
                        results: vec![WorkerFileContentResult::from_result(Err(err))],
                    };
                }
            };

            let mut results = Vec::new();
            if let Err(err) = clip_files.admit_file_content_request(conn_id, fcr.accounting_cost())
            {
                results.push(WorkerFileContentResult::from_result(Err(err)));
                return WorkerResponse::FileContents { results };
            }
            if let Some(files_res) = clip_files.get_files_for_audit(&fcr) {
                results.push(WorkerFileContentResult::from_result(Ok(files_res)));
            }
            results.push(WorkerFileContentResult::from_result(
                clip_files.serve_file_contents(conn_id, fcr),
            ));
            WorkerResponse::FileContents { results }
        }
    }
}

fn read_worker_request<R: Read>(reader: &mut R) -> io::Result<WorkerRequest> {
    let magic = read_array::<4, _>(reader)?;
    if magic != REQUEST_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad file-content worker request magic",
        ));
    }
    let version = read_u8(reader)?;
    if version != PROTOCOL_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported file-content worker protocol version",
        ));
    }
    let _reserved0 = read_u8(reader)?;
    let _reserved1 = read_u8(reader)?;
    let _reserved2 = read_u8(reader)?;
    let len = read_u32(reader)? as usize;
    if len > MAX_WORKER_REQUEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized file-content worker request",
        ));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    hbb_common::serde_json::from_slice::<WorkerRequest>(&payload).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad file-content worker request JSON: {e}"),
        )
    })
}

fn write_worker_request<W: Write>(
    writer: &mut W,
    request: &WorkerRequest,
) -> Result<(), CliprdrError> {
    let payload = hbb_common::serde_json::to_vec(request)
        .map_err(|e| common_error(format!("failed to serialize file-content request: {e}")))?;
    if payload.len() > MAX_WORKER_REQUEST_BYTES {
        return Err(CliprdrError::InvalidRequest {
            description: format!(
                "file-content worker request too large: {} > {}",
                payload.len(),
                MAX_WORKER_REQUEST_BYTES
            ),
        });
    }
    writer.write_all(&REQUEST_MAGIC).map_err(io_error)?;
    writer
        .write_all(&[PROTOCOL_VERSION, 0, 0, 0])
        .map_err(io_error)?;
    write_u32(writer, payload.len() as u32).map_err(io_error)?;
    writer.write_all(&payload).map_err(io_error)?;
    writer.flush().map_err(io_error)
}

fn worker_round_trip<R, W>(
    writer: &mut W,
    reader: &mut R,
    request: &WorkerRequest,
) -> Result<WorkerResponse, CliprdrError>
where
    R: Read,
    W: Write,
{
    write_worker_request(writer, request)?;
    read_worker_response(reader)
}

fn write_worker_response<W: Write>(
    writer: &mut W,
    response: &WorkerResponse,
) -> Result<(), CliprdrError> {
    let (status, payload) = encode_worker_response(response)?;
    if payload.len() > MAX_WORKER_RESPONSE_BYTES {
        return Err(common_error(format!(
            "file-content worker response too large: {} > {}",
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

fn encode_worker_response(response: &WorkerResponse) -> Result<(u8, Vec<u8>), CliprdrError> {
    match response {
        WorkerResponse::Ok => Ok((RESPONSE_STATUS_OK, Vec::new())),
        WorkerResponse::Error { description } => {
            let payload = description.as_bytes();
            if payload.len() > MAX_WORKER_ERROR_BYTES {
                return Err(common_error("file-content worker error message too large"));
            }
            Ok((RESPONSE_STATUS_ERROR, payload.to_vec()))
        }
        WorkerResponse::FileListPdu { pdu } => Ok((RESPONSE_STATUS_FILE_LIST_PDU, pdu.clone())),
        WorkerResponse::FileContents { results } => {
            let mut payload = Vec::new();
            if results.len() > u32::MAX as usize {
                return Err(common_error("file-content worker result count too large"));
            }
            write_u32(&mut payload, results.len() as u32).map_err(io_error)?;
            for result in results {
                write_worker_file_content_result(&mut payload, result)?;
            }
            Ok((RESPONSE_STATUS_FILE_CONTENTS, payload))
        }
    }
}

fn write_worker_file_content_result<W: Write>(
    writer: &mut W,
    result: &WorkerFileContentResult,
) -> Result<(), CliprdrError> {
    match result {
        WorkerFileContentResult::Success { value } => match value {
            ClipboardFile::FileContentsResponse {
                msg_flags,
                stream_id,
                requested_data,
            } => {
                if requested_data.len() as u64 > MAX_FILE_CONTENT_RESPONSE_BYTES {
                    return Err(common_error(format!(
                        "file-content worker response data too large: {} > {}",
                        requested_data.len(),
                        MAX_FILE_CONTENT_RESPONSE_BYTES
                    )));
                }
                write_u8(writer, FILE_CONTENT_RESULT_RESPONSE).map_err(io_error)?;
                write_i32(writer, *msg_flags).map_err(io_error)?;
                write_i32(writer, *stream_id).map_err(io_error)?;
                write_bytes(
                    writer,
                    requested_data,
                    MAX_FILE_CONTENT_RESPONSE_BYTES as usize,
                )
                .map_err(io_error)
            }
            ClipboardFile::Files { files } => {
                write_u8(writer, FILE_CONTENT_RESULT_FILES).map_err(io_error)?;
                if files.len() > u32::MAX as usize {
                    return Err(common_error(
                        "file-content worker audit file count too large",
                    ));
                }
                write_u32(writer, files.len() as u32).map_err(io_error)?;
                for (path, size) in files {
                    write_string(writer, path, MAX_WORKER_RESPONSE_BYTES)?;
                    write_u64(writer, *size).map_err(io_error)?;
                }
                Ok(())
            }
            other => Err(common_error(format!(
                "file-content worker cannot encode unexpected clipboard result: {other:?}"
            ))),
        },
        WorkerFileContentResult::Failure { description } => {
            write_u8(writer, FILE_CONTENT_RESULT_ERROR).map_err(io_error)?;
            write_string(writer, description, MAX_WORKER_ERROR_BYTES)
        }
    }
}

fn read_worker_response<R: Read>(reader: &mut R) -> Result<WorkerResponse, CliprdrError> {
    let magic = read_array::<4, _>(reader).map_err(io_error)?;
    if magic != RESPONSE_MAGIC {
        return Err(common_error("bad file-content worker response magic"));
    }
    let version = read_u8(reader).map_err(io_error)?;
    if version != PROTOCOL_VERSION {
        return Err(common_error(format!(
            "unsupported file-content worker response version {version}"
        )));
    }
    let status = read_u8(reader).map_err(io_error)?;
    let _reserved1 = read_u8(reader).map_err(io_error)?;
    let _reserved2 = read_u8(reader).map_err(io_error)?;
    let len = read_u32(reader).map_err(io_error)? as usize;
    if len > MAX_WORKER_RESPONSE_BYTES {
        return Err(common_error(format!(
            "file-content worker response too large: {len} > {MAX_WORKER_RESPONSE_BYTES}"
        )));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).map_err(io_error)?;
    match status {
        RESPONSE_STATUS_OK => {
            if !payload.is_empty() {
                return Err(common_error(
                    "file-content worker Ok response carried a payload",
                ));
            }
            Ok(WorkerResponse::Ok)
        }
        RESPONSE_STATUS_ERROR => {
            if payload.len() > MAX_WORKER_ERROR_BYTES {
                return Err(common_error("file-content worker error message too large"));
            }
            Ok(WorkerResponse::Error {
                description: String::from_utf8_lossy(&payload).to_string(),
            })
        }
        RESPONSE_STATUS_FILE_LIST_PDU => Ok(WorkerResponse::FileListPdu { pdu: payload }),
        RESPONSE_STATUS_FILE_CONTENTS => {
            let mut payload = &payload[..];
            let count = read_u32(&mut payload).map_err(io_error)? as usize;
            if count > payload.len() {
                return Err(common_error(
                    "file-content worker FileContents response count exceeds payload",
                ));
            }
            let mut results = Vec::new();
            for _ in 0..count {
                results.push(read_worker_file_content_result(&mut payload)?);
            }
            if !payload.is_empty() {
                return Err(common_error(
                    "file-content worker FileContents response had trailing bytes",
                ));
            }
            Ok(WorkerResponse::FileContents { results })
        }
        status => Err(common_error(format!(
            "file-content worker returned unknown status {status}"
        ))),
    }
}

fn read_worker_file_content_result<R: Read>(
    reader: &mut R,
) -> Result<WorkerFileContentResult, CliprdrError> {
    match read_u8(reader).map_err(io_error)? {
        FILE_CONTENT_RESULT_RESPONSE => {
            let msg_flags = read_i32(reader).map_err(io_error)?;
            let stream_id = read_i32(reader).map_err(io_error)?;
            let requested_data =
                read_bytes(reader, MAX_FILE_CONTENT_RESPONSE_BYTES as usize).map_err(io_error)?;
            Ok(WorkerFileContentResult::Success {
                value: ClipboardFile::FileContentsResponse {
                    msg_flags,
                    stream_id,
                    requested_data,
                },
            })
        }
        FILE_CONTENT_RESULT_FILES => {
            let count = read_u32(reader).map_err(io_error)? as usize;
            let mut files = Vec::new();
            for _ in 0..count {
                let path = read_string(reader, MAX_WORKER_RESPONSE_BYTES)?;
                let size = read_u64(reader).map_err(io_error)?;
                files.push((path, size));
            }
            Ok(WorkerFileContentResult::Success {
                value: ClipboardFile::Files { files },
            })
        }
        FILE_CONTENT_RESULT_ERROR => {
            let description = read_string(reader, MAX_WORKER_ERROR_BYTES)?;
            Ok(WorkerFileContentResult::Failure { description })
        }
        tag => Err(common_error(format!(
            "file-content worker returned unknown file-content result tag {tag}"
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

fn read_u64<R: Read>(reader: &mut R) -> io::Result<u64> {
    Ok(u64::from_le_bytes(read_array::<8, _>(reader)?))
}

fn read_bytes<R: Read>(reader: &mut R, max_len: usize) -> io::Result<Vec<u8>> {
    let len = read_u32(reader)? as usize;
    if len > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized file-content worker byte field",
        ));
    }
    let mut value = vec![0u8; len];
    reader.read_exact(&mut value)?;
    Ok(value)
}

fn read_string<R: Read>(reader: &mut R, max_len: usize) -> Result<String, CliprdrError> {
    let bytes = read_bytes(reader, max_len).map_err(io_error)?;
    String::from_utf8(bytes)
        .map_err(|e| common_error(format!("file-content worker returned non-UTF8 string: {e}")))
}

fn write_u8<W: Write>(writer: &mut W, value: u8) -> io::Result<()> {
    writer.write_all(&[value])
}

fn write_u32<W: Write>(writer: &mut W, value: u32) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn write_i32<W: Write>(writer: &mut W, value: i32) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn write_u64<W: Write>(writer: &mut W, value: u64) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn write_bytes<W: Write>(writer: &mut W, value: &[u8], max_len: usize) -> io::Result<()> {
    if value.len() > max_len || value.len() > u32::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized file-content worker byte field",
        ));
    }
    write_u32(writer, value.len() as u32)?;
    writer.write_all(value)
}

fn write_string<W: Write>(writer: &mut W, value: &str, max_len: usize) -> Result<(), CliprdrError> {
    write_bytes(writer, value.as_bytes(), max_len).map_err(io_error)
}

fn io_error(err: io::Error) -> CliprdrError {
    common_error(format!("file-content worker I/O failed: {err}"))
}

fn common_error(description: impl Into<String>) -> CliprdrError {
    CliprdrError::CommonError {
        description: description.into(),
    }
}

fn invalid_request(description: impl Into<String>) -> CliprdrError {
    CliprdrError::InvalidRequest {
        description: description.into(),
    }
}

#[inline]
pub fn clear_files() {
    if let Err(err) = worker_request(WorkerRequest::Clear) {
        log::error!(
            "refusing in-process clear fallback after file-content worker failure: {}",
            err
        );
    }
}

pub fn read_file_contents(
    conn_id: i32,
    stream_id: i32,
    list_index: i32,
    dw_flags: i32,
    n_position_low: i32,
    n_position_high: i32,
    cb_requested: i32,
) -> Vec<Result<ClipboardFile, CliprdrError>> {
    match worker_request(WorkerRequest::ReadFileContents {
        conn_id,
        stream_id,
        list_index,
        dw_flags,
        n_position_low,
        n_position_high,
        cb_requested,
    }) {
        Ok(WorkerResponse::FileContents { results }) => results
            .into_iter()
            .map(|result| result.into_result())
            .collect(),
        Ok(response) => vec![Err(common_error(format!(
            "file-content worker returned unexpected response: {response:?}"
        )))],
        Err(err) => {
            log::error!(
                "refusing in-process file-content fallback after file-content worker failure: {}",
                err
            );
            vec![Err(err)]
        }
    }
}

pub fn sync_files(files: &[String]) -> Result<(), CliprdrError> {
    match worker_request(WorkerRequest::SyncFiles {
        files: files.to_vec(),
    }) {
        Ok(WorkerResponse::Ok) => Ok(()),
        Ok(WorkerResponse::Error { description }) => Err(invalid_request(description)),
        Ok(response) => Err(common_error(format!(
            "file-content worker returned unexpected response: {response:?}"
        ))),
        Err(err) => {
            log::error!(
                "refusing in-process file sync fallback after file-content worker failure: {}",
                err
            );
            Err(err)
        }
    }
}

pub fn get_file_list_pdu() -> Vec<u8> {
    match worker_request(WorkerRequest::GetFileListPdu) {
        Ok(WorkerResponse::FileListPdu { pdu }) => pdu,
        Ok(WorkerResponse::Error { description }) => {
            log::error!(
                "refusing in-process file-list fallback after file-content worker error: {}",
                description
            );
            Vec::new()
        }
        Ok(response) => {
            log::error!(
                "file-content worker returned unexpected file-list response: {:?}",
                response
            );
            Vec::new()
        }
        Err(err) => {
            log::error!(
                "refusing in-process file-list fallback after file-content worker failure: {}",
                err
            );
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        parse_file_content_request, worker_loop, write_worker_request, ClipFiles,
        WorkerFileContentResult, WorkerRequest, WorkerResponse,
        MAX_FILE_CONTENT_BYTES_PER_CONN_WINDOW, MAX_FILE_CONTENT_REQUESTS_PER_CONN_WINDOW,
    };
    use crate::ClipboardFile;
    use std::io::Cursor;

    #[test]
    fn file_content_request_accounting_rejects_request_count_flood() {
        let mut files = ClipFiles::default();
        for _ in 0..MAX_FILE_CONTENT_REQUESTS_PER_CONN_WINDOW {
            assert!(files.admit_file_content_request(7, 1).is_ok());
        }

        assert!(files.admit_file_content_request(7, 1).is_err());
        assert!(files.admit_file_content_request(8, 1).is_ok());
    }

    #[test]
    fn file_content_request_accounting_rejects_byte_window_flood() {
        let mut files = ClipFiles::default();
        assert!(files
            .admit_file_content_request(7, MAX_FILE_CONTENT_BYTES_PER_CONN_WINDOW)
            .is_ok());

        assert!(files.admit_file_content_request(7, 1).is_err());
        assert!(files.admit_file_content_request(8, 1).is_ok());
    }

    #[test]
    fn file_content_request_rejects_negative_length_before_cast() {
        let result = parse_file_content_request(1, 0, 0x2, 0, 0, -1);

        assert!(result.is_err());
    }

    #[test]
    fn file_content_worker_loop_syncs_and_returns_pdu() {
        let path = make_temp_file("sync", b"abcdef");
        let files = vec![path.to_string_lossy().into_owned()];
        let mut request = Vec::new();
        write_worker_request(&mut request, &WorkerRequest::SyncFiles { files })
            .expect("write sync request");
        write_worker_request(&mut request, &WorkerRequest::GetFileListPdu)
            .expect("write pdu request");

        let mut response = Vec::new();
        worker_loop(Cursor::new(request), &mut response).expect("run file-content worker loop");
        let mut response = &response[..];

        assert!(matches!(
            super::read_worker_response(&mut response).expect("read sync response"),
            WorkerResponse::Ok
        ));
        match super::read_worker_response(&mut response).expect("read pdu response") {
            WorkerResponse::FileListPdu { pdu } => {
                assert_eq!(pdu.len(), 4 + 592);
            }
            response => panic!("unexpected response: {response:?}"),
        }
    }

    #[test]
    fn file_content_worker_loop_reads_file_range() {
        let path = make_temp_file("read", b"abcdef");
        let files = vec![path.to_string_lossy().into_owned()];
        let mut request = Vec::new();
        write_worker_request(&mut request, &WorkerRequest::SyncFiles { files })
            .expect("write sync request");
        write_worker_request(
            &mut request,
            &WorkerRequest::ReadFileContents {
                conn_id: 7,
                stream_id: 11,
                list_index: 0,
                dw_flags: 0x2,
                n_position_low: 1,
                n_position_high: 0,
                cb_requested: 3,
            },
        )
        .expect("write file-content request");

        let mut response = Vec::new();
        worker_loop(Cursor::new(request), &mut response).expect("run file-content worker loop");
        let mut response = &response[..];

        assert!(matches!(
            super::read_worker_response(&mut response).expect("read sync response"),
            WorkerResponse::Ok
        ));
        match super::read_worker_response(&mut response).expect("read file-content response") {
            WorkerResponse::FileContents { results } => {
                assert_eq!(results.len(), 1);
                match &results[0] {
                    WorkerFileContentResult::Success {
                        value:
                            ClipboardFile::FileContentsResponse {
                                msg_flags,
                                stream_id,
                                requested_data,
                            },
                    } => {
                        assert_eq!(*msg_flags, 0x1);
                        assert_eq!(*stream_id, 11);
                        assert_eq!(requested_data.as_slice(), b"bcd");
                    }
                    result => panic!("unexpected file-content result: {result:?}"),
                }
            }
            response => panic!("unexpected response: {response:?}"),
        }
    }

    #[test]
    fn file_content_worker_response_rejects_oversized_result_count() {
        let mut response = Vec::new();
        response.extend_from_slice(&super::RESPONSE_MAGIC);
        response.extend_from_slice(&[
            super::PROTOCOL_VERSION,
            super::RESPONSE_STATUS_FILE_CONTENTS,
            0,
            0,
        ]);
        super::write_u32(&mut response, 4).expect("write response payload length");
        super::write_u32(&mut response, u32::MAX).expect("write malicious count");

        assert!(super::read_worker_response(&mut &response[..]).is_err());
    }

    fn make_temp_file(name: &str, contents: &[u8]) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "rd-filecontent-worker-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("sample.txt");
        std::fs::write(&path, contents).expect("write temp file");
        path
    }
}
