use crate::ipc;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use crate::ipc::Connection;
use crate::ipc::Data;
#[cfg(target_os = "windows")]
use crate::{clipboard::ClipboardSide, ipc::ClipboardNonFile};
#[cfg(target_os = "windows")]
use clipboard::ContextSend;
#[cfg(target_os = "windows")]
use hbb_common::config::keys::*;
#[cfg(not(any(target_os = "ios")))]
use hbb_common::fs::serialize_transfer_job;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use hbb_common::{
    allow_err, bail,
    config::{keys::OPTION_FILE_TRANSFER_MAX_FILES, Config},
    fs::{self, get_string, is_write_need_confirmation, DigestCheckResult},
    log,
    message_proto::*,
    tokio::{
        self,
        sync::{mpsc, OwnedSemaphorePermit, Semaphore},
        task::spawn_blocking,
    },
    ResultType,
};
use serde_derive::Serialize;
#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
use std::iter::FromIterator;
#[cfg(not(any(target_os = "ios")))]
use std::path::PathBuf;
use std::{
    collections::{HashMap, VecDeque},
    fmt,
    io::{self, Write},
    ops::{Deref, DerefMut},
    sync::{
        atomic::{AtomicBool, AtomicI64, Ordering},
        Arc, Mutex as StdMutex, OnceLock, RwLock,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CmConnectionTerminal {
    Close,
    Disconnected,
}

impl CmConnectionTerminal {
    pub(crate) fn into_data(self) -> ipc::Data {
        match self {
            Self::Close => ipc::Data::Close,
            Self::Disconnected => ipc::Data::Disconnected,
        }
    }
}

// R-S11gy: desktop CM results cross two in-process ownership hops (producer -> CM IPC and
// CM IPC -> Connection); Android uses the second shape directly. Keep one common nonblocking,
// count-and-byte-bounded, exact-connection mailbox so a stalled consumer cannot turn either hop
// into ambient process-lifetime retention. ReadBlock bytes are serde-skipped and counted separately.
const CM_EGRESS_WAKE_CAPACITY: usize = 1;
const CM_EGRESS_MAX_MESSAGES: usize = 256;
const CM_EGRESS_MAX_MESSAGE_BYTES: usize =
    ipc::CM_IPC_MAX_FRAME_BYTES + ipc::CM_FILE_BLOCK_MAX_FRAME_BYTES;
const CM_EGRESS_MAX_QUEUED_BYTES: usize = CM_EGRESS_MAX_MESSAGE_BYTES * 2
    + std::mem::size_of::<QueuedCmEgress>() * CM_EGRESS_MAX_MESSAGES;

#[derive(Clone, Copy)]
struct CmEgressLimits {
    max_messages: usize,
    max_message_bytes: usize,
    max_queued_bytes: usize,
}

const CM_EGRESS_LIMITS: CmEgressLimits = CmEgressLimits {
    max_messages: CM_EGRESS_MAX_MESSAGES,
    max_message_bytes: CM_EGRESS_MAX_MESSAGE_BYTES,
    max_queued_bytes: CM_EGRESS_MAX_QUEUED_BYTES,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CmEgressFailure {
    WrongMessageClass,
    MessageTooLarge,
    MessageCapacity,
    ByteCapacity,
    Encoding,
    AccountingOverflow,
}

impl fmt::Display for CmEgressFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::WrongMessageClass => "unexpected message class",
            Self::MessageTooLarge => "message exceeds the encoded-byte ceiling",
            Self::MessageCapacity => "message-count capacity reached",
            Self::ByteCapacity => "retained-byte capacity reached",
            Self::Encoding => "message size could not be encoded",
            Self::AccountingOverflow => "resource accounting overflowed",
        };
        write!(f, "connection-manager egress {reason}")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CmEgressAdmissionError {
    Failed(CmEgressFailure),
    ReceiverGone,
}

impl fmt::Display for CmEgressAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed(failure) => write!(f, "{failure}"),
            Self::ReceiverGone => write!(f, "connection-manager egress receiver is gone"),
        }
    }
}

impl std::error::Error for CmEgressAdmissionError {}

struct CmEgressSizeCounter {
    bytes: usize,
    limit: usize,
    failure: Option<CmEgressFailure>,
}

impl Write for CmEgressSizeCounter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let Some(next) = self.bytes.checked_add(buf.len()) else {
            self.failure = Some(CmEgressFailure::AccountingOverflow);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "CM egress size overflow",
            ));
        };
        if next > self.limit {
            self.failure = Some(CmEgressFailure::MessageTooLarge);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "CM egress message too large",
            ));
        }
        self.bytes = next;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn is_cm_egress_data(data: &Data) -> bool {
    match data {
        Data::Close
        | Data::ClickTime(_)
        | Data::CmErr(_)
        | Data::ChatMessage { .. }
        | Data::CmFileResponse(_)
        | Data::PrivacyModeState(_)
        | Data::VoiceCallResponse(_)
        | Data::CloseVoiceCall(_) => true,
        #[cfg(target_os = "windows")]
        Data::ClipboardFile(_) => true,
        _ => false,
    }
}

fn cm_egress_encoded_bytes(data: &Data, limit: usize) -> Result<usize, CmEgressFailure> {
    let raw_bytes = match data {
        Data::CmFileResponse(envelope) => match envelope.response.as_ref() {
            ipc::CmFileResponseKind::ReadBlock { data, .. } => data.len(),
            _ => 0,
        },
        _ => 0,
    };
    if raw_bytes > ipc::CM_FILE_BLOCK_MAX_FRAME_BYTES {
        return Err(CmEgressFailure::MessageTooLarge);
    }
    let mut counter = CmEgressSizeCounter {
        bytes: 0,
        limit: limit.min(ipc::CM_IPC_MAX_FRAME_BYTES),
        failure: None,
    };
    if serde_json::to_writer(&mut counter, data).is_err() {
        return Err(counter.failure.unwrap_or(CmEgressFailure::Encoding));
    }
    counter
        .bytes
        .checked_add(raw_bytes)
        .filter(|bytes| *bytes <= limit)
        .ok_or(CmEgressFailure::MessageTooLarge)
}

struct QueuedCmEgress {
    data: Data,
    retained_bytes: usize,
}

struct CmEgressState {
    queue: VecDeque<QueuedCmEgress>,
    queued_bytes: usize,
    terminal: Option<CmEgressFailure>,
    receiver_open: bool,
}

impl Default for CmEgressState {
    fn default() -> Self {
        Self {
            queue: VecDeque::new(),
            queued_bytes: 0,
            terminal: None,
            receiver_open: true,
        }
    }
}

#[derive(Clone)]
pub(crate) struct CmEgressSender {
    state: Arc<StdMutex<CmEgressState>>,
    wake: mpsc::Sender<()>,
    limits: CmEgressLimits,
}

pub(crate) struct CmEgressReceiver {
    state: Arc<StdMutex<CmEgressState>>,
    wake: mpsc::Receiver<()>,
}

pub(crate) enum CmEgressItem {
    Data(Data),
    Failed(CmEgressFailure),
}

pub(crate) fn cm_egress_channel() -> (CmEgressSender, CmEgressReceiver) {
    cm_egress_channel_with_limits(CM_EGRESS_LIMITS)
}

fn cm_egress_channel_with_limits(limits: CmEgressLimits) -> (CmEgressSender, CmEgressReceiver) {
    let state = Arc::new(StdMutex::new(CmEgressState::default()));
    let (wake, receiver) = mpsc::channel(CM_EGRESS_WAKE_CAPACITY);
    (
        CmEgressSender {
            state: Arc::clone(&state),
            wake,
            limits,
        },
        CmEgressReceiver {
            state,
            wake: receiver,
        },
    )
}

fn lock_cm_egress(state: &StdMutex<CmEgressState>) -> std::sync::MutexGuard<'_, CmEgressState> {
    match state.lock() {
        Ok(state) => state,
        Err(poisoned) => {
            log::error!("connection-manager egress state was poisoned");
            poisoned.into_inner()
        }
    }
}

impl CmEgressSender {
    fn wake_receiver(&self) -> Result<(), CmEgressAdmissionError> {
        match self.wake.try_send(()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                let mut state = lock_cm_egress(&self.state);
                state.receiver_open = false;
                state.queue.clear();
                state.queued_bytes = 0;
                Err(CmEgressAdmissionError::ReceiverGone)
            }
        }
    }

    fn fail_with_state(
        &self,
        mut state: std::sync::MutexGuard<'_, CmEgressState>,
        failure: CmEgressFailure,
    ) -> Result<(), CmEgressAdmissionError> {
        if !state.receiver_open {
            return Err(CmEgressAdmissionError::ReceiverGone);
        }
        if let Some(existing) = state.terminal {
            return Err(CmEgressAdmissionError::Failed(existing));
        }
        state.queue.clear();
        state.queued_bytes = 0;
        state.terminal = Some(failure);
        drop(state);
        self.wake_receiver()?;
        Err(CmEgressAdmissionError::Failed(failure))
    }

    fn fail(&self, failure: CmEgressFailure) -> Result<(), CmEgressAdmissionError> {
        self.fail_with_state(lock_cm_egress(&self.state), failure)
    }

    pub(crate) fn send(&self, data: Data) -> Result<(), CmEgressAdmissionError> {
        // Exact responses have no coalescing semantics. Any refusal retires the complete mailbox;
        // continuing after one response disappeared would make CM and Connection state diverge.
        if !is_cm_egress_data(&data) {
            return self.fail(CmEgressFailure::WrongMessageClass);
        }
        {
            let state = lock_cm_egress(&self.state);
            if !state.receiver_open {
                return Err(CmEgressAdmissionError::ReceiverGone);
            }
            if let Some(failure) = state.terminal {
                return Err(CmEgressAdmissionError::Failed(failure));
            }
        }
        let encoded_bytes = match cm_egress_encoded_bytes(&data, self.limits.max_message_bytes) {
            Ok(bytes) => bytes,
            Err(failure) => return self.fail(failure),
        };
        let retained_bytes = match encoded_bytes.checked_add(std::mem::size_of::<QueuedCmEgress>())
        {
            Some(bytes) => bytes,
            None => return self.fail(CmEgressFailure::AccountingOverflow),
        };
        {
            let mut state = lock_cm_egress(&self.state);
            if !state.receiver_open {
                return Err(CmEgressAdmissionError::ReceiverGone);
            }
            if let Some(failure) = state.terminal {
                return Err(CmEgressAdmissionError::Failed(failure));
            }
            let Some(next_count) = state.queue.len().checked_add(1) else {
                return self.fail_with_state(state, CmEgressFailure::AccountingOverflow);
            };
            if next_count > self.limits.max_messages {
                return self.fail_with_state(state, CmEgressFailure::MessageCapacity);
            }
            let Some(next_bytes) = state.queued_bytes.checked_add(retained_bytes) else {
                return self.fail_with_state(state, CmEgressFailure::AccountingOverflow);
            };
            if next_bytes > self.limits.max_queued_bytes {
                return self.fail_with_state(state, CmEgressFailure::ByteCapacity);
            }
            state.queue.push_back(QueuedCmEgress {
                data,
                retained_bytes,
            });
            state.queued_bytes = next_bytes;
        }
        self.wake_receiver()
    }
}

impl CmEgressReceiver {
    fn take_next(&mut self) -> Result<Option<CmEgressItem>, ()> {
        let mut state = lock_cm_egress(&self.state);
        if let Some(failure) = state.terminal.take() {
            state.receiver_open = false;
            state.queue.clear();
            state.queued_bytes = 0;
            return Ok(Some(CmEgressItem::Failed(failure)));
        }
        if !state.receiver_open {
            return Err(());
        }
        let Some(queued) = state.queue.pop_front() else {
            return Ok(None);
        };
        let Some(next_bytes) = state.queued_bytes.checked_sub(queued.retained_bytes) else {
            state.receiver_open = false;
            state.queue.clear();
            state.queued_bytes = 0;
            return Ok(Some(CmEgressItem::Failed(
                CmEgressFailure::AccountingOverflow,
            )));
        };
        state.queued_bytes = next_bytes;
        Ok(Some(CmEgressItem::Data(queued.data)))
    }

    pub(crate) async fn recv(&mut self) -> Option<CmEgressItem> {
        loop {
            match self.take_next() {
                Ok(Some(item)) => return Some(item),
                Ok(None) => {}
                Err(()) => return None,
            }
            if self.wake.recv().await.is_none() {
                return None;
            }
        }
    }
}

impl Drop for CmEgressReceiver {
    fn drop(&mut self) {
        self.wake.close();
        let mut state = lock_cm_egress(&self.state);
        state.receiver_open = false;
        state.queue.clear();
        state.queued_bytes = 0;
        state.terminal = None;
    }
}

/// Default maximum number of files allowed per transfer request.
/// Unit: number of files (not bytes).
#[cfg(not(any(target_os = "ios")))]
const DEFAULT_MAX_VALIDATED_FILES: usize = fs::DEFAULT_FILE_TRANSFER_MAX_FILES;
#[cfg(not(any(target_os = "ios")))]
const MAX_CONCURRENT_FILE_METADATA_SCANS: usize = 4;
#[cfg(not(any(target_os = "ios")))]
static FILE_METADATA_SCAN_SEMAPHORE: OnceLock<Arc<Semaphore>> = OnceLock::new();

/// Maximum number of files allowed in a single file transfer request.
///
/// This limit prevents excessive I/O and memory usage when dealing with
/// large directories. It applies to:
/// - CM-side read jobs (server to client file transfers on Windows)
/// - `AllFiles` recursive directory listing operations
/// - Connection-side read jobs (non-Windows platforms)
///
/// Unit: number of files (not bytes).
/// Default: 10,000 files.
/// Configured via: `OPTION_FILE_TRANSFER_MAX_FILES` ("file-transfer-max-files")
#[cfg(not(any(target_os = "ios")))]
static MAX_VALIDATED_FILES: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

/// Get the maximum number of files allowed per transfer request.
///
/// Initializes the value from configuration (`OPTION_FILE_TRANSFER_MAX_FILES`)
/// on first call. Semantics:
/// - If the option is set to `0`, `DEFAULT_MAX_VALIDATED_FILES` (10,000) is used as a safe upper bound.
/// - If the option is unset, negative, or non-integer, the same safe default is
///   used. This fork never treats an unparsable peer-facing resource limit as
///   "no limit."
///
/// Unit: number of files.
#[cfg(not(any(target_os = "ios")))]
#[inline]
pub fn get_max_validated_files() -> usize {
    *MAX_VALIDATED_FILES.get_or_init(|| {
        let c = crate::get_builtin_option(OPTION_FILE_TRANSFER_MAX_FILES)
            .trim()
            .parse::<usize>()
            .unwrap_or(DEFAULT_MAX_VALIDATED_FILES);
        if c == 0 {
            DEFAULT_MAX_VALIDATED_FILES
        } else {
            c
        }
    })
}

#[cfg(not(any(target_os = "ios")))]
pub fn file_transfer_enumeration_budget() -> fs::FileEnumerationBudget {
    fs::FileEnumerationBudget::for_max_entries(get_max_validated_files())
}

#[cfg(not(any(target_os = "ios")))]
pub fn try_acquire_file_metadata_scan() -> Result<OwnedSemaphorePermit, String> {
    let semaphore = FILE_METADATA_SCAN_SEMAPHORE
        .get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_FILE_METADATA_SCANS)))
        .clone();
    semaphore.try_acquire_owned().map_err(|_| {
        format!(
            "file metadata scan rejected: {} concurrent scans already active",
            MAX_CONCURRENT_FILE_METADATA_SCANS
        )
    })
}

/// Check if file count exceeds the maximum allowed limit.
///
/// This check is enforced in:
/// - `start_read_job()` for CM-side read jobs
/// - `read_all_files()` for recursive directory listings
/// - `Connection::on_message()` for connection-side read jobs
///
/// # Arguments
/// * `file_count` - Number of files in the transfer request
///
/// # Returns
/// * `Ok(())` if within limit
/// * `Err(String)` with error message if limit exceeded
#[cfg(not(any(target_os = "ios")))]
pub fn check_file_count_limit(file_count: usize) -> Result<(), String> {
    let max_files = get_max_validated_files();
    if file_count > max_files {
        let msg = format!(
            "file transfer rejected: too many files ({} files exceeds limit of {}). \
             Adjust '{}' option to increase limit.",
            file_count, max_files, OPTION_FILE_TRANSFER_MAX_FILES
        );
        log::warn!("{}", msg);
        Err(msg)
    } else {
        Ok(())
    }
}

#[derive(Serialize, Clone)]
pub struct Client {
    pub id: i32,
    pub authorized: bool,
    pub disconnected: bool,
    pub is_file_transfer: bool,
    pub is_view_camera: bool,
    pub is_terminal: bool,
    pub port_forward: String,
    pub conn_type: ipc::CmAuthConnType,
    pub name: String,
    pub avatar: String,
    pub peer_id: String,
    pub keyboard: bool,
    pub clipboard: bool,
    pub audio: bool,
    pub file: bool,
    pub privacy_mode: bool,
    pub in_voice_call: bool,
    pub incoming_voice_call: bool,
    #[serde(skip)]
    #[cfg(not(any(target_os = "ios")))]
    tx: CmEgressSender,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct IpcTaskRunner<T: InvokeUiCM> {
    stream: Connection,
    cm: ConnectionManager<T>,
    tx: CmEgressSender,
    rx: CmEgressReceiver,
    close: bool,
    running: bool,
    conn_id: i32,
    file_authority: CmFileAuthority,
    cm_auth_token: String,
    #[cfg(target_os = "windows")]
    file_transfer_enabled: bool,
    #[cfg(target_os = "windows")]
    file_transfer_enabled_peer: bool,
    /// Read jobs for CM-side file reading (server to client transfers)
    read_jobs: Vec<CmTransferJob>,
}

#[cfg(not(any(target_os = "ios")))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CmFileAuthority {
    conn_id: i32,
    allows_fs: bool,
    token_valid: bool,
}

#[cfg(not(any(target_os = "ios")))]
impl CmFileAuthority {
    fn absent() -> Self {
        Self::default()
    }

    fn from_login(
        id: i32,
        authorized: bool,
        conn_type: ipc::CmAuthConnType,
        file: bool,
        authority: ipc::CmConnectionAuthority,
    ) -> Self {
        Self {
            conn_id: id,
            allows_fs: id > 0
                && authorized
                && file
                && authority.valid
                && authority.file
                && conn_type.allows_file_authority(),
            token_valid: authority.valid,
        }
    }

    fn allows_fs(self, token_matches: bool) -> bool {
        self.allows_fs && self.token_valid && token_matches
    }
}

#[cfg(not(any(target_os = "ios")))]
struct CmTransferJob {
    generation: u64,
    job: fs::TransferJob,
}

#[cfg(not(any(target_os = "ios")))]
#[derive(Clone, Copy)]
struct CmFileResponder<'a> {
    tx: &'a CmEgressSender,
    conn_id: i32,
    cm_auth_token: &'a str,
}

#[cfg(not(any(target_os = "ios")))]
impl CmFileResponder<'_> {
    fn send(self, response: ipc::CmFileResponseKind) {
        if let Err(error) = self.tx.send(Data::CmFileResponse(ipc::CmFileResponse {
            conn_id: self.conn_id,
            cm_auth_token: self.cm_auth_token.to_owned(),
            response: Box::new(response),
        })) {
            log::error!("failed to send CM file response: {}", error);
        }
    }
}

#[cfg(not(any(target_os = "ios")))]
fn cm_file_entry_type(entry_type: FileType) -> ipc::CmFileEntryType {
    match entry_type {
        FileType::Dir => ipc::CmFileEntryType::Directory,
        FileType::DirLink => ipc::CmFileEntryType::DirectoryLink,
        FileType::DirDrive => ipc::CmFileEntryType::DirectoryDrive,
        FileType::File => ipc::CmFileEntryType::File,
        FileType::FileLink => ipc::CmFileEntryType::FileLink,
    }
}

#[cfg(not(any(target_os = "ios")))]
fn cm_file_directory(directory: FileDirectory) -> Result<ipc::CmFileDirectory, String> {
    let mut entries = Vec::with_capacity(directory.entries.len());
    for entry in directory.entries {
        let entry_type = entry
            .entry_type
            .enum_value()
            .map_err(|value| format!("unknown file entry type {value}"))?;
        entries.push(ipc::CmFileEntry {
            entry_type: cm_file_entry_type(entry_type),
            name: entry.name,
            is_hidden: entry.is_hidden,
            size: entry.size,
            modified_time: entry.modified_time,
        });
    }
    Ok(ipc::CmFileDirectory {
        id: directory.id,
        path: directory.path,
        entries,
    })
}

lazy_static::lazy_static! {
    static ref CLIENTS: RwLock<HashMap<i32, Client>> = Default::default();
}

static CLICK_TIME: AtomicI64 = AtomicI64::new(0);
#[cfg(not(any(target_os = "android", target_os = "ios")))]
static EXIT_ON_IDLE: AtomicBool = AtomicBool::new(false);

#[cfg(not(any(target_os = "ios")))]
fn cm_egress_sender(id: i32) -> Option<CmEgressSender> {
    CLIENTS
        .read()
        .unwrap()
        .get(&id)
        .map(|client| client.tx.clone())
}

#[cfg(windows)]
fn cm_egress_senders(id: i32) -> Vec<CmEgressSender> {
    let clients = CLIENTS.read().unwrap();
    if id == 0 {
        clients.values().map(|client| client.tx.clone()).collect()
    } else {
        clients
            .get(&id)
            .map(|client| vec![client.tx.clone()])
            .unwrap_or_default()
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn set_exit_on_idle(exit_on_idle: bool) {
    EXIT_ON_IDLE.store(exit_on_idle, Ordering::SeqCst);
}

#[derive(Clone)]
pub struct ConnectionManager<T: InvokeUiCM> {
    pub ui_handler: T,
}

pub trait InvokeUiCM: Send + Clone + 'static + Sized {
    fn add_connection(&self, client: &Client);

    fn remove_connection(&self, id: i32, close: bool);

    fn new_message(&self, id: i32, text: String);

    fn change_theme(&self, dark: String);

    fn change_language(&self);

    fn update_voice_call_state(&self, client: &Client);

    fn file_transfer_log(&self, action: &str, log: &str);
}

impl<T: InvokeUiCM> Deref for ConnectionManager<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.ui_handler
    }
}

impl<T: InvokeUiCM> DerefMut for ConnectionManager<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.ui_handler
    }
}

impl<T: InvokeUiCM> ConnectionManager<T> {
    fn add_connection(
        &self,
        id: i32,
        is_file_transfer: bool,
        is_view_camera: bool,
        is_terminal: bool,
        port_forward: String,
        conn_type: ipc::CmAuthConnType,
        peer_id: String,
        name: String,
        avatar: String,
        authorized: bool,
        keyboard: bool,
        clipboard: bool,
        audio: bool,
        file: bool,
        privacy_mode: bool,
        #[cfg(not(any(target_os = "ios")))] tx: CmEgressSender,
    ) {
        let client = Client {
            id,
            authorized,
            disconnected: false,
            is_file_transfer,
            is_view_camera,
            is_terminal,
            port_forward,
            conn_type,
            name: name.clone(),
            avatar,
            peer_id: peer_id.clone(),
            keyboard,
            clipboard,
            audio,
            file,
            privacy_mode,
            #[cfg(not(any(target_os = "ios")))]
            tx,
            in_voice_call: false,
            incoming_voice_call: false,
        };
        CLIENTS
            .write()
            .unwrap()
            .retain(|_, c| !(c.disconnected && c.peer_id == client.peer_id));
        CLIENTS.write().unwrap().insert(id, client.clone());
        self.ui_handler.add_connection(&client);
    }

    #[inline]
    #[cfg(target_os = "windows")]
    fn is_authorized(&self, id: i32) -> bool {
        CLIENTS
            .read()
            .unwrap()
            .get(&id)
            .map(|c| c.authorized)
            .unwrap_or(false)
    }

    fn remove_connection(&self, id: i32, close: bool) {
        if close {
            CLIENTS.write().unwrap().remove(&id);
        } else {
            CLIENTS
                .write()
                .unwrap()
                .get_mut(&id)
                .map(|c| c.disconnected = true);
        }

        #[cfg(target_os = "windows")]
        {
            crate::clipboard::try_empty_clipboard_files(ClipboardSide::Host, id);
        }

        self.ui_handler.remove_connection(id, close);

        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        if EXIT_ON_IDLE.load(Ordering::SeqCst) && CLIENTS.read().unwrap().is_empty() {
            log::info!("R-T4: no-ui connection manager idle after last IPC client; exiting");
            quit_cm();
        }
    }

    #[cfg(not(target_os = "ios"))]
    fn voice_call_started(&self, id: i32) {
        if let Some(client) = CLIENTS.write().unwrap().get_mut(&id) {
            client.incoming_voice_call = false;
            client.in_voice_call = true;
            self.ui_handler.update_voice_call_state(client);
        }
    }

    #[cfg(not(target_os = "ios"))]
    fn voice_call_incoming(&self, id: i32) {
        if let Some(client) = CLIENTS.write().unwrap().get_mut(&id) {
            client.incoming_voice_call = true;
            client.in_voice_call = false;
            self.ui_handler.update_voice_call_state(client);
        }
    }

    #[cfg(not(target_os = "ios"))]
    fn voice_call_closed(&self, id: i32, _reason: &str) {
        if let Some(client) = CLIENTS.write().unwrap().get_mut(&id) {
            client.incoming_voice_call = false;
            client.in_voice_call = false;
            self.ui_handler.update_voice_call_state(client);
        }
    }
}

#[inline]
#[cfg(not(any(target_os = "ios")))]
pub fn check_click_time(id: i32) {
    if let Some(tx) = cm_egress_sender(id) {
        allow_err!(tx.send(Data::ClickTime(0)));
    };
}

#[inline]
pub fn get_click_time() -> i64 {
    CLICK_TIME.load(Ordering::SeqCst)
}

#[inline]
#[cfg(not(any(target_os = "ios")))]
pub fn close(id: i32) {
    if let Some(tx) = cm_egress_sender(id) {
        allow_err!(tx.send(Data::Close));
    };
}

#[inline]
pub fn remove(id: i32) {
    CLIENTS.write().unwrap().remove(&id);
}

// server mode send chat to peer
#[inline]
#[cfg(not(any(target_os = "ios")))]
pub fn send_chat(id: i32, text: String) {
    if let Some(tx) = cm_egress_sender(id) {
        allow_err!(tx.send(Data::ChatMessage { text }));
    }
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn get_clients_state() -> String {
    let clients = CLIENTS.read().unwrap();
    let res = Vec::from_iter(clients.values().cloned());
    serde_json::to_string(&res).unwrap_or("".into())
}

#[inline]
pub fn get_clients_length() -> usize {
    let clients = CLIENTS.read().unwrap();
    clients.len()
}

#[inline]
#[cfg(target_os = "android")]
pub fn has_active_clients() -> bool {
    let clients = CLIENTS.read().unwrap();
    clients.values().any(|c| !c.disconnected)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl<T: InvokeUiCM> IpcTaskRunner<T> {
    async fn run(&mut self) {
        use hbb_common::tokio::time::{self, Duration, Instant};

        const MILLI5: Duration = Duration::from_millis(5);
        const SEC30: Duration = Duration::from_secs(30);

        // for tmp use, without real conn id
        let mut write_jobs: Vec<CmTransferJob> = Vec::new();
        // File timer for processing read_jobs
        let mut file_timer =
            crate::rustdesk_interval(time::interval_at(Instant::now() + SEC30, SEC30));

        #[cfg(target_os = "windows")]
        let is_authorized = self.cm.is_authorized(self.conn_id);

        #[cfg(target_os = "windows")]
        let (_tx_clip, mut rx_clip, _cliprdr_route) = if self.conn_id > 0 && is_authorized {
            log::debug!("Clipboard is enabled from client peer: type 1");
            match clipboard::register_cliprdr_controlled(self.conn_id) {
                Ok((receiver, route)) => (None, receiver, Some(route)),
                Err(error) => {
                    log::error!(
                        "failed to register exact CM file-clipboard route for {}: {}",
                        self.conn_id,
                        error
                    );
                    return;
                }
            }
        } else {
            log::debug!("Clipboard is enabled from client peer, actually useless: type 2");
            let (sender, receiver) = clipboard::clipboard_file_egress_channel();
            (Some(sender), receiver, None)
        };
        #[cfg(not(target_os = "windows"))]
        let (_tx_clip, mut rx_clip) = clipboard::clipboard_file_egress_channel();

        #[cfg(target_os = "windows")]
        {
            if ContextSend::is_enabled() {
                log::debug!("Clipboard is enabled");
                allow_err!(
                    self.stream
                        .send(&Data::ClipboardFile(clipboard::ClipboardFile::MonitorReady))
                        .await
                );
            }
        }
        self.running = false;
        loop {
            tokio::select! {
                res = self.stream.next() => {
                    match res {
                        Err(err) => {
                            log::info!("cm ipc connection closed: {}", err);
                            break;
                        }
                        Ok(Some(data)) => {
                            match data {
                                Data::Login{id, is_file_transfer, is_view_camera, is_terminal, port_forward, conn_type, peer_id, name, avatar, authorized, keyboard, clipboard, audio, file, file_transfer_enabled: _file_transfer_enabled, privacy_mode, cm_auth_token} => {
                                    log::debug!("conn_id: {}", id);
                                    let connection_authority = match ipc::validate_cm_connection_authority(
                                        id,
                                        conn_type,
                                        &cm_auth_token,
                                    )
                                    .await
                                    {
                                        Ok(authority) => authority,
                                        Err(err) => {
                                            log::warn!(
                                                "Rejected CM login without server-validated authority: conn_id={}, err={}",
                                                id,
                                                err
                                            );
                                            ipc::CmConnectionAuthority::default()
                                        }
                                    };
                                    if !authorized || !connection_authority.valid {
                                        log::warn!(
                                            "Rejected CM login without matching authorized server connection: conn_id={}",
                                            id
                                        );
                                        break;
                                    }
                                    let file_authority = CmFileAuthority::from_login(
                                        id,
                                        authorized,
                                        conn_type,
                                        file,
                                        connection_authority,
                                    );
                                    self.cm.add_connection(id, is_file_transfer, is_view_camera, is_terminal, port_forward, conn_type, peer_id, name, avatar, authorized, keyboard, clipboard, audio, file, privacy_mode, self.tx.clone());
                                    self.conn_id = id;
                                    self.file_authority = file_authority;
                                    self.cm_auth_token = cm_auth_token;
                                    #[cfg(target_os = "windows")]
                                    {
                                        self.file_transfer_enabled = _file_transfer_enabled;
                                    }
                                    self.running = true;
                                    break;
                                }
                                Data::Close => {
                                    log::info!("cm ipc connection closed from connection request");
                                    break;
                                }
                                Data::Disconnected => {
                                    self.close = false;
                                    log::info!("cm ipc connection disconnect");
                                    break;
                                }
                                Data::PrivacyModeState((_id, _, _)) => {
                                    #[cfg(windows)]
                                    cm_inner_send(_id, data);
                                }
                                Data::ClickTime(ms) => {
                                    CLICK_TIME.store(ms, Ordering::SeqCst);
                                }
                                Data::ChatMessage { text } => {
                                    self.cm.new_message(self.conn_id, text);
                                }
                                Data::AuthorizedFS { cm_auth_token, mut fs } => {
                                    if !self.file_authority.allows_fs(cm_auth_token == self.cm_auth_token) {
                                        log::warn!(
                                            "Rejected CM AuthorizedFS without matching authorized file-capable login: conn_id={}",
                                            self.file_authority.conn_id
                                        );
                                        break;
                                    }
                                    let job_log = if let ipc::FS::WriteBlock { id, file_num, conn_id, data: _, compressed, generation } = fs {
                                        if let Ok(bytes) = self.stream.next_raw().await {
                                            fs = ipc::FS::WriteBlock{id, file_num, conn_id, data:bytes.into(), compressed, generation};
                                            handle_fs(
                                                fs,
                                                &mut write_jobs,
                                                &mut self.read_jobs,
                                                CmFileResponder {
                                                    tx: &self.tx,
                                                    conn_id: self.conn_id,
                                                    cm_auth_token: &self.cm_auth_token,
                                                },
                                                true,
                                            )
                                            .await
                                        } else {
                                            None
                                        }
                                    } else {
                                        handle_fs(
                                            fs,
                                            &mut write_jobs,
                                            &mut self.read_jobs,
                                            CmFileResponder {
                                                tx: &self.tx,
                                                conn_id: self.conn_id,
                                                cm_auth_token: &self.cm_auth_token,
                                            },
                                            true,
                                        )
                                        .await
                                    };
                                    if let Some(job_log) = job_log {
                                        self.cm.ui_handler.file_transfer_log("transfer", &job_log);
                                    }
                                    // Activate fast timer immediately when read jobs exist.
                                    // This ensures new jobs start processing without waiting for the slow 30s timer.
                                    // Deactivation (back to 30s) happens in tick handler when jobs are exhausted.
                                    if !self.read_jobs.is_empty() {
                                        file_timer = crate::rustdesk_interval(time::interval(MILLI5));
                                    }
                                    let log = serialize_cm_transfer_jobs(&write_jobs);
                                    self.cm.ui_handler.file_transfer_log("transfer", &log);
                                }
                                Data::FS(_) => {
                                    log::warn!(
                                        "Rejected unauthenticated CM Data::FS on desktop IPC: conn_id={}",
                                        self.file_authority.conn_id
                                    );
                                    break;
                                }
                                Data::FileTransferLog((action, log)) => {
                                    self.cm.ui_handler.file_transfer_log(&action, &log);
                                }
                                #[cfg(target_os = "windows")]
                                Data::ClipboardFile(_clip) => {
                                    let is_stopping_allowed = _clip.is_beginning_message();
                                    let is_clipboard_enabled = ContextSend::is_enabled();
                                    let file_transfer_enabled = self.file_transfer_enabled;
                                    let stop = !is_stopping_allowed && !(is_clipboard_enabled && file_transfer_enabled);
                                    log::debug!(
                                        "Process clipboard message from client peer, stop: {}, is_stopping_allowed: {}, is_clipboard_enabled: {}, file_transfer_enabled: {}",
                                        stop, is_stopping_allowed, is_clipboard_enabled, file_transfer_enabled);
                                    if stop {
                                        ContextSend::set_is_stopped();
                                    } else {
                                        if !is_authorized {
                                            log::debug!("Clipboard message from client peer, but not authorized");
                                            continue;
                                        }
                                        let conn_id = self.conn_id;
                                        let _ = ContextSend::proc(|context| -> ResultType<()> {
                                            context.server_clip_file(conn_id, _clip)
                                                .map_err(|e| e.into())
                                        });
                                    }
                                }
                                Data::ClipboardFileEnabled(_enabled) => {
                                    #[cfg(target_os = "windows")]
                                    {
                                        self.file_transfer_enabled_peer = _enabled;
                                    }
                                }
                                Data::StartVoiceCall => {
                                    self.cm.voice_call_started(self.conn_id);
                                }
                                Data::VoiceCallIncoming => {
                                    self.cm.voice_call_incoming(self.conn_id);
                                }
                                Data::CloseVoiceCall(reason) => {
                                    self.cm.voice_call_closed(self.conn_id, reason.as_str());
                                }
                                #[cfg(target_os = "windows")]
                                Data::AuthorizedClipboardNonFile { id, conn_type, cm_auth_token } => {
                                    let connection_authority = match ipc::validate_cm_connection_authority(
                                        id,
                                        conn_type,
                                        &cm_auth_token,
                                    )
                                    .await
                                    {
                                        Ok(authority) => authority,
                                        Err(err) => {
                                            log::warn!(
                                                "Rejected CM non-file clipboard read without server-validated authority: conn_id={}, err={}",
                                                id,
                                                err
                                            );
                                            ipc::CmConnectionAuthority::default()
                                        }
                                    };
                                    if !connection_authority.valid
                                        || !connection_authority.clipboard
                                        || !conn_type.allows_clipboard_authority()
                                    {
                                        log::warn!(
                                            "Rejected CM non-file clipboard read without matching clipboard-capable Remote authority: conn_id={}",
                                            id
                                        );
                                        allow_err!(self.stream.send(&Data::ClipboardNonFile(Some((
                                            "clipboard authority denied".to_owned(),
                                            vec![]
                                        )))).await);
                                        continue;
                                    }
                                    match crate::clipboard::check_clipboard_cm() {
                                        Ok(multi_clipoards) => {
                                            let mut raw_contents = bytes::BytesMut::new();
                                            let mut main_data = vec![];
                                            for c in multi_clipoards.clipboards.into_iter() {
                                                let content_len = c.content.len();
                                                let (content, next_raw) = {
                                                    // TODO: find out a better threshold
                                                    if content_len > 1024 * 3 {
                                                        raw_contents.extend(c.content);
                                                        (bytes::Bytes::new(), true)
                                                    } else {
                                                        (c.content, false)
                                                    }
                                                };
                                                main_data.push(ClipboardNonFile {
                                                    compress: c.compress,
                                                    content,
                                                    content_len,
                                                    next_raw,
                                                    width: c.width,
                                                    height: c.height,
                                                    format: c.format.value(),
                                                    special_name: c.special_name,
                                                });
                                            }
                                            allow_err!(self.stream.send(&Data::ClipboardNonFile(Some(("".to_owned(), main_data)))).await);
                                            if !raw_contents.is_empty() {
                                                allow_err!(self.stream.send_raw(raw_contents.into()).await);
                                            }
                                        }
                                        Err(e) => {
                                            log::debug!("Failed to get clipboard content. {}", e);
                                            allow_err!(self.stream.send(&Data::ClipboardNonFile(Some((format!("{}", e), vec![])))).await);
                                        }
                                    }
                                }
                                #[cfg(target_os = "windows")]
                                Data::ClipboardNonFile(None) => {
                                    log::warn!("Rejected unauthenticated CM non-file clipboard request");
                                    allow_err!(self.stream.send(&Data::ClipboardNonFile(Some((
                                        "clipboard authority denied".to_owned(),
                                        vec![]
                                    )))).await);
                                }
                                #[cfg(target_os = "windows")]
                                Data::ClipboardNonFile(Some(_)) => {}
                                _ => {

                                }
                            }
                        }
                        _ => {}
                    }
                }
                Some(item) = self.rx.recv() => {
                    let mut data = match item {
                        CmEgressItem::Data(data) => data,
                        CmEgressItem::Failed(failure) => {
                            log::error!("connection-manager output retired: {failure}");
                            break;
                        }
                    };
                    let raw_block = match &mut data {
                        Data::CmFileResponse(envelope) => match envelope.response.as_mut() {
                            ipc::CmFileResponseKind::ReadBlock { data, .. } => {
                                Some(std::mem::take(data))
                            }
                            _ => None,
                        },
                        _ => None,
                    };
                    if let Err(e) = self.stream.send(&data).await {
                        log::error!("error encountered in IPC task, quitting: {}", e);
                        break;
                    }
                    if let Some(raw_block) = raw_block {
                        if let Err(e) = self.stream.send_raw(raw_block).await {
                            log::error!("error sending CM read block data: {}", e);
                            break;
                        }
                    }
                },
                clip_file = rx_clip.recv() => match clip_file {
                    Some(clipboard::ClipboardFileEgressItem::Message(clip)) => {
                        #[cfg(target_os = "windows")]
                        {
                            let is_stopping_allowed = clip.is_stopping_allowed();
                            let is_clipboard_enabled = ContextSend::is_enabled();
                            let file_transfer_enabled = self.file_transfer_enabled;
                            let file_transfer_enabled_peer = self.file_transfer_enabled_peer;
                            let stop = is_stopping_allowed && !(is_clipboard_enabled && file_transfer_enabled && file_transfer_enabled_peer);
                            log::debug!(
                                "Process clipboard message from clip, stop: {}, is_stopping_allowed: {}, is_clipboard_enabled: {}, file_transfer_enabled: {}, file_transfer_enabled_peer: {}",
                                stop, is_stopping_allowed, is_clipboard_enabled, file_transfer_enabled, file_transfer_enabled_peer);
                            if stop {
                                ContextSend::set_is_stopped();
                            } else {
                                if clip.is_beginning_message() && crate::get_builtin_option(OPTION_ONE_WAY_FILE_TRANSFER) == "Y" {
                                    // If one way file transfer is enabled, don't send clipboard file to client
                                    // Don't call `ContextSend::set_is_stopped()`, because it will stop bidirectional file copy&paste.
                                } else {
                                    allow_err!(self.tx.send(Data::ClipboardFile(clip)));
                                }
                            }
                        }
                    }
                    Some(clipboard::ClipboardFileEgressItem::Failed(failure)) => {
                        log::error!("connection-manager file-clipboard route failed: {failure}");
                        break;
                    }
                    None => {
                        log::error!("connection-manager file-clipboard route closed before its IPC owner");
                        break;
                    }
                },
                _ = file_timer.tick() => {
                    if !self.read_jobs.is_empty() {
                        let conn_id = self.conn_id;
                        if let Err(e) = handle_read_jobs_tick(
                            &mut self.read_jobs,
                            CmFileResponder {
                                tx: &self.tx,
                                conn_id,
                                cm_auth_token: &self.cm_auth_token,
                            },
                        )
                        .await
                        {
                            log::error!("Error processing read jobs: {}", e);
                        }
                        let log = serialize_cm_transfer_jobs(&self.read_jobs);
                        self.cm.ui_handler.file_transfer_log("transfer", &log);
                    } else {
                        file_timer = crate::rustdesk_interval(time::interval_at(Instant::now() + SEC30, SEC30));
                    }
                }
            }
        }
    }

    async fn ipc_task(stream: Connection, cm: ConnectionManager<T>) {
        log::debug!("ipc task begin");
        let (tx, rx) = cm_egress_channel();
        let mut task_runner = Self {
            stream,
            cm,
            tx,
            rx,
            close: true,
            running: true,
            conn_id: 0,
            file_authority: CmFileAuthority::absent(),
            cm_auth_token: String::new(),
            #[cfg(target_os = "windows")]
            file_transfer_enabled: false,
            #[cfg(target_os = "windows")]
            file_transfer_enabled_peer: false,
            read_jobs: Vec::new(),
        };

        while task_runner.running {
            task_runner.run().await;
        }
        if task_runner.conn_id > 0 {
            task_runner
                .cm
                .remove_connection(task_runner.conn_id, task_runner.close);
        }
        log::debug!("ipc task end");
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[tokio::main(flavor = "current_thread")]
pub async fn start_ipc<T: InvokeUiCM>(cm: ConnectionManager<T>) {
    #[cfg(target_os = "windows")]
    {
        let enabled = crate::Connection::is_permission_enabled_locally(OPTION_ENABLE_FILE_TRANSFER);
        let mut lock = crate::ui_interface::IS_FILE_TRANSFER_ENABLED
            .lock()
            .unwrap();
        ContextSend::enable(enabled);
        *lock = Some(enabled);
    }
    match ipc::new_listener("_cm").await {
        Ok(mut incoming) => {
            while let Some(result) = incoming.next().await {
                match result {
                    Ok(stream) => {
                        log::debug!("Got new connection");
                        let mut stream = Connection::new(stream);
                        stream.set_max_packet_length(ipc::CM_IPC_MAX_FRAME_BYTES);
                        if !ipc::authorize_cm_ipc_connection(&stream) {
                            log::warn!("Rejected unauthorized _cm IPC peer");
                            continue;
                        }
                        #[cfg(any(
                            target_os = "linux",
                            target_os = "macos",
                            target_os = "windows"
                        ))]
                        if let Err(err) = ipc::answer_cm_endpoint_challenge(&mut stream).await {
                            log::warn!(
                                "Rejected _cm IPC peer without launch-bound endpoint proof: {}",
                                err
                            );
                            continue;
                        }
                        tokio::spawn(IpcTaskRunner::<T>::ipc_task(stream, cm.clone()));
                    }
                    Err(err) => {
                        log::error!("Couldn't get cm client: {:?}", err);
                    }
                }
            }
        }
        Err(err) => {
            log::error!("Failed to start cm ipc server: {}", err);
        }
    }
    quit_cm();
}

#[cfg(target_os = "android")]
#[tokio::main(flavor = "current_thread")]
pub async fn start_listen<T: InvokeUiCM>(
    cm: ConnectionManager<T>,
    mut rx: mpsc::Receiver<Data>,
    mut terminal: tokio::sync::oneshot::Receiver<CmConnectionTerminal>,
    tx: CmEgressSender,
) {
    let mut current_id = 0;
    let mut current_cm_auth_token = String::new();
    let mut file_authority = CmFileAuthority::absent();
    let mut write_jobs: Vec<CmTransferJob> = Vec::new();
    loop {
        let command = tokio::select! {
            biased;
            terminal = &mut terminal => {
                match terminal {
                    Ok(terminal) => Some(terminal.into_data()),
                    Err(_) => None,
                }
            }
            command = rx.recv() => command,
        };
        match command {
            Some(Data::Login {
                id,
                is_file_transfer,
                is_view_camera,
                is_terminal,
                port_forward,
                conn_type,
                peer_id,
                name,
                avatar,
                authorized,
                keyboard,
                clipboard,
                audio,
                file,
                privacy_mode,
                cm_auth_token,
                ..
            }) => {
                let connection_authority = ipc::CmConnectionAuthority {
                    valid: !cm_auth_token.is_empty(),
                    file,
                    clipboard: clipboard && conn_type.allows_clipboard_authority(),
                };
                file_authority = CmFileAuthority::from_login(
                    id,
                    authorized,
                    conn_type,
                    file,
                    connection_authority,
                );
                current_id = id;
                current_cm_auth_token = cm_auth_token;
                cm.add_connection(
                    id,
                    is_file_transfer,
                    is_view_camera,
                    is_terminal,
                    port_forward,
                    conn_type,
                    peer_id,
                    name,
                    avatar,
                    authorized,
                    keyboard,
                    clipboard,
                    audio,
                    file,
                    privacy_mode,
                    tx.clone(),
                );
            }
            Some(Data::ChatMessage { text }) => {
                cm.new_message(current_id, text);
            }
            Some(Data::FS(fs)) => {
                if !file_authority.allows_fs(true) {
                    log::warn!(
                        "Rejected Android CM Data::FS before authorized file-capable login: conn_id={}",
                        file_authority.conn_id
                    );
                    continue;
                }
                // Android doesn't need CM-side file reading (no need_validate_file_read_access)
                let mut read_jobs_placeholder: Vec<CmTransferJob> = Vec::new();
                let _ = handle_fs(
                    fs,
                    &mut write_jobs,
                    &mut read_jobs_placeholder,
                    CmFileResponder {
                        tx: &tx,
                        conn_id: current_id,
                        cm_auth_token: &current_cm_auth_token,
                    },
                    false,
                )
                .await;
            }
            Some(Data::Close) => {
                break;
            }
            Some(Data::StartVoiceCall) => {
                cm.voice_call_started(current_id);
            }
            Some(Data::VoiceCallIncoming) => {
                cm.voice_call_incoming(current_id);
            }
            Some(Data::CloseVoiceCall(reason)) => {
                cm.voice_call_closed(current_id, reason.as_str());
            }
            None => {
                break;
            }
            _ => {}
        }
    }
    cm.remove_connection(current_id, true);
}

#[cfg(not(any(target_os = "ios")))]
fn get_transfer_job_for_connection(
    jobs: &mut [CmTransferJob],
    id: i32,
    conn_id: i32,
    generation: u64,
) -> Option<&mut CmTransferJob> {
    jobs.iter_mut().find(|job| {
        job.job.id() == id && job.job.conn_id == conn_id && job.generation == generation
    })
}

#[cfg(not(any(target_os = "ios")))]
fn remove_transfer_job_for_connection(
    jobs: &mut Vec<CmTransferJob>,
    id: i32,
    conn_id: i32,
    generation: u64,
) -> Option<CmTransferJob> {
    jobs.iter()
        .position(|job| {
            job.job.id() == id && job.job.conn_id == conn_id && job.generation == generation
        })
        .map(|index| jobs.remove(index))
}

#[cfg(not(any(target_os = "ios")))]
fn active_jobs_for_connection(jobs: &[CmTransferJob], conn_id: i32) -> usize {
    jobs.iter().filter(|job| job.job.conn_id == conn_id).count()
}

#[cfg(not(any(target_os = "ios")))]
fn has_job_for_connection(jobs: &[CmTransferJob], id: i32, conn_id: i32) -> bool {
    jobs.iter()
        .any(|job| job.job.id() == id && job.job.conn_id == conn_id)
}

#[cfg(not(any(target_os = "ios")))]
fn serialize_cm_transfer_jobs(jobs: &[CmTransferJob]) -> String {
    let jobs = jobs.iter().map(|job| &job.job).collect::<Vec<_>>();
    match serde_json::to_string(&jobs) {
        Ok(value) => value,
        Err(err) => {
            log::error!("failed to serialize transfer jobs: {}", err);
            "[]".to_owned()
        }
    }
}

#[cfg(not(any(target_os = "ios")))]
fn reject_write_job(
    responder: CmFileResponder,
    id: i32,
    generation: u64,
    file_num: i32,
    err: String,
) {
    responder.send(ipc::CmFileResponseKind::WriteFailed {
        id,
        generation,
        file_num,
        error: err,
    });
}

#[cfg(not(any(target_os = "ios")))]
async fn handle_fs(
    fs: ipc::FS,
    write_jobs: &mut Vec<CmTransferJob>,
    read_jobs: &mut Vec<CmTransferJob>,
    responder: CmFileResponder<'_>,
    return_job_log: bool,
) -> Option<String> {
    let mut job_log = None;
    match fs {
        ipc::FS::ReadEmptyDirs {
            dir,
            include_hidden,
            request_id,
        } => {
            read_empty_dirs(&dir, include_hidden, request_id, responder).await;
        }
        ipc::FS::ReadDir {
            dir,
            include_hidden,
            request_id,
        } => {
            read_dir(&dir, include_hidden, request_id, responder).await;
        }
        ipc::FS::RemoveDir {
            path,
            id: _,
            recursive,
            request_id,
        } => {
            remove_dir(path, request_id, recursive, responder).await;
        }
        ipc::FS::RemoveFile {
            path, request_id, ..
        } => {
            remove_file(path, request_id, responder).await;
        }
        ipc::FS::CreateDir {
            path, request_id, ..
        } => {
            create_dir(path, request_id, responder).await;
        }
        ipc::FS::NewWrite {
            path,
            id,
            file_num,
            files,
            overwrite_detection,
            total_size,
            conn_id,
            generation,
        } => {
            if conn_id != responder.conn_id {
                reject_write_job(
                    responder,
                    id,
                    generation,
                    file_num,
                    "write job connection authority mismatch".to_owned(),
                );
                return None;
            }
            if has_job_for_connection(write_jobs, id, conn_id) {
                reject_write_job(
                    responder,
                    id,
                    generation,
                    file_num,
                    format!("duplicate write job id {}", id),
                );
                return None;
            }
            if active_jobs_for_connection(write_jobs, conn_id)
                >= fs::MAX_ACTIVE_FILE_TRANSFER_WRITE_JOBS_PER_CONN
            {
                reject_write_job(
                    responder,
                    id,
                    generation,
                    file_num,
                    format!(
                        "too many active write jobs for connection (limit {})",
                        fs::MAX_ACTIVE_FILE_TRANSFER_WRITE_JOBS_PER_CONN
                    ),
                );
                return None;
            }
            if let Err(msg) = check_file_count_limit(files.len()) {
                reject_write_job(responder, id, generation, file_num, msg);
                return None;
            }
            // Convert files to FileEntry
            let file_entries: Vec<FileEntry> = files
                .into_iter()
                .map(|f| FileEntry {
                    name: f.0,
                    modified_time: f.1,
                    ..Default::default()
                })
                .collect();

            // cm has no show_hidden context
            // dummy remote, show_hidden, is_remote
            let mut job = fs::TransferJob::new_write(
                id,
                fs::JobType::Generic,
                "".to_string(),
                fs::DataSource::FilePath(PathBuf::from(&path)),
                file_num,
                false,
                false,
                overwrite_detection,
            );
            if let Err(e) = job.set_files_with_limit(file_entries, get_max_validated_files()) {
                log::warn!("Reject unsafe transfer file list for {}: {}", path, e);
                reject_write_job(responder, id, generation, file_num, e.to_string());
                return None;
            }
            job.total_size = total_size;
            job.conn_id = conn_id;
            write_jobs.push(CmTransferJob { generation, job });
        }
        ipc::FS::CancelWrite {
            id,
            conn_id,
            generation,
        } => {
            if let Some(mut job) =
                remove_transfer_job_for_connection(write_jobs, id, conn_id, generation)
            {
                job.job.remove_download_file();
                if return_job_log {
                    job_log = Some(serialize_transfer_job(&job.job, false, true, ""));
                }
            }
        }
        ipc::FS::WriteDone {
            id,
            file_num,
            conn_id,
            generation,
        } => {
            let result = if let Some(job) =
                remove_transfer_job_for_connection(write_jobs, id, conn_id, generation)
            {
                job.job.modify_time();
                if return_job_log {
                    job_log = Some(serialize_transfer_job(&job.job, true, false, ""));
                }
                Ok(())
            } else {
                Err(format!(
                    "unknown write job id {} generation {} file {}",
                    id, generation, file_num
                ))
            };
            responder.send(ipc::CmFileResponseKind::WriteFinalized {
                id,
                generation,
                result,
            });
        }
        ipc::FS::WriteError {
            id,
            file_num,
            conn_id,
            err,
            generation,
        } => {
            let result = if let Some(job) =
                remove_transfer_job_for_connection(write_jobs, id, conn_id, generation)
            {
                if return_job_log {
                    job_log = Some(serialize_transfer_job(&job.job, false, false, &err));
                }
                Ok(())
            } else {
                Err(format!(
                    "unknown write job id {} generation {} file {}",
                    id, generation, file_num
                ))
            };
            responder.send(ipc::CmFileResponseKind::WriteFinalized {
                id,
                generation,
                result,
            });
        }
        ipc::FS::WriteBlock {
            id,
            file_num,
            conn_id,
            data,
            compressed,
            generation,
        } => {
            let write_result = if let Some(job) =
                get_transfer_job_for_connection(write_jobs, id, conn_id, generation)
            {
                job.job
                    .write(FileTransferBlock {
                        id,
                        file_num,
                        data,
                        compressed,
                        ..Default::default()
                    })
                    .await
                    .map_err(|error| error.to_string())
            } else {
                Err(format!(
                    "unknown write job id {} generation {}",
                    id, generation
                ))
            };
            if let Err(error) = write_result {
                if let Some(mut job) =
                    remove_transfer_job_for_connection(write_jobs, id, conn_id, generation)
                {
                    job.job.remove_download_file();
                }
                reject_write_job(responder, id, generation, file_num, error);
            }
        }
        ipc::FS::CheckDigest {
            id,
            file_num,
            conn_id,
            file_size,
            last_modified,
            is_upload,
            is_resume,
            generation,
            request_id,
        } => {
            let _ = is_upload;
            let result = if let Some(job) =
                get_transfer_job_for_connection(write_jobs, id, conn_id, generation)
            {
                let digest = FileTransferDigest {
                    id,
                    file_num,
                    last_modified,
                    file_size,
                    ..Default::default()
                };
                match (job.job.files().get(file_num as usize), &job.job.data_source) {
                    (Some(file), fs::DataSource::FilePath(base)) => {
                        let path = get_string(&fs::TransferJob::join(base, &file.name));
                        match is_write_need_confirmation(is_resume, &path, &digest) {
                            Ok(DigestCheckResult::IsSame) => {
                                job.job.set_digest(file_size, last_modified);
                                ipc::CmWriteDigestResult::SendConfirm { skip: true }
                            }
                            Ok(DigestCheckResult::NoSuchFile) => {
                                job.job.set_digest(file_size, last_modified);
                                ipc::CmWriteDigestResult::SendConfirm { skip: false }
                            }
                            Ok(DigestCheckResult::NeedConfirm(digest)) => {
                                job.job.set_digest(file_size, last_modified);
                                ipc::CmWriteDigestResult::Digest {
                                    last_modified: digest.last_modified,
                                    file_size: digest.file_size,
                                    is_identical: digest.is_identical,
                                    transferred_size: digest.transferred_size,
                                }
                            }
                            Err(error) => ipc::CmWriteDigestResult::Error(error.to_string()),
                        }
                    }
                    _ => ipc::CmWriteDigestResult::Error(format!(
                        "invalid write job file {}",
                        file_num
                    )),
                }
            } else {
                ipc::CmWriteDigestResult::Error(format!(
                    "unknown write job id {} generation {}",
                    id, generation
                ))
            };
            responder.send(ipc::CmFileResponseKind::WriteDigest {
                id,
                generation,
                request_id,
                file_num,
                result,
            });
        }
        ipc::FS::SendConfirm {
            id,
            file_num,
            skip,
            offset_blk,
            conn_id,
            generation,
        } => {
            if let Some(job) = get_transfer_job_for_connection(write_jobs, id, conn_id, generation)
            {
                let request = FileTransferSendConfirmRequest {
                    id,
                    file_num,
                    union: if skip {
                        Some(file_transfer_send_confirm_request::Union::Skip(true))
                    } else {
                        Some(file_transfer_send_confirm_request::Union::OffsetBlk(
                            offset_blk,
                        ))
                    },
                    ..Default::default()
                };
                job.job.confirm(&request).await;
            }
        }
        ipc::FS::Rename {
            path,
            new_name,
            request_id,
            ..
        } => {
            rename_file(path, new_name, request_id, responder).await;
        }
        ipc::FS::ReadFile {
            path,
            id,
            file_num,
            include_hidden,
            conn_id,
            overwrite_detection,
            generation,
        } => {
            start_read_job(
                path,
                file_num,
                include_hidden,
                id,
                conn_id,
                generation,
                overwrite_detection,
                read_jobs,
                responder,
            )
            .await;
        }
        // Cancel an ongoing read job (file transfer from server to client).
        // Note: This only cancels jobs in `read_jobs`. It does NOT cancel `ReadAllFiles`
        // operations, which are one-shot directory scans that complete quickly and don't
        // have persistent job tracking.
        ipc::FS::CancelRead {
            id,
            conn_id,
            generation,
        } => {
            if let Some(job) =
                remove_transfer_job_for_connection(read_jobs, id, conn_id, generation)
            {
                if return_job_log {
                    job_log = Some(serialize_transfer_job(&job.job, false, true, ""));
                }
            }
        }
        ipc::FS::SendConfirmForRead {
            id,
            file_num,
            skip,
            offset_blk,
            conn_id,
            generation,
        } => {
            if let Some(job) = get_transfer_job_for_connection(read_jobs, id, conn_id, generation) {
                if job.job.file_num() != file_num {
                    return None;
                }
                let req = FileTransferSendConfirmRequest {
                    id,
                    file_num,
                    union: if skip {
                        Some(file_transfer_send_confirm_request::Union::Skip(true))
                    } else {
                        Some(file_transfer_send_confirm_request::Union::OffsetBlk(
                            offset_blk,
                        ))
                    },
                    ..Default::default()
                };
                job.job.confirm(&req).await;
            }
        }
        // Recursively list all files in a directory.
        // This is a one-shot operation that cannot be cancelled via CancelRead.
        // The operation typically completes quickly as it only reads directory metadata,
        // not file contents. File count is limited by `check_file_count_limit()`.
        ipc::FS::ReadAllFiles {
            path,
            id,
            include_hidden,
            request_id,
            ..
        } => {
            read_all_files(path, include_hidden, id, request_id, responder).await;
        }
    }
    job_log
}

/// Start a read job in CM for file transfer from server to client (Windows only).
///
/// This creates a `TransferJob` using `new_read()`, validates it, and sends the
/// initial file list back to Connection via IPC.
///
/// NOTE: This is the CM-side equivalent of `create_and_start_read_job()` in
/// `src/server/connection.rs`. On non-Windows platforms, Connection handles
/// read jobs directly. Both use `TransferJob::new_read()` with similar logic.
/// When modifying job creation or validation, ensure both paths stay in sync.
#[cfg(not(any(target_os = "ios")))]
async fn start_read_job(
    path: String,
    file_num: i32,
    include_hidden: bool,
    id: i32,
    conn_id: i32,
    generation: u64,
    overwrite_detection: bool,
    read_jobs: &mut Vec<CmTransferJob>,
    responder: CmFileResponder<'_>,
) {
    let respond = |result| {
        responder.send(ipc::CmFileResponseKind::ReadJobInit {
            id,
            generation,
            result,
        });
    };
    if conn_id != responder.conn_id {
        respond(Err("read job connection authority mismatch".to_owned()));
        return;
    }
    if has_job_for_connection(read_jobs, id, conn_id) {
        respond(Err(format!("duplicate read job id {}", id)));
        return;
    }
    if active_jobs_for_connection(read_jobs, conn_id)
        >= fs::MAX_ACTIVE_FILE_TRANSFER_READ_JOBS_PER_CONN
    {
        respond(Err(format!(
            "too many active read jobs for connection (limit {})",
            fs::MAX_ACTIVE_FILE_TRANSFER_READ_JOBS_PER_CONN
        )));
        return;
    }
    let _metadata_scan_permit = match try_acquire_file_metadata_scan() {
        Ok(permit) => permit,
        Err(msg) => {
            respond(Err(msg));
            return;
        }
    };
    let budget = file_transfer_enumeration_budget();
    let path_clone = path.clone();
    let result = spawn_blocking(move || -> ResultType<fs::TransferJob> {
        let data_source = fs::DataSource::FilePath(PathBuf::from(&path));
        fs::TransferJob::new_read_with_budget(
            id,
            fs::JobType::Generic,
            "".to_string(),
            data_source,
            file_num,
            include_hidden,
            true,
            overwrite_detection,
            budget,
        )
    })
    .await;

    match result {
        Ok(Ok(mut job)) => {
            // Optional: enforce file count limit for CM-side jobs to avoid
            // excessive I/O. This is applied on the job's file list produced
            // by `new_read`, similar to how AllFiles uses the same helper.
            if let Err(msg) = check_file_count_limit(job.files().len()) {
                respond(Err(msg));
                return;
            }

            // Build FileDirectory from the job's file list and serialize
            let files = job.files().to_owned();
            let mut dir = FileDirectory::new();
            dir.id = id;
            dir.path = path_clone.clone();
            dir.entries = files.clone().into();

            let directory = match cm_file_directory(dir) {
                Ok(directory) => directory,
                Err(error) => {
                    respond(Err(error));
                    return;
                }
            };
            respond(Ok(directory));

            // Attach connection id so CM can route read blocks back correctly
            job.conn_id = conn_id;
            read_jobs.push(CmTransferJob { generation, job });
        }
        Ok(Err(e)) => {
            respond(Err(format!("validation failed: {}", e)));
        }
        Err(e) => {
            respond(Err(format!("validation task failed: {}", e)));
        }
    }
}

/// Process read jobs periodically, reading file blocks and sending them via IPC.
///
/// NOTE: This is the CM-side equivalent of `handle_read_jobs()` in
/// `libs/hbb_common/src/fs.rs`. The logic mirrors that implementation
/// but communicates via IPC instead of direct network stream.
/// When modifying job processing logic, ensure both implementations stay in sync.
#[cfg(not(any(target_os = "ios")))]
async fn handle_read_jobs_tick(
    jobs: &mut Vec<CmTransferJob>,
    responder: CmFileResponder<'_>,
) -> ResultType<()> {
    let mut finished = Vec::new();

    for transfer in jobs.iter_mut() {
        let generation = transfer.generation;
        let job = &mut transfer.job;
        if job.is_last_job {
            continue;
        }

        // Initialize data stream if needed (opens file, sends digest for overwrite detection)
        if let Err(err) = init_read_job_for_cm(job, generation, responder).await {
            responder.send(ipc::CmFileResponseKind::ReadError {
                id: job.id,
                generation,
                file_num: job.file_num(),
                error: err.to_string(),
            });
            finished.push((job.id, generation, job.conn_id));
            continue;
        }

        // Read a block from the file
        match job.read().await {
            Err(err) => {
                responder.send(ipc::CmFileResponseKind::ReadError {
                    id: job.id,
                    generation,
                    file_num: job.file_num(),
                    error: err.to_string(),
                });
                finished.push((job.id, generation, job.conn_id));
            }
            Ok(Some(block)) => {
                responder.send(ipc::CmFileResponseKind::ReadBlock {
                    id: block.id,
                    generation,
                    file_num: block.file_num,
                    data: block.data,
                    compressed: block.compressed,
                });
            }
            Ok(None) => {
                if job.job_completed() {
                    finished.push((job.id, generation, job.conn_id));
                    match job.job_error() {
                        Some(err) => {
                            responder.send(ipc::CmFileResponseKind::ReadError {
                                id: job.id,
                                generation,
                                file_num: job.file_num(),
                                error: err,
                            });
                        }
                        None => {
                            responder.send(ipc::CmFileResponseKind::ReadDone {
                                id: job.id,
                                generation,
                                file_num: job.file_num(),
                            });
                        }
                    }
                }
                // else: waiting for confirmation from peer
            }
        }
        // Break to handle jobs one by one.
        break;
    }

    for (id, generation, conn_id) in finished {
        let _ = remove_transfer_job_for_connection(jobs, id, conn_id, generation);
    }

    Ok(())
}

/// Initialize a read job's data stream and handle digest sending for overwrite detection.
///
/// NOTE: This is the CM-side equivalent of `TransferJob::init_data_stream()` in
/// `libs/hbb_common/src/fs.rs`. It calls `init_data_stream_for_cm()` and sends
/// digest via IPC instead of direct network stream.
/// When modifying initialization or digest logic, ensure both paths stay in sync.
#[cfg(not(any(target_os = "ios")))]
async fn init_read_job_for_cm(
    job: &mut fs::TransferJob,
    generation: u64,
    responder: CmFileResponder<'_>,
) -> ResultType<()> {
    // Initialize data stream and get digest info if overwrite detection is needed
    match job.init_data_stream_for_cm().await? {
        Some((last_modified, file_size)) => {
            // Send digest via IPC for overwrite detection
            responder.send(ipc::CmFileResponseKind::ReadDigest {
                id: job.id,
                generation,
                file_num: job.file_num(),
                last_modified,
                file_size,
                is_resume: job.is_resume,
            });
        }
        None => {
            // Job done or already initialized, nothing to do
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "ios")))]
async fn read_all_files(
    path: String,
    include_hidden: bool,
    id: i32,
    request_id: u64,
    responder: CmFileResponder<'_>,
) {
    let _metadata_scan_permit = match try_acquire_file_metadata_scan() {
        Ok(permit) => permit,
        Err(msg) => {
            responder.send(ipc::CmFileResponseKind::AllFiles {
                request_id,
                result: Err(msg),
            });
            return;
        }
    };
    let budget = file_transfer_enumeration_budget();
    let path_clone = path.clone();
    let result =
        spawn_blocking(move || fs::get_recursive_files_with_budget(&path, include_hidden, budget))
            .await;

    let result = match result {
        Ok(Ok(files)) => {
            // Check file count limit to prevent excessive I/O and resource usage
            if let Err(msg) = check_file_count_limit(files.len()) {
                Err(msg)
            } else {
                let mut fd = FileDirectory::new();
                fd.id = id;
                fd.path = path_clone.clone();
                fd.entries = files.into();
                cm_file_directory(fd)
            }
        }
        Ok(Err(e)) => Err(format!("{}", e)),
        Err(e) => Err(format!("task failed: {}", e)),
    };

    responder.send(ipc::CmFileResponseKind::AllFiles { request_id, result });
}

#[cfg(not(any(target_os = "ios")))]
async fn read_empty_dirs(
    dir: &str,
    include_hidden: bool,
    request_id: u64,
    responder: CmFileResponder<'_>,
) {
    let path = dir.to_owned();
    let path_clone = dir.to_owned();

    let _metadata_scan_permit = match try_acquire_file_metadata_scan() {
        Ok(permit) => permit,
        Err(msg) => {
            responder.send(ipc::CmFileResponseKind::ReadEmptyDirectories {
                request_id,
                path: path_clone,
                result: Err(msg),
            });
            return;
        }
    };
    let budget = file_transfer_enumeration_budget();
    let result = match spawn_blocking(move || {
        fs::get_empty_dirs_recursive_with_budget(&path, include_hidden, budget)
    })
    .await
    {
        Ok(Ok(fds)) => fds.into_iter().map(cm_file_directory).collect(),
        Ok(Err(error)) => Err(error.to_string()),
        Err(error) => Err(format!("metadata task failed: {}", error)),
    };
    responder.send(ipc::CmFileResponseKind::ReadEmptyDirectories {
        request_id,
        path: path_clone,
        result,
    });
}

#[cfg(not(any(target_os = "ios")))]
async fn read_dir(
    dir: &str,
    include_hidden: bool,
    request_id: u64,
    responder: CmFileResponder<'_>,
) {
    let requested_path = dir.to_owned();
    let path = {
        if dir.is_empty() {
            Config::get_home()
        } else {
            fs::get_path(dir)
        }
    };
    let _metadata_scan_permit = match try_acquire_file_metadata_scan() {
        Ok(permit) => permit,
        Err(msg) => {
            responder.send(ipc::CmFileResponseKind::ReadDirectory {
                request_id,
                path: requested_path,
                result: Err(msg),
            });
            return;
        }
    };
    let budget = file_transfer_enumeration_budget();
    let result =
        match spawn_blocking(move || fs::read_dir_with_budget(&path, include_hidden, budget)).await
        {
            Ok(Ok(directory)) => cm_file_directory(directory),
            Ok(Err(error)) => Err(error.to_string()),
            Err(error) => Err(format!("metadata task failed: {}", error)),
        };
    responder.send(ipc::CmFileResponseKind::ReadDirectory {
        request_id,
        path: requested_path,
        result,
    });
}

#[cfg(not(any(target_os = "ios")))]
fn handle_result<F: std::fmt::Display, S: std::fmt::Display>(
    res: std::result::Result<std::result::Result<(), F>, S>,
    request_id: u64,
    operation: ipc::CmFileOperation,
    responder: CmFileResponder<'_>,
) {
    let result = match res {
        Err(error) => Err(error.to_string()),
        Ok(Err(error)) => Err(error.to_string()),
        Ok(Ok(())) => Ok(()),
    };
    responder.send(ipc::CmFileResponseKind::Operation {
        request_id,
        operation,
        result,
    });
}

#[cfg(not(any(target_os = "ios")))]
async fn remove_file(path: String, request_id: u64, responder: CmFileResponder<'_>) {
    let operation = ipc::CmFileOperation::RemoveFile { path: path.clone() };
    handle_result(
        spawn_blocking(move || fs::remove_file(&path)).await,
        request_id,
        operation,
        responder,
    );
}

#[cfg(not(any(target_os = "ios")))]
async fn create_dir(path: String, request_id: u64, responder: CmFileResponder<'_>) {
    let operation = ipc::CmFileOperation::CreateDirectory { path: path.clone() };
    handle_result(
        spawn_blocking(move || fs::create_dir(&path)).await,
        request_id,
        operation,
        responder,
    );
}

#[cfg(not(any(target_os = "ios")))]
async fn rename_file(
    path: String,
    new_name: String,
    request_id: u64,
    responder: CmFileResponder<'_>,
) {
    let operation = ipc::CmFileOperation::Rename {
        path: path.clone(),
        new_name: new_name.clone(),
    };
    handle_result(
        spawn_blocking(move || fs::rename_file(&path, &new_name)).await,
        request_id,
        operation,
        responder,
    );
}

#[cfg(not(any(target_os = "ios")))]
async fn remove_dir(
    path: String,
    request_id: u64,
    recursive: bool,
    responder: CmFileResponder<'_>,
) {
    let operation = ipc::CmFileOperation::RemoveDirectory {
        path: path.clone(),
        recursive,
    };
    let path = fs::get_path(&path);
    handle_result(
        spawn_blocking(move || {
            if recursive {
                fs::remove_all_empty_dir(&path)
            } else {
                std::fs::remove_dir(&path).map_err(|err| err.into())
            }
        })
        .await,
        request_id,
        operation,
        responder,
    );
}

#[cfg(windows)]
fn cm_inner_send(id: i32, data: Data) {
    let mut senders = cm_egress_senders(id);
    let Some(last) = senders.pop() else {
        return;
    };
    for tx in senders {
        allow_err!(tx.send(data.clone()));
    }
    allow_err!(last.send(data));
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn handle_incoming_voice_call(id: i32, accept: bool) {
    // Not handled in iOS yet.
    #[cfg(not(any(target_os = "ios")))]
    if let Some(tx) = cm_egress_sender(id) {
        allow_err!(tx.send(Data::VoiceCallResponse(accept)));
    };
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn close_voice_call(id: i32) {
    // Not handled in iOS yet.
    #[cfg(not(any(target_os = "ios")))]
    if let Some(tx) = cm_egress_sender(id) {
        allow_err!(tx.send(Data::CloseVoiceCall("".to_owned())));
    };
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn quit_cm() {
    // in case of std::process::exit not work
    log::info!("quit cm");
    CLIENTS.write().unwrap().clear();
    crate::platform::quit_gui();
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ipc::Data;
    use hbb_common::tokio::runtime::Runtime;
    use std::fs;

    #[tokio::test(flavor = "current_thread")]
    async fn r_s11gy_cm_egress_is_fifo_and_releases_capacity_on_receive() {
        let sample = Data::ChatMessage {
            text: "one".to_owned(),
        };
        let sample_bytes =
            cm_egress_encoded_bytes(&sample, 1024).unwrap() + std::mem::size_of::<QueuedCmEgress>();
        let (tx, mut rx) = cm_egress_channel_with_limits(CmEgressLimits {
            max_messages: 1,
            max_message_bytes: 1024,
            max_queued_bytes: sample_bytes,
        });
        tx.send(sample).unwrap();
        match rx.recv().await.unwrap() {
            CmEgressItem::Data(Data::ChatMessage { text }) => assert_eq!(text, "one"),
            _ => panic!("unexpected CM egress item"),
        }
        tx.send(Data::ChatMessage {
            text: "two".to_owned(),
        })
        .unwrap();
        match rx.recv().await.unwrap() {
            CmEgressItem::Data(Data::ChatMessage { text }) => assert_eq!(text, "two"),
            _ => panic!("unexpected CM egress item"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn r_s11gy_cm_egress_capacity_and_wrong_class_are_terminal() {
        let (tx, mut rx) = cm_egress_channel_with_limits(CmEgressLimits {
            max_messages: 1,
            max_message_bytes: 1024,
            max_queued_bytes: 4096,
        });
        tx.send(Data::Close).unwrap();
        assert_eq!(
            tx.send(Data::Close),
            Err(CmEgressAdmissionError::Failed(
                CmEgressFailure::MessageCapacity
            ))
        );
        {
            let state = lock_cm_egress(&tx.state);
            assert!(state.queue.is_empty());
            assert_eq!(state.queued_bytes, 0);
            assert_eq!(state.terminal, Some(CmEgressFailure::MessageCapacity));
        }
        assert_eq!(
            tx.send(Data::ChatMessage {
                text: "stale".to_owned(),
            }),
            Err(CmEgressAdmissionError::Failed(
                CmEgressFailure::MessageCapacity
            ))
        );
        assert!(matches!(
            rx.recv().await,
            Some(CmEgressItem::Failed(CmEgressFailure::MessageCapacity))
        ));
        assert_eq!(
            tx.send(Data::Close),
            Err(CmEgressAdmissionError::ReceiverGone)
        );

        let (tx, mut rx) = cm_egress_channel_with_limits(CmEgressLimits {
            max_messages: 1,
            max_message_bytes: 1024,
            max_queued_bytes: 4096,
        });
        assert_eq!(
            tx.send(Data::Disconnected),
            Err(CmEgressAdmissionError::Failed(
                CmEgressFailure::WrongMessageClass
            ))
        );
        assert!(matches!(
            rx.recv().await,
            Some(CmEgressItem::Failed(CmEgressFailure::WrongMessageClass))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn r_s11gy_cm_egress_encoded_byte_limits_are_terminal() {
        let small = Data::ChatMessage {
            text: "bounded".to_owned(),
        };
        let retained =
            cm_egress_encoded_bytes(&small, 1024).unwrap() + std::mem::size_of::<QueuedCmEgress>();
        let (tx, mut rx) = cm_egress_channel_with_limits(CmEgressLimits {
            max_messages: 2,
            max_message_bytes: 1024,
            max_queued_bytes: retained,
        });
        tx.send(small).unwrap();
        assert_eq!(
            tx.send(Data::Close),
            Err(CmEgressAdmissionError::Failed(
                CmEgressFailure::ByteCapacity
            ))
        );
        assert!(matches!(
            rx.recv().await,
            Some(CmEgressItem::Failed(CmEgressFailure::ByteCapacity))
        ));

        let (tx, mut rx) = cm_egress_channel_with_limits(CmEgressLimits {
            max_messages: 1,
            max_message_bytes: 32,
            max_queued_bytes: 4096,
        });
        assert_eq!(
            tx.send(Data::ChatMessage {
                text: "x".repeat(64),
            }),
            Err(CmEgressAdmissionError::Failed(
                CmEgressFailure::MessageTooLarge
            ))
        );
        assert!(matches!(
            rx.recv().await,
            Some(CmEgressItem::Failed(CmEgressFailure::MessageTooLarge))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn r_s11gy_cm_egress_accounts_serde_skipped_raw_blocks_and_receiver_retirement() {
        let read_block = |len| {
            Data::CmFileResponse(ipc::CmFileResponse {
                conn_id: 7,
                cm_auth_token: "token".to_owned(),
                response: Box::new(ipc::CmFileResponseKind::ReadBlock {
                    id: 1,
                    generation: 2,
                    file_num: 3,
                    data: bytes::Bytes::from(vec![0xa5; len]),
                    compressed: false,
                }),
            })
        };
        let data = read_block(64);
        let structured_only = cm_egress_encoded_bytes(&read_block(0), 4096).unwrap();
        let with_raw = cm_egress_encoded_bytes(&data, 4096).unwrap();
        assert_eq!(with_raw, structured_only + 64);

        let (tx, mut rx) = cm_egress_channel_with_limits(CmEgressLimits {
            max_messages: 1,
            max_message_bytes: with_raw,
            max_queued_bytes: with_raw + std::mem::size_of::<QueuedCmEgress>(),
        });
        tx.send(data).unwrap();
        match rx.recv().await.unwrap() {
            CmEgressItem::Data(Data::CmFileResponse(response)) => match *response.response {
                ipc::CmFileResponseKind::ReadBlock { data, .. } => assert_eq!(data.len(), 64),
                _ => panic!("unexpected CM file response"),
            },
            _ => panic!("unexpected CM egress item"),
        }

        let (tx, mut rx) = cm_egress_channel();
        assert_eq!(
            tx.send(read_block(ipc::CM_FILE_BLOCK_MAX_FRAME_BYTES + 1)),
            Err(CmEgressAdmissionError::Failed(
                CmEgressFailure::MessageTooLarge
            ))
        );
        assert!(matches!(
            rx.recv().await,
            Some(CmEgressItem::Failed(CmEgressFailure::MessageTooLarge))
        ));

        let (tx, rx) = cm_egress_channel();
        drop(rx);
        assert_eq!(
            tx.send(Data::Close),
            Err(CmEgressAdmissionError::ReceiverGone)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn r_s11gy_cm_egress_wakes_without_polling_and_sender_retirement_closes() {
        let (tx, mut rx) = cm_egress_channel();
        let waiting = tokio::spawn(async move { rx.recv().await });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        tx.send(Data::ChatMessage {
            text: "wake".to_owned(),
        })
        .unwrap();
        assert!(matches!(
            waiting.await.unwrap(),
            Some(CmEgressItem::Data(Data::ChatMessage { text })) if text == "wake"
        ));

        let (tx, mut rx) = cm_egress_channel();
        let waiting = tokio::spawn(async move { rx.recv().await });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop(tx);
        assert!(waiting.await.unwrap().is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn r_s11ha_cm_file_job_log_is_returned_to_the_exact_command_owner() {
        let (tx, _rx) = cm_egress_channel();
        let mut write_jobs = Vec::new();
        let mut read_jobs = Vec::new();
        let responder = CmFileResponder {
            tx: &tx,
            conn_id: 41,
            cm_auth_token: "token",
        };
        let started = handle_fs(
            ipc::FS::NewWrite {
                path: std::env::temp_dir()
                    .join("rustdesk-r-s11ha-direct-log")
                    .to_string_lossy()
                    .into_owned(),
                id: 9,
                file_num: 0,
                files: vec![("sample.txt".to_owned(), 0)],
                overwrite_detection: false,
                total_size: 0,
                conn_id: 41,
                generation: 7,
            },
            &mut write_jobs,
            &mut read_jobs,
            responder,
            true,
        )
        .await;
        assert!(started.is_none());
        assert_eq!(write_jobs.len(), 1);

        let terminal_log = handle_fs(
            ipc::FS::CancelWrite {
                id: 9,
                conn_id: 41,
                generation: 7,
            },
            &mut write_jobs,
            &mut read_jobs,
            responder,
            true,
        )
        .await
        .expect("cancelled exact job must return its terminal log");
        assert!(write_jobs.is_empty());
        let terminal_log: serde_json::Value = serde_json::from_str(&terminal_log).unwrap();
        assert_eq!(
            terminal_log.get("cancel").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            terminal_log.get("done").and_then(|v| v.as_bool()),
            Some(false)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn r_s11ha_cm_file_job_log_can_be_omitted_without_retaining_the_job() {
        let (tx, _rx) = cm_egress_channel();
        let mut write_jobs = Vec::new();
        let mut read_jobs = Vec::new();
        let responder = CmFileResponder {
            tx: &tx,
            conn_id: 42,
            cm_auth_token: "token",
        };
        assert!(handle_fs(
            ipc::FS::NewWrite {
                path: std::env::temp_dir()
                    .join("rustdesk-r-s11ha-omitted-log")
                    .to_string_lossy()
                    .into_owned(),
                id: 10,
                file_num: 0,
                files: vec![("sample.txt".to_owned(), 0)],
                overwrite_detection: false,
                total_size: 0,
                conn_id: 42,
                generation: 8,
            },
            &mut write_jobs,
            &mut read_jobs,
            responder,
            false,
        )
        .await
        .is_none());
        assert_eq!(write_jobs.len(), 1);
        assert!(handle_fs(
            ipc::FS::CancelWrite {
                id: 10,
                conn_id: 42,
                generation: 8,
            },
            &mut write_jobs,
            &mut read_jobs,
            responder,
            false,
        )
        .await
        .is_none());
        assert!(write_jobs.is_empty());
    }

    #[cfg(not(any(target_os = "ios")))]
    fn cm_authority(valid: bool, file: bool) -> ipc::CmConnectionAuthority {
        ipc::CmConnectionAuthority {
            valid,
            file,
            clipboard: false,
        }
    }

    #[test]
    #[cfg(not(any(target_os = "ios")))]
    fn cm_file_authority_rejects_absent_and_unauthorized_login() {
        assert!(!CmFileAuthority::absent().allows_fs(true));
        assert!(!CmFileAuthority::from_login(
            1,
            false,
            ipc::CmAuthConnType::FileTransfer,
            true,
            cm_authority(true, true)
        )
        .allows_fs(true));
        assert!(!CmFileAuthority::from_login(
            0,
            true,
            ipc::CmAuthConnType::FileTransfer,
            true,
            cm_authority(true, true)
        )
        .allows_fs(true));
        assert!(!CmFileAuthority::from_login(
            1,
            true,
            ipc::CmAuthConnType::FileTransfer,
            false,
            cm_authority(true, true)
        )
        .allows_fs(true));
        assert!(!CmFileAuthority::from_login(
            1,
            true,
            ipc::CmAuthConnType::FileTransfer,
            true,
            cm_authority(false, true)
        )
        .allows_fs(true));
        assert!(!CmFileAuthority::from_login(
            1,
            true,
            ipc::CmAuthConnType::FileTransfer,
            true,
            cm_authority(true, false)
        )
        .allows_fs(true));
    }

    #[test]
    #[cfg(not(any(target_os = "ios")))]
    fn cm_file_authority_allows_only_authorized_file_capable_sessions() {
        assert!(CmFileAuthority::from_login(
            7,
            true,
            ipc::CmAuthConnType::FileTransfer,
            true,
            cm_authority(true, true)
        )
        .allows_fs(true));
        assert!(!CmFileAuthority::from_login(
            7,
            true,
            ipc::CmAuthConnType::Remote,
            true,
            cm_authority(true, true)
        )
        .allows_fs(true));
        assert!(!CmFileAuthority::from_login(
            7,
            true,
            ipc::CmAuthConnType::FileTransfer,
            true,
            cm_authority(true, true)
        )
        .allows_fs(false));
        assert!(!CmFileAuthority::from_login(
            7,
            true,
            ipc::CmAuthConnType::ViewCamera,
            true,
            cm_authority(true, true)
        )
        .allows_fs(true));
        assert!(!CmFileAuthority::from_login(
            7,
            true,
            ipc::CmAuthConnType::Terminal,
            true,
            cm_authority(true, true)
        )
        .allows_fs(true));
        assert!(!CmFileAuthority::from_login(
            7,
            true,
            ipc::CmAuthConnType::PortForward,
            true,
            cm_authority(true, true)
        )
        .allows_fs(true));
        assert!(!CmFileAuthority::from_login(
            7,
            true,
            ipc::CmAuthConnType::Remote,
            true,
            cm_authority(false, true)
        )
        .allows_fs(true));
    }

    #[test]
    #[cfg(not(any(target_os = "ios")))]
    fn cm_presentation_contract_omits_connection_only_permissions() {
        let login = Data::Login {
            id: 7,
            is_file_transfer: false,
            is_view_camera: false,
            is_terminal: false,
            peer_id: "peer".to_owned(),
            name: "owner".to_owned(),
            avatar: String::new(),
            authorized: true,
            port_forward: String::new(),
            conn_type: ipc::CmAuthConnType::Remote,
            keyboard: true,
            clipboard: true,
            audio: true,
            file: true,
            file_transfer_enabled: true,
            privacy_mode: true,
            cm_auth_token: "token".to_owned(),
        };
        let login_json = serde_json::to_value(login).unwrap();
        let login_payload = login_json
            .get("c")
            .and_then(serde_json::Value::as_object)
            .unwrap();
        assert_eq!(
            login_payload
                .get("keyboard")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        for key in ["restart", "recording", "block_input"] {
            assert!(
                !login_payload.contains_key(key),
                "CM login unexpectedly serialized {key}"
            );
        }
        assert!(!login_payload.contains_key("from_switch"));

        let (tx, _rx) = cm_egress_channel();
        let client = Client {
            id: 7,
            authorized: true,
            disconnected: false,
            is_file_transfer: false,
            is_view_camera: false,
            is_terminal: false,
            port_forward: String::new(),
            conn_type: ipc::CmAuthConnType::Remote,
            name: "owner".to_owned(),
            avatar: String::new(),
            peer_id: "peer".to_owned(),
            keyboard: true,
            clipboard: true,
            audio: true,
            file: true,
            privacy_mode: true,
            in_voice_call: false,
            incoming_voice_call: false,
            tx,
        };
        let client_json = serde_json::to_value(client).unwrap();
        let client_payload = client_json.as_object().unwrap();
        assert_eq!(
            client_payload
                .get("keyboard")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            client_payload
                .get("conn_type")
                .and_then(|value| value.get("t"))
                .and_then(serde_json::Value::as_str),
            Some("Remote")
        );
        for key in ["restart", "recording", "block_input"] {
            assert!(
                !client_payload.contains_key(key),
                "CM client unexpectedly serialized {key}"
            );
        }
        assert!(!client_payload.contains_key("from_switch"));
    }

    #[test]
    #[cfg(not(any(target_os = "ios")))]
    fn read_all_files_success() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let (tx, mut rx) = cm_egress_channel();
            let dir = std::env::temp_dir().join("rustdesk_read_all_test");
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("test.txt"), b"hello").unwrap();

            let path_str = dir.to_string_lossy().to_string();
            super::read_all_files(
                path_str,
                false,
                1,
                2,
                CmFileResponder {
                    tx: &tx,
                    conn_id: 7,
                    cm_auth_token: "token",
                },
            )
            .await;

            match rx.recv().await.unwrap() {
                CmEgressItem::Data(Data::CmFileResponse(response)) => match *response.response {
                    ipc::CmFileResponseKind::AllFiles { request_id, result } => {
                        assert_eq!(request_id, 2);
                        assert!(!result.unwrap().entries.is_empty());
                    }
                    _ => panic!("unexpected CM file response"),
                },
                _ => panic!("unexpected data"),
            }
            let _ = fs::remove_dir_all(&dir);
        });
    }

    #[test]
    #[cfg(not(any(target_os = "ios")))]
    fn read_dir_success() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let (tx, mut rx) = cm_egress_channel();
            let dir = std::env::temp_dir().join("rustdesk_read_dir_test");
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();

            super::read_dir(
                &dir.to_string_lossy(),
                false,
                3,
                CmFileResponder {
                    tx: &tx,
                    conn_id: 7,
                    cm_auth_token: "token",
                },
            )
            .await;

            match rx.recv().await.unwrap() {
                CmEgressItem::Data(Data::CmFileResponse(response)) => match *response.response {
                    ipc::CmFileResponseKind::ReadDirectory {
                        request_id,
                        path,
                        result,
                    } => {
                        assert_eq!(request_id, 3);
                        assert_eq!(path, dir.to_string_lossy());
                        assert!(result.unwrap().path.contains("rustdesk_read_dir_test"));
                    }
                    _ => panic!("unexpected CM file response"),
                },
                _ => panic!("unexpected data"),
            }
            let _ = fs::remove_dir_all(&dir);
        });
    }

    /// Tests that symlink creation works on this platform.
    /// This is a helper to verify the test environment supports symlinks.
    #[test]
    #[cfg(not(any(target_os = "ios")))]
    fn test_symlink_creation_works() {
        let base_dir = std::env::temp_dir().join("rustdesk_symlink_test");
        let _ = fs::remove_dir_all(&base_dir);
        fs::create_dir_all(&base_dir).unwrap();

        // Create target file in a subdirectory
        let target_dir = base_dir.join("target_dir");
        fs::create_dir_all(&target_dir).unwrap();
        let target_file = target_dir.join("target.txt");
        fs::write(&target_file, b"content").unwrap();

        // Create symlink in a different directory
        let link_dir = base_dir.join("link_dir");
        fs::create_dir_all(&link_dir).unwrap();
        let link_path = link_dir.join("link.txt");

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            if symlink(&target_file, &link_path).is_err() {
                let _ = fs::remove_dir_all(&base_dir);
                return;
            }
        }

        #[cfg(windows)]
        {
            use std::os::windows::fs::symlink_file;
            if symlink_file(&target_file, &link_path).is_err() {
                // Skip if no permission (needs admin or dev mode on Windows)
                let _ = fs::remove_dir_all(&base_dir);
                return;
            }
        }

        let _ = fs::remove_dir_all(&base_dir);
    }
}
