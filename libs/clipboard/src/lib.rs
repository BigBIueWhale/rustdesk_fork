use std::{
    collections::VecDeque,
    fmt,
    sync::{Arc, Mutex, RwLock},
};

#[cfg(any(target_os = "windows", feature = "unix-file-copy-paste"))]
use hbb_common::log;
#[cfg(any(
    target_os = "windows",
    all(target_os = "macos", feature = "unix-file-copy-paste")
))]
use hbb_common::ResultType;
use hbb_common::{lazy_static, tokio::sync::mpsc};
use serde_derive::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(any(
    target_os = "windows",
    all(target_os = "macos", feature = "unix-file-copy-paste")
))]
pub mod context_send;
pub mod platform;
#[cfg(any(
    target_os = "windows",
    all(target_os = "macos", feature = "unix-file-copy-paste")
))]
pub use context_send::*;

#[cfg(target_os = "windows")]
const ERR_CODE_SERVER_FUNCTION_NONE: u32 = 0x00000001;
#[cfg(target_os = "windows")]
const ERR_CODE_INVALID_PARAMETER: u32 = 0x00000002;
#[cfg(target_os = "windows")]
const ERR_CODE_SEND_MSG: u32 = 0x00000003;

#[cfg(any(
    target_os = "windows",
    all(target_os = "macos", feature = "unix-file-copy-paste")
))]
pub(crate) use platform::create_cliprdr_context;

pub struct ProgressPercent {
    pub percent: f64,
    pub is_canceled: bool,
    pub is_failed: bool,
}

// to-do: This trait may be removed, because unix file copy paste does not need it.
/// Ability to handle Clipboard File from remote rustdesk client
///
/// # Note
/// There actually should be 2 parts to implement a useable clipboard file service,
/// but this only contains the RPC server part.
/// The local listener and transport part is too platform specific to wrap up in typeclasses.
pub trait CliprdrServiceContext: Send + Sync {
    /// set to be stopped
    fn set_is_stopped(&mut self) -> Result<(), CliprdrError>;
    /// clear the content on clipboard
    fn empty_clipboard(&mut self, conn_id: i32) -> Result<bool, CliprdrError>;
    /// run as a server for clipboard RPC
    fn server_clip_file(&mut self, conn_id: i32, msg: ClipboardFile) -> Result<(), CliprdrError>;
    /// get the progress of the paste task.
    fn get_progress_percent(&self) -> Option<ProgressPercent>;
    /// cancel the paste task.
    fn cancel(&mut self);
}

#[derive(Error, Debug)]
pub enum CliprdrError {
    #[error("invalid cliprdr name")]
    CliprdrName,
    #[error("failed to init cliprdr")]
    CliprdrInit,
    #[error("cliprdr out of memory")]
    CliprdrOutOfMemory,
    #[error("cliprdr internal error")]
    ClipboardInternalError,
    #[error("cliprdr occupied")]
    ClipboardOccupied,
    #[error("conversion failure")]
    ConversionFailure,
    #[error("failure to read clipboard")]
    OpenClipboard,
    #[error("failure to read file metadata or content, path: {path}, err: {err}")]
    FileError { path: String, err: std::io::Error },
    #[error("invalid request: {description}")]
    InvalidRequest { description: String },
    #[error("common request: {description}")]
    CommonError { description: String },
    #[error("unknown cliprdr error")]
    Unknown(u32),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "t", content = "c")]
pub enum ClipboardFile {
    NotifyCallback {
        r#type: String,
        title: String,
        text: String,
    },
    MonitorReady,
    FormatList {
        format_list: Vec<(i32, String)>,
    },
    FormatListResponse {
        msg_flags: i32,
    },
    FormatDataRequest {
        requested_format_id: i32,
    },
    FormatDataResponse {
        msg_flags: i32,
        format_data: Vec<u8>,
    },
    FileContentsRequest {
        stream_id: i32,
        list_index: i32,
        dw_flags: i32,
        n_position_low: i32,
        n_position_high: i32,
        cb_requested: i32,
        have_clip_data_id: bool,
        clip_data_id: i32,
    },
    FileContentsResponse {
        msg_flags: i32,
        stream_id: i32,
        requested_data: Vec<u8>,
    },
    TryEmpty,
    Files {
        files: Vec<(String, u64)>,
    },
}

// R-S11gz: native file-clipboard callbacks are synchronous while the owning connection consumes
// asynchronously. One exact route therefore owns a finite FIFO and a one-token wake rather than a
// process-global unbounded channel. Heap capacity is counted because that is the memory retained by
// Vec/String even when their current lengths are smaller.
const CLIPBOARD_FILE_EGRESS_WAKE_CAPACITY: usize = 1;
const CLIPBOARD_FILE_EGRESS_MAX_MESSAGES: usize = 256;
const CLIPBOARD_FILE_EGRESS_MAX_MESSAGE_HEAP_BYTES: usize = hbb_common::cpace::MAX_SESSION_PACKET;
const CLIPBOARD_FILE_EGRESS_MAX_QUEUED_BYTES: usize = hbb_common::cpace::MAX_SESSION_PACKET * 2
    + std::mem::size_of::<QueuedClipboardFile>() * CLIPBOARD_FILE_EGRESS_MAX_MESSAGES;

#[derive(Clone, Copy)]
struct ClipboardFileEgressLimits {
    max_messages: usize,
    max_message_heap_bytes: usize,
    max_queued_bytes: usize,
}

const CLIPBOARD_FILE_EGRESS_LIMITS: ClipboardFileEgressLimits = ClipboardFileEgressLimits {
    max_messages: CLIPBOARD_FILE_EGRESS_MAX_MESSAGES,
    max_message_heap_bytes: CLIPBOARD_FILE_EGRESS_MAX_MESSAGE_HEAP_BYTES,
    max_queued_bytes: CLIPBOARD_FILE_EGRESS_MAX_QUEUED_BYTES,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClipboardFileEgressFailure {
    MessageTooLarge,
    MessageCapacity,
    ByteCapacity,
    AccountingOverflow,
}

impl fmt::Display for ClipboardFileEgressFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::MessageTooLarge => "message exceeds the retained-heap ceiling",
            Self::MessageCapacity => "message-count capacity reached",
            Self::ByteCapacity => "retained-byte capacity reached",
            Self::AccountingOverflow => "resource accounting overflowed",
        };
        write!(f, "file-clipboard egress {reason}")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClipboardFileEgressAdmissionError {
    Failed(ClipboardFileEgressFailure),
    ReceiverGone,
}

impl fmt::Display for ClipboardFileEgressAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed(failure) => write!(f, "{failure}"),
            Self::ReceiverGone => write!(f, "file-clipboard egress receiver is gone"),
        }
    }
}

struct QueuedClipboardFile {
    data: ClipboardFile,
    retained_bytes: usize,
}

struct ClipboardFileEgressState {
    queue: VecDeque<QueuedClipboardFile>,
    queued_bytes: usize,
    terminal: Option<ClipboardFileEgressFailure>,
    receiver_open: bool,
}

impl Default for ClipboardFileEgressState {
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
pub struct ClipboardFileEgressSender {
    state: Arc<Mutex<ClipboardFileEgressState>>,
    wake: mpsc::Sender<()>,
    limits: ClipboardFileEgressLimits,
}

pub struct ClipboardFileEgressReceiver {
    state: Arc<Mutex<ClipboardFileEgressState>>,
    wake: mpsc::Receiver<()>,
}

pub enum ClipboardFileEgressItem {
    Message(ClipboardFile),
    Failed(ClipboardFileEgressFailure),
}

pub fn clipboard_file_egress_channel() -> (ClipboardFileEgressSender, ClipboardFileEgressReceiver) {
    clipboard_file_egress_channel_with_limits(CLIPBOARD_FILE_EGRESS_LIMITS)
}

fn clipboard_file_egress_channel_with_limits(
    limits: ClipboardFileEgressLimits,
) -> (ClipboardFileEgressSender, ClipboardFileEgressReceiver) {
    let state = Arc::new(Mutex::new(ClipboardFileEgressState::default()));
    let (wake, receiver) = mpsc::channel(CLIPBOARD_FILE_EGRESS_WAKE_CAPACITY);
    (
        ClipboardFileEgressSender {
            state: Arc::clone(&state),
            wake,
            limits,
        },
        ClipboardFileEgressReceiver {
            state,
            wake: receiver,
        },
    )
}

fn lock_clipboard_file_egress(
    state: &Mutex<ClipboardFileEgressState>,
) -> std::sync::MutexGuard<'_, ClipboardFileEgressState> {
    match state.lock() {
        Ok(state) => state,
        Err(poisoned) => {
            drop(poisoned);
            hbb_common::log::error!("file-clipboard egress state was poisoned; aborting");
            std::process::abort();
        }
    }
}

fn checked_heap_add(total: &mut usize, amount: usize) -> Result<(), ClipboardFileEgressFailure> {
    *total = total
        .checked_add(amount)
        .ok_or(ClipboardFileEgressFailure::AccountingOverflow)?;
    Ok(())
}

fn checked_allocation_bytes<T>(capacity: usize) -> Result<usize, ClipboardFileEgressFailure> {
    capacity
        .checked_mul(std::mem::size_of::<T>())
        .ok_or(ClipboardFileEgressFailure::AccountingOverflow)
}

fn clipboard_file_heap_bytes(data: &ClipboardFile) -> Result<usize, ClipboardFileEgressFailure> {
    let mut bytes = 0usize;
    match data {
        ClipboardFile::NotifyCallback {
            r#type,
            title,
            text,
        } => {
            checked_heap_add(&mut bytes, r#type.capacity())?;
            checked_heap_add(&mut bytes, title.capacity())?;
            checked_heap_add(&mut bytes, text.capacity())?;
        }
        ClipboardFile::FormatList { format_list } => {
            checked_heap_add(
                &mut bytes,
                checked_allocation_bytes::<(i32, String)>(format_list.capacity())?,
            )?;
            for (_, format) in format_list {
                checked_heap_add(&mut bytes, format.capacity())?;
            }
        }
        ClipboardFile::FormatDataResponse { format_data, .. } => {
            checked_heap_add(&mut bytes, format_data.capacity())?;
        }
        ClipboardFile::FileContentsResponse { requested_data, .. } => {
            checked_heap_add(&mut bytes, requested_data.capacity())?;
        }
        ClipboardFile::Files { files } => {
            checked_heap_add(
                &mut bytes,
                checked_allocation_bytes::<(String, u64)>(files.capacity())?,
            )?;
            for (path, _) in files {
                checked_heap_add(&mut bytes, path.capacity())?;
            }
        }
        ClipboardFile::MonitorReady
        | ClipboardFile::FormatListResponse { .. }
        | ClipboardFile::FormatDataRequest { .. }
        | ClipboardFile::FileContentsRequest { .. }
        | ClipboardFile::TryEmpty => {}
    }
    Ok(bytes)
}

impl ClipboardFileEgressSender {
    fn wake_receiver(&self) -> Result<(), ClipboardFileEgressAdmissionError> {
        match self.wake.try_send(()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                let mut state = lock_clipboard_file_egress(&self.state);
                state.receiver_open = false;
                state.queue.clear();
                state.queued_bytes = 0;
                Err(ClipboardFileEgressAdmissionError::ReceiverGone)
            }
        }
    }

    fn fail_with_state(
        &self,
        mut state: std::sync::MutexGuard<'_, ClipboardFileEgressState>,
        failure: ClipboardFileEgressFailure,
    ) -> Result<(), ClipboardFileEgressAdmissionError> {
        if !state.receiver_open {
            return Err(ClipboardFileEgressAdmissionError::ReceiverGone);
        }
        if let Some(existing) = state.terminal {
            return Err(ClipboardFileEgressAdmissionError::Failed(existing));
        }
        state.queue.clear();
        state.queued_bytes = 0;
        state.terminal = Some(failure);
        drop(state);
        self.wake_receiver()?;
        Err(ClipboardFileEgressAdmissionError::Failed(failure))
    }

    fn fail(
        &self,
        failure: ClipboardFileEgressFailure,
    ) -> Result<(), ClipboardFileEgressAdmissionError> {
        self.fail_with_state(lock_clipboard_file_egress(&self.state), failure)
    }

    fn send(&self, data: ClipboardFile) -> Result<(), ClipboardFileEgressAdmissionError> {
        {
            let state = lock_clipboard_file_egress(&self.state);
            if !state.receiver_open {
                return Err(ClipboardFileEgressAdmissionError::ReceiverGone);
            }
            if let Some(failure) = state.terminal {
                return Err(ClipboardFileEgressAdmissionError::Failed(failure));
            }
        }
        let heap_bytes = match clipboard_file_heap_bytes(&data) {
            Ok(bytes) => bytes,
            Err(failure) => return self.fail(failure),
        };
        if heap_bytes > self.limits.max_message_heap_bytes {
            return self.fail(ClipboardFileEgressFailure::MessageTooLarge);
        }
        let retained_bytes =
            match heap_bytes.checked_add(std::mem::size_of::<QueuedClipboardFile>()) {
                Some(bytes) => bytes,
                None => return self.fail(ClipboardFileEgressFailure::AccountingOverflow),
            };
        {
            let mut state = lock_clipboard_file_egress(&self.state);
            if !state.receiver_open {
                return Err(ClipboardFileEgressAdmissionError::ReceiverGone);
            }
            if let Some(failure) = state.terminal {
                return Err(ClipboardFileEgressAdmissionError::Failed(failure));
            }
            let Some(next_count) = state.queue.len().checked_add(1) else {
                return self.fail_with_state(state, ClipboardFileEgressFailure::AccountingOverflow);
            };
            if next_count > self.limits.max_messages {
                return self.fail_with_state(state, ClipboardFileEgressFailure::MessageCapacity);
            }
            let Some(next_bytes) = state.queued_bytes.checked_add(retained_bytes) else {
                return self.fail_with_state(state, ClipboardFileEgressFailure::AccountingOverflow);
            };
            if next_bytes > self.limits.max_queued_bytes {
                return self.fail_with_state(state, ClipboardFileEgressFailure::ByteCapacity);
            }
            state.queue.push_back(QueuedClipboardFile {
                data,
                retained_bytes,
            });
            state.queued_bytes = next_bytes;
        }
        self.wake_receiver()
    }
}

impl ClipboardFileEgressReceiver {
    fn take_next(&mut self) -> Result<Option<ClipboardFileEgressItem>, ()> {
        let mut state = lock_clipboard_file_egress(&self.state);
        if let Some(failure) = state.terminal.take() {
            state.receiver_open = false;
            state.queue.clear();
            state.queued_bytes = 0;
            return Ok(Some(ClipboardFileEgressItem::Failed(failure)));
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
            return Ok(Some(ClipboardFileEgressItem::Failed(
                ClipboardFileEgressFailure::AccountingOverflow,
            )));
        };
        state.queued_bytes = next_bytes;
        Ok(Some(ClipboardFileEgressItem::Message(queued.data)))
    }

    pub async fn recv(&mut self) -> Option<ClipboardFileEgressItem> {
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

    #[cfg(test)]
    pub(crate) fn blocking_recv(&mut self) -> Option<ClipboardFileEgressItem> {
        loop {
            match self.take_next() {
                Ok(Some(item)) => return Some(item),
                Ok(None) => {}
                Err(()) => return None,
            }
            self.wake.blocking_recv()?;
        }
    }
}

impl Drop for ClipboardFileEgressReceiver {
    fn drop(&mut self) {
        self.wake.close();
        let mut state = lock_clipboard_file_egress(&self.state);
        state.receiver_open = false;
        state.queue.clear();
        state.queued_bytes = 0;
        state.terminal = None;
    }
}

enum ClipboardFileRouteOwner {
    Viewer { peer_id: String },
    Controlled,
}

struct ClipboardFileRoute {
    owner: ClipboardFileRouteOwner,
    conn_id: i32,
    route_generation: u64,
    sender: ClipboardFileEgressSender,
}

lazy_static::lazy_static! {
    static ref CLIPBOARD_FILE_ROUTES: RwLock<Vec<ClipboardFileRoute>> = Default::default();
    static ref VIEWER_CLIPBOARD_ROUTE_ID: Mutex<i32> = Mutex::new(0);
    static ref CLIPBOARD_FILE_ROUTE_GENERATION: Mutex<u64> = Mutex::new(0);
}

pub struct ClipboardFileRouteLease {
    conn_id: i32,
    route_generation: u64,
}

impl Drop for ClipboardFileRouteLease {
    fn drop(&mut self) {
        let mut routes = CLIPBOARD_FILE_ROUTES.write().unwrap();
        if let Some(index) = routes.iter().position(|route| {
            route.conn_id == self.conn_id && route.route_generation == self.route_generation
        }) {
            routes.remove(index);
        }
    }
}

impl ClipboardFile {
    pub fn is_stopping_allowed(&self) -> bool {
        matches!(
            self,
            ClipboardFile::MonitorReady
                | ClipboardFile::FormatList { .. }
                | ClipboardFile::FormatDataRequest { .. }
        )
    }

    pub fn is_beginning_message(&self) -> bool {
        matches!(
            self,
            ClipboardFile::MonitorReady | ClipboardFile::FormatList { .. }
        )
    }
}

pub fn current_cliprdr_viewer_id(peer_id: &str) -> Option<i32> {
    CLIPBOARD_FILE_ROUTES
        .read()
        .unwrap()
        .iter()
        .rev()
        .find_map(|route| match &route.owner {
            ClipboardFileRouteOwner::Viewer {
                peer_id: route_peer,
            } if route_peer == peer_id => Some(route.conn_id),
            _ => None,
        })
}

fn next_viewer_conn_id() -> i32 {
    let mut lock = VIEWER_CLIPBOARD_ROUTE_ID.lock().unwrap();
    let Some(next) = lock.checked_sub(1) else {
        hbb_common::log::error!("file-clipboard viewer connection identity exhausted");
        std::process::abort();
    };
    *lock = next;
    next
}

fn next_route_generation() -> u64 {
    let mut lock = CLIPBOARD_FILE_ROUTE_GENERATION.lock().unwrap();
    let Some(next) = lock.checked_add(1) else {
        hbb_common::log::error!("file-clipboard route generation exhausted");
        std::process::abort();
    };
    *lock = next;
    next
}

pub fn register_cliprdr_viewer(
    peer_id: &str,
) -> (i32, ClipboardFileEgressReceiver, ClipboardFileRouteLease) {
    // Viewer route IDs are strictly negative; controlled connection IDs are strictly positive and
    // zero remains the Unix broadcast sentinel. Windows carries this opaque identity as u32 and
    // casts it back to i32 in every callback, preserving the exact bits.
    let conn_id = next_viewer_conn_id();
    let route_generation = next_route_generation();
    let (sender, receiver) = clipboard_file_egress_channel();
    CLIPBOARD_FILE_ROUTES
        .write()
        .unwrap()
        .push(ClipboardFileRoute {
            owner: ClipboardFileRouteOwner::Viewer {
                peer_id: peer_id.to_owned(),
            },
            conn_id,
            route_generation,
            sender,
        });
    (
        conn_id,
        receiver,
        ClipboardFileRouteLease {
            conn_id,
            route_generation,
        },
    )
}

pub fn register_cliprdr_controlled(
    conn_id: i32,
) -> Result<(ClipboardFileEgressReceiver, ClipboardFileRouteLease), CliprdrError> {
    if conn_id <= 0 {
        return Err(CliprdrError::InvalidRequest {
            description: "controlled file-clipboard connection id must be positive".to_owned(),
        });
    }
    let route_generation = next_route_generation();
    let (sender, receiver) = clipboard_file_egress_channel();
    let mut routes = CLIPBOARD_FILE_ROUTES.write().unwrap();
    if routes.iter().any(|route| route.conn_id == conn_id) {
        return Err(CliprdrError::InvalidRequest {
            description: format!(
                "controlled file-clipboard route already exists for connection {conn_id}"
            ),
        });
    }
    routes.push(ClipboardFileRoute {
        owner: ClipboardFileRouteOwner::Controlled,
        conn_id,
        route_generation,
        sender,
    });
    drop(routes);
    Ok((
        receiver,
        ClipboardFileRouteLease {
            conn_id,
            route_generation,
        },
    ))
}

#[cfg(any(target_os = "windows", feature = "unix-file-copy-paste"))]
#[inline]
pub fn send_data(conn_id: i32, data: ClipboardFile) -> Result<(), CliprdrError> {
    #[cfg(target_os = "windows")]
    return send_data_to_channel(conn_id, data);
    #[cfg(not(target_os = "windows"))]
    if conn_id == 0 {
        let _ = send_data_to_all(data);
        Ok(())
    } else {
        send_data_to_channel(conn_id, data)
    }
}

#[inline]
fn send_data_to_channel(conn_id: i32, data: ClipboardFile) -> Result<(), CliprdrError> {
    let sender = CLIPBOARD_FILE_ROUTES
        .read()
        .unwrap()
        .iter()
        .find(|route| route.conn_id == conn_id)
        .map(|route| route.sender.clone())
        .ok_or_else(|| CliprdrError::InvalidRequest {
            description: "conn_id not found".to_string(),
        })?;
    sender
        .send(data)
        .map_err(|error| CliprdrError::CommonError {
            description: error.to_string(),
        })
}

#[inline]
#[cfg(target_os = "windows")]
pub fn send_data_exclude(conn_id: i32, data: ClipboardFile) {
    let senders = CLIPBOARD_FILE_ROUTES
        .read()
        .unwrap()
        .iter()
        .filter(|route| route.conn_id != conn_id)
        .map(|route| route.sender.clone())
        .collect::<Vec<_>>();
    for sender in senders {
        if let Err(error) = sender.send(data.clone()) {
            log::error!("file-clipboard broadcast route retired: {error}");
        }
    }
}

#[inline]
#[cfg(feature = "unix-file-copy-paste")]
fn send_data_to_all(data: ClipboardFile) {
    let senders = CLIPBOARD_FILE_ROUTES
        .read()
        .unwrap()
        .iter()
        .map(|route| route.sender.clone())
        .collect::<Vec<_>>();
    for sender in senders {
        if let Err(error) = sender.send(data.clone()) {
            log::error!("file-clipboard broadcast route retired: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(id: i32) -> ClipboardFile {
        ClipboardFile::FormatListResponse { msg_flags: id }
    }

    #[test]
    fn r_s11gz_file_clipboard_egress_is_fifo_and_releases_capacity() {
        let limits = ClipboardFileEgressLimits {
            max_messages: 2,
            max_message_heap_bytes: 0,
            max_queued_bytes: std::mem::size_of::<QueuedClipboardFile>() * 2,
        };
        let (sender, mut receiver) = clipboard_file_egress_channel_with_limits(limits);
        sender.send(scalar(1)).unwrap();
        sender.send(scalar(2)).unwrap();

        assert!(matches!(
            receiver.blocking_recv(),
            Some(ClipboardFileEgressItem::Message(
                ClipboardFile::FormatListResponse { msg_flags: 1 }
            ))
        ));
        sender.send(scalar(3)).unwrap();
        assert!(matches!(
            receiver.blocking_recv(),
            Some(ClipboardFileEgressItem::Message(
                ClipboardFile::FormatListResponse { msg_flags: 2 }
            ))
        ));
        assert!(matches!(
            receiver.blocking_recv(),
            Some(ClipboardFileEgressItem::Message(
                ClipboardFile::FormatListResponse { msg_flags: 3 }
            ))
        ));
    }

    #[test]
    fn r_s11gz_file_clipboard_egress_capacity_failure_is_terminal_and_clears_payloads() {
        let limits = ClipboardFileEgressLimits {
            max_messages: 1,
            max_message_heap_bytes: 0,
            max_queued_bytes: std::mem::size_of::<QueuedClipboardFile>(),
        };
        let (sender, mut receiver) = clipboard_file_egress_channel_with_limits(limits);
        sender.send(scalar(1)).unwrap();
        assert_eq!(
            sender.send(scalar(2)),
            Err(ClipboardFileEgressAdmissionError::Failed(
                ClipboardFileEgressFailure::MessageCapacity
            ))
        );
        {
            let state = lock_clipboard_file_egress(&sender.state);
            assert!(state.queue.is_empty());
            assert_eq!(state.queued_bytes, 0);
        }
        assert!(matches!(
            receiver.blocking_recv(),
            Some(ClipboardFileEgressItem::Failed(
                ClipboardFileEgressFailure::MessageCapacity
            ))
        ));
        assert!(receiver.blocking_recv().is_none());
    }

    #[test]
    fn r_s11gz_file_clipboard_egress_counts_retained_capacity_and_total_bytes() {
        let oversized = {
            let mut data = Vec::with_capacity(65);
            data.push(1);
            ClipboardFile::FormatDataResponse {
                msg_flags: 0,
                format_data: data,
            }
        };
        let limits = ClipboardFileEgressLimits {
            max_messages: 2,
            max_message_heap_bytes: 64,
            max_queued_bytes: usize::MAX,
        };
        let (sender, mut receiver) = clipboard_file_egress_channel_with_limits(limits);
        assert_eq!(
            sender.send(oversized),
            Err(ClipboardFileEgressAdmissionError::Failed(
                ClipboardFileEgressFailure::MessageTooLarge
            ))
        );
        assert!(matches!(
            receiver.blocking_recv(),
            Some(ClipboardFileEgressItem::Failed(
                ClipboardFileEgressFailure::MessageTooLarge
            ))
        ));

        let entry = std::mem::size_of::<QueuedClipboardFile>();
        let limits = ClipboardFileEgressLimits {
            max_messages: 2,
            max_message_heap_bytes: 64,
            max_queued_bytes: entry * 2 + 63,
        };
        let (sender, mut receiver) = clipboard_file_egress_channel_with_limits(limits);
        let data = || ClipboardFile::FormatDataResponse {
            msg_flags: 0,
            format_data: Vec::with_capacity(32),
        };
        sender.send(data()).unwrap();
        assert_eq!(
            sender.send(data()),
            Err(ClipboardFileEgressAdmissionError::Failed(
                ClipboardFileEgressFailure::ByteCapacity
            ))
        );
        assert!(matches!(
            receiver.blocking_recv(),
            Some(ClipboardFileEgressItem::Failed(
                ClipboardFileEgressFailure::ByteCapacity
            ))
        ));
    }

    #[hbb_common::tokio::test(flavor = "current_thread")]
    async fn r_s11gz_file_clipboard_egress_wakes_and_receiver_retirement_is_final() {
        let (sender, mut receiver) = clipboard_file_egress_channel();
        let waiting = hbb_common::tokio::spawn(async move { receiver.recv().await });
        hbb_common::tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        sender.send(scalar(7)).unwrap();
        assert!(matches!(
            waiting.await.unwrap(),
            Some(ClipboardFileEgressItem::Message(
                ClipboardFile::FormatListResponse { msg_flags: 7 }
            ))
        ));

        let (sender, receiver) = clipboard_file_egress_channel();
        let stale = sender.clone();
        drop(receiver);
        assert_eq!(
            stale.send(scalar(8)),
            Err(ClipboardFileEgressAdmissionError::ReceiverGone)
        );

        let (sender, mut receiver) = clipboard_file_egress_channel();
        drop(sender);
        assert!(receiver.recv().await.is_none());
    }

    #[test]
    fn r_s11gz_viewer_routes_are_fresh_negative_and_controlled_routes_are_disjoint() {
        let peer = "r-s11gz-exact-viewer-round";
        let (first_id, first_receiver, first_lease) = register_cliprdr_viewer(peer);
        let (second_id, mut second_receiver, second_lease) = register_cliprdr_viewer(peer);
        assert!(first_id < 0 && second_id < first_id);
        assert!(!Arc::ptr_eq(&first_receiver.state, &second_receiver.state));
        assert_eq!(current_cliprdr_viewer_id(peer), Some(second_id));

        let controlled_id = 2_000_000_001;
        let (mut controlled_receiver, controlled_lease) =
            register_cliprdr_controlled(controlled_id).unwrap();
        assert!(register_cliprdr_controlled(controlled_id).is_err());

        send_data_to_channel(second_id, scalar(21)).unwrap();
        send_data_to_channel(controlled_id, scalar(22)).unwrap();
        assert!(matches!(
            second_receiver.blocking_recv(),
            Some(ClipboardFileEgressItem::Message(
                ClipboardFile::FormatListResponse { msg_flags: 21 }
            ))
        ));
        assert!(matches!(
            controlled_receiver.blocking_recv(),
            Some(ClipboardFileEgressItem::Message(
                ClipboardFile::FormatListResponse { msg_flags: 22 }
            ))
        ));

        drop(second_lease);
        assert_eq!(current_cliprdr_viewer_id(peer), Some(first_id));
        drop(first_lease);
        assert_eq!(current_cliprdr_viewer_id(peer), None);
        drop(controlled_lease);
    }
}
