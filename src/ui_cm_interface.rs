use crate::ipc;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use crate::ipc::Connection;
#[cfg(not(any(target_os = "ios")))]
use crate::ipc::Data;
#[cfg(target_os = "windows")]
use crate::{clipboard::ClipboardSide, ipc::ClipboardNonFile};
#[cfg(target_os = "windows")]
use clipboard::ContextSend;
#[cfg(not(any(target_os = "ios")))]
use hbb_common::fs::serialize_transfer_job;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use hbb_common::tokio::sync::mpsc::unbounded_channel;
use hbb_common::{
    allow_err, bail,
    config::{keys::OPTION_FILE_TRANSFER_MAX_FILES, Config},
    fs::{self, get_string, is_write_need_confirmation, DigestCheckResult},
    log,
    message_proto::*,
    tokio::{
        self,
        sync::{
            mpsc::{self, UnboundedSender},
            OwnedSemaphorePermit, Semaphore,
        },
        task::spawn_blocking,
    },
    ResultType,
};
#[cfg(target_os = "windows")]
use hbb_common::{config::keys::*, tokio::sync::Mutex as TokioMutex};
use serde_derive::Serialize;
#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
use std::iter::FromIterator;
#[cfg(not(any(target_os = "ios")))]
use std::path::PathBuf;
use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
    sync::{
        atomic::{AtomicBool, AtomicI64, Ordering},
        Arc, OnceLock, RwLock,
    },
};

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
    tx: UnboundedSender<Data>,
}

#[cfg(any(target_os = "android", test))]
fn android_connection_requires_desktop_capture(
    authorized: bool,
    disconnected: bool,
    conn_type: ipc::CmAuthConnType,
) -> bool {
    authorized && !disconnected && conn_type == ipc::CmAuthConnType::Remote
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct IpcTaskRunner<T: InvokeUiCM> {
    stream: Connection,
    cm: ConnectionManager<T>,
    tx: mpsc::UnboundedSender<Data>,
    rx: mpsc::UnboundedReceiver<Data>,
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
    tx: &'a UnboundedSender<Data>,
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
        #[cfg(not(any(target_os = "ios")))] tx: mpsc::UnboundedSender<Data>,
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

        #[cfg(any(target_os = "android"))]
        if !CLIENTS.read().unwrap().values().any(|client| {
            android_connection_requires_desktop_capture(
                client.authorized,
                client.disconnected,
                client.conn_type,
            )
        }) {
            if let Err(e) =
                scrap::android::call_main_service_set_by_name("stop_capture", None, None)
            {
                log::debug!("stop_capture err:{}", e);
            }
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
    if let Some(client) = CLIENTS.read().unwrap().get(&id) {
        allow_err!(client.tx.send(Data::ClickTime(0)));
    };
}

#[inline]
pub fn get_click_time() -> i64 {
    CLICK_TIME.load(Ordering::SeqCst)
}

#[inline]
#[cfg(not(any(target_os = "ios")))]
pub fn close(id: i32) {
    if let Some(client) = CLIENTS.read().unwrap().get(&id) {
        allow_err!(client.tx.send(Data::Close));
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
    let clients = CLIENTS.read().unwrap();
    if let Some(client) = clients.get(&id) {
        allow_err!(client.tx.send(Data::ChatMessage { text }));
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
        let rx_clip_holder;
        let mut rx_clip;
        let _tx_clip;
        #[cfg(target_os = "windows")]
        if self.conn_id > 0 && is_authorized {
            log::debug!("Clipboard is enabled from client peer: type 1");
            let conn_id = self.conn_id;
            rx_clip_holder = (
                clipboard::get_rx_cliprdr_server(conn_id),
                Some(crate::SimpleCallOnReturn {
                    b: true,
                    f: Box::new(move || {
                        clipboard::remove_channel_by_conn_id(conn_id);
                    }),
                }),
            );
            rx_clip = rx_clip_holder.0.lock().await;
        } else {
            log::debug!("Clipboard is enabled from client peer, actually useless: type 2");
            let rx_clip2;
            (_tx_clip, rx_clip2) = mpsc::unbounded_channel();
            rx_clip_holder = (Arc::new(TokioMutex::new(rx_clip2)), None);
            rx_clip = rx_clip_holder.0.lock().await;
        }
        #[cfg(not(target_os = "windows"))]
        {
            (_tx_clip, rx_clip) = unbounded_channel::<i32>();
        }

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
        let (tx_log, mut rx_log) = mpsc::unbounded_channel::<String>();

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
                                    if let ipc::FS::WriteBlock { id, file_num, conn_id, data: _, compressed, generation } = fs {
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
                                                Some(&tx_log),
                                            )
                                            .await;
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
                                            Some(&tx_log),
                                        )
                                        .await;
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
                Some(mut data) = self.rx.recv() => {
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
                    Some(_clip) => {
                        #[cfg(target_os = "windows")]
                        {
                            let is_stopping_allowed = _clip.is_stopping_allowed();
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
                                if _clip.is_beginning_message() && crate::get_builtin_option(OPTION_ONE_WAY_FILE_TRANSFER) == "Y" {
                                    // If one way file transfer is enabled, don't send clipboard file to client
                                    // Don't call `ContextSend::set_is_stopped()`, because it will stop bidirectional file copy&paste.
                                } else {
                                    allow_err!(self.tx.send(Data::ClipboardFile(_clip)));
                                }
                            }
                        }
                    }
                    None => {
                        //
                    }
                },
                Some(job_log) = rx_log.recv() => {
                    self.cm.ui_handler.file_transfer_log("transfer", &job_log);
                }
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
        let (tx, rx) = mpsc::unbounded_channel::<Data>();
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
    mut rx: mpsc::UnboundedReceiver<Data>,
    tx: mpsc::UnboundedSender<Data>,
) {
    let mut current_id = 0;
    let mut current_cm_auth_token = String::new();
    let mut file_authority = CmFileAuthority::absent();
    let mut write_jobs: Vec<CmTransferJob> = Vec::new();
    loop {
        match rx.recv().await {
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
                handle_fs(
                    fs,
                    &mut write_jobs,
                    &mut read_jobs_placeholder,
                    CmFileResponder {
                        tx: &tx,
                        conn_id: current_id,
                        cm_auth_token: &current_cm_auth_token,
                    },
                    None,
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
    tx_log: Option<&UnboundedSender<String>>,
) {
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
                return;
            }
            if has_job_for_connection(write_jobs, id, conn_id) {
                reject_write_job(
                    responder,
                    id,
                    generation,
                    file_num,
                    format!("duplicate write job id {}", id),
                );
                return;
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
                return;
            }
            if let Err(msg) = check_file_count_limit(files.len()) {
                reject_write_job(responder, id, generation, file_num, msg);
                return;
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
                return;
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
            if let Some(job) =
                remove_transfer_job_for_connection(write_jobs, id, conn_id, generation)
            {
                job.job.remove_download_file();
                if let Some(tx) = tx_log {
                    if let Err(e) = tx.send(serialize_transfer_job(&job.job, false, true, "")) {
                        log::error!("error sending transfer job log via IPC: {}", e);
                    }
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
                if let Some(tx) = tx_log {
                    if let Err(err) = tx.send(serialize_transfer_job(&job.job, true, false, "")) {
                        log::error!("error sending transfer job log via IPC: {}", err);
                    }
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
                if let Some(tx) = tx_log {
                    if let Err(log_err) =
                        tx.send(serialize_transfer_job(&job.job, false, false, &err))
                    {
                        log::error!("error sending transfer job log via IPC: {}", log_err);
                    }
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
                if let Some(job) =
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
                if let Some(tx) = tx_log {
                    if let Err(e) = tx.send(serialize_transfer_job(&job.job, false, true, "")) {
                        log::error!("error sending transfer job log via IPC: {}", e);
                    }
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
                    return;
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
    let lock = CLIENTS.read().unwrap();
    if id != 0 {
        if let Some(s) = lock.get(&id) {
            allow_err!(s.tx.send(data));
        }
    } else {
        for s in lock.values() {
            allow_err!(s.tx.send(data.clone()));
        }
    }
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn handle_incoming_voice_call(id: i32, accept: bool) {
    if let Some(client) = CLIENTS.read().unwrap().get(&id) {
        // Not handled in iOS yet.
        #[cfg(not(any(target_os = "ios")))]
        allow_err!(client.tx.send(Data::VoiceCallResponse(accept)));
    };
}

#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
#[inline]
pub fn close_voice_call(id: i32) {
    if let Some(client) = CLIENTS.read().unwrap().get(&id) {
        // Not handled in iOS yet.
        #[cfg(not(any(target_os = "ios")))]
        allow_err!(client.tx.send(Data::CloseVoiceCall("".to_owned())));
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
    use hbb_common::tokio::{runtime::Runtime, sync::mpsc::unbounded_channel};
    use std::fs;

    #[test]
    fn android_capture_demand_is_remote_desktop_only() {
        assert!(android_connection_requires_desktop_capture(
            true,
            false,
            ipc::CmAuthConnType::Remote
        ));
        assert!(!android_connection_requires_desktop_capture(
            false,
            false,
            ipc::CmAuthConnType::Remote
        ));
        assert!(!android_connection_requires_desktop_capture(
            true,
            true,
            ipc::CmAuthConnType::Remote
        ));
        for conn_type in [
            ipc::CmAuthConnType::FileTransfer,
            ipc::CmAuthConnType::ViewCamera,
            ipc::CmAuthConnType::Terminal,
            ipc::CmAuthConnType::PortForward,
        ] {
            assert!(!android_connection_requires_desktop_capture(
                true, false, conn_type
            ));
        }
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

        let (tx, _rx) = unbounded_channel();
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
            let (tx, mut rx) = unbounded_channel();
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
                Data::CmFileResponse(response) => match *response.response {
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
            let (tx, mut rx) = unbounded_channel();
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
                Data::CmFileResponse(response) => match *response.response {
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
