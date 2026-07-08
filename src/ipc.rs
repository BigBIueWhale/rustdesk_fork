#[path = "ipc/auth.rs"]
mod ipc_auth;
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[path = "ipc/fs.rs"]
mod ipc_fs;

use crate::{
    common::{is_server, is_service_owned_server_process},
    privacy_mode,
    privacy_mode::PrivacyModeState,
    ui_interface::{get_local_option, set_local_option},
};
use bytes::Bytes;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub use clipboard::ClipboardFile;
#[cfg(target_os = "linux")]
use hbb_common::anyhow::{self, anyhow};
use hbb_common::{
    allow_err, bail, bytes,
    bytes_codec::BytesCodec,
    config::{self, Config},
    futures::StreamExt as _,
    futures_util::sink::SinkExt,
    log, timeout,
    tokio::{
        self,
        io::{AsyncRead, AsyncWrite},
    },
    tokio_util::codec::Framed,
    ResultType,
};
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) use ipc_auth::authorize_cm_ipc_connection;
#[cfg(windows)]
use ipc_auth::authorize_windows_main_ipc_connection;
#[cfg(windows)]
pub(crate) use ipc_auth::ensure_peer_executable_matches_current_by_pid_opt;
#[cfg(windows)]
pub(crate) use ipc_auth::log_rejected_windows_ipc_connection;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use ipc_auth::{active_uid, authorize_service_scoped_ipc_connection};
#[cfg(windows)]
use ipc_auth::{
    ensure_windows_ipc_server_matches_current, windows_ipc_listener_security_attributes,
    windows_named_pipe_client_access_mask,
};
// R-X13 (§8): the ipc_auth re-exports (ensure_peer_executable_matches_current_by_fd /
// is_allowed_service_peer_uid / log_rejected_uinput_connection / peer_uid_from_fd) were the uinput
// peer-authorization accessors, removed with the uinput module. The _service-channel authorization
// keeps using is_allowed_service_peer_uid / peer_uid_from_fd INTERNALLY inside ipc_auth.
// R-X6 (macOS): the `_url` deep-link IPC listener (server::start_ipc_url_server) is a SEPARATE
// listener that BYPASSES the main handle() service-accept gate, so it MUST authenticate its sender
// (peer-uid + peer-exe) before honoring a rustdesk:// URL — otherwise any same-uid process could
// inject a deep-link connect/relay/key. The only legitimate sender is the rustdesk binary itself
// (ipc::send_url_scheme, from core_main's uni-link self-handler), so the same peer-uid + same-exe
// policy the protected `_service` channel enforces is exactly the right gate.
#[cfg(target_os = "macos")]
pub(crate) fn authorize_url_ipc_sender(stream: &Connection) -> bool {
    authorize_service_scoped_ipc_connection(stream, "_url")
}
#[cfg(target_os = "linux")]
use ipc_fs::terminal_count_candidate_uids;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use ipc_fs::{
    check_pid, ensure_secure_ipc_parent_dir, scrub_secure_ipc_parent_dir,
    should_scrub_parent_entries_after_check_pid, write_pid,
};
use parity_tokio_ipc::{
    Connection as Conn, ConnectionClient as ConnClient, Endpoint, Incoming, SecurityAttributes,
};
use serde_derive::{Deserialize, Serialize};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::cell::Cell;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::HashMap,
    sync::atomic::{AtomicBool, Ordering},
};
#[cfg(windows)]
use std::{
    ffi::OsStr,
    os::windows::{ffi::OsStrExt, io::RawHandle},
};
#[cfg(windows)]
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{CloseHandle, ERROR_PIPE_BUSY},
        Storage::FileSystem::{
            CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_OVERLAPPED, FILE_SHARE_MODE,
            OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
        },
    },
};

// IPC actions here.
pub const IPC_ACTION_CLOSE: &str = "close";
pub static EXIT_RECV_CLOSE: AtomicBool = AtomicBool::new(true);

#[cfg(any(target_os = "linux", target_os = "macos"))]
thread_local! {
    static USE_USER_MAIN_IPC: Cell<bool> = Cell::new(false);
}

#[must_use = "bind this guard to a local variable to keep the IPC scope active"]
/// Thread-local guard for routing root main IPC to the active user on Linux/macOS.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) struct UserMainIpcScope {
    previous: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl UserMainIpcScope {
    pub(crate) fn new() -> Self {
        let previous = USE_USER_MAIN_IPC.with(|use_user_main| {
            let previous = use_user_main.get();
            use_user_main.set(true);
            previous
        });
        Self { previous }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for UserMainIpcScope {
    fn drop(&mut self) {
        USE_USER_MAIN_IPC.with(|use_user_main| use_user_main.set(self.previous));
    }
}

#[inline]
pub async fn connect_service(ms_timeout: u64) -> ResultType<ConnectionTmpl<ConnClient>> {
    connect(ms_timeout, crate::POSTFIX_SERVICE).await
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "t", content = "c")]
pub enum FS {
    ReadEmptyDirs {
        dir: String,
        include_hidden: bool,
    },
    ReadDir {
        dir: String,
        include_hidden: bool,
    },
    RemoveDir {
        path: String,
        id: i32,
        recursive: bool,
    },
    RemoveFile {
        path: String,
        id: i32,
        file_num: i32,
    },
    CreateDir {
        path: String,
        id: i32,
    },
    NewWrite {
        path: String,
        id: i32,
        file_num: i32,
        files: Vec<(String, u64)>,
        overwrite_detection: bool,
        total_size: u64,
        conn_id: i32,
    },
    CancelWrite {
        id: i32,
    },
    WriteBlock {
        id: i32,
        file_num: i32,
        conn_id: i32,
        data: Bytes,
        compressed: bool,
    },
    WriteDone {
        id: i32,
        file_num: i32,
        conn_id: i32,
    },
    WriteError {
        id: i32,
        file_num: i32,
        conn_id: i32,
        err: String,
    },
    WriteOffset {
        id: i32,
        file_num: i32,
        offset_blk: u32,
    },
    CheckDigest {
        id: i32,
        file_num: i32,
        conn_id: i32,
        file_size: u64,
        last_modified: u64,
        is_upload: bool,
        is_resume: bool,
    },
    SendConfirm(Vec<u8>),
    Rename {
        id: i32,
        path: String,
        new_name: String,
    },
    // CM-side file reading operations (Windows only)
    // These enable Connection Manager to read files and stream them back to Connection
    ReadFile {
        path: String,
        id: i32,
        file_num: i32,
        include_hidden: bool,
        conn_id: i32,
        overwrite_detection: bool,
    },
    CancelRead {
        id: i32,
        conn_id: i32,
    },
    SendConfirmForRead {
        id: i32,
        file_num: i32,
        skip: bool,
        offset_blk: u32,
        conn_id: i32,
    },
    ReadAllFiles {
        path: String,
        id: i32,
        include_hidden: bool,
        conn_id: i32,
    },
}

#[cfg(target_os = "windows")]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "t")]
pub struct ClipboardNonFile {
    pub compress: bool,
    pub content: bytes::Bytes,
    pub content_len: usize,
    pub next_raw: bool,
    pub width: i32,
    pub height: i32,
    // message.proto: ClipboardFormat
    pub format: i32,
    pub special_name: String,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "t", content = "c")]
pub enum DataKeyboard {
    Sequence(String),
    KeyDown(enigo::Key),
    KeyUp(enigo::Key),
    KeyClick(enigo::Key),
    GetKeyState(enigo::Key),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "t", content = "c")]
pub enum DataKeyboardResponse {
    GetKeyState(bool),
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "t", content = "c")]
pub enum DataMouse {
    MoveTo(i32, i32),
    MoveRelative(i32, i32),
    Down(enigo::MouseButton),
    Up(enigo::MouseButton),
    Click(enigo::MouseButton),
    ScrollX(i32),
    ScrollY(i32),
    Refresh,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "t", content = "c")]
pub enum DataControl {
    Resolution {
        minx: i32,
        maxx: i32,
        miny: i32,
        maxy: i32,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq)]
#[serde(tag = "t")]
pub enum CmAuthConnType {
    Remote,
    FileTransfer,
    ViewCamera,
    Terminal,
    PortForward,
}

impl CmAuthConnType {
    pub(crate) fn allows_file_authority(self) -> bool {
        matches!(self, Self::Remote | Self::FileTransfer)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq, Default)]
pub struct CmConnectionAuthority {
    pub valid: bool,
    pub file: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "t", content = "c")]
pub enum Data {
    Login {
        id: i32,
        is_file_transfer: bool,
        is_view_camera: bool,
        is_terminal: bool,
        peer_id: String,
        name: String,
        avatar: String,
        authorized: bool,
        port_forward: String,
        conn_type: CmAuthConnType,
        keyboard: bool,
        clipboard: bool,
        audio: bool,
        file: bool,
        file_transfer_enabled: bool,
        restart: bool,
        recording: bool,
        block_input: bool,
        privacy_mode: bool,
        from_switch: bool,
        cm_auth_token: String,
    },
    ChatMessage {
        text: String,
    },
    SystemInfo(Option<String>),
    ClickTime(i64),
    Close,
    ConfigRequest(String),
    ConfigValue((String, Option<String>)),
    Options(Option<HashMap<String, String>>),
    OptionsSetResult(bool),
    SetVoiceCallInput(String),
    SetUserOwnedPermanentPassword(String),
    SetUserOwnedPermanentPasswordResult(bool),
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    RequestServiceOwnedUnattendedPasswordChange(String),
    #[cfg(target_os = "macos")]
    RequestMacosServiceOwnedUnattendedPasswordChange {
        password: String,
        authorization: Vec<u8>,
    },
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    CommitServiceOwnedUnattendedPasswordChange(String),
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    ServiceOwnedUnattendedPasswordChangeResult(bool),
    #[cfg(target_os = "windows")]
    RequestServiceOwnedShareRdp(bool),
    #[cfg(target_os = "windows")]
    ServiceOwnedShareRdpResult(bool),
    NatType(Option<i32>),
    RawMessage(Vec<u8>),
    #[cfg(target_os = "linux")]
    PulseAudioSource(String),
    FS(FS),
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    AuthorizedFS {
        cm_auth_token: String,
        fs: FS,
    },
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    ValidateCmConnection {
        id: i32,
        conn_type: CmAuthConnType,
        cm_auth_token: String,
        result: Option<CmConnectionAuthority>,
    },
    Test,
    #[cfg(target_os = "windows")]
    ClipboardFile(ClipboardFile),
    ClipboardFileEnabled(bool),
    #[cfg(target_os = "windows")]
    ClipboardNonFile(Option<(String, Vec<ClipboardNonFile>)>),
    PrivacyModeState((i32, PrivacyModeState, String)),
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    Keyboard(DataKeyboard),
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    KeyboardResponse(DataKeyboardResponse),
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    Mouse(DataMouse),
    Control(DataControl),
    Theme(String),
    Language(String),
    Empty,
    Disconnected,
    UrlLink(String),
    VoiceCallIncoming,
    StartVoiceCall,
    VoiceCallResponse(bool),
    CloseVoiceCall(String),
    #[cfg(windows)]
    SyncWinCpuUsage(Option<f64>),
    FileTransferLog((String, String)),
    #[cfg(windows)]
    ControlledSessionCount(usize),
    CmErr(String),
    // CM-side file reading responses (Windows only)
    // These are sent from CM back to Connection when CM handles file reading
    /// Response to ReadFile: contains initial file list or error
    ReadJobInitResult {
        id: i32,
        file_num: i32,
        include_hidden: bool,
        conn_id: i32,
        /// Serialized protobuf bytes of FileDirectory, or error string
        result: Result<Vec<u8>, String>,
    },
    /// File data block read by CM.
    ///
    /// The actual data is sent separately via `send_raw()` after this message to avoid
    /// JSON encoding overhead for large binary data. This mirrors the `WriteBlock` pattern.
    ///
    /// **Protocol:**
    /// - Sender: `send(FileBlockFromCM{...})` then `send_raw(data)`
    /// - Receiver: `next()` returns `FileBlockFromCM`, then `next_raw()` returns data bytes
    ///
    /// **Note on empty data (e.g., empty files):**
    /// Empty data is supported. The IPC connection uses `BytesCodec` with `raw=false` (default),
    /// which prefixes each frame with a length header. So `send_raw(Bytes::new())` sends a
    /// 1-byte frame (length=0), and `next_raw()` correctly returns an empty `BytesMut`.
    /// See `libs/hbb_common/src/bytes_codec.rs` test `test_codec2` for verification.
    FileBlockFromCM {
        id: i32,
        file_num: i32,
        /// Data is sent separately via `send_raw()` to avoid JSON encoding overhead.
        /// This field is skipped during serialization; sender must call `send_raw()` after sending.
        /// Receiver must call `next_raw()` and populate this field manually.
        #[serde(skip)]
        data: bytes::Bytes,
        compressed: bool,
        conn_id: i32,
    },
    /// File read completed successfully
    FileReadDone {
        id: i32,
        file_num: i32,
        conn_id: i32,
    },
    /// File read failed with error
    FileReadError {
        id: i32,
        file_num: i32,
        err: String,
        conn_id: i32,
    },
    /// Digest info from CM for overwrite detection
    FileDigestFromCM {
        id: i32,
        file_num: i32,
        last_modified: u64,
        file_size: u64,
        is_resume: bool,
        conn_id: i32,
    },
    /// Response to ReadAllFiles: recursive directory listing
    AllFilesResult {
        id: i32,
        conn_id: i32,
        path: String,
        /// Serialized protobuf bytes of FileDirectory, or error string
        result: Result<Vec<u8>, String>,
    },
    /// CM rejected a peer-proposed write job before storing it.
    WriteJobRejected {
        id: i32,
        conn_id: i32,
        err: String,
    },
    CheckHwcodec,
    HwCodecConfig(Option<String>),
    #[cfg(all(
        feature = "flutter",
        not(any(target_os = "android", target_os = "ios"))
    ))]
    ControllingSessionCount(usize),
    #[cfg(target_os = "linux")]
    TerminalSessionCount(usize),
    #[cfg(target_os = "windows")]
    PortForwardSessionCount(Option<usize>),
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    Whiteboard((String, crate::whiteboard::CustomEvent)),
    #[cfg(target_os = "windows")]
    FileTransferEnabledState(Option<bool>),
}

#[tokio::main(flavor = "current_thread")]
pub async fn start(postfix: &str) -> ResultType<()> {
    let mut incoming = new_listener(postfix).await?;
    loop {
        if let Some(result) = incoming.next().await {
            match result {
                Ok(stream) => {
                    let mut stream = Connection::new(stream);
                    let postfix = postfix.to_owned();
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    if config::is_service_ipc_postfix(&postfix) {
                        if !authorize_service_scoped_ipc_connection(&stream, &postfix) {
                            continue;
                        }
                    }
                    #[cfg(windows)]
                    if postfix.is_empty() {
                        // Windows main IPC (`postfix == ""`) is authorized here.
                        // Other security-sensitive channels use dedicated authorization paths:
                        // - service-scoped postfixes: service-specific listener/authorization
                        if !authorize_windows_main_ipc_connection(&stream, &postfix) {
                            continue;
                        }
                    }
                    tokio::spawn(async move {
                        loop {
                            match stream.next().await {
                                Err(err) => {
                                    log::trace!("ipc '{}' connection closed: {}", postfix, err);
                                    break;
                                }
                                Ok(Some(data)) => {
                                    // On Linux/macOS, `_service` is a service-control channel, not a
                                    // config bus. Keep the world-connectable socket to narrow
                                    // receiver-authorized messages only.
                                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                                    if postfix == crate::POSTFIX_SERVICE {
                                        if service_channel_admits_message(&data) {
                                            handle(data, &mut stream, IpcChannel::Service).await;
                                        } else {
                                            log::warn!(
                                                "Rejected unauthorized data on protected _service IPC channel: postfix={}, data_kind={:?}, peer_uid={:?}",
                                                postfix,
                                                std::mem::discriminant(&data),
                                                stream.peer_uid()
                                            );
                                            // Close the connection to avoid keeping a protected channel
                                            // alive while repeatedly receiving invalid traffic.
                                            break;
                                        }
                                        continue;
                                    }
                                    // R-S11 / R-S11b / Appendix C #15/#25: the main channel is a
                                    // state-mutation boundary. Reject ordinary service-owned
                                    // policy/credential mutations before the handler reaches Config setters.
                                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                                    if !main_channel_admits_state_mutation(
                                        &data,
                                        MainIpcAuthority::for_current_process(),
                                        MainIpcPeerAuthority::for_stream(&stream),
                                    ) {
                                        log::warn!(
                                            "Rejected a state mutation on the main IPC channel (R-S11/R-S11b): data_kind={:?}, peer_uid={:?}",
                                            std::mem::discriminant(&data),
                                            stream.peer_uid()
                                        );
                                        send_main_channel_mutation_rejection_ack(
                                            &data,
                                            &mut stream,
                                        )
                                        .await;
                                        continue;
                                    }
                                    // R-S11: the SAME per-arm state-mutation allowlist binds the WINDOWS
                                    // main pipe (postfix == ""; the only postfix `start()` is ever called
                                    // with on Windows). Windows has no `_service` channel and no
                                    // SO_PEERCRED peer_uid, but the same named mutation policy MUST
                                    // be enforced here so that even a same-session, same-executable
                                    // process (already the only peer admitted by
                                    // authorize_windows_main_ipc_connection) cannot mutate privileged
                                    // state from inside — the config-integrity boundary R-S11 mandates
                                    // "per write-arm", on every shipped artifact, not Linux/macOS alone.
                                    #[cfg(target_os = "windows")]
                                    let peer_authority = match &data {
                                        Data::CommitServiceOwnedUnattendedPasswordChange(_) => {
                                            MainIpcPeerAuthority::for_windows_main_pipe(&stream)
                                        }
                                        _ => MainIpcPeerAuthority::Ordinary,
                                    };
                                    #[cfg(target_os = "windows")]
                                    if !main_channel_admits_state_mutation(
                                        &data,
                                        MainIpcAuthority::for_current_process(),
                                        peer_authority,
                                    ) {
                                        log::warn!(
                                            "Rejected a state mutation on the main IPC channel (R-S11/R-S11b): data_kind={:?}",
                                            std::mem::discriminant(&data)
                                        );
                                        send_main_channel_mutation_rejection_ack(
                                            &data,
                                            &mut stream,
                                        )
                                        .await;
                                        continue;
                                    }
                                    handle(data, &mut stream, IpcChannel::Main).await;
                                }
                                Ok(None) => {
                                    // `Ok(None)` means a complete frame arrived but did not
                                    // deserialize into `Data`. Peer close/reset is returned as
                                    // `Err` by `ConnectionTmpl::next()`. Keep the historical
                                    // ignore behavior except on the protected `_service` channel.
                                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                                    {
                                        if postfix == crate::POSTFIX_SERVICE {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    });
                }
                Err(err) => {
                    log::error!("Couldn't get client: {:?}", err);
                }
            }
        }
    }
}

pub async fn new_listener(postfix: &str) -> ResultType<Incoming> {
    let path = Config::ipc_path(postfix);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let should_scrub_parent_entries = ensure_secure_ipc_parent_dir(&path, postfix)?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let existing_listener_alive = check_pid(postfix).await;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if should_scrub_parent_entries_after_check_pid(
        should_scrub_parent_entries,
        existing_listener_alive,
    ) {
        scrub_secure_ipc_parent_dir(&path, postfix)?;
    }
    let mut endpoint = Endpoint::new(path.clone());
    #[cfg(windows)]
    let attr = windows_ipc_listener_security_attributes(postfix).map_err(|err| {
        log::error!("Failed to set ipc{} security: {}", postfix, err);
        err
    })?;
    #[cfg(not(windows))]
    let attr = SecurityAttributes::allow_everyone_create().map_err(|err| {
        log::error!("Failed to set ipc{} security: {}", postfix, err);
        hbb_common::anyhow::Error::from(err)
    })?;
    endpoint.set_security_attributes(attr);
    match endpoint.incoming() {
        Ok(incoming) => {
            if postfix == crate::POSTFIX_SERVICE {
                log::info!("Started protected ipc service server: postfix={}", postfix);
            } else {
                log::info!("Started ipc{} server at path: {}", postfix, &path);
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                // NOTE: On Linux/macOS, some IPC sockets are intentionally world-connectable
                // (0666) so the active (non-root) user process can connect. Authorization is
                // enforced at accept-time for these channels, and the protected `_service`
                // channel is further restricted by an explicit message allowlist.
                let socket_mode = if config::is_service_ipc_postfix(postfix) {
                    0o0666
                } else {
                    0o0600
                };
                if let Err(err) =
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(socket_mode))
                {
                    log::error!(
                        "Failed to set permissions on ipc{} socket at path {}: {}",
                        postfix,
                        &path,
                        err
                    );
                    std::fs::remove_file(&path).ok();
                    return Err(err.into());
                }
                write_pid(postfix);
            }
            Ok(incoming)
        }
        Err(err) => {
            log::error!(
                "Failed to start ipc{} server at path {}: {}",
                postfix,
                path,
                err
            );
            Err(err.into())
        }
    }
}

pub struct CheckIfRestart {
    audio_input: String,
    voice_call_input: String,
}

impl CheckIfRestart {
    pub fn new() -> CheckIfRestart {
        CheckIfRestart {
            audio_input: Config::get_option("audio-input"),
            voice_call_input: Config::get_option("voice-call-input"),
        }
    }
}
impl Drop for CheckIfRestart {
    fn drop(&mut self) {
        // R-D4: the audio-device watches are the ONLY live restart triggers on the direct-only
        // build. The former mediator-restart watch (stop-service / rendezvous-servers / disable-udp)
        // is removed: RendezvousMediator::restart() is a no-op here (no rendezvous registration loop
        // to break — the direct listener runs continuously, R-D4); stop-service and
        // custom-rendezvous-server are lockdown-pinned (so constant); and disable-udp is vestigial
        // (UDP is excised — no transport path reads it). The earlier allow-websocket /
        // allow-insecure-tls-fallback / api-server watches (+ the tls-cache reset they gated) were
        // already removed for the same dead-change-detection reason.
        if self.audio_input != Config::get_option("audio-input") {
            crate::audio_service::restart();
        }
        if self.voice_call_input != Config::get_option("voice-call-input") {
            crate::audio_service::set_voice_call_input_device(
                Some(Config::get_option("voice-call-input")),
                true,
            )
        }
    }
}

/// Main-channel mutation policy. Whole-config writes, identity/salt field writes, proxy writes,
/// service-owned credentials, and service-owned options stay out of ordinary IPC.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainIpcAuthority {
    UserOwned,
    ServiceOwned,
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainIpcPeerAuthority {
    Ordinary,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    RootUnixPeer,
    #[cfg(target_os = "windows")]
    WindowsLocalSystemPeer,
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
impl MainIpcPeerAuthority {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn for_stream(stream: &Connection) -> Self {
        if stream.peer_uid() == Some(0) {
            Self::RootUnixPeer
        } else {
            Self::Ordinary
        }
    }

    #[cfg(target_os = "windows")]
    fn for_windows_main_pipe(stream: &Connection) -> Self {
        match stream.windows_pipe_client_token_is_local_system() {
            Ok(true) => Self::WindowsLocalSystemPeer,
            Ok(false) => Self::Ordinary,
            Err(err) => {
                log::warn!(
                    "Failed to resolve Windows main IPC peer token for service-owned commit: {err}"
                );
                Self::Ordinary
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn allows_service_owned_unattended_password_commit(self) -> bool {
        match self {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::RootUnixPeer => true,
            #[cfg(target_os = "windows")]
            Self::WindowsLocalSystemPeer => true,
            _ => false,
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
impl MainIpcAuthority {
    fn for_current_process() -> Self {
        #[cfg(target_os = "windows")]
        if crate::platform::is_root() {
            return Self::ServiceOwned;
        }
        if is_service_owned_server_process() {
            Self::ServiceOwned
        } else {
            Self::UserOwned
        }
    }

    fn allows_main_channel_user_owned_password_write(self) -> bool {
        matches!(self, Self::UserOwned)
    }

    fn allows_main_channel_options_write(self) -> bool {
        matches!(self, Self::UserOwned)
    }

    fn allows_main_channel_password_storage_sync(self) -> bool {
        matches!(self, Self::UserOwned)
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn allows_service_owned_unattended_password_commit(self) -> bool {
        matches!(self, Self::ServiceOwned)
    }
}

#[inline]
fn current_process_allows_user_owned_permanent_password_write() -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        MainIpcAuthority::for_current_process().allows_main_channel_user_owned_password_write()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        true
    }
}

#[inline]
fn current_process_allows_main_channel_options_write() -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        MainIpcAuthority::for_current_process().allows_main_channel_options_write()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        true
    }
}

#[inline]
fn current_process_allows_main_channel_permanent_password_storage_sync() -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        MainIpcAuthority::for_current_process().allows_main_channel_password_storage_sync()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        true
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[inline]
fn current_process_allows_service_owned_unattended_password_commit(stream: &Connection) -> bool {
    let peer_authority = {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            MainIpcPeerAuthority::for_stream(stream)
        }
        #[cfg(target_os = "windows")]
        {
            MainIpcPeerAuthority::for_windows_main_pipe(stream)
        }
    };
    MainIpcAuthority::for_current_process().allows_service_owned_unattended_password_commit()
        && peer_authority.allows_service_owned_unattended_password_commit()
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn main_channel_admits_state_mutation(
    data: &Data,
    authority: MainIpcAuthority,
    peer_authority: MainIpcPeerAuthority,
) -> bool {
    match data {
        Data::SetVoiceCallInput(_) => true,
        Data::SetUserOwnedPermanentPassword(_) => {
            authority.allows_main_channel_user_owned_password_write()
        }
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        Data::CommitServiceOwnedUnattendedPasswordChange(_) => {
            authority.allows_service_owned_unattended_password_commit()
                && peer_authority.allows_service_owned_unattended_password_commit()
        }
        #[cfg(target_os = "windows")]
        Data::RequestServiceOwnedShareRdp(_) => false,
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        Data::RequestServiceOwnedUnattendedPasswordChange(_) => false,
        #[cfg(target_os = "macos")]
        Data::RequestMacosServiceOwnedUnattendedPasswordChange { .. } => false,
        // Whole-options writes are ordinary user-owned configuration writes. A service-owned server
        // enforces machine policy and must not accept them over the generic main IPC config bus.
        Data::Options(Some(_)) => authority.allows_main_channel_options_write(),
        _ => true,
    }
}

async fn send_main_channel_mutation_rejection_ack(data: &Data, stream: &mut Connection) {
    match data {
        Data::SetUserOwnedPermanentPassword(_) => {
            allow_err!(
                stream
                    .send(&Data::SetUserOwnedPermanentPasswordResult(false))
                    .await
            );
        }
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        Data::RequestServiceOwnedUnattendedPasswordChange(_) => {
            allow_err!(
                stream
                    .send(&Data::ServiceOwnedUnattendedPasswordChangeResult(false))
                    .await
            );
        }
        #[cfg(target_os = "macos")]
        Data::RequestMacosServiceOwnedUnattendedPasswordChange { .. } => {
            allow_err!(
                stream
                    .send(&Data::ServiceOwnedUnattendedPasswordChangeResult(false))
                    .await
            );
        }
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        Data::CommitServiceOwnedUnattendedPasswordChange(_) => {
            allow_err!(
                stream
                    .send(&Data::ServiceOwnedUnattendedPasswordChangeResult(false))
                    .await
            );
        }
        Data::Options(Some(_)) => {
            allow_err!(stream.send(&Data::OptionsSetResult(false)).await);
        }
        #[cfg(target_os = "windows")]
        Data::RequestServiceOwnedShareRdp(_) => {
            allow_err!(stream.send(&Data::ServiceOwnedShareRdpResult(false)).await);
        }
        _ => {}
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn service_channel_admits_message(data: &Data) -> bool {
    match data {
        Data::Test => true,
        #[cfg(target_os = "linux")]
        Data::RequestServiceOwnedUnattendedPasswordChange(_) => true,
        #[cfg(target_os = "macos")]
        Data::RequestMacosServiceOwnedUnattendedPasswordChange { .. } => true,
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IpcChannel {
    Main,
    Service,
}

#[cfg(target_os = "linux")]
const SET_UNATTENDED_PASSWORD_POLKIT_ACTION: &str = "com.carriez.RustDesk.set-unattended-password";

#[cfg(target_os = "linux")]
fn linux_proc_stat_start_time(pid: u32, stat: &str) -> ResultType<String> {
    let Some((_, after_comm)) = stat.rsplit_once(") ") else {
        bail!("Failed to parse /proc/{pid}/stat: missing command terminator");
    };
    let fields: Vec<_> = after_comm.split_whitespace().collect();
    let Some(start_time) = fields.get(19) else {
        bail!("Failed to parse /proc/{pid}/stat: missing start time");
    };
    Ok((*start_time).to_owned())
}

#[cfg(target_os = "linux")]
fn linux_proc_start_time(pid: u32) -> ResultType<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    linux_proc_stat_start_time(pid, &stat)
}

#[cfg(target_os = "linux")]
fn linux_polkit_subject_for_peer(stream: &Connection) -> ResultType<String> {
    let peer_pid = stream
        .peer_pid()
        .ok_or_else(|| anyhow!("Failed to resolve peer pid for service-owned password change"))?;
    let peer_uid = stream
        .peer_uid()
        .ok_or_else(|| anyhow!("Failed to resolve peer uid for service-owned password change"))?;
    let start_time = linux_proc_start_time(peer_pid)?;
    Ok(format!("{peer_pid},{start_time},{peer_uid}"))
}

#[cfg(target_os = "linux")]
fn linux_pkcheck_authorizes_service_owned_password_change(subject: String) -> bool {
    let status = std::process::Command::new("/usr/bin/pkcheck")
        .arg("--action-id")
        .arg(SET_UNATTENDED_PASSWORD_POLKIT_ACTION)
        .arg("--process")
        .arg(&subject)
        .arg("--allow-user-interaction")
        .status();
    match status {
        Ok(status) if status.success() => true,
        Ok(status) => {
            log::warn!(
                "Rejected service-owned unattended password change: polkit denied action={}, subject={}, status={}",
                SET_UNATTENDED_PASSWORD_POLKIT_ACTION,
                subject,
                status
            );
            false
        }
        Err(err) => {
            log::warn!(
                "Rejected service-owned unattended password change: failed to run pkcheck for action={}, subject={}, err={}",
                SET_UNATTENDED_PASSWORD_POLKIT_ACTION,
                subject,
                err
            );
            false
        }
    }
}

#[cfg(target_os = "linux")]
async fn linux_peer_is_authorized_for_service_owned_password_change(stream: &Connection) -> bool {
    let subject = match linux_polkit_subject_for_peer(stream) {
        Ok(subject) => subject,
        Err(err) => {
            log::warn!("Rejected service-owned unattended password change: {err}");
            return false;
        }
    };
    match tokio::task::spawn_blocking(move || {
        linux_pkcheck_authorizes_service_owned_password_change(subject)
    })
    .await
    {
        Ok(authorized) => authorized,
        Err(err) => {
            log::warn!(
                "Rejected service-owned unattended password change: pkcheck task failed: {err}"
            );
            false
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn commit_service_owned_unattended_password_change(value: String) -> ResultType<bool> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let _scope = UserMainIpcScope::new();
    let ms_timeout = 1_000;
    let mut c = connect(ms_timeout, "").await?;
    c.send(&Data::CommitServiceOwnedUnattendedPasswordChange(value))
        .await?;
    if let Some(Data::ServiceOwnedUnattendedPasswordChangeResult(ok)) =
        c.next_timeout(ms_timeout).await?
    {
        Ok(ok)
    } else {
        Ok(false)
    }
}

#[cfg(target_os = "linux")]
async fn handle_linux_service_owned_unattended_password_request(
    channel: IpcChannel,
    value: String,
    stream: &mut Connection,
) {
    let accepted = channel == IpcChannel::Service
        && linux_peer_is_authorized_for_service_owned_password_change(stream).await
        && match commit_service_owned_unattended_password_change(value).await {
            Ok(committed) => committed,
            Err(err) => {
                log::warn!(
                    "Rejected service-owned unattended password change: service-to-server commit failed: {err}"
                );
                false
            }
        };
    if !accepted {
        log::warn!("Rejected service-owned unattended password change");
    }
    allow_err!(
        stream
            .send(&Data::ServiceOwnedUnattendedPasswordChangeResult(accepted))
            .await
    );
}

#[cfg(target_os = "macos")]
fn macos_peer_is_authorized_for_service_owned_password_change(authorization: &[u8]) -> bool {
    if crate::platform::verify_service_owned_unattended_password_authorization(authorization) {
        return true;
    }
    log::warn!("Rejected macOS service-owned unattended password change: authorization denied");
    false
}

#[cfg(target_os = "macos")]
async fn handle_macos_service_owned_unattended_password_request(
    channel: IpcChannel,
    value: String,
    authorization: Vec<u8>,
    stream: &mut Connection,
) {
    let accepted = channel == IpcChannel::Service
        && macos_peer_is_authorized_for_service_owned_password_change(&authorization)
        && match commit_service_owned_unattended_password_change(value).await {
            Ok(committed) => committed,
            Err(err) => {
                log::warn!(
                    "Rejected macOS service-owned unattended password change: service-to-server commit failed: {err}"
                );
                false
            }
        };
    if !accepted {
        log::warn!("Rejected macOS service-owned unattended password change");
    }
    allow_err!(
        stream
            .send(&Data::ServiceOwnedUnattendedPasswordChangeResult(accepted))
            .await
    );
}

#[cfg(target_os = "windows")]
pub(crate) async fn handle_windows_service_owned_unattended_password_request(
    value: String,
    stream: &mut Connection,
) {
    let accepted = windows_peer_is_authorized_for_service_owned_password_change(stream)
        && match commit_service_owned_unattended_password_change(value).await {
            Ok(committed) => committed,
            Err(err) => {
                log::warn!(
                    "Rejected Windows service-owned unattended password change: service-to-server commit failed: {err}"
                );
                false
            }
        };
    if !accepted {
        log::warn!("Rejected Windows service-owned unattended password change");
    }
    allow_err!(
        stream
            .send(&Data::ServiceOwnedUnattendedPasswordChangeResult(accepted))
            .await
    );
}

#[cfg(target_os = "windows")]
fn windows_peer_is_authorized_for_service_owned_password_change(stream: &Connection) -> bool {
    windows_peer_is_authorized_for_service_owned_request(
        stream,
        "Windows service-owned unattended password change",
    )
}

#[cfg(target_os = "windows")]
pub(crate) async fn handle_windows_service_owned_share_rdp_request(
    enable: bool,
    stream: &mut Connection,
) {
    let accepted = windows_peer_is_authorized_for_service_owned_share_rdp_change(stream)
        && match crate::platform::windows::set_service_owned_share_rdp(enable) {
            Ok(()) => true,
            Err(err) => {
                log::warn!("Rejected Windows service-owned RDP session-sharing change: {err}");
                false
            }
        };
    if !accepted {
        log::warn!("Rejected Windows service-owned RDP session-sharing change");
    }
    allow_err!(
        stream
            .send(&Data::ServiceOwnedShareRdpResult(accepted))
            .await
    );
}

#[cfg(target_os = "windows")]
fn windows_peer_is_authorized_for_service_owned_share_rdp_change(stream: &Connection) -> bool {
    windows_peer_is_authorized_for_service_owned_request(
        stream,
        "Windows service-owned RDP session-sharing change",
    )
}

#[cfg(target_os = "windows")]
fn windows_peer_is_authorized_for_service_owned_request(stream: &Connection, action: &str) -> bool {
    match stream.windows_pipe_client_token_is_elevated() {
        Ok(true) => true,
        Ok(false) => {
            log::warn!("Rejected {action}: caller token is not elevated");
            false
        }
        Err(err) => {
            log::warn!("Rejected {action}: failed to verify caller token elevation: {err}");
            false
        }
    }
}

async fn handle(data: Data, stream: &mut Connection, channel: IpcChannel) {
    match data {
        Data::SystemInfo(_) => {
            let info = format!(
                "log_path: {}, config: {}, username: {}",
                Config::log_path().to_str().unwrap_or(""),
                Config::file().to_str().unwrap_or(""),
                crate::username(),
            );
            allow_err!(stream.send(&Data::SystemInfo(Some(info))).await);
        }
        Data::ClickTime(_) => {
            let t = crate::server::CLICK_TIME.load(Ordering::SeqCst);
            allow_err!(stream.send(&Data::ClickTime(t)).await);
        }
        Data::Close => {
            log::info!("Receive close message");
            if EXIT_RECV_CLOSE.load(Ordering::SeqCst) {
                #[cfg(not(target_os = "android"))]
                crate::server::input_service::fix_key_down_timeout_at_exit();
                if is_server() {
                    let _ = privacy_mode::turn_off_privacy(0, Some(PrivacyModeState::OffByPeer));
                }
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                if crate::is_main() {
                    // below part is for main windows can be reopen during rustdesk installation and installing service from UI
                    // this make new ipc server (domain socket) can be created.
                    std::fs::remove_file(&Config::ipc_path("")).ok();
                    #[cfg(target_os = "linux")]
                    {
                        hbb_common::sleep((crate::platform::SERVICE_INTERVAL * 2) as f32 / 1000.0)
                            .await;
                        // https://github.com/rustdesk/rustdesk/discussions/9254
                        // R-X10: --no-server removed; restart the GUI plainly (it never starts a
                        // controlled server anyway — that is the installed --service only).
                        crate::run_me::<&str>(vec![]).ok();
                    }
                    #[cfg(target_os = "macos")]
                    {
                        // our launchagent interval is 1 second
                        hbb_common::sleep(1.5).await;
                        std::process::Command::new("open")
                            .arg("-n")
                            .arg(&format!("/Applications/{}.app", crate::get_app_name()))
                            .spawn()
                            .ok();
                    }
                    // leave above open a little time
                    hbb_common::sleep(0.3).await;
                    // in case below exit failed
                    crate::platform::quit_gui();
                }
                std::process::exit(-1); // to make sure --server luauchagent process can restart because SuccessfulExit used
            }
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        Data::ValidateCmConnection {
            id,
            conn_type,
            cm_auth_token,
            result: None,
        } => {
            let result =
                crate::server::validate_cm_connection_authority(id, conn_type, &cm_auth_token);
            allow_err!(
                stream
                    .send(&Data::ValidateCmConnection {
                        id,
                        conn_type,
                        cm_auth_token: String::new(),
                        result: Some(result),
                    })
                    .await
            );
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        Data::ValidateCmConnection { .. } => {}
        Data::ConfigRequest(name) => {
            let value = if name == "id" {
                Some(Config::get_id())
            } else if name == "permanent-password-storage-and-salt" {
                if current_process_allows_main_channel_permanent_password_storage_sync() {
                    let (storage, salt) = Config::get_local_permanent_password_storage_and_salt();
                    Some(storage + "\n" + &salt)
                } else {
                    log::warn!(
                        "Rejected permanent password storage sync from service-owned server"
                    );
                    None
                }
            } else if name == "permanent-password-set" {
                Some(if Config::has_permanent_password() {
                    "Y".to_owned()
                } else {
                    "N".to_owned()
                })
            } else if name == "permanent-password-is-preset" {
                Some(if Config::is_using_preset_password() {
                    "Y".to_owned()
                } else {
                    "N".to_owned()
                })
            } else if name == "permanent-password-user-owned-writable" {
                Some(
                    if current_process_allows_user_owned_permanent_password_write()
                        && !Config::is_disable_change_permanent_password()
                    {
                        "Y".to_owned()
                    } else {
                        "N".to_owned()
                    },
                )
            } else if name == "salt" {
                if current_process_allows_main_channel_permanent_password_storage_sync() {
                    Some(Config::get_salt())
                } else {
                    log::warn!("Rejected permanent password salt sync from service-owned server");
                    None
                }
            } else if name == "hide_cm" {
                if crate::common::is_custom_client() {
                    Some(hbb_common::password_security::hide_cm().to_string())
                } else {
                    None
                }
            } else if name == "voice-call-input" {
                crate::audio_service::get_voice_call_input_device()
            } else if name == "direct-listener-bound" {
                // T1 / BR-4 (verify-ground-truth): answer the GUI's cross-process query for the
                // REAL direct-listener state. This handler runs in the process that hosts the
                // main "" IPC channel AND binds :21118 (the `--server`, server.rs), so the atomic
                // read here is the true socket state (bound / R-S9-parked / rebinding). The
                // desktop GUI is a SEPARATE process whose own atomic is always false, hence this
                // read-only IPC GET (mirrors how `permanent-password-set` is queried above).
                Some(crate::direct_service::is_direct_listener_bound().to_string())
            } else {
                None
            };
            allow_err!(stream.send(&Data::ConfigValue((name, value))).await);
        }
        Data::SetVoiceCallInput(value) => {
            crate::audio_service::set_voice_call_input_device(Some(value), true);
            log::info!("voice-call-input updated");
        }
        Data::SetUserOwnedPermanentPassword(value) => {
            let accepted = current_process_allows_user_owned_permanent_password_write()
                && !Config::is_disable_change_permanent_password()
                && Config::set_permanent_password(&value);
            if !accepted {
                log::warn!("Rejected user-owned permanent password change");
            }
            allow_err!(
                stream
                    .send(&Data::SetUserOwnedPermanentPasswordResult(accepted))
                    .await
            );
        }
        #[cfg(target_os = "linux")]
        Data::RequestServiceOwnedUnattendedPasswordChange(value) => {
            handle_linux_service_owned_unattended_password_request(channel, value, stream).await;
        }
        #[cfg(target_os = "macos")]
        Data::RequestMacosServiceOwnedUnattendedPasswordChange {
            password,
            authorization,
        } => {
            handle_macos_service_owned_unattended_password_request(
                channel,
                password,
                authorization,
                stream,
            )
            .await;
        }
        #[cfg(target_os = "windows")]
        Data::RequestServiceOwnedUnattendedPasswordChange(_) => {
            allow_err!(
                stream
                    .send(&Data::ServiceOwnedUnattendedPasswordChangeResult(false))
                    .await
            );
        }
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        Data::CommitServiceOwnedUnattendedPasswordChange(value) => {
            let accepted = channel == IpcChannel::Main
                && current_process_allows_service_owned_unattended_password_commit(stream)
                && !Config::is_disable_change_permanent_password()
                && Config::set_permanent_password(&value);
            if !accepted {
                log::warn!("Rejected service-owned unattended password commit");
            }
            allow_err!(
                stream
                    .send(&Data::ServiceOwnedUnattendedPasswordChangeResult(accepted))
                    .await
            );
        }
        Data::Options(value) => match value {
            None => {
                let v = Config::get_options();
                allow_err!(stream.send(&Data::Options(Some(v))).await);
            }
            Some(value) => {
                let accepted = current_process_allows_main_channel_options_write();
                if accepted {
                    let _chk = CheckIfRestart::new();
                    // R-A6/R-S11: CheckTestNatType Drop guard removed here too — is_direct is constant
                    // (socks inert, R-D6(d)(iii)), so it never fired; severs the service-entry probe reach.
                    if let Some(v) = value.get("privacy-mode-impl-key") {
                        crate::privacy_mode::switch(v);
                    }
                    Config::set_options(value);
                } else {
                    log::warn!("Rejected options write over ordinary IPC for service-owned server");
                }
                allow_err!(stream.send(&Data::OptionsSetResult(accepted)).await);
            }
        },
        Data::OptionsSetResult(_) => {}
        Data::SetUserOwnedPermanentPasswordResult(_) => {}
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        Data::ServiceOwnedUnattendedPasswordChangeResult(_) => {}
        #[cfg(target_os = "windows")]
        Data::ServiceOwnedShareRdpResult(_) => {}
        Data::NatType(_) => {
            let t = Config::get_nat_type();
            allow_err!(stream.send(&Data::NatType(Some(t))).await);
        }
        Data::Test => {
            allow_err!(stream.send(&Data::Test).await);
        }
        #[cfg(windows)]
        Data::SyncWinCpuUsage(None) => {
            allow_err!(
                stream
                    .send(&Data::SyncWinCpuUsage(
                        hbb_common::platform::windows::cpu_uage_one_minute()
                    ))
                    .await
            );
        }
        #[cfg(windows)]
        Data::ControlledSessionCount(_) => {
            allow_err!(
                stream
                    .send(&Data::ControlledSessionCount(
                        crate::Connection::alive_conns().len()
                    ))
                    .await
            );
        }
        #[cfg(all(
            feature = "flutter",
            not(any(target_os = "android", target_os = "ios"))
        ))]
        Data::ControllingSessionCount(_count) => {
            // R-X1: updater excised — the controlling-session count was only read to
            // defer an in-progress auto-update; with no updater it is ignored.
        }
        #[cfg(target_os = "linux")]
        Data::TerminalSessionCount(_) => {
            let count = crate::terminal_service::get_terminal_session_count(true);
            allow_err!(stream.send(&Data::TerminalSessionCount(count)).await);
        }
        #[cfg(feature = "hwcodec")]
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        Data::CheckHwcodec => {
            scrap::hwcodec::start_check_process();
        }
        #[cfg(feature = "hwcodec")]
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        Data::HwCodecConfig(c) => {
            match c {
                None => {
                    let v = match scrap::hwcodec::HwCodecConfig::get_set_value() {
                        Some(v) => Some(serde_json::to_string(&v).unwrap_or_default()),
                        None => None,
                    };
                    allow_err!(stream.send(&Data::HwCodecConfig(v)).await);
                }
                Some(v) => {
                    // --server and portable
                    scrap::hwcodec::HwCodecConfig::set(v);
                }
            }
        }
        #[cfg(target_os = "windows")]
        Data::PortForwardSessionCount(c) => match c {
            None => {
                let count = crate::server::AUTHED_CONNS
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|c| c.conn_type == crate::server::AuthConnType::PortForward)
                    .count();
                allow_err!(
                    stream
                        .send(&Data::PortForwardSessionCount(Some(count)))
                        .await
                );
            }
            _ => {
                // Port forward session count is only a get value.
            }
        },
        #[cfg(target_os = "windows")]
        Data::FileTransferEnabledState(_) => {
            use hbb_common::rendezvous_proto::control_permissions::Permission;
            let state = crate::server::get_control_permission_state(Permission::file, false);
            let enabled = state.unwrap_or_else(|| {
                crate::server::Connection::is_permission_enabled_locally(
                    config::keys::OPTION_ENABLE_FILE_TRANSFER,
                )
            });
            allow_err!(
                stream
                    .send(&Data::FileTransferEnabledState(Some(enabled)))
                    .await
            );
        }
        _ => {}
    };
}

#[inline]
async fn connect_with_path(
    ms_timeout: u64,
    path: &str,
    postfix: &str,
) -> ResultType<ConnectionTmpl<ConnClient>> {
    #[cfg(windows)]
    let client = timeout(ms_timeout, connect_windows_named_pipe(path)).await??;
    #[cfg(not(windows))]
    let _ = postfix;
    #[cfg(not(windows))]
    let client = timeout(ms_timeout, Endpoint::connect(path)).await??;
    #[cfg(windows)]
    ensure_windows_ipc_server_matches_current(&client, postfix)?;
    Ok(ConnectionTmpl::new(client))
}

#[cfg(windows)]
async fn connect_windows_named_pipe(path: &str) -> std::io::Result<ConnClient> {
    loop {
        match open_windows_named_pipe_client(path) {
            Ok(client) => return Ok(client),
            Err(err) if err.raw_os_error() == Some(ERROR_PIPE_BUSY.0 as i32) => {}
            Err(err) => return Err(err),
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[cfg(windows)]
fn open_windows_named_pipe_client(path: &str) -> std::io::Result<ConnClient> {
    let wide_path: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let flags = FILE_FLAGS_AND_ATTRIBUTES(
        FILE_FLAG_OVERLAPPED.0 | SECURITY_IDENTIFICATION.0 | SECURITY_SQOS_PRESENT.0,
    );
    let handle = match unsafe {
        CreateFileW(
            PCWSTR::from_raw(wide_path.as_ptr()),
            windows_named_pipe_client_access_mask(),
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    } {
        Ok(handle) => handle,
        Err(_) => return Err(std::io::Error::last_os_error()),
    };
    let client = unsafe { ConnClient::from_raw_handle(handle.0 as RawHandle) };
    match client {
        Ok(client) => Ok(client),
        Err(err) => {
            unsafe {
                let _ = CloseHandle(handle);
            }
            Err(err)
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[inline]
fn select_server_uid_for_user_main_ipc(
    server_uids: &[u32],
    active_uid: Option<u32>,
    prefer_root: bool,
) -> ResultType<u32> {
    let mut server_uids = server_uids.to_vec();
    server_uids.sort_unstable();
    server_uids.dedup();

    match server_uids.as_slice() {
        [] => {
            if let Some(uid) = active_uid {
                // If no `--server` processes are found but the active user is identifiable,
                // try the active user anyway because the main process may also listen on "" IPC.
                return Ok(uid);
            } else {
                bail!("No --server process found for user main IPC")
            }
        }
        [uid] => return Ok(*uid),
        _ => {}
    }

    if prefer_root && server_uids.contains(&0) {
        return Ok(0);
    }
    if let Some(active_uid) = active_uid.filter(|uid| server_uids.contains(uid)) {
        return Ok(active_uid);
    }
    bail!("Multiple --server processes found for user main IPC");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn running_server_uids_for_current_exe() -> ResultType<Vec<u32>> {
    let current_exe = std::env::current_exe()?;
    let current_exe_path = std::fs::canonicalize(&current_exe)?;
    let current_pid = hbb_common::sysinfo::Pid::from_u32(std::process::id());
    let mut sys = hbb_common::sysinfo::System::new();
    sys.refresh_processes();
    let mut server_uids = Vec::new();
    for process in sys.processes().values() {
        if process.pid() == current_pid {
            continue;
        }
        if process.cmd().get(1).map_or(true, |arg| arg != "--server") {
            continue;
        }
        let Ok(process_path) = std::fs::canonicalize(process.exe()) else {
            continue;
        };
        if process_path != current_exe_path {
            continue;
        }
        let Some(uid) = process.user_id().map(|uid| **uid as u32) else {
            // Root CLI management commands need a stable matching `--server` target.
            // If this key process races during enumeration, failing the command is clearer
            // than silently skipping it; `--server` is not expected to exit frequently.
            bail!("Failed to read --server process uid");
        };
        server_uids.push(uid);
    }
    Ok(server_uids)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn user_main_ipc_server_uid() -> ResultType<u32> {
    let server_uids = running_server_uids_for_current_exe()?;
    #[cfg(target_os = "linux")]
    let prefer_root = crate::platform::linux::is_login_screen_wayland();
    #[cfg(target_os = "macos")]
    let prefer_root = false;
    select_server_uid_for_user_main_ipc(&server_uids, active_uid(), prefer_root)
}

pub async fn connect(ms_timeout: u64, postfix: &str) -> ResultType<ConnectionTmpl<ConnClient>> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let use_user_main_ipc = USE_USER_MAIN_IPC.with(|use_user_main| use_user_main.get());
        let is_root_main_ipc =
            unsafe { hbb_common::libc::geteuid() == 0 } && postfix.is_empty() && use_user_main_ipc;
        if is_root_main_ipc {
            let uid = user_main_ipc_server_uid()?;
            let path = Config::ipc_path_for_uid(uid, postfix);
            return connect_with_path(ms_timeout, &path, postfix).await;
        }
        let path = Config::ipc_path(postfix);
        return connect_with_path(ms_timeout, &path, postfix).await;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let path = Config::ipc_path(postfix);
        connect_with_path(ms_timeout, &path, postfix).await
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) async fn validate_cm_connection_authority(
    id: i32,
    conn_type: CmAuthConnType,
    cm_auth_token: &str,
) -> ResultType<CmConnectionAuthority> {
    if id <= 0 {
        bail!("invalid cm connection id");
    }
    if cm_auth_token.is_empty() {
        bail!("missing cm authority token");
    }

    let mut stream = connect(1_000, "").await?;
    stream
        .send(&Data::ValidateCmConnection {
            id,
            conn_type,
            cm_auth_token: cm_auth_token.to_owned(),
            result: None,
        })
        .await?;

    match stream.next_timeout(1_000).await? {
        Some(Data::ValidateCmConnection {
            result: Some(result),
            ..
        }) => Ok(result),
        _ => bail!("invalid cm authority validation response"),
    }
}

#[cfg(target_os = "linux")]
pub async fn connect_for_uid(
    ms_timeout: u64,
    uid: u32,
    postfix: &str,
) -> ResultType<ConnectionTmpl<ConnClient>> {
    let path = Config::ipc_path_for_uid(uid, postfix);
    connect_with_path(ms_timeout, &path, postfix).await
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
pub async fn start_pa() {
    use crate::audio_service::AUDIO_DATA_SIZE_U8;

    match new_listener("_pa").await {
        Ok(mut incoming) => {
            loop {
                if let Some(result) = incoming.next().await {
                    match result {
                        Ok(stream) => {
                            let mut stream = Connection::new(stream);
                            let mut device: String = "".to_owned();
                            if let Some(Ok(Some(Data::PulseAudioSource(x)))) =
                                stream.next_timeout2(1000).await
                            {
                                device = x;
                            }
                            if !device.is_empty() {
                                device = crate::platform::linux::get_pa_source_name(&device);
                            }
                            if device.is_empty() {
                                device = crate::platform::linux::get_pa_monitor();
                            }
                            if device.is_empty() {
                                continue;
                            }
                            let spec = pulse::sample::Spec {
                                format: pulse::sample::Format::F32le,
                                channels: 2,
                                rate: crate::platform::PA_SAMPLE_RATE,
                            };
                            log::info!("pa monitor: {:?}", device);
                            // systemctl --user status pulseaudio.service
                            let mut buf: Vec<u8> = vec![0; AUDIO_DATA_SIZE_U8];
                            match psimple::Simple::new(
                                None,                             // Use the default server
                                &crate::get_app_name(),           // Our application’s name
                                pulse::stream::Direction::Record, // We want a record stream
                                Some(&device),                    // Use the default device
                                "record",                         // Description of our stream
                                &spec,                            // Our sample format
                                None,                             // Use default channel map
                                None, // Use default buffering attributes
                            ) {
                                Ok(s) => loop {
                                    if let Ok(_) = s.read(&mut buf) {
                                        let out =
                                            if buf.iter().filter(|x| **x != 0).next().is_none() {
                                                vec![]
                                            } else {
                                                buf.clone()
                                            };
                                        if let Err(err) = stream.send_raw(out.into()).await {
                                            log::error!("Failed to send audio data:{}", err);
                                            break;
                                        }
                                    }
                                },
                                Err(err) => {
                                    log::error!("Could not create simple pulse: {}", err);
                                }
                            }
                        }
                        Err(err) => {
                            log::error!("Couldn't get pa client: {:?}", err);
                        }
                    }
                }
            }
        }
        Err(err) => {
            log::error!("Failed to start pa ipc server: {}", err);
        }
    }
}

pub struct ConnectionTmpl<T> {
    inner: Framed<T, BytesCodec>,
}

pub type Connection = ConnectionTmpl<Conn>;

impl<T> ConnectionTmpl<T>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin,
{
    pub fn new(conn: T) -> Self {
        Self {
            inner: Framed::new(conn, BytesCodec::new()),
        }
    }

    pub async fn send(&mut self, data: &Data) -> ResultType<()> {
        let v = serde_json::to_vec(data)?;
        self.inner.send(bytes::Bytes::from(v)).await?;
        Ok(())
    }

    pub async fn next_timeout(&mut self, ms_timeout: u64) -> ResultType<Option<Data>> {
        Ok(timeout(ms_timeout, self.next()).await??)
    }

    pub async fn next_timeout2(&mut self, ms_timeout: u64) -> Option<ResultType<Option<Data>>> {
        if let Ok(x) = timeout(ms_timeout, self.next()).await {
            Some(x)
        } else {
            None
        }
    }

    pub async fn next(&mut self) -> ResultType<Option<Data>> {
        match self.inner.next().await {
            Some(res) => {
                let bytes = res?;
                if let Ok(s) = std::str::from_utf8(&bytes) {
                    if let Ok(data) = serde_json::from_str::<Data>(s) {
                        return Ok(Some(data));
                    }
                }
                return Ok(None);
            }
            _ => {
                bail!("reset by the peer");
            }
        }
    }

    pub async fn send_raw(&mut self, data: Bytes) -> ResultType<()> {
        self.inner.send(data).await?;
        Ok(())
    }

    pub async fn next_raw(&mut self) -> ResultType<bytes::BytesMut> {
        match self.inner.next().await {
            Some(Ok(res)) => Ok(res),
            _ => {
                bail!("reset by the peer");
            }
        }
    }
}

#[tokio::main(flavor = "current_thread")]
pub async fn get_config(name: &str) -> ResultType<Option<String>> {
    get_config_async(name, 1_000).await
}

async fn get_config_async(name: &str, ms_timeout: u64) -> ResultType<Option<String>> {
    let mut c = connect(ms_timeout, "").await?;
    c.send(&Data::ConfigRequest(name.to_owned())).await?;
    if let Some(Data::ConfigValue((name2, value))) = c.next_timeout(ms_timeout).await? {
        if name == name2 {
            return Ok(value);
        }
    }
    return Ok(None);
}

async fn set_voice_call_input_device_async(value: String) -> ResultType<()> {
    let mut c = connect(1000, "").await?;
    c.send(&Data::SetVoiceCallInput(value)).await?;
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
pub async fn set_data(data: &Data) -> ResultType<()> {
    set_data_async(data).await
}

async fn set_data_async(data: &Data) -> ResultType<()> {
    let mut c = connect(1000, "").await?;
    c.send(data).await?;
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
pub async fn set_voice_call_input_device(value: String) -> ResultType<()> {
    set_voice_call_input_device_async(value).await
}

fn apply_permanent_password_storage_and_salt_payload(payload: Option<&str>) -> ResultType<()> {
    let Some(payload) = payload else {
        return Ok(());
    };
    let Some((storage, salt)) = payload.split_once('\n') else {
        bail!("Invalid permanent-password-storage-and-salt payload");
    };

    Config::set_permanent_password_storage_for_sync(storage, salt)?;
    Ok(())
}

pub fn sync_permanent_password_storage_from_daemon() -> ResultType<()> {
    let v = get_config("permanent-password-storage-and-salt")?;
    apply_permanent_password_storage_and_salt_payload(v.as_deref())
}

async fn sync_permanent_password_storage_from_daemon_async() -> ResultType<()> {
    let ms_timeout = 1_000;
    let v = get_config_async("permanent-password-storage-and-salt", ms_timeout).await?;
    apply_permanent_password_storage_and_salt_payload(v.as_deref())
}

pub fn is_permanent_password_set() -> bool {
    match get_config("permanent-password-set") {
        Ok(Some(v)) => {
            let v = v.trim();
            return v == "Y";
        }
        Ok(None) => {
            // No response/value (timeout).
        }
        Err(_) => {
            // Connection error.
        }
    }
    log::warn!("Failed to query permanent password state from daemon");
    false
}

/// T1 / BR-4 (verify-ground-truth): query the daemon (`--server`) for the REAL direct-listener
/// state over the main "" IPC channel. Used by the desktop GUI, which runs in a SEPARATE process
/// from the `--server` that binds :21118 (so reading its own `direct_service` atomic would always
/// yield false). A dead/wedged service (the "" channel is unreachable → `get_config` errors) and a
/// parked/rebinding listener (atomic false in the daemon) both correctly read as NOT bound, so the
/// desktop "Reachable on :21118" status can never over-claim.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn get_direct_listener_bound() -> bool {
    matches!(get_config("direct-listener-bound"), Ok(Some(v)) if v.trim() == "true")
}

pub fn is_permanent_password_preset() -> bool {
    if let Ok(Some(v)) = get_config("permanent-password-is-preset") {
        let v = v.trim();
        return v == "Y";
    }
    false
}

pub fn can_set_user_owned_permanent_password() -> bool {
    matches!(
        get_config("permanent-password-user-owned-writable"),
        Ok(Some(v)) if v.trim() == "Y"
    )
}

pub fn set_user_owned_permanent_password(v: String) -> ResultType<()> {
    if Config::is_disable_change_permanent_password() {
        bail!("Changing permanent password is disabled");
    }
    if set_user_owned_permanent_password_with_ack(v)? {
        Ok(())
    } else {
        bail!("Changing permanent password was rejected by daemon");
    }
}

#[cfg(target_os = "linux")]
pub fn can_request_service_owned_unattended_password_change() -> bool {
    crate::platform::is_installed()
}

#[cfg(target_os = "windows")]
pub fn can_request_service_owned_unattended_password_change() -> bool {
    crate::platform::is_installed() && crate::platform::is_elevated(None).unwrap_or(false)
}

#[cfg(target_os = "macos")]
pub fn can_request_service_owned_unattended_password_change() -> bool {
    crate::platform::is_installed() && crate::platform::is_installed_daemon(false)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn can_request_service_owned_unattended_password_change() -> bool {
    false
}

pub fn can_set_permanent_password() -> bool {
    can_set_user_owned_permanent_password()
        || can_request_service_owned_unattended_password_change()
}

pub fn set_permanent_password(v: String) -> ResultType<()> {
    if Config::is_disable_change_permanent_password() {
        bail!("Changing permanent password is disabled");
    }
    if can_set_user_owned_permanent_password() {
        return set_user_owned_permanent_password(v);
    }
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        if can_request_service_owned_unattended_password_change() {
            return set_service_owned_unattended_password(v);
        }
        bail!("Changing service-owned unattended password requires administrator authorization");
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        bail!("Changing service-owned unattended password requires administrator authorization that is not implemented on this platform");
    }
}

#[tokio::main(flavor = "current_thread")]
pub async fn set_user_owned_permanent_password_with_ack(v: String) -> ResultType<bool> {
    set_user_owned_permanent_password_with_ack_async(v).await
}

async fn set_user_owned_permanent_password_with_ack_async(v: String) -> ResultType<bool> {
    // The daemon ACK/NACK is expected quickly since it applies the config in-process.
    let ms_timeout = 1_000;
    let mut c = connect(ms_timeout, "").await?;
    c.send(&Data::SetUserOwnedPermanentPassword(v)).await?;
    if let Some(Data::SetUserOwnedPermanentPasswordResult(ok)) = c.next_timeout(ms_timeout).await? {
        if ok {
            // Ensure the hashed permanent password storage is written to the user config file.
            // This sync must not affect the daemon ACK outcome.
            if let Err(err) = sync_permanent_password_storage_from_daemon_async().await {
                log::warn!("Failed to sync permanent password storage from daemon: {err}");
            }
        }
        return Ok(ok);
    }
    Ok(false)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn set_service_owned_unattended_password(v: String) -> ResultType<()> {
    if set_service_owned_unattended_password_with_ack(v)? {
        Ok(())
    } else {
        bail!("Changing service-owned unattended password was rejected by service");
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tokio::main(flavor = "current_thread")]
async fn set_service_owned_unattended_password_with_ack(v: String) -> ResultType<bool> {
    let ms_timeout = 1_000;
    let mut c = connect_service(ms_timeout).await?;
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        c.send(&Data::RequestServiceOwnedUnattendedPasswordChange(v))
            .await?;
    }
    #[cfg(target_os = "macos")]
    {
        let authorization = crate::platform::service_owned_unattended_password_authorization()?;
        c.send(&Data::RequestMacosServiceOwnedUnattendedPasswordChange {
            password: v,
            authorization,
        })
        .await?;
    }
    if let Some(Data::ServiceOwnedUnattendedPasswordChangeResult(ok)) =
        c.next_timeout(ms_timeout).await?
    {
        return Ok(ok);
    }
    Ok(false)
}

#[cfg(target_os = "windows")]
pub fn set_service_owned_share_rdp(enable: bool) -> ResultType<()> {
    if !crate::platform::is_installed() {
        bail!("Changing RDP session sharing requires an installed service");
    }
    if set_service_owned_share_rdp_with_ack(enable)? {
        Ok(())
    } else {
        bail!("Changing RDP session sharing was rejected by service");
    }
}

#[cfg(target_os = "windows")]
#[tokio::main(flavor = "current_thread")]
async fn set_service_owned_share_rdp_with_ack(enable: bool) -> ResultType<bool> {
    let ms_timeout = 1_000;
    let mut c = connect_service(ms_timeout).await?;
    c.send(&Data::RequestServiceOwnedShareRdp(enable)).await?;
    match c.next_timeout(ms_timeout).await? {
        Some(Data::ServiceOwnedShareRdpResult(ok)) => Ok(ok),
        Some(other) => bail!("Unexpected RDP session-sharing response: {:?}", other),
        None => Ok(false),
    }
}

pub fn get_id() -> String {
    if let Ok(Some(v)) = get_config("id") {
        // update salt also, so that next time reinstallation not causing first-time auto-login failure
        if let Ok(Some(v2)) = get_config("salt") {
            Config::set_salt(&v2);
        }
        if v != Config::get_id() {
            Config::set_id(&v);
        }
        v
    } else {
        Config::get_id()
    }
}

async fn get_options_(ms_timeout: u64) -> ResultType<HashMap<String, String>> {
    let mut c = connect(ms_timeout, "").await?;
    c.send(&Data::Options(None)).await?;
    if let Some(Data::Options(Some(value))) = c.next_timeout(ms_timeout).await? {
        Config::set_options(value.clone());
        Ok(value)
    } else {
        Ok(Config::get_options())
    }
}

pub async fn get_options_async() -> HashMap<String, String> {
    get_options_(1000).await.unwrap_or(Config::get_options())
}

#[tokio::main(flavor = "current_thread")]
pub async fn get_options() -> HashMap<String, String> {
    get_options_async().await
}

pub async fn get_option_async(key: &str) -> String {
    if let Some(v) = get_options_async().await.get(key) {
        v.clone()
    } else {
        "".to_owned()
    }
}

pub fn set_option(key: &str, value: &str) {
    let mut options = get_options();
    if value.is_empty() {
        options.remove(key);
    } else {
        options.insert(key.to_owned(), value.to_owned());
    }
    if let Err(err) = set_options(options) {
        log::warn!("Failed to set option via IPC: key={}, err={}", key, err);
    }
}

#[tokio::main(flavor = "current_thread")]
pub async fn set_options(value: HashMap<String, String>) -> ResultType<()> {
    match connect(1000, "").await {
        Ok(mut c) => {
            c.send(&Data::Options(Some(value.clone()))).await?;
            match c.next_timeout(1000).await? {
                Some(Data::OptionsSetResult(true)) => {
                    Config::set_options(value);
                    Ok(())
                }
                Some(Data::OptionsSetResult(false)) => {
                    bail!("Options write was rejected by daemon")
                }
                Some(other) => {
                    bail!("Unexpected options write response: {:?}", other)
                }
                None => {
                    bail!("Missing options write response")
                }
            }
        }
        Err(err) => bail!("Options write requires daemon ACK: {}", err),
    }
}

#[inline]
async fn get_nat_type_(ms_timeout: u64) -> ResultType<i32> {
    let mut c = connect(ms_timeout, "").await?;
    c.send(&Data::NatType(None)).await?;
    if let Some(Data::NatType(Some(value))) = c.next_timeout(ms_timeout).await? {
        Config::set_nat_type(value);
        Ok(value)
    } else {
        Ok(Config::get_nat_type())
    }
}

pub async fn get_nat_type(ms_timeout: u64) -> i32 {
    get_nat_type_(ms_timeout)
        .await
        .unwrap_or(Config::get_nat_type())
}

// R-D6 (Tier-4): the IPC socks CLIENT query wrappers (get_socks_/get_socks_async/get_socks/set_socks)
// and the service-side proxy handler are excised with the proxy-settings UI. The `Config` storage
// remains inert under the direct-only proxy pin.

// R-SV6(c)/R-D4: `notify_deployed()` (sent `Data::Deployed`) is removed with the deploy excision —
// device deployment is gone (deploy_device is a refuse-stub), so there was no caller and no arm to
// receive it. The `Data::Deployed` variant + its no-op handler are gone too. (notify_deployed
// carried a #[tokio::main] attribute — removed with it.)

#[tokio::main(flavor = "current_thread")]
pub async fn send_url_scheme(url: String) -> ResultType<()> {
    connect(1_000, "_url")
        .await?
        .send(&Data::UrlLink(url))
        .await?;
    Ok(())
}

// Emit `close` events to ipc.
pub fn close_all_instances() -> ResultType<bool> {
    match crate::ipc::send_url_scheme(IPC_ACTION_CLOSE.to_owned()) {
        Ok(_) => Ok(true),
        Err(err) => Err(err),
    }
}

#[tokio::main(flavor = "current_thread")]
pub async fn notify_server_to_check_hwcodec() -> ResultType<()> {
    connect(1_000, "").await?.send(&&Data::CheckHwcodec).await?;
    Ok(())
}

#[cfg(target_os = "windows")]
pub async fn get_port_forward_session_count(ms_timeout: u64) -> ResultType<usize> {
    let mut c = connect(ms_timeout, "").await?;
    c.send(&Data::PortForwardSessionCount(None)).await?;
    if let Some(Data::PortForwardSessionCount(Some(count))) = c.next_timeout(ms_timeout).await? {
        return Ok(count);
    }
    bail!("Failed to get port forward session count");
}

#[cfg(feature = "hwcodec")]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[tokio::main(flavor = "current_thread")]
pub async fn get_hwcodec_config_from_server() -> ResultType<()> {
    if !scrap::codec::enable_hwcodec_option() || scrap::hwcodec::HwCodecConfig::already_set() {
        return Ok(());
    }
    let mut c = connect(50, "").await?;
    c.send(&Data::HwCodecConfig(None)).await?;
    if let Some(Data::HwCodecConfig(v)) = c.next_timeout(50).await? {
        match v {
            Some(v) => {
                scrap::hwcodec::HwCodecConfig::set(v);
                return Ok(());
            }
            None => {
                bail!("hwcodec config is none");
            }
        }
    }
    bail!("failed to get hwcodec config");
}

#[cfg(feature = "hwcodec")]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub fn client_get_hwcodec_config_thread(wait_sec: u64) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    if !crate::platform::is_installed()
        || !scrap::codec::enable_hwcodec_option()
        || scrap::hwcodec::HwCodecConfig::already_set()
    {
        return;
    }
    ONCE.call_once(move || {
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let mut intervals: Vec<u64> = vec![wait_sec, 3, 3, 6, 9];
            for i in intervals.drain(..) {
                if i > 0 {
                    std::thread::sleep(std::time::Duration::from_secs(i));
                }
                if get_hwcodec_config_from_server().is_ok() {
                    break;
                }
            }
        });
    });
}

#[cfg(feature = "hwcodec")]
#[tokio::main(flavor = "current_thread")]
pub async fn hwcodec_process() {
    let s = scrap::hwcodec::check_available_hwcodec();
    for _ in 0..5 {
        match crate::ipc::connect(1000, "").await {
            Ok(mut conn) => {
                match conn
                    .send(&crate::ipc::Data::HwCodecConfig(Some(s.clone())))
                    .await
                {
                    Ok(()) => {
                        log::info!("send ok");
                        break;
                    }
                    Err(e) => {
                        log::error!("send failed: {e:?}");
                    }
                }
            }
            Err(e) => {
                log::error!("connect failed: {e:?}");
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

#[cfg(all(
    feature = "flutter",
    not(any(target_os = "android", target_os = "ios"))
))]
#[tokio::main(flavor = "current_thread")]
pub async fn update_controlling_session_count(count: usize) -> ResultType<()> {
    let mut c = connect(1000, "").await?;
    c.send(&Data::ControllingSessionCount(count)).await?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
pub async fn get_terminal_session_count() -> ResultType<usize> {
    let timeout_ms = 1_000;
    let effective_uid = unsafe { hbb_common::libc::geteuid() as u32 };
    let candidate_uids = terminal_count_candidate_uids(effective_uid);
    let mut last_err: Option<anyhow::Error> = None;
    for candidate_uid in candidate_uids {
        let socket_path = Config::ipc_path_for_uid(candidate_uid, "");
        let connect_result = timeout(timeout_ms, Endpoint::connect(&socket_path))
            .await
            .map_err(|err| {
                anyhow::anyhow!(
                    "Timeout connecting to terminal ipc at {}: {}",
                    socket_path,
                    err
                )
            });
        let connection = match connect_result {
            Ok(Ok(connection)) => connection,
            Ok(Err(err)) => {
                last_err = Some(anyhow::anyhow!(
                    "Failed to connect to terminal ipc at {}: {}",
                    socket_path,
                    err
                ));
                continue;
            }
            Err(err) => {
                last_err = Some(err);
                continue;
            }
        };
        let mut ipc_conn = ConnectionTmpl::new(connection);
        if let Err(err) = ipc_conn.send(&Data::TerminalSessionCount(0)).await {
            last_err = Some(anyhow::anyhow!(
                "Failed to request terminal session count via ipc at {}: {}",
                socket_path,
                err
            ));
            continue;
        }
        match ipc_conn.next_timeout(timeout_ms).await {
            Ok(Some(Data::TerminalSessionCount(session_count))) => {
                return Ok(session_count);
            }
            Ok(None) => {
                last_err = Some(anyhow::anyhow!(
                    "Invalid response when requesting terminal session count via ipc at {}",
                    socket_path
                ));
            }
            Ok(other) => {
                last_err = Some(anyhow::anyhow!(
                    "Unexpected response when requesting terminal session count via ipc at {}: {:?}",
                    socket_path,
                    other.map(|v| std::mem::discriminant(&v))
                ));
            }
            Err(err) => {
                last_err = Some(anyhow::anyhow!(
                    "Failed to read terminal session count via ipc at {}: {}",
                    socket_path,
                    err
                ));
            }
        }
    }
    if let Some(err) = last_err {
        Err(err.into())
    } else {
        Ok(0)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn verify_ffi_enum_data_size() {
        println!("{}", std::mem::size_of::<Data>());
        assert!(std::mem::size_of::<Data>() <= 120);
    }

    // R-S11 / Appendix C #15: the MAIN-channel config-write allowlist MUST reject generic
    // struct-field/proxy writes while admitting the per-key writes that legitimately stay. R-S11b adds
    // that ordinary password and options writes are user-owned only; service-owned unattended
    // credentials and machine policy are denied over ordinary config IPC.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn main_channel_rejects_untyped_state_mutations() {
        use std::collections::HashMap;

        let user_owned = MainIpcAuthority::UserOwned;
        let service_owned = MainIpcAuthority::ServiceOwned;
        let ordinary_peer = MainIpcPeerAuthority::Ordinary;
        assert!(main_channel_admits_state_mutation(
            &Data::Options(None),
            user_owned,
            ordinary_peer
        ));
        assert!(
            main_channel_admits_state_mutation(
                &Data::Options(Some(HashMap::from([(
                    "direct-server".to_owned(),
                    "Y".to_owned()
                )]))),
                user_owned,
                ordinary_peer
            ),
            "a user-owned options write stays legitimate"
        );
        assert!(
            !main_channel_admits_state_mutation(
                &Data::Options(Some(HashMap::from([(
                    "direct-server".to_owned(),
                    "Y".to_owned()
                )]))),
                service_owned,
                ordinary_peer
            ),
            "R-S11b-3: service-owned machine policy MUST NOT be changed over ordinary options IPC"
        );
        // R-S11 (Appendix C #15): the legacy Data::Config write shape is deleted. Config IPC is
        // request/value only; legitimate mutations use named operations.
        assert!(
            main_channel_admits_state_mutation(
                &Data::ConfigRequest("id".to_owned()),
                user_owned,
                ordinary_peer
            ),
            "a ConfigRequest id read must be allowed"
        );
        assert!(
            main_channel_admits_state_mutation(
                &Data::SetVoiceCallInput("mic".to_owned()),
                user_owned,
                ordinary_peer
            ),
            "voice-call-input stays as a typed non-config local operation"
        );
        assert!(
            main_channel_admits_state_mutation(
                &Data::ConfigValue(("id".to_owned(), Some("value".to_owned()))),
                user_owned,
                ordinary_peer
            ),
            "a ConfigValue response is not a write operation"
        );
        assert!(
            main_channel_admits_state_mutation(
                &Data::SetUserOwnedPermanentPassword("pw".to_owned()),
                user_owned,
                ordinary_peer
            ),
            "the typed user-owned permanent-password operation stays legitimate"
        );
        assert!(
            !main_channel_admits_state_mutation(
                &Data::SetUserOwnedPermanentPassword("pw".to_owned()),
                service_owned,
                ordinary_peer
            ),
            "R-S11b-2: the user-owned password operation MUST NOT mutate a service-owned credential"
        );
        #[cfg(target_os = "linux")]
        {
            let root_peer = MainIpcPeerAuthority::RootUnixPeer;
            assert!(
                !main_channel_admits_state_mutation(
                    &Data::RequestServiceOwnedUnattendedPasswordChange("pw".to_owned()),
                    service_owned,
                    root_peer
                ),
                "R-S11b-2: service-owned password requests go to _service, not main IPC"
            );
        }
        #[cfg(target_os = "macos")]
        {
            let root_peer = MainIpcPeerAuthority::RootUnixPeer;
            assert!(
                !main_channel_admits_state_mutation(
                    &Data::RequestMacosServiceOwnedUnattendedPasswordChange {
                        password: "pw".to_owned(),
                        authorization: vec![0; 32],
                    },
                    service_owned,
                    root_peer
                ),
                "R-S11c-1: macOS service-owned password requests go to _service, not main IPC"
            );
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let root_peer = MainIpcPeerAuthority::RootUnixPeer;
            assert!(
                !main_channel_admits_state_mutation(
                    &Data::CommitServiceOwnedUnattendedPasswordChange("pw".to_owned()),
                    user_owned,
                    root_peer
                ),
                "R-S11b-2: a root peer cannot commit into a user-owned server as a service credential"
            );
            assert!(
                !main_channel_admits_state_mutation(
                    &Data::CommitServiceOwnedUnattendedPasswordChange("pw".to_owned()),
                    service_owned,
                    ordinary_peer
                ),
                "R-S11b-2: service-owned password commits require the root service peer"
            );
            assert!(
                main_channel_admits_state_mutation(
                    &Data::CommitServiceOwnedUnattendedPasswordChange("pw".to_owned()),
                    service_owned,
                    root_peer
                ),
                "R-S11b-2: only the root service may commit the service-owned password into the service-owned server"
            );
        }
        assert!(MainIpcAuthority::UserOwned.allows_main_channel_password_storage_sync());
        assert!(
            !MainIpcAuthority::ServiceOwned.allows_main_channel_password_storage_sync(),
            "R-S11b-2: service-owned password storage/salt snapshots MUST NOT sync over ordinary IPC"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_service_owned_password_commit_requires_localsystem_peer() {
        let user_owned = MainIpcAuthority::UserOwned;
        let service_owned = MainIpcAuthority::ServiceOwned;
        let ordinary_peer = MainIpcPeerAuthority::Ordinary;
        let system_peer = MainIpcPeerAuthority::WindowsLocalSystemPeer;

        assert!(
            !main_channel_admits_state_mutation(
                &Data::RequestServiceOwnedUnattendedPasswordChange("pw".to_owned()),
                service_owned,
                system_peer
            ),
            "R-S11c-1: Windows service-owned password requests go to _service, not main IPC"
        );
        assert!(
            !main_channel_admits_state_mutation(
                &Data::RequestServiceOwnedShareRdp(true),
                service_owned,
                system_peer
            ),
            "R-S11b-3: Windows service-owned RDP session-sharing policy requests go to _service, not main IPC"
        );
        assert!(
            !main_channel_admits_state_mutation(
                &Data::CommitServiceOwnedUnattendedPasswordChange("pw".to_owned()),
                user_owned,
                system_peer
            ),
            "R-S11c-1: LocalSystem cannot commit a service credential into a user-owned server"
        );
        assert!(
            !main_channel_admits_state_mutation(
                &Data::CommitServiceOwnedUnattendedPasswordChange("pw".to_owned()),
                service_owned,
                ordinary_peer
            ),
            "R-S11c-1: Windows service-owned password commits require the LocalSystem service peer"
        );
        assert!(
            main_channel_admits_state_mutation(
                &Data::CommitServiceOwnedUnattendedPasswordChange("pw".to_owned()),
                service_owned,
                system_peer
            ),
            "R-S11c-1: only the LocalSystem service may commit the Windows service-owned password"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn service_channel_rejects_config_bus() {
        assert!(
            service_channel_admits_message(&Data::Test),
            "R-S11b-1: _service keeps a narrow liveness ping"
        );
        #[cfg(target_os = "linux")]
        assert!(
            service_channel_admits_message(&Data::RequestServiceOwnedUnattendedPasswordChange(
                "pw".to_owned()
            )),
            "R-S11b-2: Linux _service accepts only the typed admin-authorized password request in addition to liveness"
        );
        #[cfg(target_os = "macos")]
        assert!(
            service_channel_admits_message(
                &Data::RequestMacosServiceOwnedUnattendedPasswordChange {
                    password: "pw".to_owned(),
                    authorization: vec![0; 32],
                }
            ),
            "R-S11c-1: macOS _service accepts only the typed Authorization Services password request in addition to liveness"
        );
        assert!(
            !service_channel_admits_message(&Data::Options(None)),
            "R-S11b-1: _service is not an options/config read channel"
        );
        assert!(
            !service_channel_admits_message(&Data::ConfigRequest("permanent-password".to_owned())),
            "R-S11b-1: _service is not a config read channel"
        );
        assert!(
            !service_channel_admits_message(&Data::SetVoiceCallInput("mic".to_owned())),
            "R-S11b-1: _service does not accept typed main-channel mutations"
        );
        assert!(
            !service_channel_admits_message(&Data::SetUserOwnedPermanentPassword("pw".to_owned())),
            "R-S11b-2: _service does not accept user-owned credential writes"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_proc_stat_start_time_parses_comm_with_spaces() {
        let stat =
            "123 (name with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 20 21";
        assert_eq!(
            linux_proc_stat_start_time(123, stat).unwrap(),
            "424242".to_owned()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_proc_stat_start_time_rejects_missing_start_time() {
        let stat = "123 (rustdesk) S 1 2 3";
        assert!(linux_proc_stat_start_time(123, stat).is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_service_ipc_path_is_shared_across_uids() {
        assert_eq!(
            Config::ipc_path_for_uid(0, crate::POSTFIX_SERVICE),
            Config::ipc_path_for_uid(501, crate::POSTFIX_SERVICE)
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_ipc_path_differs_by_uid_for_cm() {
        let effective_uid = unsafe { hbb_common::libc::geteuid() as u32 };
        let other_uid = effective_uid.saturating_add(1);
        let postfix = "_cm";

        // Default connect path targets the current effective uid.
        assert_eq!(
            Config::ipc_path(postfix),
            Config::ipc_path_for_uid(effective_uid, postfix)
        );
        // A different uid yields a different socket path - this is the root cause of the
        // cross-user regression when root spawns a user process but still connects as uid 0.
        assert_ne!(
            Config::ipc_path(postfix),
            Config::ipc_path_for_uid(other_uid, postfix)
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_select_server_uid_uses_active_uid_when_no_server_found() {
        assert_eq!(
            select_server_uid_for_user_main_ipc(&[], Some(501), false).unwrap(),
            501
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_select_server_uid_uses_single_server_uid() {
        assert_eq!(
            select_server_uid_for_user_main_ipc(&[501], None, false).unwrap(),
            501
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_select_server_uid_prefers_active_uid_with_multiple_servers() {
        assert_eq!(
            select_server_uid_for_user_main_ipc(&[0, 501], Some(501), false).unwrap(),
            501
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_select_server_uid_prefers_root_on_wayland_login_screen() {
        assert_eq!(
            select_server_uid_for_user_main_ipc(&[0, 501], Some(501), true).unwrap(),
            0
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn test_select_server_uid_fails_when_multiple_servers_are_ambiguous() {
        assert!(select_server_uid_for_user_main_ipc(&[501, 502], None, false).is_err());
    }
}
