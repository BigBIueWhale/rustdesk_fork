#[cfg(not(target_os = "ios"))]
use crate::client::ClientClipboardSession;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use crate::clipboard::{update_clipboard, ClipboardSide};
#[cfg(not(any(target_os = "ios")))]
use crate::{
    audio_egress_channel, audio_service, clipboard::CLIPBOARD_INTERVAL, AudioEgressReceiver,
    ConnInner, CLIENT_SERVER,
};
use crate::{
    client::{
        self, new_voice_call_request, Client, Data, Interface, LoginConfigHandler, MediaData,
        OwnedMediaThread, OwnedVideoThread, QualityStatus, VideoControl, VideoFrameAdmission,
        ViewerCommandReceiver, ViewerCommandSender, MILLI1, SEC30,
    },
    common::get_default_sound_input,
    ui_session_interface::{InvokeUiSession, Session},
};
#[cfg(feature = "unix-file-copy-paste")]
use crate::{clipboard::try_empty_clipboard_files, clipboard_file::unix_file_clip};
#[cfg(any(
    target_os = "windows",
    all(target_os = "macos", feature = "unix-file-copy-paste")
))]
use clipboard::ContextSend;
use hbb_common::futures::{future::BoxFuture, stream::FuturesUnordered, FutureExt, StreamExt};
#[cfg(any(target_os = "windows", feature = "unix-file-copy-paste"))]
use hbb_common::tokio::sync::Mutex as TokioMutex;
#[cfg(any(
    target_os = "windows",
    all(target_os = "macos", feature = "unix-file-copy-paste")
))]
use hbb_common::ResultType;
use hbb_common::{
    allow_err,
    config::{self, Config, LocalConfig, PeerConfig, TransferSerde},
    fs::{
        self, can_enable_overwrite_detection, get_job, get_string, new_send_confirm,
        DigestCheckResult, RemoveJobMeta,
    },
    get_time, log,
    message_proto::{option_message::BoolOption, permission_info::Permission, *},
    protobuf::Message as _,
    rendezvous_proto::ConnType,
    timeout,
    tokio::{
        self,
        sync::mpsc,
        time::{self, Duration, Instant},
    },
    Stream,
};
use scrap::CodecFormat;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    ffi::c_void,
    num::NonZeroI64,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock,
    },
};

const MAX_PEER_VIDEO_DISPLAYS: usize = 16;
const MAX_PENDING_SCREENSHOT_RESPONSES: usize = 8;
const MAX_PEER_INFO_PLATFORM_ADDITIONS_BYTES: usize = 8 * 1024;
const MAX_PEER_INFO_RESOLUTIONS: usize = 256;
const MAX_PEER_WINDOWS_SESSIONS: usize = 64;
const MAX_PEER_PLATFORM_ADDITION_LIST_ITEMS: usize = 64;
const MAX_PEER_PRIVACY_MODE_IMPLS: usize = 8;
const MAX_PEER_DISPLAY_DIMENSION: i32 = 32_768;
const MAX_PEER_DISPLAY_ORIGIN_ABS: i32 = 1_000_000;
const MAX_PEER_DISPLAY_SCALE: f64 = 16.0;
const PRIVACY_MODE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PENDING_VIEWER_FILE_WRITES: usize = 256;
const MAX_PENDING_VIEWER_FILE_WRITE_BYTES: usize = hbb_common::cpace::MAX_SESSION_PACKET * 2;
const VIEWER_FILE_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ViewerVideoRefreshRequest {
    All,
    Display(usize),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ViewerVideoRefreshAdmissionError {
    Capacity,
    Closed,
}

#[derive(Default)]
struct ViewerVideoRefreshState {
    all: bool,
    displays: VecDeque<usize>,
    closed: bool,
}

#[derive(Clone)]
pub(crate) struct ViewerVideoRefreshSender {
    state: Arc<std::sync::Mutex<ViewerVideoRefreshState>>,
    wake: mpsc::Sender<()>,
}

pub(crate) struct ViewerVideoRefreshReceiver {
    state: Arc<std::sync::Mutex<ViewerVideoRefreshState>>,
    wake: mpsc::Receiver<()>,
}

pub(crate) fn viewer_video_refresh_channel(
) -> (ViewerVideoRefreshSender, ViewerVideoRefreshReceiver) {
    let state = Arc::new(std::sync::Mutex::new(ViewerVideoRefreshState::default()));
    let (wake, receiver) = mpsc::channel(1);
    (
        ViewerVideoRefreshSender {
            state: Arc::clone(&state),
            wake,
        },
        ViewerVideoRefreshReceiver {
            state,
            wake: receiver,
        },
    )
}

impl ViewerVideoRefreshSender {
    pub(crate) fn request(
        &self,
        request: ViewerVideoRefreshRequest,
    ) -> Result<(), ViewerVideoRefreshAdmissionError> {
        {
            let mut state = self.state.lock().unwrap();
            if state.closed {
                return Err(ViewerVideoRefreshAdmissionError::Closed);
            }
            match request {
                ViewerVideoRefreshRequest::All => {
                    state.all = true;
                    state.displays.clear();
                }
                ViewerVideoRefreshRequest::Display(display) => {
                    if !state.all && !state.displays.contains(&display) {
                        if state.displays.len() >= MAX_PEER_VIDEO_DISPLAYS {
                            return Err(ViewerVideoRefreshAdmissionError::Capacity);
                        }
                        state.displays.push_back(display);
                    }
                }
            }
        }

        match self.wake.try_send(()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                let mut state = self.state.lock().unwrap();
                state.closed = true;
                state.all = false;
                state.displays.clear();
                Err(ViewerVideoRefreshAdmissionError::Closed)
            }
        }
    }
}

impl ViewerVideoRefreshReceiver {
    fn take_next(&self) -> Option<ViewerVideoRefreshRequest> {
        let mut state = self.state.lock().unwrap();
        if state.all {
            state.all = false;
            Some(ViewerVideoRefreshRequest::All)
        } else {
            state
                .displays
                .pop_front()
                .map(ViewerVideoRefreshRequest::Display)
        }
    }

    async fn recv(&mut self) -> Option<ViewerVideoRefreshRequest> {
        loop {
            if let Some(request) = self.take_next() {
                return Some(request);
            }
            self.wake.recv().await?;
        }
    }

    #[cfg(test)]
    pub(crate) fn try_recv(&self) -> Option<ViewerVideoRefreshRequest> {
        self.take_next()
    }
}

impl Drop for ViewerVideoRefreshReceiver {
    fn drop(&mut self) {
        {
            let mut state = self.state.lock().unwrap();
            state.closed = true;
            state.all = false;
            state.displays.clear();
        }
        self.wake.close();
    }
}

fn is_video_refresh_message(message: &Message) -> bool {
    matches!(
        &message.union,
        Some(message::Union::Misc(misc))
            if matches!(
                &misc.union,
                Some(
                    misc::Union::RefreshVideo(_)
                        | misc::Union::RefreshVideoDisplay(_)
                )
            )
    )
}

fn native_video_frame_runtime_supported(vf: &VideoFrame) -> bool {
    let format = CodecFormat::from(vf);
    if format == CodecFormat::AV1 {
        log::warn!("dropping peer AV1 video frame before viewer state admission");
        false
    } else {
        true
    }
}

pub(crate) fn starts_video_sequence(vf: &VideoFrame) -> bool {
    use video_frame::Union::*;
    match &vf.union {
        Some(vf) => match vf {
            Vp8s(f) | Vp9s(f) | Av1s(f) | H264s(f) | H265s(f) => {
                f.frames.first().map_or(false, |frame| frame.key)
            }
            Rgb(_) | Yuv(_) => true,
            _ => false,
        },
        None => false,
    }
}

struct VoiceCallAudio {
    #[cfg(not(target_os = "ios"))]
    subscription: Option<ConnInner>,
    #[cfg(not(target_os = "ios"))]
    input_lease: Option<audio_service::VoiceCallInputLease>,
    #[cfg(not(target_os = "ios"))]
    receiver: AudioEgressReceiver,
}

impl VoiceCallAudio {
    #[cfg(not(target_os = "ios"))]
    fn new(
        subscription: ConnInner,
        input_lease: audio_service::VoiceCallInputLease,
        receiver: AudioEgressReceiver,
    ) -> Self {
        Self {
            subscription: Some(subscription),
            input_lease: Some(input_lease),
            receiver,
        }
    }

    fn stop(&mut self) {
        #[cfg(not(target_os = "ios"))]
        {
            if let Some(subscription) = self.subscription.take() {
                // Removing the exact subscription and dropping our retained copy closes capture
                // admission before the input lease can release the process-wide source.
                CLIENT_SERVER
                    .write()
                    .unwrap()
                    .subscribe(audio_service::NAME, subscription, false);
            }
            drop(self.input_lease.take());
        }
    }
}

impl Drop for VoiceCallAudio {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(not(target_os = "ios"))]
async fn recv_voice_call_audio(voice_call: &mut Option<VoiceCallAudio>) -> Option<Arc<Message>> {
    match voice_call.as_mut() {
        Some(voice_call) => voice_call.receiver.recv().await.map(|(_, message)| message),
        None => std::future::pending().await,
    }
}

#[cfg(target_os = "ios")]
async fn recv_voice_call_audio(voice_call: &mut Option<VoiceCallAudio>) -> Option<Arc<Message>> {
    let _ = voice_call;
    std::future::pending().await
}

// R-S11ed: this is the sole owner of the delayed OS-password sequence admitted by one
// Remote/network round. Normal replacement and final teardown abort and await the exact task;
// hard-drop still aborts it, and the task carries only that Remote's exact sender.
#[derive(Default)]
struct OwnedInputOsPasswordTask {
    task: Option<tokio::task::JoinHandle<()>>,
}

impl OwnedInputOsPasswordTask {
    async fn replace<F>(&mut self, future: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        self.stop_and_join().await;
        self.task = Some(tokio::spawn(future));
    }

    async fn stop_and_join(&mut self) {
        let Some(task) = self.task.take() else {
            return;
        };
        task.abort();
        match task.await {
            Ok(()) => {}
            Err(err) if err.is_cancelled() => {}
            Err(err) => {
                log::error!("OS-password input task failed: {err}");
            }
        }
    }
}

impl Drop for OwnedInputOsPasswordTask {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ViewerFileWriteKind {
    Control,
    TransferData,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ViewerFileWriteContext {
    job_id: Option<i32>,
    file_num: i32,
    operation: &'static str,
    kind: ViewerFileWriteKind,
}

impl ViewerFileWriteContext {
    fn control(job_id: Option<i32>, file_num: i32, operation: &'static str) -> Self {
        Self {
            job_id,
            file_num,
            operation,
            kind: ViewerFileWriteKind::Control,
        }
    }

    fn transfer_data(job_id: Option<i32>, file_num: i32) -> Self {
        Self {
            job_id,
            file_num,
            operation: "file transfer data",
            kind: ViewerFileWriteKind::TransferData,
        }
    }
}

#[derive(Clone, Copy)]
struct ViewerFileWriteLimits {
    count: usize,
    bytes: usize,
    timeout: Duration,
}

const VIEWER_FILE_WRITE_LIMITS: ViewerFileWriteLimits = ViewerFileWriteLimits {
    count: MAX_PENDING_VIEWER_FILE_WRITES,
    bytes: MAX_PENDING_VIEWER_FILE_WRITE_BYTES,
    timeout: VIEWER_FILE_WRITE_TIMEOUT,
};

#[derive(Debug)]
struct ViewerFileWriteReservation {
    id: u64,
}

struct ViewerFileWriteCompletion {
    context: Option<ViewerFileWriteContext>,
    result: Result<(), String>,
}

#[derive(Debug, Eq, PartialEq)]
enum ViewerFileBlockWrite {
    NoActiveJob,
    Written { update_status: bool },
}

#[derive(Debug, Eq, PartialEq)]
struct ViewerFileBlockWriteFailure {
    id: i32,
    file_num: i32,
    error: String,
}

async fn write_viewer_file_block(
    write_jobs: &mut Vec<fs::TransferJob>,
    block: FileTransferBlock,
) -> Result<ViewerFileBlockWrite, ViewerFileBlockWriteFailure> {
    let id = block.id;
    let file_num = block.file_num;
    let Some(job) = fs::get_job(id, write_jobs) else {
        return Ok(ViewerFileBlockWrite::NoActiveJob);
    };
    let update_status = job.r#type == fs::JobType::Generic;
    if let Err(error) = job.write(block).await {
        let mut error = error.to_string();
        match fs::remove_job(id, write_jobs) {
            Some(mut job) => job.remove_download_file(),
            None => error.push_str("; exact receive job disappeared before failure cleanup"),
        }
        return Err(ViewerFileBlockWriteFailure {
            id,
            file_num,
            error,
        });
    }
    Ok(ViewerFileBlockWrite::Written { update_status })
}

struct ViewerFileWriteTracker {
    next_id: u64,
    pending_bytes: usize,
    limits: ViewerFileWriteLimits,
    contexts: HashMap<u64, (ViewerFileWriteContext, usize)>,
    completions: FuturesUnordered<BoxFuture<'static, (u64, Result<(), String>)>>,
}

impl ViewerFileWriteTracker {
    fn new() -> Self {
        Self::with_limits(VIEWER_FILE_WRITE_LIMITS)
    }

    fn with_limits(limits: ViewerFileWriteLimits) -> Self {
        Self {
            next_id: 0,
            pending_bytes: 0,
            limits,
            contexts: HashMap::new(),
            completions: FuturesUnordered::new(),
        }
    }

    fn reserve(
        &mut self,
        context: ViewerFileWriteContext,
        bytes: usize,
    ) -> Result<ViewerFileWriteReservation, String> {
        if self.contexts.len() >= self.limits.count {
            return Err(format!(
                "viewer file writer completion capacity reached (limit {})",
                self.limits.count
            ));
        }
        let pending_bytes = self
            .pending_bytes
            .checked_add(bytes)
            .ok_or_else(|| "viewer file writer byte accounting overflowed".to_owned())?;
        if pending_bytes > self.limits.bytes {
            return Err(format!(
                "viewer file writer byte capacity reached ({} pending + {} bytes; limit {})",
                self.pending_bytes, bytes, self.limits.bytes
            ));
        }
        let id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| "viewer file writer completion sequence exhausted".to_owned())?;
        if self.contexts.contains_key(&id) {
            return Err("viewer file writer completion identity was reused".to_owned());
        }
        self.next_id = id;
        self.pending_bytes = pending_bytes;
        self.contexts.insert(id, (context, bytes));
        Ok(ViewerFileWriteReservation { id })
    }

    fn attach(
        &mut self,
        reservation: ViewerFileWriteReservation,
        receipt: hbb_common::tcp::WriterReceipt,
    ) -> Result<(), String> {
        if !self.contexts.contains_key(&reservation.id) {
            return Err("viewer file writer reservation was lost before attachment".to_owned());
        }
        let id = reservation.id;
        let timeout = self.limits.timeout;
        self.completions.push(
            async move {
                let result = match time::timeout(timeout, receipt).await {
                    Ok(Ok(Ok(()))) => Ok(()),
                    Ok(Ok(Err(err))) => Err(format!("transport writer failed: {err}")),
                    Ok(Err(_)) => {
                        Err("transport writer retired before exact completion".to_owned())
                    }
                    Err(_) => Err("transport writer completion timed out".to_owned()),
                };
                (id, result)
            }
            .boxed(),
        );
        Ok(())
    }

    fn cancel(
        &mut self,
        reservation: ViewerFileWriteReservation,
    ) -> Result<Option<ViewerFileWriteContext>, String> {
        let Some((context, bytes)) = self.contexts.remove(&reservation.id) else {
            return Ok(None);
        };
        self.pending_bytes = self
            .pending_bytes
            .checked_sub(bytes)
            .ok_or_else(|| "viewer file writer byte accounting underflowed".to_owned())?;
        Ok(Some(context))
    }

    fn is_empty(&self) -> bool {
        self.contexts.is_empty()
    }

    fn has_transfer_data(&self) -> bool {
        self.contexts
            .values()
            .any(|(context, _)| context.kind == ViewerFileWriteKind::TransferData)
    }

    async fn next(&mut self) -> Option<ViewerFileWriteCompletion> {
        let (id, mut result) = self.completions.next().await?;
        let context = match self.contexts.remove(&id) {
            Some((context, bytes)) => {
                match self.pending_bytes.checked_sub(bytes) {
                    Some(pending_bytes) => self.pending_bytes = pending_bytes,
                    None => {
                        self.pending_bytes = 0;
                        result = Err("viewer file writer byte accounting underflowed".to_owned());
                    }
                }
                Some(context)
            }
            None => {
                result = Err("viewer file writer completion identity was not pending".to_owned());
                None
            }
        };
        Some(ViewerFileWriteCompletion { context, result })
    }

    fn retire(&mut self) -> Vec<ViewerFileWriteContext> {
        self.completions = FuturesUnordered::new();
        self.pending_bytes = 0;
        self.contexts
            .drain()
            .map(|(_, (context, _))| context)
            .collect()
    }
}

pub struct Remote<T: InvokeUiSession> {
    handler: Session<T>,
    audio_thread: OwnedMediaThread,
    receiver: ViewerCommandReceiver,
    sender: ViewerCommandSender,
    video_refresh: ViewerVideoRefreshReceiver,
    input_os_password_task: OwnedInputOsPasswordTask,
    // Stop sending local audio to remote client.
    voice_call_audio: Option<VoiceCallAudio>,
    voice_call_request_timestamp: Option<NonZeroI64>,
    read_jobs: Vec<fs::TransferJob>,
    write_jobs: Vec<fs::TransferJob>,
    remove_jobs: HashMap<i32, RemoveJob>,
    timer: crate::RustDeskInterval,
    last_update_jobs_status: (Instant, HashMap<i32, u64>),
    is_connected: bool,
    first_frame: bool,
    #[cfg(any(target_os = "windows", feature = "unix-file-copy-paste"))]
    client_conn_id: i32, // used for file clipboard
    data_count: Arc<AtomicUsize>,
    video_format: CodecFormat,
    peer_info: ParsedPeerInfo,
    video_threads: HashMap<usize, VideoThread>,
    chroma: Arc<RwLock<Option<Chroma>>>,
    last_record_state: bool,
    sent_close_reason: bool,
    peer_text_gate: crate::peer_text::PeerTextGate,
    pending_screenshot_requests: PendingScreenshotRequests,
    pending_privacy_mode_request: Option<PendingPrivacyModeRequest>,
    file_writes: ViewerFileWriteTracker,
    file_flow_failure: Option<(ViewerFileWriteContext, String)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivacyModeResponseAdmission {
    Persist(bool),
    CompleteWithoutPersist,
    Ignore,
}

#[derive(Clone, Debug)]
struct PendingPrivacyModeRequest {
    on: bool,
    impl_key: String,
    sent_at: Instant,
}

#[derive(Default)]
struct PendingScreenshotRequests {
    owners: HashMap<String, String>,
    next_sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScreenshotRequestAdmissionError {
    Capacity,
    SequenceExhausted,
}

impl PendingScreenshotRequests {
    fn replace(&mut self, owner_sid: String) -> Result<String, ScreenshotRequestAdmissionError> {
        self.owners
            .retain(|_, existing_owner_sid| existing_owner_sid != &owner_sid);
        if self.owners.len() >= MAX_PENDING_SCREENSHOT_RESPONSES {
            return Err(ScreenshotRequestAdmissionError::Capacity);
        }
        let sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(ScreenshotRequestAdmissionError::SequenceExhausted)?;
        self.next_sequence = sequence;
        let request_id = format!("{owner_sid}:{sequence}");
        self.owners.insert(request_id.clone(), owner_sid);
        Ok(request_id)
    }

    fn complete(&mut self, request_id: &str) -> Option<String> {
        self.owners.remove(request_id)
    }

    fn len(&self) -> usize {
        self.owners.len()
    }
}

impl PendingPrivacyModeRequest {
    fn new(on: bool, impl_key: String) -> Self {
        Self::new_at(on, impl_key, Instant::now())
    }

    fn new_at(on: bool, impl_key: String, sent_at: Instant) -> Self {
        Self {
            on,
            impl_key: config::bound_peer_config_string(&impl_key),
            sent_at,
        }
    }

    fn from_message(msg: &Message, default_remote_session: bool) -> Option<Self> {
        if !default_remote_session {
            return None;
        }
        let Some(message::Union::Misc(misc)) = &msg.union else {
            return None;
        };
        match misc.union.as_ref()? {
            misc::Union::TogglePrivacyMode(toggle) => {
                Some(Self::new(toggle.on, toggle.impl_key.clone()))
            }
            misc::Union::Option(option) => {
                let on = match option.privacy_mode.enum_value().ok()? {
                    BoolOption::Yes => true,
                    BoolOption::No => false,
                    BoolOption::NotSet => return None,
                };
                Some(Self::new(on, String::new()))
            }
            _ => None,
        }
    }

    fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.sent_at) > PRIVACY_MODE_RESPONSE_TIMEOUT
    }

    fn classify_response(
        &self,
        state: back_notification::PrivacyModeState,
        impl_key: &str,
        now: Instant,
    ) -> PrivacyModeResponseAdmission {
        if self.is_expired(now) {
            return PrivacyModeResponseAdmission::Ignore;
        }
        if !self.impl_key.is_empty() && self.impl_key != config::bound_peer_config_string(impl_key)
        {
            return PrivacyModeResponseAdmission::Ignore;
        }
        match (self.on, state) {
            (true, back_notification::PrivacyModeState::PrvOnSucceeded) => {
                PrivacyModeResponseAdmission::Persist(true)
            }
            (
                true,
                back_notification::PrivacyModeState::PrvNotSupported
                | back_notification::PrivacyModeState::PrvOnFailedDenied
                | back_notification::PrivacyModeState::PrvOnFailedPlugin
                | back_notification::PrivacyModeState::PrvOnFailed,
            ) => PrivacyModeResponseAdmission::Persist(false),
            (true, back_notification::PrivacyModeState::PrvOnByOther) => {
                PrivacyModeResponseAdmission::CompleteWithoutPersist
            }
            (
                false,
                back_notification::PrivacyModeState::PrvOffSucceeded
                | back_notification::PrivacyModeState::PrvOffByPeer
                | back_notification::PrivacyModeState::PrvOffUnknown,
            ) => PrivacyModeResponseAdmission::Persist(false),
            (false, back_notification::PrivacyModeState::PrvOffFailed) => {
                PrivacyModeResponseAdmission::CompleteWithoutPersist
            }
            _ => PrivacyModeResponseAdmission::Ignore,
        }
    }
}

#[derive(Default)]
struct ParsedPeerInfo {
    platform: String,
    is_installed: bool,
    idd_impl: String,
    support_view_camera: bool,
    support_terminal: bool,
    display_count: usize,
}

impl ParsedPeerInfo {
    fn is_support_virtual_display(&self) -> bool {
        self.is_installed && self.platform == "Windows" && self.idd_impl == "amyuni_idd"
    }

    fn allowed_video_displays(&self) -> usize {
        if self.display_count == 0 {
            1
        } else {
            self.display_count.min(MAX_PEER_VIDEO_DISPLAYS)
        }
    }

    fn video_display_allowed(&self, display: usize) -> bool {
        display < self.allowed_video_displays()
    }
}

fn bound_peer_info(mut pi: PeerInfo) -> PeerInfo {
    pi.username = config::bound_peer_config_string(&pi.username);
    pi.hostname = config::bound_peer_config_string(&pi.hostname);
    pi.platform = config::bound_peer_config_string(&pi.platform);
    pi.version = config::bound_peer_config_string(&pi.version);
    pi.platform_additions = sanitize_peer_platform_additions(&pi.platform_additions);

    if pi.displays.len() > MAX_PEER_VIDEO_DISPLAYS {
        log::warn!(
            "peer advertised {} displays; truncating to {}",
            pi.displays.len(),
            MAX_PEER_VIDEO_DISPLAYS
        );
        pi.displays.truncate(MAX_PEER_VIDEO_DISPLAYS);
    }
    for display in pi.displays.iter_mut() {
        sanitize_peer_display_info(display);
    }
    if pi.current_display < 0 || pi.current_display as usize >= pi.displays.len() {
        pi.current_display = 0;
    }
    if let Some(resolutions) = pi.resolutions.as_mut() {
        if resolutions.resolutions.len() > MAX_PEER_INFO_RESOLUTIONS {
            log::warn!(
                "peer advertised {} resolutions; truncating to {}",
                resolutions.resolutions.len(),
                MAX_PEER_INFO_RESOLUTIONS
            );
            resolutions.resolutions.truncate(MAX_PEER_INFO_RESOLUTIONS);
        }
        let before = resolutions.resolutions.len();
        resolutions.resolutions.retain(|resolution| {
            is_peer_display_dimension(resolution.width)
                && is_peer_display_dimension(resolution.height)
        });
        if resolutions.resolutions.len() != before {
            log::warn!(
                "peer advertised {} invalid resolutions; dropping them",
                before - resolutions.resolutions.len()
            );
        }
    }
    if let Some(windows_sessions) = pi.windows_sessions.as_mut() {
        if windows_sessions.sessions.len() > MAX_PEER_WINDOWS_SESSIONS {
            log::warn!(
                "peer advertised {} Windows sessions; truncating to {}",
                windows_sessions.sessions.len(),
                MAX_PEER_WINDOWS_SESSIONS
            );
            windows_sessions
                .sessions
                .truncate(MAX_PEER_WINDOWS_SESSIONS);
        }
        for session in windows_sessions.sessions.iter_mut() {
            session.name = config::bound_peer_config_string(&session.name);
        }
    }
    pi
}

fn sanitize_peer_display_info(display: &mut DisplayInfo) {
    display.name = config::bound_peer_config_string(&display.name);
    display.x = display
        .x
        .clamp(-MAX_PEER_DISPLAY_ORIGIN_ABS, MAX_PEER_DISPLAY_ORIGIN_ABS);
    display.y = display
        .y
        .clamp(-MAX_PEER_DISPLAY_ORIGIN_ABS, MAX_PEER_DISPLAY_ORIGIN_ABS);
    display.width = sanitize_peer_display_dimension(display.width);
    display.height = sanitize_peer_display_dimension(display.height);
    let mut clear_original_resolution = false;
    if let Some(original_resolution) = display.original_resolution.as_mut() {
        if original_resolution.width == 0 && original_resolution.height == 0 {
            // RustDesk uses 0x0 as the virtual-display marker in Flutter.
        } else if is_peer_display_dimension(original_resolution.width)
            && is_peer_display_dimension(original_resolution.height)
        {
            original_resolution.width = sanitize_peer_display_dimension(original_resolution.width);
            original_resolution.height =
                sanitize_peer_display_dimension(original_resolution.height);
        } else {
            clear_original_resolution = true;
        }
    }
    if clear_original_resolution {
        display.original_resolution = Default::default();
    }
    if !display.scale.is_finite() || display.scale <= 0.0 || display.scale > MAX_PEER_DISPLAY_SCALE
    {
        display.scale = 1.0;
    }
}

fn is_peer_display_dimension(value: i32) -> bool {
    (1..=MAX_PEER_DISPLAY_DIMENSION).contains(&value)
}

fn sanitize_peer_display_dimension(value: i32) -> i32 {
    value.clamp(1, MAX_PEER_DISPLAY_DIMENSION)
}

fn sanitize_peer_platform_additions(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    if raw.len() > MAX_PEER_INFO_PLATFORM_ADDITIONS_BYTES {
        log::warn!(
            "dropping oversized peer platform_additions: {} > {} bytes",
            raw.len(),
            MAX_PEER_INFO_PLATFORM_ADDITIONS_BYTES
        );
        return String::new();
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        log::warn!("dropping malformed peer platform_additions JSON");
        return String::new();
    };
    let Some(input) = value.as_object() else {
        log::warn!("dropping non-object peer platform_additions JSON");
        return String::new();
    };

    let mut output = serde_json::Map::new();
    for key in [
        "is_wayland",
        "headless",
        "is_installed",
        "has_file_clipboard",
        "support_view_camera",
    ] {
        if let Some(value) = input.get(key).and_then(|v| v.as_bool()) {
            output.insert(key.to_owned(), serde_json::json!(value));
        }
    }
    if let Some(value) = input.get("idd_impl").and_then(|v| v.as_str()) {
        output.insert(
            "idd_impl".to_owned(),
            serde_json::json!(config::bound_peer_config_string(value)),
        );
    }
    if let Some(value) = input
        .get("amyuni_virtual_displays")
        .and_then(|v| v.as_u64())
    {
        let value = value.min(MAX_PEER_PLATFORM_ADDITION_LIST_ITEMS as u64);
        output.insert(
            "amyuni_virtual_displays".to_owned(),
            serde_json::json!(value),
        );
    }
    if let Some(values) = input
        .get("supported_privacy_mode_impl")
        .and_then(|v| v.as_array())
    {
        let values: Vec<Vec<String>> = values
            .iter()
            .filter_map(|entry| {
                let entry = entry.as_array()?;
                let key = entry.get(0)?.as_str()?;
                let label = entry.get(1)?.as_str()?;
                Some(vec![
                    config::bound_peer_config_string(key),
                    config::bound_peer_config_string(label),
                ])
            })
            .take(MAX_PEER_PRIVACY_MODE_IMPLS)
            .collect();
        output.insert(
            "supported_privacy_mode_impl".to_owned(),
            serde_json::json!(values),
        );
    }

    if output.is_empty() {
        String::new()
    } else {
        match serde_json::to_string(&output) {
            Ok(value) => value,
            Err(err) => {
                log::warn!("dropping unserializable peer platform_additions JSON: {err}");
                String::new()
            }
        }
    }
}

impl<T: InvokeUiSession> Remote<T> {
    pub(crate) fn new(
        handler: Session<T>,
        receiver: ViewerCommandReceiver,
        sender: ViewerCommandSender,
        video_refresh: ViewerVideoRefreshReceiver,
    ) -> Self {
        Self {
            handler,
            audio_thread: crate::client::start_audio_thread(),
            receiver,
            sender,
            video_refresh,
            input_os_password_task: Default::default(),
            read_jobs: Vec::new(),
            write_jobs: Vec::new(),
            remove_jobs: Default::default(),
            timer: crate::rustdesk_interval(time::interval(SEC30)),
            last_update_jobs_status: (Instant::now(), Default::default()),
            is_connected: false,
            first_frame: false,
            #[cfg(any(target_os = "windows", feature = "unix-file-copy-paste"))]
            client_conn_id: 0,
            data_count: Arc::new(AtomicUsize::new(0)),
            video_format: CodecFormat::Unknown,
            voice_call_audio: None,
            voice_call_request_timestamp: None,
            peer_info: Default::default(),
            video_threads: Default::default(),
            chroma: Default::default(),
            last_record_state: false,
            sent_close_reason: false,
            peer_text_gate: Default::default(),
            pending_screenshot_requests: Default::default(),
            pending_privacy_mode_request: None,
            file_writes: ViewerFileWriteTracker::new(),
            file_flow_failure: None,
        }
    }

    async fn enqueue_file_message(
        file_writes: &mut ViewerFileWriteTracker,
        peer: &mut Stream,
        message: &Message,
        context: ViewerFileWriteContext,
    ) -> Result<(), String> {
        let payload_bytes = usize::try_from(message.compute_size())
            .map_err(|_| "viewer file message size does not fit usize".to_owned())?;
        let retained_bytes = payload_bytes
            .checked_add(hbb_common::sodiumoxide::crypto::secretbox::MACBYTES)
            .ok_or_else(|| "viewer file message size accounting overflowed".to_owned())?;
        let reservation = file_writes.reserve(context, retained_bytes)?;
        let receipt = match peer.send_with_receipt(message).await {
            Ok(receipt) => receipt,
            Err(err) => {
                let cancel_result = file_writes.cancel(reservation);
                return match cancel_result {
                    Ok(_) => Err(format!(
                        "failed to admit file message to transport writer: {err}"
                    )),
                    Err(cancel_err) => Err(format!(
                        "failed to admit file message to transport writer: {err}; {cancel_err}"
                    )),
                };
            }
        };
        file_writes.attach(reservation, receipt)
    }

    fn file_message_context(message: &Message) -> Option<ViewerFileWriteContext> {
        let Some(message::Union::FileAction(action)) = message.union.as_ref() else {
            return None;
        };
        Some(match action.union.as_ref() {
            Some(file_action::Union::Send(value)) => {
                ViewerFileWriteContext::control(Some(value.id), value.file_num, "send files")
            }
            Some(file_action::Union::Receive(value)) => {
                ViewerFileWriteContext::control(Some(value.id), value.file_num, "receive files")
            }
            Some(file_action::Union::RemoveDir(value)) => {
                ViewerFileWriteContext::control(Some(value.id), -1, "remove remote directory")
            }
            Some(file_action::Union::RemoveFile(value)) => ViewerFileWriteContext::control(
                Some(value.id),
                value.file_num,
                "remove remote file",
            ),
            Some(file_action::Union::Create(value)) => {
                ViewerFileWriteContext::control(Some(value.id), -1, "create remote directory")
            }
            Some(file_action::Union::Cancel(value)) => {
                ViewerFileWriteContext::control(Some(value.id), -1, "cancel file transfer")
            }
            Some(file_action::Union::SendConfirm(value)) => ViewerFileWriteContext::control(
                Some(value.id),
                value.file_num,
                "confirm file transfer",
            ),
            Some(file_action::Union::Rename(value)) => {
                ViewerFileWriteContext::control(Some(value.id), -1, "rename remote file")
            }
            Some(file_action::Union::AllFiles(value)) => {
                ViewerFileWriteContext::control(Some(value.id), -1, "enumerate remote files")
            }
            Some(file_action::Union::ReadDir(_)) => {
                ViewerFileWriteContext::control(None, -1, "read remote directory")
            }
            Some(file_action::Union::ReadEmptyDirs(_)) => {
                ViewerFileWriteContext::control(None, -1, "read remote empty directories")
            }
            _ => return None,
        })
    }

    async fn send_tracked_file_action(&mut self, peer: &mut Stream, message: &Message) -> bool {
        let Some(context) = Self::file_message_context(message) else {
            let context = ViewerFileWriteContext::control(None, -1, "typed file command");
            return self.record_file_flow_failure(
                context,
                "tracked file command did not contain a recognized FileAction",
            );
        };
        match Self::enqueue_file_message(&mut self.file_writes, peer, message, context.clone())
            .await
        {
            Ok(()) => true,
            Err(err) => self.record_file_flow_failure(context, err),
        }
    }

    async fn enqueue_file_transfer_step(
        file_writes: &mut ViewerFileWriteTracker,
        read_jobs: &mut Vec<fs::TransferJob>,
        peer: &mut Stream,
        context: ViewerFileWriteContext,
    ) -> Result<(), String> {
        // Reserve before the common producer admits its one possible maximum-size session packet.
        let reservation = file_writes.reserve(context, hbb_common::cpace::MAX_SESSION_PACKET)?;
        let receipt = match fs::handle_read_jobs(read_jobs, peer).await {
            Ok((_log, Some(receipt))) => receipt,
            Ok((_log, None)) => {
                return match file_writes.cancel(reservation) {
                    Ok(Some(_)) => Ok(()),
                    Ok(None) => Err(
                        "file transfer writer reservation disappeared before cancellation"
                            .to_owned(),
                    ),
                    Err(err) => Err(err),
                };
            }
            Err(err) => {
                let cancel_result = file_writes.cancel(reservation);
                return match cancel_result {
                    Ok(_) => Err(err.to_string()),
                    Err(cancel_err) => Err(format!(
                        "file transfer producer failed: {err}; {cancel_err}"
                    )),
                };
            }
        };
        file_writes.attach(reservation, receipt)
    }

    fn record_file_flow_failure(
        &mut self,
        context: ViewerFileWriteContext,
        error: impl Into<String>,
    ) -> bool {
        let error = error.into();
        log::error!(
            "viewer {} failed before peer operation completion: {}",
            context.operation,
            error
        );
        if self.file_flow_failure.is_none() {
            self.file_flow_failure = Some((context, error));
        }
        false
    }

    fn finish_file_flow(&mut self) {
        let pending = self.file_writes.retire();
        let Some((failed, error)) = self.file_flow_failure.take() else {
            return;
        };
        let message = format!(
            "{} failed before peer operation completion: {}",
            failed.operation, error
        );
        self.handler.on_error(&message);

        let mut jobs = HashSet::new();
        if let Some(id) = failed.job_id {
            jobs.insert((id, failed.file_num));
        }
        for context in pending {
            if let Some(id) = context.job_id {
                jobs.insert((id, context.file_num));
            }
        }
        for job in &self.read_jobs {
            jobs.insert((job.id(), job.file_num()));
        }
        for job in &self.write_jobs {
            jobs.insert((job.id(), job.file_num()));
        }
        for id in self.remove_jobs.keys() {
            jobs.insert((*id, -1));
        }
        for (id, file_num) in jobs {
            self.handler.job_error(id, message.clone(), file_num);
        }
    }

    pub async fn io_loop(&mut self, key: &str, token: &str, round: u64) {
        #[cfg(not(target_os = "ios"))]
        let mut clipboard_session = self
            .handler
            .is_default()
            .then(Client::acquire_clipboard_session);

        let mut last_recv_time = Instant::now();
        let mut received = false;
        let conn_type = if self.handler.is_file_transfer() {
            ConnType::FILE_TRANSFER
        } else if self.handler.is_view_camera() {
            ConnType::VIEW_CAMERA
        } else if self.handler.is_terminal() {
            ConnType::TERMINAL
        } else {
            ConnType::default()
        };

        // Data::Close is consumed only after connection establishment. The round owner therefore
        // races Client::start against both final UI-owner retirement and explicit replacement of
        // this exact connecting round.
        let peer_id = self.handler.get_id();
        let start_result = self
            .handler
            .connection_round_owner
            .run_start(
                round,
                &self.handler.close_requested,
                &self.handler.close_notify,
                Client::start(&peer_id, key, token, conn_type, self.handler.clone()),
            )
            .await;

        match start_result {
            None => {
                log::debug!(
                    "Canceled connection start for id={} after its owner closed or its round was replaced",
                    peer_id
                );
            }
            Some(Ok((mut peer, stream_type))) => {
                if self
                    .handler
                    .connection_round_owner
                    .admit_connected(round, || self.handler.set_connection_type(stream_type))
                    .is_none()
                {
                    log::debug!(
                        "Discarded completed connection start for superseded id={} round={}",
                        peer_id,
                        round
                    );
                    self.shutdown_workers().await;
                    return;
                }

                // just build for now
                #[cfg(not(any(target_os = "windows", feature = "unix-file-copy-paste")))]
                let (_tx_holder, mut rx_clip_client) = mpsc::unbounded_channel::<i32>();

                #[cfg(any(target_os = "windows", feature = "unix-file-copy-paste"))]
                let (_tx_holder, rx) = mpsc::unbounded_channel();
                #[cfg(any(target_os = "windows", feature = "unix-file-copy-paste"))]
                let mut rx_clip_client_holder = (Arc::new(TokioMutex::new(rx)), None);
                #[cfg(any(target_os = "windows", feature = "unix-file-copy-paste"))]
                {
                    if self.handler.is_default() {
                        (self.client_conn_id, rx_clip_client_holder.0) =
                            clipboard::get_rx_cliprdr_client(&self.handler.get_id());
                        log::debug!("get cliprdr client for conn_id {}", self.client_conn_id);
                        let client_conn_id = self.client_conn_id;
                        rx_clip_client_holder.1 = Some(crate::SimpleCallOnReturn {
                            b: true,
                            f: Box::new(move || {
                                clipboard::remove_channel_by_conn_id(client_conn_id);
                            }),
                        });
                    };
                }
                #[cfg(any(target_os = "windows", feature = "unix-file-copy-paste"))]
                let mut rx_clip_client = rx_clip_client_holder.0.lock().await;

                let mut status_timer =
                    crate::rustdesk_interval(time::interval(Duration::new(1, 0)));
                let mut fps_instant = Instant::now();

                loop {
                    tokio::select! {
                        res = peer.next() => {
                            if let Some(res) = res {
                                match res {
                                    Err(err) => {
                                        self.handler.on_establish_connection_error(err.to_string());
                                        break;
                                    }
                                    Ok(ref bytes) => {
                                        last_recv_time = Instant::now();
                                        if !received {
                                            received = true;
                                            self.handler.update_received(true);
                                        }
                                        self.data_count.fetch_add(bytes.len(), Ordering::Relaxed);
                                        #[cfg(not(target_os = "ios"))]
                                        let keep_running = self
                                            .handle_msg_from_peer(
                                                bytes,
                                                &mut peer,
                                                clipboard_session.as_ref(),
                                            )
                                            .await;
                                        #[cfg(target_os = "ios")]
                                        let keep_running =
                                            self.handle_msg_from_peer(bytes, &mut peer).await;
                                        if !keep_running {
                                            break
                                        }
                                    }
                                }
                            } else {
                                if self.handler.is_restarting_remote_device() {
                                    log::info!("Restart remote device");
                                    self.handler.msgbox("restarting", "Restarting remote device", "remote_restarting_tip", "");
                                } else {
                                    log::info!("Reset by the peer");
                                    self.handler.msgbox("error", "Connection Error", "Reset by the peer", "");
                                }
                                break;
                            }
                        }
                        d = self.receiver.recv() => {
                            match d {
                                Some(Ok(d)) => {
                                    if !self.handle_msg_from_ui(d, &mut peer).await {
                                        break;
                                    }
                                }
                                Some(Err(err)) => {
                                    let err = format!("viewer command channel failed: {err}");
                                    log::error!("{err}");
                                    self.handler.on_error(&err);
                                    self.send_close_reason(&mut peer, &err).await;
                                    break;
                                }
                                None => {
                                    log::error!("viewer command channel ended without a terminal event");
                                    break;
                                }
                            }
                        }
                        completion = self.file_writes.next(), if !self.file_writes.is_empty() => {
                            let Some(completion) = completion else {
                                let context = ViewerFileWriteContext::control(
                                    None,
                                    -1,
                                    "file writer completion",
                                );
                                self.record_file_flow_failure(
                                    context,
                                    "file writer completion set ended while ownership was pending",
                                );
                                break;
                            };
                            if let Err(err) = completion.result {
                                let context = completion.context.unwrap_or_else(|| {
                                    ViewerFileWriteContext::control(
                                        None,
                                        -1,
                                        "file writer completion",
                                    )
                                });
                                self.record_file_flow_failure(context, err);
                                break;
                            }
                        }
                        refresh = self.video_refresh.recv() => {
                            let Some(refresh) = refresh else {
                                log::error!("viewer video refresh mailbox closed before its network round");
                                break;
                            };
                            if !self.handle_video_refresh(refresh, &mut peer).await {
                                break;
                            }
                        }
                        voice_call_audio = recv_voice_call_audio(&mut self.voice_call_audio) => {
                            let Some(message) = voice_call_audio else {
                                self.stop_voice_call().await;
                                self.handler.on_voice_call_closed(
                                    "Voice call audio service stopped",
                                );
                                continue;
                            };
                            if let Err(err) = peer.send(&message as &Message).await {
                                log::error!("Failed to send voice call audio to peer: {err}");
                                break;
                            }
                        }
                        _msg = rx_clip_client.recv() => {
                            #[cfg(any(target_os = "windows", feature = "unix-file-copy-paste"))]
                            self.handle_local_clipboard_msg(&mut peer, _msg).await;
                        }
                        _ = self.timer.tick(), if !self.file_writes.has_transfer_data() => {
                            if last_recv_time.elapsed() >= SEC30 {
                                self.handler.msgbox("error", "Connection Error", "Timeout", "");
                                break;
                            }
                            if !self.read_jobs.is_empty() {
                                let context = self
                                    .read_jobs
                                    .iter()
                                    .find(|job| !job.is_last_job)
                                    .or_else(|| self.read_jobs.first())
                                    .map(|job| {
                                        ViewerFileWriteContext::transfer_data(
                                            Some(job.id()),
                                            job.file_num(),
                                        )
                                    })
                                    .unwrap_or_else(|| {
                                        ViewerFileWriteContext::transfer_data(None, -1)
                                    });
                                match Self::enqueue_file_transfer_step(
                                    &mut self.file_writes,
                                    &mut self.read_jobs,
                                    &mut peer,
                                    context.clone(),
                                )
                                .await
                                {
                                    Ok(()) => {}
                                    Err(err) => {
                                        self.record_file_flow_failure(context, err);
                                        break;
                                    }
                                }
                                self.update_jobs_status();
                            } else {
                                self.timer = crate::rustdesk_interval(time::interval_at(Instant::now() + SEC30, SEC30));
                            }
                        }
                        _ = status_timer.tick() => {
                            let elapsed = fps_instant.elapsed().as_millis();
                            if elapsed < 1000 {
                                continue;
                            }
                            fps_instant = Instant::now();
                            let mut speed = self.data_count.swap(0, Ordering::Relaxed);
                            speed = speed * 1000 / elapsed as usize;
                            let speed = format!("{:.2}kB/s", speed as f32 / 1024 as f32);

                            let fps = self.video_threads.iter().map(|(k, v)| {
                                // Correcting the inaccuracy of status_timer
                                (k.clone(), (*v.frame_count.read().unwrap() as i32) * 1000 / elapsed as i32)
                            }).collect::<HashMap<usize, i32>>();
                            self.video_threads.iter().for_each(|(_, v)| {
                                *v.frame_count.write().unwrap() = 0;
                            });
                            if !self.fps_control(fps.clone()) {
                                break;
                            }
                            let chroma = self.chroma.read().unwrap().clone();
                            let chroma = match chroma {
                                Some(Chroma::I444) => "4:4:4",
                                Some(Chroma::I420) => "4:2:0",
                                None => "-",
                            };
                            let chroma = Some(chroma.to_string());
                            let codec_format = if self.video_format == CodecFormat::Unknown {
                                None
                            } else {
                                Some(self.video_format.clone())
                            };
                            self.handler.update_quality_status(QualityStatus {
                                speed: Some(speed),
                                fps,
                                chroma,
                                codec_format,
                                ..Default::default()
                            });
                        }
                    }
                }
                log::debug!("Exit io_loop of id={}", self.handler.get_id());
            }
            Some(Err(err)) => {
                let _ = self.handler.connection_round_owner.with_current(round, || {
                    self.handler.on_establish_connection_error(err.to_string())
                });
            }
        }
        self.finish_file_flow();
        self.shutdown_workers().await;
        // set_disconnected_ok is used to check if new connection round is started.
        let _set_disconnected_ok = self.handler.connection_round_owner.finish(round);

        #[cfg(not(target_os = "ios"))]
        drop(clipboard_session.take());

        #[cfg(any(target_os = "windows", feature = "unix-file-copy-paste"))]
        if self.handler.is_default() && _set_disconnected_ok {
            crate::clipboard::try_empty_clipboard_files(ClipboardSide::Client, self.client_conn_id);
        }
    }

    #[cfg(any(target_os = "windows", feature = "unix-file-copy-paste"))]
    async fn handle_local_clipboard_msg(
        &self,
        peer: &mut Stream,
        msg: Option<clipboard::ClipboardFile>,
    ) {
        match msg {
            Some(clip) => match clip {
                clipboard::ClipboardFile::NotifyCallback {
                    r#type,
                    title,
                    text,
                } => {
                    self.handler.msgbox(&r#type, &title, &text, "");
                }
                _ => {
                    let is_stopping_allowed = clip.is_stopping_allowed();
                    let server_file_transfer_enabled =
                        *self.handler.server_file_transfer_enabled.read().unwrap();
                    let file_transfer_enabled =
                        self.handler.lc.read().unwrap().enable_file_copy_paste.v;
                    let view_only = self.handler.lc.read().unwrap().view_only.v;
                    let stop = is_stopping_allowed
                        && (view_only
                            || !self.is_connected
                            || !(server_file_transfer_enabled && file_transfer_enabled));
                    log::debug!(
                        "Process clipboard message from system, stop: {}, is_stopping_allowed: {}, view_only: {}, server_file_transfer_enabled: {}, file_transfer_enabled: {}",
                        view_only, stop, is_stopping_allowed, server_file_transfer_enabled, file_transfer_enabled
                    );
                    if stop {
                        #[cfg(target_os = "windows")]
                        {
                            ContextSend::set_is_stopped();
                        }
                    } else {
                        #[cfg(target_os = "windows")]
                        if let Err(e) = ContextSend::make_sure_enabled() {
                            log::error!("failed to restart clipboard context: {}", e);
                            // to-do: Show msgbox with "Don't show again" option
                        };
                        log::debug!("Send system clipboard message to remote");
                        let msg = crate::clipboard_file::clip_2_msg(clip);
                        allow_err!(peer.send(&msg).await);
                    }
                }
            },
            None => {
                // unreachable!()
            }
        }
    }

    fn handle_job_status(&mut self, id: i32, file_num: i32, err: Option<String>) {
        if let Some(job) = self.remove_jobs.get_mut(&id) {
            if job.no_confirm {
                let file_num = (file_num + 1) as usize;
                if file_num < job.files.len() {
                    let path = format!("{}{}{}", job.path, job.sep, job.files[file_num].name);
                    if let Err(err) = self.sender.send(Data::RemoveFile((
                        id,
                        path,
                        file_num as i32,
                        job.is_remote,
                    ))) {
                        self.handler.job_error(
                            id,
                            format!("failed to continue delete operation: {err}"),
                            file_num as i32,
                        );
                        self.remove_jobs.remove(&id);
                        return;
                    }
                    let elapsed = job.last_update_job_status.elapsed().as_millis() as i32;
                    if elapsed >= 1000 {
                        job.last_update_job_status = Instant::now();
                    } else {
                        return;
                    }
                } else {
                    self.remove_jobs.remove(&id);
                }
            }
        }
        if let Some(err) = err {
            self.handler.job_error(id, err, file_num);
        } else {
            self.handler.job_done(id, file_num);
        }
    }

    async fn join_workers(workers: Vec<(&'static str, std::thread::JoinHandle<()>)>) {
        crate::client::join_media_workers_off_runtime(workers).await;
    }

    async fn stop_voice_call(&mut self) {
        let Some(mut voice_call_audio) = self.voice_call_audio.take() else {
            return;
        };
        voice_call_audio.stop();
    }

    async fn shutdown_workers(&mut self) {
        self.input_os_password_task.stop_and_join().await;
        let mut workers = Vec::with_capacity(self.video_threads.len() + 1);
        if let Some(mut voice_call_audio) = self.voice_call_audio.take() {
            voice_call_audio.stop();
        }
        for (_, mut video_thread) in self.video_threads.drain() {
            if let Some(worker) = video_thread.media_thread.close() {
                workers.push(worker);
            }
        }
        if let Some(worker) = self.audio_thread.close() {
            workers.push(worker);
        }
        Self::join_workers(workers).await;
    }

    // Start a voice call recorder, records audio and send to remote
    fn start_voice_call(&mut self) -> Option<VoiceCallAudio> {
        if self.handler.is_file_transfer()
            || self.handler.is_port_forward()
            || self.handler.is_terminal()
        {
            return None;
        }
        // iOS does not have this server.
        #[cfg(not(any(target_os = "ios")))]
        {
            let input_lease =
                match crate::audio_service::acquire_voice_call_input(get_default_sound_input()) {
                    Ok(input_lease) => input_lease,
                    Err(err) => {
                        log::error!("Failed to acquire voice-call input: {err}");
                        return None;
                    }
                };
            let (tx_audio_data, rx_audio_data) = audio_egress_channel();
            // Create a stand-alone inner, add subscribe to audio service
            let conn_id = CLIENT_SERVER.write().unwrap().get_new_id();
            let client_conn_inner = ConnInner::with_audio(conn_id, None, None, Some(tx_audio_data));
            // now we subscribe
            CLIENT_SERVER.write().unwrap().subscribe(
                audio_service::NAME,
                client_conn_inner.clone(),
                true,
            );
            return Some(VoiceCallAudio::new(
                client_conn_inner,
                input_lease,
                rx_audio_data,
            ));
        }
        #[cfg(target_os = "ios")]
        {
            None
        }
    }

    async fn send_close_reason(&mut self, peer: &mut Stream, reason: &str) {
        if self.sent_close_reason {
            return;
        }
        let mut misc = Misc::new();
        misc.set_close_reason(reason.to_owned());
        let mut msg = Message::new();
        msg.set_misc(misc);
        allow_err!(peer.send(&msg).await);
        self.sent_close_reason = true;
    }

    async fn handle_video_refresh(
        &mut self,
        request: ViewerVideoRefreshRequest,
        peer: &mut Stream,
    ) -> bool {
        let message = match request {
            ViewerVideoRefreshRequest::All => {
                self.video_threads.iter().for_each(|(_, thread)| {
                    thread.media_thread.begin_refresh();
                });
                LoginConfigHandler::refresh()
            }
            ViewerVideoRefreshRequest::Display(display) => {
                if let Some(thread) = self.video_threads.get(&display) {
                    thread.media_thread.begin_refresh();
                }
                LoginConfigHandler::refresh_display(display)
            }
        };
        match peer.send(&message).await {
            Ok(()) => true,
            Err(err) => {
                log::error!("failed to send viewer video refresh: {err}");
                false
            }
        }
    }

    async fn handle_msg_from_ui(&mut self, data: Data, peer: &mut Stream) -> bool {
        match data {
            Data::Close => {
                self.send_close_reason(peer, "").await;
                return false;
            }
            Data::Login((password, remember)) => {
                self.handler
                    .handle_login_from_ui(password, remember, peer)
                    .await;
            }
            Data::InputOsPassword { password, activate } => {
                let sequence =
                    client::prepare_input_os_password_sequence(password, activate, &self.handler);
                let sender = self.sender.clone();
                self.input_os_password_task
                    .replace(client::run_input_os_password_sequence(sequence, sender))
                    .await;
            }
            #[cfg(all(target_os = "windows", not(feature = "flutter")))]
            Data::ToggleClipboardFile => {
                self.check_clipboard_file_context();
            }
            Data::Message(msg) => {
                if is_video_refresh_message(&msg) {
                    log::error!("refusing viewer video refresh on the generic command queue");
                    return false;
                }
                if matches!(msg.union.as_ref(), Some(message::Union::FileAction(_))) {
                    let context =
                        ViewerFileWriteContext::control(None, -1, "generic-queue file command");
                    return self.record_file_flow_failure(
                        context,
                        "file action bypassed the tracked file command path",
                    );
                }
                match peer.send(&msg).await {
                    Ok(()) => self.record_pending_privacy_mode_request(&msg),
                    Err(err) => {
                        log::error!("failed to send viewer command to peer: {err}");
                        return false;
                    }
                }
            }
            Data::FileMessage(msg) => {
                if !self.send_tracked_file_action(peer, &msg).await {
                    return false;
                }
            }
            Data::SendFiles((id, r#type, path, to, file_num, include_hidden, is_remote)) => {
                log::info!("send files, is remote {}", is_remote);
                let od = can_enable_overwrite_detection(self.handler.lc.read().unwrap().version);
                if is_remote {
                    log::debug!("New job {}, write to {} from remote {}", id, to, path);
                    let to = fs::DataSource::FilePath(PathBuf::from(&to));
                    let job = fs::TransferJob::new_write(
                        id,
                        r#type,
                        path.clone(),
                        to,
                        file_num,
                        include_hidden,
                        is_remote,
                        od,
                    );
                    let message = fs::new_send(id, r#type, path, file_num, include_hidden);
                    if !self.send_tracked_file_action(peer, &message).await {
                        return false;
                    }
                    self.write_jobs.push(job);
                } else {
                    match fs::TransferJob::new_read(
                        id,
                        r#type,
                        to.clone(),
                        fs::DataSource::FilePath(PathBuf::from(&path)),
                        file_num,
                        include_hidden,
                        is_remote,
                        od,
                    ) {
                        Err(err) => {
                            self.handle_job_status(id, -1, Some(err.to_string()));
                        }
                        Ok(job) => {
                            log::debug!(
                                "New job {}, read {} to remote {}, {} files",
                                id,
                                path,
                                to,
                                job.files().len()
                            );
                            self.handler.update_folder_files(
                                job.id(),
                                job.files(),
                                path,
                                !is_remote,
                                true,
                            );
                            #[cfg(not(windows))]
                            let files = job.files().clone();
                            #[cfg(windows)]
                            let mut files = job.files().clone();
                            #[cfg(windows)]
                            if self.handler.peer_platform() != "Windows" {
                                // peer is not windows, need transform \ to /
                                fs::transform_windows_path(&mut files);
                            }
                            let total_size = job.total_size();
                            let message = fs::new_receive(id, to, file_num, files, total_size);
                            if !self.send_tracked_file_action(peer, &message).await {
                                return false;
                            }
                            self.read_jobs.push(job);
                            self.timer = crate::rustdesk_interval(time::interval(MILLI1));
                        }
                    }
                }
            }
            Data::AddJob((id, r#type, path, to, file_num, include_hidden, is_remote)) => {
                let od = can_enable_overwrite_detection(self.handler.lc.read().unwrap().version);
                if is_remote {
                    log::debug!(
                        "new write waiting job {}, write to {} from remote {}",
                        id,
                        to,
                        path
                    );
                    let mut job = fs::TransferJob::new_write(
                        id,
                        r#type,
                        path.clone(),
                        fs::DataSource::FilePath(PathBuf::from(&to)),
                        file_num,
                        include_hidden,
                        is_remote,
                        od,
                    );
                    job.is_last_job = true;
                    self.write_jobs.push(job);
                } else {
                    match fs::TransferJob::new_read(
                        id,
                        r#type,
                        to.clone(),
                        fs::DataSource::FilePath(PathBuf::from(&path)),
                        file_num,
                        include_hidden,
                        is_remote,
                        od,
                    ) {
                        Err(err) => {
                            self.handle_job_status(id, -1, Some(err.to_string()));
                        }
                        Ok(mut job) => {
                            log::debug!(
                                "new read waiting job {}, read {} to remote {}, {} files",
                                id,
                                path,
                                to,
                                job.files().len()
                            );
                            self.handler.update_folder_files(
                                job.id(),
                                job.files(),
                                path,
                                !is_remote,
                                true,
                            );
                            job.is_last_job = true;
                            self.read_jobs.push(job);
                            self.timer = crate::rustdesk_interval(time::interval(MILLI1));
                        }
                    }
                }
            }
            Data::ResumeJob((id, is_remote)) => {
                if is_remote {
                    if let Some(job) = get_job(id, &mut self.write_jobs) {
                        job.is_last_job = false;
                        job.is_resume = true;
                        let file_num = job.file_num;
                        let message = fs::new_send(
                            id,
                            fs::JobType::Generic,
                            job.remote.clone(),
                            file_num,
                            job.show_hidden,
                        );
                        if !self.send_tracked_file_action(peer, &message).await {
                            return false;
                        }
                    }
                } else {
                    if let Some(job) = get_job(id, &mut self.read_jobs) {
                        match &job.data_source {
                            fs::DataSource::FilePath(_p) => {
                                job.is_last_job = false;
                                job.is_resume = true;
                                job.set_finished_size_on_resume();
                                #[cfg(not(windows))]
                                let files = job.files().clone();
                                #[cfg(windows)]
                                let mut files = job.files().clone();
                                #[cfg(windows)]
                                if self.handler.peer_platform() != "Windows" {
                                    // peer is not windows, need transform \ to /
                                    fs::transform_windows_path(&mut files);
                                }
                                let file_num = job.file_num;
                                let message = fs::new_receive(
                                    id,
                                    job.remote.clone(),
                                    file_num,
                                    files,
                                    job.total_size(),
                                );
                                if !self.send_tracked_file_action(peer, &message).await {
                                    return false;
                                }
                            }
                            fs::DataSource::MemoryCursor(_) => {
                                // unreachable!()
                                log::error!("Resume job with memory cursor");
                            }
                        }
                    }
                }
            }
            Data::SetNoConfirm(id) => {
                if let Some(job) = self.remove_jobs.get_mut(&id) {
                    job.no_confirm = true;
                }
            }
            Data::ConfirmDeleteFiles((id, file_num)) => {
                if let Some(job) = self.remove_jobs.get_mut(&id) {
                    let i = file_num as usize;
                    if i < job.files.len() {
                        self.handler.ui_handler.confirm_delete_files(
                            id,
                            file_num,
                            job.files[i].name.clone(),
                        );
                    }
                }
            }
            Data::SetConfirmOverrideFile((id, file_num, need_override, remember, is_upload)) => {
                if is_upload {
                    if let Some(job) = fs::get_job(id, &mut self.read_jobs) {
                        if remember {
                            job.set_overwrite_strategy(Some(need_override));
                        }
                        job.confirm(&FileTransferSendConfirmRequest {
                            id,
                            file_num,
                            union: if need_override {
                                Some(file_transfer_send_confirm_request::Union::OffsetBlk(0))
                            } else {
                                Some(file_transfer_send_confirm_request::Union::Skip(true))
                            },
                            ..Default::default()
                        })
                        .await;
                    }
                } else {
                    if let Some(job) = fs::get_job(id, &mut self.write_jobs) {
                        if remember {
                            job.set_overwrite_strategy(Some(need_override));
                        }
                        let mut msg = Message::new();
                        let mut file_action = FileAction::new();
                        let req = FileTransferSendConfirmRequest {
                            id,
                            file_num,
                            union: if need_override {
                                Some(file_transfer_send_confirm_request::Union::OffsetBlk(0))
                            } else {
                                Some(file_transfer_send_confirm_request::Union::Skip(true))
                            },
                            ..Default::default()
                        };
                        job.confirm(&req).await;
                        file_action.set_send_confirm(req);
                        msg.set_file_action(file_action);
                        if !self.send_tracked_file_action(peer, &msg).await {
                            return false;
                        }
                    }
                }
            }
            Data::RemoveDirAll((id, path, is_remote, include_hidden)) => {
                let sep = self.handler.get_path_sep(is_remote);
                if is_remote {
                    let mut msg_out = Message::new();
                    let mut file_action = FileAction::new();
                    file_action.set_all_files(ReadAllFiles {
                        id,
                        path: path.clone(),
                        include_hidden,
                        ..Default::default()
                    });
                    msg_out.set_file_action(file_action);
                    if !self.send_tracked_file_action(peer, &msg_out).await {
                        return false;
                    }
                    self.remove_jobs
                        .insert(id, RemoveJob::new(Vec::new(), path, sep, is_remote));
                } else {
                    match fs::get_recursive_files(&path, include_hidden) {
                        Ok(entries) => {
                            self.handler.update_folder_files(
                                id,
                                &entries,
                                path.clone(),
                                !is_remote,
                                false,
                            );
                            self.remove_jobs
                                .insert(id, RemoveJob::new(entries, path, sep, is_remote));
                        }
                        Err(err) => {
                            self.handle_job_status(id, -1, Some(err.to_string()));
                        }
                    }
                }
            }
            Data::CancelJob(id) => {
                if !self.cancel_transfer_job(id, peer).await {
                    return false;
                }
            }
            Data::RemoveDir((id, path)) => {
                let mut msg_out = Message::new();
                let mut file_action = FileAction::new();
                file_action.set_remove_dir(FileRemoveDir {
                    id,
                    path,
                    recursive: true,
                    ..Default::default()
                });
                msg_out.set_file_action(file_action);
                if !self.send_tracked_file_action(peer, &msg_out).await {
                    return false;
                }
            }
            Data::RemoveFile((id, path, file_num, is_remote)) => {
                if is_remote {
                    let mut msg_out = Message::new();
                    let mut file_action = FileAction::new();
                    file_action.set_remove_file(FileRemoveFile {
                        id,
                        path,
                        file_num,
                        ..Default::default()
                    });
                    msg_out.set_file_action(file_action);
                    if !self.send_tracked_file_action(peer, &msg_out).await {
                        return false;
                    }
                } else {
                    match fs::remove_file(&path) {
                        Err(err) => {
                            self.handle_job_status(id, file_num, Some(err.to_string()));
                        }
                        Ok(()) => {
                            self.handle_job_status(id, file_num, None);
                        }
                    }
                }
            }
            Data::CreateDir((id, path, is_remote)) => {
                if is_remote {
                    let mut msg_out = Message::new();
                    let mut file_action = FileAction::new();
                    file_action.set_create(FileDirCreate {
                        id,
                        path,
                        ..Default::default()
                    });
                    msg_out.set_file_action(file_action);
                    if !self.send_tracked_file_action(peer, &msg_out).await {
                        return false;
                    }
                } else {
                    match fs::create_dir(&path) {
                        Err(err) => {
                            self.handle_job_status(id, -1, Some(err.to_string()));
                        }
                        Ok(()) => {
                            self.handle_job_status(id, -1, None);
                        }
                    }
                }
            }
            Data::RenameFile((id, path, new_name, is_remote)) => {
                if is_remote {
                    let mut msg_out = Message::new();
                    let mut file_action = FileAction::new();
                    file_action.set_rename(FileRename {
                        id,
                        path,
                        new_name,
                        ..Default::default()
                    });
                    msg_out.set_file_action(file_action);
                    if !self.send_tracked_file_action(peer, &msg_out).await {
                        return false;
                    }
                } else {
                    let err = fs::rename_file(&path, &new_name)
                        .err()
                        .map(|e| e.to_string());
                    self.handle_job_status(id, -1, err);
                }
            }
            Data::RecordScreen(start) => {
                self.handler.lc.write().unwrap().record_state = start;
                self.update_record_state();
            }
            Data::NewVoiceCall => {
                let msg = new_voice_call_request(true);
                // Save the voice call request timestamp for the further validation.
                self.voice_call_request_timestamp = Some(
                    NonZeroI64::new(msg.voice_call_request().req_timestamp)
                        .unwrap_or(NonZeroI64::new(get_time()).unwrap()),
                );
                allow_err!(peer.send(&msg).await);
                self.handler.on_voice_call_waiting();
            }
            Data::CloseVoiceCall => {
                self.stop_voice_call().await;
                let msg = new_voice_call_request(false);
                self.handler
                    .on_voice_call_closed("Closed manually by the peer");
                allow_err!(peer.send(&msg).await);
            }
            Data::ResetDecoder(display) => match display {
                Some(display) => {
                    if let Some(v) = self.video_threads.get_mut(&display) {
                        if let Err(err) = v.media_thread.try_send_control(VideoControl::Reset) {
                            log::warn!("viewer video decode queue full; dropping reset: {err}");
                        }
                    }
                }
                None => {
                    for (_, v) in self.video_threads.iter_mut() {
                        if let Err(err) = v.media_thread.try_send_control(VideoControl::Reset) {
                            log::warn!("viewer video decode queue full; dropping reset: {err}");
                        }
                    }
                }
            },
            Data::TakeScreenshot((display, sid)) => {
                // A UI session owns at most one current request. Retiring its prior wire ID makes a
                // late peer response stale before a new response can replace the exact-session
                // cache or wake an old dialog.
                let request_id = match self.pending_screenshot_requests.replace(sid.clone()) {
                    Ok(request_id) => request_id,
                    Err(ScreenshotRequestAdmissionError::Capacity) => {
                        log::warn!(
                            "dropping screenshot request; {} responses already pending",
                            self.pending_screenshot_requests.len()
                        );
                        self.handler.handle_screenshot_resp(
                            sid,
                            String::new(),
                            None,
                            "Too many pending screenshot requests".to_owned(),
                        );
                        return true;
                    }
                    Err(ScreenshotRequestAdmissionError::SequenceExhausted) => {
                        self.handler.handle_screenshot_resp(
                            sid,
                            String::new(),
                            None,
                            "Screenshot request sequence exhausted".to_owned(),
                        );
                        return true;
                    }
                };
                let mut msg = Message::new();
                msg.set_screenshot_request(ScreenshotRequest {
                    display,
                    sid: request_id.clone(),
                    ..Default::default()
                });
                if let Err(err) = peer.send(&msg).await {
                    log::warn!("failed to send screenshot request: {err}");
                    self.pending_screenshot_requests.complete(&request_id);
                    self.handler.handle_screenshot_resp(
                        sid,
                        request_id,
                        None,
                        "Failed to send screenshot request".to_owned(),
                    );
                }
            }
            _ => {}
        }
        true
    }

    #[inline]
    fn update_job_status(
        job: &fs::TransferJob,
        elapsed: i32,
        last_update_jobs_status: &mut (Instant, HashMap<i32, u64>),
        handler: &Session<T>,
    ) {
        if elapsed <= 0 {
            return;
        }
        let transferred = job.transferred();
        let last_transferred = {
            if let Some(v) = last_update_jobs_status.1.get(&job.id()) {
                v.to_owned()
            } else {
                0
            }
        };
        last_update_jobs_status.1.insert(job.id(), transferred);
        let speed = (transferred - last_transferred) as f64 / (elapsed as f64 / 1000.);
        let file_num = job.file_num() - 1;
        handler.job_progress(job.id(), file_num, speed, job.finished_size() as f64);
    }

    fn update_jobs_status(&mut self) {
        let elapsed = self.last_update_jobs_status.0.elapsed().as_millis() as i32;
        if elapsed >= 1000 {
            for job in self.read_jobs.iter() {
                Self::update_job_status(
                    job,
                    elapsed,
                    &mut self.last_update_jobs_status,
                    &self.handler,
                );
            }
            for job in self.write_jobs.iter() {
                Self::update_job_status(
                    job,
                    elapsed,
                    &mut self.last_update_jobs_status,
                    &mut self.handler,
                );
            }
            self.last_update_jobs_status.0 = Instant::now();
        }
    }

    async fn cancel_transfer_job(&mut self, id: i32, peer: &mut Stream) -> bool {
        let mut msg_out = Message::new();
        let mut file_action = FileAction::new();
        file_action.set_cancel(FileTransferCancel {
            id,
            ..Default::default()
        });
        msg_out.set_file_action(file_action);
        let sent = self.send_tracked_file_action(peer, &msg_out).await;
        if let Some(mut job) = fs::remove_job(id, &mut self.write_jobs) {
            job.remove_download_file();
        }
        let _ = fs::remove_job(id, &mut self.read_jobs);
        self.remove_jobs.remove(&id);
        sent
    }

    pub async fn sync_jobs_status_to_local(&mut self) -> bool {
        if !self.is_connected {
            return false;
        }
        let mut config: PeerConfig = self.handler.load_config();
        let mut transfer_metas = TransferSerde::default();
        for job in self.read_jobs.iter() {
            let json_str = serde_json::to_string(&job.gen_meta()).unwrap_or_default();
            transfer_metas.read_jobs.push(json_str);
        }
        for job in self.write_jobs.iter() {
            let json_str = serde_json::to_string(&job.gen_meta()).unwrap_or_default();
            transfer_metas.write_jobs.push(json_str);
        }
        log::info!("meta: {:?}", transfer_metas);
        if config.transfer != transfer_metas {
            config.transfer = transfer_metas;
            self.handler.save_config(config);
        }
        true
    }

    async fn send_toggle_virtual_display_msg(&self, peer: &mut Stream) {
        if !self.peer_info.is_support_virtual_display() {
            return;
        }
        let lc = self.handler.lc.read().unwrap();
        let displays = lc.get_option("virtual-display");
        for d in displays.split(',') {
            if let Ok(index) = d.parse::<i32>() {
                let mut misc = Misc::new();
                misc.set_toggle_virtual_display(ToggleVirtualDisplay {
                    display: index,
                    on: true,
                    ..Default::default()
                });
                let mut msg_out = Message::new();
                msg_out.set_misc(misc);
                allow_err!(peer.send(&msg_out).await);
            }
        }
    }

    async fn send_toggle_privacy_mode_msg(&mut self, peer: &mut Stream) {
        let impl_key = {
            let lc = self.handler.lc.read().unwrap();
            if lc.version < hbb_common::get_version_number("1.2.4")
                || !lc.get_toggle_option("privacy-mode")
            {
                return;
            }
            lc.get_option("privacy-mode-impl-key")
        };
        if impl_key == crate::privacy_mode::PRIVACY_MODE_IMPL_WIN_VIRTUAL_DISPLAY
            && !self.peer_info.is_support_virtual_display()
        {
            return;
        }
        let mut misc = Misc::new();
        misc.set_toggle_privacy_mode(TogglePrivacyMode {
            impl_key,
            on: true,
            ..Default::default()
        });
        let mut msg_out = Message::new();
        msg_out.set_misc(misc);
        match peer.send(&msg_out).await {
            Ok(()) => self.record_pending_privacy_mode_request(&msg_out),
            Err(err) => log::error!("Failed to send privacy-mode request: {}", err),
        }
    }

    fn record_pending_privacy_mode_request(&mut self, msg: &Message) {
        if let Some(request) =
            PendingPrivacyModeRequest::from_message(msg, self.handler.is_default())
        {
            self.pending_privacy_mode_request = Some(request);
        }
    }

    fn privacy_mode_response_admission(
        &mut self,
        state: back_notification::PrivacyModeState,
        impl_key: &str,
    ) -> PrivacyModeResponseAdmission {
        let now = Instant::now();
        if self
            .pending_privacy_mode_request
            .as_ref()
            .map_or(false, |request| request.is_expired(now))
        {
            self.pending_privacy_mode_request = None;
        }
        let Some(request) = self.pending_privacy_mode_request.as_ref() else {
            return PrivacyModeResponseAdmission::Ignore;
        };
        let admission = request.classify_response(state, impl_key, now);
        if !matches!(admission, PrivacyModeResponseAdmission::Ignore) {
            self.pending_privacy_mode_request = None;
        }
        admission
    }

    fn native_video_frame_within_limit(vf: &VideoFrame) -> bool {
        use video_frame::Union::*;
        let result = match &vf.union {
            Some(Vp8s(f)) => scrap::codec::validate_native_video_frames("vp8", f),
            Some(Vp9s(f)) => scrap::codec::validate_native_video_frames("vp9", f),
            Some(Av1s(f)) => scrap::codec::validate_native_video_frames("av1", f),
            Some(H264s(f)) => scrap::codec::validate_native_video_frames("h264", f),
            Some(H265s(f)) => scrap::codec::validate_native_video_frames("h265", f),
            _ => Ok(()),
        };
        if let Err(err) = result {
            log::warn!("dropping oversized video frame before decode queue: {err}");
            false
        } else {
            true
        }
    }

    // Currently, this function only considers decoding speed and queue length, not network delay.
    // The controlled end can consider auto fps as the maximum decoding fps.
    #[inline]
    fn fps_control(&mut self, real_fps_map: HashMap<usize, i32>) -> bool {
        self.video_threads.iter_mut().for_each(|(k, v)| {
            let real_fps = real_fps_map.get(k).cloned().unwrap_or_default();
            if real_fps == 0 {
                v.fps_control.inactive_counter += 1;
            } else {
                v.fps_control.inactive_counter = 0;
            }
        });
        let custom_fps = self.handler.lc.read().unwrap().custom_fps.clone();
        let custom_fps = custom_fps.lock().unwrap().clone();
        let mut custom_fps = custom_fps.unwrap_or(30);
        if custom_fps < 5 || custom_fps > 120 {
            custom_fps = 30;
        }
        let inactive_threshold = 15;
        let max_queue_len = self
            .video_threads
            .iter()
            .map(|v| v.1.media_thread.pending_frames())
            .max()
            .unwrap_or_default();
        let min_decode_fps = self
            .video_threads
            .iter()
            .filter(|v| v.1.fps_control.inactive_counter < inactive_threshold)
            .map(|v| *v.1.decode_fps.read().unwrap())
            .min()
            .flatten();
        let Some(min_decode_fps) = min_decode_fps else {
            return true;
        };
        let mut limited_fps = min_decode_fps * 9 / 10; // 30 got 27
        if limited_fps > custom_fps {
            limited_fps = custom_fps;
        }
        let last_auto_fps = self.handler.lc.read().unwrap().last_auto_fps.clone();
        let displays = self.video_threads.keys().cloned().collect::<Vec<_>>();
        let mut fps_trending = |display: usize| {
            let thread = self.video_threads.get_mut(&display)?;
            let ctl = &mut thread.fps_control;
            let len = thread.media_thread.pending_frames();
            let decode_fps = thread.decode_fps.read().unwrap().clone()?;
            let last_auto_fps = last_auto_fps.clone().unwrap_or(custom_fps as _);
            if ctl.inactive_counter > inactive_threshold {
                return None;
            }
            if len > 1 && last_auto_fps > limited_fps || len > std::cmp::max(1, decode_fps / 2) {
                ctl.idle_counter = 0;
                return Some(false);
            }
            if len <= 1 {
                ctl.idle_counter += 1;
                if ctl.idle_counter > 3 && last_auto_fps + 3 <= limited_fps {
                    return Some(true);
                }
            }
            if len > 1 {
                ctl.idle_counter = 0;
            }
            None
        };
        let trendings: Vec<_> = displays.iter().map(|k| fps_trending(*k)).collect();
        let should_decrease = trendings.iter().any(|v| *v == Some(false));
        let should_increase = !should_decrease && trendings.iter().any(|v| *v == Some(true));
        if last_auto_fps.is_none() || should_decrease || should_increase {
            // limited_fps to ensure decoding is faster than encoding
            let mut auto_fps = limited_fps;
            if should_decrease && limited_fps < max_queue_len {
                auto_fps = limited_fps / 2;
            }
            if auto_fps < 1 {
                auto_fps = 1;
            }
            if Some(auto_fps) != last_auto_fps {
                let mut misc = Misc::new();
                misc.set_option(OptionMessage {
                    custom_fps: auto_fps as _,
                    ..Default::default()
                });
                let mut msg = Message::new();
                msg.set_misc(misc);
                if let Err(err) = self.sender.send(Data::Message(msg)) {
                    log::error!("failed to admit automatic FPS update: {err}");
                    return false;
                }
                log::info!("Set fps to {}", auto_fps);
                self.handler.lc.write().unwrap().last_auto_fps = Some(auto_fps);
            }
        }
        // A real-time frame backlog must not remain delayed merely because the producer and
        // decoder later run at the same rate. Supersede the obsolete GOP immediately; the
        // mailbox admits no further deltas until the requested keyframe arrives.
        for (display, thread) in self.video_threads.iter_mut() {
            let tolerable = std::cmp::min(min_decode_fps, client::VIDEO_FRAME_QUEUE_CAPACITY / 2);
            if thread.media_thread.pending_frames() > tolerable
                && thread.media_thread.begin_refresh()
            {
                if let Err(err) = self.handler.refresh_video(*display as _) {
                    log::error!(
                        "failed to admit viewer backlog refresh for display {display}: {err}"
                    );
                    return false;
                }
                log::info!("Refresh display {} to supersede queued video", display);
            }
        }
        true
    }

    fn check_view_camera_support(&self, peer_version: &str, peer_platform: &str) -> bool {
        if self.peer_info.support_view_camera {
            return true;
        }
        if hbb_common::get_version_number(&peer_version) < hbb_common::get_version_number("1.3.9")
            && (peer_platform == "Windows" || peer_platform == "Linux")
        {
            self.handler.msgbox(
                "error",
                "Download new version",
                "upgrade_remote_rustdesk_client_to_{1.3.9}_tip",
                "",
            );
        } else {
            self.handler.on_error("view_camera_unsupported_tip");
        }
        return false;
    }

    fn check_terminal_support(&self, peer_version: &str) -> bool {
        if self.peer_info.support_terminal {
            return true;
        }
        if hbb_common::get_version_number(&peer_version) < hbb_common::get_version_number("1.4.1") {
            self.handler.msgbox(
                "error",
                "Remote terminal not supported",
                "Remote terminal is not supported by the remote side. Please upgrade to version 1.4.1 or higher.",
                "",
            );
        } else {
            self.handler
                .on_error("Remote terminal is not supported by the remote side");
        }
        return false;
    }

    fn terminal_response_allowed(&self) -> bool {
        self.handler.is_terminal()
            && config::option2bool(
                config::keys::OPTION_ENABLE_TERMINAL,
                &Config::get_option(config::keys::OPTION_ENABLE_TERMINAL),
            )
    }

    async fn handle_msg_from_peer(
        &mut self,
        data: &[u8],
        peer: &mut Stream,
        #[cfg(not(target_os = "ios"))] clipboard_session: Option<&ClientClipboardSession>,
    ) -> bool {
        let msg_in = match Message::parse_from_bytes(data) {
            Ok(msg) => msg,
            Err(err) => {
                log::warn!("Malformed post-key Message frame from peer: {err}");
                self.handler
                    .on_error("Malformed encrypted message from peer");
                return false;
            }
        };
        {
            match msg_in.union {
                Some(message::Union::VideoFrame(vf)) => {
                    if !native_video_frame_runtime_supported(&vf) {
                        return true;
                    }
                    if !Self::native_video_frame_within_limit(&vf) {
                        return true;
                    }
                    if !self.first_frame {
                        self.first_frame = true;
                        self.handler.close_success();
                        self.handler.adapt_size();
                        self.send_toggle_virtual_display_msg(peer).await;
                        self.send_toggle_privacy_mode_msg(peer).await;
                    }
                    self.video_format = CodecFormat::from(&vf);

                    let display = vf.display as usize;
                    if !self.accept_peer_video_display(display) {
                        return true;
                    }
                    if !self.video_threads.contains_key(&display) {
                        self.new_video_thread(display);
                    }
                    let Some(thread) = self.video_threads.get_mut(&display) else {
                        return true;
                    };
                    let is_keyframe = starts_video_sequence(&vf);
                    match thread.media_thread.admit_frame(vf, is_keyframe) {
                        VideoFrameAdmission::Queued => {}
                        VideoFrameAdmission::AwaitingKeyframe => {
                            log::debug!(
                                "dropping peer delta frame while awaiting a fresh keyframe"
                            );
                        }
                        VideoFrameAdmission::RefreshRequired => {
                            log::warn!(
                                "viewer video backlog lost freshness; requesting a fresh keyframe"
                            );
                            if let Err(err) = self.handler.refresh_video(display as _) {
                                log::error!(
                                    "failed to admit viewer video recovery for display {display}: {err}"
                                );
                                return false;
                            }
                        }
                        VideoFrameAdmission::Closed => {
                            log::debug!("dropping peer video frame after decoder mailbox closure");
                        }
                    }
                }
                // R-T15c: the server no longer sends `Hash` (CPace is the sole authenticator); the
                // viewer logs in PROACTIVELY in Client::start, so there is no reactive Hash arm.
                Some(message::Union::LoginResponse(lr)) => match lr.union {
                    Some(login_response::Union::Error(err)) => {
                        let err = crate::peer_text::bound_peer_login_error(err);
                        if !self.handler.handle_login_error(&err) {
                            return false;
                        }
                    }
                    Some(login_response::Union::PeerInfo(pi)) => {
                        let pi = bound_peer_info(pi);
                        let peer_version = pi.version.clone();
                        let peer_platform = pi.platform.clone();
                        self.set_peer_info(&pi);
                        if self.handler.is_view_camera() {
                            if !self.check_view_camera_support(&peer_version, &peer_platform) {
                                self.handler.lc.write().unwrap().handle_peer_info(&pi);
                                return false;
                            }
                        }
                        if self.handler.is_terminal() {
                            if !self.check_terminal_support(&peer_version) {
                                self.handler.lc.write().unwrap().handle_peer_info(&pi);
                                return false;
                            }
                        }
                        self.handler.handle_peer_info(pi);
                        #[cfg(all(target_os = "windows", not(feature = "flutter")))]
                        self.check_clipboard_file_context();
                        if self.handler.is_default() {
                            #[cfg(feature = "flutter")]
                            #[cfg(not(target_os = "ios"))]
                            let rx = clipboard_session.and_then(|session| {
                                Client::try_start_clipboard(session, Default::default())
                            });
                            #[cfg(not(feature = "flutter"))]
                            #[cfg(not(any(target_os = "android", target_os = "ios")))]
                            let rx = clipboard_session.and_then(|session| {
                                Client::try_start_clipboard(
                                    session,
                                    Some(crate::client::ClientClipboardContext {
                                        cfg: self.handler.get_permission_config(),
                                        tx: self.sender.clone(),
                                        #[cfg(feature = "unix-file-copy-paste")]
                                        is_file_supported: crate::is_support_file_copy_paste(
                                            &peer_version,
                                        ),
                                    }),
                                )
                            });
                            // To make sure current text clipboard data is updated.
                            #[cfg(not(target_os = "ios"))]
                            if let Some(mut rx) = rx {
                                timeout(CLIPBOARD_INTERVAL, rx.recv()).await.ok();
                            }

                            #[cfg(not(any(target_os = "android", target_os = "ios")))]
                            if self.handler.lc.read().unwrap().sync_init_clipboard.v {
                                if let Some(msg_out) = crate::clipboard::get_current_clipboard_msg(
                                    &peer_version,
                                    &peer_platform,
                                    crate::clipboard::ClipboardSide::Client,
                                ) {
                                    let sender = self.sender.clone();
                                    let permission_config = self.handler.get_permission_config();
                                    tokio::spawn(async move {
                                        if permission_config.is_text_clipboard_required() {
                                            if let Err(err) = sender.send(Data::Message(msg_out)) {
                                                log::debug!(
                                                    "initial clipboard update outlived its viewer round: {err}"
                                                );
                                            }
                                        }
                                    });
                                }
                            }
                            // to-do: Android, is `sync_init_clipboard` really needed?
                            // https://github.com/rustdesk/rustdesk/discussions/9010

                            #[cfg(feature = "flutter")]
                            #[cfg(not(target_os = "ios"))]
                            crate::flutter::update_text_clipboard_required();

                            #[cfg(all(feature = "flutter", feature = "unix-file-copy-paste"))]
                            crate::flutter::update_file_clipboard_required();
                        }

                        if self.handler.is_file_transfer() {
                            self.handler.load_last_jobs();
                        }

                        self.is_connected = true;
                    }
                    _ => {}
                },
                Some(message::Union::CursorData(cd)) => {
                    self.handler.set_cursor_data(cd);
                }
                Some(message::Union::CursorId(id)) => {
                    self.handler.set_cursor_id(id.to_string());
                }
                Some(message::Union::CursorPosition(cp)) => {
                    self.handler.set_cursor_position(cp);
                }
                Some(message::Union::Clipboard(cb)) => {
                    // R-S19 (viewer side): only a default (Remote-control) session syncs the peer's
                    // clipboard into the viewer's OS clipboard — mirrors the is_default() gate on the
                    // clipboard-thread start above. A hostile peer in a FileTransfer/ViewCamera/Terminal
                    // session the viewer opened cannot write the viewer's clipboard.
                    if self.handler.is_default()
                        && !self.handler.lc.read().unwrap().disable_clipboard.v
                    {
                        #[cfg(not(any(target_os = "android", target_os = "ios")))]
                        update_clipboard(vec![cb], ClipboardSide::Client);
                        #[cfg(target_os = "android")]
                        crate::clipboard::handle_msg_clipboard(cb);
                        #[cfg(target_os = "ios")]
                        {
                            let _ = cb;
                            log::warn!(
                                "refusing in-process mobile peer clipboard SET until a platform worker/service boundary exists"
                            );
                        }
                    }
                }
                Some(message::Union::MultiClipboards(_mcb)) => {
                    // R-S19 (viewer side): default (Remote-control) session only, as the Clipboard arm.
                    if self.handler.is_default()
                        && !self.handler.lc.read().unwrap().disable_clipboard.v
                    {
                        #[cfg(not(any(target_os = "android", target_os = "ios")))]
                        update_clipboard(_mcb.clipboards, ClipboardSide::Client);
                        #[cfg(target_os = "android")]
                        crate::clipboard::handle_msg_multi_clipboards(_mcb);
                        #[cfg(target_os = "ios")]
                        {
                            let _ = _mcb;
                            log::warn!(
                                "refusing in-process mobile peer multi-clipboard SET until a platform worker/service boundary exists"
                            );
                        }
                    }
                }
                #[cfg(any(target_os = "windows", feature = "unix-file-copy-paste"))]
                Some(message::Union::Cliprdr(clip)) => {
                    self.handle_cliprdr_msg(clip, peer).await;
                }
                Some(message::Union::FileResponse(fr)) => {
                    match fr.union {
                        Some(file_response::Union::EmptyDirs(res)) => {
                            self.handler.update_empty_dirs(res);
                        }
                        Some(file_response::Union::Dir(fd)) => {
                            #[cfg(windows)]
                            let entries = fd.entries.to_vec();
                            #[cfg(not(windows))]
                            let mut entries = fd.entries.to_vec();
                            #[cfg(not(windows))]
                            {
                                if self.handler.peer_platform() == "Windows" {
                                    fs::transform_windows_path(&mut entries);
                                }
                            }
                            // We cannot call cancel_transfer_job/handle_job_status while holding
                            // a mutable borrow from fs::get_job(&mut self.write_jobs), so defer
                            // the error handling until after the borrow scope ends.
                            let mut set_files_err = None;
                            if let Some(job) = fs::get_job(fd.id, &mut self.write_jobs) {
                                log::info!("job set_files: {:?}", entries);
                                if let Err(err) = job.set_files(entries) {
                                    set_files_err = Some(err.to_string());
                                } else {
                                    job.set_finished_size_on_resume();
                                    self.handler.update_folder_files(
                                        fd.id,
                                        job.files(),
                                        fd.path,
                                        false,
                                        false,
                                    );
                                }
                            } else if let Some(job) = self.remove_jobs.get_mut(&fd.id) {
                                // Intentionally keep raw entries here:
                                // - remote remove flow executes deletions on peer side;
                                // - local remove flow is populated from local get_recursive_files().
                                job.files = entries;
                                self.handler
                                    .update_folder_files(fd.id, &job.files, fd.path, false, false);
                            } else {
                                self.handler
                                    .update_folder_files(fd.id, &entries, fd.path, false, false);
                            }
                            if let Some(err) = set_files_err {
                                log::warn!(
                                    "Rejected unsafe file list from remote peer for job {}: {}",
                                    fd.id,
                                    err
                                );
                                if !self.cancel_transfer_job(fd.id, peer).await {
                                    return false;
                                }
                                self.handle_job_status(fd.id, -1, Some(err));
                            }
                        }
                        Some(file_response::Union::Digest(digest)) => {
                            if digest.is_upload {
                                if let Some(job) = fs::get_job(digest.id, &mut self.read_jobs) {
                                    if let Some(file) = job.files().get(digest.file_num as usize) {
                                        if let fs::DataSource::FilePath(p) = &job.data_source {
                                            let read_path =
                                                get_string(&fs::TransferJob::join(p, &file.name));
                                            let mut overwrite_strategy =
                                                job.default_overwrite_strategy();
                                            let mut offset = 0;
                                            if digest.is_identical && job.is_resume {
                                                if digest.transferred_size > 0 {
                                                    overwrite_strategy = Some(true);
                                                    offset = digest.transferred_size as _;
                                                }
                                            }
                                            if let Some(overwrite) = overwrite_strategy {
                                                let req = FileTransferSendConfirmRequest {
                                                    id: digest.id,
                                                    file_num: digest.file_num,
                                                    union: Some(if overwrite {
                                                        file_transfer_send_confirm_request::Union::OffsetBlk(offset)
                                                    } else {
                                                        file_transfer_send_confirm_request::Union::Skip(
                                                            true,
                                                        )
                                                    }),
                                                    ..Default::default()
                                                };
                                                job.confirm(&req).await;
                                                let msg = new_send_confirm(req);
                                                if !self.send_tracked_file_action(peer, &msg).await
                                                {
                                                    return false;
                                                }
                                            } else {
                                                self.handler.override_file_confirm(
                                                    digest.id,
                                                    digest.file_num,
                                                    read_path,
                                                    true,
                                                    digest.is_identical,
                                                );
                                            }
                                        }
                                    }
                                }
                            } else {
                                if let Some(job) = fs::get_job(digest.id, &mut self.write_jobs) {
                                    if let Some(file) = job.files().get(digest.file_num as usize) {
                                        if let fs::DataSource::FilePath(p) = &job.data_source {
                                            let write_path =
                                                get_string(&fs::TransferJob::join(p, &file.name));
                                            job.set_digest(digest.file_size, digest.last_modified);
                                            let peer_ver = self.handler.lc.read().unwrap().version;
                                            let is_support_resume =
                                                crate::is_support_file_transfer_resume_num(
                                                    peer_ver,
                                                );
                                            match fs::is_write_need_confirmation(
                                                is_support_resume && job.is_resume,
                                                &write_path,
                                                &digest,
                                            ) {
                                                Ok(res) => match res {
                                                    DigestCheckResult::IsSame => {
                                                        let req = FileTransferSendConfirmRequest {
                                                            id: digest.id,
                                                            file_num: digest.file_num,
                                                            union: Some(file_transfer_send_confirm_request::Union::Skip(true)),
                                                            ..Default::default()
                                                        };
                                                        job.confirm(&req).await;
                                                        let msg = new_send_confirm(req);
                                                        if !self
                                                            .send_tracked_file_action(peer, &msg)
                                                            .await
                                                        {
                                                            return false;
                                                        }
                                                    }
                                                    DigestCheckResult::NeedConfirm(digest) => {
                                                        let mut overwrite_strategy =
                                                            job.default_overwrite_strategy();
                                                        let mut offset = 0;
                                                        if digest.is_identical
                                                            && job.is_resume
                                                            && digest.transferred_size > 0
                                                        {
                                                            overwrite_strategy = Some(true);
                                                            offset = digest.transferred_size as _;
                                                        }
                                                        if let Some(overwrite) = overwrite_strategy
                                                        {
                                                            let req =
                                                                FileTransferSendConfirmRequest {
                                                                    id: digest.id,
                                                                    file_num: digest.file_num,
                                                                    union: Some(if overwrite {
                                                                        file_transfer_send_confirm_request::Union::OffsetBlk(offset)
                                                                    } else {
                                                                        file_transfer_send_confirm_request::Union::Skip(true)
                                                                    }),
                                                                    ..Default::default()
                                                                };
                                                            job.confirm(&req).await;
                                                            let msg = new_send_confirm(req);
                                                            if !self
                                                                .send_tracked_file_action(
                                                                    peer, &msg,
                                                                )
                                                                .await
                                                            {
                                                                return false;
                                                            }
                                                        } else {
                                                            self.handler.override_file_confirm(
                                                                digest.id,
                                                                digest.file_num,
                                                                write_path,
                                                                false,
                                                                digest.is_identical,
                                                            );
                                                        }
                                                    }
                                                    DigestCheckResult::NoSuchFile => {
                                                        let req = FileTransferSendConfirmRequest {
                                                        id: digest.id,
                                                        file_num: digest.file_num,
                                                        union: Some(file_transfer_send_confirm_request::Union::OffsetBlk(0)),
                                                        ..Default::default()
                                                        };
                                                        job.confirm(&req).await;
                                                        let msg = new_send_confirm(req);
                                                        if !self
                                                            .send_tracked_file_action(peer, &msg)
                                                            .await
                                                        {
                                                            return false;
                                                        }
                                                    }
                                                },
                                                Err(err) => {
                                                    println!("error receiving digest: {}", err);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Some(file_response::Union::Block(block)) => {
                            match write_viewer_file_block(&mut self.write_jobs, block).await {
                                Ok(ViewerFileBlockWrite::NoActiveJob) => {}
                                Ok(ViewerFileBlockWrite::Written { update_status }) => {
                                    if update_status {
                                        self.update_jobs_status();
                                    }
                                }
                                Err(failure) => {
                                    let context = ViewerFileWriteContext::control(
                                        Some(failure.id),
                                        failure.file_num,
                                        "receive file data",
                                    );
                                    return self.record_file_flow_failure(
                                        context,
                                        format!("local file write failed: {}", failure.error),
                                    );
                                }
                            }
                        }
                        Some(file_response::Union::Done(d)) => {
                            let mut err: Option<String> = None;
                            if let Some(job) = fs::remove_job(d.id, &mut self.write_jobs) {
                                job.modify_time();
                                err = job.job_error();
                            }
                            self.handle_job_status(d.id, d.file_num, err);
                        }
                        Some(file_response::Union::Error(e)) => {
                            let _ = fs::remove_job(e.id, &mut self.write_jobs)
                                .or_else(|| fs::remove_job(e.id, &mut self.read_jobs));
                            self.handle_job_status(e.id, e.file_num, Some(e.error));
                        }
                        _ => {}
                    }
                }
                Some(message::Union::Misc(misc)) => match misc.union {
                    Some(misc::Union::AudioFormat(f)) => {
                        if client::native_opus_format_within_limit(f.sample_rate, f.channels) {
                            if let Err(err) = self.audio_thread.try_send(MediaData::AudioFormat(f))
                            {
                                log::warn!(
                                    "viewer audio decode queue full; dropping peer audio format: {err}"
                                );
                            }
                        } else {
                            log::warn!(
                                "dropping unsupported Opus format before audio queue: sample_rate={}, channels={}",
                                f.sample_rate,
                                f.channels
                            );
                        }
                    }
                    Some(misc::Union::ChatMessage(c)) => {
                        if let Some(text) = self.peer_text_gate.admit_chat(c.text) {
                            self.handler.new_message(text);
                        }
                    }
                    Some(misc::Union::PermissionInfo(p)) => {
                        log::info!("Change permission {:?} -> {}", p.permission, p.enabled);
                        // https://github.com/rustdesk/rustdesk/issues/3703#issuecomment-1474734754
                        match p.permission.enum_value() {
                            Ok(Permission::Keyboard) => {
                                *self.handler.server_keyboard_enabled.write().unwrap() = p.enabled;
                                #[cfg(feature = "flutter")]
                                #[cfg(not(target_os = "ios"))]
                                crate::flutter::update_text_clipboard_required();
                                #[cfg(all(feature = "flutter", feature = "unix-file-copy-paste"))]
                                crate::flutter::update_file_clipboard_required();
                                self.handler.set_permission("keyboard", p.enabled);
                            }
                            Ok(Permission::Clipboard) => {
                                *self.handler.server_clipboard_enabled.write().unwrap() = p.enabled;
                                #[cfg(feature = "flutter")]
                                #[cfg(not(target_os = "ios"))]
                                crate::flutter::update_text_clipboard_required();
                                self.handler.set_permission("clipboard", p.enabled);
                            }
                            Ok(Permission::Audio) => {
                                self.handler.set_permission("audio", p.enabled);
                            }
                            Ok(Permission::File) => {
                                *self.handler.server_file_transfer_enabled.write().unwrap() =
                                    p.enabled;
                                if !p.enabled && self.handler.is_file_transfer() {
                                    return true;
                                }
                                #[cfg(all(feature = "flutter", feature = "unix-file-copy-paste"))]
                                crate::flutter::update_file_clipboard_required();
                                self.handler.set_permission("file", p.enabled);
                                #[cfg(feature = "unix-file-copy-paste")]
                                if !p.enabled {
                                    try_empty_clipboard_files(
                                        ClipboardSide::Client,
                                        self.client_conn_id,
                                    );
                                }
                            }
                            Ok(Permission::Restart) => {
                                self.handler.set_permission("restart", p.enabled);
                            }
                            Ok(Permission::Recording) => {
                                self.handler.lc.write().unwrap().record_permission = p.enabled;
                                self.update_record_state();
                                self.handler.set_permission("recording", p.enabled);
                            }
                            Ok(Permission::BlockInput) => {
                                self.handler.set_permission("block_input", p.enabled);
                            }
                            Ok(Permission::PrivacyMode) => {
                                self.handler.set_permission("privacy_mode", p.enabled);
                            }
                            _ => {}
                        }
                    }
                    Some(misc::Union::SwitchDisplay(s)) => {
                        self.handler.handle_peer_switch_display(&s);
                        if let Some(thread) = self.video_threads.get_mut(&(s.display as usize)) {
                            if let Err(err) =
                                thread.media_thread.try_send_control(VideoControl::Reset)
                            {
                                log::warn!("viewer video decode queue full; dropping reset: {err}");
                            }
                        }

                        let mut scale = 1.0;
                        if let Some(pi) = &self.handler.lc.read().unwrap().peer_info {
                            if let Some(d) = pi.displays.get(s.display as usize) {
                                scale = d.scale;
                            }
                        }

                        if s.width > 0 && s.height > 0 {
                            self.handler.set_display(
                                s.x,
                                s.y,
                                s.width,
                                s.height,
                                s.cursor_embedded,
                                scale,
                            );
                        }
                    }
                    Some(misc::Union::CloseReason(c)) => {
                        self.sent_close_reason = true; // The controlled end will close, no need to send close reason
                        let c = crate::peer_text::bound_peer_close_reason(c);
                        self.handler.msgbox("error", "Connection Error", &c, "");
                        return false;
                    }
                    Some(misc::Union::BackNotification(notification)) => {
                        if !self.handle_back_notification(notification).await {
                            return false;
                        }
                    }
                    Some(misc::Union::Uac(uac)) => {
                        let keyboard = self.handler.server_keyboard_enabled.read().unwrap().clone();
                        #[cfg(feature = "flutter")]
                        {
                            if uac && keyboard {
                                self.peer_notification_msgbox(
                                    "on-uac",
                                    "Prompt",
                                    "Please wait for confirmation of UAC...",
                                    "",
                                );
                            } else {
                                self.handler.cancel_msgbox("on-uac");
                                self.handler.cancel_msgbox("wait-uac");
                                self.handler.cancel_msgbox("elevation-error");
                            }
                        }
                        #[cfg(not(feature = "flutter"))]
                        {
                            let msgtype = "custom-uac-nocancel";
                            let title = "Prompt";
                            let text = "Please wait for confirmation of UAC...";
                            let link = "";
                            if uac && keyboard {
                                self.peer_notification_msgbox(msgtype, title, text, link);
                            } else {
                                self.handler.cancel_msgbox(&format!(
                                    "{}-{}-{}-{}",
                                    msgtype, title, text, link,
                                ));
                            }
                        }
                    }
                    Some(misc::Union::ForegroundWindowElevated(elevated)) => {
                        let keyboard = self.handler.server_keyboard_enabled.read().unwrap().clone();
                        #[cfg(feature = "flutter")]
                        {
                            if elevated && keyboard {
                                self.peer_notification_msgbox(
                                    "on-foreground-elevated",
                                    "Prompt",
                                    "elevated_foreground_window_tip",
                                    "",
                                );
                            } else {
                                self.handler.cancel_msgbox("on-foreground-elevated");
                                self.handler.cancel_msgbox("wait-uac");
                                self.handler.cancel_msgbox("elevation-error");
                            }
                        }
                        #[cfg(not(feature = "flutter"))]
                        {
                            let msgtype = "custom-elevated-foreground-nocancel";
                            let title = "Prompt";
                            let text = "elevated_foreground_window_tip";
                            let link = "";
                            if elevated && keyboard {
                                self.peer_notification_msgbox(msgtype, title, text, link);
                            } else {
                                self.handler.cancel_msgbox(&format!(
                                    "{}-{}-{}-{}",
                                    msgtype, title, text, link,
                                ));
                            }
                        }
                    }
                    // R-X9 (slices 2-4): the `PortableServiceRunning` Misc variant (proto
                    // field 20) is excised with the portable run-mode — the host never sends
                    // it; the viewer-side status handler is removed too.
                    Some(misc::Union::SupportedEncoding(e)) => {
                        log::info!("update supported encoding:{:?}", e);
                        self.handler.lc.write().unwrap().supported_encoding = e;
                    }
                    Some(misc::Union::FollowCurrentDisplay(d_idx)) => {
                        self.handler.set_current_display(d_idx);
                    }
                    _ => {}
                },
                Some(message::Union::TestDelay(t)) => {
                    self.handler.handle_test_delay(t, peer).await;
                }
                Some(message::Union::AudioFrame(frame)) => {
                    if !self.handler.lc.read().unwrap().disable_audio.v {
                        if client::native_opus_packet_within_limit(frame.data.len()) {
                            if let Err(err) = self
                                .audio_thread
                                .try_send(MediaData::AudioFrame(Box::new(frame)))
                            {
                                log::warn!(
                                    "viewer audio decode queue full; dropping peer audio frame: {err}"
                                );
                            }
                        } else {
                            log::warn!(
                                "dropping oversized Opus packet before audio queue: {} > {}",
                                frame.data.len(),
                                client::MAX_NATIVE_OPUS_PACKET_BYTES
                            );
                        }
                    }
                }
                Some(message::Union::FileAction(action)) => match action.union {
                    Some(file_action::Union::SendConfirm(c)) => {
                        if let Some(job) = fs::get_job(c.id, &mut self.read_jobs) {
                            job.confirm(&c).await;
                        }
                    }
                    _ => {}
                },
                Some(message::Union::MessageBox(msgbox)) => {
                    let Some(msgbox) = self.peer_text_gate.admit_message_box(msgbox) else {
                        return true;
                    };
                    let mut link = msgbox.link;
                    if let Some(v) = config::HELPER_URL.get(&link as &str) {
                        link = v.to_string();
                    } else {
                        log::warn!("Message box ignore link {} for security", &link);
                        link = "".to_string();
                    }
                    self.handler
                        .msgbox(&msgbox.msgtype, &msgbox.title, &msgbox.text, &link);
                }
                Some(message::Union::VoiceCallRequest(request)) => {
                    if request.is_connect {
                        // TODO: maybe we will do a voice call from the peer in the future.
                    } else {
                        log::debug!("The remote has requested to close the voice call");
                        if self.voice_call_audio.is_some() {
                            self.stop_voice_call().await;
                            self.handler.on_voice_call_closed("");
                        }
                    }
                }
                Some(message::Union::VoiceCallResponse(response)) => {
                    let ts = std::mem::replace(&mut self.voice_call_request_timestamp, None);
                    if let Some(ts) = ts {
                        if response.req_timestamp != ts.get() {
                            log::debug!("Possible encountering a voice call attack.");
                        } else {
                            if response.accepted {
                                // The peer accepted the voice call.
                                self.stop_voice_call().await;
                                self.voice_call_audio = self.start_voice_call();
                                if self.voice_call_audio.is_some() {
                                    self.handler.on_voice_call_started();
                                } else {
                                    self.handler
                                        .on_voice_call_closed("Failed to start voice call audio");
                                    let msg = new_voice_call_request(false);
                                    allow_err!(peer.send(&msg).await);
                                }
                            } else {
                                // The peer refused the voice call.
                                self.handler.on_voice_call_closed("");
                            }
                        }
                    }
                }
                Some(message::Union::PeerInfo(pi)) => {
                    let pi = bound_peer_info(pi);
                    self.set_peer_info(&pi);
                    self.handler.set_displays(&pi.displays);
                    self.handler.set_platform_additions(&pi.platform_additions);
                }
                Some(message::Union::ScreenshotResponse(response)) => {
                    match crate::peer_text::admit_peer_screenshot_response(response) {
                        Ok(response) => {
                            let request_id = response.sid;
                            let Some(sid) = self.pending_screenshot_requests.complete(&request_id)
                            else {
                                log::warn!("dropping unrequested or stale screenshot response");
                                return true;
                            };
                            let data = response.data;
                            let msg = response.msg;
                            let data = (!data.is_empty()).then_some(data);
                            self.handler
                                .handle_screenshot_resp(sid, request_id, data, msg);
                        }
                        Err((request_id, msg)) => {
                            if let Some(sid) =
                                self.pending_screenshot_requests.complete(&request_id)
                            {
                                self.handler
                                    .handle_screenshot_resp(sid, request_id, None, msg);
                            } else {
                                log::warn!(
                                    "dropping oversized screenshot response for unrequested or stale sid"
                                );
                            }
                        }
                    }
                }
                Some(message::Union::TerminalResponse(response)) => {
                    if !self.terminal_response_allowed() {
                        log::warn!(
                            "dropping TerminalResponse while terminal is disabled or not the active session type"
                        );
                        return true;
                    }
                    use hbb_common::message_proto::terminal_response::Union;
                    if let Some(Union::Opened(opened)) = &response.union {
                        if opened.success && !opened.service_id.is_empty() {
                            let mut lc = self.handler.lc.write().unwrap();
                            let key = lc.get_key_terminal_service_id().to_owned();
                            // R-S15 / Appendix C #19: the peer-supplied service_id is persisted to the
                            // on-disk PeerConfig (via save_config) — bound it (strip control chars +
                            // clamp to 256) so a keyed-but-hostile host can't write an arbitrary blob,
                            // the same treatment the impl_key and PeerInfo strings already get.
                            lc.set_option(
                                key,
                                hbb_common::config::bound_peer_config_string(&opened.service_id),
                            );
                        }
                    }
                    self.handler.handle_terminal_response(response);
                }
                _ => {}
            }
        }
        true
    }

    fn set_peer_info(&mut self, pi: &PeerInfo) {
        self.peer_info.platform = pi.platform.clone();
        self.peer_info.display_count = pi.displays.len().min(MAX_PEER_VIDEO_DISPLAYS);

        // Check features field for terminal support
        if let Some(features) = pi.features.as_ref() {
            self.peer_info.support_terminal = features.terminal;
        }

        self.peer_info.is_installed = false;
        self.peer_info.idd_impl.clear();
        self.peer_info.support_view_camera = false;
        if !pi.platform_additions.is_empty() {
            match serde_json::from_str::<HashMap<String, serde_json::Value>>(&pi.platform_additions)
            {
                Ok(platform_additions) => {
                    self.peer_info.is_installed = platform_additions
                        .get("is_installed")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    self.peer_info.idd_impl = platform_additions
                        .get("idd_impl")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    self.peer_info.support_view_camera = platform_additions
                        .get("support_view_camera")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                }
                Err(err) => {
                    log::warn!("dropping unparsable sanitized peer platform_additions: {err}");
                }
            }
        }
    }

    fn peer_notification_msgbox(&mut self, msgtype: &str, title: &str, text: &str, link: &str) {
        if self.peer_text_gate.admit_notification() {
            self.handler.msgbox(msgtype, title, text, link);
        }
    }

    async fn handle_back_notification(&mut self, mut notification: BackNotification) -> bool {
        notification.details =
            crate::peer_text::bound_peer_notification_details(notification.details);
        match notification.union {
            Some(back_notification::Union::BlockInputState(state)) => {
                self.handle_back_msg_block_input(
                    state.enum_value_or(back_notification::BlockInputState::BlkStateUnknown),
                    notification.details,
                )
                .await;
            }
            Some(back_notification::Union::PrivacyModeState(state)) => {
                if !self
                    .handle_back_msg_privacy_mode(
                        state.enum_value_or(back_notification::PrivacyModeState::PrvStateUnknown),
                        notification.details,
                        notification.impl_key,
                    )
                    .await
                {
                    return false;
                }
            }
            _ => {}
        }
        true
    }

    #[inline(always)]
    fn update_block_input_state(&mut self, on: bool) {
        self.handler.update_block_input_state(on);
    }

    async fn handle_back_msg_block_input(
        &mut self,
        state: back_notification::BlockInputState,
        details: String,
    ) {
        match state {
            back_notification::BlockInputState::BlkOnSucceeded => {
                self.update_block_input_state(true);
            }
            back_notification::BlockInputState::BlkOnFailed => {
                self.peer_notification_msgbox(
                    "custom-error",
                    "Block user input",
                    if details.is_empty() {
                        "Failed"
                    } else {
                        &details
                    },
                    "",
                );
                self.update_block_input_state(false);
            }
            back_notification::BlockInputState::BlkOffSucceeded => {
                self.update_block_input_state(false);
            }
            back_notification::BlockInputState::BlkOffFailed => {
                self.peer_notification_msgbox(
                    "custom-error",
                    "Unblock user input",
                    if details.is_empty() {
                        "Failed"
                    } else {
                        &details
                    },
                    "",
                );
            }
            _ => {}
        }
    }

    #[inline(always)]
    fn update_privacy_mode(&mut self, impl_key: String, on: bool) {
        let mut config = self.handler.load_config();
        config.privacy_mode.v = on;
        if on {
            // For compatibility, version < 1.2.4, the default value is 'privacy_mode_impl_mag'.
            let impl_key = if impl_key.is_empty() {
                "privacy_mode_impl_mag".to_string()
            } else {
                // R-S15: bound the peer-supplied impl_key before it reaches the on-disk PeerConfig.
                hbb_common::config::bound_peer_config_string(&impl_key)
            };
            // R-S15 / Appendix C #19: REJECT a peer-supplied impl_key that is not in the compile-time
            // get_supported_privacy_mode_impl() set — a keyed-but-hostile host must not persist an
            // arbitrary privacy-mode-impl-key to our PeerConfig (the bound above is belt-and-suspenders).
            // On the Linux fork that set is empty (privacy mode is Windows/macOS-only), so no impl_key
            // is persisted here; on Windows/macOS only a recognized compile-time constant passes.
            if crate::privacy_mode::get_supported_privacy_mode_impl()
                .iter()
                .any(|(k, _)| *k == impl_key.as_str())
            {
                config
                    .options
                    .insert("privacy-mode-impl-key".to_string(), impl_key);
            }
        }
        self.handler.save_config(config);

        self.handler.update_privacy_mode();
    }

    fn persist_privacy_mode_response_if_admitted(
        &mut self,
        admission: PrivacyModeResponseAdmission,
        impl_key: String,
        on: bool,
    ) {
        if admission == PrivacyModeResponseAdmission::Persist(on) {
            self.update_privacy_mode(impl_key, on);
        }
    }

    async fn handle_back_msg_privacy_mode(
        &mut self,
        state: back_notification::PrivacyModeState,
        details: String,
        impl_key: String,
    ) -> bool {
        let admission = self.privacy_mode_response_admission(state, &impl_key);
        match state {
            back_notification::PrivacyModeState::PrvOnByOther => {
                self.peer_notification_msgbox(
                    "error",
                    "Connecting...",
                    "Someone turns on privacy mode, exit",
                    "",
                );
                return false;
            }
            back_notification::PrivacyModeState::PrvNotSupported => {
                self.peer_notification_msgbox("custom-error", "Privacy mode", "Unsupported", "");
                self.persist_privacy_mode_response_if_admitted(admission, impl_key, false);
            }
            back_notification::PrivacyModeState::PrvOnSucceeded => {
                self.peer_notification_msgbox(
                    "custom-nocancel",
                    "Privacy mode",
                    "Enter privacy mode",
                    "",
                );
                self.persist_privacy_mode_response_if_admitted(admission, impl_key, true);
            }
            back_notification::PrivacyModeState::PrvOnFailedDenied => {
                self.peer_notification_msgbox("custom-error", "Privacy mode", "Peer denied", "");
                self.persist_privacy_mode_response_if_admitted(admission, impl_key, false);
            }
            back_notification::PrivacyModeState::PrvOnFailedPlugin => {
                self.peer_notification_msgbox(
                    "custom-error",
                    "Privacy mode",
                    "Please install plugins",
                    "",
                );
                self.persist_privacy_mode_response_if_admitted(admission, impl_key, false);
            }
            back_notification::PrivacyModeState::PrvOnFailed => {
                self.peer_notification_msgbox(
                    "custom-error",
                    "Privacy mode",
                    if details.is_empty() {
                        "Failed"
                    } else {
                        &details
                    },
                    "",
                );
                self.persist_privacy_mode_response_if_admitted(admission, impl_key, false);
            }
            back_notification::PrivacyModeState::PrvOffSucceeded => {
                self.peer_notification_msgbox(
                    "custom-nocancel",
                    "Privacy mode",
                    "Exit privacy mode",
                    "",
                );
                self.persist_privacy_mode_response_if_admitted(admission, impl_key, false);
            }
            back_notification::PrivacyModeState::PrvOffByPeer => {
                self.peer_notification_msgbox("custom-error", "Privacy mode", "Peer exit", "");
                self.persist_privacy_mode_response_if_admitted(admission, impl_key, false);
            }
            back_notification::PrivacyModeState::PrvOffFailed => {
                self.peer_notification_msgbox(
                    "custom-error",
                    "Privacy mode",
                    if details.is_empty() {
                        "Failed to turn off"
                    } else {
                        &details
                    },
                    "",
                );
            }
            back_notification::PrivacyModeState::PrvOffUnknown => {
                self.peer_notification_msgbox("custom-error", "Privacy mode", "Turned off", "");
                // log::error!("Privacy mode is turned off with unknown reason");
                self.persist_privacy_mode_response_if_admitted(admission, impl_key, false);
            }
            _ => {}
        }
        true
    }

    #[cfg(all(target_os = "windows", not(feature = "flutter")))]
    fn check_clipboard_file_context(&self) {
        let enabled = *self.handler.server_file_transfer_enabled.read().unwrap()
            && self.handler.lc.read().unwrap().enable_file_copy_paste.v;
        ContextSend::enable(enabled);
    }

    #[cfg(any(target_os = "windows", feature = "unix-file-copy-paste"))]
    async fn handle_cliprdr_msg(
        &mut self,
        clip: hbb_common::message_proto::Cliprdr,
        _peer: &mut Stream,
    ) {
        log::debug!("handling cliprdr msg from server peer");
        #[cfg(feature = "flutter")]
        if let Some(hbb_common::message_proto::cliprdr::Union::FormatList(_)) = &clip.union {
            if self.client_conn_id
                != clipboard::get_client_conn_id(&crate::flutter::get_cur_peer_id()).unwrap_or(0)
            {
                return;
            }
        }

        let Some(clip) = crate::clipboard_file::msg_2_clip(clip) else {
            log::warn!("failed to decode cliprdr msg from server peer");
            return;
        };

        let is_stopping_allowed = clip.is_beginning_message();
        let file_transfer_enabled = self.handler.is_file_clipboard_required();
        let stop = is_stopping_allowed && !file_transfer_enabled;
        log::debug!(
                "Process clipboard message from server peer, stop: {}, is_stopping_allowed: {}, file_transfer_enabled: {}",
                stop, is_stopping_allowed, file_transfer_enabled);
        if !stop {
            #[cfg(any(
                target_os = "windows",
                all(target_os = "macos", feature = "unix-file-copy-paste")
            ))]
            if let Err(e) = ContextSend::make_sure_enabled() {
                log::error!("failed to restart clipboard context: {}", e);
            };
            #[cfg(target_os = "windows")]
            {
                let _ = ContextSend::proc(|context| -> ResultType<()> {
                    context
                        .server_clip_file(self.client_conn_id, clip)
                        .map_err(|e| e.into())
                });
            }
            #[cfg(feature = "unix-file-copy-paste")]
            if crate::is_support_file_copy_paste_num(self.handler.lc.read().unwrap().version) {
                let mut out_msgs = vec![];

                #[cfg(target_os = "macos")]
                if clipboard::platform::unix::macos::should_handle_msg(&clip) {
                    if let Err(e) = ContextSend::proc(|context| -> ResultType<()> {
                        context
                            .server_clip_file(self.client_conn_id, clip)
                            .map_err(|e| e.into())
                    }) {
                        log::error!("failed to handle cliprdr msg: {}", e);
                    }
                } else {
                    out_msgs = unix_file_clip::serve_clip_messages(
                        ClipboardSide::Client,
                        clip,
                        self.client_conn_id,
                    );
                }

                #[cfg(not(target_os = "macos"))]
                {
                    out_msgs = unix_file_clip::serve_clip_messages(
                        ClipboardSide::Client,
                        clip,
                        self.client_conn_id,
                    );
                }

                for msg in out_msgs.into_iter() {
                    allow_err!(_peer.send(&msg).await);
                }
            }
        }
    }

    fn accept_peer_video_display(&self, display: usize) -> bool {
        if !self.peer_info.video_display_allowed(display) {
            log::warn!(
                "dropping peer video frame for out-of-range display {} (allowed displays: {})",
                display,
                self.peer_info.allowed_video_displays()
            );
            return false;
        }
        if !self.video_threads.contains_key(&display)
            && self.video_threads.len() >= MAX_PEER_VIDEO_DISPLAYS
        {
            log::warn!(
                "dropping peer video frame for display {}; decoder thread cap {} reached",
                display,
                MAX_PEER_VIDEO_DISPLAYS
            );
            return false;
        }
        true
    }

    fn new_video_thread(&mut self, display: usize) {
        let (video_sender, video_receiver) = client::video_mailbox();
        let decode_fps = Arc::new(RwLock::new(None));
        let frame_count = Arc::new(RwLock::new(0));
        let handler = self.handler.ui_handler.clone();
        let decoder_frame_count = frame_count.clone();
        let thread = crate::client::start_video_thread(
            self.handler.clone(),
            display,
            video_receiver,
            decode_fps.clone(),
            self.chroma.clone(),
            move |display: usize,
                  data: &mut scrap::ImageRgb,
                  _texture: *mut c_void,
                  pixelbuffer: bool| {
                *decoder_frame_count.write().unwrap() += 1;
                if pixelbuffer {
                    handler.on_rgba(display, data);
                }
            },
        );
        let video_thread = VideoThread {
            media_thread: OwnedVideoThread::new("video decoder", video_sender, thread),
            decode_fps,
            frame_count,
            fps_control: Default::default(),
        };
        self.video_threads.insert(display, video_thread);
        if self.video_threads.len() == 1 {
            let auto_record =
                LocalConfig::get_bool_option(config::keys::OPTION_ALLOW_AUTO_RECORD_OUTGOING);
            self.handler.lc.write().unwrap().record_state = auto_record;
            self.update_record_state();
        }
    }

    fn update_record_state(&mut self) {
        // state
        let permission = self.handler.lc.read().unwrap().record_permission;
        if !permission {
            self.handler.lc.write().unwrap().record_state = false;
        }
        let state = self.handler.lc.read().unwrap().record_state;
        let start = state && permission;
        if self.last_record_state == start {
            return;
        }
        self.last_record_state = start;
        log::info!("record screen start: {start}");
        // update local
        for (_, v) in self.video_threads.iter_mut() {
            if let Err(err) = v
                .media_thread
                .try_send_control(VideoControl::RecordScreen(start))
            {
                log::warn!("viewer video decode queue full; dropping record-state update: {err}");
            }
        }
        self.handler.update_record_status(start);
        // update remote
        let mut misc = Misc::new();
        misc.set_client_record_status(start);
        let mut msg = Message::new();
        msg.set_misc(misc);
        if let Err(err) = self.sender.send(Data::Message(msg)) {
            log::error!("failed to admit remote recording-state update: {err}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    fn file_write_test_limits(count: usize, bytes: usize) -> ViewerFileWriteLimits {
        ViewerFileWriteLimits {
            count,
            bytes,
            timeout: Duration::from_millis(25),
        }
    }

    #[hbb_common::tokio::test]
    async fn r_s11fg_file_writer_success_releases_exact_count_and_bytes() {
        let mut tracker = ViewerFileWriteTracker::with_limits(file_write_test_limits(2, 16));
        let context = ViewerFileWriteContext::control(Some(7), 3, "test file request");
        let reservation = tracker.reserve(context.clone(), 16).unwrap();
        let (completion, receipt) = hbb_common::tokio::sync::oneshot::channel();
        tracker.attach(reservation, receipt).unwrap();
        assert!(!tracker.is_empty());
        completion.send(Ok(())).unwrap();

        let completed = tracker.next().await.unwrap();
        assert_eq!(completed.context, Some(context));
        assert_eq!(completed.result, Ok(()));
        assert!(tracker.is_empty());
        assert_eq!(tracker.pending_bytes, 0);

        let replacement = tracker
            .reserve(
                ViewerFileWriteContext::control(Some(8), 4, "replacement request"),
                16,
            )
            .unwrap();
        assert!(tracker.cancel(replacement).unwrap().is_some());
        assert_eq!(tracker.pending_bytes, 0);
    }

    #[test]
    fn r_s11fg_file_writer_count_byte_and_sequence_limits_fail_closed() {
        let mut tracker = ViewerFileWriteTracker::with_limits(file_write_test_limits(1, 8));
        let first = tracker
            .reserve(
                ViewerFileWriteContext::control(Some(1), 0, "first request"),
                8,
            )
            .unwrap();
        assert!(tracker
            .reserve(
                ViewerFileWriteContext::control(Some(2), 0, "count overflow"),
                0,
            )
            .unwrap_err()
            .contains("completion capacity"));
        tracker.cancel(first).unwrap();
        assert!(tracker
            .reserve(
                ViewerFileWriteContext::control(Some(3), 0, "byte overflow"),
                9,
            )
            .unwrap_err()
            .contains("byte capacity"));

        tracker.next_id = u64::MAX;
        assert!(tracker
            .reserve(
                ViewerFileWriteContext::control(Some(4), 0, "sequence overflow"),
                1,
            )
            .unwrap_err()
            .contains("sequence exhausted"));
        assert!(tracker.is_empty());
        assert_eq!(tracker.pending_bytes, 0);
    }

    #[hbb_common::tokio::test]
    async fn r_s11fg_file_writer_failure_and_retirement_are_explicit() {
        let mut tracker = ViewerFileWriteTracker::with_limits(file_write_test_limits(2, 16));
        let failed_context = ViewerFileWriteContext::control(Some(5), 2, "failed request");
        let reservation = tracker.reserve(failed_context.clone(), 4).unwrap();
        let (completion, receipt) = hbb_common::tokio::sync::oneshot::channel();
        tracker.attach(reservation, receipt).unwrap();
        completion
            .send(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "test writer failure",
            )))
            .unwrap();
        let completed = tracker.next().await.unwrap();
        assert_eq!(completed.context, Some(failed_context));
        assert!(completed
            .result
            .unwrap_err()
            .contains("test writer failure"));

        let canceled_context = ViewerFileWriteContext::control(Some(11), 4, "canceled receipt");
        let reservation = tracker.reserve(canceled_context.clone(), 4).unwrap();
        let (completion, receipt) = hbb_common::tokio::sync::oneshot::channel();
        tracker.attach(reservation, receipt).unwrap();
        drop(completion);
        let completed = tracker.next().await.unwrap();
        assert_eq!(completed.context, Some(canceled_context));
        assert!(completed
            .result
            .unwrap_err()
            .contains("retired before exact completion"));

        let retained_context = ViewerFileWriteContext::transfer_data(Some(6), 9);
        let reservation = tracker.reserve(retained_context.clone(), 4).unwrap();
        let (_completion, receipt) = hbb_common::tokio::sync::oneshot::channel();
        tracker.attach(reservation, receipt).unwrap();
        assert!(tracker.has_transfer_data());
        assert_eq!(tracker.retire(), vec![retained_context]);
        assert!(tracker.is_empty());
        assert_eq!(tracker.pending_bytes, 0);
    }

    #[hbb_common::tokio::test]
    async fn r_s11fg_file_writer_timeout_is_terminal_and_bounded() {
        let mut tracker = ViewerFileWriteTracker::with_limits(file_write_test_limits(1, 8));
        let context = ViewerFileWriteContext::control(Some(10), 0, "timed request");
        let reservation = tracker.reserve(context.clone(), 1).unwrap();
        let (_completion, receipt) = hbb_common::tokio::sync::oneshot::channel();
        tracker.attach(reservation, receipt).unwrap();

        let completed = tracker.next().await.unwrap();
        assert_eq!(completed.context, Some(context));
        assert!(completed.result.unwrap_err().contains("timed out"));
        assert!(tracker.is_empty());
    }

    struct ViewerFileTestDir {
        path: PathBuf,
    }

    impl ViewerFileTestDir {
        fn new() -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "rustdesk_viewer_file_failure_{}_{}",
                std::process::id(),
                nonce
            ));
            std::fs::create_dir(&path).expect("create viewer file test directory");
            Self { path }
        }
    }

    impl Drop for ViewerFileTestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[hbb_common::tokio::test]
    async fn r_s11fi_incoming_write_failure_retires_exact_job_and_partial_artifacts() {
        let temp = ViewerFileTestDir::new();
        let mut entry = FileEntry::new();
        entry.name = "incoming.bin".to_owned();
        let job = fs::TransferJob::new_write(
            73,
            fs::JobType::Generic,
            "remote.bin".to_owned(),
            fs::DataSource::FilePath(temp.path.clone()),
            0,
            false,
            true,
            false,
        )
        .with_files(vec![entry])
        .expect("create exact viewer receive job");
        let download = temp.path.join("incoming.bin.download");
        let digest = temp.path.join("incoming.bin.digest");
        std::fs::write(&download, b"partial").expect("stage partial download");
        std::fs::write(&digest, b"{}").expect("stage partial digest");
        let mut jobs = vec![job];

        let written = write_viewer_file_block(
            &mut jobs,
            FileTransferBlock {
                id: 73,
                file_num: 0,
                data: vec![0x40].into(),
                ..Default::default()
            },
        )
        .await
        .expect("open the exact receive stream before the terminal failure");
        assert_eq!(
            written,
            ViewerFileBlockWrite::Written {
                update_status: true
            }
        );
        assert_eq!(jobs.len(), 1);

        let failure = write_viewer_file_block(
            &mut jobs,
            FileTransferBlock {
                id: 73,
                file_num: 1,
                data: vec![0x41].into(),
                ..Default::default()
            },
        )
        .await
        .expect_err("an out-of-range peer file number must fail the exact receive job");

        assert_eq!(failure.id, 73);
        assert_eq!(failure.file_num, 1);
        assert!(failure.error.contains("Wrong file number"));
        assert!(jobs.is_empty(), "the failed exact receive job must retire");
        assert!(!download.exists(), "the partial download must be removed");
        assert!(!digest.exists(), "the partial digest must be removed");
    }

    #[cfg(unix)]
    #[hbb_common::tokio::test]
    async fn r_s11fi_incoming_nofollow_open_failure_retires_job_and_sidecars() {
        let temp = ViewerFileTestDir::new();
        let mut entry = FileEntry::new();
        entry.name = "incoming.bin".to_owned();
        let job = fs::TransferJob::new_write(
            74,
            fs::JobType::Generic,
            "remote.bin".to_owned(),
            fs::DataSource::FilePath(temp.path.clone()),
            0,
            false,
            true,
            false,
        )
        .with_files(vec![entry])
        .expect("create exact viewer receive job");
        let download = temp.path.join("incoming.bin.download");
        let digest = temp.path.join("incoming.bin.digest");
        std::os::unix::fs::symlink("forbidden-target", &download)
            .expect("stage a no-follow receive target");
        std::fs::write(&digest, b"{}").expect("stage partial digest");
        let mut jobs = vec![job];

        let failure = write_viewer_file_block(
            &mut jobs,
            FileTransferBlock {
                id: 74,
                file_num: 0,
                data: vec![0x41].into(),
                ..Default::default()
            },
        )
        .await
        .expect_err("a no-follow local receive-target failure must fail the exact job");

        assert_eq!(failure.id, 74);
        assert_eq!(failure.file_num, 0);
        assert!(!failure.error.is_empty());
        assert!(jobs.is_empty(), "the failed exact receive job must retire");
        assert!(
            std::fs::symlink_metadata(&download).is_err(),
            "the rejected receive-target symlink must be removed"
        );
        assert!(!digest.exists(), "the partial digest must be removed");
        assert!(
            !temp.path.join("forbidden-target").exists(),
            "cleanup must not follow the rejected target"
        );
    }

    #[test]
    fn r_s11ff_refresh_mailbox_coalesces_duplicates_and_preserves_distinct_order() {
        let (sender, receiver) = viewer_video_refresh_channel();
        assert_eq!(
            sender.request(ViewerVideoRefreshRequest::Display(3)),
            Ok(())
        );
        assert_eq!(
            sender.request(ViewerVideoRefreshRequest::Display(3)),
            Ok(())
        );
        assert_eq!(
            sender.request(ViewerVideoRefreshRequest::Display(7)),
            Ok(())
        );

        assert_eq!(
            receiver.try_recv(),
            Some(ViewerVideoRefreshRequest::Display(3))
        );
        assert_eq!(
            receiver.try_recv(),
            Some(ViewerVideoRefreshRequest::Display(7))
        );
        assert_eq!(receiver.try_recv(), None);
    }

    #[test]
    fn r_s11ff_all_displays_supersedes_pending_display_refreshes() {
        let (sender, receiver) = viewer_video_refresh_channel();
        assert_eq!(
            sender.request(ViewerVideoRefreshRequest::Display(1)),
            Ok(())
        );
        assert_eq!(
            sender.request(ViewerVideoRefreshRequest::Display(2)),
            Ok(())
        );
        assert_eq!(sender.request(ViewerVideoRefreshRequest::All), Ok(()));
        assert_eq!(
            sender.request(ViewerVideoRefreshRequest::Display(3)),
            Ok(())
        );

        assert_eq!(receiver.try_recv(), Some(ViewerVideoRefreshRequest::All));
        assert_eq!(receiver.try_recv(), None);
    }

    #[test]
    fn r_s11ff_refresh_mailbox_has_a_fixed_display_identity_cap() {
        let (sender, receiver) = viewer_video_refresh_channel();
        for display in 0..MAX_PEER_VIDEO_DISPLAYS {
            assert_eq!(
                sender.request(ViewerVideoRefreshRequest::Display(display)),
                Ok(())
            );
        }
        assert_eq!(
            sender.request(ViewerVideoRefreshRequest::Display(MAX_PEER_VIDEO_DISPLAYS)),
            Err(ViewerVideoRefreshAdmissionError::Capacity)
        );
        assert_eq!(
            receiver.try_recv(),
            Some(ViewerVideoRefreshRequest::Display(0))
        );
        assert_eq!(
            sender.request(ViewerVideoRefreshRequest::Display(MAX_PEER_VIDEO_DISPLAYS)),
            Ok(())
        );
    }

    #[test]
    fn r_s11ff_refresh_mailbox_fails_after_its_exact_round_receiver_drops() {
        let (sender, receiver) = viewer_video_refresh_channel();
        assert_eq!(
            sender.request(ViewerVideoRefreshRequest::Display(2)),
            Ok(())
        );
        drop(receiver);
        assert_eq!(
            sender.request(ViewerVideoRefreshRequest::Display(2)),
            Err(ViewerVideoRefreshAdmissionError::Closed)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn r_s11ff_refresh_mailbox_wakes_without_polling() {
        let (sender, mut receiver) = viewer_video_refresh_channel();
        sender
            .request(ViewerVideoRefreshRequest::Display(5))
            .expect("the exact round is live");
        assert_eq!(
            receiver.recv().await,
            Some(ViewerVideoRefreshRequest::Display(5))
        );
    }

    #[derive(Clone, Default)]
    struct InputSequenceTestInterface {
        lch: Arc<RwLock<crate::client::LoginConfigHandler>>,
    }

    #[async_trait]
    impl Interface for InputSequenceTestInterface {
        fn send(&self, _data: Data) {
            panic!("the exact-round input sequence must not use the mutable interface sender");
        }

        fn try_send(&self, _data: Data) -> hbb_common::ResultType<()> {
            panic!("the exact-round input sequence must not use the mutable interface sender");
        }

        fn msgbox(&self, _msgtype: &str, _title: &str, _text: &str, _link: &str) {}

        fn handle_login_error(&self, _err: &str) -> bool {
            false
        }

        fn handle_peer_info(&self, _pi: PeerInfo) {}

        fn set_multiple_windows_session(&self, _sessions: Vec<WindowsSession>) {}

        async fn handle_login_from_ui(
            &self,
            _password: String,
            _remember: bool,
            _peer: &mut Stream,
        ) {
        }

        async fn handle_test_delay(&self, _delay: TestDelay, _peer: &mut Stream) {}

        fn get_lch(&self) -> Arc<RwLock<crate::client::LoginConfigHandler>> {
            self.lch.clone()
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn r_s11e148_os_password_input_is_cancelled_and_joined_before_round_replacement() {
        let mut owner = OwnedInputOsPasswordTask::default();
        let (old_sender, mut old_receiver) = client::viewer_command_channel();
        let (replacement_sender, mut replacement_receiver) = client::viewer_command_channel();

        owner
            .replace(client::run_input_os_password_sequence(
                client::prepare_input_os_password_sequence(
                    "test-password".to_owned(),
                    true,
                    &InputSequenceTestInterface::default(),
                ),
                old_sender,
            ))
            .await;

        let first = time::timeout(Duration::from_secs(1), old_receiver.recv())
            .await
            .expect("the admitted round must receive the sequence's first event")
            .expect("the exact old-round sender must be live")
            .expect("the exact old-round command must be admitted");
        assert!(
            matches!(first, Data::Message(_)),
            "the first activation event must stay on the admitted round"
        );

        owner
            .replace(async move {
                replacement_sender
                    .send(Data::Close)
                    .expect("the replacement test receiver must remain live");
            })
            .await;

        assert!(
            matches!(
                old_receiver.try_recv(),
                Some(Err(client::ViewerCommandFailure::ProducersGone))
            ),
            "replacement must abort, await, and drop the old exact-round sender before it starts"
        );
        assert!(
            matches!(replacement_receiver.recv().await, Some(Ok(Data::Close))),
            "the replacement task must retain only its replacement-round sender"
        );
        assert!(
            replacement_receiver.recv().await.is_none(),
            "the completed replacement task must release its exact sender"
        );

        owner.stop_and_join().await;
    }

    #[test]
    fn r_s11e149_screenshot_responses_require_the_current_exact_request() {
        let mut pending = PendingScreenshotRequests::default();
        let first = pending
            .replace("ui-session".to_owned())
            .expect("first screenshot request");
        let replacement = pending
            .replace("ui-session".to_owned())
            .expect("replacement screenshot request");

        assert_ne!(first, replacement);
        assert!(
            pending.complete(&first).is_none(),
            "a response for the replaced request must be stale"
        );
        assert_eq!(
            pending.complete(&replacement).as_deref(),
            Some("ui-session"),
            "only the current exact request may recover its owning UI session"
        );
        assert!(
            pending.complete(&replacement).is_none(),
            "a response ID may complete only once"
        );
    }

    fn peer_info_with_display_count(count: usize) -> PeerInfo {
        let mut pi = PeerInfo::new();
        pi.displays = (0..count).map(|_| DisplayInfo::new()).collect();
        pi
    }

    #[test]
    fn peer_video_display_gate_allows_only_display_zero_before_peer_info() {
        let info = ParsedPeerInfo::default();
        assert!(info.video_display_allowed(0));
        assert!(!info.video_display_allowed(1));
    }

    #[test]
    fn peer_video_display_gate_caps_advertised_display_count() {
        let info = ParsedPeerInfo {
            display_count: MAX_PEER_VIDEO_DISPLAYS + 100,
            ..Default::default()
        };
        assert!(info.video_display_allowed(MAX_PEER_VIDEO_DISPLAYS - 1));
        assert!(!info.video_display_allowed(MAX_PEER_VIDEO_DISPLAYS));
    }

    #[test]
    fn peer_info_display_list_is_truncated_to_thread_cap() {
        let mut pi = peer_info_with_display_count(MAX_PEER_VIDEO_DISPLAYS + 1);
        pi.current_display = (MAX_PEER_VIDEO_DISPLAYS + 10) as i32;
        let bounded = bound_peer_info(pi);
        assert_eq!(bounded.displays.len(), MAX_PEER_VIDEO_DISPLAYS);
        assert_eq!(bounded.current_display, 0);
    }

    fn one_encoded_video_frame() -> EncodedVideoFrames {
        EncodedVideoFrames {
            frames: vec![EncodedVideoFrame {
                data: vec![0; 8].into(),
                key: true,
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[test]
    fn av1_video_frame_is_rejected_before_viewer_state_admission() {
        let mut av1 = VideoFrame::new();
        av1.set_av1s(one_encoded_video_frame());
        assert!(!native_video_frame_runtime_supported(&av1));

        let mut vp9 = VideoFrame::new();
        vp9.set_vp9s(one_encoded_video_frame());
        assert!(native_video_frame_runtime_supported(&vp9));
    }

    #[test]
    fn peer_info_bounder_limits_peer_strings_and_vectors() {
        let mut pi = peer_info_with_display_count(MAX_PEER_VIDEO_DISPLAYS + 1);
        pi.username = format!("user\u{0000}{}", "x".repeat(400));
        pi.hostname = "h".repeat(400);
        pi.platform = "p".repeat(400);
        pi.version = "v".repeat(400);
        pi.displays[0].name = format!("display\u{0000}{}", "x".repeat(400));
        pi.displays[0].x = MAX_PEER_DISPLAY_ORIGIN_ABS + 1;
        pi.displays[0].y = -MAX_PEER_DISPLAY_ORIGIN_ABS - 1;
        pi.displays[0].width = 0;
        pi.displays[0].height = MAX_PEER_DISPLAY_DIMENSION + 1;
        pi.displays[0].scale = f64::INFINITY;
        pi.displays[0].original_resolution = Some(Resolution {
            width: -1,
            height: 1080,
            ..Default::default()
        })
        .into();
        pi.resolutions = Some(SupportedResolutions {
            resolutions: (0..(MAX_PEER_INFO_RESOLUTIONS + 1))
                .map(|i| Resolution {
                    width: if i == 0 { 0 } else { 1920 },
                    height: if i == 1 {
                        MAX_PEER_DISPLAY_DIMENSION + 1
                    } else {
                        1080
                    },
                    ..Default::default()
                })
                .chain(std::iter::once(Resolution {
                    width: 1920,
                    height: 1080,
                    ..Default::default()
                }))
                .collect(),
            ..Default::default()
        })
        .into();
        pi.windows_sessions = Some(WindowsSessions {
            sessions: (0..(MAX_PEER_WINDOWS_SESSIONS + 1))
                .map(|i| WindowsSession {
                    sid: i as u32,
                    name: format!("name\u{0007}{}", "x".repeat(400)),
                    ..Default::default()
                })
                .collect(),
            current_sid: 1,
            ..Default::default()
        })
        .into();
        pi.platform_additions = serde_json::json!({
            "is_installed": true,
            "unknown": "drop",
            "idd_impl": format!("idd\u{0000}{}", "x".repeat(270)),
            "amyuni_virtual_displays": 9_999,
            "supported_privacy_mode_impl": (0..(MAX_PEER_PRIVACY_MODE_IMPLS + 4))
                .map(|_| vec![format!("impl\u{0000}{}", "x".repeat(270)), "tip".repeat(90)])
                .collect::<Vec<_>>(),
        })
        .to_string();

        let bounded = bound_peer_info(pi);

        assert_eq!(bounded.displays.len(), MAX_PEER_VIDEO_DISPLAYS);
        assert_eq!(bounded.current_display, 0);
        assert!(bounded.displays[0].name.len() <= 256);
        assert!(!bounded.displays[0].name.contains('\u{0000}'));
        assert_eq!(bounded.displays[0].x, MAX_PEER_DISPLAY_ORIGIN_ABS);
        assert_eq!(bounded.displays[0].y, -MAX_PEER_DISPLAY_ORIGIN_ABS);
        assert_eq!(bounded.displays[0].width, 1);
        assert_eq!(bounded.displays[0].height, MAX_PEER_DISPLAY_DIMENSION);
        assert_eq!(bounded.displays[0].scale, 1.0);
        assert!(bounded.displays[0].original_resolution.as_ref().is_none());
        assert!(bounded.username.len() <= 256);
        assert!(!bounded.username.contains('\u{0000}'));
        assert!(bounded.hostname.len() <= 256);
        assert!(bounded.platform.len() <= 256);
        assert!(bounded.version.len() <= 256);
        assert!(bounded.resolutions.resolutions.len() <= MAX_PEER_INFO_RESOLUTIONS);
        assert!(bounded.resolutions.resolutions.iter().all(|resolution| {
            is_peer_display_dimension(resolution.width)
                && is_peer_display_dimension(resolution.height)
        }));
        assert_eq!(
            bounded.windows_sessions.sessions.len(),
            MAX_PEER_WINDOWS_SESSIONS
        );
        assert!(!bounded.windows_sessions.sessions[0]
            .name
            .contains('\u{0007}'));

        let additions: serde_json::Value =
            serde_json::from_str(&bounded.platform_additions).unwrap();
        assert!(additions.get("unknown").is_none());
        assert_eq!(additions["is_installed"], serde_json::json!(true));
        assert_eq!(
            additions["amyuni_virtual_displays"],
            serde_json::json!(MAX_PEER_PLATFORM_ADDITION_LIST_ITEMS as u64)
        );
        let privacy_impls = additions["supported_privacy_mode_impl"].as_array().unwrap();
        assert_eq!(privacy_impls.len(), MAX_PEER_PRIVACY_MODE_IMPLS);
        assert!(privacy_impls[0][0].as_str().unwrap().len() <= 256);
        assert!(!privacy_impls[0][0].as_str().unwrap().contains('\u{0000}'));
    }

    #[test]
    fn peer_platform_additions_rejects_oversized_or_malformed_json() {
        assert_eq!(
            sanitize_peer_platform_additions(
                &"x".repeat(MAX_PEER_INFO_PLATFORM_ADDITIONS_BYTES + 1)
            ),
            ""
        );
        assert_eq!(sanitize_peer_platform_additions("{not-json"), "");
        assert_eq!(sanitize_peer_platform_additions("[1,2,3]"), "");
    }

    #[test]
    fn privacy_mode_response_classifier_requires_matching_pending_request() {
        let now = Instant::now();
        let request = PendingPrivacyModeRequest::new_at(true, "impl-a".to_owned(), now);

        assert_eq!(
            request.classify_response(
                back_notification::PrivacyModeState::PrvOnSucceeded,
                "impl-a",
                now,
            ),
            PrivacyModeResponseAdmission::Persist(true)
        );
        assert_eq!(
            request.classify_response(
                back_notification::PrivacyModeState::PrvOnFailed,
                "impl-a",
                now,
            ),
            PrivacyModeResponseAdmission::Persist(false)
        );
        assert_eq!(
            request.classify_response(
                back_notification::PrivacyModeState::PrvOnSucceeded,
                "impl-b",
                now,
            ),
            PrivacyModeResponseAdmission::Ignore
        );
        assert_eq!(
            request.classify_response(
                back_notification::PrivacyModeState::PrvOffSucceeded,
                "impl-a",
                now,
            ),
            PrivacyModeResponseAdmission::Ignore
        );
    }

    #[test]
    fn privacy_mode_response_classifier_handles_off_and_expiry() {
        let now = Instant::now();
        let request = PendingPrivacyModeRequest::new_at(false, "impl-a".to_owned(), now);

        assert_eq!(
            request.classify_response(
                back_notification::PrivacyModeState::PrvOffSucceeded,
                "impl-a",
                now,
            ),
            PrivacyModeResponseAdmission::Persist(false)
        );
        assert_eq!(
            request.classify_response(
                back_notification::PrivacyModeState::PrvOffFailed,
                "impl-a",
                now,
            ),
            PrivacyModeResponseAdmission::CompleteWithoutPersist
        );
        assert_eq!(
            request.classify_response(
                back_notification::PrivacyModeState::PrvOnSucceeded,
                "impl-a",
                now,
            ),
            PrivacyModeResponseAdmission::Ignore
        );

        let old = PendingPrivacyModeRequest::new_at(
            true,
            "impl-a".to_owned(),
            now - PRIVACY_MODE_RESPONSE_TIMEOUT - Duration::from_secs(1),
        );
        assert_eq!(
            old.classify_response(
                back_notification::PrivacyModeState::PrvOnSucceeded,
                "impl-a",
                now,
            ),
            PrivacyModeResponseAdmission::Ignore
        );
    }

    #[test]
    fn privacy_mode_pending_request_is_recorded_only_from_local_remote_toggle() {
        let mut toggle = Misc::new();
        toggle.set_toggle_privacy_mode(TogglePrivacyMode {
            impl_key: "impl-a".to_owned(),
            on: true,
            ..Default::default()
        });
        let mut msg = Message::new();
        msg.set_misc(toggle);
        let request = PendingPrivacyModeRequest::from_message(&msg, true).unwrap();
        assert!(request.on);
        assert_eq!(request.impl_key, "impl-a");
        assert!(PendingPrivacyModeRequest::from_message(&msg, false).is_none());

        let mut option = OptionMessage::new();
        option.privacy_mode = BoolOption::No.into();
        let mut legacy = Misc::new();
        legacy.set_option(option);
        let mut legacy_msg = Message::new();
        legacy_msg.set_misc(legacy);
        let request = PendingPrivacyModeRequest::from_message(&legacy_msg, true).unwrap();
        assert!(!request.on);
        assert_eq!(request.impl_key, "");
    }

    fn encoded_video_frame(keys: &[bool]) -> VideoFrame {
        let mut frames = EncodedVideoFrames::new();
        for key in keys {
            let mut frame = EncodedVideoFrame::new();
            frame.key = *key;
            frames.frames.push(frame);
        }
        let mut video = VideoFrame::new();
        video.set_vp8s(frames);
        video
    }

    #[test]
    fn r_s11ev_only_a_leading_keyframe_starts_an_encoded_sequence() {
        assert!(starts_video_sequence(&encoded_video_frame(&[true, false])));
        assert!(
            !starts_video_sequence(&encoded_video_frame(&[false, true])),
            "a later keyframe cannot recover when an earlier dependent frame fails first"
        );
        assert!(!starts_video_sequence(&encoded_video_frame(&[])));
    }

    #[test]
    fn r_s11ev_raw_video_frames_are_independent_sequences() {
        let mut rgb = VideoFrame::new();
        rgb.set_rgb(RGB::new());
        assert!(starts_video_sequence(&rgb));

        let mut yuv = VideoFrame::new();
        yuv.set_yuv(YUV::new());
        assert!(starts_video_sequence(&yuv));
    }
}

struct RemoveJob {
    files: Vec<FileEntry>,
    path: String,
    sep: &'static str,
    is_remote: bool,
    no_confirm: bool,
    last_update_job_status: Instant,
}

impl RemoveJob {
    fn new(files: Vec<FileEntry>, path: String, sep: &'static str, is_remote: bool) -> Self {
        Self {
            files,
            path,
            sep,
            is_remote,
            no_confirm: false,
            last_update_job_status: Instant::now(),
        }
    }

    pub fn _gen_meta(&self) -> RemoveJobMeta {
        RemoveJobMeta {
            path: self.path.clone(),
            is_remote: self.is_remote,
            no_confirm: self.no_confirm,
        }
    }
}

#[derive(Debug, Default)]
struct FpsControl {
    idle_counter: usize,
    inactive_counter: usize,
}

struct VideoThread {
    media_thread: OwnedVideoThread,
    decode_fps: Arc<RwLock<Option<usize>>>,
    frame_count: Arc<RwLock<usize>>,
    fps_control: FpsControl,
}
