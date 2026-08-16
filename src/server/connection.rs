use super::{input_service::*, *};
#[cfg(feature = "unix-file-copy-paste")]
use crate::clipboard::try_empty_clipboard_files;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use crate::clipboard::{update_clipboard, ClipboardSide};
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
use crate::clipboard_file::*;
use crate::input::{MOUSE_TYPE_MASK, MOUSE_TYPE_TRACKPAD, MOUSE_TYPE_WHEEL};
#[cfg(target_os = "android")]
use crate::keyboard::client::map_key_to_control_key;
#[cfg(target_os = "linux")]
use crate::platform::linux_desktop_manager;
#[cfg(any(target_os = "windows", target_os = "linux"))]
use crate::platform::WallPaperRemover;
// R-X9 (slices 2-4): the `portable_service::client as portable_client` import is excised
// with the portable run-mode (the CM RequestStart->start_portable_service trigger and the
// portable_check running-state probe are removed below).
#[cfg(windows)]
use crate::virtual_display_manager;
use crate::{
    client::{
        native_opus_format_admission, native_opus_format_key, native_opus_format_within_limit,
        new_voice_call_request, new_voice_call_response, start_audio_thread, MediaData,
        NativeOpusFormatAdmission, OwnedMediaThread,
    },
    display_service, ipc, privacy_mode, video_service, VERSION,
};
#[cfg(any(target_os = "android", target_os = "ios"))]
use crate::{common::DEVICE_NAME, flutter::connection_manager::start_channel};
#[cfg(any(target_os = "macos", target_os = "windows", test))]
use hbb_common::anyhow::anyhow;
#[cfg(target_os = "android")]
use hbb_common::protobuf::EnumOrUnknown;
use hbb_common::tokio::sync::oneshot;
use hbb_common::{
    config::{self, keys, Config},
    fs::{self, can_enable_overwrite_detection, JobType},
    futures::{future::BoxFuture, stream::FuturesUnordered, FutureExt, SinkExt, StreamExt},
    get_time, get_version_number,
    message_proto::{option_message::BoolOption, permission_info::Permission},
    sleep, timeout,
    tokio::{
        net::TcpStream,
        sync::mpsc,
        time::{self, Duration, Instant},
    },
    tokio_util::codec::{BytesCodec, Framed},
    VIDEO_FRAME_RECEIPT_VERSION,
};
#[cfg(target_os = "android")]
use scrap::android::{
    call_main_service_key_event_for_generation, call_main_service_pointer_input_for_generation,
};
use scrap::camera;
use serde_derive::Serialize;
use serde_json::{json, value::Value};
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use std::sync::{atomic::AtomicUsize, mpsc as std_mpsc, Condvar};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    num::NonZeroI64,
    path::PathBuf,
    sync::{
        atomic::{AtomicI64, Ordering},
        Mutex as StdMutex,
    },
};
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use system_shutdown;
pub type Sender = mpsc::UnboundedSender<(Instant, Arc<Message>)>;
// R-F1/R-D6/R-S5/R-A9: port-forward/RDP relay tuning. The R-T3 writer-task refactor removed the old
// SEND_TIMEOUT_*/H1 consts, so the sealed tunnel loop carries its own. SEND bounds a write to the
// LOCAL target socket (a stuck local service must not stall the relay); IDLE tears down a silent
// tunnel (mirrors upstream H1 = 1 h). The relay rides the KEYED session stream — send_bytes SEALS,
// next() decrypts — and NEVER set_raw's (R-A3), so every byte on the wire is ciphertext (R-A9).
const PORT_FORWARD_SEND_TIMEOUT: u64 = 120_000;
const PORT_FORWARD_IDLE_TIMEOUT: Duration = Duration::from_secs(3600);
const MAX_PEER_DISPLAY_DIMENSION: i32 = 16_384;
const MAX_PEER_CAPTURE_DISPLAY_ENTRIES: usize = 32;
const DISPLAY_CONTROL_LOG_INTERVAL: Duration = Duration::from_secs(5);
const MAX_CM_FILE_ERROR_BYTES: usize = 4096;
const MAX_PENDING_CM_FILE_REQUESTS: usize = 32;
const CM_FILE_BLOCK_READ_TIMEOUT_MS: u64 = 5_000;
const CM_COMMAND_QUEUE_CAPACITY: usize = 2;
const CM_COMMAND_QUEUE_SEND_TIMEOUT: Duration = Duration::from_secs(5);
const CM_IPC_COMMAND_SEND_TIMEOUT_MS: u64 = 5_000;
const CM_OWNER_TERMINAL_DRAIN_TIMEOUT: Duration = Duration::from_secs(6);
const MAX_PENDING_CONTROLLED_FILE_WRITES: usize = 256;
const MAX_PENDING_CONTROLLED_FILE_WRITE_BYTES: usize = hbb_common::cpace::MAX_SESSION_PACKET * 2;
const CONTROLLED_FILE_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const INPUT_QUEUE_CAPACITY: usize = 256;
const INPUT_QUEUE_MAX_BYTES: usize = 256 * 1024;
const INPUT_EVENT_MAX_BYTES: usize = 4 * 1024;
const INPUT_KEY_SEQUENCE_MAX_BYTES: usize = 1024;
const INPUT_MODIFIER_MAX_ENTRIES: usize = 16;
const INPUT_SCROLL_MAX_DELTA: i32 = 64;

fn capture_display_has_exactly_one_operation(displays: &CaptureDisplays) -> bool {
    usize::from(!displays.add.is_empty())
        + usize::from(!displays.sub.is_empty())
        + usize::from(!displays.set.is_empty())
        == 1
}

fn switch_display_resolution_is_well_formed(width: i32, height: i32) -> bool {
    (width == 0 && height == 0)
        || (width > 0
            && height > 0
            && width <= MAX_PEER_DISPLAY_DIMENSION
            && height <= MAX_PEER_DISPLAY_DIMENSION)
}

#[derive(Default)]
struct DisplayControlRejectLog {
    last_log_at: Option<Instant>,
    suppressed: u64,
}

impl DisplayControlRejectLog {
    fn on_reject(&mut self) -> Option<u64> {
        let now = Instant::now();
        if let Some(last) = self.last_log_at {
            if now.saturating_duration_since(last) < DISPLAY_CONTROL_LOG_INTERVAL {
                self.suppressed += 1;
                return None;
            }
        }
        self.last_log_at = Some(now);
        Some(std::mem::take(&mut self.suppressed))
    }
}

#[derive(Debug)]
enum CmReadPhase {
    Initializing,
    Reading { file_num: i32 },
    AwaitingPeerConfirm { file_num: i32 },
}

#[derive(Debug)]
struct CmReadAuthority {
    generation: u64,
    phase: CmReadPhase,
    path: String,
    first_file_num: i32,
    file_count: Option<usize>,
}

#[derive(Debug)]
enum CmWritePhase {
    Active,
    CheckingDigest {
        request_id: u64,
        file_num: i32,
    },
    AwaitingPeerConfirm {
        file_num: i32,
    },
    Finalizing {
        file_num: i32,
        peer_error: Option<String>,
    },
}

#[derive(Debug)]
struct CmWriteAuthority {
    generation: u64,
    phase: CmWritePhase,
}

#[derive(Debug)]
enum CmFileRequestAuthority {
    ReadDirectory {
        id: i32,
        path: String,
    },
    ReadEmptyDirectories {
        path: String,
    },
    AllFiles {
        id: i32,
        path: String,
    },
    Operation {
        id: i32,
        file_num: i32,
        operation: ipc::CmFileOperation,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlledFileWriteKind {
    Response,
    TransferData,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ControlledFileWriteContext {
    job_id: Option<i32>,
    file_num: i32,
    operation: &'static str,
    kind: ControlledFileWriteKind,
}

impl ControlledFileWriteContext {
    fn response(job_id: Option<i32>, file_num: i32, operation: &'static str) -> Self {
        Self {
            job_id,
            file_num,
            operation,
            kind: ControlledFileWriteKind::Response,
        }
    }

    fn transfer_data(job_id: Option<i32>, file_num: i32) -> Self {
        Self {
            job_id,
            file_num,
            operation: "controlled file transfer data",
            kind: ControlledFileWriteKind::TransferData,
        }
    }
}

#[derive(Clone, Copy)]
struct ControlledFileWriteLimits {
    count: usize,
    bytes: usize,
    timeout: Duration,
}

const CONTROLLED_FILE_WRITE_LIMITS: ControlledFileWriteLimits = ControlledFileWriteLimits {
    count: MAX_PENDING_CONTROLLED_FILE_WRITES,
    bytes: MAX_PENDING_CONTROLLED_FILE_WRITE_BYTES,
    timeout: CONTROLLED_FILE_WRITE_TIMEOUT,
};

#[derive(Debug)]
struct ControlledFileWriteReservation {
    id: u64,
}

struct ControlledFileWriteCompletion {
    context: Option<ControlledFileWriteContext>,
    result: Result<(), String>,
}

struct ControlledFileWriteTracker {
    next_id: u64,
    pending_bytes: usize,
    limits: ControlledFileWriteLimits,
    contexts: HashMap<u64, (ControlledFileWriteContext, usize)>,
    completions: FuturesUnordered<BoxFuture<'static, (u64, Result<(), String>)>>,
}

impl ControlledFileWriteTracker {
    fn new() -> Self {
        Self::with_limits(CONTROLLED_FILE_WRITE_LIMITS)
    }

    fn with_limits(limits: ControlledFileWriteLimits) -> Self {
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
        context: ControlledFileWriteContext,
        bytes: usize,
    ) -> Result<ControlledFileWriteReservation, String> {
        if self.contexts.len() >= self.limits.count {
            return Err(format!(
                "controlled file writer completion capacity reached (limit {})",
                self.limits.count
            ));
        }
        let pending_bytes = self
            .pending_bytes
            .checked_add(bytes)
            .ok_or_else(|| "controlled file writer byte accounting overflowed".to_owned())?;
        if pending_bytes > self.limits.bytes {
            return Err(format!(
                "controlled file writer byte capacity reached ({} pending + {} bytes; limit {})",
                self.pending_bytes, bytes, self.limits.bytes
            ));
        }
        let id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| "controlled file writer completion sequence exhausted".to_owned())?;
        if self.contexts.contains_key(&id) {
            return Err("controlled file writer completion identity was reused".to_owned());
        }
        self.next_id = id;
        self.pending_bytes = pending_bytes;
        self.contexts.insert(id, (context, bytes));
        Ok(ControlledFileWriteReservation { id })
    }

    fn attach(
        &mut self,
        reservation: ControlledFileWriteReservation,
        receipt: hbb_common::tcp::WriterReceipt,
    ) -> Result<(), String> {
        if !self.contexts.contains_key(&reservation.id) {
            return Err("controlled file writer reservation was lost before attachment".to_owned());
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
        reservation: ControlledFileWriteReservation,
    ) -> Result<Option<ControlledFileWriteContext>, String> {
        let Some((context, bytes)) = self.contexts.remove(&reservation.id) else {
            return Ok(None);
        };
        self.pending_bytes = self
            .pending_bytes
            .checked_sub(bytes)
            .ok_or_else(|| "controlled file writer byte accounting underflowed".to_owned())?;
        Ok(Some(context))
    }

    fn is_empty(&self) -> bool {
        self.contexts.is_empty()
    }

    fn has_transfer_data(&self) -> bool {
        self.contexts
            .values()
            .any(|(context, _)| context.kind == ControlledFileWriteKind::TransferData)
    }

    async fn next(&mut self) -> Option<ControlledFileWriteCompletion> {
        let (id, mut result) = self.completions.next().await?;
        let context = match self.contexts.remove(&id) {
            Some((context, bytes)) => {
                match self.pending_bytes.checked_sub(bytes) {
                    Some(pending_bytes) => self.pending_bytes = pending_bytes,
                    None => {
                        self.pending_bytes = 0;
                        result =
                            Err("controlled file writer byte accounting underflowed".to_owned());
                    }
                }
                Some(context)
            }
            None => {
                result =
                    Err("controlled file writer completion identity was not pending".to_owned());
                None
            }
        };
        Some(ControlledFileWriteCompletion { context, result })
    }

    fn retire(&mut self) -> Vec<ControlledFileWriteContext> {
        self.completions = FuturesUnordered::new();
        self.pending_bytes = 0;
        self.contexts
            .drain()
            .map(|(_, (context, _))| context)
            .collect()
    }
}

fn controlled_file_response_context(message: &Message) -> Option<ControlledFileWriteContext> {
    let Some(message::Union::FileResponse(response)) = message.union.as_ref() else {
        return None;
    };
    Some(match response.union.as_ref() {
        Some(file_response::Union::Dir(value)) => {
            ControlledFileWriteContext::response(Some(value.id), -1, "file directory response")
        }
        Some(file_response::Union::Block(value)) => ControlledFileWriteContext::response(
            Some(value.id),
            value.file_num,
            "file block response",
        ),
        Some(file_response::Union::Error(value)) => ControlledFileWriteContext::response(
            Some(value.id),
            value.file_num,
            "file error response",
        ),
        Some(file_response::Union::Done(value)) => ControlledFileWriteContext::response(
            Some(value.id),
            value.file_num,
            "file completion response",
        ),
        Some(file_response::Union::Digest(value)) => ControlledFileWriteContext::response(
            Some(value.id),
            value.file_num,
            "file digest response",
        ),
        Some(file_response::Union::EmptyDirs(_)) => {
            ControlledFileWriteContext::response(None, -1, "empty-directory response")
        }
        Some(_) => ControlledFileWriteContext::response(None, -1, "unknown file response"),
        None => ControlledFileWriteContext::response(None, -1, "empty file response"),
    })
}

async fn enqueue_controlled_file_message(
    file_writes: &mut ControlledFileWriteTracker,
    stream: &mut super::Stream,
    message: &Message,
    context: ControlledFileWriteContext,
) -> Result<(), String> {
    let payload_bytes = usize::try_from(message.compute_size())
        .map_err(|_| "controlled file message size does not fit usize".to_owned())?;
    let retained_bytes = payload_bytes
        .checked_add(hbb_common::sodiumoxide::crypto::secretbox::MACBYTES)
        .ok_or_else(|| "controlled file message size accounting overflowed".to_owned())?;
    let reservation = file_writes.reserve(context, retained_bytes)?;
    let receipt = match stream.send_with_receipt(message).await {
        Ok(receipt) => receipt,
        Err(err) => {
            let cancel_result = file_writes.cancel(reservation);
            return match cancel_result {
                Ok(_) => Err(format!(
                    "failed to admit controlled file message to transport writer: {err}"
                )),
                Err(cancel_err) => Err(format!(
                    "failed to admit controlled file message to transport writer: {err}; {cancel_err}"
                )),
            };
        }
    };
    file_writes.attach(reservation, receipt)
}

async fn enqueue_controlled_file_transfer_step(
    file_writes: &mut ControlledFileWriteTracker,
    read_jobs: &mut Vec<fs::TransferJob>,
    stream: &mut super::Stream,
    context: ControlledFileWriteContext,
) -> Result<String, String> {
    let reservation = file_writes.reserve(context, hbb_common::cpace::MAX_SESSION_PACKET)?;
    let (log, receipt) = match fs::handle_read_jobs(read_jobs, stream).await {
        Ok(result) => result,
        Err(err) => {
            let cancel_result = file_writes.cancel(reservation);
            return match cancel_result {
                Ok(_) => Err(err.to_string()),
                Err(cancel_err) => Err(format!(
                    "controlled file transfer producer failed: {err}; {cancel_err}"
                )),
            };
        }
    };
    let Some(receipt) = receipt else {
        return match file_writes.cancel(reservation) {
            Ok(Some(_)) => Ok(log),
            Ok(None) => {
                Err("controlled file writer reservation disappeared before cancellation".to_owned())
            }
            Err(err) => Err(err),
        };
    };
    file_writes.attach(reservation, receipt)?;
    Ok(log)
}

// R-T1(a) (§20): a self-enforced hard cap on concurrent AUTHORIZED sessions — the post-key
// population the pre-key handshake semaphore (R-T1(b)) does not cover. Bounds a descriptor/session
// runaway (a leak, or a password-knower looping reconnects) under ANY launcher, not only the
// systemd cgroup. A single owner never has this many concurrent sessions.
const MAX_AUTHED_SESSIONS: usize = 16;

lazy_static::lazy_static! {
    // R-T15(b)/R-S10: the inherited LOGIN_FAILURES limiter is excised (see update/check_failure) —
    // an unbounded/never-decaying/full-IPv6-keyed map on dead paths; CPace's GUESS_FAILURES is live.
    static ref ALIVE_CONNS: Arc::<Mutex<Vec<i32>>> = Default::default();
    pub static ref AUTHED_CONNS: Arc::<Mutex<Vec<AuthedConn>>> = Default::default();
    pub static ref CONTROL_PERMISSIONS_ARRAY: Arc::<Mutex<Vec<(i32, ControlPermissions)>>> = Default::default();
    static ref WAKELOCK_SENDER: Arc::<Mutex<std::sync::mpsc::Sender<(usize, usize)>>> = Arc::new(Mutex::new(start_wakelock_thread()));
    static ref WAKELOCK_KEEP_AWAKE_OPTION: Arc::<Mutex<Option<bool>>> = Default::default();
}

#[cfg(target_os = "linux")]
lazy_static::lazy_static! {
    static ref CM_PEER_IDENTITIES: Arc::<Mutex<Vec<(i32, crate::ipc::LinuxProcessIdentity)>>> = Default::default();
}

#[cfg(target_os = "linux")]
lazy_static::lazy_static! {
    static ref CM_LAUNCH_TOKEN: String = crate::encode64(hbb_common::rand::random::<[u8; 32]>());
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
trait CmOwnedProcess: Send {
    type Identity: Copy + Eq + fmt::Debug;

    fn identity(&self) -> Self::Identity;
    fn try_reap_exited(&mut self) -> ResultType<bool>;
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
struct CmProcessGeneration<P: CmOwnedProcess> {
    role: &'static str,
    launch_token: String,
    identity: P::Identity,
    process: StdMutex<P>,
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
fn lease_existing_cm_process<P: CmOwnedProcess>(
    state: &StdMutex<Option<Arc<CmProcessGeneration<P>>>>,
    expected_role: &'static str,
) -> ResultType<Arc<CmProcessGeneration<P>>> {
    let state = state
        .lock()
        .map_err(|_| anyhow!("connection-manager process state lock poisoned"))?;
    let generation = state
        .as_ref()
        .ok_or_else(|| anyhow!("no server-owned connection-manager generation"))?;
    if generation.role != expected_role {
        bail!(
            "connection-manager role mismatch: expected {}, retained {}",
            expected_role,
            generation.role
        );
    }
    Ok(generation.clone())
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
fn lease_or_launch_cm_process<P, F>(
    state: &StdMutex<Option<Arc<CmProcessGeneration<P>>>>,
    role: &'static str,
    launch: F,
) -> ResultType<Arc<CmProcessGeneration<P>>>
where
    P: CmOwnedProcess,
    F: FnOnce(&str) -> ResultType<P>,
{
    let mut state = state
        .lock()
        .map_err(|_| anyhow!("connection-manager process state lock poisoned"))?;
    if let Some(generation) = state.as_ref() {
        if generation.role != role {
            bail!(
                "connection-manager role mismatch: requested {}, retained {}",
                role,
                generation.role
            );
        }
        let exited = if Arc::strong_count(generation) == 1 {
            generation
                .process
                .lock()
                .map_err(|_| anyhow!("connection-manager child lock poisoned"))?
                .try_reap_exited()?
        } else {
            false
        };
        if !exited {
            return Ok(generation.clone());
        }
        state.take();
    }

    let launch_token = crate::encode64(hbb_common::rand::random::<[u8; 32]>());
    let process = launch(&launch_token)?;
    let generation = Arc::new(CmProcessGeneration {
        role,
        launch_token,
        identity: process.identity(),
        process: StdMutex::new(process),
    });
    *state = Some(generation.clone());
    Ok(generation)
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
fn retire_failed_cm_process_if_exited<P: CmOwnedProcess>(
    state: &StdMutex<Option<Arc<CmProcessGeneration<P>>>>,
    failed: &Arc<CmProcessGeneration<P>>,
) -> ResultType<()> {
    let mut state = state
        .lock()
        .map_err(|_| anyhow!("connection-manager process state lock poisoned"))?;
    let Some(current) = state.as_ref() else {
        return Ok(());
    };
    if !Arc::ptr_eq(current, failed) || Arc::strong_count(current) != 2 {
        return Ok(());
    }
    let exited = current
        .process
        .lock()
        .map_err(|_| anyhow!("connection-manager child lock poisoned"))?
        .try_reap_exited()?;
    if exited {
        state.take();
    }
    Ok(())
}

#[cfg(target_os = "macos")]
struct MacosCmProcess(std::process::Child);

#[cfg(target_os = "macos")]
impl CmOwnedProcess for MacosCmProcess {
    type Identity = u32;

    fn identity(&self) -> Self::Identity {
        self.0.id()
    }

    fn try_reap_exited(&mut self) -> ResultType<bool> {
        self.0
            .try_wait()
            .map(|status| status.is_some())
            .map_err(|err| anyhow!("failed to reap connection-manager child: {err}"))
    }
}

#[cfg(target_os = "windows")]
impl CmOwnedProcess for crate::platform::WindowsConnectionManagerProcess {
    type Identity = crate::ipc::WindowsProcessIdentityKey;

    fn identity(&self) -> Self::Identity {
        crate::platform::WindowsConnectionManagerProcess::identity(self)
    }

    fn try_reap_exited(&mut self) -> ResultType<bool> {
        crate::platform::WindowsConnectionManagerProcess::try_reap_exited(self)
    }
}

#[cfg(target_os = "macos")]
type PlatformCmProcess = MacosCmProcess;
#[cfg(target_os = "windows")]
type PlatformCmProcess = crate::platform::WindowsConnectionManagerProcess;

#[cfg(any(target_os = "macos", target_os = "windows"))]
lazy_static::lazy_static! {
    static ref OWNED_CM_PROCESS: StdMutex<Option<Arc<CmProcessGeneration<PlatformCmProcess>>>> =
        StdMutex::new(None);
}

#[cfg(target_os = "linux")]
struct CmPeerIdentityRegistration {
    conn_id: i32,
}

#[cfg(target_os = "linux")]
impl Drop for CmPeerIdentityRegistration {
    fn drop(&mut self) {
        clear_cm_peer_identity_for_conn(self.conn_id);
    }
}

#[cfg(target_os = "linux")]
fn register_cm_peer_identity_for_conn(
    conn_id: i32,
    cm_peer_identity: crate::ipc::LinuxProcessIdentity,
) -> ResultType<CmPeerIdentityRegistration> {
    if conn_id <= 0 || cm_peer_identity.pid() == 0 {
        bail!("invalid connection-manager peer identity");
    }
    let mut peer_identities = CM_PEER_IDENTITIES.lock().unwrap();
    if let Some((_, peer_identity)) = peer_identities.iter_mut().find(|(id, _)| *id == conn_id) {
        *peer_identity = cm_peer_identity;
    } else {
        peer_identities.push((conn_id, cm_peer_identity));
    }
    Ok(CmPeerIdentityRegistration { conn_id })
}

#[cfg(target_os = "linux")]
pub(crate) fn clear_cm_peer_identity_for_conn(conn_id: i32) {
    CM_PEER_IDENTITIES
        .lock()
        .unwrap()
        .retain(|(id, _)| *id != conn_id);
}

#[cfg(target_os = "linux")]
pub(crate) fn expected_cm_peer_identity_for_conn_ids(
    conn_ids: &[i32],
) -> ResultType<crate::ipc::LinuxProcessIdentity> {
    if conn_ids.is_empty() {
        bail!("no active audio subscriber");
    }

    let peer_identities = CM_PEER_IDENTITIES.lock().unwrap();
    let mut expected_peer_identity = None;
    for conn_id in conn_ids {
        let Some((_, cm_peer_identity)) = peer_identities.iter().find(|(id, _)| id == conn_id)
        else {
            bail!(
                "missing connection-manager peer identity for audio subscriber {}",
                conn_id
            );
        };
        if !crate::ipc::linux_cm_child_identity_is_live(cm_peer_identity, std::process::id()) {
            bail!(
                "stale connection-manager peer identity for audio subscriber {}",
                conn_id
            );
        }
        match &expected_peer_identity {
            Some(expected) if expected != cm_peer_identity => {
                bail!("audio subscribers span multiple connection-manager processes")
            }
            Some(_) => {}
            None => expected_peer_identity = Some(cm_peer_identity.clone()),
        }
    }

    let Some(expected_peer_identity) = expected_peer_identity else {
        bail!("missing connection-manager peer identity for audio subscribers");
    };
    Ok(expected_peer_identity)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // Avoid data-dependent early exits.
    let mut x: u8 = 0;
    for i in 0..a.len() {
        x |= a[i] ^ b[i];
    }
    x == 0
}

fn cm_file_response_session_authorized(
    authorized: bool,
    is_file_transfer: bool,
    expected_conn_id: i32,
    expected_token: &str,
    response_conn_id: i32,
    response_token: &str,
) -> bool {
    authorized
        && is_file_transfer
        && cm_file_response_matches_connection(
            expected_conn_id,
            expected_token,
            response_conn_id,
            response_token,
        )
}

fn cm_file_response_matches_connection(
    expected_conn_id: i32,
    expected_token: &str,
    response_conn_id: i32,
    response_token: &str,
) -> bool {
    !expected_token.is_empty()
        && response_conn_id == expected_conn_id
        && constant_time_eq(response_token.as_bytes(), expected_token.as_bytes())
}

fn cm_file_request_session_authorized(
    authorized: bool,
    is_file_transfer: bool,
    file_capability: bool,
    cm_file_login_published: bool,
) -> bool {
    authorized && is_file_transfer && file_capability && cm_file_login_published
}

fn cm_read_file_num_authorized(
    authority: &CmReadAuthority,
    file_num: i32,
    allow_terminal_index: bool,
) -> bool {
    if file_num < authority.first_file_num {
        return false;
    }
    let Some(file_count) = authority.file_count else {
        return false;
    };
    let Ok(file_num) = usize::try_from(file_num) else {
        return false;
    };
    file_num < file_count || (allow_terminal_index && file_num == file_count)
}

fn cm_read_progress_authorized(authority: &CmReadAuthority, file_num: i32) -> bool {
    if !cm_read_file_num_authorized(authority, file_num, false) {
        return false;
    }
    matches!(
        authority.phase,
        CmReadPhase::Reading {
            file_num: current_file_num,
        } if file_num == current_file_num
            || current_file_num.checked_add(1) == Some(file_num)
    )
}

fn cm_read_terminal_authorized(authority: &CmReadAuthority, file_num: i32, done: bool) -> bool {
    if !cm_read_file_num_authorized(authority, file_num, true) {
        return false;
    }
    match authority.phase {
        CmReadPhase::Reading {
            file_num: _current_file_num,
        } if done => authority.file_count == usize::try_from(file_num).ok(),
        CmReadPhase::Reading {
            file_num: current_file_num,
        } => file_num == current_file_num || current_file_num.checked_add(1) == Some(file_num),
        CmReadPhase::AwaitingPeerConfirm {
            file_num: expected_file_num,
        } => !done && expected_file_num == file_num,
        CmReadPhase::Initializing => false,
    }
}

fn active_cm_write_authority_generation(
    jobs: &HashMap<i32, CmWriteAuthority>,
    id: i32,
) -> Option<u64> {
    let authority = jobs.get(&id)?;
    if matches!(authority.phase, CmWritePhase::Active) {
        Some(authority.generation)
    } else {
        None
    }
}

fn cm_write_finalization_authorized(phase: &CmWritePhase, is_peer_error: bool) -> bool {
    matches!(phase, CmWritePhase::Active)
        || (is_peer_error
            && matches!(
                phase,
                CmWritePhase::CheckingDigest { .. } | CmWritePhase::AwaitingPeerConfirm { .. }
            ))
}

// R-X14 / R-T15 (line 254): the Linux-headless OS-auth limiter helpers
// (should_check/should_record_linux_headless_os_auth_*) are excised — the inherited per-site
// failure counter for the headless OS-login is gone (the limiter is reconstituted wholesale at the
// CPace key-confirmation choke point, R-P14c). The os_login->PAM desktop-start they guarded was
// already removed (linux_desktop_manager, 62177b1); headless is also policy-pinned off (R-S16).

// R-X8: should_use_terminal_os_login_scope removed — the terminal is SessionUser-only
// (one PAKE password -> the service user's shell, R-F1); no peer-supplied OS credential.

#[cfg(any(target_os = "windows", target_os = "linux"))]
lazy_static::lazy_static! {
    static ref WALLPAPER_REMOVER: Arc<Mutex<Option<WallPaperRemover>>> = Default::default();
}
pub static CLICK_TIME: AtomicI64 = AtomicI64::new(0);

const AUDIO_EGRESS_WAKE_CAPACITY: usize = 1;
const VIDEO_EGRESS_WAKE_CAPACITY: usize = 1;
const VIDEO_EGRESS_MAX_DISPLAYS: usize = 32;

#[derive(Default)]
struct AudioEgressState {
    format: Option<(Instant, Arc<Message>)>,
    frame: Option<(Instant, Arc<Message>)>,
}

#[derive(Clone)]
pub(crate) struct AudioEgressSender {
    state: Arc<Mutex<AudioEgressState>>,
    wake: mpsc::Sender<()>,
}

pub(crate) struct AudioEgressReceiver {
    state: Arc<Mutex<AudioEgressState>>,
    wake: mpsc::Receiver<()>,
}

pub(crate) fn audio_egress_channel() -> (AudioEgressSender, AudioEgressReceiver) {
    let state = Arc::new(Mutex::new(AudioEgressState::default()));
    let (wake, receiver) = mpsc::channel(AUDIO_EGRESS_WAKE_CAPACITY);
    (
        AudioEgressSender {
            state: Arc::clone(&state),
            wake,
        },
        AudioEgressReceiver {
            state,
            wake: receiver,
        },
    )
}

fn lock_audio_egress_state(
    state: &Mutex<AudioEgressState>,
) -> std::sync::MutexGuard<'_, AudioEgressState> {
    match state.lock() {
        Ok(state) => state,
        Err(poisoned) => {
            log::error!("audio egress state was poisoned");
            poisoned.into_inner()
        }
    }
}

impl AudioEgressSender {
    pub(crate) fn send(&self, msg: Arc<Message>) {
        let queued = (Instant::now(), msg);
        {
            let mut state = lock_audio_egress_state(&self.state);
            match &queued.1.union {
                Some(message::Union::AudioFrame(_)) => {
                    state.frame = Some(queued);
                }
                Some(message::Union::Misc(misc))
                    if matches!(&misc.union, Some(misc::Union::AudioFormat(_))) =>
                {
                    // A new codec generation must be observed before any frame encoded for it.
                    // Retire a pending old-generation frame rather than delivering it afterwards.
                    state.format = Some(queued);
                    state.frame = None;
                }
                _ => {
                    log::error!("refusing a non-audio message on the audio egress mailbox");
                    return;
                }
            }
        }

        match self.wake.try_send(()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // The receiver is terminal. Release any retained local audio immediately even if
                // an exact service unsubscribe is still propagating.
                let mut state = lock_audio_egress_state(&self.state);
                state.format = None;
                state.frame = None;
            }
        }
    }
}

impl AudioEgressReceiver {
    fn take_next(&mut self) -> Option<(Instant, Arc<Message>)> {
        let mut state = lock_audio_egress_state(&self.state);
        state.format.take().or_else(|| state.frame.take())
    }

    pub(crate) async fn recv(&mut self) -> Option<(Instant, Arc<Message>)> {
        loop {
            if let Some(queued) = self.take_next() {
                return Some(queued);
            }
            self.wake.recv().await?;
        }
    }

    #[cfg(test)]
    fn blocking_recv(&mut self) -> Option<(Instant, Arc<Message>)> {
        loop {
            if let Some(queued) = self.take_next() {
                return Some(queued);
            }
            self.wake.blocking_recv()?;
        }
    }
}

impl Drop for AudioEgressReceiver {
    fn drop(&mut self) {
        self.wake.close();
        let mut state = lock_audio_egress_state(&self.state);
        state.format = None;
        state.frame = None;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VideoFrameIdentity {
    source: VideoSource,
    display: usize,
    generation: u64,
}

pub(crate) struct VideoEgressFrame {
    queued_at: Instant,
    message: Arc<Message>,
    identity: VideoFrameIdentity,
}

impl VideoEgressFrame {
    fn identity(&self) -> VideoFrameIdentity {
        self.identity
    }

    #[cfg(test)]
    pub(crate) fn test_identity_generation(&self) -> u64 {
        self.identity.generation
    }

    #[cfg(test)]
    pub(crate) fn test_wire_generation(&self) -> Option<u64> {
        match self.message.union.as_ref() {
            Some(message::Union::VideoFrame(frame)) => Some(frame.generation),
            _ => None,
        }
    }
}

struct PendingVideoDelivery {
    writer_receipt: Option<hbb_common::tcp::WriterReceipt>,
    identity: VideoFrameIdentity,
    queued_at: Instant,
    writer_complete: bool,
    peer_received: bool,
}

impl PendingVideoDelivery {
    fn new(writer_receipt: hbb_common::tcp::WriterReceipt, frame: &VideoEgressFrame) -> Self {
        Self {
            writer_receipt: Some(writer_receipt),
            identity: frame.identity,
            queued_at: frame.queued_at,
            writer_complete: false,
            peer_received: false,
        }
    }

    fn writer_pending(&self) -> bool {
        self.writer_receipt.is_some()
    }

    fn mark_writer_complete(&mut self) {
        self.writer_receipt = None;
        self.writer_complete = true;
    }

    fn observe_peer_receipt(
        &mut self,
        authenticated_source: Option<VideoSource>,
        receipt: &VideoFrameReceipt,
    ) -> bool {
        if self.peer_received
            || authenticated_source != Some(self.identity.source)
            || usize::try_from(receipt.display).ok() != Some(self.identity.display)
            || receipt.generation == 0
            || receipt.generation != self.identity.generation
        {
            return false;
        }
        self.peer_received = true;
        true
    }

    fn is_complete(&self) -> bool {
        self.writer_complete && self.peer_received
    }
}

async fn wait_for_video_write(
    pending: &mut Option<PendingVideoDelivery>,
) -> Result<std::io::Result<()>, oneshot::error::RecvError> {
    if let Some(receipt) = pending
        .as_mut()
        .and_then(|pending| pending.writer_receipt.as_mut())
    {
        receipt.await
    } else {
        std::future::pending().await
    }
}

fn complete_video_delivery(pending: &mut Option<PendingVideoDelivery>, connection_id: i32) {
    if !pending
        .as_ref()
        .map_or(false, PendingVideoDelivery::is_complete)
    {
        return;
    }
    let Some(pending) = pending.take() else {
        return;
    };
    video_service::notify_video_frame_fetched(
        pending.identity.source,
        pending.identity.display,
        pending.identity.generation,
        connection_id,
        Some(pending.queued_at.into()),
    );
}

pub(crate) enum VideoEgressItem {
    SwitchDisplay((Instant, Arc<Message>)),
    Frame(VideoEgressFrame),
    RefreshRequired { display: usize },
}

enum PendingVideoEgress {
    Frame(VideoEgressFrame),
    RefreshRequired,
}

struct VideoDisplayEgress {
    pending: Option<PendingVideoEgress>,
    awaiting_independent: bool,
    ready: bool,
}

impl Default for VideoDisplayEgress {
    fn default() -> Self {
        Self {
            pending: None,
            // A fresh or switched decoder has no GOP history. It must not receive a delta before
            // this mailbox has admitted an independently decodable key/raw frame.
            awaiting_independent: true,
            ready: false,
        }
    }
}

#[derive(Default)]
struct VideoEgressState {
    switch_display: Option<(Instant, Arc<Message>)>,
    displays: HashMap<usize, VideoDisplayEgress>,
    ready_displays: VecDeque<usize>,
}

#[derive(Clone)]
pub(crate) struct VideoEgressSender {
    state: Arc<StdMutex<VideoEgressState>>,
    wake: mpsc::Sender<()>,
}

pub(crate) struct VideoEgressReceiver {
    state: Arc<StdMutex<VideoEgressState>>,
    wake: mpsc::Receiver<()>,
    connection_id: Option<i32>,
}

pub(crate) fn video_egress_channel() -> (VideoEgressSender, VideoEgressReceiver) {
    let state = Arc::new(StdMutex::new(VideoEgressState::default()));
    let (wake, receiver) = mpsc::channel(VIDEO_EGRESS_WAKE_CAPACITY);
    (
        VideoEgressSender {
            state: Arc::clone(&state),
            wake,
        },
        VideoEgressReceiver {
            state,
            wake: receiver,
            connection_id: None,
        },
    )
}

fn lock_video_egress_state(
    state: &StdMutex<VideoEgressState>,
) -> std::sync::MutexGuard<'_, VideoEgressState> {
    match state.lock() {
        Ok(state) => state,
        Err(poisoned) => {
            log::error!("video egress state was poisoned");
            poisoned.into_inner()
        }
    }
}

impl VideoEgressSender {
    fn wake_receiver(&self) -> bool {
        match self.wake.try_send(()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => true,
            Err(mpsc::error::TrySendError::Closed(_)) => {
                let mut state = lock_video_egress_state(&self.state);
                state.switch_display = None;
                state.displays.clear();
                state.ready_displays.clear();
                false
            }
        }
    }

    fn mark_ready(state: &mut VideoEgressState, display: usize) {
        let Some(slot) = state.displays.get_mut(&display) else {
            return;
        };
        if !slot.ready {
            slot.ready = true;
            state.ready_displays.push_back(display);
        }
    }

    fn send_video_frame(
        &self,
        message: Arc<Message>,
        source: VideoSource,
        display: usize,
        generation: u64,
    ) -> Vec<VideoFrameIdentity> {
        let identity = VideoFrameIdentity {
            source,
            display,
            generation,
        };
        let Some(message::Union::VideoFrame(frame)) = &message.union else {
            log::error!("refusing a non-video-frame message on the video egress mailbox");
            return vec![identity];
        };
        if usize::try_from(frame.display).ok() != Some(display) {
            log::error!("refusing a controlled video frame whose display ownership mismatches");
            return vec![identity];
        }
        if generation == 0 || frame.generation != generation {
            log::error!("refusing a controlled video frame whose wire generation mismatches");
            return vec![identity];
        }
        let independent = crate::client::io_loop::starts_video_sequence(frame);
        let queued = VideoEgressFrame {
            queued_at: Instant::now(),
            message,
            identity,
        };
        let mut retired = Vec::new();
        {
            let mut state = lock_video_egress_state(&self.state);
            if !state.displays.contains_key(&display)
                && state.displays.len() >= VIDEO_EGRESS_MAX_DISPLAYS
            {
                log::error!(
                    "controlled video egress display capacity {} reached",
                    VIDEO_EGRESS_MAX_DISPLAYS
                );
                return vec![identity];
            }
            let slot = state.displays.entry(display).or_default();
            let previous = slot.pending.take();
            if let Some(PendingVideoEgress::Frame(previous)) = &previous {
                retired.push(previous.identity());
            }
            if independent {
                slot.awaiting_independent = false;
                slot.pending = Some(PendingVideoEgress::Frame(queued));
            } else if slot.awaiting_independent {
                retired.push(identity);
                slot.pending = Some(PendingVideoEgress::RefreshRequired);
            } else if previous.is_some() {
                // Replacing a dependent frame would make the replacement undecodable. Retire the
                // pending GOP and ask the encoder for a new independently decodable sequence.
                retired.push(identity);
                slot.awaiting_independent = true;
                slot.pending = Some(PendingVideoEgress::RefreshRequired);
            } else {
                slot.pending = Some(PendingVideoEgress::Frame(queued));
            }
            Self::mark_ready(&mut state, display);
        }
        if !self.wake_receiver() && !retired.contains(&identity) {
            // A stale service subscriber can race exact connection teardown. Once the receiver is
            // closed, this frame has no consumer and its newly prepared round must be retired by
            // the sender that still owns the connection ID.
            retired.push(identity);
        }
        retired
    }

    fn send_switch_display(&self, message: Arc<Message>) -> Vec<VideoFrameIdentity> {
        let mut retired = Vec::new();
        {
            let mut state = lock_video_egress_state(&self.state);
            state.switch_display = Some((Instant::now(), message));
            retired.extend(
                state
                    .displays
                    .values()
                    .filter_map(|slot| match &slot.pending {
                        Some(PendingVideoEgress::Frame(frame)) => Some(frame.identity()),
                        _ => None,
                    }),
            );
            state.displays.clear();
            state.ready_displays.clear();
        }
        self.wake_receiver();
        retired
    }
}

impl VideoEgressReceiver {
    fn with_connection_owner(mut self, connection_id: i32) -> Self {
        self.connection_id = Some(connection_id);
        self
    }

    fn take_next(&mut self) -> Option<VideoEgressItem> {
        let mut state = lock_video_egress_state(&self.state);
        if let Some(switch) = state.switch_display.take() {
            return Some(VideoEgressItem::SwitchDisplay(switch));
        }
        while let Some(display) = state.ready_displays.pop_front() {
            let Some(slot) = state.displays.get_mut(&display) else {
                continue;
            };
            slot.ready = false;
            match slot.pending.take() {
                Some(PendingVideoEgress::Frame(frame)) => {
                    return Some(VideoEgressItem::Frame(frame));
                }
                Some(PendingVideoEgress::RefreshRequired) => {
                    return Some(VideoEgressItem::RefreshRequired { display });
                }
                None => {}
            }
        }
        None
    }

    pub(crate) async fn recv(&mut self) -> Option<VideoEgressItem> {
        loop {
            if let Some(item) = self.take_next() {
                return Some(item);
            }
            self.wake.recv().await?;
        }
    }

    #[cfg(test)]
    pub(crate) fn try_recv(&mut self) -> Option<VideoEgressItem> {
        self.take_next()
    }
}

impl Drop for VideoEgressReceiver {
    fn drop(&mut self) {
        self.wake.close();
        let mut state = lock_video_egress_state(&self.state);
        state.switch_display = None;
        state.displays.clear();
        state.ready_displays.clear();
        drop(state);
        if let Some(connection_id) = self.connection_id {
            // This receiver is local connection-lifetime authority. Retire after closing admission
            // so a concurrent or later stale subscriber either lands in this retirement or sees
            // the closed wake and retires its exact newly prepared generation itself.
            video_service::retire_video_frame_connection(connection_id);
        }
    }
}

#[derive(Clone, Default)]
pub struct ConnInner {
    id: i32,
    tx: Option<Sender>,
    tx_video: Option<VideoEgressSender>,
    tx_audio: Option<AudioEgressSender>,
    #[cfg(target_os = "windows")]
    cm_clipboard_authority: Option<ipc::CmClipboardAuthority>,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct InputMouse {
    msg: MouseEvent,
    conn_id: i32,
    username: String,
    argb: u32,
    simulate: bool,
    show_cursor: bool,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
enum MessageInput {
    Mouse(InputMouse),
    Key((KeyEvent, bool)),
    SpecialKey(KeyEvent),
    Pointer((PointerDeviceEvent, i32)),
    BlockOn,
    BlockOff,
}

fn protobuf_input_size<M: hbb_common::protobuf::Message>(message: &M) -> ResultType<usize> {
    usize::try_from(message.compute_size())
        .map_err(|_| hbb_common::anyhow::anyhow!("remote input event size is not representable"))
}

fn validate_mouse_input(event: &MouseEvent) -> ResultType<usize> {
    if event.modifiers.len() > INPUT_MODIFIER_MAX_ENTRIES {
        bail!("mouse input has too many modifiers");
    }
    let event_type = event.mask & MOUSE_TYPE_MASK;
    if event_type == MOUSE_TYPE_WHEEL || event_type == MOUSE_TYPE_TRACKPAD {
        for delta in [event.x, event.y] {
            let magnitude = delta
                .checked_abs()
                .ok_or_else(|| hbb_common::anyhow::anyhow!("scroll delta is not representable"))?;
            if magnitude > INPUT_SCROLL_MAX_DELTA {
                bail!("scroll delta exceeds its protocol limit");
            }
        }
    }
    validate_input_size(protobuf_input_size(event)?)
}

fn validate_key_input(event: &KeyEvent) -> ResultType<usize> {
    if event.modifiers.len() > INPUT_MODIFIER_MAX_ENTRIES {
        bail!("keyboard input has too many modifiers");
    }
    let mode = event
        .mode
        .enum_value()
        .map_err(|_| hbb_common::anyhow::anyhow!("keyboard input has an unknown mode"))?;
    let structurally_valid = match (mode, &event.union) {
        (KeyboardMode::Map, Some(key_event::Union::Chr(_))) => true,
        (
            KeyboardMode::Translate,
            Some(
                key_event::Union::Chr(_)
                | key_event::Union::Seq(_)
                | key_event::Union::ControlKey(_),
            ),
        ) => true,
        (KeyboardMode::Translate, Some(key_event::Union::Win2winHotkey(_))) => {
            cfg!(target_os = "windows")
        }
        (
            KeyboardMode::Legacy,
            Some(
                key_event::Union::Chr(_)
                | key_event::Union::Unicode(_)
                | key_event::Union::Seq(_)
                | key_event::Union::ControlKey(_),
            ),
        ) => true,
        _ => false,
    };
    if !structurally_valid {
        bail!("keyboard input mode and payload are inconsistent");
    }
    if let Some(key_event::Union::Win2winHotkey(code)) = &event.union {
        if event.press
            || (event.down && code & 0x0000_FFFF == 0)
            || (!event.down && code & 0x0000_FFFF != 0)
        {
            bail!("Win2win hotkey down/release shape is inconsistent");
        }
    }
    if matches!(
        &event.union,
        Some(key_event::Union::Seq(sequence)) if sequence.len() > INPUT_KEY_SEQUENCE_MAX_BYTES
    ) {
        bail!("keyboard sequence exceeds its structural limit");
    }
    validate_input_size(protobuf_input_size(event)?)
}

fn validate_pointer_input(event: &PointerDeviceEvent) -> ResultType<usize> {
    if event.modifiers.len() > INPUT_MODIFIER_MAX_ENTRIES {
        bail!("pointer input has too many modifiers");
    }
    validate_input_size(protobuf_input_size(event)?)
}

fn validate_input_size(payload_bytes: usize) -> ResultType<usize> {
    if payload_bytes > INPUT_EVENT_MAX_BYTES {
        bail!("remote input event exceeds its byte limit");
    }
    Ok(payload_bytes.max(1))
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl MessageInput {
    fn validated_weight(&self) -> ResultType<usize> {
        let payload_bytes = match self {
            Self::Mouse(input) => validate_mouse_input(&input.msg)?
                .checked_add(input.username.len())
                .ok_or_else(|| hbb_common::anyhow::anyhow!("remote mouse input size overflow"))?,
            Self::Key((event, _)) => validate_key_input(event)?,
            Self::SpecialKey(event) => validate_key_input(event)?,
            Self::Pointer((event, _)) => validate_pointer_input(event)?,
            Self::BlockOn | Self::BlockOff => 1,
        };
        validate_input_size(payload_bytes)
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct QueuedInput {
    input: Option<MessageInput>,
    weight: usize,
    queued_bytes: Arc<AtomicUsize>,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl Drop for QueuedInput {
    fn drop(&mut self) {
        self.queued_bytes.fetch_sub(self.weight, Ordering::AcqRel);
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct InputQueue {
    sender: std_mpsc::SyncSender<QueuedInput>,
    queued_bytes: Arc<AtomicUsize>,
    execution: Arc<InputExecutionGate>,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl InputQueue {
    fn try_enqueue(&self, input: MessageInput) -> ResultType<()> {
        if self.execution.is_cancelled() {
            bail!("remote input worker is stopping");
        }
        let weight = input.validated_weight()?;
        let mut current = self.queued_bytes.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(weight) else {
                bail!("remote input queue byte accounting overflow");
            };
            if next > INPUT_QUEUE_MAX_BYTES {
                bail!("remote input queue reached its byte capacity");
            }
            match self.queued_bytes.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        let queued = QueuedInput {
            input: Some(input),
            weight,
            queued_bytes: Arc::clone(&self.queued_bytes),
        };
        match self.sender.try_send(queued) {
            Ok(()) => Ok(()),
            Err(std_mpsc::TrySendError::Full(_)) => {
                bail!("remote input queue reached its item capacity")
            }
            Err(std_mpsc::TrySendError::Disconnected(_)) => {
                bail!("remote input worker is unavailable")
            }
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct InputWorker {
    execution: Arc<InputExecutionGate>,
    completion: Arc<InputWorkerCompletion>,
}

const INPUT_EXECUTION_CANCELLED: usize = 1;
const INPUT_EXECUTION_ACTIVE: usize = 2;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct InputWorkerCompletion {
    result: StdMutex<Option<bool>>,
    changed: Condvar,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl InputWorkerCompletion {
    fn new() -> Self {
        Self {
            result: StdMutex::new(None),
            changed: Condvar::new(),
        }
    }

    fn complete(&self, succeeded: bool) {
        let mut result = self.lock_result();
        *result = Some(succeeded);
        self.changed.notify_all();
    }

    fn wait(&self) -> bool {
        let mut result = self.lock_result();
        loop {
            if let Some(succeeded) = *result {
                return succeeded;
            }
            result = match self.changed.wait(result) {
                Ok(result) => result,
                Err(poisoned) => {
                    log::error!("remote input worker completion wait was poisoned");
                    poisoned.into_inner()
                }
            };
        }
    }

    fn lock_result(&self) -> std::sync::MutexGuard<'_, Option<bool>> {
        match self.result.lock() {
            Ok(result) => result,
            Err(poisoned) => {
                log::error!("remote input worker completion state was poisoned");
                poisoned.into_inner()
            }
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn spawn_input_worker_supervisor(
    name: String,
    queued_bytes: Arc<AtomicUsize>,
) -> std::io::Result<(
    std_mpsc::SyncSender<std::thread::JoinHandle<()>>,
    Arc<InputWorkerCompletion>,
)> {
    let (join_tx, join_rx) = std_mpsc::sync_channel::<std::thread::JoinHandle<()>>(1);
    let completion = Arc::new(InputWorkerCompletion::new());
    let supervisor_completion = Arc::clone(&completion);
    std::thread::Builder::new().name(name).spawn(move || {
        let succeeded = match join_rx.recv() {
            Ok(join) => {
                let succeeded = join.join().is_ok();
                if !succeeded {
                    log::error!("remote input worker panicked before supervisor join");
                }
                succeeded
            }
            Err(_) => {
                log::error!("remote input worker handle was not delivered to its supervisor");
                false
            }
        };
        let remaining = queued_bytes.load(Ordering::Acquire);
        if remaining != 0 {
            log::error!(
                "remote input worker exited with {remaining} bytes still charged to its queue"
            );
        }
        supervisor_completion.complete(succeeded);
    })?;
    Ok((join_tx, completion))
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Default)]
struct InputExecutionGate {
    state: AtomicUsize,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct InputDispatchGuard<'a> {
    gate: &'a InputExecutionGate,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl Drop for InputDispatchGuard<'_> {
    fn drop(&mut self) {
        self.gate
            .state
            .fetch_sub(INPUT_EXECUTION_ACTIVE, Ordering::AcqRel);
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl InputExecutionGate {
    fn is_cancelled(&self) -> bool {
        self.state.load(Ordering::Acquire) & INPUT_EXECUTION_CANCELLED != 0
    }

    fn cancel(&self) {
        // Revocation is nonblocking. A successful dispatch CAS defines an operation as
        // started/admitted even if its native body enters later; no operation can start after this.
        self.state
            .fetch_or(INPUT_EXECUTION_CANCELLED, Ordering::AcqRel);
    }

    fn dispatch(&self, action: impl FnOnce()) -> bool {
        self.dispatch_with_admission_hook(|| {}, action)
    }

    fn dispatch_with_admission_hook(&self, admitted: impl FnOnce(), action: impl FnOnce()) -> bool {
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            if state & INPUT_EXECUTION_CANCELLED != 0 {
                return false;
            }
            let Some(active) = state.checked_add(INPUT_EXECUTION_ACTIVE) else {
                log::error!("remote input execution admission overflow");
                return false;
            };
            match self.state.compare_exchange_weak(
                state,
                active,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => state = observed,
            }
        }
        // This CAS is the operation's start/admission point; native execution may follow later.
        admitted();
        let _dispatch = InputDispatchGuard { gate: self };
        action();
        true
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Default)]
struct InputOwnerState {
    count: usize,
    transition_uncertain: bool,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Default)]
struct InputKeyOwnerRegistry {
    owners: StdMutex<HashMap<OwnedPhysicalKey, InputOwnerState>>,
    mouse_buttons: StdMutex<HashMap<OwnedMouseButton, InputOwnerState>>,
    workers: StdMutex<usize>,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl InputKeyOwnerRegistry {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<OwnedPhysicalKey, InputOwnerState>> {
        match self.owners.lock() {
            Ok(owners) => owners,
            Err(poisoned) => {
                log::error!("remote input key-owner registry was poisoned");
                poisoned.into_inner()
            }
        }
    }

    fn lock_mouse_buttons(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<OwnedMouseButton, InputOwnerState>> {
        match self.mouse_buttons.lock() {
            Ok(buttons) => buttons,
            Err(poisoned) => {
                log::error!("remote input mouse-button owner registry was poisoned");
                poisoned.into_inner()
            }
        }
    }

    fn register_worker(&self) {
        let mut workers = match self.workers.lock() {
            Ok(workers) => workers,
            Err(poisoned) => {
                log::error!("remote input worker registry was poisoned");
                poisoned.into_inner()
            }
        };
        if *workers == 0 {
            initialize_owned_input_dispatch();
        }
        *workers += 1;
    }

    fn unregister_worker(&self, on_last_worker: impl FnOnce()) -> bool {
        let mut workers = match self.workers.lock() {
            Ok(workers) => workers,
            Err(poisoned) => {
                log::error!("remote input worker registry was poisoned");
                poisoned.into_inner()
            }
        };
        if *workers == 0 {
            log::error!("remote input worker registry underflow");
            return false;
        }
        *workers -= 1;
        if *workers == 0 {
            // Keep registration excluded until process-global injector state has been retired.
            on_last_worker();
            true
        } else {
            false
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
lazy_static::lazy_static! {
    static ref INPUT_KEY_OWNERS: Arc<InputKeyOwnerRegistry> = Default::default();
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct InputKeyOwnership {
    registry: Arc<InputKeyOwnerRegistry>,
    held: HashMap<OwnedPhysicalKey, KeyEvent>,
    held_mouse_buttons: HashSet<OwnedMouseButton>,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl InputKeyOwnership {
    fn new(registry: Arc<InputKeyOwnerRegistry>) -> Self {
        registry.register_worker();
        Self::unregistered(registry)
    }

    fn unregistered(registry: Arc<InputKeyOwnerRegistry>) -> Self {
        Self {
            registry,
            held: HashMap::new(),
            held_mouse_buttons: HashSet::new(),
        }
    }

    fn dispatch(
        &mut self,
        event: &KeyEvent,
        mut action: impl FnMut(&KeyEvent, &[ControlKey]) -> ResultType<()>,
    ) -> ResultType<bool> {
        let registry = Arc::clone(&self.registry);
        let mut owners = registry.lock();
        let key = owned_physical_key(event);
        let releasing_uncertain_key = key.as_ref().map_or(false, |key| {
            !event.down
                && self.held.contains_key(key)
                && owners
                    .get(key)
                    .map_or(false, |state| state.transition_uncertain)
        });
        if owners.values().any(|state| state.transition_uncertain) && !releasing_uncertain_key {
            bail!("an aggregate physical key transition is uncertain");
        }
        if registry
            .lock_mouse_buttons()
            .values()
            .any(|state| state.transition_uncertain)
        {
            bail!("an aggregate mouse-button transition is uncertain");
        }
        let Some(key) = key else {
            self.dispatch_action(event, &owners, &mut action)?;
            return Ok(true);
        };
        if event.down {
            if self.held.contains_key(&key) {
                if owners
                    .get(&key)
                    .map_or(true, |state| state.transition_uncertain)
                {
                    bail!("physical key transition is uncertain");
                }
                self.dispatch_action(event, &owners, &mut action)?;
                return Ok(true);
            }
            if owners
                .get(&key)
                .map_or(false, |state| state.transition_uncertain)
            {
                bail!("physical key transition is uncertain");
            }
            let first_owner = !owners.contains_key(&key);
            self.held.insert(key.clone(), event.clone());
            let state = owners.entry(key.clone()).or_default();
            state.count += 1;
            if first_owner {
                state.transition_uncertain = true;
                self.dispatch_action(event, &owners, &mut action)?;
                let Some(state) = owners.get_mut(&key) else {
                    bail!("physical key ownership disappeared after key-down");
                };
                state.transition_uncertain = false;
            }
            return Ok(first_owner);
        }
        if !self.held.contains_key(&key) {
            return Ok(false);
        }
        let final_owner = owners.get(&key).map(|state| state.count) == Some(1);
        if final_owner {
            // Do not retire either ownership record until native release reports success.
            if let Some(state) = owners.get_mut(&key) {
                state.transition_uncertain = true;
            }
            self.dispatch_action(event, &owners, &mut action)?;
        }
        self.held.remove(&key);
        Self::release_owner(&mut owners, &key);
        Ok(final_owner)
    }

    fn dispatch_press(
        &mut self,
        event: &KeyEvent,
        mut action: impl FnMut(&KeyEvent, &[ControlKey]) -> ResultType<()>,
    ) -> ResultType<()> {
        let registry = Arc::clone(&self.registry);
        let mut owners = registry.lock();
        if owners.values().any(|state| state.transition_uncertain) {
            bail!("an aggregate physical key transition is uncertain");
        }
        if registry
            .lock_mouse_buttons()
            .values()
            .any(|state| state.transition_uncertain)
        {
            bail!("an aggregate mouse-button transition is uncertain");
        }
        let mut event = event.clone();
        event.press = false;
        event.down = true;
        let Some(key) = owned_physical_key(&event) else {
            return self.dispatch_action(&event, &owners, &mut action);
        };
        if self.held.contains_key(&key) || owners.contains_key(&key) {
            bail!("physical press is ambiguous while the key is already owned");
        }
        self.held.insert(key.clone(), event.clone());
        owners.insert(
            key.clone(),
            InputOwnerState {
                count: 1,
                transition_uncertain: true,
            },
        );
        self.dispatch_action(&event, &owners, &mut action)?;
        if let Some(state) = owners.get_mut(&key) {
            state.transition_uncertain = false;
        }
        event.down = false;
        if let Some(state) = owners.get_mut(&key) {
            state.transition_uncertain = true;
        }
        self.dispatch_action(&event, &owners, &mut action)?;
        self.held.remove(&key);
        Self::release_owner(&mut owners, &key);
        Ok(())
    }

    fn dispatch_action(
        &self,
        event: &KeyEvent,
        owners: &HashMap<OwnedPhysicalKey, InputOwnerState>,
        action: &mut impl FnMut(&KeyEvent, &[ControlKey]) -> ResultType<()>,
    ) -> ResultType<()> {
        let preserve_modifiers = owners
            .keys()
            .filter_map(owned_physical_modifier)
            .collect::<Vec<_>>();
        let mut event = event.clone();
        for modifier in &preserve_modifiers {
            if !event
                .modifiers
                .iter()
                .any(|candidate| candidate.value() == modifier.value())
            {
                event.modifiers.push((*modifier).into());
            }
        }
        action(&event, &preserve_modifiers)
    }

    fn dispatch_mouse(
        &mut self,
        event: &MouseEvent,
        native: bool,
        action: impl FnOnce(&MouseEvent, &[ControlKey], bool) -> ResultType<()>,
    ) -> ResultType<()> {
        let registry = Arc::clone(&self.registry);
        let owners = registry.lock();
        if owners.values().any(|state| state.transition_uncertain) {
            bail!("an aggregate physical key transition is uncertain");
        }
        let mut event = event.clone();
        Self::merge_owned_modifiers(&mut event.modifiers, &owners);
        let preserve_modifiers = owners
            .keys()
            .filter_map(owned_physical_modifier)
            .collect::<Vec<_>>();
        if !native {
            return action(&event, &preserve_modifiers, true);
        }
        let mut button_owners = registry.lock_mouse_buttons();
        let transition = owned_mouse_button(&event);
        let releasing_uncertain_button = transition.map_or(false, |(button, down)| {
            !down
                && self.held_mouse_buttons.contains(&button)
                && button_owners
                    .get(&button)
                    .map_or(false, |state| state.transition_uncertain)
        });
        if button_owners
            .values()
            .any(|state| state.transition_uncertain)
            && !releasing_uncertain_button
        {
            bail!("an aggregate mouse-button transition is uncertain");
        }
        let Some((button, down)) = transition else {
            return action(&event, &preserve_modifiers, true);
        };
        if down {
            if button_owners
                .get(&button)
                .map_or(false, |state| state.transition_uncertain)
            {
                bail!("mouse-button transition is uncertain");
            }
            if !self.held_mouse_buttons.insert(button) {
                return action(&event, &preserve_modifiers, false);
            }
            let first_owner = !button_owners.contains_key(&button);
            let state = button_owners.entry(button).or_default();
            state.count += 1;
            if first_owner {
                state.transition_uncertain = true;
                action(&event, &preserve_modifiers, true)?;
                let Some(state) = button_owners.get_mut(&button) else {
                    bail!("mouse-button ownership disappeared after button-down");
                };
                state.transition_uncertain = false;
            } else {
                action(&event, &preserve_modifiers, false)?;
            }
            return Ok(());
        }
        if !self.held_mouse_buttons.contains(&button) {
            return action(&event, &preserve_modifiers, false);
        }
        let final_owner = button_owners.get(&button).map(|state| state.count) == Some(1);
        if final_owner {
            if let Some(state) = button_owners.get_mut(&button) {
                state.transition_uncertain = true;
            }
        }
        action(&event, &preserve_modifiers, final_owner)?;
        self.held_mouse_buttons.remove(&button);
        Self::release_mouse_button_owner(&mut button_owners, button);
        Ok(())
    }

    fn dispatch_pointer(
        &self,
        event: &PointerDeviceEvent,
        action: impl FnOnce(&PointerDeviceEvent) -> ResultType<()>,
    ) -> ResultType<()> {
        let registry = Arc::clone(&self.registry);
        let owners = registry.lock();
        if owners.values().any(|state| state.transition_uncertain) {
            bail!("an aggregate physical key transition is uncertain");
        }
        if registry
            .lock_mouse_buttons()
            .values()
            .any(|state| state.transition_uncertain)
        {
            bail!("an aggregate mouse-button transition is uncertain");
        }
        let mut event = event.clone();
        Self::merge_owned_modifiers(&mut event.modifiers, &owners);
        action(&event)
    }

    fn merge_owned_modifiers(
        modifiers: &mut Vec<hbb_common::protobuf::EnumOrUnknown<ControlKey>>,
        owners: &HashMap<OwnedPhysicalKey, InputOwnerState>,
    ) {
        for modifier in owners.keys().filter_map(owned_physical_modifier) {
            if !modifiers
                .iter()
                .any(|candidate| candidate.value() == modifier.value())
            {
                modifiers.push(modifier.into());
            }
        }
    }

    fn release_all(
        &mut self,
        mut action: impl FnMut(&KeyEvent, &[ControlKey]) -> ResultType<()>,
    ) -> ResultType<()> {
        let registry = Arc::clone(&self.registry);
        let mut owners = registry.lock();
        let held_keys = self.held.keys().cloned().collect::<Vec<_>>();
        for key in held_keys {
            let final_owner = owners.get(&key).map(|state| state.count) == Some(1);
            if final_owner {
                let Some(mut event) = self.held.get(&key).cloned() else {
                    bail!("remote input key disappeared during teardown");
                };
                event.press = false;
                event.down = false;
                let preserve_modifiers = owners
                    .keys()
                    .filter(|owned| *owned != &key)
                    .filter_map(owned_physical_modifier)
                    .collect::<Vec<_>>();
                // A failure or unwind leaves both maps intact so cleanup can retry or fail fatal.
                if let Some(state) = owners.get_mut(&key) {
                    state.transition_uncertain = true;
                }
                action(&event, &preserve_modifiers)?;
            }
            self.held.remove(&key);
            Self::release_owner(&mut owners, &key);
        }
        Ok(())
    }

    fn release_all_mouse_buttons(
        &mut self,
        mut action: impl FnMut(OwnedMouseButton) -> ResultType<()>,
    ) -> ResultType<()> {
        let registry = Arc::clone(&self.registry);
        let mut owners = registry.lock_mouse_buttons();
        let held_buttons = self.held_mouse_buttons.iter().copied().collect::<Vec<_>>();
        for button in held_buttons {
            if owners.get(&button).map(|state| state.count) == Some(1) {
                if let Some(state) = owners.get_mut(&button) {
                    state.transition_uncertain = true;
                }
                action(button)?;
            }
            self.held_mouse_buttons.remove(&button);
            Self::release_mouse_button_owner(&mut owners, button);
        }
        Ok(())
    }

    fn finish_worker(&self, on_last_worker: impl FnOnce()) -> bool {
        self.registry.unregister_worker(on_last_worker)
    }

    fn release_remaining(&mut self) -> ResultType<()> {
        self.release_all(handle_owned_key)?;
        self.release_all_mouse_buttons(|button| {
            if let Err(first_err) = release_owned_mouse_button(button) {
                if let Err(retry_err) = release_owned_mouse_button(button) {
                    bail!(
                        "mouse-button release failed twice: first={first_err}, retry={retry_err}"
                    );
                }
                log::warn!("mouse-button release required a retry: {first_err}");
            }
            Ok(())
        })
    }

    fn release_mouse_button_owner(
        owners: &mut HashMap<OwnedMouseButton, InputOwnerState>,
        button: OwnedMouseButton,
    ) -> bool {
        let Some(count) = owners.get_mut(&button) else {
            log::error!("remote mouse-button ownership was released without an aggregate owner");
            return false;
        };
        if count.count <= 1 {
            owners.remove(&button);
            true
        } else {
            count.count -= 1;
            false
        }
    }

    fn release_owner(
        owners: &mut HashMap<OwnedPhysicalKey, InputOwnerState>,
        key: &OwnedPhysicalKey,
    ) -> bool {
        let Some(count) = owners.get_mut(key) else {
            log::error!("remote input key ownership was released without an aggregate owner");
            return false;
        };
        match count.count {
            0 => {
                log::error!("remote input key ownership aggregate reached zero prematurely");
                owners.remove(key);
                false
            }
            1 => {
                owners.remove(key);
                true
            }
            _ => {
                count.count -= 1;
                false
            }
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct InputWorkerCleanup {
    conn_id: i32,
    keys: InputKeyOwnership,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Default)]
struct InputBlockState {
    owners: HashSet<i32>,
    applied: bool,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Default)]
struct InputBlockOwnerRegistry {
    state: StdMutex<InputBlockState>,
}

#[cfg(target_os = "windows")]
fn apply_block_input(blocked: bool) -> (bool, String) {
    match dispatch_windows_owned_input(move || Ok(crate::platform::block_input(blocked))) {
        Ok(result) => result,
        Err(err) => (false, format!("Windows owned-input executor failed: {err}")),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn apply_block_input(blocked: bool) -> (bool, String) {
    crate::platform::block_input(blocked)
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl InputBlockOwnerRegistry {
    fn set(&self, conn_id: i32, blocked: bool) -> (bool, String) {
        self.set_with(conn_id, blocked, apply_block_input)
    }

    fn set_with(
        &self,
        conn_id: i32,
        blocked: bool,
        mut apply: impl FnMut(bool) -> (bool, String),
    ) -> (bool, String) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                log::error!("remote block-input owner registry was poisoned");
                poisoned.into_inner()
            }
        };
        if blocked {
            if state.owners.contains(&conn_id) {
                return (true, String::new());
            }
            if !state.applied {
                let result = apply(true);
                if !result.0 {
                    return result;
                }
                state.applied = true;
            }
            state.owners.insert(conn_id);
            return (true, String::new());
        }
        state.owners.remove(&conn_id);
        if state.owners.is_empty() && state.applied {
            let result = apply(false);
            if result.0 {
                state.applied = false;
            }
            return result;
        }
        (true, String::new())
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn release_block_owner_with_retry(
    registry: &InputBlockOwnerRegistry,
    conn_id: i32,
    mut apply: impl FnMut(bool) -> (bool, String),
) -> ResultType<()> {
    let (released, details) = registry.set_with(conn_id, false, &mut apply);
    if released {
        return Ok(());
    }
    log::error!("Failed to release local input; retrying aggregate transition: {details}");
    let (retried, retry_details) = registry.set_with(conn_id, false, apply);
    if retried {
        Ok(())
    } else {
        bail!("could not prove local input was unblocked: {retry_details}")
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
lazy_static::lazy_static! {
    static ref INPUT_BLOCK_OWNERS: InputBlockOwnerRegistry = Default::default();
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn run_input_cleanup_action(context: &str, action: impl FnOnce()) -> bool {
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)).is_ok() {
        true
    } else {
        log::error!("remote input cleanup panicked while {context}");
        false
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl Drop for InputWorkerCleanup {
    fn drop(&mut self) {
        if !run_input_cleanup_action("releasing blocked local input", || {
            if let Err(err) =
                release_block_owner_with_retry(&INPUT_BLOCK_OWNERS, self.conn_id, apply_block_input)
            {
                log::error!("Could not prove local input was unblocked during teardown: {err}");
                std::process::abort();
            }
        }) {
            std::process::abort();
        }
        if let Err(err) = self.keys.release_remaining() {
            log::error!("Could not prove release of all remote-owned keys: {err}");
            std::process::abort();
        }
        #[cfg(target_os = "macos")]
        if !run_input_cleanup_action(
            "finishing macOS input dispatch",
            finish_owned_input_dispatch,
        ) {
            std::process::abort();
        }
        #[cfg(target_os = "linux")]
        self.keys.finish_worker(|| {
            if !run_input_cleanup_action("clearing remapped keycodes", clear_remapped_keycode) {
                std::process::abort();
            }
        });
        #[cfg(not(target_os = "linux"))]
        self.keys.finish_worker(|| {});
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SpecialKeyAction {
    CtrlAltDel,
    LockScreen,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[derive(Default)]
struct SpecialKeyState {
    ctrl_alt_del_down: bool,
    lock_screen_down: bool,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
impl SpecialKeyState {
    fn action(event: &KeyEvent) -> Option<SpecialKeyAction> {
        let Some(key_event::Union::ControlKey(key)) = &event.union else {
            return None;
        };
        if key.value() == ControlKey::CtrlAltDel.value() {
            Some(SpecialKeyAction::CtrlAltDel)
        } else if key.value() == ControlKey::LockScreen.value() {
            Some(SpecialKeyAction::LockScreen)
        } else {
            None
        }
    }

    fn observe(&mut self, event: &KeyEvent) -> Option<Option<SpecialKeyAction>> {
        let action = Self::action(event)?;
        let held = match action {
            SpecialKeyAction::CtrlAltDel => &mut self.ctrl_alt_del_down,
            SpecialKeyAction::LockScreen => &mut self.lock_screen_down,
        };
        if event.press {
            return Some(Some(action));
        }
        if event.down {
            if *held {
                Some(None)
            } else {
                *held = true;
                Some(Some(action))
            }
        } else {
            *held = false;
            Some(None)
        }
    }
}

#[cfg(target_os = "windows")]
fn dispatch_windows_service_owned_sas(
    runtime: &tokio::runtime::Handle,
    execution: &InputExecutionGate,
) {
    let (result_tx, result_rx) = std_mpsc::sync_channel(1);
    let task = runtime.spawn(async move {
        let result = ipc::request_windows_service_owned_sas().await;
        if result_tx.send(result).is_err() {
            log::debug!("Ctrl+Alt+Del result receiver ended before service dispatch completed");
        }
    });
    let mut cancellation_requested = false;
    loop {
        match result_rx.recv_timeout(std::time::Duration::from_millis(50)) {
            Ok(Ok(())) => return,
            Ok(Err(err)) => {
                log::warn!(
                    "Service-owned Ctrl+Alt+Del dispatch did not reach a known accepted result: {err}"
                );
                return;
            }
            Err(std_mpsc::RecvTimeoutError::Disconnected) => return,
            Err(std_mpsc::RecvTimeoutError::Timeout) => {
                if execution.is_cancelled() && !cancellation_requested {
                    cancellation_requested = true;
                    task.abort();
                }
            }
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn try_enqueue_input(queue: &InputQueue, input: MessageInput) -> ResultType<()> {
    queue.try_enqueue(input)
}

#[cfg(all(test, not(any(target_os = "android", target_os = "ios"))))]
mod desktop_input_queue_tests {
    use super::*;
    use crate::input::{
        MOUSE_BUTTON_LEFT, MOUSE_BUTTON_RIGHT, MOUSE_TYPE_DOWN, MOUSE_TYPE_MASK,
        MOUSE_TYPE_TRACKPAD, MOUSE_TYPE_UP, MOUSE_TYPE_WHEEL,
    };

    #[test]
    fn desktop_input_queue_fails_closed_when_full_or_disconnected() {
        let (sender, receiver) = std_mpsc::sync_channel(1);
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let queue = InputQueue {
            sender,
            queued_bytes: Arc::clone(&queued_bytes),
            execution: Arc::new(InputExecutionGate::default()),
        };
        assert!(try_enqueue_input(&queue, MessageInput::BlockOn).is_ok());
        assert!(try_enqueue_input(&queue, MessageInput::BlockOff).is_err());

        let received = receiver.recv().unwrap();
        assert!(matches!(
            received.input.as_ref(),
            Some(MessageInput::BlockOn)
        ));
        drop(received);
        assert_eq!(queued_bytes.load(Ordering::Acquire), 0);
        drop(receiver);
        assert!(try_enqueue_input(&queue, MessageInput::BlockOff).is_err());
        assert_eq!(queued_bytes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn desktop_input_queue_rejects_oversized_key_sequences() {
        let (sender, _receiver) = std_mpsc::sync_channel(1);
        let queue = InputQueue {
            sender,
            queued_bytes: Arc::new(AtomicUsize::new(0)),
            execution: Arc::new(InputExecutionGate::default()),
        };
        let mut event = KeyEvent::new();
        event.set_seq("x".repeat(INPUT_KEY_SEQUENCE_MAX_BYTES + 1));
        assert!(try_enqueue_input(&queue, MessageInput::Key((event, false))).is_err());
    }

    #[test]
    fn desktop_input_validators_enforce_structural_and_serialized_boundaries() {
        let mut mouse = MouseEvent::new();
        let mut key = KeyEvent::new();
        key.set_control_key(ControlKey::Alt);
        let mut pointer = PointerDeviceEvent::new();
        for _ in 0..INPUT_MODIFIER_MAX_ENTRIES {
            mouse.modifiers.push(ControlKey::Alt.into());
            key.modifiers.push(ControlKey::Alt.into());
            pointer.modifiers.push(ControlKey::Alt.into());
        }
        assert!(validate_mouse_input(&mouse).is_ok());
        assert!(validate_key_input(&key).is_ok());
        assert!(validate_pointer_input(&pointer).is_ok());

        mouse.modifiers.push(ControlKey::Alt.into());
        key.modifiers.push(ControlKey::Alt.into());
        pointer.modifiers.push(ControlKey::Alt.into());
        assert!(validate_mouse_input(&mouse).is_err());
        assert!(validate_key_input(&key).is_err());
        assert!(validate_pointer_input(&pointer).is_err());

        let mut sequence = KeyEvent::new();
        sequence.set_seq("x".repeat(INPUT_KEY_SEQUENCE_MAX_BYTES));
        assert!(validate_key_input(&sequence).is_ok());
        sequence.set_seq("x".repeat(INPUT_KEY_SEQUENCE_MAX_BYTES + 1));
        assert!(validate_key_input(&sequence).is_err());
        let mut inconsistent = KeyEvent::new();
        inconsistent.mode = KeyboardMode::Map.into();
        inconsistent.set_seq("not a raw-position key".to_owned());
        assert!(validate_key_input(&inconsistent).is_err());
        assert_eq!(
            validate_input_size(INPUT_EVENT_MAX_BYTES).unwrap(),
            INPUT_EVENT_MAX_BYTES
        );
        assert!(validate_input_size(INPUT_EVENT_MAX_BYTES + 1).is_err());
    }

    #[test]
    fn desktop_scroll_validation_enforces_checked_protocol_bounds() {
        for event_type in [MOUSE_TYPE_WHEEL, MOUSE_TYPE_TRACKPAD] {
            for delta in [-INPUT_SCROLL_MAX_DELTA, INPUT_SCROLL_MAX_DELTA] {
                let mut event = MouseEvent::new();
                event.mask = event_type;
                event.x = delta;
                event.y = -delta;
                assert!(validate_mouse_input(&event).is_ok());
            }

            for delta in [
                INPUT_SCROLL_MAX_DELTA + 1,
                -INPUT_SCROLL_MAX_DELTA - 1,
                i32::MIN,
            ] {
                let mut event = MouseEvent::new();
                event.mask = event_type;
                event.x = delta;
                assert!(validate_mouse_input(&event).is_err());
            }
        }
    }

    #[test]
    fn desktop_input_queue_enforces_item_capacity_and_releases_all_charges() {
        let (sender, receiver) = std_mpsc::sync_channel(INPUT_QUEUE_CAPACITY);
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let queue = InputQueue {
            sender,
            queued_bytes: Arc::clone(&queued_bytes),
            execution: Arc::new(InputExecutionGate::default()),
        };
        for _ in 0..INPUT_QUEUE_CAPACITY {
            try_enqueue_input(&queue, MessageInput::BlockOn).unwrap();
        }
        assert_eq!(queued_bytes.load(Ordering::Acquire), INPUT_QUEUE_CAPACITY);
        assert!(try_enqueue_input(&queue, MessageInput::BlockOff).is_err());
        assert_eq!(queued_bytes.load(Ordering::Acquire), INPUT_QUEUE_CAPACITY);

        assert_eq!(receiver.try_iter().count(), INPUT_QUEUE_CAPACITY);
        assert_eq!(queued_bytes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn desktop_input_queue_byte_accounting_is_checked_and_rolls_back_on_failure() {
        let (sender, receiver) = std_mpsc::sync_channel(1);
        let queued_bytes = Arc::new(AtomicUsize::new(INPUT_QUEUE_MAX_BYTES - 1));
        let execution = Arc::new(InputExecutionGate::default());
        let queue = InputQueue {
            sender,
            queued_bytes: Arc::clone(&queued_bytes),
            execution: Arc::clone(&execution),
        };
        try_enqueue_input(&queue, MessageInput::BlockOn).unwrap();
        assert_eq!(queued_bytes.load(Ordering::Acquire), INPUT_QUEUE_MAX_BYTES);
        assert!(try_enqueue_input(&queue, MessageInput::BlockOff).is_err());
        assert_eq!(queued_bytes.load(Ordering::Acquire), INPUT_QUEUE_MAX_BYTES);
        drop(receiver.recv().unwrap());
        assert_eq!(
            queued_bytes.load(Ordering::Acquire),
            INPUT_QUEUE_MAX_BYTES - 1
        );

        queued_bytes.store(usize::MAX, Ordering::Release);
        assert!(try_enqueue_input(&queue, MessageInput::BlockOff).is_err());
        assert_eq!(queued_bytes.load(Ordering::Acquire), usize::MAX);
        queued_bytes.store(0, Ordering::Release);

        execution.cancel();
        assert!(try_enqueue_input(&queue, MessageInput::BlockOff).is_err());
        assert_eq!(queued_bytes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn desktop_input_cancellation_is_nonblocking_and_closes_admission() {
        let gate = Arc::new(InputExecutionGate::default());
        let (admitted_tx, admitted_rx) = std_mpsc::channel();
        let (started_tx, started_rx) = std_mpsc::channel();
        let (release_tx, release_rx) = std_mpsc::channel();
        let dispatch_gate = Arc::clone(&gate);
        let dispatch = std::thread::spawn(move || {
            dispatch_gate.dispatch_with_admission_hook(
                || {
                    admitted_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                },
                || {
                    started_tx.send(()).unwrap();
                },
            )
        });
        admitted_rx.recv().unwrap();

        gate.cancel();
        assert!(gate.is_cancelled());
        assert!(!gate.dispatch(|| panic!("work was admitted after cancellation")));
        assert!(started_rx
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err());

        release_tx.send(()).unwrap();
        started_rx.recv().unwrap();
        assert!(dispatch.join().unwrap());
    }

    #[test]
    fn desktop_special_keys_are_structurally_validated_and_queue_accounted() {
        let (sender, receiver) = std_mpsc::sync_channel(1);
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let queue = InputQueue {
            sender,
            queued_bytes: Arc::clone(&queued_bytes),
            execution: Arc::new(InputExecutionGate::default()),
        };
        let mut oversized = special_key(ControlKey::LockScreen, true, false);
        for _ in 0..=INPUT_MODIFIER_MAX_ENTRIES {
            oversized.modifiers.push(ControlKey::Alt.into());
        }
        assert!(try_enqueue_input(&queue, MessageInput::SpecialKey(oversized)).is_err());
        assert_eq!(queued_bytes.load(Ordering::Acquire), 0);

        let valid = special_key(ControlKey::LockScreen, true, false);
        let expected_weight = validate_key_input(&valid).unwrap();
        try_enqueue_input(&queue, MessageInput::SpecialKey(valid)).unwrap();
        assert_eq!(queued_bytes.load(Ordering::Acquire), expected_weight);
        let queued = receiver.recv().unwrap();
        assert!(matches!(queued.input, Some(MessageInput::SpecialKey(_))));
        drop(queued);
        assert_eq!(queued_bytes.load(Ordering::Acquire), 0);
    }

    #[test]
    fn desktop_key_teardown_releases_only_the_last_connection_owner() {
        let registry = Arc::new(InputKeyOwnerRegistry::default());
        let mut first = InputKeyOwnership::new(Arc::clone(&registry));
        let mut second = InputKeyOwnership::new(Arc::clone(&registry));
        let mut down = KeyEvent::new();
        down.set_control_key(ControlKey::Control);
        down.down = true;

        assert!(first.dispatch(&down, |_, _| Ok(())).unwrap());
        assert!(!second.dispatch(&down, |_, _| Ok(())).unwrap());
        let mut releases = Vec::new();
        first
            .release_all(|event, _| {
                releases.push(event.clone());
                Ok(())
            })
            .unwrap();
        assert!(releases.is_empty());
        second
            .release_all(|event, _| {
                releases.push(event.clone());
                Ok(())
            })
            .unwrap();
        assert_eq!(releases.len(), 1);
        assert!(!releases[0].down);
        assert!(registry.lock().is_empty());

        let mut stray_up = down;
        stray_up.down = false;
        assert!(!first.dispatch(&stray_up, |_, _| Ok(())).unwrap());
    }

    #[test]
    fn desktop_map_and_translate_share_backend_physical_key_identity() {
        let mut map = KeyEvent::new();
        map.mode = KeyboardMode::Map.into();
        map.set_chr(42);
        let mut translate = map.clone();
        translate.mode = KeyboardMode::Translate.into();
        assert_eq!(owned_physical_key(&map), owned_physical_key(&translate));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_win2win_click_and_source_release_have_no_physical_owner() {
        let mut down = KeyEvent::new();
        down.mode = KeyboardMode::Translate.into();
        down.set_win2win_hotkey((0x41 << 16) | ('a' as u32));
        down.down = true;
        assert!(validate_key_input(&down).is_ok());
        assert!(owned_physical_key(&down).is_none());

        let mut up = down;
        up.set_win2win_hotkey(0x41 << 16);
        up.down = false;
        assert!(validate_key_input(&up).is_ok());
        assert!(owned_physical_key(&up).is_none());
    }

    #[test]
    fn desktop_legacy_and_raw_control_share_backend_physical_key_identity() {
        #[cfg(target_os = "linux")]
        let code = rdev::linux_keycode_from_key(rdev::Key::ControlLeft).unwrap() as u32;
        #[cfg(target_os = "windows")]
        let code = rdev::win_scancode_from_key(rdev::Key::ControlLeft).unwrap() as u32;
        #[cfg(target_os = "macos")]
        let code = rdev::macos_keycode_from_key(rdev::Key::ControlLeft).unwrap() as u32;

        let mut legacy = KeyEvent::new();
        legacy.set_control_key(ControlKey::Control);
        let mut raw = KeyEvent::new();
        raw.mode = KeyboardMode::Map.into();
        raw.set_chr(code);
        assert_eq!(owned_physical_key(&legacy), owned_physical_key(&raw));
    }

    #[test]
    fn desktop_dispatch_preserves_modifiers_owned_by_other_connections() {
        let registry = Arc::new(InputKeyOwnerRegistry::default());
        let mut first = InputKeyOwnership::new(Arc::clone(&registry));
        let mut second = InputKeyOwnership::new(Arc::clone(&registry));
        let mut control = KeyEvent::new();
        control.set_control_key(ControlKey::Control);
        control.down = true;
        assert!(first.dispatch(&control, |_, _| Ok(())).unwrap());

        let mut character = KeyEvent::new();
        character.set_chr('x' as u32);
        character.down = true;
        assert!(second
            .dispatch(&character, |event, preserve_modifiers| {
                assert!(preserve_modifiers.contains(&ControlKey::Control));
                assert!(event
                    .modifiers
                    .iter()
                    .any(|modifier| modifier.value() == ControlKey::Control.value()));
                Ok(())
            })
            .unwrap());
        first.release_all(|_, _| Ok(())).unwrap();
        second.release_all(|_, _| Ok(())).unwrap();
        assert!(registry.lock().is_empty());
    }

    #[test]
    fn desktop_dispatch_preserves_exact_right_side_modifiers() {
        let registry = Arc::new(InputKeyOwnerRegistry::default());
        let mut owner = InputKeyOwnership::new(Arc::clone(&registry));
        for modifier in [
            ControlKey::RShift,
            ControlKey::RControl,
            ControlKey::RAlt,
            ControlKey::RWin,
        ] {
            let mut event = KeyEvent::new();
            event.set_control_key(modifier);
            event.down = true;
            assert!(owner.dispatch(&event, |_, _| Ok(())).unwrap());
        }

        let mut other = InputKeyOwnership::new(Arc::clone(&registry));
        let mut character = KeyEvent::new();
        character.set_chr('x' as u32);
        character.down = true;
        other
            .dispatch(&character, |event, preserve_modifiers| {
                for modifier in [
                    ControlKey::RShift,
                    ControlKey::RControl,
                    ControlKey::RAlt,
                    ControlKey::RWin,
                ] {
                    assert!(preserve_modifiers.contains(&modifier));
                    assert!(event
                        .modifiers
                        .iter()
                        .any(|candidate| candidate.value() == modifier.value()));
                }
                Ok(())
            })
            .unwrap();
        owner.release_all(|_, _| Ok(())).unwrap();
        other.release_all(|_, _| Ok(())).unwrap();
        assert!(registry.lock().is_empty());
    }

    #[test]
    fn desktop_key_failure_retains_ownership_until_release_succeeds() {
        let registry = Arc::new(InputKeyOwnerRegistry::default());
        let mut owner = InputKeyOwnership::new(Arc::clone(&registry));
        let mut event = KeyEvent::new();
        event.set_control_key(ControlKey::Control);
        event.down = true;
        assert!(owner.dispatch(&event, |_, _| Ok(())).unwrap());

        event.down = false;
        assert!(owner
            .dispatch(&event, |_, _| bail!("injected key-up failure"))
            .is_err());
        assert_eq!(owner.held.len(), 1);
        let owners = registry.lock();
        assert_eq!(owners.values().map(|state| state.count).sum::<usize>(), 1);
        assert!(owners.values().all(|state| state.transition_uncertain));
        drop(owners);
        let mut other = InputKeyOwnership::new(Arc::clone(&registry));
        let mut other_down = KeyEvent::new();
        other_down.set_control_key(ControlKey::Shift);
        other_down.down = true;
        assert!(other.dispatch(&other_down, |_, _| Ok(())).is_err());

        assert!(owner.dispatch(&event, |_, _| Ok(())).unwrap());
        assert!(owner.held.is_empty());
        assert!(registry.lock().is_empty());
    }

    #[test]
    fn desktop_key_teardown_failure_keeps_registry_for_fail_stop() {
        let registry = Arc::new(InputKeyOwnerRegistry::default());
        let mut owner = InputKeyOwnership::new(Arc::clone(&registry));
        let mut event = KeyEvent::new();
        event.set_control_key(ControlKey::RControl);
        event.down = true;
        owner.dispatch(&event, |_, _| Ok(())).unwrap();

        assert!(owner
            .release_all(|_, _| bail!("injected teardown release failure"))
            .is_err());
        assert_eq!(owner.held.len(), 1);
        let owners = registry.lock();
        assert_eq!(owners.values().map(|state| state.count).sum::<usize>(), 1);
        assert!(owners.values().all(|state| state.transition_uncertain));
        drop(owners);

        owner.release_all(|_, _| Ok(())).unwrap();
        assert!(owner.held.is_empty());
        assert!(registry.lock().is_empty());
    }

    fn mouse_button_event(button: i32, down: bool) -> MouseEvent {
        let mut event = MouseEvent::new();
        event.mask = (button << 3) | if down { MOUSE_TYPE_DOWN } else { MOUSE_TYPE_UP };
        event
    }

    #[test]
    fn desktop_mouse_button_uses_aggregate_multi_connection_transitions() {
        let registry = Arc::new(InputKeyOwnerRegistry::default());
        let mut first = InputKeyOwnership::new(Arc::clone(&registry));
        let mut second = InputKeyOwnership::new(Arc::clone(&registry));
        let down = mouse_button_event(MOUSE_BUTTON_LEFT, true);
        let up = mouse_button_event(MOUSE_BUTTON_LEFT, false);
        let transitions = Arc::new(StdMutex::new(Vec::new()));

        let dispatch = |owner: &mut InputKeyOwnership, event: &MouseEvent| {
            let transitions = Arc::clone(&transitions);
            owner
                .dispatch_mouse(event, true, move |event, _, inject_native| {
                    if inject_native {
                        transitions
                            .lock()
                            .unwrap()
                            .push((event.mask & MOUSE_TYPE_MASK) == MOUSE_TYPE_DOWN);
                    }
                    Ok(())
                })
                .unwrap();
        };
        dispatch(&mut first, &down);
        dispatch(&mut second, &down);
        dispatch(&mut first, &up);
        dispatch(&mut second, &up);
        assert_eq!(*transitions.lock().unwrap(), vec![true, false]);
        assert!(registry.lock_mouse_buttons().is_empty());
    }

    #[test]
    fn desktop_mouse_button_failures_retain_ownership_until_proven_release() {
        let registry = Arc::new(InputKeyOwnerRegistry::default());
        let mut owner = InputKeyOwnership::new(Arc::clone(&registry));
        let down = mouse_button_event(MOUSE_BUTTON_LEFT, true);
        let up = mouse_button_event(MOUSE_BUTTON_LEFT, false);

        assert!(owner
            .dispatch_mouse(&down, true, |_, _, inject_native| {
                assert!(inject_native);
                bail!("injected mouse-down failure")
            })
            .is_err());
        assert!(owner.held_mouse_buttons.contains(&OwnedMouseButton::Left));
        assert_eq!(
            registry
                .lock_mouse_buttons()
                .get(&OwnedMouseButton::Left)
                .map(|state| state.count),
            Some(1)
        );
        assert!(registry
            .lock_mouse_buttons()
            .values()
            .all(|state| state.transition_uncertain));
        let mut other = InputKeyOwnership::new(Arc::clone(&registry));
        let movement = MouseEvent::new();
        assert!(other
            .dispatch_mouse(&movement, true, |_, _, _| Ok(()))
            .is_err());

        owner
            .dispatch_mouse(&up, true, |_, _, inject_native| {
                assert!(inject_native);
                bail!("injected mouse-up failure")
            })
            .unwrap_err();
        assert!(owner.held_mouse_buttons.contains(&OwnedMouseButton::Left));

        owner
            .dispatch_mouse(&up, true, |_, _, inject_native| {
                assert!(inject_native);
                Ok(())
            })
            .unwrap();
        assert!(owner.held_mouse_buttons.is_empty());
        assert!(registry.lock_mouse_buttons().is_empty());
    }

    #[test]
    fn desktop_mouse_disconnect_failure_keeps_registry_for_fail_stop() {
        let registry = Arc::new(InputKeyOwnerRegistry::default());
        let mut owner = InputKeyOwnership::new(Arc::clone(&registry));
        let down = mouse_button_event(MOUSE_BUTTON_RIGHT, true);
        owner.dispatch_mouse(&down, true, |_, _, _| Ok(())).unwrap();

        assert!(owner
            .release_all_mouse_buttons(|_| bail!("injected disconnect release failure"))
            .is_err());
        assert!(owner.held_mouse_buttons.contains(&OwnedMouseButton::Right));
        assert_eq!(
            registry
                .lock_mouse_buttons()
                .get(&OwnedMouseButton::Right)
                .map(|state| state.count),
            Some(1)
        );
        assert!(registry
            .lock_mouse_buttons()
            .values()
            .all(|state| state.transition_uncertain));

        owner.release_all_mouse_buttons(|_| Ok(())).unwrap();
        assert!(owner.held_mouse_buttons.is_empty());
        assert!(registry.lock_mouse_buttons().is_empty());
    }

    #[test]
    fn desktop_key_state_survives_unwind_until_cleanup_release() {
        let registry = Arc::new(InputKeyOwnerRegistry::default());
        let mut owner = InputKeyOwnership::new(Arc::clone(&registry));
        let mut down = KeyEvent::new();
        down.set_control_key(ControlKey::Control);
        down.down = true;
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = owner.dispatch(&down, |_, _| panic!("injected key-down panic"));
        }));
        assert!(panic.is_err());
        assert_eq!(owner.held.len(), 1);
        assert!(registry
            .lock()
            .values()
            .all(|state| state.transition_uncertain));

        let mut releases = Vec::new();
        owner
            .release_all(|event, _| {
                releases.push(event.clone());
                Ok(())
            })
            .unwrap();
        assert_eq!(releases.len(), 1);
        assert!(!releases[0].down);
        assert!(registry.lock().is_empty());

        let mut owner = InputKeyOwnership::new(Arc::clone(&registry));
        assert!(owner.dispatch(&down, |_, _| Ok(())).unwrap());
        let mut up = down;
        up.down = false;
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = owner.dispatch(&up, |_, _| panic!("injected key-up panic"));
        }));
        assert!(panic.is_err());
        assert_eq!(owner.held.len(), 1);
        assert!(registry
            .lock()
            .values()
            .all(|state| state.transition_uncertain));
        let mut releases = Vec::new();
        owner
            .release_all(|event, _| {
                releases.push(event.clone());
                Ok(())
            })
            .unwrap();
        assert_eq!(releases.len(), 1);
        assert!(registry.lock().is_empty());
    }

    #[test]
    fn desktop_block_input_is_released_only_by_the_final_owner() {
        let registry = InputBlockOwnerRegistry::default();
        let transitions = Arc::new(StdMutex::new(Vec::new()));
        let apply = |blocked, transitions: &Arc<StdMutex<Vec<bool>>>| {
            transitions.lock().unwrap().push(blocked);
            (true, String::new())
        };
        assert!(
            registry
                .set_with(1, true, |blocked| apply(blocked, &transitions))
                .0
        );
        assert!(
            registry
                .set_with(2, true, |blocked| apply(blocked, &transitions))
                .0
        );
        assert!(
            registry
                .set_with(1, false, |blocked| apply(blocked, &transitions))
                .0
        );
        assert_eq!(*transitions.lock().unwrap(), vec![true]);
        assert!(
            registry
                .set_with(2, false, |blocked| apply(blocked, &transitions))
                .0
        );
        assert_eq!(*transitions.lock().unwrap(), vec![true, false]);
    }

    #[test]
    fn desktop_block_input_failed_release_remains_retryable() {
        let registry = InputBlockOwnerRegistry::default();
        assert!(registry.set_with(1, true, |_| (true, String::new())).0);
        assert!(
            !registry
                .set_with(1, false, |_| (false, "injected failure".to_owned()))
                .0
        );
        assert!(registry.set_with(1, false, |_| (true, String::new())).0);
        let state = registry.state.lock().unwrap();
        assert!(!state.applied);
        assert!(state.owners.is_empty());
    }

    #[test]
    fn desktop_block_cleanup_failure_retains_applied_state_for_fail_stop() {
        let registry = InputBlockOwnerRegistry::default();
        assert!(registry.set_with(7, true, |_| (true, String::new())).0);
        let attempts = AtomicUsize::new(0);
        let result = release_block_owner_with_retry(&registry, 7, |_| {
            attempts.fetch_add(1, Ordering::AcqRel);
            (false, "injected unblock failure".to_owned())
        });
        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::Acquire), 2);
        let state = registry.state.lock().unwrap();
        assert!(state.applied);
        assert!(state.owners.is_empty());
    }

    #[test]
    fn desktop_owned_executor_orders_block_and_input_on_one_stable_thread() {
        let executor = Arc::new(OwnedInputExecutor::spawn("owned-input-test").unwrap());
        let registry = Arc::new(InputBlockOwnerRegistry::default());
        let operations = Arc::new(StdMutex::new(Vec::new()));
        let (blocked_tx, blocked_rx) = std_mpsc::channel();
        let (second_owned_tx, second_owned_rx) = std_mpsc::channel();
        let (first_released_tx, first_released_rx) = std_mpsc::channel();

        let first_executor = Arc::clone(&executor);
        let first_registry = Arc::clone(&registry);
        let first_operations = Arc::clone(&operations);
        let first = std::thread::spawn(move || {
            let caller = std::thread::current().id();
            assert!(
                first_registry
                    .set_with(1, true, move |blocked| {
                        let operations = Arc::clone(&first_operations);
                        first_executor
                            .dispatch(move || {
                                operations
                                    .lock()
                                    .unwrap()
                                    .push(("block-on", std::thread::current().id()));
                                Ok((blocked, String::new()))
                            })
                            .unwrap()
                    })
                    .0
            );
            blocked_tx.send(()).unwrap();
            second_owned_rx.recv().unwrap();
            assert!(first_registry.set_with(1, false, |_| unreachable!()).0);
            first_released_tx.send(()).unwrap();
            caller
        });

        let second_executor = Arc::clone(&executor);
        let second_registry = Arc::clone(&registry);
        let second_operations = Arc::clone(&operations);
        let second = std::thread::spawn(move || {
            let caller = std::thread::current().id();
            blocked_rx.recv().unwrap();
            assert!(second_registry.set_with(2, true, |_| unreachable!()).0);
            let operations = Arc::clone(&second_operations);
            second_executor
                .dispatch(move || {
                    operations
                        .lock()
                        .unwrap()
                        .push(("input", std::thread::current().id()));
                    Ok(())
                })
                .unwrap();
            second_owned_tx.send(()).unwrap();
            first_released_rx.recv().unwrap();
            let off_executor = Arc::clone(&second_executor);
            assert!(
                second_registry
                    .set_with(2, false, move |blocked| {
                        let operations = Arc::clone(&second_operations);
                        off_executor
                            .dispatch(move || {
                                operations
                                    .lock()
                                    .unwrap()
                                    .push(("block-off", std::thread::current().id()));
                                Ok((!blocked, String::new()))
                            })
                            .unwrap()
                    })
                    .0
            );
            caller
        });

        let first_caller = first.join().unwrap();
        let second_caller = second.join().unwrap();
        let operations = operations.lock().unwrap();
        assert_eq!(
            operations.iter().map(|entry| entry.0).collect::<Vec<_>>(),
            vec!["block-on", "input", "block-off"]
        );
        let executor_thread = operations[0].1;
        assert!(operations.iter().all(|entry| entry.1 == executor_thread));
        assert_ne!(first_caller, executor_thread);
        assert_ne!(second_caller, executor_thread);
        assert_ne!(first_caller, second_caller);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_last_worker_cleanup_excludes_concurrent_registration() {
        let registry = Arc::new(InputKeyOwnerRegistry::default());
        registry.register_worker();
        let (cleanup_entered_tx, cleanup_entered_rx) = std_mpsc::channel();
        let (allow_cleanup_tx, allow_cleanup_rx) = std_mpsc::channel();
        let final_registry = Arc::clone(&registry);
        let final_worker = std::thread::spawn(move || {
            assert!(final_registry.unregister_worker(|| {
                cleanup_entered_tx.send(()).unwrap();
                allow_cleanup_rx.recv().unwrap();
            }));
        });
        cleanup_entered_rx.recv().unwrap();

        let (registered_tx, registered_rx) = std_mpsc::channel();
        let registering_registry = Arc::clone(&registry);
        let registering = std::thread::spawn(move || {
            registering_registry.register_worker();
            registered_tx.send(()).unwrap();
        });
        assert!(registered_rx
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err());
        allow_cleanup_tx.send(()).unwrap();
        registered_rx.recv().unwrap();
        final_worker.join().unwrap();
        registering.join().unwrap();
        assert!(registry.unregister_worker(|| {}));
    }

    #[test]
    fn desktop_key_owner_transition_is_linearized_with_physical_dispatch() {
        let registry = Arc::new(InputKeyOwnerRegistry::default());
        let mut first = InputKeyOwnership::new(Arc::clone(&registry));
        let second = InputKeyOwnership::new(Arc::clone(&registry));
        let mut down = KeyEvent::new();
        down.set_control_key(ControlKey::Control);
        down.down = true;
        assert!(first.dispatch(&down, |_, _| Ok(())).unwrap());

        let mut up = down.clone();
        up.down = false;
        let (up_entered_tx, up_entered_rx) = std_mpsc::channel();
        let (release_up_tx, release_up_rx) = std_mpsc::channel();
        let dispatch_order = Arc::new(StdMutex::new(Vec::new()));
        let up_order = Arc::clone(&dispatch_order);
        let first_thread = std::thread::spawn(move || {
            assert!(first
                .dispatch(&up, |_, _| {
                    up_order.lock().unwrap().push(false);
                    up_entered_tx.send(()).unwrap();
                    release_up_rx.recv().unwrap();
                    Ok(())
                })
                .unwrap());
            first
        });
        up_entered_rx.recv().unwrap();

        let (down_dispatched_tx, down_dispatched_rx) = std_mpsc::channel();
        let down_order = Arc::clone(&dispatch_order);
        let second_thread = std::thread::spawn(move || {
            let mut second = second;
            assert!(second
                .dispatch(&down, |_, _| {
                    down_order.lock().unwrap().push(true);
                    down_dispatched_tx.send(()).unwrap();
                    Ok(())
                })
                .unwrap());
            second
        });
        assert!(down_dispatched_rx
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err());
        release_up_tx.send(()).unwrap();
        down_dispatched_rx.recv().unwrap();

        let first = first_thread.join().unwrap();
        let mut second = second_thread.join().unwrap();
        assert_eq!(*dispatch_order.lock().unwrap(), vec![false, true]);
        assert!(first.held.is_empty());
        let mut final_releases = Vec::new();
        second
            .release_all(|event, _| {
                final_releases.push(event.clone());
                Ok(())
            })
            .unwrap();
        assert_eq!(final_releases.len(), 1);
        assert!(registry.lock().is_empty());
    }

    #[test]
    fn desktop_input_cleanup_contains_panics() {
        assert!(!run_input_cleanup_action(
            "testing panic containment",
            || { panic!("expected cleanup panic") }
        ));
        assert!(run_input_cleanup_action(
            "testing successful cleanup",
            || {}
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn desktop_input_join_ownership_survives_cancelled_async_wait() {
        let (release_tx, release_rx) = std_mpsc::channel();
        let (join_tx, completion) = spawn_input_worker_supervisor(
            "test-input-supervisor".to_owned(),
            Arc::new(AtomicUsize::new(0)),
        )
        .unwrap();
        let worker = std::thread::spawn(move || {
            let _ = release_rx.recv();
        });
        join_tx.try_send(worker).unwrap();
        let first_completion = Arc::clone(&completion);
        let first_wait = tokio::task::spawn_blocking(move || first_completion.wait());
        tokio::task::yield_now().await;
        first_wait.abort();

        let final_completion = Arc::clone(&completion);
        let final_wait = tokio::task::spawn_blocking(move || final_completion.wait());
        tokio::task::yield_now().await;
        assert!(!final_wait.is_finished());
        release_tx.send(()).unwrap();
        assert!(final_wait.await.unwrap());
    }

    #[test]
    fn desktop_input_drop_delegates_join_without_waiting_for_dispatch() {
        let execution = Arc::new(InputExecutionGate::default());
        let worker_execution = Arc::clone(&execution);
        let (entered_tx, entered_rx) = std_mpsc::channel();
        let (release_tx, release_rx) = std_mpsc::channel();
        let (join_tx, completion) = spawn_input_worker_supervisor(
            "test-input-supervisor".to_owned(),
            Arc::new(AtomicUsize::new(0)),
        )
        .unwrap();
        let worker = std::thread::spawn(move || {
            worker_execution.dispatch(|| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            });
        });
        join_tx.try_send(worker).unwrap();
        entered_rx.recv().unwrap();

        let input_worker = InputWorker {
            execution,
            completion: Arc::clone(&completion),
        };
        input_worker.execution.cancel();
        drop(input_worker);
        assert!(completion.lock_result().is_none());

        release_tx.send(()).unwrap();
        assert!(completion.wait());
    }

    fn special_key(key: ControlKey, down: bool, press: bool) -> KeyEvent {
        let mut event = KeyEvent::new();
        event.set_control_key(key);
        event.down = down;
        event.press = press;
        event
    }

    #[test]
    fn desktop_special_keys_are_consumed_and_trigger_only_on_edges() {
        let mut state = SpecialKeyState::default();
        assert_eq!(
            state.observe(&special_key(ControlKey::CtrlAltDel, true, false)),
            Some(Some(SpecialKeyAction::CtrlAltDel))
        );
        assert_eq!(
            state.observe(&special_key(ControlKey::CtrlAltDel, true, false)),
            Some(None)
        );
        assert_eq!(
            state.observe(&special_key(ControlKey::CtrlAltDel, false, false)),
            Some(None)
        );
        assert_eq!(
            state.observe(&special_key(ControlKey::CtrlAltDel, true, false)),
            Some(Some(SpecialKeyAction::CtrlAltDel))
        );
        assert_eq!(
            state.observe(&special_key(ControlKey::LockScreen, false, true)),
            Some(Some(SpecialKeyAction::LockScreen))
        );

        let mut ordinary = KeyEvent::new();
        ordinary.set_control_key(ControlKey::Return);
        assert_eq!(state.observe(&ordinary), None);
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct SessionKey {
    peer_id: String,
    name: String,
    session_id: u64,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
struct StartCmIpcPara {
    conn_id: i32,
    cm_auth_token: String,
    rx_to_cm: mpsc::Receiver<ipc::Data>,
    cm_terminal: oneshot::Receiver<crate::ui_cm_interface::CmConnectionTerminal>,
    tx_from_cm: mpsc::UnboundedSender<ipc::Data>,
    rx_desktop_ready: mpsc::Receiver<()>,
    tx_cm_stream_ready: mpsc::Sender<()>,
    owner_closed: oneshot::Receiver<()>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AuthConnType {
    Remote,
    FileTransfer,
    PortForward,
    ViewCamera,
    Terminal,
}

fn login_video_frame_receipt_version_is_compatible(login: &LoginRequest) -> bool {
    let is_video_session = matches!(
        login.union.as_ref(),
        None | Some(login_request::Union::ViewCamera(_))
    );
    !is_video_session || login.video_frame_receipt_version == VIDEO_FRAME_RECEIPT_VERSION
}

#[cfg(target_os = "windows")]
impl AuthConnType {
    fn to_cm_auth_conn_type(self) -> ipc::CmAuthConnType {
        match self {
            Self::Remote => ipc::CmAuthConnType::Remote,
            Self::FileTransfer => ipc::CmAuthConnType::FileTransfer,
            Self::PortForward => ipc::CmAuthConnType::PortForward,
            Self::ViewCamera => ipc::CmAuthConnType::ViewCamera,
            Self::Terminal => ipc::CmAuthConnType::Terminal,
        }
    }
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Eq, PartialEq)]
enum WindowsTerminalProcessAuthority {
    ProcessOwner,
    ActiveSessionUser,
}

enum CmLoginFollowup {
    NoAction,
    ReadInitialDirectory {
        path: String,
        include_hidden: bool,
    },
}

#[cfg(any(target_os = "windows", test))]
fn windows_terminal_process_authority(
    service_owned: bool,
    local_system: bool,
) -> Result<WindowsTerminalProcessAuthority, &'static str> {
    match (service_owned, local_system) {
        (true, true) => Ok(WindowsTerminalProcessAuthority::ActiveSessionUser),
        (false, false) => Ok(WindowsTerminalProcessAuthority::ProcessOwner),
        (true, false) => Err("Service-owned Windows terminal server is not LocalSystem."),
        (false, true) => Err("Unclassified LocalSystem server cannot provide a terminal."),
    }
}

struct ControlledAudioThread {
    format: (u32, u32),
    decoder: OwnedMediaThread,
}

pub struct Connection {
    inner: ConnInner,
    display_idx: usize,
    // R-T8 (§20): the single owner — and therefore the single writer — of this
    // connection's `FramedStream`. The stream is never `.split()`, cloned, or shared;
    // this `Connection`'s run-loop task is the sole task that ever writes it. Every other
    // producer (video/audio/clipboard/camera/CM) reaches the wire only by sending on an
    // `mpsc` whose receiver this loop drains, so all output funnels through one writer and
    // frame/seal order equals wire order. See `FramedStream`'s contract doc in hbb_common.
    stream: super::Stream,
    server: super::ServerPtrWeak,
    read_jobs: Vec<fs::TransferJob>,
    file_timer: crate::RustDeskInterval,
    file_transfer: Option<(String, bool)>,
    view_camera: bool,
    terminal: bool,
    // R-F1/R-S5: the dialed LOCAL target socket of a port-forward/RDP tunnel — a PLAINTEXT loopback/
    // LAN connection to the actual service (e.g. localhost:3389). The peer side of the relay is
    // self.stream, the KEYED session, so the tunnel is SEALED on the wire (R-A9); only the last hop
    // to the local target is raw. `port_forward_address` is surfaced to the CM for display.
    port_forward_socket: Option<Framed<TcpStream, BytesCodec>>,
    port_forward_address: String,
    tx_to_cm: mpsc::Sender<ipc::Data>,
    authorized: bool,
    credential_generation: u64,
    #[cfg(target_os = "android")]
    android_server_generation: u64,
    keyboard: bool,
    clipboard: bool,
    audio: bool,
    file: bool,
    restart: bool,
    recording: bool,
    block_input: bool,
    privacy_mode: bool,
    control_permissions: Option<ControlPermissions>,
    last_test_delay: Option<Instant>,
    network_delay: u32,
    lock_after_session_end: bool,
    show_remote_cursor: bool,
    // by peer
    ip: String,
    // by peer
    disable_keyboard: bool,
    // by peer
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    show_my_cursor: bool,
    // by peer
    disable_clipboard: bool,
    // by peer
    disable_audio: bool,
    // by peer
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    enable_file_transfer: bool,
    // The accepted peer-audio format and its exact decoder worker are one
    // voice-call-owned lifetime; neither can survive or replace the other.
    controlled_audio: Option<ControlledAudioThread>,
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    tx_input: InputQueue,
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    rx_input: Option<std_mpsc::Receiver<QueuedInput>>,
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    input_worker: Option<InputWorker>,
    lr: LoginRequest,
    peer_argb: u32,
    chat_unanswered: bool,
    file_transferred: bool,
    #[cfg(windows)]
    portable: PortableState,
    voice_call_request_timestamp: Option<NonZeroI64>,
    voice_call_input: Option<audio_service::VoiceCallInputLease>,
    options_in_login: Option<OptionMessage>,
    #[cfg(target_os = "android")]
    pressed_modifiers: HashSet<rdev::Key>,
    #[cfg(target_os = "linux")]
    linux_headless_handle: LinuxHeadlessHandle,
    closed: bool,
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    start_cm_ipc_para: Option<StartCmIpcPara>,
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    cm_ipc_owner: Option<oneshot::Sender<()>>,
    cm_terminal: Option<oneshot::Sender<crate::ui_cm_interface::CmConnectionTerminal>>,
    cm_command_failure: Option<String>,
    cm_auth_token: String,
    cm_file_login_published: bool,
    auto_disconnect_timer: Option<(Instant, u64)>,
    authed_conn_id: Option<self::raii::AuthedConnID>,
    file_remove_log_control: FileRemoveLogControl,
    last_supported_encoding: Option<SupportedEncoding>,
    services_subed: bool,
    delayed_read_dir: Option<(String, bool)>,
    #[cfg(target_os = "macos")]
    retina: Retina,
    follow_remote_cursor: bool,
    follow_remote_window: bool,
    multi_ui_session: bool,
    cm_file_authority_counter: u64,
    cm_read_jobs: HashMap<i32, CmReadAuthority>,
    cm_write_jobs: HashMap<i32, CmWriteAuthority>,
    cm_file_job_ids_seen: HashSet<i32>,
    cm_file_requests: HashMap<u64, CmFileRequestAuthority>,
    file_writes: ControlledFileWriteTracker,
    file_flow_failure: Option<(ControlledFileWriteContext, String)>,
    peer_text_gate: crate::peer_text::PeerTextGate,
    terminal_service_id: String,
    terminal_persistent: bool,
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    terminal_service_lease: Option<terminal_service::TerminalServiceLease>,
    display_control_reject_log: DisplayControlRejectLog,
}

impl ConnInner {
    pub(crate) fn new(id: i32, tx: Option<Sender>, tx_video: Option<VideoEgressSender>) -> Self {
        Self::with_audio(id, tx, tx_video, None)
    }

    pub(crate) fn with_audio(
        id: i32,
        tx: Option<Sender>,
        tx_video: Option<VideoEgressSender>,
        tx_audio: Option<AudioEgressSender>,
    ) -> Self {
        Self {
            id,
            tx,
            tx_video,
            tx_audio,
            #[cfg(target_os = "windows")]
            cm_clipboard_authority: None,
        }
    }

    fn retire_video_frames(&self, retired: Vec<VideoFrameIdentity>) {
        for frame in retired {
            video_service::retire_video_frame_round(
                frame.source,
                frame.display,
                frame.generation,
                self.id,
            );
        }
    }

    pub(crate) fn send_video_frame(
        &self,
        msg: Arc<Message>,
        source: VideoSource,
        display: usize,
        generation: u64,
    ) {
        if let Some(tx) = self.tx_video.as_ref() {
            self.retire_video_frames(tx.send_video_frame(msg, source, display, generation));
        } else {
            video_service::retire_video_frame_round(source, display, generation, self.id);
        }
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn cm_clipboard_authority(&self) -> Option<ipc::CmClipboardAuthority> {
        self.cm_clipboard_authority.clone()
    }

    #[cfg(target_os = "windows")]
    fn set_cm_clipboard_authority(
        &mut self,
        conn_type: ipc::CmAuthConnType,
        cm_auth_token: String,
    ) {
        self.cm_clipboard_authority = Some(ipc::CmClipboardAuthority {
            id: self.id,
            conn_type,
            cm_auth_token,
        });
    }
}

impl Subscriber for ConnInner {
    #[inline]
    fn id(&self) -> i32 {
        self.id
    }

    #[inline]
    fn send(&mut self, msg: Arc<Message>) {
        let tx_by_audio = match &msg.union {
            Some(message::Union::AudioFrame(_)) => true,
            Some(message::Union::Misc(misc)) => {
                matches!(&misc.union, Some(misc::Union::AudioFormat(_)))
            }
            _ => false,
        };
        if tx_by_audio {
            if let Some(tx) = self.tx_audio.as_ref() {
                tx.send(msg);
            }
            return;
        }

        match &msg.union {
            Some(message::Union::VideoFrame(_)) => {
                log::error!("video frame bypassed exact acknowledgement-round enqueue");
            }
            Some(message::Union::Misc(misc))
                if matches!(&misc.union, Some(misc::Union::SwitchDisplay(_))) =>
            {
                if let Some(tx) = self.tx_video.as_ref() {
                    self.retire_video_frames(tx.send_switch_display(msg));
                }
            }
            _ => {
                if let Some(tx) = self.tx.as_mut() {
                    allow_err!(tx.send((Instant::now(), msg)));
                }
            }
        }
    }
}

#[cfg(test)]
mod display_control_validation_tests {
    use super::*;

    #[test]
    fn r_s11go_controlled_display_requests_are_exact_or_terminal() {
        assert!(!capture_display_has_exactly_one_operation(
            &CaptureDisplays::new()
        ));
        for displays in [
            CaptureDisplays {
                add: vec![0],
                ..Default::default()
            },
            CaptureDisplays {
                sub: vec![0],
                ..Default::default()
            },
            CaptureDisplays {
                set: vec![0],
                ..Default::default()
            },
        ] {
            assert!(capture_display_has_exactly_one_operation(&displays));
        }
        assert!(!capture_display_has_exactly_one_operation(
            &CaptureDisplays {
                add: vec![0],
                set: vec![0],
                ..Default::default()
            }
        ));

        assert!(switch_display_resolution_is_well_formed(0, 0));
        assert!(switch_display_resolution_is_well_formed(1, 1));
        assert!(!switch_display_resolution_is_well_formed(1, 0));
        assert!(!switch_display_resolution_is_well_formed(-1, -1));
        assert!(!switch_display_resolution_is_well_formed(
            MAX_PEER_DISPLAY_DIMENSION + 1,
            MAX_PEER_DISPLAY_DIMENSION + 1,
        ));
    }
}

#[cfg(test)]
mod cm_process_generation_tests {
    use super::*;

    struct FakeCmProcess {
        identity: u64,
        exited: bool,
        reap_error: bool,
        reap_count: Arc<AtomicUsize>,
    }

    impl CmOwnedProcess for FakeCmProcess {
        type Identity = u64;

        fn identity(&self) -> Self::Identity {
            self.identity
        }

        fn try_reap_exited(&mut self) -> ResultType<bool> {
            self.reap_count.fetch_add(1, Ordering::SeqCst);
            if self.reap_error {
                bail!("synthetic process liveness query failed");
            }
            Ok(self.exited)
        }
    }

    #[test]
    fn active_authentication_lease_prevents_reap_and_generation_replacement() {
        let state = StdMutex::new(None);
        let launches = AtomicUsize::new(0);
        let reaps = Arc::new(AtomicUsize::new(0));
        let launch = |_: &str| {
            let identity = launches.fetch_add(1, Ordering::SeqCst) as u64 + 1;
            Ok(FakeCmProcess {
                identity,
                exited: false,
                reap_error: false,
                reap_count: reaps.clone(),
            })
        };

        let first = lease_or_launch_cm_process(&state, "--cm", launch).unwrap();
        let second = lease_or_launch_cm_process(&state, "--cm", launch).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(launches.load(Ordering::SeqCst), 1);

        first.process.lock().unwrap().exited = true;
        let third = lease_or_launch_cm_process(&state, "--cm", launch).unwrap();
        assert!(Arc::ptr_eq(&first, &third));
        assert_eq!(reaps.load(Ordering::SeqCst), 0);
        assert_eq!(launches.load(Ordering::SeqCst), 1);

        drop(second);
        drop(third);
        drop(first);
        let replacement = lease_or_launch_cm_process(&state, "--cm", launch).unwrap();
        assert_eq!(replacement.identity, 2);
        assert_eq!(reaps.load(Ordering::SeqCst), 1);
        assert_eq!(launches.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn failed_authentication_retires_only_the_unshared_exited_generation() {
        let state = StdMutex::new(None);
        let reaps = Arc::new(AtomicUsize::new(0));
        let generation = lease_or_launch_cm_process(&state, "--cm", |_| {
            Ok(FakeCmProcess {
                identity: 7,
                exited: true,
                reap_error: false,
                reap_count: reaps.clone(),
            })
        })
        .unwrap();
        let other_authentication = generation.clone();

        retire_failed_cm_process_if_exited(&state, &generation).unwrap();
        assert_eq!(reaps.load(Ordering::SeqCst), 0);
        assert!(lease_existing_cm_process(&state, "--cm").is_ok());

        drop(other_authentication);
        retire_failed_cm_process_if_exited(&state, &generation).unwrap();
        assert_eq!(reaps.load(Ordering::SeqCst), 1);
        assert!(lease_existing_cm_process(&state, "--cm").is_err());
        assert!(lease_existing_cm_process(&state, "--cm-no-ui").is_err());
    }

    #[test]
    fn concurrent_selection_launches_one_generation() {
        let state = Arc::new(StdMutex::new(None));
        let launches = Arc::new(AtomicUsize::new(0));
        let reaps = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(std::sync::Barrier::new(9));

        std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for _ in 0..8 {
                let state = state.clone();
                let launches = launches.clone();
                let reaps = reaps.clone();
                let start = start.clone();
                workers.push(scope.spawn(move || {
                    start.wait();
                    lease_or_launch_cm_process(&state, "--cm", |_| {
                        let identity = launches.fetch_add(1, Ordering::SeqCst) as u64 + 1;
                        Ok(FakeCmProcess {
                            identity,
                            exited: false,
                            reap_error: false,
                            reap_count: reaps,
                        })
                    })
                    .unwrap()
                }));
            }
            start.wait();
            for worker in workers {
                assert_eq!(worker.join().unwrap().identity, 1);
            }
        });

        assert_eq!(launches.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn uncertain_liveness_preserves_the_exact_generation() {
        let state = StdMutex::new(None);
        let launches = AtomicUsize::new(0);
        let reaps = Arc::new(AtomicUsize::new(0));
        let generation = lease_or_launch_cm_process(&state, "--cm", |_| {
            launches.fetch_add(1, Ordering::SeqCst);
            Ok(FakeCmProcess {
                identity: 11,
                exited: false,
                reap_error: true,
                reap_count: reaps.clone(),
            })
        })
        .unwrap();
        drop(generation);

        assert!(lease_or_launch_cm_process(&state, "--cm", |_| {
            launches.fetch_add(1, Ordering::SeqCst);
            Ok(FakeCmProcess {
                identity: 12,
                exited: false,
                reap_error: false,
                reap_count: reaps.clone(),
            })
        })
        .is_err());
        assert_eq!(launches.load(Ordering::SeqCst), 1);
        assert_eq!(reaps.load(Ordering::SeqCst), 1);
        assert_eq!(
            lease_existing_cm_process(&state, "--cm").unwrap().identity,
            11
        );
    }
}

#[cfg(test)]
mod audio_egress_tests {
    use super::*;

    fn frame(data: &[u8]) -> Arc<Message> {
        let mut message = Message::new();
        message.set_audio_frame(AudioFrame {
            data: data.to_vec().into(),
            ..Default::default()
        });
        Arc::new(message)
    }

    fn format(sample_rate: u32) -> Arc<Message> {
        let mut misc = Misc::new();
        misc.set_audio_format(AudioFormat {
            sample_rate,
            channels: 2,
            ..Default::default()
        });
        let mut message = Message::new();
        message.set_misc(misc);
        Arc::new(message)
    }

    fn frame_data(message: &Message) -> &[u8] {
        match &message.union {
            Some(message::Union::AudioFrame(frame)) => &frame.data,
            _ => panic!("expected an audio frame"),
        }
    }

    fn format_sample_rate(message: &Message) -> u32 {
        match &message.union {
            Some(message::Union::Misc(misc)) => match &misc.union {
                Some(misc::Union::AudioFormat(format)) => format.sample_rate,
                _ => panic!("expected an audio format"),
            },
            _ => panic!("expected an audio format"),
        }
    }

    #[test]
    fn r_s11eh_audio_egress_retains_only_the_latest_frame() {
        let (sender, mut receiver) = audio_egress_channel();
        sender.send(frame(b"first"));
        sender.send(frame(b"second"));
        sender.send(frame(b"latest"));

        let (_, actual) = receiver
            .blocking_recv()
            .expect("the latest frame must remain available");
        assert_eq!(frame_data(&actual), b"latest");
        assert!(receiver.take_next().is_none());
    }

    #[test]
    fn r_s11eh_audio_format_precedes_its_latest_frame() {
        let (sender, mut receiver) = audio_egress_channel();
        sender.send(format(48_000));
        sender.send(frame(b"first"));
        sender.send(frame(b"latest"));

        let (_, actual_format) = receiver
            .blocking_recv()
            .expect("the pending format must remain available");
        let (_, actual_frame) = receiver
            .blocking_recv()
            .expect("the pending frame must remain available");
        assert_eq!(format_sample_rate(&actual_format), 48_000);
        assert_eq!(frame_data(&actual_frame), b"latest");
        assert!(receiver.take_next().is_none());
    }

    #[test]
    fn r_s11eh_new_audio_format_retires_an_old_pending_frame() {
        let (sender, mut receiver) = audio_egress_channel();
        sender.send(format(24_000));
        sender.send(frame(b"old-generation"));
        sender.send(format(48_000));
        sender.send(frame(b"new-generation"));

        let (_, actual_format) = receiver
            .blocking_recv()
            .expect("the replacement format must remain available");
        let (_, actual_frame) = receiver
            .blocking_recv()
            .expect("the replacement frame must remain available");
        assert_eq!(format_sample_rate(&actual_format), 48_000);
        assert_eq!(frame_data(&actual_frame), b"new-generation");
        assert!(receiver.take_next().is_none());
    }

    #[test]
    fn r_s11eh_conn_inner_routes_audio_away_from_control_and_video() {
        let (control_sender, mut control_receiver) = mpsc::unbounded_channel();
        let (video_sender, mut video_receiver) = video_egress_channel();
        let (audio_sender, mut audio_receiver) = audio_egress_channel();
        let mut subscriber = ConnInner::with_audio(
            41,
            Some(control_sender),
            Some(video_sender),
            Some(audio_sender),
        );

        subscriber.send(format(48_000));
        subscriber.send(frame(b"audio"));
        let control = Arc::new(Message::new());
        subscriber.send(Arc::clone(&control));
        let mut video = Message::new();
        video.set_video_frame(VideoFrame {
            display: 0,
            generation: 1,
            union: Some(video_frame::Union::Rgb(RGB::new())),
            ..Default::default()
        });
        subscriber.send_video_frame(Arc::new(video), VideoSource::Monitor, 0, 1);

        let (_, actual_control) = control_receiver
            .try_recv()
            .expect("control traffic must retain its existing channel");
        assert!(Arc::ptr_eq(&actual_control, &control));
        assert!(control_receiver.try_recv().is_err());
        assert!(matches!(
            video_receiver.take_next(),
            Some(VideoEgressItem::Frame(_))
        ));
        assert!(video_receiver.take_next().is_none());

        let (_, actual_format) = audio_receiver
            .blocking_recv()
            .expect("audio format must use the audio mailbox");
        let (_, actual_frame) = audio_receiver
            .blocking_recv()
            .expect("audio frame must use the audio mailbox");
        assert_eq!(format_sample_rate(&actual_format), 48_000);
        assert_eq!(frame_data(&actual_frame), b"audio");
    }

    #[test]
    fn r_s11eh_audio_egress_closes_after_the_exact_sender_retires() {
        let (sender, mut receiver) = audio_egress_channel();
        drop(sender);
        assert!(receiver.blocking_recv().is_none());

        let (sender, receiver) = audio_egress_channel();
        let pending = frame(b"retained-until-receiver-close");
        let pending_weak = Arc::downgrade(&pending);
        sender.send(pending);
        drop(receiver);
        assert!(
            pending_weak.upgrade().is_none(),
            "receiver retirement must release retained audio without another producer send"
        );
        drop(sender);
    }

    #[tokio::test]
    async fn r_s11eh_async_audio_egress_waits_without_polling_and_closes() {
        let (sender, mut receiver) = audio_egress_channel();
        assert!(
            time::timeout(Duration::from_millis(20), receiver.recv())
                .await
                .is_err(),
            "an empty audio mailbox must remain pending"
        );

        let expected = frame(b"async");
        sender.send(Arc::clone(&expected));
        let (_, actual) = time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .expect("audio wake must be bounded")
            .expect("the live sender must keep the mailbox open");
        assert!(Arc::ptr_eq(&actual, &expected));

        drop(sender);
        assert!(time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .expect("sender retirement must wake the receiver")
            .is_none());
    }
}

#[cfg(test)]
mod video_delivery_tests {
    use super::*;

    fn pending(source: VideoSource, display: usize, generation: u64) -> PendingVideoDelivery {
        let (_completion, receipt) = oneshot::channel();
        PendingVideoDelivery {
            writer_receipt: Some(receipt),
            identity: VideoFrameIdentity {
                source,
                display,
                generation,
            },
            queued_at: Instant::now(),
            writer_complete: false,
            peer_received: false,
        }
    }

    fn receipt(display: i32, generation: u64) -> VideoFrameReceipt {
        VideoFrameReceipt {
            display,
            generation,
            ..Default::default()
        }
    }

    #[test]
    fn r_s11fk_local_write_then_exact_peer_receipt_completes_once() {
        let mut delivery = pending(VideoSource::Monitor, 2, 41);
        delivery.mark_writer_complete();
        assert!(!delivery.is_complete());
        assert!(delivery.observe_peer_receipt(Some(VideoSource::Monitor), &receipt(2, 41)));
        assert!(delivery.is_complete());
        assert!(!delivery.observe_peer_receipt(Some(VideoSource::Monitor), &receipt(2, 41)));
    }

    #[test]
    fn r_s11fk_exact_peer_receipt_then_local_write_completes() {
        let mut delivery = pending(VideoSource::Camera, 3, 52);
        assert!(delivery.observe_peer_receipt(Some(VideoSource::Camera), &receipt(3, 52)));
        assert!(!delivery.is_complete());
        delivery.mark_writer_complete();
        assert!(delivery.is_complete());
    }

    #[test]
    fn r_s11fk_wrong_scope_zero_stale_and_mismatched_receipts_are_inert() {
        let mut delivery = pending(VideoSource::Monitor, 4, 63);
        for (source, receipt) in [
            (None, receipt(4, 63)),
            (Some(VideoSource::Camera), receipt(4, 63)),
            (Some(VideoSource::Monitor), receipt(-1, 63)),
            (Some(VideoSource::Monitor), receipt(4, 0)),
            (Some(VideoSource::Monitor), receipt(4, 62)),
            (Some(VideoSource::Monitor), receipt(4, 64)),
            (Some(VideoSource::Monitor), receipt(5, 63)),
        ] {
            assert!(!delivery.observe_peer_receipt(source, &receipt));
            assert!(!delivery.peer_received);
        }
        delivery.mark_writer_complete();
        assert!(!delivery.is_complete());
    }

    #[test]
    fn r_s11fk_video_login_requires_exact_version_without_affecting_nonvideo_sessions() {
        let mut remote = LoginRequest::new();
        assert!(!login_video_frame_receipt_version_is_compatible(&remote));
        remote.video_frame_receipt_version = VIDEO_FRAME_RECEIPT_VERSION;
        assert!(login_video_frame_receipt_version_is_compatible(&remote));

        let mut camera = LoginRequest::new();
        camera.set_view_camera(ViewCamera::new());
        assert!(!login_video_frame_receipt_version_is_compatible(&camera));
        camera.video_frame_receipt_version = VIDEO_FRAME_RECEIPT_VERSION;
        assert!(login_video_frame_receipt_version_is_compatible(&camera));

        let mut file = LoginRequest::new();
        file.set_file_transfer(FileTransfer::new());
        assert!(login_video_frame_receipt_version_is_compatible(&file));

        let mut terminal = LoginRequest::new();
        terminal.set_terminal(Terminal::new());
        assert!(login_video_frame_receipt_version_is_compatible(&terminal));
    }
}

#[cfg(test)]
mod video_egress_tests {
    use super::*;

    fn encoded_video(display: usize, key: bool, data: &[u8], generation: u64) -> Arc<Message> {
        let mut video = VideoFrame::new();
        video.display = i32::try_from(display).expect("test display must fit i32");
        video.generation = generation;
        video.set_vp9s(EncodedVideoFrames {
            frames: vec![EncodedVideoFrame {
                data: data.to_vec().into(),
                key,
                ..Default::default()
            }],
            ..Default::default()
        });
        let mut message = Message::new();
        message.set_video_frame(video);
        Arc::new(message)
    }

    fn switch_display(display: usize) -> Arc<Message> {
        let mut misc = Misc::new();
        misc.set_switch_display(SwitchDisplay {
            display: i32::try_from(display).expect("test display must fit i32"),
            ..Default::default()
        });
        let mut message = Message::new();
        message.set_misc(misc);
        Arc::new(message)
    }

    fn identity(source: VideoSource, display: usize, generation: u64) -> VideoFrameIdentity {
        VideoFrameIdentity {
            source,
            display,
            generation,
        }
    }

    #[test]
    fn r_s11fb_latest_independent_frame_replaces_only_the_same_display() {
        let (sender, mut receiver) = video_egress_channel();
        assert!(sender
            .send_video_frame(
                encoded_video(0, true, b"old", 1),
                VideoSource::Monitor,
                0,
                1
            )
            .is_empty());
        assert_eq!(
            sender.send_video_frame(
                encoded_video(0, true, b"latest", 2),
                VideoSource::Monitor,
                0,
                2,
            ),
            vec![identity(VideoSource::Monitor, 0, 1)]
        );

        let Some(VideoEgressItem::Frame(frame)) = receiver.take_next() else {
            panic!("the latest independent frame must remain ready");
        };
        assert_eq!(frame.identity(), identity(VideoSource::Monitor, 0, 2));
        assert!(receiver.take_next().is_none());
    }

    #[test]
    fn r_s11fb_fresh_display_rejects_dependent_until_independent() {
        let (sender, mut receiver) = video_egress_channel();
        assert_eq!(
            sender.send_video_frame(
                encoded_video(0, false, b"delta", 9),
                VideoSource::Monitor,
                0,
                9,
            ),
            vec![identity(VideoSource::Monitor, 0, 9)]
        );
        assert!(matches!(
            receiver.take_next(),
            Some(VideoEgressItem::RefreshRequired { display: 0 })
        ));

        assert!(sender
            .send_video_frame(
                encoded_video(0, true, b"key", 10),
                VideoSource::Monitor,
                0,
                10
            )
            .is_empty());
        let Some(VideoEgressItem::Frame(frame)) = receiver.take_next() else {
            panic!("an independent frame must open a fresh display");
        };
        assert_eq!(frame.identity(), identity(VideoSource::Monitor, 0, 10));
    }

    #[test]
    fn r_s11fb_dependent_replacement_requests_an_independent_sequence() {
        let (sender, mut receiver) = video_egress_channel();
        assert!(sender
            .send_video_frame(
                encoded_video(0, true, b"key", 10),
                VideoSource::Monitor,
                0,
                10
            )
            .is_empty());
        assert!(matches!(
            receiver.take_next(),
            Some(VideoEgressItem::Frame(_))
        ));
        assert!(sender
            .send_video_frame(
                encoded_video(0, false, b"one", 11),
                VideoSource::Monitor,
                0,
                11
            )
            .is_empty());
        assert_eq!(
            sender.send_video_frame(
                encoded_video(0, false, b"two", 12),
                VideoSource::Monitor,
                0,
                12,
            ),
            vec![
                identity(VideoSource::Monitor, 0, 11),
                identity(VideoSource::Monitor, 0, 12),
            ]
        );
        assert!(matches!(
            receiver.take_next(),
            Some(VideoEgressItem::RefreshRequired { display: 0 })
        ));

        assert_eq!(
            sender.send_video_frame(
                encoded_video(0, false, b"three", 13),
                VideoSource::Monitor,
                0,
                13,
            ),
            vec![identity(VideoSource::Monitor, 0, 13)]
        );
        assert!(matches!(
            receiver.take_next(),
            Some(VideoEgressItem::RefreshRequired { display: 0 })
        ));

        assert!(sender
            .send_video_frame(
                encoded_video(0, true, b"key", 14),
                VideoSource::Monitor,
                0,
                14
            )
            .is_empty());
        let Some(VideoEgressItem::Frame(frame)) = receiver.take_next() else {
            panic!("an independent frame must reopen the display");
        };
        assert_eq!(frame.identity(), identity(VideoSource::Monitor, 0, 14));
    }

    #[test]
    fn r_s11fb_displays_are_isolated_and_round_robin_ready() {
        let (sender, mut receiver) = video_egress_channel();
        assert!(sender
            .send_video_frame(
                encoded_video(2, true, b"two", 20),
                VideoSource::Monitor,
                2,
                20
            )
            .is_empty());
        assert!(sender
            .send_video_frame(
                encoded_video(7, true, b"seven", 21),
                VideoSource::Camera,
                7,
                21
            )
            .is_empty());

        let Some(VideoEgressItem::Frame(first)) = receiver.take_next() else {
            panic!("first display must be ready");
        };
        assert!(sender
            .send_video_frame(
                encoded_video(2, true, b"two-again", 22),
                VideoSource::Monitor,
                2,
                22,
            )
            .is_empty());
        let Some(VideoEgressItem::Frame(second)) = receiver.take_next() else {
            panic!("second display must be ready");
        };
        let Some(VideoEgressItem::Frame(third)) = receiver.take_next() else {
            panic!("requeued first display must follow already-ready second display");
        };
        assert_eq!(first.identity(), identity(VideoSource::Monitor, 2, 20));
        assert_eq!(second.identity(), identity(VideoSource::Camera, 7, 21));
        assert_eq!(third.identity(), identity(VideoSource::Monitor, 2, 22));
        assert!(receiver.take_next().is_none());
    }

    #[test]
    fn r_s11fb_switch_display_precedes_new_video_and_retires_old_video() {
        let (sender, mut receiver) = video_egress_channel();
        assert!(sender
            .send_video_frame(
                encoded_video(0, true, b"old", 30),
                VideoSource::Monitor,
                0,
                30
            )
            .is_empty());
        assert_eq!(
            sender.send_switch_display(switch_display(1)),
            vec![identity(VideoSource::Monitor, 0, 30)]
        );
        assert!(sender
            .send_video_frame(
                encoded_video(1, true, b"new", 31),
                VideoSource::Monitor,
                1,
                31
            )
            .is_empty());

        assert!(matches!(
            receiver.take_next(),
            Some(VideoEgressItem::SwitchDisplay(_))
        ));
        let Some(VideoEgressItem::Frame(frame)) = receiver.take_next() else {
            panic!("new-display video must follow the switch");
        };
        assert_eq!(frame.identity(), identity(VideoSource::Monitor, 1, 31));
    }

    #[test]
    fn r_s11fb_display_ownership_is_fixed_capacity() {
        let (sender, _receiver) = video_egress_channel();
        for display in 0..VIDEO_EGRESS_MAX_DISPLAYS {
            assert!(sender
                .send_video_frame(
                    encoded_video(display, true, b"bounded", display as u64 + 1),
                    VideoSource::Monitor,
                    display,
                    display as u64 + 1,
                )
                .is_empty());
        }
        let rejected = VIDEO_EGRESS_MAX_DISPLAYS;
        assert_eq!(
            sender.send_video_frame(
                encoded_video(rejected, true, b"overflow", 999),
                VideoSource::Monitor,
                rejected,
                999,
            ),
            vec![identity(VideoSource::Monitor, rejected, 999)]
        );
    }

    #[tokio::test]
    async fn r_s11fb_async_video_egress_waits_without_polling_and_closes() {
        let (sender, mut receiver) = video_egress_channel();
        assert!(time::timeout(Duration::from_millis(20), receiver.recv())
            .await
            .is_err());

        sender.send_video_frame(
            encoded_video(0, true, b"async", 40),
            VideoSource::Monitor,
            0,
            40,
        );
        assert!(matches!(
            time::timeout(Duration::from_secs(1), receiver.recv())
                .await
                .expect("video wake must be bounded"),
            Some(VideoEgressItem::Frame(_))
        ));
        drop(sender);
        assert!(time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .expect("sender retirement must wake the receiver")
            .is_none());
    }

    #[test]
    fn r_s11fb_closed_receiver_retires_a_stale_subscriber_enqueue() {
        let (sender, receiver) = video_egress_channel();
        drop(receiver);

        assert_eq!(
            sender.send_video_frame(
                encoded_video(0, true, b"closed", 50),
                VideoSource::Monitor,
                0,
                50,
            ),
            vec![identity(VideoSource::Monitor, 0, 50)]
        );
    }
}

const TEST_DELAY_TIMEOUT: Duration = Duration::from_secs(1);
const SEC30: Duration = Duration::from_secs(30);
const MILLI1: Duration = Duration::from_millis(1);

impl Connection {
    pub async fn start(
        addr: SocketAddr,
        stream: super::Stream,
        id: i32,
        server: super::ServerPtrWeak,
        control_permissions: Option<ControlPermissions>,
        credential_generation: u64,
        android_generation: Option<u64>,
    ) {
        // Android is not supported yet, so we always set control_permissions to None.
        #[cfg(target_os = "android")]
        let control_permissions = None;
        let _raii_id = raii::ConnectionID::new(id);
        let _raii_control_permissions_id =
            raii::ControlPermissionsID::new(id, &control_permissions);
        // R-T15c: no legacy `Hash` challenge is constructed/sent -- CPace is the sole authenticator.
        let (tx_from_cm_holder, mut rx_from_cm) = mpsc::unbounded_channel::<ipc::Data>();
        // holding tx_from_cm_holder to avoid cpu burning of rx_from_cm.recv when all sender closed
        let tx_from_cm = tx_from_cm_holder.clone();
        let (tx_to_cm, rx_to_cm) = mpsc::channel::<ipc::Data>(CM_COMMAND_QUEUE_CAPACITY);
        let (cm_terminal, cm_terminal_rx) = oneshot::channel();
        let (tx, mut rx) = mpsc::unbounded_channel::<(Instant, Arc<Message>)>();
        let (tx_video, rx_video) = video_egress_channel();
        let (tx_audio, mut rx_audio) = audio_egress_channel();
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        let (tx_input, rx_input) = std_mpsc::sync_channel(INPUT_QUEUE_CAPACITY);
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        let input_execution = Arc::new(InputExecutionGate::default());
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        let tx_input = InputQueue {
            sender: tx_input,
            queued_bytes: Arc::new(AtomicUsize::new(0)),
            execution: Arc::clone(&input_execution),
        };
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        let (tx_cm_stream_ready, _rx_cm_stream_ready) = mpsc::channel(1);
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        let (_tx_desktop_ready, rx_desktop_ready) = mpsc::channel(1);
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        let (cm_ipc_owner, cm_ipc_owner_closed) = oneshot::channel();
        #[cfg(target_os = "linux")]
        let linux_headless_handle =
            LinuxHeadlessHandle::new(_rx_cm_stream_ready, _tx_desktop_ready);

        let cm_auth_token = crate::encode64(hbb_common::rand::random::<[u8; 32]>());
        let mut conn = Self {
            inner: ConnInner::with_audio(id, Some(tx), Some(tx_video), Some(tx_audio)),
            display_idx: *display_service::PRIMARY_DISPLAY_IDX,
            stream,
            server,
            read_jobs: Vec::new(),
            file_timer: crate::rustdesk_interval(time::interval(SEC30)),
            file_transfer: None,
            view_camera: false,
            terminal: false,
            port_forward_socket: None,
            port_forward_address: "".to_owned(),
            tx_to_cm,
            authorized: false,
            credential_generation,
            #[cfg(target_os = "android")]
            android_server_generation: android_generation.unwrap_or_default(),
            keyboard: Self::permission(keys::OPTION_ENABLE_KEYBOARD, &control_permissions),
            clipboard: Self::permission(keys::OPTION_ENABLE_CLIPBOARD, &control_permissions),
            audio: Self::permission(keys::OPTION_ENABLE_AUDIO, &control_permissions),
            // to-do: make sure is the option correct here
            file: Self::permission(keys::OPTION_ENABLE_FILE_TRANSFER, &control_permissions),
            restart: Self::permission(keys::OPTION_ENABLE_REMOTE_RESTART, &control_permissions),
            recording: Self::permission(keys::OPTION_ENABLE_RECORD_SESSION, &control_permissions),
            block_input: Self::permission(keys::OPTION_ENABLE_BLOCK_INPUT, &control_permissions),
            privacy_mode: Self::permission(keys::OPTION_ENABLE_PRIVACY_MODE, &control_permissions),
            control_permissions,
            last_test_delay: None,
            network_delay: 0,
            lock_after_session_end: false,
            show_remote_cursor: false,
            follow_remote_cursor: false,
            follow_remote_window: false,
            multi_ui_session: false,
            ip: "".to_owned(),
            disable_audio: false,
            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
            enable_file_transfer: false,
            disable_clipboard: false,
            disable_keyboard: false,
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            show_my_cursor: false,
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            tx_input,
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            rx_input: Some(rx_input),
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            input_worker: None,
            lr: Default::default(),
            peer_argb: 0u32,
            chat_unanswered: false,
            file_transferred: false,
            #[cfg(windows)]
            portable: Default::default(),
            controlled_audio: None,
            voice_call_request_timestamp: None,
            voice_call_input: None,
            options_in_login: None,
            #[cfg(target_os = "android")]
            pressed_modifiers: Default::default(),
            #[cfg(target_os = "linux")]
            linux_headless_handle,
            closed: false,
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            start_cm_ipc_para: Some(StartCmIpcPara {
                conn_id: id,
                cm_auth_token: cm_auth_token.clone(),
                rx_to_cm,
                cm_terminal: cm_terminal_rx,
                tx_from_cm,
                rx_desktop_ready,
                tx_cm_stream_ready,
                owner_closed: cm_ipc_owner_closed,
            }),
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            cm_ipc_owner: Some(cm_ipc_owner),
            cm_terminal: Some(cm_terminal),
            cm_command_failure: None,
            cm_auth_token,
            cm_file_login_published: false,
            auto_disconnect_timer: None,
            authed_conn_id: None,
            file_remove_log_control: FileRemoveLogControl::new(id),
            last_supported_encoding: None,
            services_subed: false,
            delayed_read_dir: None,
            #[cfg(target_os = "macos")]
            retina: Retina::default(),
            cm_file_authority_counter: 0,
            cm_read_jobs: HashMap::new(),
            cm_write_jobs: HashMap::new(),
            cm_file_job_ids_seen: HashSet::new(),
            cm_file_requests: HashMap::new(),
            file_writes: ControlledFileWriteTracker::new(),
            file_flow_failure: None,
            peer_text_gate: Default::default(),
            terminal_service_id: "".to_owned(),
            terminal_persistent: false,
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            terminal_service_lease: None,
            display_control_reject_log: Default::default(),
        };
        let mut rx_video = rx_video.with_connection_owner(id);
        let addr = hbb_common::try_into_v4(addr);
        if !conn.on_open(addr).await {
            conn.closed = true;
            // sleep to ensure msg got received.
            sleep(1.).await;
            return;
        }
        #[cfg(target_os = "android")]
        start_channel(
            rx_to_cm,
            cm_terminal_rx,
            tx_from_cm,
            conn.android_server_generation,
        );
        #[cfg(target_os = "android")]
        conn.send_permission(Permission::Keyboard, conn.keyboard)
            .await;
        #[cfg(not(target_os = "android"))]
        if !conn.keyboard {
            conn.send_permission(Permission::Keyboard, false).await;
        }
        if !conn.clipboard {
            conn.send_permission(Permission::Clipboard, false).await;
        }
        if !conn.audio {
            conn.send_permission(Permission::Audio, false).await;
        }
        if !conn.file {
            conn.send_permission(Permission::File, false).await;
        }
        if !conn.restart {
            conn.send_permission(Permission::Restart, false).await;
        }
        if !conn.recording {
            conn.send_permission(Permission::Recording, false).await;
        }
        if !conn.block_input {
            conn.send_permission(Permission::BlockInput, false).await;
        }
        if !conn.privacy_mode {
            conn.send_permission(Permission::PrivacyMode, false).await;
        }
        let mut test_delay_timer =
            crate::rustdesk_interval(time::interval_at(Instant::now(), TEST_DELAY_TIMEOUT));
        let mut last_recv_time = Instant::now();

        let mut second_timer = crate::rustdesk_interval(time::interval(Duration::from_secs(1)));
        let mut pending_video_delivery: Option<PendingVideoDelivery> = None;

        #[cfg(feature = "unix-file-copy-paste")]
        let rx_clip_holder;
        let mut rx_clip;
        let _tx_clip: mpsc::UnboundedSender<i32>;
        #[cfg(feature = "unix-file-copy-paste")]
        {
            rx_clip_holder = (
                clipboard::get_rx_cliprdr_server(id),
                crate::SimpleCallOnReturn {
                    b: true,
                    f: Box::new(move || {
                        clipboard::remove_channel_by_conn_id(id);
                    }),
                },
            );
            rx_clip = rx_clip_holder.0.lock().await;
        }
        #[cfg(not(feature = "unix-file-copy-paste"))]
        {
            (_tx_clip, rx_clip) = mpsc::unbounded_channel::<i32>();
        }

        // R-T9 (§20): an owned clone of the process-wide shutdown token, selected on below so a
        // SIGTERM/SIGINT drains this session gracefully. Bound outside the loop because
        // `cancelled()` borrows the token for the future's lifetime.
        let shutdown = crate::server::shutdown_token();

        loop {
            if let Some(error) = conn.cm_command_failure.take() {
                conn.on_close(
                    &format!("connection-manager command publication failed: {error}"),
                    false,
                )
                .await;
                break;
            }
            if let Some((context, error)) = conn.file_flow_failure.take() {
                let reason = format!(
                    "controlled {} failed before peer operation completion (job={:?}, file={}): {}",
                    context.operation, context.job_id, context.file_num, error
                );
                conn.on_close(&reason, false).await;
                break;
            }

            tokio::select! {
                // biased; // video has higher priority // causing test_delay_timer failed while transferring big file

                completion = conn.file_writes.next(), if !conn.file_writes.is_empty() => {
                    let Some(completion) = completion else {
                        conn.on_close(
                            "controlled file writer completion set ended while ownership was pending",
                            false,
                        ).await;
                        break;
                    };
                    if let Err(error) = completion.result {
                        let context = completion.context.unwrap_or_else(|| {
                            ControlledFileWriteContext::response(
                                None,
                                -1,
                                "file writer completion",
                            )
                        });
                        let reason = format!(
                            "controlled {} failed before peer operation completion (job={:?}, file={}): {}",
                            context.operation, context.job_id, context.file_num, error
                        );
                        conn.on_close(&reason, false).await;
                        break;
                    }
                }

                // R-T9 (§20): graceful shutdown — drain this session cleanly instead of being
                // SIGKILL'd mid-write (which would truncate a file block on the peer and skip the
                // CM Close). Send a CloseReason, then break so the post-loop tail runs its full
                // cleanup (remove_connection + on_close → CM Close, capture/resolution restore).
                _ = shutdown.cancelled() => {
                    log::info!("#{} graceful shutdown — closing session", id);
                    conn.send_close_reason_no_retry("Server is shutting down").await;
                    break;
                }

                Some(data) = rx_from_cm.recv() => {
                    match data {
                        ipc::Data::Close => {
                            conn.chat_unanswered = false; // seen
                            conn.file_transferred = false; //seen
                            conn.send_close_reason_no_retry("").await;
                            conn.on_close("connection manager", true).await;
                            break;
                        }
                        ipc::Data::CmErr(e) => {
                            if e != "expected" {
                                // cm closed before connection
                                conn.on_close(&format!("connection manager error: {}", e), false).await;
                                break;
                            }
                        }
                        ipc::Data::ChatMessage{text} => {
                            let mut misc = Misc::new();
                            misc.set_chat_message(ChatMessage {
                                text,
                                ..Default::default()
                            });
                            let mut msg_out = Message::new();
                            msg_out.set_misc(misc);
                            conn.send(msg_out).await;
                            conn.chat_unanswered = false;
                        }
                        // R-S16(d)(ii) / R-S19: there is NO runtime `SwitchPermission` widener.
                        // Inherited, a CM-driven IPC message reassigned conn.keyboard / clipboard /
                        // audio / file / restart / recording / block_input / privacy_mode at runtime,
                        // BYPASSING `permission()` (and thus the pinned policy). With the policy fixed
                        // at the config funnel (PINNED_SETTINGS, UNCONDITIONAL — R-S16/R-R2b) and every
                        // capability derived from AuthConnType (R-S19), a mid-session re-widener has no
                        // place: it could re-grant a capability the pin resolved off. The WHOLE pipeline
                        // — the CM-side senders, the FFI shim, and the `Data::SwitchPermission` IPC
                        // variant itself — is excised (not merely covered by R-S11's allowlist), and the
                        // headless `--service` has no CM to send one anyway. R-A6 asserts the widener is
                        // absent. (The peer's inbound `disable_*` overlays only ever RESTRICT the cached
                        // booleans, so they are unaffected — R-S16(d)(ii).)
                        ipc::Data::CmFileResponse(response) => {
                            conn.handle_cm_file_response(response).await;
                        }
                        #[cfg(target_os = "windows")]
                        ipc::Data::ClipboardFile(clip) => {
                            if !conn.is_remote() {
                                continue;
                            }
                            match clip {
                                // Files announcement: consumed without forwarding (upstream
                                // intercepted it here to audit-only); the egress is removed.
                                clipboard::ClipboardFile::Files { .. } => {}
                                _ => {
                                    allow_err!(conn.stream.send(&clip_2_msg(clip)).await);
                                }
                            }
                        }
                        ipc::Data::PrivacyModeState((_, state, impl_key)) => {
                            let msg_out = match state {
                                privacy_mode::PrivacyModeState::OffSucceeded => {
                                    crate::common::make_privacy_mode_msg(
                                        back_notification::PrivacyModeState::PrvOffSucceeded,
                                        impl_key,
                                    )
                                }
                                privacy_mode::PrivacyModeState::OffByPeer => {
                                    crate::common::make_privacy_mode_msg(
                                        back_notification::PrivacyModeState::PrvOffByPeer,
                                        impl_key,
                                    )
                                }
                                privacy_mode::PrivacyModeState::OffUnknown => {
                                     crate::common::make_privacy_mode_msg(
                                        back_notification::PrivacyModeState::PrvOffUnknown,
                                        impl_key,
                                    )
                                }
                            };
                            conn.send(msg_out).await;
                        }
                        // R-X9 (slices 2-4): the CM `DataPortableService::RequestStart` ->
                        // start_portable_service handler is excised — the portable SYSTEM
                        // helper is gone. Such a message now falls through to the catch-all
                        // `_ => {}` below and is ignored (no portable process is ever started).
                        ipc::Data::VoiceCallResponse(accepted) => {
                            conn.handle_voice_call(accepted).await;
                        }
                        ipc::Data::CloseVoiceCall(_reason) => {
                            log::debug!("Close the voice call from the ipc.");
                            if conn.close_voice_call().await {
                                let msg = new_voice_call_request(false);
                                conn.send(msg).await;
                            }
                        }
                        _ => {}
                    }
                },
                res = conn.stream.next() => {
                    if let Some(res) = res {
                        match res {
                            Err(err) => {
                                conn.on_close(&err.to_string(), true).await;
                                break;
                            },
                            Ok(bytes) => {
                                last_recv_time = Instant::now();
                                let msg_in = match Message::parse_from_bytes(&bytes) {
                                    Ok(msg) => msg,
                                    Err(err) => {
                                        let reason =
                                            format!("Malformed post-key Message frame: {err}");
                                        log::warn!("{reason}");
                                        conn.on_close(&reason, true).await;
                                        break;
                                    }
                                };
                                if let Some(message::Union::VideoFrameReceipt(receipt)) =
                                    msg_in.union.as_ref()
                                {
                                    if let Some(pending) = pending_video_delivery.as_mut() {
                                        pending.observe_peer_receipt(
                                            conn.authenticated_video_source(),
                                            receipt,
                                        );
                                    }
                                    complete_video_delivery(&mut pending_video_delivery, id);
                                    continue;
                                }
                                if !conn.on_message(msg_in).await {
                                    break;
                                }
                                // R-F1/R-D6/R-S5: the login path authorizes INSIDE on_message
                                // (send_logon_response_and_keep_alive dials the target + sets
                                // port_forward_socket). This fork has no attended CM accept step
                                // (approve-mode is pinned to "password"; the Data::Authorize echo is
                                // excised), so break to the sealed relay (try_port_forward_loop) HERE
                                // the moment a tunnel is authorized. Unconditional (no last_test_delay
                                // guard): the port-forward viewer never replies to TestDelay
                                // (connect_and_login), so no latency-probe frame can be injected into
                                // the forwarded stream — and a TestDelay is only ever emitted BEFORE
                                // this login iteration, so it precedes PeerInfo on the wire.
                                if conn.port_forward_socket.is_some() && conn.authorized {
                                    break;
                                }
                            }
                        }
                    } else {
                        conn.on_close("Reset by the peer", true).await;
                        break;
                    }
                },
                _ = conn.file_timer.tick(), if !conn.file_writes.has_transfer_data() => {
                    if !conn.read_jobs.is_empty() {
                        conn.send_to_cm(ipc::Data::FileTransferLog((
                            "transfer".to_string(),
                            fs::serialize_transfer_jobs(&conn.read_jobs),
                        )))
                        .await;
                        let context = conn
                            .read_jobs
                            .iter()
                            .find(|job| !job.is_last_job)
                            .or_else(|| conn.read_jobs.first())
                            .map(|job| {
                                ControlledFileWriteContext::transfer_data(
                                    Some(job.id()),
                                    job.file_num(),
                                )
                            })
                            .unwrap_or_else(|| {
                                ControlledFileWriteContext::transfer_data(None, -1)
                            });
                        match enqueue_controlled_file_transfer_step(
                            &mut conn.file_writes,
                            &mut conn.read_jobs,
                            &mut conn.stream,
                            context,
                        ).await {
                            Ok(log) => {
                                if !log.is_empty() {
                                    conn.send_to_cm(ipc::Data::FileTransferLog((
                                        "transfer".to_string(),
                                        log,
                                    )))
                                    .await;
                                }
                            }
                            Err(err) =>  {
                                conn.on_close(&err.to_string(), false).await;
                                break;
                            }
                        }
                    } else {
                        conn.file_timer = crate::rustdesk_interval(time::interval_at(Instant::now() + SEC30, SEC30));
                    }
                }
                completion = wait_for_video_write(&mut pending_video_delivery), if pending_video_delivery.as_ref().map_or(false, PendingVideoDelivery::writer_pending) => {
                    let Some(pending) = pending_video_delivery.as_mut() else {
                        log::error!("video writer completion fired without exact pending ownership");
                        conn.on_close("video writer completion ownership failed", false).await;
                        break;
                    };
                    match completion {
                        Ok(Ok(())) => {
                            pending.mark_writer_complete();
                            complete_video_delivery(&mut pending_video_delivery, id);
                        }
                        Ok(Err(err)) => {
                            conn.on_close(&err.to_string(), false).await;
                            break;
                        }
                        Err(_) => {
                            conn.on_close("video writer retired before exact completion", false).await;
                            break;
                        }
                    }
                },
                item = rx_video.recv(), if pending_video_delivery.is_none() => {
                    let Some(item) = item else {
                        conn.on_close("video egress mailbox retired", false).await;
                        break;
                    };
                    match item {
                        VideoEgressItem::SwitchDisplay((_queued_at, value)) => {
                            if let Err(err) = conn.stream.send(&value as &Message).await {
                                conn.on_close(&err.to_string(), false).await;
                                break;
                            }
                        }
                        VideoEgressItem::Frame(frame) => {
                            match conn.stream.send_with_receipt(frame.message.as_ref()).await {
                                Ok(receipt) => {
                                    pending_video_delivery =
                                        Some(PendingVideoDelivery::new(receipt, &frame));
                                }
                                Err(err) => {
                                    conn.on_close(&err.to_string(), false).await;
                                    break;
                                }
                            }
                        }
                        VideoEgressItem::RefreshRequired { display } => {
                            if !conn.refresh_video_display(Some(display)) {
                                conn.on_close("video service retired before refresh", false).await;
                                break;
                            }
                        }
                    }
                },
                Some((instant, value)) = rx_audio.recv() => {
                    if instant.elapsed() > Duration::from_secs(1)
                        && matches!(&value.union, Some(message::Union::AudioFrame(_)))
                    {
                        continue;
                    }
                    if let Err(err) = conn.stream.send(&value as &Message).await {
                        conn.on_close(&err.to_string(), false).await;
                        break;
                    }
                },
                Some((_instant, value)) = rx.recv() => {
                    #[allow(unused_mut)]
                    let mut msg = value;

                    match &msg.union {
                        Some(message::Union::Misc(m)) => {
                            match &m.union {
                                Some(misc::Union::StopService(_)) => {
                                    conn.send_close_reason_no_retry("").await;
                                    conn.on_close("stop service", false).await;
                                    break;
                                }
                                _ => {},
                            }
                        }
                        Some(message::Union::PeerInfo(_pi)) => {
                            if !conn.refresh_video_display(None) {
                                conn.on_close("video service retired before refresh", false).await;
                                break;
                            }
                            #[cfg(target_os = "macos")]
                            conn.retina.set_displays(&_pi.displays);
                        }
                        Some(message::Union::CursorPosition(pos)) => {
                            #[cfg(not(any(target_os = "android", target_os = "ios")))]
                            {
                                if conn.follow_remote_cursor {
                                    conn.handle_cursor_switch_display(pos.clone()).await;
                                }
                            }
                            #[cfg(target_os = "macos")]
                            if let Some(new_msg) = conn.retina.on_cursor_pos(&pos, conn.display_idx) {
                                msg = Arc::new(new_msg);
                            }
                        }
                        Some(message::Union::MultiClipboards(_multi_clipboards)) => {
                            #[cfg(not(target_os = "ios"))]
                            if let Some(msg_out) = crate::clipboard::get_msg_if_not_support_multi_clip(&conn.lr.version, &conn.lr.my_platform, _multi_clipboards) {
                                if let Err(err) = conn.stream.send(&msg_out).await {
                                    conn.on_close(&err.to_string(), false).await;
                                    break;
                                }
                                continue;
                            }
                        }
                        _ => {}
                    }

                    let msg: &Message = &msg;
                    if let Err(err) = conn.stream.send(msg).await {
                        conn.on_close(&err.to_string(), false).await;
                        break;
                    }
                },
                _ = second_timer.tick() => {
                    #[cfg(windows)]
                    conn.portable_check();
                    #[cfg(not(any(target_os = "android", target_os = "ios")))]
                    if let Some(lease) = conn.terminal_service_lease.as_ref() {
                        if let Err(err) = lease.ensure_attached_authority() {
                            log::warn!(
                                "Closing terminal connection after asynchronous authority revocation: ip={} conn_id={} err='{}'",
                                conn.ip,
                                conn.inner.id(),
                                err
                            );
                            conn.send_close_reason_no_retry(
                                "Terminal authority is no longer valid",
                            )
                            .await;
                            conn.on_close("terminal authority revoked", false).await;
                            break;
                        }
                    }
                    raii::AuthedConnID::check_wake_lock_on_setting_changed();
                    if let Some((instant, minute)) = conn.auto_disconnect_timer.as_ref() {
                        if instant.elapsed().as_secs() > minute * 60 {
                            conn.send_close_reason_no_retry("Connection failed due to inactivity").await;
                            conn.on_close("auto disconnect", true).await;
                            break;
                        }
                    }
                    for data in conn.file_remove_log_control.on_timer().drain(..) {
                        conn.send_to_cm(data).await;
                    }
                    #[cfg(feature = "hwcodec")]
                    conn.update_supported_encoding();
                }
                _ = test_delay_timer.tick() => {
                    if last_recv_time.elapsed() >= SEC30 {
                        conn.on_close("Timeout", true).await;
                        break;
                    }
                    // The control end will jump out of the loop after receiving LoginResponse and will not reply to the TestDelay.
                    if conn.last_test_delay.is_none() {
                        conn.last_test_delay = Some(Instant::now());
                        let mut msg_out = Message::new();
                        msg_out.set_test_delay(TestDelay{
                            last_delay: conn.network_delay,
                            target_bitrate: video_service::VIDEO_QOS.lock().unwrap().bitrate(),
                            ..Default::default()
                        });
                        conn.send(msg_out.into()).await;
                    }
                    if conn.is_authed_remote_conn() || conn.view_camera {
                        if let Some(last_test_delay) = conn.last_test_delay {
                            video_service::VIDEO_QOS.lock().unwrap().user_delay_response_elapsed(id, last_test_delay.elapsed().as_millis());
                        }
                    }
                }
                clip_file = rx_clip.recv() => match clip_file {
                    Some(_clip) => {
                        #[cfg(feature = "unix-file-copy-paste")]
                        if crate::is_support_file_copy_paste(&conn.lr.version)
                        {
                            conn.handle_file_clip(_clip).await;
                        }
                    }
                    None => {
                        //
                    }
                },
            }
        }

        let retired_file_writes = conn.file_writes.retire();
        if !retired_file_writes.is_empty() {
            log::debug!(
                "#{} retiring {} controlled file writer completions with the connection round",
                id,
                retired_file_writes.len()
            );
        }

        // R-F1/R-D6/R-S5/R-A9: run the SEALED port-forward/RDP relay. A no-op unless this is a tunnel
        // session (port_forward_socket is Some); then it relays the local target socket <-> the KEYED
        // self.stream until either side closes — every wire-bound byte sealed by send_bytes, every
        // inbound byte decrypted by next(), never a set_raw plaintext downgrade (R-A3/R-A9).
        if let Err(err) = conn.try_port_forward_loop(&mut rx_from_cm).await {
            conn.on_close(&err.to_string(), false).await;
        }

        #[cfg(feature = "unix-file-copy-paste")]
        {
            conn.try_empty_file_clipboard();
        }

        // R-T4 (§20): privacy-off (screen-unblank), the video-fetch notify, `remove_connection`,
        // cursor-record-stop, and the synchronous CM `Data::Close` notification have MOVED into
        // `Connection`'s `Drop` so they run on cancellation too, not only on this normal-exit tail
        // (a dropped session previously left the console blanked + the Server map/CM diverged).
        // The async `on_close` (CloseReason + lock_screen) remains here on the normal path. (R-X7:
        // the
        // temporary-password rotation that ran here on authorized-exit is removed with the OTP.)
        conn.on_close("End", true).await;
        log::info!("#{} connection loop exited", id);
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    async fn start_input_worker(&mut self) -> bool {
        if self.input_worker.is_some() {
            return true;
        }
        let Some(receiver) = self.rx_input.take() else {
            log::error!("remote input receiver is unavailable before worker startup");
            return false;
        };
        let Some(tx) = self.inner.tx.clone() else {
            log::error!("remote input response sender is unavailable before worker startup");
            return false;
        };
        let execution = Arc::clone(&self.tx_input.execution);
        let queued_bytes = Arc::clone(&self.tx_input.queued_bytes);
        let id = self.inner.id();
        let (join_tx, completion) = match spawn_input_worker_supervisor(
            format!("remote-input-supervisor-{id}"),
            queued_bytes,
        ) {
            Ok(supervisor) => supervisor,
            Err(err) => {
                log::error!("Failed to start remote input worker supervisor: {err}");
                return false;
            }
        };
        let worker_execution = Arc::clone(&execution);
        #[cfg(target_os = "windows")]
        let input_runtime = tokio::runtime::Handle::current();
        let join = match std::thread::Builder::new()
            .name(format!("remote-input-{id}"))
            .spawn(move || {
                Self::handle_input(
                    id,
                    receiver,
                    tx,
                    worker_execution,
                    #[cfg(target_os = "windows")]
                    input_runtime,
                )
            }) {
            Ok(join) => join,
            Err(err) => {
                log::error!("Failed to start remote input worker: {err}");
                drop(join_tx);
                let completion = Arc::clone(&completion);
                let _ = tokio::task::spawn_blocking(move || completion.wait()).await;
                return false;
            }
        };
        if let Err(err) = join_tx.try_send(join) {
            log::error!("Failed to transfer remote input worker to its supervisor");
            execution.cancel();
            let join = match err {
                std_mpsc::TrySendError::Full(join) | std_mpsc::TrySendError::Disconnected(join) => {
                    join
                }
            };
            let _ = tokio::task::spawn_blocking(move || join.join()).await;
            let completion = Arc::clone(&completion);
            let _ = tokio::task::spawn_blocking(move || completion.wait()).await;
            return false;
        }
        self.input_worker = Some(InputWorker {
            execution,
            completion,
        });
        true
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn handle_input(
        conn_id: i32,
        receiver: std_mpsc::Receiver<QueuedInput>,
        tx: Sender,
        execution: Arc<InputExecutionGate>,
        #[cfg(target_os = "windows")] runtime: tokio::runtime::Handle,
    ) {
        let mut cleanup = InputWorkerCleanup {
            conn_id,
            keys: InputKeyOwnership::new(Arc::clone(&INPUT_KEY_OWNERS)),
        };
        let mut special_keys = SpecialKeyState::default();
        loop {
            if execution.is_cancelled() {
                break;
            }
            match receiver.recv_timeout(std::time::Duration::from_millis(50)) {
                Ok(mut queued) => {
                    let Some(v) = queued.input.take() else {
                        log::error!("remote input queue yielded an empty item");
                        break;
                    };
                    let mut input_result = Ok(());
                    let dispatched = execution.dispatch(|| {
                        input_result = match v {
                            MessageInput::Mouse(mouse_input) => cleanup.keys.dispatch_mouse(
                                &mouse_input.msg,
                                mouse_input.simulate,
                                |event, preserve_modifiers, inject_native| {
                                    handle_owned_mouse(
                                        event,
                                        mouse_input.conn_id,
                                        mouse_input.username,
                                        mouse_input.argb,
                                        mouse_input.simulate && inject_native,
                                        mouse_input.show_cursor,
                                        preserve_modifiers,
                                    )
                                },
                            ),
                            MessageInput::Key((mut msg, press)) => {
                                msg.press = false;
                                if press {
                                    cleanup.keys.dispatch_press(&msg, handle_owned_key)
                                } else {
                                    cleanup.keys.dispatch(&msg, handle_owned_key).map(|_| ())
                                }
                            }
                            MessageInput::SpecialKey(event) => {
                                if let Some(Some(action)) = special_keys.observe(&event) {
                                    match action {
                                        SpecialKeyAction::CtrlAltDel => {
                                            #[cfg(target_os = "windows")]
                                            dispatch_windows_service_owned_sas(
                                                &runtime, &execution,
                                            );
                                            Ok(())
                                        }
                                        SpecialKeyAction::LockScreen => {
                                            handle_owned_lock_screen(|event| {
                                                cleanup
                                                    .keys
                                                    .dispatch(event, handle_owned_key)
                                                    .map(|_| ())
                                            })
                                        }
                                    }
                                } else {
                                    Ok(())
                                }
                            }
                            MessageInput::Pointer((msg, id)) => cleanup
                                .keys
                                .dispatch_pointer(&msg, |event| handle_owned_pointer(event, id)),
                            MessageInput::BlockOn => {
                                let (ok, msg) = INPUT_BLOCK_OWNERS.set(conn_id, true);
                                if !ok {
                                    Self::send_block_input_error(
                                        &tx,
                                        back_notification::BlockInputState::BlkOnFailed,
                                        msg,
                                    );
                                    Err(hbb_common::anyhow::anyhow!(
                                        "Windows owned-input executor could not block local input"
                                    ))
                                } else {
                                    Ok(())
                                }
                            }
                            MessageInput::BlockOff => {
                                let (ok, msg) = INPUT_BLOCK_OWNERS.set(conn_id, false);
                                if !ok {
                                    Self::send_block_input_error(
                                        &tx,
                                        back_notification::BlockInputState::BlkOffFailed,
                                        msg,
                                    );
                                    Err(hbb_common::anyhow::anyhow!(
                                    "Windows owned-input executor could not unblock local input"
                                ))
                                } else {
                                    Ok(())
                                }
                            }
                        };
                    });
                    if !dispatched {
                        break;
                    }
                    if let Err(err) = input_result {
                        log::error!(
                            "remote input dispatch failed; stopping worker for cleanup: {err}"
                        );
                        break;
                    }
                }
                Err(err) => {
                    if std_mpsc::RecvTimeoutError::Disconnected == err {
                        break;
                    }
                }
            }
        }
        drop(receiver);
        drop(cleanup);
        log::debug!("Input thread exited");
    }

    async fn send_permission(&mut self, permission: Permission, enabled: bool) {
        let mut misc = Misc::new();
        misc.set_permission_info(PermissionInfo {
            permission: permission.into(),
            enabled,
            ..Default::default()
        });
        let mut msg_out = Message::new();
        msg_out.set_misc(misc);
        self.send(msg_out).await;
    }

    async fn check_privacy_mode_on(&mut self) -> bool {
        if privacy_mode::is_in_privacy_mode() {
            self.send_login_error("Someone turns on privacy mode, exit")
                .await;
            false
        } else {
            true
        }
    }

    async fn on_open(&mut self, addr: SocketAddr) -> bool {
        log::debug!("#{} Connection opened from {}.", self.inner.id, addr);
        // R-T1(a): reject past the global authorized-session cap (post-key, pre-authorization) so a
        // session/descriptor runaway is bounded under any launcher, not only the systemd cgroup.
        if crate::server::AUTHED_CONNS.lock().unwrap().len() >= MAX_AUTHED_SESSIONS {
            self.send_login_error("Too many active sessions").await;
            return false;
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        if crate::is_server() && Config::get_option("allow-only-conn-window-open") == "Y" {
            if !crate::check_process("", !crate::platform::is_root()) {
                self.send_login_error("The main window is not open").await;
                return false;
            }
        }
        self.ip = addr.ip().to_string();
        // R-T15c: the server no longer sends a `Hash` challenge here -- under CPace the viewer sends its
        // login proactively (Client::start) the moment the stream is keyed.
        true
    }

    // Returns the action that may run only after the CM login has been queued. `None`
    // closes the connection. A no-action result does not necessarily mean authorization
    // succeeded (a pending terminal login can keep the stream alive while unauthorized).
    async fn send_logon_response_and_keep_alive(&mut self) -> Option<CmLoginFollowup> {
        if self.authorized {
            return Some(CmLoginFollowup::NoAction);
        }
        #[cfg(target_os = "macos")]
        if super::effective_permanent_password_credential_snapshot()
            .await
            .generation()
            != self.credential_generation
        {
            self.send_login_error("Permanent password changed during authorization")
                .await;
            return None;
        }
        if Config::with_current_permanent_password_generation(self.credential_generation, || ())
            .is_none()
        {
            self.send_login_error("Permanent password changed during authorization")
                .await;
            return None;
        }
        // R-X7 / §18: the responder 2FA gate is removed. 2FA was pinned-off-dead
        // (`2fa` ∈ PINNED_SETTINGS = "" ⇒ `require_2fa` always None ⇒ this branch never
        // executed), so the whole responder 2FA machinery — the `require_2fa` field, the
        // `Auth2fa` message handler, the trusted-device bypass, and the raii session-2FA
        // state — is excised here. (The earlier Telegram-push leak that lived in this gate
        // was already removed in R-SV7; the viewer-side `send2fa` sender, the `Auth2FA` proto
        // field, src/auth_2fa.rs, the totp-rs dep, and the Sciter 2FA UI are now excised too —
        // R-X7 complete: no 2FA path survives on either side or on the wire.)
        if let Some(keep_alive) = self.prepare_terminal_authority_for_authorization().await {
            return keep_alive.then_some(CmLoginFollowup::NoAction);
        }
        // R-F1/R-D6/R-S5: dial the peer-named LOCAL target of a port-forward/RDP tunnel NOW (the
        // funnel gate in the PortForward login arm already passed — enable-tunnel is pinned Y). A
        // dial failure fails the login CLOSED; on success self.port_forward_socket is Some and the
        // sealed relay (try_port_forward_loop) runs after the main loop. No-op for non-tunnel logins.
        if !self.connect_port_forward_if_needed().await {
            return None;
        }
        #[cfg(target_os = "macos")]
        if super::effective_permanent_password_credential_snapshot()
            .await
            .generation()
            != self.credential_generation
        {
            self.send_login_error("Permanent password changed during authorization")
                .await;
            return None;
        }
        if Config::with_current_permanent_password_generation(self.credential_generation, || {
            self.authorized = true;
        })
        .is_none()
        {
            self.send_login_error("Permanent password changed during authorization")
                .await;
            return None;
        }
        let auth_conn_type = if self.file_transfer.is_some() {
            AuthConnType::FileTransfer
        } else if self.port_forward_socket.is_some() {
            AuthConnType::PortForward
        } else if self.view_camera {
            AuthConnType::ViewCamera
        } else if self.terminal {
            AuthConnType::Terminal
        } else {
            AuthConnType::Remote
        };
        // R-S19 (CWE-863): confine every peer-triggerable capability to the authorized AuthConnType
        // NOW — at authorization time, before any peer LoginRequest option is applied
        // (self.update_options below) — so no login-time option can transiently re-grant a capability
        // the session type was not authorized for (the ordering window behind CVE-2026-58056). Under
        // the pinned access-mode=full (R-S16) every capability boolean is seeded true, so this
        // derivation is the ONLY real session-type confinement.
        self.confine_capabilities_to_conn_type(auth_conn_type);
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        if auth_conn_type == AuthConnType::Remote && !self.start_input_worker().await {
            self.authorized = false;
            self.send_login_error("Remote input service is unavailable")
                .await;
            return None;
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        let cm_file = self.file && auth_conn_type == AuthConnType::FileTransfer;
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        let cm_clipboard =
            auth_conn_type == AuthConnType::Remote && self.can_sub_clipboard_service();
        #[cfg(target_os = "windows")]
        self.inner.set_cm_clipboard_authority(
            auth_conn_type.to_cm_auth_conn_type(),
            self.cm_auth_token.clone(),
        );
        self.authed_conn_id = Some(self::raii::AuthedConnID::new(
            self.inner.id(),
            auth_conn_type,
            self.session_key(),
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            self.cm_auth_token.clone(),
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            cm_file,
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            cm_clipboard,
        ));
        #[allow(unused_mut)]
        let mut username = crate::platform::get_active_username();
        // On a headless unix box there is no logind/console session for `get_active_username` to
        // resolve, so it returns empty. File transfer runs in the CM process as the `--server` owner
        // (the same process owner used by the terminal — R-F1), so report that real user rather than an
        // empty console user. Windows/Android keep their WTS/console-session semantics untouched.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if username.is_empty() {
            username = hbb_common::whoami::username();
        }
        let mut res = LoginResponse::new();
        let mut pi = PeerInfo {
            username: username.clone(),
            version: VERSION.to_owned(),
            video_frame_receipt_version: if matches!(
                auth_conn_type,
                AuthConnType::Remote | AuthConnType::ViewCamera
            ) {
                VIDEO_FRAME_RECEIPT_VERSION
            } else {
                0
            },
            ..Default::default()
        };

        #[cfg(not(target_os = "android"))]
        {
            pi.hostname = crate::whoami_hostname();
            pi.platform = hbb_common::whoami::platform().to_string();
        }
        #[cfg(target_os = "android")]
        {
            pi.hostname = DEVICE_NAME.lock().unwrap().clone();
            pi.platform = "Android".into();
        }
        #[cfg(all(target_os = "macos", not(feature = "unix-file-copy-paste")))]
        let mut platform_additions = serde_json::Map::new();
        #[cfg(any(
            target_os = "windows",
            target_os = "linux",
            all(target_os = "macos", feature = "unix-file-copy-paste")
        ))]
        let mut platform_additions = serde_json::Map::new();
        #[cfg(target_os = "linux")]
        {
            if crate::platform::current_is_wayland() {
                platform_additions.insert("is_wayland".into(), json!(true));
            }
            #[cfg(target_os = "linux")]
            if crate::platform::is_headless_allowed() {
                if linux_desktop_manager::is_headless() {
                    platform_additions.insert("headless".into(), json!(true));
                }
            }
        }
        #[cfg(target_os = "windows")]
        {
            platform_additions.insert(
                "is_installed".into(),
                json!(crate::platform::is_installed()),
            );
            if crate::platform::is_installed() {
                platform_additions.extend(virtual_display_manager::get_platform_additions());
            }
            platform_additions.insert(
                "supported_privacy_mode_impl".into(),
                json!(privacy_mode::get_supported_privacy_mode_impl()),
            );
        }
        #[cfg(target_os = "macos")]
        {
            platform_additions.insert(
                "supported_privacy_mode_impl".into(),
                json!(privacy_mode::get_supported_privacy_mode_impl()),
            );
        }

        #[cfg(any(target_os = "windows", feature = "unix-file-copy-paste"))]
        {
            let is_both_windows = cfg!(target_os = "windows")
                && self.lr.my_platform == hbb_common::whoami::Platform::Windows.to_string();
            #[cfg(feature = "unix-file-copy-paste")]
            let is_unix_and_peer_supported = crate::is_support_file_copy_paste(&self.lr.version);
            #[cfg(not(feature = "unix-file-copy-paste"))]
            let is_unix_and_peer_supported = false;
            let is_both_macos = cfg!(target_os = "macos")
                && self.lr.my_platform == hbb_common::whoami::Platform::MacOS.to_string();
            let is_peer_support_paste_if_macos =
                crate::is_support_file_paste_if_macos(&self.lr.version);
            let has_file_clipboard = is_both_windows
                || (is_unix_and_peer_supported
                    && (!is_both_macos || is_peer_support_paste_if_macos));
            platform_additions.insert("has_file_clipboard".into(), json!(has_file_clipboard));
        }

        #[cfg(any(target_os = "windows", target_os = "linux"))]
        {
            platform_additions.insert("support_view_camera".into(), json!(true));
        }

        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        if !platform_additions.is_empty() {
            pi.platform_additions = serde_json::to_string(&platform_additions).unwrap_or("".into());
        }

        #[cfg(target_os = "linux")]
        if self.is_remote() {
            let mut msg = "".to_string();
            if crate::platform::linux::is_login_screen_wayland() {
                msg = crate::client::LOGIN_SCREEN_WAYLAND.to_owned()
            } else {
                let dtype = crate::platform::linux::get_display_server();
                if dtype != crate::platform::linux::DISPLAY_SERVER_X11
                    && dtype != crate::platform::linux::DISPLAY_SERVER_WAYLAND
                {
                    msg = format!(
                        "Unsupported display server type \"{}\", x11 or wayland expected",
                        dtype
                    );
                }
            }
            if !msg.is_empty() {
                res.set_error(msg);
                let mut msg_out = Message::new();
                msg_out.set_login_response(res);
                self.send(msg_out).await;
                return Some(CmLoginFollowup::NoAction);
            }
        }
        #[allow(unused_mut)]
        let mut sas_enabled = false;
        #[cfg(windows)]
        if crate::platform::is_root() {
            sas_enabled = true;
        }
        // The pre-logon SYSTEM session has no interactive user or reachable profile, so a Windows
        // file-transfer login there reports no console user — the viewer's matching Windows-only gate
        // then refuses it. On unix, file transfer serves at the CM service privilege regardless of any
        // console session (like the terminal process owner, R-F1), so the process-owner username above
        // stands with no prelogin blanking. Mirrors the terminal's Windows-only is_prelogin handling
        // (select_terminal_launch_authority); on a headless unix box is_prelogin() is true (no seat0), which
        // must NOT blank the file-transfer user.
        #[cfg(target_os = "windows")]
        if self.file_transfer.is_some() && crate::platform::is_prelogin() {
            username = "".to_owned();
        }
        // Terminal feature is supported on desktop only
        #[allow(unused_mut)]
        let mut terminal = cfg!(not(any(target_os = "android", target_os = "ios")));
        #[cfg(target_os = "windows")]
        {
            terminal = terminal && portable_pty::win::check_support().is_ok();
        }
        pi.username = username;
        pi.sas_enabled = sas_enabled;
        pi.features = Some(Features {
            privacy_mode: privacy_mode::is_privacy_mode_supported(),
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            terminal,
            ..Default::default()
        })
        .into();

        let mut sub_service = false;
        #[allow(unused_mut)]
        let mut wait_session_id_confirm = false;
        #[cfg(windows)]
        if !self.terminal {
            self.handle_windows_specific_session(&mut pi, &mut wait_session_id_confirm);
        }
        // R-F1/R-D6/R-S5: a port-forward/RDP tunnel needs no screen / encoding / display enumeration.
        // Send the minimal PeerInfo (the viewer's connect_and_login only waits for it before it starts
        // relaying) and RETURN, skipping the remote-desktop branch below (which enumerates displays +
        // negotiates a video encoder — wrong for a tunnel and failure-prone on a headless box). The
        // sealed relay then runs in try_port_forward_loop once the main loop breaks.
        if self.port_forward_socket.is_some() {
            res.set_peer_info(pi);
            let mut msg_out = Message::new();
            msg_out.set_login_response(res);
            self.send(msg_out).await;
            return Some(CmLoginFollowup::NoAction);
        }
        if self.file_transfer.is_some() || self.terminal {
            res.set_peer_info(pi);
        } else if self.view_camera {
            let supported_encoding = scrap::codec::Encoder::supported_encoding();
            self.last_supported_encoding = Some(supported_encoding.clone());
            log::info!("peer info supported_encoding: {:?}", supported_encoding);
            pi.encoding = Some(supported_encoding).into();

            pi.displays = camera::Cameras::all_info().unwrap_or(Vec::new());
            pi.current_display = camera::PRIMARY_CAMERA_IDX as _;
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            {
                pi.resolutions = Some(SupportedResolutions {
                    resolutions: camera::Cameras::get_camera_resolution(
                        pi.current_display as usize,
                    )
                    .ok()
                    .into_iter()
                    .collect(),
                    ..Default::default()
                })
                .into();
            }
            res.set_peer_info(pi);
            self.update_codec_on_login();
        } else {
            let supported_encoding = scrap::codec::Encoder::supported_encoding();
            self.last_supported_encoding = Some(supported_encoding.clone());
            log::info!("peer info supported_encoding: {:?}", supported_encoding);
            pi.encoding = Some(supported_encoding).into();
            if let Some(msg_out) = super::display_service::is_inited_msg() {
                self.send(msg_out).await;
            }

            try_activate_screen();

            match super::display_service::update_get_sync_displays_on_login(
                #[cfg(target_os = "android")]
                self.android_server_generation,
            )
            .await
            {
                Err(err) => {
                    res.set_error(format!("{}", err));
                }
                Ok(displays) => {
                    // For compatibility with old versions, we need to send the displays to the peer.
                    // But the displays may be updated later, before creating the video capturer.
                    #[cfg(target_os = "macos")]
                    {
                        self.retina.set_displays(&displays);
                    }
                    pi.displays = displays;
                    pi.current_display = self.display_idx as _;
                    #[cfg(not(any(target_os = "android", target_os = "ios")))]
                    {
                        pi.resolutions = Some(SupportedResolutions {
                            resolutions: pi
                                .displays
                                .get(self.display_idx)
                                .map(|d| crate::platform::resolutions(&d.name))
                                .unwrap_or(vec![]),
                            ..Default::default()
                        })
                        .into();
                    }
                    res.set_peer_info(pi);
                    sub_service = true;
                }
            }
            self.on_remote_authorized();
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        if self.terminal {
            let Some(lease) = self.terminal_service_lease.as_ref() else {
                log::error!("Terminal service lease is missing before login response");
                return None;
            };
            if let Err(err) = lease.validate_for_activation() {
                log::warn!(
                    "Terminal authority validation failed before login response: ip={} conn_id={} err='{}'",
                    self.ip,
                    self.inner.id(),
                    err
                );
                return None;
            }
        }
        let mut msg_out = Message::new();
        msg_out.set_login_response(res);
        if let Err(err) = self.send_checked(msg_out).await {
            log::warn!(
                "Failed to send login response: ip={} conn_id={} err='{}'",
                self.ip,
                self.inner.id(),
                err
            );
            return None;
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        if self.terminal {
            let Some(lease) = self.terminal_service_lease.as_mut() else {
                log::error!("Terminal service lease is missing after authorization");
                return None;
            };
            if let Err(err) = lease.activate(self.inner.clone()) {
                log::error!("Failed to activate terminal service lease: {}", err);
                return None;
            }
        }
        if let Some(o) = self.options_in_login.take() {
            if let Err(err) = self.update_options(&o).await {
                log::error!("Failed to apply login options: {}", err);
                return None;
            }
        }
        let mut cm_login_followup = CmLoginFollowup::NoAction;
        if let Some((dir, show_hidden)) = self.file_transfer.clone() {
            // R-S19 (CVE-2026-58056 / CWE-863, Appendix C #24): capability confinement for FileTransfer
            // (keyboard / block_input / privacy_mode / restart / audio cleared; clipboard + file kept
            // for the file-clipboard / CLIPRDR + file transfer) is now done structurally in
            // confine_capabilities_to_conn_type above — BEFORE update_options, which closes the
            // login-time ordering window the old in-branch clears left open (a peer's
            // LoginRequest.option{block_input:Yes} fired once before the clear landed). This branch
            // keeps only its non-capability action: the initial directory read.
            let dir = if !dir.is_empty() && std::path::Path::new(&dir).is_dir() {
                &dir
            } else {
                ""
            };
            if !wait_session_id_confirm {
                // The desktop CM validates its per-connection authority from Data::Login.
                // Preserve FIFO authority by returning this operation to the caller, which
                // queues Login first. Sending AuthorizedFS here made a fresh file-transfer
                // connection deterministically fail before the CM could authenticate it.
                cm_login_followup = CmLoginFollowup::ReadInitialDirectory {
                    path: dir.to_owned(),
                    include_hidden: show_hidden,
                };
            } else {
                self.delayed_read_dir = Some((dir.to_owned(), show_hidden));
            }
        } else if self.terminal {
            // Terminal activation completed immediately after the checked login-response write.
        } else if self.view_camera {
            if !wait_session_id_confirm {
                self.try_sub_camera_displays();
            }
            // keyboard/clipboard/file confined in confine_capabilities_to_conn_type above (R-S19);
            // audio is kept for voice calls. Still notify the peer so its UI reflects no keyboard.
            self.send_permission(Permission::Keyboard, false).await;
        } else if sub_service {
            if !wait_session_id_confirm {
                self.try_sub_monitor_services();
            }
        }
        Some(cm_login_followup)
    }

    fn try_sub_camera_displays(&mut self) {
        if let Some(s) = self.server.upgrade() {
            let mut s = s.write().unwrap();

            s.try_add_primary_camera_service();
            s.add_camera_connection(self.inner.clone());
        }
    }

    #[inline]
    fn is_remote(&self) -> bool {
        // R-F1/R-S5: a port-forward/RDP tunnel is NOT a remote-desktop session — exclude it so the
        // login display-check, the monitor/video sub-services, and remote-only clipboard paths never
        // fire for a tunnel (they would enumerate/capture a screen the tunnel does not use — wrong,
        // and failure-prone on a headless box).
        self.file_transfer.is_none()
            && self.port_forward_socket.is_none()
            && !self.view_camera
            && !self.terminal
    }

    fn try_sub_monitor_services(&mut self) {
        let is_remote = self.is_remote();
        if is_remote && !self.services_subed {
            self.services_subed = true;
            if let Some(s) = self.server.upgrade() {
                let mut noperms = Vec::new();
                if !self.peer_keyboard_enabled() && !self.show_remote_cursor {
                    noperms.push(NAME_CURSOR);
                }
                if !self.show_remote_cursor {
                    noperms.push(NAME_POS);
                }
                if !self.follow_remote_window {
                    noperms.push(NAME_WINDOW_FOCUS);
                }
                if !self.can_sub_clipboard_service() {
                    noperms.push(super::clipboard_service::NAME);
                }
                #[cfg(feature = "unix-file-copy-paste")]
                if !self.can_sub_file_clipboard_service() {
                    noperms.push(super::clipboard_service::FILE_NAME);
                }
                if !self.audio_enabled() {
                    noperms.push(super::audio_service::NAME);
                }
                let mut s = s.write().unwrap();
                #[cfg(not(any(target_os = "android", target_os = "ios")))]
                let _h = try_start_record_cursor_pos();
                self.auto_disconnect_timer = Self::get_auto_disconenct_timer();
                s.try_add_primay_video_service();
                s.add_connection(self.inner.clone(), &noperms);
            }
        }
    }

    #[cfg(windows)]
    fn handle_windows_specific_session(
        &mut self,
        pi: &mut PeerInfo,
        wait_session_id_confirm: &mut bool,
    ) {
        let sessions = crate::platform::get_available_sessions(true);
        if let Some(current_sid) = crate::platform::get_current_process_session_id() {
            if crate::platform::is_installed()
                && crate::platform::is_share_rdp()
                && raii::AuthedConnID::non_port_forward_conn_count() == 1
                && sessions.len() > 1
                && sessions.iter().any(|e| e.sid == current_sid)
                && get_version_number(&self.lr.version) >= get_version_number("1.2.4")
            {
                pi.windows_sessions = Some(WindowsSessions {
                    sessions,
                    current_sid,
                    ..Default::default()
                })
                .into();
                *wait_session_id_confirm = true;
            }
        }
    }

    fn on_remote_authorized(&self) {
        self.update_codec_on_login();
        #[cfg(any(target_os = "windows", target_os = "linux"))]
        if config::option2bool(
            "allow-remove-wallpaper",
            &Config::get_option("allow-remove-wallpaper"),
        ) {
            // multi connections set once
            let mut wallpaper = WALLPAPER_REMOVER.lock().unwrap();
            if wallpaper.is_none() {
                match crate::platform::WallPaperRemover::new() {
                    Ok(remover) => {
                        *wallpaper = Some(remover);
                    }
                    Err(e) => {
                        log::info!("create wallpaper remover failed: {:?}", e);
                    }
                }
            }
        }
    }

    fn peer_keyboard_enabled(&self) -> bool {
        self.keyboard && !self.disable_keyboard
    }

    fn clipboard_enabled(&self) -> bool {
        self.clipboard && !self.disable_clipboard
    }

    #[inline]
    fn can_sub_clipboard_service(&self) -> bool {
        self.clipboard_enabled()
            && self.peer_keyboard_enabled()
            && crate::get_builtin_option(keys::OPTION_ONE_WAY_CLIPBOARD_REDIRECTION) != "Y"
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn refresh_cm_clipboard_authority(&self) {
        set_authed_conn_cm_clipboard_authority(
            self.inner.id(),
            self.is_authed_remote_conn() && self.can_sub_clipboard_service(),
        );
    }

    fn audio_enabled(&self) -> bool {
        self.audio && !self.disable_audio
    }

    #[cfg(any(target_os = "windows", feature = "unix-file-copy-paste"))]
    fn file_transfer_enabled(&self) -> bool {
        self.file && self.enable_file_transfer
    }

    #[cfg(feature = "unix-file-copy-paste")]
    fn can_sub_file_clipboard_service(&self) -> bool {
        self.clipboard_enabled()
            && self.file_transfer_enabled()
            && crate::get_builtin_option(keys::OPTION_ONE_WAY_FILE_TRANSFER) != "Y"
    }

    async fn try_start_cm(&mut self, peer_id: String, name: String, authorized: bool) {
        let cm_conn_type = if self.file_transfer.is_some() {
            ipc::CmAuthConnType::FileTransfer
        } else if self.view_camera {
            ipc::CmAuthConnType::ViewCamera
        } else if self.terminal {
            ipc::CmAuthConnType::Terminal
        } else if !self.port_forward_address.is_empty() {
            ipc::CmAuthConnType::PortForward
        } else {
            ipc::CmAuthConnType::Remote
        };
        let publishes_file_authority = authorized
            && self.file
            && cm_conn_type == ipc::CmAuthConnType::FileTransfer;
        self.cm_file_login_published = false;
        let login = ipc::Data::Login {
            id: self.inner.id(),
            is_file_transfer: self.file_transfer.is_some(),
            is_view_camera: self.view_camera,
            is_terminal: self.terminal,
            port_forward: self.port_forward_address.clone(),
            conn_type: cm_conn_type,
            peer_id,
            name,
            avatar: self.lr.avatar.clone(),
            authorized,
            keyboard: self.keyboard,
            clipboard: self.clipboard,
            audio: self.audio,
            file: self.file,
            file_transfer_enabled: self.file,
            privacy_mode: self.privacy_mode,
            cm_auth_token: self.cm_auth_token.clone(),
        };
        if self.send_to_cm(login).await {
            self.cm_file_login_published = publishes_file_authority;
        }
    }

    #[inline]
    async fn send_to_cm(&mut self, data: ipc::Data) -> bool {
        let error = match time::timeout(
            CM_COMMAND_QUEUE_SEND_TIMEOUT,
            self.tx_to_cm.send(data),
        )
        .await
        {
            Ok(Ok(())) => return true,
            Ok(Err(_)) => "connection-manager command queue is closed".to_owned(),
            Err(_) => "connection-manager command queue backpressure timed out".to_owned(),
        };
        log::error!("#{}: {}", self.inner.id(), error);
        if self.cm_command_failure.is_none() {
            self.cm_command_failure = Some(error);
        }
        false
    }

    fn publish_cm_terminal(
        &mut self,
        terminal: crate::ui_cm_interface::CmConnectionTerminal,
    ) {
        let Some(sender) = self.cm_terminal.take() else {
            return;
        };
        if sender.send(terminal).is_err() {
            log::warn!(
                "#{}: connection-manager terminal receiver retired first",
                self.inner.id()
            );
        }
    }

    #[inline]
    async fn send_fs(&mut self, data: ipc::FS) -> Result<(), String> {
        if !cm_file_request_session_authorized(
            self.authorized,
            self.file_transfer.is_some(),
            self.file,
            self.cm_file_login_published,
        ) {
            return Err("connection-manager file authority is not published".to_owned());
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        let data = ipc::Data::AuthorizedFS {
            cm_auth_token: self.cm_auth_token.clone(),
            fs: data,
        };
        #[cfg(any(target_os = "android", target_os = "ios"))]
        let data = ipc::Data::FS(data);
        let result = match time::timeout(
            CM_COMMAND_QUEUE_SEND_TIMEOUT,
            self.tx_to_cm.send(data),
        )
        .await
        {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(_)) => "connection-manager command queue is closed".to_owned(),
            Err(_) => "connection-manager command queue backpressure timed out".to_owned(),
        };
        log::error!("#{}: {}", self.inner.id(), result);
        if self.cm_command_failure.is_none() {
            self.cm_command_failure = Some(result.clone());
        }
        Err(result)
    }

    async fn send_login_error<T: std::string::ToString>(&mut self, err: T) {
        let mut msg_out = Message::new();
        let mut res = LoginResponse::new();
        res.set_error(err.to_string());
        msg_out.set_login_response(res);
        self.send(msg_out).await;
    }

    #[inline]
    pub fn send_block_input_error(
        s: &Sender,
        state: back_notification::BlockInputState,
        details: String,
    ) {
        let mut misc = Misc::new();
        let mut back_notification = BackNotification {
            details,
            ..Default::default()
        };
        back_notification.set_block_input_state(state);
        misc.set_back_notification(back_notification);
        let mut msg_out = Message::new();
        msg_out.set_misc(misc);
        s.send((Instant::now(), Arc::new(msg_out))).ok();
    }

    #[inline]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn input_mouse(
        &self,
        msg: MouseEvent,
        conn_id: i32,
        username: String,
        argb: u32,
        simulate: bool,
        show_cursor: bool,
    ) -> ResultType<()> {
        try_enqueue_input(
            &self.tx_input,
            MessageInput::Mouse(InputMouse {
                msg,
                conn_id,
                username,
                argb,
                simulate,
                show_cursor,
            }),
        )
    }

    #[inline]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn input_pointer(&self, msg: PointerDeviceEvent, conn_id: i32) -> ResultType<()> {
        try_enqueue_input(&self.tx_input, MessageInput::Pointer((msg, conn_id)))
    }

    #[inline]
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn input_key(&self, msg: KeyEvent, press: bool) -> ResultType<()> {
        try_enqueue_input(&self.tx_input, MessageInput::Key((msg, press)))
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn input_special_key(&self, event: KeyEvent) -> ResultType<()> {
        try_enqueue_input(&self.tx_input, MessageInput::SpecialKey(event))
    }

    // R-X7: check_update_temporary_password (the consecutive-wrong-attempt OTP rotation — a
    // remotely-triggerable lockout) is removed with the temporary-password credential.

    #[inline]
    pub fn is_permission_enabled_locally(enable_prefix_option: &str) -> bool {
        #[cfg(feature = "flutter")]
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            let access_mode = Config::get_option("access-mode");
            if access_mode == "full" {
                return true;
            } else if access_mode == "view" {
                return false;
            }
        }
        config::option2bool(
            enable_prefix_option,
            &Config::get_option(enable_prefix_option),
        )
    }

    // R-F1/R-D6/R-S5: resolve the peer-requested port-forward target to a concrete `host:port` for
    // the LOCAL dial, and flag the RDP shortcut. "RDP"/port 0 and an empty host both resolve to the
    // box's own RDP/loopback service, so a bare RDP request lands on localhost:3389.
    fn normalize_port_forward_target(pf: &mut PortForward) -> (String, bool) {
        let mut is_rdp = false;
        if pf.host == "RDP" && pf.port == 0 {
            pf.host = "localhost".to_owned();
            pf.port = 3389;
            is_rdp = true;
        }
        if pf.host.is_empty() {
            pf.host = "localhost".to_owned();
        }
        (format!("{}:{}", pf.host, pf.port), is_rdp)
    }

    // R-F1/R-D6/R-S5: dial the LOCAL target of a port-forward/RDP tunnel (idempotent; a no-op for a
    // non-tunnel login, which returns true). The dialed socket is PLAINTEXT to the local service —
    // the wire-facing half of the relay is the KEYED self.stream, so the tunnel is sealed on the
    // wire (R-A9). A connect failure/timeout reports a login error and fails CLOSED (returns false).
    async fn connect_port_forward_if_needed(&mut self) -> bool {
        if self.port_forward_socket.is_some() {
            return true;
        }
        let Some(login_request::Union::PortForward(pf)) = self.lr.union.as_ref() else {
            return true;
        };
        let mut pf = pf.clone();
        let (mut addr, is_rdp) = Self::normalize_port_forward_target(&mut pf);
        self.port_forward_address = addr.clone();
        match timeout(3000, TcpStream::connect(&addr)).await {
            Ok(Ok(sock)) => {
                self.port_forward_socket = Some(Framed::new(sock, BytesCodec::new()));
                true
            }
            Ok(Err(e)) => {
                log::warn!("Port forward connect failed for {}: {}", addr, e);
                if is_rdp {
                    addr = "RDP".to_owned();
                }
                self.send_login_error(format!(
                    "Failed to access remote {}. Please make sure it is reachable/open.",
                    addr
                ))
                .await;
                false
            }
            Err(e) => {
                log::warn!("Port forward connect timed out for {}: {}", addr, e);
                if is_rdp {
                    addr = "RDP".to_owned();
                }
                self.send_login_error(format!(
                    "Failed to access remote {}. Please make sure it is reachable/open.",
                    addr
                ))
                .await;
                false
            }
        }
    }

    // R-F1/R-D6/R-S5/R-A9: the SEALED port-forward/RDP relay. Runs after the main loop for a tunnel
    // session (no-op otherwise). It shuttles bytes between the LOCAL target socket (`forward`,
    // plaintext to the service) and the KEYED session stream (`self.stream`, encrypted to the peer):
    //   local target --forward.next()-->  self.stream.send_bytes(..)  [SEALS -> ciphertext on wire]
    //   peer         --self.stream.next()--> forward.send(..)         [next() already DECRYPTED it]
    // Critically it does NOT call self.stream.set_raw() (upstream did, dropping the secretbox to pass
    // raw plaintext — the R-S5 "plaintext tunnel" escape). On a keyed stream set_raw would panic
    // (tcp.rs R-A3) anyway; here it is simply absent so every relayed byte stays inside the seal.
    async fn try_port_forward_loop(
        &mut self,
        rx_from_cm: &mut mpsc::UnboundedReceiver<ipc::Data>,
    ) -> ResultType<()> {
        if let Some(mut forward) = self.port_forward_socket.take() {
            log::info!("Running port forwarding loop");
            let mut last_recv_time = Instant::now();
            let mut idle_timer = crate::rustdesk_interval(time::interval(Duration::from_secs(1)));
            loop {
                tokio::select! {
                    Some(data) = rx_from_cm.recv() => {
                        match data {
                            ipc::Data::Close => {
                                bail!("Close requested from connection manager");
                            }
                            ipc::Data::CmErr(e) => {
                                log::error!("Connection manager error: {e}");
                                bail!("{e}");
                            }
                            _ => {}
                        }
                    }
                    res = forward.next() => {
                        if let Some(res) = res {
                            last_recv_time = Instant::now();
                            // local target -> SEAL (send_bytes on the keyed stream) -> peer.
                            self.stream.send_bytes(res?.into()).await?;
                        } else {
                            bail!("Forward reset by the peer");
                        }
                    },
                    res = self.stream.next() => {
                        if let Some(res) = res {
                            last_recv_time = Instant::now();
                            // peer -> next() already DECRYPTED the frame -> write to the local target.
                            timeout(PORT_FORWARD_SEND_TIMEOUT, forward.send(res?)).await??;
                        } else {
                            bail!("Stream reset by the peer");
                        }
                    },
                    _ = idle_timer.tick() => {
                        if last_recv_time.elapsed() >= PORT_FORWARD_IDLE_TIMEOUT {
                            bail!("Timeout");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn permission(
        enable_prefix_option: &str,
        control_permissions: &Option<ControlPermissions>,
    ) -> bool {
        // R-S16(d)(i): the controlled-side policy (the pinned PINNED_SETTINGS funnel)
        // is the single source of truth — UNCONDITIONALLY on every build (R-R2b). The
        // rendezvous-server-pushed `control_permissions` capability bits are never
        // consulted, closing that server-push vector by construction (not merely by the
        // mediator's absence under R-D4): `is_permission_enabled_locally` is the only path.
        let _ = control_permissions;
        Self::is_permission_enabled_locally(enable_prefix_option)
    }

    fn update_codec_on_login(&self) {
        use scrap::codec::{Encoder, EncodingUpdate::*};
        if let Some(o) = self.lr.clone().option.as_ref() {
            if let Some(q) = o.supported_decoding.clone().take() {
                Encoder::update(Update(self.inner.id(), q));
            } else {
                Encoder::update(NewOnlyVP9(self.inner.id()));
            }
        } else {
            Encoder::update(NewOnlyVP9(self.inner.id()));
        }
    }

    async fn handle_login_request_without_validation(&mut self, lr: &LoginRequest) {
        self.lr = lr.clone();
        self.peer_argb = crate::str2color(&format!("{}{}", &lr.my_id, &lr.my_platform), 0xff);
        if let Some(o) = lr.option.as_ref() {
            self.options_in_login = Some(o.clone());
        }
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    async fn run_cm_ipc_until_owner_closed<F, T>(
        owner_closed: oneshot::Receiver<()>,
        bootstrap_complete: oneshot::Receiver<()>,
        task: F,
    ) -> Option<T>
    where
        F: std::future::Future<Output = T>,
    {
        let mut owner_closed = owner_closed;
        let mut bootstrap_complete = bootstrap_complete;
        let mut task = Box::pin(task);
        tokio::select! {
            biased;
            result = &mut task => Some(result),
            _ = &mut bootstrap_complete => {
                tokio::select! {
                    result = &mut task => Some(result),
                    _ = &mut owner_closed => {
                        time::timeout(CM_OWNER_TERMINAL_DRAIN_TIMEOUT, &mut task)
                            .await
                            .ok()
                    }
                }
            }
            _ = &mut owner_closed => None,
        }
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn try_start_cm_ipc(&mut self) {
        if let Some(p) = self.start_cm_ipc_para.take() {
            tokio::spawn(async move {
                #[cfg(windows)]
                let tx_from_cm_clone = p.tx_from_cm.clone();
                let (bootstrap_complete, bootstrap_completed) = oneshot::channel();
                let result = Self::run_cm_ipc_until_owner_closed(
                    p.owner_closed,
                    bootstrap_completed,
                    start_ipc(
                        p.rx_to_cm,
                        p.cm_terminal,
                        p.tx_from_cm,
                        p.rx_desktop_ready,
                        p.tx_cm_stream_ready,
                        p.conn_id,
                        p.cm_auth_token,
                        bootstrap_complete,
                    ),
                )
                .await;
                if let Some(Err(err)) = result {
                    log::warn!("ipc to connection manager exit: {}", err);
                    // https://github.com/rustdesk/rustdesk-server-pro/discussions/382#discussioncomment-10525725, cm may start failed
                    #[cfg(windows)]
                    if !crate::platform::is_prelogin() {
                        allow_err!(tx_from_cm_clone.send(Data::CmErr(err.to_string())));
                    }
                }
            });
            #[cfg(all(windows, feature = "flutter"))]
            std::thread::spawn(move || {
                if crate::is_server() && !crate::check_process("--tray", false) {
                    crate::platform::run_user_helper(
                        crate::platform::WindowsUserHelperLaunch::Tray,
                    )
                    .ok();
                }
            });
        }
    }

    async fn on_message(&mut self, msg: Message) -> bool {
        if let Some(message::Union::Misc(misc)) = &msg.union {
            // Move the CloseReason forward, as this message needs to be received when unauthorized, especially for kcp.
            if let Some(misc::Union::CloseReason(s)) = &misc.union {
                log::info!("receive close reason: {}", s);
                self.on_close("Peer close", true).await;
                return false;
            }
        }
        // After handling CloseReason messages, proceed to process other message types
        if let Some(message::Union::LoginRequest(lr)) = msg.union {
            if !login_video_frame_receipt_version_is_compatible(&lr) {
                self.send_login_error(
                    "Incompatible remote video protocol. Upgrade both RustDesk peers.",
                )
                .await;
                sleep(1.).await;
                return false;
            }
            // R-X14 / R-S18: the peer MUST NOT select an OS user or trigger a PAM os-login (the
            // second OS-credential subsystem — try_start_x_session / pam::Client). CPace's password
            // is the sole credential (R-P1). The OSLogin os_login field is now DELETED from
            // LoginRequest (message.proto, R-S18 cleanup) — the peer cannot even encode an OS
            // username/password, so no PAM / X-session login can run on its behalf and the session
            // uses the box's local desktop context only. (allow-linux-headless=N pins the headless
            // path off; the field deletion closes the peer-driven trigger by construction.)
            self.handle_login_request_without_validation(&lr).await;
            if self.authorized {
                return true;
            }
            match lr.union {
                Some(login_request::Union::FileTransfer(ft)) => {
                    if !Self::permission(
                        keys::OPTION_ENABLE_FILE_TRANSFER,
                        &self.control_permissions,
                    ) {
                        self.send_login_error("No permission of file transfer")
                            .await;
                        sleep(1.).await;
                        return false;
                    }
                    self.file_transfer = Some((ft.dir, ft.show_hidden));
                }
                Some(login_request::Union::ViewCamera(_vc)) => {
                    if !Self::permission(keys::OPTION_ENABLE_CAMERA, &self.control_permissions) {
                        self.send_login_error("No permission of viewing camera")
                            .await;
                        sleep(1.).await;
                        return false;
                    }
                    self.view_camera = true;
                }
                // R-X8/R-D8/R-F1: the terminal is GRANTED to the authenticated owner — full access
                // is the one pinned mode. The pinned enable-terminal=Y (R-S16, UNCONDITIONAL) makes
                // Self::permission(OPTION_ENABLE_TERMINAL) resolve true, so this arm AUTHORIZES the
                // LoginRequest.Terminal below (self.terminal is set; the root PTY is the owner's by
                // design — they already hold the box's sudo password, and §2 does not confine a
                // password-knower). Still defensive: the terminal is the service user's shell (R-F1),
                // the Windows-LogonUserW / Linux os_login SECOND credential stays excised (R-X14/
                // R-S18 — the plain PTY adds no second credential), and the pin is funnel-locked so
                // no runtime write can narrow it (R-A6). The check below is that funnel gate itself.
                Some(login_request::Union::Terminal(terminal)) => {
                    if !Self::permission(keys::OPTION_ENABLE_TERMINAL, &self.control_permissions) {
                        self.send_login_error("No permission of terminal").await;
                        sleep(1.).await;
                        return false;
                    }
                    // R-S18: the upstream "os_login.username set but not installed -> refuse"
                    // check is gone with the os_login field — the fork's terminal is SessionUser-
                    // only (no peer OS-login), so there is no such request to refuse.
                    self.terminal = true;
                    if let Some(o) = self.options_in_login.as_ref() {
                        self.terminal_persistent =
                            o.terminal_persistent.enum_value() == Ok(BoolOption::Yes);
                    }
                    self.terminal_service_id = terminal.service_id;
                }
                // R-F1/R-D6/R-S5: the port-forward/RDP tunnel is GRANTED, not refused. enable-tunnel
                // is pinned Y (R-S16, UNCONDITIONAL), so this funnel gate resolves true — the fork
                // does NOT deny the forward (that is R-S5's "or refuse" fallback, OVERRIDDEN here by
                // R-F1/R-D6/R-A9). Instead it relays the tunnel INSIDE the sealed session stream
                // (R-S5 option 1: the bytes stay in the secretbox; see try_port_forward_loop, which
                // never set_raw's — R-A3). Here we only FIX the target address; the dial happens at
                // authorize (connect_port_forward_if_needed). normalize resolves "RDP" -> localhost:3389.
                Some(login_request::Union::PortForward(mut pf)) => {
                    if !Self::permission(keys::OPTION_ENABLE_TUNNEL, &self.control_permissions) {
                        self.send_login_error("No permission of IP tunneling").await;
                        sleep(1.).await;
                        return false;
                    }
                    let (addr, _is_rdp) = Self::normalize_port_forward_target(&mut pf);
                    self.port_forward_address = addr;
                }
                _ => {
                    if !self.check_privacy_mode_on().await {
                        return false;
                    }
                }
            }

            if !hbb_common::is_ip_str(&lr.username) && !hbb_common::is_domain_port_str(&lr.username)
            {
                self.send_login_error(crate::client::LOGIN_MSG_OFFLINE)
                    .await;
                return false;
            }

            // R-S18: dropped the always-true `os_login.username is empty` clause (the field is
            // deleted) — the prelogin guard now rests solely on terminal + is_prelogin().
            #[cfg(target_os = "windows")]
            if self.terminal && crate::platform::is_prelogin() {
                self.send_login_error(
                    "No active console user logged on, please connect and logon first.",
                )
                .await;
                sleep(1.).await;
                return false;
            }

            // R-X8: terminal cm_ipc starts unconditionally now (was gated on the removed
            // OS-login scope; SessionUser is the only terminal mode).
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            self.try_start_cm_ipc();

            #[cfg(not(target_os = "linux"))]
            let err_msg = "".to_owned();
            #[cfg(target_os = "linux")]
            let err_msg = self.linux_headless_handle.try_start_desktop();

            // If err is LOGIN_MSG_DESKTOP_SESSION_NOT_READY, just keep this msg and go on checking password.
            if !err_msg.is_empty() && err_msg != crate::client::LOGIN_MSG_DESKTOP_SESSION_NOT_READY
            {
                self.send_login_error(err_msg).await;
                return true;
            }

            // R-A2/R-S2: approve-mode is pinned to "password" (the config funnel's PINNED_SETTINGS),
            // so CPace at the choke point is the SOLE authorizer and every connection reaches login
            // already authorized. The inherited attended "click-to-accept" branch — Click/Both
            // approve-mode gated by is_logon()/allow-logon-screen-password, the
            // try_start_cm(authorized=false) + the LOGIN_MSG_NO_PASSWORD_ACCESS "wait for the remote
            // side to accept" prompt — is UNREACHABLE (both approve_mode() comparisons are always
            // false) and is excised.
            //
            // R-S18 / R-S2 / R-S6: LoginRequest is now session metadata only. CPace at the choke
            // point is the sole authenticator, so no legacy salted-hash password field is parsed
            // or re-validated here.
            debug_assert!(
                self.stream.is_secured(),
                "R-A1: login reached on an unkeyed stream"
            );
            if !self.stream.is_secured() {
                self.send_login_error(crate::client::LOGIN_MSG_PASSWORD_WRONG)
                    .await;
                return true;
            }

            if err_msg.is_empty() {
                #[cfg(target_os = "linux")]
                self.linux_headless_handle.wait_desktop_cm_ready().await;
                let Some(cm_login_followup) =
                    self.send_logon_response_and_keep_alive().await
                else {
                    return false;
                };
                self.try_start_cm(lr.my_id, lr.my_name, self.authorized)
                    .await;
                if let CmLoginFollowup::ReadInitialDirectory {
                    path,
                    include_hidden,
                } = cm_login_followup
                {
                    if let Err(error) = self.read_dir(&path, include_hidden).await {
                        log::error!(
                            "Failed to reserve initial file directory request after CM login: {}",
                            error
                        );
                        return false;
                    }
                }
            } else {
                self.send_login_error(err_msg).await;
            }
        } else if let Some(message::Union::TestDelay(t)) = msg.union {
            if t.from_client {
                let mut msg_out = Message::new();
                msg_out.set_test_delay(t);
                self.inner.send(msg_out.into());
            } else {
                if let Some(tm) = self.last_test_delay {
                    self.last_test_delay = None;
                    let new_delay = tm.elapsed().as_millis() as u32;
                    video_service::VIDEO_QOS
                        .lock()
                        .unwrap()
                        .user_network_delay(self.inner.id(), new_delay);
                    self.network_delay = new_delay;
                }
            }
        } else if self.authorized {
            // R-F1/R-S5: an authorized port-forward/RDP tunnel does NOT process application messages
            // (mouse/keyboard/clipboard/…) — its bytes are raw relay traffic handled by
            // try_port_forward_loop, not on_message. The main loop breaks to that relay the instant
            // the tunnel is authorized, so this is a defensive guard: ignore any stray app message on
            // a tunnel connection rather than mis-dispatch it as input.
            if self.port_forward_socket.is_some() {
                return true;
            }
            // CVE-2026-58056 / CWE-863 (Appendix C #24): confine desktop INPUT and DISPLAY
            // capture/control to the session's AuthConnType, not the broad `self.authorized` state.
            // Upstream gates these on per-capability flags, and a FileTransfer login (unlike
            // terminal/view-camera) never cleared them — so a peer authorized only for FileTransfer
            // could inject input and capture the screen. Here input is Remote-only, and desktop
            // capture/control is Remote-or-ViewCamera (view-camera legitimately drives its own camera
            // displays — handle_switch_display/capture_displays have `view_camera` branches). All other
            // message families (file transfer, clipboard, chat, options, audio, …) are unaffected, so a
            // real FileTransfer session keeps working. This is the allowlist-keyed-by-AuthConnType the
            // finding's own fix direction calls for; the per-handler view-camera guards below stay as
            // secondary defense.
            {
                let is_remote_input = matches!(
                    &msg.union,
                    Some(message::Union::MouseEvent(_))
                        | Some(message::Union::PointerDeviceEvent(_))
                        | Some(message::Union::KeyEvent(_))
                );
                // Remote-only control actions that are NOT screen capture (R-S19): reboot the host,
                // toggle its privacy-mode screen blanking, or plug/unplug a virtual display. ViewCamera
                // drives its own camera displays but has no business rebooting the box, blanking the
                // host screen (turn_off_privacy has no per-handler Remote gate), or attaching a virtual
                // monitor — so these are Remote-only, unlike the capture set below which ViewCamera shares.
                let is_remote_control = match &msg.union {
                    Some(message::Union::Misc(m)) => matches!(
                        &m.union,
                        Some(misc::Union::RestartRemoteDevice(_))
                            | Some(misc::Union::TogglePrivacyMode(_))
                            | Some(misc::Union::ToggleVirtualDisplay(_))
                    ),
                    _ => false,
                };
                let is_desktop_capture = match &msg.union {
                    Some(message::Union::ScreenshotRequest(_)) => true,
                    Some(message::Union::Misc(m)) => matches!(
                        &m.union,
                        Some(misc::Union::SwitchDisplay(_))
                            | Some(misc::Union::CaptureDisplays(_))
                            | Some(misc::Union::RefreshVideo(_))
                            | Some(misc::Union::RefreshVideoDisplay(_))
                            | Some(misc::Union::ChangeResolution(_))
                            | Some(misc::Union::ChangeDisplayResolution(_))
                            // MessageQuery answers with make_display_changed_msg — display
                            // geometry/resolution, the same monitor metadata ViewCamera legitimately
                            // needs but a FileTransfer/Terminal/PortForward peer has no business reading.
                            | Some(misc::Union::MessageQuery(_))
                    ),
                    _ => false,
                };
                if ((is_remote_input || is_remote_control) && !self.is_authed_remote_conn())
                    || (is_desktop_capture
                        && !self.is_authed_remote_conn()
                        && !self.is_authed_view_camera_conn())
                {
                    return true;
                }
            }
            match msg.union {
                #[allow(unused_mut)]
                Some(message::Union::MouseEvent(mut me)) => {
                    if self.is_authed_view_camera_conn() {
                        return true;
                    }
                    #[cfg(target_os = "android")]
                    {
                        if let Err(err) = validate_mouse_input(&me) {
                            log::warn!(
                                "Closing Android connection after invalid mouse input: {err}"
                            );
                            return false;
                        }
                        match call_main_service_pointer_input_for_generation(
                            self.android_server_generation,
                            self.inner.id(),
                            "mouse",
                            me.mask,
                            me.x,
                            me.y,
                        ) {
                            Ok(true) => {}
                            Ok(false) => {
                                log::warn!(
                                    "Closing Android connection after input owner or queue refusal: conn_id={}",
                                    self.inner.id()
                                );
                                return false;
                            }
                            Err(err) => {
                                log::warn!(
                                    "Closing Android connection after input JNI failure: conn_id={} err={err}",
                                    self.inner.id()
                                );
                                return false;
                            }
                        }
                    }
                    #[cfg(not(any(target_os = "android", target_os = "ios")))]
                    if self.is_authed_remote_conn() && self.peer_keyboard_enabled() {
                        if is_left_up(&me) {
                            CLICK_TIME.store(get_time(), Ordering::SeqCst);
                        }
                        #[cfg(target_os = "macos")]
                        self.retina.on_mouse_event(&mut me, self.display_idx);
                        if let Err(err) = self.input_mouse(
                            me,
                            self.inner.id(),
                            self.lr.my_name.clone(),
                            self.peer_argb,
                            true,
                            self.show_my_cursor,
                        ) {
                            log::warn!(
                                "Closing connection after mouse input queue failure: ip={} conn_id={} err='{}'",
                                self.ip,
                                self.inner.id(),
                                err
                            );
                            return false;
                        }
                    } else if self.show_my_cursor {
                        #[cfg(target_os = "macos")]
                        self.retina.on_mouse_event(&mut me, self.display_idx);
                        if let Err(err) = self.input_mouse(
                            me,
                            self.inner.id(),
                            self.lr.my_name.clone(),
                            self.peer_argb,
                            false,
                            true,
                        ) {
                            log::warn!(
                                "Closing connection after cursor input queue failure: ip={} conn_id={} err='{}'",
                                self.ip,
                                self.inner.id(),
                                err
                            );
                            return false;
                        }
                    }
                    self.update_auto_disconnect_timer();
                }
                Some(message::Union::PointerDeviceEvent(pde)) => {
                    if self.is_authed_view_camera_conn() {
                        return true;
                    }
                    #[cfg(target_os = "android")]
                    {
                        if let Err(err) = validate_pointer_input(&pde) {
                            log::warn!(
                                "Closing Android connection after invalid pointer input: {err}"
                            );
                            return false;
                        }
                        let dispatch_result = match pde.union {
                            Some(pointer_device_event::Union::TouchEvent(touch)) => {
                                match touch.union {
                                    Some(touch_event::Union::PanStart(pan_start)) => {
                                        call_main_service_pointer_input_for_generation(
                                            self.android_server_generation,
                                            self.inner.id(),
                                            "touch",
                                            4,
                                            pan_start.x,
                                            pan_start.y,
                                        )
                                    }
                                    Some(touch_event::Union::PanUpdate(pan_update)) => {
                                        call_main_service_pointer_input_for_generation(
                                            self.android_server_generation,
                                            self.inner.id(),
                                            "touch",
                                            5,
                                            pan_update.x,
                                            pan_update.y,
                                        )
                                    }
                                    Some(touch_event::Union::PanEnd(pan_end)) => {
                                        call_main_service_pointer_input_for_generation(
                                            self.android_server_generation,
                                            self.inner.id(),
                                            "touch",
                                            6,
                                            pan_end.x,
                                            pan_end.y,
                                        )
                                    }
                                    _ => Ok(true),
                                }
                            }
                            _ => Ok(true),
                        };
                        match dispatch_result {
                            Ok(true) => {}
                            Ok(false) => {
                                log::warn!(
                                    "Closing Android connection after pointer owner or queue refusal: conn_id={}",
                                    self.inner.id()
                                );
                                return false;
                            }
                            Err(err) => {
                                log::warn!(
                                    "Closing Android connection after pointer JNI failure: conn_id={} err={err}",
                                    self.inner.id()
                                );
                                return false;
                            }
                        }
                    }
                    #[cfg(not(any(target_os = "android", target_os = "ios")))]
                    if self.is_authed_remote_conn() && self.peer_keyboard_enabled() {
                        if let Err(err) = self.input_pointer(pde, self.inner.id()) {
                            log::warn!(
                                "Closing connection after pointer input queue failure: ip={} conn_id={} err='{}'",
                                self.ip,
                                self.inner.id(),
                                err
                            );
                            return false;
                        }
                    }
                    self.update_auto_disconnect_timer();
                }
                #[cfg(any(target_os = "ios"))]
                Some(message::Union::KeyEvent(..)) => {}
                #[cfg(any(target_os = "android"))]
                Some(message::Union::KeyEvent(mut me)) => {
                    if self.is_authed_view_camera_conn() {
                        return true;
                    }
                    if let Err(err) = validate_key_input(&me) {
                        log::warn!(
                            "Closing Android connection after invalid raw keyboard input: {err}"
                        );
                        return false;
                    }
                    let key = match me.mode.enum_value() {
                        Ok(KeyboardMode::Map) => {
                            Some(crate::keyboard::keycode_to_rdev_key(me.chr()))
                        }
                        Ok(KeyboardMode::Translate) => {
                            if let Some(key_event::Union::Chr(code)) = me.union {
                                Some(crate::keyboard::keycode_to_rdev_key(code & 0x0000FFFF))
                            } else {
                                None
                            }
                        }
                        _ => None,
                    }
                    .filter(crate::keyboard::is_modifier);

                    let is_press =
                        (me.press || me.down) && !(crate::is_modifier(&me) || key.is_some());

                    if let Some(key) = key {
                        if is_press {
                            self.pressed_modifiers.insert(key);
                        } else {
                            self.pressed_modifiers.remove(&key);
                        }
                    }

                    let mut modifiers = vec![];

                    for key in self.pressed_modifiers.iter() {
                        if let Some(control_key) = map_key_to_control_key(key) {
                            modifiers.push(EnumOrUnknown::new(control_key));
                        }
                    }

                    me.modifiers = modifiers;

                    if let Err(err) = validate_key_input(&me) {
                        log::warn!(
                            "Closing Android connection after invalid keyboard input: {err}"
                        );
                        return false;
                    }

                    let encode_result = me.write_to_bytes();

                    match encode_result {
                        Ok(data) => {
                            let result = call_main_service_key_event_for_generation(
                                self.android_server_generation,
                                self.inner.id(),
                                &data,
                            );
                            match result {
                                Ok(true) => {}
                                Ok(false) => {
                                    log::warn!(
                                        "Closing Android connection after key owner or queue refusal: conn_id={}",
                                        self.inner.id()
                                    );
                                    return false;
                                }
                                Err(err) => {
                                    log::warn!(
                                        "Closing Android connection after key JNI failure: conn_id={} err={err}",
                                        self.inner.id()
                                    );
                                    return false;
                                }
                            }
                        }
                        Err(e) => {
                            log::debug!("encode key event fail: {}", e);
                        }
                    }
                }
                #[cfg(not(any(target_os = "android", target_os = "ios")))]
                Some(message::Union::KeyEvent(me)) => {
                    if self.is_authed_view_camera_conn() {
                        return true;
                    }
                    if self.is_authed_remote_conn() && self.peer_keyboard_enabled() {
                        if SpecialKeyState::action(&me).is_some() {
                            if let Err(err) = self.input_special_key(me) {
                                log::warn!(
                                    "Closing connection after special-key input queue failure: ip={} conn_id={} err='{}'",
                                    self.ip,
                                    self.inner.id(),
                                    err
                                );
                                return false;
                            }
                            self.update_auto_disconnect_timer();
                            return true;
                        }
                        if is_enter(&me) {
                            CLICK_TIME.store(get_time(), Ordering::SeqCst);
                        }

                        let key = match me.mode.enum_value() {
                            Ok(KeyboardMode::Map) => {
                                Some(crate::keyboard::keycode_to_rdev_key(me.chr()))
                            }
                            Ok(KeyboardMode::Translate) => {
                                if let Some(key_event::Union::Chr(code)) = me.union {
                                    Some(crate::keyboard::keycode_to_rdev_key(code & 0x0000FFFF))
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        }
                        .filter(crate::keyboard::is_modifier);

                        // handle all down as press
                        // fix unexpected repeating key on remote linux, seems also fix abnormal alt/shift, which
                        // make sure all key are released
                        // https://github.com/rustdesk/rustdesk/issues/6793
                        let is_press = if cfg!(target_os = "linux") {
                            (me.press || me.down) && !(crate::is_modifier(&me) || key.is_some())
                        } else {
                            me.press
                        };

                        let input_result = if is_press {
                            match me.union {
                                Some(key_event::Union::Unicode(_))
                                | Some(key_event::Union::Seq(_)) => self.input_key(me, false),
                                _ => self.input_key(me, true),
                            }
                        } else {
                            self.input_key(me, false)
                        };
                        if let Err(err) = input_result {
                            log::warn!(
                                "Closing connection after keyboard input queue failure: ip={} conn_id={} err='{}'",
                                self.ip,
                                self.inner.id(),
                                err
                            );
                            return false;
                        }
                    }
                    self.update_auto_disconnect_timer();
                }
                Some(message::Union::Clipboard(cb)) => {
                    // R-S19: host clipboard-TEXT write is Remote-only. self.clipboard is kept for
                    // FileTransfer (the file-clipboard/CLIPRDR is a separate arm gated on
                    // can_sub_file_clipboard_service), so this AuthConnType check is what confines the
                    // text sink without breaking the file-clipboard.
                    if self.clipboard && self.is_authed_remote_conn() {
                        #[cfg(not(any(target_os = "android", target_os = "ios")))]
                        update_clipboard(vec![cb], ClipboardSide::Host);
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
                    // R-S19: host clipboard-TEXT write is Remote-only (see the Clipboard arm above).
                    #[cfg(not(any(target_os = "android", target_os = "ios")))]
                    if self.clipboard && self.is_authed_remote_conn() {
                        update_clipboard(_mcb.clipboards, ClipboardSide::Host);
                    }
                    #[cfg(target_os = "android")]
                    if self.clipboard && self.is_authed_remote_conn() {
                        crate::clipboard::handle_msg_multi_clipboards(_mcb);
                    }
                    #[cfg(target_os = "ios")]
                    {
                        let _ = _mcb;
                        log::warn!(
                            "refusing in-process mobile peer multi-clipboard SET until a platform worker/service boundary exists"
                        );
                    }
                }
                #[cfg(any(target_os = "windows", feature = "unix-file-copy-paste"))]
                Some(message::Union::Cliprdr(clip)) => {
                    if let Some(cliprdr::Union::Files(_)) = &clip.union {
                        // Files announcement: consumed without forwarding (upstream
                        // intercepted it here to audit-only); the egress is removed.
                    } else if let Some(clip) = msg_2_clip(clip) {
                        // R-S19: gate the Windows file-clipboard->CM forward on the confined file
                        // capability (self.clipboard && self.file), mirroring the unix
                        // can_sub_file_clipboard_service sibling below. Both are cleared by
                        // confine_capabilities_to_conn_type for ViewCamera/Terminal, so a non-Remote/
                        // non-FileTransfer peer can no longer drive the host CLIPRDR handshake. Do NOT
                        // add file_transfer_enabled here (that toggle can lag the first handshake
                        // message); self.file is the AuthConnType discriminator, and the CM applies
                        // file_transfer_enabled to non-beginning messages. This also removes the prior
                        // latent dependence on approve-mode-pin ordering (CM-seeded file_transfer_enabled).
                        #[cfg(target_os = "windows")]
                        if self.clipboard && self.file {
                            self.send_to_cm(ipc::Data::ClipboardFile(clip)).await;
                        }
                        // R-A2 / R-S16 policy parity: gate inbound clipboard-FILE processing on the SAME
                        // capability as the subscription (can_sub_file_clipboard_service = clipboard +
                        // file-transfer enabled, NOT one-way) — not merely the peer-reported version. The
                        // text-clipboard arms gate on `if self.clipboard`; this file-clipboard arm gated
                        // ONLY on the version, so a keyed peer could drive the cliprdr FUSE context +
                        // inject file:// URLs into the host clipboard even with file-transfer disabled
                        // (one-way-file-transfer=Y / enable-file-transfer=N). Close that asymmetry.
                        #[cfg(feature = "unix-file-copy-paste")]
                        if self.can_sub_file_clipboard_service()
                            && crate::is_support_file_copy_paste(&self.lr.version)
                        {
                            let mut out_msgs = vec![];

                            #[cfg(target_os = "macos")]
                            if clipboard::platform::unix::macos::should_handle_msg(&clip) {
                                if let Err(e) = clipboard::ContextSend::make_sure_enabled() {
                                    log::error!("failed to restart clipboard context: {}", e);
                                } else {
                                    let _ =
                                        clipboard::ContextSend::proc(|context| -> ResultType<()> {
                                            context
                                                .server_clip_file(self.inner.id(), clip)
                                                .map_err(|e| e.into())
                                        });
                                }
                            } else {
                                out_msgs = unix_file_clip::serve_clip_messages(
                                    ClipboardSide::Host,
                                    clip,
                                    self.inner.id(),
                                );
                            }

                            #[cfg(not(target_os = "macos"))]
                            {
                                out_msgs = unix_file_clip::serve_clip_messages(
                                    ClipboardSide::Host,
                                    clip,
                                    self.inner.id(),
                                );
                            }

                            for msg in out_msgs.into_iter() {
                                if let Some(message::Union::Cliprdr(cliprdr)) = msg.union.as_ref() {
                                    if let Some(cliprdr::Union::Files(_)) = cliprdr.union.as_ref() {
                                        // Files announcement: not forwarded (egress removed).
                                        continue;
                                    }
                                }
                                self.send(msg).await;
                            }
                        }
                    }
                }
                Some(message::Union::FileAction(fa)) => {
                    let handle_fa = self.file_transfer.is_some();
                    if handle_fa {
                        if self.delayed_read_dir.is_some() {
                            if let Some(file_action::Union::ReadDir(rd)) = fa.union {
                                self.delayed_read_dir = Some((rd.path, rd.include_hidden));
                            }
                            return true;
                        }
                        if crate::get_builtin_option(keys::OPTION_ONE_WAY_FILE_TRANSFER) == "Y" {
                            let mut job_id = None;
                            match &fa.union {
                                Some(file_action::Union::Send(s)) => {
                                    job_id = Some(s.id);
                                }
                                Some(file_action::Union::RemoveFile(rf)) => {
                                    job_id = Some(rf.id);
                                }
                                Some(file_action::Union::Rename(r)) => {
                                    job_id = Some(r.id);
                                }
                                Some(file_action::Union::Create(c)) => {
                                    job_id = Some(c.id);
                                }
                                Some(file_action::Union::RemoveDir(rd)) => {
                                    job_id = Some(rd.id);
                                }
                                _ => {}
                            }
                            if let Some(job_id) = job_id {
                                self.send(fs::new_error(job_id, "one-way-file-transfer-tip", 0))
                                    .await;
                                return true;
                            }
                        }
                        match fa.union {
                            Some(file_action::Union::ReadEmptyDirs(rd)) => {
                                if let Err(error) =
                                    self.read_empty_dirs(&rd.path, rd.include_hidden).await
                                {
                                    self.send(fs::new_error(0, error, 0)).await;
                                }
                            }
                            Some(file_action::Union::ReadDir(rd)) => {
                                if let Err(error) =
                                    self.read_dir(&rd.path, rd.include_hidden).await
                                {
                                    self.send(fs::new_error(0, error, 0)).await;
                                }
                            }
                            Some(file_action::Union::AllFiles(f)) => {
                                if crate::common::need_fs_cm_send_files() {
                                    let request_id = match self.reserve_cm_file_request(
                                        CmFileRequestAuthority::AllFiles {
                                            id: f.id,
                                            path: f.path.clone(),
                                        },
                                    ) {
                                        Ok(request_id) => request_id,
                                        Err(error) => {
                                            self.send(fs::new_error(f.id, error, -1)).await;
                                            return true;
                                        }
                                    };
                                    if let Err(error) = self.send_fs(ipc::FS::ReadAllFiles {
                                        path: f.path,
                                        id: f.id,
                                        include_hidden: f.include_hidden,
                                        conn_id: self.inner.id(),
                                        request_id,
                                    })
                                    .await
                                    {
                                        self.cm_file_requests.remove(&request_id);
                                        self.send(fs::new_error(f.id, error, -1)).await;
                                        return true;
                                    }
                                } else {
                                    let _metadata_scan_permit =
                                        match crate::ui_cm_interface::try_acquire_file_metadata_scan(
                                        ) {
                                            Ok(permit) => permit,
                                            Err(msg) => {
                                                self.send(fs::new_error(f.id, msg, -1)).await;
                                                return true;
                                            }
                                        };
                                    let budget =
                                        crate::ui_cm_interface::file_transfer_enumeration_budget();
                                    match fs::get_recursive_files_with_budget(
                                        &f.path,
                                        f.include_hidden,
                                        budget,
                                    ) {
                                        Err(err) => {
                                            log::error!(
                                                "Failed to get recursive files for {}: {}",
                                                f.path,
                                                err
                                            );
                                            self.send(fs::new_error(f.id, err, -1)).await;
                                        }
                                        Ok(files) => {
                                            if let Err(msg) =
                                                crate::ui_cm_interface::check_file_count_limit(
                                                    files.len(),
                                                )
                                            {
                                                self.send(fs::new_error(f.id, msg, -1)).await;
                                            } else {
                                                self.send(fs::new_dir(f.id, f.path, files)).await;
                                            }
                                        }
                                    }
                                }
                            }
                            Some(file_action::Union::Send(s)) => {
                                // server to client
                                let id = s.id;
                                if s.file_num < 0 {
                                    self.send(fs::new_error(id, "invalid file number", s.file_num))
                                        .await;
                                    return true;
                                }
                                let path = s.path.clone();
                                let job_type = JobType::from_proto(s.file_type);
                                match job_type {
                                    JobType::Generic => {
                                        let od = can_enable_overwrite_detection(
                                            get_version_number(&self.lr.version),
                                        );
                                        if crate::common::need_fs_cm_send_files() {
                                            // Delegate file reading to CM on Windows
                                            let generation = match self.reserve_cm_read_job(
                                                id,
                                                path.clone(),
                                                s.file_num,
                                            ) {
                                                Ok(generation) => generation,
                                                Err(msg) => {
                                                    self.send(fs::new_error(id, msg, -1)).await;
                                                    return true;
                                                }
                                            };
                                            if let Err(error) = self.send_fs(ipc::FS::ReadFile {
                                                path,
                                                id,
                                                file_num: s.file_num,
                                                include_hidden: s.include_hidden,
                                                conn_id: self.inner.id(),
                                                overwrite_detection: od,
                                                generation,
                                            })
                                            .await
                                            {
                                                self.cm_read_jobs.remove(&id);
                                                self.send(fs::new_error(id, error, s.file_num))
                                                    .await;
                                                return true;
                                            }
                                        } else {
                                            // Handle file reading in Connection on non-Windows
                                            let data_source =
                                                fs::DataSource::FilePath(PathBuf::from(&path));
                                            self.create_and_start_read_job(
                                                id,
                                                job_type,
                                                data_source,
                                                s.file_num,
                                                s.include_hidden,
                                                od,
                                                path,
                                                true, // check file count limit
                                            )
                                            .await;
                                        }
                                    }
                                }
                                self.file_transferred = true;
                            }
                            Some(file_action::Union::Receive(r)) => {
                                // client to server
                                // note: 1.1.10 introduced identical file detection, which breaks original logic of send/recv files
                                // whenever got send/recv request, check peer version to ensure old version of rustdesk
                                let od = can_enable_overwrite_detection(get_version_number(
                                    &self.lr.version,
                                ));
                                if let Err(msg) =
                                    crate::ui_cm_interface::check_file_count_limit(r.files.len())
                                {
                                    self.send(fs::new_error(r.id, msg, r.file_num)).await;
                                    return true;
                                }
                                let files = r.files.to_vec();
                                let base = PathBuf::from(&r.path);
                                if let Err(err) = fs::validate_transfer_file_list(
                                    Some(&base),
                                    &files,
                                    crate::ui_cm_interface::get_max_validated_files(),
                                ) {
                                    self.send(fs::new_error(r.id, err, r.file_num)).await;
                                    return true;
                                }
                                let generation = match self.reserve_write_job(r.id) {
                                    Ok(generation) => generation,
                                    Err(msg) => {
                                        self.send(fs::new_error(r.id, msg, r.file_num)).await;
                                        return true;
                                    }
                                };
                                if let Err(error) = self.send_fs(ipc::FS::NewWrite {
                                    path: r.path.clone(),
                                    id: r.id,
                                    file_num: r.file_num,
                                    files: files
                                        .into_iter()
                                        .map(|f| (f.name, f.modified_time))
                                        .collect(),
                                    overwrite_detection: od,
                                    total_size: r.total_size,
                                    conn_id: self.inner.id(),
                                    generation,
                                })
                                .await
                                {
                                    self.cm_write_jobs.remove(&r.id);
                                    self.send(fs::new_error(r.id, error, r.file_num)).await;
                                    return true;
                                }
                                self.file_transferred = true;
                            }
                            Some(file_action::Union::RemoveDir(d)) => {
                                let operation = ipc::CmFileOperation::RemoveDirectory {
                                    path: d.path.clone(),
                                    recursive: d.recursive,
                                };
                                let request_id = match self.reserve_cm_file_request(
                                    CmFileRequestAuthority::Operation {
                                        id: d.id,
                                        file_num: 0,
                                        operation,
                                    },
                                ) {
                                    Ok(request_id) => request_id,
                                    Err(error) => {
                                        self.send(fs::new_error(d.id, error, 0)).await;
                                        return true;
                                    }
                                };
                                if let Err(error) = self.send_fs(ipc::FS::RemoveDir {
                                    path: d.path.clone(),
                                    id: d.id,
                                    recursive: d.recursive,
                                    request_id,
                                })
                                .await
                                {
                                    self.cm_file_requests.remove(&request_id);
                                    self.send(fs::new_error(d.id, error, 0)).await;
                                    return true;
                                }
                                self.file_remove_log_control.on_remove_dir(d);
                            }
                            Some(file_action::Union::RemoveFile(f)) => {
                                let operation = ipc::CmFileOperation::RemoveFile {
                                    path: f.path.clone(),
                                };
                                let request_id = match self.reserve_cm_file_request(
                                    CmFileRequestAuthority::Operation {
                                        id: f.id,
                                        file_num: f.file_num,
                                        operation,
                                    },
                                ) {
                                    Ok(request_id) => request_id,
                                    Err(error) => {
                                        self.send(fs::new_error(f.id, error, f.file_num)).await;
                                        return true;
                                    }
                                };
                                if let Err(error) = self.send_fs(ipc::FS::RemoveFile {
                                    path: f.path.clone(),
                                    id: f.id,
                                    file_num: f.file_num,
                                    request_id,
                                })
                                .await
                                {
                                    self.cm_file_requests.remove(&request_id);
                                    self.send(fs::new_error(f.id, error, f.file_num)).await;
                                    return true;
                                }
                                self.file_remove_log_control.on_remove_file(f);
                            }
                            Some(file_action::Union::Create(c)) => {
                                let operation = ipc::CmFileOperation::CreateDirectory {
                                    path: c.path.clone(),
                                };
                                let request_id = match self.reserve_cm_file_request(
                                    CmFileRequestAuthority::Operation {
                                        id: c.id,
                                        file_num: 0,
                                        operation,
                                    },
                                ) {
                                    Ok(request_id) => request_id,
                                    Err(error) => {
                                        self.send(fs::new_error(c.id, error, 0)).await;
                                        return true;
                                    }
                                };
                                if let Err(error) = self.send_fs(ipc::FS::CreateDir {
                                    path: c.path.clone(),
                                    id: c.id,
                                    request_id,
                                })
                                .await
                                {
                                    self.cm_file_requests.remove(&request_id);
                                    self.send(fs::new_error(c.id, error, 0)).await;
                                    return true;
                                }
                                self.send_to_cm(ipc::Data::FileTransferLog((
                                    "create_dir".to_string(),
                                    serde_json::to_string(&FileActionLog {
                                        id: c.id,
                                        conn_id: self.inner.id(),
                                        path: c.path,
                                        dir: true,
                                    })
                                    .unwrap_or_default(),
                                )))
                                .await;
                            }
                            Some(file_action::Union::Cancel(c)) => {
                                if let Some(authority) = self.cm_write_jobs.remove(&c.id) {
                                    if let Err(error) = self.send_fs(ipc::FS::CancelWrite {
                                        id: c.id,
                                        conn_id: self.inner.id(),
                                        generation: authority.generation,
                                    })
                                    .await
                                    {
                                        log::warn!(
                                            "Failed to cancel CM write job {}: {}",
                                            c.id,
                                            error
                                        );
                                    }
                                }
                                if let Some(authority) = self.cm_read_jobs.remove(&c.id) {
                                    if let Err(error) = self.send_fs(ipc::FS::CancelRead {
                                        id: c.id,
                                        conn_id: self.inner.id(),
                                        generation: authority.generation,
                                    })
                                    .await
                                    {
                                        log::warn!(
                                            "Failed to cancel CM read job {}: {}",
                                            c.id,
                                            error
                                        );
                                    }
                                }
                                if let Some(job) = fs::remove_job(c.id, &mut self.read_jobs) {
                                    self.send_to_cm(ipc::Data::FileTransferLog((
                                        "transfer".to_string(),
                                        fs::serialize_transfer_job(&job, false, true, ""),
                                    )))
                                    .await;
                                }
                            }
                            Some(file_action::Union::SendConfirm(r)) => {
                                if let Some(job) = fs::get_job(r.id, &mut self.read_jobs) {
                                    job.confirm(&r).await;
                                } else if let Some(generation) =
                                    self.consume_cm_read_confirmation(r.id, r.file_num, r.skip())
                                {
                                    if let Err(error) = self.send_fs(ipc::FS::SendConfirmForRead {
                                        id: r.id,
                                        file_num: r.file_num,
                                        skip: r.skip(),
                                        offset_blk: r.offset_blk(),
                                        conn_id: self.inner.id(),
                                        generation,
                                    })
                                    .await
                                    {
                                        self.cm_read_jobs.remove(&r.id);
                                        self.send(fs::new_error(r.id, error, r.file_num)).await;
                                    }
                                } else if self.cm_read_jobs.contains_key(&r.id) {
                                    return true;
                                } else if let Some(generation) =
                                    self.consume_cm_write_confirmation(r.id, r.file_num)
                                {
                                    if let Err(error) = self.send_fs(ipc::FS::SendConfirm {
                                        id: r.id,
                                        file_num: r.file_num,
                                        skip: r.skip(),
                                        offset_blk: r.offset_blk(),
                                        conn_id: self.inner.id(),
                                        generation,
                                    })
                                    .await
                                    {
                                        self.cm_write_jobs.remove(&r.id);
                                        self.send(fs::new_error(r.id, error, r.file_num)).await;
                                    }
                                }
                            }
                            Some(file_action::Union::Rename(r)) => {
                                let operation = ipc::CmFileOperation::Rename {
                                    path: r.path.clone(),
                                    new_name: r.new_name.clone(),
                                };
                                let request_id = match self.reserve_cm_file_request(
                                    CmFileRequestAuthority::Operation {
                                        id: r.id,
                                        file_num: 0,
                                        operation,
                                    },
                                ) {
                                    Ok(request_id) => request_id,
                                    Err(error) => {
                                        self.send(fs::new_error(r.id, error, 0)).await;
                                        return true;
                                    }
                                };
                                if let Err(error) = self.send_fs(ipc::FS::Rename {
                                    id: r.id,
                                    path: r.path.clone(),
                                    new_name: r.new_name.clone(),
                                    request_id,
                                })
                                .await
                                {
                                    self.cm_file_requests.remove(&request_id);
                                    self.send(fs::new_error(r.id, error, 0)).await;
                                    return true;
                                }
                                self.send_to_cm(ipc::Data::FileTransferLog((
                                    "rename".to_string(),
                                    serde_json::to_string(&FileRenameLog {
                                        conn_id: self.inner.id(),
                                        path: r.path,
                                        new_name: r.new_name,
                                    })
                                    .unwrap_or_default(),
                                )))
                                .await;
                            }
                            _ => {}
                        }
                    }
                }
                Some(message::Union::FileResponse(fr)) => match fr.union {
                    Some(file_response::Union::Block(block)) => {
                        let generation = match self.active_cm_write_generation(block.id, "Block") {
                            Some(generation) => generation,
                            None => return true,
                        };
                        if let Err(error) = self.send_fs(ipc::FS::WriteBlock {
                            id: block.id,
                            file_num: block.file_num,
                            conn_id: self.inner.id(),
                            data: block.data,
                            compressed: block.compressed,
                            generation,
                        })
                        .await
                        {
                            self.cm_write_jobs.remove(&block.id);
                            self.send(fs::new_error(block.id, error, block.file_num))
                                .await;
                        }
                    }
                    Some(file_response::Union::Done(d)) => {
                        let generation = match self
                            .begin_cm_write_finalization(d.id, d.file_num, None, "Done")
                        {
                            Some(generation) => generation,
                            None => return true,
                        };
                        if let Err(error) = self.send_fs(ipc::FS::WriteDone {
                            id: d.id,
                            file_num: d.file_num,
                            conn_id: self.inner.id(),
                            generation,
                        })
                        .await
                        {
                            self.cm_write_jobs.remove(&d.id);
                            self.send(fs::new_error(d.id, error, d.file_num)).await;
                        }
                    }
                    Some(file_response::Union::Digest(d)) => {
                        let generation = match self.active_cm_write_generation(d.id, "Digest") {
                            Some(generation) => generation,
                            None => return true,
                        };
                        let request_id = match self.next_cm_file_authority() {
                            Ok(request_id) => request_id,
                            Err(error) => {
                                self.send(fs::new_error(d.id, error, d.file_num)).await;
                                return true;
                            }
                        };
                        let Some(authority) = self.cm_write_jobs.get_mut(&d.id) else {
                            return true;
                        };
                        if authority.generation != generation
                            || !matches!(authority.phase, CmWritePhase::Active)
                        {
                            return true;
                        }
                        authority.phase = CmWritePhase::CheckingDigest {
                            request_id,
                            file_num: d.file_num,
                        };
                        if let Err(error) = self
                            .send_fs(ipc::FS::CheckDigest {
                            id: d.id,
                            file_num: d.file_num,
                            conn_id: self.inner.id(),
                            file_size: d.file_size,
                            last_modified: d.last_modified,
                            is_upload: true,
                            is_resume: d.is_resume,
                            generation,
                            request_id,
                        })
                            .await
                        {
                            self.cm_write_jobs.remove(&d.id);
                            self.send(fs::new_error(d.id, error, d.file_num)).await;
                        }
                    }
                    Some(file_response::Union::Error(e)) => {
                        let peer_error = if e.error.len() <= MAX_CM_FILE_ERROR_BYTES {
                            e.error
                        } else {
                            "peer file transfer error exceeded limit".to_owned()
                        };
                        let generation = match self.begin_cm_write_finalization(
                            e.id,
                            e.file_num,
                            Some(peer_error.clone()),
                            "Error",
                        ) {
                            Some(generation) => generation,
                            None => return true,
                        };
                        if let Err(error) = self
                            .send_fs(ipc::FS::WriteError {
                            id: e.id,
                            file_num: e.file_num,
                            conn_id: self.inner.id(),
                            err: peer_error,
                            generation,
                        })
                            .await
                        {
                            self.cm_write_jobs.remove(&e.id);
                            self.send(fs::new_error(e.id, error, e.file_num)).await;
                        }
                    }
                    _ => {}
                },
                Some(message::Union::Misc(misc)) => match misc.union {
                    Some(misc::Union::SwitchDisplay(s)) => {
                        if !self.handle_switch_display(s).await {
                            return false;
                        }
                    }
                    Some(misc::Union::CaptureDisplays(displays)) => {
                        if !capture_display_has_exactly_one_operation(&displays) {
                            self.note_display_control_reject(format_args!(
                                "capture display message must have exactly one non-empty operation"
                            ));
                            return false;
                        }
                        if !self.validate_peer_display_indexes_syntax(&displays.add, "capture add")
                            || !self
                                .validate_peer_display_indexes_syntax(&displays.sub, "capture sub")
                            || !self
                                .validate_peer_display_indexes_syntax(&displays.set, "capture set")
                        {
                            return false;
                        }
                        let Some(display_count) = self.peer_display_count() else {
                            return false;
                        };
                        let Some(add) = self.validate_peer_display_indexes(
                            &displays.add,
                            "capture add",
                            display_count,
                        ) else {
                            return false;
                        };
                        let Some(sub) = self.validate_peer_display_indexes(
                            &displays.sub,
                            "capture sub",
                            display_count,
                        ) else {
                            return false;
                        };
                        let Some(set) = self.validate_peer_display_indexes(
                            &displays.set,
                            "capture set",
                            display_count,
                        ) else {
                            return false;
                        };
                        if !self.capture_displays(&add, &sub, &set).await {
                            return false;
                        }
                    }
                    #[cfg(windows)]
                    Some(misc::Union::ToggleVirtualDisplay(t)) => {
                        self.toggle_virtual_display(t).await;
                    }
                    Some(misc::Union::TogglePrivacyMode(t)) => {
                        self.toggle_privacy_mode(t).await;
                    }
                    Some(misc::Union::ChatMessage(c)) => {
                        if let Some(text) = self.peer_text_gate.admit_chat(c.text) {
                            self.send_to_cm(ipc::Data::ChatMessage { text }).await;
                            self.chat_unanswered = true;
                        }
                        self.update_auto_disconnect_timer();
                    }
                    Some(misc::Union::Option(o)) => {
                        if let Err(err) = self.update_options(&o).await {
                            log::warn!(
                                "Closing connection after option authority failure: ip={} conn_id={} err='{}'",
                                self.ip,
                                self.inner.id(),
                                err
                            );
                            return false;
                        }
                    }
                    Some(misc::Union::RefreshVideo(r)) => {
                        if r {
                            // Refresh all videos.
                            // Compatibility with old versions and sciter(remote).
                            if !self.refresh_video_display(None) {
                                return false;
                            }
                        }
                        self.update_auto_disconnect_timer();
                    }
                    Some(misc::Union::RefreshVideoDisplay(display)) => {
                        let Some(display) =
                            self.validate_peer_display_index(display, "refresh video display")
                        else {
                            return false;
                        };
                        if !self.refresh_video_display(Some(display)) {
                            return false;
                        }
                        self.update_auto_disconnect_timer();
                    }
                    Some(misc::Union::RestartRemoteDevice(_)) => {
                        #[cfg(not(any(target_os = "android", target_os = "ios")))]
                        if self.restart {
                            // force_reboot, not work on linux vm and macos 14
                            #[cfg(any(target_os = "linux", target_os = "windows"))]
                            match system_shutdown::force_reboot() {
                                Ok(_) => log::info!("Restart by the peer"),
                                Err(e) => log::error!("Failed to restart: {}", e),
                            }
                            #[cfg(any(target_os = "linux", target_os = "macos"))]
                            match system_shutdown::reboot() {
                                Ok(_) => log::info!("Restart by the peer"),
                                Err(e) => log::error!("Failed to restart: {}", e),
                            }
                        }
                    }
                    Some(misc::Union::AudioFormat(format)) => {
                        // R-S19: peer->host audio playback is voice-call only. The input lease is
                        // installed (for Remote AND ViewCamera) exactly when the operator accepts a voice
                        // call, and the honest client streams AudioFormat only after that accept — so
                        // this gate admits both legitimate voice flows while refusing stray host-audio
                        // playback from any session outside an accepted call.
                        if !self.disable_audio && self.voice_call_input.is_some() {
                            if !native_opus_format_within_limit(format.sample_rate, format.channels)
                            {
                                log::warn!(
                                    "dropping unsupported Opus format before controlled audio thread setup: sample_rate={}, channels={}",
                                    format.sample_rate,
                                    format.channels
                                );
                            } else {
                                match native_opus_format_admission(
                                    self.controlled_audio.as_ref().map(|audio| audio.format),
                                    format.sample_rate,
                                    format.channels,
                                ) {
                                    NativeOpusFormatAdmission::AcceptFirst => {
                                        let decoder = start_audio_thread();
                                        let format_key = native_opus_format_key(
                                            format.sample_rate,
                                            format.channels,
                                        );
                                        if let Err(err) =
                                            decoder.try_send(MediaData::AudioFormat(format))
                                        {
                                            log::warn!(
                                                "controlled audio decode queue full; dropping peer audio format: {err}"
                                            );
                                            decoder.close_and_join().await;
                                        } else {
                                            self.controlled_audio = Some(ControlledAudioThread {
                                                format: format_key,
                                                decoder,
                                            });
                                        }
                                    }
                                    NativeOpusFormatAdmission::Duplicate => {
                                        log::debug!(
                                            "dropping repeated peer Opus format without recreating controlled audio thread"
                                        );
                                    }
                                    NativeOpusFormatAdmission::Changed => {
                                        log::warn!(
                                            "dropping peer Opus format change after controlled audio setup: sample_rate={}, channels={}",
                                            format.sample_rate,
                                            format.channels
                                        );
                                    }
                                }
                            }
                        }
                    }
                    #[cfg(not(any(target_os = "android", target_os = "ios")))]
                    Some(misc::Union::ChangeResolution(r)) => self.change_resolution(None, &r),
                    #[cfg(not(any(target_os = "android", target_os = "ios")))]
                    Some(misc::Union::ChangeDisplayResolution(dr)) => {
                        self.change_resolution(Some(dr.display), &dr.resolution)
                    }
                    Some(misc::Union::AutoAdjustFps(fps)) => video_service::VIDEO_QOS
                        .lock()
                        .unwrap()
                        .user_auto_adjust_fps(self.inner.id(), fps),
                    Some(misc::Union::ClientRecordStatus(status)) => video_service::VIDEO_QOS
                        .lock()
                        .unwrap()
                        .user_record(self.inner.id(), status),
                    #[cfg(windows)]
                    Some(misc::Union::SelectedSid(sid)) => {
                        if let Some(current_process_sid) =
                            crate::platform::get_current_process_session_id()
                        {
                            let sessions = crate::platform::get_available_sessions(false);
                            if crate::platform::is_installed()
                                && crate::platform::is_share_rdp()
                                && raii::AuthedConnID::non_port_forward_conn_count() == 1
                                && sessions.len() > 1
                                && current_process_sid != sid
                                && sessions.iter().any(|e| e.sid == sid)
                                && self.is_authed_remote_conn()
                            {
                                log::warn!(
                                    "Rejected Windows session switch request: service-owned session switching requires a receiver-authorized capability"
                                );
                                return true;
                            }
                            if self.file_transfer.is_some() {
                                if let Some((dir, show_hidden)) = self.delayed_read_dir.take() {
                                    if let Err(error) = self.read_dir(&dir, show_hidden).await {
                                        self.send(fs::new_error(0, error, 0)).await;
                                    }
                                }
                            } else if self.view_camera {
                                self.try_sub_camera_displays();
                            } else if !self.terminal {
                                self.try_sub_monitor_services();
                            }
                        }
                    }
                    Some(misc::Union::MessageQuery(mq)) => {
                        let Some(display) = self.validate_peer_display_index(
                            mq.switch_display,
                            "message query switch display",
                        ) else {
                            return true;
                        };
                        if let Some(msg_out) = video_service::make_display_changed_msg(
                            display,
                            None,
                            self.video_source(),
                        ) {
                            self.send(msg_out).await;
                        }
                    }
                    _ => {}
                },
                Some(message::Union::AudioFrame(frame)) => {
                    // R-S19: peer->host audio frames are voice-call only. The voice authority is
                    // cleared before controlled_audio admission closes and its exact decoder joins.
                    if !self.disable_audio && self.voice_call_input.is_some() {
                        if let Some(audio) = &self.controlled_audio {
                            if let Err(err) = audio
                                .decoder
                                .try_send(MediaData::AudioFrame(Box::new(frame)))
                            {
                                log::warn!(
                                    "controlled audio decode queue full; dropping peer audio frame: {err}"
                                );
                            }
                        } else {
                            log::warn!(
                                "Processing audio frame without the voice call audio decoder."
                            );
                        }
                    }
                }
                Some(message::Union::VoiceCallRequest(request)) => {
                    if request.is_connect {
                        // R-S19: voice calls are legit only for Remote/ViewCamera (the client refuses
                        // to offer them for file-transfer/terminal/port-forward, io_loop.rs) — do not
                        // even raise the operator's incoming-call prompt for other session types.
                        if !self.can_drive_voice_call() {
                            return true;
                        }
                        if self.voice_call_input.is_some()
                            || self.voice_call_request_timestamp.is_some()
                        {
                            log::warn!(
                                "dropping overlapping voice-call request before owner replacement"
                            );
                            return true;
                        }
                        self.voice_call_request_timestamp = Some(
                            NonZeroI64::new(request.req_timestamp)
                                .unwrap_or(NonZeroI64::new(get_time()).unwrap()),
                        );
                        // Notify the connection manager.
                        self.send_to_cm(Data::VoiceCallIncoming).await;
                    } else {
                        self.close_voice_call().await;
                    }
                }
                Some(message::Union::VoiceCallResponse(_response)) => {
                    // TODO: Maybe we can do a voice call from cm directly.
                }
                Some(message::Union::ScreenshotRequest(request)) => {
                    if let Some(tx) = self.inner.tx.clone() {
                        if !crate::peer_text::is_bounded_peer_screenshot_request_id(&request.sid) {
                            log::warn!(
                                "dropping screenshot request with an invalid request id from conn_id={}",
                                self.inner.id()
                            );
                            return true;
                        }
                        let Some(display) =
                            self.validate_peer_display_index(request.display, "screenshot request")
                        else {
                            return true;
                        };
                        // R-S11ef/R-S19: the exact connection/channel owns the request and its
                        // source selects the only capture loop allowed to fulfill it.
                        if crate::video_service::set_take_screenshot(
                            self.inner.id(),
                            self.video_source(),
                            display,
                            request.sid.clone(),
                            tx,
                        ) {
                            if !self.refresh_video_display(Some(display)) {
                                return false;
                            }
                        }
                    }
                }
                Some(message::Union::TerminalAction(action)) => {
                    // R-X8/R-D8: the handler stays compiled into the one binary (§14) and is gated
                    // by platform. On the desktop box the terminal is GRANTED (enable-terminal=Y,
                    // full access — the one mode), so an authorized Terminal session sets
                    // self.terminal and a terminal service lease (the service user's shell,
                    // no second credential, R-X14/R-S18) and handle_terminal_action drives the
                    // owner's PTY. It fails closed if no Terminal service lease was authorized.
                    #[cfg(not(any(target_os = "android", target_os = "ios")))]
                    if let Err(err) = self.handle_terminal_action(action).await {
                        log::warn!(
                            "Closing terminal connection after authority failure: ip={} conn_id={} err='{}'",
                            self.ip,
                            self.inner.id(),
                            err
                        );
                        return false;
                    }
                    #[cfg(any(target_os = "android", target_os = "ios"))]
                    {
                        // Terminal is unsupported on mobile — a TerminalAction is ignored.
                        let _ = action;
                        log::warn!(
                            "Terminal action ignored — terminal not available on this build"
                        );
                    }
                }
                _ => {}
            }
        }
        true
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn select_terminal_launch_authority(
        &self,
    ) -> ResultType<terminal_service::TerminalLaunchAuthority> {
        Ok(terminal_service::process_owner_launch_authority())
    }

    #[cfg(target_os = "windows")]
    fn select_terminal_launch_authority(
        &self,
    ) -> ResultType<terminal_service::TerminalLaunchAuthority> {
        match windows_terminal_process_authority(
            crate::common::is_service_owned_server_process(),
            crate::platform::is_root(),
        ) {
            Ok(WindowsTerminalProcessAuthority::ProcessOwner) => {
                Ok(terminal_service::process_owner_launch_authority())
            }
            Ok(WindowsTerminalProcessAuthority::ActiveSessionUser) => {
                self.windows_service_session_launch_authority()
            }
            Err(message) => bail!(message),
        }
    }

    #[cfg(target_os = "windows")]
    fn windows_service_session_launch_authority(
        &self,
    ) -> ResultType<terminal_service::TerminalLaunchAuthority> {
        let session_id = crate::platform::get_current_process_session_id().ok_or_else(|| {
            hbb_common::anyhow::anyhow!("Failed to get server process session ID")
        })?;
        if session_id == 0 {
            bail!("Service-owned terminal server is not in a user session");
        }
        let token = crate::platform::get_user_token(session_id, true);
        if token.is_null() {
            bail!(
                "Failed to get terminal user token for the served session: {}",
                std::io::Error::last_os_error()
            );
        }
        terminal_service::windows_session_launch_authority(session_id, token as usize)
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    async fn prepare_terminal_authority_for_authorization(&mut self) -> Option<bool> {
        if !self.terminal || self.terminal_service_lease.is_some() {
            return None;
        }
        // R-X8: terminal authorization is SessionUser-only — the terminal runs as the
        // service/session user (one PAKE password -> that user's shell, R-F1). The OS
        // second-credential mode (peer os_login username/password -> LogonUserW -> admin
        // check) and its rate-limit + concurrency machinery are excised; CPace's
        // GUESS_FAILURES (R-P14c) is the sole online-guess limiter.
        if let Err(err) = self.prepare_terminal_service() {
            log::warn!(
                "Terminal service authorization failed: ip={} conn_id={} err='{}'",
                self.ip,
                self.inner.id(),
                err
            );
            self.send_login_error("Failed to establish terminal authority.")
                .await;
            sleep(1.).await;
            return Some(false);
        }
        None
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    async fn prepare_terminal_authority_for_authorization(&mut self) -> Option<bool> {
        None
    }

    // R-T15(b) / R-S10 / R-X8: the entire inherited connection-level failure limiter — the
    // LOGIN_FAILURES map + its IPv6-prefix helpers AND the check_failure / update_failure_with_scope
    // shims — is EXCISED. The legacy unkeyed/salted-hash login is gone (R-A1 refuses unkeyed streams
    // before Connection::start; R-S2/R-S6 collapsed the password proof into CPace), and R-X8 removed
    // the last consumer (the terminal OS-credential scope). The sole live online-guess limiter is now
    // the bounded, decaying, per-v4-source GUESS_FAILURES in cpace.rs (R-P14c).

    fn refresh_video_display(&self, display: Option<usize>) -> bool {
        let Some(server) = self.server.upgrade() else {
            log::warn!(
                "refusing video refresh after the controlled server owner retired: conn_id={}",
                self.inner.id()
            );
            return false;
        };
        server.read().unwrap().set_video_service_opt(
            display.map(|d| (self.video_source(), d)),
            video_service::OPTION_REFRESH,
            super::service::SERVICE_OPTION_VALUE_TRUE,
        );
        true
    }

    fn note_display_control_reject(&mut self, detail: fmt::Arguments<'_>) {
        let Some(suppressed) = self.display_control_reject_log.on_reject() else {
            return;
        };
        if suppressed > 0 {
            log::warn!(
                "refusing peer display-control message: {detail}; ip={} conn_id={} (suppressed {} similar events)",
                self.ip,
                self.inner.id(),
                suppressed
            );
        } else {
            log::warn!(
                "refusing peer display-control message: {detail}; ip={} conn_id={}",
                self.ip,
                self.inner.id()
            );
        }
    }

    fn peer_display_count(&mut self) -> Option<usize> {
        if self.view_camera {
            Some(camera::Cameras::get_sync_cameras().len())
        } else {
            #[cfg(target_os = "android")]
            let displays =
                display_service::try_get_displays_for_generation(self.android_server_generation);
            #[cfg(not(target_os = "android"))]
            let displays = display_service::try_get_displays();
            match displays {
                Ok(displays) => Some(displays.len()),
                Err(err) => {
                    self.note_display_control_reject(format_args!(
                        "failed to enumerate displays: {err}"
                    ));
                    None
                }
            }
        }
    }

    fn validate_peer_display_index(&mut self, raw_display: i32, context: &str) -> Option<usize> {
        if !self.validate_peer_display_index_syntax(raw_display, context) {
            return None;
        }
        let Some(display_count) = self.peer_display_count() else {
            return None;
        };
        self.validate_peer_display_index_against_count(raw_display, context, display_count)
    }

    fn validate_peer_display_index_syntax(&mut self, raw_display: i32, context: &str) -> bool {
        if raw_display < 0 {
            self.note_display_control_reject(format_args!(
                "{context}: negative display index {raw_display}"
            ));
            return false;
        }
        true
    }

    fn validate_peer_display_indexes_syntax(&mut self, displays: &[i32], context: &str) -> bool {
        if displays.len() > MAX_PEER_CAPTURE_DISPLAY_ENTRIES {
            self.note_display_control_reject(format_args!(
                "{context}: {} display entries exceeds cap {}",
                displays.len(),
                MAX_PEER_CAPTURE_DISPLAY_ENTRIES
            ));
            return false;
        }
        let mut seen = HashSet::with_capacity(displays.len());
        for raw in displays {
            let display = match usize::try_from(*raw) {
                Ok(display) => display,
                Err(_) => {
                    self.note_display_control_reject(format_args!(
                        "{context}: negative display index {raw}"
                    ));
                    return false;
                }
            };
            if !seen.insert(display) {
                self.note_display_control_reject(format_args!(
                    "{context}: duplicate display index {display}"
                ));
                return false;
            }
        }
        true
    }

    fn validate_peer_display_index_against_count(
        &mut self,
        raw_display: i32,
        context: &str,
        display_count: usize,
    ) -> Option<usize> {
        let display = match usize::try_from(raw_display) {
            Ok(display) => display,
            Err(_) => {
                self.note_display_control_reject(format_args!(
                    "{context}: negative display index {raw_display}"
                ));
                return None;
            }
        };
        if display >= display_count {
            self.note_display_control_reject(format_args!(
                "{context}: display index {display} outside display_count={display_count}"
            ));
            return None;
        }
        Some(display)
    }

    fn validate_peer_display_indexes(
        &mut self,
        displays: &[i32],
        context: &str,
        display_count: usize,
    ) -> Option<Vec<usize>> {
        if displays.len() > MAX_PEER_CAPTURE_DISPLAY_ENTRIES {
            self.note_display_control_reject(format_args!(
                "{context}: {} display entries exceeds cap {}",
                displays.len(),
                MAX_PEER_CAPTURE_DISPLAY_ENTRIES
            ));
            return None;
        }
        if displays.len() > display_count {
            self.note_display_control_reject(format_args!(
                "{context}: {} display entries exceeds display_count={display_count}",
                displays.len()
            ));
            return None;
        }
        let mut out = Vec::with_capacity(displays.len());
        let mut seen = HashSet::with_capacity(displays.len());
        for raw in displays {
            let display = match usize::try_from(*raw) {
                Ok(display) => display,
                Err(_) => {
                    self.note_display_control_reject(format_args!(
                        "{context}: negative display index {raw}"
                    ));
                    return None;
                }
            };
            if display >= display_count {
                self.note_display_control_reject(format_args!(
                    "{context}: display index {display} outside display_count={display_count}"
                ));
                return None;
            }
            if !seen.insert(display) {
                self.note_display_control_reject(format_args!(
                    "{context}: duplicate display index {display}"
                ));
                return None;
            }
            out.push(display);
        }
        Some(out)
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn validate_peer_resolution_dims(&mut self, r: &Resolution, context: &str) -> bool {
        if r.width <= 0
            || r.height <= 0
            || r.width > MAX_PEER_DISPLAY_DIMENSION
            || r.height > MAX_PEER_DISPLAY_DIMENSION
        {
            self.note_display_control_reject(format_args!(
                "{context}: invalid resolution {}x{}",
                r.width, r.height
            ));
            return false;
        }
        true
    }

    async fn handle_switch_display(&mut self, s: SwitchDisplay) -> bool {
        if !switch_display_resolution_is_well_formed(s.width, s.height) {
            self.note_display_control_reject(format_args!(
                "switch display resolution: invalid dimensions {}x{}",
                s.width, s.height
            ));
            return false;
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        if s.width != 0 {
            self.note_display_control_reject(format_args!(
                "switch display resolution is unsupported on this controlled platform"
            ));
            return false;
        }
        let Some(display_idx) = self.validate_peer_display_index(s.display, "switch display")
        else {
            return false;
        };
        let Some(server) = self.server.upgrade() else {
            self.note_display_control_reject(format_args!(
                "switch display server owner is no longer active"
            ));
            return false;
        };
        if self.display_idx != display_idx {
            self.switch_display_to(display_idx, server);

            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            if s.width != 0 && s.height != 0 {
                self.change_resolution(
                    None,
                    &Resolution {
                        width: s.width,
                        height: s.height,
                        ..Default::default()
                    },
                );
            }

            // Send display changed message.
            // 1. For compatibility with old versions ( < 1.2.4 ).
            // 2. Sciter version.
            // 3. Update `SupportedResolutions`.
            if let Some(msg_out) =
                video_service::make_display_changed_msg(self.display_idx, None, self.video_source())
            {
                self.send(msg_out).await;
            }
        }
        true
    }

    fn video_source(&self) -> VideoSource {
        if self.view_camera {
            VideoSource::Camera
        } else {
            VideoSource::Monitor
        }
    }

    fn switch_display_to(&mut self, display_idx: usize, server: Arc<RwLock<Server>>) {
        let new_service_name = video_service::get_service_name(self.video_source(), display_idx);
        let old_service_name =
            video_service::get_service_name(self.video_source(), self.display_idx);
        let mut lock = server.write().unwrap();
        if display_idx != *display_service::PRIMARY_DISPLAY_IDX {
            lock.ensure_video_service(self.video_source(), display_idx);
        }
        // For versions greater than 1.2.4, a `CaptureDisplays` message will be sent immediately.
        // Unnecessary capturers will be removed then.
        if !crate::common::is_support_multi_ui_session(&self.lr.version) {
            lock.subscribe(&old_service_name, self.inner.clone(), false);
        }
        lock.subscribe(&new_service_name, self.inner.clone(), true);
        self.display_idx = display_idx;
    }

    async fn capture_displays(&mut self, add: &[usize], sub: &[usize], set: &[usize]) -> bool {
        let video_source = self.video_source();
        let Some(server) = self.server.upgrade() else {
            self.note_display_control_reject(format_args!(
                "capture display server owner is no longer active"
            ));
            return false;
        };
        let mut lock = server.write().unwrap();
        for display in add.iter() {
            lock.ensure_video_service(video_source, *display);
        }
        for display in set.iter() {
            lock.ensure_video_service(video_source, *display);
        }
        if !add.is_empty() {
            lock.capture_displays(self.inner.clone(), video_source, add, true, false);
        } else if !sub.is_empty() {
            lock.capture_displays(self.inner.clone(), video_source, sub, false, true);
        } else {
            lock.capture_displays(self.inner.clone(), video_source, set, true, true);
        }
        self.multi_ui_session = lock.get_subbed_displays_count(self.inner.id()) > 1;
        if self.follow_remote_window {
            lock.subscribe(
                NAME_WINDOW_FOCUS,
                self.inner.clone(),
                !self.multi_ui_session,
            );
        }
        true
    }

    #[cfg(windows)]
    async fn toggle_virtual_display(&mut self, t: ToggleVirtualDisplay) {
        if !config::option2bool(
            keys::OPTION_ENABLE_VIRTUAL_DISPLAY,
            &Config::get_option(keys::OPTION_ENABLE_VIRTUAL_DISPLAY),
        ) {
            self.note_display_control_reject(format_args!(
                "refusing peer virtual-display toggle under pinned policy: display={} on={}",
                t.display, t.on
            ));
            return;
        }
        if t.display < 0 {
            self.note_display_control_reject(format_args!(
                "virtual-display toggle with negative display index: display={} on={}",
                t.display, t.on
            ));
            return;
        }
        let make_msg = |text: String| {
            let mut msg_out = Message::new();
            let res = MessageBox {
                msgtype: "nook-nocancel-hasclose".to_owned(),
                title: "Virtual display".to_owned(),
                text,
                link: "".to_owned(),
                ..Default::default()
            };
            msg_out.set_message_box(res);
            msg_out
        };

        if t.on {
            if !virtual_display_manager::is_virtual_display_supported() {
                self.send(make_msg("idd_not_support_under_win10_2004_tip".to_string()))
                    .await;
            } else {
                if let Err(e) = virtual_display_manager::plug_in_monitor(t.display as _, Vec::new())
                {
                    log::error!("Failed to plug in virtual display: {}", e);
                    self.send(make_msg(format!(
                        "Failed to plug in virtual display: {}",
                        e
                    )))
                    .await;
                }
            }
        } else {
            if let Err(e) = virtual_display_manager::plug_out_monitor(t.display, false, true) {
                log::error!("Failed to plug out virtual display {}: {}", t.display, e);
                self.send(make_msg(format!(
                    "Failed to plug out virtual displays: {}",
                    e
                )))
                .await;
            }
        }
    }

    async fn toggle_privacy_mode(&mut self, t: TogglePrivacyMode) {
        if t.on {
            self.turn_on_privacy(t.impl_key).await;
        } else {
            self.turn_off_privacy(t.impl_key).await;
        }
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn change_resolution(&mut self, d: Option<i32>, r: &Resolution) {
        if self.keyboard {
            if !self.validate_peer_resolution_dims(r, "change resolution") {
                return;
            }
            if let Some(display) = d {
                if !self.validate_peer_display_index_syntax(display, "change resolution") {
                    return;
                }
            }
            let displays = match display_service::try_get_displays() {
                Ok(displays) => displays,
                Err(err) => {
                    self.note_display_control_reject(format_args!(
                        "change resolution: failed to enumerate displays: {err}"
                    ));
                    return;
                }
            };
            let display_idx = match d {
                Some(display) => {
                    let Some(display) = self.validate_peer_display_index_against_count(
                        display,
                        "change resolution",
                        displays.len(),
                    ) else {
                        return;
                    };
                    display
                }
                None => {
                    if self.display_idx >= displays.len() {
                        let current_display_idx = self.display_idx;
                        let display_count = displays.len();
                        self.note_display_control_reject(format_args!(
                            "change resolution: current display index {} outside display_count={}",
                            current_display_idx, display_count
                        ));
                        return;
                    }
                    self.display_idx
                }
            };
            if let Some(display) = displays.get(display_idx) {
                let name = display.name();
                let supported_modes = crate::platform::resolutions(&name);
                if !supported_modes
                    .iter()
                    .any(|mode| mode.width == r.width && mode.height == r.height)
                {
                    self.note_display_control_reject(format_args!(
                        "change resolution for '{}': unsupported mode {}x{}",
                        &name, r.width, r.height
                    ));
                    return;
                }
                #[allow(unused_mut)]
                let mut record_changed = true;
                #[cfg(windows)]
                if virtual_display_manager::amyuni_idd::is_my_display(&name) {
                    record_changed = false;
                }
                #[cfg(not(target_os = "macos"))]
                let scale = 1.0;
                #[cfg(target_os = "macos")]
                let scale = display.scale();
                let original = (
                    ((display.width() as f64) / scale).round() as _,
                    (display.height() as f64 / scale).round() as _,
                );
                if record_changed {
                    display_service::set_last_changed_resolution(
                        &name,
                        original,
                        (r.width, r.height),
                    );
                }
                if let Err(e) =
                    crate::platform::change_resolution(&name, r.width as _, r.height as _)
                {
                    log::error!(
                        "Failed to change resolution '{}' to ({},{}): {:?}",
                        &name,
                        r.width,
                        r.height,
                        e
                    );
                }
            }
        }
    }

    pub async fn handle_voice_call(&mut self, accepted: bool) {
        if !self.can_drive_voice_call() {
            return;
        }
        if let Some(ts) = self.voice_call_request_timestamp.take() {
            // Establish synchronous Drop-visible ownership before the first await.
            // If response transmission is cancelled, Connection::drop still releases
            // this exact call without clearing another call's process-wide input.
            let accepted = if accepted {
                match crate::audio_service::acquire_voice_call_input(
                    crate::get_default_sound_input(),
                ) {
                    Ok(input_lease) => {
                        self.voice_call_input = Some(input_lease);
                        true
                    }
                    Err(err) => {
                        log::error!("Failed to acquire controlled voice-call input: {err}");
                        false
                    }
                }
            } else {
                false
            };
            let msg = new_voice_call_response(ts.get(), accepted);
            if accepted {
                self.send_to_cm(Data::StartVoiceCall).await;
            } else {
                self.send_to_cm(Data::CloseVoiceCall("".to_owned())).await;
            }
            self.send(msg).await;
            if self.is_authed_view_camera_conn() {
                if let Some(s) = self.server.upgrade() {
                    s.write().unwrap().subscribe(
                        super::audio_service::NAME,
                        self.inner.clone(),
                        self.audio_enabled() && accepted,
                    );
                }
            }
        } else {
            log::warn!("Possible a voice call attack.");
        }
    }

    async fn stop_controlled_audio(&mut self) {
        if let Some(audio) = self.controlled_audio.take() {
            audio.decoder.close_and_join().await;
        }
    }

    pub async fn close_voice_call(&mut self) -> bool {
        if !self.can_drive_voice_call()
            || (self.voice_call_input.is_none() && self.voice_call_request_timestamp.is_none())
        {
            return false;
        }
        drop(self.voice_call_input.take());
        self.voice_call_request_timestamp = None;
        self.send_to_cm(Data::CloseVoiceCall("".to_owned())).await;
        if self.is_authed_view_camera_conn() {
            if let Some(s) = self.server.upgrade() {
                s.write()
                    .unwrap()
                    .subscribe(super::audio_service::NAME, self.inner.clone(), false);
            }
        }
        self.stop_controlled_audio().await;
        true
    }

    async fn update_options(&mut self, o: &OptionMessage) -> ResultType<()> {
        log::info!("Option update: {:?}", o);
        if let Ok(q) = o.image_quality.enum_value() {
            let image_quality;
            if let ImageQuality::NotSet = q {
                if o.custom_image_quality > 0 {
                    image_quality = o.custom_image_quality;
                } else {
                    image_quality = -1;
                }
            } else {
                image_quality = q.value();
            }
            if image_quality > 0 {
                video_service::VIDEO_QOS
                    .lock()
                    .unwrap()
                    .user_image_quality(self.inner.id(), image_quality);
            }
        }
        if o.custom_fps > 0 {
            video_service::VIDEO_QOS
                .lock()
                .unwrap()
                .user_custom_fps(self.inner.id(), o.custom_fps as _);
        }
        if let Some(q) = o.supported_decoding.clone().take() {
            scrap::codec::Encoder::update(scrap::codec::EncodingUpdate::Update(self.inner.id(), q));
        }
        if let Ok(q) = o.lock_after_session_end.enum_value() {
            if q != BoolOption::NotSet {
                self.lock_after_session_end = q == BoolOption::Yes;
            }
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        if let Ok(q) = o.show_remote_cursor.enum_value() {
            if q != BoolOption::NotSet {
                // R-S19: cursor-position / window-focus capture is Remote-only screen metadata; force
                // the peer-set overlay flag false for non-Remote so the NAME_CURSOR/NAME_POS subscribes
                // below (and the disable_keyboard re-subscribe) never capture for FileTransfer/Terminal.
                self.show_remote_cursor = q == BoolOption::Yes && self.is_authed_remote_conn();
                if let Some(s) = self.server.upgrade() {
                    s.write().unwrap().subscribe(
                        NAME_CURSOR,
                        self.inner.clone(),
                        self.peer_keyboard_enabled() || self.show_remote_cursor,
                    );
                    s.write().unwrap().subscribe(
                        NAME_POS,
                        self.inner.clone(),
                        self.show_remote_cursor,
                    );
                }
            }
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        if let Ok(q) = o.follow_remote_cursor.enum_value() {
            if q != BoolOption::NotSet {
                self.follow_remote_cursor = q == BoolOption::Yes;
            }
        }
        if let Ok(q) = o.follow_remote_window.enum_value() {
            if q != BoolOption::NotSet {
                // R-S19: window-focus capture is Remote-only metadata (see show_remote_cursor above).
                self.follow_remote_window = q == BoolOption::Yes && self.is_authed_remote_conn();
                if let Some(s) = self.server.upgrade() {
                    s.write().unwrap().subscribe(
                        NAME_WINDOW_FOCUS,
                        self.inner.clone(),
                        self.follow_remote_window,
                    );
                }
            }
        }
        if let Ok(q) = o.disable_audio.enum_value() {
            if q != BoolOption::NotSet {
                self.disable_audio = q == BoolOption::Yes;
                if self.disable_audio {
                    self.stop_controlled_audio().await;
                }
                if let Some(s) = self.server.upgrade() {
                    if self.is_authed_view_camera_conn() {
                        if self.voice_call_input.is_some() || !self.audio_enabled() {
                            s.write().unwrap().subscribe(
                                super::audio_service::NAME,
                                self.inner.clone(),
                                self.audio_enabled(),
                            );
                        }
                    } else {
                        s.write().unwrap().subscribe(
                            super::audio_service::NAME,
                            self.inner.clone(),
                            self.audio_enabled(),
                        );
                    }
                }
            }
        }
        #[cfg(any(target_os = "windows", feature = "unix-file-copy-paste"))]
        if let Ok(q) = o.enable_file_transfer.enum_value() {
            if q != BoolOption::NotSet {
                self.enable_file_transfer = q == BoolOption::Yes;
                #[cfg(target_os = "windows")]
                self.send_to_cm(ipc::Data::ClipboardFileEnabled(
                    self.file_transfer_enabled(),
                ))
                .await;
                #[cfg(feature = "unix-file-copy-paste")]
                if !self.enable_file_transfer {
                    self.try_empty_file_clipboard();
                }
                #[cfg(feature = "unix-file-copy-paste")]
                if let Some(s) = self.server.upgrade() {
                    s.write().unwrap().subscribe(
                        super::clipboard_service::FILE_NAME,
                        self.inner.clone(),
                        self.can_sub_file_clipboard_service(),
                    );
                }
            }
        }
        if let Ok(q) = o.disable_clipboard.enum_value() {
            if q != BoolOption::NotSet {
                self.disable_clipboard = q == BoolOption::Yes;
                #[cfg(not(any(target_os = "android", target_os = "ios")))]
                self.refresh_cm_clipboard_authority();
                if let Some(s) = self.server.upgrade() {
                    s.write().unwrap().subscribe(
                        super::clipboard_service::NAME,
                        self.inner.clone(),
                        self.can_sub_clipboard_service(),
                    );
                }
            }
        }
        if let Ok(q) = o.disable_keyboard.enum_value() {
            if q != BoolOption::NotSet {
                self.disable_keyboard = q == BoolOption::Yes;
                #[cfg(not(any(target_os = "android", target_os = "ios")))]
                self.refresh_cm_clipboard_authority();
                if let Some(s) = self.server.upgrade() {
                    s.write().unwrap().subscribe(
                        super::clipboard_service::NAME,
                        self.inner.clone(),
                        self.can_sub_clipboard_service(),
                    );
                    #[cfg(feature = "unix-file-copy-paste")]
                    s.write().unwrap().subscribe(
                        super::clipboard_service::FILE_NAME,
                        self.inner.clone(),
                        self.can_sub_file_clipboard_service(),
                    );
                    s.write().unwrap().subscribe(
                        NAME_CURSOR,
                        self.inner.clone(),
                        self.peer_keyboard_enabled() || self.show_remote_cursor,
                    );
                }
            }
        }
        // For compatibility with old versions ( < 1.2.4 ).
        if hbb_common::get_version_number(&self.lr.version)
            < hbb_common::get_version_number("1.2.4")
        {
            if let Ok(q) = o.privacy_mode.enum_value() {
                if self.keyboard {
                    match q {
                        BoolOption::Yes => {
                            self.turn_on_privacy("".to_owned()).await;
                        }
                        BoolOption::No => {
                            self.turn_off_privacy("".to_owned()).await;
                        }
                        _ => {}
                    }
                }
            }
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        if let Ok(q) = o.block_input.enum_value() {
            if self.keyboard && self.block_input {
                match q {
                    BoolOption::Yes => {
                        try_enqueue_input(&self.tx_input, MessageInput::BlockOn)?;
                    }
                    BoolOption::No => {
                        try_enqueue_input(&self.tx_input, MessageInput::BlockOff)?;
                    }
                    _ => {}
                }
            } else {
                if q != BoolOption::NotSet {
                    let state = if q == BoolOption::Yes {
                        back_notification::BlockInputState::BlkOnFailed
                    } else {
                        back_notification::BlockInputState::BlkOffFailed
                    };
                    if let Some(tx) = &self.inner.tx {
                        Self::send_block_input_error(tx, state, "No permission".to_string());
                    }
                }
            }
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        if let Ok(q) = o.terminal_persistent.enum_value() {
            // terminal_persistent is a Terminal-session capability; self.terminal is set only in the
            // Terminal login arm, so key the apply on the session type (R-S19) rather than let any
            // conn type drive terminal state — the non-Terminal apply is inert (empty service_id) but
            // confining it structurally keeps the capability a function of the AuthConnType.
            if self.terminal && q != BoolOption::NotSet {
                self.update_terminal_persistence(q == BoolOption::Yes)?;
            }
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        if let Ok(q) = o.show_my_cursor.enum_value() {
            if q != BoolOption::NotSet {
                use crate::whiteboard;
                self.show_my_cursor = q == BoolOption::Yes;
                #[cfg(target_os = "windows")]
                let is_lower_win10 = !crate::platform::windows::is_win_10_or_greater();
                #[cfg(not(target_os = "windows"))]
                let is_lower_win10 = false;
                #[cfg(target_os = "linux")]
                let is_linux_supported = crate::whiteboard::is_supported();
                #[cfg(not(target_os = "linux"))]
                let is_linux_supported = false;
                let not_support_msg = if is_lower_win10 {
                    "Windows 10 or greater is required."
                } else if cfg!(target_os = "linux") && !is_linux_supported {
                    "This feature is not supported on native Wayland, please install XWayland or switch to X11."
                } else {
                    ""
                };
                if q == BoolOption::Yes {
                    if not_support_msg.is_empty() {
                        // R-S19: the whiteboard cursor overlay is a Remote-only screen-interaction
                        // feature; do not spawn the --whiteboard overlay process for other types.
                        if self.is_authed_remote_conn() {
                            whiteboard::register_whiteboard(self.inner.id);
                        }
                    } else {
                        let mut msg_out = Message::new();
                        let res = MessageBox {
                            msgtype: "nook-nocancel-hasclose".to_owned(),
                            title: "Show my cursor".to_owned(),
                            text: not_support_msg.to_owned(),
                            link: "".to_owned(),
                            ..Default::default()
                        };
                        msg_out.set_message_box(res);
                        self.send(msg_out).await;
                    }
                } else {
                    if not_support_msg.is_empty() {
                        whiteboard::unregister_whiteboard(self.inner.id);
                    }
                }
            }
        }
        Ok(())
    }

    async fn turn_on_privacy(&mut self, impl_key: String) {
        if !self.is_authed_remote_conn() || !self.privacy_mode {
            let msg_out = crate::common::make_privacy_mode_msg(
                back_notification::PrivacyModeState::PrvOnFailedDenied,
                impl_key,
            );
            self.send(msg_out).await;
            return;
        }

        let msg_out = if !privacy_mode::is_privacy_mode_supported() {
            crate::common::make_privacy_mode_msg_with_details(
                back_notification::PrivacyModeState::PrvNotSupported,
                "Unsupported. 1 Multi-screen is not supported. 2 Please confirm the license is activated.".to_string(),
                impl_key,
            )
        } else {
            let is_pre_privacy_on = privacy_mode::is_in_privacy_mode();
            let pre_impl_key = privacy_mode::get_cur_impl_key();

            if is_pre_privacy_on {
                if let Some(pre_impl_key) = pre_impl_key {
                    if !privacy_mode::is_current_privacy_mode_impl(&pre_impl_key) {
                        let off_msg = crate::common::make_privacy_mode_msg(
                            back_notification::PrivacyModeState::PrvOffSucceeded,
                            pre_impl_key,
                        );
                        self.send(off_msg).await;
                    }
                }
            }

            let turn_on_res = privacy_mode::turn_on_privacy(&impl_key, self.inner.id).await;
            match turn_on_res {
                Some(Ok(res)) => {
                    if res {
                        let err_msg = privacy_mode::check_privacy_mode_err(
                            self.inner.id,
                            self.display_idx,
                            5_000,
                        );
                        if err_msg.is_empty() {
                            crate::common::make_privacy_mode_msg(
                                back_notification::PrivacyModeState::PrvOnSucceeded,
                                impl_key,
                            )
                        } else {
                            log::error!(
                                "Check privacy mode failed: {}, turn off privacy mode.",
                                &err_msg
                            );
                            let _ = Self::turn_off_privacy_to_msg(self.inner.id, String::new());
                            crate::common::make_privacy_mode_msg_with_details(
                                back_notification::PrivacyModeState::PrvOnFailed,
                                err_msg,
                                impl_key,
                            )
                        }
                    } else {
                        crate::common::make_privacy_mode_msg(
                            back_notification::PrivacyModeState::PrvOnFailedPlugin,
                            impl_key,
                        )
                    }
                }
                Some(Err(e)) => {
                    log::error!("Failed to turn on privacy mode. {}", e);
                    if privacy_mode::is_in_privacy_mode() {
                        let _ = Self::turn_off_privacy_to_msg(
                            privacy_mode::INVALID_PRIVACY_MODE_CONN_ID,
                            String::new(),
                        );
                    }
                    crate::common::make_privacy_mode_msg_with_details(
                        back_notification::PrivacyModeState::PrvOnFailed,
                        e.to_string(),
                        impl_key,
                    )
                }
                None => crate::common::make_privacy_mode_msg_with_details(
                    back_notification::PrivacyModeState::PrvOffFailed,
                    "Not supported".to_string(),
                    impl_key,
                ),
            }
        };
        self.send(msg_out).await;
    }

    async fn turn_off_privacy(&mut self, impl_key: String) {
        let msg_out = if !privacy_mode::is_privacy_mode_supported() {
            crate::common::make_privacy_mode_msg_with_details(
                back_notification::PrivacyModeState::PrvNotSupported,
                // This error message is used for magnifier. It is ok to use it here.
                "Unsupported. 1 Multi-screen is not supported. 2 Please confirm the license is activated.".to_string(),
                impl_key,
            )
        } else {
            Self::turn_off_privacy_to_msg(self.inner.id, impl_key)
        };
        self.send(msg_out).await;
    }

    pub fn turn_off_privacy_to_msg(_conn_id: i32, impl_key: String) -> Message {
        Self::turn_off_privacy_result_to_msg(
            privacy_mode::turn_off_privacy(_conn_id, None),
            impl_key,
        )
    }

    fn turn_off_privacy_result_to_msg(
        turn_off_res: Option<hbb_common::ResultType<()>>,
        impl_key: String,
    ) -> Message {
        match turn_off_res {
            Some(Ok(_)) => crate::common::make_privacy_mode_msg(
                back_notification::PrivacyModeState::PrvOffSucceeded,
                impl_key,
            ),
            Some(Err(e)) => {
                log::error!("Failed to turn off privacy mode {}", e);
                crate::common::make_privacy_mode_msg_with_details(
                    back_notification::PrivacyModeState::PrvOffFailed,
                    e.to_string(),
                    impl_key,
                )
            }
            None => crate::common::make_privacy_mode_msg_with_details(
                back_notification::PrivacyModeState::PrvOffFailed,
                "Not supported".to_string(),
                impl_key,
            ),
        }
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    async fn stop_input_worker(&mut self) {
        let Some(worker) = self.input_worker.as_ref() else {
            return;
        };
        worker.execution.cancel();
        let completion = Arc::clone(&worker.completion);
        match tokio::task::spawn_blocking(move || completion.wait()).await {
            Ok(true) => {
                self.input_worker.take();
            }
            Ok(false) => {
                self.input_worker.take();
                log::error!("remote input worker panicked while stopping");
            }
            Err(err) => log::error!("remote input worker join task failed: {err}"),
        }
        if self.input_worker.is_none() {
            let queued_bytes = self.tx_input.queued_bytes.load(Ordering::Acquire);
            if queued_bytes != 0 {
                log::error!(
                    "remote input worker stopped with {queued_bytes} bytes still charged to its queue"
                );
            }
        }
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn lock_screen_with_input_arbiter() {
        let mut keys = InputKeyOwnership::unregistered(Arc::clone(&INPUT_KEY_OWNERS));
        let lock_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handle_owned_lock_screen(|event| keys.dispatch(event, handle_owned_key).map(|_| ()))
        }));
        let result = match lock_result {
            Ok(result) => result,
            Err(_) => Err(hbb_common::anyhow::anyhow!(
                "lock-screen input dispatch unwound"
            )),
        };
        if let Err(err) = result.and_then(|_| keys.release_remaining()) {
            log::error!("Could not prove lock-screen input cleanup: {err}");
            std::process::abort();
        }
    }

    async fn on_close(&mut self, reason: &str, lock: bool) {
        if self.closed {
            return;
        }
        drop(self.voice_call_input.take());
        self.voice_call_request_timestamp = None;
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        self.stop_input_worker().await;
        self.stop_controlled_audio().await;
        log::info!("#{} Connection closed: {}", self.inner.id(), reason);
        if lock && self.lock_after_session_end && self.keyboard {
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            Self::lock_screen_with_input_arbiter();
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        let terminal = if self.chat_unanswered || self.file_transferred && cfg!(feature = "flutter") {
            crate::ui_cm_interface::CmConnectionTerminal::Disconnected
        } else {
            crate::ui_cm_interface::CmConnectionTerminal::Close
        };
        #[cfg(any(target_os = "android", target_os = "ios"))]
        let terminal = crate::ui_cm_interface::CmConnectionTerminal::Close;
        self.publish_cm_terminal(terminal);
        // Set this only after the synchronous terminal publication. If this future
        // is cancelled while waiting for a worker above, Drop still publishes Close.
        self.closed = true;
        // R-F1/R-S5: drop the dialed LOCAL target socket promptly on close (try_port_forward_loop
        // already took it for a running tunnel; this covers a tunnel that closed BEFORE relaying).
        self.port_forward_socket.take();
    }

    // The `reason` should be consistent with `check_if_retry` if not empty
    async fn send_close_reason_no_retry(&mut self, reason: &str) {
        let mut misc = Misc::new();
        if reason.is_empty() {
            misc.set_close_reason("Closed manually by the peer".to_string());
        } else {
            misc.set_close_reason(reason.to_string());
        }
        let mut msg_out = Message::new();
        msg_out.set_misc(misc);
        if let Err(err) = self.stream.send(&msg_out).await {
            log::warn!(
                "#{} R-T9: failed to queue CloseReason before closing: {}",
                self.inner.id(),
                err
            );
            return;
        }
        if let Err(err) = self.stream.flush_writer().await {
            log::warn!(
                "#{} R-T9: failed to flush CloseReason before closing: {}",
                self.inner.id(),
                err
            );
        }
    }

    fn next_cm_file_authority(&mut self) -> Result<u64, String> {
        self.cm_file_authority_counter = self
            .cm_file_authority_counter
            .checked_add(1)
            .ok_or_else(|| "connection file authority exhausted".to_owned())?;
        Ok(self.cm_file_authority_counter)
    }

    fn reserve_cm_file_request(
        &mut self,
        authority: CmFileRequestAuthority,
    ) -> Result<u64, String> {
        if self.cm_file_requests.len() >= MAX_PENDING_CM_FILE_REQUESTS {
            return Err(format!(
                "too many pending connection file requests (limit {})",
                MAX_PENDING_CM_FILE_REQUESTS
            ));
        }
        let request_id = self.next_cm_file_authority()?;
        if self
            .cm_file_requests
            .insert(request_id, authority)
            .is_some()
        {
            return Err("duplicate connection file request authority".to_owned());
        }
        Ok(request_id)
    }

    fn valid_cm_file_error(error: String) -> String {
        if error.len() <= MAX_CM_FILE_ERROR_BYTES {
            error
        } else {
            "connection manager error exceeded limit".to_owned()
        }
    }

    fn cm_file_directory_to_proto(
        directory: ipc::CmFileDirectory,
        allow_windows_virtual_drives: bool,
    ) -> Result<FileDirectory, String> {
        crate::ui_cm_interface::check_file_count_limit(directory.entries.len())?;
        let entries: Vec<FileEntry> = directory
            .entries
            .into_iter()
            .map(|entry| {
                let entry_type = match entry.entry_type {
                    ipc::CmFileEntryType::Directory => FileType::Dir,
                    ipc::CmFileEntryType::DirectoryLink => FileType::DirLink,
                    ipc::CmFileEntryType::DirectoryDrive => FileType::DirDrive,
                    ipc::CmFileEntryType::File => FileType::File,
                    ipc::CmFileEntryType::FileLink => FileType::FileLink,
                };
                FileEntry {
                    entry_type: entry_type.into(),
                    name: entry.name,
                    is_hidden: entry.is_hidden,
                    size: entry.size,
                    modified_time: entry.modified_time,
                    ..Default::default()
                }
            })
            .collect();
        if allow_windows_virtual_drives {
            for entry in &entries {
                let entry_type = entry
                    .entry_type
                    .enum_value()
                    .map_err(|value| format!("invalid connection manager entry type {value}"))?;
                if entry_type == FileType::DirDrive {
                    let bytes = entry.name.as_bytes();
                    if !cfg!(windows)
                        || directory.path != "/"
                        || bytes.len() != 2
                        || !bytes[0].is_ascii_uppercase()
                        || bytes[1] != b':'
                    {
                        return Err("invalid connection manager drive entry".to_owned());
                    }
                } else {
                    if entry.name.is_empty() {
                        return Err("invalid empty connection manager directory entry".to_owned());
                    }
                    fs::validate_file_name_no_traversal(&entry.name).map_err(|error| {
                        format!("invalid connection manager directory: {}", error)
                    })?;
                }
            }
        } else {
            if entries
                .iter()
                .any(|entry| entry.entry_type.enum_value().ok() == Some(FileType::DirDrive))
            {
                return Err("unexpected connection manager drive entry".to_owned());
            }
            fs::validate_transfer_file_list(
                None,
                &entries,
                crate::ui_cm_interface::get_max_validated_files(),
            )
            .map_err(|error| format!("invalid connection manager directory: {}", error))?;
        }
        let directory = FileDirectory {
            id: directory.id,
            path: directory.path,
            entries,
            ..Default::default()
        };
        let serialized_len = directory
            .write_to_bytes()
            .map_err(|error| format!("invalid connection manager directory: {}", error))?
            .len();
        if serialized_len > fs::MAX_FILE_ENUM_SERIALIZED_BYTES {
            return Err(format!(
                "connection manager directory exceeds {} serialized bytes",
                fs::MAX_FILE_ENUM_SERIALIZED_BYTES
            ));
        }
        Ok(directory)
    }

    fn active_cm_write_generation(&self, id: i32, kind: &str) -> Option<u64> {
        if self.authorized && self.file_transfer.is_some() {
            if let Some(generation) = active_cm_write_authority_generation(&self.cm_write_jobs, id)
            {
                return Some(generation);
            }
        }
        log::debug!(
            "Dropping FileResponse::{} for non-file, unknown, or inactive write job id={}, conn_id={}",
            kind,
            id,
            self.inner.id()
        );
        None
    }

    fn begin_cm_write_finalization(
        &mut self,
        id: i32,
        file_num: i32,
        peer_error: Option<String>,
        kind: &str,
    ) -> Option<u64> {
        if !self.authorized || self.file_transfer.is_none() {
            return None;
        }
        let conn_id = self.inner.id();
        let authority = self.cm_write_jobs.get_mut(&id)?;
        if !cm_write_finalization_authorized(&authority.phase, peer_error.is_some()) {
            log::debug!(
                "Dropping FileResponse::{} for out-of-phase write job id={}, conn_id={}",
                kind,
                id,
                conn_id
            );
            return None;
        }
        let generation = authority.generation;
        authority.phase = CmWritePhase::Finalizing {
            file_num,
            peer_error,
        };
        Some(generation)
    }

    fn consume_cm_write_confirmation(&mut self, id: i32, file_num: i32) -> Option<u64> {
        let authority = self.cm_write_jobs.get_mut(&id)?;
        if !matches!(
            authority.phase,
            CmWritePhase::AwaitingPeerConfirm {
                file_num: expected_file_num,
            } if expected_file_num == file_num
        ) {
            return None;
        }
        authority.phase = CmWritePhase::Active;
        Some(authority.generation)
    }

    async fn handle_cm_file_response(&mut self, envelope: ipc::CmFileResponse) {
        if !cm_file_response_session_authorized(
            self.authorized,
            self.file_transfer.is_some(),
            self.inner.id(),
            &self.cm_auth_token,
            envelope.conn_id,
            &envelope.cm_auth_token,
        ) {
            log::warn!("Rejected connection-manager file response without exact session authority");
            return;
        }

        match *envelope.response {
            ipc::CmFileResponseKind::ReadDirectory {
                request_id,
                path,
                result,
            } => {
                if !matches!(
                    self.cm_file_requests.get(&request_id),
                    Some(CmFileRequestAuthority::ReadDirectory { .. })
                ) {
                    return;
                }
                let Some(CmFileRequestAuthority::ReadDirectory {
                    id,
                    path: expected_path,
                }) = self.cm_file_requests.remove(&request_id)
                else {
                    return;
                };
                if path != expected_path {
                    self.send(fs::new_error(
                        id,
                        "connection manager response path mismatch",
                        0,
                    ))
                    .await;
                    return;
                }
                let expected_result_path = (!expected_path.is_empty())
                    .then(|| fs::get_string(&fs::get_path(&expected_path)));
                match result.and_then(|directory| {
                    if expected_result_path
                        .as_ref()
                        .is_some_and(|expected| directory.path != *expected)
                    {
                        return Err("connection manager directory path mismatch".to_owned());
                    }
                    Self::cm_file_directory_to_proto(directory, expected_path == "/")
                }) {
                    Ok(directory) if directory.id == id => {
                        let mut response = FileResponse::new();
                        response.set_dir(directory);
                        let mut message = Message::new();
                        message.set_file_response(response);
                        self.send(message).await;
                    }
                    Ok(_) => {
                        self.send(fs::new_error(
                            id,
                            "connection manager response id mismatch",
                            0,
                        ))
                        .await
                    }
                    Err(error) => {
                        self.send(fs::new_error(id, Self::valid_cm_file_error(error), 0))
                            .await
                    }
                }
            }
            ipc::CmFileResponseKind::ReadEmptyDirectories {
                request_id,
                path,
                result,
            } => {
                if !matches!(
                    self.cm_file_requests.get(&request_id),
                    Some(CmFileRequestAuthority::ReadEmptyDirectories { .. })
                ) {
                    return;
                }
                let Some(CmFileRequestAuthority::ReadEmptyDirectories {
                    path: expected_path,
                }) = self.cm_file_requests.remove(&request_id)
                else {
                    return;
                };
                if path != expected_path {
                    self.send(fs::new_error(
                        0,
                        "connection manager response path mismatch",
                        0,
                    ))
                    .await;
                    return;
                }
                match result.and_then(|directories| {
                    crate::ui_cm_interface::check_file_count_limit(directories.len())?;
                    directories
                        .into_iter()
                        .map(|directory| Self::cm_file_directory_to_proto(directory, false))
                        .collect::<Result<Vec<_>, _>>()
                }) {
                    Ok(empty_dirs) => {
                        let mut response = FileResponse::new();
                        response.set_empty_dirs(ReadEmptyDirsResponse {
                            path,
                            empty_dirs,
                            ..Default::default()
                        });
                        let mut message = Message::new();
                        message.set_file_response(response);
                        self.send(message).await;
                    }
                    Err(error) => {
                        self.send(fs::new_error(0, Self::valid_cm_file_error(error), 0))
                            .await
                    }
                }
            }
            ipc::CmFileResponseKind::Operation {
                request_id,
                operation,
                result,
            } => {
                if !matches!(
                    self.cm_file_requests.get(&request_id),
                    Some(CmFileRequestAuthority::Operation {
                        operation: expected_operation,
                        ..
                    }) if expected_operation == &operation
                ) {
                    return;
                }
                let Some(CmFileRequestAuthority::Operation {
                    id,
                    file_num,
                    operation: _,
                }) = self.cm_file_requests.remove(&request_id)
                else {
                    return;
                };
                match result {
                    Ok(()) => self.send(fs::new_done(id, file_num)).await,
                    Err(error) => {
                        self.send(fs::new_error(
                            id,
                            Self::valid_cm_file_error(error),
                            file_num,
                        ))
                        .await
                    }
                }
            }
            ipc::CmFileResponseKind::AllFiles { request_id, result } => {
                if !matches!(
                    self.cm_file_requests.get(&request_id),
                    Some(CmFileRequestAuthority::AllFiles { .. })
                ) {
                    return;
                }
                let Some(CmFileRequestAuthority::AllFiles { id, path }) =
                    self.cm_file_requests.remove(&request_id)
                else {
                    return;
                };
                match result
                    .and_then(|directory| Self::cm_file_directory_to_proto(directory, false))
                {
                    Ok(directory) if directory.id == id && directory.path == path => {
                        let mut response = FileResponse::new();
                        response.set_dir(directory);
                        let mut message = Message::new();
                        message.set_file_response(response);
                        self.send(message).await;
                    }
                    Ok(_) => {
                        self.send(fs::new_error(
                            id,
                            "connection manager response id mismatch",
                            -1,
                        ))
                        .await
                    }
                    Err(error) => {
                        self.send(fs::new_error(id, Self::valid_cm_file_error(error), -1))
                            .await
                    }
                }
            }
            ipc::CmFileResponseKind::ReadJobInit {
                id,
                generation,
                result,
            } => {
                let Some(authority) = self.cm_read_jobs.get_mut(&id) else {
                    return;
                };
                if authority.generation != generation
                    || !matches!(authority.phase, CmReadPhase::Initializing)
                {
                    return;
                }
                match result
                    .and_then(|directory| Self::cm_file_directory_to_proto(directory, false))
                {
                    Ok(directory)
                        if directory.id == id
                            && directory.path == authority.path
                            && usize::try_from(authority.first_file_num)
                                .map(|file_num| file_num <= directory.entries.len())
                                .unwrap_or(false) =>
                    {
                        authority.file_count = Some(directory.entries.len());
                        authority.phase = CmReadPhase::Reading {
                            file_num: authority.first_file_num,
                        };
                        self.send(fs::new_dir(id, directory.path, directory.entries))
                            .await;
                        self.file_transferred = true;
                    }
                    Ok(_) => {
                        self.cm_read_jobs.remove(&id);
                        self.send(fs::new_error(
                            id,
                            "connection manager read job metadata mismatch",
                            0,
                        ))
                        .await;
                    }
                    Err(error) => {
                        self.cm_read_jobs.remove(&id);
                        self.send(fs::new_error(id, Self::valid_cm_file_error(error), 0))
                            .await;
                    }
                }
            }
            ipc::CmFileResponseKind::ReadBlock {
                id,
                generation,
                file_num,
                data,
                compressed,
            } => {
                if !self.advance_cm_read(id, generation, file_num) {
                    return;
                }
                if data.len() > ipc::CM_FILE_BLOCK_MAX_FRAME_BYTES {
                    self.cm_read_jobs.remove(&id);
                    self.send(fs::new_error(
                        id,
                        "connection manager file block exceeded limit",
                        file_num,
                    ))
                    .await;
                    return;
                }
                let mut block = FileTransferBlock::new();
                block.id = id;
                block.file_num = file_num;
                block.data = data.to_vec().into();
                block.compressed = compressed;
                self.send(fs::new_block(block)).await;
            }
            ipc::CmFileResponseKind::ReadDone {
                id,
                generation,
                file_num,
            } => {
                if !self.remove_cm_read_authority(id, generation, file_num, true) {
                    return;
                }
                self.send(fs::new_done(id, file_num)).await;
            }
            ipc::CmFileResponseKind::ReadError {
                id,
                generation,
                file_num,
                error,
            } => {
                if !self.remove_cm_read_authority(id, generation, file_num, false) {
                    return;
                }
                self.send(fs::new_error(
                    id,
                    Self::valid_cm_file_error(error),
                    file_num,
                ))
                .await;
            }
            ipc::CmFileResponseKind::ReadDigest {
                id,
                generation,
                file_num,
                last_modified,
                file_size,
                is_resume,
            } => {
                if !self.begin_cm_read_confirmation(id, generation, file_num) {
                    return;
                }
                let digest = FileTransferDigest {
                    id,
                    file_num,
                    last_modified,
                    file_size,
                    is_upload: false,
                    is_resume,
                    ..Default::default()
                };
                let mut response = FileResponse::new();
                response.set_digest(digest);
                let mut message = Message::new();
                message.set_file_response(response);
                self.send(message).await;
            }
            ipc::CmFileResponseKind::WriteFailed {
                id,
                generation,
                file_num,
                error,
            } => {
                if !self.remove_active_cm_write_authority(id, generation) {
                    return;
                }
                self.send(fs::new_error(
                    id,
                    Self::valid_cm_file_error(error),
                    file_num,
                ))
                .await;
            }
            ipc::CmFileResponseKind::WriteFinalized {
                id,
                generation,
                result,
            } => {
                let Some(authority) = self.cm_write_jobs.get(&id) else {
                    return;
                };
                if authority.generation != generation {
                    return;
                }
                let CmWritePhase::Finalizing {
                    file_num,
                    peer_error,
                } = &authority.phase
                else {
                    return;
                };
                let file_num = *file_num;
                let peer_error = peer_error.clone();
                self.cm_write_jobs.remove(&id);
                match (result, peer_error) {
                    (Ok(()), None) => self.send(fs::new_done(id, file_num)).await,
                    (Ok(()), Some(error)) => self.send(fs::new_error(id, error, file_num)).await,
                    (Err(error), _) => {
                        self.send(fs::new_error(
                            id,
                            Self::valid_cm_file_error(error),
                            file_num,
                        ))
                        .await
                    }
                }
            }
            ipc::CmFileResponseKind::WriteDigest {
                id,
                generation,
                request_id,
                file_num,
                result,
            } => {
                let Some(authority) = self.cm_write_jobs.get_mut(&id) else {
                    return;
                };
                if authority.generation != generation
                    || !matches!(
                        authority.phase,
                        CmWritePhase::CheckingDigest {
                            request_id: expected_request_id,
                            file_num: expected_file_num,
                        } if expected_request_id == request_id && expected_file_num == file_num
                    )
                {
                    return;
                }
                match result {
                    ipc::CmWriteDigestResult::SendConfirm { skip } => {
                        authority.phase = CmWritePhase::Active;
                        let request = FileTransferSendConfirmRequest {
                            id,
                            file_num,
                            union: if skip {
                                Some(file_transfer_send_confirm_request::Union::Skip(true))
                            } else {
                                Some(file_transfer_send_confirm_request::Union::OffsetBlk(0))
                            },
                            ..Default::default()
                        };
                        self.send(fs::new_send_confirm(request)).await;
                    }
                    ipc::CmWriteDigestResult::Digest {
                        last_modified,
                        file_size,
                        is_identical,
                        transferred_size,
                    } => {
                        authority.phase = CmWritePhase::AwaitingPeerConfirm { file_num };
                        let digest = FileTransferDigest {
                            id,
                            file_num,
                            last_modified,
                            file_size,
                            is_upload: true,
                            is_identical,
                            transferred_size,
                            ..Default::default()
                        };
                        let mut response = FileResponse::new();
                        response.set_digest(digest);
                        let mut message = Message::new();
                        message.set_file_response(response);
                        self.send(message).await;
                    }
                    ipc::CmWriteDigestResult::Error(error) => {
                        self.cm_write_jobs.remove(&id);
                        if let Err(cancel_error) = self
                            .send_fs(ipc::FS::CancelWrite {
                                id,
                                conn_id: self.inner.id(),
                                generation,
                            })
                            .await
                        {
                            log::warn!("Failed to cancel CM write job {}: {}", id, cancel_error);
                        }
                        self.send(fs::new_error(
                            id,
                            Self::valid_cm_file_error(error),
                            file_num,
                        ))
                        .await;
                    }
                }
            }
        }
    }

    fn advance_cm_read(&mut self, id: i32, generation: u64, file_num: i32) -> bool {
        let Some(authority) = self.cm_read_jobs.get_mut(&id) else {
            return false;
        };
        if authority.generation != generation || !cm_read_progress_authorized(authority, file_num) {
            return false;
        }
        authority.phase = CmReadPhase::Reading { file_num };
        true
    }

    fn begin_cm_read_confirmation(&mut self, id: i32, generation: u64, file_num: i32) -> bool {
        if !self.advance_cm_read(id, generation, file_num) {
            return false;
        }
        let Some(authority) = self.cm_read_jobs.get_mut(&id) else {
            return false;
        };
        authority.phase = CmReadPhase::AwaitingPeerConfirm { file_num };
        true
    }

    fn consume_cm_read_confirmation(&mut self, id: i32, file_num: i32, skip: bool) -> Option<u64> {
        let authority = self.cm_read_jobs.get_mut(&id)?;
        if !matches!(
            authority.phase,
            CmReadPhase::AwaitingPeerConfirm {
                file_num: expected_file_num,
            } if expected_file_num == file_num
        ) {
            return None;
        }
        let next_file_num = if skip {
            file_num.checked_add(1)?
        } else {
            file_num
        };
        if !cm_read_file_num_authorized(authority, next_file_num, true) {
            return None;
        }
        authority.phase = CmReadPhase::Reading {
            file_num: next_file_num,
        };
        Some(authority.generation)
    }

    fn remove_cm_read_authority(
        &mut self,
        id: i32,
        generation: u64,
        file_num: i32,
        done: bool,
    ) -> bool {
        let Some(authority) = self.cm_read_jobs.get(&id) else {
            return false;
        };
        if authority.generation != generation
            || !cm_read_terminal_authorized(authority, file_num, done)
        {
            return false;
        }
        self.cm_read_jobs.remove(&id);
        true
    }

    fn remove_active_cm_write_authority(&mut self, id: i32, generation: u64) -> bool {
        if !matches!(
            self.cm_write_jobs.get(&id),
            Some(authority)
                if authority.generation == generation
                    && matches!(authority.phase, CmWritePhase::Active)
        ) {
            return false;
        }
        self.cm_write_jobs.remove(&id);
        true
    }

    fn active_read_job_count(&self) -> usize {
        self.cm_read_jobs.len() + self.read_jobs.iter().filter(|job| !job.is_last_job).count()
    }

    fn has_read_job_id(&self, id: i32) -> bool {
        self.cm_read_jobs.contains_key(&id) || self.read_jobs.iter().any(|job| job.id() == id)
    }

    fn ensure_can_start_read_job(&self, id: i32) -> Result<(), String> {
        if self.cm_file_job_ids_seen.contains(&id)
            || self.has_read_job_id(id)
            || self.cm_write_jobs.contains_key(&id)
        {
            return Err(format!("duplicate file transfer job id {}", id));
        }
        if self.active_read_job_count() >= fs::MAX_ACTIVE_FILE_TRANSFER_READ_JOBS_PER_CONN {
            return Err(format!(
                "too many active read jobs for connection (limit {})",
                fs::MAX_ACTIVE_FILE_TRANSFER_READ_JOBS_PER_CONN
            ));
        }
        Ok(())
    }

    fn reserve_cm_read_job(
        &mut self,
        id: i32,
        path: String,
        first_file_num: i32,
    ) -> Result<u64, String> {
        self.ensure_can_start_read_job(id)?;
        let generation = self.next_cm_file_authority()?;
        if !self.cm_file_job_ids_seen.insert(id) {
            return Err(format!("reused read job id {}", id));
        }
        if self
            .cm_read_jobs
            .insert(
                id,
                CmReadAuthority {
                    generation,
                    phase: CmReadPhase::Initializing,
                    path,
                    first_file_num,
                    file_count: None,
                },
            )
            .is_some()
        {
            return Err(format!("duplicate read job id {}", id));
        }
        Ok(generation)
    }

    fn reserve_write_job(&mut self, id: i32) -> Result<u64, String> {
        if self.cm_file_job_ids_seen.contains(&id)
            || self.cm_write_jobs.contains_key(&id)
            || self.has_read_job_id(id)
        {
            return Err(format!("duplicate file transfer job id {}", id));
        }
        if self.cm_write_jobs.len() >= fs::MAX_ACTIVE_FILE_TRANSFER_WRITE_JOBS_PER_CONN {
            return Err(format!(
                "too many active write jobs for connection (limit {})",
                fs::MAX_ACTIVE_FILE_TRANSFER_WRITE_JOBS_PER_CONN
            ));
        }
        let generation = self.next_cm_file_authority()?;
        if !self.cm_file_job_ids_seen.insert(id) {
            return Err(format!("reused write job id {}", id));
        }
        if self
            .cm_write_jobs
            .insert(
                id,
                CmWriteAuthority {
                    generation,
                    phase: CmWritePhase::Active,
                },
            )
            .is_some()
        {
            return Err(format!("duplicate write job id {}", id));
        }
        Ok(generation)
    }

    async fn process_new_read_job(&mut self, mut job: fs::TransferJob, path: String) {
        let files = job.files().to_owned();
        self.send(fs::new_dir(job.id, path.clone(), files.clone()))
            .await;
        job.is_remote = true;
        job.conn_id = self.inner.id();
        self.read_jobs.push(job);
        self.file_timer = crate::rustdesk_interval(time::interval(MILLI1));
    }

    async fn read_empty_dirs(
        &mut self,
        dir: &str,
        include_hidden: bool,
    ) -> Result<(), String> {
        let dir = dir.to_string();
        let request_id =
            self.reserve_cm_file_request(CmFileRequestAuthority::ReadEmptyDirectories {
                path: dir.clone(),
            })?;
        if let Err(error) = self
            .send_fs(ipc::FS::ReadEmptyDirs {
                dir,
                include_hidden,
                request_id,
            })
            .await
        {
            self.cm_file_requests.remove(&request_id);
            return Err(error);
        }
        Ok(())
    }

    async fn read_dir(&mut self, dir: &str, include_hidden: bool) -> Result<(), String> {
        let request_id = self.reserve_cm_file_request(CmFileRequestAuthority::ReadDirectory {
            id: 0,
            path: dir.to_owned(),
        })?;
        let dir = dir.to_string();
        if let Err(error) = self
            .send_fs(ipc::FS::ReadDir {
                dir,
                include_hidden,
                request_id,
            })
            .await
        {
            self.cm_file_requests.remove(&request_id);
            return Err(error);
        }
        Ok(())
    }

    /// Create a new read job and start processing it (Connection-side).
    ///
    /// This is a generic Connection-side read job creation helper used for
    /// generic file transfers on non-Windows platforms.
    ///
    /// On Windows, generic file reads are delegated to CM via `start_read_job()` in
    /// `src/ui_cm_interface.rs` for elevated access.
    ///
    /// Both Connection-side and CM-side implementations use `TransferJob::new_read()`
    /// with similar parameters. When modifying job creation logic, ensure both paths
    /// stay in sync.
    async fn create_and_start_read_job(
        &mut self,
        id: i32,
        job_type: fs::JobType,
        data_source: fs::DataSource,
        file_num: i32,
        include_hidden: bool,
        overwrite_detection: bool,
        path: String,
        check_file_limit: bool,
    ) {
        if let Err(msg) = self.ensure_can_start_read_job(id) {
            self.send(fs::new_error(id, msg, -1)).await;
            return;
        }
        let _metadata_scan_permit = if matches!(&data_source, fs::DataSource::FilePath(_)) {
            match crate::ui_cm_interface::try_acquire_file_metadata_scan() {
                Ok(permit) => Some(permit),
                Err(msg) => {
                    self.send(fs::new_error(id, msg, -1)).await;
                    return;
                }
            }
        } else {
            None
        };
        let budget = crate::ui_cm_interface::file_transfer_enumeration_budget();
        match fs::TransferJob::new_read_with_budget(
            id,
            job_type,
            "".to_string(),
            data_source,
            file_num,
            include_hidden,
            false,
            overwrite_detection,
            budget,
        ) {
            Err(err) => {
                self.send(fs::new_error(id, err, 0)).await;
            }
            Ok(job) => {
                if check_file_limit {
                    if let Err(msg) =
                        crate::ui_cm_interface::check_file_count_limit(job.files().len())
                    {
                        self.send(fs::new_error(id, msg, -1)).await;
                        return;
                    }
                }
                self.process_new_read_job(job, path).await;
            }
        }
    }

    fn record_controlled_file_flow_failure(
        &mut self,
        context: ControlledFileWriteContext,
        error: impl Into<String>,
    ) {
        let error = error.into();
        log::error!(
            "controlled {} failed before peer operation completion (job={:?}, file={}): {}",
            context.operation,
            context.job_id,
            context.file_num,
            error
        );
        if self.file_flow_failure.is_none() {
            self.file_flow_failure = Some((context, error));
        }
    }

    #[inline]
    async fn send(&mut self, msg: Message) {
        if let Some(context) = controlled_file_response_context(&msg) {
            if let Err(error) = enqueue_controlled_file_message(
                &mut self.file_writes,
                &mut self.stream,
                &msg,
                context.clone(),
            )
            .await
            {
                self.record_controlled_file_flow_failure(context, error);
            }
            return;
        }
        allow_err!(self.stream.send(&msg).await);
    }

    #[inline]
    async fn send_checked(&mut self, msg: Message) -> ResultType<()> {
        self.stream.send(&msg).await
    }

    pub fn alive_conns() -> Vec<i32> {
        ALIVE_CONNS.lock().unwrap().clone()
    }

    // R-X9 (slices 2-4): the portable-service running-state half of this check is excised.
    // The portable SYSTEM helper is gone, so `portable_client::running()` is permanently
    // false; the `CmShowElevation` prompt send and the `portable_service_running` misc
    // (proto field 20, also excised) are removed. The UAC / foreground-window-elevated
    // status senders are KEPT and unchanged in behavior: their old `!running` guard term
    // was always true on the installed-service fork (portable never ran), so they now send
    // on any value change exactly as before.
    #[cfg(windows)]
    fn portable_check(&mut self) {
        if self.portable.is_installed || !self.is_remote() || !self.keyboard {
            return;
        }
        if self.authorized {
            let p = &mut self.portable;
            let uac = crate::video_service::IS_UAC_RUNNING.lock().unwrap().clone();
            if p.last_uac != uac {
                p.last_uac = uac;
                let mut misc = Misc::new();
                misc.set_uac(uac);
                let mut msg = Message::new();
                msg.set_misc(misc);
                self.inner.send(msg.into());
            }
            let foreground_window_elevated = crate::video_service::IS_FOREGROUND_WINDOW_ELEVATED
                .lock()
                .unwrap()
                .clone();
            if p.last_foreground_window_elevated != foreground_window_elevated {
                p.last_foreground_window_elevated = foreground_window_elevated;
                let mut misc = Misc::new();
                misc.set_foreground_window_elevated(foreground_window_elevated);
                let mut msg = Message::new();
                msg.set_misc(misc);
                self.inner.send(msg.into());
            }
        }
    }

    fn get_auto_disconenct_timer() -> Option<(Instant, u64)> {
        if Config::get_option("allow-auto-disconnect") == "Y" {
            let mut minute: u64 = Config::get_option("auto-disconnect-timeout")
                .parse()
                .unwrap_or(10);
            if minute == 0 {
                minute = 10;
            }
            Some((Instant::now(), minute))
        } else {
            None
        }
    }

    fn update_auto_disconnect_timer(&mut self) {
        self.auto_disconnect_timer
            .as_mut()
            .map(|t| t.0 = Instant::now());
    }

    #[cfg(feature = "hwcodec")]
    fn update_supported_encoding(&mut self) {
        let Some(last) = &self.last_supported_encoding else {
            return;
        };
        let usable = scrap::codec::Encoder::usable_encoding();
        let Some(usable) = usable else {
            return;
        };
        if usable.vp8 != last.vp8
            || usable.av1 != last.av1
            || usable.h264 != last.h264
            || usable.h265 != last.h265
        {
            let mut misc: Misc = Misc::new();
            let supported_encoding = SupportedEncoding {
                vp8: usable.vp8,
                av1: usable.av1,
                h264: usable.h264,
                h265: usable.h265,
                ..last.clone()
            };
            log::info!("update supported encoding: {:?}", supported_encoding);
            self.last_supported_encoding = Some(supported_encoding.clone());
            misc.set_supported_encoding(supported_encoding);
            let mut msg = Message::new();
            msg.set_misc(misc);
            self.inner.send(msg.into());
        };
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    async fn handle_cursor_switch_display(&mut self, pos: CursorPosition) {
        if self.multi_ui_session {
            return;
        }
        let displays = super::display_service::get_sync_displays();
        let d_index = displays.iter().position(|d| {
            let scale = d.scale;
            pos.x >= d.x
                && pos.y >= d.y
                && (pos.x - d.x) as f64 * scale < d.width as f64
                && (pos.y - d.y) as f64 * scale < d.height as f64
        });
        if let Some(d_index) = d_index {
            if self.display_idx != d_index {
                let mut misc = Misc::new();
                misc.set_follow_current_display(d_index as i32);
                let mut msg_out = Message::new();
                msg_out.set_misc(misc);
                self.send(msg_out).await;
            }
        }
    }

    #[inline]
    fn session_key(&self) -> SessionKey {
        SessionKey {
            peer_id: self.lr.my_id.clone(),
            name: self.lr.my_name.clone(),
            session_id: self.lr.session_id,
        }
    }

    // R-S19 (CWE-863): derive every peer-triggerable capability boolean from the authorized
    // AuthConnType. Called once at authorization time, BEFORE any peer LoginRequest option is applied
    // (update_options), so no login-time option can transiently re-grant a capability the session
    // type was not authorized for (the shape of CVE-2026-58056). Under the pinned access-mode=full
    // (R-S16) every boolean is seeded true, so this — not the per-capability flags — is the only real
    // session-type confinement. Remote keeps full control; each narrower type keeps only what it
    // legitimately needs. This is the single source of truth that replaces the ad-hoc, incomplete
    // per-login-branch clears. Verified retained-capability set (all-platform research):
    //   ViewCamera KEEPS audio  -> voice calls (handle_voice_call / is_authed_view_camera_conn sub).
    //   FileTransfer KEEPS clipboard + file -> the file-clipboard (CLIPRDR) and file transfer itself.
    // Clearing self.audio for FileTransfer/Terminal also closes the outbound host-audio-capture path,
    // because the update_options audio_service subscribe reads audio_enabled() (= self.audio && ...).
    fn confine_capabilities_to_conn_type(&mut self, conn_type: AuthConnType) {
        match conn_type {
            // The sovereign owner's single access-mode=full session (R-S16/§2): full control.
            AuthConnType::Remote => {}
            // File transfer: keeps clipboard (file-clipboard/CLIPRDR) + file; loses desktop input,
            // block-input, privacy, restart, session-recording, and host-audio capture.
            AuthConnType::FileTransfer => {
                self.keyboard = false;
                self.block_input = false;
                self.privacy_mode = false;
                self.restart = false;
                self.recording = false;
                self.audio = false;
            }
            // View camera: keeps audio (voice calls); loses desktop input/control, clipboard, file.
            AuthConnType::ViewCamera => {
                self.keyboard = false;
                self.block_input = false;
                self.privacy_mode = false;
                self.restart = false;
                self.clipboard = false;
                self.file = false;
            }
            // Terminal: keeps only its own PTY; loses every desktop/content capability.
            AuthConnType::Terminal => {
                self.keyboard = false;
                self.block_input = false;
                self.privacy_mode = false;
                self.restart = false;
                self.recording = false;
                self.clipboard = false;
                self.file = false;
                self.audio = false;
            }
            // Port forward never reaches app-message dispatch (early-return in on_message); clear all
            // for hygiene so no stale capability lingers on the tunnel connection.
            AuthConnType::PortForward => {
                self.keyboard = false;
                self.block_input = false;
                self.privacy_mode = false;
                self.restart = false;
                self.recording = false;
                self.clipboard = false;
                self.file = false;
                self.audio = false;
            }
        }
    }

    fn is_authed_remote_conn(&self) -> bool {
        if let Some(id) = self.authed_conn_id.as_ref() {
            return id.conn_type() == AuthConnType::Remote;
        }
        false
    }

    fn is_authed_view_camera_conn(&self) -> bool {
        if let Some(id) = self.authed_conn_id.as_ref() {
            return id.conn_type() == AuthConnType::ViewCamera;
        }
        false
    }

    fn authenticated_video_source(&self) -> Option<VideoSource> {
        if self.is_authed_remote_conn() {
            Some(VideoSource::Monitor)
        } else if self.is_authed_view_camera_conn() {
            Some(VideoSource::Camera)
        } else {
            None
        }
    }

    fn can_drive_voice_call(&self) -> bool {
        self.is_authed_remote_conn() || self.is_authed_view_camera_conn()
    }

    #[cfg(feature = "unix-file-copy-paste")]
    async fn handle_file_clip(&mut self, clip: clipboard::ClipboardFile) {
        let is_stopping_allowed = clip.is_stopping_allowed();
        let file_transfer_enabled = self.file_transfer_enabled();
        let stop = is_stopping_allowed && !file_transfer_enabled;
        log::debug!(
            "Process clipboard message from clip, stop: {}, is_stopping_allowed: {}, file_transfer_enabled: {}",
            stop, is_stopping_allowed, file_transfer_enabled);
        if !stop {
            use hbb_common::config::keys::OPTION_ONE_WAY_FILE_TRANSFER;
            // Note: Code will not reach here if `crate::get_builtin_option(OPTION_ONE_WAY_FILE_TRANSFER) == "Y"` is true.
            // Because `file-clipboard` service will not be subscribed.
            // But we still check it here to keep the same logic to windows version in `ui_cm_interface.rs`.
            if clip.is_beginning_message()
                && crate::get_builtin_option(OPTION_ONE_WAY_FILE_TRANSFER) == "Y"
            {
                // If one way file transfer is enabled, don't send clipboard file to client
            } else {
                // Maybe we should end the connection, because copy&paste files causes everything to wait.
                allow_err!(
                    self.stream
                        .send(&crate::clipboard_file::clip_2_msg(clip))
                        .await
                );
            }
        }
    }

    #[inline]
    #[cfg(feature = "unix-file-copy-paste")]
    fn try_empty_file_clipboard(&mut self) {
        try_empty_clipboard_files(ClipboardSide::Host, self.inner.id());
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn update_terminal_persistence(&mut self, persistent: bool) -> ResultType<()> {
        self.terminal_persistent = persistent;
        let Some(lease) = &self.terminal_service_lease else {
            bail!("Terminal service lease is not set while updating persistence");
        };
        lease.set_persistent(persistent)
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn prepare_terminal_service(&mut self) -> ResultType<()> {
        if self.terminal_service_id.is_empty() {
            self.terminal_service_id = terminal_service::generate_service_id();
        }
        let launch_authority = self.select_terminal_launch_authority()?;
        let lease = terminal_service::prepare(
            self.terminal_service_id.clone(),
            self.terminal_persistent,
            launch_authority,
        )?;
        self.terminal_service_id = lease.service_id().to_owned();
        self.terminal_service_lease = Some(lease);
        Ok(())
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    async fn handle_terminal_action(&mut self, action: TerminalAction) -> ResultType<()> {
        let Some(lease) = &self.terminal_service_lease else {
            bail!("Terminal service lease is not set.");
        };
        if let Err(err) = lease.enqueue_action(action) {
            if terminal_service::is_fatal_authority_error(&err) {
                return Err(err);
            }
            let mut response = TerminalResponse::new();
            let mut error = TerminalError::new();
            error.message = "Failed to queue terminal action".to_owned();
            response.set_error(error);
            let mut msg_out = Message::new();
            msg_out.set_terminal_response(response);
            self.send(msg_out).await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod cm_file_response_authority_tests {
    use super::*;

    #[test]
    fn request_binding_requires_published_authorized_file_transfer_login() {
        assert!(cm_file_request_session_authorized(true, true, true, true));
        assert!(!cm_file_request_session_authorized(false, true, true, true));
        assert!(!cm_file_request_session_authorized(true, false, true, true));
        assert!(!cm_file_request_session_authorized(true, true, false, true));
        assert!(!cm_file_request_session_authorized(true, true, true, false));
    }

    #[test]
    fn session_binding_requires_exact_file_transfer_connection_and_token() {
        assert!(cm_file_response_session_authorized(
            true,
            true,
            7,
            "session-token",
            7,
            "session-token"
        ));
        assert!(!cm_file_response_session_authorized(
            false,
            true,
            7,
            "session-token",
            7,
            "session-token"
        ));
        assert!(!cm_file_response_session_authorized(
            true,
            false,
            7,
            "session-token",
            7,
            "session-token"
        ));
        assert!(!cm_file_response_session_authorized(
            true,
            true,
            7,
            "session-token",
            8,
            "session-token"
        ));
        assert!(!cm_file_response_session_authorized(
            true,
            true,
            7,
            "session-token",
            7,
            "stale-token"
        ));
    }

    #[test]
    fn read_response_requires_monotonic_file_and_confirmation_phases() {
        let mut authority = CmReadAuthority {
            generation: 10,
            phase: CmReadPhase::Initializing,
            path: "/source".to_owned(),
            first_file_num: 1,
            file_count: Some(3),
        };
        assert!(!cm_read_progress_authorized(&authority, 1));

        authority.phase = CmReadPhase::Reading { file_num: 1 };
        assert!(cm_read_progress_authorized(&authority, 1));
        assert!(cm_read_progress_authorized(&authority, 2));
        assert!(!cm_read_progress_authorized(&authority, 0));
        assert!(!cm_read_progress_authorized(&authority, 3));
        assert!(!cm_read_terminal_authorized(&authority, 2, true));
        assert!(cm_read_terminal_authorized(&authority, 3, true));
        assert!(cm_read_terminal_authorized(&authority, 2, false));

        authority.phase = CmReadPhase::AwaitingPeerConfirm { file_num: 1 };
        assert!(!cm_read_progress_authorized(&authority, 1));
        assert!(!cm_read_terminal_authorized(&authority, 3, true));
        assert!(cm_read_terminal_authorized(&authority, 1, false));
        assert!(!cm_read_terminal_authorized(&authority, 2, false));
    }

    #[test]
    fn write_response_requires_active_matching_generation() {
        let mut jobs = HashMap::new();
        jobs.insert(
            4,
            CmWriteAuthority {
                generation: 20,
                phase: CmWritePhase::Active,
            },
        );
        assert_eq!(active_cm_write_authority_generation(&jobs, 4), Some(20));

        jobs.get_mut(&4).unwrap().phase = CmWritePhase::AwaitingPeerConfirm { file_num: 1 };
        assert_eq!(active_cm_write_authority_generation(&jobs, 4), None);

        jobs.get_mut(&4).unwrap().phase = CmWritePhase::CheckingDigest {
            request_id: 9,
            file_num: 1,
        };
        assert_eq!(active_cm_write_authority_generation(&jobs, 4), None);

        jobs.get_mut(&4).unwrap().phase = CmWritePhase::Finalizing {
            file_num: 1,
            peer_error: None,
        };
        assert_eq!(active_cm_write_authority_generation(&jobs, 4), None);

        jobs.insert(
            4,
            CmWriteAuthority {
                generation: 21,
                phase: CmWritePhase::Active,
            },
        );
        assert_eq!(active_cm_write_authority_generation(&jobs, 4), Some(21));
    }

    #[test]
    fn write_finalization_accepts_error_while_confirmation_is_pending() {
        assert!(cm_write_finalization_authorized(
            &CmWritePhase::Active,
            false
        ));
        let awaiting = CmWritePhase::AwaitingPeerConfirm { file_num: 2 };
        assert!(!cm_write_finalization_authorized(&awaiting, false));
        assert!(cm_write_finalization_authorized(&awaiting, true));
        let checking = CmWritePhase::CheckingDigest {
            request_id: 3,
            file_num: 2,
        };
        assert!(!cm_write_finalization_authorized(&checking, false));
        assert!(cm_write_finalization_authorized(&checking, true));
        assert!(!cm_write_finalization_authorized(
            &CmWritePhase::Finalizing {
                file_num: 2,
                peer_error: None,
            },
            true
        ));
    }

    #[test]
    fn cm_error_text_is_bounded_before_network_construction() {
        assert_eq!(Connection::valid_cm_file_error("short".to_owned()), "short");
        assert_eq!(
            Connection::valid_cm_file_error("x".repeat(MAX_CM_FILE_ERROR_BYTES + 1)),
            "connection manager error exceeded limit"
        );
    }
}

#[cfg(target_os = "linux")]
fn current_euid() -> u32 {
    unsafe { hbb_common::libc::geteuid() as u32 }
}

#[cfg(target_os = "linux")]
async fn uid_for_username(username: &str) -> ResultType<String> {
    if username.is_empty() {
        bail!("Cannot resolve uid for empty username");
    }
    let lookup_name = username.to_owned();
    let uid = hbb_common::tokio::task::spawn_blocking(move || {
        hbb_common::users::get_user_by_name(&lookup_name).map(|user| user.uid())
    })
    .await
    .map_err(|err| hbb_common::anyhow::anyhow!("Failed to join uid lookup: {}", err))?
    .ok_or_else(|| hbb_common::anyhow::anyhow!("Failed to resolve uid for {}", username))?;
    Ok(uid.to_string())
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinuxDesktopReadyWait {
    Wake,
    OwnerClosed,
}

#[cfg(target_os = "linux")]
async fn wait_for_linux_desktop_ready(
    receiver: &mut mpsc::Receiver<()>,
    ms_timeout: u64,
) -> LinuxDesktopReadyWait {
    match timeout(ms_timeout, receiver.recv()).await {
        Ok(None) => LinuxDesktopReadyWait::OwnerClosed,
        Ok(Some(())) | Err(_) => LinuxDesktopReadyWait::Wake,
    }
}

#[cfg(all(test, target_os = "linux"))]
mod cm_startup_lifecycle_tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn closed_desktop_readiness_is_terminal() {
        let (sender, mut receiver) = mpsc::channel(1);
        drop(sender);

        assert_eq!(
            wait_for_linux_desktop_ready(&mut receiver, 5_000).await,
            LinuxDesktopReadyWait::OwnerClosed
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn desktop_readiness_signal_remains_a_wake_only() {
        let (sender, mut receiver) = mpsc::channel(1);
        sender.send(()).await.unwrap();

        assert_eq!(
            wait_for_linux_desktop_ready(&mut receiver, 5_000).await,
            LinuxDesktopReadyWait::Wake
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn connection_owner_closure_cancels_pending_cm_bootstrap() {
        let (owner, owner_closed) = oneshot::channel::<()>();
        let (_bootstrap, bootstrap_complete) = oneshot::channel::<()>();
        drop(owner);

        assert_eq!(
            Connection::run_cm_ipc_until_owner_closed(
                owner_closed,
                bootstrap_complete,
                std::future::pending::<()>(),
            )
            .await,
            None
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn live_connection_allows_cm_bootstrap_completion() {
        let (owner, owner_closed) = oneshot::channel::<()>();
        let (_bootstrap, bootstrap_complete) = oneshot::channel::<()>();
        let result =
            Connection::run_cm_ipc_until_owner_closed(owner_closed, bootstrap_complete, async {
                7
            })
            .await;
        drop(owner);

        assert_eq!(result, Some(7));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn completed_bootstrap_allows_bounded_terminal_completion_after_owner_closure() {
        let (owner, owner_closed) = oneshot::channel::<()>();
        let (bootstrap, bootstrap_complete) = oneshot::channel::<()>();
        let (bridge_started, bridge_is_running) = oneshot::channel::<()>();
        let (finish_bridge, bridge_finished) = oneshot::channel::<()>();
        bootstrap.send(()).unwrap();

        let task = tokio::spawn(Connection::run_cm_ipc_until_owner_closed(
            owner_closed,
            bootstrap_complete,
            async move {
                bridge_started.send(()).unwrap();
                bridge_finished.await.unwrap();
                7
            },
        ));
        bridge_is_running.await.unwrap();
        drop(owner);
        finish_bridge.send(()).unwrap();

        assert_eq!(task.await.unwrap(), Some(7));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cm_command_queue_has_exact_capacity_and_recovers_after_dequeue() {
        let (sender, mut receiver) = mpsc::channel(CM_COMMAND_QUEUE_CAPACITY);
        sender.try_send(ipc::Data::ClickTime(1)).unwrap();
        sender.try_send(ipc::Data::ClickTime(2)).unwrap();
        assert!(matches!(
            sender.try_send(ipc::Data::ClickTime(3)),
            Err(mpsc::error::TrySendError::Full(_))
        ));

        assert!(matches!(receiver.recv().await, Some(ipc::Data::ClickTime(1))));
        sender.try_send(ipc::Data::ClickTime(3)).unwrap();
        assert!(matches!(receiver.recv().await, Some(ipc::Data::ClickTime(2))));
        assert!(matches!(receiver.recv().await, Some(ipc::Data::ClickTime(3))));
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn cm_launch_token() -> &'static str {
    &CM_LAUNCH_TOKEN
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn cm_launch_env(launch_token: &str) -> Vec<(&'static str, String)> {
    vec![
        (crate::common::CM_LAUNCH_TOKEN_ENV, launch_token.to_owned()),
        (
            crate::common::CM_LAUNCH_PARENT_ENV,
            std::process::id().to_string(),
        ),
    ]
}

#[cfg(target_os = "macos")]
fn lease_or_launch_platform_cm(
    expected_role: &'static str,
) -> ResultType<Arc<CmProcessGeneration<PlatformCmProcess>>> {
    lease_or_launch_cm_process(&OWNED_CM_PROCESS, expected_role, |launch_token| {
        let child = crate::run_me_with_env(vec![expected_role], cm_launch_env(launch_token))?;
        Ok(MacosCmProcess(child))
    })
}

#[cfg(target_os = "windows")]
fn lease_or_launch_platform_cm(
    expected_role: &'static str,
) -> ResultType<Arc<CmProcessGeneration<PlatformCmProcess>>> {
    if expected_role != "--cm" {
        bail!("unsupported Windows connection-manager role {expected_role}");
    }
    lease_or_launch_cm_process(&OWNED_CM_PROCESS, expected_role, |launch_token| {
        crate::platform::run_connection_manager_user_helper(launch_token)
    })
}

#[cfg(all(target_os = "windows", feature = "windows-cm-lifecycle-probe"))]
pub fn windows_cm_lifecycle_probe_lease(
) -> ResultType<(crate::ipc::WindowsProcessIdentityKey, String)> {
    let generation = lease_or_launch_platform_cm("--cm")?;
    Ok((generation.identity, generation.launch_token.clone()))
}

#[cfg(target_os = "linux")]
async fn connect_authenticated_cm(
    ms_timeout: u64,
    uid: u32,
    expected_arg: &str,
) -> ResultType<(
    ipc::ConnectionTmpl<parity_tokio_ipc::ConnectionClient>,
    crate::ipc::LinuxProcessIdentity,
)> {
    let mut stream = crate::ipc::connect_for_uid(ms_timeout, uid, "_cm").await?;
    let identity = crate::ipc::authenticate_cm_endpoint(&stream, uid, std::process::id())?;
    crate::ipc::authenticate_cm_endpoint_launch_proof(&mut stream, cm_launch_token(), expected_arg)
        .await?;
    Ok((stream, identity))
}

#[cfg(target_os = "macos")]
async fn connect_authenticated_cm_inner(
    ms_timeout: u64,
    expected_arg: &'static str,
) -> ResultType<ipc::ConnectionTmpl<parity_tokio_ipc::ConnectionClient>> {
    let generation = lease_existing_cm_process(&OWNED_CM_PROCESS, expected_arg)?;
    let mut stream = crate::ipc::connect(ms_timeout, "_cm").await?;
    crate::ipc::authenticate_macos_cm_endpoint(&stream, expected_arg, generation.identity)?;
    crate::ipc::authenticate_cm_endpoint_launch_proof(
        &mut stream,
        &generation.launch_token,
        expected_arg,
    )
    .await?;
    Ok(stream)
}

#[cfg(target_os = "windows")]
async fn connect_authenticated_cm_inner(
    ms_timeout: u64,
    expected_arg: &'static str,
) -> ResultType<ipc::ConnectionTmpl<parity_tokio_ipc::ConnectionClient>> {
    let generation = lease_existing_cm_process(&OWNED_CM_PROCESS, expected_arg)?;
    crate::ipc::connect_authenticated_windows_cm(
        ms_timeout,
        expected_arg,
        &generation.launch_token,
        generation.identity,
    )
    .await
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) async fn connect_authenticated_cm(
    ms_timeout: u64,
    expected_arg: &'static str,
) -> ResultType<ipc::ConnectionTmpl<parity_tokio_ipc::ConnectionClient>> {
    let generation = lease_existing_cm_process(&OWNED_CM_PROCESS, expected_arg)?;
    let result = connect_authenticated_cm_inner(ms_timeout, expected_arg).await;
    if result.is_err() {
        if let Err(err) = retire_failed_cm_process_if_exited(&OWNED_CM_PROCESS, &generation) {
            log::warn!("Failed to retire exited connection-manager generation: {err}");
        }
    }
    result
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
// IPC bootstrap summary:
// - Resolve target CM socket (headless/non-headless, optional UID-scoped path on Linux).
// - Start CM when missing, then bridge bidirectional messages between this task and CM IPC.
async fn start_ipc(
    mut rx_to_cm: mpsc::Receiver<ipc::Data>,
    mut cm_terminal: oneshot::Receiver<crate::ui_cm_interface::CmConnectionTerminal>,
    tx_from_cm: mpsc::UnboundedSender<ipc::Data>,
    mut _rx_desktop_ready: mpsc::Receiver<()>,
    tx_stream_ready: mpsc::Sender<()>,
    conn_id: i32,
    cm_auth_token: String,
    bootstrap_complete: oneshot::Sender<()>,
) -> ResultType<()> {
    use hbb_common::anyhow::anyhow;

    // On a normal desktop the connection-manager (`--cm`) runs in the console user's session, so we
    // wait until that user has logged in (`is_prelogin()` clears) before spawning it. But on a
    // headless direct-`--server` box there is no seat0/console user and none will ever arrive, so
    // this wait would spin forever and the CM (which serves file transfer, host audio, chat/voice)
    // would never start. In that case run the CM as the `--server` process owner — the service user,
    // the same process owner the terminal and screen-capture already use (R-S8/R-F1) — instead of
    // waiting. `headless_service_user` records which case we took so the spawn below picks the
    // matching same-user launch. An installed Linux service or macOS LaunchAgent owns the exact
    // user-context server; an unexpected root server must not invent a second privilege transition.
    let headless_service_user = loop {
        if rx_to_cm.is_closed() {
            bail!("connection owner closed before connection-manager target selection");
        }
        if crate::platform::is_headless_no_console_user() {
            break true;
        }
        if !crate::platform::is_prelogin() {
            break false;
        }
        sleep(1.).await;
    };
    #[cfg(target_os = "linux")]
    let headless_cm = crate::is_server()
        && crate::platform::is_headless_allowed()
        && linux_desktop_manager::is_headless();
    #[cfg(not(target_os = "linux"))]
    let headless_cm = false;
    let mut stream = None;
    #[cfg(target_os = "linux")]
    let mut cm_peer_identity = None;
    if !headless_cm {
        #[cfg(target_os = "linux")]
        {
            match connect_authenticated_cm(1000, current_euid(), "--cm").await {
                Ok((s, identity)) => {
                    stream = Some(s);
                    cm_peer_identity = Some(identity);
                }
                Err(err) => {
                    log::debug!("No trusted existing _cm endpoint: {}", err);
                }
            }
        }
        #[cfg(target_os = "macos")]
        match connect_authenticated_cm(1000, "--cm").await {
            Ok(s) => {
                stream = Some(s);
            }
            Err(err) => {
                log::debug!("No trusted existing _cm endpoint: {}", err);
            }
        }
        #[cfg(target_os = "windows")]
        match connect_authenticated_cm(1000, "--cm").await {
            Ok(s) => {
                stream = Some(s);
            }
            Err(err) => {
                log::debug!("No trusted existing _cm endpoint: {}", err);
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        if let Ok(s) = crate::ipc::connect(1000, "_cm").await {
            stream = Some(s);
        }
    }
    if stream.is_none() {
        #[allow(unused_mut)]
        #[allow(unused_assignments)]
        let mut args = vec!["--cm"];
        #[allow(unused_mut)]
        #[cfg(target_os = "linux")]
        let mut user = None;

        // Cm run as user, wait until desktop session is ready.
        #[cfg(target_os = "linux")]
        if headless_cm {
            let mut username = linux_desktop_manager::get_username();
            loop {
                if rx_to_cm.is_closed() {
                    bail!("connection owner closed while waiting for headless connection-manager user");
                }
                if !username.is_empty() {
                    break;
                }
                // `_rx_desktop_ready` is used as a wake-up signal from desktop/session state changes
                // (for example wait_desktop_cm_ready paths). It is not itself a proof of CM readiness.
                if wait_for_linux_desktop_ready(&mut _rx_desktop_ready, 1_000).await
                    == LinuxDesktopReadyWait::OwnerClosed
                {
                    bail!(
                        "desktop readiness owner closed before headless connection-manager startup"
                    );
                }
                username = linux_desktop_manager::get_username();
            }
            let uid = uid_for_username(&username).await?;
            user = Some((uid, username));
            args = vec!["--cm-no-ui"];
        }
        #[cfg(target_os = "linux")]
        let cm_uid: Option<u32> = match &user {
            Some((uid, _)) => Some(
                uid.parse::<u32>()
                    .map_err(|_| anyhow!("Invalid uid {}", uid))?,
            ),
            None => None,
        };
        #[cfg(target_os = "linux")]
        if let Some(uid) = cm_uid {
            match connect_authenticated_cm(1000, uid, "--cm-no-ui").await {
                Ok((s, identity)) => {
                    stream = Some(s);
                    cm_peer_identity = Some(identity);
                }
                Err(err) => {
                    log::debug!("No trusted existing uid-scoped _cm endpoint: {}", err);
                }
            }
        }
        if stream.is_none() {
            if rx_to_cm.is_closed() {
                bail!("connection owner closed before connection-manager launch");
            }
            // The headless path and ordinary user-owned server start the CM without crossing a
            // credential boundary. Windows is the sole exception: its installed LocalSystem server
            // needs the typed current-image helper transition into the active desktop session.
            if crate::platform::is_root() && !headless_service_user {
                #[cfg(target_os = "windows")]
                {
                    let mut res = None;
                    for _ in 0..10 {
                        log::debug!("Start cm");
                        match lease_or_launch_platform_cm("--cm") {
                            Ok(_) => {
                                res = None;
                                break;
                            }
                            Err(err) => {
                                log::error!("Failed to run cm: {err}");
                                res = Some(err);
                            }
                        }
                        sleep(1.).await;
                    }
                    if let Some(err) = res {
                        return Err(err);
                    }
                }
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                bail!(
                    "Refusing root-to-user connection-manager launch; the user-context service must own it"
                );
                #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
                bail!("Refusing unsupported root-to-user connection-manager launch");
            } else {
                log::debug!("Start cm");
                #[cfg(target_os = "linux")]
                let child = crate::common::run_me_with_env_and_parent_death(
                    args,
                    cm_launch_env(cm_launch_token()),
                )?;
                #[cfg(target_os = "linux")]
                super::CHILD_PROCESS.lock().unwrap().push(child);
                #[cfg(target_os = "macos")]
                lease_or_launch_platform_cm("--cm")?;
                #[cfg(target_os = "windows")]
                lease_or_launch_platform_cm("--cm")?;
                #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
                super::CHILD_PROCESS
                    .lock()
                    .unwrap()
                    .push(crate::run_me(args)?);
            }
            for _ in 0..20 {
                if rx_to_cm.is_closed() {
                    bail!("connection owner closed while waiting for connection-manager startup");
                }
                sleep(0.3).await;
                #[cfg(target_os = "linux")]
                {
                    if let Some(uid) = cm_uid {
                        match connect_authenticated_cm(1000, uid, "--cm-no-ui").await {
                            Ok((s, identity)) => {
                                stream = Some(s);
                                cm_peer_identity = Some(identity);
                                break;
                            }
                            Err(err) => {
                                log::debug!("Waiting for trusted uid-scoped _cm endpoint: {}", err);
                            }
                        }
                        continue;
                    }
                }
                #[cfg(target_os = "linux")]
                {
                    match connect_authenticated_cm(1000, current_euid(), "--cm").await {
                        Ok((s, identity)) => {
                            stream = Some(s);
                            cm_peer_identity = Some(identity);
                            break;
                        }
                        Err(err) => {
                            log::debug!("Waiting for trusted _cm endpoint: {}", err);
                        }
                    }
                    continue;
                }
                #[cfg(target_os = "macos")]
                {
                    match connect_authenticated_cm(1000, "--cm").await {
                        Ok(s) => {
                            stream = Some(s);
                            break;
                        }
                        Err(err) => {
                            log::debug!("Waiting for trusted _cm endpoint: {}", err);
                        }
                    }
                    continue;
                }
                #[cfg(target_os = "windows")]
                {
                    match connect_authenticated_cm(1000, "--cm").await {
                        Ok(s) => {
                            stream = Some(s);
                            break;
                        }
                        Err(err) => {
                            log::debug!("Waiting for trusted _cm endpoint: {}", err);
                        }
                    }
                    continue;
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
                if let Ok(s) = crate::ipc::connect(1000, "_cm").await {
                    stream = Some(s);
                    break;
                }
            }
        }
    }
    if stream.is_none() {
        bail!("Failed to connect to connection manager");
    }

    let mut stream = stream.ok_or(anyhow!("none stream"))?;
    #[cfg(target_os = "linux")]
    let _cm_peer_identity_registration = register_cm_peer_identity_for_conn(
        conn_id,
        cm_peer_identity.ok_or_else(|| anyhow!("missing authenticated _cm peer identity"))?,
    )?;
    bootstrap_complete
        .send(())
        .map_err(|_| anyhow!("connection-manager bootstrap owner disappeared"))?;
    let _res = tx_stream_ready.send(()).await;
    let mut cm_file_response_enabled = false;
    loop {
        tokio::select! {
            biased;
            terminal = &mut cm_terminal => {
                let terminal = terminal
                    .map_err(|_| anyhow!("connection-manager terminal owner disappeared"))?
                    .into_data();
                timeout(
                    CM_IPC_COMMAND_SEND_TIMEOUT_MS,
                    stream.send(&terminal),
                )
                .await??;
                return Ok(());
            }
            event = async {
                tokio::select! {
                    res = stream.next() => hbb_common::futures::future::Either::Left(res),
                    res = rx_to_cm.recv() => hbb_common::futures::future::Either::Right(res),
                }
            } => match event {
            hbb_common::futures::future::Either::Left(res) => {
                match res {
                    Err(err) => {
                        return Err(err.into());
                    }
                    Ok(Some(data)) => {
                        match data {
                            ipc::Data::ClickTime(_)=> {
                                let ct = CLICK_TIME.load(Ordering::SeqCst);
                                let data = ipc::Data::ClickTime(ct);
                                timeout(
                                    CM_IPC_COMMAND_SEND_TIMEOUT_MS,
                                    stream.send(&data),
                                )
                                .await??;
                            }
                            ipc::Data::CmFileResponse(mut envelope)
                                if matches!(
                                    envelope.response.as_ref(),
                                    ipc::CmFileResponseKind::ReadBlock { .. }
                                ) =>
                            {
                                if !cm_file_response_enabled
                                    || !cm_file_response_matches_connection(
                                        conn_id,
                                        &cm_auth_token,
                                        envelope.conn_id,
                                        &envelope.cm_auth_token,
                                    )
                                {
                                    bail!("connection-manager read block lacks exact connection authority");
                                }
                                stream.set_max_packet_length(ipc::CM_FILE_BLOCK_MAX_FRAME_BYTES);
                                let raw_data = timeout(
                                    CM_FILE_BLOCK_READ_TIMEOUT_MS,
                                    stream.next_raw(),
                                )
                                .await??;
                                stream.set_max_packet_length(ipc::CM_IPC_MAX_FRAME_BYTES);
                                if let ipc::CmFileResponseKind::ReadBlock { data, .. } =
                                    envelope.response.as_mut()
                                {
                                    *data = raw_data.into();
                                }
                                tx_from_cm.send(ipc::Data::CmFileResponse(envelope))?;
                            }
                            _ => {
                                tx_from_cm.send(data)?;
                            }
                        }
                    }
                    _ => {}
                }
            }
            hbb_common::futures::future::Either::Right(res) => {
                match res {
                    Some(data) => {
                        if let Data::Login {
                            authorized,
                            conn_type,
                            file,
                            ..
                        } = &data
                        {
                            cm_file_response_enabled = *authorized
                                && *file
                                && conn_type.allows_file_authority();
                        }
                        if let Data::AuthorizedFS { cm_auth_token, fs: ipc::FS::WriteBlock{id,
                            file_num,
                            conn_id,
                            data,
                            compressed,
                            generation} } = data {
                                timeout(
                                    CM_IPC_COMMAND_SEND_TIMEOUT_MS,
                                    async {
                                        stream.send(&Data::AuthorizedFS {
                                            cm_auth_token,
                                            fs: ipc::FS::WriteBlock{id, file_num, conn_id, data: Bytes::new(), compressed, generation},
                                        }).await?;
                                        stream.send_raw(data).await
                                    },
                                )
                                .await??;
                        } else {
                            timeout(
                                CM_IPC_COMMAND_SEND_TIMEOUT_MS,
                                stream.send(&data),
                            )
                            .await??;
                        }
                    }
                    None => {
                        bail!("expected");
                    }
                }
            }
            },
        }
    }
}

// in case screen is sleep and blank, here to activate it
fn try_activate_screen() {
    #[cfg(windows)]
    std::thread::spawn(|| {
        mouse_move_relative(-6, -6);
        std::thread::sleep(std::time::Duration::from_millis(30));
        mouse_move_relative(6, 6);
    });
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FileActionLog {
    id: i32,
    conn_id: i32,
    path: String,
    dir: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FileRenameLog {
    conn_id: i32,
    path: String,
    new_name: String,
}

struct FileRemoveLogControl {
    conn_id: i32,
    instant: Instant,
    removed_files: Vec<FileRemoveFile>,
    removed_dirs: Vec<FileRemoveDir>,
}

impl FileRemoveLogControl {
    fn new(conn_id: i32) -> Self {
        FileRemoveLogControl {
            conn_id,
            instant: Instant::now(),
            removed_files: vec![],
            removed_dirs: vec![],
        }
    }

    fn on_remove_file(&mut self, f: FileRemoveFile) -> Option<ipc::Data> {
        self.instant = Instant::now();
        self.removed_files.push(f.clone());
        Some(ipc::Data::FileTransferLog((
            "remove".to_string(),
            serde_json::to_string(&FileActionLog {
                id: f.id,
                conn_id: self.conn_id,
                path: f.path,
                dir: false,
            })
            .unwrap_or_default(),
        )))
    }

    fn on_remove_dir(&mut self, d: FileRemoveDir) -> Option<ipc::Data> {
        self.instant = Instant::now();
        let direct_child = |parent: &str, child: &str| {
            PathBuf::from(child).parent().map(|x| x.to_path_buf()) == Some(PathBuf::from(parent))
        };
        self.removed_files
            .retain(|f| !direct_child(&f.path, &d.path));
        self.removed_dirs
            .retain(|x| !direct_child(&d.path, &x.path));
        if !self
            .removed_dirs
            .iter()
            .any(|x| direct_child(&x.path, &d.path))
        {
            self.removed_dirs.push(d.clone());
        }
        Some(ipc::Data::FileTransferLog((
            "remove".to_string(),
            serde_json::to_string(&FileActionLog {
                id: d.id,
                conn_id: self.conn_id,
                path: d.path,
                dir: true,
            })
            .unwrap_or_default(),
        )))
    }

    fn on_timer(&mut self) -> Vec<ipc::Data> {
        if self.instant.elapsed().as_secs() < 1 {
            return vec![];
        }
        let mut v: Vec<ipc::Data> = vec![];
        self.removed_files
            .drain(..)
            .map(|f| {
                v.push(ipc::Data::FileTransferLog((
                    "remove".to_string(),
                    serde_json::to_string(&FileActionLog {
                        id: f.id,
                        conn_id: self.conn_id,
                        path: f.path,
                        dir: false,
                    })
                    .unwrap_or_default(),
                )));
            })
            .count();
        self.removed_dirs
            .drain(..)
            .map(|d| {
                v.push(ipc::Data::FileTransferLog((
                    "remove".to_string(),
                    serde_json::to_string(&FileActionLog {
                        id: d.id,
                        conn_id: self.conn_id,
                        path: d.path,
                        dir: true,
                    })
                    .unwrap_or_default(),
                )));
            })
            .count();
        v
    }
}

fn start_wakelock_thread() -> std::sync::mpsc::Sender<(usize, usize)> {
    // Check if we should keep awake during incoming sessions
    use crate::platform::{get_wakelock, WakeLock};
    let (tx, rx) = std::sync::mpsc::channel::<(usize, usize)>();
    std::thread::spawn(move || {
        let mut wakelock: Option<WakeLock> = None;
        let mut last_display = false;
        loop {
            match rx.recv() {
                Ok((conn_count, remote_count)) => {
                    let keep_awake = config::Config::get_bool_option(
                        keys::OPTION_KEEP_AWAKE_DURING_INCOMING_SESSIONS,
                    );
                    *WAKELOCK_KEEP_AWAKE_OPTION.lock().unwrap() = Some(keep_awake);
                    if conn_count == 0 || !keep_awake {
                        if wakelock.is_some() {
                            wakelock = None;
                            log::info!("drop wakelock");
                        }
                    } else {
                        let mut display = remote_count > 0;
                        if let Some(_w) = wakelock.as_mut() {
                            if display != last_display {
                                #[cfg(any(target_os = "windows", target_os = "macos"))]
                                {
                                    log::info!("set wakelock display to {display}");
                                    if let Err(e) = _w.set_display(display) {
                                        log::error!(
                                            "failed to set wakelock display to {display}: {e:?}"
                                        );
                                    }
                                }
                            }
                        } else {
                            if cfg!(target_os = "linux") {
                                display = true;
                            }
                            wakelock = Some(get_wakelock(display));
                        }
                        last_display = display;
                    }
                }
                Err(e) => {
                    log::error!("wakelock receive error: {e:?}");
                    break;
                }
            }
        }
    });
    tx
}

#[cfg(windows)]
pub struct PortableState {
    pub last_uac: bool,
    pub last_foreground_window_elevated: bool,
    // R-X9 (slices 2-4): `last_running` (portable-service running-state tracking) removed
    // with the portable run-mode; the UAC / foreground-elevated trackers are kept.
    pub is_installed: bool,
}

#[cfg(windows)]
impl Default for PortableState {
    fn default() -> Self {
        Self {
            is_installed: crate::platform::is_installed(),
            last_uac: Default::default(),
            last_foreground_window_elevated: Default::default(),
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if !self.closed {
            // R-T4: cancellation can drop the run-loop future at any `.await`, skipping
            // `on_close()`. The dedicated one-shot terminal path cannot be starved by the bounded
            // command queue, so publish Close at the start of Drop; the normal path consumes the
            // sender in `on_close()` and does not double-send.
            self.publish_cm_terminal(crate::ui_cm_interface::CmConnectionTerminal::Close);
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        drop(self.cm_ipc_owner.take());
        drop(self.voice_call_input.take());
        // OwnedMediaThread::drop closes peer-audio admission and transfers the
        // exact decoder handle to the fixed reaper; it never joins inline here.
        drop(self.controlled_audio.take());
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        if let Some(worker) = self.input_worker.take() {
            worker.execution.cancel();
            drop(worker);
        }
        // R-T4 (§20): the per-connection cleanup that was previously straight-line AFTER the
        // run-loop — and so LOST on cancellation (a dropped session could leave the physical
        // console BLANKED, a local-security regression; and the `Server`'s own connection map
        // diverged from the RAII-pruned globals) — runs HERE in `Drop`, which executes on BOTH
        // normal exit AND cancellation (the run-loop future being dropped at its `.await`). Every
        // action is synchronous and Drop-safe: the server lock is taken with `if let Ok` (never
        // `.unwrap()` — a poisoned-lock panic in Drop would abort), and each effect is best-effort.
        let id = self.inner.id();
        if let Some(tx) = self.inner.tx.as_ref() {
            video_service::cancel_take_screenshot(id, tx);
        }
        if let Some(video_privacy_conn_id) = privacy_mode::get_privacy_mode_conn_id() {
            if video_privacy_conn_id == id {
                let _ = Self::turn_off_privacy_to_msg(id, String::new());
            }
        }
        video_service::retire_video_frame_connection(id);
        if let Some(s) = self.server.upgrade() {
            if let Ok(mut s) = s.write() {
                s.remove_connection(&self.inner);
            }
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            try_stop_record_cursor_pos();
        }

        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        drop(self.terminal_service_lease.take());
    }
}

#[cfg(target_os = "linux")]
struct LinuxHeadlessHandle {
    pub is_headless_allowed: bool,
    pub is_headless: bool,
    pub wait_ipc_timeout: u64,
    pub rx_cm_stream_ready: mpsc::Receiver<()>,
    pub tx_desktop_ready: mpsc::Sender<()>,
}

#[cfg(target_os = "linux")]
impl LinuxHeadlessHandle {
    pub fn new(rx_cm_stream_ready: mpsc::Receiver<()>, tx_desktop_ready: mpsc::Sender<()>) -> Self {
        let is_headless_allowed = crate::is_server() && crate::platform::is_headless_allowed();
        let is_headless = is_headless_allowed && linux_desktop_manager::is_headless();
        Self {
            is_headless_allowed,
            is_headless,
            wait_ipc_timeout: 10_000,
            rx_cm_stream_ready,
            tx_desktop_ready,
        }
    }

    pub fn try_start_desktop(&mut self) -> String {
        // R-X14 / R-S18: there is no peer os_login to consider — the field is deleted from
        // LoginRequest. The controlled side never spawns an X session or authenticates a peer OS
        // credential; the PAM/session-spawn path is excised from linux_desktop_manager (Appendix C
        // #17), so the collapsed call only reports whether a seat0 desktop session already exists
        // for capture (R-S14). On the shipped build allow-linux-headless is pinned off (R-S16),
        // so this returns "".
        if self.is_headless_allowed {
            linux_desktop_manager::try_start_desktop("", "")
        } else {
            "".to_string()
        }
    }

    pub async fn wait_desktop_cm_ready(&mut self) {
        if self.is_headless {
            self.tx_desktop_ready.send(()).await.ok();
            let _res = timeout(self.wait_ipc_timeout, self.rx_cm_stream_ready.recv()).await;
        }
    }
}

extern "C" fn connection_shutdown_hook() {
    // https://stackoverflow.com/questions/35980148/why-does-an-atexit-handler-panic-when-it-accesses-stdout
    // Please make sure there is no print in the call stack
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    {
        *WALLPAPER_REMOVER.lock().unwrap() = None;
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug, Default)]
struct Retina {
    displays: Vec<DisplayInfo>,
}

#[cfg(target_os = "macos")]
impl Retina {
    #[inline]
    fn set_displays(&mut self, displays: &Vec<DisplayInfo>) {
        self.displays = displays.clone();
    }

    #[inline]
    fn on_mouse_event(&mut self, e: &mut MouseEvent, current: usize) {
        let evt_type = e.mask & crate::input::MOUSE_TYPE_MASK;
        // Delta-based events do not contain absolute coordinates.
        // Avoid applying Retina coordinate scaling to them.
        if evt_type == crate::input::MOUSE_TYPE_WHEEL
            || evt_type == crate::input::MOUSE_TYPE_TRACKPAD
            || evt_type == crate::input::MOUSE_TYPE_MOVE_RELATIVE
        {
            return;
        }
        let Some(d) = self.displays.get(current) else {
            return;
        };
        let s = d.scale;
        if s > 1.0 && e.x >= d.x && e.y >= d.y && e.x < d.x + d.width && e.y < d.y + d.height {
            e.x = d.x + ((e.x - d.x) as f64 / s) as i32;
            e.y = d.y + ((e.y - d.y) as f64 / s) as i32;
        }
    }

    #[inline]
    fn on_cursor_pos(&mut self, pos: &CursorPosition, current: usize) -> Option<Message> {
        let Some(d) = self.displays.get(current) else {
            return None;
        };
        let s = d.scale;
        if s > 1.0
            && pos.x >= d.x
            && pos.y >= d.y
            && (pos.x - d.x) as f64 * s < d.width as f64
            && (pos.y - d.y) as f64 * s < d.height as f64
        {
            let mut pos = pos.clone();
            pos.x = d.x + ((pos.x - d.x) as f64 * s) as i32;
            pos.y = d.y + ((pos.y - d.y) as f64 * s) as i32;
            let mut msg = Message::new();
            msg.set_cursor_position(pos);
            return Some(msg);
        }
        None
    }
}

/// Get control permission state from CONTROL_PERMISSIONS_ARRAY.
/// Returns: Some(false) if any disable, Some(true) if any enable (and no disable), None if not set.
pub fn get_control_permission_state(
    permission: hbb_common::rendezvous_proto::control_permissions::Permission,
    disable_if_has_disabled: bool,
) -> Option<bool> {
    let control_permissions = CONTROL_PERMISSIONS_ARRAY.lock().unwrap();
    let mut has_enable = false;
    let mut has_disable = false;
    for (_, cp) in control_permissions.iter() {
        match crate::get_control_permission(cp.permissions, permission) {
            Some(false) => has_disable = true,
            Some(true) => has_enable = true,
            None => {}
        }
    }
    if disable_if_has_disabled {
        if has_disable {
            Some(false)
        } else if has_enable {
            Some(true)
        } else {
            None
        }
    } else {
        if has_enable {
            Some(true)
        } else if has_disable {
            Some(false)
        } else {
            None
        }
    }
}

pub struct AuthedConn {
    pub conn_id: i32,
    pub conn_type: AuthConnType,
    pub session_key: SessionKey,
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub cm_auth_token: String,
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub cm_file: bool,
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub cm_clipboard: bool,
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn set_authed_conn_cm_clipboard_authority(conn_id: i32, cm_clipboard: bool) {
    if let Some(conn) = AUTHED_CONNS
        .lock()
        .unwrap()
        .iter_mut()
        .find(|conn| conn.conn_id == conn_id)
    {
        conn.cm_clipboard = cm_clipboard;
    }
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub(crate) fn validate_cm_connection_authority(
    conn_id: i32,
    conn_type: ipc::CmAuthConnType,
    cm_auth_token: &str,
) -> ipc::CmConnectionAuthority {
    if conn_id <= 0 || cm_auth_token.is_empty() {
        return ipc::CmConnectionAuthority::default();
    }
    let authed_conns = AUTHED_CONNS.lock().unwrap();
    let Some(conn) = authed_conns.iter().find(|conn| {
        conn.conn_id == conn_id
            && conn.cm_auth_token == cm_auth_token
            && match (conn.conn_type, conn_type) {
                (AuthConnType::Remote, ipc::CmAuthConnType::Remote)
                | (AuthConnType::FileTransfer, ipc::CmAuthConnType::FileTransfer)
                | (AuthConnType::ViewCamera, ipc::CmAuthConnType::ViewCamera)
                | (AuthConnType::Terminal, ipc::CmAuthConnType::Terminal)
                | (AuthConnType::PortForward, ipc::CmAuthConnType::PortForward) => true,
                _ => false,
            }
    }) else {
        return ipc::CmConnectionAuthority::default();
    };
    ipc::CmConnectionAuthority {
        valid: true,
        file: conn.cm_file && conn_type.allows_file_authority(),
        clipboard: conn.cm_clipboard && conn_type.allows_clipboard_authority(),
    }
}

mod raii {
    // ALIVE_CONNS: all connections, including unauthorized connections
    // AUTHED_CONNS: all authorized connections
    // CONTROL_PERMISSIONS_ARRAY: all non-None control permissions

    use super::*;
    pub struct ConnectionID(i32);

    impl ConnectionID {
        pub fn new(id: i32) -> Self {
            ALIVE_CONNS.lock().unwrap().push(id);
            Self(id)
        }
    }

    impl Drop for ConnectionID {
        fn drop(&mut self) {
            #[cfg(target_os = "linux")]
            clear_cm_peer_identity_for_conn(self.0);
            let mut active_conns_lock = ALIVE_CONNS.lock().unwrap();
            active_conns_lock.retain(|&c| c != self.0);
        }
    }

    pub struct AuthedConnID(i32, AuthConnType);

    impl AuthedConnID {
        pub fn new(
            conn_id: i32,
            conn_type: AuthConnType,
            session_key: SessionKey,
            #[cfg(not(any(target_os = "android", target_os = "ios")))] cm_auth_token: String,
            #[cfg(not(any(target_os = "android", target_os = "ios")))] cm_file: bool,
            #[cfg(not(any(target_os = "android", target_os = "ios")))] cm_clipboard: bool,
        ) -> Self {
            AUTHED_CONNS.lock().unwrap().push(AuthedConn {
                conn_id,
                conn_type,
                session_key,
                #[cfg(not(any(target_os = "android", target_os = "ios")))]
                cm_auth_token,
                #[cfg(not(any(target_os = "android", target_os = "ios")))]
                cm_file,
                #[cfg(not(any(target_os = "android", target_os = "ios")))]
                cm_clipboard,
            });
            Self::check_wake_lock();
            use std::sync::Once;
            static _ONCE: Once = Once::new();
            _ONCE.call_once(|| {
                shutdown_hooks::add_shutdown_hook(connection_shutdown_hook);
            });
            if conn_type == AuthConnType::Remote || conn_type == AuthConnType::ViewCamera {
                video_service::VIDEO_QOS
                    .lock()
                    .unwrap()
                    .on_connection_open(conn_id);
            }
            Self(conn_id, conn_type)
        }

        fn check_wake_lock() {
            let conn_count = AUTHED_CONNS.lock().unwrap().len();
            let remote_count = AUTHED_CONNS
                .lock()
                .unwrap()
                .iter()
                .filter(|c| c.conn_type == AuthConnType::Remote)
                .count();
            allow_err!(WAKELOCK_SENDER
                .lock()
                .unwrap()
                .send((conn_count, remote_count)));
        }

        pub fn check_wake_lock_on_setting_changed() {
            let current =
                config::Config::get_bool_option(keys::OPTION_KEEP_AWAKE_DURING_INCOMING_SESSIONS);
            let cached = *WAKELOCK_KEEP_AWAKE_OPTION.lock().unwrap();
            if cached != Some(current) {
                Self::check_wake_lock();
            }
        }

        #[cfg(windows)]
        pub fn non_port_forward_conn_count() -> usize {
            AUTHED_CONNS
                .lock()
                .unwrap()
                .iter()
                .filter(|c| c.conn_type != AuthConnType::PortForward)
                .count()
        }

        pub fn conn_type(&self) -> AuthConnType {
            self.1
        }
    }

    impl Drop for AuthedConnID {
        fn drop(&mut self) {
            if self.1 == AuthConnType::Remote || self.1 == AuthConnType::ViewCamera {
                scrap::codec::Encoder::update(scrap::codec::EncodingUpdate::Remove(self.0));
                video_service::VIDEO_QOS
                    .lock()
                    .unwrap()
                    .on_connection_close(self.0);
            }
            // Clear per-connection state to avoid stale behavior if conn ids are reused.
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            clear_relative_mouse_active(self.0);
            AUTHED_CONNS.lock().unwrap().retain(|c| c.conn_id != self.0);
            let remote_count = AUTHED_CONNS
                .lock()
                .unwrap()
                .iter()
                .filter(|c| c.conn_type == AuthConnType::Remote)
                .count();
            if remote_count == 0 {
                #[cfg(any(target_os = "windows", target_os = "linux"))]
                {
                    *WALLPAPER_REMOVER.lock().unwrap() = None;
                }
                #[cfg(not(any(target_os = "android", target_os = "ios")))]
                display_service::restore_resolutions();
                #[cfg(windows)]
                let _ = virtual_display_manager::reset_all();
                // R-X12: scrap::wayland::pipewire::try_close_session() removed — the Wayland portal
                // capture session is compiled out (X11-pinned, is_x11()==true).
            }
            Self::check_wake_lock();
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            {
                use crate::whiteboard;
                whiteboard::unregister_whiteboard(self.0);
            }
        }
    }

    pub struct ControlPermissionsID {
        id: i32,
        control_permissions: Option<ControlPermissions>,
    }

    impl Drop for ControlPermissionsID {
        fn drop(&mut self) {
            if self.control_permissions.is_some() {
                let mut lock = CONTROL_PERMISSIONS_ARRAY.lock().unwrap();
                lock.retain(|(conn_id, _)| *conn_id != self.id);
            }
        }
    }
    impl ControlPermissionsID {
        pub fn new(id: i32, control_permissions: &Option<ControlPermissions>) -> Self {
            if let Some(s) = control_permissions {
                CONTROL_PERMISSIONS_ARRAY
                    .lock()
                    .unwrap()
                    .push((id, s.clone()));
            }
            Self {
                id,
                control_permissions: control_permissions.clone(),
            }
        }
    }
}

mod test {
    #[allow(unused)]
    use super::*;

    #[test]
    fn windows_terminal_process_authority_is_role_exact() {
        assert_eq!(
            windows_terminal_process_authority(true, true),
            Ok(WindowsTerminalProcessAuthority::ActiveSessionUser)
        );
        assert_eq!(
            windows_terminal_process_authority(false, false),
            Ok(WindowsTerminalProcessAuthority::ProcessOwner)
        );
        assert!(windows_terminal_process_authority(true, false).is_err());
        assert!(windows_terminal_process_authority(false, true).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn retina() {
        let mut retina = Retina {
            displays: vec![DisplayInfo {
                x: 10,
                y: 10,
                width: 1000,
                height: 1000,
                scale: 2.0,
                ..Default::default()
            }],
        };
        let mut mouse: MouseEvent = MouseEvent {
            x: 510,
            y: 510,
            ..Default::default()
        };
        retina.on_mouse_event(&mut mouse, 0);
        assert_eq!(mouse.x, 260);
        assert_eq!(mouse.y, 260);
        let pos = CursorPosition {
            x: 260,
            y: 260,
            ..Default::default()
        };
        let msg = retina.on_cursor_pos(&pos, 0).unwrap();
        let pos = msg.cursor_position();
        assert_eq!(pos.x, 510);
        assert_eq!(pos.y, 510);
    }
}

#[cfg(test)]
mod controlled_file_write_tests {
    use super::*;

    fn limits(count: usize, bytes: usize) -> ControlledFileWriteLimits {
        ControlledFileWriteLimits {
            count,
            bytes,
            timeout: Duration::from_millis(25),
        }
    }

    #[hbb_common::tokio::test]
    async fn r_s11fh_controlled_file_writer_success_releases_exact_count_and_bytes() {
        let mut tracker = ControlledFileWriteTracker::with_limits(limits(2, 16));
        let context = ControlledFileWriteContext::response(Some(7), 3, "test file response");
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
                ControlledFileWriteContext::response(Some(8), 4, "replacement response"),
                16,
            )
            .unwrap();
        assert!(tracker.cancel(replacement).unwrap().is_some());
        assert_eq!(tracker.pending_bytes, 0);
    }

    #[test]
    fn r_s11fh_controlled_file_writer_count_byte_and_sequence_limits_fail_closed() {
        let mut tracker = ControlledFileWriteTracker::with_limits(limits(1, 8));
        let first = tracker
            .reserve(
                ControlledFileWriteContext::response(Some(1), 0, "first response"),
                8,
            )
            .unwrap();
        assert!(tracker
            .reserve(
                ControlledFileWriteContext::response(Some(2), 0, "count overflow"),
                0,
            )
            .unwrap_err()
            .contains("completion capacity"));
        tracker.cancel(first).unwrap();
        assert!(tracker
            .reserve(
                ControlledFileWriteContext::response(Some(3), 0, "byte overflow"),
                9,
            )
            .unwrap_err()
            .contains("byte capacity"));

        tracker.next_id = u64::MAX;
        assert!(tracker
            .reserve(
                ControlledFileWriteContext::response(Some(4), 0, "sequence overflow"),
                1,
            )
            .unwrap_err()
            .contains("sequence exhausted"));
        assert!(tracker.is_empty());
        assert_eq!(tracker.pending_bytes, 0);
    }

    #[hbb_common::tokio::test]
    async fn r_s11fh_controlled_file_writer_failure_and_retirement_are_explicit() {
        let mut tracker = ControlledFileWriteTracker::with_limits(limits(2, 16));
        let failed_context = ControlledFileWriteContext::response(Some(5), 2, "failed response");
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

        let canceled_context =
            ControlledFileWriteContext::response(Some(11), 4, "canceled receipt");
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

        let retained_context = ControlledFileWriteContext::transfer_data(Some(6), 9);
        let reservation = tracker.reserve(retained_context.clone(), 4).unwrap();
        let (_completion, receipt) = hbb_common::tokio::sync::oneshot::channel();
        tracker.attach(reservation, receipt).unwrap();
        assert!(tracker.has_transfer_data());
        assert_eq!(tracker.retire(), vec![retained_context]);
        assert!(tracker.is_empty());
        assert_eq!(tracker.pending_bytes, 0);
    }

    #[hbb_common::tokio::test]
    async fn r_s11fh_controlled_file_writer_timeout_is_terminal_and_bounded() {
        let mut tracker = ControlledFileWriteTracker::with_limits(limits(1, 8));
        let context = ControlledFileWriteContext::response(Some(10), 0, "timed response");
        let reservation = tracker.reserve(context.clone(), 1).unwrap();
        let (_completion, receipt) = hbb_common::tokio::sync::oneshot::channel();
        tracker.attach(reservation, receipt).unwrap();

        let completed = tracker.next().await.unwrap();
        assert_eq!(completed.context, Some(context));
        assert!(completed.result.unwrap_err().contains("timed out"));
        assert!(tracker.is_empty());
    }

    #[hbb_common::tokio::test]
    async fn r_s11fh_controlled_file_frame_retains_its_exact_keyed_writer_receipt() {
        let (sender_side, receiver_side) = hbb_common::tokio::io::duplex(64);
        let local_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        let mut sender_tcp = hbb_common::tcp::FramedStream::from(sender_side, local_addr);
        let mut receiver_tcp = hbb_common::tcp::FramedStream::from(receiver_side, local_addr);
        sender_tcp.set_max_packet_length(8 * 1024);
        receiver_tcp.set_max_packet_length(8 * 1024);
        sender_tcp.set_session_keys(hbb_common::cpace::DirectionalKeys {
            send: [0x31; 32],
            recv: [0x42; 32],
        });
        receiver_tcp.set_session_keys(hbb_common::cpace::DirectionalKeys {
            send: [0x42; 32],
            recv: [0x31; 32],
        });
        let mut sender = hbb_common::Stream::Tcp(sender_tcp);
        let mut receiver = hbb_common::Stream::Tcp(receiver_tcp);
        let message = fs::new_block(FileTransferBlock {
            id: 73,
            file_num: 6,
            data: vec![0x5a; 4_096].into(),
            ..Default::default()
        });
        let context = controlled_file_response_context(&message)
            .expect("the exact file response context must derive from its protobuf");
        let mut tracker = ControlledFileWriteTracker::with_limits(ControlledFileWriteLimits {
            count: 2,
            bytes: 8 * 1024,
            timeout: Duration::from_secs(1),
        });

        enqueue_controlled_file_message(&mut tracker, &mut sender, &message, context.clone())
            .await
            .expect("the exact controlled file frame must enter the bounded writer");
        assert!(
            hbb_common::tokio::time::timeout(Duration::from_millis(20), tracker.next())
                .await
                .is_err()
        );

        let encoded = receiver
            .next()
            .await
            .expect("the exact controlled file frame must arrive")
            .expect("the exact controlled file frame must authenticate");
        let decoded = Message::parse_from_bytes(encoded.as_ref())
            .expect("the exact controlled file frame must decode");
        assert!(matches!(
            decoded.union,
            Some(message::Union::FileResponse(response))
                if matches!(
                    &response.union,
                    Some(file_response::Union::Block(block))
                        if block.id == 73 && block.file_num == 6
                )
        ));

        let completed = tracker.next().await.unwrap();
        assert_eq!(completed.context, Some(context));
        assert_eq!(completed.result, Ok(()));
        assert!(tracker.is_empty());
    }
}
