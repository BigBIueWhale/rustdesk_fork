use crate::ui_interface::get_option;
#[cfg(windows)]
use crate::{display_service, ipc::Data, platform::is_installed};
use hbb_common::tokio;
use hbb_common::{anyhow::anyhow, bail, lazy_static, tokio::sync::oneshot, ResultType};
use serde_derive::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc as std_mpsc,
        Arc, Condvar, Mutex,
    },
    time::Duration,
};

#[cfg(windows)]
pub mod win_exclude_from_capture;
#[cfg(windows)]
mod win_privacy_hotkey;
#[cfg(windows)]
pub mod win_mag;
#[cfg(windows)]
pub mod win_topmost_window;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(windows)]
mod win_virtual_display;

pub const INVALID_PRIVACY_MODE_CONN_ID: i32 = 0;
pub const OCCUPIED: &'static str = "Privacy occupied by another one.";
pub const TURN_OFF_OTHER_OWNER: &'static str =
    "Failed to turn off privacy mode that belongs to another connection.";
pub const NO_PHYSICAL_DISPLAYS: &'static str = "no_need_privacy_mode_no_physical_displays_tip";

const PRIVACY_ACTIVATION_RESPONSE_DEADLINE: Duration = Duration::from_millis(7_500);

pub const PRIVACY_MODE_IMPL_WIN_MAG: &str = "privacy_mode_impl_mag";
pub const PRIVACY_MODE_IMPL_WIN_EXCLUDE_FROM_CAPTURE: &str =
    "privacy_mode_impl_exclude_from_capture";
pub const PRIVACY_MODE_IMPL_WIN_VIRTUAL_DISPLAY: &str = "privacy_mode_impl_virtual_display";

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "t", content = "c")]
pub enum PrivacyModeState {
    OffSucceeded,
    OffByPeer,
    OffUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrivacyActivationDecision {
    Commit,
    Cancel,
}

struct PrivacyActivationGate {
    cancelled: Arc<AtomicBool>,
    endpoints: Mutex<
        Option<(
            oneshot::Sender<()>,
            std_mpsc::Receiver<PrivacyActivationDecision>,
        )>,
    >,
}

struct PrivacyActivationController {
    cancelled: Arc<AtomicBool>,
}

impl PrivacyActivationController {
    fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    fn cancellation_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

impl Drop for PrivacyActivationController {
    fn drop(&mut self) {
        self.cancel();
    }
}

type PrivacyActivationResult = Option<ResultType<bool>>;

struct PrivacyActivationJoinRequest {
    worker: std::thread::JoinHandle<PrivacyActivationResult>,
    completed: oneshot::Sender<PrivacyActivationResult>,
    admission_permit: tokio::sync::OwnedSemaphorePermit,
    pending_owner: PendingPrivacyActivation,
}

struct PrivacyActivationReaper {
    sender: std_mpsc::Sender<PrivacyActivationJoinRequest>,
    _worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

const PRIVACY_ACTIVATION_CONCURRENCY: usize = 1;
#[cfg(any(windows, target_os = "macos", test))]
const PRIVACY_RETIREMENT_QUEUE_CAPACITY: usize = 32;

#[cfg(any(windows, target_os = "macos", test))]
struct PrivacyRetirementRequest {
    conn_id: i32,
    cm_auth_token: String,
}

#[derive(Clone)]
struct PrivacyOwnerIdentity {
    conn_id: i32,
    cm_auth_token: String,
}

impl PrivacyOwnerIdentity {
    fn from_owner(owner: &PrivacyModeConnectionOwner) -> Self {
        Self {
            conn_id: owner.conn_id,
            cm_auth_token: owner.cm_auth_token.clone(),
        }
    }

    fn matches_parts(&self, conn_id: i32, cm_auth_token: &str) -> bool {
        self.conn_id == conn_id
            && !cm_auth_token.is_empty()
            && hbb_common::sodiumoxide::utils::memcmp(
                self.cm_auth_token.as_bytes(),
                cm_auth_token.as_bytes(),
            )
    }
}

#[derive(Default)]
struct PrivacyOwnerLifecycle {
    active: Option<PrivacyOwnerIdentity>,
    activating: Option<PrivacyOwnerIdentity>,
}

struct PrivacyOwnerLifecycleCell {
    state: Mutex<PrivacyOwnerLifecycle>,
    changed: Condvar,
}

impl Default for PrivacyOwnerLifecycleCell {
    fn default() -> Self {
        Self {
            state: Mutex::new(PrivacyOwnerLifecycle::default()),
            changed: Condvar::new(),
        }
    }
}

struct PendingPrivacyActivation {
    owner: PrivacyOwnerIdentity,
}

#[cfg(any(windows, target_os = "macos"))]
struct PrivacyRetirementDispatcher {
    sender: std_mpsc::SyncSender<PrivacyRetirementRequest>,
    _worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

lazy_static::lazy_static! {
    static ref PRIVACY_ACTIVATION_ADMISSION: Arc<tokio::sync::Semaphore> =
        Arc::new(tokio::sync::Semaphore::new(PRIVACY_ACTIVATION_CONCURRENCY));

    static ref PRIVACY_ACTIVATION_REAPER:
        Result<PrivacyActivationReaper, String> = {
        let (sender, receiver) = std_mpsc::channel::<PrivacyActivationJoinRequest>();
        std::thread::Builder::new()
            .name("rustdesk-privacy-activation-reaper".to_owned())
            .spawn(move || run_privacy_activation_reaper(receiver))
            .map(|worker| PrivacyActivationReaper {
                sender,
                _worker: Mutex::new(Some(worker)),
            })
            .map_err(|error| format!("failed to create privacy activation reaper: {error}"))
    };

    static ref PRIVACY_OWNER_LIFECYCLE: PrivacyOwnerLifecycleCell =
        PrivacyOwnerLifecycleCell::default();

    // Disconnect-time retirement must survive cancellation of the connection future without
    // making Drop wait for the global privacy transaction or native display restoration. The
    // queue is deliberately bounded above the process's authenticated-session ceiling, and the
    // sole process-lifetime worker owns every accepted request through its exact result.
    #[cfg(any(windows, target_os = "macos"))]
    static ref PRIVACY_RETIREMENT_DISPATCHER:
        Result<PrivacyRetirementDispatcher, String> = {
        let (sender, receiver) =
            std_mpsc::sync_channel::<PrivacyRetirementRequest>(PRIVACY_RETIREMENT_QUEUE_CAPACITY);
        std::thread::Builder::new()
            .name("rustdesk-privacy-retirement".to_owned())
            .spawn(move || run_privacy_retirement_dispatcher(receiver))
            .map(|worker| PrivacyRetirementDispatcher {
                sender,
                _worker: Mutex::new(Some(worker)),
            })
            .map_err(|error| format!("failed to create privacy retirement worker: {error}"))
    };
}

fn run_privacy_activation_reaper(
    receiver: std_mpsc::Receiver<PrivacyActivationJoinRequest>,
) {
    while let Ok(request) = receiver.recv() {
        let PrivacyActivationJoinRequest {
            worker,
            completed,
            admission_permit,
            pending_owner,
        } = request;
        let result = match worker.join() {
            Ok(result) => result,
            Err(_) => Some(Err(anyhow!(
                "owned privacy activation worker panicked before reaper join"
            ))),
        };
        drop(pending_owner);
        drop(admission_permit);
        if completed.send(result).is_err() {
            log::debug!("Privacy activation drained after its connection owner retired");
        }
    }
}

impl PendingPrivacyActivation {
    fn new(owner: &PrivacyModeConnectionOwner) -> Self {
        let owner = PrivacyOwnerIdentity::from_owner(owner);
        PRIVACY_OWNER_LIFECYCLE
            .state
            .lock()
            .unwrap()
            .activating = Some(owner.clone());
        Self { owner }
    }
}

impl Drop for PendingPrivacyActivation {
    fn drop(&mut self) {
        let mut lifecycle = PRIVACY_OWNER_LIFECYCLE.state.lock().unwrap();
        if lifecycle
            .activating
            .as_ref()
            .map(|owner| owner.matches_parts(self.owner.conn_id, &self.owner.cm_auth_token))
            .unwrap_or(false)
        {
            lifecycle.activating = None;
            drop(lifecycle);
            PRIVACY_OWNER_LIFECYCLE.changed.notify_all();
        }
    }
}

fn publish_privacy_owner(owner: Option<&PrivacyModeConnectionOwner>) {
    PRIVACY_OWNER_LIFECYCLE
        .state
        .lock()
        .unwrap()
        .active = owner.map(PrivacyOwnerIdentity::from_owner);
}

#[cfg(any(windows, target_os = "macos"))]
fn has_privacy_retirement_owner(conn_id: i32, cm_auth_token: &str) -> bool {
    let lifecycle = PRIVACY_OWNER_LIFECYCLE.state.lock().unwrap();
    lifecycle
        .active
        .as_ref()
        .map(|owner| owner.matches_parts(conn_id, cm_auth_token))
        .unwrap_or(false)
        || lifecycle
            .activating
            .as_ref()
            .map(|owner| owner.matches_parts(conn_id, cm_auth_token))
            .unwrap_or(false)
}

pub(crate) fn wait_for_pending_privacy_activation() -> ResultType<()> {
    let mut lifecycle = PRIVACY_OWNER_LIFECYCLE
        .state
        .lock()
        .map_err(|_| anyhow!("privacy owner lifecycle lock was poisoned"))?;
    while lifecycle.activating.is_some() {
        lifecycle = PRIVACY_OWNER_LIFECYCLE
            .changed
            .wait(lifecycle)
            .map_err(|_| anyhow!("privacy owner lifecycle wait was poisoned"))?;
    }
    Ok(())
}

fn privacy_activation_reaper_sender() -> ResultType<std_mpsc::Sender<PrivacyActivationJoinRequest>> {
    match &*PRIVACY_ACTIVATION_REAPER {
        Ok(reaper) => Ok(reaper.sender.clone()),
        Err(error) => bail!(error.to_owned()),
    }
}

#[cfg(any(windows, target_os = "macos"))]
fn run_privacy_retirement_dispatcher(receiver: std_mpsc::Receiver<PrivacyRetirementRequest>) {
    run_privacy_retirement_requests(receiver, |request| {
        retire_privacy_for_owner(request.conn_id, &request.cm_auth_token)
    });
}

#[cfg(any(windows, target_os = "macos", test))]
fn run_privacy_retirement_requests<F>(
    receiver: std_mpsc::Receiver<PrivacyRetirementRequest>,
    mut retire: F,
) where
    F: FnMut(&PrivacyRetirementRequest) -> Option<ResultType<()>>,
{
    while let Ok(request) = receiver.recv() {
        if let Some(Err(error)) = retire(&request) {
            log::error!(
                "Failed to retire exact connection privacy owner {}: {error}",
                request.conn_id
            );
        }
    }
}

#[cfg(any(windows, target_os = "macos"))]
pub(crate) fn request_privacy_retirement_for_owner(
    conn_id: i32,
    cm_auth_token: &str,
) -> ResultType<()> {
    if conn_id <= 0 || cm_auth_token.is_empty() {
        bail!("privacy retirement requires an exact positive connection owner");
    }
    if !has_privacy_retirement_owner(conn_id, cm_auth_token) {
        return Ok(());
    }
    let dispatcher = match &*PRIVACY_RETIREMENT_DISPATCHER {
        Ok(dispatcher) => dispatcher,
        Err(error) => bail!(error.to_owned()),
    };
    let request = PrivacyRetirementRequest {
        conn_id,
        cm_auth_token: cm_auth_token.to_owned(),
    };
    match dispatcher.sender.try_send(request) {
        Ok(()) => Ok(()),
        Err(std_mpsc::TrySendError::Full(_)) => {
            bail!("privacy retirement queue reached its bounded capacity")
        }
        Err(std_mpsc::TrySendError::Disconnected(_)) => {
            bail!("privacy retirement worker stopped unexpectedly")
        }
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
pub(crate) fn request_privacy_retirement_for_owner(
    conn_id: i32,
    cm_auth_token: &str,
) -> ResultType<()> {
    if conn_id <= 0 || cm_auth_token.is_empty() {
        bail!("privacy retirement requires an exact positive connection owner");
    }
    Ok(())
}

pub struct PrivacyModeConnectionOwner {
    conn_id: i32,
    cm_auth_token: String,
    activation: Option<PrivacyActivationGate>,
    #[cfg(windows)]
    runtime: tokio::runtime::Handle,
}

impl PrivacyModeConnectionOwner {
    pub fn new(conn_id: i32, cm_auth_token: String) -> ResultType<Self> {
        if conn_id <= 0 {
            bail!("privacy mode requires a positive connection ID");
        }
        if cm_auth_token.is_empty() {
            bail!("privacy mode requires an exact connection authority token");
        }
        #[cfg(windows)]
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| anyhow!("privacy mode requires the owning Tokio runtime"))?;
        Ok(Self {
            conn_id,
            cm_auth_token,
            activation: None,
            #[cfg(windows)]
            runtime,
        })
    }

    pub fn conn_id(&self) -> i32 {
        self.conn_id
    }

    fn matches(&self, other: &Self) -> bool {
        self.matches_parts(other.conn_id, &other.cm_auth_token)
    }

    fn matches_parts(&self, conn_id: i32, cm_auth_token: &str) -> bool {
        self.conn_id == conn_id
            && !cm_auth_token.is_empty()
            && hbb_common::sodiumoxide::utils::memcmp(
                self.cm_auth_token.as_bytes(),
                cm_auth_token.as_bytes(),
            )
    }

    fn arm_activation(
        &mut self,
        cancelled: Arc<AtomicBool>,
        prepared: oneshot::Sender<()>,
        decision: std_mpsc::Receiver<PrivacyActivationDecision>,
    ) {
        self.activation = Some(PrivacyActivationGate {
            cancelled,
            endpoints: Mutex::new(Some((prepared, decision))),
        });
    }

    fn ensure_activation_current(&self) -> ResultType<()> {
        if self
            .activation
            .as_ref()
            .map(|activation| activation.cancelled.load(Ordering::Acquire))
            .unwrap_or(false)
        {
            bail!("privacy activation owner retired before native commit");
        }
        Ok(())
    }

    fn commit_activation(&mut self) -> ResultType<()> {
        let Some(activation) = self.activation.take() else {
            return Ok(());
        };
        if activation.cancelled.load(Ordering::Acquire) {
            bail!("privacy activation owner retired before prepare");
        }
        let PrivacyActivationGate {
            cancelled,
            endpoints,
        } = activation;
        let (prepared, decision) = endpoints
            .into_inner()
            .map_err(|_| anyhow!("privacy activation gate was poisoned before commit"))?
            .ok_or_else(|| anyhow!("privacy activation gate was already consumed"))?;
        prepared
            .send(())
            .map_err(|_| anyhow!("privacy activation owner retired before prepare"))?;
        match decision.recv() {
            Ok(PrivacyActivationDecision::Commit)
                if !cancelled.load(Ordering::Acquire) =>
            {
                Ok(())
            }
            Ok(PrivacyActivationDecision::Commit) => {
                bail!("privacy activation owner retired during commit")
            }
            Ok(PrivacyActivationDecision::Cancel) => {
                bail!("privacy activation was cancelled before commit")
            }
            Err(_) => bail!("privacy activation owner retired before commit"),
        }
    }

    #[cfg(windows)]
    fn cm_auth_token(&self) -> &str {
        &self.cm_auth_token
    }

    #[cfg(windows)]
    fn runtime(&self) -> &tokio::runtime::Handle {
        &self.runtime
    }
}

pub trait PrivacyMode: Sync + Send {
    fn clear(&mut self) -> ResultType<()>;
    fn turn_on_privacy(&mut self, owner: PrivacyModeConnectionOwner) -> ResultType<bool>;
    fn turn_off_privacy(&mut self, state: Option<PrivacyModeState>) -> ResultType<()>;

    fn connection_owner(&self) -> Option<&PrivacyModeConnectionOwner>;

    fn get_impl_key(&self) -> &str;

    #[inline]
    fn check_on_owner(&self, owner: &PrivacyModeConnectionOwner) -> ResultType<bool> {
        match self.connection_owner() {
            Some(current) if current.matches(owner) => Ok(true),
            Some(_) => bail!(OCCUPIED),
            None => Ok(false),
        }
    }
}

lazy_static::lazy_static! {
    pub static ref DEFAULT_PRIVACY_MODE_IMPL: String = {
        #[cfg(windows)]
        {
            if win_exclude_from_capture::is_supported() {
                PRIVACY_MODE_IMPL_WIN_EXCLUDE_FROM_CAPTURE
            } else {
                if display_service::is_privacy_mode_mag_supported() {
                    PRIVACY_MODE_IMPL_WIN_MAG
                } else {
                    if is_installed() {
                        PRIVACY_MODE_IMPL_WIN_VIRTUAL_DISPLAY
                    } else {
                        ""
                    }
                }
            }.to_owned()
        }
        #[cfg(not(windows))]
        {
            #[cfg(target_os = "macos")]
            {
                macos::PRIVACY_MODE_IMPL.to_owned()
            }
            #[cfg(not(target_os = "macos"))]
            {
                "".to_owned()
            }
        }
    };

    static ref PRIVACY_MODE: Arc<Mutex<Option<Box<dyn PrivacyMode>>>> = {
        let mut cur_impl = get_option("privacy-mode-impl-key".to_owned());
        if !get_supported_privacy_mode_impl().iter().any(|(k, _)| k == &cur_impl) {
            cur_impl = DEFAULT_PRIVACY_MODE_IMPL.to_owned();
        }

        let privacy_mode = match PRIVACY_MODE_CREATOR.lock().unwrap().get(&(&cur_impl as &str)) {
            Some(creator) => Some(creator(&cur_impl)),
            None => None,
        };
        Arc::new(Mutex::new(privacy_mode))
    };
}

pub type PrivacyModeCreator = fn(impl_key: &str) -> Box<dyn PrivacyMode>;
lazy_static::lazy_static! {
    static ref PRIVACY_MODE_CREATOR: Arc<Mutex<HashMap<&'static str, PrivacyModeCreator>>> = {
        #[cfg(not(windows))]
        let mut map: HashMap<&'static str, PrivacyModeCreator> = HashMap::new();
        #[cfg(target_os = "macos")]
        {
            map.insert(macos::PRIVACY_MODE_IMPL, |impl_key: &str| {
                Box::new(macos::PrivacyModeImpl::new(impl_key))
            });
        }
        #[cfg(windows)]
        let mut map: HashMap<&'static str, PrivacyModeCreator> = HashMap::new();
        #[cfg(windows)]
        {
            if win_exclude_from_capture::is_supported() {
                map.insert(win_exclude_from_capture::PRIVACY_MODE_IMPL, |impl_key: &str| {
                    Box::new(win_exclude_from_capture::PrivacyModeImpl::new(impl_key))
                });
            } else {
                map.insert(win_mag::PRIVACY_MODE_IMPL, |impl_key: &str| {
                    Box::new(win_mag::PrivacyModeImpl::new(impl_key))
                });
            }

            map.insert(win_virtual_display::PRIVACY_MODE_IMPL, |impl_key: &str| {
                    Box::new(win_virtual_display::PrivacyModeImpl::new(impl_key))
                });
        }
        Arc::new(Mutex::new(map))
    };
}

fn get_supported_impl(impl_key: &str) -> ResultType<String> {
    let supported_impls = get_supported_privacy_mode_impl();
    if !impl_key.is_empty() {
        if supported_impls.iter().any(|(key, _)| key == &impl_key) {
            return Ok(impl_key.to_owned());
        }
        bail!("Unsupported privacy mode: {impl_key}");
    }

    let configured = get_option("privacy-mode-impl-key".to_owned());
    if supported_impls.iter().any(|(key, _)| key == &configured) {
        return Ok(configured);
    }
    if supported_impls
        .iter()
        .any(|(key, _)| key == &DEFAULT_PRIVACY_MODE_IMPL.as_str())
    {
        return Ok(DEFAULT_PRIVACY_MODE_IMPL.to_owned());
    }
    bail!("No supported privacy mode implementation is available")
}

pub async fn turn_on_privacy(
    impl_key: &str,
    conn_id: i32,
    cm_auth_token: String,
) -> Option<ResultType<bool>> {
    let owner = match PrivacyModeConnectionOwner::new(conn_id, cm_auth_token) {
        Ok(owner) => owner,
        Err(error) => return Some(Err(error)),
    };
    let impl_key = impl_key.to_owned();
    run_privacy_activation(
        owner,
        PRIVACY_ACTIVATION_RESPONSE_DEADLINE,
        move |owner| turn_on_privacy_sync(&impl_key, owner),
    )
    .await
}

fn normalize_privacy_activation_result(
    result: Result<PrivacyActivationResult, oneshot::error::RecvError>,
) -> Option<ResultType<bool>> {
    match result {
        Ok(result) => result,
        Err(error) => Some(Err(anyhow!(
            "privacy activation reaper ended without an exact result: {error}"
        ))),
    }
}

async fn run_privacy_activation<F>(
    mut owner: PrivacyModeConnectionOwner,
    response_deadline: Duration,
    activate: F,
) -> Option<ResultType<bool>>
where
    F: FnOnce(PrivacyModeConnectionOwner) -> Option<ResultType<bool>> + Send + 'static,
{
    let deadline_at = tokio::time::Instant::now() + response_deadline;
    let admission = PRIVACY_ACTIVATION_ADMISSION.clone();
    let admission_permit = tokio::select! {
        biased;
        _ = tokio::time::sleep_until(deadline_at) => {
            return Some(Err(anyhow!(
                "privacy activation exceeded its {} ms response deadline before admission",
                response_deadline.as_millis(),
            )))
        },
        permit = admission.acquire_owned() => match permit {
            Ok(permit) => permit,
            Err(error) => {
                return Some(Err(anyhow!(
                    "privacy activation admission closed unexpectedly: {error}"
                )))
            }
        }
    };
    let reaper = match privacy_activation_reaper_sender() {
        Ok(reaper) => reaper,
        Err(error) => return Some(Err(error)),
    };
    let (prepared, mut preparation) = oneshot::channel();
    let (decision, activation_decision) = std_mpsc::channel();
    let activation_controller = PrivacyActivationController::new();
    owner.arm_activation(
        activation_controller.cancellation_flag(),
        prepared,
        activation_decision,
    );
    let pending_owner = PendingPrivacyActivation::new(&owner);

    // Display enumeration, driver readiness, and native display mutation are blocking operations.
    // One admission permit prevents an unbounded queue of threads behind the global privacy state.
    // The fixed reaper takes the exact JoinHandle before the start gate releases the worker. The
    // prepare/commit rendezvous then prevents publication after the connection-side future has
    // timed out or been dropped. Only after the native body returns and the exact thread has been
    // joined does the reaper publish its result and release the next activation permit.
    let conn_id = owner.conn_id();
    let (completed, mut completion) = oneshot::channel();
    let (start_worker, await_start) = std_mpsc::sync_channel(1);
    let worker = match std::thread::Builder::new()
        .name(format!("rustdesk-privacy-activation-{conn_id}"))
        .spawn(move || match await_start.recv() {
            Ok(()) => activate(owner),
            Err(error) => Some(Err(anyhow!(
                "privacy activation worker was not admitted to start: {error}"
            ))),
        })
    {
        Ok(worker) => worker,
        Err(error) => {
            return Some(Err(anyhow!(
                "failed to create owned privacy activation worker: {error}"
            )))
        }
    };
    if let Err(error) = reaper.send(PrivacyActivationJoinRequest {
        worker,
        completed,
        admission_permit,
        pending_owner,
    }) {
        let PrivacyActivationJoinRequest {
            worker,
            completed,
            admission_permit,
            pending_owner,
        } = error.0;
        drop(start_worker);
        let join_result = worker.join();
        drop(pending_owner);
        drop(admission_permit);
        drop(completed);
        let join_detail = if join_result.is_err() {
            "; unstarted worker also panicked while being joined"
        } else {
            ""
        };
        return Some(Err(anyhow!(
            "privacy activation reaper stopped before worker handoff{join_detail}"
        )));
    }
    if start_worker.try_send(()).is_err() {
        return normalize_privacy_activation_result(completion.await);
    }
    let deadline = tokio::time::sleep_until(deadline_at);
    tokio::pin!(deadline);

    tokio::select! {
        biased;
        _ = &mut deadline => {
            activation_controller.cancel();
            let decision_error = decision
                .send(PrivacyActivationDecision::Cancel)
                .err()
                .map(|_| "privacy activation cancellation receiver had already closed");
            // A deadline classifies the request but never detaches its physical mutation. The
            // worker must reach its commit gate, observe cancellation, roll back, and drain first.
            let drained = normalize_privacy_activation_result(completion.await);
            let drain_detail = match drained {
                Some(Ok(_)) => {
                    "owned operation completed without a new cancellable commit".to_owned()
                }
                Some(Err(error)) => format!("owned operation drained with: {error}"),
                None => {
                    "privacy implementation was unavailable when the owned operation drained"
                        .to_owned()
                }
            };
            let decision_detail = decision_error
                .map(|error| format!("; {error}"))
                .unwrap_or_default();
            Some(Err(anyhow!(
                "privacy activation exceeded its {} ms response deadline; {}{}",
                response_deadline.as_millis(),
                drain_detail,
                decision_detail,
            )))
        }
        result = &mut completion => normalize_privacy_activation_result(result),
        prepared = &mut preparation => {
            if prepared.is_ok() {
                let _ = decision.send(PrivacyActivationDecision::Commit);
            }
            normalize_privacy_activation_result(completion.await)
        }
    }
}

fn turn_on_privacy_sync(
    impl_key: &str,
    owner: PrivacyModeConnectionOwner,
) -> Option<ResultType<bool>> {
    let result = turn_on_privacy_sync_inner(impl_key, owner);
    let privacy_mode = PRIVACY_MODE.lock().unwrap();
    publish_privacy_owner(
        privacy_mode
            .as_ref()
            .and_then(|privacy_mode| privacy_mode.connection_owner()),
    );
    result
}

fn turn_on_privacy_sync_inner(
    impl_key: &str,
    owner: PrivacyModeConnectionOwner,
) -> Option<ResultType<bool>> {
    // Check if privacy mode is already on or occupied by another one
    let mut privacy_mode_lock = PRIVACY_MODE.lock().unwrap();

    // Check or switch privacy mode implementation
    let impl_key = match get_supported_impl(impl_key) {
        Ok(impl_key) => impl_key,
        Err(error) => return Some(Err(error)),
    };

    let mut cur_impl_key = "".to_string();
    if let Some(privacy_mode) = privacy_mode_lock.as_ref() {
        cur_impl_key = privacy_mode.get_impl_key().to_string();
        let check_on_owner = privacy_mode.check_on_owner(&owner);
        match check_on_owner.as_ref() {
            Ok(true) => {
                if cur_impl_key == impl_key {
                    // Same peer, same implementation.
                    return Some(Ok(true));
                } else {
                    // Same peer, switch to new implementation.
                }
            }
            Err(_) => return Some(check_on_owner),
            _ => {}
        }
    }

    if cur_impl_key != impl_key {
        if let Some(creator) = PRIVACY_MODE_CREATOR
            .lock()
            .unwrap()
            .get(&(&impl_key as &str))
        {
            if let Some(privacy_mode) = privacy_mode_lock.as_mut() {
                if let Err(error) = privacy_mode.clear() {
                    return Some(Err(anyhow!(
                        "failed to retire the previous privacy implementation: {error}"
                    )));
                }
            }

            *privacy_mode_lock = Some(creator(&impl_key));
        } else {
            return Some(Err(anyhow!("Unsupported privacy mode: {}", impl_key)));
        }
    }

    // turn on privacy mode
    Some(privacy_mode_lock.as_mut()?.turn_on_privacy(owner))
}

pub(crate) fn turn_off_privacy_for_owner(
    conn_id: i32,
    cm_auth_token: &str,
    state: Option<PrivacyModeState>,
) -> Option<ResultType<()>> {
    if conn_id <= 0 || cm_auth_token.is_empty() {
        return Some(Err(anyhow!(
            "privacy teardown requires an exact positive connection owner"
        )));
    }
    let mut privacy_mode = PRIVACY_MODE.lock().unwrap();
    let privacy_mode = privacy_mode.as_mut()?;
    let Some(owner) = privacy_mode.connection_owner() else {
        publish_privacy_owner(None);
        return Some(Ok(()));
    };
    if !owner.matches_parts(conn_id, cm_auth_token) {
        return Some(Err(anyhow!(TURN_OFF_OTHER_OWNER)));
    }
    let result = privacy_mode.turn_off_privacy(state);
    publish_privacy_owner(privacy_mode.connection_owner());
    Some(result)
}

pub(crate) fn retire_privacy_for_owner(
    conn_id: i32,
    cm_auth_token: &str,
) -> Option<ResultType<()>> {
    if conn_id <= 0 || cm_auth_token.is_empty() {
        return Some(Err(anyhow!(
            "privacy retirement requires an exact positive connection owner"
        )));
    }
    let mut privacy_mode = PRIVACY_MODE.lock().unwrap();
    let privacy_mode = privacy_mode.as_mut()?;
    let Some(owner) = privacy_mode.connection_owner() else {
        publish_privacy_owner(None);
        return Some(Ok(()));
    };
    if !owner.matches_parts(conn_id, cm_auth_token) {
        return Some(Ok(()));
    }
    let result = privacy_mode.turn_off_privacy(None);
    publish_privacy_owner(privacy_mode.connection_owner());
    Some(result)
}

/// Machine-local emergency teardown only: the final-Remote virtual-display reset cannot carry a
/// network connection token. The Ctrl+P escape and every network/connection path use
/// `turn_off_privacy_for_owner` and may never acquire this force-off authority.
pub(crate) fn force_turn_off_privacy(
    state: Option<PrivacyModeState>,
) -> Option<ResultType<()>> {
    let mut privacy_mode = PRIVACY_MODE.lock().unwrap();
    let privacy_mode = privacy_mode.as_mut()?;
    let result = privacy_mode.turn_off_privacy(state);
    publish_privacy_owner(privacy_mode.connection_owner());
    Some(result)
}

#[cfg(windows)]
fn set_privacy_mode_state(
    owner: &PrivacyModeConnectionOwner,
    state: PrivacyModeState,
    impl_key: String,
    ms_timeout: u64,
) -> ResultType<()> {
    // The only state-bearing caller is the bounded privacy escape dispatcher.
    // Reuse the owning server runtime instead of nesting one here.
    if tokio::runtime::Handle::try_current().is_ok() {
        bail!("privacy callback must run outside a Tokio runtime thread");
    }
    let conn_id = owner.conn_id();
    let cm_auth_token = owner.cm_auth_token().to_owned();
    owner.runtime().block_on(async move {
        tokio::time::timeout(std::time::Duration::from_millis(ms_timeout), async move {
            let mut c = crate::server::connect_authenticated_cm(ms_timeout, "--cm").await?;
            c.send(&Data::AuthorizedPrivacyModeState {
                id: conn_id,
                cm_auth_token,
                state,
                impl_key,
            })
            .await
        })
        .await
        .map_err(|_| anyhow!("privacy callback exceeded its bounded deadline"))?
    })
}

pub fn get_supported_privacy_mode_impl() -> Vec<(&'static str, &'static str)> {
    #[cfg(target_os = "windows")]
    {
        let mut vec_impls = Vec::new();

        if win_exclude_from_capture::is_supported() {
            vec_impls.push((
                PRIVACY_MODE_IMPL_WIN_EXCLUDE_FROM_CAPTURE,
                "privacy_mode_impl_mag_tip",
            ));
        } else {
            if display_service::is_privacy_mode_mag_supported() {
                vec_impls.push((PRIVACY_MODE_IMPL_WIN_MAG, "privacy_mode_impl_mag_tip"));
            }
        }

        if is_installed() && crate::platform::windows::is_self_service_running() {
            vec_impls.push((
                PRIVACY_MODE_IMPL_WIN_VIRTUAL_DISPLAY,
                "privacy_mode_impl_virtual_display_tip",
            ));
        }

        vec_impls
    }
    #[cfg(target_os = "macos")]
    {
        // No translation is intended for privacy_mode_impl_macos_tip as it is a
        // placeholder for macOS specific privacy mode implementation which currently
        // doesn't provide multiple modes like Windows does.
        vec![(macos::PRIVACY_MODE_IMPL, "privacy_mode_impl_macos_tip")]
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        Vec::new()
    }
}

#[inline]
pub fn get_cur_impl_key() -> Option<String> {
    PRIVACY_MODE
        .lock()
        .unwrap()
        .as_ref()
        .map(|pm| pm.get_impl_key().to_owned())
}

#[inline]
pub fn is_current_privacy_mode_impl(impl_key: &str) -> bool {
    PRIVACY_MODE
        .lock()
        .unwrap()
        .as_ref()
        .map(|pm| pm.get_impl_key() == impl_key)
        .unwrap_or(false)
}

#[inline]
#[cfg(not(windows))]
pub fn check_privacy_mode_err(
    _privacy_mode_id: i32,
    _display_idx: usize,
    _timeout_millis: u64,
) -> String {
    "".to_owned()
}

#[inline]
#[cfg(windows)]
pub fn check_privacy_mode_err(
    privacy_mode_id: i32,
    display_idx: usize,
    timeout_millis: u64,
) -> String {
    // win magnifier implementation requires a test of creating a capturer.
    if is_current_privacy_mode_impl(PRIVACY_MODE_IMPL_WIN_MAG) {
        crate::video_service::test_create_capturer(privacy_mode_id, display_idx, timeout_millis)
    } else {
        "".to_owned()
    }
}

#[inline]
pub fn is_privacy_mode_supported() -> bool {
    !DEFAULT_PRIVACY_MODE_IMPL.is_empty()
}

#[inline]
pub fn get_privacy_mode_conn_id() -> Option<i32> {
    PRIVACY_MODE
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|pm| pm.connection_owner())
        .map(PrivacyModeConnectionOwner::conn_id)
}

#[inline]
pub fn is_in_privacy_mode() -> bool {
    PRIVACY_MODE
        .lock()
        .unwrap()
        .as_ref()
        .map(|pm| pm.connection_owner().is_some())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{
        run_privacy_activation, run_privacy_retirement_requests, PrivacyModeConnectionOwner,
        PrivacyRetirementRequest,
    };
    use hbb_common::tokio;
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc as std_mpsc, Arc,
        },
        time::Duration,
    };

    #[tokio::test(flavor = "current_thread")]
    async fn r_s11iu_privacy_resource_owner_distinguishes_same_id_token_replacement() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PrivacyModeConnectionOwner>();

        let incumbent = PrivacyModeConnectionOwner::new(71, "incumbent-token".to_owned()).unwrap();
        let same = PrivacyModeConnectionOwner::new(71, "incumbent-token".to_owned()).unwrap();
        let replacement =
            PrivacyModeConnectionOwner::new(71, "replacement-token".to_owned()).unwrap();

        assert!(incumbent.matches(&same));
        assert!(!incumbent.matches(&replacement));
        assert!(PrivacyModeConnectionOwner::new(0, "token".to_owned()).is_err());
        assert!(PrivacyModeConnectionOwner::new(71, String::new()).is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn r_s11iu_privacy_activation_commits_only_after_prepare() {
        let owner = PrivacyModeConnectionOwner::new(72, "owner-token".to_owned()).unwrap();
        let result = run_privacy_activation(owner, Duration::from_secs(1), |mut owner| {
            Some(owner.commit_activation().map(|()| true))
        })
        .await;

        assert!(matches!(result, Some(Ok(true))));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn r_s11iu_privacy_activation_deadline_cancels_and_drains_before_return() {
        let owner = PrivacyModeConnectionOwner::new(73, "owner-token".to_owned()).unwrap();
        let (entered, entered_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std_mpsc::sync_channel(1);
        let rolled_back = Arc::new(AtomicBool::new(false));
        let worker_rolled_back = Arc::clone(&rolled_back);
        let activation = tokio::spawn(run_privacy_activation(
            owner,
            Duration::from_millis(10),
            move |mut owner| {
                let _ = entered.send(());
                let _ = release_rx.recv();
                let result = owner.commit_activation().map(|()| true);
                if result.is_err() {
                    worker_rolled_back.store(true, Ordering::Release);
                }
                Some(result)
            },
        ));

        entered_rx.await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !activation.is_finished(),
            "the response deadline must not detach an undrained activation"
        );
        release.try_send(()).unwrap();
        let result = activation.await.unwrap();
        let error = result.unwrap().unwrap_err().to_string();
        assert!(error.contains("exceeded its 10 ms response deadline"));
        assert!(error.contains("owner retired before prepare"));
        assert!(rolled_back.load(Ordering::Acquire));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn r_s11iu_privacy_activation_future_drop_refuses_late_commit() {
        let owner = PrivacyModeConnectionOwner::new(74, "owner-token".to_owned()).unwrap();
        let (entered, entered_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std_mpsc::sync_channel(1);
        let (completed, completed_rx) = tokio::sync::oneshot::channel();
        let activation = tokio::spawn(run_privacy_activation(
            owner,
            Duration::from_secs(1),
            move |mut owner| {
                let _ = entered.send(());
                let _ = release_rx.recv();
                let result = owner
                    .ensure_activation_current()
                    .and_then(|()| owner.commit_activation())
                    .map(|()| true);
                let _ = completed.send(result.is_err());
                Some(result)
            },
        ));

        entered_rx.await.unwrap();
        activation.abort();
        assert!(activation.await.unwrap_err().is_cancelled());
        release.try_send(()).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), completed_rx)
                .await
                .expect("owned blocking task must drain after controller drop")
                .expect("owned blocking task must report completion")
        );
    }

    #[test]
    fn r_s11iu_r_s19a_privacy_retirement_dispatcher_owns_work_off_caller_thread() {
        let (sender, receiver) = std_mpsc::sync_channel(2);
        let (entered, entered_rx) = std_mpsc::channel();
        let (release, release_rx) = std_mpsc::sync_channel(1);
        let retired = Arc::new(std::sync::Mutex::new(Vec::new()));
        let worker_retired = Arc::clone(&retired);
        let worker = std::thread::spawn(move || {
            let mut first = true;
            run_privacy_retirement_requests(receiver, move |request| {
                if first {
                    first = false;
                    entered.send(()).unwrap();
                    release_rx.recv().unwrap();
                }
                worker_retired.lock().unwrap().push(request.conn_id);
                Some(Ok(()))
            });
        });

        sender
            .try_send(PrivacyRetirementRequest {
                conn_id: 81,
                cm_auth_token: "first-owner-token".to_owned(),
            })
            .unwrap();
        entered_rx.recv().unwrap();

        // The worker is deliberately stalled inside physical teardown. Submission of a later
        // exact owner remains a bounded nonblocking handoff and does not wait for that teardown.
        sender
            .try_send(PrivacyRetirementRequest {
                conn_id: 82,
                cm_auth_token: "second-owner-token".to_owned(),
            })
            .unwrap();
        assert!(retired.lock().unwrap().is_empty());

        release.try_send(()).unwrap();
        drop(sender);
        worker.join().unwrap();
        assert_eq!(*retired.lock().unwrap(), vec![81, 82]);
    }
}
