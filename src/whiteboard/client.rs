use super::Cursor;
use crate::ipc::{self, WhiteboardIpcCommand};
use hbb_common::{
    anyhow::anyhow,
    bail,
    futures::FutureExt,
    log, sleep,
    tokio::{
        self,
        sync::{
            mpsc::{channel, error::TrySendError, Sender},
            Notify,
        },
        time::{interval_at, Interval},
    },
    tokio_util::sync::CancellationToken,
    ResultType,
};
use lazy_static::lazy_static;
use std::{
    collections::HashMap,
    future::{poll_fn, Future},
    panic::AssertUnwindSafe,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

lazy_static! {
    static ref WHITEBOARD_CLIENT: Mutex<WhiteboardClientState> =
        Mutex::new(WhiteboardClientState::default());
    static ref WHITEBOARD_OWNER_WAKE: Notify = Notify::new();
}

#[cfg(all(target_os = "linux", feature = "linux-whiteboard-lifecycle-probe"))]
pub(crate) fn probe_whiteboard_client_state() -> (&'static str, u64, bool, usize) {
    let state = WHITEBOARD_CLIENT.lock().unwrap();
    let (phase, generation) = match state.lifecycle.phase {
        WhiteboardWorkerPhase::Idle => ("Idle", 0),
        WhiteboardWorkerPhase::Starting { generation } => ("Starting", generation),
        WhiteboardWorkerPhase::Running { generation } => ("Running", generation),
        WhiteboardWorkerPhase::Stopping { generation, .. } => ("Stopping", generation),
    };
    (phase, generation, state.generation.as_ref().is_some_and(|owner| owner.worker.is_some()), state.conns.len())
}

#[cfg(all(target_os = "linux", feature = "linux-whiteboard-lifecycle-probe"))]
pub(crate) fn probe_whiteboard_helper() -> (Option<u32>, bool) {
    let state = WHITEBOARD_CLIENT.lock().unwrap();
    match state.generation.as_ref() {
        Some(owner) => (owner.helper.as_ref().and_then(|helper| helper.id().ok()), owner.worker_joined),
        None => (None, false),
    }
}

#[cfg(all(target_os = "linux", feature = "linux-whiteboard-lifecycle-probe"))]
pub(crate) fn probe_whiteboard_helper_exit() -> Option<(u64, bool)> {
    WHITEBOARD_CLIENT.lock().unwrap().last_reaped_helper
}

#[cfg(all(target_os = "linux", feature = "linux-whiteboard-lifecycle-probe"))]
pub(crate) fn probe_whiteboard_owner_loss() -> (bool, bool, bool) {
    let state = WHITEBOARD_CLIENT.lock().unwrap();
    let (finished, joined) = match state.generation.as_ref() {
        Some(owner) => (owner.worker.as_ref().map_or(true, |task| task.is_finished()), owner.worker_joined),
        None => (true, state.lifecycle.phase == WhiteboardWorkerPhase::Idle),
    };
    (finished, joined, state.owner != WhiteboardOwnerAdmission::Serving
        && !state.conns.contains_key(&9) && !state.conns.contains_key(&10))
}

#[cfg(all(target_os = "linux", feature = "linux-whiteboard-lifecycle-probe"))]
pub(crate) fn probe_whiteboard_helper_endpoint() -> ResultType<String> {
    let state = WHITEBOARD_CLIENT.lock().unwrap();
    let owner = state.generation.as_ref().ok_or_else(|| anyhow!("whiteboard probe has no generation"))?;
    ipc::linux_whiteboard_endpoint_address(&owner.postfix)
}

#[cfg(all(target_os = "linux", feature = "linux-whiteboard-lifecycle-probe"))]
lazy_static! {
    static ref WHITEBOARD_LAUNCH_GATE: (Mutex<(Option<u32>, bool)>, std::sync::Condvar) =
        (Mutex::new((None, false)), std::sync::Condvar::new());
}

#[cfg(all(target_os = "linux", feature = "linux-whiteboard-lifecycle-probe"))]
pub(crate) fn probe_whiteboard_launch_state() -> (Option<u32>, bool) {
    let pid = WHITEBOARD_LAUNCH_GATE.0.lock().unwrap().0;
    let state = WHITEBOARD_CLIENT.lock().unwrap();
    (pid, state.generation.as_ref().and_then(|owner| owner.launch.as_ref())
        .is_some_and(|launch| launch.is_finished()))
}

#[cfg(all(target_os = "linux", feature = "linux-whiteboard-lifecycle-probe"))]
pub(crate) fn probe_release_whiteboard_launch() {
    WHITEBOARD_LAUNCH_GATE.0.lock().unwrap().1 = true;
    WHITEBOARD_LAUNCH_GATE.1.notify_one();
}

#[cfg(all(target_os = "linux", feature = "linux-whiteboard-lifecycle-probe"))]
fn probe_hold_whiteboard_launch(pid: u32) {
    if std::env::var("WHITEBOARD_PROBE_CLIENT_GENERATION").as_deref() != Ok("launch-owner-loss") {
        return;
    }
    let mut gate = WHITEBOARD_LAUNCH_GATE.0.lock().unwrap();
    gate.0 = Some(pid);
    while !gate.1 { gate = WHITEBOARD_LAUNCH_GATE.1.wait(gate).unwrap(); }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WhiteboardWorkerPhase {
    Idle,
    Starting {
        generation: u64,
    },
    Running {
        generation: u64,
    },
    Stopping {
        generation: u64,
        restart_requested: bool,
    },
}

impl Default for WhiteboardWorkerPhase {
    fn default() -> Self {
        Self::Idle
    }
}

#[derive(Default)]
struct WhiteboardWorkerLifecycle {
    phase: WhiteboardWorkerPhase,
    last_generation: u64,
}

impl WhiteboardWorkerLifecycle {
    fn reserve_next_generation(&mut self) -> ResultType<u64> {
        let generation = self
            .last_generation
            .checked_add(1)
            .ok_or_else(|| anyhow!("whiteboard worker generation exhausted"))?;
        self.last_generation = generation;
        self.phase = WhiteboardWorkerPhase::Starting { generation };
        Ok(generation)
    }

    fn request_worker(&mut self) -> ResultType<Option<u64>> {
        match self.phase {
            WhiteboardWorkerPhase::Idle => self.reserve_next_generation().map(Some),
            WhiteboardWorkerPhase::Starting { .. }
            | WhiteboardWorkerPhase::Running { .. } => Ok(None),
            WhiteboardWorkerPhase::Stopping {
                generation,
                ..
            } => {
                self.phase = WhiteboardWorkerPhase::Stopping {
                    generation,
                    restart_requested: true,
                };
                Ok(None)
            }
        }
    }

    fn publish(&mut self, generation: u64) -> bool {
        if self.phase != (WhiteboardWorkerPhase::Starting { generation }) {
            return false;
        }
        self.phase = WhiteboardWorkerPhase::Running { generation };
        true
    }

    fn running_generation(&self) -> Option<u64> {
        match self.phase {
            WhiteboardWorkerPhase::Running { generation } => Some(generation),
            _ => None,
        }
    }

    fn begin_stop(&mut self, generation: u64) -> bool {
        if self.phase != (WhiteboardWorkerPhase::Running { generation }) {
            return false;
        }
        self.phase = WhiteboardWorkerPhase::Stopping {
            generation,
            restart_requested: false,
        };
        true
    }

    fn sender_failed(&mut self, generation: u64) {
        match self.phase {
            WhiteboardWorkerPhase::Running {
                generation: current,
            } if current == generation => {
                self.phase = WhiteboardWorkerPhase::Stopping {
                    generation,
                    restart_requested: false,
                };
            }
            _ => {}
        }
    }

    fn retire_generation(&mut self, generation: u64) {
        match self.phase {
            WhiteboardWorkerPhase::Starting { generation: current }
            | WhiteboardWorkerPhase::Running { generation: current } if current == generation => {
                self.phase = WhiteboardWorkerPhase::Stopping { generation, restart_requested: false };
            }
            _ => {}
        }
    }

    fn cancel_reserved_generation(&mut self, generation: u64) {
        if self.phase == (WhiteboardWorkerPhase::Starting { generation }) {
            self.phase = WhiteboardWorkerPhase::Idle;
        }
    }

    fn finish(
        &mut self,
        generation: u64,
        has_demand: bool,
    ) -> ResultType<Option<u64>> {
        let restart = match self.phase {
            WhiteboardWorkerPhase::Starting {
                generation: current,
            }
            | WhiteboardWorkerPhase::Running {
                generation: current,
            } if current == generation => false,
            WhiteboardWorkerPhase::Stopping {
                generation: current,
                restart_requested,
            } if current == generation => restart_requested && has_demand,
            _ => return Ok(None),
        };
        self.phase = WhiteboardWorkerPhase::Idle;
        if restart {
            self.reserve_next_generation().map(Some)
        } else {
            Ok(None)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WhiteboardCommandAdmission {
    Accepted,
    NoWorker,
    CursorDropped,
    WorkerRetiredAfterSaturation,
    WorkerRetiredAfterClosure,
}

struct WhiteboardClientState {
    lifecycle: WhiteboardWorkerLifecycle,
    sender: Option<(u64, Sender<WhiteboardIpcCommand>)>,
    owner: WhiteboardOwnerAdmission,
    retirement: Option<Arc<CancellationToken>>,
    generation: Option<WhiteboardGeneration>,
    #[cfg(all(target_os = "linux", feature = "linux-whiteboard-lifecycle-probe"))]
    last_reaped_helper: Option<(u64, bool)>,
    conns: HashMap<i32, Conn>,
}

impl Default for WhiteboardClientState {
    fn default() -> Self {
        Self {
            lifecycle: WhiteboardWorkerLifecycle::default(),
            sender: None,
            owner: WhiteboardOwnerAdmission::Absent,
            retirement: None,
            generation: None,
            #[cfg(all(target_os = "linux", feature = "linux-whiteboard-lifecycle-probe"))]
            last_reaped_helper: None,
            conns: HashMap::new(),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum WhiteboardOwnerAdmission {
    Absent,
    Serving,
    Draining,
    Orphaned,
}

struct WhiteboardGeneration {
    generation: u64,
    launch_token: String,
    postfix: String,
    launch: Option<tokio::task::JoinHandle<ResultType<WhiteboardLaunch>>>,
    helper: Option<WhiteboardHelperProcess>,
    worker: Option<tokio::task::JoinHandle<()>>,
    worker_joined: bool,
    cancellation: CancellationToken,
    launch_not_before: tokio::time::Instant,
    retirement_deadline: Option<tokio::time::Instant>,
    launch_uncertain: bool,
    retirement_error_logged: bool,
}

enum WhiteboardLaunch {
    WaitingForUser,
    Spawned,
    Retired,
}

#[cfg(target_os = "windows")]
type WhiteboardHelperProcess = crate::platform::WindowsWhiteboardProcess;

#[cfg(not(target_os = "windows"))]
struct WhiteboardHelperProcess {
    child: std::process::Child,
    exit_success: Option<bool>,
}

#[cfg(not(target_os = "windows"))]
impl WhiteboardHelperProcess {
    fn id(&self) -> ResultType<u32> {
        Ok(self.child.id())
    }
    fn try_reap_exited(&mut self) -> ResultType<bool> {
        match self.child.try_wait()? {
            Some(status) => {
                self.exit_success = Some(status.success());
                if !status.success() {
                    log::error!("whiteboard helper {} exited with {status}", self.child.id());
                }
                Ok(true)
            }
            None => Ok(false),
        }
    }
    fn terminate(&mut self) -> ResultType<()> {
        Ok(self.child.kill()?)
    }
}

/// Retained and polled by the desktop IPC worker through exact generation retirement.
pub(crate) struct WhiteboardClientRoot {
    timer: Interval,
    retirement: Arc<CancellationToken>,
}

/// The controlled server's admission lease; losing it does not lose the resource owner.
pub(crate) struct WhiteboardClientController {
    retirement: Arc<CancellationToken>,
}

impl WhiteboardClientRoot {
    pub(crate) fn new() -> ResultType<(Self, WhiteboardClientController)> {
        tokio::runtime::Handle::try_current()?;
        let mut state = WHITEBOARD_CLIENT.lock().unwrap();
        if state.owner != WhiteboardOwnerAdmission::Absent || state.retirement.is_some() || state.generation.is_some()
            || state.lifecycle.phase != WhiteboardWorkerPhase::Idle {
            bail!("whiteboard client already has an owner or unreconciled generation");
        }
        let retirement = Arc::new(CancellationToken::new());
        state.retirement = Some(retirement.clone());
        state.owner = WhiteboardOwnerAdmission::Serving;
        let mut timer = tokio::time::interval(Duration::from_millis(100));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let controller = WhiteboardClientController { retirement: retirement.clone() };
        Ok((Self { timer, retirement }, controller))
    }

    async fn observe(&mut self) -> bool {
        poll_fn(|cx| {
            let mut state = WHITEBOARD_CLIENT.lock().unwrap();
            poll_whiteboard_generation(&mut state, cx);
            if state.generation.is_none() && state.owner != WhiteboardOwnerAdmission::Serving {
                self.retirement.cancel();
            }
            Poll::Ready(state.generation.is_some())
        }).await
    }

    pub(crate) async fn run(&mut self) {
        loop {
            let active = self.observe().await;
            tokio::select! {
                _ = WHITEBOARD_OWNER_WAKE.notified() => {},
                _ = self.timer.tick(), if active => {},
            }
        }
    }

    pub(crate) async fn stop_and_join(&mut self) {
        {
            let mut state = WHITEBOARD_CLIENT.lock().unwrap();
            close_whiteboard_admission(&mut state, WhiteboardOwnerAdmission::Draining);
        }
        while self.observe().await { self.timer.tick().await; }
    }
}

fn close_whiteboard_admission(state: &mut WhiteboardClientState, admission: WhiteboardOwnerAdmission) {
    state.owner = admission;
    state.sender.take();
    state.conns.clear();
    if let Some(owner) = state.generation.as_ref() {
        let generation = owner.generation;
        owner.cancellation.cancel();
        state.lifecycle.retire_generation(generation);
    }
    WHITEBOARD_OWNER_WAKE.notify_one();
}

impl WhiteboardClientController {
    pub(crate) fn begin_shutdown(&mut self) {
        let mut state = WHITEBOARD_CLIENT.lock().unwrap();
        if state.retirement.as_ref().is_some_and(|retirement| Arc::ptr_eq(retirement, &self.retirement)) {
            close_whiteboard_admission(&mut state, WhiteboardOwnerAdmission::Draining);
        }
    }

    pub(crate) async fn stop_and_join(&mut self) {
        self.begin_shutdown();
        self.retirement.cancelled().await;
    }
}

impl Drop for WhiteboardClientController {
    fn drop(&mut self) {
        let mut state = WHITEBOARD_CLIENT.lock().unwrap();
        if state.owner == WhiteboardOwnerAdmission::Serving
            && state.retirement.as_ref().is_some_and(|retirement| Arc::ptr_eq(retirement, &self.retirement)) {
            close_whiteboard_admission(&mut state, WhiteboardOwnerAdmission::Orphaned);
            log::error!("whiteboard controller was lost; the desktop IPC owner will retire its generation");
        }
    }
}

impl Drop for WhiteboardClientRoot {
    fn drop(&mut self) {
        let mut state = WHITEBOARD_CLIENT.lock().unwrap();
        if state.generation.is_none() {
            state.owner = WhiteboardOwnerAdmission::Absent;
            state.retirement.take();
            self.retirement.cancel();
            return;
        }
        close_whiteboard_admission(&mut state, WhiteboardOwnerAdmission::Orphaned);
        if let Some(owner) = state.generation.as_mut() {
            if let Some(helper) = owner.helper.as_mut() {
                match helper.try_reap_exited() {
                    Ok(false) => if let Err(err) = helper.terminate() {
                        log::error!("whiteboard owner cancellation could not terminate its helper: {err}");
                    },
                    Ok(true) => {},
                    Err(err) => log::error!("whiteboard owner cancellation could not observe its helper: {err}"),
                }
            }
        }
        // Retain all handles in the locked owner; uncertainty can never admit a replacement.
        log::error!("whiteboard root was dropped without joining its generation; replacement is refused");
    }
}

fn poll_whiteboard_generation(state: &mut WhiteboardClientState, cx: &mut Context<'_>) {
    let has_demand = !state.conns.is_empty();
    let Some(owner) = state.generation.as_mut() else { return; };
    let generation = owner.generation;
    let now = tokio::time::Instant::now();
    if !has_demand && state.lifecycle.phase == (WhiteboardWorkerPhase::Starting { generation }) {
        state.lifecycle.retire_generation(generation);
        owner.cancellation.cancel();
    }
    if let Some(launch) = owner.launch.as_mut() {
        if let Poll::Ready(result) = Pin::new(launch).poll(cx) {
            owner.launch.take();
            match result {
                Ok(Ok(WhiteboardLaunch::Spawned)) => {},
                Ok(Ok(WhiteboardLaunch::Retired)) => state.lifecycle.retire_generation(generation),
                Ok(Ok(WhiteboardLaunch::WaitingForUser)) => owner.launch_not_before = now + Duration::from_secs(1),
                Ok(Err(err)) => {
                    state.lifecycle.retire_generation(generation);
                    log::error!("whiteboard generation {generation} launch failed: {err}");
                }
                Err(err) => {
                    // A panicked creation operation cannot prove that it created no process.
                    owner.launch_uncertain = err.is_panic();
                    state.lifecycle.retire_generation(generation);
                    log::error!("whiteboard generation {generation} launch task failed: {err}; uncertain={}", owner.launch_uncertain);
                }
            }
        }
    }
    let mut helper_known_live = false;
    if let Some(helper) = owner.helper.as_mut() {
        match helper.try_reap_exited() {
            Ok(true) => {
                #[cfg(all(target_os = "linux", feature = "linux-whiteboard-lifecycle-probe"))]
                { state.last_reaped_helper = Some((generation, helper.exit_success == Some(true))); }
                owner.helper.take();
                state.lifecycle.retire_generation(generation);
                state.sender.take();
                owner.cancellation.cancel();
            }
            Ok(false) => helper_known_live = true,
            Err(err) => {
                state.lifecycle.retire_generation(generation);
                state.sender.take();
                owner.cancellation.cancel();
                if !owner.retirement_error_logged {
                    log::error!("whiteboard generation {generation} helper observation failed; ownership retained: {err}");
                    owner.retirement_error_logged = true;
                }
            }
        }
    }
    if state.lifecycle.phase == (WhiteboardWorkerPhase::Starting { generation }) {
        if owner.helper.is_none() && owner.launch.is_none() && now >= owner.launch_not_before {
            let launch_token = owner.launch_token.clone();
            owner.launch = Some(tokio::task::spawn_blocking(move || launch_whiteboard_helper(generation, &launch_token)));
        } else if let Some(helper) = owner.helper.as_ref().filter(|_| owner.launch.is_none()) {
            if owner.worker.is_none() {
                match helper.id() {
                    Ok(pid) => {
                        owner.worker = Some(tokio::spawn(run_whiteboard_worker(generation,
                            owner.launch_token.clone(), owner.postfix.clone(), pid, owner.cancellation.clone())));
                    }
                    Err(err) => {
                        state.lifecycle.retire_generation(generation);
                        log::error!("whiteboard generation {generation} helper launch identity failed: {err}");
                    }
                }
            }
        }
    }
    if let Some(worker) = owner.worker.as_mut() {
        if let Poll::Ready(result) = Pin::new(worker).poll(cx) {
            owner.worker.take();
            owner.worker_joined = true;
            state.lifecycle.retire_generation(generation);
            state.sender.take();
            if let Err(err) = result { log::error!("whiteboard generation {generation} task join failed: {err}"); }
        }
    }
    if matches!(state.lifecycle.phase, WhiteboardWorkerPhase::Stopping { generation: current, .. } if current == generation) {
        let deadline = *owner.retirement_deadline.get_or_insert(now + Duration::from_secs(3));
        if now >= deadline {
            owner.cancellation.cancel();
            if helper_known_live {
                if let Some(helper) = owner.helper.as_mut() {
                    if let Err(err) = helper.terminate() {
                        if !owner.retirement_error_logged {
                            log::error!("whiteboard generation {generation} helper termination failed; ownership retained: {err}");
                            owner.retirement_error_logged = true;
                        }
                    }
                }
            }
        }
        if owner.worker.is_none() && owner.launch.is_none() && owner.helper.is_none() && !owner.launch_uncertain {
            state.generation.take();
            match state.lifecycle.finish(generation, has_demand && state.owner == WhiteboardOwnerAdmission::Serving) {
                Ok(Some(next)) => if let Err(err) = reserve_whiteboard_generation(state, next) {
                    state.lifecycle.cancel_reserved_generation(next);
                    log::error!("failed to reserve demanded whiteboard generation {next}: {err}");
                },
                Ok(None) => {},
                Err(err) => log::error!("whiteboard generation {generation} retirement failed: {err}"),
            }
        }
    }
}

impl WhiteboardClientState {
    fn send_command(&mut self, command: WhiteboardIpcCommand) -> WhiteboardCommandAdmission {
        let (generation, result) = {
            let Some((generation, sender)) = self.sender.as_ref() else {
                if let Some(generation) = self.lifecycle.running_generation() {
                    self.lifecycle.sender_failed(generation);
                    if let Some(owner) = self.generation.as_ref() { owner.cancellation.cancel(); }
                    WHITEBOARD_OWNER_WAKE.notify_one();
                }
                return WhiteboardCommandAdmission::NoWorker;
            };
            (*generation, sender.try_send(command))
        };
        match result {
            Ok(()) => WhiteboardCommandAdmission::Accepted,
            Err(TrySendError::Full(WhiteboardIpcCommand::Cursor { .. })) => {
                WhiteboardCommandAdmission::CursorDropped
            }
            Err(TrySendError::Full(_)) => {
                self.sender.take();
                self.lifecycle.sender_failed(generation);
                if let Some(owner) = self.generation.as_ref() { owner.cancellation.cancel(); }
                WHITEBOARD_OWNER_WAKE.notify_one();
                WhiteboardCommandAdmission::WorkerRetiredAfterSaturation
            }
            Err(TrySendError::Closed(_)) => {
                self.sender.take();
                self.lifecycle.sender_failed(generation);
                if let Some(owner) = self.generation.as_ref() { owner.cancellation.cancel(); }
                WHITEBOARD_OWNER_WAKE.notify_one();
                WhiteboardCommandAdmission::WorkerRetiredAfterClosure
            }
        }
    }
}

struct Conn {
    token: String,
    last_cursor_pos: (f32, f32), // For click ripple
    last_cursor_evt: LastCursorEvent,
}

struct LastCursorEvent {
    cursor: Option<Cursor>,
    tm: Instant,
    c: usize,
}

fn reserve_whiteboard_generation(
    state: &mut WhiteboardClientState,
    generation: u64,
) -> ResultType<()> {
    if state.lifecycle.phase != (WhiteboardWorkerPhase::Starting { generation }) {
        bail!("whiteboard worker generation {generation} was not reserved");
    }
    if state.generation.is_some() {
        bail!("whiteboard worker ownership overlaps generation {generation}");
    }
    if state.owner != WhiteboardOwnerAdmission::Serving {
        bail!("whiteboard controlled-server owner is unavailable");
    }
    let launch_token = crate::encode64(hbb_common::rand::random::<[u8; 32]>());
    let postfix = ipc::whiteboard_endpoint_postfix(&launch_token)?;
    state.generation = Some(WhiteboardGeneration {
        generation, launch_token, postfix, launch: None, helper: None, worker: None,
        worker_joined: false, cancellation: CancellationToken::new(),
        launch_not_before: tokio::time::Instant::now(), retirement_deadline: None,
        launch_uncertain: false, retirement_error_logged: false,
    });
    WHITEBOARD_OWNER_WAKE.notify_one();
    Ok(())
}

struct WhiteboardClientWorkerGuard {
    generation: u64,
}

impl Drop for WhiteboardClientWorkerGuard {
    fn drop(&mut self) {
        finish_whiteboard_worker(self.generation);
    }
}

fn finish_whiteboard_worker(generation: u64) {
    let mut state = WHITEBOARD_CLIENT.lock().unwrap();
    if state.generation.as_ref().map(|owner| owner.generation) != Some(generation) {
        log::error!("stale whiteboard generation {generation} task finalizer");
        return;
    }
    if state.sender.as_ref().map(|(owner, _)| *owner) == Some(generation) { state.sender.take(); }
    state.lifecycle.retire_generation(generation);
    WHITEBOARD_OWNER_WAKE.notify_one();
}

async fn run_whiteboard_worker(generation: u64, launch_token: String, postfix: String,
    helper_pid: u32, cancellation: CancellationToken) {
    let _terminal = WhiteboardClientWorkerGuard { generation };
    let result = async {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => bail!("whiteboard generation {generation} cancelled"),
            result = start_whiteboard_(generation, &launch_token, &postfix, helper_pid) => result,
        }
    };
    match AssertUnwindSafe(result)
        .catch_unwind()
        .await
    {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            log::error!("Whiteboard worker generation {generation} failed: {err}")
        }
        Err(_) => log::error!("Whiteboard worker generation {generation} panicked"),
    }
}

fn log_whiteboard_command_admission(admission: WhiteboardCommandAdmission) {
    match admission {
        WhiteboardCommandAdmission::Accepted | WhiteboardCommandAdmission::NoWorker => {}
        WhiteboardCommandAdmission::CursorDropped => {
            log::debug!("Dropping a whiteboard cursor because the bounded queue is full");
        }
        WhiteboardCommandAdmission::WorkerRetiredAfterSaturation => {
            log::warn!("Retiring a saturated whiteboard command owner");
        }
        WhiteboardCommandAdmission::WorkerRetiredAfterClosure => {
            log::warn!("Retiring a closed whiteboard command owner");
        }
    }
}

pub fn register_whiteboard(conn_id: i32) {
    if conn_id <= 0 {
        log::warn!("Rejecting whiteboard registration for invalid connection id {conn_id}");
        return;
    }
    let mut launch_error = None;
    let mut admission = WhiteboardCommandAdmission::NoWorker;
    {
        let mut state = WHITEBOARD_CLIENT.lock().unwrap();
        if state.owner != WhiteboardOwnerAdmission::Serving {
            log::warn!("whiteboard registration refused while the controlled-server owner is unavailable");
            return;
        }
        let bind = if state.conns.contains_key(&conn_id) {
            None
        } else {
            if state.conns.len() >= ipc::WHITEBOARD_IPC_MAX_ACTIVE_CONNECTIONS {
                drop(state);
                log::warn!(
                    "Rejecting whiteboard registration beyond the active-connection limit"
                );
                return;
            }
            let token = crate::encode64(hbb_common::rand::random::<[u8; 32]>());
            state.conns.insert(
                conn_id,
                Conn {
                    token: token.clone(),
                    last_cursor_pos: (0.0, 0.0),
                    last_cursor_evt: LastCursorEvent {
                        cursor: None,
                        tm: Instant::now(),
                        c: 0,
                    },
                },
            );
            Some(WhiteboardIpcCommand::Bind { conn_id, token })
        };
        let launch_generation = match state.lifecycle.request_worker() {
            Ok(generation) => generation,
            Err(err) => {
                launch_error = Some(err.to_string());
                None
            }
        };
        if let Some(command) = bind {
            admission = state.send_command(command);
            if !matches!(admission, WhiteboardCommandAdmission::Accepted) {
                if let Err(err) = state.lifecycle.request_worker() {
                    launch_error = Some(err.to_string());
                }
            }
        }
        if let Some(generation) = launch_generation {
            if let Err(err) = reserve_whiteboard_generation(&mut state, generation) {
                state.lifecycle.cancel_reserved_generation(generation);
                launch_error = Some(err.to_string());
            }
        }
    }
    log_whiteboard_command_admission(admission);
    if let Some(err) = launch_error {
        log::error!("Failed to start whiteboard worker: {err}");
    }
}

pub fn unregister_whiteboard(conn_id: i32) {
    let admissions = {
        let mut state = WHITEBOARD_CLIENT.lock().unwrap();
        let command = state
            .conns
            .remove(&conn_id)
            .map(|conn| WhiteboardIpcCommand::Close {
                conn_id,
                token: conn.token,
            });
        let is_empty = state.conns.is_empty();
        let mut admissions = [None; 2];
        if let Some(command) = command {
            admissions[0] = Some(state.send_command(command));
        }
        if is_empty {
            admissions[1] = Some(state.send_command(WhiteboardIpcCommand::Shutdown));
        }
        admissions
    };
    admissions
        .into_iter()
        .flatten()
        .for_each(log_whiteboard_command_admission);
}

pub fn update_whiteboard_cursor(conn_id: i32, cursor: Cursor) {
    let admissions = {
        let mut state = WHITEBOARD_CLIENT.lock().unwrap();
        let commands = {
            let Some(conn) = state.conns.get_mut(&conn_id) else {
                return;
            };
            let mut commands = [None, None];
            let mut command_count = 0;
            conn.last_cursor_evt.c += 1;
            conn.last_cursor_evt.tm = Instant::now();
            if cursor.btns == 0 {
                // Send one movement event every 4.
                if conn.last_cursor_evt.c > 3 {
                    conn.last_cursor_evt.c = 0;
                    conn.last_cursor_evt.cursor = None;
                    commands[command_count] =
                        Some(whiteboard_cursor_command(conn, conn_id, cursor));
                } else {
                    conn.last_cursor_evt.cursor = Some(cursor);
                }
            } else {
                if let Some(pending_cursor) = conn.last_cursor_evt.cursor.take() {
                    commands[command_count] =
                        Some(whiteboard_cursor_command(conn, conn_id, pending_cursor));
                    command_count += 1;
                }
                conn.last_cursor_evt.c = 0;
                let click_cursor = Cursor {
                    x: conn.last_cursor_pos.0,
                    y: conn.last_cursor_pos.1,
                    argb: cursor.argb,
                    btns: cursor.btns,
                    text: cursor.text,
                };
                commands[command_count] =
                    Some(whiteboard_cursor_command(conn, conn_id, click_cursor));
            }
            commands
        };
        let mut admissions = [None; 2];
        for (index, command) in commands.into_iter().flatten().enumerate() {
            admissions[index] = Some(state.send_command(command));
        }
        admissions
    };
    admissions
        .into_iter()
        .flatten()
        .for_each(log_whiteboard_command_admission);
}

#[inline]
fn whiteboard_cursor_command(
    conn: &mut Conn,
    conn_id: i32,
    cursor: Cursor,
) -> WhiteboardIpcCommand {
    if cursor.btns == 0 {
        conn.last_cursor_pos = (cursor.x, cursor.y);
    }

    WhiteboardIpcCommand::Cursor {
        conn_id,
        token: conn.token.clone(),
        cursor,
    }
}

fn close_whiteboard_if_idle(generation: u64) -> bool {
    let mut state = WHITEBOARD_CLIENT.lock().unwrap();
    if !state.conns.is_empty() {
        return false;
    }
    if state.lifecycle.begin_stop(generation)
        && state.sender.as_ref().map(|(owner, _)| *owner) == Some(generation)
    {
        state.sender.take();
    }
    true
}

fn whiteboard_launch_env(launch_token: &str) -> Vec<(&'static str, String)> {
    vec![
        (
            crate::common::WHITEBOARD_LAUNCH_TOKEN_ENV,
            launch_token.to_owned(),
        ),
        (
            crate::common::WHITEBOARD_LAUNCH_PARENT_ENV,
            std::process::id().to_string(),
        ),
    ]
}

#[cfg(target_os = "linux")]
pub(crate) fn whiteboard_helper_command(launch_token: &str) -> ResultType<std::process::Command> {
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command.arg("--whiteboard").envs(whiteboard_launch_env(launch_token));
    hbb_common::platform::linux::configure_command_close_nonstdio_on_exec(&mut command)?;
    Ok(command)
}

async fn connect_whiteboard_endpoint(
    ms_timeout: u64,
    postfix: &str,
    launch_token: &str,
    helper_pid: u32,
) -> ResultType<ipc::ConnectionTmpl<parity_tokio_ipc::ConnectionClient>> {
    let mut stream = ipc::connect(ms_timeout, postfix).await?;
    #[cfg(target_os = "linux")]
    if stream.peer_pid() != Some(helper_pid) { bail!("whiteboard endpoint is not the retained helper"); }
    #[cfg(not(target_os = "linux"))]
    let _ = helper_pid;
    ipc::authenticate_whiteboard_endpoint_launch_proof(&mut stream, launch_token).await?;
    Ok(stream)
}

fn launch_whiteboard_helper(generation: u64, launch_token: &str) -> ResultType<WhiteboardLaunch> {
    let headless_service_user = crate::platform::is_headless_no_console_user();
    if !headless_service_user && crate::platform::is_prelogin() {
        return Ok(WhiteboardLaunch::WaitingForUser);
    }
    #[cfg(target_os = "windows")]
    let mut helper = crate::platform::launch_whiteboard_user_helper(launch_token)?;
    #[cfg(not(target_os = "windows"))]
    let mut helper = {
    if crate::platform::is_root() && !headless_service_user {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        bail!("Refusing root-to-user whiteboard launch; the user-context service must own it");
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        bail!("Refusing unsupported root-to-user whiteboard launch");
    }
    #[cfg(target_os = "linux")]
    let child = whiteboard_helper_command(launch_token)?.spawn()?;
    #[cfg(all(target_os = "linux", feature = "linux-whiteboard-lifecycle-probe"))]
    probe_hold_whiteboard_launch(child.id());
    #[cfg(not(target_os = "linux"))]
    let child = crate::run_me_with_env(vec!["--whiteboard"], whiteboard_launch_env(launch_token))?;
    WhiteboardHelperProcess { child, exit_success: None }
    };
    match WHITEBOARD_CLIENT.lock() {
        Ok(mut state) => {
            if matches!(state.owner, WhiteboardOwnerAdmission::Serving | WhiteboardOwnerAdmission::Draining) {
                if let Some(owner) = state.generation.as_mut().filter(|owner|
                    owner.generation == generation && owner.helper.is_none()) {
                    owner.helper = Some(helper);
                    return Ok(WhiteboardLaunch::Spawned);
                }
            }
        }
        Err(err) => log::error!("whiteboard generation {generation} helper handoff failed; creation job retains ownership: {err}"),
    }
    // A finished launch result must never hide a live helper from a dropped root.
    let mut termination_requested = false;
    let mut observation_error_logged = false;
    let mut termination_error_logged = false;
    loop {
        match helper.try_reap_exited() {
            Ok(true) => return Ok(WhiteboardLaunch::Retired),
            Ok(false) => {
                if !termination_requested {
                    match helper.terminate() {
                        Ok(()) => termination_requested = true,
                        Err(err) => {
                            if !termination_error_logged {
                                log::error!("whiteboard generation {generation} unpublished helper termination failed; ownership retained: {err}");
                                termination_error_logged = true;
                            }
                        }
                    }
                }
            }
            Err(err) => {
                if !observation_error_logged {
                    log::error!("whiteboard generation {generation} unpublished helper observation failed; ownership retained: {err}");
                    observation_error_logged = true;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

async fn start_whiteboard_(generation: u64, launch_token: &str, postfix: &str, helper_pid: u32) -> ResultType<()> {
    let mut stream = None;
    for _ in 0..20 {
        sleep(0.3).await;
        match connect_whiteboard_endpoint(1000, postfix, launch_token, helper_pid).await {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(err) => {
                log::debug!("No authenticated whiteboard endpoint yet: {}", err);
            }
        }
    }
    if stream.is_none() {
        bail!("Failed to connect to authenticated whiteboard helper");
    }

    let mut stream = stream.ok_or(anyhow!("none stream"))?;
    let (tx, mut rx) = channel(ipc::WHITEBOARD_IPC_COMMAND_CAPACITY);
    let initial_binds = {
        let mut state = WHITEBOARD_CLIENT.lock().unwrap();
        if !state.lifecycle.publish(generation) {
            bail!("whiteboard worker generation {generation} lost startup ownership");
        }
        if state.sender.is_some() {
            bail!("whiteboard command sender ownership overlapped generation {generation}");
        }
        state.sender = Some((generation, tx.clone()));
        for (conn_id, conn) in state.conns.iter() {
            tx.try_send(WhiteboardIpcCommand::Bind {
                conn_id: *conn_id,
                token: conn.token.clone(),
            })
            .map_err(|err| anyhow!("failed to enqueue initial whiteboard bind: {err}"))?;
        }
        state.conns.len()
    };
    if initial_binds == 0 {
        tx.try_send(WhiteboardIpcCommand::Shutdown)
            .map_err(|err| anyhow!("failed to enqueue initial whiteboard shutdown: {err}"))?;
    }
    drop(tx);

    let dur = tokio::time::Duration::from_millis(300);
    let mut timer = interval_at(tokio::time::Instant::now() + dur, dur);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            result = stream.wait_whiteboard_helper_eof() => {
                result?;
                bail!("whiteboard helper closed its command stream");
            }
            res = rx.recv() => {
                match res {
                    Some(command @ WhiteboardIpcCommand::Bind { .. }) => {
                        stream
                            .send_whiteboard_command_timeout(
                                &command,
                                ipc::WHITEBOARD_IPC_IO_TIMEOUT_MS,
                            )
                            .await?;
                        timer.reset();
                    }
                    Some(command @ WhiteboardIpcCommand::Cursor { .. }) => {
                        stream
                            .send_whiteboard_command_timeout(
                                &command,
                                ipc::WHITEBOARD_IPC_IO_TIMEOUT_MS,
                            )
                            .await?;
                        timer.reset();
                    }
                    Some(command @ WhiteboardIpcCommand::Close { .. }) => {
                        stream
                            .send_whiteboard_command_timeout(
                                &command,
                                ipc::WHITEBOARD_IPC_IO_TIMEOUT_MS,
                            )
                            .await?;
                        timer.reset();
                    }
                    Some(WhiteboardIpcCommand::Shutdown) => {
                        if close_whiteboard_if_idle(generation) {
                            break;
                        }
                    }
                    None => {
                        break;
                    }
                }
            },
            _ = timer.tick() => {
                let pending = {
                    let mut state = WHITEBOARD_CLIENT.lock().unwrap();
                    let mut pending: [Option<(i32, String, Cursor)>;
                        ipc::WHITEBOARD_IPC_MAX_ACTIVE_CONNECTIONS] =
                        std::array::from_fn(|_| None);
                    let mut pending_count = 0;
                    for (k, conn) in state.conns.iter_mut() {
                        if conn.last_cursor_evt.tm.elapsed().as_millis() > 300 {
                            if let Some(cursor) = conn.last_cursor_evt.cursor.take() {
                                pending[pending_count] =
                                    Some((*k, conn.token.clone(), cursor));
                                pending_count += 1;
                                conn.last_cursor_evt.c = 0;
                            }
                        }
                    }
                    pending
                };
                for (conn_id, token, cursor) in pending.into_iter().flatten() {
                    stream
                        .send_whiteboard_command_timeout(
                            &WhiteboardIpcCommand::Cursor {
                                conn_id,
                                token,
                                cursor,
                            },
                            ipc::WHITEBOARD_IPC_IO_TIMEOUT_MS,
                        )
                        .await?;
                }
            }
        }
    }
    stream
        .send_whiteboard_command_timeout(
            &WhiteboardIpcCommand::Shutdown,
            ipc::WHITEBOARD_IPC_IO_TIMEOUT_MS,
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reserved_client() -> (WhiteboardClientState, u64) {
        let mut state = WhiteboardClientState::default();
        state.owner = WhiteboardOwnerAdmission::Serving;
        let generation = state.lifecycle.request_worker().unwrap().unwrap();
        reserve_whiteboard_generation(&mut state, generation).unwrap();
        state.lifecycle.retire_generation(generation);
        state.owner = WhiteboardOwnerAdmission::Draining;
        (state, generation)
    }

    async fn observe_client(state: &mut WhiteboardClientState) {
        poll_fn(|cx| {
            poll_whiteboard_generation(state, cx);
            Poll::Ready(())
        }).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn r_s11ho_cancelled_task_retains_generation_until_external_join() {
        let (mut state, generation) = reserved_client();
        let (started, running) = tokio::sync::oneshot::channel();
        state.generation.as_mut().unwrap().worker = Some(tokio::spawn(async move {
            started.send(()).unwrap();
            std::future::pending::<()>().await;
        }));
        running.await.unwrap();
        observe_client(&mut state).await;
        assert_eq!(state.lifecycle.phase, WhiteboardWorkerPhase::Stopping {
            generation, restart_requested: false,
        });
        let worker = state.generation.as_ref().unwrap().worker.as_ref().unwrap();
        worker.abort();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !worker.is_finished() { tokio::task::yield_now().await; }
        }).await.unwrap();
        assert!(state.generation.as_ref().unwrap().worker.is_some());
        assert!(!state.generation.as_ref().unwrap().worker_joined);
        observe_client(&mut state).await;
        assert!(state.generation.is_none());
        assert_eq!(state.lifecycle.phase, WhiteboardWorkerPhase::Idle);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn r_s11ho_started_launch_retains_generation_through_cancellation() {
        let (mut state, generation) = reserved_client();
        let (started, running) = tokio::sync::oneshot::channel();
        let (release, finish) = std::sync::mpsc::channel();
        state.generation.as_mut().unwrap().launch = Some(tokio::task::spawn_blocking(move || {
            started.send(()).unwrap();
            finish.recv().unwrap();
            Ok(WhiteboardLaunch::WaitingForUser)
        }));
        running.await.unwrap();
        let owner = state.generation.as_mut().unwrap();
        owner.cancellation.cancel();
        owner.retirement_deadline = Some(tokio::time::Instant::now());
        owner.launch.as_ref().unwrap().abort();
        observe_client(&mut state).await;
        assert_eq!(state.lifecycle.phase, WhiteboardWorkerPhase::Stopping {
            generation, restart_requested: false,
        });
        assert!(!state.generation.as_ref().unwrap().launch.as_ref().unwrap().is_finished());
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while state.generation.is_some() {
                observe_client(&mut state).await;
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        assert_eq!(state.lifecycle.phase, WhiteboardWorkerPhase::Idle);
    }

    #[test]
    fn r_s11ho_duplicate_whiteboard_demand_owns_one_generation() {
        let mut lifecycle = WhiteboardWorkerLifecycle::default();
        let generation = lifecycle.request_worker().unwrap().unwrap();
        assert_eq!(lifecycle.request_worker().unwrap(), None);
        assert!(lifecycle.publish(generation));
        assert_eq!(lifecycle.request_worker().unwrap(), None);
        assert_eq!(
            lifecycle.phase,
            WhiteboardWorkerPhase::Running { generation }
        );
    }

    #[test]
    fn r_s11ho_demand_during_committed_stop_starts_one_successor() {
        let mut lifecycle = WhiteboardWorkerLifecycle::default();
        let first = lifecycle.request_worker().unwrap().unwrap();
        assert!(lifecycle.publish(first));
        assert!(lifecycle.begin_stop(first));
        assert_eq!(lifecycle.request_worker().unwrap(), None);
        assert_eq!(lifecycle.request_worker().unwrap(), None);

        let second = lifecycle.finish(first, true).unwrap().unwrap();
        assert_ne!(first, second);
        assert_eq!(
            lifecycle.phase,
            WhiteboardWorkerPhase::Starting { generation: second }
        );
        assert_eq!(lifecycle.request_worker().unwrap(), None);

        assert!(lifecycle.publish(second));
        assert!(lifecycle.begin_stop(second));
        assert_eq!(lifecycle.request_worker().unwrap(), None);
        assert_eq!(lifecycle.finish(second, false).unwrap(), None);
        assert_eq!(lifecycle.phase, WhiteboardWorkerPhase::Idle);
    }

    #[test]
    fn r_s11ho_unexpected_worker_failure_does_not_self_retry() {
        let mut lifecycle = WhiteboardWorkerLifecycle::default();
        let failed = lifecycle.request_worker().unwrap().unwrap();
        assert_eq!(lifecycle.finish(failed, true).unwrap(), None);
        assert_eq!(lifecycle.phase, WhiteboardWorkerPhase::Idle);

        let failed_transport = lifecycle.request_worker().unwrap().unwrap();
        assert_ne!(failed, failed_transport);
        assert!(lifecycle.publish(failed_transport));
        lifecycle.sender_failed(failed_transport);
        assert_eq!(lifecycle.finish(failed_transport, true).unwrap(), None);
        assert_eq!(lifecycle.phase, WhiteboardWorkerPhase::Idle);

        let explicit_retry = lifecycle.request_worker().unwrap().unwrap();
        assert_ne!(failed_transport, explicit_retry);
    }

    #[test]
    fn r_s11ho_stale_finalizer_cannot_retire_current_generation() {
        let mut lifecycle = WhiteboardWorkerLifecycle::default();
        let retired = lifecycle.request_worker().unwrap().unwrap();
        assert_eq!(lifecycle.finish(retired, false).unwrap(), None);
        let generation = lifecycle.request_worker().unwrap().unwrap();
        for phase in [
            WhiteboardWorkerPhase::Starting { generation },
            WhiteboardWorkerPhase::Running { generation },
            WhiteboardWorkerPhase::Stopping {
                generation,
                restart_requested: true,
            },
        ] {
            lifecycle.phase = phase;
            for stale in [retired, generation + 1] {
                assert_eq!(lifecycle.finish(stale, true).unwrap(), None);
                assert_eq!(lifecycle.phase, phase);
                assert_eq!(lifecycle.last_generation, generation);
            }
        }
        assert_eq!(
            lifecycle.finish(generation, true).unwrap(),
            Some(generation + 1)
        );
    }

    fn running_client() -> (
        WhiteboardClientState,
        tokio::sync::mpsc::Receiver<WhiteboardIpcCommand>,
        u64,
    ) {
        let mut state = WhiteboardClientState::default();
        let generation = state.lifecycle.request_worker().unwrap().unwrap();
        assert!(state.lifecycle.publish(generation));
        let (sender, receiver) = channel(ipc::WHITEBOARD_IPC_COMMAND_CAPACITY);
        state.sender = Some((generation, sender));
        (state, receiver, generation)
    }

    fn cursor_command(index: i32) -> WhiteboardIpcCommand {
        WhiteboardIpcCommand::Cursor {
            conn_id: 1,
            token: "queued".to_owned(),
            cursor: Cursor {
                x: index as f32,
                y: 0.0,
                argb: 0xff00ff00,
                btns: 0,
                text: String::new(),
            },
        }
    }

    fn required_commands() -> [WhiteboardIpcCommand; 3] {
        [
            WhiteboardIpcCommand::Bind {
                conn_id: 1,
                token: "required".to_owned(),
            },
            WhiteboardIpcCommand::Close {
                conn_id: 1,
                token: "required".to_owned(),
            },
            WhiteboardIpcCommand::Shutdown,
        ]
    }

    #[test]
    fn r_s11ho_saturation_drops_only_cursor_and_retires_required_commands() {
        for command in required_commands() {
            let (mut state, mut receiver, generation) = running_client();
            for index in 0..64 {
                assert_eq!(
                    state.send_command(cursor_command(index)),
                    WhiteboardCommandAdmission::Accepted
                );
            }
            assert_eq!(
                state.send_command(cursor_command(64)),
                WhiteboardCommandAdmission::CursorDropped
            );
            assert_eq!(
                state.lifecycle.phase,
                WhiteboardWorkerPhase::Running { generation }
            );
            assert_eq!(
                state.sender.as_ref().map(|(owner, _)| *owner),
                Some(generation)
            );

            assert_eq!(
                state.send_command(command),
                WhiteboardCommandAdmission::WorkerRetiredAfterSaturation
            );
            assert!(state.sender.is_none());
            assert_eq!(
                state.lifecycle.phase,
                WhiteboardWorkerPhase::Stopping {
                    generation,
                    restart_requested: false,
                }
            );
            for index in 0..64 {
                match receiver.try_recv().unwrap() {
                    WhiteboardIpcCommand::Cursor {
                        conn_id,
                        token,
                        cursor,
                    } => {
                        assert_eq!(conn_id, 1);
                        assert_eq!(token, "queued");
                        assert_eq!(cursor.x, index as f32);
                    }
                    command => panic!("queued cursor was replaced: {command:?}"),
                }
            }
            assert!(matches!(
                receiver.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
            ));
            assert_eq!(state.lifecycle.finish(generation, true).unwrap(), None);
            assert_eq!(state.lifecycle.phase, WhiteboardWorkerPhase::Idle);
        }
    }

    #[test]
    fn r_s11ho_closed_sender_retires_every_command_without_retry() {
        for command in required_commands().into_iter().chain([cursor_command(0)]) {
            let (mut state, receiver, generation) = running_client();
            drop(receiver);
            assert_eq!(
                state.send_command(command),
                WhiteboardCommandAdmission::WorkerRetiredAfterClosure
            );
            assert!(state.sender.is_none());
            assert_eq!(
                state.lifecycle.phase,
                WhiteboardWorkerPhase::Stopping {
                    generation,
                    restart_requested: false,
                }
            );
            assert_eq!(state.lifecycle.finish(generation, true).unwrap(), None);
            assert_eq!(state.lifecycle.phase, WhiteboardWorkerPhase::Idle);
        }
    }

    #[test]
    fn r_s11ho_exhausted_generation_cannot_wrap_or_start_a_successor() {
        let mut lifecycle = WhiteboardWorkerLifecycle {
            phase: WhiteboardWorkerPhase::Idle,
            last_generation: u64::MAX,
        };
        assert!(lifecycle.request_worker().is_err());
        assert_eq!(lifecycle.phase, WhiteboardWorkerPhase::Idle);
        assert_eq!(lifecycle.last_generation, u64::MAX);
        lifecycle.phase = WhiteboardWorkerPhase::Stopping {
            generation: u64::MAX,
            restart_requested: true,
        };
        assert!(lifecycle.finish(u64::MAX, true).is_err());
        assert_eq!(lifecycle.phase, WhiteboardWorkerPhase::Idle);
        assert_eq!(lifecycle.last_generation, u64::MAX);
    }
}
