use super::{Cursor, CustomEvent};
use crate::{
    ipc::{self, WhiteboardIpcCommand},
    CHILD_PROCESS,
};
use hbb_common::{
    anyhow::anyhow,
    bail,
    futures::FutureExt,
    log, sleep,
    tokio::{
        self,
        sync::mpsc::{channel, error::TrySendError, Sender},
        time::interval_at,
    },
    ResultType,
};
use lazy_static::lazy_static;
use std::{
    collections::HashMap,
    panic::AssertUnwindSafe,
    sync::Mutex,
    time::Instant,
};

lazy_static! {
    static ref WHITEBOARD_CLIENT: Mutex<WhiteboardClientState> =
        Mutex::new(WhiteboardClientState::default());
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
    EventDropped,
    WorkerRetiredAfterSaturation,
    WorkerRetiredAfterClosure,
}

struct WhiteboardClientState {
    lifecycle: WhiteboardWorkerLifecycle,
    sender: Option<(u64, Sender<WhiteboardIpcCommand>)>,
    worker: Option<(u64, tokio::task::JoinHandle<()>)>,
    conns: HashMap<i32, Conn>,
}

impl Default for WhiteboardClientState {
    fn default() -> Self {
        Self {
            lifecycle: WhiteboardWorkerLifecycle::default(),
            sender: None,
            worker: None,
            conns: HashMap::new(),
        }
    }
}

impl WhiteboardClientState {
    fn send_command(&mut self, command: WhiteboardIpcCommand) -> WhiteboardCommandAdmission {
        let (generation, result) = {
            let Some((generation, sender)) = self.sender.as_ref() else {
                if let Some(generation) = self.lifecycle.running_generation() {
                    self.lifecycle.sender_failed(generation);
                }
                return WhiteboardCommandAdmission::NoWorker;
            };
            (*generation, sender.try_send(command))
        };
        match result {
            Ok(()) => WhiteboardCommandAdmission::Accepted,
            Err(TrySendError::Full(WhiteboardIpcCommand::Event { .. })) => {
                WhiteboardCommandAdmission::EventDropped
            }
            Err(TrySendError::Full(_)) => {
                self.sender.take();
                self.lifecycle.sender_failed(generation);
                WhiteboardCommandAdmission::WorkerRetiredAfterSaturation
            }
            Err(TrySendError::Closed(_)) => {
                self.sender.take();
                self.lifecycle.sender_failed(generation);
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
    evt: Option<CustomEvent>,
    tm: Instant,
    c: usize,
}

#[inline]
pub fn get_key_cursor(conn_id: i32) -> String {
    format!("{}-cursor", conn_id)
}

fn install_reserved_whiteboard_worker(
    state: &mut WhiteboardClientState,
    generation: u64,
) -> ResultType<()> {
    if state.lifecycle.phase != (WhiteboardWorkerPhase::Starting { generation }) {
        bail!("whiteboard worker generation {generation} was not reserved");
    }
    if state.worker.is_some() {
        bail!("whiteboard worker ownership overlaps generation {generation}");
    }
    let runtime = tokio::runtime::Handle::try_current()
        .map_err(|err| anyhow!("whiteboard worker requires the existing Tokio runtime: {err}"))?;
    let worker = std::panic::catch_unwind(AssertUnwindSafe(|| {
        runtime.spawn(run_whiteboard_worker(generation))
    }))
    .map_err(|_| {
        anyhow!("existing Tokio runtime refused whiteboard worker generation {generation}")
    })?;
    state.worker = Some((generation, worker));
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
    let mut diagnostics = Vec::new();
    let retired_worker = {
        let mut state = WHITEBOARD_CLIENT.lock().unwrap();
        if state.sender.as_ref().map(|(owner, _)| *owner) == Some(generation) {
            state.sender.take();
        }
        let retired_worker =
            if state.worker.as_ref().map(|(owner, _)| *owner) == Some(generation) {
                state.worker.take().map(|(_, worker)| worker)
            } else {
                diagnostics.push(format!(
                    "whiteboard worker generation {generation} lost its exact task handle"
                ));
                None
            };
        let has_demand = !state.conns.is_empty();
        let restart_generation = match state.lifecycle.finish(generation, has_demand) {
            Ok(generation) => generation,
            Err(err) => {
                diagnostics.push(format!("whiteboard worker finalization failed: {err}"));
                None
            }
        };
        if let Some(restart_generation) = restart_generation {
            if let Err(err) =
                install_reserved_whiteboard_worker(&mut state, restart_generation)
            {
                state
                    .lifecycle
                    .cancel_reserved_generation(restart_generation);
                diagnostics.push(format!(
                    "failed to start demanded whiteboard successor generation {restart_generation}: {err}"
                ));
            }
        }
        retired_worker
    };
    drop(retired_worker);
    for diagnostic in diagnostics {
        log::error!("{diagnostic}");
    }
}

async fn run_whiteboard_worker(generation: u64) {
    let _terminal = WhiteboardClientWorkerGuard { generation };
    match AssertUnwindSafe(start_whiteboard_(generation))
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
        WhiteboardCommandAdmission::EventDropped => {
            log::debug!("Dropping a whiteboard event because the bounded queue is full");
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
                        evt: None,
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
            if let Err(err) = install_reserved_whiteboard_worker(&mut state, generation) {
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

pub fn update_whiteboard(conn_id: i32, e: CustomEvent) {
    let admissions = {
        let mut state = WHITEBOARD_CLIENT.lock().unwrap();
        let commands = {
            let Some(conn) = state.conns.get_mut(&conn_id) else {
                return;
            };
            let mut commands = [None, None];
            let mut command_count = 0;
            match &e {
                CustomEvent::Cursor(cursor) => {
                    conn.last_cursor_evt.c += 1;
                    conn.last_cursor_evt.tm = Instant::now();
                    if cursor.btns == 0 {
                        // Send one movement event every 4.
                        if conn.last_cursor_evt.c > 3 {
                            conn.last_cursor_evt.c = 0;
                            conn.last_cursor_evt.evt = None;
                            commands[command_count] =
                                Some(whiteboard_event_command(conn, conn_id, e));
                        } else {
                            conn.last_cursor_evt.evt = Some(e);
                        }
                    } else {
                        if let Some(evt) = conn.last_cursor_evt.evt.take() {
                            commands[command_count] =
                                Some(whiteboard_event_command(conn, conn_id, evt));
                            command_count += 1;
                            conn.last_cursor_evt.c = 0;
                        }
                        let click_evt = CustomEvent::Cursor(Cursor {
                            x: conn.last_cursor_pos.0,
                            y: conn.last_cursor_pos.1,
                            argb: cursor.argb,
                            btns: cursor.btns,
                            text: cursor.text.clone(),
                        });
                        commands[command_count] =
                            Some(whiteboard_event_command(conn, conn_id, click_evt));
                    }
                }
                _ => {
                    commands[command_count] =
                        Some(whiteboard_event_command(conn, conn_id, e));
                }
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
fn whiteboard_event_command(
    conn: &mut Conn,
    conn_id: i32,
    event: CustomEvent,
) -> WhiteboardIpcCommand {
    if let CustomEvent::Cursor(cursor) = &event {
        if cursor.btns == 0 {
            conn.last_cursor_pos = (cursor.x, cursor.y);
        }
    }

    WhiteboardIpcCommand::Event {
        conn_id,
        token: conn.token.clone(),
        event,
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

async fn connect_whiteboard_endpoint(
    ms_timeout: u64,
    postfix: &str,
    launch_token: &str,
) -> ResultType<ipc::ConnectionTmpl<parity_tokio_ipc::ConnectionClient>> {
    let mut stream = ipc::connect(ms_timeout, postfix).await?;
    ipc::authenticate_whiteboard_endpoint_launch_proof(&mut stream, launch_token).await?;
    Ok(stream)
}

async fn start_whiteboard_(generation: u64) -> ResultType<()> {
    let headless_service_user = loop {
        if crate::platform::is_headless_no_console_user() {
            break true;
        }
        if !crate::platform::is_prelogin() {
            break false;
        }
        sleep(1.).await;
    };
    let mut stream = None;
    let launch_token = crate::encode64(hbb_common::rand::random::<[u8; 32]>());
    let postfix = ipc::whiteboard_endpoint_postfix(&launch_token)?;
    let args = vec!["--whiteboard"];

    if crate::platform::is_root() && !headless_service_user {
        #[cfg(target_os = "windows")]
        {
            let mut res = Ok(None);
            for _ in 0..10 {
                log::debug!("Start whiteboard");
                res = crate::platform::run_user_helper(
                    crate::platform::WindowsUserHelperLaunch::Whiteboard {
                        launch_token: &launch_token,
                    },
                );
                if res.is_ok() {
                    break;
                }
                log::error!("Failed to run whiteboard: {res:?}");
                sleep(1.).await;
            }
            if let Some(task) = res? {
                CHILD_PROCESS.lock().unwrap().push(task);
            }
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        bail!("Refusing root-to-user whiteboard launch; the user-context service must own it");
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        bail!("Refusing unsupported root-to-user whiteboard launch");
    } else {
        log::debug!("Start whiteboard");
        #[cfg(target_os = "linux")]
        let child = crate::common::run_me_with_env_and_parent_death(
            args,
            whiteboard_launch_env(&launch_token),
        )?;
        #[cfg(not(target_os = "linux"))]
        let child = crate::run_me_with_env(args, whiteboard_launch_env(&launch_token))?;
        CHILD_PROCESS.lock().unwrap().push(child);
    }
    for _ in 0..20 {
        sleep(0.3).await;
        match connect_whiteboard_endpoint(1000, &postfix, &launch_token).await {
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
                    Some(command @ WhiteboardIpcCommand::Event { .. }) => {
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
                    let mut pending = Vec::new();
                    for (k, conn) in state.conns.iter_mut() {
                        if conn.last_cursor_evt.tm.elapsed().as_millis() > 300 {
                            if let Some(evt) = conn.last_cursor_evt.evt.take() {
                                pending.push((*k, conn.token.clone(), evt));
                                conn.last_cursor_evt.c = 0;
                            }
                        }
                    }
                    pending
                };
                for (conn_id, token, event) in pending {
                    stream
                        .send_whiteboard_command_timeout(
                            &WhiteboardIpcCommand::Event {
                                conn_id,
                                token,
                                event,
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
        let generation = lifecycle.request_worker().unwrap().unwrap();
        assert_eq!(lifecycle.finish(generation + 1, true).unwrap(), None);
        assert_eq!(
            lifecycle.phase,
            WhiteboardWorkerPhase::Starting { generation }
        );
        assert!(lifecycle.publish(generation));
    }

    #[test]
    fn whiteboard_command_queue_has_a_hard_capacity() {
        let (sender, _receiver) = channel(ipc::WHITEBOARD_IPC_COMMAND_CAPACITY);
        for _ in 0..ipc::WHITEBOARD_IPC_COMMAND_CAPACITY {
            sender
                .try_send(WhiteboardIpcCommand::Shutdown)
                .unwrap();
        }
        assert!(matches!(
            sender.try_send(WhiteboardIpcCommand::Shutdown),
            Err(TrySendError::Full(WhiteboardIpcCommand::Shutdown))
        ));
    }
}
