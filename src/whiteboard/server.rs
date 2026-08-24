use super::CustomEvent;
use crate::ipc::{self, new_listener, Connection, WhiteboardIpcCommand};
use hbb_common::{
    allow_err, anyhow::anyhow, log,
    tokio::{self, sync::oneshot},
    ResultType,
};
use lazy_static::lazy_static;
use std::time::{Duration, Instant};
use std::{collections::HashMap, sync::RwLock};

#[cfg(any(target_os = "windows", target_os = "macos"))]
use tao::event_loop::EventLoopProxy;
#[cfg(target_os = "linux")]
use winit::event_loop::EventLoopProxy;

struct WhiteboardEventLifecycle<Proxy> {
    proxy: Option<Proxy>,
    ipc_terminated: bool,
}

impl<Proxy> Default for WhiteboardEventLifecycle<Proxy> {
    fn default() -> Self {
        Self {
            proxy: None,
            ipc_terminated: false,
        }
    }
}

impl<Proxy> WhiteboardEventLifecycle<Proxy> {
    fn install(&mut self, proxy: Proxy) -> Option<Proxy> {
        if self.ipc_terminated {
            Some(proxy)
        } else {
            self.proxy = Some(proxy);
            None
        }
    }

    fn terminate(&mut self) -> Option<Proxy> {
        if self.ipc_terminated {
            return None;
        }
        self.ipc_terminated = true;
        self.proxy.take()
    }

    fn clear_proxy(&mut self) {
        self.proxy = None;
    }
}

lazy_static! {
    static ref EVENT_LIFECYCLE: RwLock<
        WhiteboardEventLifecycle<EventLoopProxy<(String, CustomEvent)>>,
    > = RwLock::new(WhiteboardEventLifecycle::default());
}

pub(super) struct WhiteboardEventProxyGuard;

impl Drop for WhiteboardEventProxyGuard {
    fn drop(&mut self) {
        EVENT_LIFECYCLE.write().unwrap().clear_proxy();
    }
}

pub(super) fn install_whiteboard_event_proxy(
    proxy: EventLoopProxy<(String, CustomEvent)>,
) -> WhiteboardEventProxyGuard {
    let terminal_proxy = EVENT_LIFECYCLE.write().unwrap().install(proxy);
    if let Some(proxy) = terminal_proxy {
        allow_err!(proxy.send_event((String::new(), CustomEvent::Exit)));
    }
    WhiteboardEventProxyGuard
}

fn terminate_whiteboard_ipc_generation() {
    let terminal_proxy = EVENT_LIFECYCLE.write().unwrap().terminate();
    if let Some(proxy) = terminal_proxy {
        allow_err!(proxy.send_event((String::new(), CustomEvent::Exit)));
    }
}

struct WhiteboardIpcTerminalGuard;

impl Drop for WhiteboardIpcTerminalGuard {
    fn drop(&mut self) {
        terminate_whiteboard_ipc_generation();
    }
}

pub(super) struct WhiteboardIpcWorker {
    stop: oneshot::Sender<()>,
    thread: std::thread::JoinHandle<()>,
}

impl WhiteboardIpcWorker {
    pub(super) fn spawn() -> ResultType<Self> {
        let (stop, stop_requested) = oneshot::channel();
        let thread = std::thread::Builder::new()
            .name("rustdesk-whiteboard-ipc".to_owned())
            .spawn(move || run_whiteboard_ipc_worker(stop_requested))
            .map_err(|err| anyhow!("failed to spawn whiteboard IPC worker: {err}"))?;
        Ok(Self { stop, thread })
    }

    pub(super) fn stop_and_join(self) -> ResultType<()> {
        if self.stop.send(()).is_err() {
            log::debug!("whiteboard IPC worker had already terminated before stop");
        }
        self.thread
            .join()
            .map_err(|_| anyhow!("whiteboard IPC worker panicked"))
    }
}

fn run_whiteboard_ipc_worker(stop_requested: oneshot::Receiver<()>) {
    let _terminal = WhiteboardIpcTerminalGuard;
    start_ipc(stop_requested);
}

const RIPPLE_DURATION: Duration = Duration::from_millis(500);
#[cfg(target_os = "macos")]
type RippleFloat = f64;
#[cfg(any(target_os = "windows", target_os = "linux"))]
type RippleFloat = f32;

#[cfg(target_os = "linux")]
pub use super::linux::run;

#[cfg(any(target_os = "windows", target_os = "macos"))]
pub fn run() {
    let worker = match WhiteboardIpcWorker::spawn() {
        Ok(worker) => worker,
        Err(err) => {
            log::error!("Failed to start whiteboard IPC worker: {err}");
            return;
        }
    };
    if let Err(e) = super::create_event_loop() {
        log::error!("Failed to create event loop: {}", e);
    }
    if let Err(err) = worker.stop_and_join() {
        log::error!("Failed to finish whiteboard IPC worker: {err}");
    }
}

#[tokio::main(flavor = "current_thread")]
async fn start_ipc(mut stop_requested: oneshot::Receiver<()>) {
    let postfix = match ipc::whiteboard_endpoint_postfix_from_env() {
        Ok(postfix) => postfix,
        Err(err) => {
            log::error!("Failed to resolve whiteboard IPC endpoint: {}", err);
            return;
        }
    };
    let expected_parent_pid = match std::env::var(crate::common::WHITEBOARD_LAUNCH_PARENT_ENV)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
    {
        Some(pid) if pid != 0 => pid,
        _ => {
            log::error!("Failed to resolve whiteboard launch parent");
            return;
        }
    };
    match new_listener(&postfix).await {
        Ok(mut incoming) => loop {
            tokio::select! {
                _ = &mut stop_requested => {
                    log::info!("Exiting IPC");
                    break;
                }
                res = incoming.next() => match res {
                    Some(result) => match result {
                        Ok(stream) => {
                            log::debug!("Got new connection");
                            let mut stream = Connection::new_whiteboard(stream);
                            if !ipc::authorize_whiteboard_ipc_connection(&stream, expected_parent_pid) {
                                continue;
                            }
                            if let Err(err) = ipc::answer_whiteboard_endpoint_challenge(&mut stream).await {
                                log::warn!(
                                    "Rejected _whiteboard IPC peer without launch-bound endpoint proof: {}",
                                    err
                                );
                                continue;
                            }
                            handle_new_stream(stream, &mut stop_requested).await;
                            break;
                        }
                        Err(err) => {
                            log::error!("Couldn't get whiteboard client: {:?}", err);
                        }
                    },
                    None => {
                        log::error!("Failed to get whiteboard client");
                        break;
                    }
                }
            }
        },
        Err(err) => {
            log::error!("Failed to start whiteboard ipc server: {}", err);
        }
    }
}

enum WhiteboardIpcAction {
    Event(String, CustomEvent),
    Shutdown,
}

#[derive(Default)]
struct WhiteboardIpcState {
    active: HashMap<i32, String>,
}

impl WhiteboardIpcState {
    fn apply(&mut self, command: WhiteboardIpcCommand) -> Option<WhiteboardIpcAction> {
        match command {
            WhiteboardIpcCommand::Bind { conn_id, token } => {
                if conn_id > 0
                    && whiteboard_connection_token_is_valid(&token)
                    && (self.active.contains_key(&conn_id)
                        || self.active.len() < ipc::WHITEBOARD_IPC_MAX_ACTIVE_CONNECTIONS)
                {
                    self.active.insert(conn_id, token);
                }
                None
            }
            WhiteboardIpcCommand::Event {
                conn_id,
                token,
                event,
            } => {
                if matches!(event, CustomEvent::Exit) {
                    return None;
                }
                if self
                    .active
                    .get(&conn_id)
                    .is_some_and(|expected| expected == &token)
                {
                    Some(WhiteboardIpcAction::Event(
                        super::client::get_key_cursor(conn_id),
                        event,
                    ))
                } else {
                    None
                }
            }
            WhiteboardIpcCommand::Close { conn_id, token } => {
                let authorized = self
                    .active
                    .get(&conn_id)
                    .is_some_and(|expected| expected == &token);
                if authorized {
                    self.active.remove(&conn_id);
                    Some(WhiteboardIpcAction::Event(
                        super::client::get_key_cursor(conn_id),
                        CustomEvent::Clear,
                    ))
                } else {
                    None
                }
            }
            WhiteboardIpcCommand::Shutdown => {
                if self.active.is_empty() {
                    Some(WhiteboardIpcAction::Shutdown)
                } else {
                    None
                }
            }
        }
    }
}

fn whiteboard_connection_token_is_valid(token: &str) -> bool {
    crate::decode64(token)
        .map(|decoded| decoded.len() == 32)
        .unwrap_or(false)
}

fn send_whiteboard_event(k: String, evt: CustomEvent) {
    if let Some(ep) = EVENT_LIFECYCLE.read().unwrap().proxy.as_ref() {
        allow_err!(ep.send_event((k, evt)));
    }
}

async fn handle_new_stream(
    mut conn: Connection,
    stop_requested: &mut oneshot::Receiver<()>,
) {
    let mut state = WhiteboardIpcState::default();
    loop {
        match stop_requested.try_recv() {
            Ok(_) | Err(oneshot::error::TryRecvError::Closed) => break,
            Err(oneshot::error::TryRecvError::Empty) => {}
        }
        match conn
            .next_whiteboard_command_timeout(ipc::WHITEBOARD_IPC_IO_TIMEOUT_MS)
            .await
        {
            Err(err) => {
                log::info!("whiteboard IPC connection terminated: {err}");
                break;
            }
            Ok(Some(command)) => match state.apply(command) {
                Some(WhiteboardIpcAction::Event(k, evt)) => send_whiteboard_event(k, evt),
                Some(WhiteboardIpcAction::Shutdown) => break,
                None => {}
            },
            Ok(None) => {
                // The read deadline is a cancellation wake for the event-loop exit channel.
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r_s11hn_whiteboard_ipc_termination_before_proxy_is_delivered_once() {
        let mut lifecycle = WhiteboardEventLifecycle::default();
        assert_eq!(lifecycle.terminate(), None);
        assert_eq!(lifecycle.install(7), Some(7));
        assert_eq!(lifecycle.terminate(), None);
        assert!(lifecycle.proxy.is_none());
    }

    #[test]
    fn r_s11hn_whiteboard_ipc_termination_takes_exact_installed_proxy_once() {
        let mut lifecycle = WhiteboardEventLifecycle::default();
        assert_eq!(lifecycle.install(11), None);
        assert_eq!(lifecycle.terminate(), Some(11));
        assert_eq!(lifecycle.terminate(), None);
        assert!(lifecycle.proxy.is_none());
    }

    #[test]
    fn r_s11hn_whiteboard_event_loop_retirement_preserves_terminal_latch() {
        let mut lifecycle = WhiteboardEventLifecycle::default();
        assert_eq!(lifecycle.install(13), None);
        lifecycle.clear_proxy();
        assert_eq!(lifecycle.terminate(), None);
        assert_eq!(lifecycle.install(17), Some(17));
        assert!(lifecycle.proxy.is_none());
    }

    fn token(value: u8) -> String {
        crate::encode64(&[value; 32])
    }

    #[test]
    fn whiteboard_authority_rejects_unbound_events_and_exit() {
        let mut state = WhiteboardIpcState::default();
        let token = token(7);
        assert!(state
            .apply(WhiteboardIpcCommand::Event {
                conn_id: 7,
                token: token.clone(),
                event: CustomEvent::Clear,
            })
            .is_none());
        assert!(state
            .apply(WhiteboardIpcCommand::Close {
                conn_id: 7,
                token: token.clone(),
            })
            .is_none());
        assert!(state
            .apply(WhiteboardIpcCommand::Bind {
                conn_id: 7,
                token: token.clone(),
            })
            .is_none());
        assert!(state
            .apply(WhiteboardIpcCommand::Event {
                conn_id: 7,
                token,
                event: CustomEvent::Exit,
            })
            .is_none());
    }

    #[test]
    fn whiteboard_authority_is_per_connection_token() {
        let mut state = WhiteboardIpcState::default();
        let alpha = token(1);
        let beta = token(2);
        state.apply(WhiteboardIpcCommand::Bind {
            conn_id: 7,
            token: alpha.clone(),
        });
        state.apply(WhiteboardIpcCommand::Bind {
            conn_id: 8,
            token: beta.clone(),
        });

        match state.apply(WhiteboardIpcCommand::Event {
            conn_id: 7,
            token: alpha.clone(),
            event: CustomEvent::Clear,
        }) {
            Some(WhiteboardIpcAction::Event(k, CustomEvent::Clear)) => {
                assert_eq!(k, super::super::client::get_key_cursor(7));
            }
            _ => panic!("authorized whiteboard event was not forwarded"),
        }

        assert!(state
            .apply(WhiteboardIpcCommand::Close {
                conn_id: 7,
                token: beta.clone(),
            })
            .is_none());
        assert!(state.apply(WhiteboardIpcCommand::Shutdown).is_none());

        match state.apply(WhiteboardIpcCommand::Close {
            conn_id: 7,
            token: alpha,
        }) {
            Some(WhiteboardIpcAction::Event(k, CustomEvent::Clear)) => {
                assert_eq!(k, super::super::client::get_key_cursor(7));
            }
            _ => panic!("authorized whiteboard close was not forwarded"),
        }
        assert!(state.apply(WhiteboardIpcCommand::Shutdown).is_none());

        match state.apply(WhiteboardIpcCommand::Close {
            conn_id: 8,
            token: beta,
        }) {
            Some(WhiteboardIpcAction::Event(k, CustomEvent::Clear)) => {
                assert_eq!(k, super::super::client::get_key_cursor(8));
            }
            _ => panic!("second whiteboard close was not forwarded"),
        }
        assert!(matches!(
            state.apply(WhiteboardIpcCommand::Shutdown),
            Some(WhiteboardIpcAction::Shutdown)
        ));
    }

    #[test]
    fn whiteboard_authority_bounds_active_tokens_and_rejects_malformed_tokens() {
        let mut state = WhiteboardIpcState::default();
        state.apply(WhiteboardIpcCommand::Bind {
            conn_id: 1,
            token: "not-a-token".to_owned(),
        });
        assert!(state.active.is_empty());

        for conn_id in 1..=ipc::WHITEBOARD_IPC_MAX_ACTIVE_CONNECTIONS as i32 {
            state.apply(WhiteboardIpcCommand::Bind {
                conn_id,
                token: token(conn_id as u8),
            });
        }
        assert_eq!(
            state.active.len(),
            ipc::WHITEBOARD_IPC_MAX_ACTIVE_CONNECTIONS
        );

        state.apply(WhiteboardIpcCommand::Bind {
            conn_id: ipc::WHITEBOARD_IPC_MAX_ACTIVE_CONNECTIONS as i32 + 1,
            token: token(100),
        });
        assert_eq!(
            state.active.len(),
            ipc::WHITEBOARD_IPC_MAX_ACTIVE_CONNECTIONS
        );
        assert!(!state
            .active
            .contains_key(&(ipc::WHITEBOARD_IPC_MAX_ACTIVE_CONNECTIONS as i32 + 1)));

        let replacement = token(200);
        state.apply(WhiteboardIpcCommand::Bind {
            conn_id: 1,
            token: replacement.clone(),
        });
        assert_eq!(
            state.active.len(),
            ipc::WHITEBOARD_IPC_MAX_ACTIVE_CONNECTIONS
        );
        assert_eq!(state.active.get(&1), Some(&replacement));
    }
}

#[cfg(any(target_os = "windows", target_os = "linux"))]
pub(super) fn get_displays_rect() -> ResultType<(i32, i32, u32, u32)> {
    let displays = crate::server::display_service::try_get_displays()?;
    let mut min_x = i32::MAX;
    let mut min_y = i32::MAX;
    let mut max_x = i32::MIN;
    let mut max_y = i32::MIN;

    for display in displays {
        let (x, y) = (display.origin().0 as i32, display.origin().1 as i32);
        let (w, h) = (display.width() as i32, display.height() as i32);
        min_x = min_x.min(x);
        min_y = min_y.min(y);
        max_x = max_x.max(x + w);
        max_y = max_y.max(y + h);
    }
    let (x, y) = (min_x, min_y);
    let (w, h) = ((max_x - min_x) as u32, (max_y - min_y) as u32);
    Ok((x, y, w, h))
}

#[inline]
pub(super) fn argb_to_rgba(argb: u32) -> (u8, u8, u8, u8) {
    (
        (argb >> 16 & 0xFF) as u8,
        (argb >> 8 & 0xFF) as u8,
        (argb & 0xFF) as u8,
        (argb >> 24 & 0xFF) as u8,
    )
}

pub(super) struct Ripple {
    pub x: RippleFloat,
    pub y: RippleFloat,
    pub start_time: Instant,
}

impl Ripple {
    #[inline]
    pub fn retain_active(ripples: &mut Vec<Ripple>) {
        ripples.retain(|r| r.start_time.elapsed() < RIPPLE_DURATION);
    }

    pub fn get_radius_alpha(&self) -> (RippleFloat, RippleFloat) {
        let elapsed = self.start_time.elapsed();
        #[cfg(target_os = "macos")]
        let progress = (elapsed.as_secs_f64() / RIPPLE_DURATION.as_secs_f64()).min(1.0);
        #[cfg(any(target_os = "windows", target_os = "linux"))]
        let progress = (elapsed.as_secs_f32() / RIPPLE_DURATION.as_secs_f32()).min(1.0);
        #[cfg(target_os = "macos")]
        let radius = 25.0 * progress;
        #[cfg(any(target_os = "windows", target_os = "linux"))]
        let radius = 45.0 * progress;
        let alpha = 1.0 - progress;
        (radius, alpha)
    }
}
