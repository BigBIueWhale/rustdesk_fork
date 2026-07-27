use super::CustomEvent;
use crate::ipc::{self, new_listener, Connection, WhiteboardIpcCommand};
#[cfg(any(target_os = "windows", target_os = "macos"))]
use hbb_common::tokio::sync::mpsc::unbounded_channel;
#[cfg(any(target_os = "windows", target_os = "linux"))]
use hbb_common::ResultType;
use hbb_common::{
    allow_err, log,
    tokio::{self, sync::mpsc::UnboundedReceiver},
};
use lazy_static::lazy_static;
use std::time::{Duration, Instant};
use std::{collections::HashMap, sync::RwLock};

#[cfg(any(target_os = "windows", target_os = "macos"))]
use tao::event_loop::EventLoopProxy;
#[cfg(target_os = "linux")]
use winit::event_loop::EventLoopProxy;

lazy_static! {
    pub(super) static ref EVENT_PROXY: RwLock<Option<EventLoopProxy<(String, CustomEvent)>>> =
        RwLock::new(None);
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
    let (tx_exit, rx_exit) = unbounded_channel();
    std::thread::spawn(move || {
        start_ipc(rx_exit);
    });
    if let Err(e) = super::create_event_loop() {
        log::error!("Failed to create event loop: {}", e);
        tx_exit.send(()).ok();
        return;
    }
}

#[tokio::main(flavor = "current_thread")]
pub(super) async fn start_ipc(mut rx_exit: UnboundedReceiver<()>) {
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
                _ = rx_exit.recv() => {
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
                            handle_new_stream(stream, &mut rx_exit).await;
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
    EVENT_PROXY.read().unwrap().as_ref().map(|ep| {
        allow_err!(ep.send_event((k, evt)));
    });
}

async fn handle_new_stream(
    mut conn: Connection,
    rx_exit: &mut UnboundedReceiver<()>,
) {
    let mut state = WhiteboardIpcState::default();
    loop {
        match rx_exit.try_recv() {
            Ok(_) | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
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
    send_whiteboard_event("".to_string(), CustomEvent::Exit);
}

#[cfg(test)]
mod tests {
    use super::*;

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
