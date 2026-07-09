use super::CustomEvent;
use crate::ipc::{self, new_listener, Connection, Data};
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
                            let mut stream = Connection::new(stream);
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
                            tokio::spawn(handle_new_stream(stream));
                        }
                        Err(err) => {
                            log::error!("Couldn't get whiteboard client: {:?}", err);
                        }
                    },
                    None => {
                        log::error!("Failed to get whiteboard client");
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
    fn apply(&mut self, data: Data) -> Option<WhiteboardIpcAction> {
        match data {
            Data::WhiteboardBind { conn_id, token } => {
                if conn_id > 0 && !token.is_empty() {
                    self.active.insert(conn_id, token);
                }
                None
            }
            Data::WhiteboardEvent {
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
            Data::WhiteboardClose { conn_id, token } => {
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
            Data::WhiteboardShutdown => {
                if self.active.is_empty() {
                    Some(WhiteboardIpcAction::Shutdown)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

fn send_whiteboard_event(k: String, evt: CustomEvent) {
    EVENT_PROXY.read().unwrap().as_ref().map(|ep| {
        allow_err!(ep.send_event((k, evt)));
    });
}

async fn handle_new_stream(mut conn: Connection) {
    let mut state = WhiteboardIpcState::default();
    let shutdown_overlay = loop {
        tokio::select! {
            res = conn.next() => {
                match res {
                    Err(err) => {
                        log::info!("whiteboard ipc connection closed: {}", err);
                        break !state.active.is_empty();
                    }
                    Ok(Some(data)) => {
                        match state.apply(data) {
                            Some(WhiteboardIpcAction::Event(k, evt)) => send_whiteboard_event(k, evt),
                            Some(WhiteboardIpcAction::Shutdown) => {
                                break true;
                            }
                            None => {}
                        }
                    }
                    Ok(None) => {
                        log::info!("whiteboard ipc connection closed");
                        break !state.active.is_empty();
                    }
                }
            }
        }
    };
    if shutdown_overlay {
        send_whiteboard_event("".to_string(), CustomEvent::Exit);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whiteboard_authority_rejects_unbound_events_and_exit() {
        let mut state = WhiteboardIpcState::default();
        assert!(state
            .apply(Data::WhiteboardEvent {
                conn_id: 7,
                token: "token".to_owned(),
                event: CustomEvent::Clear,
            })
            .is_none());
        assert!(state
            .apply(Data::WhiteboardClose {
                conn_id: 7,
                token: "token".to_owned(),
            })
            .is_none());
        assert!(state
            .apply(Data::WhiteboardBind {
                conn_id: 7,
                token: "token".to_owned(),
            })
            .is_none());
        assert!(state
            .apply(Data::WhiteboardEvent {
                conn_id: 7,
                token: "token".to_owned(),
                event: CustomEvent::Exit,
            })
            .is_none());
    }

    #[test]
    fn whiteboard_authority_is_per_connection_token() {
        let mut state = WhiteboardIpcState::default();
        state.apply(Data::WhiteboardBind {
            conn_id: 7,
            token: "alpha".to_owned(),
        });
        state.apply(Data::WhiteboardBind {
            conn_id: 8,
            token: "beta".to_owned(),
        });

        match state.apply(Data::WhiteboardEvent {
            conn_id: 7,
            token: "alpha".to_owned(),
            event: CustomEvent::Clear,
        }) {
            Some(WhiteboardIpcAction::Event(k, CustomEvent::Clear)) => {
                assert_eq!(k, super::super::client::get_key_cursor(7));
            }
            _ => panic!("authorized whiteboard event was not forwarded"),
        }

        assert!(state
            .apply(Data::WhiteboardClose {
                conn_id: 7,
                token: "beta".to_owned(),
            })
            .is_none());
        assert!(state.apply(Data::WhiteboardShutdown).is_none());

        match state.apply(Data::WhiteboardClose {
            conn_id: 7,
            token: "alpha".to_owned(),
        }) {
            Some(WhiteboardIpcAction::Event(k, CustomEvent::Clear)) => {
                assert_eq!(k, super::super::client::get_key_cursor(7));
            }
            _ => panic!("authorized whiteboard close was not forwarded"),
        }
        assert!(state.apply(Data::WhiteboardShutdown).is_none());

        match state.apply(Data::WhiteboardClose {
            conn_id: 8,
            token: "beta".to_owned(),
        }) {
            Some(WhiteboardIpcAction::Event(k, CustomEvent::Clear)) => {
                assert_eq!(k, super::super::client::get_key_cursor(8));
            }
            _ => panic!("second whiteboard close was not forwarded"),
        }
        assert!(matches!(
            state.apply(Data::WhiteboardShutdown),
            Some(WhiteboardIpcAction::Shutdown)
        ));
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
