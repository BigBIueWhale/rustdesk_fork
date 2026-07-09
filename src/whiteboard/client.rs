use super::{Cursor, CustomEvent};
use crate::{
    ipc::{self, Data},
    CHILD_PROCESS,
};
use hbb_common::{
    allow_err,
    anyhow::anyhow,
    bail, log, sleep,
    tokio::{
        self,
        sync::mpsc::{unbounded_channel, UnboundedSender},
        time::interval_at,
    },
    ResultType,
};
use lazy_static::lazy_static;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        RwLock,
    },
    time::Instant,
};

lazy_static! {
    static ref TX_WHITEBOARD: RwLock<Option<UnboundedSender<WhiteboardCommand>>> =
        RwLock::new(None);
    static ref CONNS: RwLock<HashMap<i32, Conn>> = Default::default();
    static ref STARTING_WHITEBOARD: AtomicBool = AtomicBool::new(false);
}

#[derive(Clone)]
enum WhiteboardCommand {
    Bind {
        conn_id: i32,
        token: String,
    },
    Event {
        conn_id: i32,
        token: String,
        event: CustomEvent,
    },
    Close {
        conn_id: i32,
        token: String,
    },
    Shutdown,
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

pub fn register_whiteboard(conn_id: i32) {
    if conn_id <= 0 {
        log::warn!("Rejecting whiteboard registration for invalid connection id {conn_id}");
        return;
    }
    let mut bind = None;
    {
        let mut conns = CONNS.write().unwrap();
        if !conns.contains_key(&conn_id) {
            let token = crate::encode64(hbb_common::rand::random::<[u8; 32]>());
            conns.insert(
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
            bind = Some(WhiteboardCommand::Bind { conn_id, token });
        }
    }
    std::thread::spawn(|| {
        allow_err!(start_whiteboard_());
    });
    if let Some(command) = bind {
        send_whiteboard_command(command);
    }
}

pub fn unregister_whiteboard(conn_id: i32) {
    let (command, is_conns_empty) = {
        let mut conns = CONNS.write().unwrap();
        let command = conns.remove(&conn_id).map(|conn| WhiteboardCommand::Close {
            conn_id,
            token: conn.token,
        });
        (command, conns.is_empty())
    };

    if let Some(command) = command {
        send_whiteboard_command(command);
    }
    if is_conns_empty {
        send_whiteboard_command(WhiteboardCommand::Shutdown);
    }
}

pub fn update_whiteboard(conn_id: i32, e: CustomEvent) {
    let mut conns = CONNS.write().unwrap();
    let Some(conn) = conns.get_mut(&conn_id) else {
        return;
    };
    match &e {
        CustomEvent::Cursor(cursor) => {
            conn.last_cursor_evt.c += 1;
            conn.last_cursor_evt.tm = Instant::now();
            if cursor.btns == 0 {
                // Send one movement event every 4.
                if conn.last_cursor_evt.c > 3 {
                    conn.last_cursor_evt.c = 0;
                    conn.last_cursor_evt.evt = None;
                    tx_send_event(conn, conn_id, e);
                } else {
                    conn.last_cursor_evt.evt = Some(e);
                }
            } else {
                if let Some(evt) = conn.last_cursor_evt.evt.take() {
                    tx_send_event(conn, conn_id, evt);
                    conn.last_cursor_evt.c = 0;
                }
                let click_evt = CustomEvent::Cursor(Cursor {
                    x: conn.last_cursor_pos.0,
                    y: conn.last_cursor_pos.1,
                    argb: cursor.argb,
                    btns: cursor.btns,
                    text: cursor.text.clone(),
                });
                tx_send_event(conn, conn_id, click_evt);
            }
        }
        _ => {
            tx_send_event(conn, conn_id, e);
        }
    }
}

#[inline]
fn tx_send_event(conn: &mut Conn, conn_id: i32, event: CustomEvent) {
    if let CustomEvent::Cursor(cursor) = &event {
        if cursor.btns == 0 {
            conn.last_cursor_pos = (cursor.x, cursor.y);
        }
    }

    send_whiteboard_command(WhiteboardCommand::Event {
        conn_id,
        token: conn.token.clone(),
        event,
    });
}

fn send_whiteboard_command(command: WhiteboardCommand) {
    TX_WHITEBOARD.read().unwrap().as_ref().map(|tx| {
        allow_err!(tx.send(command));
    });
}

fn close_whiteboard_if_idle() -> bool {
    let conns = CONNS.read().unwrap();
    if !conns.is_empty() {
        return false;
    }
    TX_WHITEBOARD.write().unwrap().take();
    STARTING_WHITEBOARD.store(false, Ordering::SeqCst);
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

#[tokio::main(flavor = "current_thread")]
async fn start_whiteboard_() -> ResultType<()> {
    if TX_WHITEBOARD.read().unwrap().is_some() {
        log::warn!("Whiteboard already started");
        return Ok(());
    }
    if STARTING_WHITEBOARD.swap(true, Ordering::SeqCst) {
        log::warn!("Whiteboard already starting");
        return Ok(());
    }
    let _starting_guard = crate::common::SimpleCallOnReturn {
        b: true,
        f: Box::new(move || {
            STARTING_WHITEBOARD.store(false, Ordering::SeqCst);
        }),
    };

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
    #[allow(unused_mut)]
    #[allow(unused_assignments)]
    let mut args = vec!["--whiteboard"];
    #[allow(unused_mut)]
    #[cfg(target_os = "linux")]
    let mut user = None;

    let run_done;
    if crate::platform::is_root() && !headless_service_user {
        let mut res = Ok(None);
        for _ in 0..10 {
            #[cfg(target_os = "windows")]
            {
                log::debug!("Start whiteboard");
                res = crate::platform::run_as_user_with_env(
                    args.clone(),
                    whiteboard_launch_env(&launch_token),
                );
            }
            #[cfg(target_os = "macos")]
            {
                log::debug!("Start whiteboard");
                res = crate::platform::run_as_user_with_env(
                    args.clone(),
                    whiteboard_launch_env(&launch_token),
                );
            }
            #[cfg(target_os = "linux")]
            {
                log::debug!("Start whiteboard");
                res = crate::platform::run_as_user(
                    args.clone(),
                    user.clone(),
                    whiteboard_launch_env(&launch_token),
                );
            }
            if res.is_ok() {
                break;
            }
            log::error!("Failed to run whiteboard: {res:?}");
            sleep(1.).await;
        }
        if let Some(task) = res? {
            CHILD_PROCESS.lock().unwrap().push(task);
        }
        run_done = true;
    } else {
        run_done = false;
    }
    if !run_done {
        log::debug!("Start whiteboard");
        CHILD_PROCESS.lock().unwrap().push(crate::run_me_with_env(
            args,
            whiteboard_launch_env(&launch_token),
        )?);
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
    let (tx, mut rx) = unbounded_channel();
    let initial_binds = {
        let conns = CONNS.read().unwrap();
        let mut tx_whiteboard = TX_WHITEBOARD.write().unwrap();
        if tx_whiteboard.is_some() {
            log::warn!("Whiteboard already started");
            return Ok(());
        }
        tx_whiteboard.replace(tx.clone());
        for (conn_id, conn) in conns.iter() {
            allow_err!(tx.send(WhiteboardCommand::Bind {
                conn_id: *conn_id,
                token: conn.token.clone(),
            }));
        }
        conns.len()
    };
    if initial_binds == 0 {
        allow_err!(tx.send(WhiteboardCommand::Shutdown));
    }
    let _call_on_ret = crate::common::SimpleCallOnReturn {
        b: true,
        f: Box::new(move || {
            let _ = TX_WHITEBOARD.write().unwrap().take();
        }),
    };

    let dur = tokio::time::Duration::from_millis(300);
    let mut timer = interval_at(tokio::time::Instant::now() + dur, dur);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            res = rx.recv() => {
                match res {
                    Some(WhiteboardCommand::Bind { conn_id, token }) => {
                        allow_err!(stream.send(&Data::WhiteboardBind { conn_id, token }).await);
                        timer.reset();
                    }
                    Some(WhiteboardCommand::Event { conn_id, token, event }) => {
                        allow_err!(stream.send(&Data::WhiteboardEvent { conn_id, token, event }).await);
                        timer.reset();
                    }
                    Some(WhiteboardCommand::Close { conn_id, token }) => {
                        allow_err!(stream.send(&Data::WhiteboardClose { conn_id, token }).await);
                        timer.reset();
                    }
                    Some(WhiteboardCommand::Shutdown) => {
                        if close_whiteboard_if_idle() {
                            break;
                        }
                    }
                    None => {
                        bail!("expected");
                    }
                }
            },
            _ = timer.tick() => {
                let pending = {
                    let mut conns = CONNS.write().unwrap();
                    let mut pending = Vec::new();
                    for (k, conn) in conns.iter_mut() {
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
                    allow_err!(
                        stream
                            .send(&Data::WhiteboardEvent {
                                conn_id,
                                token,
                                event,
                            })
                            .await
                    );
                }
            }
        }
    }
    allow_err!(stream.send(&Data::WhiteboardShutdown).await);
    Ok(())
}
