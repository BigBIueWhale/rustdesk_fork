use crate::client::*;
use async_trait::async_trait;
use hbb_common::{
    config::PeerConfig,
    config::READ_TIMEOUT,
    futures::{SinkExt, StreamExt},
    log,
    message_proto::*,
    protobuf::Message as _,
    rendezvous_proto::ConnType,
    tokio::{self, sync::mpsc},
    Stream,
};
use std::sync::{Arc, RwLock};

#[derive(Clone)]
pub struct Session {
    id: String,
    lc: Arc<RwLock<LoginConfigHandler>>,
    sender: mpsc::UnboundedSender<Data>,
    password: String,
}

impl Session {
    pub fn new(id: &str, conn_type: ConnType, sender: mpsc::UnboundedSender<Data>) -> Self {
        let mut password = "".to_owned();
        if PeerConfig::load(id).password.is_empty() {
            match rpassword::prompt_password("Enter password: ") {
                Ok(p) => password = p,
                Err(e) => {
                    log::error!("Failed to read password: {:?}", e);
                    password = "".to_owned();
                }
            }
        }
        let session = Self {
            id: id.to_owned(),
            sender,
            password,
            lc: Default::default(),
        };
        session
            .lc
            .write()
            .unwrap()
            .initialize(id.to_owned(), conn_type, None, None);
        session
    }
}

#[async_trait]
impl Interface for Session {
    fn get_lch(&self) -> Arc<RwLock<LoginConfigHandler>> {
        self.lc.clone()
    }

    fn get_connect_password(&self) -> String {
        let password = self.lc.read().unwrap().connect_password.clone();
        if password.is_empty() {
            self.password.clone()
        } else {
            password
        }
    }

    fn set_multiple_windows_session(&self, sessions: Vec<WindowsSession>) {
        log::warn!(
            "CLI viewer cannot select among {} Windows sessions",
            sessions.len()
        );
    }

    fn msgbox(&self, msgtype: &str, title: &str, text: &str, _link: &str) {
        // R-A1/R-S18: CPace is the sole authenticator — the responder never asks the CLI to
        // (re-)enter a login password over a keyed stream, so the `input-password` /
        // `re-input-password` prompt arms are excised. The pre-keying password (if any) is read
        // once in `Session::new`. Remaining message types are logged.
        match msgtype {
            msg if msg.contains("error") => {
                log::error!("{}: {}: {}", msgtype, title, text);
            }
            _ => {
                log::info!("{}: {}: {}", msgtype, title, text);
            }
        }
    }

    fn handle_login_error(&self, err: &str) -> bool {
        handle_login_error(err, self)
    }

    fn handle_peer_info(&self, pi: PeerInfo) {
        self.lc.write().unwrap().handle_peer_info(&pi);
    }

    async fn handle_login_from_ui(&self, password: String, remember: bool, peer: &mut Stream) {
        handle_login_from_ui(self.lc.clone(), password, remember, peer).await;
    }

    async fn handle_test_delay(&self, t: TestDelay, peer: &mut Stream) {
        handle_test_delay(t, peer).await;
    }

    fn send(&self, data: Data) {
        self.sender.send(data).ok();
    }
}

#[tokio::main(flavor = "current_thread")]
pub async fn connect_test(id: &str, key: String, token: String) {
    let (sender, mut receiver) = mpsc::unbounded_channel::<Data>();
    let handler = Session::new(&id, ConnType::DEFAULT_CONN, sender);
    match crate::client::Client::start(id, &key, &token, ConnType::DEFAULT_CONN, handler).await {
        Err(err) => {
            log::error!("Failed to connect {}: {}", &id, err);
        }
        Ok((mut stream, stream_type)) => {
            log::info!("stream: {}", stream_type);
            // rpassword::prompt_password("Input anything to exit").ok();
            loop {
                tokio::select! {
                    res = hbb_common::timeout(READ_TIMEOUT, stream.next()) => match res {
                        Err(_) => {
                            log::error!("Timeout");
                            break;
                        }
                        Ok(Some(Ok(bytes))) => {
                            if let Ok(msg_in) = Message::parse_from_bytes(&bytes) {
                                // R-T15c: the server no longer sends a `Hash` challenge to break on
                                // (CPace is the sole authenticator); the loop ends on EOF/timeout.
                                let _ = msg_in.union;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

#[tokio::main(flavor = "current_thread")]
pub async fn start_one_port_forward(
    id: String,
    port: i32,
    remote_host: String,
    remote_port: i32,
    key: String,
    token: String,
) {
    let (sender, _receiver) = mpsc::unbounded_channel::<Data>();
    let handler = Session::new(&id, ConnType::PORT_FORWARD, sender);
    let (_control, receiver) = crate::port_forward::port_forward_control();
    if let Err(err) = crate::port_forward::listen(
        handler.id.clone(),
        port,
        handler.clone(),
        receiver,
        &key,
        &token,
        remote_host,
        remote_port,
    )
    .await
    {
        log::error!("Failed to listen on {}: {}", port, err);
    }
    log::info!("port forward (:{}) exit", port);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_with_password(password: &str) -> Session {
        let (sender, _receiver) = mpsc::unbounded_channel();
        Session {
            id: "127.0.0.1".to_owned(),
            lc: Default::default(),
            sender,
            password: password.to_owned(),
        }
    }

    #[test]
    fn prompted_password_is_available_before_cli_keying() {
        let session = session_with_password("prompted-password");
        assert_eq!(session.get_connect_password(), "prompted-password");
    }

    #[test]
    fn explicit_connect_password_precedes_prompted_password() {
        let session = session_with_password("prompted-password");
        session.lc.write().unwrap().connect_password = "explicit-password".to_owned();
        assert_eq!(session.get_connect_password(), "explicit-password");
    }
}
