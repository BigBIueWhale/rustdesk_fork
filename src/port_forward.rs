use std::sync::{Arc, RwLock};

use crate::client::{Client, Data, Interface, LoginConfigHandler};
use hbb_common::{
    allow_err, bail,
    config::READ_TIMEOUT,
    futures::{SinkExt, StreamExt},
    log,
    message_proto::*,
    protobuf::Message as _,
    rendezvous_proto::ConnType,
    tcp, timeout,
    tokio::{self, net::TcpStream, sync::mpsc},
    tokio_util::codec::{BytesCodec, Framed},
    ResultType, Stream,
};

// R-F1/R-D6: the RDP convenience — launch the local Windows RDP client (mstsc) pointed at the
// tunnel's ephemeral local port, seeding cmdkey with any supplied rdp_username/rdp_password. Compiles
// cross-platform (cmdkey/mstsc simply fail closed off Windows, where the operator dials 127.0.0.1:port
// with their own client). Unlike upstream this does NOT `println!` the cmdkey args — those include
// `/pass:<rdp_password>`, and the hardened fork does not leak the RDP credential to stdout.
fn run_rdp(port: u16) {
    std::process::Command::new("cmdkey")
        .arg("/delete:localhost")
        .output()
        .ok();
    let username = std::env::var("rdp_username").unwrap_or_default();
    let password = std::env::var("rdp_password").unwrap_or_default();
    if !username.is_empty() || !password.is_empty() {
        let mut args = vec!["/generic:localhost".to_owned()];
        if !username.is_empty() {
            args.push(format!("/user:{}", username));
        }
        if !password.is_empty() {
            args.push(format!("/pass:{}", password));
        }
        std::process::Command::new("cmdkey")
            .args(&args)
            .output()
            .ok();
    }
    std::process::Command::new("mstsc")
        .arg(format!("/v:localhost:{}", port))
        .spawn()
        .ok();
}

// R-F1/R-D6/R-S5: the viewer-side port-forward/RDP tunnel. Bind a LOCAL 127.0.0.1 listener (never
// exposed off-box); for each accepted local connection, establish a fresh PAKE-keyed session to the
// box (Client::start) and relay the raw local bytes <-> the SEALED session stream. R-S5 option 1: the
// tunnel rides the secretbox — the relay never set_raw's (a downgrade that would panic on the keyed
// stream, tcp.rs R-A3), so every wire-bound byte is ciphertext (R-A9). connect_and_login asserts
// is_secured() before a single byte is tunnelled (§4.4 fail-closed).
pub async fn listen(
    id: String,
    password: String,
    port: i32,
    interface: impl Interface,
    ui_receiver: mpsc::UnboundedReceiver<Data>,
    key: &str,
    token: &str,
    lc: Arc<RwLock<LoginConfigHandler>>,
    remote_host: String,
    remote_port: i32,
) -> ResultType<()> {
    // 127.0.0.1 only — the tunnel entry point is a loopback listener, never bound to a public
    // interface (direct-IP-only, R-SV4/R-F4).
    let listener = tcp::new_listener(format!("127.0.0.1:{}", port), true).await?;
    let addr = listener.local_addr()?;
    log::info!("listening on port {:?}", addr);
    let is_rdp = port == 0;
    if is_rdp {
        run_rdp(addr.port());
    }
    let mut ui_receiver = ui_receiver;
    loop {
        tokio::select! {
            Ok((forward, addr)) = listener.accept() => {
                log::info!("new connection from {:?}", addr);
                lc.write().unwrap().port_forward = (remote_host.clone(), remote_port);
                let id = id.clone();
                let password = password.clone();
                let mut forward = Framed::new(forward, BytesCodec::new());
                match connect_and_login(&id, &password, &mut ui_receiver, interface.clone(), &mut forward, key, token, is_rdp).await {
                    Ok(Some(stream)) => {
                        let interface = interface.clone();
                        tokio::spawn(async move {
                            if let Err(err) = run_forward(forward, stream).await {
                                interface.msgbox("error", "Error", &err.to_string(), "");
                            }
                            log::info!("connection from {:?} closed", addr);
                        });
                    }
                    Err(err) => {
                        interface.on_establish_connection_error(err.to_string());
                    }
                    _ => {}
                }
            }
            d = ui_receiver.recv() => {
                match d {
                    Some(Data::Close) => {
                        break;
                    }
                    Some(Data::NewRDP) => {
                        run_rdp(addr.port());
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

// Establish a PAKE-keyed session to the box and drive it to a successful login, then hand back the
// KEYED stream for the raw relay. The fork's `Client::start` already runs the single mandatory CPace
// handshake (keying the stream + verifying/pinning the box's Ed25519 host key) and sends the login
// PROACTIVELY (empty-password, CPace-authenticated), so there is NO legacy `Hash` challenge to answer
// here (R-T15c). `_password` is consumed at keying time via the interface (Session::get_connect_password
// folds it into the PRS), not in this function — it stays only for signature parity with the caller.
async fn connect_and_login(
    id: &str,
    _password: &str,
    ui_receiver: &mut mpsc::UnboundedReceiver<Data>,
    interface: impl Interface,
    forward: &mut Framed<TcpStream, BytesCodec>,
    key: &str,
    token: &str,
    is_rdp: bool,
) -> ResultType<Option<Stream>> {
    let conn_type = if is_rdp {
        ConnType::RDP
    } else {
        ConnType::PORT_FORWARD
    };
    let ((mut stream, direct, _pk, _stream_type), (_feedback, _rendezvous_server)) =
        Client::start(id, key, token, conn_type, interface.clone()).await?;
    interface.update_direct(Some(direct));

    // R-S5 note / R-S13 (§4.4): the fork's direct-IP initiator MUST tunnel only over a PAKE-keyed
    // stream. `Client::start`/`_start` already key and assert is_secured, but assert AGAIN here —
    // before a single tunnelled byte, at the exact choke where the raw relay begins — and abort
    // fail-closed otherwise. A forward that rode an unkeyed stream would put the RDP/port-forward
    // payload on the wire in plaintext, exactly the leak R-A9 forbids.
    if !stream.is_secured() {
        bail!("R-S5/R-S13: refusing to port-forward over an unkeyed stream (fail-closed)");
    }

    let mut buffer = Vec::new();
    let mut received = false;

    loop {
        tokio::select! {
            res = timeout(READ_TIMEOUT, stream.next()) => match res {
                Err(_) => {
                    bail!("Timeout");
                }
                Ok(Some(Ok(bytes))) => {
                    if !received {
                        received = true;
                        interface.update_received(true);
                    }
                    let msg_in = Message::parse_from_bytes(&bytes)?;
                    match msg_in.union {
                        Some(message::Union::LoginResponse(lr)) => match lr.union {
                            Some(login_response::Union::Error(err)) => {
                                if !interface.handle_login_error(&err) {
                                    return Ok(None);
                                }
                            }
                            Some(login_response::Union::PeerInfo(pi)) => {
                                interface.handle_peer_info(pi);
                                break;
                            }
                            _ => {}
                        },
                        // R-F1/R-S5/R-A9: do NOT reply to a latency-probe TestDelay in port-forward
                        // mode. The box switches to the raw tunnel relay the instant it authorizes
                        // (connection.rs breaks to try_port_forward_loop), so a TestDelay reply sent
                        // afterwards would be relayed as DATA into the forwarded (RDP) stream and
                        // corrupt it. The port-forward viewer commits to the tunnel and silently drops
                        // TestDelay (a port forward has no video QoS to tune). The frame is still
                        // consumed here (read + dropped), so it never leaks into run_forward either.
                        Some(message::Union::TestDelay(_t)) => {}
                        _ => {}
                    }
                }
                Ok(Some(Err(err))) => {
                    bail!("Connection closed: {}", err);
                }
                _ => {
                    bail!("Reset by the peer");
                }
            },
            d = ui_receiver.recv() => {
                match d {
                    Some(Data::Login((password, remember))) => {
                        interface.handle_login_from_ui(password, remember, &mut stream).await;
                    }
                    Some(Data::Message(msg)) => {
                        allow_err!(stream.send(&msg).await);
                    }
                    _ => {}
                }
            },
            res = forward.next() => {
                if let Some(Ok(bytes)) = res {
                    buffer.extend(bytes);
                } else {
                    return Ok(None);
                }
            },
        }
    }
    // R-A3/R-S5/R-A9: NO `stream.set_raw()` — the tunnel stays on the KEYED framed stream so every
    // relayed byte is sealed by the secretbox. `set_raw()` would panic on a keyed stream (tcp.rs
    // R-A3). Flush any bytes the local client already sent during the login handshake through the
    // SEALED path (`send_bytes` seals on the keyed stream).
    if !buffer.is_empty() {
        allow_err!(stream.send_bytes(buffer.into()).await);
    }
    Ok(Some(stream))
}

// The raw relay: shuttle bytes between the LOCAL socket (`forward`, plaintext to the operator's RDP /
// port-forward client) and the KEYED session `stream`. `send_bytes` SEALS on the keyed stream, so the
// wire bytes are ciphertext (R-A9); `stream.next()` yields already-DECRYPTED frames. No `set_raw` —
// the secretbox rides the whole tunnel end-to-end.
async fn run_forward(forward: Framed<TcpStream, BytesCodec>, stream: Stream) -> ResultType<()> {
    log::info!("new port forwarding connection started");
    let mut forward = forward;
    let mut stream = stream;
    loop {
        tokio::select! {
            res = forward.next() => {
                if let Some(Ok(bytes)) = res {
                    // local client -> SEAL (send_bytes on the keyed stream) -> box (ciphertext).
                    allow_err!(stream.send_bytes(bytes.into()).await);
                } else {
                    break;
                }
            },
            res = stream.next() => {
                if let Some(Ok(bytes)) = res {
                    // box -> next() already DECRYPTED the frame -> local client.
                    allow_err!(forward.send(bytes).await);
                } else {
                    break;
                }
            },
        }
    }
    Ok(())
}
