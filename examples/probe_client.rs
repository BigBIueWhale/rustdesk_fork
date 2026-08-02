//! TEST-ONLY CPace-initiator probe for the docker-loopback runtime tests. NOT shipped.
//!
//! Connects to a loopback `--server`, runs the CPace handshake (`run_initiator`) with a password,
//! and reports whether KEYING succeeded — runtime-validating, end-to-end against the REAL server:
//!   - R-A1 / R-S1   : the mandatory CPace keying choke-point — a correct password keys;
//!   - R-P3 / R-P14c : a WRONG password is refused (key-confirmation fails, no key derived).
//! (CPace keying is the sole gate; there is no source-IP ACL — the probe keys on the correct password.)
//!
//! 4th arg modes (after keying):
//!   - `read`   : engage the session keys and read the post-key keyed session flow;
//!   - `login`  : also send a minimal `LoginRequest` (CPace already authenticated, so the password
//!                proof is collapsed — empty `password`) with the exact current video-receipt
//!                capability to drive the post-key Remote login flow. It succeeds only after an
//!                exact receipt-version PeerInfo or the pinned headless image's post-authorization
//!                `connection refused` display error. Its
//!                `my_id` is the ASCII canary `PLAINTEXT-CANARY-DEADBEEF` so the R-A9 wire-capture
//!                test can assert it NEVER appears on the wire (the post-key frame is AEAD-sealed);
//!   - `inject` : R-A8/R-T7 — after keying, corrupt the engaged SEND key, then send a frame
//!                and send a forged frame; the server's AEAD MUST reject it (`decryption error`);
//!   - `filetransfer` : R-F1/R-F2 — send a FileTransfer `LoginRequest`, then a `ReadDir("")`, and
//!                report the `PeerInfo` (its `username` MUST be NON-EMPTY on a headless unix
//!                `--server` — the process-owner fallback — never the "No active console user"
//!                refusal) plus any directory `FileResponse`.
//!
//! 5th arg (optional) = local source address, e.g. `127.0.0.2:0`, to connect as a DIFFERENT source
//! for the R-A8.2 owner-safe-limiter test (a guess-flood from one source must not block another).
//!
//! Usage: `probe_client <addr> <password> <ok|fail> [read|login|inject|portforward|filetransfer] [local_addr]`  (exit 0 = matched)
use hbb_common::cpace::run_initiator;
use hbb_common::message_proto::{login_response, message, Message};
use hbb_common::protobuf::Message as _; // parse_from_bytes / write_to_bytes
use hbb_common::tcp::FramedStream;

fn remote_login_admission(response: &login_response::Union) -> Option<&'static str> {
    match response {
        login_response::Union::PeerInfo(peer)
            if peer.video_frame_receipt_version == hbb_common::VIDEO_FRAME_RECEIPT_VERSION =>
        {
            Some("peer-info")
        }
        login_response::Union::Error(error) if error == "connection refused" => {
            Some("headless-display-error")
        }
        _ => None,
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let addr = a
        .get(1)
        .cloned()
        .expect("usage: probe_client <addr> <password> <ok|fail> [read|login]");
    let pw = a.get(2).cloned().expect("password");
    let expect = a.get(3).map(String::as_str).unwrap_or("ok").to_string();
    let mode = a.get(4).map(String::as_str).unwrap_or("").to_string();
    let do_read = mode == "read"
        || mode == "login"
        || mode == "inject"
        || mode == "portforward"
        || mode == "filetransfer";
    // Optional local source address (6th arg) — e.g. 127.0.0.2:0 to connect as a DIFFERENT source,
    // for the R-A8.2 owner-safe limiter test (a flood from one source must not block another).
    let local = a
        .get(5)
        .and_then(|s| s.parse::<std::net::SocketAddr>().ok());

    // R-P1: the CPace PRS is base64(Argon2id(NFC(pw), fixed salt)) — a faithful viewer derives it
    // from the password alone (nothing per-box in the salt). This loopback probe shares the server's
    // config dir ($HOME) and derives the SAME PRS the server stored at provisioning. A WRONG password
    // derives a DIFFERENT PRS ⇒ CPace key-confirmation fails (the `fail` path) — exactly as for a real
    // viewer. This is the decisive two-process keying proof: viewer-derived PRS == server-stored PRS.
    let prs = hbb_common::config::derive_cpace_prs(&pw).unwrap_or_default();

    let rt = hbb_common::tokio::runtime::Runtime::new().expect("tokio runtime");
    let (keyed, postkey, file_transfer_ok, remote_login_ok) = rt.block_on(async {
        let mut stream = match FramedStream::new(&addr, local, 5000).await {
            Ok(s) => s,
            Err(e) => {
                println!("probe_client: CONNECT_FAIL {e}");
                std::process::exit(2);
            }
        };
        match run_initiator(&mut stream, &prs).await {
            Ok(keys) => {
                let mut pk = String::new();
                let mut remote_login_ok = mode != "login";
                if do_read {
                    stream.set_session_keys(keys); // engage the two-key cipher
                    if mode == "portforward" {
                        // R-F1/R-D6/R-S5/R-A9 END-TO-END: drive a REAL port-forward tunnel against the
                        // live server. Send a PortForward LoginRequest naming the LOCAL target the box
                        // will dial (PF_TARGET = the pf_echo server), wait for PeerInfo (the box
                        // authorized + dialed the target + switched to try_port_forward_loop), then send
                        // a canary THROUGH the tunnel and expect it echoed back — proving the restored
                        // relay shuttles sealed bytes both ways (login-grant + dial + break + relay).
                        use hbb_common::message_proto::{LoginRequest, PortForward};
                        let target = std::env::var("PF_TARGET").unwrap_or_default();
                        let (thost, tport) = target
                            .rsplit_once(':')
                            .map(|(h, p)| (h.to_string(), p.parse::<i32>().unwrap_or(0)))
                            .unwrap_or_default();
                        let mut lr = LoginRequest::new();
                        lr.username = addr.clone();
                        lr.my_id = "pf-probe".to_string();
                        lr.my_name = "pf-probe".to_string();
                        lr.version = "1.4.0".to_string();
                        lr.my_platform = "Linux".to_string();
                        lr.set_port_forward(PortForward {
                            host: thost,
                            port: tport,
                            ..Default::default()
                        });
                        let mut msg = Message::new();
                        msg.set_login_request(lr);
                        let _ = stream.send_raw(msg.write_to_bytes().unwrap_or_default()).await;
                        // Wait for PeerInfo (a latency-probe TestDelay is skipped, never replied to —
                        // exactly as the real port-forward viewer does, so no reply is injected).
                        let mut authed = false;
                        for _ in 0..8 {
                            match stream.next_timeout(4000).await {
                                Some(Ok(bytes)) => {
                                    match Message::parse_from_bytes(&bytes).map(|m| m.union) {
                                        Ok(Some(message::Union::LoginResponse(r))) => match r.union {
                                            Some(login_response::Union::PeerInfo(_)) => {
                                                authed = true;
                                                break;
                                            }
                                            Some(login_response::Union::Error(e)) => {
                                                pk.push_str(&format!("[PF-LOGIN-ERROR {e}] "));
                                                break;
                                            }
                                            _ => {}
                                        },
                                        Ok(Some(message::Union::TestDelay(_))) => {} // ignore, no reply
                                        _ => {}
                                    }
                                }
                                _ => {
                                    pk.push_str("[PF-NO-PEERINFO] ");
                                    break;
                                }
                            }
                        }
                        if authed {
                            const CANARY: &[u8] =
                                b"PF-RELAY-CANARY-abcdef-0123456789-through-the-sealed-tunnel";
                            let _ = stream.send_raw(CANARY.to_vec()).await;
                            // Reassemble until the full canary echoes back (localhost won't fragment
                            // ~58 bytes, but be robust to a split read).
                            let mut got = Vec::new();
                            for _ in 0..4 {
                                match stream.next_timeout(4000).await {
                                    Some(Ok(b)) => {
                                        got.extend_from_slice(&b);
                                        if got == CANARY {
                                            break;
                                        }
                                    }
                                    _ => break,
                                }
                            }
                            if got == CANARY {
                                pk.push_str("[PF-RELAY-ECHO-OK] ");
                            } else {
                                pk.push_str(&format!("[PF-RELAY-ECHO-FAIL got={}B] ", got.len()));
                            }
                        }
                    }
                    if mode == "login" {
                        use hbb_common::message_proto::LoginRequest;
                        let mut lr = LoginRequest::new();
                        lr.username = addr.clone();
                        // A distinctive ASCII canary so the R-A9 wire-capture test can assert it
                        // NEVER appears on the wire (the post-key LoginRequest is encrypted).
                        lr.my_id = "PLAINTEXT-CANARY-DEADBEEF".to_string();
                        lr.my_name = "probe".to_string();
                        lr.version = "1.4.0".to_string();
                        lr.my_platform = "Linux".to_string();
                        lr.video_frame_receipt_version =
                            hbb_common::VIDEO_FRAME_RECEIPT_VERSION;
                        let mut msg = Message::new();
                        msg.set_login_request(lr);
                        let remote_login_bytes = match msg.write_to_bytes() {
                            Ok(bytes) => bytes,
                            Err(err) => {
                                pk.push_str(&format!("[REMOTE-LOGIN-SERIALIZE-ERROR {err}] "));
                                return (true, pk, true, false);
                            }
                        };
                        if let Err(err) = stream.send_raw(remote_login_bytes).await {
                            pk.push_str(&format!("[REMOTE-LOGIN-SEND-ERROR {err}] "));
                            return (true, pk, true, false);
                        }
                    }
                    if mode == "filetransfer" {
                        // R-F1/R-F2 END-TO-END against a headless unix --server. Before the fix this box
                        // (no logind/console session) reported an EMPTY PeerInfo.username and the viewer
                        // refused file transfer with "No active console user logged on". The server now
                        // falls back to the --server process owner, so the keyed FileTransfer login MUST
                        // yield a PeerInfo whose username is NON-EMPTY — never that refusal. A ReadDir("")
                        // then drives the file path (served in the CM process at service privilege; its
                        // dir FileResponse is reported if the CM round-trips).
                        use hbb_common::message_proto::{file_response, FileAction, FileTransfer, LoginRequest, ReadDir};
                        let mut lr = LoginRequest::new();
                        lr.username = addr.clone();
                        lr.my_id = "ft-probe".to_string();
                        lr.my_name = "ft-probe".to_string();
                        lr.version = "1.4.0".to_string();
                        lr.my_platform = "Linux".to_string();
                        lr.set_file_transfer(FileTransfer {
                            dir: "".to_string(),
                            show_hidden: false,
                            ..Default::default()
                        });
                        let mut msg = Message::new();
                        msg.set_login_request(lr);
                        let login_bytes = match msg.write_to_bytes() {
                            Ok(bytes) => bytes,
                            Err(err) => {
                                pk.push_str(&format!("[FT-LOGIN-SERIALIZE-ERROR {err}] "));
                                return (true, pk, false, true);
                            }
                        };
                        if let Err(err) = stream.send_raw(login_bytes).await {
                            pk.push_str(&format!("[FT-LOGIN-SEND-ERROR {err}] "));
                            return (true, pk, false, true);
                        }
                        let mut sent_readdir = false;
                        let mut peer_username_nonempty = false;
                        let mut readdir_send_ok = true;
                        for _ in 0..10 {
                            let bytes = match stream.next_timeout(4000).await {
                                Some(Ok(b)) => b,
                                _ => {
                                    pk.push_str("[FT-NO-RESPONSE] ");
                                    break;
                                }
                            };
                            match Message::parse_from_bytes(&bytes).map(|m| m.union) {
                                Ok(Some(message::Union::LoginResponse(r))) => match r.union {
                                    Some(login_response::Union::PeerInfo(peer)) => {
                                        peer_username_nonempty = !peer.username.is_empty();
                                        pk.push_str(&format!(
                                            "[FT-PEERINFO username_nonempty={} username={:?} platform={:?}] ",
                                            !peer.username.is_empty(),
                                            peer.username,
                                            peer.platform
                                        ));
                                        if !sent_readdir {
                                            let mut fa = FileAction::new();
                                            fa.set_read_dir(ReadDir {
                                                path: "".to_string(),
                                                include_hidden: false,
                                                ..Default::default()
                                            });
                                            let mut m = Message::new();
                                            m.set_file_action(fa);
                                            let readdir_bytes = match m.write_to_bytes() {
                                                Ok(bytes) => bytes,
                                                Err(err) => {
                                                    pk.push_str(&format!("[FT-READDIR-SERIALIZE-ERROR {err}] "));
                                                    readdir_send_ok = false;
                                                    break;
                                                }
                                            };
                                            if let Err(err) = stream.send_raw(readdir_bytes).await {
                                                pk.push_str(&format!("[FT-READDIR-SEND-ERROR {err}] "));
                                                readdir_send_ok = false;
                                                break;
                                            }
                                            sent_readdir = true;
                                        }
                                    }
                                    Some(login_response::Union::Error(e)) => {
                                        pk.push_str(&format!("[FT-LOGIN-ERROR {e}] "));
                                        break;
                                    }
                                    _ => {}
                                },
                                Ok(Some(message::Union::FileResponse(fr))) => match fr.union {
                                    Some(file_response::Union::Dir(d)) => {
                                        pk.push_str(&format!(
                                            "[FT-DIR-RESPONSE path={:?} entries={}] ",
                                            d.path,
                                            d.entries.len()
                                        ));
                                        break;
                                    }
                                    Some(file_response::Union::Error(e)) => {
                                        pk.push_str(&format!("[FT-FILE-ERROR {e:?}] "));
                                        break;
                                    }
                                    _ => {}
                                },
                                _ => {}
                            }
                        }
                        if !peer_username_nonempty || !readdir_send_ok {
                            return (true, pk, false, true);
                        }
                    }
                    // The generic post-key frame dump is for read/login/inject only; a port-forward
                    // tunnel already did its round-trip above, and its post-PeerInfo bytes are RAW
                    // relay data (not Messages), so skip the dump there.
                    for i in 0..6 {
                        if mode == "portforward" || mode == "filetransfer" {
                            break;
                        }
                        match stream.next_timeout(3000).await {
                            Some(Ok(bytes)) => {
                                let parsed = Message::parse_from_bytes(&bytes);
                                if mode == "login" {
                                    if let Ok(parsed_message) = &parsed {
                                        if let Some(message::Union::LoginResponse(response)) =
                                            &parsed_message.union
                                        {
                                            match response.union.as_ref() {
                                                Some(response) => {
                                                    if let Some(outcome) =
                                                        remote_login_admission(response)
                                                    {
                                                        remote_login_ok = true;
                                                        pk.push_str(&format!(
                                                            "[REMOTE-LOGIN-ADMITTED {outcome}] "
                                                        ));
                                                    } else {
                                                        pk.push_str(&format!(
                                                            "[REMOTE-LOGIN-REJECTED {response:?}] "
                                                        ));
                                                    }
                                                }
                                                None => pk.push_str(
                                                    "[REMOTE-LOGIN-REJECTED empty-response] ",
                                                ),
                                            }
                                        }
                                    }
                                }
                                let u = match parsed {
                                    Ok(m) => format!("{:?}", m.union)
                                        .chars()
                                        .take(140)
                                        .collect::<String>(),
                                    Err(e) => format!("PARSE_ERR {e}"),
                                };
                                pk.push_str(&format!("[{i} len={} {u}] ", bytes.len()));
                            }
                            Some(Err(e)) => {
                                pk.push_str(&format!("[{i}=READ_ERR {e}] "));
                                break;
                            }
                            None => {
                                pk.push_str(&format!("[{i}=TIMEOUT] "));
                                break;
                            }
                        }
                    }
                    if mode == "login" && !remote_login_ok {
                        pk.push_str("[REMOTE-LOGIN-NOT-ADMITTED] ");
                    }
                    if mode == "inject" {
                        // R-A8 / R-T7: POST-KEY injection. Garble the engaged SEND key (the recv
                        // direction is untouched — a benign, local, send-only corruption) and send a
                        // frame on the KEYED stream. The server still holds the REAL keys, so its
                        // AEAD MUST reject the frame fail-closed (secretbox::open fails the Poly1305
                        // tag), poison the recv direction, and tear the connection down — an
                        // unauthenticated/forged frame MUST NEVER reach the application parser.
                        // (Pre-R-T3 this re-keyed via set_session_keys; keying is now one-shot, so
                        // the forged frame comes from a deliberately-corrupted send key instead.)
                        stream.corrupt_send_key_for_test();
                        let _ = stream.send_raw(b"INJECTED-GARBAGE-KEY-FRAME".to_vec()).await;
                        pk.push_str("[sent a garbage-key frame] ");
                        // Hold briefly so the server processes + logs the AEAD rejection.
                        let _ = stream.next_timeout(2500).await;
                    }
                }
                (true, pk, true, remote_login_ok)
            }
            Err(_) => (false, String::new(), false, false),
        }
    });

    println!("probe_client: keying ok={keyed} (expected={expect})");
    if do_read {
        println!("probe_client: post-key = {postkey}");
    }

    let keying_matches = match expect.as_str() {
        "ok" => keyed,
        "fail" => !keyed,
        _ => false,
    };
    let pass = keying_matches
        && (mode != "filetransfer" || file_transfer_ok)
        && (mode != "login" || remote_login_ok);
    if pass {
        println!("probe_client: PASS");
    } else {
        println!("probe_client: FAIL");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::message_proto::PeerInfo;

    #[test]
    fn remote_login_admission_requires_current_protocol_or_exact_headless_error() {
        let mut peer = PeerInfo::new();
        peer.video_frame_receipt_version = hbb_common::VIDEO_FRAME_RECEIPT_VERSION;
        assert_eq!(
            remote_login_admission(&login_response::Union::PeerInfo(peer.clone())),
            Some("peer-info")
        );

        peer.video_frame_receipt_version = 0;
        assert_eq!(
            remote_login_admission(&login_response::Union::PeerInfo(peer)),
            None
        );
        assert_eq!(
            remote_login_admission(&login_response::Union::Error(
                "connection refused".to_owned()
            )),
            Some("headless-display-error")
        );
        assert_eq!(
            remote_login_admission(&login_response::Union::Error(
                "Incompatible remote video protocol. Upgrade both RustDesk peers.".to_owned()
            )),
            None
        );
    }
}
