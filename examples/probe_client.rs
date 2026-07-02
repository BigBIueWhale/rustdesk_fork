//! TEST-ONLY CPace-initiator probe for the docker-loopback runtime tests. NOT shipped.
//!
//! Connects to a loopback `--server`, runs the CPace handshake (`run_initiator`) with a password,
//! and reports whether KEYING succeeded — runtime-validating, end-to-end against the REAL server:
//!   - R-A1 / R-S1   : the mandatory CPace keying choke-point — a correct password keys;
//!   - R-P3 / R-P14c : a WRONG password is refused (key-confirmation fails, no key derived).
//! (CPace keying is the sole gate; there is no source-IP ACL — the probe keys on the correct password.)
//!
//! 4th arg modes (after keying):
//!   - `read`   : engage the session keys and read the post-key flow (the host-proof and the
//!                normal keyed session);
//!   - `login`  : also send a minimal `LoginRequest` (CPace already authenticated, so the password
//!                proof is collapsed — empty `password`) to drive the post-key login flow. Its
//!                `my_id` is the ASCII canary `PLAINTEXT-CANARY-DEADBEEF` so the R-A9 wire-capture
//!                test can assert it NEVER appears on the wire (the post-key frame is AEAD-sealed);
//!   - `inject` : R-A8/R-T7 — after keying, corrupt the engaged SEND key, then send a frame
//!                and send a forged frame; the server's AEAD MUST reject it (`decryption error`).
//!
//! 5th arg (optional) = local source address, e.g. `127.0.0.2:0`, to connect as a DIFFERENT source
//! for the R-A8.2 owner-safe-limiter test (a guess-flood from one source must not block another).
//!
//! Usage: `probe_client <addr> <password> <ok|fail> [read|login|inject] [local_addr]`  (exit 0 = matched)
use hbb_common::cpace::{run_initiator_with_transcript, verify_host_identity};
use hbb_common::message_proto::Message;
use hbb_common::protobuf::Message as _; // parse_from_bytes / write_to_bytes
use hbb_common::tcp::FramedStream;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let addr = a
        .get(1)
        .cloned()
        .expect("usage: probe_client <addr> <password> <ok|fail> [read|login]");
    let pw = a.get(2).cloned().expect("password");
    let expect = a.get(3).map(String::as_str).unwrap_or("ok").to_string();
    let mode = a.get(4).map(String::as_str).unwrap_or("").to_string();
    let do_read = mode == "read" || mode == "login" || mode == "inject" || mode == "portforward";
    // Optional local source address (6th arg) — e.g. 127.0.0.2:0 to connect as a DIFFERENT source,
    // for the R-A8.2 owner-safe limiter test (a flood from one source must not block another).
    let local = a.get(5).and_then(|s| s.parse::<std::net::SocketAddr>().ok());

    // R-P1: the CPace PRS is base64(Argon2id(NFC(pw), salt(host_pubkey))) — a faithful viewer derives
    // it from the box's PINNED host key. This loopback probe shares the server's config dir ($HOME),
    // so it reads the box's own Ed25519 host public key directly (equivalent to having pinned it via
    // `--pin-host`) and derives the SAME PRS the server stored at provisioning. A WRONG password
    // derives a DIFFERENT PRS ⇒ CPace key-confirmation fails (the `fail` path) — exactly as for a real
    // viewer. This is the decisive two-process keying proof: viewer-derived PRS == server-stored PRS.
    let host_pubkey = hbb_common::config::Config::get_key_pair().1;
    let prs = hbb_common::config::derive_cpace_prs(&pw, &host_pubkey).unwrap_or_default();

    let rt = hbb_common::tokio::runtime::Runtime::new().expect("tokio runtime");
    let (keyed, postkey) = rt.block_on(async {
        let mut stream = match FramedStream::new(&addr, local, 5000).await {
            Ok(s) => s,
            Err(e) => {
                println!("probe_client: CONNECT_FAIL {e}");
                std::process::exit(2);
            }
        };
        match run_initiator_with_transcript(&mut stream, &prs).await {
            Ok((keys, transcript)) => {
                let mut pk = String::new();
                if do_read {
                    stream.set_session_keys(keys); // engage the two-key cipher
                    // R-S17: the responder's FIRST post-key frame is its HostIdentity host-proof;
                    // a faithful viewer reads + verifies it (the SSH-known_hosts-style host pin
                    // against substitution) BEFORE anything else.
                    match stream.next_timeout(3000).await {
                        Some(Ok(proof)) => match verify_host_identity(&transcript, &proof) {
                            Ok(_) => pk.push_str("[R-S17 host-proof VERIFIED] "),
                            Err(_) => pk.push_str("[R-S17 host-proof FAILED] "),
                        },
                        _ => pk.push_str("[R-S17 no host-proof] "),
                    }
                    if mode == "portforward" {
                        // R-F1/R-D6/R-S5/R-A9 END-TO-END: drive a REAL port-forward tunnel against the
                        // live server. Send a PortForward LoginRequest naming the LOCAL target the box
                        // will dial (PF_TARGET = the pf_echo server), wait for PeerInfo (the box
                        // authorized + dialed the target + switched to try_port_forward_loop), then send
                        // a canary THROUGH the tunnel and expect it echoed back — proving the restored
                        // relay shuttles sealed bytes both ways (login-grant + dial + break + relay).
                        use hbb_common::message_proto::{login_response, message, LoginRequest, PortForward};
                        let target = std::env::var("PF_TARGET").unwrap_or_default();
                        let (thost, tport) = target
                            .rsplit_once(':')
                            .map(|(h, p)| (h.to_string(), p.parse::<i32>().unwrap_or(0)))
                            .unwrap_or_default();
                        let mut lr = LoginRequest::new();
                        // The box's own id, so the responder's username guard admits the login.
                        lr.username = hbb_common::config::Config::get_id();
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
                        // A distinctive ASCII canary so the R-A9 wire-capture test can assert it
                        // NEVER appears on the wire (the post-key LoginRequest is encrypted).
                        lr.my_id = "PLAINTEXT-CANARY-DEADBEEF".to_string();
                        lr.my_name = "probe".to_string();
                        lr.version = "1.4.0".to_string();
                        lr.my_platform = "Linux".to_string();
                        let mut msg = Message::new();
                        msg.set_login_request(lr);
                        let _ = stream.send_raw(msg.write_to_bytes().unwrap_or_default()).await;
                    }
                    // The generic post-key frame dump is for read/login/inject only; a port-forward
                    // tunnel already did its round-trip above, and its post-PeerInfo bytes are RAW
                    // relay data (not Messages), so skip the dump there.
                    for i in 0..6 {
                        if mode == "portforward" {
                            break;
                        }
                        match stream.next_timeout(3000).await {
                            Some(Ok(bytes)) => {
                                let u = match Message::parse_from_bytes(&bytes) {
                                    Ok(m) => format!("{:?}", m.union).chars().take(140).collect::<String>(),
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
                (true, pk)
            }
            Err(_) => (false, String::new()),
        }
    });

    println!("probe_client: keying ok={keyed} (expected={expect})");
    if do_read {
        println!("probe_client: post-key = {postkey}");
    }

    let pass = match expect.as_str() {
        "ok" => keyed,
        "fail" => !keyed,
        _ => false,
    };
    if pass {
        println!("probe_client: PASS");
    } else {
        println!("probe_client: FAIL");
        std::process::exit(1);
    }
}
