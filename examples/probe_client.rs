//! TEST-ONLY CPace-initiator probe for the docker-loopback runtime tests. NOT shipped.
//!
//! Connects to a loopback `--server`, runs the CPace handshake (`run_initiator`) with a password,
//! and reports whether KEYING succeeded — runtime-validating, end-to-end against the REAL server:
//!   - R-A1 / R-S1   : the mandatory CPace keying choke-point — a correct password keys;
//!   - R-P3 / R-P14c : a WRONG password is refused (key-confirmation fails, no key derived).
//! (Keying runs BEFORE `check_whitelist`, so the probe keys regardless of the whitelist policy.)
//!
//! 4th arg modes (after keying):
//!   - `read`   : engage the session keys and read the post-key flow (observe the R-T15(d)
//!                default-deny ENFORCEMENT on a keyed connection, or the legacy `Hash` on admit);
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
    let do_read = mode == "read" || mode == "login" || mode == "inject";
    // Optional local source address (6th arg) — e.g. 127.0.0.2:0 to connect as a DIFFERENT source,
    // for the R-A8.2 owner-safe limiter test (a flood from one source must not block another).
    let local = a.get(5).and_then(|s| s.parse::<std::net::SocketAddr>().ok());

    let rt = hbb_common::tokio::runtime::Runtime::new().expect("tokio runtime");
    let (keyed, postkey) = rt.block_on(async {
        let mut stream = match FramedStream::new(&addr, local, 5000).await {
            Ok(s) => s,
            Err(e) => {
                println!("probe_client: CONNECT_FAIL {e}");
                std::process::exit(2);
            }
        };
        match run_initiator_with_transcript(&mut stream, &pw).await {
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
                    for i in 0..6 {
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
