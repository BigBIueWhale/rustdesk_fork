//! TEST-ONLY CPace-initiator probe for the docker-loopback runtime tests. NOT shipped.
//!
//! Connects to a loopback `--server`, runs the CPace handshake (`run_initiator`) with a password,
//! and reports whether KEYING succeeded — runtime-validating, end-to-end against the REAL server:
//!   - R-A1 / R-S1   : the mandatory CPace keying choke-point — a correct password keys;
//!   - R-P3 / R-P14c : a WRONG password is refused (key-confirmation fails, no key derived).
//! (Keying runs BEFORE `check_whitelist`, so the probe keys regardless of the whitelist policy.)
//!
//! 4th arg modes (after keying):
//!   - `read`  : engage the session keys and read the post-key flow (observe the R-T15(d)
//!               default-deny ENFORCEMENT on a keyed connection, or the legacy `Hash` on admit);
//!   - `login` : also send a minimal `LoginRequest` (CPace already authenticated, so the password
//!               proof is collapsed — empty `password`), to drive the post-key login flow.
//!
//! Usage: `probe_client <addr> <password> <ok|fail> [read|login]`  (exit 0 = matched expectation)
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
    let do_read = mode == "read" || mode == "login";

    let rt = hbb_common::tokio::runtime::Runtime::new().expect("tokio runtime");
    let (keyed, postkey) = rt.block_on(async {
        let mut stream = match FramedStream::new(&addr, None, 5000).await {
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
                        lr.my_id = "probe-id".to_string();
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
