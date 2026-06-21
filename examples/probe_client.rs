//! TEST-ONLY CPace-initiator probe for the docker-loopback runtime tests. NOT shipped.
//!
//! Connects to a loopback `--server`, runs the CPace handshake (`run_initiator`) with a password,
//! and reports whether KEYING succeeded — runtime-validating, end-to-end against the REAL server:
//!   - R-A1 / R-S1 : the mandatory CPace keying choke-point — a correct password keys;
//!   - R-P3 / R-P14c : a WRONG password is refused (key-confirmation fails, no key derived).
//! (Keying runs BEFORE `check_whitelist`, so the probe keys regardless of the whitelist policy.)
//!
//! With a 4th arg `read`, after keying it engages the session keys and reads ONE post-key message,
//! printing its union — to observe the server's post-key flow at runtime (the R-T15(d) default-deny
//! ENFORCEMENT on a keyed connection: an empty whitelist yields a `LoginResponse{error}`, vs the
//! legacy `Hash` emission when admitted).
//!
//! Usage: `probe_client <addr> <password> <ok|fail> [read]`  (exit 0 = matched expectation)
use hbb_common::cpace::run_initiator;
use hbb_common::protobuf::Message as _; // for Message::parse_from_bytes
use hbb_common::tcp::FramedStream;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let addr = a
        .get(1)
        .cloned()
        .expect("usage: probe_client <addr> <password> <ok|fail> [read]");
    let pw = a.get(2).cloned().expect("password");
    let expect = a.get(3).map(String::as_str).unwrap_or("ok").to_string();
    let read_postkey = a.get(4).map(|s| s == "read").unwrap_or(false);

    let rt = hbb_common::tokio::runtime::Runtime::new().expect("tokio runtime");
    let (keyed, postkey) = rt.block_on(async {
        let mut stream = match FramedStream::new(&addr, None, 5000).await {
            Ok(s) => s,
            Err(e) => {
                println!("probe_client: CONNECT_FAIL {e}");
                std::process::exit(2);
            }
        };
        // CPace initiator: sends step1 first, so the client drives the handshake the responder awaits.
        match run_initiator(&mut stream, &pw).await {
            Ok(keys) => {
                let mut pk = String::new();
                if read_postkey {
                    stream.set_session_keys(keys); // engage the two-key cipher
                    for i in 0..5 {
                        match stream.next_timeout(3000).await {
                            Some(Ok(bytes)) => {
                                let u = match hbb_common::message_proto::Message::parse_from_bytes(&bytes) {
                                    Ok(msg) => {
                                        let s = format!("{:?}", msg.union);
                                        s.chars().take(180).collect::<String>()
                                    }
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
    if read_postkey {
        println!("probe_client: post-key union = {postkey}");
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
