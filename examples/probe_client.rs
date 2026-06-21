//! TEST-ONLY CPace-initiator probe for the docker-loopback runtime tests. NOT shipped.
//!
//! Connects to a loopback `--server`, runs the CPace handshake (`run_initiator`) with a password,
//! and reports whether KEYING succeeded — runtime-validating, end-to-end against the REAL server:
//!   - R-A1 / R-S1 : the mandatory CPace keying choke-point — a correct password keys;
//!   - R-P3 / R-P14c : a WRONG password is refused (key-confirmation fails, no key derived).
//! (Keying runs BEFORE `check_whitelist`, so the probe keys regardless of the whitelist policy.)
//!
//! Usage: `probe_client <addr> <password> <ok|fail>`  (exit 0 = matched expectation)
use hbb_common::cpace::run_initiator;
use hbb_common::tcp::FramedStream;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let addr = a
        .get(1)
        .cloned()
        .expect("usage: probe_client <addr> <password> <ok|fail>");
    let pw = a.get(2).cloned().expect("password");
    let expect = a.get(3).map(String::as_str).unwrap_or("ok").to_string();

    // The main crate has no direct `tokio` dep; use hbb_common's re-export for the runtime.
    let rt = hbb_common::tokio::runtime::Runtime::new().expect("tokio runtime");
    let keyed = rt.block_on(async {
        let mut stream = match FramedStream::new(&addr, None, 5000).await {
            Ok(s) => s,
            Err(e) => {
                println!("probe_client: CONNECT_FAIL {e}");
                std::process::exit(2);
            }
        };
        // CPace initiator: sends step1 first, so the client drives the handshake the responder awaits.
        run_initiator(&mut stream, &pw).await.is_ok()
    });
    println!("probe_client: keying ok={keyed} (expected={expect})");

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
