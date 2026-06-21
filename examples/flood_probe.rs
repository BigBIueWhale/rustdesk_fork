//! TEST-ONLY flood probe for the docker-loopback runtime test of R-T1 (the §20 CRITICAL
//! connection-flood bound). NOT shipped.
//!
//! Opens many pre-key TCP connections to the loopback `--server` and HOLDS them without ever
//! sending the CPace step1, so each occupies a `PREKEY_HANDSHAKE_SLOTS` permit (budget 256) while
//! its `run_responder` blocks waiting for the first frame. Past the budget the server MUST
//! CAPACITY-shed the excess (R-T1) — a capacity shed, never a per-source ban (R-S10) — which it
//! records in the rate-limited `R-S10/R-T12 security summary … shed=N`. Retries past the
//! transient TCP backlog (128) so enough connections are accepted to cross the 256 budget.
//!
//! Usage: `flood_probe <addr> <count>`
use std::time::Duration;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let addr = a.get(1).cloned().expect("usage: flood_probe <addr> <count>");
    let n: usize = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(300);

    let mut holds = Vec::with_capacity(n);
    for _ in 0..n {
        for _ in 0..8 {
            match std::net::TcpStream::connect(&addr) {
                Ok(s) => {
                    holds.push(s);
                    break;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(15)),
            }
        }
    }
    println!("flood_probe: held {} / {} pre-key connections", holds.len(), n);
    // Hold them (no CPace) so the permits stay occupied while the server's accept loop sheds the
    // excess; the held sockets drop (closing) only when this process exits.
    std::thread::sleep(Duration::from_secs(6));
}
