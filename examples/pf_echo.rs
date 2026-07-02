//! TEST-ONLY local target for the port-forward/RDP relay smoke probe (R-F1/R-D6/R-A9). NOT shipped.
//!
//! Binds `127.0.0.1:<port>`, accepts connections, and echoes every byte straight back until EOF. In
//! the smoke test this stands in for the "local service" (an RDP server, a web app, …) that the box's
//! `try_port_forward_loop` dials. A port-forward probe (a viewer) sends a canary through the SEALED
//! tunnel; the box relays it here, we echo it, the box relays it back sealed — proving the restored
//! relay works END-TO-END (not just that the seal is ciphertext, which the R-A9 unit test proves).
use std::io::{Read, Write};
use std::net::TcpListener;

fn main() {
    let port = std::env::args()
        .nth(1)
        .expect("usage: pf_echo <port>");
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).expect("pf_echo bind");
    // Readiness signal so the smoke stage can wait for the listener before starting the box.
    println!("pf_echo: listening on 127.0.0.1:{port}");
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Each connection echoes independently; the smoke stage kills this process when done.
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        let _ = stream.flush();
                    }
                    Err(_) => break,
                }
            }
        });
    }
}
