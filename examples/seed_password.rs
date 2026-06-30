//! TEST-ONLY seeder for the docker-loopback runtime tests. NOT shipped.
//!
//! Seeds the at-rest config a headless `rustdesk --server` reads, so a test container can get the
//! server past the R-A4 fail-closed startup (it refuses without a permanent password), so a keyed session
//! can be ADMITTED. It calls the
//! library setters directly (the production `--password` CLI is install-privilege-gated and refuses
//! in a container). Same `$HOME` + APP_NAME "RustDesk" => same config path as the server.
//!
//! Usage: `cargo run --example seed_password --features linux-pkg-config -- <password>`
//!
//! R-P1 note: the permanent-password PRS is a memory-hard Argon2id hash SALTED with the box's own
//! Ed25519 host PUBLIC key. set_permanent_password co-persists that key SYNCHRONOUSLY (the lazy
//! get_key_pair() background flush would otherwise race a short-lived seeder), so the separate
//! `--server` process reads the SAME key the PRS binds to.
fn main() {
    use hbb_common::config::Config;
    let a: Vec<String> = std::env::args().collect();
    let pw = a.get(1).expect("usage: seed_password <password>");
    let ok = Config::set_permanent_password(pw);
    let prs = Config::get_permanent_password_prs();
    let prs_empty = prs.is_empty();
    // R-P1: the stored PRS is the Argon2id hash, NEVER the plaintext.
    let prs_is_plaintext = &prs == pw;
    println!("seed_password: set_permanent_password ok={ok}, prs_empty={prs_empty}, prs_is_plaintext={prs_is_plaintext}");
    assert!(
        ok && !prs_empty && !prs_is_plaintext,
        "seed_password: the credential did not round-trip into at-rest storage as a non-plaintext PRS"
    );
}
