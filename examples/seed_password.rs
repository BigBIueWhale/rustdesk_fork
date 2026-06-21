//! TEST-ONLY seeder for the docker-loopback runtime tests. NOT shipped.
//!
//! Seeds the at-rest config a headless `rustdesk --server` reads, so a test container can get the
//! server past the R-A4 fail-closed startup (it refuses without a permanent password) and, with an
//! optional whitelist, past the R-S9 default-deny so a keyed session can be ADMITTED. It calls the
//! library setters directly (the production `--password` CLI is install-privilege-gated and refuses
//! in a container). Same `$HOME` + APP_NAME "RustDesk" => same config path as the server.
//!
//! Usage: `cargo run --example seed_password --features linux-pkg-config -- <password> [whitelist]`
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let pw = a.get(1).expect("usage: seed_password <password> [whitelist]");
    let ok = hbb_common::config::Config::set_permanent_password(pw);
    let prs_empty = hbb_common::config::Config::get_permanent_password_prs().is_empty();
    println!("seed_password: set_permanent_password ok={ok}, prs_empty={prs_empty}");
    assert!(
        ok && !prs_empty,
        "seed_password: the credential did not round-trip into at-rest storage"
    );

    if let Some(wl) = a.get(2) {
        hbb_common::config::Config::set_option("whitelist".to_string(), wl.to_string());
        let got = hbb_common::config::Config::get_option("whitelist");
        println!("seed_password: set whitelist={wl:?} (read back {got:?})");
        assert_eq!(&got, wl, "seed_password: whitelist did not round-trip");
    }
}
