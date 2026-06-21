//! TEST-ONLY seeder for the docker-loopback runtime tests (R-B4 socket-surface / R-T9 drain /
//! the two-process rig). NOT shipped — an `examples/` binary, never linked into a release.
//!
//! A headless `rustdesk --server` refuses to listen until a PRS-usable permanent password is set
//! (R-A4 fail-closed startup), and the production `--password` CLI is install-privilege-gated
//! (`core_main.rs`: `is_installed() && is_root()`), which a test container is not. This calls the
//! library setter `Config::set_permanent_password` DIRECTLY — the same at-rest storage the CLI
//! ultimately writes — so a test container can seed the credential and let the server get past
//! R-A4 and actually BIND, enabling the `ss`/`/proc` socket-surface check and the SIGTERM drain.
//!
//! It writes the SAME at-rest config the server reads: same `$HOME`, and `APP_NAME` defaults to
//! "RustDesk" for both (this seeder does not change it), so the config path matches.
//!
//! Usage: `cargo run --example seed_password --features linux-pkg-config -- <password>`
fn main() {
    let pw = std::env::args()
        .nth(1)
        .expect("usage: seed_password <password>");
    let ok = hbb_common::config::Config::set_permanent_password(&pw);
    let prs_empty = hbb_common::config::Config::get_permanent_password_prs().is_empty();
    println!("seed_password: set_permanent_password ok={ok}, prs_empty={prs_empty}");
    assert!(
        ok && !prs_empty,
        "seed_password: the credential did not round-trip into at-rest storage"
    );
}
