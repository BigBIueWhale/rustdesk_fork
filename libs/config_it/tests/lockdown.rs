//! R-S16 policy funnel (UNCONDITIONAL — the lockdown build-split feature was
//! retired, R-R2b): the controlled-side PINNED_SETTINGS policy is the single
//! source of truth on every artifact — pinned keys return their compile-time
//! values (read funnel, R-S16b) and cannot be written (write guard, R-S16c), so
//! no local/IPC/server-pushed write can default-permissive or re-enable them. A
//! wrong funnel here is fail-open and "looks fine", so this test pins the
//! behavior exactly.

use hbb_common::config::Config;

#[test]
fn pinned_policy_is_the_single_source_of_truth() {
    // ── Read funnel (R-S16b): every pinned key returns its policy value,
    //    regardless of stored/overwrite/default state. ──
    assert_eq!(
        Config::get_option("verification-method"),
        "use-permanent-password"
    );
    assert_eq!(Config::get_option("approve-mode"), "password");
    // FULL ACCESS is the one pinned mode: access-mode=full + every capability granted (R-D8/R-X8/R-F1).
    assert_eq!(Config::get_option("access-mode"), "full");
    // Every session-type / content capability is granted to the authenticated owner (Y).
    for k in [
        "enable-keyboard",
        "enable-clipboard",
        "enable-file-transfer",
        "enable-audio",
        "enable-camera",
        "enable-terminal",
        "enable-tunnel",
        "enable-remote-restart",
        "enable-record-session",
        "enable-block-input",
        "enable-privacy-mode",
        "enable-remote-printer",
        "allow-remote-config-modification",
    ] {
        assert_eq!(Config::get_option(k), "Y", "{k} must be pinned Y (full access)");
    }
    // Pinned OFF (N): the egress / transport / service sovereignty + no-self-DoS invariants
    // (R-D6/R-X9), PLUS the ONE capability exception — enable-virtual-display (R-T0/Appendix C #2b:
    // a native display-DRIVER surface kept off as defense-in-depth; everything else is full access).
    for k in [
        "enable-virtual-display",
        "allow-websocket",
        "allow-insecure-tls-fallback",
        "allow-linux-headless",
        "stop-service",
    ] {
        assert_eq!(Config::get_option(k), "N", "{k} must be pinned N");
    }
    // Egress-silent: no rendezvous/relay/api/proxy, no 2FA/bot (empty).
    for k in [
        "api-server",
        "custom-rendezvous-server",
        "relay-server",
        "proxy-url",
        "2fa",
        "bot",
        "allow-only-conn-window-open",
    ] {
        assert_eq!(Config::get_option(k), "", "{k} must be pinned empty");
    }

    // The bool resolver (option2bool) sees the pin too.
    assert!(Config::get_bool_option("enable-keyboard"));
    assert!(Config::get_bool_option("enable-terminal")); // full access — terminal granted
    assert!(!Config::get_bool_option("stop-service"));

    // ── Write guard (R-S16c): an attempt to override a pinned key is rejected and the pin still
    //    holds — in EITHER direction. A password-knower can neither WIDEN the policy (egress, kill
    //    the service) nor NARROW the pinned full-access policy (drop to view-only, disable the
    //    terminal) at runtime; the funnel rejects every write to a pinned key. ──
    Config::set_option("access-mode".into(), "view".into()); // try to narrow to view-only
    Config::set_option("approve-mode".into(), "click".into()); // silent click-to-accept
    Config::set_option("api-server".into(), "https://evil.example".into()); // egress
    Config::set_option("enable-terminal".into(), "N".into()); // try to disable the terminal
    Config::set_option("stop-service".into(), "Y".into()); // kill the service
    assert_eq!(Config::get_option("access-mode"), "full");
    assert_eq!(Config::get_option("approve-mode"), "password");
    assert_eq!(Config::get_option("api-server"), "");
    assert_eq!(Config::get_option("enable-terminal"), "Y");
    assert_eq!(Config::get_option("stop-service"), "N");
    // The rejected writes never reach the persisted options map.
    let opts = Config::get_options();
    for k in ["access-mode", "approve-mode", "api-server", "enable-terminal"] {
        assert!(!opts.contains_key(k), "{k} must not be persisted");
    }

    // ── A non-pinned key is unaffected: the funnel touches only the policy table. ──
    Config::set_option("a-non-pinned-ui-key".into(), "hello".into());
    assert_eq!(Config::get_option("a-non-pinned-ui-key"), "hello");
}

/// R-P1/R-S16: the permanent password is held at rest ONLY as the memory-hard,
/// host-key-salted Argon2id CPace PRS — NEVER the plaintext and NEVER a fast
/// (SHA256) hash. Read live on every connection, so a change takes effect on the
/// next handshake.
#[test]
fn permanent_password_prs_is_memory_hard_hash() {
    let pw = "hunter2-correct-horse";
    assert!(Config::set_permanent_password(pw));
    let prs = Config::get_permanent_password_prs();

    // The stored PRS is a HASH, not the plaintext.
    assert_ne!(prs, pw, "the PRS must not be the plaintext password");
    assert!(!prs.is_empty(), "a set password yields a non-empty PRS");

    // It is EXACTLY base64(Argon2id(NFC(pw), salt(host_pubkey))): deriving against the
    // box's own host public key reproduces the stored PRS, so both ends agree (the
    // viewer derives the identical value from the box's PINNED key).
    let host_pubkey = Config::get_key_pair().1;
    assert_eq!(
        prs,
        hbb_common::config::derive_cpace_prs(pw, &host_pubkey).expect("derive PRS"),
        "the stored PRS must equal the documented Argon2id derivation"
    );

    // Stable for the same password + key: re-setting the SAME password is idempotent
    // and yields the SAME PRS (no per-set randomness — the salt is the host key).
    assert!(Config::set_permanent_password(pw));
    assert_eq!(Config::get_permanent_password_prs(), prs);

    // A different password yields a different PRS, and the change takes effect at once
    // (no cached PRS).
    assert!(Config::set_permanent_password("a-new-password"));
    let prs2 = Config::get_permanent_password_prs();
    assert_ne!(prs2, prs, "a new password must change the PRS");
    assert_ne!(prs2, "a-new-password", "the new PRS is the hash, not the plaintext");

    // The legacy `config.password` slot also holds the Argon2id PRS (NOT the plaintext,
    // NOT a fast SHA256) and stays salt-bound — so a full config dump has no plaintext
    // and no fast hash of the password.
    let (pw_storage, salt) = Config::get_local_permanent_password_storage_and_salt();
    assert_ne!(pw_storage, "a-new-password");
    assert!(!pw_storage.is_empty());
    assert!(!salt.is_empty(), "the hash-shaped storage stays salt-bound (R-S9)");

    // Clearing the password clears the PRS (no shared secret ⇒ handshake fails closed).
    assert!(Config::set_permanent_password(""));
    assert_eq!(Config::get_permanent_password_prs(), "");
}

// R-D6(d)(iii)/R-S11: the fork is direct-only. proxy-url is pinned, and set_socks/get_socks/
// get_network_type bypass the get_option funnel — so they MUST honor the pin AT THE ACCESSOR.
// Otherwise a local main-channel IPC write (Data::Socks) installs a proxy: a local-MITM /
// egress-reroute primitive, and the trigger that flips CheckTestNatType's is_direct to fire a
// STUN UDP probe (an R-A4 zero-UDP violation). This proves the accessors refuse it.
#[test]
fn socks_is_inert_under_the_proxy_pin() {
    use hbb_common::config::{NetworkType, Socks5Server};
    // a local Data::Socks write attempts to install an attacker proxy
    Config::set_socks(Some(Socks5Server {
        proxy: "127.0.0.1:1080".into(),
        ..Default::default()
    }));
    // the accessors refuse it — no proxy is ever surfaced
    assert!(
        Config::get_socks().is_none(),
        "R-D6(d)(iii): get_socks must be None when proxy-url is pinned (set_socks must be inert)"
    );
    assert_eq!(
        Config::get_network_type(),
        NetworkType::Direct,
        "R-D6(d)(iii): get_network_type must be Direct (the proxy/socks accessor is pinned inert)"
    );
    assert!(!Config::is_proxy(), "the direct-only box is never a proxy client");
}
