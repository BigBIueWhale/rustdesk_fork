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
    assert_eq!(Config::get_option("access-mode"), "custom");
    // Content channels a remote-control + file-transfer box needs (Y).
    for k in [
        "enable-keyboard",
        "enable-clipboard",
        "enable-file-transfer",
        "enable-audio",
        "enable-camera",
    ] {
        assert_eq!(Config::get_option(k), "Y", "{k} must be pinned Y");
    }
    // Escalation / headless-meaningless capabilities off (N).
    for k in [
        "enable-terminal",
        "enable-tunnel",
        "enable-remote-restart",
        "enable-record-session",
        "enable-block-input",
        "enable-privacy-mode",
        "enable-remote-printer",
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
    assert!(!Config::get_bool_option("enable-terminal"));
    assert!(!Config::get_bool_option("stop-service"));

    // ── Write guard (R-S16c): an attempt to override a pinned key is rejected
    //    and the pin still holds. ──
    Config::set_option("access-mode".into(), "full".into()); // the dangerous shortcut
    Config::set_option("approve-mode".into(), "click".into()); // silent click-to-accept
    Config::set_option("api-server".into(), "https://evil.example".into()); // egress
    Config::set_option("enable-terminal".into(), "Y".into()); // re-enable escalation
    Config::set_option("stop-service".into(), "Y".into()); // kill the service
    assert_eq!(Config::get_option("access-mode"), "custom");
    assert_eq!(Config::get_option("approve-mode"), "password");
    assert_eq!(Config::get_option("api-server"), "");
    assert_eq!(Config::get_option("enable-terminal"), "N");
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

/// R-P1/R-S16: the permanent password is held as PRS-usable plaintext at rest
/// (not a one-way salted hash), read live on every connection, so a change takes
/// effect on the next handshake.
#[test]
fn permanent_password_is_prs_usable_plaintext() {
    assert!(Config::set_permanent_password("hunter2-correct-horse"));
    assert_eq!(Config::get_permanent_password_prs(), "hunter2-correct-horse");

    // A change takes effect immediately — no cached PRS.
    assert!(Config::set_permanent_password("a-new-password"));
    assert_eq!(Config::get_permanent_password_prs(), "a-new-password");

    // The legacy hashed storage stays a hash (not the plaintext) — the PRS lives
    // in its own at-rest slot, so this is additive, not a downgrade of the hash.
    let (h1_storage, _) = Config::get_local_permanent_password_storage_and_salt();
    assert_ne!(h1_storage, "a-new-password");
    assert!(!h1_storage.is_empty());

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
