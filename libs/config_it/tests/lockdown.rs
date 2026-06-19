//! R-S16 lockdown funnel: with the `lockdown` feature on, the controlled-side
//! PINNED_SETTINGS policy is the single source of truth — pinned keys return
//! their compile-time values (read funnel, R-S16b) and cannot be written
//! (write guard, R-S16c), so no local/IPC/server-pushed write can defaulted-
//! permissive or re-enable them. A wrong funnel here is fail-open and "looks
//! fine", so this test pins the behavior exactly.

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
        "enable-trusted-devices",
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
