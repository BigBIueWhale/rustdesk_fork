//! R-S15 (Appendix C #19): the viewer's in-session PeerConfig writes from peer-controlled data —
//! the `PeerInfo` arm's username/hostname/platform (client.rs `handle_peer_info`) and the
//! `BackNotification` privacy-mode impl_key (io_loop.rs `update_privacy_mode`) — are funnelled
//! through `bound_peer_config_string` before they reach the on-disk PeerConfig. Keying (R-S13)
//! authenticates the peer but does NOT make a hostile-but-keyed peer's payload trustworthy, so a
//! bound is required: control characters stripped (no TOML / terminal / UI-injection bytes) and
//! the length clamped (no config-bloat DoS). The initiator-side twin of the responder's R-S11
//! config-write gate. A wrong bound here is silently fail-open, so this pins the behavior.

use hbb_common::config::bound_peer_config_string;

#[test]
fn strips_control_chars_and_clamps_length() {
    // Control characters (NUL, newline, tab, DEL) are stripped.
    assert_eq!(bound_peer_config_string("a\0b\nc\td\x7fe"), "abcde");
    // Length is clamped to the 256-char bound.
    assert_eq!(
        bound_peer_config_string(&"x".repeat(1000)).chars().count(),
        256
    );
    // Benign identity strings pass through unchanged.
    assert_eq!(bound_peer_config_string("Windows"), "Windows");
    assert_eq!(bound_peer_config_string("user@host-01"), "user@host-01");
    // A multi-byte unicode string is clamped by CHAR count (never panics on a byte boundary).
    let s = "é".repeat(300);
    assert_eq!(bound_peer_config_string(&s).chars().count(), 256);
    // An all-control-char string collapses to empty (fully neutralized).
    assert_eq!(bound_peer_config_string("\0\n\r\t\x1b"), "");
}
