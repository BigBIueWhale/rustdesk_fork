//! Guards the IPC socket-mode classification (`is_service_ipc_postfix`) that decides whether a
//! per-channel unix-domain socket is created WORLD-CONNECTABLE (0o0666 — for the root-service
//! cross-user channels) or OWNER-ONLY (0o0600 — everything else). See `ipc.rs` ~608-614.
//!
//! Why this matters: the per-connection task connects to the connection-manager over the `_cm`
//! channel, which carries `ipc::Data::Authorize` (the session-authorize trigger that reaches the
//! single `self.authorized = true` point). An audit confirmed that surface is sound — the keyed
//! edge (CPace) + the default-deny whitelist gate Authorize UPSTREAM of the CM's existence, and
//! `_cm` is owner-only so a *different* OS user cannot even connect — but the 0o0600 mode is the
//! defence-in-depth perimeter on the IPC itself. A regression that reclassified `_cm` (or the
//! default/data channels) as a "service" postfix would silently make it world-connectable and open
//! a same-box cross-user injection surface. Pin the classification exactly.

use hbb_common::config::is_service_ipc_postfix;

#[test]
fn cm_and_data_channels_are_owner_only() {
    // 0o0600 (owner-only): the CM channel (carries Data::Authorize) and the generic channels.
    assert!(
        !is_service_ipc_postfix("_cm"),
        "_cm carries Data::Authorize and MUST be owner-only (0o0600), never world-connectable"
    );
    assert!(
        !is_service_ipc_postfix(""),
        "the default/control channel must be owner-only"
    );
    assert!(
        !is_service_ipc_postfix("_pa"),
        "the audio channel must be owner-only"
    );
}

#[test]
fn only_root_service_channels_are_world_connectable() {
    // 0o0666 (world-connectable): ONLY the root-service cross-user channels, by design — the user
    // `--server`/UI process must reach the root service and its Wayland uinput injectors.
    assert!(is_service_ipc_postfix("_service"));
    assert!(is_service_ipc_postfix("_uinput_control"));
    assert!(is_service_ipc_postfix("_uinput_keyboard"));
    // Lookalikes that are NOT the protected set must stay owner-only (no prefix/substring slip).
    assert!(
        !is_service_ipc_postfix("_service_x"),
        "only an EXACT _service match is world-connectable, not a prefix"
    );
    assert!(
        !is_service_ipc_postfix("_cm_uinput_"),
        "_uinput_ is matched only as a leading prefix, not anywhere in the string"
    );
}
