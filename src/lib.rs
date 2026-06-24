mod keyboard;
/// cbindgen:ignore
pub mod platform;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub use platform::{
    clip_cursor, get_cursor, get_cursor_data, get_cursor_pos, get_focused_display,
    set_cursor_pos, start_os_service,
};
#[cfg(not(any(target_os = "ios")))]
/// cbindgen:ignore
mod server;
#[cfg(not(any(target_os = "ios")))]
pub use self::server::*;
mod client;
// R-X5 / R-SV1 / R-D7a: LAN discovery is fully removed (the `mod lan` no-op stubs — discover()
// and send_wol() — are gone, along with the sciter Discovered-tab UI, ui_interface get_lan_peers/
// remove_discovered, and config::LanPeers). The discovery LISTENER/querier was already excised
// (322aebb); this completes the "removed not disabled" excision cross-harness.
// R-D4 Stage 3 / R-SV10: the rendezvous mediator is excised; what survives is the direct-only
// service path (start_direct_only -> direct_server, the single PAKE-gated v4 TCP listener), so the
// module is honestly named `direct_service` — the inherited mediator module name is grep-absent.
#[cfg(not(any(target_os = "ios")))]
mod direct_service;
#[cfg(not(any(target_os = "ios")))]
pub use self::direct_service::*;
/// cbindgen:ignore
pub mod common;
#[cfg(not(any(target_os = "ios")))]
pub mod ipc;
#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "cli",
    feature = "flutter"
)))]
pub mod ui;
mod version;
pub use version::*;
#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
mod bridge_generated;
#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
pub mod flutter;
#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
pub mod flutter_ffi;
use common::*;
#[cfg(feature = "cli")]
pub mod cli;
#[cfg(not(target_os = "ios"))]
mod clipboard;
#[cfg(not(any(target_os = "android", target_os = "ios", feature = "cli")))]
pub mod core_main;
// R-X4: mod custom_server removed (the custom-rendezvous-server-from-exe-name parser).
mod lang;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod port_forward;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod tray;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod whiteboard;

mod ui_cm_interface;
mod ui_interface;
mod ui_session_interface;

mod hbbs_http;

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub mod clipboard_file;

pub mod privacy_mode;

#[cfg(windows)]
pub mod virtual_display_manager;
