use hbb_common::ResultType;

// R-X5 / R-SV1: LAN discovery is REMOVED. The fork is direct-IP only and does NOT
// broadcast a discovery ping to the LAN — the querier machinery (send_query + the
// broadcast sockets + wait_response + spawn_wait_responses + handle_received_peers)
// is EXCISED, and the 0.0.0.0:21119 responder (start_listening) was removed in
// 322aebb. `discover` survives as a no-op ONLY until its UI callers — the flutter
// Discovered-tab trigger (`peers_view.dart` `mainDiscover`) and the sciter discover
// binding (`ui.rs`/`ui_interface.rs`) — are excised cross-harness (a peer-tab / R-G2
// follow-on). It can no longer announce this box on the network or bind a socket.
pub fn discover() -> ResultType<()> {
    Ok(())
}

// R-SV4(c)/R-SV10 / §18: Wake-on-LAN is DROPPED — a deliberate, accepted loss (WoL is LAN-only,
// moot for the static-IP direct deployment, and orthogonal to the direct-IP-only / sovereign
// posture). The inherited `send_wol` broadcast WoL magic packets (UDP) over EVERY LAN interface
// (`wol::send_wol`, iterating `default_net` interfaces × the stored LanPeers MACs) — a viewer-side
// LAN egress. Now a no-op; its only caller (`flutter_ffi::main_wol`) is a harmless stub until the
// Dart WoL peer-card action is removed (the R-G2 / R-SV4(c) Discovered-tab/WoL-UI follow-on).
pub fn send_wol(_id: String) {}
