use hbb_common::{allow_err, config, log, ResultType};
use std::net::IpAddr;

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

pub fn send_wol(id: String) {
    let interfaces = default_net::get_interfaces();
    for peer in &config::LanPeers::load().peers {
        if peer.id == id {
            for (_, mac) in peer.ip_mac.iter() {
                if let Ok(mac_addr) = mac.parse() {
                    for interface in &interfaces {
                        for ipv4 in &interface.ipv4 {
                            // remove below mask check to avoid unexpected bug
                            // if (u32::from(ipv4.addr) & u32::from(ipv4.netmask)) == (u32::from(peer_ip) & u32::from(ipv4.netmask))
                            log::info!("Send wol to {mac_addr} of {}", ipv4.addr);
                            allow_err!(wol::send_wol(mac_addr, None, Some(IpAddr::V4(ipv4.addr))));
                        }
                    }
                }
            }
            break;
        }
    }
}
