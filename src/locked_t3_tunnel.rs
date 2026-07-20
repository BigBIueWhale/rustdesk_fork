use hbb_common::config::PeerConfig;

pub const PEER_ID: &str = "ronenzyroff.com:21128";

const PORT_FORWARDS: [(i32, &str, i32); 2] = [(3779, "localhost", 3773), (3722, "localhost", 22)];

pub fn port_forwards() -> Vec<(i32, String, i32)> {
    PORT_FORWARDS
        .iter()
        .map(|(local_port, remote_host, remote_port)| {
            (*local_port, (*remote_host).to_owned(), *remote_port)
        })
        .collect()
}

pub fn enforce_peer_config() {
    let mut config = PeerConfig::load(PEER_ID);
    let locked_port_forwards = port_forwards();
    if config.port_forwards != locked_port_forwards {
        config.port_forwards = locked_port_forwards;
        config.store(PEER_ID);
    }
}

#[cfg(test)]
mod tests {
    use super::{port_forwards, PEER_ID};

    #[test]
    fn locks_t3_tunnel_peer_and_ports() {
        assert_eq!(PEER_ID, "ronenzyroff.com:21128");
        assert_eq!(
            port_forwards(),
            vec![
                (3779, "localhost".to_owned(), 3773),
                (3722, "localhost".to_owned(), 22),
            ]
        );
    }
}
