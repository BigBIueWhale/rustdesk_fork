//! Platform-independent R-A4 socket-surface policy regressions.

use hbb_common::socket_surface::{check_controlled_surface, SocketSurface};

const PINNED_PORT: u16 = 21118;

#[test]
fn r_f4_pinned_port_constant() {
    assert_eq!(hbb_common::config::DIRECT_PORT as u16, PINNED_PORT);
}

#[test]
fn policy_accepts_the_audited_surface() {
    let s = SocketSurface {
        tcp4_listen_ports: vec![21118],
        tcp6_listen_ports: vec![],
        udp_sockets: 0,
    };
    assert_eq!(s.tcp4_listen_ports, vec![21118]);
    assert!(check_controlled_surface(&s, PINNED_PORT).is_ok());
}

#[test]
fn policy_rejects_any_udp_socket() {
    // The blind spot R-A4 closes: an ephemeral/egress UDP socket with the lone
    // correct TCP listener still present MUST be refused.
    let s = SocketSurface {
        tcp4_listen_ports: vec![21118],
        tcp6_listen_ports: vec![],
        udp_sockets: 1,
    };
    let err = check_controlled_surface(&s, PINNED_PORT).unwrap_err();
    assert!(err.contains("UDP"), "{err}");
}

#[test]
fn policy_rejects_a_second_tcp_listener() {
    let s = SocketSurface {
        tcp4_listen_ports: vec![21118, 631],
        tcp6_listen_ports: vec![],
        udp_sockets: 0,
    };
    let err = check_controlled_surface(&s, PINNED_PORT).unwrap_err();
    assert!(err.contains("exactly 1"), "{err}");
}

#[test]
fn policy_rejects_zero_listeners() {
    let s = SocketSurface::default();
    let err = check_controlled_surface(&s, PINNED_PORT).unwrap_err();
    assert!(err.contains("found 0"), "{err}");
}

#[test]
fn policy_rejects_an_ipv6_face() {
    // R-D5: the lone listener must be v4. A dual-stack/v6 listener is a violation
    // even on the right port — IPv6 unreachability is a property of the bind.
    let s = SocketSurface {
        tcp4_listen_ports: vec![],
        tcp6_listen_ports: vec![21118],
        udp_sockets: 0,
    };
    let err = check_controlled_surface(&s, PINNED_PORT).unwrap_err();
    assert!(err.contains("IPv6") || err.contains("R-D5"), "{err}");
}

#[test]
fn policy_rejects_the_wrong_port() {
    let s = SocketSurface {
        tcp4_listen_ports: vec![12345],
        tcp6_listen_ports: vec![],
        udp_sockets: 0,
    };
    let err = check_controlled_surface(&s, PINNED_PORT).unwrap_err();
    assert!(err.contains("pinned"), "{err}");
}
