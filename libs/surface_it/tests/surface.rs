//! R-A4 socket-surface parser + policy (hbb_common::socket_surface).
//!
//! The live runtime check reads /proc/self/net/{tcp,tcp6,udp,udp6}; that read is
//! Linux-only and needs the server running (two-host R-A8/A9 territory). What is
//! unit-testable here — and where a silent bug would be fail-OPEN — is the table
//! PARSER and the surface POLICY. These fixtures match the real kernel format
//! (whitespace columns, HEXIP:HEXPORT local_address, hex `st` state) so the
//! parser is pinned, and every policy branch (the lone v4:port listener, a stray
//! listener, a v6 face, the wrong port, any UDP) is asserted.

use hbb_common::socket_surface::{
    check_controlled_surface, count_udp_sockets, parse_tcp_listen_ports, SocketSurface,
};

// 0x527E == 21118 (the pinned direct port, R-F4); 0x0277 == 631 (a loopback
// CUPS listener); the third row is ESTABLISHED (st 01), not a listener.
const TCP_TABLE: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:527E 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 ffff8800abcd0000 100 0 0 10 0
   1: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 23456 1 ffff8800abcd1111 100 0 0 10 0
   2: 0100007F:E0F2 0100007F:527E 01 00000000:00000000 00:00000000 00000000  1000        0 34567 1 ffff8800abcd2222 20 4 30 10 -1
";

// The clean controlled-box table: a single v4:21118 LISTEN, plus an ESTABLISHED
// session row (which must NOT count as a listener).
const TCP_TABLE_CLEAN: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:527E 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 ffff8800abcd0000 100 0 0 10 0
   1: 0100007F:E0F2 0A00000A:527E 01 00000000:00000000 00:00000000 00000000  1000        0 34567 1 ffff8800abcd2222 20 4 30 10 -1
";

const UDP_TABLE_TWO: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  123: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101        0 45678 2 ffff8800dead0000 0
  456: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 56789 2 ffff8800dead1111 0
";

const UDP_TABLE_EMPTY: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
";

const PINNED_PORT: u16 = 21118;

#[test]
fn r_f4_pinned_port_constant() {
    // Tie the fixtures to the pinned port — if DIRECT_PORT ever moves, the
    // hardcoded 0x527E fixtures (and the §10.4 CPace CI KAT) must move with it.
    assert_eq!(hbb_common::config::DIRECT_PORT as u16, PINNED_PORT);
}

#[test]
fn parser_returns_only_listen_state_ports() {
    // LISTEN rows 0 and 1 → ports; the ESTABLISHED row 2 and the header are skipped.
    assert_eq!(parse_tcp_listen_ports(TCP_TABLE), vec![21118, 631]);
}

#[test]
fn parser_clean_table_is_one_listener() {
    // The ESTABLISHED session row must not be mistaken for a listener.
    assert_eq!(parse_tcp_listen_ports(TCP_TABLE_CLEAN), vec![21118]);
}

#[test]
fn parser_empty_and_header_only() {
    assert!(parse_tcp_listen_ports("").is_empty());
    assert!(parse_tcp_listen_ports(UDP_TABLE_EMPTY).is_empty());
    assert_eq!(count_udp_sockets(UDP_TABLE_EMPTY), 0);
    assert_eq!(count_udp_sockets(""), 0);
}

#[test]
fn udp_counter_counts_every_socket() {
    // Both a :53 (DNS) and a :5353 (mDNS) row count — listening or not, any UDP
    // socket trips R-A4 on the controlled-only build.
    assert_eq!(count_udp_sockets(UDP_TABLE_TWO), 2);
}

#[test]
fn policy_accepts_the_audited_surface() {
    // The clean parse: exactly one v4:21118 listener, zero UDP → Ok.
    let s = SocketSurface {
        tcp4_listen_ports: parse_tcp_listen_ports(TCP_TABLE_CLEAN),
        tcp6_listen_ports: parse_tcp_listen_ports(""),
        udp_sockets: count_udp_sockets(UDP_TABLE_EMPTY),
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
