//! R-A4 live socket-surface self-check (§9, "secure by assertion").
//!
//! After the direct listener binds, the controlled box's reachable network
//! surface MUST equal **exactly one TCP listener on the pinned v4 port** (21118,
//! R-F4) and **zero UDP sockets of any kind** — not merely "no UDP listener" but
//! no UDP socket at all, so an ephemeral OS-assigned-port egress UDP socket (a
//! STUN probe — R-S11 — or a dependency phoning home) cannot slip past a
//! listener-only check (§4.1). This reads the kernel's per-netns socket tables
//! at `/proc/self/net/{tcp,tcp6,udp,udp6}`. On the hardened appliance the box is
//! the sole network service in its namespace, so the netns surface *is* the
//! process surface (§14 / R-D3 confinement); if other network services share the
//! namespace they must be accounted for, or the box must run in its own netns.
//!
//! It is a **bind/listener-surface check only**: an outbound TCP `connect` has no
//! listener row, so TCP-egress silence rests on the compile-time removal (R-D6)
//! plus the operator firewall, **not** on this assertion — R-A4 explicitly
//! forbids over-crediting it with catching egress.
//!
//! macOS/iOS have no `/proc`; a Darwin port would use `proc_pidfdinfo` /
//! `sysctl net.inet.*.pcblist`, or record the runtime check as *unavailable*
//! (the surface then rests on the §18 compile-out + the R-B4 build smoke-test).
//! iOS binds no inbound socket, so the check is moot there. On any non-Linux
//! target this module reports [`SurfaceCheck::Unavailable`] rather than asserting.

/// TCP socket state from the kernel's `net/tcp_states.h`. `TCP_LISTEN == 0x0A`;
/// it is the only state that denotes a *listener* (a bound, passive socket).
/// Sessions are `ESTABLISHED` (`0x01`) and so never count as listeners — the
/// "exactly one listener" assertion holds mid-session as well as at startup.
const TCP_LISTEN: u8 = 0x0A;

/// Parsed view of the per-netns socket tables relevant to R-A4.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SocketSurface {
    /// Local ports of v4 TCP sockets in the `LISTEN` state (`/proc/self/net/tcp`).
    pub tcp4_listen_ports: Vec<u16>,
    /// Local ports of v6 TCP sockets in the `LISTEN` state (`/proc/self/net/tcp6`).
    pub tcp6_listen_ports: Vec<u16>,
    /// Count of *all* UDP sockets — listening or ephemeral — across udp + udp6.
    pub udp_sockets: usize,
}

/// Outcome of the socket-surface check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurfaceCheck {
    /// The surface matches the audited expectation.
    Ok,
    /// The check could not run on this platform/environment (e.g. no `/proc`).
    /// The caller records this and proceeds — the surface then rests on the §18
    /// compile-out plus the R-B4 build smoke-test (R-A4's macOS/iOS clause).
    Unavailable(String),
    /// The live surface does **not** match the audited expectation. The caller
    /// refuses to listen (fail-closed) — a stray listener or any UDP socket
    /// means something leaked back in (R-D4/R-X5) or a dependency opened egress.
    Violation(String),
}

/// Parse the local port of `LISTEN`-state rows from a `/proc/self/net/{tcp,tcp6}`
/// table. The whitespace-separated columns are: `sl  local_address rem_address st
/// …`; column 1 (0-based) is `local_address` as `HEXIP:HEXPORT`, column 3 is `st`
/// (the TCP state, hex). Only rows whose state == `LISTEN` contribute a port. The
/// header row and any malformed/short row are skipped (neither is a listener).
pub fn parse_tcp_listen_ports(contents: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for line in contents.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // need at least `sl local rem st`
        if cols.len() < 4 {
            continue;
        }
        // the header row's `st` column ("st") fails the hex parse → skipped
        let st = match u8::from_str_radix(cols[3], 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if st != TCP_LISTEN {
            continue;
        }
        if let Some(port) = parse_local_port(cols[1]) {
            ports.push(port);
        }
    }
    ports
}

/// Count data rows (sockets) in a `/proc/self/net/{udp,udp6}` table — every data
/// row is a UDP socket, listening or not. The header line and blank lines are
/// skipped. R-A4 (controlled-only) requires this total to be zero.
pub fn count_udp_sockets(contents: &str) -> usize {
    contents
        .lines()
        .filter(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            // a data row's column 1 parses as HEXIP:HEXPORT; the header's
            // "local_address" does not, so the header is excluded.
            cols.len() >= 4 && parse_local_port(cols[1]).is_some()
        })
        .count()
}

/// Parse `HEXIP:HEXPORT` (the `/proc/net` `local_address` form) → the port. For
/// v6 the IP is one 32-char hex run with no embedded colon, so splitting on the
/// *last* colon yields the port for both families.
fn parse_local_port(local: &str) -> Option<u16> {
    let (_ip, port_hex) = local.rsplit_once(':')?;
    u16::from_str_radix(port_hex, 16).ok()
}

/// The R-A4 surface policy for the controlled-only (lockdown) build: **exactly
/// one** TCP listener, on the pinned **v4** port (R-D5 makes the bind v4-only),
/// and **zero** UDP sockets of any kind. Returns a human-readable violation
/// description on failure — the caller refuses to listen (fail-closed).
pub fn check_controlled_surface(s: &SocketSurface, expected_tcp_port: u16) -> Result<(), String> {
    let total_tcp_listen = s.tcp4_listen_ports.len() + s.tcp6_listen_ports.len();
    if total_tcp_listen != 1 {
        return Err(format!(
            "expected exactly 1 TCP listener (v4 :{expected_tcp_port}), found {total_tcp_listen} \
             (v4 {:?}, v6 {:?})",
            s.tcp4_listen_ports, s.tcp6_listen_ports
        ));
    }
    // The lone listener MUST be v4 (R-D5 v4-only bind), not an IPv6 face.
    if !s.tcp6_listen_ports.is_empty() {
        return Err(format!(
            "the lone TCP listener is on IPv6 {:?}, but R-D5 pins a v4-only bind",
            s.tcp6_listen_ports
        ));
    }
    // …and on the pinned port, not any other (R-F4).
    if s.tcp4_listen_ports.first() != Some(&expected_tcp_port) {
        return Err(format!(
            "TCP listener is on v4 :{:?}, expected the pinned :{expected_tcp_port} (R-F4)",
            s.tcp4_listen_ports.first()
        ));
    }
    if s.udp_sockets != 0 {
        return Err(format!(
            "found {} UDP socket(s); R-A4 (controlled-only) requires zero UDP of any kind — a \
             stray UDP means LAN/probe leaked back in (R-D4/R-X5) or a dependency opened an \
             egress UDP socket",
            s.udp_sockets
        ));
    }
    Ok(())
}

/// Read and parse `/proc/self/net/{tcp,tcp6,udp,udp6}` (the caller's network
/// namespace). The v6 tables may be absent when the kernel has IPv6 disabled —
/// a missing v6 table means "no v6 sockets", not an error. The v4 tables are
/// always present on Linux; their absence is propagated as an error (and the
/// caller treats it fail-closed).
#[cfg(target_os = "linux")]
pub fn read_proc_self_net() -> std::io::Result<SocketSurface> {
    let tcp4 = std::fs::read_to_string("/proc/self/net/tcp")?;
    let tcp6 = std::fs::read_to_string("/proc/self/net/tcp6").unwrap_or_default();
    let udp = std::fs::read_to_string("/proc/self/net/udp")?;
    let udp6 = std::fs::read_to_string("/proc/self/net/udp6").unwrap_or_default();
    Ok(SocketSurface {
        tcp4_listen_ports: parse_tcp_listen_ports(&tcp4),
        tcp6_listen_ports: parse_tcp_listen_ports(&tcp6),
        udp_sockets: count_udp_sockets(&udp) + count_udp_sockets(&udp6),
    })
}

/// R-A4 post-listen socket-surface assertion. On Linux, read the live socket
/// tables and check them against the audited surface; a read failure is
/// fail-closed (we cannot confirm the surface, so we refuse). On non-Linux
/// targets there is no `/proc/self/net`, so the runtime check is *unavailable*.
#[cfg(target_os = "linux")]
pub fn check_surface(expected_tcp_port: u16) -> SurfaceCheck {
    let surface = match read_proc_self_net() {
        Ok(s) => s,
        // Fail-closed: on Linux the v4 tables always exist; if we cannot read
        // them we cannot confirm the audited surface, so refuse to listen.
        Err(e) => {
            return SurfaceCheck::Violation(format!(
                "cannot read /proc/self/net to confirm the surface: {e}"
            ))
        }
    };
    match check_controlled_surface(&surface, expected_tcp_port) {
        Ok(()) => SurfaceCheck::Ok,
        Err(why) => SurfaceCheck::Violation(why),
    }
}

/// Non-Linux: no `/proc/self/net`. Per R-A4's macOS/iOS clause the runtime check
/// is unavailable here and the surface rests on the §18 compile-out + R-B4.
#[cfg(not(target_os = "linux"))]
pub fn check_surface(_expected_tcp_port: u16) -> SurfaceCheck {
    SurfaceCheck::Unavailable("no /proc/self/net on this platform".to_string())
}
