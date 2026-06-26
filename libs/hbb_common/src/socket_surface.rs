//! R-A4 live socket-surface self-check (§9, "secure by assertion").
//!
//! After the direct listener binds, the controlled box's reachable network
//! surface MUST equal **exactly one TCP listener on the pinned v4 port** (21118,
//! R-F4) and **zero UDP sockets of any kind** — not merely "no UDP listener" but
//! no UDP socket at all, so an ephemeral OS-assigned-port egress UDP socket (a
//! STUN probe — R-S11 — or a dependency phoning home) cannot slip past a
//! listener-only check (§4.1). This reads the kernel's per-netns socket tables
//! at `/proc/self/net/{tcp,tcp6,udp,udp6}`. On the hardened Linux appliance the box is
//! the sole network service in its namespace, so the netns surface *is* the
//! process surface (§14 / R-D3 confinement); if other network services share the
//! namespace they must be accounted for, or the box must run in its own netns.
//! Windows and Android do not get that netns guarantee, so their runtime checks
//! filter to sockets owned by this process: Windows uses IP Helper owner-PID
//! tables, while Android maps `/proc/self/fd` `socket:[inode]` links back to
//! `/proc/self/net/*` rows.
//!
//! It is a **bind/listener-surface check only**: an outbound TCP `connect` has no
//! listener row, so TCP-egress silence rests on the compile-time removal (R-D6)
//! plus the operator firewall, **not** on this assertion — R-A4 explicitly
//! forbids over-crediting it with catching egress.
//!
//! macOS/iOS still report [`SurfaceCheck::Unavailable`]: iOS binds no inbound
//! socket, and macOS artifact parity remains a separate Apple-toolchain path.

#[cfg(target_os = "android")]
use std::collections::HashSet;

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
    parse_tcp_listen_ports_filtered(contents, None)
}

/// Android process-owned TCP parser: same `/proc/self/net/{tcp,tcp6}` format as
/// Linux, but rows are filtered to inodes referenced by this process's
/// `/proc/self/fd/socket:[inode]` links.
pub fn parse_tcp_listen_ports_for_inodes(
    contents: &str,
    socket_inodes: &std::collections::HashSet<u64>,
) -> Vec<u16> {
    parse_tcp_listen_ports_filtered(contents, Some(socket_inodes))
}

fn parse_tcp_listen_ports_filtered(
    contents: &str,
    socket_inodes: Option<&std::collections::HashSet<u64>>,
) -> Vec<u16> {
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
        if let Some(socket_inodes) = socket_inodes {
            let Some(inode) = parse_proc_net_inode(&cols) else {
                continue;
            };
            if !socket_inodes.contains(&inode) {
                continue;
            }
        }
        if let Some(port) = parse_local_port(cols[1]) {
            ports.push(port);
        }
    }
    ports
}

/// Count data rows (sockets) in a `/proc/self/net/{udp,udp6}` table — every data
/// row is a UDP socket, listening or not. The header line and blank lines are
/// skipped. R-A4 requires this total to be zero on the --server process.
pub fn count_udp_sockets(contents: &str) -> usize {
    count_udp_sockets_filtered(contents, None)
}

/// Android process-owned UDP parser. Counts only UDP rows whose inode belongs to
/// this process.
pub fn count_udp_sockets_for_inodes(
    contents: &str,
    socket_inodes: &std::collections::HashSet<u64>,
) -> usize {
    count_udp_sockets_filtered(contents, Some(socket_inodes))
}

fn count_udp_sockets_filtered(
    contents: &str,
    socket_inodes: Option<&std::collections::HashSet<u64>>,
) -> usize {
    contents
        .lines()
        .filter(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            // a data row's column 1 parses as HEXIP:HEXPORT; the header's
            // "local_address" does not, so the header is excluded.
            if cols.len() < 4 || parse_local_port(cols[1]).is_none() {
                return false;
            }
            if let Some(socket_inodes) = socket_inodes {
                let Some(inode) = parse_proc_net_inode(&cols) else {
                    return false;
                };
                socket_inodes.contains(&inode)
            } else {
                true
            }
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

fn parse_proc_net_inode(cols: &[&str]) -> Option<u64> {
    // /proc/net/{tcp,udp} rows place `inode` after `uid timeout`, at column 9
    // in the kernel format emitted on Linux and Android.
    cols.get(9)?.parse().ok()
}

pub fn parse_proc_fd_socket_inode(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// The R-A4 surface policy for the --server process: **exactly
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
            "found {} UDP socket(s); R-A4 requires zero UDP of any kind — a \
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

#[cfg(target_os = "android")]
fn read_proc_self_socket_inodes() -> std::io::Result<HashSet<u64>> {
    let mut inodes = HashSet::new();
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let target = match std::fs::read_link(entry.path()) {
            Ok(target) => target,
            Err(_) => continue,
        };
        if let Some(inode) = parse_proc_fd_socket_inode(&target.to_string_lossy()) {
            inodes.insert(inode);
        }
    }
    Ok(inodes)
}

#[cfg(target_os = "android")]
pub fn read_android_proc_self_net() -> std::io::Result<SocketSurface> {
    let socket_inodes = read_proc_self_socket_inodes()?;
    let tcp4 = std::fs::read_to_string("/proc/self/net/tcp")?;
    let tcp6 = std::fs::read_to_string("/proc/self/net/tcp6").unwrap_or_default();
    let udp = std::fs::read_to_string("/proc/self/net/udp")?;
    let udp6 = std::fs::read_to_string("/proc/self/net/udp6").unwrap_or_default();
    Ok(SocketSurface {
        tcp4_listen_ports: parse_tcp_listen_ports_for_inodes(&tcp4, &socket_inodes),
        tcp6_listen_ports: parse_tcp_listen_ports_for_inodes(&tcp6, &socket_inodes),
        udp_sockets: count_udp_sockets_for_inodes(&udp, &socket_inodes)
            + count_udp_sockets_for_inodes(&udp6, &socket_inodes),
    })
}

#[cfg(target_os = "windows")]
fn windows_port_from_network_order(port: u32) -> u16 {
    u16::from_be(port as u16)
}

#[cfg(target_os = "windows")]
fn windows_table_buffer<F>(mut call: F) -> std::io::Result<Vec<usize>>
where
    F: FnMut(winapi::shared::ntdef::PVOID, *mut winapi::shared::minwindef::DWORD) -> u32,
{
    use std::mem::size_of;
    use std::ptr::null_mut;
    use winapi::shared::{
        minwindef::DWORD,
        winerror::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR},
    };

    let mut size: DWORD = 0;
    let first = call(null_mut(), &mut size);
    if first != ERROR_INSUFFICIENT_BUFFER && first != NO_ERROR {
        return Err(std::io::Error::from_raw_os_error(first as i32));
    }
    if size == 0 {
        return Ok(Vec::new());
    }
    let words = (size as usize + size_of::<usize>() - 1) / size_of::<usize>();
    let mut buffer = vec![0usize; words];
    let rc = call(buffer.as_mut_ptr() as _, &mut size);
    if rc == NO_ERROR {
        Ok(buffer)
    } else {
        Err(std::io::Error::from_raw_os_error(rc as i32))
    }
}

#[cfg(target_os = "windows")]
unsafe fn windows_tcp4_listen_ports_for_pid(pid: u32) -> std::io::Result<Vec<u16>> {
    use std::slice;
    use winapi::{
        shared::{
            iprtrmib::TCP_TABLE_OWNER_PID_ALL,
            ntdef::ULONG,
            tcpmib::{MIB_TCP_STATE_LISTEN, MIB_TCPTABLE_OWNER_PID},
            ws2def::AF_INET,
        },
        um::iphlpapi::GetExtendedTcpTable,
    };

    let buffer = windows_table_buffer(|table, size| unsafe {
        GetExtendedTcpTable(table, size, 0, AF_INET as ULONG, TCP_TABLE_OWNER_PID_ALL, 0)
    })?;
    if buffer.is_empty() {
        return Ok(Vec::new());
    }
    let table = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
    let rows = slice::from_raw_parts((*table).table.as_ptr(), (*table).dwNumEntries as usize);
    Ok(rows
        .iter()
        .filter(|row| row.dwOwningPid == pid && row.dwState == MIB_TCP_STATE_LISTEN as u32)
        .map(|row| windows_port_from_network_order(row.dwLocalPort))
        .collect())
}

#[cfg(target_os = "windows")]
unsafe fn windows_tcp6_listen_ports_for_pid(pid: u32) -> std::io::Result<Vec<u16>> {
    use std::slice;
    use winapi::{
        shared::{
            iprtrmib::TCP_TABLE_OWNER_PID_ALL,
            ntdef::ULONG,
            tcpmib::{MIB_TCP_STATE_LISTEN, MIB_TCP6TABLE_OWNER_PID},
            ws2def::AF_INET6,
        },
        um::iphlpapi::GetExtendedTcpTable,
    };

    let buffer = windows_table_buffer(|table, size| unsafe {
        GetExtendedTcpTable(
            table,
            size,
            0,
            AF_INET6 as ULONG,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    })?;
    if buffer.is_empty() {
        return Ok(Vec::new());
    }
    let table = buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
    let rows = slice::from_raw_parts((*table).table.as_ptr(), (*table).dwNumEntries as usize);
    Ok(rows
        .iter()
        .filter(|row| row.dwOwningPid == pid && row.dwState == MIB_TCP_STATE_LISTEN as u32)
        .map(|row| windows_port_from_network_order(row.dwLocalPort))
        .collect())
}

#[cfg(target_os = "windows")]
unsafe fn windows_udp4_socket_count_for_pid(pid: u32) -> std::io::Result<usize> {
    use std::slice;
    use winapi::{
        shared::{
            iprtrmib::UDP_TABLE_OWNER_PID, ntdef::ULONG, udpmib::MIB_UDPTABLE_OWNER_PID,
            ws2def::AF_INET,
        },
        um::iphlpapi::GetExtendedUdpTable,
    };

    let buffer = windows_table_buffer(|table, size| unsafe {
        GetExtendedUdpTable(table, size, 0, AF_INET as ULONG, UDP_TABLE_OWNER_PID, 0)
    })?;
    if buffer.is_empty() {
        return Ok(0);
    }
    let table = buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
    let rows = slice::from_raw_parts((*table).table.as_ptr(), (*table).dwNumEntries as usize);
    Ok(rows.iter().filter(|row| row.dwOwningPid == pid).count())
}

#[cfg(target_os = "windows")]
unsafe fn windows_udp6_socket_count_for_pid(pid: u32) -> std::io::Result<usize> {
    use std::slice;
    use winapi::{
        shared::{
            iprtrmib::UDP_TABLE_OWNER_PID, ntdef::ULONG, udpmib::MIB_UDP6TABLE_OWNER_PID,
            ws2def::AF_INET6,
        },
        um::iphlpapi::GetExtendedUdpTable,
    };

    let buffer = windows_table_buffer(|table, size| unsafe {
        GetExtendedUdpTable(table, size, 0, AF_INET6 as ULONG, UDP_TABLE_OWNER_PID, 0)
    })?;
    if buffer.is_empty() {
        return Ok(0);
    }
    let table = buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID;
    let rows = slice::from_raw_parts((*table).table.as_ptr(), (*table).dwNumEntries as usize);
    Ok(rows.iter().filter(|row| row.dwOwningPid == pid).count())
}

#[cfg(target_os = "windows")]
pub fn read_windows_process_tables() -> std::io::Result<SocketSurface> {
    let pid = std::process::id();
    unsafe {
        Ok(SocketSurface {
            tcp4_listen_ports: windows_tcp4_listen_ports_for_pid(pid)?,
            tcp6_listen_ports: windows_tcp6_listen_ports_for_pid(pid)?,
            udp_sockets: windows_udp4_socket_count_for_pid(pid)?
                + windows_udp6_socket_count_for_pid(pid)?,
        })
    }
}

/// R-A4 post-listen socket-surface assertion. On Linux, read the live namespace
/// socket tables and check them against the audited surface; a read failure is
/// fail-closed (we cannot confirm the surface, so we refuse).
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

#[cfg(target_os = "android")]
pub fn check_surface(expected_tcp_port: u16) -> SurfaceCheck {
    let surface = match read_android_proc_self_net() {
        Ok(s) => s,
        Err(e) => {
            return SurfaceCheck::Violation(format!(
                "cannot read Android /proc self socket tables to confirm this process's surface: {e}"
            ))
        }
    };
    match check_controlled_surface(&surface, expected_tcp_port) {
        Ok(()) => SurfaceCheck::Ok,
        Err(why) => SurfaceCheck::Violation(why),
    }
}

#[cfg(target_os = "windows")]
pub fn check_surface(expected_tcp_port: u16) -> SurfaceCheck {
    let surface = match read_windows_process_tables() {
        Ok(s) => s,
        Err(e) => {
            return SurfaceCheck::Violation(format!(
                "cannot read Windows IP Helper owner tables to confirm this process's surface: {e}"
            ))
        }
    };
    match check_controlled_surface(&surface, expected_tcp_port) {
        Ok(()) => SurfaceCheck::Ok,
        Err(why) => SurfaceCheck::Violation(why),
    }
}

/// macOS/iOS and other non-Linux, non-Android, non-Windows targets still have no
/// shipped runtime socket assertion in this repository.
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "windows")))]
pub fn check_surface(_expected_tcp_port: u16) -> SurfaceCheck {
    SurfaceCheck::Unavailable("no platform socket-surface assertion on this target".to_string())
}
