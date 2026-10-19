//! R-A4 live socket-surface self-check (§9, "secure by assertion").
//!
//! After the direct listener binds, the controlled box's reachable network
//! surface MUST equal **exactly one TCP listener on the pinned v4 port** (21118,
//! R-F4) and **zero UDP sockets of any kind** — not merely "no UDP listener" but
//! no UDP socket at all, so an ephemeral OS-assigned-port egress UDP socket (a
//! STUN probe — R-S11 — or a dependency phoning home) cannot slip past a
//! listener-only check (§4.1). Every platform scopes the check to the sockets
//! **owned by this process** — the assertion is about *this rustdesk --server
//! process's* reachable surface, never the whole host: Linux and Android map the
//! `/proc/self/fd` `socket:[inode]` links back to the
//! `/proc/self/net/{tcp,tcp6,udp,udp6}` rows, and Windows uses the IP Helper
//! owner-PID tables. Process-scoping is REQUIRED, not merely convenient: the box
//! is **not** guaranteed its own network namespace — `docs/DEPLOYMENT.md` runs
//! the fork on a host that also serves SSH (and Ubuntu's `systemd-resolved` holds
//! a UDP `:53`), so the assertion counts only THIS process's inodes rather than
//! a netns-wide read that would sweep in those co-resident, unrelated host
//! sockets. Scoping to this process's own inodes still catches the real threat
//! this assertion exists for — a rogue listener or an egress UDP socket opened by
//! rustdesk or one of its dependencies — while ignoring the host's other services.
//!
//! It is a **bind/listener-surface check only**: an outbound TCP `connect` has no
//! listener row, so TCP-egress silence rests on the compile-time removal (R-D6)
//! plus the operator firewall, **not** on this assertion — R-A4 explicitly
//! forbids over-crediting it with catching egress.
//!
//! macOS/iOS still report [`SurfaceCheck::Unavailable`]: iOS binds no inbound
//! socket, and macOS artifact parity remains a separate Apple-toolchain path.

#[cfg(any(target_os = "linux", target_os = "android"))]
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

/// Read `/proc/self/net/{tcp,tcp6,udp,udp6}` and filter to the sockets **owned by
/// this process** (matched by inode against the `/proc/self/fd` `socket:[inode]`
/// links) — used on **both Linux and Android** so the R-A4 assertion is about
/// this --server process's surface, not every socket that merely shares the
/// network namespace (see the module header: the box is not guaranteed its own
/// netns). Missing v6 tables (IPv6 disabled) mean no v6 sockets; every other
/// table or descriptor-enumeration read failure is propagated to the caller.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn read_proc_self_net_owned() -> std::io::Result<SocketSurface> {
    let socket_inodes = read_proc_self_socket_inodes()?;
    let tcp4 = std::fs::read_to_string("/proc/self/net/tcp")?;
    let tcp6 = read_optional_ipv6_table(std::path::Path::new("/proc/self/net/tcp6"))?;
    let udp = std::fs::read_to_string("/proc/self/net/udp")?;
    let udp6 = read_optional_ipv6_table(std::path::Path::new("/proc/self/net/udp6"))?;
    Ok(SocketSurface {
        tcp4_listen_ports: parse_tcp_listen_ports_for_inodes(&tcp4, &socket_inodes),
        tcp6_listen_ports: parse_tcp_listen_ports_for_inodes(&tcp6, &socket_inodes),
        udp_sockets: count_udp_sockets_for_inodes(&udp, &socket_inodes)
            + count_udp_sockets_for_inodes(&udp6, &socket_inodes),
    })
}

/// This process's own socket inodes, read from the `socket:[inode]` symlinks in
/// `/proc/self/fd`. Used by `read_proc_self_net_owned` (Linux + Android) to scope
/// the surface check to sockets this process actually opened.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_proc_self_socket_inodes() -> std::io::Result<HashSet<u64>> {
    read_proc_socket_inodes(std::fs::read_dir("/proc/self/fd")?)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_optional_ipv6_table(path: &std::path::Path) -> std::io::Result<String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_proc_socket_inodes(
    entries: impl IntoIterator<Item = std::io::Result<std::fs::DirEntry>>,
) -> std::io::Result<HashSet<u64>> {
    let mut inodes = HashSet::new();
    for entry in entries {
        let entry = entry?;
        let target = match std::fs::read_link(entry.path()) {
            Ok(target) => target,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if let Some(inode) = parse_proc_fd_socket_inode(&target.to_string_lossy()) {
            inodes.insert(inode);
        }
    }
    Ok(inodes)
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

/// R-A4 post-listen socket-surface assertion (Linux + Android). Read the live
/// socket tables **scoped to this process** and check them against the audited
/// surface; a read failure is fail-closed (we cannot confirm the surface, so we
/// refuse). Both platforms map the `/proc/self/fd` socket inodes to the
/// `/proc/self/net` rows (`read_proc_self_net_owned`), so a co-resident
/// SSH/DNS/desktop socket in a shared network namespace is correctly ignored.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn check_surface(expected_tcp_port: u16) -> SurfaceCheck {
    let surface = match read_proc_self_net_owned() {
        Ok(s) => s,
        // Fail-closed: /proc/self always exists for the running process; if we
        // cannot read it we cannot confirm the audited surface, so refuse.
        Err(e) => {
            return SurfaceCheck::Violation(format!(
                "cannot read /proc/self to confirm this process's socket surface: {e}"
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn unbound_socket(domain: i32, kind: i32, protocol: i32) -> OwnedFd {
        let fd = unsafe { crate::libc::socket(domain, kind | crate::libc::SOCK_CLOEXEC, protocol) };
        assert!(fd >= 0, "{}", std::io::Error::last_os_error());
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    fn assert_udp_refused(port: u16) {
        let result = check_surface(port);
        println!("SOCKET_DESCRIPTOR=observed kind=udp result={result:?}");
        assert!(matches!(result, SurfaceCheck::Violation(ref why) if why.contains("found 1 UDP")), "{result:?}");
    }

    #[test]
    fn unbound_ipv4_udp_is_refused() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let udp = std::net::UdpSocket::from(unbound_socket(crate::libc::AF_INET,
            crate::libc::SOCK_DGRAM, crate::libc::IPPROTO_UDP));
        assert_eq!(udp.local_addr().unwrap().port(), 0);
        assert_udp_refused(listener.local_addr().unwrap().port());
    }

    #[test]
    fn unbound_ipv6_udp_is_refused() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let udp = std::net::UdpSocket::from(unbound_socket(crate::libc::AF_INET6,
            crate::libc::SOCK_DGRAM, crate::libc::IPPROTO_UDP));
        assert_eq!(udp.local_addr().unwrap().port(), 0);
        assert_udp_refused(listener.local_addr().unwrap().port());
    }

    #[test]
    fn bound_udp_aliases_count_once_until_last_owner_closes() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let alias = udp.try_clone().unwrap();
        assert_udp_refused(port);
        drop(udp);
        assert_udp_refused(port);
        drop(alias);
        assert_eq!(check_surface(port), SurfaceCheck::Ok);
    }

    #[test]
    fn listener_aliases_and_local_descriptors_preserve_surface_and_fd_count() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let alias = listener.try_clone().unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();
        let local = std::os::unix::net::UnixStream::pair().unwrap();
        let count = || std::fs::read_dir("/proc/self/fd").unwrap()
            .collect::<std::io::Result<Vec<_>>>().unwrap().len();
        let before = count();
        for _ in 0..16 {
            assert_eq!(check_surface(alias.local_addr().unwrap().port()), SurfaceCheck::Ok);
        }
        assert_eq!(count(), before);
        drop((file, local, alias));
    }

    #[test]
    fn additional_ipv4_listener_is_refused() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let extra = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(matches!(check_surface(port), SurfaceCheck::Violation(ref why) if why.contains("found 2")));
        drop(extra);
        assert_eq!(check_surface(port), SurfaceCheck::Ok);
    }

    #[test]
    fn ipv6_listener_is_refused() {
        // This executes only in the zero-NIC VM's network-none container.
        let listener = std::net::TcpListener::bind("[::]:0").unwrap();
        let result = check_surface(listener.local_addr().unwrap().port());
        assert!(matches!(result, SurfaceCheck::Violation(ref why) if why.contains("IPv6")), "{result:?}");
    }

    #[test]
    fn foreign_process_udp_is_not_part_of_this_process_surface() {
        use std::io::{BufRead, Read};
        use std::process::{Child, Command, Stdio};
        struct Peer(Child);
        impl Drop for Peer {
            fn drop(&mut self) {
                if let Err(error) = self.0.kill() { eprintln!("peer kill: {error}"); }
                self.0.wait().unwrap();
            }
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = Peer(Command::new("python3").args(["-I", "-S", "-c",
            "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('127.0.0.1',0)); print('ready',flush=True); sys.stdin.read(1)"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap());
        let mut ready = String::new();
        std::io::BufReader::new(peer.0.stdout.take().unwrap()).take(32).read_line(&mut ready).unwrap();
        assert_eq!(ready, "ready\n");
        assert_eq!(check_surface(listener.local_addr().unwrap().port()), SurfaceCheck::Ok);
    }

    #[test]
    fn unbound_tcp_is_not_a_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = unbound_socket(crate::libc::AF_INET, crate::libc::SOCK_STREAM, crate::libc::IPPROTO_TCP);
        assert!(tcp.as_raw_fd() >= 0);
        assert_eq!(check_surface(listener.local_addr().unwrap().port()), SurfaceCheck::Ok);
    }

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "rustdesk-socket-io-{}-{}",
                std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn ipv6_table_missing_is_optional_and_readable_contents_are_preserved() {
        let fixture = Fixture::new();
        let table = fixture.path("tcp6");
        assert!(read_optional_ipv6_table(&table).unwrap().is_empty());
        std::fs::write(&table, b"unchanged table\n").unwrap();
        assert_eq!(read_optional_ipv6_table(&table).unwrap(), "unchanged table\n");
        assert_eq!(std::fs::read(&table).unwrap(), b"unchanged table\n");
    }

    #[test]
    fn ipv6_table_permission_failure_is_not_an_empty_table() {
        assert_ne!(unsafe { crate::libc::geteuid() }, 0);
        let fixture = Fixture::new();
        let table = fixture.path("udp6");
        std::fs::write(&table, b"unchanged table\n").unwrap();
        std::fs::set_permissions(&table, std::fs::Permissions::from_mode(0)).unwrap();
        let native_error = std::fs::read_to_string(&table).unwrap_err();
        let result = read_optional_ipv6_table(&table);
        std::fs::set_permissions(&table, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(native_error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read(&table).unwrap(), b"unchanged table\n");
        println!("SOCKET_SURFACE_IO=observed kind=ipv6-permission errno={} refused={}",
            native_error.raw_os_error().unwrap(), result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn ipv6_table_invalid_utf8_is_reported() {
        let fixture = Fixture::new();
        let table = fixture.path("tcp6");
        std::fs::write(&table, [0xff]).unwrap();
        let native_error = std::fs::read_to_string(&table).unwrap_err();
        let result = read_optional_ipv6_table(&table);
        assert_eq!(native_error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read(&table).unwrap(), [0xff]);
        println!("SOCKET_SURFACE_IO=observed kind=ipv6-invalid-utf8 refused={}", result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn ipv6_table_directory_failure_is_reported() {
        let fixture = Fixture::new();
        let native_error = std::fs::read_to_string(&fixture.0).unwrap_err();
        let result = read_optional_ipv6_table(&fixture.0);
        println!("SOCKET_SURFACE_IO=observed kind=ipv6-directory errno={} refused={}",
            native_error.raw_os_error().unwrap(), result.is_err());
        assert_eq!(result.unwrap_err().raw_os_error(), native_error.raw_os_error());
    }

    fn entries(path: &Path) -> Vec<std::fs::DirEntry> {
        std::fs::read_dir(path).unwrap().collect::<std::io::Result<Vec<_>>>().unwrap()
    }

    #[test]
    fn socket_inode_lookup_permission_failure_is_reported() {
        assert_ne!(unsafe { crate::libc::geteuid() }, 0);
        let fixture = Fixture::new();
        let directory = fixture.path("fd");
        std::fs::create_dir(&directory).unwrap();
        let link = directory.join("7");
        std::os::unix::fs::symlink("socket:[12345]", &link).unwrap();
        let entries = entries(&directory);
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o400)).unwrap();
        let native_error = std::fs::read_link(&link).unwrap_err();
        let result = read_proc_socket_inodes(entries.into_iter().map(Ok));
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(native_error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read_link(&link).unwrap(), Path::new("socket:[12345]"));
        println!("SOCKET_SURFACE_IO=observed kind=fd-permission errno={} refused={}",
            native_error.raw_os_error().unwrap(), result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn socket_inode_vanished_entry_is_ignored() {
        let fixture = Fixture::new();
        std::os::unix::fs::symlink("socket:[17]", fixture.path("vanished")).unwrap();
        std::os::unix::fs::symlink("socket:[23]", fixture.path("live")).unwrap();
        std::os::unix::fs::symlink("/dev/null", fixture.path("ordinary")).unwrap();
        let entries = entries(&fixture.0);
        std::fs::remove_file(fixture.path("vanished")).unwrap();
        let inodes = read_proc_socket_inodes(entries.into_iter().map(Ok)).unwrap();
        assert_eq!(inodes, HashSet::from([23]));
        assert_eq!(std::fs::read_link(fixture.path("live")).unwrap(), Path::new("socket:[23]"));
    }

    #[test]
    fn socket_inode_iterator_failure_is_reported() {
        let entries = vec![Err(std::io::Error::from_raw_os_error(crate::libc::EIO))];
        let result = read_proc_socket_inodes(entries);
        println!("SOCKET_SURFACE_IO=observed kind=iterator injected_errno={} refused={}",
            crate::libc::EIO, result.is_err());
        assert_eq!(result.unwrap_err().raw_os_error(), Some(crate::libc::EIO));
    }

    #[test]
    fn socket_inode_nonlink_failure_is_reported() {
        let fixture = Fixture::new();
        let entry = fixture.path("unexpected");
        std::fs::write(&entry, b"unchanged").unwrap();
        let native_error = std::fs::read_link(&entry).unwrap_err();
        let result = read_proc_socket_inodes(entries(&fixture.0).into_iter().map(Ok));
        assert_eq!(std::fs::read(&entry).unwrap(), b"unchanged");
        println!("SOCKET_SURFACE_IO=observed kind=fd-nonlink errno={} refused={}",
            native_error.raw_os_error().unwrap(), result.is_err());
        assert_eq!(result.unwrap_err().raw_os_error(), native_error.raw_os_error());
    }

    #[test]
    fn live_process_surface_tracks_owned_tcp_and_udp() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let clean = read_proc_self_net_owned().unwrap();
        assert_eq!(clean.tcp4_listen_ports, [port]);
        assert!(clean.tcp6_listen_ports.is_empty());
        assert_eq!(clean.udp_sockets, 0);
        check_controlled_surface(&clean, port).unwrap();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let surface = read_proc_self_net_owned().unwrap();
        assert_eq!(surface.tcp4_listen_ports, [port]);
        assert_eq!(surface.udp_sockets, 1);
        assert!(check_controlled_surface(&surface, port).unwrap_err().contains("UDP"));
        drop(udp);
        check_controlled_surface(&read_proc_self_net_owned().unwrap(), port).unwrap();
        drop(listener);
        assert!(read_proc_self_net_owned().unwrap().tcp4_listen_ports.is_empty());
        println!("SOCKET_SURFACE_IO=observed kind=live-proc tcp4=1 udp=1 udp_retired=true listener_retired=true");
    }
}
