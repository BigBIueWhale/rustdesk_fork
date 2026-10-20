//! R-A4 live socket-surface self-check (§9, "secure by assertion").
//!
//! After the direct listener binds, the controlled box's reachable network
//! surface MUST equal **exactly one TCP listener on the pinned v4 port** (21118,
//! R-F4) and **zero UDP sockets of any kind** — not merely "no UDP listener" but
//! no UDP socket at all, so an ephemeral OS-assigned-port egress UDP socket (a
//! STUN probe — R-S11 — or a dependency phoning home) cannot slip past a
//! listener-only check (§4.1). Every platform scopes the check to the sockets
//! **owned by this process** — the assertion is about *this rustdesk --server
//! process's* reachable surface, never the whole host. Linux and Android query
//! owned socket descriptors; Windows uses the IP Helper owner-PID tables.
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

/// This process's TCP listeners and UDP sockets relevant to R-A4.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SocketSurface {
    /// Local ports of v4 TCP listeners.
    pub tcp4_listen_ports: Vec<u16>,
    /// Local ports of v6 TCP listeners.
    pub tcp6_listen_ports: Vec<u16>,
    /// Count of all owned IPv4/IPv6 UDP sockets, including unbound sockets.
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

/// Query the sockets owned by this process, including UDP sockets not yet bound.
/// Enumeration is observational, not atomic with other threads opening or changing sockets.
/// Every retained query descriptor closes before returning, including on failure.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn read_process_socket_surface() -> std::io::Result<SocketSurface> {
    read_process_socket_descriptors(std::fs::read_dir("/proc/thread-self/fd")?.map(|entry| {
        entry?.file_name().to_str()
            .and_then(|name| name.parse::<std::os::fd::RawFd>().ok())
            .filter(|fd| *fd >= 0)
            .ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::InvalidData, "invalid process descriptor name"))
    }))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_process_socket_descriptors(
    descriptors: impl IntoIterator<Item = std::io::Result<std::os::fd::RawFd>>,
) -> std::io::Result<SocketSurface> {
    use crate::libc;
    use std::os::fd::{AsFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    // Finish enumeration before duplicating: our query descriptors must not grow the walk.
    let descriptors = descriptors.into_iter().collect::<std::io::Result<Vec<_>>>()?;
    let mut surface = SocketSurface::default();
    let mut seen = HashSet::new();
    let mut retained: Vec<OwnedFd> = Vec::new();
    for fd in descriptors {
        // Pin the exact open file description through every query.
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EBADF) {
                continue; // The enumerated descriptor has closed.
            }
            return Err(error);
        }
        // SAFETY: successful F_DUPFD_CLOEXEC returned a new, exclusively owned descriptor.
        let file = unsafe { std::fs::File::from_raw_fd(duplicate) };
        let metadata = file.metadata()?;
        if !metadata.file_type().is_socket() {
            continue;
        }
        let identity = (metadata.dev(), metadata.ino());
        if seen.contains(&identity) {
            continue;
        }
        let domain = socket_int_option(file.as_fd(), libc::SO_DOMAIN)?;
        if domain != libc::AF_INET && domain != libc::AF_INET6 {
            continue;
        }
        let protocol = socket_int_option(file.as_fd(), libc::SO_PROTOCOL)?;
        if protocol == libc::IPPROTO_UDP {
            surface.udp_sockets += 1;
            seen.insert(identity);
            retained.push(file.into());
            continue;
        }
        if protocol != libc::IPPROTO_TCP
            || socket_int_option(file.as_fd(), libc::SO_TYPE)? != libc::SOCK_STREAM
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData, "unexpected Internet socket protocol or type"));
        }
        match socket_int_option(file.as_fd(), libc::SO_ACCEPTCONN)? {
            0 => continue,
            1 => {}
            _ => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData, "invalid socket listener state")),
        }
        let listener = std::net::TcpListener::from(OwnedFd::from(file));
        match listener.local_addr()? {
            std::net::SocketAddr::V4(address) if domain == libc::AF_INET =>
                surface.tcp4_listen_ports.push(address.port()),
            std::net::SocketAddr::V6(address) if domain == libc::AF_INET6 =>
                surface.tcp6_listen_ports.push(address.port()),
            _ => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData, "socket address family changed")),
        }
        // Retain reported sockets until enumeration completes so inode identities cannot recycle.
        seen.insert(identity);
        retained.push(listener.into());
    }
    Ok(surface)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn socket_int_option(
    fd: std::os::fd::BorrowedFd<'_>,
    option: crate::libc::c_int,
) -> std::io::Result<crate::libc::c_int> {
    use std::os::fd::AsRawFd;
    let mut value: crate::libc::c_int = 0;
    let mut length = std::mem::size_of_val(&value) as crate::libc::socklen_t;
    // SAFETY: the borrowed descriptor stays live; value and length are initialized and writable.
    if unsafe { crate::libc::getsockopt(fd.as_raw_fd(), crate::libc::SOL_SOCKET, option,
        &mut value as *mut _ as *mut _, &mut length) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of_val(&value) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData, "invalid socket option length"));
    }
    Ok(value)
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

/// R-A4 post-listen assertion for this process's own socket descriptors.
/// A query failure refuses admission because the required surface is unconfirmed.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn check_surface(expected_tcp_port: u16) -> SurfaceCheck {
    let surface = match read_process_socket_surface() {
        Ok(s) => s,
        // Incomplete descriptor inspection cannot confirm the audited surface.
        Err(e) => {
            return SurfaceCheck::Violation(format!(
                "cannot query this process's socket surface: {e}"
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

    #[test]
    fn closed_descriptor_is_ignored() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let fd = file.as_raw_fd();
        drop(file);
        assert_eq!(read_process_socket_descriptors([Ok(fd)]).unwrap(), SocketSurface::default());
    }

    #[test]
    fn descriptor_iterator_failure_is_reported() {
        let descriptors = [Err(std::io::Error::from_raw_os_error(crate::libc::EIO))];
        assert_eq!(read_process_socket_descriptors(descriptors).unwrap_err().raw_os_error(),
            Some(crate::libc::EIO));
    }

    #[test]
    fn live_process_surface_tracks_owned_tcp_and_udp() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let _outgoing = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let _accepted = listener.accept().unwrap();
        let clean = read_process_socket_surface().unwrap();
        assert_eq!(clean.tcp4_listen_ports, [port]);
        assert!(clean.tcp6_listen_ports.is_empty());
        assert_eq!(clean.udp_sockets, 0);
        check_controlled_surface(&clean, port).unwrap();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let surface = read_process_socket_surface().unwrap();
        assert_eq!(surface.tcp4_listen_ports, [port]);
        assert_eq!(surface.udp_sockets, 1);
        assert!(check_controlled_surface(&surface, port).unwrap_err().contains("UDP"));
        drop(udp);
        check_controlled_surface(&read_process_socket_surface().unwrap(), port).unwrap();
        drop(listener);
        assert!(read_process_socket_surface().unwrap().tcp4_listen_ports.is_empty());
        println!("SOCKET_SURFACE_IO=observed kind=live-proc tcp4=1 udp=1 udp_retired=true listener_retired=true");
    }
}
