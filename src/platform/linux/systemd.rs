use std::{
    io,
    os::{
        linux::net::SocketAddrExt,
        unix::{
            ffi::OsStrExt,
            net::{SocketAddr, UnixDatagram},
        },
    },
};

pub(super) struct ServiceNotification {
    socket: Option<UnixDatagram>,
}

impl ServiceNotification {
    pub(super) fn from_environment() -> io::Result<Self> {
        let socket = std::env::var_os("NOTIFY_SOCKET")
            .map(|address| Self::connect(address.as_bytes()))
            .transpose()?;
        Ok(Self { socket })
    }

    fn connect(address: &[u8]) -> io::Result<UnixDatagram> {
        let address = match address.first() {
            Some(b'@') if address.len() > 1 => SocketAddr::from_abstract_name(&address[1..])?,
            Some(b'/') => SocketAddr::from_pathname(std::ffi::OsStr::from_bytes(address))?,
            _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid NOTIFY_SOCKET")),
        };
        let socket = UnixDatagram::unbound()?;
        socket.set_nonblocking(true)?;
        socket.connect_addr(&address)?;
        Ok(socket)
    }

    fn send(&mut self, message: &[u8]) -> io::Result<()> {
        let Some(socket) = self.socket.as_ref() else {
            return Ok(());
        };
        socket.send(message).and_then(|sent| {
            if sent == message.len() {
                Ok(())
            } else {
                Err(io::Error::new(io::ErrorKind::WriteZero, "Incomplete systemd notification"))
            }
        })
    }

    pub(super) fn ready(&mut self) -> io::Result<()> {
        self.send(b"READY=1")
    }

    pub(super) fn stopping(&mut self) -> io::Result<()> {
        self.send(b"STOPPING=1\nEXTEND_TIMEOUT_USEC=30000000")
    }

    pub(super) fn extend_stop(&mut self) -> io::Result<()> {
        self.send(b"EXTEND_TIMEOUT_USEC=30000000")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::{fs::DirBuilderExt, io::AsRawFd},
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    fn name() -> String {
        format!("rustdesk-notify-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))
    }

    fn abstract_peer() -> (UnixDatagram, ServiceNotification, SocketAddr) {
        let name = name();
        let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let peer = UnixDatagram::bind_addr(&address).unwrap();
        peer.set_nonblocking(true).unwrap();
        let socket = ServiceNotification::connect(format!("@{name}").as_bytes()).unwrap();
        (peer, ServiceNotification { socket: Some(socket) }, address)
    }

    fn receive(peer: &UnixDatagram, expected: &[u8]) {
        let mut data = [0; 128];
        let count = peer.recv(&mut data).unwrap();
        assert_eq!(&data[..count], expected);
    }

    #[test]
    fn absent_manager_is_optional() {
        assert!(std::env::var_os("NOTIFY_SOCKET").is_none());
        let mut notification = ServiceNotification::from_environment().unwrap();
        assert!(notification.socket.is_none());
        notification.ready().unwrap();
        notification.stopping().unwrap();
        notification.extend_stop().unwrap();
    }

    #[test]
    fn malformed_addresses_refuse() {
        for address in [b"".as_slice(), b"@", b"relative", b"/invalid\0address"] {
            assert_eq!(ServiceNotification::connect(address).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn pathname_notifications_preserve_exact_datagrams() {
        let directory = std::env::temp_dir().join(name());
        std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let path = directory.join("notify");
        let peer = UnixDatagram::bind(&path).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut notification = ServiceNotification {
            socket: Some(ServiceNotification::connect(path.as_os_str().as_bytes()).unwrap()),
        };
        notification.ready().unwrap();
        receive(&peer, b"READY=1");
        notification.stopping().unwrap();
        receive(&peer, b"STOPPING=1\nEXTEND_TIMEOUT_USEC=30000000");
        notification.extend_stop().unwrap();
        receive(&peer, b"EXTEND_TIMEOUT_USEC=30000000");
        drop(peer);
        drop(notification);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn queue_pressure_retains_endpoint_and_recovers() {
        let (peer, mut notification, address) = abstract_peer();
        let descriptor = notification.socket.as_ref().unwrap().as_raw_fd();
        let filler = UnixDatagram::unbound().unwrap();
        filler.set_nonblocking(true).unwrap();
        filler.connect_addr(&address).unwrap();
        let mut queued = 0;
        loop {
            assert!(queued < 4096, "kernel queue never reached backpressure");
            match filler.send(b"occupied") {
                Ok(count) => { assert_eq!(count, 8); queued += 1; }
                Err(error) => { assert_eq!(error.kind(), io::ErrorKind::WouldBlock); break; }
            }
        }
        assert!(queued > 0);
        assert_eq!(notification.stopping().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(notification.extend_stop().unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(notification.socket.as_ref().unwrap().as_raw_fd(), descriptor);
        for _ in 0..queued { receive(&peer, b"occupied"); }
        let mut data = [0; 128];
        assert_eq!(peer.recv(&mut data).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        notification.stopping().unwrap();
        receive(&peer, b"STOPPING=1\nEXTEND_TIMEOUT_USEC=30000000");
        notification.extend_stop().unwrap();
        receive(&peer, b"EXTEND_TIMEOUT_USEC=30000000");
        assert_eq!(notification.socket.as_ref().unwrap().as_raw_fd(), descriptor);
    }

    #[test]
    fn closed_peer_errors_persist_without_redirecting_to_replacement() {
        let (peer, mut notification, address) = abstract_peer();
        let descriptor = notification.socket.as_ref().unwrap().as_raw_fd();
        drop(peer);
        assert!(notification.stopping().is_err());
        let replacement = UnixDatagram::bind_addr(&address).unwrap();
        replacement.set_nonblocking(true).unwrap();
        for _ in 0..3 {
            assert!(notification.extend_stop().is_err());
            assert_eq!(notification.socket.as_ref().unwrap().as_raw_fd(), descriptor);
        }
        let mut data = [0; 128];
        assert_eq!(replacement.recv(&mut data).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        let mut fresh = ServiceNotification {
            socket: Some(ServiceNotification::connect(
                format!("@{}", std::str::from_utf8(address.as_abstract_name().unwrap()).unwrap()).as_bytes(),
            ).unwrap()),
        };
        fresh.ready().unwrap();
        receive(&replacement, b"READY=1");
    }
}
