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
        let result = socket.send(message).and_then(|sent| {
            if sent == message.len() {
                Ok(())
            } else {
                Err(io::Error::new(io::ErrorKind::WriteZero, "Incomplete systemd notification"))
            }
        });
        if result.is_err() {
            self.socket.take();
        }
        result
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
