use crate::{tcp, ResultType};
use std::net::SocketAddr;
use tokio::net::TcpStream;

// The flagship direct path is always TCP. The dead WebSocket transport (never
// reachable on the direct-IP fork — targets are `IP:port`, never `ws://`) was
// excised entirely (§8 "removed not disabled"). The WebRTC transport — a
// public-server ICE/STUN/TURN path, antithetical to direct-IP-only (R-SV4) — is
// likewise fully excised, so TCP is now the sole stream variant.
pub enum Stream {
    Tcp(tcp::FramedStream),
}

impl Stream {
    #[inline]
    pub fn set_raw(&mut self) {
        match self {
            Stream::Tcp(s) => s.set_raw(),
        }
    }

    #[inline]
    pub async fn send_bytes(&mut self, bytes: bytes::Bytes) -> ResultType<()> {
        match self {
            Stream::Tcp(s) => s.send_bytes(bytes).await,
        }
    }

    #[inline]
    pub async fn send_raw(&mut self, bytes: Vec<u8>) -> ResultType<()> {
        match self {
            Stream::Tcp(s) => s.send_raw(bytes).await,
        }
    }

    /// Engage the CPace two-key per-direction cipher after a confirmed handshake
    /// (R-P2/R-P10) — the keying call that carries role/direction. The legacy
    /// symmetric single-key `set_key` was removed at R-A6; CPace/Dual is the only
    /// keying path now.
    #[inline]
    pub fn set_session_keys(&mut self, keys: crate::cpace::DirectionalKeys) {
        match self {
            Stream::Tcp(s) => s.set_session_keys(keys),
        }
    }

    #[inline]
    pub fn is_secured(&self) -> bool {
        match self {
            Stream::Tcp(s) => s.is_secured(),
        }
    }

    /// The inner TCP `FramedStream`, if this is a TCP stream — the choke point's
    /// CPace handshake runs over it (the flagship direct path is always TCP).
    #[inline]
    pub fn as_framed_tcp_mut(&mut self) -> Option<&mut tcp::FramedStream> {
        match self {
            Stream::Tcp(s) => Some(s),
        }
    }

    #[inline]
    pub async fn next_timeout(
        &mut self,
        timeout: u64,
    ) -> Option<Result<bytes::BytesMut, std::io::Error>> {
        match self {
            Stream::Tcp(s) => s.next_timeout(timeout).await,
        }
    }

    /// send message
    #[inline]
    pub async fn send(&mut self, msg: &impl protobuf::Message) -> ResultType<()> {
        match self {
            Self::Tcp(tcp) => tcp.send(msg).await,
        }
    }

    /// receive message
    #[inline]
    pub async fn next(&mut self) -> Option<Result<bytes::BytesMut, std::io::Error>> {
        match self {
            Self::Tcp(tcp) => tcp.next().await,
        }
    }

    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        match self {
            Self::Tcp(tcp) => tcp.local_addr(),
        }
    }

    #[inline]
    pub fn from(stream: TcpStream, stream_addr: SocketAddr) -> Self {
        Self::Tcp(tcp::FramedStream::from(stream, stream_addr))
    }
}
