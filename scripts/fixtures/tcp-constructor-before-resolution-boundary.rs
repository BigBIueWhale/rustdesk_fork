// Exact constructor from d4c6daf5; only its name is changed for test-only A/B execution.
// Original method SHA-256: fa24872b5d95674f0bfb51223c4ce88dd7362fbac3e89fe70039007f050e988c
use crate::{bail, tcp::{new_socket, DynTcpStream, FramedStream, SecretboxCodec}, ResultType};
use std::net::SocketAddr;
use tokio::net::{lookup_host, ToSocketAddrs};
use tokio_util::codec::Framed;

impl FramedStream {
    pub async fn before_resolution_boundary<T: ToSocketAddrs + std::fmt::Display>(
        remote_addr: T,
        local_addr: Option<SocketAddr>,
        ms_timeout: u64,
    ) -> ResultType<Self> {
        for remote_addr in lookup_host(&remote_addr).await? {
            let local = if let Some(addr) = local_addr {
                addr
            } else {
                crate::config::Config::get_any_listen_addr(remote_addr.is_ipv4())
            };
            if let Ok(socket) = new_socket(local, true) {
                if let Ok(Ok(stream)) =
                    super::timeout(ms_timeout, socket.connect(remote_addr)).await
                {
                    stream.set_nodelay(true).ok();
                    let addr = stream.local_addr()?;
                    return Ok(Self::from_parts(
                        Framed::new(DynTcpStream(Box::new(stream)), SecretboxCodec::new()),
                        addr,
                    ));
                }
            }
        }
        bail!(format!("Failed to connect to {remote_addr}"));
    }
}
