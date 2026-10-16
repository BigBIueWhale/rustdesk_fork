use crate::{bail, tcp::FramedStream, ResultType, Stream};
use anyhow::Context as _;
use std::net::SocketAddr;
use tokio::net::{lookup_host, ToSocketAddrs};

#[inline]
pub fn check_port<T: std::string::ToString>(host: T, port: i32) -> String {
    let host = host.to_string();
    if crate::is_ipv6_str(&host) {
        if host.starts_with('[') {
            return host;
        }
        return format!("[{host}]:{port}");
    }
    if !host.contains(':') {
        return format!("{host}:{port}");
    }
    host
}

#[inline]
pub fn increase_port<T: std::string::ToString>(host: T, offset: i32) -> String {
    let host = host.to_string();
    if crate::is_ipv6_str(&host) {
        if host.starts_with('[') {
            let tmp: Vec<&str> = host.split("]:").collect();
            if tmp.len() == 2 {
                let port: i32 = tmp[1].parse().unwrap_or(0);
                if port > 0 {
                    return format!("{}]:{}", tmp[0], port + offset);
                }
            }
        }
    } else if host.contains(':') {
        let tmp: Vec<&str> = host.split(':').collect();
        if tmp.len() == 2 {
            let port: i32 = tmp[1].parse().unwrap_or(0);
            if port > 0 {
                return format!("{}:{}", tmp[0], port + offset);
            }
        }
    }
    host
}

pub fn split_host_port<T: std::string::ToString>(host: T) -> Option<(String, i32)> {
    let host = host.to_string();
    if crate::is_ipv6_str(&host) {
        if host.starts_with('[') {
            let tmp: Vec<&str> = host.split("]:").collect();
            if tmp.len() == 2 {
                let port: i32 = tmp[1].parse().unwrap_or(0);
                if port > 0 {
                    return Some((format!("{}]", tmp[0]), port));
                }
            }
        }
    } else if host.contains(':') {
        let tmp: Vec<&str> = host.split(':').collect();
        if tmp.len() == 2 {
            let port: i32 = tmp[1].parse().unwrap_or(0);
            if port > 0 {
                return Some((tmp[0].to_string(), port));
            }
        }
    }
    None
}

// Direct-IP fork: the flagship path is always TCP (WebSocket transport excised, §8).
#[inline]
pub async fn connect_tcp<T: ToSocketAddrs + std::fmt::Display>(
    target: T,
    ms_timeout: u64,
) -> ResultType<crate::Stream> {
    connect_tcp_local(target, None, ms_timeout).await
}

// Resolve the target before connecting its candidate socket addresses.
pub async fn connect_tcp_local<T: ToSocketAddrs + std::fmt::Display>(
    target: T,
    local: Option<SocketAddr>,
    ms_timeout: u64,
) -> ResultType<Stream> {
    let mut last_error = None;
    for address in lookup_host(&target).await? {
        match FramedStream::new(address, local, ms_timeout).await {
            Ok(stream) => return Ok(Stream::Tcp(stream)),
            Err(error) => last_error = Some(error),
        }
    }
    match last_error {
        Some(error) => Err(error).with_context(|| format!("Failed to connect to {target}")),
        None => bail!("No socket address was found for {target}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn single_address_connect_owns_the_literal_socket() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let remote = listener.local_addr().unwrap();
        for before in [true, false] {
            let stream = if before {
                FramedStream::before_resolution_boundary(remote, None, 1000).await
            } else {
                FramedStream::new(remote, None, 1000).await
            }
            .unwrap();
            let (accepted, peer) = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                listener.accept(),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(accepted.local_addr().unwrap(), remote);
            assert_eq!(peer, stream.local_addr());
            drop((accepted, stream));
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn bind_collision_preserves_the_native_error() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let before = FramedStream::before_resolution_boundary(address, Some(address), 1000)
            .await
            .err()
            .expect("occupied local bind must fail");
        assert!(before.downcast_ref::<std::io::Error>().is_none());
        let after = FramedStream::new(address, Some(address), 1000)
            .await
            .err()
            .expect("occupied local bind must fail");
        assert_eq!(
            after.downcast_ref::<std::io::Error>()
                .expect("native bind error must be retained")
                .raw_os_error(),
            Some(libc::EADDRINUSE)
        );
        let connector = connect_tcp_local(address, Some(address), 1000)
            .await
            .err()
            .expect("connector must preserve the occupied local bind");
        assert_eq!(
            connector.downcast_ref::<std::io::Error>()
                .expect("connector must retain the native cause")
                .raw_os_error(),
            Some(libc::EADDRINUSE)
        );
    }

    #[test]
    fn test_check_port() {
        assert_eq!(check_port("[::1]:12", 32), "[::1]:12");
        assert_eq!(check_port("::1", 32), "[::1]:32");
        assert_eq!(check_port("1:2", 32), "1:2");
        assert_eq!(check_port("z1:2", 32), "z1:2");
        assert_eq!(check_port("1.1.1.1", 32), "1.1.1.1:32");
        assert_eq!(check_port("1.1.1.1:32", 32), "1.1.1.1:32");
        assert_eq!(check_port("test.com:32", 0), "test.com:32");
        assert_eq!(increase_port("[::1]:12", 1), "[::1]:13");
        assert_eq!(split_host_port("[::1]:12"), Some(("[::1]".to_owned(), 12)));
        assert_eq!(split_host_port("[1:2]:12"), None);
        assert_eq!(increase_port("1.2.2.4:12", 1), "1.2.2.4:13");
        assert_eq!(increase_port("1.2.2.4", 1), "1.2.2.4");
        assert_eq!(increase_port("test.com", 1), "test.com");
        assert_eq!(increase_port("test.com:13", 4), "test.com:17");
        assert_eq!(increase_port("::1", 4), "::1");
        assert_eq!(increase_port("22:1:13", 4), "22:1:13");
        assert_eq!(increase_port("z1:2", 1), "z1:3");
    }
}
