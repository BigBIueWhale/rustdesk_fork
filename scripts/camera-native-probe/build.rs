use std::{error::Error, net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream}, time::Duration};

fn main() -> Result<(), Box<dyn Error>> {
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 443));
    match TcpStream::connect_timeout(&target, Duration::from_millis(200)) {
        // This fixture compiles only in its Linux/x86_64 network-none container.
        Err(error) if error.raw_os_error() == Some(101) => {
            println!("cargo:warning=CAMERA_NATIVE_COMPILE_NETWORK_CANARY=refused");
            Ok(())
        }
        Err(error) => Err(format!("compile canary failed for a different reason: {error}").into()),
        Ok(_) => Err("compiler reached an external address".into()),
    }
}
