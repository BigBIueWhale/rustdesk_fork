use std::{error::Error, fs, net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream}, path::PathBuf, time::Duration};

// Compile the production declarations verbatim without linking unrelated screen
// capture/encoder backends. Missing or ambiguous boundaries refuse the build.
fn section<'a>(source: &'a str, begin: &str, end: &str) -> Result<&'a str, Box<dyn Error>> {
    if source.matches(begin).count() != 1 || source.matches(end).count() != 1 {
        return Err("production camera declaration boundary differs".into());
    }
    let start = source.find(begin).ok_or("missing declaration start")?;
    let finish = source.find(end).ok_or("missing declaration end")?;
    source.get(start..finish).ok_or_else(|| "production declaration order differs".into())
}

fn camera_types() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?).join("../../libs/scrap/src/common");
    let common = fs::read_to_string(root.join("mod.rs"))?;
    let x11 = fs::read_to_string(root.join("x11.rs"))?;
    let mut declarations = String::from("use std::{ffi::c_void, io};\n");
    declarations.push_str(section(&common, "pub trait TraitCapturer {", "#[cfg(not(any(target_os = \"ios\")))]\nimpl Frame<'_> {")?);
    declarations.push_str(section(&common, "#[derive(Debug, PartialEq, Eq, Clone, Copy)]\npub enum Pixfmt {", "#[derive(Debug, Clone, Copy)]\npub struct EncodeYuvFormat {")?);
    declarations.push_str(section(&x11, "pub struct PixelBuffer<'a> {", "pub struct Display(x11::Display);")?);
    fs::write(PathBuf::from(std::env::var("OUT_DIR")?).join("camera_types.rs"), declarations)?;
    println!("cargo:rerun-if-changed={}", root.display());
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 443));
    match TcpStream::connect_timeout(&target, Duration::from_millis(200)) {
        // This fixture compiles only in its Linux/x86_64 network-none container.
        Err(error) if error.raw_os_error() == Some(101) => {
            println!("cargo:warning=CAMERA_NATIVE_COMPILE_NETWORK_CANARY=refused");
            camera_types()
        }
        Err(error) => Err(format!("compile canary failed for a different reason: {error}").into()),
        Ok(_) => Err("compiler reached an external address".into()),
    }
}
