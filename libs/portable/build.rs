use std::{env, error::Error, io, path::PathBuf};

#[path = "src/installer_package.rs"]
mod installer_package;

#[cfg(windows)]
#[path = "../../res/windows_resource.rs"]
mod windows_resource;

fn main() -> Result<(), Box<dyn Error>> {
    if env::var("CARGO_CFG_TARGET_OS")? == "windows" {
        let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "CARGO_MANIFEST_DIR is not set")
        })?);
        let root = manifest_dir
            .parent()
            .and_then(|libs| libs.parent())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "portable crate is not beneath repository root",
                )
            })?;
        let msi = root.join("target/rustdesk-setup-payload/rustdesk-installer.msi");
        println!("cargo:rerun-if-changed={}", msi.display());
        println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
        let output = PathBuf::from(env::var_os("OUT_DIR").ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "OUT_DIR is not set")
        })?);
        installer_package::generate(&msi, &output, &env::var("SOURCE_DATE_EPOCH")?)?;
    }
    #[cfg(windows)]
    compile_windows_resource()?;
    Ok(())
}

#[cfg(windows)]
fn compile_windows_resource() -> Result<(), Box<dyn Error>> {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "CARGO_MANIFEST_DIR is not set"))?;
    let resource_root = manifest_dir
        .parent()
        .and_then(|libs| libs.parent())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "portable crate is not beneath repository root",
            )
        })?;
    windows_resource::compile(env!("CARGO_PKG_VERSION"), resource_root)
}
