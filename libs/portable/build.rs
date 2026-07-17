use std::{env, error::Error, io, path::PathBuf};

#[cfg(windows)]
#[path = "../../res/windows_resource.rs"]
mod windows_resource;

fn main() -> Result<(), Box<dyn Error>> {
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
