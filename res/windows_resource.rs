use std::{
    env,
    error::Error,
    ffi::OsString,
    fs, io,
    path::{Path, PathBuf},
    process::Command,
};

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn remove_prior_regular_file(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(invalid_data(format!(
                    "Windows resource output is not an ordinary file: {}",
                    path.display()
                )));
            }
            fs::remove_file(path)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub fn compile(version: &str, resource_root: &Path) -> Result<(), Box<dyn Error>> {
    let mut components = version.split('.');
    let major = components
        .next()
        .ok_or_else(|| invalid_data("missing Windows major version"))?
        .parse::<u16>()?;
    let minor = components
        .next()
        .ok_or_else(|| invalid_data("missing Windows minor version"))?
        .parse::<u16>()?;
    let patch = components
        .next()
        .ok_or_else(|| invalid_data("missing Windows patch version"))?
        .parse::<u16>()?;
    if components.next().is_some() || version != format!("{major}.{minor}.{patch}") {
        return Err(invalid_data("Windows version is not canonical major.minor.patch").into());
    }

    let icon = resource_root.join("res/icon.ico");
    let manifest = resource_root.join("res/manifest.xml");
    let shared_source = resource_root.join("res/windows_resource.rs");
    for input in [&icon, &manifest, &shared_source] {
        let metadata = fs::symlink_metadata(input)?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(invalid_data(format!(
                "Windows resource input is not an ordinary file: {}",
                input.display()
            ))
            .into());
        }
        println!("cargo:rerun-if-changed={}", input.display());
    }
    println!("cargo:rerun-if-env-changed=RUSTDESK_LLVM_RC");

    let resource = format!(
        r#"1 VERSIONINFO
FILEVERSION {major}, {minor}, {patch}, 0
PRODUCTVERSION {major}, {minor}, {patch}, 0
FILEOS 0x40004
FILETYPE 0x1
FILESUBTYPE 0x0
FILEFLAGSMASK 0x3f
FILEFLAGS 0x0
{{
BLOCK "StringFileInfo"
{{
BLOCK "040904b0"
{{
VALUE "FileDescription", "RustDesk Remote Desktop"
VALUE "FileVersion", "{version}"
VALUE "LegalCopyright", "Copyright © 2025 Purslane Ltd. All rights reserved."
VALUE "OriginalFilename", "rustdesk.exe"
VALUE "ProductName", "RustDesk"
VALUE "ProductVersion", "{version}"
}}
}}
BLOCK "VarFileInfo"
{{
VALUE "Translation", 0x0409, 0x04b0
}}
}}
1 ICON "res/icon.ico"
1 24 "res/manifest.xml"
"#
    );

    let out_dir = env::var_os("OUT_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "OUT_DIR is not set"))?;
    let resource_path = out_dir.join("resource.rc");
    let compiled_resource = out_dir.join("resource.lib");
    remove_prior_regular_file(&resource_path)?;
    remove_prior_regular_file(&compiled_resource)?;
    fs::write(&resource_path, resource.as_bytes())?;

    let llvm_rc = env::var_os("RUSTDESK_LLVM_RC")
        .map(PathBuf::from)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "RUSTDESK_LLVM_RC is not set to the pinned LLVM resource compiler",
            )
        })?;
    let producer_metadata = fs::symlink_metadata(&llvm_rc)?;
    if !producer_metadata.file_type().is_file() || producer_metadata.file_type().is_symlink() {
        return Err(invalid_data(format!(
            "LLVM resource compiler is not an ordinary file: {}",
            llvm_rc.display()
        ))
        .into());
    }

    let mut output_argument = OsString::from("/FO");
    output_argument.push(&compiled_resource);
    let output = Command::new(&llvm_rc)
        .current_dir(resource_root)
        .arg("-no-preprocess")
        .arg("-C65001")
        .arg(output_argument)
        .arg("--")
        .arg(&resource_path)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "pinned LLVM resource compiler failed with {}: stdout={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        )
        .into());
    }
    if fs::read(&resource_path)? != resource.as_bytes() {
        return Err(invalid_data("LLVM resource compiler changed its ordered RC input").into());
    }
    let compiled_metadata = fs::symlink_metadata(&compiled_resource)?;
    if !compiled_metadata.file_type().is_file()
        || compiled_metadata.file_type().is_symlink()
        || compiled_metadata.len() <= 32
    {
        return Err(invalid_data(format!(
            "LLVM resource compiler did not emit an ordinary nonempty resource: {}",
            compiled_resource.display()
        ))
        .into());
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=dylib=resource");
    Ok(())
}
