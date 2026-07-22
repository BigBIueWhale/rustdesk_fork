use std::{env, error::Error, fs, io, path::PathBuf};

#[cfg(windows)]
#[path = "res/windows_resource.rs"]
mod windows_resource;

#[cfg(windows)]
fn build_windows() {
    let file = "src/platform/windows.cc";
    cc::Build::new().file(file).compile("windows");
    println!("cargo:rustc-link-lib=WtsApi32");
    println!("cargo:rerun-if-changed={}", file);
}

#[cfg(target_os = "macos")]
fn build_mac() {
    let file = "src/platform/macos.mm";
    let mut b = cc::Build::new();
    if let Ok(os_version::OsVersion::MacOS(v)) = os_version::detect() {
        let v = v.version;
        if v.contains("10.14") {
            b.flag("-DNO_InputMonitoringAuthStatus=1");
        }
    }
    b.flag("-std=c++17").file(file).compile("macos");
    println!("cargo:rustc-link-lib=framework=IOKit");
    println!("cargo:rerun-if-changed={}", file);
}

#[cfg(windows)]
fn build_manifest(version: &str) -> Result<(), Box<dyn Error>> {
    if env::var("PROFILE")? != "release" {
        return Ok(());
    }
    let resource_root = env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "CARGO_MANIFEST_DIR is not set"))?;
    windows_resource::compile(version, &resource_root)
}

fn install_android_deps() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os != "android" {
        return;
    }
    let mut target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    if target_arch == "x86_64" {
        target_arch = "x64".to_owned();
    } else if target_arch == "x86" {
        target_arch = "x86".to_owned();
    } else if target_arch == "aarch64" {
        target_arch = "arm64".to_owned();
    } else {
        target_arch = "arm".to_owned();
    }
    let target = format!("{}-android", target_arch);
    let vcpkg_root = std::env::var("VCPKG_ROOT").unwrap();
    let mut path: std::path::PathBuf = vcpkg_root.into();
    if let Ok(vcpkg_root) = std::env::var("VCPKG_INSTALLED_ROOT") {
        path = vcpkg_root.into();
    } else {
        path.push("installed");
    }
    path.push(target);
    println!(
        "cargo:rustc-link-search={}",
        path.join("lib").to_str().unwrap()
    );
    // oboe's vcpkg port at the pinned baseline (1.8.0) folds the old separate
    // ndk_compat shim into liboboe.a — there is no libndk_compat.a to link, so
    // upstream's `-lndk_compat` is dead for this oboe version (its symbols arrive
    // via -loboe + the oboe-sys liboboe-ext.a). R-B5a: pinned vcpkg, not "latest".
    println!("cargo:rustc-link-lib=oboe");
    println!("cargo:rustc-link-lib=c++");
    println!("cargo:rustc-link-lib=OpenSLES");
}

// R-B10: the offline-build network canary. The fork's release artifacts are compiled in a
// network-isolated container (`--network=none`, build-debian.sh / build-android.sh /
// build-windows-vm.sh) so "no fetch at compile time" is a PROVEN property, not a trusted one.
// This makes the proof ACTIVE: when the offline compile stage sets RUSTDESK_CANARY_OFFLINE=1,
// attempt a short outbound TCP connect to a couple of literal anycast IPs (no DNS needed). A
// SUCCESS means the container is NOT isolated — a build.rs/cargo/vcpkg/gradle fetch could have
// leaked in and broken byte-reproducibility (R-B2) — so the build MUST fail. The expected
// offline result (connect failure / network-unreachable) is a no-op. The env var is ABSENT in
// dev builds and in the verify.sh cargo-check (which legitimately have network), so this can
// NEVER break a networked build; it only fires when a build that CLAIMS to be offline can in
// fact reach the network. Belt-and-suspenders to the `--network=none` namespace itself.
fn r_b10_offline_canary() {
    println!("cargo:rerun-if-env-changed=RUSTDESK_CANARY_OFFLINE");
    if std::env::var("RUSTDESK_CANARY_OFFLINE").as_deref() != Ok("1") {
        return;
    }
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;
    for probe in ["1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"] {
        if let Ok(sa) = probe.parse::<SocketAddr>() {
            if TcpStream::connect_timeout(&sa, Duration::from_millis(800)).is_ok() {
                panic!(
                    "R-B10 offline-build canary: outbound TCP to {probe} SUCCEEDED during a build \
                     flagged RUSTDESK_CANARY_OFFLINE=1. The compile container is NOT network-isolated \
                     — a compile-time fetch could leak in and break byte-reproducibility (R-B2). \
                     Refusing to build. Run the compile stage under --network=none."
                );
            }
        }
    }
    println!(
        "cargo:warning=R-B10 canary: build confirmed network-isolated (offline compile stage)."
    );
}

// The FORK RELEASE identity for `rustdesk --version` / the About dialog (docs/VERSIONING.md). It is
// DISTINCT from crate::VERSION, which stays the upstream base (the wire/protocol version peers exchange
// for feature-negotiation, hbb_common::get_version_number). Single source of truth is the repo-root
// FORK_VERSION file; emit it as a compile-time env so the binary reads it with env!. Reading a
// committed, fixed file keeps it deterministic (R-B2); rerun-if-changed rebuilds when the file is
// bumped. Missing or malformed release identity aborts the build.
fn canonical_numeric_version(value: &str) -> bool {
    let mut components = value.split('.');
    let canonical_component = |component: &str| {
        !component.is_empty()
            && component.bytes().all(|byte| byte.is_ascii_digit())
            && (component == "0" || !component.starts_with('0'))
    };
    matches!(
        (components.next(), components.next(), components.next(), components.next()),
        (Some(major), Some(minor), Some(patch), None)
            if canonical_component(major)
                && canonical_component(minor)
                && canonical_component(patch)
    )
}

fn emit_fork_version(version: &str) -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=FORK_VERSION");
    if !canonical_numeric_version(version) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CARGO_PKG_VERSION is not a canonical numeric version",
        )
        .into());
    }
    if !fs::symlink_metadata("FORK_VERSION")?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "FORK_VERSION must be a regular file",
        )
        .into());
    }
    let contents = fs::read_to_string("FORK_VERSION")?;
    let fork_version = contents.strip_suffix('\n').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "FORK_VERSION must contain exactly one newline-terminated line",
        )
    })?;
    if fork_version.is_empty() || fork_version.contains('\r') || fork_version.contains('\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "FORK_VERSION must contain exactly one newline-terminated line",
        )
        .into());
    }
    let counter = fork_version
        .strip_prefix(&format!("{version}-hardened."))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "FORK_VERSION base must equal CARGO_PKG_VERSION",
            )
        })?;
    if counter.is_empty()
        || !counter.bytes().all(|byte| byte.is_ascii_digit())
        || counter.starts_with('0')
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "FORK_VERSION must end in a positive canonical hardened counter",
        )
        .into());
    }
    println!("cargo:rustc-env=RUSTDESK_FORK_VERSION={fork_version}");
    Ok(())
}

fn generate_version(version: &str) -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    let out_dir = env::var_os("OUT_DIR")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "OUT_DIR is not set"))?;
    let build_date = match env::var("SOURCE_DATE_EPOCH") {
        Ok(raw) => {
            if raw.is_empty()
                || !raw.bytes().all(|byte| byte.is_ascii_digit())
                || (raw.len() > 1 && raw.starts_with('0'))
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SOURCE_DATE_EPOCH is not a canonical non-negative integer",
                )
                .into());
            }
            let epoch = raw.parse::<i64>().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("SOURCE_DATE_EPOCH is outside the supported integer range: {error}"),
                )
            })?;
            let date =
                chrono::DateTime::<chrono::Utc>::from_timestamp(epoch, 0).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "SOURCE_DATE_EPOCH is outside chrono's supported range",
                    )
                })?;
            date.format("%Y-%m-%d %H:%M").to_string()
        }
        Err(env::VarError::NotPresent) => chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
        Err(error) => return Err(error.into()),
    };
    let generated = format!(
        "pub const VERSION: &str = {version:?};\n#[allow(dead_code)]\npub const BUILD_DATE: &str = {build_date:?};\n"
    );
    fs::write(PathBuf::from(out_dir).join("version.rs"), generated)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    r_b10_offline_canary();
    let version = env::var("CARGO_PKG_VERSION")?;
    emit_fork_version(&version)?;
    generate_version(&version)?;
    install_android_deps();
    #[cfg(windows)]
    build_manifest(&version)?;
    #[cfg(windows)]
    build_windows();
    let target_os = env::var("CARGO_CFG_TARGET_OS")?;
    if target_os == "macos" {
        #[cfg(target_os = "macos")]
        build_mac();
        println!("cargo:rustc-link-lib=framework=ApplicationServices");
    }
    println!("cargo:rerun-if-changed=build.rs");
    Ok(())
}
