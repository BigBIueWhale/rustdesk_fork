#[cfg(windows)]
fn build_windows() {
    let file = "src/platform/windows.cc";
    let file2 = "src/platform/windows_delete_test_cert.cc";
    cc::Build::new().file(file).file(file2).compile("windows");
    println!("cargo:rustc-link-lib=WtsApi32");
    println!("cargo:rerun-if-changed={}", file);
    println!("cargo:rerun-if-changed={}", file2);
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
    println!("cargo:rerun-if-changed={}", file);
}

#[cfg(all(windows, feature = "inline"))]
fn build_manifest() {
    use std::io::Write;
    if std::env::var("PROFILE").unwrap() == "release" {
        let mut res = winres::WindowsResource::new();
        res.set_icon("res/icon.ico")
            .set_language(winapi::um::winnt::MAKELANGID(
                winapi::um::winnt::LANG_ENGLISH,
                winapi::um::winnt::SUBLANG_ENGLISH_US,
            ))
            .set_manifest_file("res/manifest.xml");
        match res.compile() {
            Err(e) => {
                write!(std::io::stderr(), "{}", e).unwrap();
                std::process::exit(1);
            }
            Ok(_) => {}
        }
    }
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
    println!("cargo:warning=R-B10 canary: build confirmed network-isolated (offline compile stage).");
}

fn main() {
    r_b10_offline_canary();
    hbb_common::gen_version();
    install_android_deps();
    #[cfg(all(windows, feature = "inline"))]
    build_manifest();
    #[cfg(windows)]
    build_windows();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os == "macos" {
        #[cfg(target_os = "macos")]
        build_mac();
        println!("cargo:rustc-link-lib=framework=ApplicationServices");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
