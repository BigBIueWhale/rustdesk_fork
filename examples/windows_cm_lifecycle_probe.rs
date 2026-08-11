#[cfg(target_os = "windows")]
fn main() {
    if let Err(err) = librustdesk::windows_cm_lifecycle_probe::run() {
        eprintln!("windows_cm_lifecycle_probe: FAIL: {err:#}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("windows_cm_lifecycle_probe is Windows-only");
    std::process::exit(1);
}
