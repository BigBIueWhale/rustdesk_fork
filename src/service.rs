use librustdesk::*;

#[cfg(not(target_os = "macos"))]
fn main() {}

#[cfg(target_os = "macos")]
fn main() {
    if let Err(err) = crate::platform::macos::run_service() {
        eprintln!("macOS service bootstrap authority failed closed: {err}");
        std::process::exit(1);
    }
}
