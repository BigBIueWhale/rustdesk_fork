use librustdesk::*;

#[cfg(not(target_os = "macos"))]
fn main() {}

#[cfg(target_os = "macos")]
fn main() {
    crate::common::load_custom_client();
    hbb_common::init_log(false, "service");
    if let Err(err) = crate::start_os_service() {
        hbb_common::log::error!("macOS service principal authority failed closed: {err}");
        std::process::exit(1);
    }
}
