#[cfg(target_os = "linux")]
fn main() {
    use hbb_common::{anyhow::bail, tokio, ResultType};

    let result = (|| -> ResultType<()> {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        match args.as_slice() {
            [role] if role == "--whiteboard" => {
                if librustdesk::core_main::core_main().is_some() {
                    bail!("whiteboard core CLI did not dispatch the helper");
                }
                librustdesk::common::global_clean();
                Ok(())
            }
            [role] if role == "--server" => {
                let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
                runtime.block_on(librustdesk::linux_whiteboard_lifecycle_probe::run())
            }
            _ => bail!("native fixture requires an exact server or whiteboard role"),
        }
    })();
    if let Err(err) = result {
        eprintln!("linux_whiteboard_lifecycle_probe: FAIL: {err:#}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("linux_whiteboard_lifecycle_probe is Linux-only");
    std::process::exit(1);
}
