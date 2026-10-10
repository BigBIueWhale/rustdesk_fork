#[cfg(target_os = "linux")]
fn main() {
    use hbb_common::{anyhow::{bail, ensure}, tokio, ResultType};
    use std::io::{Read, Write};

    let result = (|| -> ResultType<()> {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        match args.as_slice() {
            [role] if role == "--whiteboard" => {
                if librustdesk::core_main::core_main().is_some() {
                    bail!("whiteboard core CLI did not dispatch the helper");
                }
                librustdesk::common::global_clean();
                for task in std::fs::read_dir("/proc/self/task")? {
                    let name = std::fs::read_to_string(task?.path().join("comm"))?;
                    ensure!(name.trim_end() != "rustdesk-whiteb", "whiteboard IPC worker survived core CLI return");
                }
                std::io::stdout().write_all(b"returned\n")?;
                std::io::stdout().flush()?;
                let mut acknowledgement = [0; 7];
                std::io::stdin().read_exact(&mut acknowledgement)?;
                ensure!(&acknowledgement == b"finish\n", "helper retirement acknowledgment differs");
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
