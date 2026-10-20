#[cfg(target_os = "linux")]
mod linux {
    use hbb_common::fs::{self as product, JobType, TransferJob};
    use hbb_common::socket_surface::{read_process_socket_surface, check_surface, SurfaceCheck};
    use std::{
        collections::BTreeSet,
        fs::{self, DirBuilder, File},
        net::TcpListener,
        os::fd::{FromRawFd, OwnedFd},
        os::unix::{fs::{symlink, DirBuilderExt, MetadataExt}, io::AsRawFd},
        path::{Path, PathBuf},
        process::{Command, Stdio},
        sync::{Arc, Barrier},
        time::{Duration, Instant},
    };

    fn socket_observation(mode: &str, operation: &str, port: u16, udp: usize,
                          report: bool) -> bool {
        let surface = read_process_socket_surface();
        let policy = check_surface(port);
        let measured = matches!(&surface, Ok(value) if value.tcp4_listen_ports == [port]
            && value.tcp6_listen_ports.is_empty() && value.udp_sockets == udp);
        let policy_matches = if udp == 0 {
            policy == SurfaceCheck::Ok
        } else {
            matches!(&policy, SurfaceCheck::Violation(why) if why.contains("found 1 UDP"))
        };
        let good = measured && policy_matches;
        if report {
            println!("SOCKET_DESCRIPTOR_LIFETIME=case mode={mode} operation={operation} ok={good} surface={surface:?} policy={policy:?}");
        }
        good
    }

    fn socket_observations(mode: &str, report: bool) -> bool {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the worker's loopback listener");
        let port = listener.local_addr().expect("read the exact listener port").port();
        let mut good = socket_observation(mode, "clean", port, 0, report);
        let descriptor = unsafe { libc::socket(libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, libc::IPPROTO_UDP) };
        assert!(descriptor >= 0, "create the worker's unbound UDP socket: {}",
            std::io::Error::last_os_error());
        // SAFETY: socket returned a fresh descriptor exclusively owned by this fixture.
        let udp = unsafe { OwnedFd::from_raw_fd(descriptor) };
        good &= socket_observation(mode, "unbound-udp", port, 1, report);
        drop(udp);
        good &= socket_observation(mode, "udp-retired", port, 0, report);
        good
    }

    async fn observations(root: &Path, mode: &str, report: bool) -> bool {
        let listing = product::read_dir(root, true).map(|value| {
            value.entries.into_iter().map(|entry| entry.name).collect::<BTreeSet<_>>()
                == ["file", "link", "sub"].iter().map(|name| name.to_string()).collect()
        }).unwrap_or(false);
        if report {
            println!("FILE_METADATA_DESCRIPTOR_LIFETIME=case mode={mode} operation=list ok={listing}");
        }
        let mut good = listing;
        for name in ["file", "link"] {
            let result = async {
                let mut job = TransferJob::new_read(1, JobType::Generic, String::new(),
                    root.join(name), 0, true, false, false)?;
                job.init_data_stream_for_cm().await?;
                let block = job.read().await?.ok_or_else(|| anyhow::anyhow!("missing outgoing bytes"))?;
                let data: &[u8] = block.data.as_ref();
                Ok::<_, anyhow::Error>(!block.compressed && data == b"data")
            }.await.unwrap_or(false);
            if report {
                println!("FILE_METADATA_DESCRIPTOR_LIFETIME=case mode={mode} operation={name} ok={result}");
            }
            good &= result;
        }
        good & socket_observations(mode, report)
    }

    fn worker(root: PathBuf, mode: String, ready: Arc<Barrier>) -> ! {
        assert_ne!(unsafe { libc::syscall(libc::SYS_gettid) } as u32, std::process::id());
        let probe = File::open(root.join("file")).expect("retain the worker's probe inode");
        let original = probe.metadata().expect("identify the retained probe");
        let leader = format!("/proc/self/fd/{}", probe.as_raw_fd());
        ready.wait();
        if mode == "exited" {
            let deadline = Instant::now() + Duration::from_secs(2);
            while fs::metadata(&leader).is_ok() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        let leader_available = fs::metadata(&leader).is_ok();
        let alias = fs::metadata(format!("/proc/thread-self/fd/{}", probe.as_raw_fd()))
            .map(|value| (value.dev(), value.ino()) == (original.dev(), original.ino())).unwrap_or(false);
        let path_read = fs::read(root.join("file")).map(|value| value == b"data").unwrap_or(false);
        let kernel = leader_available == (mode == "alive") && alias && path_read;
        println!("FILE_METADATA_DESCRIPTOR_LIFETIME=kernel mode={mode} leader_available={leader_available} thread_alias={alias} path_read={path_read}");
        let handles = || fs::read_dir("/proc/thread-self/fd").expect("enumerate the worker's descriptors").count();
        // This synchronous process worker explicitly owns its sole test runtime.
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()
            .expect("create the isolated worker runtime");
        let mut good = runtime.block_on(observations(&root, &mode, false));
        let before = handles();
        for round in 0..8 {
            good &= runtime.block_on(observations(&root, &mode, round == 7));
        }
        let after = handles();
        println!("FILE_METADATA_DESCRIPTOR_LIFETIME=resources mode={mode} rounds=8 fds_before={before} fds_after={after}");
        drop(runtime);
        drop(probe);
        std::process::exit(if kernel && good && before == after { 0 } else { 73 });
    }

    pub fn main() {
        assert_ne!(unsafe { libc::geteuid() }, 0);
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        if args.len() == 3 && args[0] == "--worker" && matches!(args[1].as_str(), "alive" | "exited") {
            assert_eq!(unsafe { libc::syscall(libc::SYS_gettid) } as u32, std::process::id());
            let ready = Arc::new(Barrier::new(2));
            let child_ready = Arc::clone(&ready);
            let mode = args[1].clone();
            let exited = mode == "exited";
            let root = PathBuf::from(&args[2]);
            let thread = std::thread::spawn(move || worker(root, mode, child_ready));
            ready.wait();
            if exited {
                // At this controlled boundary no application or library lock is held.
                // The raw Linux syscall exits this leader alone; the worker owns finality.
                unsafe { libc::syscall(libc::SYS_exit, 0); }
                unreachable!("the leader exit syscall returned");
            }
            thread.join().expect("join the live-leader worker");
            unreachable!("the worker owns the process result");
        }
        assert!(args.is_empty(), "unexpected fixture arguments");
        let root = std::env::temp_dir().join(format!("descriptor-lifetime-{}", uuid::Uuid::new_v4()));
        DirBuilder::new().mode(0o700).create(&root).expect("create private fixture root");
        fs::write(root.join("file"), b"data").expect("create the read-only source fixture");
        fs::create_dir(root.join("sub")).expect("create listing directory");
        symlink(root.join("file"), root.join("link")).expect("create the supported source link");
        let mut good = true;
        for mode in ["alive", "exited"] {
            let mut child = Command::new(std::env::current_exe().expect("resolve the exact fixture artifact"))
                .arg("--worker").arg(mode).arg(&root).env_clear().env("LANG", "C").env("LC_ALL", "C")
                .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
                .spawn().expect("start the exact owned child");
            let deadline = Instant::now() + Duration::from_secs(5);
            let timed_out = loop {
                if child.try_wait().expect("observe the owned child").is_some() { break false; }
                if Instant::now() >= deadline { child.kill().expect("stop the timed-out owned child"); break true; }
                std::thread::sleep(Duration::from_millis(5));
            };
            let output = child.wait_with_output().expect("join and collect the owned child");
            assert!(output.stdout.len() + output.stderr.len() < 16384);
            let stdout = String::from_utf8(output.stdout).expect("decode fixture observations");
            print!("{stdout}");
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
            let cases = stdout.lines().filter(|line| line.starts_with("FILE_METADATA_DESCRIPTOR_LIFETIME=case ")).count();
            let kernel = stdout.lines().filter(|line| line.starts_with("FILE_METADATA_DESCRIPTOR_LIFETIME=kernel ")).count();
            let resources = stdout.lines().filter(|line| line.starts_with("FILE_METADATA_DESCRIPTOR_LIFETIME=resources ")).count();
            let sockets = stdout.lines().filter(|line| line.starts_with("SOCKET_DESCRIPTOR_LIFETIME=case ")).count();
            println!("FILE_METADATA_DESCRIPTOR_LIFETIME=child mode={mode} success={} timed_out={timed_out} cleanup=joined", output.status.success());
            good &= output.status.success() && !timed_out && cases == 3 && kernel == 1 && resources == 1
                && sockets == 3;
        }
        fs::remove_dir_all(&root).expect("retire the private fixture after both child joins");
        assert!(!root.exists());
        if !good { std::process::exit(1); }
        println!("FILE_METADATA_DESCRIPTOR_LIFETIME=pass modes=2 cases=6 children=joined fixture=retired");
        println!("SOCKET_DESCRIPTOR_LIFETIME=pass modes=2 cases=6 children=joined fixture=retired");
    }
}

#[cfg(target_os = "linux")]
fn main() { linux::main(); }

#[cfg(not(target_os = "linux"))]
fn main() { panic!("this explicit fixture requires Linux"); }
