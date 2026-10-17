extern crate self as hbb_common;
pub extern crate libc;
pub extern crate log;
pub extern crate regex;
pub extern crate tokio;

#[path = "../src/platform/linux/xrandr_command.rs"]
mod xrandr_command;
#[path = "../src/server/connection/resolution_work.rs"]
mod resolution_work;
#[path = "test-linux-xrandr-query.rs"]
mod query_regressions;

#[cfg(test)]
mod command_tests {
    use super::{libc, xrandr_command};
    use std::{fs, io, os::unix::process::ExitStatusExt, path::PathBuf, process::Command,
        sync::atomic::{AtomicUsize, Ordering}, time::{Duration, SystemTime, UNIX_EPOCH}};

    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);
    const CHILD: &str = "import os, pathlib, signal, sys, time\nroot=pathlib.Path(sys.argv[1])\nmode=sys.argv[2]\n(root/'pid').write_text(str(os.getpid()))\nif mode=='hold':\n while not (root/'release').exists(): time.sleep(0.005)\n print('complete')\nelif mode=='fail': print('plausible stdout'); sys.exit(7)\nelif mode=='signal': os.kill(os.getpid(),signal.SIGTERM)\nelif mode=='flood':\n while True: os.write(1,b'x'*8192)\n";

    pub(super) struct Directory(pub(super) PathBuf);
    impl Directory {
        pub(super) fn new() -> Self {
            let path = std::env::temp_dir().join(format!("resolution-child-{}-{}-{}",
                std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        pub(super) fn command(&self, mode: &str) -> Command {
            let mut command = Command::new("/usr/bin/python3");
            command.args(["-I", "-S", "-c", CHILD]).arg(&self.0).arg(mode);
            command
        }
        pub(super) fn assert_reaped(&self) {
            let pid: libc::pid_t = fs::read_to_string(self.0.join("pid")).unwrap().parse().unwrap();
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) }, -1,
                "the production owner must already have reaped this exact child");
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); }
    }

    #[test]
    fn successful_command_waits_for_exact_child_completion() {
        let root = Directory::new();
        let command = root.command("hold");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || done_tx.send(xrandr_command::run(command)).unwrap());
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !root.0.join("pid").exists() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(matches!(done_rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)));
        fs::write(root.0.join("release"), b"release").unwrap();
        let output = done_rx.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
        worker.join().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"complete\n");
        root.assert_reaped();
    }

    #[test]
    fn unsuccessful_child_status_is_preserved() {
        let root = Directory::new();
        let output = xrandr_command::run(root.command("fail")).unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"plausible stdout\n");
        root.assert_reaped();
    }

    #[test]
    fn signalled_child_status_is_preserved() {
        let root = Directory::new();
        let output = xrandr_command::run(root.command("signal")).unwrap();
        assert_eq!(output.status.signal(), Some(15));
        root.assert_reaped();
    }

    fn wait_disposition_refusal(test_name: &str, ignore: bool) {
        const PROBE: &str = "RUSTDESK_XRANDR_WAIT_DISPOSITION_PROBE";
        let mode = if ignore { "ignored" } else { "no-cldwait" };
        if std::env::var_os(PROBE).is_none() {
            // Signal disposition is process-wide. Change it only in this exact re-exec child.
            let mut command = Command::new(std::env::current_exe().unwrap());
            command.args(["--exact", test_name, "--test-threads=1", "--color", "never"])
                .env(PROBE, mode);
            let output = xrandr_command::run(command).unwrap();
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
            let text = String::from_utf8(output.stdout).unwrap();
            assert!(text.lines().any(|line| line == format!("test {test_name} ... ok")));
            assert!(text.lines().any(|line| line.starts_with(
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;"
            )));
            return;
        }
        assert_eq!(std::env::var(PROBE).unwrap(), mode);

        fn admitted_child() {
            let root = Directory::new();
            let output = xrandr_command::run(root.command("fail")).unwrap();
            assert_eq!(output.status.code(), Some(7));
            assert_eq!(output.stdout, b"plausible stdout\n");
            root.assert_reaped();
        }
        admitted_child();

        struct RestoreDisposition(libc::sigaction);
        impl Drop for RestoreDisposition {
            fn drop(&mut self) {
                assert_eq!(unsafe {
                    libc::sigaction(libc::SIGCHLD, &self.0, std::ptr::null_mut())
                }, 0);
            }
        }

        let refused = Directory::new();
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = if ignore { libc::SIG_IGN } else { libc::SIG_DFL };
        action.sa_flags = if ignore { 0 } else { libc::SA_NOCLDWAIT };
        assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
        let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::sigaction(libc::SIGCHLD, &action, &mut previous) }, 0);
        let restore = RestoreDisposition(previous);
        let mut observed: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe {
            libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut observed)
        }, 0);
        assert_eq!(observed.sa_sigaction, action.sa_sigaction);
        assert_eq!(observed.sa_flags & libc::SA_NOCLDWAIT, action.sa_flags);

        let result = xrandr_command::run(refused.command("fail"));
        drop(restore);
        let error = result.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert_eq!(error.to_string(), "xrandr requires retained child wait authority");
        assert!(!refused.0.join("pid").exists(), "refused child must never execute");
        admitted_child();
    }

    #[test]
    fn ignored_sigchld_refuses_before_child_creation() {
        wait_disposition_refusal(
            "command_tests::ignored_sigchld_refuses_before_child_creation", true,
        );
    }

    #[test]
    fn no_cldwait_refuses_before_child_creation() {
        wait_disposition_refusal(
            "command_tests::no_cldwait_refuses_before_child_creation", false,
        );
    }

    #[test]
    fn timeout_terminates_and_reaps_owned_child() {
        let root = Directory::new();
        let error = xrandr_command::run(root.command("hold")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        root.assert_reaped();
    }

    #[test]
    fn output_limit_terminates_and_reaps_owned_child() {
        let root = Directory::new();
        let error = xrandr_command::run(root.command("flood")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        root.assert_reaped();
    }
}

#[cfg(test)]
mod work_tests {
    use super::{resolution_work::{ResolutionWork, ResolutionWorkOwner}, tokio};
    use std::{sync::{atomic::{AtomicBool, Ordering}, Arc, mpsc}, time::Duration};

    struct Owner {
        retired: Arc<AtomicBool>,
        poisoned: Arc<AtomicBool>,
        retired_tx: Option<tokio::sync::oneshot::Sender<()>>,
    }
    impl ResolutionWorkOwner for Owner {
        fn fail_closed(&self, _: String) { self.poisoned.store(true, Ordering::Release); }
    }
    impl Drop for Owner {
        fn drop(&mut self) {
            self.retired.store(true, Ordering::Release);
            if let Some(sender) = self.retired_tx.take() { let _ = sender.send(()); }
        }
    }
    fn owner() -> (Owner, Arc<AtomicBool>, Arc<AtomicBool>, tokio::sync::oneshot::Receiver<()>) {
        let retired = Arc::new(AtomicBool::new(false));
        let poisoned = Arc::new(AtomicBool::new(false));
        let (retired_tx, retired_rx) = tokio::sync::oneshot::channel();
        (Owner { retired: Arc::clone(&retired), poisoned: Arc::clone(&poisoned),
            retired_tx: Some(retired_tx) }, retired, poisoned, retired_rx)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn normal_completion_holds_owner_and_runtime_stays_responsive() {
        let (owner, retired, poisoned, _) = owner();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let mut work = ResolutionWork::start(owner, move || {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            Ok(())
        });
        tokio::time::timeout(Duration::from_secs(2), entered_rx).await.unwrap().unwrap();
        tokio::time::timeout(Duration::from_millis(500), tokio::time::sleep(Duration::from_millis(20)))
            .await.unwrap();
        assert!(!retired.load(Ordering::Acquire));
        release_tx.send(()).unwrap();
        work.wait().await.unwrap();
        assert!(retired.load(Ordering::Acquire));
        assert!(!poisoned.load(Ordering::Acquire));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn queued_cancellation_performs_no_native_work() {
        let (owner, retired, poisoned, retired_rx) = owner();
        let executed = Arc::new(AtomicBool::new(false));
        let action_executed = Arc::clone(&executed);
        let work = ResolutionWork::start(owner, move || {
            action_executed.store(true, Ordering::Release); Ok(())
        });
        drop(work);
        tokio::time::timeout(Duration::from_secs(2), retired_rx).await.unwrap().unwrap();
        assert!(retired.load(Ordering::Acquire));
        assert!(!executed.load(Ordering::Acquire));
        assert!(!poisoned.load(Ordering::Acquire));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn controller_drop_retains_admitted_owner_until_completion() {
        let (owner, retired, _, retired_rx) = owner();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let work = ResolutionWork::start(owner, move || {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(2)).unwrap(); Ok(())
        });
        tokio::time::timeout(Duration::from_secs(2), entered_rx).await.unwrap().unwrap();
        drop(work);
        assert!(!retired.load(Ordering::Acquire));
        release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), retired_rx).await.unwrap().unwrap();
        assert!(retired.load(Ordering::Acquire));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_waiter_keeps_the_retained_ticket() {
        let (owner, retired, _, _) = owner();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let mut work = ResolutionWork::start(owner, move || {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(2)).unwrap(); Ok(())
        });
        tokio::time::timeout(Duration::from_secs(2), entered_rx).await.unwrap().unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(20), work.wait()).await.is_err());
        assert!(!retired.load(Ordering::Acquire));
        release_tx.send(()).unwrap();
        work.wait().await.unwrap();
        assert!(retired.load(Ordering::Acquire));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn native_failure_is_reported() {
        let (owner, retired, poisoned, _) = owner();
        let mut work: ResolutionWork = ResolutionWork::start(owner, || Err("native refusal".to_owned()));
        assert_eq!(work.wait().await, Err("native refusal".to_owned()));
        assert!(retired.load(Ordering::Acquire));
        assert!(!poisoned.load(Ordering::Acquire));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn native_panic_poison_and_release() {
        let (owner, retired, poisoned, _) = owner();
        let mut work: ResolutionWork = ResolutionWork::start(owner, || panic!("native panic"));
        assert!(work.wait().await.unwrap_err().contains("panicked"));
        assert!(retired.load(Ordering::Acquire));
        assert!(poisoned.load(Ordering::Acquire));
    }

    async fn native_query(cancel_waiter: bool) {
        use super::{command_tests::Directory, xrandr_command};
        let root = Directory::new();
        let command = root.command("hold");
        let (owner, retired, poisoned, retired_rx) = owner();
        let mut work = ResolutionWork::start(owner, move || {
            let output = xrandr_command::run(command).map_err(|error| error.to_string())?;
            if !output.status.success() { return Err("query child failed".to_owned()); }
            Ok(output.stdout)
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !root.0.join("pid").exists() {
            assert!(std::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        // This timer must run while the exact native child is still held.
        let heartbeat = std::time::Instant::now();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(heartbeat.elapsed() < Duration::from_millis(500));
        assert!(!retired.load(Ordering::Acquire));
        if cancel_waiter {
            assert!(tokio::time::timeout(Duration::from_millis(20), work.wait()).await.is_err());
            drop(work);
            assert!(!retired.load(Ordering::Acquire));
            std::fs::write(root.0.join("release"), b"release").unwrap();
            tokio::time::timeout(Duration::from_secs(2), retired_rx).await.unwrap().unwrap();
        } else {
            std::fs::write(root.0.join("release"), b"release").unwrap();
            assert_eq!(work.wait().await.unwrap(), b"complete\n");
            assert!(retired.load(Ordering::Acquire));
        }
        assert!(!poisoned.load(Ordering::Acquire));
        root.assert_reaped();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn native_query_returns_value_without_blocking_runtime() {
        native_query(false).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_native_query_retains_owner_until_child_reaped() {
        native_query(true).await;
    }
}
