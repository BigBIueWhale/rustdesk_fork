use hbb_common::{log, tokio};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{atomic::{AtomicU8, Ordering}, Arc},
};

const PENDING: u8 = 0;
const ADMITTED: u8 = 1;
const CANCELLED: u8 = 2;

pub(super) trait ResolutionWorkOwner: Send + 'static {
    fn fail_closed(&self, error: String);
}

pub(super) struct ResolutionWork<T = ()> {
    admission: Arc<AtomicU8>,
    supervisor: tokio::task::JoinHandle<Result<T, String>>,
}

impl<T: Send + 'static> ResolutionWork<T> {
    pub(super) fn start(
        owner: impl ResolutionWorkOwner,
        action: impl FnOnce() -> Result<T, String> + Send + 'static,
    ) -> Self {
        let admission = Arc::new(AtomicU8::new(PENDING));
        let worker_admission = Arc::clone(&admission);
        let supervisor = tokio::spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                if worker_admission
                    .compare_exchange(PENDING, ADMITTED, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    return Err("resolution work cancelled before native admission".to_owned());
                }
                let result = match catch_unwind(AssertUnwindSafe(action)) {
                    Ok(result) => result,
                    Err(_) => {
                        let error = "resolution worker panicked during native execution".to_owned();
                        owner.fail_closed(error.clone());
                        Err(error)
                    }
                };
                if let Err(error) = &result {
                    log::error!("Resolution work failed: {error}");
                }
                // This owner stays in the native task if its async supervisor is cancelled.
                drop(owner);
                result
            })
            .await;
            let result = match result {
                Ok(result) => result,
                Err(error) => {
                    let error = format!("resolution worker did not complete normally: {error}");
                    log::error!("{error}");
                    Err(error)
                }
            };
            result
        });
        Self { admission, supervisor }
    }

    pub(super) async fn wait(&mut self) -> Result<T, String> {
        match (&mut self.supervisor).await {
            Ok(result) => result,
            Err(error) => Err(format!("resolution supervisor failed: {error}")),
        }
    }
}

impl<T> ResolutionWork<T> {
    pub(super) fn cancel_pending(&self) -> bool {
        self.admission.compare_exchange(
            PENDING,
            CANCELLED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ).is_ok()
    }
}

impl<T> Drop for ResolutionWork<T> {
    fn drop(&mut self) {
        self.cancel_pending();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    struct Owner(tokio::sync::oneshot::Sender<()>);
    impl ResolutionWorkOwner for Owner {
        fn fail_closed(&self, error: String) { panic!("unexpected native failure: {error}"); }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn r_s11iu_resolution_supervisor_abort_keeps_native_owner() {
        let (owner_tx, mut owner_rx) = tokio::sync::oneshot::channel();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let mut work = ResolutionWork::start(Owner(owner_tx), move || {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
            Ok(())
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), entered_rx).await.unwrap().unwrap();
        work.supervisor.abort();
        assert!(work.wait().await.is_err());
        assert!(matches!(owner_rx.try_recv(), Err(tokio::sync::oneshot::error::TryRecvError::Empty)));
        release_tx.send(()).unwrap();
        assert!(tokio::time::timeout(std::time::Duration::from_secs(2), owner_rx).await.unwrap().is_err());
    }

    #[cfg(all(target_os = "linux", feature = "linux-pkg-config"))]
    mod native_parent_tests {
        use super::*;
        use hbb_common::{message_proto::Resolution, protobuf::Message};
        use std::{io::Write, process::{Command, Stdio}, time::Duration};

        async fn query(cancel: bool) {
            assert_eq!(std::env::var("RUSTDESK_RESOLUTION_PARENT_TEST").as_deref(), Ok("1"));
            let expected = Resolution { width: 1920, height: 1080, ..Default::default() };
            let bytes = expected.write_to_bytes().unwrap();
            let (owner_tx, mut owner_rx) = tokio::sync::oneshot::channel();
            let (input_tx, input_rx) = tokio::sync::oneshot::channel();
            let mut work = ResolutionWork::start(Owner(owner_tx), move || {
                let mut child = Command::new("/bin/cat")
                    .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
                    .spawn().map_err(|error| error.to_string())?;
                let pid = child.id();
                let input = child.stdin.take().ok_or_else(|| "child stdin missing".to_owned());
                let sent = match input {
                    Ok(input) => input_tx.send((pid, input)).is_ok(),
                    Err(_) => false,
                };
                // Failed publication drops the last writer; wait still owns exact retirement.
                let output = child.wait_with_output().map_err(|error| error.to_string())?;
                if !sent || !output.status.success() {
                    return Err("native query child did not complete".to_owned());
                }
                Resolution::parse_from_bytes(&output.stdout)
                    .map(|resolution| vec![resolution])
                    .map_err(|error| error.to_string())
            });
            let (pid, mut input) = tokio::time::timeout(Duration::from_secs(2), input_rx)
                .await.unwrap().unwrap();
            let heartbeat = std::time::Instant::now();
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert!(heartbeat.elapsed() < Duration::from_millis(500));
            assert!(matches!(owner_rx.try_recv(), Err(tokio::sync::oneshot::error::TryRecvError::Empty)));
            if cancel {
                assert!(tokio::time::timeout(Duration::from_millis(20), work.wait()).await.is_err());
                drop(work);
                assert!(matches!(owner_rx.try_recv(), Err(tokio::sync::oneshot::error::TryRecvError::Empty)));
                input.write_all(&bytes).unwrap();
                drop(input);
                assert!(tokio::time::timeout(Duration::from_secs(2), owner_rx).await.unwrap().is_err());
            } else {
                input.write_all(&bytes).unwrap();
                drop(input);
                assert_eq!(work.wait().await.unwrap(), vec![expected]);
                assert!(owner_rx.await.is_err());
            }
            let mut status = 0;
            assert_eq!(unsafe { hbb_common::libc::waitpid(pid as _, &mut status, hbb_common::libc::WNOHANG) }, -1);
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(hbb_common::libc::ECHILD));
        }

        #[tokio::test(flavor = "current_thread")]
        #[ignore = "requires the owned Linux parent-test VM"]
        async fn actual_resolution_result_returns_after_native_child_reap() {
            query(false).await;
        }

        #[tokio::test(flavor = "current_thread")]
        #[ignore = "requires the owned Linux parent-test VM"]
        async fn cancelled_resolution_result_keeps_native_child_and_owner() {
            query(true).await;
        }
    }
}
