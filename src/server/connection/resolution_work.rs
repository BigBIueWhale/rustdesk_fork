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
}
