// Native counterexample from c16ec444530f001145395c3d4974d2d5d57df960:
// src/server/connection.rs::Connection::run_cm_ipc_until_owner_closed.
// The complete function is retained verbatim; only its enclosing test type differs.
impl BeforeConnection {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    async fn run_cm_ipc_until_owner_closed<F, T>(
        owner_closed: oneshot::Receiver<()>,
        bootstrap_complete: oneshot::Receiver<()>,
        task: F,
    ) -> Option<T>
    where
        F: std::future::Future<Output = T>,
    {
        let mut owner_closed = owner_closed;
        let mut bootstrap_complete = bootstrap_complete;
        let mut task = Box::pin(task);
        tokio::select! {
            biased;
            result = &mut task => Some(result),
            _ = &mut bootstrap_complete => {
                tokio::select! {
                    result = &mut task => Some(result),
                    _ = &mut owner_closed => {
                        time::timeout(CM_OWNER_TERMINAL_DRAIN_TIMEOUT, &mut task)
                            .await
                            .ok()
                    }
                }
            }
            _ = &mut owner_closed => None,
        }
    }

}
