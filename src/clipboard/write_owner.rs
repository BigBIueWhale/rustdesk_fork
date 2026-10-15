use hbb_common::{bail, log, tokio::sync::oneshot, ResultType};
use std::sync::{Arc, Mutex};

pub(crate) struct ClipboardWriteOwner {
    writer: ClipboardWriter,
    completion: Option<oneshot::Receiver<()>>,
}

#[derive(Clone)]
pub(crate) struct ClipboardWriter(Arc<Mutex<State>>);

struct State {
    open: bool,
    active: bool,
    completion: Option<oneshot::Sender<()>>,
}

pub(super) struct ClipboardWritePermit(ClipboardWriter);

fn publish_completion(completion: Option<oneshot::Sender<()>>) {
    if let Some(completion) = completion {
        if completion.send(()).is_err() {
            log::debug!("clipboard write owner retired before observing native completion");
        }
    }
}

impl ClipboardWriteOwner {
    pub(crate) fn new() -> Self {
        let (completion, receiver) = oneshot::channel();
        Self {
            writer: ClipboardWriter(Arc::new(Mutex::new(State {
                open: true,
                active: false,
                completion: Some(completion),
            }))),
            completion: Some(receiver),
        }
    }

    pub(crate) fn writer(&self) -> ClipboardWriter {
        self.writer.clone()
    }

    pub(crate) fn close(&self) {
        let completion = {
            let mut state = self.writer.0.lock().unwrap();
            state.open = false;
            if state.active {
                None
            } else {
                state.completion.take()
            }
        };
        publish_completion(completion);
    }

    pub(crate) async fn close_and_wait(&mut self) -> ResultType<()> {
        self.close();
        if let Some(completion) = self.completion.as_mut() {
            completion.await?;
        }
        self.completion.take();
        Ok(())
    }
}

impl Drop for ClipboardWriteOwner {
    fn drop(&mut self) {
        self.close();
    }
}

impl ClipboardWriter {
    pub(super) fn is_live(&self) -> bool {
        self.0.lock().unwrap().open
    }

    // Called with the native clipboard locks already held, immediately before SET.
    // Retirement cancels unselected work; an admitted native effect retains its
    // exact owner until it settles, even if the connection task is cancelled.
    pub(super) fn begin(&self) -> ResultType<Option<ClipboardWritePermit>> {
        let mut state = self.0.lock().unwrap();
        if !state.open {
            return Ok(None);
        }
        if state.active {
            state.open = false;
            bail!("clipboard owner already has an admitted native write");
        }
        state.active = true;
        Ok(Some(ClipboardWritePermit(self.clone())))
    }
}

impl Drop for ClipboardWritePermit {
    fn drop(&mut self) {
        let completion = {
            let mut state = self.0.0.lock().unwrap();
            state.active = false;
            if state.open {
                None
            } else {
                state.completion.take()
            }
        };
        publish_completion(completion);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn owner_drop_retires_every_queued_writer() {
        let owner = ClipboardWriteOwner::new();
        let writer = owner.writer();
        let queued = writer.clone();
        drop(owner);
        assert!(!writer.is_live());
        assert!(queued.begin().unwrap().is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_waits_for_the_admitted_native_effect() {
        let mut owner = ClipboardWriteOwner::new();
        let writer = owner.writer();
        let permit = writer.begin().unwrap().unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(20), owner.close_and_wait())
            .await.is_err());
        assert!(writer.begin().unwrap().is_none());
        drop(permit);
        tokio::time::timeout(Duration::from_secs(2), owner.close_and_wait())
            .await.unwrap().unwrap();
        owner.close_and_wait().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stale_retirement_cannot_close_a_fresh_owner() {
        let mut old = ClipboardWriteOwner::new();
        let stale = old.writer();
        old.close_and_wait().await.unwrap();
        let mut fresh = ClipboardWriteOwner::new();
        let writer = fresh.writer();
        old.close();
        drop(old);
        assert!(stale.begin().unwrap().is_none());
        let permit = writer.begin().unwrap().unwrap();
        drop(permit);
        fresh.close_and_wait().await.unwrap();
    }
}
