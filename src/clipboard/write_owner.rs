use hbb_common::{bail, log, tokio::sync::oneshot, ResultType};
use std::sync::{Arc, Mutex};

pub(crate) struct ClipboardWriteOwner {
    writer: ClipboardWriter,
    completion: Option<oneshot::Receiver<()>>,
}

#[derive(Clone)]
pub(crate) struct ClipboardWriter(Arc<Mutex<State>>);

#[derive(Clone, Default)]
pub(crate) struct ViewerClipboardPermissionRevision(Arc<Mutex<u64>>);

pub(crate) struct ViewerClipboardPermission {
    source: ViewerClipboardPermissionRevision,
    revision: u64,
}

enum Authority {
    Controlled,
    Viewer(ViewerClipboardPermissionRevision),
}

pub(super) struct ClipboardWriteRequest {
    writer: ClipboardWriter,
    permission: Option<ViewerClipboardPermission>,
}

struct State {
    open: bool,
    active: bool,
    authority: Authority,
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
    pub(crate) fn controlled() -> Self {
        Self::new(Authority::Controlled)
    }

    pub(crate) fn viewer(permission: &ViewerClipboardPermissionRevision) -> Self {
        Self::new(Authority::Viewer(permission.clone()))
    }

    fn new(authority: Authority) -> Self {
        let (completion, receiver) = oneshot::channel();
        Self {
            writer: ClipboardWriter(Arc::new(Mutex::new(State {
                open: true,
                active: false,
                authority,
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
}

impl ViewerClipboardPermissionRevision {
    pub(crate) fn advance(&self) {
        let exhausted = {
            let mut revision = self.0.lock().unwrap();
            match revision.checked_add(1) {
                Some(next) => {
                    *revision = next;
                    next == u64::MAX
                }
                None => true,
            }
        };
        if exhausted {
            log::error!("viewer clipboard permission revision exhausted; refusing writes");
        }
    }

    pub(crate) fn capture(&self) -> Option<ViewerClipboardPermission> {
        let revision = *self.0.lock().unwrap();
        (revision != u64::MAX).then(|| ViewerClipboardPermission {
            source: self.clone(),
            revision,
        })
    }
}

impl ClipboardWriteRequest {
    pub(super) fn controlled(writer: &ClipboardWriter) -> Self {
        Self {
            writer: writer.clone(),
            permission: None,
        }
    }

    pub(super) fn viewer(writer: &ClipboardWriter, permission: ViewerClipboardPermission) -> Self {
        Self {
            writer: writer.clone(),
            permission: Some(permission),
        }
    }

    pub(super) fn is_live(&self) -> bool {
        self.writer.is_live() && self.permission.as_ref().map_or(true, |permission| {
            *permission.source.0.lock().unwrap() == permission.revision
        })
    }

    // Called with the native clipboard locks already held, immediately before SET.
    // Retirement cancels unselected work; an admitted native effect retains its
    // exact owner until it settles, even if the connection task is cancelled.
    pub(super) fn begin(&self) -> ResultType<Option<ClipboardWritePermit>> {
        let mut locked = self.writer.0.lock().unwrap();
        let state = &mut *locked;
        if !state.open {
            return Ok(None);
        }
        let _revision = match (&state.authority, self.permission.as_ref()) {
            (Authority::Controlled, None) => None,
            (Authority::Viewer(source), Some(permission)) => {
                if !Arc::ptr_eq(&source.0, &permission.source.0) {
                    bail!("clipboard permission did not belong to this viewer round");
                }
                let revision = source.0.lock().unwrap();
                if *revision == u64::MAX || *revision != permission.revision {
                    return Ok(None);
                }
                Some(revision)
            }
            _ => bail!("clipboard write did not match its round authority"),
        };
        if state.active {
            state.open = false;
            bail!("clipboard owner already has an admitted native write");
        }
        state.active = true;
        Ok(Some(ClipboardWritePermit(self.writer.clone())))
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
    use hbb_common::tokio;
    use std::time::Duration;

    #[test]
    fn owner_drop_retires_every_queued_writer() {
        let owner = ClipboardWriteOwner::controlled();
        let writer = owner.writer();
        let queued = writer.clone();
        drop(owner);
        assert!(!writer.is_live());
        assert!(ClipboardWriteRequest::controlled(&queued).begin().unwrap().is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retirement_waits_for_the_admitted_native_effect() {
        let mut owner = ClipboardWriteOwner::controlled();
        let writer = owner.writer();
        let permit = ClipboardWriteRequest::controlled(&writer).begin().unwrap().unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(20), owner.close_and_wait())
            .await.is_err());
        assert!(ClipboardWriteRequest::controlled(&writer).begin().unwrap().is_none());
        drop(permit);
        tokio::time::timeout(Duration::from_secs(2), owner.close_and_wait())
            .await.unwrap().unwrap();
        owner.close_and_wait().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stale_retirement_cannot_close_a_fresh_owner() {
        let mut old = ClipboardWriteOwner::controlled();
        let stale = old.writer();
        old.close_and_wait().await.unwrap();
        let mut fresh = ClipboardWriteOwner::controlled();
        let writer = fresh.writer();
        old.close();
        drop(old);
        assert!(ClipboardWriteRequest::controlled(&stale).begin().unwrap().is_none());
        let permit = ClipboardWriteRequest::controlled(&writer).begin().unwrap().unwrap();
        drop(permit);
        fresh.close_and_wait().await.unwrap();
    }

    #[test]
    fn viewer_permission_is_source_bound() {
        let source = ViewerClipboardPermissionRevision::default();
        let other = ViewerClipboardPermissionRevision::default();
        let owner = ClipboardWriteOwner::viewer(&source);
        let writer = owner.writer();
        assert!(ClipboardWriteRequest::viewer(&writer, other.capture().unwrap()).begin().is_err());
        assert!(writer.is_live());
        let permit = ClipboardWriteRequest::viewer(&writer, source.capture().unwrap())
            .begin().unwrap().unwrap();
        drop(permit);
    }

    #[test]
    fn viewer_permission_exhaustion_cannot_wrap() {
        let source = ViewerClipboardPermissionRevision::default();
        *source.0.lock().unwrap() = u64::MAX - 1;
        let owner = ClipboardWriteOwner::viewer(&source);
        let request = ClipboardWriteRequest::viewer(&owner.writer(), source.capture().unwrap());
        source.advance();
        assert!(source.capture().is_none());
        assert!(request.begin().unwrap().is_none());
        source.advance();
        assert_eq!(*source.0.lock().unwrap(), u64::MAX);
        assert!(source.capture().is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn revocation_keeps_admitted_native_effect_owned() {
        let source = ViewerClipboardPermissionRevision::default();
        let mut owner = ClipboardWriteOwner::viewer(&source);
        let request = ClipboardWriteRequest::viewer(&owner.writer(), source.capture().unwrap());
        let permit = request.begin().unwrap().unwrap();
        source.advance();
        source.advance();
        assert!(request.begin().unwrap().is_none());
        assert!(tokio::time::timeout(Duration::from_millis(20), owner.close_and_wait())
            .await.is_err());
        drop(permit);
        tokio::time::timeout(Duration::from_secs(2), owner.close_and_wait())
            .await.unwrap().unwrap();
    }
}
