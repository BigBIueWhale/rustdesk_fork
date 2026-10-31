use super::{FileTransferSendConfirmRequest, TransferJob, MAX_ACTIVE_FILE_TRANSFER_READ_JOBS_PER_CONN};
use crate::{anyhow::anyhow, bail, log, ResultType};
use std::{
    future::Future,
    pin::Pin,
    sync::{atomic::{AtomicBool, Ordering}, mpsc, Arc, OnceLock},
    task::Poll,
};
use tokio::{sync::{OwnedSemaphorePermit, Semaphore}, task::JoinHandle};

// Capacity stays charged through native completion and exact task joining, including
// after connection cancellation. Dropping a connection cannot admit unbounded readers.
const DRAIN_CAPACITY: usize = 32;

struct Join {
    task: JoinHandle<(TransferJob, ResultType<()>)>,
    _permit: OwnedSemaphorePermit,
}

struct Drain {
    sender: mpsc::SyncSender<Join>,
    capacity: Arc<Semaphore>,
    _thread: std::thread::JoinHandle<()>,
}

static DRAIN: OnceLock<Result<Drain, String>> = OnceLock::new();

fn drain() -> ResultType<&'static Drain> {
    DRAIN.get_or_init(|| {
        let (sender, receiver) = mpsc::sync_channel::<Join>(DRAIN_CAPACITY);
        let thread = std::thread::Builder::new()
            .name("rustdesk-resume-drain".to_owned())
            .spawn(move || {
                while let Ok(join) = receiver.recv() {
                    match crate::futures::executor::block_on(join.task) {
                        Ok((mut job, _)) => {
                            if let Err(error) = job.retire_current_file_state() {
                                log::error!("abandoned file confirmation cleanup failed: {error}");
                            }
                        }
                        Err(error) => {
                            log::error!("file confirmation worker failed during drain: {error}");
                            // A task failure does not prove its native IO has retired.
                            std::process::abort();
                        }
                    }
                    // The permit remains owned until the exact task and its returned job retire.
                }
            })
            .map_err(|error| format!("cannot start file confirmation drain: {error}"))?;
        Ok(Drain { sender, capacity: Arc::new(Semaphore::new(DRAIN_CAPACITY)), _thread: thread })
    }).as_ref().map_err(|error| anyhow!("{error}"))
}

struct Pending {
    id: i32,
    file_num: i32,
    cancelled: Arc<AtomicBool>,
    join: Option<Join>,
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            // Every queued or locally owned join carries one of the same finite permits.
            let sent = drain().map(|drain| drain.sender.try_send(join).is_ok());
            if !matches!(sent, Ok(true)) {
                log::error!("file confirmation lost its exact drain owner");
                std::process::abort();
            }
        }
    }
}

/// One connection owns these jobs until completion or cooperative cancellation.
/// Workers never publish peer messages or return themselves to a job list.
#[derive(Default)]
pub struct FileConfirmations {
    pending: Vec<Pending>,
}

pub struct Completion {
    pub id: i32,
    pub file_num: i32,
    pub job: ResultType<Option<TransferJob>>,
    pub cancelled_log: Option<String>,
}

impl FileConfirmations {
    pub fn len(&self) -> usize { self.pending.len() }

    pub fn is_empty(&self) -> bool { self.pending.is_empty() }

    pub fn contains(&self, id: i32) -> bool {
        self.pending.iter().any(|pending| pending.id == id)
    }

    pub fn start(&mut self, mut job: TransferJob, request: FileTransferSendConfirmRequest) -> ResultType<()> {
        let admission = (|| {
            if self.contains(job.id()) { bail!("file confirmation is already pending"); }
            if self.len() >= MAX_ACTIVE_FILE_TRANSFER_READ_JOBS_PER_CONN {
                bail!("too many pending file confirmations");
            }
            job.validate_confirmation_target(request.id, request.file_num)?;
            super::receive_confirmation_prefix(&request)?;
            self.pending.try_reserve(1)
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::OutOfMemory))?;
            let runtime = tokio::runtime::Handle::try_current()?;
            let permit = drain()?.capacity.clone().try_acquire_owned()
                .map_err(|_| anyhow!("file confirmation drain capacity reached"))?;
            Ok((runtime, permit))
        })();
        let (runtime, permit) = match admission {
            Ok(admission) => admission,
            Err(error) => {
                return match job.retire_current_file_state() {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(anyhow!("{error}; file confirmation cleanup failed: {cleanup}")),
                };
            }
        };
        let id = job.id();
        let file_num = job.file_num();
        let cancelled = Arc::new(AtomicBool::new(false));
        job.resume_cancelled = Some(cancelled.clone());
        let worker_cancelled = cancelled.clone();
        let task = runtime.spawn(async move {
            let result = if worker_cancelled.load(Ordering::Acquire) {
                Err(anyhow!("file confirmation cancelled before admission"))
            } else { job.confirm(&request).await };
            (job, result)
        });
        self.pending.push(Pending { id, file_num, cancelled,
            join: Some(Join { task, _permit: permit }) });
        Ok(())
    }

    pub fn cancel(&self, id: i32) -> bool {
        let mut found = false;
        for pending in &self.pending {
            if pending.id == id {
                pending.cancelled.store(true, Ordering::Release);
                found = true;
            }
        }
        found
    }

    pub async fn next(&mut self) -> Completion {
        let (index, result) = std::future::poll_fn(|cx| {
            for (index, pending) in self.pending.iter_mut().enumerate() {
                if let Some(join) = pending.join.as_mut() {
                    if let Poll::Ready(result) = Pin::new(&mut join.task).poll(cx) {
                        return Poll::Ready((index, result));
                    }
                }
            }
            Poll::Pending
        }).await;
        let mut pending = self.pending.remove(index);
        let cancelled = pending.cancelled.load(Ordering::Acquire);
        // Keep the permit through disposal of a cancelled/failed returned job.
        let _joined = pending.join.take();
        let mut cancelled_log = None;
        let job = match result {
            Ok((mut job, result)) if !cancelled && result.is_ok() => {
                job.resume_cancelled = None;
                Ok(Some(job))
            }
            Ok((mut job, result)) => {
                match job.retire_current_file_state() {
                    Err(cleanup) => Err(anyhow!("file confirmation cleanup failed: {cleanup}; operation: {result:?}")),
                    Ok(()) if cancelled => {
                        cancelled_log = Some(super::serialize_transfer_job(&job, false, true, ""));
                        Ok(None)
                    }
                    Ok(()) => result.map(|()| None),
                }
            }
            Err(error) => {
                log::error!("file confirmation worker lost its exact owner: {error}");
                std::process::abort();
            }
        };
        Completion { id: pending.id, file_num: pending.file_num, job, cancelled_log }
    }

    pub async fn close_and_wait(&mut self) -> ResultType<()> {
        for pending in &self.pending {
            pending.cancelled.store(true, Ordering::Release);
        }
        let mut failure = None;
        while !self.is_empty() {
            if let Err(error) = self.next().await.job {
                if failure.is_none() { failure = Some(error); }
                else { log::error!("additional file confirmation cleanup failure: {error}"); }
            }
        }
        match failure { Some(error) => Err(error), None => Ok(()) }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::{fs::JobType, message_proto::*};
    use std::{io::{Read, Seek, Write}, os::{fd::FromRawFd, unix::{ffi::OsStrExt, fs::MetadataExt}},
        path::PathBuf, time::Duration};

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("rustdesk-confirmation-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            std::fs::write(path.join("source.zip"), b"abcdef").unwrap();
            Self(path)
        }
        fn source(&self) -> PathBuf { self.0.join("source.zip") }
        fn job(&self, id: i32) -> TransferJob {
            TransferJob::new_read(id, JobType::Generic, String::new(), self.source(),
                0, false, false, true).unwrap()
        }
        async fn request(&self, id: i32) -> FileTransferSendConfirmRequest {
            let mut producer = self.job(id);
            producer.confirm_with_offset(0, 3).await.unwrap()
        }
        fn large_source(&self) -> FileTransferSendConfirmRequest {
            let offset = u32::MAX;
            let mut file = std::fs::File::create(self.source()).unwrap();
            file.set_len(u64::from(offset) + 4).unwrap();
            file.seek(std::io::SeekFrom::Start(u64::from(offset))).unwrap();
            file.write_all(b"tail").unwrap();
            assert!(file.metadata().unwrap().blocks() * 512 <= 128 * 1024);
            FileTransferSendConfirmRequest { id: 701, file_num: 0,
                union: Some(file_transfer_send_confirm_request::Union::Resume(FileTransferResume {
                    offset, prefix_sha256: vec![0; 32].into(), ..Default::default()
                })), ..Default::default() }
        }
        fn source_handles(&self) -> usize {
            let expected = std::fs::metadata(self.source()).unwrap();
            std::fs::read_dir("/proc/thread-self/fd").unwrap().filter_map(|entry| {
                let path = entry.unwrap().path();
                match std::fs::metadata(path) {
                    Ok(value) => Some(value),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => panic!("cannot inspect owned source handle: {error}"),
                }
            }).filter(|value| (value.dev(), value.ino()) == (expected.dev(), expected.ino())).count()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) { std::fs::remove_dir_all(&self.0).unwrap(); }
    }

    struct AccessWatch(std::fs::File);
    impl AccessWatch {
        fn new(path: &std::path::Path) -> Self {
            let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
            assert!(fd >= 0);
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            assert!(unsafe { libc::inotify_add_watch(fd, path.as_ptr(), libc::IN_ACCESS) } >= 0);
            Self(file)
        }
        async fn wait(&mut self) {
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let mut events = [0; 4096];
                    match self.0.read(&mut events) {
                        Ok(count) => { assert!(count > 0); return; }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(error) => panic!("cannot observe native prefix read: {error}"),
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }).await.unwrap();
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exact_proof_completion_returns_only_the_owned_job() {
        for valid in [false, true] {
            let fixture = Fixture::new();
            let mut request = fixture.request(700).await;
            if !valid {
                if let Some(file_transfer_send_confirm_request::Union::Resume(value)) = request.union.as_mut() {
                    value.prefix_sha256 = vec![0; 32].into();
                }
            }
            let mut owner = FileConfirmations::default();
            owner.start(fixture.job(700), request).unwrap();
            let result = owner.next().await;
            assert_eq!((result.id, result.file_num, owner.len()), (700, 0, 0));
            assert!(result.cancelled_log.is_none());
            if valid {
                let mut job = result.job.unwrap().unwrap();
                assert!(job.file_confirmed());
                assert_eq!((job.finished_size(), job.transferred()), (3, 3));
                assert_eq!(job.read().await.unwrap().unwrap().data.as_ref(), b"def");
                job.retire_current_file_state().unwrap();
            } else {
                assert!(result.job.err().unwrap().to_string().contains("resume prefix differs"));
            }
            assert_eq!(fixture.source_handles(), 0);
            assert_eq!(std::fs::read(fixture.source()).unwrap(), b"abcdef");
            drop(fixture);
            println!("FILE_CONFIRMATION_PROOF=pass valid={valid} source=preserved handles=retired");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pending_hash_allows_tcp_control_and_cancelled_wait_keeps_ownership() {
        use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};
        let fixture = Fixture::new();
        let request = fixture.large_source();
        let mut watch = AccessWatch::new(&fixture.source());
        let mut owner = FileConfirmations::default();
        owner.start(fixture.job(701), request).unwrap();
        let mut wait = Box::pin(owner.next());
        let first = std::future::poll_fn(|cx| Poll::Ready(wait.as_mut().poll(cx))).await;
        assert!(first.is_pending());
        drop(wait);
        assert_eq!(owner.len(), 1);
        watch.wait().await;
        assert!(fixture.source_handles() > 0);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (outgoing, incoming) = tokio::join!(TcpStream::connect(address), listener.accept());
        let (mut outgoing, mut incoming) = (outgoing.unwrap(), incoming.unwrap().0);
        let control = async {
            outgoing.write_all(b"ping").await.unwrap();
            let mut bytes = [0; 4];
            incoming.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ping");
            incoming.write_all(b"pong").await.unwrap();
            outgoing.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"pong");
        };
        tokio::time::timeout(Duration::from_secs(1), control).await.unwrap();
        assert!(!owner.pending[0].join.as_ref().unwrap().task.is_finished());
        assert!(owner.cancel(701));
        assert_eq!(owner.len(), 1);
        assert_eq!(drain().unwrap().capacity.available_permits(), DRAIN_CAPACITY - 1);
        let completion = tokio::time::timeout(Duration::from_secs(3), owner.next()).await.unwrap();
        assert!(completion.job.unwrap().is_none());
        let log: serde_json::Value = serde_json::from_str(&completion.cancelled_log.unwrap()).unwrap();
        assert_eq!(log["id"], 701);
        assert_eq!(log["cancel"], true);
        assert_eq!(log["done"], false);
        assert_eq!((owner.len(), fixture.source_handles()), (0, 0));
        assert_eq!(drain().unwrap().capacity.available_permits(), DRAIN_CAPACITY);
        drop((outgoing, incoming, listener, watch, fixture));
        println!("FILE_CONFIRMATION_CONTROL=pass native_read=observed tcp=ping-pong worker=pending cancellation=joined source_handles=retired");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_after_worker_completion_cannot_restore_job() {
        let fixture = Fixture::new();
        let mut owner = FileConfirmations::default();
        owner.start(fixture.job(702), fixture.request(702).await).unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while !owner.pending[0].join.as_ref().unwrap().task.is_finished() {
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        assert!(owner.cancel(702));
        assert!(owner.next().await.job.unwrap().is_none());
        assert_eq!(fixture.source_handles(), 0);
        drop(fixture);
        println!("FILE_CONFIRMATION_LATE_CANCEL=pass completed_worker=retired restored_job=absent");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn owner_drop_drains_the_exact_native_reader() {
        let fixture = Fixture::new();
        let request = fixture.large_source();
        let mut watch = AccessWatch::new(&fixture.source());
        let mut owner = FileConfirmations::default();
        owner.start(fixture.job(701), request).unwrap();
        watch.wait().await;
        assert!(fixture.source_handles() > 0);
        drop(owner);
        tokio::time::timeout(Duration::from_secs(3), async {
            while drain().unwrap().capacity.available_permits() != DRAIN_CAPACITY {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }).await.unwrap();
        assert_eq!(fixture.source_handles(), 0);
        drop((watch, fixture));
        println!("FILE_CONFIRMATION_DROP=pass native_reader=joined permits=returned source_handles=retired");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn completed_and_cancelled_jobs_remain_charged_until_joined() {
        let fixture = Fixture::new();
        let mut owner = FileConfirmations::default();
        let mut other = FileConfirmations::default();
        let request = fixture.request(710).await;
        for index in 0..DRAIN_CAPACITY {
            let id = 710 + index as i32;
            let mut request = request.clone(); request.id = id;
            owner.start(fixture.job(id), request).unwrap();
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            while owner.pending.iter().any(|pending| !pending.join.as_ref().unwrap().task.is_finished()) {
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        assert_eq!(owner.len(), DRAIN_CAPACITY);
        assert!(owner.start(fixture.job(710), request.clone()).is_err());
        assert!(other.start(fixture.job(710), request.clone()).unwrap_err()
            .to_string().contains("drain capacity"));
        owner.cancel(710);
        assert_eq!(owner.len(), DRAIN_CAPACITY);
        owner.close_and_wait().await.unwrap();
        assert_eq!((owner.len(), fixture.source_handles()), (0, 0));
        other.start(fixture.job(710), request).unwrap();
        let mut job = other.next().await.job.unwrap().unwrap();
        job.retire_current_file_state().unwrap();
        assert_eq!(fixture.source_handles(), 0);
        assert_eq!(std::fs::read(fixture.source()).unwrap(), b"abcdef");
        drop(fixture);
        println!("FILE_CONFIRMATION_CAPACITY=pass limit=32 duplicate=refused shared=bounded cancellation=charged retry=accepted");
    }
}
