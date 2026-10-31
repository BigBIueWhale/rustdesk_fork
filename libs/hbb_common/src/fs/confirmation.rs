use super::{FileTransferSendConfirmRequest, TransferJob, TransferJobMeta, MAX_ACTIVE_FILE_TRANSFER_READ_JOBS_PER_CONN};
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
    task: JoinHandle<WorkerResult>,
    _permit: OwnedSemaphorePermit,
}

enum WorkerResult {
    Confirmed(TransferJob, ResultType<Option<FileTransferSendConfirmRequest>>),
    Retired { result: ResultType<()>, cancelled_log: Option<String> },
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
                        Ok(WorkerResult::Confirmed(mut job, _)) => {
                            if let Err(error) = job.retire_current_file_state() {
                                log::error!("abandoned file confirmation cleanup failed: {error}");
                            }
                        }
                        Ok(WorkerResult::Retired { result: Err(error), .. }) => {
                            log::error!("abandoned file confirmation failed: {error}");
                        }
                        Ok(WorkerResult::Retired { result: Ok(()), .. }) => {}
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
    meta: TransferJobMeta,
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
    closed: bool,
}

pub struct Completion {
    pub id: i32,
    pub file_num: i32,
    pub job: ResultType<Option<TransferJob>>,
    pub cancelled_log: Option<String>,
    pub confirmation: Option<FileTransferSendConfirmRequest>,
}

enum Operation {
    Apply(FileTransferSendConfirmRequest),
    Prepare { file_num: i32, offset: u64 },
}

impl FileConfirmations {
    pub fn len(&self) -> usize { self.pending.len() }

    pub fn is_empty(&self) -> bool { self.pending.is_empty() }

    pub fn contains(&self, id: i32) -> bool {
        self.pending.iter().any(|pending| pending.id == id)
    }

    /// Snapshot metadata is available while the worker exclusively owns the file.
    /// Explicitly cancelled transfers must not reappear in a reconnect checkpoint.
    pub fn metas(&self) -> impl Iterator<Item = &TransferJobMeta> {
        self.pending.iter()
            .filter(|pending| !pending.cancelled.load(Ordering::Acquire))
            .map(|pending| &pending.meta)
    }

    pub fn start(&mut self, job: TransferJob, request: FileTransferSendConfirmRequest) -> ResultType<()> {
        self.start_operation(job, Operation::Apply(request))
    }

    pub fn prepare(&mut self, job: TransferJob, file_num: i32, offset: u64) -> ResultType<()> {
        self.start_operation(job, Operation::Prepare { file_num, offset })
    }

    fn start_operation(&mut self, mut job: TransferJob, operation: Operation) -> ResultType<()> {
        let admission = (|| {
            if self.closed { bail!("file confirmation admission is closed"); }
            if self.contains(job.id()) { bail!("file confirmation is already pending"); }
            if self.len() >= MAX_ACTIVE_FILE_TRANSFER_READ_JOBS_PER_CONN {
                bail!("too many pending file confirmations");
            }
            match &operation {
                Operation::Apply(request) => {
                    job.validate_confirmation_target(request.id, request.file_num)?;
                    super::receive_confirmation_prefix(request)?;
                }
                Operation::Prepare { file_num, offset } => {
                    job.validate_confirmation_target(job.id(), *file_num)?;
                    if *offset > u32::MAX as u64 {
                        bail!("resume byte offset exceeds the protocol limit");
                    }
                }
            }
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
        let meta = job.gen_meta();
        let cancelled = Arc::new(AtomicBool::new(false));
        job.resume_cancelled = Some(cancelled.clone());
        let worker_cancelled = cancelled.clone();
        let task = runtime.spawn(async move {
            let result = if worker_cancelled.load(Ordering::Acquire) {
                Err(anyhow!("file confirmation cancelled before admission"))
            } else {
                match operation {
                    Operation::Apply(request) => job.confirm(&request).await.map(|()| None),
                    Operation::Prepare { file_num, offset } =>
                        job.confirm_with_offset(file_num, offset).await.map(Some),
                }
            };
            WorkerResult::Confirmed(job, result)
        });
        self.pending.push(Pending { id, file_num, meta, cancelled,
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
                    loop {
                        let result = match Pin::new(&mut join.task).poll(cx) {
                            Poll::Ready(result) => result,
                            Poll::Pending => break,
                        };
                        match result {
                            Ok(WorkerResult::Confirmed(mut job, result))
                                if pending.cancelled.load(Ordering::Acquire) || result.is_err() => {
                                let cancelled = pending.cancelled.clone();
                                // Replace only a joined task. Pending retains the same permit
                                // and owns cleanup even if this wait or its connection disappears.
                                join.task = tokio::task::spawn_blocking(move || {
                                    let mut cancelled_log = None;
                                    let result = match job.retire_current_file_state() {
                                        Err(cleanup) => Err(anyhow!("file confirmation cleanup failed: {cleanup}; operation error: {:?}", result.err())),
                                        Ok(()) if cancelled.load(Ordering::Acquire) => {
                                            cancelled_log = Some(super::serialize_transfer_job(&job, false, true, ""));
                                            Ok(())
                                        }
                                        Ok(()) => result.map(|_| ()),
                                    };
                                    WorkerResult::Retired { result, cancelled_log }
                                });
                                // Poll the replacement to register this waiter's waker.
                            }
                            result => return Poll::Ready((index, result)),
                        }
                    }
                }
            }
            Poll::Pending
        }).await;
        let mut pending = self.pending.remove(index);
        // Native retirement has completed before its permit can be returned.
        let _joined = pending.join.take();
        let mut cancelled_log = None;
        let mut confirmation = None;
        let job = match result {
            Ok(WorkerResult::Confirmed(mut job, result)) => {
                job.resume_cancelled = None;
                confirmation = result.ok().flatten();
                Ok(Some(job))
            }
            Ok(WorkerResult::Retired { result, cancelled_log: retired_log }) => {
                cancelled_log = retired_log;
                result.map(|()| None)
            }
            Err(error) => {
                log::error!("file confirmation worker lost its exact owner: {error}");
                std::process::abort();
            }
        };
        Completion { id: pending.id, file_num: pending.file_num, job, cancelled_log, confirmation }
    }

    pub fn close(&mut self) {
        self.closed = true;
        for pending in &self.pending {
            pending.cancelled.store(true, Ordering::Release);
        }
    }

    pub async fn close_and_wait(&mut self) -> ResultType<()> {
        self.close();
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
    #[cfg(target_arch = "x86_64")]
    mod slow_sync;

    use super::*;
    use crate::{fs::JobType, message_proto::*};
    use crate::protobuf::Message as _;
    use std::{io::{Read, Seek, Write}, os::{fd::{AsRawFd, FromRawFd}, unix::{ffi::OsStrExt, fs::MetadataExt}},
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

    struct ReceiveFixture {
        directory: Fixture,
        target: PathBuf,
        payload: PathBuf,
        digest: PathBuf,
        lease: PathBuf,
        size: u64,
        offset: u64,
    }

    impl ReceiveFixture {
        fn new(large: bool) -> Self {
            use super::super::{FileDigest, ReceiveClaimCleanup, ReceiveWriteClaim};
            let directory = Fixture::new();
            let (size, offset) = if large { (u32::MAX as u64 + 4, u32::MAX as u64) } else { (6, 3) };
            let target = directory.0.join("received.zip");
            std::fs::write(&target, b"original").unwrap();
            let (mut stream, mut claim) = ReceiveWriteClaim::start_new(
                target.clone(), FileDigest { size, modified: 31 },
            ).unwrap();
            if large { stream.set_len(offset).unwrap(); }
            else { stream.write_all(b"abc").unwrap(); }
            stream.sync_all().unwrap();
            let path = |file: &std::fs::File| std::fs::read_link(format!("/proc/thread-self/fd/{}", file.as_raw_fd())).unwrap();
            let (payload, digest, lease) = (path(&claim.download_file), path(&claim.digest_file), path(&claim._lease.file));
            drop(stream);
            claim.cleanup_on_drop = ReceiveClaimCleanup::Lease;
            claim.cleanup().unwrap();
            Self { directory, target, payload, digest, lease, size, offset }
        }

        async fn job(&self, id: i32) -> TransferJob {
            let mut job = TransferJob::new_write(id, JobType::Generic, "source.zip".to_owned(),
                self.directory.0.clone(), 0, false, true, true)
                .with_files(vec![FileEntry { name: "received.zip".into(), size: self.size,
                    modified_time: 31, ..Default::default() }]).unwrap();
            job.is_resume = true;
            let result = job.inspect_receive_digest(&FileTransferDigest {
                id, file_num: 0, file_size: self.size, last_modified: 31, ..Default::default()
            }, true).await.unwrap();
            let super::super::DigestCheckResult::NeedConfirm(digest) = result.0 else {
                panic!("saved prefix must be resumable");
            };
            assert_eq!(digest.transferred_size, self.offset);
            job
        }

        fn assert_preserved(&self, digest: &[u8]) {
            assert_eq!(std::fs::read(&self.target).unwrap(), b"original");
            assert_eq!(std::fs::metadata(&self.payload).unwrap().len(), self.offset);
            if self.offset == 3 { assert_eq!(std::fs::read(&self.payload).unwrap(), b"abc"); }
            assert_eq!(std::fs::read(&self.digest).unwrap(), digest);
            assert!(!self.lease.exists());
            let expected = std::fs::metadata(&self.payload).unwrap();
            for entry in std::fs::read_dir("/proc/thread-self/fd").unwrap() {
                match std::fs::metadata(entry.unwrap().path()) {
                    Ok(meta) => assert_ne!((meta.dev(), meta.ino()), (expected.dev(), expected.ino())),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => panic!("cannot inspect receive handle retirement: {error}"),
                }
            }
        }
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
            assert!(result.confirmation.is_none());
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
        for prepare in [false, true] {
        let fixture = Fixture::new();
        let request = fixture.large_source();
        let mut watch = AccessWatch::new(&fixture.source());
        let mut owner = FileConfirmations::default();
        if prepare { owner.prepare(fixture.job(701), 0, u32::MAX as u64).unwrap(); }
        else { owner.start(fixture.job(701), request).unwrap(); }
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
        assert!(completion.confirmation.is_none());
        let log: serde_json::Value = serde_json::from_str(&completion.cancelled_log.unwrap()).unwrap();
        assert_eq!(log["id"], 701);
        assert_eq!(log["cancel"], true);
        assert_eq!(log["done"], false);
        assert_eq!((owner.len(), fixture.source_handles()), (0, 0));
        assert_eq!(drain().unwrap().capacity.available_permits(), DRAIN_CAPACITY);
        drop((outgoing, incoming, listener, watch, fixture));
        println!("FILE_CONFIRMATION_CONTROL=pass prepare={prepare} native_read=observed tcp=ping-pong worker=pending cancellation=joined source_handles=retired");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn prepared_proofs_roundtrip_both_transfer_roles() {
        for receiving in [false, true] {
            let fixture = ReceiveFixture::new(false);
            let sender = fixture.directory.job(720);
            let receiver = fixture.job(720).await;
            let (producer, peer) = if receiving { (receiver, sender) } else { (sender, receiver) };
            let expected_meta = serde_json::to_value(producer.gen_meta()).unwrap();
            let mut owner = FileConfirmations::default();
            owner.prepare(producer, 0, 3).unwrap();
            assert_eq!(serde_json::to_value(owner.metas().next().unwrap()).unwrap(), expected_meta);
            let completion = owner.next().await;
            assert_eq!(owner.metas().count(), 0);
            let producer = completion.job.unwrap().unwrap();
            let request = completion.confirmation.unwrap();
            let request = FileTransferSendConfirmRequest::parse_from_bytes(&request.write_to_bytes().unwrap()).unwrap();
            assert!(matches!(request.union.as_ref(), Some(file_transfer_send_confirm_request::Union::Resume(resume))
                if resume.offset == 3 && resume.prefix_sha256.len() == 32));
            owner.start(peer, request).unwrap();
            let completion = owner.next().await;
            assert!(completion.confirmation.is_none());
            let peer = completion.job.unwrap().unwrap();
            let (mut sender, mut receiver) = if receiving { (peer, producer) } else { (producer, peer) };
            assert_eq!(std::fs::read(&fixture.target).unwrap(), b"original");
            while let Some(block) = sender.read().await.unwrap() {
                receiver.write(block).await.unwrap();
            }
            receiver.finalize_write(sender.file_num()).await.unwrap();
            assert_eq!(std::fs::read(&fixture.target).unwrap(), b"abcdef");
            assert_eq!((sender.finished_size(), receiver.finished_size()), (6, 6));
            assert!(!fixture.payload.exists() && !fixture.digest.exists() && !fixture.lease.exists());
            assert_eq!(fixture.directory.source_handles(), 0);
            drop((sender, receiver, fixture));
            println!("FILE_CONFIRMATION_PREPARE=pass receiving={receiving} wire=roundtripped peer=verified final=exact handles=retired");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn prepared_receive_cancellation_preserves_partial_and_checkpoint_rules() {
        for phase in ["before", "during", "completed", "close", "drop"] {
            let large = matches!(phase, "during" | "close" | "drop");
            let fixture = ReceiveFixture::new(large);
            let digest = std::fs::read(&fixture.digest).unwrap();
            let job = fixture.job(721).await;
            let expected_meta = serde_json::to_value(job.gen_meta()).unwrap();
            let mut watch = AccessWatch::new(&fixture.payload);
            let mut owner = FileConfirmations::default();
            owner.prepare(job, 0, fixture.offset).unwrap();
            if large { watch.wait().await; }
            if phase == "completed" {
                tokio::time::timeout(Duration::from_secs(3), async {
                    while !owner.pending[0].join.as_ref().unwrap().task.is_finished() {
                        tokio::task::yield_now().await;
                    }
                }).await.unwrap();
            }
            let checkpoint = owner.metas().cloned().collect::<Vec<_>>();
            assert_eq!(checkpoint.len(), 1);
            assert_eq!(serde_json::to_value(&checkpoint[0]).unwrap(), expected_meta);
            if phase == "drop" {
                drop(owner);
                tokio::time::timeout(Duration::from_secs(3), async {
                    while drain().unwrap().capacity.available_permits() != DRAIN_CAPACITY {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                }).await.unwrap();
            } else if phase == "close" {
                let other_fixture = Fixture::new();
                other_fixture.large_source();
                let mut other_watch = AccessWatch::new(&other_fixture.source());
                let mut other = FileConfirmations::default();
                other.prepare(other_fixture.job(723), 0, u32::MAX as u64).unwrap();
                other_watch.wait().await;
                owner.close();
                other.close();
                assert_eq!((owner.len(), other.len()), (1, 1));
                assert_eq!((owner.metas().count(), other.metas().count()), (0, 0));
                tokio::time::timeout(Duration::from_secs(3), owner.close_and_wait()).await.unwrap().unwrap();
                tokio::time::timeout(Duration::from_secs(3), other.close_and_wait()).await.unwrap().unwrap();
                assert_eq!(other_fixture.source_handles(), 0);
                drop((other_watch, other, other_fixture));
                assert_eq!(owner.metas().count(), 0);
            } else {
                assert!(owner.cancel(721));
                assert_eq!(owner.metas().count(), 0);
                assert_eq!(owner.len(), 1);
                let result = tokio::time::timeout(Duration::from_secs(3), owner.next()).await.unwrap();
                assert!(result.job.unwrap().is_none() && result.confirmation.is_none());
                assert!(result.cancelled_log.is_some());
            }
            fixture.assert_preserved(&digest);
            let mut lease = super::super::ReceivePathLease::acquire(&fixture.target, false).unwrap();
            lease.retire().unwrap();
            drop((lease, watch, fixture));
            println!("FILE_CONFIRMATION_RECEIVE_CANCEL=pass phase={phase} partial=preserved final=preserved proof=unpublished lease=reacquired checkpoint=exact");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn prepare_refuses_invalid_targets_before_worker_admission() {
        let fixture = Fixture::new();
        let mut owner = FileConfirmations::default();
        for (file_num, offset) in [(-1, 1), (1, 1), (0, u32::MAX as u64 + 1)] {
            assert!(owner.prepare(fixture.job(722), file_num, offset).is_err());
            assert_eq!((owner.len(), owner.metas().count(), fixture.source_handles()), (0, 0, 0));
        }
        let mut fresh = fixture.job(722);
        assert!(fresh.init_data_stream_for_cm().await.unwrap().is_some());
        owner.prepare(fresh, 0, 0).unwrap();
        let completion = owner.next().await;
        assert!(matches!(completion.confirmation.unwrap().union,
            Some(file_transfer_send_confirm_request::Union::OffsetBlk(0))));
        let mut job = completion.job.unwrap().unwrap();
        assert_eq!(job.read().await.unwrap().unwrap().data.as_ref(), b"abcdef");
        job.retire_current_file_state().unwrap();
        owner.close_and_wait().await.unwrap();
        assert!(owner.prepare(fixture.job(722), 0, 0).unwrap_err().to_string().contains("admission is closed"));
        assert_eq!(fixture.source_handles(), 0);
        drop((job, fixture));
        println!("FILE_CONFIRMATION_PREPARE_ADMISSION=pass invalid=refused fresh=exact closed=refused handles=retired");
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
