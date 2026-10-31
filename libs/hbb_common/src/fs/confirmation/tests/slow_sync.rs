use super::*;
use std::time::Instant;
use tokio::sync::oneshot;

// Linux x86_64 UAPI: observe fsync entry, then let the original syscall execute.
// This is a timing fixture, not an authorization filter or an emulated sync.
#[repr(C)]
#[derive(Default)]
struct Syscall { nr: i32, arch: u32, ip: u64, args: [u64; 6] }
#[repr(C)]
#[derive(Default)]
struct Notification { id: u64, pid: u32, flags: u32, data: Syscall }
#[repr(C)]
struct Response { id: u64, value: i64, error: i32, flags: u32 }

struct Gate {
    identity: (u64, u64),
    held: oneshot::Sender<u32>,
    release: mpsc::Receiver<()>,
    finished: oneshot::Sender<bool>,
}

struct Observer {
    commands: mpsc::SyncSender<(Gate, oneshot::Sender<()>)>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Observer {
    fn new() -> Self {
        let (commands, receiver) = mpsc::sync_channel::<(Gate, oneshot::Sender<()>)>(1);
        let (send_fd, receive_fd) = mpsc::sync_channel::<std::fs::File>(1);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        // Start before installing the filter: the observer must remain runnable.
        let thread = std::thread::spawn(move || {
            let Ok(fd) = receive_fd.recv() else { return; };
            let mut gate: Option<Gate> = None;
            while !stopped.load(Ordering::Acquire) {
                if let Ok((next, armed)) = receiver.try_recv() {
                    assert!(gate.is_none());
                    gate = Some(next);
                    armed.send(()).unwrap();
                }
                let mut poll = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
                let ready = unsafe { libc::poll(&mut poll, 1, 10) };
                if ready < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted { continue; }
                assert!(ready >= 0);
                if ready == 0 { continue; }
                let mut notification = Notification::default();
                assert_eq!(unsafe { libc::ioctl(fd.as_raw_fd(), 0xc050_2100u64, &mut notification) }, 0);
                assert_eq!((notification.data.nr, notification.data.arch), (libc::SYS_fsync as i32, 0xc000_003e));
                let mut report = None;
                if let Some(active) = gate.as_ref() {
                    let meta = std::fs::metadata(format!("/proc/thread-self/fd/{}", notification.data.args[0])).unwrap();
                    if (meta.dev(), meta.ino()) == active.identity {
                        let active = gate.take().unwrap();
                        let _ = active.held.send(notification.pid);
                        // The unchanged blocking baseline must be released without help
                        // from its stalled executor, so it can retire before the verdict.
                        let explicit = active.release.recv_timeout(Duration::from_secs(3)).is_ok();
                        report = Some((active.finished, explicit));
                    }
                }
                let response = Response { id: notification.id, value: 0, error: 0, flags: 1 };
                assert_eq!(unsafe { libc::ioctl(fd.as_raw_fd(), 0xc018_2101u64, &response) }, 0);
                if let Some((finished, explicit)) = report { let _ = finished.send(explicit); }
            }
            assert!(gate.is_none());
        });
        assert_eq!(std::mem::size_of::<Notification>(), 80);
        assert_eq!(std::mem::size_of::<Response>(), 24);
        let stmt = |code, k| libc::sock_filter { code, jt: 0, jf: 0, k };
        let mut filters = [
            stmt(0x20, 4), // architecture
            libc::sock_filter { code: 0x15, jt: 1, jf: 0, k: 0xc000_003e },
            stmt(0x06, 0x8000_0000),
            stmt(0x20, 0), // syscall number
            libc::sock_filter { code: 0x15, jt: 0, jf: 1, k: libc::SYS_fsync as u32 },
            stmt(0x06, 0x7fc0_0000),
            stmt(0x06, 0x7fff_0000),
        ];
        let program = libc::sock_fprog { len: filters.len() as u16, filter: filters.as_mut_ptr() };
        let ready = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        let fd = if ready == 0 { unsafe { libc::syscall(libc::SYS_seccomp, 1, 8, &program) } } else { -1 };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            drop(send_fd);
            thread.join().unwrap();
            panic!("cannot observe native fsync: {error}");
        }
        send_fd.send(unsafe { std::fs::File::from_raw_fd(fd as i32) }).unwrap();
        Self { commands, stop, thread: Some(thread) }
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() { thread.join().unwrap(); }
    }
}

#[test]
fn stalled_receive_retirement_keeps_control_and_exact_cleanup_ownership() {
    use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}};
    let observer = Observer::new();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let main_tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
    let observations = runtime.block_on(async {
        let mut observations = Vec::new();
        for abandon in [false, true] {
            let fixture = ReceiveFixture::new(false);
            let digest = std::fs::read(&fixture.digest).unwrap();
            let mut owner = FileConfirmations::default();
            owner.prepare(fixture.job(724).await, 0, 3).unwrap();
            tokio::time::timeout(Duration::from_secs(3), async {
                while !owner.pending[0].join.as_ref().unwrap().task.is_finished() {
                    tokio::task::yield_now().await;
                }
            }).await.unwrap();
            let meta = std::fs::metadata(fixture.lease.parent().unwrap()).unwrap();
            let (armed, ready) = oneshot::channel();
            let (held, mut notification) = oneshot::channel();
            let (release, released) = mpsc::sync_channel(1);
            let (finished, continued) = oneshot::channel();
            observer.commands.send((Gate { identity: (meta.dev(), meta.ino()), held,
                release: released, finished }, armed)).unwrap();
            ready.await.unwrap();
            assert!(owner.cancel(724));
            let mut wait = Box::pin(owner.next());
            let mut completion = None;
            let start = Instant::now();
            let tid = tokio::select! {
                biased;
                value = &mut notification => Some(value.unwrap()),
                value = &mut wait => { completion = Some(value); None },
            };
            drop(wait);
            let responsive = if let Some(tid) = tid {
                assert_eq!(owner.len(), 1);
                assert_eq!(drain().unwrap().capacity.available_permits(), DRAIN_CAPACITY - 1);
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let (outgoing, incoming) = tokio::join!(TcpStream::connect(listener.local_addr().unwrap()), listener.accept());
                let (mut outgoing, mut incoming) = (outgoing.unwrap(), incoming.unwrap().0);
                tokio::time::timeout(Duration::from_secs(1), async {
                    outgoing.write_all(b"ping").await.unwrap();
                    let mut bytes = [0; 4];
                    incoming.read_exact(&mut bytes).await.unwrap();
                    assert_eq!(&bytes, b"ping");
                    incoming.write_all(b"pong").await.unwrap();
                    outgoing.read_exact(&mut bytes).await.unwrap();
                    assert_eq!(&bytes, b"pong");
                }).await.unwrap();
                tid != main_tid && start.elapsed() < Duration::from_secs(1)
            } else { false };
            if abandon {
                drop(owner);
                if responsive { assert_eq!(drain().unwrap().capacity.available_permits(), DRAIN_CAPACITY - 1); }
                let _ = release.send(());
            } else {
                let _ = release.send(());
                if completion.is_none() { completion = Some(owner.next().await); }
                assert!(owner.is_empty());
                let completed = completion.take().unwrap();
                assert!(completed.job.unwrap().is_none() && completed.confirmation.is_none());
                assert!(completed.cancelled_log.is_some());
            }
            let explicit = continued.await.unwrap();
            tokio::time::timeout(Duration::from_secs(3), async {
                while drain().unwrap().capacity.available_permits() != DRAIN_CAPACITY {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }).await.unwrap();
            fixture.assert_preserved(&digest);
            let mut lease = super::super::super::ReceivePathLease::acquire(&fixture.target, false).unwrap();
            lease.retire().unwrap();
            drop((lease, fixture));
            println!("FILE_CONFIRMATION_SYNC=observed abandon={abandon} responsive={responsive} explicit_release={explicit} permits=returned partial=preserved lease=reacquired");
            observations.push(responsive && explicit);
        }
        observations
    });
    drop(runtime);
    drop(observer);
    assert_eq!(observations, vec![true, true]);
}
