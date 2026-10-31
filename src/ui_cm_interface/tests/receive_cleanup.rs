use super::*;
use hbb_common::libc;
use std::{
    os::{fd::{AsRawFd, FromRawFd}, unix::fs::MetadataExt},
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

// Linux x86_64 timing observer: continue the original fsync, without changing
// its arguments or result. The observer starts before the per-thread filter.
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
    owner: CmClientOwner,
    ui: CmTaskOwnerTestUi,
    held: oneshot::Sender<(u32, HeldOwnership)>,
    release: std_mpsc::Receiver<()>,
    finished: oneshot::Sender<bool>,
}

#[derive(Debug)]
struct HeldOwnership {
    current: bool,
    in_flight: bool,
    capacity: bool,
    ui_pending: bool,
    admission_refused: bool,
}

impl HeldOwnership {
    fn observe(owner: CmClientOwner, ui: &CmTaskOwnerTestUi) -> Self {
        let mut registry = CLIENTS.write().unwrap();
        let current = registry.clients.get(&owner.id).map(|client|
            client.registry_generation == owner.generation && !client.disconnected).unwrap_or(false);
        let in_flight = registry.in_flight_file_operations.get(&owner.id) == Some(&owner.generation);
        let mut successor = registry_test_client(owner.id, "same-peer");
        // Try a newer source too: an unfinished cleanup must exclude replacement.
        // Roll back an unexpectedly accepted reservation without publishing it.
        let admission_refused = match registry.prepare_admission(&mut successor, 1) {
            Err(CmClientAdmissionError::FileOperationInFlight) => true,
            Ok(reservation) => { registry.abort_admission(reservation); false }
            Err(_) => false,
        };
        drop(registry);
        Self { current, in_flight, admission_refused,
            capacity: CM_FILE_OPERATION_LIMIT.available_permits() == CM_FILE_OPERATION_DRAIN_CAPACITY - 1,
            ui_pending: lock_cm_egress_test(&ui.removed).is_empty() }
    }

    fn retained(&self) -> bool {
        self.current && self.in_flight && self.capacity && self.ui_pending && self.admission_refused
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Exit { Cancel, CancelAbandoned, Close, Disconnected, Eof, Abort }

struct Observer {
    commands: std_mpsc::SyncSender<(Gate, oneshot::Sender<()>)>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Observer {
    fn new() -> Self {
        let (commands, receiver) = std_mpsc::sync_channel::<(Gate, oneshot::Sender<()>)>(1);
        let (send_fd, receive_fd) = std_mpsc::sync_channel::<fs::File>(1);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
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
                if ready < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted { continue; }
                assert!(ready >= 0);
                if ready == 0 { continue; }
                let mut notification = Notification::default();
                assert_eq!(unsafe { libc::ioctl(fd.as_raw_fd(), 0xc050_2100u64, &mut notification) }, 0);
                assert_eq!((notification.data.nr, notification.data.arch), (libc::SYS_fsync as i32, 0xc000_003e));
                let mut report = None;
                if let Some(active) = &gate {
                    let meta = fs::metadata(format!("/proc/thread-self/fd/{}", notification.data.args[0])).unwrap();
                    if (meta.dev(), meta.ino()) == active.identity {
                        let active = gate.take().unwrap();
                        // Observe before releasing fsync even if the runtime is blocked.
                        let ownership = HeldOwnership::observe(active.owner, &active.ui);
                        let _ = active.held.send((notification.pid, ownership));
                        // Release a stalled baseline without depending on its executor.
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
            stmt(0x20, 4),
            libc::sock_filter { code: 0x15, jt: 1, jf: 0, k: 0xc000_003e },
            stmt(0x06, 0x8000_0000),
            stmt(0x20, 0),
            libc::sock_filter { code: 0x15, jt: 0, jf: 1, k: libc::SYS_fsync as u32 },
            stmt(0x06, 0x7fc0_0000),
            stmt(0x06, 0x7fff_0000),
        ];
        let program = libc::sock_fprog { len: filters.len() as u16, filter: filters.as_mut_ptr() };
        let ready = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        let fd = if ready == 0 { unsafe { libc::syscall(libc::SYS_seccomp, 1, 8, &program) } } else { -1 };
        if fd < 0 {
            let error = io::Error::last_os_error();
            drop(send_fd);
            thread.join().unwrap();
            panic!("cannot observe native fsync: {error}");
        }
        send_fd.send(unsafe { fs::File::from_raw_fd(fd as i32) }).unwrap();
        Self { commands, stop, thread: Some(thread) }
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() { thread.join().unwrap(); }
    }
}

async fn command(peer: &mut ipc::ConnectionTmpl<tokio::net::UnixStream>, fs: ipc::FS) {
    peer.send(&Data::AuthorizedFS { cm_auth_token: "test-token".to_owned(), fs }).await.unwrap();
}

async fn reply(peer: &mut ipc::ConnectionTmpl<tokio::net::UnixStream>, id: i32) -> ipc::CmFileResponseKind {
    let data = tokio::time::timeout(Duration::from_secs(2), peer.next()).await.unwrap().unwrap().unwrap();
    let Data::CmFileResponse(envelope) = data else { panic!("expected typed CM reply: {data:?}"); };
    assert_eq!(envelope.conn_id, id);
    assert_eq!(envelope.cm_auth_token, "test-token");
    *envelope.response
}

async fn listing(peer: &mut ipc::ConnectionTmpl<tokio::net::UnixStream>, id: i32, path: &std::path::Path) {
    command(peer, ipc::FS::ReadDir { dir: get_string(path), include_hidden: true, request_id: 901 }).await;
    let response = reply(peer, id).await;
    assert!(matches!(response,
        ipc::CmFileResponseKind::ReadDirectory { request_id: 901, result: Ok(_), .. }),
        "expected successful directory response, received {response:?}");
}

#[test]
fn stalled_retirement_retains_owner_and_keeps_other_connection_responsive() {
    cm_file_operation_reaper().unwrap();
    let observer = Observer::new();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let main_tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
    let observations = runtime.block_on(async {
        let mut observations = Vec::new();
        for (offset, exit) in [Exit::Cancel, Exit::CancelAbandoned, Exit::Close,
            Exit::Disconnected, Exit::Eof, Exit::Abort].into_iter().enumerate() {
            let abandon = exit == Exit::CancelAbandoned;
            let cancel = matches!(exit, Exit::Cancel | Exit::CancelAbandoned);
            let id = 2_000_200_030 + offset as i32;
            let temp = CmFileTestDir::new("native_receive_cleanup");
            fs::write(temp.join("incoming"), b"original").unwrap();
            let (mut task, mut peer, socket, ui) = admitted_cm_native_output_test(id).await;
            let generation = CLIENTS.read().unwrap().clients[&id].registry_generation;
            let (mut other_task, mut other_peer, _other_socket, other_ui) = admitted_cm_native_output_test(id + 10).await;
            command(&mut peer, ipc::FS::NewWrite { path: get_string(&temp.path), id: 17,
                file_num: 0, files: vec![ipc::CmReceiveFile { name: "incoming".to_owned(), size: 8, modified_time: 19 }],
                overwrite_detection: false, total_size: 8, conn_id: id, generation: 4 }).await;
            command(&mut peer, ipc::FS::WriteBlock { id: 17, file_num: 0, conn_id: id,
                data: bytes::Bytes::new(), compressed: false, generation: 4 }).await;
            peer.send_raw(bytes::Bytes::from_static(b"abc")).await.unwrap();
            listing(&mut peer, id, &temp.path).await;
            let namespaces: Vec<_> = fs::read_dir(&temp.path).unwrap().map(|e| e.unwrap().path())
                .filter(|p| p.is_dir()).collect();
            assert_eq!(namespaces.len(), 1);
            let artifacts: Vec<_> = fs::read_dir(&namespaces[0]).unwrap().map(|e| e.unwrap().path())
                .filter(|p| p.is_dir()).collect();
            assert_eq!(artifacts.len(), 1);
            assert_eq!(fs::read(artifacts[0].join("payload.download")).unwrap(), b"abc");
            let meta = fs::metadata(&artifacts[0]).unwrap();
            let (armed, ready) = oneshot::channel();
            let (held, notification) = oneshot::channel();
            let (release, released) = std_mpsc::sync_channel(1);
            let (finished, continued) = oneshot::channel();
            observer.commands.send((Gate { identity: (meta.dev(), meta.ino()), held,
                owner: CmClientOwner { id, generation }, ui: ui.clone(),
                release: released, finished }, armed)).unwrap();
            ready.await.unwrap();
            let started = Instant::now();
            match exit {
                Exit::Cancel | Exit::CancelAbandoned =>
                    command(&mut peer, ipc::FS::CancelWrite { id: 17, conn_id: id, generation: 4 }).await,
                Exit::Close => peer.send(&Data::Close).await.unwrap(),
                Exit::Disconnected => peer.send(&Data::Disconnected).await.unwrap(),
                Exit::Eof => socket.shutdown(std::net::Shutdown::Both).unwrap(),
                Exit::Abort => task.abort(),
            }
            let (tid, ownership) = tokio::time::timeout(Duration::from_secs(4), notification).await.unwrap().unwrap();
            let responsive = tid != main_tid && started.elapsed() < Duration::from_secs(1);
            if responsive {
                tokio::time::timeout(Duration::from_secs(1), listing(&mut other_peer, id + 10, &temp.path)).await.unwrap();
                if cancel {
                    assert!(tokio::time::timeout(Duration::from_millis(50), peer.next()).await.is_err(),
                        "cleanup result preceded native retirement");
                } else if exit != Exit::Abort {
                    assert!(!task.is_finished(), "connection returned before native retirement");
                }
            }
            let elapsed = started.elapsed();
            if abandon {
                task.abort();
                assert!((&mut task).await.unwrap_err().is_cancelled());
                if responsive {
                    assert_eq!(CM_FILE_OPERATION_LIMIT.available_permits(), CM_FILE_OPERATION_DRAIN_CAPACITY - 1);
                    assert!(CLIENTS.read().unwrap().in_flight_file_operations.contains_key(&id));
                    assert!(lock_cm_egress_test(&ui.removed).is_empty());
                }
            }
            let _ = release.send(());
            let explicit = continued.await.unwrap();
            if exit == Exit::Cancel {
                assert!(matches!(reply(&mut peer, id).await,
                    ipc::CmFileResponseKind::WriteCancelled { id: 17, generation: 4, file_num: 0, result: Ok(()) }));
                peer.send(&Data::Close).await.unwrap();
                tokio::time::timeout(Duration::from_secs(3), &mut task).await.unwrap().unwrap();
            } else if exit == Exit::Abort {
                assert!(tokio::time::timeout(Duration::from_secs(3), &mut task).await.unwrap().unwrap_err().is_cancelled());
            } else if !abandon {
                tokio::time::timeout(Duration::from_secs(3), &mut task).await.unwrap().unwrap();
            }
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let registry = CLIENTS.read().unwrap();
                    let retired = registry.clients.get(&id).map(|client|
                        exit == Exit::Disconnected && client.disconnected && client.registry_generation == generation).unwrap_or(true);
                    if retired && !registry.in_flight_file_operations.contains_key(&id)
                        && CM_FILE_OPERATION_LIMIT.available_permits() == CM_FILE_OPERATION_DRAIN_CAPACITY { break; }
                    drop(registry);
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }).await.unwrap();
            assert_eq!(*lock_cm_egress_test(&ui.removed), vec![(id, generation, exit != Exit::Disconnected)]);
            assert_eq!(fs::read(temp.join("incoming")).unwrap(), b"original");
            assert!(!namespaces[0].exists());
            listing(&mut other_peer, id + 10, &temp.path).await;
            other_peer.send(&Data::Close).await.unwrap();
            tokio::time::timeout(Duration::from_secs(3), &mut other_task).await.unwrap().unwrap();
            assert_eq!(lock_cm_egress_test(&other_ui.removed).len(), 1);
            if exit == Exit::Disconnected {
                let registry = CLIENTS.read().unwrap();
                let retired = registry.clients.get(&id).unwrap();
                assert!(retired.disconnected);
                assert_eq!(retired.registry_generation, generation);
            }
            let (mut successor, mut successor_peer, _socket, successor_ui) = admitted_cm_native_output_test(id).await;
            assert!(CLIENTS.read().unwrap().clients[&id].registry_generation > generation);
            listing(&mut successor_peer, id, &temp.path).await;
            successor_peer.send(&Data::Close).await.unwrap();
            tokio::time::timeout(Duration::from_secs(3), &mut successor).await.unwrap().unwrap();
            assert_eq!(lock_cm_egress_test(&successor_ui.removed).len(), 1);
            println!("CM_RECEIVE_SYNC=observed exit={exit:?} responsive={responsive} held_us={} explicit_release={explicit} held_owner={ownership:?} owner=retired permits=returned original=preserved staging=absent successor=usable", elapsed.as_micros());
            observations.push(responsive && explicit && ownership.retained());
        }
        observations
    });
    drop(runtime);
    drop(observer);
    assert_eq!(observations, vec![true; 6]);
}
