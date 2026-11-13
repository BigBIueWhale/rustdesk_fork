use super::*;
use std::{
    mem::size_of,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

#[repr(C)]
#[derive(Default)]
struct Syscall {
    number: i32,
    arch: u32,
    instruction: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Default)]
struct Notification {
    id: u64,
    tid: u32,
    flags: u32,
    syscall: Syscall,
}

#[repr(C)]
struct Response {
    id: u64,
    value: i64,
    error: i32,
    flags: u32,
}

struct WriteObserver(OwnedFd);

impl WriteObserver {
    // Only the disposable test's capture thread and its future children inherit
    // this filter. The observing test thread remains outside it. This delays
    // actual file syscalls; it is not an authorization policy or a product hook.
    fn install() -> Self {
        let mut sizes = [0u16; 3];
        assert_eq!(unsafe { libc::syscall(libc::SYS_seccomp, 3, 0, sizes.as_mut_ptr()) }, 0);
        assert_eq!(sizes, [size_of::<Notification>() as u16,
            size_of::<Response>() as u16, size_of::<Syscall>() as u16]);
        let instruction = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
        let mut filter = [
            instruction(0x20, 0, 0, 4), // seccomp_data.arch
            instruction(0x15, 1, 0, 0xc000003e), // AUDIT_ARCH_X86_64
            instruction(0x06, 0, 0, 0x80000000), // KILL_PROCESS on wrong architecture
            instruction(0x20, 0, 0, 0), // seccomp_data.nr
            instruction(0x15, 0, 3, libc::SYS_write as u32),
            instruction(0x20, 0, 0, 16), // first syscall argument: fd
            instruction(0x35, 0, 1, 3), // preserve standard streams
            instruction(0x06, 0, 0, 0x7fc00000), // USER_NOTIF
            instruction(0x06, 0, 0, 0x7fff0000), // ALLOW
        ];
        let program = libc::sock_fprog { len: filter.len() as u16, filter: filter.as_mut_ptr() };
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }, 0);
        let fd = unsafe { libc::syscall(libc::SYS_seccomp, 1, 8, &program) };
        assert!(fd >= 0, "install notification filter: {}", std::io::Error::last_os_error());
        Self(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }

    fn receive(&self, timeout_ms: i32) -> Option<Notification> {
        let mut poll = libc::pollfd { fd: self.0.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let ready = unsafe { libc::poll(&mut poll, 1, timeout_ms) };
        assert!(ready >= 0, "poll: {}", std::io::Error::last_os_error());
        if ready == 0 { return None; }
        if poll.revents == libc::POLLHUP { return None; }
        assert_ne!(poll.revents & libc::POLLIN, 0);
        let mut event = Notification::default();
        assert_eq!(unsafe { libc::ioctl(self.0.as_raw_fd(), 0xc0502100 as libc::c_ulong, &mut event) }, 0);
        assert_eq!(event.syscall.number, libc::SYS_write as i32);
        assert_eq!(event.syscall.arch, 0xc000003e);
        self.validate(&event);
        Some(event)
    }

    fn validate(&self, event: &Notification) {
        assert_eq!(unsafe { libc::ioctl(self.0.as_raw_fd(), 0x40082102 as libc::c_ulong, &event.id) }, 0);
    }

    fn resume(&self, event: &Notification) {
        self.respond(event, 0);
    }

    fn respond(&self, event: &Notification, error: i32) {
        self.validate(event);
        assert!(error >= 0);
        let response = Response {
            id: event.id, value: 0, error: -error,
            flags: if error == 0 { 1 } else { 0 }, // CONTINUE or injected errno
        };
        assert_eq!(unsafe { libc::ioctl(self.0.as_raw_fd(), 0xc0182101 as libc::c_ulong, &response) }, 0);
    }

    fn recording_write(&self, dir: &RecordingDirectory) -> Notification {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(Instant::now() < deadline, "native recording write was not observed");
            if let Some(event) = self.receive(20) {
                let path = fs::read_link(format!("/proc/self/fd/{}", event.syscall.args[0])).unwrap();
                self.validate(&event);
                if path.parent() == Some(dir.0.as_path()) {
                    assert!(path.file_name().unwrap().to_str().unwrap().starts_with("incoming_"));
                    assert!(event.syscall.args[2] > 0);
                    return event;
                }
                self.resume(&event);
            }
        }
    }

    fn drive_until(&self, mut complete: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !complete() {
            assert!(Instant::now() < deadline, "recording did not drain after release");
            if let Some(event) = self.receive(20) { self.resume(&event); }
        }
    }
}

struct WorkerGroup {
    producers: Vec<IncomingRecording>,
    shutdown: Option<mpsc::Sender<()>>,
    done: mpsc::Receiver<()>,
}

impl WorkerGroup {
    fn close(&mut self) {
        self.producers.clear();
        self.shutdown.take();
    }
}

fn with_workers(dir: &RecordingDirectory, count: usize, test: impl FnOnce(&WriteObserver, &mut WorkerGroup)) {
    thread::scope(|scope| {
        let (ready_tx, ready_rx) = mpsc::channel();
        let (shutdown, stop) = mpsc::channel::<()>();
        let (done_tx, done) = mpsc::channel();
        let owner = scope.spawn(move || {
            let observer = WriteObserver::install();
            let mut workers = RecordingWorkers::default();
            let producers: Vec<_> = (0..count).map(|display_idx| workers.start(RecorderContext {
                server: true, id: "worker-boundary".into(), dir: dir.0.to_str().unwrap().into(),
                display_idx, camera: false,
            }).unwrap()).collect();
            ready_tx.send((producers, observer)).unwrap();
            let _ = stop.recv();
            drop(workers);
            let _ = done_tx.send(());
        });
        let (producers, observer) = ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut group = WorkerGroup { producers, shutdown: Some(shutdown), done };
        // The observer closes on unwind before scope joins the owner, releasing
        // intercepted writes with ENOSYS. Dropping shutdown also wakes the owner.
        test(&observer, &mut group);
        group.close();
        observer.drive_until(|| match group.done.try_recv() {
            Ok(()) => true,
            Err(mpsc::TryRecvError::Empty) => false,
            Err(error) => panic!("recording owner failed: {error}"),
        });
        owner.join().unwrap();
        assert_eq!(crate::server::incoming_recording::retained_resources(), (0, 0));
        assert_eq!(snapshot().writers(), 0);
    });
}

#[test]
fn blocked_writers_share_and_release_the_byte_budget() {
    use crate::server::incoming_recording::retained_resources;
    use scrap::codec::MAX_NATIVE_VIDEO_BATCH_BYTES;
    let dir = RecordingDirectory::new();
    let mut encoder = encoder();
    let yuv = vec![128; encoder.yuvfmt().buffer_len];
    let native = encoder.encode_to_message(EncodeInput::YUV(&yuv), 0).unwrap().unwrap().union.unwrap();
    let video_frame::Union::Vp8s(batch) = &native else { panic!("native VP8 output"); };
    assert_eq!(batch.frames.len(), 1);
    let payload = batch.frames[0].data.clone();
    let budget = 2 * MAX_NATIVE_VIDEO_BATCH_BYTES;
    with_workers(&dir, 3, |observer, group| {
        for producer in &mut group.producers[..2] { producer.enqueue_frame(&native, 64, 48).unwrap(); }
        let held = [observer.recording_write(&dir), observer.recording_write(&dir)];
        assert_ne!(held[0].tid, held[1].tid, "two independently blocked workers");
        assert_eq!(retained_resources(), (3, 2 * payload.len()));
        // These synthetic payloads test admission/accounting only. The held
        // real writes fail below, so these bytes never enter the native muxer.
        for producer in &mut group.producers[..2] {
            let mut fill = native.clone();
            let video_frame::Union::Vp8s(batch) = &mut fill else { unreachable!(); };
            batch.frames[0].data = vec![0x7f; MAX_NATIVE_VIDEO_BATCH_BYTES - payload.len()].into();
            producer.enqueue_frame(&fill, 64, 48).unwrap();
        }
        assert_eq!(retained_resources(), (3, budget));
        assert!(group.producers[2].enqueue_frame(&native, 64, 48).is_err(),
            "another writer cannot borrow capacity beyond the process budget");
        assert_eq!(retained_resources(), (3, budget), "refusal cannot consume credits");
        assert_eq!(snapshot().last_failure, Some(RecordingFailure {
            display: 2, camera: false, stage: FailureStage::Write,
        }));
        for event in &held { observer.respond(event, libc::EIO); }
    });
    let files: Vec<_> = fs::read_dir(&dir.0).unwrap().map(|entry| entry.unwrap().path()).collect();
    assert_eq!(files.len(), 2);
    assert!(files.iter().all(|path| fs::metadata(path).unwrap().len() == 0));
    // Recovered credits admit a genuinely encoded frame and finalized output.
    let history = snapshot().last_failure;
    let mut workers = RecordingWorkers::default();
    let mut retry = dir.recorder(&mut workers);
    retry.enqueue_frame(&native, 64, 48).unwrap();
    wait_status(|status| status.active == 1);
    drop(retry);
    drop(workers);
    assert_eq!(retained_resources(), (0, 0));
    assert_eq!(snapshot().writers(), 0);
    assert_eq!(snapshot().last_failure, history);
    let outputs: Vec<_> = fs::read_dir(&dir.0).unwrap().map(|entry| entry.unwrap().path())
        .filter(|path| !files.contains(path)).collect();
    assert_eq!(outputs.len(), 1);
    let bytes = fs::read(&outputs[0]).unwrap();
    assert!(bytes.starts_with(&[0x1a, 0x45, 0xdf, 0xa3]));
    assert!(bytes.windows(payload.len()).any(|part| part == payload.as_ref()));
}

#[test]
fn blocked_finalization_retains_status_and_join_ownership() {
    use crate::server::incoming_recording::retained_resources;
    for fail in [false, true] {
        let dir = RecordingDirectory::new();
        let mut encoder = encoder();
        let yuv = vec![128; encoder.yuvfmt().buffer_len];
        let frame = encoder.encode_to_message(EncodeInput::YUV(&yuv), 0).unwrap().unwrap();
        let history = snapshot().last_failure;
        let mut before = Vec::new();
        with_workers(&dir, 1, |observer, group| {
            group.producers[0].enqueue_frame(frame.union.as_ref().unwrap(), 64, 48).unwrap();
            observer.drive_until(|| snapshot().active == 1 && retained_resources().1 == 0);
            let files: Vec<_> = fs::read_dir(&dir.0).unwrap().map(|entry| entry.unwrap().path()).collect();
            assert_eq!(files.len(), 1);
            before = fs::read(&files[0]).unwrap();
            // All admitted frames have completed before closing. The next file
            // write can therefore only belong to actual native finalization.
            group.close();
            let held = observer.recording_write(&dir);
            assert!(matches!(group.done.recv_timeout(Duration::from_millis(100)),
                Err(mpsc::RecvTimeoutError::Timeout)), "owner must wait for native finalization");
            observer.validate(&held);
            assert_eq!((snapshot().starting, snapshot().active, snapshot().finishing), (0, 0, 1));
            assert_eq!(snapshot().last_failure, history);
            assert_eq!(retained_resources(), (1, 0), "worker slot outlives its final frame");
            assert_eq!(fs::read(&files[0]).unwrap(), before);
            observer.respond(&held, if fail { libc::EIO } else { 0 });
        });
        let path = fs::read_dir(&dir.0).unwrap().next().unwrap().unwrap().path();
        if fail {
            assert_eq!(snapshot().last_failure.unwrap().stage, FailureStage::Finish);
            assert_eq!(fs::read(path).unwrap(), before, "failed finalization cannot rewrite bytes");
        } else {
            assert_eq!(snapshot().last_failure, history);
            assert_ne!(fs::read(path).unwrap(), before, "released finalization must reach the file");
        }
    }
}

#[test]
fn blocked_recording_write_preserves_capture_progress() {
    assert_ne!(unsafe { libc::geteuid() }, 0, "ordinary isolated principal");
    let dir = RecordingDirectory::new();
    let service = GenericService::new("incoming-blocked-write".into(), false);
    let (sender, mut receiver) = video_egress_channel();
    service.on_subscribe(ConnInner::new(72, None, Some(sender)));
    let mut decoder = Decoder::new(CodecFormat::VP8, None);
    let mut rgb = ImageRgb::new(ImageFormat::ABGR, crate::get_dst_align_rgba());
    let mut texture = ImageTexture::default();
    thread::scope(|scope| {
        let (observer_tx, observer_rx) = mpsc::channel();
        let (advance_tx, advance_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let service = &service;
        let dir = &dir;
        let capture = scope.spawn(move || {
            let mut encoder = encoder();
            let observer = WriteObserver::install();
            observer_tx.send(observer).unwrap();
            let mut workers = RecordingWorkers::default();
            let mut recorder = Some(dir.recorder(&mut workers));
            let controller = VideoFrameController::new(VideoSource::Monitor, 0).unwrap();
            let mut first = true;
            let mut failures = 0;
            let mut retired_at = None;
            for index in 0..12 {
                let format = encoder.yuvfmt();
                let mut yuv = vec![128; format.buffer_len];
                for row in 0..48 {
                    yuv[row * format.stride[0]..row * format.stride[0] + 64]
                        .fill(30 + index as u8 * 15);
                }
                controller.reset();
                assert_eq!(handle_one_frame(0, service, &controller, EncodeInput::YUV(&yuv),
                    index * 250, &mut encoder, &mut recorder, &mut failures, &mut first,
                    64, 48, &mut None).unwrap(), ControlFlow::Continue(true));
                if recorder.is_none() && retired_at.is_none() { retired_at = Some(index); }
                if index < 11 && !advance_rx.recv().unwrap_or(false) { break; }
            }
            drop(recorder);
            drop(workers);
            done_tx.send(retired_at).unwrap();
        });
        // Closing this descriptor during unwinding releases intercepted writes
        // with ENOSYS before the scoped capture thread is joined.
        let observer = observer_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let held = observer.recording_write(&dir);
        let held_at = Instant::now();
        let mut samples = Vec::new();
        while samples.len() < 12 && held_at.elapsed() < Duration::from_secs(1) {
            if let Some(VideoEgressItem::Frame(frame)) = receiver.try_recv() {
                assert_eq!(frame.test_wire_generation(), Some(samples.len() as u64 + 1));
                let Some(message::Union::VideoFrame(video)) = &frame.test_message().union else {
                    panic!("native encoded video");
                };
                assert!(decoder.handle_video_frame(video.union.as_ref().unwrap(), &mut rgb,
                    &mut texture, &mut true, &mut None).unwrap());
                samples.push(rgb.raw.clone());
                if samples.len() < 12 { advance_tx.send(true).unwrap(); }
            } else {
                thread::sleep(Duration::from_millis(2));
            }
        }
        observer.validate(&held);
        let pending = matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty));
        let stalled = snapshot();
        let retained = crate::server::incoming_recording::retained_resources();
        let held_ms = held_at.elapsed().as_millis();
        // Always release the syscall and join before asserting the behavioral
        // result, including when testing the synchronous baseline.
        let _ = advance_tx.send(false);
        observer.resume(&held);
        let deadline = Instant::now() + Duration::from_secs(5);
        let retired_at = loop {
            match done_rx.try_recv() {
                Ok(retired_at) => break retired_at,
                Err(mpsc::TryRecvError::Empty) => {},
                Err(error) => panic!("capture worker failed: {error}"),
            }
            assert!(Instant::now() < deadline, "recording did not drain after release");
            if let Some(event) = observer.receive(20) { observer.resume(&event); }
        };
        capture.join().unwrap();
        assert_eq!(snapshot().writers(), 0);
        println!("INCOMING_BLOCKED_WRITE frames={} held_ms={held_ms} completion_pending={pending} syscall=write cleanup=joined",
            samples.len());
        assert!(pending, "completion cannot precede the held recording write");
        assert_eq!(samples.len(), 12, "recording I/O must not stall capture publication");
        assert!(samples.windows(2).all(|pair| pair[0] != pair[1]));
        assert_eq!(retired_at, Some(9), "one in-flight plus eight queued batches");
        assert_eq!((stalled.starting, stalled.active, stalled.finishing), (0, 0, 1));
        assert_eq!(stalled.last_failure.unwrap().stage, FailureStage::Write);
        assert_eq!(retained.0, 1, "retain worker ownership through blocked I/O");
        assert!(retained.1 > 0 && retained.1 <= 2 * scrap::codec::MAX_NATIVE_VIDEO_BATCH_BYTES);
        assert_eq!(crate::server::incoming_recording::retained_resources(), (0, 0));
    });
    service.on_unsubscribe(72);
}
