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
        self.validate(event);
        let response = Response { id: event.id, value: 0, error: 0, flags: 1 }; // CONTINUE
        assert_eq!(unsafe { libc::ioctl(self.0.as_raw_fd(), 0xc0182101 as libc::c_ulong, &response) }, 0);
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
                assert!(handle_one_frame(0, service, &controller, EncodeInput::YUV(&yuv),
                    index * 250, &mut encoder, &mut recorder, &mut failures, &mut first,
                    64, 48, &mut None).unwrap());
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
        let deadline = Instant::now() + Duration::from_secs(5);
        let held = loop {
            assert!(Instant::now() < deadline, "native recording write was not observed");
            if let Some(event) = observer.receive(50) {
                let path = fs::read_link(format!("/proc/self/fd/{}", event.syscall.args[0])).unwrap();
                observer.validate(&event);
                if path.parent() == Some(dir.0.as_path()) {
                    assert!(path.file_name().unwrap().to_str().unwrap().starts_with("incoming_"));
                    assert!(event.syscall.args[2] > 0);
                    break event;
                }
                observer.resume(&event);
            }
        };
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
