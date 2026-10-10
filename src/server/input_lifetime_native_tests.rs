use super::*;
use crate::input::{MOUSE_BUTTON_LEFT, MOUSE_TYPE_DOWN};
use hbb_common::libloading::Library;
use std::os::unix::fs::OpenOptionsExt;

struct Worker {
    queue: InputQueue,
    join: Option<std::thread::JoinHandle<()>>,
    _responses: ControlEgressReceiver,
}

impl Worker {
    fn new(id: i32) -> Self {
        let (sender, receiver) = std_mpsc::sync_channel(INPUT_QUEUE_CAPACITY);
        let execution = Arc::new(InputExecutionGate::default());
        let queue = InputQueue {
            sender,
            queued_bytes: Arc::new(AtomicUsize::new(0)),
            execution: Arc::clone(&execution),
        };
        let (tx, responses) = control_egress_channel();
        let join = std::thread::Builder::new()
            .name(format!("input-lifetime-native-{id}"))
            .spawn(move || Connection::handle_input(id, receiver, tx, execution))
            .unwrap();
        Self { queue, join: Some(join), _responses: responses }
    }

    fn enqueue(&self, input: MessageInput) {
        try_enqueue_input(&self.queue, input).unwrap();
        let start = std::time::Instant::now();
        while self.queue.queued_bytes.load(Ordering::Acquire) != 0 {
            assert!(start.elapsed() < std::time::Duration::from_secs(3), "input queue did not drain");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    fn join(&mut self) {
        let join = self.join.take().unwrap();
        let start = std::time::Instant::now();
        let mut expired = false;
        while !join.is_finished() {
            if start.elapsed() >= std::time::Duration::from_secs(3) {
                expired = true;
                self.queue.execution.cancel();
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        join.join().unwrap();
        assert!(!expired, "input worker exceeded its initiating deadline");
        assert_eq!(self.queue.queued_bytes.load(Ordering::Acquire), 0);
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.queue.execution.cancel();
        if let Some(join) = self.join.take() {
            // The enclosing isolated process has its own initiating timeout.
            // Keep this exact handle through cleanup even during an assertion unwind.
            assert!(join.join().is_ok(), "input worker unwound");
        }
    }
}

fn key_a() -> MessageInput {
    let mut event = KeyEvent::new();
    event.mode = KeyboardMode::Map.into();
    event.set_chr(rdev::linux_keycode_from_key(rdev::Key::KeyA).unwrap());
    event.down = true;
    MessageInput::Key((event, false))
}

fn button(id: i32) -> MessageInput {
    let mut event = MouseEvent::new();
    event.mask = MOUSE_TYPE_DOWN | (MOUSE_BUTTON_LEFT << 3);
    MessageInput::Mouse(InputMouse {
        msg: event, conn_id: id, username: String::new(), argb: 0,
        simulate: true, show_cursor: false,
    })
}

fn resources(path: &str) -> usize {
    std::fs::read_dir(path).unwrap().count()
}

#[test]
#[ignore = "requires the isolated protected-provider input-lifetime profile"]
fn input_workers_retire_pending_text_before_the_global_display() {
    assert_eq!(std::env::var("DISPLAY").unwrap(), ":97");
    let fault = std::env::var("INPUT_LIFETIME_FAULT").unwrap();
    assert!(fault == "map" || fault == "key");
    // Only observation/fault hooks come from this handle. Production input opens
    // the same fixed protected provider through the ordinary libxdo-sys loader.
    let provider = unsafe { Library::new("/usr/lib/rustdesk-fork/libxdo.so.3").unwrap() };
    let begin = unsafe { *provider.get::<unsafe extern "C" fn(i32)>(b"input_lifetime_begin").unwrap() };
    let observe = unsafe { *provider.get::<unsafe extern "C" fn(i32) -> u32>(b"input_lifetime_observe").unwrap() };
    let foreign = unsafe { *provider.get::<unsafe extern "C" fn()>(b"input_lifetime_foreign").unwrap() };
    let allow = unsafe { *provider.get::<unsafe extern "C" fn()>(b"input_lifetime_allow_retirement").unwrap() };
    let finish = unsafe { *provider.get::<unsafe extern "C" fn()>(b"input_lifetime_finish").unwrap() };
    let baseline_fds = resources("/proc/self/fd");
    let baseline_tasks = resources("/proc/self/task");
    for generation in 0..16 {
        unsafe { begin(i32::from(fault == "key")); }
        let outcome = std::panic::catch_unwind(|| {
            let mut first = Worker::new(9001);
            let mut second = Worker::new(9002);
            first.enqueue(key_a());
            assert_eq!(unsafe { observe(0) }, 1);
            first.enqueue(button(9001));
            assert_eq!(unsafe { observe(1) }, 1);
            second.enqueue(key_a());
            second.enqueue(button(9002));
            assert_eq!(unsafe { observe(2) }, 1);
            let mut text = KeyEvent::new();
            text.mode = KeyboardMode::Legacy.into();
            text.set_seq("🙂".into());
            text.down = true;
            first.enqueue(MessageInput::Key((text, false)));
            // This worker returns because real text dispatch reports cleanup
            // uncertainty. Its actual Drop must retain the other worker's keys.
            first.join();
            assert_eq!(unsafe { observe(3) }, 1);
            assert!(!second.join.as_ref().unwrap().is_finished());
            unsafe { foreign(); allow(); }
            second.queue.execution.cancel();
            assert!(try_enqueue_input(&second.queue, key_a()).is_err());
            second.join();
            assert!(INPUT_KEY_OWNERS.lock().is_empty());
            assert!(INPUT_KEY_OWNERS.lock_mouse_buttons().is_empty());
            let native = unsafe { observe(4) };
            let fds = resources("/proc/self/fd");
            let tasks = resources("/proc/self/task");
            println!("INPUT_LIFETIME_OBSERVED fault={fault} generation={generation} native={native:#x} fd_delta={} task_delta={}",
                fds as isize - baseline_fds as isize - 1,
                tasks as isize - baseline_tasks as isize);
            (native, fds, tasks)
        });
        // Restore only this fixture's private X server state, including on the
        // before failure. Never free a retained native context behind its Rust owner.
        unsafe { finish(); }
        let (native, fds, tasks) = outcome.unwrap();
        assert_eq!(native, 15, "native global input retirement is incomplete");
        assert_eq!(fds, baseline_fds + 1, "Display descriptor was retained");
        assert_eq!(tasks, baseline_tasks, "input worker was retained");
        assert_eq!(resources("/proc/self/fd"), baseline_fds);
    }
    use std::io::Write;
    let mut receipt = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(format!("/tmp/input-lifetime-{fault}.receipt")).unwrap();
    writeln!(receipt, "INPUT_LIFETIME_NATIVE=pass fault={fault} generations=16 workers=2 producer=typed-queue worker=production loader=protected keys=exact-owner foreign=preserved pending=retired mapping=restored child_before_display=true descriptors=retired tasks=retired network_auth=false").unwrap();
}
