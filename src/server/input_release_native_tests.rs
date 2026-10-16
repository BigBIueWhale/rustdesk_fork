use super::*;
use hbb_common::x11::xlib;
use rdev::{EventType, Key as RdevKey};

struct Observer {
    display: *mut xlib::Display,
    window: xlib::Window,
    previous_focus: xlib::Window,
    previous_revert: i32,
}

impl Observer {
    fn new() -> Self {
        unsafe {
            let display = xlib::XOpenDisplay(std::ptr::null());
            assert!(!display.is_null());
            let mut previous_focus = 0;
            let mut previous_revert = 0;
            xlib::XGetInputFocus(display, &mut previous_focus, &mut previous_revert);
            let window = xlib::XCreateSimpleWindow(
                display, xlib::XDefaultRootWindow(display), 0, 0, 100, 100, 0, 0, 0,
            );
            assert_ne!(window, 0);
            xlib::XSelectInput(display, window, xlib::KeyPressMask | xlib::KeyReleaseMask);
            xlib::XMapWindow(display, window);
            xlib::XSetInputFocus(display, window, xlib::RevertToPointerRoot, xlib::CurrentTime);
            xlib::XSync(display, 0);
            Self { display, window, previous_focus, previous_revert }
        }
    }

    fn keys(&self, expected: &[u32]) -> bool {
        let mut actual = [0i8; 32];
        let mut wanted = [0i8; 32];
        for code in expected {
            wanted[*code as usize / 8] |= (1u8 << (*code % 8)) as i8;
        }
        unsafe { xlib::XQueryKeymap(self.display, actual.as_mut_ptr()) != 0 && actual == wanted }
    }

    fn events(&self) -> Vec<(i32, u32)> {
        let mut events = Vec::new();
        unsafe {
            xlib::XSync(self.display, 0);
            let mut event: xlib::XEvent = std::mem::zeroed();
            while xlib::XCheckWindowEvent(
                self.display, self.window, xlib::KeyPressMask | xlib::KeyReleaseMask, &mut event,
            ) != 0 {
                assert_eq!(event.key.window, self.window);
                assert_eq!(event.key.send_event, 0);
                events.push((event.get_type(), event.key.keycode));
            }
        }
        events
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        unsafe {
            xlib::XSetInputFocus(
                self.display, self.previous_focus, self.previous_revert, xlib::CurrentTime,
            );
            xlib::XDestroyWindow(self.display, self.window);
            xlib::XSync(self.display, 0);
            xlib::XCloseDisplay(self.display);
        }
    }
}

fn descriptors() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

#[test]
#[ignore = "requires the owned isolated X11 input-release profile"]
fn physical_lease_retirement_survives_unavailable_keyboard_state() {
    assert_eq!(std::env::var("DISPLAY").unwrap(), ":98");
    assert!(!std::path::Path::new("/usr/lib/rustdesk-fork/libxdo.so.3").exists());
    let baseline = descriptors();
    let observer = Observer::new();
    assert!(observer.keys(&[]));
    let foreign = RdevKey::KeyA;
    let foreign_code = rdev::linux_keycode_from_key(foreign).unwrap();
    let controls = [
        ControlKey::Control, ControlKey::RControl, ControlKey::Shift, ControlKey::RShift,
        ControlKey::Alt, ControlKey::RAlt, ControlKey::Meta, ControlKey::RWin,
    ];
    for map_mode in [false, true] {
        for control in controls {
            let mut event = KeyEvent::new();
            event.set_control_key(control);
            event.down = true;
            let OwnedPhysicalKey::Key(physical) = owned_physical_key(&event).unwrap();
            let code = match physical {
                RdevKey::RawKey(rdev::RawKey::LinuxXorgKeycode(code)) => code,
                _ => rdev::linux_keycode_from_key(physical).unwrap(),
            };
            if map_mode {
                event.mode = KeyboardMode::Map.into();
                event.set_chr(code);
            }
            // The unavailable state collector closes ordinary dispatch. The fixture
            // supplies a real accepted physical press to the production lease registry.
            let refusal = handle_owned_key(&event, &[]).unwrap_err();
            assert!(refusal.to_string().contains("owned input dispatch is unavailable"));
            assert!(observer.keys(&[]) && observer.events().is_empty());
            rdev::simulate(&EventType::KeyPress(foreign)).unwrap();
            assert_eq!(observer.events(), vec![(xlib::KeyPress, foreign_code)]);
            let registry = Arc::new(InputKeyOwnerRegistry::default());
            let mut first = InputKeyOwnership::new(Arc::clone(&registry));
            let mut second = InputKeyOwnership::new(Arc::clone(&registry));
            assert!(first.dispatch(&event, |_, _| {
                rdev::simulate(&EventType::KeyPress(physical)).unwrap();
                Ok(())
            }).unwrap());
            assert!(!second.dispatch(&event, |_, _| panic!("duplicate owner emitted input")).unwrap());
            assert_eq!(observer.events(), vec![(xlib::KeyPress, code)]);
            assert!(observer.keys(&[foreign_code, code]));
            assert!(first.release_remaining().is_ok());
            assert!(first.held.is_empty());
            assert!(observer.keys(&[foreign_code, code]) && observer.events().is_empty());
            let released = second.release_remaining();
            let observed = observer.events();
            let finality = released.is_ok() && observed == [(xlib::KeyRelease, code)]
                && observer.keys(&[foreign_code]) && second.held.is_empty()
                && registry.lock().is_empty();
            // Retire only fixture-introduced keys before reporting a product failure.
            rdev::simulate(&EventType::KeyRelease(physical)).unwrap();
            rdev::simulate(&EventType::KeyRelease(foreign)).unwrap();
            observer.events();
            assert!(observer.keys(&[]));
            assert!(finality, "physical lease retirement failed: result={released:?}, events={observed:?}");
            assert_eq!(descriptors(), baseline + 1);
        }
    }
    drop(observer);
    assert_eq!(descriptors(), baseline);
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut receipt = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open("/tmp/input-release-native.receipt").unwrap();
    receipt.write_all(b"INPUT_RELEASE_NATIVE=pass cases=16 shared_owners=2 prior_owner_retirement=no-events final_owner_release=exact-key foreign_key=preserved keyboard_state=unavailable ordinary_admission=refused registry=retired descriptors=retired whole_app=false\n").unwrap();
}

struct LiveInputWorker {
    queue: InputQueue,
    owner: InputWorker,
    _responses: ControlEgressReceiver,
}

impl LiveInputWorker {
    async fn new(id: i32) -> Self {
        let (sender, receiver) = std_mpsc::sync_channel(INPUT_QUEUE_CAPACITY);
        let execution = Arc::new(InputExecutionGate::default());
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let (join_tx, completion, admission) =
            spawn_input_worker_supervisor(format!("input-revoke-supervisor-{id}"),
                Arc::clone(&queued_bytes)).unwrap();
        let (tx, responses) = control_egress_channel();
        let native_execution = Arc::clone(&execution);
        let join = std::thread::spawn(move || {
            Connection::handle_input(id, receiver, tx, native_execution);
        });
        join_tx.try_send(join).unwrap();
        drop(join_tx);
        drop(admission);
        let worker = Self {
            queue: InputQueue { sender, queued_bytes, execution: Arc::clone(&execution) },
            owner: InputWorker { execution, completion },
            _responses: responses,
        };
        worker.barrier().await;
        worker
    }

    async fn barrier(&self) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        try_enqueue_input(&self.queue, MessageInput::Ready(tx)).unwrap();
        tokio::time::timeout(Duration::from_secs(3), rx).await.unwrap().unwrap();
    }

    async fn hold(&self, key: RdevKey) {
        let mut event = KeyEvent::new();
        event.mode = KeyboardMode::Map.into();
        event.set_chr(rdev::linux_keycode_from_key(key).unwrap());
        event.down = true;
        try_enqueue_input(&self.queue, MessageInput::Key((event, false))).unwrap();
        self.barrier().await;
    }

    async fn stop(&self) {
        self.owner.execution.cancel();
        let completion = Arc::clone(&self.owner.completion);
        assert!(tokio::task::spawn_blocking(move || completion.wait()).await.unwrap());
        assert_eq!(self.queue.queued_bytes.load(Ordering::Acquire), 0);
    }
}

impl Drop for LiveInputWorker {
    fn drop(&mut self) {
        // The production supervisor retains the sole native JoinHandle on unwind.
        self.owner.execution.cancel();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the isolated plain-provider input-revocation profile"]
async fn keyboard_disable_retires_native_ownership_before_return() {
    assert_eq!(std::env::var("DISPLAY").unwrap(), ":96");
    let observer = tokio::task::block_in_place(|| {
        assert_ne!(unsafe { xlib::XInitThreads() }, 0);
        Observer::new()
    });
    let control = RdevKey::ControlLeft;
    let shared = RdevKey::ShiftLeft;
    let foreign = RdevKey::KeyB;
    let control_code = rdev::linux_keycode_from_key(control).unwrap();
    let shared_code = rdev::linux_keycode_from_key(shared).unwrap();
    let foreign_code = rdev::linux_keycode_from_key(foreign).unwrap();
    let first = LiveInputWorker::new(9101).await;
    let second = LiveInputWorker::new(9102).await;
    let mut first_disabled = false;
    let mut second_disabled = false;
    let outcome: ResultType<_> = async {
        first.hold(control).await;
        first.hold(shared).await;
        second.hold(shared).await;
        tokio::task::block_in_place(|| {
            rdev::simulate(&EventType::KeyPress(foreign)).unwrap();
            assert!(observer.keys(&[control_code, shared_code, foreign_code]));
            observer.events();
        });

        set_peer_keyboard_disabled(&mut first_disabled, true, Some(&first.owner)).await?;
        let first_released = tokio::task::block_in_place(|| {
            observer.keys(&[shared_code, foreign_code])
                && observer.events() == [(xlib::KeyRelease, control_code)]
        });
        first.barrier().await;
        set_peer_keyboard_disabled(&mut first_disabled, true, Some(&first.owner)).await?;
        let duplicate_inert = tokio::task::block_in_place(|| {
            observer.keys(&[shared_code, foreign_code]) && observer.events().is_empty()
        });

        set_peer_keyboard_disabled(&mut first_disabled, false, Some(&first.owner)).await?;
        first.hold(control).await;
        let fresh_press = tokio::task::block_in_place(|| {
            observer.keys(&[control_code, shared_code, foreign_code])
                && observer.events() == [(xlib::KeyPress, control_code)]
        });
        set_peer_keyboard_disabled(&mut first_disabled, true, Some(&first.owner)).await?;
        let fresh_release = tokio::task::block_in_place(|| {
            observer.keys(&[shared_code, foreign_code])
                && observer.events() == [(xlib::KeyRelease, control_code)]
        });
        set_peer_keyboard_disabled(&mut second_disabled, true, Some(&second.owner)).await?;
        let final_owner = tokio::task::block_in_place(|| {
            observer.keys(&[foreign_code])
                && observer.events() == [(xlib::KeyRelease, shared_code)]
        });
        Ok((first_released, duplicate_inert, fresh_press, fresh_release, final_owner))
    }.await;
    // Retire both actual workers and the fixture's own foreign press before
    // reporting a product assertion, so even the baseline has joined cleanup.
    first.stop().await;
    second.stop().await;
    tokio::task::block_in_place(|| {
        rdev::simulate(&EventType::KeyRelease(foreign)).unwrap();
        assert!(observer.keys(&[]));
        drop(observer);
    });
    assert!(INPUT_KEY_OWNERS.lock().is_empty());
    assert!(INPUT_KEY_OWNERS.lock_mouse_buttons().is_empty());
    let actual = outcome.unwrap();
    println!("INPUT_REVOCATION_OBSERVED first_release={} duplicate_inert={} fresh_press={} fresh_release={} final_owner={}",
        actual.0, actual.1, actual.2, actual.3, actual.4);
    assert_eq!(actual, (true, true, true, true, true));
    println!("INPUT_REVOCATION_NATIVE=pass workers=2 shared_modifier=preserved foreign_key=preserved disable=before-return duplicate=inert reenable=same-worker cleanup=joined network_auth=false");
}
