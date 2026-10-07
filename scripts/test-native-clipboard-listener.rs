// Included inside the production listener module by the isolated component fixture.
use super::*;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;
use x11rb_listener as x11rb;
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{ConnectionExt, CreateWindowAux, WindowClass};
use x11rb::protocol::{xfixes, Event};

fn wait_finished(thread: &JoinHandle<()>, deadline: Instant) -> bool {
    while !thread.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    thread.is_finished()
}

#[test]
fn a_retired_startup_observer() {
    let subscribers = Subscribers::default();
    let (sender, receiver) = channel();
    drop(receiver);
    let thread = start_clipboard_master_thread(
        Handler { subscribers: Arc::clone(&subscribers) },
        Arc::clone(&subscribers),
        sender,
    ).unwrap();
    assert!(wait_finished(&thread, Instant::now() + Duration::from_secs(2)));
    thread.join().unwrap();
    assert!(subscribers.lock().unwrap().terminal.is_some());
    println!("CLIPBOARD_NATIVE_STARTUP=pass observer=retired worker=joined");
}

fn resources() -> (usize, usize) {
    (
        std::fs::read_dir("/proc/self/task").unwrap().count(),
        std::fs::read_dir("/proc/self/fd").unwrap().count(),
    )
}

fn assert_resources_retired(baseline: (usize, usize)) {
    // pthread_join observes clear_child_tid before Linux unlinks the task from
    // /proc. Keep join and kernel task absence as separate required observations.
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let actual = resources();
        assert_eq!(actual.1, baseline.1, "joined retirement retained descriptors");
        if actual.0 == baseline.0 {
            return;
        }
        assert!(Instant::now() < deadline, "joined retirement retained tasks: {baseline:?} -> {actual:?}");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn change_and_observe(
    connection: &x11rb::rust_connection::RustConnection,
    selection: u32,
    windows: [u32; 2],
    receivers: &[&CallbackReceiver],
) {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut observed = vec![false; receivers.len()];
    let mut sequence = 0;
    let mut native_events = 0;
    while observed.iter().any(|received| !received) {
        assert!(Instant::now() < deadline, "actual XFixes callback did not arrive");
        connection.set_selection_owner(windows[sequence % 2], selection, x11rb::CURRENT_TIME)
            .unwrap().check().unwrap();
        assert_eq!(connection.get_selection_owner(selection).unwrap().reply().unwrap().owner,
                   windows[sequence % 2]);
        connection.flush().unwrap();
        sequence += 1;
        for (receiver, received) in receivers.iter().zip(&mut observed) {
            if !*received {
                match receiver.recv_timeout(Duration::from_millis(30)) {
                    Some(CallbackResult::Next) => *received = true,
                    None => {},
                    _ => panic!("healthy native listener returned a terminal result"),
                }
            }
        }
        while let Some(event) = connection.poll_for_event().unwrap() {
            if matches!(event, Event::XfixesSelectionNotify(_)) {
                native_events += 1;
            }
        }
        if sequence == 1 || sequence % 25 == 0 {
            let listener = CLIPBOARD_LISTENER.lock().unwrap();
            let registry = listener.subscribers.lock().unwrap();
            println!("CLIPBOARD_NATIVE_CHANGE requests={} server_events={} observed={:?} members={} terminal={:?} master_finished={}",
                     sequence, native_events, observed, registry.subscribers.len(), registry.terminal,
                     listener.handle.as_ref().unwrap().1.is_finished());
        }
    }
}

fn native_selection_driver() -> (x11rb::rust_connection::RustConnection, u32, [u32; 2]) {
    let (connection, screen) = x11rb::connect(None).unwrap();
    let root = connection.setup().roots[screen].root;
    let windows = [connection.generate_id().unwrap(), connection.generate_id().unwrap()];
    for window in windows {
        connection.create_window(x11rb::COPY_DEPTH_FROM_PARENT, window, root,
                                 0, 0, 1, 1, 0, WindowClass::INPUT_OUTPUT, 0,
                                 &CreateWindowAux::new()).unwrap().check().unwrap();
    }
    let selection = connection.intern_atom(false, b"CLIPBOARD").unwrap().reply().unwrap().atom;
    xfixes::query_version(&connection, 5, 0).unwrap().reply().unwrap();
    xfixes::select_selection_input(&connection, root, selection,
                                  xfixes::SelectionEventMask::SET_SELECTION_OWNER).unwrap().check().unwrap();
    (connection, selection, windows)
}

fn root_children(connection: &x11rb::rust_connection::RustConnection) -> Vec<u32> {
    let root = connection.setup().roots[0].root;
    let mut children = connection.query_tree(root).unwrap().reply().unwrap().children;
    children.sort_unstable();
    children
}

fn assert_native_window_retired(connection: &x11rb::rust_connection::RustConnection, baseline: &[u32]) {
    let deadline = Instant::now() + Duration::from_secs(1);
    while root_children(connection) != baseline {
        assert!(Instant::now() < deadline, "owned native clipboard window survived joined retirement");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn b_native_startup_failure_retires_exact_state() {
    let display = std::env::var("DISPLAY").unwrap();
    let baseline = resources();
    std::env::set_var("DISPLAY", "127.0.0.1:94.0");
    assert!(subscribe("invalid-native-display".to_owned()).is_err());
    std::env::set_var("DISPLAY", display);
    {
        let listener = CLIPBOARD_LISTENER.lock().unwrap();
        assert!(listener.handle.is_none());
        let registry = listener.subscribers.lock().unwrap();
        assert!(registry.subscribers.is_empty() && registry.terminal.is_none());
    }
    assert_eq!(resources(), baseline);
    let (connection, selection, windows) = native_selection_driver();
    let native_baseline = resources();
    let children = root_children(&connection);
    let (owner, receiver) = subscribe("after-native-startup-failure".to_owned()).unwrap();
    change_and_observe(&connection, selection, windows, &[&receiver]);
    drop(receiver);
    drop(owner);
    assert_native_window_retired(&connection, &children);
    assert_eq!(resources(), native_baseline);
    println!("CLIPBOARD_NATIVE_STARTUP_FAILURE=pass selector=refused subscription=removed worker=joined next_start=working resources=retired");
}

#[test]
fn c_native_thread_creation_failure_retires_exact_state() {
    assert_eq!(unsafe { libc::getuid() }, 4000);
    struct ThreadLimit(libc::rlimit);
    impl Drop for ThreadLimit {
        fn drop(&mut self) {
            // Only this isolated process's soft limit was changed; the hard limit is retained.
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &self.0) }, 0);
        }
    }
    let mut original = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut original) }, 0);
    let limited = libc::rlimit { rlim_cur: 0, rlim_max: original.rlim_max };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &limited) }, 0);
    let limit = ThreadLimit(original);
    match std::thread::Builder::new().spawn(|| {}) {
        Err(error) => assert_eq!(error.raw_os_error(), Some(libc::EAGAIN)),
        Ok(thread) => {
            thread.join().unwrap();
            panic!("isolated thread limit did not cause a real kernel denial");
        }
    }
    let baseline = resources();
    println!("CLIPBOARD_NATIVE_THREAD_LIMIT=ready kernel=EAGAIN soft=0 hard=unchanged");
    std::io::stdout().flush().unwrap();
    for _ in 0..4 {
        let error = match subscribe("thread-budget".to_owned()) {
            Err(error) => error,
            Ok(_) => panic!("native clipboard worker ignored the thread limit"),
        };
        assert_eq!(error.downcast_ref::<io::Error>().unwrap().raw_os_error(), Some(libc::EAGAIN));
        {
            let listener = CLIPBOARD_LISTENER.lock().unwrap();
            assert!(listener.handle.is_none());
            let registry = listener.subscribers.lock().unwrap();
            assert!(registry.subscribers.is_empty() && registry.terminal.is_none());
        }
        assert_eq!(resources(), baseline);
    }
    drop(limit);
    let (connection, selection, windows) = native_selection_driver();
    let native_baseline = resources();
    let children = root_children(&connection);
    let (owner, receiver) = subscribe("thread-budget".to_owned()).unwrap();
    change_and_observe(&connection, selection, windows, &[&receiver]);
    drop(receiver);
    drop(owner);
    assert_native_window_retired(&connection, &children);
    assert_eq!(resources(), native_baseline);
    println!("CLIPBOARD_NATIVE_THREAD_FAILURE=pass kernel=EAGAIN refusals=4 subscription=removed lock=usable next_start=working resources=retired");
}

#[test]
fn d_native_busy_retirement() {
    let (connection, selection, windows) = native_selection_driver();
    let root = connection.setup().roots[0].root;
    // Remove only the fixture's redundant observer, not the production subscription.
    xfixes::select_selection_input(&connection, root, selection,
                                  xfixes::SelectionEventMask::default()).unwrap().check().unwrap();
    let baseline = resources();
    let children = root_children(&connection);
    struct StopTraffic(Arc<AtomicBool>);
    impl Drop for StopTraffic {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    for cycle in 0..4 {
        let stop = Arc::new(AtomicBool::new(false));
        let acknowledged = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            let stop_on_exit = StopTraffic(Arc::clone(&stop));
            let writer_stop = Arc::clone(&stop);
            let writer_acknowledged = Arc::clone(&acknowledged);
            let (ready, started) = channel();
            let producer = scope.spawn(move || {
                let (writer, _) = x11rb::connect(None).unwrap();
                ready.send(()).unwrap();
                let mut changes = 0;
                let mut writes = Vec::with_capacity(64);
                while !writer_stop.load(Ordering::Acquire) {
                    assert!(changes < 1_048_576, "busy fixture exceeded its request budget");
                    for change in 0..64 {
                        writes.push(writer.set_selection_owner(windows[change % 2], selection, x11rb::CURRENT_TIME)
                            .unwrap());
                    }
                    writer.flush().unwrap();
                    assert_eq!(writer.get_selection_owner(selection).unwrap().reply().unwrap().owner, windows[1]);
                    for write in writes.drain(..) {
                        write.check().unwrap();
                    }
                    changes += 64;
                    writer_acknowledged.store(changes, Ordering::Release);
                }
                changes
            });
            started.recv_timeout(Duration::from_secs(1)).unwrap();
            let live_producer_baseline = resources();
            let (first, first_receiver) = subscribe(format!("busy-first-{cycle}")).unwrap();
            let (last, last_receiver) = subscribe(format!("busy-last-{cycle}")).unwrap();
            assert!(matches!(first_receiver.recv_timeout(Duration::from_secs(3)), Some(CallbackResult::Next)));
            assert!(matches!(last_receiver.recv_timeout(Duration::from_secs(3)), Some(CallbackResult::Next)));
            assert_eq!(root_children(&connection).len(), children.len() + 1);
            drop(first_receiver);
            drop(first);
            assert!(CLIPBOARD_LISTENER.lock().unwrap().handle.is_some());
            assert!(matches!(last_receiver.recv_timeout(Duration::from_secs(3)), Some(CallbackResult::Next)));
            let before_retirement = acknowledged.load(Ordering::Acquire);
            assert!(before_retirement >= 64 && !producer.is_finished());
            let retiring = Instant::now();
            drop(last_receiver);
            drop(last);
            let retirement = retiring.elapsed();
            assert!(retirement < Duration::from_secs(1), "busy listener retirement exceeded one second");
            {
                let listener = CLIPBOARD_LISTENER.lock().unwrap();
                assert!(listener.handle.is_none());
                let registry = listener.subscribers.lock().unwrap();
                assert!(registry.subscribers.is_empty() && registry.terminal.is_none());
            }
            let after_join = acknowledged.load(Ordering::Acquire);
            let deadline = Instant::now() + Duration::from_secs(1);
            while acknowledged.load(Ordering::Acquire) == after_join {
                assert!(Instant::now() < deadline && !producer.is_finished(), "producer did not continue after listener join");
                std::thread::sleep(Duration::from_millis(1));
            }
            assert_native_window_retired(&connection, &children);
            assert_resources_retired(live_producer_baseline);
            assert!(!producer.is_finished());
            drop(stop_on_exit);
            let changes = producer.join().unwrap();
            assert_resources_retired(baseline);
            println!("CLIPBOARD_NATIVE_BUSY_TIMING cycle={cycle} before_retirement={before_retirement} after_join={after_join} changes={changes} retirement_us={}", retirement.as_micros());
        });
    }
    println!("CLIPBOARD_NATIVE_BUSY=pass cycles=4 source=live first_retirement=preserved last_retirement=joined native_window=retired resources=baseline");
}

#[test]
fn e_native_startup_deadline() {
    use std::io::Read;
    use std::os::unix::net::UnixListener;
    use x11rb::x11_utils::Serialize;

    let display = std::env::var("DISPLAY").unwrap();
    let (connection, selection, windows) = native_selection_driver();
    let setup = connection.setup().serialize();
    let baseline = resources();
    let children = root_children(&connection);
    for case in ["silent", "fragmented", "first-reply"] {
        let path = "/tmp/.X11-unix/X95";
        assert!(!std::path::Path::new(path).exists());
        let listener = UnixListener::bind(path).unwrap();
        let setup = setup.clone();
        let peer = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
            socket.set_write_timeout(Some(Duration::from_secs(1))).unwrap();
            let mut header = [0u8; 12];
            socket.read_exact(&mut header).unwrap();
            assert_eq!(header[0], b'l');
            assert_eq!(u16::from_le_bytes([header[2], header[3]]), 11);
            let auth_name = u16::from_le_bytes([header[6], header[7]]) as usize;
            let auth_data = u16::from_le_bytes([header[8], header[9]]) as usize;
            let auth_size = ((auth_name + 3) & !3) + ((auth_data + 3) & !3);
            assert!(auth_size <= 512);
            socket.read_exact(&mut vec![0u8; auth_size]).unwrap();
            if case == "fragmented" {
                // Never complete the eight-byte setup header. Drip progress must not
                // restart the production connection's one startup budget.
                for byte in &setup[..7] {
                    socket.write_all(&[*byte]).unwrap();
                    std::thread::sleep(Duration::from_millis(400));
                }
            } else if case == "first-reply" {
                socket.write_all(&setup).unwrap();
                let mut request = [0u8; 4];
                socket.read_exact(&mut request).unwrap();
                assert_eq!(request[0], 98, "production did not request native extension metadata");
                let length = u16::from_le_bytes([request[2], request[3]]) as usize * 4;
                assert!((4..=512).contains(&length));
                socket.read_exact(&mut vec![0u8; length - 4]).unwrap();
            }
            println!("CLIPBOARD_NATIVE_STALL_READY case={case} transport=unix setup_request=actual");
            std::io::stdout().flush().unwrap();
            let mut byte = [0u8; 1];
            match socket.read(&mut byte) {
                Ok(0) => true,
                Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => false,
                result => panic!("unexpected stalled peer outcome: {result:?}"),
            }
        });
        std::env::set_var("DISPLAY", ":95.0");
        let started = Instant::now();
        let result = subscribe("startup-budget".to_owned());
        let elapsed = started.elapsed();
        std::env::set_var("DISPLAY", &display);
        let closed = peer.join().unwrap();
        std::fs::remove_file(path).unwrap();
        println!("CLIPBOARD_NATIVE_STALL_RESULT case={case} startup_ms={} peer_closed={closed}", elapsed.as_millis());
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("stalled native startup was admitted"),
        };
        assert!(error.to_string().contains("X11 clipboard startup deadline expired"),
                "stalled startup was not classified by its own deadline: {error}");
        assert!(closed && elapsed < Duration::from_secs(4), "native startup did not cancel its exact socket in time");
        {
            let listener = CLIPBOARD_LISTENER.lock().unwrap();
            assert!(listener.handle.is_none());
            let registry = listener.subscribers.lock().unwrap();
            assert!(registry.subscribers.is_empty() && registry.terminal.is_none());
        }
        assert_resources_retired(baseline);
        let (owner, receiver) = subscribe("startup-budget".to_owned()).unwrap();
        change_and_observe(&connection, selection, windows, &[&receiver]);
        drop(receiver);
        drop(owner);
        assert_native_window_retired(&connection, &children);
        assert_resources_retired(baseline);
    }
    println!("CLIPBOARD_NATIVE_DEADLINE=pass cases=3 source=production transport=unix budget=one peer=closed startup_worker=joined next_start=working resources=baseline");
}

#[test]
fn f_native_cookie_authentication() {
    let correct = std::env::var("XAUTHORITY").unwrap();
    let (connection, selection, windows) = native_selection_driver();
    let baseline = resources();
    let children = root_children(&connection);
    let (owner, receiver) = subscribe("cookie-authority".to_owned()).unwrap();
    // The startup budget must be disarmed once registration commits; it is not
    // a lifetime limit on a healthy native clipboard connection.
    std::thread::sleep(Duration::from_millis(3200));
    change_and_observe(&connection, selection, windows, &[&receiver]);
    drop(receiver);
    drop(owner);
    assert_native_window_retired(&connection, &children);
    assert_resources_retired(baseline);
    for variable in ["CLIPBOARD_TEST_BAD_AUTHORITY", "CLIPBOARD_TEST_EMPTY_AUTHORITY"] {
        std::env::set_var("XAUTHORITY", std::env::var(variable).unwrap());
        let refused = subscribe("cookie-authority".to_owned()).is_err();
        std::env::set_var("XAUTHORITY", &correct);
        assert!(refused, "native cookie-authenticated server admitted {variable}");
        {
            let listener = CLIPBOARD_LISTENER.lock().unwrap();
            assert!(listener.handle.is_none());
            let registry = listener.subscribers.lock().unwrap();
            assert!(registry.subscribers.is_empty() && registry.terminal.is_none());
        }
        assert_resources_retired(baseline);
        let (owner, receiver) = subscribe("cookie-authority".to_owned()).unwrap();
        change_and_observe(&connection, selection, windows, &[&receiver]);
        drop(receiver);
        drop(owner);
        assert_native_window_retired(&connection, &children);
        assert_resources_retired(baseline);
    }
    println!("CLIPBOARD_NATIVE_AUTH=pass server=cookie-required valid=3 wrong=refused missing=refused startup_budget=disarmed next_start=working resources=baseline");
}

#[test]
fn y_native_x11_warm_restart() {
    let (connection, selection, windows) = native_selection_driver();
    let baseline = resources();
    let children = root_children(&connection);
    for cycle in 0..4 {
        println!("CLIPBOARD_NATIVE_CYCLE cycle={cycle} stage=subscribe");
        let (owner, receiver) = subscribe(format!("native-cycle-{cycle}")).unwrap();
        if !HISTORICAL_CLIPBOARD_ERROR {
            assert_eq!(root_children(&connection).len(), children.len() + 1,
                       "a native subscription did not own exactly one window");
        }
        let started = Instant::now();
        change_and_observe(&connection, selection, windows, &[&receiver]);
        println!("CLIPBOARD_NATIVE_WARM_TIMING cycle={cycle} callback_ms={}", started.elapsed().as_millis());
        drop(receiver);
        drop(owner);
        let listener = CLIPBOARD_LISTENER.lock().unwrap();
        assert!(listener.handle.is_none());
        let registry = listener.subscribers.lock().unwrap();
        assert!(registry.subscribers.is_empty() && registry.terminal.is_none());
        drop(registry);
        drop(listener);
        if !HISTORICAL_CLIPBOARD_ERROR {
            assert_native_window_retired(&connection, &children);
            assert_eq!(resources(), baseline);
        }
        for change in 0..1000 {
            connection.set_selection_owner(windows[change % 2], selection, x11rb::CURRENT_TIME)
                .unwrap();
        }
        connection.flush().unwrap();
        assert_eq!(connection.get_selection_owner(selection).unwrap().reply().unwrap().owner, windows[1]);
    }
    println!("CLIPBOARD_NATIVE_WARM=pass callbacks=4 normal_cycles=4 workers=joined");
}

#[test]
fn z_native_x11_peer_retirement() {
    let (connection, selection, windows) = native_selection_driver();
    let baseline = resources();
    let (first, first_receiver) = subscribe("native-first".to_owned()).unwrap();
    let (second, second_receiver) = subscribe("native-second".to_owned()).unwrap();
    change_and_observe(&connection, selection, windows, &[&first_receiver, &second_receiver]);
    println!("CLIPBOARD_NATIVE_READY callbacks=2 subscribers=2");
    std::io::stdout().flush().unwrap();
    // The external driver retires and joins only this fixture's Unix-only Xvfb.
    let terminal_at = Instant::now();
    assert!(matches!(first_receiver.recv_timeout(Duration::from_secs(3)), Some(CallbackResult::StopWithError(_))));
    assert!(matches!(second_receiver.recv_timeout(Duration::from_secs(1)), Some(CallbackResult::StopWithError(_))));
    let finished = {
        let listener = CLIPBOARD_LISTENER.lock().unwrap();
        wait_finished(&listener.handle.as_ref().unwrap().1, Instant::now() + Duration::from_secs(2))
    };
    if HISTORICAL_CLIPBOARD_ERROR {
        assert!(!finished, "historical error callback unexpectedly retired the worker");
        println!("CLIPBOARD_NATIVE_OLD=retained terminal=delivered worker=live process_reset=required");
        std::io::stdout().flush().unwrap();
        // An ordinary join would hang. End this exact isolated historical process explicitly.
        std::process::exit(86);
    }
    assert!(finished, "terminal native worker did not finish");
    for attempt in 0..64 {
        assert!(subscribe(format!("native-late-{attempt}")).is_err());
    }
    let termination_ms = terminal_at.elapsed().as_millis();
    drop(first_receiver);
    drop(first);
    assert!(CLIPBOARD_LISTENER.lock().unwrap().handle.is_some());
    drop(second_receiver);
    drop(second);
    let listener = CLIPBOARD_LISTENER.lock().unwrap();
    assert!(listener.handle.is_none());
    let registry = listener.subscribers.lock().unwrap();
    assert!(registry.subscribers.is_empty() && registry.terminal.is_none());
    drop(registry);
    drop(listener);
    let final_resources = resources();
    assert_eq!(final_resources, baseline,
            "listener retirement retained resources: {baseline:?} -> {final_resources:?}");
    println!("CLIPBOARD_NATIVE_FINAL threads_before={} threads_after={} fds_before={} fds_after={} terminal_ms={}",
             baseline.0, final_resources.0, baseline.1, final_resources.1, termination_ms);
    println!("CLIPBOARD_NATIVE_CURRENT=pass callbacks=2 subscribers=2 late_refusals=64 workers=joined");
}
