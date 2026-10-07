// Included inside the production listener module by the isolated component fixture.
use super::*;
use std::io::Write;
use std::time::Instant;
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{ConnectionExt, CreateWindowAux, WindowClass};

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
    );
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

fn change_and_observe(
    connection: &x11rb::rust_connection::RustConnection,
    selection: u32,
    windows: [u32; 2],
    receivers: &[&CallbackReceiver],
) {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut observed = vec![false; receivers.len()];
    let mut sequence = 0;
    while observed.iter().any(|received| !received) {
        assert!(Instant::now() < deadline, "actual XFixes callback did not arrive");
        connection.set_selection_owner(windows[sequence % 2], selection, x11rb::CURRENT_TIME)
            .unwrap().check().unwrap();
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
    }
}

#[test]
fn z_native_x11_peer_retirement() {
    assert!(Master::<Handler>::x11_clipboard().is_ok());
    let (connection, screen) = x11rb::connect(None).unwrap();
    let root = connection.setup().roots[screen].root;
    let windows = [connection.generate_id().unwrap(), connection.generate_id().unwrap()];
    for window in windows {
        connection.create_window(x11rb::COPY_DEPTH_FROM_PARENT, window, root,
                                 0, 0, 1, 1, 0, WindowClass::INPUT_OUTPUT, 0,
                                 &CreateWindowAux::new()).unwrap().check().unwrap();
    }
    let selection = connection.intern_atom(false, b"CLIPBOARD").unwrap().reply().unwrap().atom;
    let baseline = resources();

    for cycle in 0..4 {
        let (owner, receiver) = subscribe(format!("native-cycle-{cycle}")).unwrap();
        change_and_observe(&connection, selection, windows, &[&receiver]);
        drop(receiver);
        drop(owner);
        let listener = CLIPBOARD_LISTENER.lock().unwrap();
        assert!(listener.handle.is_none());
        let registry = listener.subscribers.lock().unwrap();
        assert!(registry.subscribers.is_empty() && registry.terminal.is_none());
    }
    let (first, first_receiver) = subscribe("native-first".to_owned()).unwrap();
    let (second, second_receiver) = subscribe("native-second".to_owned()).unwrap();
    change_and_observe(&connection, selection, windows, &[&first_receiver, &second_receiver]);
    println!("CLIPBOARD_NATIVE_READY callbacks=6 normal_cycles=4 subscribers=2");
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
    assert!(final_resources.0 <= baseline.0 && final_resources.1 <= baseline.1,
            "listener retirement retained resources: {baseline:?} -> {final_resources:?}");
    println!("CLIPBOARD_NATIVE_FINAL threads_before={} threads_after={} fds_before={} fds_after={} terminal_ms={}",
             baseline.0, final_resources.0, baseline.1, final_resources.1, termination_ms);
    println!("CLIPBOARD_NATIVE_CURRENT=pass callbacks=6 normal_cycles=4 subscribers=2 late_refusals=64 workers=joined");
}
