// Production sender/state with recorded publication and an injected wall clock.
// std::time::Instant remains the native clock. No OS input or peer transport runs.
mod service {
    pub trait Reset {
        fn reset(&mut self);
    }
}

mod sender {
    use crate::{message_proto::{CursorPosition, Message, MouseEvent}, ResultType};
    use std::{
        sync::{Arc, Mutex, atomic::{AtomicI64, Ordering}},
        time::{Duration, Instant},
    };

    include!(env!("CURSOR_ECHO_STATE"));
    include!(env!("CURSOR_ECHO_INPUT"));
    include!(env!("CURSOR_ECHO_GLOBALS"));
    include!(env!("CURSOR_ECHO_CLOCK"));
    include!(env!("CURSOR_ECHO_SENDER"));
    include!(env!("CURSOR_ECHO_WRITERS"));

    static WALL_MILLIS: AtomicI64 = AtomicI64::new(1_000_000);

    fn get_time() -> i64 {
        WALL_MILLIS.load(Ordering::SeqCst)
    }

    #[derive(Clone, Default)]
    struct EmptyExtraFieldService {
        sent: Arc<Mutex<Vec<(Message, i32)>>>,
        snapshots: Arc<Mutex<Vec<Message>>>,
    }

    impl EmptyExtraFieldService {
        fn send_without(&self, message: Message, excluded: i32) {
            self.sent.lock().unwrap().push((message, excluded));
        }

        fn snapshot(&self, send: impl FnOnce(&Self) -> ResultType<()>) -> ResultType<()> {
            send(self)
        }

        fn send(&self, message: Message) {
            self.snapshots.lock().unwrap().push(message);
        }
    }

    fn observe(service: &EmptyExtraFieldService, state: &mut StatePos, x: i32) -> i32 {
        *LATEST_SYS_CURSOR_POS.lock().unwrap() = (None, (x, -17));
        let before = service.sent.lock().unwrap().len();
        run_pos(service.clone(), state).unwrap();
        let sent = service.sent.lock().unwrap();
        assert_eq!(sent.len(), before + 1);
        let (message, excluded) = sent.last().unwrap();
        assert_eq!((message.cursor_position().x, message.cursor_position().y), (x, -17));
        let snapshots = service.snapshots.lock().unwrap();
        let snapshot = snapshots.last().unwrap().cursor_position();
        assert_eq!((snapshot.x, snapshot.y), (x, -17));
        assert_eq!(state.cursor_pos, (x, -17));
        *excluded
    }

    #[test]
    fn cursor_echo_clock_adjustments_preserve_elapsed_window() {
        let mut correct = true;
        for (case, delta) in [("backward", -600_000), ("forward", 600_000)] {
            WALL_MILLIS.store(1_000_000, Ordering::SeqCst);
            *LATEST_PEER_INPUT_CURSOR.lock().unwrap() = Input::default();
            let service = EmptyExtraFieldService::default();
            let mut state = StatePos { cursor_pos: (0, 0) };
            let start = Instant::now();
            update_latest_input_cursor_time(7);
            WALL_MILLIS.fetch_add(delta, Ordering::SeqCst);
            let fresh = observe(&service, &mut state, 10);
            let fresh_elapsed = start.elapsed();
            assert!(fresh_elapsed < Duration::from_millis(250), "fixture missed fresh window");
            std::thread::sleep(Duration::from_millis(350));
            let expired = observe(&service, &mut state, 11);
            let elapsed = start.elapsed();
            let case_correct = fresh == 7 && expired == 0;
            correct &= case_correct;
            println!("CURSOR_ECHO_CLOCK_CASE=observed case={case} delta_ms={delta} wall_ms={} fresh={fresh} expired={expired} fresh_us={} expired_ms={} correct={case_correct}",
                get_time(), fresh_elapsed.as_micros(), elapsed.as_millis());
        }
        assert!(correct, "wall-clock adjustment changed the 300ms echo window");
        println!("CURSOR_ECHO_CLOCK=pass cases=2 wall_fault_ms=600000 window_ms=300 elapsed=native source=production-sender");
    }

    #[test]
    fn cursor_echo_input_writers_preserve_owner_position_and_defaults() {
        WALL_MILLIS.store(1_000_000, Ordering::SeqCst);
        *LATEST_PEER_INPUT_CURSOR.lock().unwrap() = Input::default();
        let service = EmptyExtraFieldService::default();
        let mut state = StatePos { cursor_pos: (0, 0) };
        assert_eq!(observe(&service, &mut state, 20), 0);
        assert_eq!(get_last_input_cursor_pos(), (0, 0));

        update_latest_input_cursor_time(7);
        assert_eq!(observe(&service, &mut state, 21), 7);
        assert_eq!(get_last_input_cursor_pos(), (0, 0));
        let mut event = MouseEvent::new();
        event.x = -31;
        event.y = 42;
        record_absolute(9, &event);
        assert_eq!(get_last_input_cursor_pos(), (-31, 42));
        assert_eq!(observe(&service, &mut state, 22), 9);
        record_relative(11, 51, -62);
        assert_eq!(get_last_input_cursor_pos(), (51, -62));
        assert_eq!(observe(&service, &mut state, 23), 11);
        update_latest_input_cursor_time(0);
        assert_eq!(get_last_input_cursor_pos(), (51, -62));
        assert_eq!(observe(&service, &mut state, 24), 0);

        let sent = service.sent.lock().unwrap().len();
        run_pos(service.clone(), &mut state).unwrap();
        assert_eq!(service.sent.lock().unwrap().len(), sent);
        *LATEST_SYS_CURSOR_POS.lock().unwrap() = (None, (INVALID_CURSOR_POS, 1));
        run_pos(service.clone(), &mut state).unwrap();
        assert_eq!(service.sent.lock().unwrap().len(), sent);
        assert_eq!(state.cursor_pos, (24, -17));
        println!("CURSOR_ECHO_WRITERS=pass paths=3 owner=exact position=preserved default=none movement=unchanged snapshots=exact");
    }
}
