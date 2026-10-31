// Execute the complete production FPS decision method with controlled decode/mailbox
// observations and a real local message channel. No decoder, network or UI runs here.
use crate::message_proto::{message, misc, Message, Misc, OptionMessage};
use std::{cell::RefCell, collections::HashMap, sync::{mpsc, Mutex, RwLock}};

mod client { include!(env!("VIEWER_FPS_LIMIT")); }
include!(env!("VIEWER_FPS_STATE"));

struct MediaThread { pending: RefCell<Option<usize>> }
impl MediaThread {
    fn pending_frames(&self) -> Option<usize> { *self.pending.borrow() }
    fn begin_refresh(&self) -> bool {
        let mut pending = self.pending.borrow_mut();
        if pending.is_none() { return false; }
        *pending = Some(0);
        true
    }
}
struct VideoThread {
    fps_control: FpsControl,
    media_thread: MediaThread,
    decode_fps: RwLock<Option<usize>>,
}
struct Config { custom_fps: std::sync::Arc<Mutex<Option<usize>>>, last_auto_fps: Option<usize> }
struct Handler { lc: RwLock<Config>, errors: RefCell<Vec<String>>, refreshes: RefCell<Vec<i32>> }
impl Handler {
    fn on_error(&self, error: &str) { self.errors.borrow_mut().push(error.into()); }
    fn refresh_video(&self, display: i32) -> Result<(), &'static str> {
        self.refreshes.borrow_mut().push(display);
        Ok(())
    }
}
enum Data { Message(Message) }
struct ViewerFps { handler: Handler, video_threads: HashMap<usize, VideoThread>, sender: mpsc::Sender<Data> }
include!(env!("VIEWER_FPS_METHOD"));

fn fixture(previous: Option<usize>, decode_fps: usize, queued: usize) -> (ViewerFps, mpsc::Receiver<Data>) {
    let (sender, receiver) = mpsc::channel();
    (ViewerFps {
        handler: Handler {
            lc: RwLock::new(Config { custom_fps: std::sync::Arc::new(Mutex::new(Some(20))), last_auto_fps: previous }),
            errors: RefCell::new(Vec::new()), refreshes: RefCell::new(Vec::new()),
        },
        video_threads: HashMap::from([(0, VideoThread {
            fps_control: FpsControl::default(),
            media_thread: MediaThread { pending: RefCell::new(Some(queued)) },
            decode_fps: RwLock::new(Some(decode_fps)),
        })]),
        sender,
    }, receiver)
}

fn sent_rates(receiver: &mpsc::Receiver<Data>) -> Vec<i32> {
    receiver.try_iter().map(|Data::Message(message)| {
        let Some(message::Union::Misc(misc)) = message.union else { panic!("expected misc"); };
        let Some(misc::Union::Option(option)) = misc.union else { panic!("expected FPS option"); };
        option.custom_fps
    }).collect()
}

#[test]
fn congested_viewer_limits_never_increase_and_healthy_feedback_recovers() {
    let mut outcomes = Vec::new();
    for (previous, decoded, queued, expected) in [
        (1, 3, 2, 1), (1, 4, 3, 1), (3, 10, 6, 3),
        (8, 10, 6, 8), (15, 10, 6, 9), (15, 8, 8, 3),
    ] {
        let (mut viewer, receiver) = fixture(Some(previous), decoded, queued);
        assert!(viewer.fps_control(HashMap::from([(0, 1)])));
        let actual = viewer.handler.lc.read().unwrap().last_auto_fps;
        let sent = sent_rates(&receiver);
        let expected_messages = if expected == previous { vec![] } else { vec![expected as i32] };
        let correct = actual == Some(expected) && sent == expected_messages;
        let thread = viewer.video_threads.get_mut(&0).unwrap();
        *thread.decode_fps.write().unwrap() = Some(100);
        *thread.media_thread.pending.borrow_mut() = Some(0);
        for _ in 0..4 { assert!(viewer.fps_control(HashMap::from([(0, 1)]))); }
        let recovered = viewer.handler.lc.read().unwrap().last_auto_fps == Some(20)
            && sent_rates(&receiver) == [20];
        println!("VIEWER_FPS_CASE=observed previous={previous} decode_fps={decoded} queued={queued} expected={expected} actual={actual:?} sent={sent:?} correct={correct} recovered={recovered}");
        outcomes.push(correct && recovered);
    }

    let (mut viewer, receiver) = fixture(None, 100, 0);
    assert!(viewer.fps_control(HashMap::from([(0, 1)])));
    let first = sent_rates(&receiver) == [20] && viewer.handler.lc.read().unwrap().last_auto_fps == Some(20);

    let (mut viewer, receiver) = fixture(Some(20), 10, 6);
    drop(receiver);
    let failed_send = !viewer.fps_control(HashMap::from([(0, 1)]))
        && viewer.handler.lc.read().unwrap().last_auto_fps == Some(20)
        && viewer.handler.refreshes.borrow().is_empty();

    let (mut viewer, receiver) = fixture(Some(20), 10, 6);
    *viewer.video_threads[&0].media_thread.pending.borrow_mut() = None;
    let closed = !viewer.fps_control(HashMap::from([(0, 1)]))
        && viewer.handler.lc.read().unwrap().last_auto_fps == Some(20)
        && sent_rates(&receiver).is_empty() && viewer.handler.errors.borrow().len() == 1;
    let failures = outcomes.iter().filter(|&&correct| !correct).count();
    println!("VIEWER_FPS_RESULT=observed cases=6 failures={failures} initial={first} failed_send={failed_send} closed={closed}");
    assert!(failures == 0 && first && failed_send && closed,
        "congestion feedback must not raise an admitted rate or falsely confirm a failed update");
}

#[test]
fn displays_without_decode_estimates_do_not_suppress_measured_display_recovery() {
    let mut failures = 0;
    for measured_display in [0, 1] {
        for (previous, decoded, queued, expected) in [
            (None, 100, 0, 20),
            (Some(20), 5, 8, 2),
            (Some(2), 100, 0, 20),
        ] {
            let (mut viewer, receiver) = fixture(previous, decoded, queued);
            let measured = viewer.video_threads.remove(&0).unwrap();
            viewer.video_threads.insert(measured_display, measured);
            let unmeasured_display = 1 - measured_display;
            viewer.video_threads.insert(unmeasured_display, VideoThread {
                fps_control: FpsControl::default(),
                media_thread: MediaThread { pending: RefCell::new(Some(0)) },
                decode_fps: RwLock::new(None),
            });
            let observations = HashMap::from([(measured_display, 1), (unmeasured_display, 0)]);
            let ticks = if previous == Some(2) { 4 } else { 1 };
            for _ in 0..ticks {
                assert!(viewer.fps_control(observations.clone()));
            }
            let actual = viewer.handler.lc.read().unwrap().last_auto_fps;
            let sent = sent_rates(&receiver);
            let refreshes = viewer.handler.refreshes.borrow().clone();
            let expected_refreshes = if queued == 0 { vec![] } else { vec![measured_display as i32] };
            let correct = actual == Some(expected) && sent == [expected as i32]
                && refreshes == expected_refreshes
                && viewer.video_threads[&measured_display].media_thread.pending_frames() == Some(0)
                && viewer.video_threads[&unmeasured_display].decode_fps.read().unwrap().is_none()
                && viewer.handler.errors.borrow().is_empty();
            println!("VIEWER_FPS_UNMEASURED=observed measured_display={measured_display} previous={previous:?} decoded={decoded} queued={queued} actual={actual:?} sent={sent:?} refreshes={refreshes:?} correct={correct}");
            failures += usize::from(!correct);
        }
    }

    let (mut viewer, receiver) = fixture(Some(20), 100, 0);
    *viewer.video_threads[&0].decode_fps.write().unwrap() = None;
    assert!(viewer.fps_control(HashMap::from([(0, 1)])));
    let unknown_only = viewer.handler.lc.read().unwrap().last_auto_fps == Some(20)
        && sent_rates(&receiver).is_empty() && viewer.handler.refreshes.borrow().is_empty();

    // A second measured, slower display still supplies the shared rate bound.
    viewer.video_threads.insert(1, VideoThread {
        fps_control: FpsControl::default(),
        media_thread: MediaThread { pending: RefCell::new(Some(8)) },
        decode_fps: RwLock::new(Some(5)),
    });
    *viewer.video_threads[&0].decode_fps.write().unwrap() = Some(100);
    assert!(viewer.fps_control(HashMap::from([(0, 1), (1, 1)])));
    let slow_measured = viewer.handler.lc.read().unwrap().last_auto_fps == Some(2)
        && sent_rates(&receiver) == [2] && *viewer.handler.refreshes.borrow() == [1];
    println!("VIEWER_FPS_UNMEASURED_RESULT=observed cases=6 failures={failures} unknown_only={unknown_only} slow_measured={slow_measured}");
    assert!(failures == 0 && unknown_only && slow_measured,
        "an absent estimate must not hide measured congestion or healthy recovery");
}
