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
