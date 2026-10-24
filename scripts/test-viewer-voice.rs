// Exact production viewer branches and stop method; audio and transport are explicit doubles.
// No physical capture, complete IoLoop, native IPC or authenticated peer runs here.
use crate::message_proto::{message, Message, VoiceCallRequest, VoiceCallResponse};
use std::{cell::RefCell, num::NonZeroI64, rc::Rc, sync::atomic::{AtomicI64, Ordering}};

#[derive(Default)]
struct Effects { starts: usize, stops: usize, events: Vec<String> }

struct VoiceCallAudio(Rc<RefCell<Effects>>);
impl VoiceCallAudio {
    fn stop(&mut self) { self.0.borrow_mut().stops += 1; }
}

struct Handler(Rc<RefCell<Effects>>);
impl Handler {
    fn on_voice_call_waiting(&self) { self.0.borrow_mut().events.push("waiting".into()); }
    fn on_voice_call_started(&self) { self.0.borrow_mut().events.push("started".into()); }
    fn on_voice_call_closed(&self, reason: &str) {
        self.0.borrow_mut().events.push(format!("closed:{reason}"));
    }
}

#[derive(Default)]
struct Peer { sent: Vec<Message>, attempted: Vec<Message>, fail: bool }
impl Peer {
    async fn send(&mut self, message: &Message) -> Result<(), &'static str> {
        self.attempted.push(message.clone());
        if self.fail { return Err("injected voice send failure"); }
        self.sent.push(message.clone());
        Ok(())
    }
}

enum Data { NewVoiceCall, CloseVoiceCall }
// Only the diagnostic response timestamp may depend on this explicit clock double.
static TEST_VOICE_CLOCK: AtomicI64 = AtomicI64::new(1234);
fn get_time() -> i64 { TEST_VOICE_CLOCK.load(Ordering::Relaxed) }
include!(env!("VIEWER_VOICE_HELPERS"));

struct ViewerVoice {
    voice_call_request_timestamp: Option<NonZeroI64>,
    voice_call_audio: Option<VoiceCallAudio>,
    handler: Handler,
    audio_available: bool,
}
impl ViewerVoice {
    fn fixture(pending: bool, active: bool, available: bool) -> Self {
        let effects = Rc::new(RefCell::new(Effects::default()));
        Self {
            voice_call_request_timestamp: if pending { NonZeroI64::new(42) } else { None },
            voice_call_audio: active.then(|| VoiceCallAudio(effects.clone())),
            handler: Handler(effects),
            audio_available: available,
        }
    }

    fn start_voice_call(&mut self) -> Option<VoiceCallAudio> {
        self.handler.0.borrow_mut().starts += 1;
        self.audio_available.then(|| VoiceCallAudio(self.handler.0.clone()))
    }
}
include!(env!("VIEWER_VOICE_STOP"));
include!(env!("VIEWER_VOICE_RECEIVE"));
include!(env!("VIEWER_VOICE_COMMAND"));
include!(env!("VIEWER_VOICE_REQUEST"));

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_closes(peer: &Peer) -> usize {
        for message in &peer.sent {
            assert!(matches!(&message.union,
                Some(message::Union::VoiceCallRequest(request)) if !request.is_connect));
        }
        peer.sent.len()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn viewer_voice_matching_replies_complete_once() {
        for (case, accepted, available, active) in [
            ("accept", true, true, false), ("replace-audio", true, true, true),
            ("refuse", false, true, false), ("audio-failure", true, false, false),
        ] {
            let mut viewer = ViewerVoice::fixture(true, active, available);
            let mut peer = Peer::default();
            assert!(viewer.receive(&mut peer, new_voice_call_response(42, accepted)).await);
            assert!(viewer.voice_call_request_timestamp.is_none());
            let event = if accepted && available { "started" }
                else if accepted { "closed:Failed to start voice call audio" } else { "closed:" };
            assert_eq!(viewer.handler.0.borrow().events, [event]);
            for duplicate in [true, false] {
                assert!(viewer.receive(&mut peer, new_voice_call_response(42, duplicate)).await);
            }
            let effects = viewer.handler.0.borrow();
            assert_eq!(effects.events, [event]);
            assert_eq!(effects.starts, usize::from(accepted));
            assert_eq!(effects.stops, usize::from(active));
            assert_eq!(viewer.voice_call_audio.is_some(), accepted && available);
            assert_eq!(peer_closes(&peer), usize::from(accepted && !available));
            println!("VIEWER_VOICE_CONTROL_CASE=pass case={case} starts={} stops={} callbacks={} peer_closes={} pending=false",
                effects.starts, effects.stops, effects.events.len(), peer_closes(&peer));
        }
        println!("VIEWER_VOICE_CONTROLS=pass cases=4 duplicate_replies=8 matching=once audio_failure=closed replacement=stopped constructors=production");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn viewer_voice_mismatch_preserves_pending_for_matching_reply() {
        let mut correct = true;
        for wrong in [0, -1, i64::MIN, i64::MAX, 41, 43] {
            for wrong_accept in [false, true] {
                for accepted in [false, true] {
                    let mut viewer = ViewerVoice::fixture(true, false, true);
                    let mut peer = Peer::default();
                    assert!(viewer.receive(&mut peer, new_voice_call_response(wrong, wrong_accept)).await);
                    let preserved = viewer.voice_call_request_timestamp.map(NonZeroI64::get) == Some(42);
                    let quiet = viewer.handler.0.borrow().events.is_empty();
                    assert!(viewer.receive(&mut peer, new_voice_call_response(42, accepted)).await);
                    let effects = viewer.handler.0.borrow();
                    let event = if accepted { "started" } else { "closed:" };
                    let case_correct = preserved && quiet && viewer.voice_call_request_timestamp.is_none()
                        && effects.events == [event] && effects.starts == usize::from(accepted)
                        && effects.stops == 0 && peer.sent.is_empty()
                        && viewer.voice_call_audio.is_some() == accepted;
                    println!("VIEWER_VOICE_MISMATCH_CASE=observed wrong={wrong} wrong_accept={wrong_accept} accepted={accepted} preserved={preserved} quiet={quiet} callbacks={} starts={} correct={case_correct}",
                        effects.events.len(), effects.starts);
                    correct &= case_correct;
                }
            }
        }
        assert!(correct, "an unmatched voice response consumed current request authority");
        println!("VIEWER_VOICE_MISMATCH=pass cases=24 stale=ignored pending=preserved matching=usable");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn viewer_voice_manual_close_retires_pending_before_late_reply() {
        let mut correct = true;
        for accepted in [false, true] {
            let mut viewer = ViewerVoice::fixture(true, false, true);
            let mut peer = Peer::default();
            viewer.manual_close(&mut peer).await;
            let cancelled = viewer.voice_call_request_timestamp.is_none();
            assert!(viewer.receive(&mut peer, new_voice_call_response(42, accepted)).await);
            let effects = viewer.handler.0.borrow();
            let case_correct = cancelled && viewer.voice_call_request_timestamp.is_none()
                && viewer.voice_call_audio.is_none() && effects.starts == 0 && effects.stops == 0
                && effects.events == ["closed:Closed manually by the peer"] && peer_closes(&peer) == 1;
            println!("VIEWER_VOICE_MANUAL_CASE=observed accepted={accepted} cancelled={cancelled} callbacks={} starts={} peer_closes={} correct={case_correct}",
                effects.events.len(), effects.starts, peer_closes(&peer));
            correct &= case_correct;
        }
        assert!(correct, "a late voice response survived manual cancellation");
        println!("VIEWER_VOICE_MANUAL=pass cases=2 pending=retired late_reply=ignored peer_close=once");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn viewer_voice_remote_close_retires_pending_before_late_reply() {
        let mut correct = true;
        for pending in [false, true] {
            for active in [false, true] {
                for accepted in [false, true] {
                    let mut viewer = ViewerVoice::fixture(pending, active, true);
                    let mut peer = Peer::default();
                    assert!(viewer.receive(&mut peer, new_voice_call_close()).await);
                    let cancelled = viewer.voice_call_request_timestamp.is_none();
                    assert!(viewer.receive(&mut peer, new_voice_call_response(42, accepted)).await);
                    let effects = viewer.handler.0.borrow();
                    let expected: Vec<&str> = if pending || active { vec!["closed:"] } else { Vec::new() };
                    let case_correct = cancelled && viewer.voice_call_request_timestamp.is_none()
                        && viewer.voice_call_audio.is_none() && effects.starts == 0
                        && effects.stops == usize::from(active) && effects.events == expected
                        && peer.sent.is_empty();
                    println!("VIEWER_VOICE_REMOTE_CASE=observed pending={pending} active={active} accepted={accepted} cancelled={cancelled} callbacks={} starts={} stops={} correct={case_correct}",
                        effects.events.len(), effects.starts, effects.stops);
                    correct &= case_correct;
                }
            }
        }
        assert!(correct, "remote close failed to retire the current pending voice request");
        println!("VIEWER_VOICE_REMOTE=pass cases=8 pending=retired active=stopped empty=quiet late_reply=ignored");
    }

    struct ClockRestore(i64);
    impl ClockRestore {
        fn fixed() -> Self { Self(TEST_VOICE_CLOCK.swap(1234, Ordering::Relaxed)) }
    }
    impl Drop for ClockRestore {
        fn drop(&mut self) { TEST_VOICE_CLOCK.store(self.0, Ordering::Relaxed); }
    }

    #[test]
    fn viewer_voice_request_ids_ignore_clock_changes_and_share_process_ownership() {
        let _clock = ClockRestore::fixed();
        let mut ids = std::collections::HashSet::new();
        let mut correct = true;
        for clock in [1234, 1234, -500, 0, 1234] {
            TEST_VOICE_CLOCK.store(clock, Ordering::Relaxed);
            let request = new_voice_call_request();
            let id = request.as_ref().map(|(id, _)| id.get()).unwrap_or(0);
            let case_correct = request.map(|(_, message)| {
                message.voice_call_request().is_connect
                    && message.voice_call_request().req_timestamp == id
                    && id > 0 && ids.insert(id)
            }).unwrap_or(false);
            println!("VIEWER_VOICE_REQUEST_CLOCK_CASE=observed clock={clock} id={id} correct={case_correct}");
            correct &= case_correct;
        }
        TEST_VOICE_CLOCK.store(1234, Ordering::Relaxed);
        let workers: Vec<_> = (0..4).map(|_| std::thread::spawn(|| {
            (0..16).map(|_| {
                let (id, message) = new_voice_call_request().expect("available process request ID");
                assert_eq!(message.voice_call_request().req_timestamp, id.get());
                assert!(message.voice_call_request().is_connect);
                id.get()
            }).collect::<Vec<_>>()
        })).collect();
        let concurrent: Vec<_> = workers.into_iter().flat_map(|worker| worker.join().unwrap()).collect();
        let unique: std::collections::HashSet<_> = concurrent.iter().copied().collect();
        let disjoint = unique.is_disjoint(&ids);
        let concurrent_correct = unique.len() == 64 && disjoint && concurrent.iter().all(|id| *id > 0);
        println!("VIEWER_VOICE_REQUEST_THREADS=observed messages={} unique={} disjoint={disjoint} correct={concurrent_correct}", concurrent.len(), unique.len());
        assert!(correct && concurrent_correct, "voice request IDs depend on clock or repeat across callers");
        println!("VIEWER_VOICE_REQUEST_IDS=pass clocks=5 threads=4 requests=64 namespace=process-wide workers=joined");
    }

    #[test]
    fn viewer_voice_request_id_exhaustion_never_wraps_or_mutates_refusal() {
        let _clock = ClockRestore::fixed();
        let mut correct = true;
        for (case, initial, expected_first, expected_second, expected_last) in [
            ("origin", 0, 1, 2, 2),
            ("last", i64::MAX - 1, i64::MAX, 0, i64::MAX),
            ("negative", -1, 0, 0, -1),
            ("minimum", i64::MIN, 0, 0, i64::MIN),
        ] {
            let counter = AtomicI64::new(initial);
            let first = allocate_voice_call_request_id(&counter).map(NonZeroI64::get).unwrap_or(0);
            let second = allocate_voice_call_request_id(&counter).map(NonZeroI64::get).unwrap_or(0);
            let last = counter.load(Ordering::Relaxed);
            let case_correct = (first, second, last) == (expected_first, expected_second, expected_last);
            println!("VIEWER_VOICE_REQUEST_ALLOC_CASE=observed case={case} first={first} second={second} retained={last} correct={case_correct}");
            correct &= case_correct;
        }
        assert!(correct, "voice request allocation wrapped, repeated or changed a refusing counter");
        println!("VIEWER_VOICE_REQUEST_ALLOC=pass cases=4 exhaustion=refused negative=refused last_positive=usable");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn viewer_voice_new_request_preserves_pending_and_active_owners() {
        let _clock = ClockRestore::fixed();
        let mut correct = true;
        for (case, pending, active) in [("empty", false, false), ("pending", true, false),
            ("active", false, true), ("both", true, true)]
        {
            let mut viewer = ViewerVoice::fixture(pending, active, true);
            let before = viewer.voice_call_request_timestamp;
            let mut peer = Peer::default();
            assert!(viewer.request(&mut peer).await);
            let first = viewer.voice_call_request_timestamp;
            if !pending && !active { assert!(viewer.request(&mut peer).await); }
            let effects = viewer.handler.0.borrow();
            let retained = if pending || active { viewer.voice_call_request_timestamp == before }
                else { first.is_some() && viewer.voice_call_request_timestamp == first };
            let expected_events: Vec<&str> = if pending || active { Vec::new() } else { vec!["waiting"] };
            let case_correct = retained && viewer.voice_call_audio.is_some() == active
                && peer.sent.len() == usize::from(!pending && !active)
                && effects.events == expected_events && effects.starts == 0 && effects.stops == 0;
            if !pending && !active && !peer.sent.is_empty() {
                assert_eq!(peer.sent[0].voice_call_request().req_timestamp, first.unwrap().get());
                assert!(peer.sent[0].voice_call_request().is_connect);
            }
            println!("VIEWER_VOICE_REQUEST_OWNER_CASE=observed case={case} requests={} callbacks={} retained={retained} correct={case_correct}", peer.sent.len(), effects.events.len());
            correct &= case_correct;
        }
        assert!(correct, "a new voice command replaced an existing pending/active owner");
        println!("VIEWER_VOICE_REQUEST_OWNER=pass cases=4 idle=usable repeated=quiet pending=preserved active=preserved");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn viewer_voice_cancel_retry_ignores_the_retired_request_reply() {
        let _clock = ClockRestore::fixed();
        let mut correct = true;
        for old_accept in [false, true] {
            for accepted in [false, true] {
                let mut viewer = ViewerVoice::fixture(false, false, true);
                let mut peer = Peer::default();
                assert!(viewer.request(&mut peer).await);
                let first = viewer.voice_call_request_timestamp.unwrap();
                viewer.manual_close(&mut peer).await;
                assert!(viewer.request(&mut peer).await);
                let second = viewer.voice_call_request_timestamp.unwrap();
                assert!(viewer.receive(&mut peer, new_voice_call_response(first.get(), old_accept)).await);
                let retained = viewer.voice_call_request_timestamp == Some(second)
                    && viewer.voice_call_audio.is_none() && viewer.handler.0.borrow().events.len() == 3;
                assert!(viewer.receive(&mut peer, new_voice_call_response(second.get(), accepted)).await);
                let effects = viewer.handler.0.borrow();
                let terminal = if accepted { "started" } else { "closed:" };
                let case_correct = first != second && retained && viewer.voice_call_request_timestamp.is_none()
                    && viewer.voice_call_audio.is_some() == accepted && effects.starts == usize::from(accepted)
                    && effects.events == ["waiting", "closed:Closed manually by the peer", "waiting", terminal]
                    && peer.sent.len() == 3;
                println!("VIEWER_VOICE_REQUEST_RETRY_CASE=observed old_accept={old_accept} accepted={accepted} distinct={} retained={retained} starts={} callbacks={} correct={case_correct}",
                    first != second, effects.starts, effects.events.len());
                correct &= case_correct;
            }
        }
        assert!(correct, "a retired voice reply completed the next request");
        println!("VIEWER_VOICE_REQUEST_RETRY=pass cases=4 clock=frozen retired=ignored current=usable");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn viewer_voice_request_send_failure_retires_before_late_reply() {
        let _clock = ClockRestore::fixed();
        let mut viewer = ViewerVoice::fixture(false, false, true);
        let mut peer = Peer { fail: true, ..Default::default() };
        let round = viewer.request(&mut peer).await;
        assert_eq!(peer.attempted.len(), 1);
        let failed_id = peer.attempted[0].voice_call_request().req_timestamp;
        let retired = viewer.voice_call_request_timestamp.is_none();
        assert!(viewer.receive(&mut peer, new_voice_call_response(failed_id, true)).await);
        let mut fresh = ViewerVoice::fixture(false, false, true);
        let mut fresh_peer = Peer::default();
        assert!(fresh.request(&mut fresh_peer).await);
        let fresh_distinct = fresh.voice_call_request_timestamp.unwrap().get() != failed_id;
        let effects = viewer.handler.0.borrow();
        let correct = !round && retired && viewer.voice_call_request_timestamp.is_none()
            && viewer.voice_call_audio.is_none() && effects.starts == 0 && peer.sent.is_empty()
            && effects.events == ["closed:Failed to send voice-call request"] && fresh_distinct
            && fresh.handler.0.borrow().events == ["waiting"];
        println!("VIEWER_VOICE_REQUEST_SEND_CASE=observed round={round} retired={retired} starts={} callbacks={} fresh_distinct={fresh_distinct} correct={correct}",
            effects.starts, effects.events.len());
        assert!(correct, "a failed request remained pending or reported waiting/success");
        println!("VIEWER_VOICE_REQUEST_SEND=pass attempts=1 pending=retired waiting=absent round=failed fresh=usable");
    }
}
