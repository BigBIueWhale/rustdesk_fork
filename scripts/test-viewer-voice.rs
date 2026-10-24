// Exact production viewer branches and stop method; audio and transport are explicit doubles.
// No physical capture, complete IoLoop, native IPC or authenticated peer runs here.
use crate::message_proto::{message, Message, VoiceCallRequest, VoiceCallResponse};
use std::{cell::RefCell, num::NonZeroI64, rc::Rc};

#[derive(Default)]
struct Effects { starts: usize, stops: usize, events: Vec<String> }

struct VoiceCallAudio(Rc<RefCell<Effects>>);
impl VoiceCallAudio {
    fn stop(&mut self) { self.0.borrow_mut().stops += 1; }
}

struct Handler(Rc<RefCell<Effects>>);
impl Handler {
    fn on_voice_call_started(&self) { self.0.borrow_mut().events.push("started".into()); }
    fn on_voice_call_closed(&self, reason: &str) {
        self.0.borrow_mut().events.push(format!("closed:{reason}"));
    }
}

#[derive(Default)]
struct Peer { sent: Vec<Message> }
impl Peer {
    async fn send(&mut self, message: &Message) -> Result<(), &'static str> {
        self.sent.push(message.clone());
        Ok(())
    }
}

enum Data { CloseVoiceCall }
// The unchanged constructors use this explicit clock double. Request-ID generation is untested.
fn get_time() -> i64 { 1234 }
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
                    assert!(viewer.receive(&mut peer, new_voice_call_request(false)).await);
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
}
