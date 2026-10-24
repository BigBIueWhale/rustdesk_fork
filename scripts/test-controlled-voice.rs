// Exact receiver/type predicates and CM sender; post-auth identity, input-lease
// presence and clock are explicit doubles. No full server, CPace, IPC or audio runs.
use crate::{ipc::{self, Data}, message_proto::{message, Message, VoiceCallRequest}};
use futures::FutureExt;
use crate::viewer_voice::new_voice_call_close;
use std::{num::NonZeroI64, panic::AssertUnwindSafe, sync::atomic::{AtomicI64, Ordering}};
use tokio::{sync::mpsc, time::{self, Duration}};

static TEST_CLOCK: AtomicI64 = AtomicI64::new(1234);
fn get_time() -> i64 { TEST_CLOCK.load(Ordering::Relaxed) }

struct TestAuthedConnId(AuthConnType);
impl TestAuthedConnId {
    fn conn_type(&self) -> AuthConnType { self.0 }
}
struct TestInner;
impl TestInner { fn id(&self) -> i32 { 17 } }

struct ControlledVoice {
    authed_conn_id: Option<TestAuthedConnId>,
    voice_call_request_timestamp: Option<NonZeroI64>,
    voice_call_input: Option<()>,
    voice_call_id: i64,
    voice_call_generation: i64,
    responses: usize,
    sent: Vec<Message>,
    tx_to_cm: mpsc::Sender<Data>,
    cm_command_failure: Option<String>,
    inner: TestInner,
    close_calls: usize,
}
impl ControlledVoice {
    fn fixture(kind: Option<AuthConnType>) -> (Self, mpsc::Receiver<Data>) {
        let (tx_to_cm, rx) = mpsc::channel(1);
        (Self {
            authed_conn_id: kind.map(TestAuthedConnId),
            voice_call_request_timestamp: None, voice_call_input: None,
            tx_to_cm, cm_command_failure: None, inner: TestInner, close_calls: 0,
            voice_call_id: 0, voice_call_generation: 0, responses: 0, sent: Vec::new(),
        }, rx)
    }
    // Effect doubles model state changes; no audio lease, native cleanup or transport runs.
    async fn close_voice_call(&mut self) -> bool {
        self.close_calls += 1;
        let owned = self.voice_call_input.is_some() || self.voice_call_request_timestamp.is_some();
        self.voice_call_input = None;
        self.voice_call_request_timestamp = None;
        self.voice_call_id = 0;
        owned
    }
    async fn handle_voice_call(&mut self, accepted: bool) {
        self.responses += 1;
        if self.voice_call_request_timestamp.take().is_some() {
            self.voice_call_input = accepted.then_some(());
            if !accepted { self.voice_call_id = 0; }
        }
    }
    async fn send(&mut self, message: Message) { self.sent.push(message); }
    // Cleanup effects remain outside the component; check the actual caller's policy.
    async fn on_close(&mut self, reason: &str, lock: bool) {
        assert_eq!(reason, "connection-manager voice request publication failed");
        assert!(!lock);
    }
}
include!(env!("CONTROLLED_VOICE_TYPES"));
include!(env!("CONTROLLED_VOICE_RECEIVE"));
include!(env!("CONTROLLED_VOICE_SEND"));
include!(env!("CONTROLLED_VOICE_COMMAND"));

#[cfg(test)]
mod tests {
    use super::*;

    fn request(id: i64) -> Message {
        let mut message = Message::new();
        message.set_voice_call_request(VoiceCallRequest {
            is_connect: true, req_timestamp: id, ..Default::default()
        });
        message
    }
    fn drain(rx: &mut mpsc::Receiver<Data>) -> Vec<Data> {
        let mut items = Vec::new();
        while let Ok(item) = rx.try_recv() { items.push(item); }
        items
    }
    fn unchanged(voice: &ControlledVoice, pending: i64, active: bool) -> bool {
        voice.voice_call_request_timestamp.map(NonZeroI64::get).unwrap_or(0) == pending
            && voice.voice_call_input.is_some() == active
            && voice.cm_command_failure.is_none() && voice.close_calls == 0
    }

    #[tokio::test(flavor = "current_thread")]
    async fn controlled_voice_cm_commands_require_current_call_and_phase() {
        let mut all_correct = true;
        for action in ["accept", "dismiss", "stop"] {
            let mut calls = 0;
            let mut correct_cases = 0;
            for kind in [AuthConnType::Remote, AuthConnType::ViewCamera] {
                for phase in ["idle", "incoming", "active"] {
                    for call_id in [0, -1, 1, 2, 3, i64::MAX] {
                        let (mut voice, _rx) = ControlledVoice::fixture(Some(kind));
                        voice.voice_call_id = if phase == "idle" { 0 } else { 2 };
                        voice.voice_call_generation = 2;
                        voice.voice_call_request_timestamp = if phase == "incoming" { NonZeroI64::new(42) } else { None };
                        voice.voice_call_input = (phase == "active").then_some(());
                        let before = (voice.voice_call_id, voice.voice_call_request_timestamp, voice.voice_call_input);
                        let command = match action {
                            "stop" => ipc::CmVoiceCallCommand::Stop { call_id },
                            _ => ipc::CmVoiceCallCommand::Respond { call_id, accept: action == "accept" },
                        };
                        voice.handle_cm_voice_call(command).await;
                        let expected = call_id == 2 && phase == if action == "stop" { "active" } else { "incoming" };
                        let selected = voice.responses + voice.close_calls;
                        calls += selected;
                        let effects = if expected {
                            match action {
                                "accept" => voice.voice_call_input.is_some() && voice.voice_call_request_timestamp.is_none() && voice.voice_call_id == 2 && voice.sent.is_empty(),
                                "dismiss" => voice.voice_call_input.is_none() && voice.voice_call_request_timestamp.is_none() && voice.voice_call_id == 0 && voice.sent.is_empty(),
                                _ => voice.voice_call_input.is_none() && voice.voice_call_request_timestamp.is_none() && voice.voice_call_id == 0 && matches!(voice.sent.as_slice(), [Message { union: Some(message::Union::VoiceCallRequest(request)), .. }] if !request.is_connect),
                            }
                        } else {
                            (voice.voice_call_id, voice.voice_call_request_timestamp, voice.voice_call_input) == before && voice.sent.is_empty()
                        };
                        let correct = selected == usize::from(expected) && effects;
                        correct_cases += usize::from(correct);
                        all_correct &= correct;
                    }
                }
            }
            println!("CONTROLLED_VOICE_CALL_COMMAND_CASE=observed action={action} cases=36 selected={calls} expected=2 correct_cases={correct_cases}");
        }
        assert!(all_correct);
        println!("CONTROLLED_VOICE_CALL_COMMAND=pass cases=108 identity=exact phase=exact retired=quiet current=usable effects=doubles");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn controlled_voice_call_ids_are_connection_owned_and_never_wrap() {
        TEST_CLOCK.store(1234, Ordering::Relaxed);
        for kind in [AuthConnType::Remote, AuthConnType::ViewCamera] {
            let (mut voice, mut rx) = ControlledVoice::fixture(Some(kind));
            for call_id in [1, 2, 3] {
                assert!(voice.receive(request(42)).await);
                assert_eq!(voice.voice_call_id, call_id);
                assert_eq!(voice.voice_call_request_timestamp, NonZeroI64::new(42));
                assert!(matches!(drain(&mut rx).as_slice(), [Data::VoiceCallEvent(ipc::CmVoiceCallEvent::Incoming { call_id: observed })] if *observed == call_id));
                assert!(voice.close_voice_call().await);
            }
            voice.voice_call_generation = i64::MAX - 1;
            assert!(voice.receive(request(42)).await);
            assert_eq!(voice.voice_call_id, i64::MAX);
            assert!(matches!(drain(&mut rx).as_slice(), [Data::VoiceCallEvent(ipc::CmVoiceCallEvent::Incoming { call_id: i64::MAX })]));
            assert!(voice.close_voice_call().await);
            for counter in [i64::MAX, -1, i64::MIN] {
                voice.voice_call_generation = counter;
                assert!(voice.receive(request(42)).await);
                assert_eq!(voice.voice_call_generation, counter);
                assert_eq!(voice.voice_call_id, 0);
                assert!(voice.voice_call_request_timestamp.is_none());
                assert!(voice.voice_call_input.is_none());
                assert!(drain(&mut rx).is_empty());
            }
        }
        println!("CONTROLLED_VOICE_CALL_IDS=pass types=2 repeated_peer_ids=6 last_positive=usable exhaustion=refused negative=refused namespace=connection-owned");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn controlled_voice_admission_preserves_positive_and_confined_controls() {
        TEST_CLOCK.store(1234, Ordering::Relaxed);
        for kind in [AuthConnType::Remote, AuthConnType::ViewCamera] {
            for id in [1, 42, i64::MAX] {
                let (mut voice, mut rx) = ControlledVoice::fixture(Some(kind));
                assert!(voice.receive(request(id)).await);
                assert!(unchanged(&voice, id, false));
                assert!(matches!(drain(&mut rx).as_slice(), [Data::VoiceCallEvent(ipc::CmVoiceCallEvent::Incoming { call_id: 1 })]));
            }
        }
        for kind in [None, Some(AuthConnType::FileTransfer), Some(AuthConnType::Terminal),
            Some(AuthConnType::PortForward)] {
            for id in [0, 42] {
                for clock in [0, 1234] {
                    TEST_CLOCK.store(clock, Ordering::Relaxed);
                    let (mut voice, mut rx) = ControlledVoice::fixture(kind);
                    assert!(voice.receive(request(id)).await);
                    assert!(unchanged(&voice, 0, false));
                    assert!(drain(&mut rx).is_empty());
                }
            }
        }
        TEST_CLOCK.store(0, Ordering::Relaxed);
        for kind in [AuthConnType::Remote, AuthConnType::ViewCamera] {
            for active in [false, true] {
                for id in [0, 42] {
                    let (mut voice, mut rx) = ControlledVoice::fixture(Some(kind));
                    voice.voice_call_request_timestamp = if active { None } else { NonZeroI64::new(41) };
                    voice.voice_call_input = active.then_some(());
                    assert!(voice.receive(request(id)).await);
                    assert!(unchanged(&voice, if active { 0 } else { 41 }, active));
                    assert!(drain(&mut rx).is_empty());
                }
            }
        }
        println!("CONTROLLED_VOICE_CONTROLS=pass positive=6 type_refusals=16 overlap=8 exact_id=preserved queues=real");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn controlled_voice_nonpositive_ids_never_invent_an_owner() {
        let mut all_correct = true;
        for kind in [AuthConnType::Remote, AuthConnType::ViewCamera] {
            for id in [0, -1, i64::MIN] {
                for clock in [1234, 0] {
                    TEST_CLOCK.store(clock, Ordering::Relaxed);
                    let (mut voice, mut rx) = ControlledVoice::fixture(Some(kind));
                    let result = AssertUnwindSafe(voice.receive(request(id))).catch_unwind().await;
                    let completed = result.is_ok();
                    let round = result.unwrap_or(false);
                    let queued = drain(&mut rx).len();
                    let pending = voice.voice_call_request_timestamp.map(NonZeroI64::get).unwrap_or(0);
                    let correct = completed && round && queued == 0 && unchanged(&voice, 0, false);
                    println!("CONTROLLED_VOICE_INVALID_CASE=observed kind={kind:?} id={id} clock={clock} completed={completed} round={round} pending={pending} queued={queued} correct={correct}");
                    all_correct &= correct;
                }
            }
        }
        assert!(all_correct);
        println!("CONTROLLED_VOICE_INVALID=pass cases=12 nonpositive=refused pending=absent notice=absent clock=irrelevant");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn controlled_voice_positive_ids_ignore_wall_clock() {
        TEST_CLOCK.store(0, Ordering::Relaxed);
        let mut all_correct = true;
        for kind in [AuthConnType::Remote, AuthConnType::ViewCamera] {
            for id in [1, 42, i64::MAX] {
                let (mut voice, mut rx) = ControlledVoice::fixture(Some(kind));
                let result = AssertUnwindSafe(voice.receive(request(id))).catch_unwind().await;
                let completed = result.is_ok();
                let round = result.unwrap_or(false);
                let messages = drain(&mut rx);
                let pending = voice.voice_call_request_timestamp.map(NonZeroI64::get).unwrap_or(0);
                let correct = completed && round && unchanged(&voice, id, false)
                    && matches!(messages.as_slice(), [Data::VoiceCallEvent(ipc::CmVoiceCallEvent::Incoming { call_id: 1 })]);
                println!("CONTROLLED_VOICE_CLOCK_CASE=observed kind={kind:?} id={id} clock=0 completed={completed} round={round} pending={pending} queued={} correct={correct}", messages.len());
                all_correct &= correct;
            }
        }
        assert!(all_correct);
        println!("CONTROLLED_VOICE_CLOCK=pass cases=6 positive=exact zero_clock=usable notice=once");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn controlled_voice_failed_cm_handoff_retires_pending() {
        TEST_CLOCK.store(1234, Ordering::Relaxed);
        let mut all_correct = true;
        for saturated in [false, true] {
            let (mut voice, rx) = ControlledVoice::fixture(Some(AuthConnType::Remote));
            let mut rx = if saturated {
                voice.tx_to_cm.try_send(Data::Empty).unwrap();
                Some(rx)
            } else { drop(rx); None };
            let started = time::Instant::now();
            let round = voice.receive(request(42)).await;
            let elapsed = started.elapsed();
            let pending = voice.voice_call_request_timestamp.map(NonZeroI64::get).unwrap_or(0);
            let messages = rx.as_mut().map(drain).unwrap_or_default();
            let expected_error = if saturated {
                "connection-manager command queue backpressure timed out"
            } else { "connection-manager command queue is closed" };
            let latched = voice.cm_command_failure.as_deref() == Some(expected_error);
            let preserved = if saturated { matches!(messages.as_slice(), [Data::Empty]) }
                else { messages.is_empty() };
            let deadline = !saturated || elapsed >= CM_COMMAND_QUEUE_SEND_TIMEOUT;
            let correct = !round && pending == 0 && latched && preserved && deadline
                && voice.voice_call_input.is_none() && voice.close_calls == 0;
            println!("CONTROLLED_VOICE_HANDOFF_CASE=observed saturated={saturated} round={round} pending={pending} latched={latched} preserved={preserved} deadline={deadline} correct={correct}");
            all_correct &= correct;
        }
        assert!(all_correct);
        println!("CONTROLLED_VOICE_HANDOFF=pass cases=2 closed=refused timeout=refused pending=retired latch=preserved queues=real deadline=production");
    }
}
