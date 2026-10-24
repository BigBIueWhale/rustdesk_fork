// Production registry, voice receivers and FFI over real CM mailboxes.
// Controlled replacement schedules do not execute native CM IPC or audio effects.
#[cfg(test)]
mod voice_tests {
    use super::*;
    use super::chat_tests::{admit, client};
    use crate::{CmEgressItem, CmEgressReceiver};

    #[derive(Clone, Copy, Debug)]
    enum Action { Accept, Dismiss, Stop }

    impl Action {
        fn send(self, owner: CmClientOwner) -> bool { self.send_call(owner, 42) }

        fn send_call(self, owner: CmClientOwner, call_id: i64) -> bool {
            match self {
                Self::Accept => crate::cm_handle_incoming_voice_call(owner.id, owner.generation, call_id, true),
                Self::Dismiss => crate::cm_handle_incoming_voice_call(owner.id, owner.generation, call_id, false),
                Self::Stop => crate::cm_close_voice_call(owner.id, owner.generation, call_id),
            }
        }

        fn name(self) -> &'static str {
            match self { Self::Accept => "accept", Self::Dismiss => "dismiss", Self::Stop => "stop" }
        }
    }

    fn queued(receiver: &mut CmEgressReceiver) -> Vec<&'static str> {
        queued_calls(receiver).into_iter().map(|(action, id)| {
            assert_eq!(id, 42);
            action
        }).collect()
    }

    fn queued_calls(receiver: &mut CmEgressReceiver) -> Vec<(&'static str, i64)> {
        let mut messages = Vec::new();
        while let Some(item) = receiver.take_next().expect("healthy CM mailbox") {
            match item {
                CmEgressItem::Data(Data::VoiceCallCommand(ipc::CmVoiceCallCommand::Respond { call_id, accept })) => {
                    messages.push((if accept { "accept" } else { "dismiss" }, call_id));
                }
                CmEgressItem::Data(Data::VoiceCallCommand(ipc::CmVoiceCallCommand::Stop { call_id })) => {
                    messages.push(("stop", call_id));
                }
                CmEgressItem::Data(Data::Close) => {}, // Exact predecessor retirement.
                _ => panic!("unexpected CM voice output"),
            }
        }
        messages
    }

    fn phase(owner: CmClientOwner, action: Action, call_id: i64) {
        let mut clients = CLIENTS.write().unwrap();
        let client = clients.current_mut(owner).unwrap();
        client.voice_call_id = call_id;
        client.incoming_voice_call = !matches!(action, Action::Stop);
        client.in_voice_call = matches!(action, Action::Stop);
    }

    #[test]
    fn cm_voice_actions_require_current_call_and_phase() {
        let mut all_correct = true;
        for action in [Action::Accept, Action::Dismiss, Action::Stop] {
            let mut admitted = 0;
            let mut correct_cases = 0;
            for conn_type in [ipc::CmAuthConnType::Remote, ipc::CmAuthConnType::ViewCamera] {
                for state in ["idle", "incoming", "active"] {
                    for call_id in [0, -1, 41, 42, 43, i64::MAX] {
                        *CLIENTS.write().unwrap() = CmClientRegistry::default();
                        let (mut current, mut receiver) = client(7, "current", conn_type);
                        let owner = admit(&mut current, 1);
                        if state != "idle" {
                            let mut registry = CLIENTS.write().unwrap();
                            assert!(registry.update_voice_call(owner, ipc::CmVoiceCallEvent::Incoming { call_id: 42 }).is_some());
                            if state == "active" {
                                assert!(registry.update_voice_call(owner, ipc::CmVoiceCallEvent::Started { call_id: 42 }).is_some());
                            }
                        }
                        let reported = action.send_call(owner, call_id);
                        let queued = queued_calls(&mut receiver);
                        admitted += usize::from(reported);
                        let expected = call_id == 42 && state == if matches!(action, Action::Stop) { "active" } else { "incoming" };
                        let correct = reported == expected && queued == if expected { vec![(action.name(), call_id)] } else { Vec::new() };
                        correct_cases += usize::from(correct);
                        all_correct &= correct;
                    }
                }
            }
            println!("CM_VOICE_CALL_ACTION_CASE=observed action={} cases=36 admitted={admitted} expected=2 correct_cases={correct_cases}", action.name());
        }
        assert!(all_correct);
        println!("CM_VOICE_CALL_ACTION=pass cases=108 identity=exact phase=exact invalid=refused queues=real");
    }

    #[test]
    fn cm_voice_events_require_current_call_and_transition() {
        let mut all_correct = true;
        for event_name in ["incoming", "started", "closed"] {
            let mut admitted = 0;
            let mut correct_cases = 0;
            for conn_type in [ipc::CmAuthConnType::Remote, ipc::CmAuthConnType::ViewCamera] {
                for state in ["idle", "incoming", "active"] {
                    for call_id in [0, -1, 41, 42, 43, i64::MAX] {
                        let mut registry = CmClientRegistry::default();
                        let (mut current, _receiver) = client(7, "current", conn_type);
                        let owner = registry.admit(&mut current, 1).unwrap().0;
                        let current = registry.current_mut(owner).unwrap();
                        current.last_voice_call_id = if state == "idle" { 41 } else { 42 };
                        current.voice_call_id = if state == "idle" { 0 } else { 42 };
                        current.incoming_voice_call = state == "incoming";
                        current.in_voice_call = state == "active";
                        let before = (current.voice_call_id, current.last_voice_call_id, current.incoming_voice_call, current.in_voice_call);
                        let event = match event_name {
                            "incoming" => ipc::CmVoiceCallEvent::Incoming { call_id },
                            "started" => ipc::CmVoiceCallEvent::Started { call_id },
                            _ => ipc::CmVoiceCallEvent::Closed { call_id, reason: String::new() },
                        };
                        let reported = registry.update_voice_call(owner, event).is_some();
                        admitted += usize::from(reported);
                        let expected = match event_name {
                            "incoming" => state == "idle" && call_id > 41,
                            "started" => state == "incoming" && call_id == 42,
                            _ => state != "idle" && call_id == 42,
                        };
                        let current = registry.current_mut(owner).unwrap();
                        let after = (current.voice_call_id, current.last_voice_call_id, current.incoming_voice_call, current.in_voice_call);
                        let wanted = if !expected { before } else { match event_name {
                            "incoming" => (call_id, call_id, true, false),
                            "started" => (42, 42, false, true),
                            _ => (0, 42, false, false),
                        }};
                        let correct = reported == expected && after == wanted;
                        correct_cases += usize::from(correct);
                        all_correct &= correct;
                    }
                }
            }
            println!("CM_VOICE_CALL_EVENT_CASE=observed event={event_name} cases=36 admitted={admitted} correct_cases={correct_cases}");
        }
        assert!(all_correct);
        println!("CM_VOICE_CALL_EVENT=pass cases=108 incoming=fresh started=matching-pending closed=matching replay=refused state=preserved");
    }

    #[test]
    fn cm_voice_current_owners_keep_actions_and_allowed_types() {
        for conn_type in [ipc::CmAuthConnType::Remote, ipc::CmAuthConnType::ViewCamera] {
            *CLIENTS.write().unwrap() = CmClientRegistry::default();
            let (mut current, mut receiver) = client(7, "current", conn_type);
            let owner = admit(&mut current, 1);
            let (mut sibling, mut sibling_receiver) = client(8, "sibling", conn_type);
            let sibling_owner = admit(&mut sibling, 1);
            for action in [Action::Accept, Action::Dismiss, Action::Stop] {
                phase(owner, action, 42);
                assert!(action.send(owner));
                assert_eq!(queued(&mut receiver), [action.name()]);
                assert!(queued(&mut sibling_receiver).is_empty());
                assert!(CLIENTS.read().unwrap().is_current(owner));
                assert!(CLIENTS.read().unwrap().is_current(sibling_owner));
            }
        }
        println!("CM_VOICE_CONTROLS=pass actions=3 conn_types=2 messages=6 siblings=preserved registry=production ffi=production queues=real");
    }

    #[test]
    fn cm_voice_requires_exact_live_owner_and_truthful_admission() {
        let mut correct = true;
        for action in [Action::Accept, Action::Dismiss, Action::Stop] {
            for case in ["zero-generation", "negative-generation", "wrong-generation", "missing-id",
                "pending", "disconnected", "reused", "file-transfer", "terminal", "port-forward",
                "receiver-gone", "saturated", "aborted-control", "accepted-control"]
            {
                *CLIENTS.write().unwrap() = CmClientRegistry::default();
                let conn_type = match case {
                    "file-transfer" => ipc::CmAuthConnType::FileTransfer,
                    "terminal" => ipc::CmAuthConnType::Terminal,
                    "port-forward" => ipc::CmAuthConnType::PortForward,
                    _ => ipc::CmAuthConnType::Remote,
                };
                let (mut current, receiver) = client(7, "current", conn_type);
                let mut receiver = Some(receiver);
                if case == "saturated" {
                    let (sender, limited_receiver) = crate::cm_egress_channel_with_limits(
                        crate::CmEgressLimits { max_messages: 0, ..crate::CM_EGRESS_LIMITS });
                    current.tx = sender;
                    receiver = Some(limited_receiver);
                }
                let owner = admit(&mut current, 1);
                phase(owner, action, 42);
                let (mut replacement, mut replacement_receiver) = client(7, "replacement", ipc::CmAuthConnType::Remote);
                let mut pending = if case == "pending" || case == "aborted-control" {
                    Some(CLIENTS.write().unwrap().prepare_admission(&mut replacement, 2).unwrap())
                } else { None };
                if case == "aborted-control" {
                    CLIENTS.write().unwrap().abort_admission(pending.take().unwrap());
                } else if case == "disconnected" {
                    assert!(CLIENTS.write().unwrap().retire(owner, false));
                } else if case == "reused" {
                    admit(&mut replacement, 2);
                } else if case == "receiver-gone" {
                    drop(receiver.take());
                }
                let requested = CmClientOwner {
                    id: if case == "missing-id" { 404 } else { owner.id },
                    generation: match case {
                        "zero-generation" => 0,
                        "negative-generation" => -1,
                        "wrong-generation" => owner.generation + 1,
                        _ => owner.generation,
                    },
                };
                let reported = action.send(requested);
                let old = if case == "saturated" {
                    assert!(matches!(receiver.as_mut().unwrap().take_next().unwrap(),
                        Some(CmEgressItem::Failed(crate::CmEgressFailure::MessageCapacity))));
                    Vec::new()
                } else if let Some(receiver) = receiver.as_mut() { queued(receiver) } else { Vec::new() };
                let new = queued(&mut replacement_receiver);
                if case == "pending" { CLIENTS.write().unwrap().abort_admission(pending.take().unwrap()); }
                let expected = case == "accepted-control" || case == "aborted-control";
                let case_correct = reported == expected && new.is_empty()
                    && old == if expected { vec![action.name()] } else { Vec::new() };
                println!("CM_VOICE_OWNER_CASE=observed action={} case={case} reported={reported} old={} new={} expected={expected} correct={case_correct}",
                    action.name(), old.len(), new.len());
                correct &= case_correct;
            }
        }
        assert!(correct, "CM voice selected a stale/forbidden owner or misreported admission");
        println!("CM_VOICE_OWNER=pass actions=3 cases=42 invalid=refused pending=refused stale=refused disconnected=refused type=confined queue=truthful fresh=usable");
    }

    #[test]
    fn cm_voice_delayed_actions_never_retarget_replacements() {
        let mut correct = true;
        for action in [Action::Accept, Action::Dismiss, Action::Stop] {
            *CLIENTS.write().unwrap() = CmClientRegistry::default();
            let (mut first, mut first_receiver) = client(7, "first", ipc::CmAuthConnType::Remote);
            let first_owner = admit(&mut first, 1);
            phase(first_owner, action, 42);
            let (mut replacement, mut replacement_receiver) = client(7, "replacement", ipc::CmAuthConnType::Remote);
            let mut registry = CLIENTS.write().unwrap();
            let (ready, started) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                ready.send(()).unwrap();
                action.send(first_owner)
            });
            started.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
            let replacement_owner = registry.admit(&mut replacement, 2).unwrap().0;
            let client = registry.current_mut(replacement_owner).unwrap();
            client.voice_call_id = 42;
            client.incoming_voice_call = !matches!(action, Action::Stop);
            client.in_voice_call = matches!(action, Action::Stop);
            drop(registry);
            let stale_admitted = worker.join().unwrap();
            let fresh = action.send(replacement_owner);
            let old = queued(&mut first_receiver);
            let new = queued(&mut replacement_receiver);
            let case_correct = !stale_admitted && fresh && old.is_empty() && new == [action.name()];
            println!("CM_VOICE_DELAYED_CASE=observed action={} stale_admitted={stale_admitted} fresh={fresh} old={} new={} correct={case_correct}",
                action.name(), old.len(), new.len());
            correct &= case_correct;
        }
        assert!(correct, "a delayed voice command selected a successor mailbox");
        println!("CM_VOICE_DELAYED=pass actions=3 replacement=observed stale=refused successor=preserved fresh=usable workers=joined");
    }
}
