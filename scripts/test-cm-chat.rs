// Exact production registry, FFI forwarding and sender over real CM mailboxes.
// Registry schedules are controlled; no native IPC or peer transport runs.
#[cfg(test)]
mod chat_tests {
    use super::*;
    use crate::{cm_egress_channel, CmEgressItem, CmEgressReceiver};

    fn client(id: i32, peer: &str, conn_type: ipc::CmAuthConnType) -> (Client, CmEgressReceiver) {
        let (tx, receiver) = cm_egress_channel();
        (Client {
            id,
            registry_generation: 0,
            authorized: true,
            disconnected: false,
            is_file_transfer: conn_type == ipc::CmAuthConnType::FileTransfer,
            is_view_camera: conn_type == ipc::CmAuthConnType::ViewCamera,
            is_terminal: conn_type == ipc::CmAuthConnType::Terminal,
            port_forward: String::new(),
            conn_type,
            name: peer.to_owned(),
            avatar: String::new(),
            peer_id: peer.to_owned(),
            keyboard: true,
            clipboard: true,
            audio: true,
            file: true,
            privacy_mode: false,
            in_voice_call: false,
            incoming_voice_call: false,
            source_generation: 0,
            cm_auth_token: "synthetic-owned-chat".to_owned(),
            tx,
        }, receiver)
    }

    fn admit(client: &mut Client, source: u64) -> CmClientOwner {
        CLIENTS.write().unwrap().admit(client, source).unwrap().0
    }

    fn queued(receiver: &mut CmEgressReceiver) -> Vec<String> {
        let mut messages = Vec::new();
        while let Some(item) = receiver.take_next().expect("healthy CM mailbox") {
            match item {
                CmEgressItem::Data(ipc::Data::ChatMessage { text }) => messages.push(text),
                _ => panic!("unexpected CM chat output"),
            }
        }
        messages
    }

    fn observe(case: &str, receiver: &mut CmEgressReceiver, expected: &[&str]) -> bool {
        let actual = queued(receiver);
        let correct = actual == expected;
        println!("CM_CHAT_OWNER_CASE=observed case={case} queued={} expected={} correct={correct}",
            actual.len(), expected.len());
        correct
    }

    #[test]
    fn cm_chat_current_owners_keep_payloads_and_session_types() {
        *CLIENTS.write().unwrap() = CmClientRegistry::default();
        for (index, conn_type) in [ipc::CmAuthConnType::Remote, ipc::CmAuthConnType::FileTransfer,
            ipc::CmAuthConnType::ViewCamera, ipc::CmAuthConnType::Terminal,
            ipc::CmAuthConnType::PortForward].into_iter().enumerate()
        {
            let (mut client, mut receiver) = client(7 + index as i32, "peer", conn_type);
            let owner = admit(&mut client, 1);
            assert!(owner.generation > 0);
            for text in ["  exact text  ", "unicode \u{05e9}\u{05dc}\u{05d5}\u{05dd}\nnext line"] {
                crate::cm_send_chat(owner.id, owner.generation, text.to_owned());
            }
            assert_eq!(queued(&mut receiver), ["  exact text  ", "unicode \u{05e9}\u{05dc}\u{05d5}\u{05dd}\nnext line"]);
            let registry = CLIENTS.read().unwrap();
            assert!(registry.is_current(owner));
            assert_eq!(registry.clients[&owner.id].conn_type, conn_type);
            assert!(!registry.clients[&owner.id].disconnected);
        }
        println!("CM_CHAT_CONTROLS=pass conn_types=5 payloads=10 registry=production bridge=production queue=production");
    }

    #[test]
    fn cm_chat_requires_current_owner_during_admission_and_reuse() {
        *CLIENTS.write().unwrap() = CmClientRegistry::default();
        let (mut first, mut first_receiver) = client(7, "first-peer", ipc::CmAuthConnType::Remote);
        let first_owner = admit(&mut first, 1);
        let mut correct = true;
        for generation in [0, -1, first_owner.generation + 1] {
            crate::cm_send_chat(7, generation, "invalid-generation".to_owned());
        }
        crate::cm_send_chat(7, first_owner.generation, "fresh-first".to_owned());
        correct &= observe("invalid-generation", &mut first_receiver, &["fresh-first"]);

        let (mut replacement, mut replacement_receiver) = client(7, "replacement-peer", ipc::CmAuthConnType::Remote);
        let pending = CLIENTS.write().unwrap().prepare_admission(&mut replacement, 2).unwrap();
        crate::cm_send_chat(7, first_owner.generation, "pending-admission".to_owned());
        correct &= observe("pending-admission", &mut first_receiver, &[]);
        CLIENTS.write().unwrap().abort_admission(pending);
        crate::cm_send_chat(7, first_owner.generation, "after-abort".to_owned());
        correct &= observe("aborted-admission-control", &mut first_receiver, &["after-abort"]);

        assert!(CLIENTS.write().unwrap().retire(first_owner, false));
        crate::cm_send_chat(7, first_owner.generation, "disconnected".to_owned());
        correct &= observe("disconnected", &mut first_receiver, &[]);
        let replacement_owner = admit(&mut replacement, 3);
        assert!(replacement_owner.generation > first_owner.generation);
        crate::cm_send_chat(7, first_owner.generation, "stale-first".to_owned());
        crate::cm_send_chat(7, replacement_owner.generation, "fresh-replacement".to_owned());
        correct &= observe("reused-id", &mut replacement_receiver, &["fresh-replacement"]);
        crate::cm_send_chat(404, replacement_owner.generation, "missing-id".to_owned());
        correct &= observe("missing-id-control", &mut replacement_receiver, &[]);
        assert!(queued(&mut first_receiver).is_empty());
        assert!(correct, "CM chat command selected an unowned registry generation");
        println!("CM_CHAT_OWNER=pass cases=6 invalid=refused pending=refused disconnected=refused reused_id=exact fresh=usable");
    }

    #[test]
    fn cm_chat_delayed_command_refuses_after_registry_replacement() {
        *CLIENTS.write().unwrap() = CmClientRegistry::default();
        let (mut first, mut first_receiver) = client(7, "first-peer", ipc::CmAuthConnType::Remote);
        let first_owner = admit(&mut first, 1);
        let (mut replacement, mut replacement_receiver) = client(7, "replacement-peer", ipc::CmAuthConnType::Remote);
        let mut registry = CLIENTS.write().unwrap();
        let (ready, started) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            ready.send(()).unwrap();
            crate::cm_send_chat(first_owner.id, first_owner.generation, "delayed-first".to_owned());
        });
        started.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        let replacement_owner = registry.admit(&mut replacement, 2).unwrap().0;
        drop(registry);
        worker.join().unwrap();
        crate::cm_send_chat(7, replacement_owner.generation, "fresh-after-delay".to_owned());
        let old = queued(&mut first_receiver);
        let fresh = queued(&mut replacement_receiver);
        let correct = old.is_empty() && fresh == ["fresh-after-delay"];
        println!("CM_CHAT_DELAYED_CASE=observed old_queued={} fresh_queued={} expected_fresh=1 correct={correct}", old.len(), fresh.len());
        assert!(correct, "delayed chat command was retargeted to the replacement");
        println!("CM_CHAT_DELAYED=pass ready=observed registry=replaced queues=exact worker=joined");
    }
}
