// Production registry, close/remove receivers and FFI over real CM mailboxes.
// Controlled replacement schedules do not execute native CM IPC or peer teardown.
#[cfg(test)]
mod disconnect_tests {
    use super::*;
    use super::chat_tests::{admit, client};
    use crate::{CmEgressItem, CmEgressReceiver};

    fn closes(receiver: &mut CmEgressReceiver) -> usize {
        let mut count = 0;
        while let Some(item) = receiver.take_next().expect("healthy CM mailbox") {
            assert!(matches!(item, CmEgressItem::Data(Data::Close)));
            count += 1;
        }
        count
    }

    fn present(owner: CmClientOwner) -> bool {
        CLIENTS.read().unwrap().record_is_current(owner)
    }

    #[test]
    fn cm_disconnect_current_owners_keep_all_session_types() {
        *CLIENTS.write().unwrap() = CmClientRegistry::default();
        let (mut sibling, mut sibling_receiver) = client(99, "sibling", ipc::CmAuthConnType::Remote);
        let sibling_owner = admit(&mut sibling, 1);
        for (index, conn_type) in [ipc::CmAuthConnType::Remote, ipc::CmAuthConnType::FileTransfer,
            ipc::CmAuthConnType::ViewCamera, ipc::CmAuthConnType::Terminal,
            ipc::CmAuthConnType::PortForward].into_iter().enumerate()
        {
            let (mut current, mut receiver) = client(7 + index as i32, "peer", conn_type);
            let owner = admit(&mut current, 1);
            crate::cm_remove_disconnected_connection(owner.id, owner.generation);
            assert!(present(owner), "active history must remain");
            crate::cm_close_connection(owner.id, owner.generation);
            assert_eq!(closes(&mut receiver), 1);
            assert!(present(owner), "queue submission does not retire the registry");
            assert!(CLIENTS.write().unwrap().retire(owner, false));
            crate::cm_remove_disconnected_connection(owner.id, owner.generation);
            assert!(!present(owner));
            assert!(present(sibling_owner));
            assert_eq!(closes(&mut sibling_receiver), 0);
        }
        println!("CM_DISCONNECT_CONTROLS=pass conn_types=5 closes=5 history_removals=5 active_history=preserved siblings=preserved");
    }

    #[test]
    fn cm_disconnect_requires_exact_live_owner() {
        let mut correct = true;
        for case in ["zero-generation", "negative-generation", "wrong-generation", "missing-id",
            "pending-admission", "disconnected", "reused-id", "aborted-admission-control"]
        {
            *CLIENTS.write().unwrap() = CmClientRegistry::default();
            let (mut first, mut first_receiver) = client(7, "first", ipc::CmAuthConnType::Remote);
            let first_owner = admit(&mut first, 1);
            let (mut replacement, mut replacement_receiver) = client(7, "replacement", ipc::CmAuthConnType::Remote);
            let mut current_owner = first_owner;
            let mut pending = None;
            if matches!(case, "pending-admission" | "aborted-admission-control") {
                pending = Some(CLIENTS.write().unwrap().prepare_admission(&mut replacement, 2).unwrap());
            } else if case == "disconnected" {
                assert!(CLIENTS.write().unwrap().retire(first_owner, false));
            } else if case == "reused-id" {
                current_owner = admit(&mut replacement, 2);
            }
            if case == "aborted-admission-control" {
                CLIENTS.write().unwrap().abort_admission(pending.take().unwrap());
            }
            let generation = match case {
                "zero-generation" => 0,
                "negative-generation" => -1,
                "wrong-generation" => first_owner.generation + 1,
                _ => first_owner.generation,
            };
            let id = if case == "missing-id" { 404 } else { first_owner.id };
            crate::cm_close_connection(id, generation);
            let old = closes(&mut first_receiver);
            let new = closes(&mut replacement_receiver);
            let expected = if case == "aborted-admission-control" { 1 } else { 0 };
            if let Some(owner) = pending {
                CLIENTS.write().unwrap().abort_admission(owner);
            }
            if case == "disconnected" {
                current_owner = admit(&mut replacement, 2);
            }
            crate::cm_close_connection(current_owner.id, current_owner.generation);
            let fresh = if current_owner == first_owner {
                closes(&mut first_receiver)
            } else {
                closes(&mut replacement_receiver)
            };
            let case_correct = old == expected && new == 0 && fresh == 1;
            println!("CM_DISCONNECT_OWNER_CASE=observed case={case} old={old} new={new} expected_old={expected} fresh={fresh} correct={case_correct}");
            correct &= case_correct;
        }
        assert!(correct, "CM disconnect selected an unowned registry generation");
        println!("CM_DISCONNECT_OWNER=pass cases=8 invalid=refused pending=refused disconnected=refused reused_id=refused fresh=usable");
    }

    #[test]
    fn cm_history_removal_requires_exact_disconnected_owner() {
        let mut correct = true;
        for case in ["zero-generation", "negative-generation", "wrong-generation", "missing-id",
            "pending-admission", "reused-id", "active-control"]
        {
            *CLIENTS.write().unwrap() = CmClientRegistry::default();
            let (mut first, mut first_receiver) = client(7, "first", ipc::CmAuthConnType::Remote);
            let first_owner = admit(&mut first, 1);
            if case != "active-control" {
                assert!(CLIENTS.write().unwrap().retire(first_owner, false));
            }
            let (mut replacement, mut replacement_receiver) = client(7, "replacement", ipc::CmAuthConnType::Remote);
            let mut current_owner = first_owner;
            let pending = if case == "pending-admission" {
                Some(CLIENTS.write().unwrap().prepare_admission(&mut replacement, 2).unwrap())
            } else {
                None
            };
            if case == "reused-id" {
                current_owner = admit(&mut replacement, 2);
                assert!(CLIENTS.write().unwrap().retire(current_owner, false));
            }
            let generation = match case {
                "zero-generation" => 0,
                "negative-generation" => -1,
                "wrong-generation" => first_owner.generation + 1,
                _ => first_owner.generation,
            };
            let id = if case == "missing-id" { 404 } else { first_owner.id };
            crate::cm_remove_disconnected_connection(id, generation);
            let preserved = present(current_owner);
            if let Some(owner) = pending {
                CLIENTS.write().unwrap().abort_admission(owner);
            }
            if case == "active-control" {
                assert!(CLIENTS.write().unwrap().retire(current_owner, false));
            }
            crate::cm_remove_disconnected_connection(current_owner.id, current_owner.generation);
            let removed = !present(current_owner);
            let queues_empty = closes(&mut first_receiver) == 0 && closes(&mut replacement_receiver) == 0;
            let case_correct = preserved && removed && queues_empty;
            println!("CM_HISTORY_OWNER_CASE=observed case={case} preserved={preserved} fresh_removed={removed} queues_empty={queues_empty} correct={case_correct}");
            correct &= case_correct;
        }
        assert!(correct, "CM history removal mutated an unowned registry generation");
        println!("CM_HISTORY_OWNER=pass cases=7 invalid=refused pending=refused reused_id=refused active=preserved fresh=removed");
    }

    #[test]
    fn cm_disconnect_and_history_delayed_commands_do_not_retarget() {
        let mut correct = true;
        for history in [false, true] {
            *CLIENTS.write().unwrap() = CmClientRegistry::default();
            let (mut first, mut first_receiver) = client(7, "first", ipc::CmAuthConnType::Remote);
            let first_owner = admit(&mut first, 1);
            let (mut replacement, mut replacement_receiver) = client(7, "replacement", ipc::CmAuthConnType::Remote);
            let mut registry = CLIENTS.write().unwrap();
            let (ready, started) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                ready.send(()).unwrap();
                if history {
                    crate::cm_remove_disconnected_connection(first_owner.id, first_owner.generation);
                } else {
                    crate::cm_close_connection(first_owner.id, first_owner.generation);
                }
            });
            started.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
            let replacement_owner = registry.admit(&mut replacement, 2).unwrap().0;
            if history {
                assert!(registry.retire(replacement_owner, false));
            }
            drop(registry);
            worker.join().unwrap();
            let old = closes(&mut first_receiver);
            let new = closes(&mut replacement_receiver);
            let preserved = present(replacement_owner);
            let fresh = if history {
                crate::cm_remove_disconnected_connection(replacement_owner.id, replacement_owner.generation);
                !present(replacement_owner)
            } else {
                crate::cm_close_connection(replacement_owner.id, replacement_owner.generation);
                closes(&mut replacement_receiver) == 1
            };
            let case_correct = old == 0 && new == 0 && preserved && fresh;
            println!("CM_DISCONNECT_DELAYED_CASE=observed history={history} old={old} new={new} successor_preserved={preserved} fresh={fresh} correct={case_correct}");
            correct &= case_correct;
        }
        assert!(correct, "delayed CM command selected a replacement owner");
        println!("CM_DISCONNECT_DELAYED=pass commands=2 registry=replaced successor=preserved fresh=usable workers=joined");
    }
}
