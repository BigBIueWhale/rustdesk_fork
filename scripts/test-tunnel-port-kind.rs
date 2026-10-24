use super::*;

#[tokio::test(flavor = "current_thread")]
async fn one_off_mappings_refuse_reserved_ports_and_join_their_listener() {
    let mut correct = true;
    for name in ["zero", "negative", "oversized", "valid"] {
        let fixture = Fixture::new(None);
        let reservation = tcp::new_exclusive_listener("127.0.0.1:0").await.unwrap();
        let valid_port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let port = match name { "zero" => 0, "negative" => -1, "oversized" => 65536,
            "valid" => i32::from(valid_port), _ => unreachable!() };
        let (control, receiver) = port_forward_control();
        let launch_start = RDP_LAUNCH_PORTS.lock().unwrap().len();
        let session = fixture.session.clone();
        let operation = tokio::spawn(listen_one_off(
            session.get_id(), port, session, receiver, "localhost".into(), 22));
        let observed = tokio::time::timeout(Duration::from_secs(2), async {
            while !operation.is_finished()
                && fixture.session.listener_starts.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        }).await.is_ok();
        let started = fixture.session.listener_starts.load(Ordering::SeqCst) == 1;
        let launches = RDP_LAUNCH_PORTS.lock().unwrap()[launch_start..].to_vec();
        let owned_ports = if port == 0 { launches.clone() }
            else if started { vec![valid_port] } else { vec![] };
        let mut bound = true;
        for local in &owned_ports {
            bound &= tcp::new_exclusive_listener(("127.0.0.1", *local)).await.is_err();
        }
        control.close();
        let outcome = operation.await.unwrap();
        let mut rebindable = true;
        for local in owned_ports {
            rebindable &= tcp::new_exclusive_listener(("127.0.0.1", local)).await.is_ok();
        }
        let valid = name == "valid";
        let precise = valid || outcome.as_ref().err()
            .is_some_and(|e| e.to_string().contains("Invalid local port-forward port"));
        let case_correct = observed && outcome.is_ok() == valid && started == valid
            && launches.is_empty() && bound && rebindable && precise;
        println!("PF_SETTINGS_ONE_OFF_CASE=observed name={name} accepted={} started={started} launch_branch={} observed={observed} bound={bound} rebindable={rebindable} precise={precise} correct={case_correct}", outcome.is_ok(), launches.len());
        correct &= case_correct;
    }
    assert!(correct, "the one-off route admitted the RDP sentinel or failed owned listener cleanup");
    println!("PF_SETTINGS_ONE_OFF=pass cases=4 invalid=before-bind-and-launch valid=native-listener owner-thread=joined ports=rebindable");
}

#[tokio::test(flavor = "current_thread")]
async fn ordinary_mapping_producer_rejects_reserved_and_invalid_ports() {
    let mut correct = true;
    for port in [0, -1, 65536, 1, 65535] {
        let (sender, mut receiver) = viewer_command_channel();
        let fixture = Fixture::new(Some(sender));
        let saved = fixture.bytes();
        let session = fixture.session.clone();
        let mut operation = tokio::task::spawn_blocking(move ||
            session.add_port_forward(port, "localhost".into(), 22));
        let (queued, outcome) = tokio::select! {
            result = &mut operation => (false, result.unwrap()),
            request = receiver.recv() => {
                let Some(Ok(Data::SavedPortForward(request))) = request else {
                    panic!("ordinary add did not carry its owned request");
                };
                request.completed.try_send(Ok(())).unwrap();
                (true, operation.await.unwrap())
            }
        };
        let valid = (1..=65535).contains(&port);
        let precise = valid || outcome.as_ref().err()
            .is_some_and(|e| e.to_string().contains("Invalid local port-forward port"));
        let preserved = fixture.bytes() == saved;
        let case_correct = queued == valid && outcome.is_ok() == valid && precise && preserved;
        println!("PF_SETTINGS_PORT_PRODUCER_CASE=observed port={port} queued={queued} accepted={} precise={precise} saved={preserved} correct={case_correct}", outcome.is_ok());
        correct &= case_correct;
    }
    assert!(correct, "an ordinary saved-port request admitted the RDP sentinel or an invalid port");
    println!("PF_SETTINGS_PORT_PRODUCER=pass cases=5 invalid=prequeue-refused bounds=accepted saved=unchanged");
}

#[test]
fn saved_mapping_writer_validates_ports_and_preserves_legacy_removal() {
    let mut correct = true;
    for port in [0, -1, 65536, 1, 65535] {
        let fixture = Fixture::new(None);
        fixture.seed(31050);
        let saved = fixture.bytes();
        let id = fixture.session.get_id();
        let outcome = PeerConfig::add_port_forward(&id, &(port, "localhost".into(), 22));
        let valid = (1..=65535).contains(&port);
        let precise = valid || outcome.as_ref().err()
            .is_some_and(|e| e.to_string().contains("Invalid local port-forward port"));
        let state = PeerConfig::load_for_write(&id).unwrap();
        let state_correct = if valid {
            state.port_forwards == vec![(31050, "localhost".into(), 22), (port, "localhost".into(), 22)]
        } else {
            fixture.bytes() == saved && state.port_forwards == vec![(31050, "localhost".into(), 22)]
        };
        let case_correct = outcome.is_ok() == valid && precise && state_correct;
        println!("PF_SETTINGS_PORT_WRITER_CASE=observed port={port} accepted={} precise={precise} state={state_correct} correct={case_correct}", outcome.is_ok());
        correct &= case_correct;
    }
    let fixture = Fixture::new(None);
    let id = fixture.session.get_id();
    let sibling = (31050, "localhost".into(), 22);
    PeerConfig { port_forwards: vec![(0, "localhost".into(), 22), sibling.clone()] }.store(&id).unwrap();
    assert_eq!(PeerConfig::remove_port_forward(&id, 0).unwrap(), vec![sibling]);
    println!("PF_SETTINGS_PORT_REPAIR=pass zero=removed sibling=preserved");
    assert!(correct, "the saved mapping writer persisted an invalid local port");
    println!("PF_SETTINGS_PORT_WRITER=pass cases=5 invalid=unchanged bounds=stored legacy-removal=usable");
}

#[tokio::test(flavor = "current_thread")]
async fn mapping_receiver_binds_port_kind_to_its_session_owner() {
    let mut correct = true;
    for (name, rdp, ephemeral, expected_admitted) in [
        ("ordinary-zero", false, true, false),
        ("rdp-zero", true, true, true),
        ("ordinary-fixed", false, false, true),
        ("rdp-fixed", true, false, false),
    ] {
        let mut fixture = Fixture::new(None);
        fixture.session.rdp = rdp;
        let saved = fixture.bytes();
        let reservation = tcp::new_exclusive_listener("127.0.0.1:0").await.unwrap();
        let fixed_port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let port = if ephemeral { 0 } else { i32::from(fixed_port) };
        let launch_start = RDP_LAUNCH_PORTS.lock().unwrap().len();
        let supervisor = PortForwardSupervisorOwner::start(fixture.session.clone()).unwrap();
        let outcome = supervisor.add((port, "localhost".into(), 22).into()).await;
        let admitted = outcome.is_ok();
        let launches = RDP_LAUNCH_PORTS.lock().unwrap()[launch_start..].to_vec();
        let expected_launches = usize::from(rdp && ephemeral);
        let owned_ports = if ephemeral { launches.clone() }
            else if admitted { vec![fixed_port] } else { vec![] };
        let mut bound = true;
        for local in &owned_ports {
            bound &= tcp::new_exclusive_listener(("127.0.0.1", *local)).await.is_err();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while fixture.session.listener_starts.load(Ordering::SeqCst) < usize::from(admitted) {
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        supervisor.close_and_join().await.unwrap();
        let mut rebindable = true;
        for local in owned_ports {
            rebindable &= tcp::new_exclusive_listener(("127.0.0.1", local)).await.is_ok();
        }
        let preserved = fixture.bytes() == saved;
        let case_correct = admitted == expected_admitted && launches.len() == expected_launches
            && bound && rebindable && preserved;
        println!("PF_SETTINGS_PORT_OWNER_CASE=observed name={name} admitted={admitted} launch_branch={} expected_launch_branch={expected_launches} bound={bound} rebindable={rebindable} saved={preserved} correct={case_correct}", launches.len());
        correct &= case_correct;
    }
    assert!(correct, "a mapping's port kind escaped its session owner");
    println!("PF_SETTINGS_PORT_OWNER=pass cases=4 RDP=ephemeral-only ordinary=fixed-only refusal=before-bind-and-launch cleanup=joined");
}
