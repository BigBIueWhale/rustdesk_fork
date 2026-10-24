// Exact RDP producers/receivers and real command/control queues. The session
// kind and relay consumer are controlled doubles; Windows mstsc is not executed.
use super::*;

fn request(session: &Session) -> tokio::task::JoinHandle<ResultType<RdpLaunchRequest>> {
    let session = session.clone();
    tokio::task::spawn_blocking(move || {
        #[cfg(rdp_launch_results)]
        { session.request_rdp_launch() }
        #[cfg(not(rdp_launch_results))]
        { session.new_rdp(); Ok(RdpLaunchRequest::Queued) }
    })
}

async fn command(receiver: &mut ViewerCommandReceiver) -> Data {
    tokio::time::timeout(Duration::from_secs(2), receiver.recv()).await.unwrap().unwrap().unwrap()
}

async fn dispatch(session: &Session, command: Data, owner: &PortForwardSupervisorOwner) {
    #[cfg(rdp_launch_results)]
    match command {
        Data::RequestRdpLaunch(request) => session.handle_rdp_launch_request(request, owner).await,
        _ => panic!("wrong RDP request"),
    }
    #[cfg(not(rdp_launch_results))]
    match command {
        Data::NewRDP => { let _ = owner.launch_rdp(0).await; }
        _ => panic!("wrong RDP request"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn rdp_request_refuses_unavailable_and_wrong_kind_rounds() {
    let mut correct = true;
    for state in ["unpublished", "closed", "receiver-gone", "full", "wrong-kind"] {
        let (sender, receiver) = viewer_command_channel();
        let mut receiver = Some(receiver);
        match state {
            "closed" => { sender.send(Data::Close).unwrap(); }
            "receiver-gone" => { receiver.take(); }
            "full" => { for _ in 0..VIEWER_COMMAND_QUEUE_CAPACITY { sender.send(Data::CancelJob(1)).unwrap(); } }
            _ => {}
        }
        let mut fixture = Fixture::new((state != "unpublished").then_some(sender));
        fixture.session.rdp = state != "wrong-kind";
        let result = request(&fixture.session).await.unwrap();
        let refused = result.is_err();
        let preserved = fixture.bytes().is_none();
        correct &= refused && preserved;
        println!("RDP_LAUNCH_REFUSAL_CASE=observed state={state} refused={refused} storage_unchanged={preserved}");
        drop(receiver);
    }
    #[cfg(rdp_launch_results)]
    {
        let _: fn(ffi::SessionID) -> ResultType<()> = ffi::session_request_rdp_launch;
        assert!(ffi::session_request_rdp_launch(uuid::Uuid::new_v4()).is_err());
    }
    #[cfg(not(rdp_launch_results))]
    {
        let _: fn(ffi::SessionID) -> ResultType<()> = ffi::session_new_rdp;
        assert!(ffi::session_new_rdp(uuid::Uuid::new_v4()).is_err());
    }
    assert!(correct, "an unavailable or non-RDP owner reported request admission");
    println!("RDP_LAUNCH_REFUSAL=pass cases=5 round=exact kind=RDP ffi=worker-result unknown-session=refused");
}

#[tokio::test(flavor = "current_thread")]
async fn rdp_request_reports_manager_admission_and_deadline_finality() {
    let (sender, mut receiver) = viewer_command_channel();
    let mut fixture = Fixture::new(Some(sender));
    fixture.session.rdp = true;
    let owner = PortForwardSupervisorOwner::start(fixture.session.clone()).unwrap();
    let missing = request(&fixture.session);
    let first_command = command(&mut receiver).await;
    let waited = !missing.is_finished();
    dispatch(&fixture.session, first_command, &owner).await;
    let missing_refused = missing.await.unwrap().is_err();
    owner.add((0, "localhost".into(), 3389).into()).await.unwrap();

    #[cfg(rdp_launch_results)]
    let wrong_receiver_refused = {
        let (completed, result) = std::sync::mpsc::sync_channel(1);
        let other = Fixture::new(None);
        other.session.handle_rdp_launch_request(RdpLaunchCommand { completed }, &owner).await;
        result.try_recv().unwrap().is_err()
    };
    #[cfg(not(rdp_launch_results))]
    let wrong_receiver_refused = true; // New receiver defense has no baseline equivalent.

    let queued = request(&fixture.session);
    let queued_command = command(&mut receiver).await;
    dispatch(&fixture.session, queued_command, &owner).await;
    let queued = queued.await.unwrap().unwrap() == RdpLaunchRequest::Queued;
    let coalesced = request(&fixture.session);
    let coalesced_command = command(&mut receiver).await;
    dispatch(&fixture.session, coalesced_command, &owner).await;
    let coalesced = coalesced.await.unwrap().unwrap() == RdpLaunchRequest::Coalesced;

    let late = request(&fixture.session);
    let late_command = command(&mut receiver).await;
    let start = std::time::Instant::now();
    let late = tokio::time::timeout(Duration::from_secs(7), late).await.unwrap().unwrap();
    let uncertain = late.as_ref().err().is_some_and(|e| e.to_string().contains("not yet known"));
    let bounded_wait = start.elapsed() >= Duration::from_millis(4500) && start.elapsed() < Duration::from_secs(7);
    dispatch(&fixture.session, late_command, &owner).await;
    let retained = owner.launch_rdp(0).await.unwrap() == RdpLaunchRequest::Coalesced;
    let unchanged = fixture.bytes().is_none();
    owner.close_and_join().await.unwrap();
    println!("RDP_LAUNCH_OWNER=observed waited={waited} missing_refused={missing_refused} wrong_receiver_refused={wrong_receiver_refused} queued={queued} coalesced={coalesced} uncertain={uncertain} bounded_wait={bounded_wait} retained={retained} storage_unchanged={unchanged}");
    assert!(waited && missing_refused && wrong_receiver_refused && queued && coalesced && uncertain && bounded_wait && retained && unchanged);
    println!("RDP_LAUNCH_FINALITY=pass manager=authoritative queue=one-slot coalesced=preserved deadline=uncertain admitted=retained shutdown=joined");
}
