use super::*;
use hbb_common::libloading::Library;

async fn session_owner(id: i32, kind: AuthConnType) -> ResultType<raii::AuthedConnID> {
    raii::AuthedConnID::new(
        id,
        kind,
        SessionKey {
            peer_id: "shutdown-fixture".into(),
            name: "owner".into(),
            session_id: id as u64,
        },
        format!("shutdown-fixture-{id}"),
        false,
        false,
    )
    .await
}

async fn wait_for(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !condition() {
        assert!(Instant::now() < deadline, "native shutdown observation timed out");
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

#[tokio::test]
#[ignore = "requires the isolated protected-provider input-lifetime profile"]
async fn graceful_process_exit_retires_connection_workers() {
    assert_eq!(std::env::var("DISPLAY").unwrap(), ":97");
    let provider = unsafe { Library::new("/usr/lib/rustdesk-fork/libxdo.so.3").unwrap() };
    let init = unsafe { *provider.get::<unsafe extern "C" fn()>(b"cursor_recorder_init").unwrap() };
    let probe = unsafe { *provider.get::<unsafe extern "C" fn(i32) -> i32>(b"cursor_recorder_probe").unwrap() };
    let ready = unsafe { *provider.get::<unsafe extern "C" fn() -> i32>(b"connection_workers_ready").unwrap() };
    let arm = unsafe { *provider.get::<unsafe extern "C" fn()>(b"connection_workers_arm").unwrap() };
    let admission = unsafe { *provider.get::<unsafe extern "C" fn(i32)>(b"connection_workers_late_admission").unwrap() };
    let allow = unsafe { *provider.get::<unsafe extern "C" fn()>(b"cursor_recorder_allow").unwrap() };
    unsafe { init(); }
    // Exercise worker ownership without claiming an OS wake-inhibition facility.
    Config::set_option(keys::OPTION_KEEP_AWAKE_DURING_INCOMING_SESSIONS.into(), "N".into());
    assert!(!Config::get_bool_option(keys::OPTION_KEEP_AWAKE_DURING_INCOMING_SESSIONS));
    let mut owner = session_owner(35000, AuthConnType::Remote).await.unwrap();
    owner.commit_publication().unwrap();
    owner.publish_resources().unwrap();
    wait_for(|| unsafe { probe(6) > 0 && ready() == 1 }).await;
    unsafe { arm(); }
    wait_for(|| unsafe { probe(3) == 1 }).await;
    crate::server::request_graceful_shutdown();
    let mut late_admitted = false;
    for (offset, kind) in [AuthConnType::Remote, AuthConnType::FileTransfer,
        AuthConnType::ViewCamera, AuthConnType::Terminal, AuthConnType::PortForward]
        .into_iter().enumerate()
    {
        let late = session_owner(35001 + offset as i32, kind).await;
        let accepted = late.is_ok();
        println!("\nCONNECTION_ADMISSION_OBSERVED type={kind:?} accepted={accepted}");
        late_admitted |= accepted;
        drop(late);
    }
    unsafe { admission(i32::from(late_admitted)); }
    drop(owner);
    println!("\nCONNECTION_WORKERS_ENTERED boundary=graceful-process-exit network_auth=false");
    let retirement = crate::server::finish_graceful_shutdown();
    tokio::pin!(retirement);
    tokio::select! {
        _ = &mut retirement => unreachable!(),
        _ = tokio::time::sleep(Duration::from_millis(100)) => unsafe { allow(); },
    }
    retirement.await
}

extern "C" fn connection_workers_uninitialized() -> i32 {
    i32::from(FINAL_REMOTE_CLEANUP_DISPATCHER.get().is_none()
        && WAKELOCK_WORKER.get().is_none())
}

#[tokio::test]
#[ignore = "requires the isolated protected-provider input-lifetime profile"]
async fn graceful_empty_process_exit_leaves_connection_workers_uninitialized() {
    assert_eq!(std::env::var("DISPLAY").unwrap(), ":97");
    let provider = unsafe { Library::new("/usr/lib/rustdesk-fork/libxdo.so.3").unwrap() };
    let arm = unsafe {
        *provider.get::<unsafe extern "C" fn(extern "C" fn() -> i32)>(b"connection_workers_arm_empty").unwrap()
    };
    let admission = unsafe { *provider.get::<unsafe extern "C" fn(i32)>(b"connection_workers_late_admission").unwrap() };
    assert_eq!(authenticated_connection_reservation_count(), 0);
    assert_eq!(connection_workers_uninitialized(), 1);
    unsafe { arm(connection_workers_uninitialized); }
    crate::server::request_graceful_shutdown();
    let mut late_admitted = false;
    for (offset, kind) in [AuthConnType::Remote, AuthConnType::FileTransfer,
        AuthConnType::ViewCamera, AuthConnType::Terminal, AuthConnType::PortForward]
        .into_iter().enumerate()
    {
        let late = session_owner(36000 + offset as i32, kind).await;
        let accepted = late.is_ok();
        println!("\nCONNECTION_EMPTY_ADMISSION_OBSERVED type={kind:?} accepted={accepted}");
        late_admitted |= accepted;
        drop(late);
    }
    unsafe { admission(i32::from(late_admitted)); }
    assert_eq!(authenticated_connection_reservation_count(), 0);
    assert_eq!(connection_workers_uninitialized(), 1);
    println!("\nCONNECTION_WORKERS_EMPTY_ENTERED boundary=graceful-process-exit network_auth=false");
    crate::server::finish_graceful_shutdown().await
}
