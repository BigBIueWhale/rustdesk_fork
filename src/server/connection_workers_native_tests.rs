use super::*;
use hbb_common::{libc, libloading::Library};

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

extern "C" fn connection_cleanup_start_failed() -> i32 {
    i32::from(matches!(FINAL_REMOTE_CLEANUP_DISPATCHER.get(), Some(Err(_)))
        && WAKELOCK_WORKER.get().is_none())
}

#[tokio::test]
#[ignore = "requires the isolated protected-provider input-lifetime profile"]
async fn graceful_process_exit_preserves_failed_cleanup_worker_start() {
    assert_eq!(unsafe { libc::getuid() }, 1000);
    assert_eq!(std::env::var("DISPLAY").unwrap(), ":97");
    let provider = unsafe { Library::new("/usr/lib/rustdesk-fork/libxdo.so.3").unwrap() };
    let arm = unsafe {
        *provider.get::<unsafe extern "C" fn(extern "C" fn() -> i32)>(b"connection_workers_arm_failed_start").unwrap()
    };
    let admission = unsafe { *provider.get::<unsafe extern "C" fn(i32)>(b"connection_workers_late_admission").unwrap() };
    assert_eq!(authenticated_connection_reservation_count(), 0);
    assert_eq!(connection_workers_uninitialized(), 1);
    struct ThreadLimit(libc::rlimit);
    impl Drop for ThreadLimit {
        fn drop(&mut self) {
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &self.0) }, 0);
        }
    }
    let mut original = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut original) }, 0);
    let limited = libc::rlimit { rlim_cur: 0, rlim_max: original.rlim_max };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &limited) }, 0);
    let limit = ThreadLimit(original);
    let refusal = std::thread::Builder::new().spawn(|| ()).unwrap_err();
    assert_eq!(refusal.raw_os_error(), Some(libc::EAGAIN));
    let failed = session_owner(37000, AuthConnType::Remote).await;
    assert!(failed.is_err());
    let failure = failed.err().unwrap().to_string();
    assert_eq!(authenticated_connection_reservation_count(), 0);
    assert_eq!(connection_cleanup_start_failed(), 1);
    drop(limit);
    let mut restored = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut restored) }, 0);
    assert_eq!((restored.rlim_cur, restored.rlim_max), (original.rlim_cur, original.rlim_max));
    let recovered = tokio::task::spawn_blocking(|| {
        std::thread::Builder::new().spawn(|| 42).unwrap().join().unwrap()
    }).await.unwrap();
    assert_eq!(recovered, 42);
    let retry = session_owner(37000, AuthConnType::Remote).await;
    assert!(retry.is_err());
    assert_eq!(retry.err().unwrap().to_string(), failure);
    assert_eq!(authenticated_connection_reservation_count(), 0);
    let reused = session_owner(37000, AuthConnType::FileTransfer).await.unwrap();
    assert_eq!(authenticated_connection_reservation_count(), 1);
    drop(reused);
    assert_eq!(authenticated_connection_reservation_count(), 0);
    assert_eq!(connection_cleanup_start_failed(), 1);
    println!("\nCONNECTION_START_FAILURE_OBSERVED kernel=EAGAIN admission=refused reservation=retired reuse=reserved retry=refused limit=restored recovery=joined");
    unsafe { arm(connection_cleanup_start_failed); }
    crate::server::request_graceful_shutdown();
    let mut late_admitted = false;
    for (offset, kind) in [AuthConnType::Remote, AuthConnType::FileTransfer,
        AuthConnType::ViewCamera, AuthConnType::Terminal, AuthConnType::PortForward]
        .into_iter().enumerate()
    {
        let late = session_owner(37001 + offset as i32, kind).await;
        let accepted = late.is_ok();
        println!("\nCONNECTION_FAILED_START_ADMISSION_OBSERVED type={kind:?} accepted={accepted}");
        late_admitted |= accepted;
        drop(late);
    }
    unsafe { admission(i32::from(late_admitted)); }
    assert_eq!(authenticated_connection_reservation_count(), 0);
    println!("\nCONNECTION_WORKERS_FAILED_START_ENTERED boundary=graceful-process-exit network_auth=false");
    crate::server::finish_graceful_shutdown().await
}
