use super::*;
use hbb_common::libloading::Library;
use std::os::unix::fs::OpenOptionsExt;

// The before API returns its thread; the corrected API owns it internally.
// Retain before handles solely to reap the fixture after observing false finality.
struct StartReceipt(Option<std::thread::JoinHandle<()>>);

trait IntoStartReceipt {
    fn into_start_receipt(self) -> ResultType<StartReceipt>;
}

impl IntoStartReceipt for Option<std::thread::JoinHandle<()>> {
    fn into_start_receipt(self) -> ResultType<StartReceipt> { Ok(StartReceipt(self)) }
}

impl IntoStartReceipt for ResultType<()> {
    fn into_start_receipt(self) -> ResultType<StartReceipt> {
        self.map(|()| StartReceipt(None))
    }
}

impl IntoStartReceipt for () {
    fn into_start_receipt(self) -> ResultType<StartReceipt> { Ok(StartReceipt(None)) }
}

async fn owner(id: i32, kind: AuthConnType) -> ResultType<raii::AuthedConnID> {
    raii::AuthedConnID::new(id, kind, SessionKey {
        peer_id: "cursor-fixture".into(), name: "owner".into(), session_id: id as u64,
    }, format!("cursor-fixture-{id}"), false, false).await
}

async fn wait_for(mut condition: impl FnMut() -> bool) -> ResultType<()> {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !condition() {
        if Instant::now() >= deadline { bail!("cursor fixture observation timed out"); }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    Ok(())
}

async fn reap(receipts: Vec<StartReceipt>) {
    tokio::task::spawn_blocking(move || {
        try_stop_record_cursor_pos().into_start_receipt().unwrap();
        for receipt in receipts {
            if let Some(join) = receipt.0 { join.join().unwrap(); }
        }
    }).await.unwrap();
    wait_for(final_remote_cleanup_is_drained).await.unwrap();
}

fn resources(path: &str) -> usize { std::fs::read_dir(path).unwrap().count() }

#[tokio::test]
#[ignore = "requires the isolated protected-provider input-lifetime profile"]
async fn remote_cursor_retirement_waits_for_native_query_and_thread_context() {
    assert_eq!(std::env::var("DISPLAY").unwrap(), ":97");
    let provider = unsafe { Library::new("/usr/lib/rustdesk-fork/libxdo.so.3").unwrap() };
    let init = unsafe { *provider.get::<unsafe extern "C" fn()>(b"cursor_recorder_init").unwrap() };
    let begin = unsafe { *provider.get::<unsafe extern "C" fn(i32)>(b"cursor_recorder_begin").unwrap() };
    let allow = unsafe { *provider.get::<unsafe extern "C" fn()>(b"cursor_recorder_allow").unwrap() };
    let probe = unsafe { *provider.get::<unsafe extern "C" fn(i32) -> i32>(b"cursor_recorder_probe").unwrap() };
    let finish = unsafe { *provider.get::<unsafe extern "C" fn()>(b"cursor_recorder_finish").unwrap() };
    unsafe { init(); }
    let warm = owner(31000, AuthConnType::Remote).await.unwrap();
    let warm_start = try_start_record_cursor_pos().into_start_receipt().unwrap();
    wait_for(|| unsafe { probe(4) > 0 }).await.unwrap();
    drop(warm);
    reap(vec![warm_start]).await;
    let baseline_fds = resources("/proc/self/fd");
    let baseline_tasks = resources("/proc/self/task");
    for generation in 0..32 {
        unsafe { begin(generation); }
        let mut owners = Vec::new();
        let mut receipts = Vec::new();
        let mut successor = None;
        let outcome: ResultType<_> = async {
            for (offset, kind) in [(0, AuthConnType::FileTransfer), (1, AuthConnType::ViewCamera)] {
                let unrelated = owner(32000 + generation * 4 + offset, kind).await?;
                drop(unrelated);
            }
            if unsafe { probe(1) } != 0 { bail!("non-Remote admission started a recorder"); }
            owners.push(owner(33000 + generation * 4, AuthConnType::Remote).await?);
            receipts.push(try_start_record_cursor_pos().into_start_receipt()?);
            wait_for(|| unsafe { probe(3) == 1 }).await?;
            owners.push(owner(33001 + generation * 4, AuthConnType::Remote).await?);
            receipts.push(try_start_record_cursor_pos().into_start_receipt()?);
            drop(owners.remove(0));
            tokio::time::sleep(Duration::from_millis(40)).await;
            let shared = unsafe { probe(0) == 1 && probe(1) == 1 && probe(2) == 0 };
            drop(owners.pop());
            tokio::time::sleep(Duration::from_millis(40)).await;
            let cleanup_pending = !final_remote_cleanup_is_drained();
            successor = Some(tokio::spawn(async move {
                let next = owner(33002 + generation * 4, AuthConnType::Remote).await?;
                Ok::<_, hbb_common::anyhow::Error>((next, try_start_record_cursor_pos().into_start_receipt()?))
            }));
            tokio::time::sleep(Duration::from_millis(40)).await;
            let successor_pending = successor.as_ref().map_or(false, |next| !next.is_finished());
            let held_contexts = unsafe { probe(0) };
            Ok((shared, cleanup_pending, successor_pending, held_contexts))
        }.await;
        // Release the test-only native barrier before any assertion or owned join.
        unsafe { allow(); }
        let mut successor_error = None;
        if let Some(mut next) = successor {
            let result = match tokio::time::timeout(Duration::from_secs(3), &mut next).await {
                Ok(result) => result,
                Err(_) => { next.abort(); next.await }
            };
            match result {
                Ok(Ok((next_owner, receipt))) => {
                    owners.push(next_owner); receipts.push(receipt);
                }
                Ok(Err(error)) => successor_error = Some(error.to_string()),
                Err(error) => successor_error = Some(error.to_string()),
            }
        }
        let expected = (21 + generation, 45 + generation);
        let position_observed = wait_for(|| recorded_cursor_pos_for_test() == expected).await.is_ok();
        drop(owners);
        reap(receipts).await;
        let retired = unsafe { probe(0) == 0 && probe(1) == 2 && probe(2) == 2
            && probe(3) == 0 && probe(5) == 1 && probe(6) > 0 };
        let invalidated = recorded_cursor_pos_for_test() == (i32::MIN, i32::MIN);
        let fd_delta = resources("/proc/self/fd") as isize - baseline_fds as isize;
        let task_delta = resources("/proc/self/task") as isize - baseline_tasks as isize;
        println!("CURSOR_RECORDER_OBSERVED generation={generation} held={outcome:?} position={position_observed} retired={retired} invalidated={invalidated} fd_delta={fd_delta} task_delta={task_delta}");
        // Only the fixture's observer connection remains until final cleanup.
        if outcome.as_ref().map_or(true, |value| *value != (true, true, true, 1))
            || successor_error.is_some() || !position_observed || !retired || !invalidated
            || fd_delta != 0 || task_delta != 0 {
            unsafe { finish(); }
            panic!("cursor retirement is incomplete: outcome={outcome:?}, successor={successor_error:?}");
        }
    }
    unsafe { finish(); }
    assert_eq!(resources("/proc/self/fd"), baseline_fds - 1);
    use std::io::Write;
    let mut receipt = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open("/tmp/input-lifetime-cursor.receipt").unwrap();
    writeln!(receipt, "CURSOR_RECORDER_NATIVE=pass generations=32 producer=authenticated-resource-admission query=native-x11 sharing=one-worker retirement=exact-join successor=blocked-until-tls-drop position=observed invalidation=before-finality descriptors=retired tasks=retired network_auth=false").unwrap();
}
