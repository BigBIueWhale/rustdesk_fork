use super::*;
use std::{future::Future, pin::Pin, task::Poll};

type JoinResult = Pin<Box<dyn Future<Output = Result<(), String>>>>;

async fn admit_pending(join: &mut JoinResult) {
    std::future::poll_fn(|cx| {
        assert!(join.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    }).await;
}

fn held_owner(supervisor: bool) -> (std::sync::mpsc::SyncSender<()>, JoinResult, Arc<AtomicUsize>) {
    let (release, released) = std::sync::mpsc::sync_channel(1);
    let live = Arc::new(AtomicUsize::new(1));
    let worker_live = Arc::clone(&live);
    let join: JoinResult = if supervisor {
        let thread = std::thread::spawn(move || {
            released.recv_timeout(Duration::from_secs(10)).unwrap();
            worker_live.store(0, Ordering::SeqCst);
        });
        Box::pin(join_port_forward_supervisor_off_runtime(thread))
    } else {
        let thread = std::thread::spawn(move || {
            released.recv_timeout(Duration::from_secs(10)).unwrap();
            worker_live.store(0, Ordering::SeqCst);
            Ok(())
        });
        Box::pin(async move {
            join_one_off_owner_off_runtime(thread).await.map_err(|e| e.to_string())
        })
    };
    (release, join, live)
}

fn finished_owner(kind: &'static str) -> JoinResult {
    if kind.starts_with("supervisor") {
        let thread = std::thread::spawn(move || {
            if kind == "supervisor-panic" { panic!("fixture owner panic"); }
        });
        Box::pin(join_port_forward_supervisor_off_runtime(thread))
    } else {
        let thread = std::thread::spawn(move || {
            match kind {
                "one-off-error" => Err(anyhow!("fixture owner error")),
                "one-off-panic" => panic!("fixture owner panic"),
                "one-off-ok" => Ok(()),
                _ => unreachable!(),
            }
        });
        Box::pin(async move {
            join_one_off_owner_off_runtime(thread).await.map_err(|e| e.to_string())
        })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn finished_owner_is_joined_while_an_earlier_owner_remains_live() {
    let mut correct = true;
    for supervisor in [false, true] {
        for kind in ["one-off-ok", "one-off-error", "one-off-panic",
                     "supervisor-ok", "supervisor-panic"] {
            let (release, mut held, live) = held_owner(supervisor);
            admit_pending(&mut held).await;
            let mut finished = finished_owner(kind);
            let early = tokio::time::timeout(Duration::from_millis(500), &mut finished).await;
            let timely = early.is_ok();
            let independent = live.load(Ordering::SeqCst) == 1;
            release.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(2), held).await.unwrap().unwrap();
            let result = match early {
                Ok(result) => result,
                Err(_) => tokio::time::timeout(Duration::from_secs(2), finished).await.unwrap(),
            };
            let exact_result = match kind {
                "one-off-error" => result.as_ref().err().map(String::as_str) == Some("fixture owner error"),
                "one-off-panic" | "supervisor-panic" =>
                    result.as_ref().err().map(String::as_str) == Some("Port-forward owner thread panicked"),
                _ => result.is_ok(),
            };
            let case_correct = timely && independent && exact_result;
            println!("PF_REAPER_ORDER_CASE=observed held_supervisor={supervisor} finished={kind} timely={timely} independent={independent} exact_result={exact_result} correct={case_correct}");
            correct &= case_correct;
        }
    }
    assert!(correct, "an unrelated live owner delayed a completed owner or changed its result");
    println!("PF_REAPER_ORDER=pass cases=10 deadline_ms=500 owners=native results=exact cleanup=joined");
}

#[derive(Debug)]
struct RetainedResult(Arc<()>);
impl std::fmt::Display for RetainedResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "retained result {}", Arc::strong_count(&self.0))
    }
}
impl std::error::Error for RetainedResult {}

#[tokio::test(flavor = "current_thread")]
async fn dropped_waiter_retains_owner_and_allows_repeated_independent_joins() {
    let (release, released) = std::sync::mpsc::sync_channel(1);
    let result_owner = Arc::new(());
    let result_observer = Arc::downgrade(&result_owner);
    let thread = std::thread::spawn(move || {
        released.recv_timeout(Duration::from_secs(10)).unwrap();
        Err(anyhow!(RetainedResult(result_owner)))
    });
    let mut abandoned: JoinResult = Box::pin(async move {
        join_one_off_owner_off_runtime(thread).await.map_err(|e| e.to_string())
    });
    admit_pending(&mut abandoned).await;
    drop(abandoned);
    let mut completed = 0;
    let mut late = None;
    for _ in 0..64 {
        let mut finished = finished_owner("supervisor-ok");
        match tokio::time::timeout(Duration::from_millis(500), &mut finished).await {
            Ok(Ok(())) => completed += 1,
            _ => { late = Some(finished); break; }
        }
    }
    let retained_before_release = result_observer.upgrade().is_some();
    release.send(()).unwrap();
    if let Some(late) = late {
        tokio::time::timeout(Duration::from_secs(2), late).await.unwrap().unwrap();
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while result_observer.upgrade().is_some() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }).await.unwrap();
    println!("PF_REAPER_DROPPED=observed completed={completed} retained_before_release={retained_before_release} result_reclaimed=true");
    assert_eq!(completed, 64, "a dropped waiter held up independent reaping");
    assert!(retained_before_release);
    println!("PF_REAPER_REUSE=pass later_owners=64 pending_waiter=dropped retained_until_exit=true result=reclaimed");
}

#[test]
fn reaper_capacity_counts_queued_and_pending_owners_together() {
    const ENV: &str = "RUSTDESK_TEST_TUNNEL_REAPER_CAPACITY";
    if let Ok(mode) = std::env::var(ENV) {
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) }, 0);
        let mut releases = Vec::new();
        let mut results = Vec::new();
        let count = if mode == "within" { 32 } else { assert_eq!(mode, "overflow"); 33 };
        for index in 0..count {
            if index == 32 { std::thread::sleep(Duration::from_millis(500)); }
            let (release, released) = std::sync::mpsc::sync_channel(1);
            let thread = std::thread::spawn(move || {
                released.recv_timeout(Duration::from_secs(10)).unwrap();
            });
            let (completed, result) = tokio::sync::oneshot::channel();
            handoff_port_forward_owner(PortForwardOwnerJoinRequest::Supervisor {
                thread, completed: Some(completed),
            });
            releases.push(release);
            results.push(result);
        }
        for release in releases { release.send(()).unwrap(); }
        for result in results { result.blocking_recv().unwrap().unwrap(); }
        return;
    }
    use std::os::unix::process::ExitStatusExt;
    let executable = std::env::current_exe().unwrap();
    let exact = "port_forward_settings::reaper_tests::reaper_capacity_counts_queued_and_pending_owners_together";
    let mut correct = true;
    for mode in ["within", "overflow"] {
        let output = std::process::Command::new(&executable)
            .args(["--exact", exact, "--test-threads=1", "--color", "never"])
            .env(ENV, mode).output().unwrap();
        assert!(output.stdout.len() + output.stderr.len() < 8192);
        let case_correct = if mode == "within" { output.status.success() }
            else { output.status.signal() == Some(libc::SIGABRT) };
        println!("PF_REAPER_CAPACITY_CASE=observed mode={mode} code={:?} signal={:?} correct={case_correct}", output.status.code(), output.status.signal());
        correct &= case_correct;
    }
    assert!(correct, "reaper capacity did not admit 32 owners and fail-stop the 33rd");
    println!("PF_REAPER_CAPACITY=pass accepted=32 overflow=33 action=SIGABRT child_cleanup=waited core=disabled");
}

#[tokio::test(flavor = "current_thread")]
async fn live_one_off_listener_does_not_delay_supervisor_close() {
    let fixture = Fixture::new(None);
    let reservation = tcp::new_exclusive_listener("127.0.0.1:0").await.unwrap();
    let one_off_addr = reservation.local_addr().unwrap();
    let second = tcp::new_exclusive_listener("127.0.0.1:0").await.unwrap();
    let supervisor_addr = second.local_addr().unwrap();
    drop(reservation);
    let (control, receiver) = port_forward_control();
    let session = fixture.session.clone();
    let one_off = tokio::spawn(listen_one_off(
        session.get_id(), i32::from(one_off_addr.port()), session,
        receiver, "localhost".into(), 22,
    ));
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.session.listener_starts.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    drop(second);
    let supervisor = PortForwardSupervisorOwner::start(fixture.session.clone()).unwrap();
    supervisor.add((i32::from(supervisor_addr.port()), "localhost".into(), 22).into())
        .await.unwrap();
    let mut close = Box::pin(supervisor.close_and_join());
    let early = tokio::time::timeout(Duration::from_millis(500), &mut close).await;
    let timely = early.is_ok();
    let one_off_live = tcp::new_exclusive_listener(one_off_addr).await.is_err();
    control.close();
    tokio::time::timeout(Duration::from_secs(2), one_off).await.unwrap().unwrap().unwrap();
    match early {
        Ok(result) => result.unwrap(),
        Err(_) => tokio::time::timeout(Duration::from_secs(2), close).await.unwrap().unwrap(),
    }
    let rebindable = tcp::new_exclusive_listener(one_off_addr).await.is_ok()
        && tcp::new_exclusive_listener(supervisor_addr).await.is_ok();
    println!("PF_REAPER_LISTENERS=observed timely={timely} one_off_live={one_off_live} rebindable={rebindable}");
    assert!(timely && one_off_live && rebindable,
        "a live one-off mapping delayed supervisor shutdown or retained a listener");
    println!("PF_REAPER_NATIVE=pass listeners=2 supervisor=independent deadline_ms=500 one_off=preserved cleanup=joined ports=rebindable");
}
