extern crate self as hbb_common;

pub use log;
pub use sodiumoxide;
pub use tokio;

#[path = "../libs/hbb_common/src/protos/mod.rs"]
pub mod protos;
pub use protos::message as message_proto;

pub mod cpace {
    include!(env!("CONTROL_EGRESS_LIMIT"));
}

use message_proto::*;
use protobuf::Message as _;
use std::{
    collections::VecDeque,
    fmt,
    io::{self, Write},
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use tokio::{sync::mpsc, time};

include!(env!("CONTROL_EGRESS_SOURCE"));
include!(env!("CONTROL_EGRESS_TESTS"));

pub mod enigo {
    use serde_derive::{Deserialize, Serialize};
    include!(env!("CM_ENIGO_TYPES"));
}

pub mod ipc {
    use crate::enigo;
    use bytes::Bytes;
    use serde_derive::{Deserialize, Serialize};
    include!(env!("CM_IPC_TYPES"));
    include!(env!("CM_EGRESS_LIMIT"));
}

use ipc::Data;
include!(env!("CM_EGRESS_SOURCE"));

mod cm_egress_tests {
    use super::*;
    include!(env!("CM_EGRESS_TESTS"));
}

struct QueueAllocator;
thread_local! {
    static QUEUE_BUDGET: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static QUEUE_REFUSALS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn refuse_queue_allocation() -> bool {
    QUEUE_BUDGET.try_with(|budget| match budget.get() {
        None => false,
        Some(0) => {
            QUEUE_REFUSALS.with(|count| count.set(count.get() + 1));
            true
        }
        Some(remaining) => { budget.set(Some(remaining - 1)); false }
    }).unwrap_or(false)
}

unsafe impl std::alloc::GlobalAlloc for QueueAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        if refuse_queue_allocation() { std::ptr::null_mut() }
        else { std::alloc::GlobalAlloc::alloc(&std::alloc::System, layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        if refuse_queue_allocation() { std::ptr::null_mut() }
        else { std::alloc::GlobalAlloc::alloc_zeroed(&std::alloc::System, layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        if refuse_queue_allocation() { std::ptr::null_mut() }
        else { std::alloc::GlobalAlloc::realloc(&std::alloc::System, pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        std::alloc::GlobalAlloc::dealloc(&std::alloc::System, pointer, layout);
    }
}

#[global_allocator]
static QUEUE_ALLOCATOR: QueueAllocator = QueueAllocator;

fn with_queue_budget<T>(budget: usize, action: impl FnOnce() -> T) -> (T, usize) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) { QUEUE_BUDGET.with(|budget| budget.set(None)); }
    }
    QUEUE_REFUSALS.with(|count| count.set(0));
    QUEUE_BUDGET.with(|current| { assert!(current.get().is_none()); current.set(Some(budget)); });
    let reset = Reset;
    let result = action();
    drop(reset);
    (result, QUEUE_REFUSALS.with(std::cell::Cell::get))
}

fn queue_allocation_case(case: &str) {
    fn message(cursor: bool, x: i32) -> Arc<Message> {
        let mut message = Message::new();
        if cursor { message.set_cursor_position(CursorPosition { x, ..Default::default() }); }
        Arc::new(message)
    }
    if case == "probe" {
        with_queue_budget(0, || std::hint::black_box(Vec::<u8>::with_capacity(31)));
        panic!("allocation refusal probe returned");
    }
    let parts: Vec<_> = case.split(':').collect();
    assert_eq!(parts.len(), 3);
    let kind = parts[0];
    let queued: usize = parts[1].parse().unwrap();
    let budget: usize = parts[2].parse().unwrap();
    let replace = kind == "cursor";
    let (sender, mut receiver) = control_egress_channel();
    let stale = sender.clone();
    let mut retained = Vec::new();
    for _ in 0..queued {
        let message = message(replace, 1);
        retained.push(Arc::downgrade(&message));
        sender.send(message).unwrap();
    }
    let capacity = lock_control_egress_state(&sender.state).queue.capacity();
    if kind == "refuse" || kind == "healthy" { assert_eq!(capacity, queued); }
    else { assert!(capacity > queued); }
    let pending = message(replace, 2);
    let pending_weak = Arc::downgrade(&pending);
    let (outcome, refusals) = with_queue_budget(budget, || sender.send(pending));
    if kind == "refuse" {
        assert_eq!(refusals, 1);
        let failure = match outcome {
            Err(ControlEgressAdmissionError::Failed(failure)) => failure,
            other => panic!("allocation failure did not terminate the queue: {other:?}"),
        };
        assert_eq!(failure.to_string(), "controlled control queue storage is unavailable");
        assert!(retained.iter().all(|message| message.upgrade().is_none()));
        assert!(pending_weak.upgrade().is_none());
        assert_eq!(lock_control_egress_state(&sender.state).queued_bytes, 0);
        assert_eq!(stale.send(message(false, 0)), Err(ControlEgressAdmissionError::Failed(failure)));
        assert_eq!(receiver.wake.try_recv(), Ok(()));
        assert!(matches!(receiver.take_next(), Ok(Some(ControlEgressItem::Failed(actual))) if actual == failure));
        assert!(receiver.take_next().is_err());
        assert_eq!(stale.send(message(false, 0)), Err(ControlEgressAdmissionError::ReceiverGone));
        let (fresh, mut fresh_receiver) = control_egress_channel();
        let expected = message(false, 0);
        fresh.send(Arc::clone(&expected)).unwrap();
        assert!(matches!(fresh_receiver.take_next(), Ok(Some(ControlEgressItem::Message(actual))) if Arc::ptr_eq(&actual, &expected)));
    } else {
        assert_eq!(outcome, Ok(()));
        assert_eq!(refusals, 0);
        for weak in &retained {
            if replace { assert!(weak.upgrade().is_none()); continue; }
            let Ok(Some(ControlEgressItem::Message(actual))) = receiver.take_next() else { panic!("queued message lost"); };
            assert_eq!(Arc::as_ptr(&actual), weak.as_ptr());
        }
        let Ok(Some(ControlEgressItem::Message(actual))) = receiver.take_next() else { panic!("new message lost"); };
        assert_eq!(Arc::as_ptr(&actual), pending_weak.as_ptr());
        drop(actual);
        assert!(retained.iter().all(|message| message.upgrade().is_none()));
        assert!(pending_weak.upgrade().is_none());
        assert!(receiver.take_next().unwrap().is_none());
    }
    println!("CONTROL_QUEUE_ALLOC_CASE=pass kind={kind} queued={queued} capacity={capacity} budget={budget} refusals={refusals} state=checked");
}

fn run_allocation_child(test: &str, variable: &str, case: &str) -> std::process::Output {
    use std::{process::{Command, Stdio}, time::Instant};
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env(variable, case).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut timed_out = false;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline { timed_out = true; child.kill().unwrap(); break; }
        std::thread::sleep(Duration::from_millis(2));
    }
    let output = child.wait_with_output().unwrap();
    assert!(!timed_out, "allocation child exceeded deadline after joined cleanup: {case}");
    assert!(output.stdout.len() + output.stderr.len() <= 65536);
    output
}

#[test]
fn queue_growth_failure_is_terminal_and_releases_retained_messages() {
    use std::os::unix::process::ExitStatusExt;
    if let Ok(case) = std::env::var("CONTROL_QUEUE_ALLOC_CASE") {
        queue_allocation_case(&case);
        return;
    }
    let run = |case: &str| run_allocation_child(
        "queue_growth_failure_is_terminal_and_releases_retained_messages", "CONTROL_QUEUE_ALLOC_CASE", case);
    let probe = run("probe");
    assert_eq!(probe.status.signal(), Some(6));
    assert!(String::from_utf8_lossy(&probe.stderr).contains("memory allocation of 31 bytes failed"));
    println!("CONTROL_QUEUE_ALLOC_PROBE=observed bytes=31 signal=6");
    let mut passed = 0;
    for case in ["refuse:0:0", "healthy:0:1", "refuse:4:0", "healthy:4:1",
                 "refuse:8:0", "healthy:8:1", "spare:1:0", "cursor:1:0"] {
        let output = run(case);
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if line.starts_with("CONTROL_QUEUE_ALLOC_CASE=") { println!("{line}"); }
        }
        print!("{}", String::from_utf8_lossy(&output.stderr));
        println!("CONTROL_QUEUE_ALLOC_CHILD=observed case={case} success={} signal={:?}", output.status.success(), output.status.signal());
        passed += usize::from(output.status.success());
    }
    assert_eq!(passed, 8, "allocation failures must terminate only their queue; healthy and replacement controls must preserve messages");
    println!("CONTROL_QUEUE_ALLOC=pass refusals=3 healthy=5 probe=SIGABRT children=joined");
}

fn cm_queue_allocation_case(case: &str) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Payload {
        bytes: Vec<u8>,
        retired: Arc<AtomicUsize>,
    }
    impl AsRef<[u8]> for Payload {
        fn as_ref(&self) -> &[u8] { &self.bytes }
    }
    impl Drop for Payload {
        fn drop(&mut self) { self.retired.fetch_add(1, Ordering::SeqCst); }
    }
    fn response(id: i32, retired: &Arc<AtomicUsize>) -> Data {
        Data::CmFileResponse(ipc::CmFileResponse {
            conn_id: 7, cm_auth_token: "token".to_owned(),
            response: Box::new(ipc::CmFileResponseKind::ReadBlock {
                id, generation: 2, file_num: 3, compressed: false,
                data: bytes::Bytes::from_owner(Payload { bytes: vec![0xa5; 64], retired: Arc::clone(retired) }),
            }),
        })
    }
    if case == "probe" {
        with_queue_budget(0, || std::hint::black_box(Vec::<u8>::with_capacity(31)));
        panic!("CM allocation refusal probe returned");
    }
    let parts: Vec<_> = case.split(':').collect();
    assert_eq!(parts.len(), 3);
    let kind = parts[0];
    let queued: usize = parts[1].parse().unwrap();
    let budget: usize = parts[2].parse().unwrap();
    let retired = Arc::new(AtomicUsize::new(0));
    let (sender, mut receiver) = cm_egress_channel();
    let stale = sender.clone();
    for id in 0..queued { sender.send(response(id as i32, &retired)).unwrap(); }
    let capacity = lock_cm_egress(&sender.state).queue.capacity();
    if kind == "spare" { assert!(capacity > queued); }
    else { assert_eq!(capacity, queued); }
    let pending = response(999, &retired);
    let (outcome, refusals) = with_queue_budget(budget, || sender.send(pending));
    if kind == "refuse" {
        assert_eq!(refusals, 1);
        let failure = match outcome {
            Err(CmEgressAdmissionError::Failed(failure)) => failure,
            other => panic!("CM allocation failure did not terminate the queue: {other:?}"),
        };
        assert_eq!(failure.to_string(), "connection-manager egress queue storage is unavailable");
        assert_eq!(retired.load(Ordering::SeqCst), queued + 1);
        assert_eq!(lock_cm_egress(&sender.state).queued_bytes, 0);
        assert_eq!(stale.send(Data::Close), Err(CmEgressAdmissionError::Failed(failure)));
        assert_eq!(receiver.wake.try_recv(), Ok(()));
        assert!(matches!(receiver.take_next(), Ok(Some(CmEgressItem::Failed(actual))) if actual == failure));
        assert!(receiver.take_next().is_err());
        assert_eq!(stale.send(Data::Close), Err(CmEgressAdmissionError::ReceiverGone));
        let (fresh, mut fresh_receiver) = cm_egress_channel();
        fresh.send(Data::ChatMessage { text: "fresh".to_owned() }).unwrap();
        assert!(matches!(fresh_receiver.take_next(), Ok(Some(CmEgressItem::Data(Data::ChatMessage { text }))) if text == "fresh"));
    } else {
        assert_eq!(outcome, Ok(()));
        assert_eq!(refusals, 0);
        for id in (0..queued).map(|id| id as i32).chain(std::iter::once(999)) {
            let Ok(Some(CmEgressItem::Data(Data::CmFileResponse(response)))) = receiver.take_next() else { panic!("CM response lost"); };
            assert_eq!(response.conn_id, 7);
            assert_eq!(response.cm_auth_token, "token");
            let ipc::CmFileResponseKind::ReadBlock { id: actual, generation, file_num, data, compressed } = *response.response else { panic!("CM response kind changed"); };
            assert_eq!((actual, generation, file_num, compressed), (id, 2, 3, false));
            assert_eq!(data.as_ref(), &[0xa5; 64]);
        }
        assert_eq!(retired.load(Ordering::SeqCst), queued + 1);
        assert!(receiver.take_next().unwrap().is_none());
    }
    println!("CM_QUEUE_ALLOC_CASE=pass kind={kind} queued={queued} capacity={capacity} budget={budget} refusals={refusals} payloads_retired={} state=checked", retired.load(Ordering::SeqCst));
}

#[test]
fn cm_queue_growth_failure_is_terminal_and_releases_payloads() {
    use std::os::unix::process::ExitStatusExt;
    if let Ok(case) = std::env::var("CM_QUEUE_ALLOC_CASE") {
        cm_queue_allocation_case(&case);
        return;
    }
    let run = |case: &str| run_allocation_child(
        "cm_queue_growth_failure_is_terminal_and_releases_payloads", "CM_QUEUE_ALLOC_CASE", case);
    let probe = run("probe");
    assert_eq!(probe.status.signal(), Some(6));
    assert!(String::from_utf8_lossy(&probe.stderr).contains("memory allocation of 31 bytes failed"));
    println!("CM_QUEUE_ALLOC_PROBE=observed bytes=31 signal=6");
    let mut passed = 0;
    for case in ["refuse:0:0", "healthy:0:1", "refuse:4:0", "healthy:4:1",
                 "refuse:8:0", "healthy:8:1", "spare:1:0"] {
        let output = run(case);
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if line.starts_with("CM_QUEUE_ALLOC_CASE=") { println!("{line}"); }
        }
        print!("{}", String::from_utf8_lossy(&output.stderr));
        println!("CM_QUEUE_ALLOC_CHILD=observed case={case} success={} signal={:?}", output.status.success(), output.status.signal());
        passed += usize::from(output.status.success());
    }
    assert_eq!(passed, 7, "CM allocation refusal must retire its queue; healthy responses must preserve exact bytes");
    println!("CM_QUEUE_ALLOC=pass refusals=3 healthy=4 probe=SIGABRT children=joined");
}
