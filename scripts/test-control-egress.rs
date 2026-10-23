extern crate self as hbb_common;

pub use log;
pub use sodiumoxide;
pub use tokio;

#[path = "../libs/hbb_common/src/bytes_codec.rs"]
pub mod bytes_codec;

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
include!(env!("CM_DIRECTORY_SOURCE"));

mod cm_egress_tests {
    use super::*;
    include!(env!("CM_EGRESS_TESTS"));
}

struct QueueAllocator;
thread_local! {
    static QUEUE_BUDGET: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static QUEUE_REFUSALS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CM_BACKING_TARGET: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CM_BACKING_RETIRED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static CM_DIRECTORY_TARGET: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}

fn refuse_queue_allocation(size: usize) -> bool {
    if CM_DIRECTORY_TARGET.try_with(|state| {
        let (target, refusals) = state.get();
        if target != 0 && target == size {
            state.set((0, refusals + 1));
            true
        } else { false }
    }).unwrap_or(false) { return true; }
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
        if refuse_queue_allocation(layout.size()) { std::ptr::null_mut() }
        else { std::alloc::GlobalAlloc::alloc(&std::alloc::System, layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        if refuse_queue_allocation(layout.size()) { std::ptr::null_mut() }
        else { std::alloc::GlobalAlloc::alloc_zeroed(&std::alloc::System, layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        if refuse_queue_allocation(size) { std::ptr::null_mut() }
        else { std::alloc::GlobalAlloc::realloc(&std::alloc::System, pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        if CM_BACKING_TARGET.try_with(|target| target.get() == pointer as usize).unwrap_or(false) {
            CM_BACKING_RETIRED.with(|retired| retired.set(true));
        }
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

fn cm_directory_input(count: usize) -> FileDirectory {
    let kinds = [FileType::Dir, FileType::DirLink, FileType::DirDrive, FileType::File, FileType::FileLink];
    FileDirectory {
        id: 41,
        path: "fixture/目录".into(),
        entries: (0..count).map(|index| FileEntry {
            entry_type: kinds[index % kinds.len()].into(),
            name: format!("entry-{index}-é"),
            is_hidden: index % 2 == 0,
            size: index as u64 * 123,
            modified_time: 1000 + index as u64,
            ..Default::default()
        }).collect(),
        ..Default::default()
    }
}

fn assert_cm_directory(directory: &ipc::CmFileDirectory, count: usize) {
    let kinds = [ipc::CmFileEntryType::Directory, ipc::CmFileEntryType::DirectoryLink,
        ipc::CmFileEntryType::DirectoryDrive, ipc::CmFileEntryType::File, ipc::CmFileEntryType::FileLink];
    assert_eq!(directory.id, 41);
    assert_eq!(directory.path, "fixture/目录");
    assert_eq!(directory.entries.len(), count);
    for (index, entry) in directory.entries.iter().enumerate() {
        assert_eq!(entry.entry_type, kinds[index % kinds.len()]);
        assert_eq!(entry.name, format!("entry-{index}-é"));
        assert_eq!(entry.is_hidden, index % 2 == 0);
        assert_eq!(entry.size, index as u64 * 123);
        assert_eq!(entry.modified_time, 1000 + index as u64);
    }
}

fn cm_directory_roundtrip(result: Result<ipc::CmFileDirectory, String>) -> Result<ipc::CmFileDirectory, String> {
    let response = ipc::CmFileResponse {
        conn_id: 17,
        cm_auth_token: "owned-token".into(),
        response: Box::new(ipc::CmFileResponseKind::ReadDirectory {
            request_id: 93, path: "requested-path".into(), result,
        }),
    };
    let decoded: ipc::CmFileResponse = serde_json::from_slice(&serde_json::to_vec(&response).unwrap()).unwrap();
    assert_eq!(decoded, response);
    let (sender, mut receiver) = cm_egress_channel();
    sender.send(Data::CmFileResponse(decoded)).unwrap();
    let Some(CmEgressItem::Data(Data::CmFileResponse(actual))) = receiver.take_next().unwrap() else {
        panic!("directory response was not retained");
    };
    assert_eq!(actual.conn_id, 17);
    assert_eq!(actual.cm_auth_token, "owned-token");
    let ipc::CmFileResponseKind::ReadDirectory { request_id, path, result } = *actual.response else {
        panic!("directory response changed class");
    };
    assert_eq!(request_id, 93);
    assert_eq!(path, "requested-path");
    assert!(receiver.take_next().unwrap().is_none());
    result
}

#[test]
fn cm_directory_conversion_preserves_fields_and_queue_identity() {
    for count in [0, 1, 5, 64] {
        let result = cm_directory_roundtrip(cm_file_directory(cm_directory_input(count))).unwrap();
        assert_cm_directory(&result, count);
    }
    let mut invalid = cm_directory_input(1);
    invalid.entries[0].entry_type = protobuf::EnumOrUnknown::from_i32(-9);
    assert_eq!(cm_directory_roundtrip(cm_file_directory(invalid)).unwrap_err(), "unknown file entry type -9");
    println!("CM_DIRECTORY_CONTROL=pass counts=4 kinds=5 fields=exact unknown=refused json=exact queue_identity=preserved");
}

#[test]
fn cm_directory_output_allocation_refusal_reports_error_and_retries() {
    use std::os::unix::process::ExitStatusExt;
    fn observe<T>(target: usize, action: impl FnOnce() -> T) -> (T, usize) {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) { CM_DIRECTORY_TARGET.with(|state| state.set((0, 0))); }
        }
        CM_DIRECTORY_TARGET.with(|state| { assert_eq!(state.get(), (0, 0)); state.set((target, 0)); });
        let reset = Reset;
        let result = action();
        let refusals = CM_DIRECTORY_TARGET.with(|state| state.get().1);
        drop(reset);
        (result, refusals)
    }
    if let Ok(case) = std::env::var("CM_DIRECTORY_ALLOC_CASE") {
        if case == "probe" {
            observe(31, || std::hint::black_box(Vec::<u8>::with_capacity(31)));
            panic!("directory allocation-refusal probe returned");
        }
        let count: usize = case.parse().unwrap();
        assert!([1, 5, 64].contains(&count));
        let input = cm_directory_input(count);
        let target = count * std::mem::size_of::<ipc::CmFileEntry>();
        let (result, refusals) = observe(target, || cm_file_directory(input));
        assert_eq!(refusals, 1);
        assert_eq!(cm_directory_roundtrip(result).unwrap_err(), "Not enough memory for directory entries");
        let retry = cm_directory_roundtrip(cm_file_directory(cm_directory_input(count))).unwrap();
        assert_cm_directory(&retry, count);
        println!("CM_DIRECTORY_ALLOC_CASE=pass entries={count} refusals={refusals} error=reported retry=exact queue_identity=preserved");
        return;
    }
    let run = |case: &str| run_allocation_child(
        "cm_directory_output_allocation_refusal_reports_error_and_retries", "CM_DIRECTORY_ALLOC_CASE", case);
    let probe = run("probe");
    assert_eq!(probe.status.signal(), Some(6));
    assert!(String::from_utf8_lossy(&probe.stderr).contains("memory allocation of 31 bytes failed"));
    println!("CM_DIRECTORY_ALLOC_PROBE=observed bytes=31 signal=6");
    let mut passed = 0;
    for count in [1, 5, 64] {
        let output = run(&count.to_string());
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if line.starts_with("CM_DIRECTORY_ALLOC_CASE=") { println!("{line}"); }
        }
        print!("{}", String::from_utf8_lossy(&output.stderr));
        println!("CM_DIRECTORY_ALLOC_CHILD=observed entries={count} success={} signal={:?}", output.status.success(), output.status.signal());
        passed += usize::from(output.status.success());
    }
    assert_eq!(passed, 3, "directory output refusal must report an error without aborting its process");
    println!("CM_DIRECTORY_ALLOC=pass refusals=3 retries=exact queue_identity=preserved probe=SIGABRT children=joined");
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
    if queued == 1 { assert!(capacity > queued); }
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
    for case in ["refuse:0:0", "refuse:0:1", "healthy:0:2",
                 "refuse:4:0", "refuse:4:1", "healthy:4:2",
                 "refuse:8:0", "refuse:8:1", "healthy:8:2",
                 "refuse:1:0", "spare:1:1"] {
        let output = run(case);
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if line.starts_with("CM_QUEUE_ALLOC_CASE=") { println!("{line}"); }
        }
        print!("{}", String::from_utf8_lossy(&output.stderr));
        println!("CM_QUEUE_ALLOC_CHILD=observed case={case} success={} signal={:?}", output.status.success(), output.status.signal());
        passed += usize::from(output.status.success());
    }
    assert_eq!(passed, 11, "CM queue and payload allocation refusal must retire its queue; healthy responses must preserve exact bytes");
    println!("CM_QUEUE_ALLOC=pass refusals=7 healthy=4 probe=SIGABRT children=joined");
}

#[test]
fn cm_queue_admission_owns_only_raw_payload_bytes() {
    use tokio_util::codec::{Decoder, Encoder};
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) { CM_BACKING_TARGET.with(|target| target.set(0)); }
    }
    let mut failures = 0;
    for length in [0, 1, 64, 65_536, ipc::CM_FILE_BLOCK_MAX_FRAME_BYTES] {
        let (sender, mut receiver) = cm_egress_channel();
        let mut wire = bytes::BytesMut::with_capacity(8 * 1024 * 1024);
        let pointer = wire.as_ptr() as usize;
        let capacity = wire.capacity();
        wire.resize(capacity, 0x7d);
        wire.clear();
        CM_BACKING_RETIRED.with(|retired| retired.set(false));
        CM_BACKING_TARGET.with(|target| { assert_eq!(target.get(), 0); target.set(pointer); });
        let reset = Reset;
        let mut codec = bytes_codec::BytesCodec::new();
        codec.set_max_packet_length(ipc::CM_IPC_MAX_FRAME_BYTES);
        codec.encode(bytes::Bytes::from(serde_json::to_vec(&Data::ChatMessage {
            text: "x".repeat(4 * 1024 * 1024),
        }).unwrap()), &mut wire).unwrap();
        codec.encode(bytes::Bytes::from(serde_json::to_vec(&Data::CmFileResponse(ipc::CmFileResponse {
            conn_id: 7, cm_auth_token: "token".to_owned(),
            response: Box::new(ipc::CmFileResponseKind::ReadBlock {
                id: 41, generation: 2, file_num: 3, compressed: false, data: bytes::Bytes::new(),
            }),
        })).unwrap()), &mut wire).unwrap();
        codec.encode(bytes::Bytes::from(vec![0xa5; length]), &mut wire).unwrap();
        assert_eq!(wire.as_ptr() as usize, pointer);
        let previous = codec.decode(&mut wire).unwrap().unwrap();
        assert!(matches!(serde_json::from_slice::<Data>(&previous).unwrap(), Data::ChatMessage { text } if text.len() == 4 * 1024 * 1024));
        drop(previous);
        let metadata = codec.decode(&mut wire).unwrap().unwrap();
        let mut response = serde_json::from_slice::<Data>(&metadata).unwrap();
        drop(metadata);
        codec.set_max_packet_length(ipc::CM_FILE_BLOCK_MAX_FRAME_BYTES);
        let raw = codec.decode(&mut wire).unwrap().unwrap().freeze();
        assert_eq!(raw.len(), length);
        assert!(codec.decode_eof(&mut wire).unwrap().is_none());
        drop(wire);
        let Data::CmFileResponse(envelope) = &mut response else { panic!("CM metadata changed"); };
        let ipc::CmFileResponseKind::ReadBlock { data, .. } = envelope.response.as_mut() else { panic!("CM response kind changed"); };
        *data = raw;
        sender.send(response).unwrap();
        let released_at_admission = CM_BACKING_RETIRED.with(std::cell::Cell::get);
        let item = receiver.take_next().unwrap().unwrap();
        let exact = match &item {
            CmEgressItem::Data(Data::CmFileResponse(response)) => {
                response.conn_id == 7 && response.cm_auth_token == "token"
                    && matches!(response.response.as_ref(), ipc::CmFileResponseKind::ReadBlock {
                        id: 41, generation: 2, file_num: 3, compressed: false, data,
                    } if data.len() == length && data.iter().all(|byte| *byte == 0xa5))
            }
            _ => false,
        };
        drop(item);
        let released_after_drain = CM_BACKING_RETIRED.with(std::cell::Cell::get);
        assert!(released_after_drain, "deallocation observer must see the original buffer retire");
        failures += usize::from(!released_at_admission || !exact);
        println!("CM_RAW_BACKING_CASE=observed length={length} backing_capacity={capacity} released_at_admission={released_at_admission} released_after_drain={released_after_drain} payload_exact={exact}");
        drop(reset);
    }
    assert_eq!(failures, 0, "a queued raw payload must not pin unrelated transport-buffer capacity");
    println!("CM_RAW_BACKING=pass cases=5 original_allocation=retired-at-admission payload=exact");
}

fn concurrent_cm_response(id: i32) -> (Data, Arc<std::sync::atomic::AtomicBool>) {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Source {
        storage: Vec<u8>,
        retired: Arc<AtomicBool>,
    }
    impl AsRef<[u8]> for Source {
        fn as_ref(&self) -> &[u8] { &self.storage }
    }
    impl Drop for Source {
        fn drop(&mut self) { self.retired.store(true, Ordering::SeqCst); }
    }
    let retired = Arc::new(AtomicBool::new(false));
    let mut storage = Vec::with_capacity(ipc::CM_FILE_BLOCK_MAX_FRAME_BYTES);
    storage.resize(64, id as u8);
    let data = bytes::Bytes::from_owner(Source { storage, retired: Arc::clone(&retired) });
    (Data::CmFileResponse(ipc::CmFileResponse {
        conn_id: 7, cm_auth_token: "token".to_owned(),
        response: Box::new(ipc::CmFileResponseKind::ReadBlock {
            id, generation: 2, file_num: 3, compressed: false, data,
        }),
    }), retired)
}

#[test]
fn cm_queue_concurrent_producers_release_sources_and_preserve_fifo() {
    use std::sync::{atomic::Ordering, Barrier};
    let (sender, mut receiver) = cm_egress_channel();
    let start = Arc::new(Barrier::new(9));
    let workers: Vec<_> = (0..8).map(|producer| {
        let sender = sender.clone();
        let start = Arc::clone(&start);
        std::thread::spawn(move || {
            start.wait();
            (0..16).map(|sequence| {
                let (response, retired) = concurrent_cm_response(1 + producer * 16 + sequence);
                let result = sender.send(response);
                (result, retired.load(Ordering::SeqCst))
            }).collect::<Vec<_>>()
        })
    }).collect();
    start.wait();
    let outcomes: Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
    assert!(outcomes.iter().flatten().all(|(result, retired)| result.is_ok() && *retired));
    let mut next = [0; 8];
    for _ in 0..128 {
        let Ok(Some(CmEgressItem::Data(Data::CmFileResponse(response)))) = receiver.take_next() else {
            panic!("concurrent CM response lost");
        };
        assert_eq!((response.conn_id, response.cm_auth_token.as_str()), (7, "token"));
        let ipc::CmFileResponseKind::ReadBlock { id, generation, file_num, compressed, data } = *response.response else {
            panic!("concurrent CM response kind changed");
        };
        assert!((1..=128).contains(&id));
        let producer = ((id - 1) / 16) as usize;
        assert_eq!((id - 1) % 16, next[producer]);
        next[producer] += 1;
        assert_eq!((generation, file_num, compressed), (2, 3, false));
        assert_eq!(data.as_ref(), &[id as u8; 64]);
    }
    assert_eq!(next, [16; 8]);
    assert!(receiver.take_next().unwrap().is_none());
    assert_eq!(lock_cm_egress(&sender.state).queued_bytes, 0);
    println!("CM_QUEUE_CONCURRENT=pass case=fifo producers=8 messages=128 raw_source=retired payload=exact threads=joined");
}

#[test]
fn cm_queue_concurrent_saturation_is_terminal() {
    use std::sync::{atomic::Ordering, Barrier};
    let (sender, mut receiver) = cm_egress_channel_with_limits(CmEgressLimits {
        max_messages: 8, ..CM_EGRESS_LIMITS
    });
    let start = Arc::new(Barrier::new(9));
    let filled = Arc::new(Barrier::new(9));
    let overflow = Arc::new(Barrier::new(9));
    let workers: Vec<_> = (0..8).map(|producer| {
        let sender = sender.clone();
        let start = Arc::clone(&start);
        let filled = Arc::clone(&filled);
        let overflow = Arc::clone(&overflow);
        std::thread::spawn(move || {
            start.wait();
            let (response, retired) = concurrent_cm_response(1 + producer);
            let first = sender.send(response);
            let first_retired = retired.load(Ordering::SeqCst);
            filled.wait();
            overflow.wait();
            let (response, retired) = concurrent_cm_response(9 + producer);
            let second = sender.send(response);
            (first, first_retired, second, retired.load(Ordering::SeqCst))
        })
    }).collect();
    start.wait();
    filled.wait();
    let held_count = lock_cm_egress(&sender.state).queue.len();
    overflow.wait();
    let outcomes: Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
    assert_eq!(held_count, 8);
    let failure = CmEgressAdmissionError::Failed(CmEgressFailure::MessageCapacity);
    assert!(outcomes.iter().all(|(first, retired, second, refused_retired)|
        first.is_ok() && *retired && *second == Err(failure) && *refused_retired));
    {
        let state = lock_cm_egress(&sender.state);
        assert!(state.queue.is_empty());
        assert_eq!(state.queued_bytes, 0);
    }
    assert_eq!(receiver.wake.try_recv(), Ok(()));
    assert!(matches!(receiver.take_next(), Ok(Some(CmEgressItem::Failed(CmEgressFailure::MessageCapacity)))));
    assert!(receiver.take_next().is_err());
    assert_eq!(sender.send(Data::Close), Err(CmEgressAdmissionError::ReceiverGone));
    let (fresh, mut fresh_receiver) = cm_egress_channel();
    let (response, retired) = concurrent_cm_response(17);
    fresh.send(response).unwrap();
    assert!(retired.load(Ordering::SeqCst));
    assert!(matches!(fresh_receiver.take_next(), Ok(Some(CmEgressItem::Data(Data::CmFileResponse(_))))));
    assert!(fresh_receiver.take_next().unwrap().is_none());
    println!("CM_QUEUE_CONCURRENT=pass case=saturation producers=8 admitted=8 refused=8 terminal=once stale=refused fresh=usable threads=joined");
}
