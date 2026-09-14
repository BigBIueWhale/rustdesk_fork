#!/usr/bin/env python3
"""Verify Android's nonblocking exact outgoing-owner lifecycle drain."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, Tuple


class VerificationError(RuntimeError):
    pass


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}")


def forbid(source: str, needle: str, label: str) -> None:
    if needle in source:
        raise VerificationError(f"forbidden {label}")


def require_count(source: str, needle: str, count: int, label: str) -> None:
    actual = source.count(needle)
    if actual != count:
        raise VerificationError(f"{label}: expected {count}, found {actual}")


def require_order(source: str, needles: Tuple[str, ...], label: str) -> None:
    position = -1
    for needle in needles:
        position = source.find(needle, position + 1)
        if position < 0:
            raise VerificationError(f"{label}: missing or misordered {needle!r}")


def extract_item(source: str, signature: str, label: str) -> str:
    start = source.find(signature)
    if start < 0:
        raise VerificationError(f"missing {label}")
    open_brace = source.find("{", start + len(signature))
    if open_brace < 0:
        raise VerificationError(f"missing body for {label}")
    depth = 0
    for offset in range(open_brace, len(source)):
        character = source[offset]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return source[start : offset + 1]
    raise VerificationError(f"unterminated body for {label}")


def load_sources(repo: Path) -> Dict[str, str]:
    android = repo / "flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb"
    return {
        "flutter": (repo / "src/flutter.rs").read_text(encoding="utf-8"),
        "flutter_ffi": (repo / "src/flutter_ffi.rs").read_text(encoding="utf-8"),
        "ffi_kt": (repo / "flutter/android/app/src/main/kotlin/ffi.kt").read_text(
            encoding="utf-8"
        ),
        "activity": (android / "MainActivity.kt").read_text(encoding="utf-8"),
        "service": (android / "MainService.kt").read_text(encoding="utf-8"),
    }


def validate(sources: Dict[str, str]) -> None:
    flutter = sources["flutter"]
    owner_state = extract_item(
        flutter, "struct AndroidClientOwnerState", "Android client-owner state"
    )
    require(
        owner_state,
        "drain_barrier: u64",
        "generation-bound predecessor-drain barrier",
    )
    owner_impl = extract_item(
        flutter, "impl AndroidClientOwnerState", "Android client-owner transitions"
    )
    owner_begin_state = extract_item(
        owner_impl, "fn begin(", "Android client-owner begin transition"
    )
    require(
        owner_begin_state,
        "fn begin(&mut self, drain_barrier: u64)",
        "begin-time exact drain barrier",
    )
    require_order(
        owner_begin_state,
        (
            "self.generation = generation;",
            "self.drain_barrier = drain_barrier;",
            "self.session_id.take()",
        ),
        "generation/barrier/owner replacement transition",
    )
    owner_barrier = extract_item(
        owner_impl,
        "fn admission_barrier(",
        "Android exact-owner admission barrier lookup",
    )
    require(
        owner_barrier,
        "fn admission_barrier(&self, session_id: &SessionID) -> Option<(u64, u64)>",
        "exact generation-and-ticket lookup",
    )
    require_order(
        owner_barrier,
        (
            "self.allows(session_id)",
            "self.generation",
            "self.drain_barrier",
        ),
        "exact owner generation-and-ticket lookup",
    )

    require(
        flutter,
        "const ANDROID_CLIENT_DRAIN_QUEUE_CAPACITY: usize = 1;",
        "one-slot Android lifecycle drain capacity",
    )
    request = extract_item(
        flutter, "struct AndroidClientDrainRequest", "owned Android drain request"
    )
    require(
        request,
        "drain: sessions::ClientOwnerDrain",
        "complete exact client-owner drain ownership",
    )
    coordinator = extract_item(
        flutter,
        "struct AndroidClientDrainCoordinator",
        "process-owned Android drain coordinator",
    )
    require(
        coordinator,
        "sender: mpsc::SyncSender<AndroidClientDrainRequest>",
        "bounded synchronous drain sender",
    )
    require(
        coordinator,
        "_worker: std::thread::JoinHandle<()>",
        "retained process-lifetime drain worker handle",
    )
    coordinator_impl = extract_item(
        flutter,
        "impl AndroidClientDrainCoordinator",
        "Android drain coordinator implementation",
    )
    coordinator_new = extract_item(
        coordinator_impl, "fn new()", "Android drain coordinator construction"
    )
    require_order(
        coordinator_new,
        (
            "mpsc::sync_channel(ANDROID_CLIENT_DRAIN_QUEUE_CAPACITY)",
            "let progress = Arc::new((",
            "Mutex::new(AndroidClientDrainProgress::default())",
            "Condvar::new()",
            '.name("rustdesk-android-client-drain".to_owned())',
            "run_android_client_drain_worker(receiver, worker_progress)",
            "Err(error)",
            "std::process::abort();",
            "_worker: worker",
        ),
        "bounded retained Android drain-worker construction",
    )
    coordinator_progress_lock = extract_item(
        coordinator_impl,
        "fn lock_progress(",
        "Android drain progress fail-stop lock",
    )
    require_order(
        coordinator_progress_lock,
        (
            "self.progress.0.lock()",
            'log::error!("Android client drain progress lock was poisoned")',
            "std::process::abort();",
        ),
        "poisoned coordinator progress fail-stop",
    )
    coordinator_handoff = extract_item(
        coordinator_impl, "fn handoff(", "Android drain ownership handoff"
    )
    require_order(
        coordinator_handoff,
        (
            "let counts = (drain.sessions.len(), drain.handlers.len());",
            "if counts == (0, 0)",
            "self.latest_ticket()",
            "progress.issued.checked_add(1)",
            "progress.issued = ticket;",
            ".try_send(AndroidClientDrainRequest { ticket, drain })",
            "std::process::abort();",
            "(counts, ticket)",
        ),
        "checked nonblocking complete-drain handoff",
    )
    forbid(
        coordinator_handoff,
        ".send(AndroidClientDrainRequest",
        "blocking lifecycle drain handoff",
    )
    coordinator_wait = extract_item(
        coordinator_impl, "fn wait(", "exact Android drain completion wait"
    )
    require_order(
        coordinator_wait,
        (
            "if ticket > progress.issued",
            "while progress.completed < ticket",
            ".wait(progress)",
            "Ok(())",
        ),
        "condition-variable exact-ticket wait",
    )
    require_count(
        coordinator_wait,
        "std::process::abort();",
        2,
        "initial and condition-variable progress poison fail-stop",
    )
    for forbidden, label in (
        ("wait_timeout", "false drain completion timeout"),
        ("sleep(", "polling drain completion sleep"),
        ("yield_now", "spinning drain completion wait"),
    ):
        forbid(coordinator_wait, forbidden, label)

    drain_worker = extract_item(
        flutter,
        "fn run_android_client_drain_worker(",
        "exact Android client drain worker",
    )
    require_order(
        drain_worker,
        (
            "receiver.recv()",
            "std::process::abort();",
            "let ticket = request.ticket;",
            "std::panic::catch_unwind",
            "close_client_owner_drain(request.drain)",
            "std::process::abort();",
            "progress.completed.checked_add(1) != Some(ticket)",
            "ticket > progress.issued",
            "std::process::abort();",
            "progress.completed = ticket;",
            "completed.notify_all();",
        ),
        "exact drain-before-strict-completion worker",
    )
    require(
        flutter,
        "static ref ANDROID_CLIENT_DRAIN_COORDINATOR: AndroidClientDrainCoordinator =\n"
        "        AndroidClientDrainCoordinator::new();",
        "process-lifetime Android client drain coordinator",
    )

    owner_begin = extract_item(
        flutter, "pub fn begin_android_client_owner()", "Android lifecycle owner begin"
    )
    require_order(
        owner_begin,
        (
            "let drain_coordinator = &*ANDROID_CLIENT_DRAIN_COORDINATOR;",
            "ANDROID_CLIENT_OWNER.write()",
            "owner.begin(drain_coordinator.latest_ticket())",
            "sessions::take_sessions_owned_by(&previous_owner)",
            "drain_coordinator.handoff(",
            "owner.drain_barrier = drain_barrier;",
            "drop(owner);",
        ),
        "atomic owner transition and nonblocking exact-drain handoff",
    )
    for forbidden, label in (
        ("close_sessions_owned_by", "synchronous lifecycle owner close"),
        ("close_client_owner_drain", "inline lifecycle owner drain"),
        ("close_and_join", "inline lifecycle worker join"),
        (".wait(", "lifecycle completion wait"),
    ):
        forbid(owner_begin, forbidden, label)

    owner_wait = extract_item(
        flutter,
        "pub fn wait_for_android_client_owner_drain(",
        "Android replacement admission barrier",
    )
    require_order(
        owner_wait,
        (
            "ANDROID_CLIENT_OWNER",
            ".read()",
            ".admission_barrier(session_id)",
            "ANDROID_CLIENT_DRAIN_COORDINATOR.wait(drain_barrier)?;",
            "ANDROID_CLIENT_OWNER.read()",
            "owner.generation != generation",
            "owner.admission_barrier(session_id) != Some((generation, drain_barrier))",
            "bail!",
            "Ok(())",
        ),
        "pre/post-wait exact owner revalidation",
    )
    owner_retire = extract_item(
        flutter,
        "pub fn retire_android_client_owner(",
        "Android lifecycle owner retirement",
    )
    require_order(
        owner_retire,
        (
            "let drain_coordinator = &*ANDROID_CLIENT_DRAIN_COORDINATOR;",
            "ANDROID_CLIENT_OWNER.write()",
            "owner.retire(generation, session_id)",
            "sessions::take_sessions_owned_by(session_id)",
            "drain_coordinator.handoff(",
            "drop(owner);",
            "retired",
        ),
        "exact retirement and nonblocking complete-drain handoff",
    )
    for forbidden, label in (
        ("close_sessions_owned_by", "synchronous lifecycle retirement close"),
        ("close_client_owner_drain", "inline lifecycle retirement drain"),
        ("close_and_join", "inline lifecycle retirement worker join"),
        (".wait(", "lifecycle retirement completion wait"),
    ):
        forbid(owner_retire, forbidden, label)

    replacement_take = extract_item(
        flutter,
        "fn take_previous_android_mobile_client_sessions(",
        "Android prior-mobile removal transaction",
    )
    require_order(
        replacement_take,
        (
            "acquire_android_client_owner(client_owner_id)?",
            "sessions::take_mobile_sessions_except(client_owner_id, session_id)",
            "drop(owner_admission);",
            "Ok(drain)",
        ),
        "owner-admitted removal before releasing authority for exact finality",
    )
    for forbidden, label in (
        ("close_client_owner_drain", "prior-mobile finality under the owner guard"),
        ("close_and_join", "prior-mobile worker join under the owner guard"),
    ):
        forbid(replacement_take, forbidden, label)
    session_add = extract_item(
        flutter, "pub fn session_add(", "mobile session-add transaction"
    )
    require_order(
        session_add,
        (
            "take_previous_android_mobile_client_sessions(client_owner_id, session_id)?",
            "close_client_owner_drain(previous_mobile_client_sessions)",
            "let owner_admission = acquire_android_client_owner(client_owner_id)?;",
            "sessions::insert_session(",
            "drop(owner_admission);",
        ),
        "off-component finality then exact-owner revalidation and insertion",
    )

    lifecycle_test = extract_item(
        flutter,
        "fn android_lifecycle_retirement_is_nonblocking_and_replacement_waits_for_exact_drain()",
        "blocked-worker lifecycle/admission regression",
    )
    require_order(
        lifecycle_test,
        (
            "begin_android_client_owner()",
            "bind_android_client_owner(generation, owner)",
            "insert_test_session_for_owner(",
            "begin_android_client_owner()",
            'expect("Activity owner transition blocked on predecessor finality")',
            'expect("exact drain did not close the predecessor worker")',
            "assert!(!finished.load(Ordering::Acquire));",
            "bind_android_client_owner(",
            "wait_for_android_client_owner_drain(&replacement_owner)",
            '"replacement admission crossed an incomplete predecessor drain"',
            "release_worker_tx.send(())",
            '"replacement drain barrier did not complete"',
            "assert!(finished.load(Ordering::Acquire));",
            "session.thread.lock().unwrap().is_none()",
        ),
        "nonblocking transition and exact pre-insertion barrier behavior",
    )
    replacement_drain_test = extract_item(
        flutter,
        "fn android_lifecycle_transition_does_not_wait_for_mobile_replacement_drain()",
        "blocked mobile-replacement drain regression",
    )
    require_order(
        replacement_drain_test,
        (
            "take_previous_android_mobile_client_sessions(&owner, &replacement_session_id)",
            "close_client_owner_drain(predecessor_drain)",
            'expect("mobile replacement drain did not close its predecessor worker")',
            "begin_android_client_owner()",
            'expect("Activity owner transition waited on mobile replacement finality")',
            "release_worker_tx.send(())",
            "cleanup.join()",
        ),
        "lifecycle transition independent of asynchronous mobile replacement finality",
    )

    flutter_ffi = sources["flutter_ffi"]
    mobile_add = extract_item(
        flutter_ffi, "pub fn session_add_mobile(", "asynchronous mobile add bridge"
    )
    require_order(
        mobile_add,
        (
            "MOBILE_SESSION_ADD_TRANSACTION",
            ".lock()",
            '#[cfg(target_os = "android")]',
            "flutter::wait_for_android_client_owner_drain(&client_owner_id)?;",
            "session_add(",
        ),
        "serialized off-component predecessor barrier before insertion",
    )
    lifecycle_jni = extract_item(
        flutter_ffi,
        "fn Java_ffi_FFI_retireClientSessions(",
        "Android retirement JNI",
    )
    require_order(
        lifecycle_jni,
        (
            "parse_client_session_owner",
            "crate::flutter::retire_android_client_owner(generation, &session_id)",
            "Retired {peer_count} Android client peer session(s)",
        ),
        "typed JNI exact retirement",
    )
    forbid(
        flutter_ffi,
        "Java_ffi_FFI_closeClientSessions",
        "old synchronous-close JNI name",
    )

    ffi_kt = sources["ffi_kt"]
    require(
        ffi_kt,
        "external fun retireClientSessions(generation: Long, sessionId: String): Int",
        "typed Kotlin retirement JNI",
    )
    forbid(ffi_kt, "closeClientSessions", "old Kotlin synchronous-close name")

    activity = sources["activity"]
    on_create = extract_item(activity, "override fun onCreate", "Activity creation")
    require_order(
        on_create,
        (
            "clientSessionOwnerGeneration = FFI.beginClientSessionOwner()",
            "super.onCreate(savedInstanceState)",
        ),
        "owner invalidation before replacement engine startup",
    )
    on_destroy = extract_item(activity, "override fun onDestroy()", "Activity teardown")
    require(
        on_destroy,
        "FFI.retireClientSessions(owner.generation, owner.sessionId)",
        "Activity exact nonblocking retirement",
    )
    require_count(
        activity,
        "FFI.retireClientSessions(owner.generation, owner.sessionId)",
        3,
        "all Activity exact retirement paths",
    )
    forbid(activity, "FFI.closeClientSessions", "old Activity synchronous close call")

    task_removed = extract_item(
        sources["service"], "override fun onTaskRemoved", "foreground-service task removal"
    )
    require_order(
        task_removed,
        (
            "MainActivity.takeStoppedClientSessionOwners()",
            "VoiceCallAudioCoordinator.unregisterOutgoingOwner(owner.toVoiceCallOwner())",
            "FFI.retireClientSessions(owner.generation, owner.sessionId)",
            "super.onTaskRemoved(rootIntent)",
        ),
        "task-removal exact nonblocking owner retirement",
    )
    forbid(
        sources["service"],
        "FFI.closeClientSessions",
        "old service synchronous close call",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="repository root")
    args = parser.parse_args()
    sources = load_sources(Path(args.repo).resolve())
    validate(sources)
    print("android client lifecycle-drain verifier: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
