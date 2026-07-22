#!/usr/bin/env python3
"""Verify event-driven worker and exact voice-call input ownership."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, Tuple


class VerificationError(RuntimeError):
    pass


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}")


def require_exact_count(source: str, needle: str, count: int, label: str) -> None:
    actual = source.count(needle)
    if actual != count:
        raise VerificationError(f"{label}: expected {count}, found {actual}")


def require_order(source: str, needles: Tuple[str, ...], label: str) -> None:
    position = -1
    for needle in needles:
        position = source.find(needle, position + 1)
        if position < 0:
            raise VerificationError(f"{label}: missing or misordered {needle!r}")


def extract_rust_item(source: str, signature: str, label: str) -> str:
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
    return {
        "io_loop": (repo / "src/client/io_loop.rs").read_text(encoding="utf-8"),
        "client": (repo / "src/client.rs").read_text(encoding="utf-8"),
        "audio": (repo / "src/server/audio_service.rs").read_text(encoding="utf-8"),
        "connection": (repo / "src/server/connection.rs").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "apple": (repo / "scripts/apple-conform-check.sh").read_text(encoding="utf-8"),
    }


def validate(sources: Dict[str, str]) -> None:
    io_loop = sources["io_loop"]
    owner = extract_rust_item(io_loop, "struct VoiceCallThread", "voice-call owner")
    for needle, label in (
        ("stop_requested: Arc<AtomicBool>", "durable stop owner"),
        ("subscription: Option<ConnInner>", "exact subscription owner"),
        ("input_lease: Option<audio_service::VoiceCallInputLease>", "exact input lease owner"),
        ("thread: Option<std::thread::JoinHandle<()>>", "exact worker owner"),
    ):
        require(owner, needle, label)

    stop = extract_rust_item(
        io_loop,
        "fn stop(&mut self) -> Option<std::thread::JoinHandle<()>>",
        "voice-call stop",
    )
    require_order(
        stop,
        (
            "self.stop_requested.store(true, Ordering::Release);",
            "if let Some(subscription) = self.subscription.take()",
            "CLIENT_SERVER.write().unwrap().subscribe(",
            "audio_service::NAME",
            "subscription",
            "false",
            "drop(self.input_lease.take());",
            "self.thread.take()",
        ),
        "durable stop, exact unsubscribe, and handle transfer",
    )
    for forbidden in ("try_recv", "thread::sleep", "Runtime::new", "block_on"):
        if forbidden in stop:
            raise VerificationError(f"voice-call stop retains polling/runtime shape {forbidden!r}")

    receive = extract_rust_item(
        io_loop, "fn recv_voice_call_audio(", "blocking voice-call receive"
    )
    require_exact_count(
        receive,
        "stop_requested.load(Ordering::Acquire)",
        2,
        "pre/post-wake retirement checks",
    )
    require_order(
        receive,
        (
            "if stop_requested.load(Ordering::Acquire)",
            "receiver.blocking_recv()?",
            "if stop_requested.load(Ordering::Acquire)",
            "None",
            "Some(message)",
        ),
        "blocking receive and post-wake retirement refusal",
    )
    for forbidden in ("try_recv", "thread::sleep", "tokio::spawn", "Runtime::new", "block_on"):
        if forbidden in receive:
            raise VerificationError(
                f"voice-call receive retains polling/detached-runtime shape {forbidden!r}"
            )

    start = extract_rust_item(
        io_loop,
        "fn start_voice_call(&mut self) -> Option<VoiceCallThread>",
        "voice-call start",
    )
    require_order(
        start,
        (
            "let input_lease = match crate::audio_service::acquire_voice_call_input(",
            "get_default_sound_input()",
            "let client_conn_inner = ConnInner::new(",
            "client_conn_inner.clone()",
            "true",
            "let stop_requested = Arc::new(AtomicBool::new(false));",
            "let cleanup_subscription = ConnInner::new(conn_id, None, None);",
            "std::thread::Builder::new()",
            '.name("rustdesk-viewer-voice-call".to_owned())',
            "while let Some(msg) =",
            "recv_voice_call_audio(&mut rx_audio_data, &worker_stop_requested)",
            'log::debug!("Exit voice call audio service of client")',
            "cleanup_subscription",
        ),
        "input lease, subscription, blocking worker, and idempotent cleanup",
    )
    require(
        start,
        "audio_service::NAME,\n                        cleanup_subscription,\n                        false,",
        "worker cleanup exact unsubscribe",
    )
    require_order(
        start,
        (
            "Err(err) =>",
            'log::error!("Failed to start voice-call audio worker: {err}")',
            "client_conn_inner",
            "false",
            "return None;",
        ),
        "worker spawn subscription rollback",
    )
    require(
        start,
        "audio_service::NAME,\n                        client_conn_inner,\n                        false,",
        "spawn failure exact unsubscribe",
    )
    require_order(
        start,
        (
            "VoiceCallThread::new(",
            "stop_requested",
            "client_conn_inner",
            "input_lease",
            "thread",
        ),
        "composite owner construction",
    )
    for forbidden in (
        "std::sync::mpsc::channel",
        "rx.try_recv()",
        "rx_audio_data.try_recv()",
        "TryRecvError",
        "std::thread::spawn(move ||",
    ):
        if forbidden in start:
            raise VerificationError(f"voice-call start retains legacy polling shape {forbidden!r}")
    if "set_voice_call_input_device(None" in start:
        raise VerificationError("outgoing worker retains ambient global input cleanup")

    shutdown = extract_rust_item(io_loop, "async fn shutdown_workers", "viewer worker shutdown")
    require_exact_count(
        io_loop,
        "voice_call_thread.stop()",
        2,
        "explicit voice-call stop sinks",
    )
    require_order(
        shutdown,
        (
            "voice_call_thread.stop()",
            'workers.push(("voice-call", worker));',
            "Self::join_workers(workers).await;",
        ),
        "voice-call stop and exact completion join",
    )
    require(
        sources["client"],
        "join_media_workers_off_runtime(workers).await",
        "fixed media-completion pool join sink",
    )
    require(
        io_loop,
        'reap_media_worker("voice-call", thread)',
        "hard-Drop voice-call completion handoff",
    )

    for test_name in (
        "r_s11e82_voice_call_audio_wait_is_event_driven_and_stop_is_terminal",
        "r_s11e82_voice_call_audio_wait_delivers_a_live_message",
    ):
        require_exact_count(io_loop, f"fn {test_name}()", 1, f"focused test {test_name}")
    for needle, label in (
        ("an idle voice-call worker must block instead of polling", "idle blocking assertion"),
        ("subscription closure must wake the blocked worker", "closure wake assertion"),
        (
            "queued audio must wake into the post-receive stop check",
            "post-wake queued-audio refusal assertion",
        ),
        ("stop_requested = AtomicBool::new(true)", "queued stop fixture"),
        ("Arc::ptr_eq(&actual, &expected)", "live-message identity assertion"),
    ):
        require(io_loop, needle, label)

    audio = sources["audio"]
    input_state = extract_rust_item(
        audio, "struct VoiceCallInputState", "voice-call input state"
    )
    require(input_state, "device: Option<String>", "shared selected input")
    require(input_state, "owners: usize", "active input owner count")
    acquire_state = extract_rust_item(
        audio,
        "fn acquire(&mut self, default_device: Option<String>)",
        "voice-call input state acquisition",
    )
    require_order(
        acquire_state,
        (
            "self.owners.checked_add(1)",
            "self.owners = owners;",
            "if self.device.is_none() && default_device.is_some()",
            "self.device = default_device;",
        ),
        "bounded owner acquisition and first-owner default",
    )
    release_state = extract_rust_item(
        audio, "fn release(&mut self)", "voice-call input state release"
    )
    require_order(
        release_state,
        (
            "self.owners.checked_sub(1)",
            "self.owners = owners;",
            "if owners == 0",
            "self.device.take().is_some()",
        ),
        "final-owner-only input reset",
    )
    input_lease = extract_rust_item(
        audio, "pub struct VoiceCallInputLease", "private voice-call input lease"
    )
    require(input_lease, "_private: ()", "non-forgeable input lease")
    input_drop = extract_rust_item(
        audio, "impl Drop for VoiceCallInputLease", "voice-call input lease Drop"
    )
    require_order(
        input_drop,
        (
            "VOICE_CALL_INPUT_STATE.lock().unwrap().release()",
            "std::process::abort();",
            "if restart_required",
            "restart();",
        ),
        "exact lease release and invariant failure",
    )
    acquire_input = extract_rust_item(
        audio,
        "pub fn acquire_voice_call_input(",
        "voice-call input lease acquisition",
    )
    require_order(
        acquire_input,
        (
            ".acquire(default_device)",
            "if restart_required",
            "restart();",
            "Ok(VoiceCallInputLease { _private: () })",
        ),
        "state acquisition before private lease construction",
    )
    setter = extract_rust_item(
        audio,
        "pub fn set_voice_call_input_device(device: String)",
        "voice-call device selection",
    )
    require(setter, ".select_device(device)", "device selection without owner mutation")
    select_device = extract_rust_item(
        audio,
        "fn select_device(&mut self, device: String)",
        "non-clearing voice-call device selection",
    )
    require(
        select_device,
        "self.device = Some(device);",
        "selected voice-call device installation",
    )
    if "set_if_present" in audio:
        raise VerificationError("voice-call input retains boolean ownership ambiguity")
    for test_name in (
        "r_s11e83_voice_call_input_remains_selected_until_the_final_owner_releases",
        "r_s11e83_voice_call_input_owner_count_fails_closed",
    ):
        require_exact_count(audio, f"fn {test_name}()", 1, f"focused test {test_name}")

    connection = sources["connection"]
    require(
        connection,
        "voice_call_input: Option<audio_service::VoiceCallInputLease>",
        "controlled exact input owner",
    )
    if "voice_calling" in connection:
        raise VerificationError("controlled call retains parallel boolean ownership")
    handle_voice = extract_rust_item(
        connection,
        "pub async fn handle_voice_call(&mut self, accepted: bool)",
        "controlled voice-call acceptance",
    )
    require_order(
        handle_voice,
        (
            "crate::audio_service::acquire_voice_call_input(",
            "self.voice_call_input = Some(input_lease);",
            "let msg = new_voice_call_response(ts.get(), accepted);",
            "self.send(msg).await;",
        ),
        "lease-before-response acceptance ownership",
    )
    close_voice = extract_rust_item(
        connection,
        "pub async fn close_voice_call(&mut self)",
        "controlled voice-call close",
    )
    require_order(
        close_voice,
        (
            "drop(self.voice_call_input.take());",
            "self.voice_call_request_timestamp = None;",
            "self.stop_controlled_audio().await;",
        ),
        "exact input release before decoder drain",
    )
    on_close = extract_rust_item(connection, "async fn on_close", "connection close")
    require_order(
        on_close,
        (
            "drop(self.voice_call_input.take());",
            "self.stop_controlled_audio().await;",
        ),
        "connection close input release before await",
    )
    connection_drop = extract_rust_item(
        connection, "impl Drop for Connection", "connection Drop"
    )
    require(
        connection_drop,
        "drop(self.voice_call_input.take());",
        "cancellation-safe controlled input release",
    )
    require_exact_count(
        connection,
        "drop(self.voice_call_input.take());",
        3,
        "controlled input release sinks",
    )
    if "set_voice_call_input_device(None" in connection:
        raise VerificationError("controlled call retains ambient global input cleanup")

    for key, needle, label in (
        ("requirements", '<span class="id">R-S11bp</span>', "R-S11bp requirement"),
        ("requirements", "<tr><td>209</td>", "Appendix C #209"),
        ("requirements", '<span class="id">R-S11bq</span>', "R-S11bq requirement"),
        ("requirements", "<tr><td>210</td>", "Appendix C #210"),
        (
            "hardening",
            "R-S11bp/R-S11e-82 — outgoing voice-call capture is event-driven and exact-subscription-owned",
            "voice-call worker hardening ledger",
        ),
        (
            "hardening",
            "R-S11bq/R-S11e-83 — voice-call input selection has exact concurrent owners",
            "voice-call input ownership ledger",
        ),
        (
            "verify",
            "python3 scripts/verify-viewer-voice-call-worker.py --repo . --self-test",
            "shared focused-verifier wiring",
        ),
        (
            "apple",
            "python3 scripts/verify-viewer-voice-call-worker.py --repo . --self-test",
            "Apple focused-verifier wiring",
        ),
    ):
        require(sources[key], needle, label)


Mutation = Tuple[str, str, str, str]

MUTATIONS: Tuple[Mutation, ...] = (
    ("io_loop", "stop_requested: Arc<AtomicBool>", "stop_requested_removed: Arc<AtomicBool>", "stop owner"),
    ("io_loop", "subscription: Option<ConnInner>", "subscription_removed: Option<ConnInner>", "subscription owner"),
    ("io_loop", "input_lease: Option<audio_service::VoiceCallInputLease>", "input_lease_removed: Option<audio_service::VoiceCallInputLease>", "input lease owner"),
    ("io_loop", "self.stop_requested.store(true, Ordering::Release);", "", "durable stop publication"),
    ("io_loop", "if let Some(subscription) = self.subscription.take()", "if false", "exact unsubscribe"),
    ("io_loop", "drop(self.input_lease.take());", "", "exact input release"),
    ("io_loop", "receiver.blocking_recv()?", "receiver.try_recv().ok()?", "blocking receive"),
    ("io_loop", "if stop_requested.load(Ordering::Acquire) {\n        None", "if false {\n        None", "post-wake stop check"),
    ("io_loop", "let cleanup_subscription = ConnInner::new(conn_id, None, None);", "let cleanup_subscription = client_conn_inner.clone();", "sender-free cleanup identity"),
    ("io_loop", '.name("rustdesk-viewer-voice-call".to_owned())', '.name("rustdesk-viewer-audio".to_owned())', "named worker"),
    ("io_loop", "cleanup_subscription,\n                        false", "cleanup_subscription,\n                        true", "worker cleanup unsubscribe"),
    ("io_loop", 'log::error!("Failed to start voice-call audio worker: {err}")', 'log::debug!("Failed to start voice-call audio worker: {err}")', "spawn failure diagnostic"),
    ("io_loop", "client_conn_inner,\n                        false", "client_conn_inner,\n                        true", "spawn rollback unsubscribe"),
    ("io_loop", "let input_lease = match crate::audio_service::acquire_voice_call_input(", "let input_lease = match crate::audio_service::acquire_voice_call_input_removed(", "outgoing input acquisition"),
    ("io_loop", "voice_call_thread.stop()", "voice_call_thread.thread.take()", "shutdown stop sink"),
    ("io_loop", "fn r_s11e82_voice_call_audio_wait_is_event_driven_and_stop_is_terminal()", "fn voice_call_audio_wait_is_event_driven_and_stop_is_terminal()", "terminal wait regression"),
    ("io_loop", "fn r_s11e82_voice_call_audio_wait_delivers_a_live_message()", "fn voice_call_audio_wait_delivers_a_live_message()", "live delivery regression"),
    ("requirements", '<span class="id">R-S11bp</span>', '<span class="id">R-S11bp-disabled</span>', "normative requirement"),
    ("requirements", "<tr><td>209</td>", "<tr><td>209-disabled</td>", "Appendix disposition"),
    ("hardening", "R-S11bp/R-S11e-82 — outgoing voice-call capture is event-driven and exact-subscription-owned", "R-S11bp/R-S11e-82 — outgoing voice-call capture polls", "hardening ledger"),
    ("audio", "self.owners.checked_add(1)", "self.owners.saturating_add(1)", "bounded owner acquisition"),
    ("audio", "if owners == 0", "if owners <= 1", "final-owner-only reset"),
    ("audio", "pub fn set_voice_call_input_device(device: String)", "pub fn set_voice_call_input_device(device: Option<String>)", "non-clearing explicit selection API"),
    ("audio", "self.device = Some(device);", "self.device = None;", "selected device installation"),
    ("audio", "pub struct VoiceCallInputLease {\n    _private: (),", "pub struct VoiceCallInputLease;\n//", "non-forgeable lease"),
    ("audio", "VOICE_CALL_INPUT_STATE.lock().unwrap().release()", "Ok(false)", "lease Drop release"),
    ("audio", "fn r_s11e83_voice_call_input_remains_selected_until_the_final_owner_releases()", "fn voice_call_input_remains_selected_until_the_final_owner_releases()", "concurrent-owner regression"),
    ("audio", "fn r_s11e83_voice_call_input_owner_count_fails_closed()", "fn voice_call_input_owner_count_fails_closed()", "owner-bound regression"),
    ("connection", "voice_call_input: Option<audio_service::VoiceCallInputLease>", "voice_call_input_removed: Option<audio_service::VoiceCallInputLease>", "controlled lease owner"),
    ("connection", "self.voice_call_input = Some(input_lease);", "drop(input_lease);", "controlled lease installation"),
    ("connection", "drop(self.voice_call_input.take());", "self.voice_call_input.take();", "controlled exact release"),
    ("requirements", '<span class="id">R-S11bq</span>', '<span class="id">R-S11bq-disabled</span>', "input ownership requirement"),
    ("requirements", "<tr><td>210</td>", "<tr><td>210-disabled</td>", "input ownership Appendix disposition"),
    ("hardening", "R-S11bq/R-S11e-83 — voice-call input selection has exact concurrent owners", "R-S11bq/R-S11e-83 — voice-call input selection is ambient", "input ownership ledger"),
    ("verify", "python3 scripts/verify-viewer-voice-call-worker.py --repo . --self-test", "python3 scripts/verify-viewer-voice-call-worker.py --repo .", "shared gate self-test"),
    ("apple", "python3 scripts/verify-viewer-voice-call-worker.py --repo . --self-test", "python3 scripts/verify-viewer-voice-call-worker.py --repo .", "Apple gate self-test"),
)


def run_self_test(sources: Dict[str, str]) -> None:
    for key, old, new, label in MUTATIONS:
        if old not in sources[key]:
            raise VerificationError(f"self-test fixture missing for {label}")
        mutated = dict(sources)
        mutated[key] = sources[key].replace(old, new, 1)
        try:
            validate(mutated)
        except VerificationError:
            continue
        raise VerificationError(f"self-test mutation survived: {label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    sources = load_sources(args.repo.resolve())
    validate(sources)
    if args.self_test:
        run_self_test(sources)
        print(f"viewer voice-call worker verifier self-test passed ({len(MUTATIONS)} mutations)")
    else:
        print("viewer voice-call worker verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"viewer voice-call worker verifier failed: {error}")
        raise SystemExit(1)
