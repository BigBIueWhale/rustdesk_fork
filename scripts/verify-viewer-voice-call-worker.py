#!/usr/bin/env python3
"""Verify event-driven ownership of the outgoing voice-call capture worker."""

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
            "set_voice_call_input_device(None, true);",
        ),
        "subscription, blocking worker, and idempotent cleanup",
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
            "set_voice_call_input_device(None, true);",
            "return None;",
        ),
        "worker spawn rollback",
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

    for key, needle, label in (
        ("requirements", '<span class="id">R-S11bp</span>', "R-S11bp requirement"),
        ("requirements", "<tr><td>209</td>", "Appendix C #209"),
        (
            "hardening",
            "R-S11bp/R-S11e-82 — outgoing voice-call capture is event-driven and exact-subscription-owned",
            "voice-call worker hardening ledger",
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
    ("io_loop", "self.stop_requested.store(true, Ordering::Release);", "", "durable stop publication"),
    ("io_loop", "if let Some(subscription) = self.subscription.take()", "if false", "exact unsubscribe"),
    ("io_loop", "receiver.blocking_recv()?", "receiver.try_recv().ok()?", "blocking receive"),
    ("io_loop", "if stop_requested.load(Ordering::Acquire) {\n        None", "if false {\n        None", "post-wake stop check"),
    ("io_loop", "let cleanup_subscription = ConnInner::new(conn_id, None, None);", "let cleanup_subscription = client_conn_inner.clone();", "sender-free cleanup identity"),
    ("io_loop", '.name("rustdesk-viewer-voice-call".to_owned())', '.name("rustdesk-viewer-audio".to_owned())', "named worker"),
    ("io_loop", "cleanup_subscription,\n                        false", "cleanup_subscription,\n                        true", "worker cleanup unsubscribe"),
    ("io_loop", 'log::error!("Failed to start voice-call audio worker: {err}")', 'log::debug!("Failed to start voice-call audio worker: {err}")', "spawn failure diagnostic"),
    ("io_loop", "client_conn_inner,\n                        false", "client_conn_inner,\n                        true", "spawn rollback unsubscribe"),
    ("io_loop", "set_voice_call_input_device(None, true);\n                    return None;", "return None;", "spawn rollback input reset"),
    ("io_loop", "voice_call_thread.stop()", "voice_call_thread.thread.take()", "shutdown stop sink"),
    ("io_loop", "fn r_s11e82_voice_call_audio_wait_is_event_driven_and_stop_is_terminal()", "fn voice_call_audio_wait_is_event_driven_and_stop_is_terminal()", "terminal wait regression"),
    ("io_loop", "fn r_s11e82_voice_call_audio_wait_delivers_a_live_message()", "fn voice_call_audio_wait_delivers_a_live_message()", "live delivery regression"),
    ("requirements", '<span class="id">R-S11bp</span>', '<span class="id">R-S11bp-disabled</span>', "normative requirement"),
    ("requirements", "<tr><td>209</td>", "<tr><td>209-disabled</td>", "Appendix disposition"),
    ("hardening", "R-S11bp/R-S11e-82 — outgoing voice-call capture is event-driven and exact-subscription-owned", "R-S11bp/R-S11e-82 — outgoing voice-call capture polls", "hardening ledger"),
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
