#!/usr/bin/env python3
"""Verify bounded, failure-visible controlled-side service egress."""

from __future__ import annotations

import argparse
import ast
import hashlib
from pathlib import Path
from typing import Dict, Tuple


class VerificationError(RuntimeError):
    pass


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}: {needle!r}")


def forbid(source: str, needle: str, label: str) -> None:
    if needle in source:
        raise VerificationError(f"forbidden {label} remains: {needle!r}")


def require_order(source: str, needles: Tuple[str, ...], label: str) -> None:
    position = -1
    for needle in needles:
        position = source.find(needle, position + 1)
        if position < 0:
            raise VerificationError(f"{label}: missing or misordered {needle!r}")


def extract_braced_item(source: str, signature: str, label: str) -> str:
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


def extract_between(source: str, start: str, end: str, label: str) -> str:
    begin = source.find(start)
    if begin < 0:
        raise VerificationError(f"missing start for {label}")
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise VerificationError(f"missing end for {label}")
    return source[begin:finish]


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "connection": "src/server/connection.rs",
        "service": "src/server/service.rs",
        "input": "src/server/input_service.rs",
        "video": "src/server/video_service.rs",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "native_watch": "docs/NATIVE-CODEC-WATCH.md",
        "verify": "scripts/verify.sh",
        "apple": "scripts/apple-conform-check.sh",
        "workspace": "scripts/verify-verifier-workspace.py",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def validate(sources: Dict[str, str]) -> None:
    connection = sources["connection"]
    forbid(
        connection,
        "pub type Sender = mpsc::UnboundedSender<(Instant, Arc<Message>)>;",
        "unbounded controlled service sender alias",
    )
    forbid(
        connection,
        "mpsc::unbounded_channel::<(Instant, Arc<Message>)>()",
        "unbounded per-connection controlled service channel",
    )
    for needle, label in (
        ("const CONTROL_EGRESS_WAKE_CAPACITY: usize = 1;", "one-slot wake"),
        ("const CONTROL_EGRESS_MAX_MESSAGES: usize = 256;", "message-count ceiling"),
        ("hbb_common::cpace::MAX_SESSION_PACKET - hbb_common::sodiumoxide::crypto::secretbox::MACBYTES", "single wire-message ceiling"),
        ("hbb_common::cpace::MAX_SESSION_PACKET * 2", "retained-byte ceiling"),
        ("struct ControlEgressState", "bounded mailbox state"),
        ("queue: VecDeque<QueuedControlEgress>", "finite FIFO storage"),
        ("queued_bytes: usize", "checked retained-byte state"),
        ("terminal: Option<ControlEgressFailure>", "terminal failure state"),
        ("receiver_open: bool", "receiver lifetime state"),
    ):
        require(connection, needle, label)

    channel = extract_braced_item(
        connection,
        "fn control_egress_channel_with_limits(",
        "controlled egress channel",
    )
    require_order(
        channel,
        (
            "StdMutex::new(ControlEgressState::default())",
            "mpsc::channel(CONTROL_EGRESS_WAKE_CAPACITY)",
            "state: Arc::clone(&state)",
            "wake,",
            "limits,",
        ),
        "shared state, bounded wake, and exact limits",
    )

    classification = extract_braced_item(
        connection,
        "fn is_control_egress_message(",
        "controlled egress message classification",
    )
    require_order(
        classification,
        (
            "Some(message::Union::AudioFrame(_)) | Some(message::Union::VideoFrame(_)) => false",
            "Some(misc::Union::AudioFormat(_) | misc::Union::SwitchDisplay(_))",
        ),
        "all semantic media classes remain outside control egress",
    )

    sender = extract_between(
        connection,
        "impl Sender {",
        "impl ControlEgressReceiver {",
        "controlled egress producer",
    )
    send = extract_braced_item(
        sender,
        "pub(crate) fn send(",
        "synchronous controlled egress admission",
    )
    wake = extract_braced_item(
        sender,
        "fn wake_receiver(",
        "nonblocking controlled egress wake",
    )
    require(
        wake,
        "self.wake.try_send(())",
        "nonblocking one-slot receiver wake",
    )
    require_order(
        send,
        (
            "if !is_control_egress_message(&message)",
            "message.compute_size()",
            "payload_bytes > self.limits.max_payload_bytes",
            "payload_bytes.checked_add(std::mem::size_of::<QueuedControlEgress>())",
            "let replace_cursor = is_cursor_position(&message);",
            "filter(|queued| is_cursor_position(&queued.message))",
            ".checked_add(usize::from(replaced_bytes.is_none()))",
            "next_count > self.limits.max_messages",
            "let Some(queued_bytes) = state.queued_bytes.checked_sub(replaced_bytes)",
            "let Some(next_bytes) = queued_bytes.checked_add(retained_bytes)",
            "next_bytes > self.limits.max_queued_bytes",
            "state.queue.pop_back();",
            "state.queue.push_back(QueuedControlEgress {",
            "state.queued_bytes = next_bytes;",
            "self.wake_receiver()",
        ),
        "checked latest-trailing-cursor admission without exact-message reordering",
    )
    if send.count("return self.fail_with_state(") != 5:
        raise VerificationError(
            "every in-guard count/byte failure must publish through the same exact state guard"
        )
    failure = extract_braced_item(
        sender,
        "fn fail_with_state(",
        "atomic terminal producer failure",
    )
    require_order(
        failure,
        (
            "if !state.receiver_open",
            "if let Some(existing) = state.terminal",
            "state.queue.clear();",
            "state.queued_bytes = 0;",
            "state.terminal = Some(failure);",
            "drop(state);",
            "self.wake_receiver()?;",
            "Err(ControlEgressAdmissionError::Failed(failure))",
        ),
        "one in-guard failure clears retained work before waking the exact receiver",
    )
    fail = extract_braced_item(sender, "fn fail(", "terminal failure entry point")
    require_order(
        fail,
        (
            "let state = lock_control_egress_state(&self.state);",
            "self.fail_with_state(state, failure)",
        ),
        "terminal failure uses the same state transition",
    )
    for needle, label in (
        (".await", "awaiting service-producer admission"),
        ("blocking_send", "blocking service-producer admission"),
        ("std::thread::sleep", "sleeping service-producer admission"),
        ("tokio::runtime", "nested service-producer runtime"),
        ("Runtime::new", "nested service-producer runtime constructor"),
        ("tokio::spawn", "detached controlled egress task"),
        ("std::fs::", "filesystem I/O under synchronous admission"),
        ("saturating_sub", "lossy retained-byte accounting"),
        ("drop(state);", "failure re-lock after state inspection"),
    ):
        forbid(send, needle, label)

    receiver = extract_between(
        connection,
        "impl ControlEgressReceiver {",
        "impl Drop for ControlEgressReceiver {",
        "controlled egress receiver",
    )
    require_order(
        receiver,
        (
            "if let Some(failure) = state.terminal.take()",
            "state.receiver_open = false;",
            "state.queue.clear();",
            "ControlEgressItem::Failed(failure)",
            "state.queue.pop_front()",
            "state.queued_bytes.checked_sub(queued.retained_bytes)",
            "ControlEgressItem::Message(queued.message)",
            "self.wake.recv().await",
        ),
        "terminal-first FIFO drain and checked retirement",
    )
    receiver_drop = extract_braced_item(
        connection,
        "impl Drop for ControlEgressReceiver",
        "controlled egress receiver retirement",
    )
    require_order(
        receiver_drop,
        (
            "self.wake.close();",
            "state.receiver_open = false;",
            "state.queue.clear();",
            "state.queued_bytes = 0;",
            "state.terminal = None;",
        ),
        "receiver retirement releases every retained message",
    )

    subscriber = extract_braced_item(
        connection, "impl Subscriber for ConnInner", "service subscriber routing"
    )
    require_order(
        subscriber,
        (
            "if tx_by_audio",
            "tx.send(msg);",
            "Some(message::Union::VideoFrame(_))",
            "Some(misc::Union::SwitchDisplay(_))",
            "tx.send_switch_display(msg)",
            "if let Some(tx) = self.tx.as_ref()",
            "if let Err(err) = tx.send(msg)",
        ),
        "media separation and failure-visible generic service routing",
    )

    start = extract_braced_item(connection, "pub async fn start(", "connection run loop")
    require(start, "let (tx, mut rx) = control_egress_channel();", "bounded channel construction")
    control_arm = extract_between(
        start,
        "item = rx.recv() => {",
        "_ = second_timer.tick()",
        "controlled egress select arm",
    )
    require_order(
        control_arm,
        (
            "let Some(item) = item else",
            'conn.on_close("controlled control egress retired", false).await;',
            "ControlEgressItem::Message(message)",
            "ControlEgressItem::Failed(failure)",
            "conn.on_close(&failure.to_string(), false).await;",
            "conn.stream.send(msg).await",
        ),
        "receiver and admission failure terminate the exact connection",
    )

    service_trait = extract_braced_item(
        sources["service"], "pub trait Subscriber", "synchronous service subscriber"
    )
    require(
        service_trait,
        "fn send(&mut self, msg: Arc<Message>);",
        "synchronous producer contract",
    )
    run_pos = extract_braced_item(
        sources["input"], "fn run_pos(", "controlled cursor producer"
    )
    require_order(
        run_pos,
        (
            "if state.is_moved(x, y)",
            "msg_out.set_cursor_position(CursorPosition {",
            "sp.send_without(msg_out, exclude);",
        ),
        "high-rate cursor service path",
    )
    require(
        sources["input"],
        "GenericService::repeat::<StatePos, _, _>(&svc.clone(), 33, run_pos);",
        "33-millisecond cursor cadence",
    )
    screenshot_send = extract_braced_item(
        sources["video"], "fn send_screenshot_response(", "screenshot response producer"
    )
    require_order(
        screenshot_send,
        (
            "msg_out.set_screenshot_response(response);",
            "tx.send(Arc::new(msg_out))",
            'log::error!("Failed to send screenshot: {err}")',
        ),
        "large exact screenshot response uses the bounded sender",
    )
    block_input_send = extract_braced_item(
        connection,
        "pub fn send_block_input_error(",
        "block-input response producer",
    )
    require_order(
        block_input_send,
        (
            "msg_out.set_misc(misc);",
            "s.send(Arc::new(msg_out))",
            'log::warn!("controlled control egress rejected a block-input response: {err}")',
        ),
        "exact block-input response uses failure-visible bounded egress",
    )

    for test in (
        "r_s11gw_cursor_positions_replace_only_the_trailing_cursor",
        "r_s11gw_count_saturation_is_terminal_and_releases_exact_messages",
        "r_s11gw_byte_and_wire_bounds_fail_the_exact_round_closed",
        "r_s11gw_media_bypass_and_receiver_retirement_are_visible",
        "r_s11gw_async_receiver_waits_without_polling_and_closes",
    ):
        require(connection, test, f"deterministic {test} regression")
    for needle, label in (
        ("audio.set_audio_frame(AudioFrame::default());", "audio-frame bypass regression"),
        ("audio_misc.set_audio_format(AudioFormat::default());", "audio-format bypass regression"),
        ("video.set_video_frame(VideoFrame::default());", "video-frame bypass regression"),
        ("switch_misc.set_switch_display(SwitchDisplay::default());", "switch-display bypass regression"),
        ("small_cursor_weak.upgrade().is_none()", "replacement-byte release regression"),
        ("sender.send(Arc::clone(&after_drain)).unwrap();", "drain-byte reuse regression"),
    ):
        require(connection, needle, label)

    gate_command = "python3 scripts/verify-controlled-control-egress.py --repo . --self-test"
    for key, needle, label in (
        ("verify", gate_command, "shared focused gate"),
        ("verify", "cargo test --lib --features linux-pkg-config,flutter r_s11gw_ --color never", "shared Rust behavior gate"),
        ("apple", gate_command, "Apple/shared focused gate"),
        ("requirements", '<div class="req"><span class="id">R-S11gw</span>', "normative controlled egress requirement"),
        ("requirements", "may hold only this mailbox's short in-process state mutex while mutating bounded state", "short synchronous state-mutex authority"),
        ("requirements", "MUST NOT</span> hold it across I/O, block on mailbox capacity, await, create a runtime", "nonblocking synchronous admission requirement"),
        ("requirements", "<tr><td>358</td>", "Appendix C controlled egress row"),
        ("hardening", "### R-S11gw/R-S11e-235 — bounded controlled-side service-to-connection egress", "hardening ledger entry"),
        ("workspace", "def validate_controlled_control_egress_contract(sources):", "independent workspace contract"),
        ("workspace", "validate_controlled_control_egress_contract(sources)", "independent workspace dispatch"),
    ):
        require(sources[key], needle, label)

    workspace_module = ast.parse(sources["workspace"])
    validate_sources_function = next(
        (
            node
            for node in workspace_module.body
            if isinstance(node, ast.FunctionDef) and node.name == "validate_sources"
        ),
        None,
    )
    if validate_sources_function is None:
        raise VerificationError("independent controlled-egress dispatch owner is absent")
    dispatches = [
        node
        for node in validate_sources_function.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "validate_controlled_control_egress_contract"
    ]
    if len(dispatches) != 1:
        raise VerificationError(
            "independent controlled-egress dispatch must occur exactly once"
        )

    requirements_digest = hashlib.sha256(
        sources["requirements"].encode("utf-8")
    ).hexdigest()
    require(
        sources["hardening"],
        f"{requirements_digest}  requirements.html",
        "exact hardening requirements digest",
    )
    require(
        sources["native_watch"],
        f"Requirements hash: {requirements_digest}",
        "exact native-watch requirements digest",
    )


Mutation = Tuple[str, str, str, str]

MUTATIONS: Tuple[Mutation, ...] = (
    ("connection", "const CONTROL_EGRESS_WAKE_CAPACITY: usize = 1;", "const CONTROL_EGRESS_WAKE_CAPACITY: usize = 64;", "bounded wake"),
    ("connection", "const CONTROL_EGRESS_MAX_MESSAGES: usize = 256;", "const CONTROL_EGRESS_MAX_MESSAGES: usize = usize::MAX;", "count ceiling"),
    ("connection", "MAX_SESSION_PACKET - hbb_common::sodiumoxide::crypto::secretbox::MACBYTES", "MAX_SESSION_PACKET", "wire payload ceiling"),
    ("connection", "queue: VecDeque<QueuedControlEgress>,", "queue: Vec<QueuedControlEgress>,", "FIFO state"),
    ("connection", "terminal: Option<ControlEgressFailure>,", "terminal: Option<String>,", "typed terminal state"),
    ("connection", "mpsc::channel(CONTROL_EGRESS_WAKE_CAPACITY)", "mpsc::unbounded_channel()", "bounded channel construction"),
    ("connection", "if !is_control_egress_message(&message)", "if false && !is_control_egress_message(&message)", "media bypass rejection"),
    ("connection", "Some(message::Union::AudioFrame(_)) | Some(message::Union::VideoFrame(_))", "Some(message::Union::AudioFrame(_))", "frame-class separation"),
    ("connection", "Some(misc::Union::AudioFormat(_) | misc::Union::SwitchDisplay(_))", "Some(misc::Union::AudioFormat(_))", "misc-media-class separation"),
    ("connection", "payload_bytes > self.limits.max_payload_bytes", "false", "message-size bound"),
    ("connection", "payload_bytes.checked_add(std::mem::size_of::<QueuedControlEgress>())", "Some(payload_bytes + std::mem::size_of::<QueuedControlEgress>())", "checked entry-byte accounting"),
    ("connection", "filter(|queued| is_cursor_position(&queued.message))", "filter(|_| true)", "cursor-only replacement"),
    ("connection", ".checked_add(usize::from(replaced_bytes.is_none()))", ".checked_add(0)", "checked count accounting"),
    ("connection", "return self.fail_with_state(state, ControlEgressFailure::AccountingOverflow);", "return self.fail(ControlEgressFailure::AccountingOverflow);", "atomic inspected-state failure"),
    ("connection", "next_count > self.limits.max_messages", "false", "count admission"),
    ("connection", "let Some(queued_bytes) = state.queued_bytes.checked_sub(replaced_bytes)", "let Some(queued_bytes) = Some(state.queued_bytes)", "checked replacement subtraction"),
    ("connection", "let Some(next_bytes) = queued_bytes.checked_add(retained_bytes)", "let Some(next_bytes) = Some(queued_bytes + retained_bytes)", "checked retained-byte addition"),
    ("connection", "next_bytes > self.limits.max_queued_bytes", "false", "byte admission"),
    ("connection", "state.queue.pop_back();", "state.queue.pop_front();", "trailing cursor replacement"),
    ("connection", "state.queue.push_back(QueuedControlEgress {", "state.queue.push_front(QueuedControlEgress {", "FIFO admission"),
    ("connection", "fn fail_with_state(", "fn fail_after_relock(", "atomic in-guard terminal publication"),
    ("connection", "state.terminal = Some(failure);", "state.terminal = None;", "terminal publication"),
    ("connection", "if let Some(existing) = state.terminal {\n            return Err(ControlEgressAdmissionError::Failed(existing));\n        }\n        state.queue.clear();", "if let Some(existing) = state.terminal {\n            return Err(ControlEgressAdmissionError::Failed(existing));\n        }", "failure releases retained work"),
    ("connection", "state.terminal = Some(failure);\n        drop(state);\n        self.wake_receiver()?;", "state.terminal = Some(failure);\n        self.wake_receiver()?;", "unlock before wake"),
    ("connection", "if let Some(failure) = state.terminal.take()", "if false && state.terminal.is_some()", "terminal-first receiver"),
    ("connection", "state.queue.pop_front()", "state.queue.pop_back()", "FIFO drain"),
    ("connection", "state.queued_bytes.checked_sub(queued.retained_bytes)", "Some(state.queued_bytes)", "checked drain accounting"),
    ("connection", "self.wake.close();", "// wake left open", "receiver retirement"),
    ("connection", "let (tx, mut rx) = control_egress_channel();", "let (tx, mut rx) = mpsc::unbounded_channel();", "connection channel"),
    ("connection", "ControlEgressItem::Failed(failure) => {\n                            conn.on_close(&failure.to_string(), false).await;", "ControlEgressItem::Failed(_failure) => {\n                            conn.on_close(\"controlled egress failed\", false).await;", "terminal select arm"),
    ("connection", "ControlEgressItem::Failed(failure) => {\n                            conn.on_close(&failure.to_string(), false).await;\n                            break;", "ControlEgressItem::Failed(_failure) => {\n                            continue;", "failure-visible connection close"),
    ("connection", "if let Err(err) = tx.send(msg)", "let _ = tx.send(msg)", "producer failure visibility"),
    ("video", "tx.send(Arc::new(msg_out))", "drop(msg_out); Ok(())", "screenshot bounded egress"),
    ("connection", "s.send(Arc::new(msg_out))", "drop(msg_out); Ok(())", "block-input bounded egress"),
    ("input", "&svc.clone(), 33, run_pos", "&svc.clone(), 3, run_pos", "high-rate producer cadence"),
    ("connection", "fn r_s11gw_cursor_positions_replace_only_the_trailing_cursor", "fn cursor_positions_accumulate", "cursor regression"),
    ("connection", "fn r_s11gw_count_saturation_is_terminal_and_releases_exact_messages", "fn count_saturation_is_ignored", "count regression"),
    ("connection", "fn r_s11gw_byte_and_wire_bounds_fail_the_exact_round_closed", "fn bytes_are_unbounded", "byte regression"),
    ("connection", "audio.set_audio_frame(AudioFrame::default());", "audio.clear_audio_frame();", "audio-frame bypass regression"),
    ("connection", "audio_misc.set_audio_format(AudioFormat::default());", "audio_misc.clear_audio_format();", "audio-format bypass regression"),
    ("connection", "video.set_video_frame(VideoFrame::default());", "video.clear_video_frame();", "video-frame bypass regression"),
    ("connection", "switch_misc.set_switch_display(SwitchDisplay::default());", "switch_misc.clear_switch_display();", "switch-display bypass regression"),
    ("connection", "small_cursor_weak.upgrade().is_none()", "small_cursor_weak.upgrade().is_some()", "replacement-byte release regression"),
    ("connection", "sender.send(Arc::clone(&after_drain)).unwrap();", "drop(after_drain);", "drain-byte reuse regression"),
    ("verify", "python3 scripts/verify-controlled-control-egress.py --repo . --self-test", "true # controlled egress gate disabled", "shared gate wiring"),
    ("apple", "python3 scripts/verify-controlled-control-egress.py --repo . --self-test", "true # controlled egress gate disabled", "Apple gate wiring"),
    ("requirements", '<div class="req"><span class="id">R-S11gw</span>', '<div class="req"><span class="id">R-S11gw-disabled</span>', "normative requirement"),
    ("requirements", "may hold only this mailbox's short in-process state mutex while mutating bounded state", "may hold arbitrary locks while publishing", "short synchronous state-mutex authority"),
    ("requirements", "<tr><td>358</td>", "<tr><td>358-disabled</td>", "Appendix disposition"),
    ("hardening", "### R-S11gw/R-S11e-235 — bounded controlled-side service-to-connection egress", "### R-S11gw-disabled/R-S11e-235 — bounded controlled-side service-to-connection egress", "hardening ledger"),
    ("workspace", "    validate_viewer_cursor_resources_contract(sources)\n    validate_controlled_control_egress_contract(sources)\n    validate_cm_egress_budget_contract(sources)\n    validate_keyed_writer_budget_contract(sources)\n    validate_display_selection_finality_contract(sources)", "    validate_viewer_cursor_resources_contract(sources)\n    validate_controlled_control_egress_contract_disabled(sources)\n    validate_cm_egress_budget_contract(sources)\n    validate_keyed_writer_budget_contract(sources)\n    validate_display_selection_finality_contract(sources)", "independent dispatch"),
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
        print(
            "controlled control egress verifier self-test passed "
            f"({len(MUTATIONS)} mutations)"
        )
    else:
        print("controlled control egress verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"controlled control egress verifier failed: {error}")
        raise SystemExit(1)
