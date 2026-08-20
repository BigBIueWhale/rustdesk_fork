#!/usr/bin/env python3
"""Verify exact, bounded, connection-round-owned file-clipboard routing."""

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
        "clipboard": "libs/clipboard/src/lib.rs",
        "windows": "libs/clipboard/src/platform/windows.rs",
        "fuse": "libs/clipboard/src/platform/unix/fuse/cs.rs",
        "client": "src/client/io_loop.rs",
        "connection": "src/server/connection.rs",
        "ui_cm": "src/ui_cm_interface.rs",
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
    clipboard = sources["clipboard"]
    client = sources["client"]
    connection = sources["connection"]
    ui_cm = sources["ui_cm"]

    for source, needle, label in (
        (clipboard, "UnboundedSender<ClipboardFile>", "unbounded file-clipboard sender"),
        (clipboard, "UnboundedReceiver<ClipboardFile>", "unbounded file-clipboard receiver"),
        (clipboard, "Arc<TokioMutex<UnboundedReceiver", "shared process-global receiver"),
        (clipboard, "struct MsgChannel", "legacy shared channel abstraction"),
        (clipboard, "VEC_MSG_CHANNEL", "legacy channel registry"),
        (clipboard, "get_rx_cliprdr_client", "reused viewer receiver API"),
        (clipboard, "get_rx_cliprdr_server", "reused controlled receiver API"),
        (clipboard, "remove_channel_by_conn_id", "identity-only stale cleanup API"),
        (clipboard, "get_client_conn_id", "legacy ambiguous viewer lookup"),
    ):
        forbid(source, needle, label)

    for needle, label in (
        ("const CLIPBOARD_FILE_EGRESS_WAKE_CAPACITY: usize = 1;", "one-slot wake"),
        ("const CLIPBOARD_FILE_EGRESS_MAX_MESSAGES: usize = 256;", "message-count ceiling"),
        (
            "const CLIPBOARD_FILE_EGRESS_MAX_MESSAGE_HEAP_BYTES: usize = hbb_common::cpace::MAX_SESSION_PACKET;",
            "individual retained-heap ceiling",
        ),
        ("hbb_common::cpace::MAX_SESSION_PACKET * 2", "two-message retained-heap ceiling"),
        (
            "std::mem::size_of::<QueuedClipboardFile>() * CLIPBOARD_FILE_EGRESS_MAX_MESSAGES",
            "fixed entry accounting",
        ),
        ("queue: VecDeque<QueuedClipboardFile>", "finite FIFO state"),
        ("queued_bytes: usize", "retained-byte state"),
        ("terminal: Option<ClipboardFileEgressFailure>", "typed terminal state"),
        ("receiver_open: bool", "receiver lifetime state"),
        ("mpsc::channel(CLIPBOARD_FILE_EGRESS_WAKE_CAPACITY)", "bounded wake constructor"),
    ):
        require(clipboard, needle, label)

    sizing = extract_braced_item(
        clipboard,
        "fn clipboard_file_heap_bytes(",
        "file-clipboard retained-heap sizing",
    )
    for needle, label in (
        ("r#type.capacity()", "notification type capacity"),
        ("title.capacity()", "notification title capacity"),
        ("text.capacity()", "notification text capacity"),
        (
            "checked_allocation_bytes::<(i32, String)>(format_list.capacity())",
            "format-list allocation capacity",
        ),
        ("format.capacity()", "nested format-name capacity"),
        ("format_data.capacity()", "format-data capacity"),
        ("requested_data.capacity()", "file-content capacity"),
        (
            "checked_allocation_bytes::<(String, u64)>(files.capacity())",
            "file-list allocation capacity",
        ),
        ("path.capacity()", "nested file-path capacity"),
    ):
        require(sizing, needle, label)
    for needle, label in (
        (".len()", "length-only heap accounting"),
        ("saturating_", "lossy heap accounting"),
    ):
        forbid(sizing, needle, label)

    sender = extract_between(
        clipboard,
        "impl ClipboardFileEgressSender {",
        "impl ClipboardFileEgressReceiver {",
        "file-clipboard producer",
    )
    wake = extract_braced_item(sender, "fn wake_receiver(", "nonblocking wake")
    require(wake, "self.wake.try_send(())", "nonblocking one-slot wake")
    require(wake, "TrySendError::Full(_)", "coalesced wake token")
    failure = extract_braced_item(sender, "fn fail_with_state(", "atomic terminal failure")
    require_order(
        failure,
        (
            "state.queue.clear();",
            "state.queued_bytes = 0;",
            "state.terminal = Some(failure);",
            "drop(state);",
            "self.wake_receiver()?;",
            "Err(ClipboardFileEgressAdmissionError::Failed(failure))",
        ),
        "terminal clear-before-wake finality",
    )
    send = extract_braced_item(sender, "fn send(", "checked file-clipboard admission")
    require_order(
        send,
        (
            "clipboard_file_heap_bytes(&data)",
            "heap_bytes > self.limits.max_message_heap_bytes",
            "heap_bytes.checked_add(std::mem::size_of::<QueuedClipboardFile>())",
            "state.queue.len().checked_add(1)",
            "next_count > self.limits.max_messages",
            "state.queued_bytes.checked_add(retained_bytes)",
            "next_bytes > self.limits.max_queued_bytes",
            "state.queue.push_back(QueuedClipboardFile {",
            "state.queued_bytes = next_bytes;",
            "self.wake_receiver()",
        ),
        "checked FIFO nonwaiting admission",
    )
    if send.count("return self.fail_with_state(") != 4:
        raise VerificationError("every guarded admission refusal must share one atomic terminal transition")
    for needle, label in (
        (".await", "awaiting synchronous producer"),
        ("blocking_send", "blocking synchronous producer"),
        ("saturating_", "lossy producer accounting"),
        ("tokio::spawn", "detached producer task"),
        ("Runtime::new", "nested producer runtime"),
        ("std::fs::", "filesystem I/O under producer ownership"),
    ):
        forbid(send, needle, label)

    receiver = extract_between(
        clipboard,
        "impl ClipboardFileEgressReceiver {",
        "impl Drop for ClipboardFileEgressReceiver {",
        "file-clipboard receiver",
    )
    require_order(
        receiver,
        (
            "if let Some(failure) = state.terminal.take()",
            "state.receiver_open = false;",
            "state.queue.pop_front()",
            "state.queued_bytes.checked_sub(queued.retained_bytes)",
            "ClipboardFileEgressItem::Message(queued.data)",
            "self.wake.recv().await",
        ),
        "terminal-first checked FIFO drain",
    )
    receiver_drop = extract_braced_item(
        clipboard,
        "impl Drop for ClipboardFileEgressReceiver",
        "receiver retirement",
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
        "receiver retirement releases retained state",
    )

    route = extract_between(
        clipboard,
        "enum ClipboardFileRouteOwner",
        "impl ClipboardFile {",
        "sender-only exact route registry",
    )
    for needle, label in (
        ("Viewer { peer_id: String }", "viewer route class"),
        ("Controlled", "controlled route class"),
        ("struct ClipboardFileRoute", "route record"),
        ("route_generation: u64", "route generation"),
        ("sender: ClipboardFileEgressSender", "sender-only route"),
        ("RwLock<Vec<ClipboardFileRoute>>", "route registry"),
        ("struct ClipboardFileRouteLease", "route lease"),
    ):
        require(route, needle, label)
    forbid(route, "ClipboardFileEgressReceiver", "receiver in global route registry")
    route_drop = extract_braced_item(
        clipboard,
        "impl Drop for ClipboardFileRouteLease",
        "generation-bound route cleanup",
    )
    require_order(
        route_drop,
        (
            "route.conn_id == self.conn_id",
            "route.route_generation == self.route_generation",
            "routes.remove(index);",
        ),
        "exact generation-bound route cleanup",
    )

    next_viewer = extract_braced_item(
        clipboard, "fn next_viewer_conn_id(", "viewer route identity allocation"
    )
    require(next_viewer, "lock.checked_sub(1)", "checked negative viewer IDs")
    require(next_viewer, "std::process::abort();", "viewer ID exhaustion finality")
    viewer_registration = extract_braced_item(
        clipboard, "pub fn register_cliprdr_viewer(", "fresh viewer route"
    )
    require_order(
        viewer_registration,
        (
            "next_viewer_conn_id()",
            "next_route_generation()",
            "clipboard_file_egress_channel()",
            "ClipboardFileRouteOwner::Viewer",
            "ClipboardFileRouteLease",
        ),
        "fresh viewer route and exact lease",
    )
    controlled_registration = extract_braced_item(
        clipboard, "pub fn register_cliprdr_controlled(", "exclusive controlled route"
    )
    require_order(
        controlled_registration,
        (
            "if conn_id <= 0",
            "routes.iter().any(|route| route.conn_id == conn_id)",
            "ClipboardFileRouteOwner::Controlled",
            "ClipboardFileRouteLease",
        ),
        "positive exclusive controlled route",
    )
    sender_lookup = extract_braced_item(
        clipboard, "fn send_data_to_channel(", "sender snapshot before admission"
    )
    require_order(
        sender_lookup,
        (
            "CLIPBOARD_FILE_ROUTES",
            ".read()",
            ".map(|route| route.sender.clone())",
            ".ok_or_else(",
            "sender\n        .send(data)",
        ),
        "registry lock ends at sender snapshot",
    )
    for function in ("pub fn send_data_exclude(", "fn send_data_to_all("):
        broadcast = extract_braced_item(clipboard, function, "bounded sender broadcast")
        require_order(
            broadcast,
            (".map(|route| route.sender.clone())", ".collect::<Vec<_>>()", "sender.send(data.clone())"),
            "broadcast snapshots routes before admission",
        )
        require(broadcast, 'log::error!("file-clipboard broadcast route retired: {error}")', "visible broadcast refusal")

    for needle, label in (
        ("conn_id as UINT32", "Windows outbound opaque ID bit preservation"),
        ("conn_id = (*clip_format_list).connID as i32;", "Windows inbound viewer ID bit restoration"),
        ("conn_id = (*file_contents_response).connID as i32;", "Windows inbound file-response ID bit restoration"),
    ):
        require(sources["windows"], needle, label)

    for source, needles, label in (
        (
            client,
            (
                "clipboard::register_cliprdr_viewer(&self.handler.get_id())",
                "rx_clip_client = receiver;",
                "ClipboardFileEgressItem::Failed(failure)",
                "break;",
            ),
            "viewer round owns and retires its exact route",
        ),
        (
            connection,
            (
                '#[cfg(all(feature = "unix-file-copy-paste", not(target_os = "windows")))]',
                "clipboard::register_cliprdr_controlled(id)",
                "ClipboardFileEgressItem::Failed(failure)",
                "conn.on_close(",
                "break;",
            ),
            "Unix controlled round exact route and terminal finality",
        ),
        (
            ui_cm,
            (
                '#[cfg(target_os = "windows")]',
                "clipboard::register_cliprdr_controlled(self.conn_id)",
                "ClipboardFileEgressItem::Failed(failure)",
                "break;",
            ),
            "Windows CM exact route and terminal finality",
        ),
    ):
        require_order(source, needles, label)
    forbid(
        connection,
        '#[cfg(feature = "unix-file-copy-paste")]\n        let (mut rx_clip',
        "Windows direct controlled route competing with CM",
    )

    for test in (
        "r_s11gz_file_clipboard_egress_is_fifo_and_releases_capacity",
        "r_s11gz_file_clipboard_egress_capacity_failure_is_terminal_and_clears_payloads",
        "r_s11gz_file_clipboard_egress_counts_retained_capacity_and_total_bytes",
        "r_s11gz_file_clipboard_egress_wakes_and_receiver_retirement_is_final",
        "r_s11gz_viewer_routes_are_fresh_negative_and_controlled_routes_are_disjoint",
    ):
        require(clipboard, test, f"{test} regression")
    for needle, label in (
        ("drop(sender);\n        assert!(receiver.recv().await.is_none());", "producer retirement regression"),
        ("assert!(!Arc::ptr_eq(&first_receiver.state, &second_receiver.state));", "fresh receiver regression"),
        ("assert!(register_cliprdr_controlled(controlled_id).is_err());", "duplicate controlled route regression"),
        ("crate::register_cliprdr_controlled(conn_id).unwrap();", "FUSE exact-route regression wiring"),
    ):
        require(clipboard if "FUSE" not in label else sources["fuse"], needle, label)

    gate_command = "python3 scripts/verify-clipboard-route-budget.py --repo . --self-test"
    for key, needle, label in (
        ("verify", gate_command, "shared focused gate"),
        (
            "verify",
            "cargo test -p clipboard --features unix-file-copy-paste --lib r_s11gz_ --color never",
            "shared Rust behavior gate",
        ),
        ("apple", gate_command, "Apple/shared focused gate"),
        ("requirements", '<div class="req"><span class="id">R-S11gz</span>', "normative requirement"),
        ("requirements", "<tr><td>361</td>", "Appendix C row"),
        ("hardening", "### R-S11gz/R-S11e-238 — exact bounded file-clipboard route ownership", "hardening ledger"),
        ("workspace", "def validate_clipboard_route_budget_contract(sources):", "independent contract"),
        ("workspace", "validate_clipboard_route_budget_contract(sources)", "independent dispatch"),
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
        raise VerificationError("independent file-clipboard dispatch owner is absent")
    dispatches = [
        node
        for node in validate_sources_function.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "validate_clipboard_route_budget_contract"
    ]
    if len(dispatches) != 1:
        raise VerificationError("independent file-clipboard dispatch must occur exactly once")

    requirements_digest = hashlib.sha256(sources["requirements"].encode("utf-8")).hexdigest()
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
    ("clipboard", "const CLIPBOARD_FILE_EGRESS_WAKE_CAPACITY: usize = 1;", "const CLIPBOARD_FILE_EGRESS_WAKE_CAPACITY: usize = 64;", "one-slot wake"),
    ("clipboard", "const CLIPBOARD_FILE_EGRESS_MAX_MESSAGES: usize = 256;", "const CLIPBOARD_FILE_EGRESS_MAX_MESSAGES: usize = usize::MAX;", "message ceiling"),
    ("clipboard", "hbb_common::cpace::MAX_SESSION_PACKET * 2", "hbb_common::cpace::MAX_SESSION_PACKET * 8", "retained-byte ceiling"),
    ("clipboard", "mpsc::channel(CLIPBOARD_FILE_EGRESS_WAKE_CAPACITY)", "mpsc::unbounded_channel()", "bounded wake"),
    ("clipboard", "r#type.capacity()", "r#type.len()", "notification capacity accounting"),
    ("clipboard", "checked_allocation_bytes::<(i32, String)>(format_list.capacity())", "format_list.len()", "format-list allocation accounting"),
    ("clipboard", "format_data.capacity()", "format_data.len()", "format-data capacity accounting"),
    ("clipboard", "requested_data.capacity()", "requested_data.len()", "file-content capacity accounting"),
    ("clipboard", "checked_allocation_bytes::<(String, u64)>(files.capacity())", "files.len()", "file-list allocation accounting"),
    ("clipboard", "self.wake.try_send(())", "self.wake.blocking_send(())", "nonblocking wake"),
    ("clipboard", "state.queue.clear();\n        state.queued_bytes = 0;\n        state.terminal = Some(failure);", "state.terminal = Some(failure);", "terminal payload release"),
    ("clipboard", "heap_bytes.checked_add(std::mem::size_of::<QueuedClipboardFile>())", "Some(heap_bytes)", "fixed entry accounting"),
    ("clipboard", "state.queue.len().checked_add(1)", "Some(state.queue.len() + 1)", "checked count"),
    ("clipboard", "next_count > self.limits.max_messages", "false", "count admission"),
    ("clipboard", "state.queued_bytes.checked_add(retained_bytes)", "Some(state.queued_bytes + retained_bytes)", "checked retained bytes"),
    ("clipboard", "next_bytes > self.limits.max_queued_bytes", "false", "byte admission"),
    ("clipboard", "state.queue.push_back(QueuedClipboardFile {", "state.queue.push_front(QueuedClipboardFile {", "FIFO admission"),
    ("clipboard", "state.queued_bytes.checked_sub(queued.retained_bytes)", "Some(state.queued_bytes)", "checked drain"),
    ("clipboard", "self.wake.close();", "// wake left open", "receiver retirement"),
    ("clipboard", "struct ClipboardFileRoute {", "struct MsgChannel {", "legacy abstraction exclusion"),
    ("clipboard", "sender: ClipboardFileEgressSender,", "receiver: ClipboardFileEgressReceiver,", "sender-only registry"),
    ("clipboard", "route.route_generation == self.route_generation", "true", "generation-bound cleanup"),
    ("clipboard", "lock.checked_sub(1)", "lock.checked_add(1)", "negative viewer identity"),
    ("clipboard", "if conn_id <= 0", "if false", "positive controlled identity"),
    ("clipboard", "routes.iter().any(|route| route.conn_id == conn_id)", "false", "exclusive controlled route"),
    ("clipboard", ".map(|route| route.sender.clone())", ".map(|route| { route.sender.send(data.clone()).ok(); route.sender.clone() })", "sender snapshot"),
    ("windows", "conn_id = (*clip_format_list).connID as i32;", "conn_id = (*clip_format_list).connID as i16 as i32;", "Windows ID restoration"),
    ("client", "clipboard::register_cliprdr_viewer(&self.handler.get_id())", "clipboard::current_cliprdr_viewer_id(&self.handler.get_id())", "fresh viewer route"),
    ("client", "ClipboardFileEgressItem::Failed(failure)", "ClipboardFileEgressItem::Failed(_failure)", "viewer terminal finality"),
    ("connection", '#[cfg(all(feature = "unix-file-copy-paste", not(target_os = "windows")))]', '#[cfg(feature = "unix-file-copy-paste")]', "single Windows controlled owner"),
    ("connection", "clipboard::register_cliprdr_controlled(id)", "clipboard::clipboard_file_egress_channel()", "Unix exact controlled route"),
    ("ui_cm", "clipboard::register_cliprdr_controlled(self.conn_id)", "clipboard::clipboard_file_egress_channel()", "Windows CM exact route"),
    ("verify", "python3 scripts/verify-clipboard-route-budget.py --repo . --self-test", "true # file-clipboard route gate disabled", "shared gate"),
    ("apple", "python3 scripts/verify-clipboard-route-budget.py --repo . --self-test", "true # file-clipboard route gate disabled", "Apple gate"),
    ("requirements", '<div class="req"><span class="id">R-S11gz</span>', '<div class="req"><span class="id">R-S11gz-disabled</span>', "normative requirement"),
    ("requirements", "<tr><td>361</td>", "<tr><td>361-disabled</td>", "Appendix disposition"),
    ("hardening", "### R-S11gz/R-S11e-238 — exact bounded file-clipboard route ownership", "### R-S11gz-disabled/R-S11e-238 — exact bounded file-clipboard route ownership", "hardening ledger"),
    ("workspace", "    validate_cm_egress_budget_contract(sources)\n    validate_clipboard_listener_ownership_contract(sources)\n    validate_clipboard_route_budget_contract(sources)\n    validate_keyed_writer_budget_contract(sources)", "    validate_cm_egress_budget_contract(sources)\n    validate_clipboard_listener_ownership_contract(sources)\n    validate_clipboard_route_budget_contract_disabled(sources)\n    validate_keyed_writer_budget_contract(sources)", "independent dispatch"),
)


def run_self_test(sources: Dict[str, str]) -> None:
    for key, old, new, label in MUTATIONS:
        if old not in sources[key]:
            raise VerificationError(f"self-test fixture missing for {label}")
        mutated = dict(sources)
        mutated[key] = sources[key].replace(old, new, 1)
        try:
            validate(mutated)
        except (VerificationError, SyntaxError):
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
        print(f"File-clipboard route verifier self-test passed ({len(MUTATIONS)} mutations)")
    else:
        print("File-clipboard route verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"File-clipboard route verifier failed: {error}")
        raise SystemExit(1)
