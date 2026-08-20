#!/usr/bin/env python3
"""Verify latest-state, receiver-final Windows tray session-count ownership."""

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


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "tray": "src/tray.rs",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "native_watch": "docs/NATIVE-CODEC-WATCH.md",
        "verify": "scripts/verify.sh",
        "workspace": "scripts/verify-verifier-workspace.py",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def validate(sources: Dict[str, str]) -> None:
    tray = sources["tray"]
    for needle, label in (
        (
            "std::sync::mpsc::channel::<usize>()",
            "unbounded tray session-count queue",
        ),
        ("sender.send(count).ok();", "silently ignored tray publication"),
        ("start_query_session_count(ipc_sender.clone());", "retained poller sender clone"),
    ):
        forbid(tray, needle, label)

    update = extract_braced_item(
        tray, "enum TraySessionCountUpdate", "typed tray session-count update"
    )
    require_order(
        update,
        ("Unchanged", "Count(usize)", "Closed"),
        "closed latest-state update classification",
    )

    channel = extract_braced_item(
        tray, "fn tray_session_count_channel()", "tray session-count channel"
    )
    require(
        channel,
        "tokio::sync::watch::channel(0)",
        "zero-initialized latest-state watch",
    )

    publish = extract_braced_item(
        tray,
        "fn publish_tray_session_count(",
        "tray session-count publication",
    )
    require_order(
        publish,
        (
            "let changed = {",
            "let current = sender.borrow();",
            "*current != count",
            "if changed && sender.send(count).is_err()",
            "return false;",
            "!sender.is_closed()",
        ),
        "read-release-before-write and receiver-final publication",
    )

    receive = extract_braced_item(
        tray,
        "fn take_tray_session_count_update(",
        "tray session-count receive",
    )
    require_order(
        receive,
        (
            "match receiver.has_changed()",
            "Ok(true) => TraySessionCountUpdate::Count(*receiver.borrow_and_update())",
            "Ok(false) => TraySessionCountUpdate::Unchanged",
            "Err(_) => TraySessionCountUpdate::Closed",
        ),
        "one-revision receive and publisher finality",
    )

    make_tray = extract_braced_item(tray, "fn make_tray()", "tray event-loop owner")
    require_order(
        make_tray,
        (
            "let (ipc_sender, ipc_receiver) = tray_session_count_channel();",
            "let mut ipc_receiver = Some(ipc_receiver);",
            "start_query_session_count(ipc_sender);",
            "ipc_receiver.as_mut().map(take_tray_session_count_update)",
            "Some(TraySessionCountUpdate::Count(count))",
            "t.set_tooltip(Some(tooltip(count)))",
            "Some(TraySessionCountUpdate::Closed)",
            "ipc_receiver = None;",
        ),
        "single sender handoff and UI-owned receiver lifecycle",
    )

    poller = extract_braced_item(
        tray,
        "async fn start_query_session_count(",
        "tray session-count poller",
    )
    require_order(
        poller,
        (
            "if sender.is_closed()",
            "return;",
            "crate::ipc::get_controlled_session_count(1000).await",
            "if !publish_tray_session_count(&sender, count)",
            "return;",
            "hbb_common::sleep(1.).await;",
        ),
        "receiver-final nonblocking poller",
    )

    for test in (
        "tray_session_count_publication_is_latest_state_only",
        "unchanged_tray_session_count_does_not_wake_the_ui",
        "tray_session_count_receiver_retirement_closes_publication",
        "tray_session_count_publisher_retirement_is_observable",
    ):
        require(tray, test, f"{test} regression")

    gate_command = "python3 scripts/verify-tray-session-count-mailbox.py --repo . --self-test"
    for key, needle, label in (
        ("verify", gate_command, "shared focused gate"),
        (
            "verify",
            "cargo test --lib --features linux-pkg-config,flutter tray::tests:: --color never",
            "shared behavior gate",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11hc</span>',
            "normative requirement",
        ),
        ("requirements", "<tr><td>364</td>", "Appendix C row"),
        (
            "hardening",
            "### R-S11hc/R-S11e-241 — latest-state Windows tray session-count ownership",
            "hardening ledger",
        ),
        (
            "workspace",
            "def validate_tray_session_count_mailbox_contract(sources):",
            "independent workspace contract",
        ),
        (
            "workspace",
            "validate_tray_session_count_mailbox_contract(sources)",
            "independent workspace dispatch",
        ),
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
        raise VerificationError("independent tray dispatch owner is absent")
    dispatches = [
        node
        for node in validate_sources_function.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "validate_tray_session_count_mailbox_contract"
    ]
    if len(dispatches) != 1:
        raise VerificationError("independent tray dispatch must occur exactly once")

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
    ("tray", "tokio::sync::watch::channel(0)", "tokio::sync::mpsc::unbounded_channel()", "latest-state channel"),
    ("tray", "tokio::sync::watch::channel(0)", "tokio::sync::watch::channel(1)", "zero initial state"),
    ("tray", "let current = sender.borrow();", "let current = sender.borrow_and_update();", "read-only publication snapshot"),
    ("tray", "*current != count", "true", "unchanged-count coalescing"),
    ("tray", "if changed && sender.send(count).is_err()", "if false && sender.send(count).is_err()", "failed publication finality"),
    ("tray", "!sender.is_closed()", "true", "receiver retirement publication result"),
    ("tray", "match receiver.has_changed()", "match Ok(false)", "revision observation"),
    ("tray", "receiver.borrow_and_update()", "receiver.borrow()", "revision acknowledgement"),
    ("tray", "Err(_) => TraySessionCountUpdate::Closed", "Err(_) => TraySessionCountUpdate::Unchanged", "publisher retirement classification"),
    ("tray", "let mut ipc_receiver = Some(ipc_receiver);", "let mut ipc_receiver = None;", "UI receiver ownership"),
    ("tray", "start_query_session_count(ipc_sender);", "start_query_session_count(ipc_sender.clone());", "sole sender handoff"),
    ("tray", "ipc_receiver = None;", "// closed receiver retained", "closed receiver retirement"),
    ("tray", "if sender.is_closed() {", "if false && sender.is_closed() {", "poller pre-query finality"),
    ("tray", "if !publish_tray_session_count(&sender, count) {", "if false && !publish_tray_session_count(&sender, count) {", "poller publication finality"),
    ("tray", "fn tray_session_count_publication_is_latest_state_only", "fn tray_session_count_publication_may_queue_history", "latest-state regression"),
    ("tray", "fn unchanged_tray_session_count_does_not_wake_the_ui", "fn unchanged_tray_session_count_may_wake_the_ui", "unchanged regression"),
    ("tray", "fn tray_session_count_receiver_retirement_closes_publication", "fn tray_session_count_receiver_retirement_is_advisory", "receiver regression"),
    ("tray", "fn tray_session_count_publisher_retirement_is_observable", "fn tray_session_count_publisher_retirement_is_hidden", "publisher regression"),
    ("verify", "python3 scripts/verify-tray-session-count-mailbox.py --repo . --self-test", "true # tray mailbox gate disabled", "shared focused gate"),
    ("verify", "cargo test --lib --features linux-pkg-config,flutter tray::tests:: --color never", "true # tray mailbox tests disabled", "shared behavior gate"),
    ("requirements", '<div class="req"><span class="id">R-S11hc</span>', '<div class="req"><span class="id">R-S11hc-disabled</span>', "normative requirement"),
    ("requirements", "<tr><td>364</td>", "<tr><td>364-disabled</td>", "Appendix disposition"),
    ("hardening", "### R-S11hc/R-S11e-241 — latest-state Windows tray session-count ownership", "### R-S11hc-disabled/R-S11e-241 — latest-state Windows tray session-count ownership", "hardening ledger"),
    ("workspace", "    validate_tray_session_count_mailbox_contract(sources)\n", "    validate_tray_session_count_mailbox_contract_disabled(sources)\n", "independent dispatch"),
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
        print(
            "Tray session-count mailbox verifier self-test passed "
            f"({len(MUTATIONS)} mutations)"
        )
    else:
        print("Tray session-count mailbox verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"Tray session-count mailbox verifier failed: {error}")
        raise SystemExit(1)
