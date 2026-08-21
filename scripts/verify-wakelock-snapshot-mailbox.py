#!/usr/bin/env python3
"""Verify coherent latest-state controlled-side wakelock snapshot ownership."""

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
        "connection": "src/server/connection.rs",
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
    for needle, label in (
        ("static ref WAKELOCK_SENDER", "old global wakelock event sender"),
        ("fn start_wakelock_thread()", "old detached wakelock worker"),
        (
            "std::sync::mpsc::channel::<(usize, usize)>()",
            "unbounded wakelock snapshot queue",
        ),
        ("allow_err!(WAKELOCK_SENDER", "silently ignored wakelock publication"),
    ):
        forbid(connection, needle, label)

    type_start = connection.find("struct WakelockSnapshot")
    type_end = connection.find(
        '#[cfg(target_os = "linux")]\nlazy_static::lazy_static! {', type_start
    )
    worker_start = connection.find("fn wakelock_snapshot_channel()", type_end)
    worker_end = connection.find("#[cfg(windows)]\npub struct PortableState", worker_start)
    if min(type_start, type_end, worker_start, worker_end) < 0:
        raise VerificationError("wakelock ownership region is incomplete")
    wakelock_region = connection[type_start:type_end] + connection[worker_start:worker_end]
    for needle, label in (
        ("std::sync::mpsc", "standard-library event queue in wakelock region"),
        ("std_mpsc", "aliased standard-library event queue in wakelock region"),
        ("mpsc::unbounded", "Tokio unbounded event queue in wakelock region"),
        ("VecDeque<WakelockSnapshot>", "retained wakelock snapshot history"),
        (
            "#[derive(Clone)]\nstruct WakelockSnapshotPublisher",
            "cloneable wakelock publisher",
        ),
        (
            "#[derive(Clone)]\nstruct WakelockSnapshotReceiver",
            "cloneable wakelock receiver",
        ),
    ):
        forbid(wakelock_region, needle, label)

    snapshot = extract_braced_item(
        connection, "struct WakelockSnapshot", "typed wakelock snapshot"
    )
    require_order(
        snapshot,
        ("connection_count: usize", "remote_count: usize"),
        "coherent wakelock snapshot fields",
    )

    owner = extract_braced_item(
        connection, "struct WakelockWorker", "process-owned wakelock worker"
    )
    require_order(
        owner,
        (
            "sender: WakelockSnapshotPublisher",
            "_thread: Option<std::thread::JoinHandle<()>>",
        ),
        "retained worker and latest-state publisher ownership",
    )
    require(
        connection,
        "static ref WAKELOCK_WORKER: WakelockWorker = start_wakelock_worker();",
        "single process-owned wakelock worker",
    )

    state = extract_braced_item(
        connection, "struct WakelockSnapshotState", "wakelock latest-state storage"
    )
    require_order(
        state,
        (
            "snapshot: WakelockSnapshot",
            "pending: bool",
            "publisher_alive: bool",
            "receiver_alive: bool",
        ),
        "one snapshot, one readiness bit, and bidirectional finality",
    )
    cell = extract_braced_item(
        connection, "struct WakelockSnapshotCell", "wakelock latest-state cell"
    )
    require_order(
        cell,
        ("state: StdMutex<WakelockSnapshotState>", "changed: Condvar"),
        "bounded synchronized latest-state cell",
    )

    channel = extract_braced_item(
        connection, "fn wakelock_snapshot_channel()", "wakelock snapshot channel"
    )
    require_order(
        channel,
        (
            "snapshot: WakelockSnapshot::default()",
            "pending: false",
            "publisher_alive: true",
            "receiver_alive: true",
            "changed: Condvar::new()",
            "WakelockSnapshotPublisher",
            "WakelockSnapshotReceiver",
        ),
        "zero-initialized one-bit latest-state cell",
    )

    publish = extract_braced_item(
        connection, "fn publish_wakelock_snapshot(", "wakelock snapshot publication"
    )
    require_order(
        publish,
        (
            "let mut state = sender.inner.state.lock().unwrap();",
            "if !state.receiver_alive",
            "return false;",
            "state.snapshot = snapshot;",
            "state.pending = true;",
            "drop(state);",
            "sender.inner.changed.notify_one();",
            "true",
        ),
        "nonblocking latest-state replacement and receiver-final wake",
    )

    receive = extract_braced_item(
        connection, "fn wait_for_wakelock_snapshot(", "wakelock snapshot receive"
    )
    require_order(
        receive,
        (
            "let mut state = receiver.inner.state.lock().unwrap();",
            "while !state.pending && state.publisher_alive",
            "receiver.inner.changed.wait(state).unwrap()",
            "if !state.publisher_alive",
            "state.pending = false;",
            "return None;",
            "state.pending = false;",
            "Some(state.snapshot)",
        ),
        "blocking one-bit observation, acknowledgement, and publisher finality",
    )

    publisher_drop = extract_braced_item(
        connection,
        "impl Drop for WakelockSnapshotPublisher",
        "wakelock publisher retirement",
    )
    require_order(
        publisher_drop,
        (
            "state.publisher_alive = false;",
            "drop(state);",
            "self.inner.changed.notify_one();",
        ),
        "publisher-retirement terminal wake",
    )
    receiver_drop = extract_braced_item(
        connection,
        "impl Drop for WakelockSnapshotReceiver",
        "wakelock receiver retirement",
    )
    require_order(
        receiver_drop,
        (
            "state.receiver_alive = false;",
            "state.pending = false;",
            "drop(state);",
            "self.inner.changed.notify_one();",
        ),
        "receiver-retirement closure and retained-state release",
    )

    worker = extract_braced_item(
        connection, "fn run_wakelock_worker(", "wakelock worker loop"
    )
    require_order(
        worker,
        (
            "wait_for_wakelock_snapshot(&mut receiver)",
            'log::error!("wakelock snapshot publisher stopped")',
            "config::Config::get_bool_option(",
            "*WAKELOCK_KEEP_AWAKE_OPTION.lock().unwrap() = Some(keep_awake);",
            "snapshot.connection_count == 0",
            "snapshot.remote_count > 0",
        ),
        "latest snapshot consumption and existing option/platform behavior",
    )

    start = extract_braced_item(
        connection, "fn start_wakelock_worker()", "wakelock worker start"
    )
    require_order(
        start,
        (
            "let (sender, receiver) = wakelock_snapshot_channel();",
            "std::thread::Builder::new()",
            '.name("rustdesk-wakelock".to_owned())',
            ".spawn(move || run_wakelock_worker(receiver))",
            "Ok(thread) => Some(thread)",
            'log::error!("failed to start wakelock worker: {err}")',
            "_thread: thread",
        ),
        "single named retained worker with visible startup failure",
    )

    check = extract_braced_item(
        connection, "fn check_wake_lock()", "authenticated connection snapshot"
    )
    if check.count("AUTHED_CONNS.lock().unwrap()") != 1:
        raise VerificationError(
            "wakelock snapshot must derive both counts under exactly one connection lock"
        )
    require_order(
        check,
        (
            "let authed_conns = AUTHED_CONNS.lock().unwrap();",
            "connection_count: authed_conns.len()",
            "remote_count: authed_conns",
            "conn.conn_type == AuthConnType::Remote",
            "let published = publish_wakelock_snapshot(&WAKELOCK_WORKER.sender, snapshot);",
            "drop(authed_conns);",
            "if !published",
            'log::error!("wakelock worker stopped before snapshot publication")',
        ),
        "coherent mutation-ordered snapshot and visible publication failure",
    )

    setting = extract_braced_item(
        connection,
        "pub fn check_wake_lock_on_setting_changed()",
        "wakelock option reevaluation",
    )
    require_order(
        setting,
        (
            "cached != Some(current)",
            "Self::check_wake_lock();",
        ),
        "existing option-change reevaluation route",
    )

    for test in (
        "wakelock_publication_keeps_only_the_latest_coherent_snapshot",
        "identical_wakelock_snapshot_requests_option_reevaluation",
        "wakelock_receiver_retirement_closes_publication",
        "wakelock_publisher_retirement_is_observable",
    ):
        require(connection, test, f"{test} regression")

    gate_command = "python3 scripts/verify-wakelock-snapshot-mailbox.py --repo . --self-test"
    for key, needle, label in (
        ("verify", gate_command, "shared focused gate"),
        ("apple", gate_command, "Apple/shared focused gate"),
        (
            "verify",
            "cargo test --lib --features linux-pkg-config,flutter server::connection::wakelock_snapshot_tests:: --color never",
            "shared behavior gate",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11hd</span>',
            "normative requirement",
        ),
        ("requirements", "<tr><td>365</td>", "Appendix C row"),
        (
            "hardening",
            "### R-S11hd/R-S11e-242 — coherent latest-state wakelock snapshot ownership",
            "hardening ledger",
        ),
        (
            "workspace",
            "def validate_wakelock_snapshot_mailbox_contract(sources):",
            "independent workspace contract",
        ),
        (
            "workspace",
            "validate_wakelock_snapshot_mailbox_contract(sources)",
            "independent workspace dispatch",
        ),
    ):
        require(sources[key], needle, label)

    workspace_module = ast.parse(sources["workspace"])
    main_function = next(
        (
            node
            for node in workspace_module.body
            if isinstance(node, ast.FunctionDef) and node.name == "main"
        ),
        None,
    )
    if main_function is None:
        raise VerificationError("independent wakelock source map is absent")
    source_maps = [
        node.value
        for node in ast.walk(main_function)
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Dict)
        and any(
            isinstance(target, ast.Name) and target.id == "sources"
            for target in node.targets
        )
    ]
    if len(source_maps) != 1:
        raise VerificationError("independent wakelock source map is not singular")
    source_map_keys = [
        key.value
        for key in source_maps[0].keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    ]
    if source_map_keys.count("wakelock_snapshot_mailbox_verifier") != 1:
        raise VerificationError("independent wakelock verifier binding is absent")
    if source_map_keys.count("connection_source") != 1:
        raise VerificationError("independent connection source binding is absent")

    validate_sources_function = next(
        (
            node
            for node in workspace_module.body
            if isinstance(node, ast.FunctionDef) and node.name == "validate_sources"
        ),
        None,
    )
    if validate_sources_function is None:
        raise VerificationError("independent wakelock dispatch owner is absent")
    dispatches = [
        node
        for node in validate_sources_function.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "validate_wakelock_snapshot_mailbox_contract"
    ]
    if len(dispatches) != 1:
        raise VerificationError("independent wakelock dispatch must occur exactly once")

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
    ("connection", "sender: WakelockSnapshotPublisher", "sender: mpsc::UnboundedSender<WakelockSnapshot>", "latest-state sender"),
    ("connection", "_thread: Option<std::thread::JoinHandle<()>>", "_thread: ()", "retained worker handle"),
    ("connection", "static ref WAKELOCK_WORKER: WakelockWorker = start_wakelock_worker();", "static ref WAKELOCK_WORKER_DISABLED: WakelockWorker = start_wakelock_worker();", "process-owned worker"),
    ("connection", "struct WakelockSnapshotState {\n    snapshot: WakelockSnapshot,", "struct WakelockSnapshotState {\n    snapshot: Vec<WakelockSnapshot>,", "single retained snapshot"),
    ("connection", "pending: bool,", "pending: usize,", "one-bit readiness"),
    ("connection", "state: StdMutex<WakelockSnapshotState>", "state: Vec<WakelockSnapshotState>", "synchronized latest-state cell"),
    ("connection", "struct WakelockSnapshotCell {\n    state: StdMutex<WakelockSnapshotState>,\n    changed: Condvar", "struct WakelockSnapshotCell {\n    state: StdMutex<WakelockSnapshotState>,\n    changed: ()", "blocking latest-state wake"),
    ("connection", "state: StdMutex<WakelockSnapshotState>,\n    changed: Condvar,", "state: StdMutex<WakelockSnapshotState>,\n    changed: Condvar,\n    history: VecDeque<WakelockSnapshot>,", "no retained snapshot history"),
    ("connection", "struct WakelockSnapshotPublisher {", "#[derive(Clone)]\nstruct WakelockSnapshotPublisher {", "sole snapshot publisher"),
    ("connection", "struct WakelockSnapshotReceiver {", "#[derive(Clone)]\nstruct WakelockSnapshotReceiver {", "sole snapshot receiver"),
    ("connection", "snapshot: WakelockSnapshot::default()", "snapshot: WakelockSnapshot { connection_count: 1, remote_count: 1 }", "zero initial snapshot"),
    ("connection", "pending: false,", "pending: true,", "no initial revision"),
    ("connection", "publisher_alive: true,", "publisher_alive: false,", "live initial publisher"),
    ("connection", "receiver_alive: true,", "receiver_alive: false,", "live initial receiver"),
    ("connection", "receiver_alive: true,\n        }),\n        changed: Condvar::new(),", "receiver_alive: true,\n        }),\n        changed: Condvar::default(),", "condition wake initialization"),
    ("connection", "if !state.receiver_alive {", "if false && !state.receiver_alive {", "publication receiver finality"),
    ("connection", "state.snapshot = snapshot;", "// snapshot replacement disabled", "latest-state replacement"),
    ("connection", "state.pending = true;", "state.pending = false;", "identical revision publication"),
    ("connection", "sender.inner.changed.notify_one();", "// publisher wake disabled", "nonblocking publisher wake"),
    ("connection", "while !state.pending && state.publisher_alive {", "while !state.pending && false {", "blocking observation predicate"),
    ("connection", "receiver.inner.changed.wait(state).unwrap()", "state", "condition wait"),
    ("connection", "if !state.publisher_alive {", "if false && !state.publisher_alive {", "publisher retirement observation"),
    ("connection", "Some(state.snapshot)", "None", "latest snapshot delivery"),
    ("connection", "state.publisher_alive = false;", "state.publisher_alive = true;", "publisher retirement transition"),
    ("connection", "state.receiver_alive = false;", "state.receiver_alive = true;", "receiver retirement transition"),
    ("connection", 'log::error!("wakelock snapshot publisher stopped")', 'log::debug!("wakelock snapshot publisher stopped")', "publisher retirement visibility"),
    ("connection", "snapshot.connection_count == 0", "false", "connection snapshot consumption"),
    ("connection", "snapshot.remote_count > 0", "false", "remote snapshot consumption"),
    ("connection", '.name("rustdesk-wakelock".to_owned())', '.name("rustdesk-wakelock-disabled".to_owned())', "named worker"),
    ("connection", ".spawn(move || run_wakelock_worker(receiver))", ".spawn(move || drop(receiver))", "sole worker receiver"),
    ("connection", "Ok(thread) => Some(thread)", "Ok(_thread) => None", "successful worker retention"),
    ("connection", 'log::error!("failed to start wakelock worker: {err}")', 'log::debug!("failed to start wakelock worker: {err}")', "startup failure visibility"),
    ("connection", "connection_count: authed_conns.len()", "connection_count: 0", "coherent connection count"),
    ("connection", "conn.conn_type == AuthConnType::Remote", "false", "coherent remote count"),
    ("connection", "let published = publish_wakelock_snapshot(&WAKELOCK_WORKER.sender, snapshot);", "let published = true;", "ordered snapshot publication"),
    ("connection", "drop(authed_conns);", "// connection guard retained implicitly", "explicit publication ordering"),
    ("connection", "if !published {", "if false && !published {", "publication failure branch"),
    ("connection", 'log::error!("wakelock worker stopped before snapshot publication")', 'log::debug!("wakelock worker stopped before snapshot publication")', "publication failure visibility"),
    ("connection", "cached != Some(current)", "false", "option reevaluation"),
    ("connection", "fn wakelock_publication_keeps_only_the_latest_coherent_snapshot", "fn wakelock_publication_may_queue_history", "latest-state regression"),
    ("connection", "fn identical_wakelock_snapshot_requests_option_reevaluation", "fn identical_wakelock_snapshot_skips_option_reevaluation", "identical-revision regression"),
    ("connection", "fn wakelock_receiver_retirement_closes_publication", "fn wakelock_receiver_retirement_is_advisory", "receiver regression"),
    ("connection", "fn wakelock_publisher_retirement_is_observable", "fn wakelock_publisher_retirement_is_hidden", "publisher regression"),
    ("verify", "python3 scripts/verify-wakelock-snapshot-mailbox.py --repo . --self-test", "true # wakelock snapshot gate disabled", "shared focused gate"),
    ("apple", "python3 scripts/verify-wakelock-snapshot-mailbox.py --repo . --self-test", "true # wakelock snapshot gate disabled", "Apple/shared focused gate"),
    ("verify", "cargo test --lib --features linux-pkg-config,flutter server::connection::wakelock_snapshot_tests:: --color never", "true # wakelock snapshot tests disabled", "shared behavior gate"),
    ("requirements", '<div class="req"><span class="id">R-S11hd</span>', '<div class="req"><span class="id">R-S11hd-disabled</span>', "normative requirement"),
    ("requirements", "<tr><td>365</td>", "<tr><td>365-disabled</td>", "Appendix disposition"),
    ("hardening", "### R-S11hd/R-S11e-242 — coherent latest-state wakelock snapshot ownership", "### R-S11hd-disabled/R-S11e-242 — coherent latest-state wakelock snapshot ownership", "hardening ledger"),
    ("workspace", "    validate_wakelock_snapshot_mailbox_contract(sources)\n", "    validate_wakelock_snapshot_mailbox_contract_disabled(sources)\n", "independent dispatch"),
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
            "Wakelock snapshot mailbox verifier self-test passed "
            f"({len(MUTATIONS)} mutations)"
        )
    else:
        print("Wakelock snapshot mailbox verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"Wakelock snapshot mailbox verifier failed: {error}")
        raise SystemExit(1)
