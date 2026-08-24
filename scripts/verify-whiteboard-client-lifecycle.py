#!/usr/bin/env python3
"""Verify exact-generation whiteboard client worker lifecycle ownership."""

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
        "client": "src/whiteboard/client.rs",
        "connection": "src/server/connection.rs",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "native_watch": "docs/NATIVE-CODEC-WATCH.md",
        "verify": "scripts/verify.sh",
        "apple": "scripts/apple-conform-check.sh",
        "linux_verifier": "scripts/verify-linux-nondumpable-cm.py",
        "workspace": "scripts/verify-verifier-workspace.py",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def validate(sources: Dict[str, str]) -> None:
    client = sources["client"]
    for needle, label in (
        ("std::thread::spawn", "detached whiteboard client thread"),
        ("#[tokio::main", "nested whiteboard client runtime"),
        ("STARTING_WHITEBOARD", "split whiteboard startup flag"),
        ("TX_WHITEBOARD", "split whiteboard sender global"),
        ("static ref CONNS", "split whiteboard connection global"),
        ("SimpleCallOnReturn", "ad-hoc whiteboard client cleanup callback"),
        ("runtime::Builder", "replacement whiteboard client runtime"),
        ("Vec::with_capacity(2)", "heap allocation in two-command cursor path"),
    ):
        forbid(client, needle, label)

    phase = extract_braced_item(
        client, "enum WhiteboardWorkerPhase", "whiteboard worker phase"
    )
    require_order(
        phase,
        (
            "Idle",
            "Starting",
            "generation: u64",
            "Running",
            "Stopping",
            "restart_requested: bool",
        ),
        "closed whiteboard worker phase vocabulary",
    )

    lifecycle_state = extract_braced_item(
        client,
        "struct WhiteboardWorkerLifecycle",
        "whiteboard worker lifecycle state",
    )
    require_order(
        lifecycle_state,
        ("phase: WhiteboardWorkerPhase", "last_generation: u64"),
        "phase and monotonic generation owner",
    )

    reserve = extract_braced_item(
        client,
        "fn reserve_next_generation(&mut self)",
        "checked generation reservation",
    )
    require_order(
        reserve,
        (
            ".checked_add(1)",
            'anyhow!("whiteboard worker generation exhausted")',
            "self.last_generation = generation;",
            "self.phase = WhiteboardWorkerPhase::Starting { generation };",
        ),
        "checked monotonic generation reservation",
    )

    request = extract_braced_item(
        client, "fn request_worker(&mut self)", "level-triggered worker request"
    )
    require_order(
        request,
        (
            "WhiteboardWorkerPhase::Idle",
            "self.reserve_next_generation().map(Some)",
            "WhiteboardWorkerPhase::Starting { .. }",
            "WhiteboardWorkerPhase::Running { .. }",
            "WhiteboardWorkerPhase::Stopping",
            "restart_requested: true",
        ),
        "one active generation and stop-window successor demand",
    )
    require(
        request,
        "WhiteboardWorkerPhase::Starting { .. }\n"
        "            | WhiteboardWorkerPhase::Running { .. } => Ok(None),",
        "shared Starting/Running duplicate-launch refusal",
    )

    publish = extract_braced_item(
        client, "fn publish(&mut self, generation: u64)", "exact startup publication"
    )
    require_order(
        publish,
        (
            "WhiteboardWorkerPhase::Starting { generation }",
            "return false;",
            "WhiteboardWorkerPhase::Running { generation }",
        ),
        "exact generation startup publication",
    )

    begin_stop = extract_braced_item(
        client,
        "fn begin_stop(&mut self, generation: u64)",
        "exact idle-stop commit",
    )
    require_order(
        begin_stop,
        (
            "WhiteboardWorkerPhase::Running { generation }",
            "return false;",
            "WhiteboardWorkerPhase::Stopping",
            "restart_requested: false",
        ),
        "running-to-stopping transition without implicit retry",
    )

    sender_failed = extract_braced_item(
        client,
        "fn sender_failed(&mut self, generation: u64)",
        "terminal sender failure",
    )
    require_order(
        sender_failed,
        (
            "WhiteboardWorkerPhase::Running",
            "if current == generation",
            "WhiteboardWorkerPhase::Stopping",
            "restart_requested: false",
        ),
        "sender failure without automatic restart",
    )
    forbid(
        sender_failed,
        "has_demand",
        "ambient demand converted into sender-failure retry",
    )

    finish = extract_braced_item(
        client, "fn finish(", "exact worker finalization state"
    )
    require_order(
        finish,
        (
            "WhiteboardWorkerPhase::Starting",
            "WhiteboardWorkerPhase::Running",
            "=> false",
            "WhiteboardWorkerPhase::Stopping",
            "restart_requested && has_demand",
            "_ => return Ok(None)",
            "self.phase = WhiteboardWorkerPhase::Idle;",
            "self.reserve_next_generation().map(Some)",
        ),
        "exact finalizer and one explicitly demanded successor",
    )

    state = extract_braced_item(
        client, "struct WhiteboardClientState", "unified whiteboard client state"
    )
    require_order(
        state,
        (
            "lifecycle: WhiteboardWorkerLifecycle",
            "sender: Option<(u64, Sender<WhiteboardIpcCommand>)>",
            "worker: Option<(u64, tokio::task::JoinHandle<()>)>",
            "conns: HashMap<i32, Conn>",
        ),
        "single generation-bound client authority state",
    )
    require(
        client,
        "static ref WHITEBOARD_CLIENT: Mutex<WhiteboardClientState>",
        "single locked client authority owner",
    )

    send_command = extract_braced_item(
        client, "fn send_command(&mut self", "bounded command admission"
    )
    require_order(
        send_command,
        (
            "self.sender.as_ref()",
            "self.lifecycle.running_generation()",
            "self.lifecycle.sender_failed(generation)",
            "sender.try_send(command)",
            "TrySendError::Full(WhiteboardIpcCommand::Event { .. })",
            "WhiteboardCommandAdmission::EventDropped",
            "TrySendError::Full(_)",
            "self.sender.take()",
            "self.lifecycle.sender_failed(generation)",
            "TrySendError::Closed(_)",
        ),
        "bounded nonblocking command and terminal critical overflow policy",
    )
    forbid(send_command, "sender.clone()", "per-command sender clone")
    forbid(send_command, "blocking_send", "blocking whiteboard command admission")

    install = extract_braced_item(
        client,
        "fn install_reserved_whiteboard_worker(",
        "existing-runtime worker installation",
    )
    require_order(
        install,
        (
            "WhiteboardWorkerPhase::Starting { generation }",
            "state.worker.is_some()",
            "tokio::runtime::Handle::try_current()",
            "runtime.spawn(run_whiteboard_worker(generation))",
            "state.worker = Some((generation, worker));",
        ),
        "reserved generation and retained existing-runtime task",
    )

    task_finalizer = extract_braced_item(
        client,
        "impl Drop for WhiteboardClientWorkerGuard",
        "worker terminal finalizer",
    )
    require(
        task_finalizer,
        "finish_whiteboard_worker(self.generation);",
        "exact generation terminal publication",
    )
    finish_worker = extract_braced_item(
        client,
        "fn finish_whiteboard_worker(generation: u64)",
        "worker ownership finalizer",
    )
    require_order(
        finish_worker,
        (
            "WHITEBOARD_CLIENT.lock().unwrap()",
            "Some(generation)",
            "state.sender.take()",
            "state.worker.take()",
            "state.lifecycle.finish(generation, has_demand)",
            "install_reserved_whiteboard_worker(&mut state, restart_generation)",
            "cancel_reserved_generation(restart_generation)",
            "drop(retired_worker);",
        ),
        "exact handle retirement and one demanded successor",
    )

    run_worker = extract_braced_item(
        client,
        "async fn run_whiteboard_worker(generation: u64)",
        "runtime-owned whiteboard task",
    )
    require(
        run_worker,
        "async fn run_whiteboard_worker(generation: u64) {\n"
        "    let _terminal = WhiteboardClientWorkerGuard { generation };",
        "first-action client worker finalizer",
    )
    require_order(
        run_worker,
        (
            "WhiteboardClientWorkerGuard { generation }",
            "AssertUnwindSafe(start_whiteboard_(generation))",
            ".catch_unwind()",
            "Whiteboard worker generation {generation} failed",
            "Whiteboard worker generation {generation} panicked",
        ),
        "visible task error and panic finality",
    )

    register = extract_braced_item(
        client, "pub fn register_whiteboard", "whiteboard registration"
    )
    require_order(
        register,
        (
            "if conn_id <= 0",
            "WHITEBOARD_CLIENT.lock().unwrap()",
            "state.conns.contains_key(&conn_id)",
            "state.conns.len() >= ipc::WHITEBOARD_IPC_MAX_ACTIVE_CONNECTIONS",
            "random::<[u8; 32]>()",
            "WhiteboardIpcCommand::Bind",
            "state.lifecycle.request_worker()",
            "state.send_command(command)",
            "if !matches!(admission, WhiteboardCommandAdmission::Accepted)",
            "state.lifecycle.request_worker()",
            "install_reserved_whiteboard_worker(&mut state, generation)",
            "cancel_reserved_generation(generation)",
        ),
        "registration, exact bind, terminal-window demand, and task installation",
    )

    unregister = extract_braced_item(
        client, "pub fn unregister_whiteboard", "whiteboard unregistration"
    )
    require_order(
        unregister,
        (
            "WHITEBOARD_CLIENT.lock().unwrap()",
            ".remove(&conn_id)",
            "WhiteboardIpcCommand::Close",
            "state.conns.is_empty()",
            "state.send_command(command)",
            "state.send_command(WhiteboardIpcCommand::Shutdown)",
        ),
        "atomic connection retirement and idle shutdown request",
    )

    update = extract_braced_item(
        client, "pub fn update_whiteboard", "whiteboard event publication"
    )
    require_order(
        update,
        (
            "let mut commands = [None, None];",
            "commands.into_iter().flatten().enumerate()",
            "admissions[index] = Some(state.send_command(command));",
        ),
        "fixed-allocation two-command cursor publication",
    )

    close_idle = extract_braced_item(
        client,
        "fn close_whiteboard_if_idle(generation: u64)",
        "idle stop commit",
    )
    require_order(
        close_idle,
        (
            "WHITEBOARD_CLIENT.lock().unwrap()",
            "if !state.conns.is_empty()",
            "state.lifecycle.begin_stop(generation)",
            "Some(generation)",
            "state.sender.take()",
        ),
        "atomic demand check and exact sender retirement",
    )

    start = extract_braced_item(
        client,
        "async fn start_whiteboard_(generation: u64)",
        "generation-bound whiteboard stream owner",
    )
    require_order(
        start,
        (
            "run_me_with_env_and_parent_death(",
            "connect_whiteboard_endpoint(1000, &postfix, &launch_token)",
            "channel(ipc::WHITEBOARD_IPC_COMMAND_CAPACITY)",
            "state.lifecycle.publish(generation)",
            "state.sender = Some((generation, tx.clone()));",
            "state.conns.iter()",
            "drop(tx);",
            "close_whiteboard_if_idle(generation)",
        ),
        "generation publication, initial snapshot, and exact idle stop",
    )
    if start.count(".send_whiteboard_command_timeout(") != 5:
        raise VerificationError("whiteboard client must retain exactly five deadline write sites")

    for test in (
        "r_s11ho_duplicate_whiteboard_demand_owns_one_generation",
        "r_s11ho_demand_during_committed_stop_starts_one_successor",
        "r_s11ho_unexpected_worker_failure_does_not_self_retry",
        "r_s11ho_stale_finalizer_cannot_retire_current_generation",
    ):
        require(client, test, f"{test} regression")

    remote_context = sources["connection"]
    require_order(
        remote_context,
        (
            "if self.is_authed_remote_conn()",
            "whiteboard::register_whiteboard(self.inner.id);",
        ),
        "authenticated Remote-only whiteboard registration",
    )

    focused_gate = "python3 scripts/verify-whiteboard-client-lifecycle.py --repo . --self-test"
    behavior_gate = "cargo test --lib --features linux-pkg-config,flutter r_s11ho_ --color never"
    for key, needle, label in (
        ("verify", focused_gate, "shared focused gate"),
        ("verify", behavior_gate, "shared behavior gate"),
        ("apple", focused_gate, "Apple focused gate"),
        (
            "linux_verifier",
            "retained generation-bound whiteboard task",
            "adjacent Linux verifier contract",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11ho</span>',
            "normative lifecycle requirement",
        ),
        ("requirements", "<tr><td>375</td>", "Appendix C lifecycle disposition"),
        (
            "hardening",
            "### R-S11ho/R-S11e-252 — exact-generation whiteboard client worker ownership",
            "hardening lifecycle ledger",
        ),
        (
            "workspace",
            "def validate_whiteboard_client_lifecycle_contract(sources):",
            "independent workspace contract",
        ),
        (
            "workspace",
            '            "whiteboard_client_lifecycle_verifier": (\n'
            '                repo / "scripts/verify-whiteboard-client-lifecycle.py"\n'
            '            ).read_text(encoding="utf-8"),',
            "independent focused-verifier source binding",
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
        raise VerificationError("independent whiteboard client lifecycle dispatch is absent")
    dispatches = [
        node
        for node in validate_sources_function.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "validate_whiteboard_client_lifecycle_contract"
    ]
    if len(dispatches) != 1:
        raise VerificationError(
            "independent whiteboard client lifecycle dispatch must occur exactly once"
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
    ("client", "restart_requested: bool", "restart_requested: usize", "terminal demand bit"),
    ("client", ".checked_add(1)", ".wrapping_add(1)", "checked generation advance"),
    ("client", "WhiteboardWorkerPhase::Starting { generation };", "WhiteboardWorkerPhase::Idle;", "generation reservation"),
    ("client", "WhiteboardWorkerPhase::Starting { .. }\n            | WhiteboardWorkerPhase::Running { .. } => Ok(None)", "WhiteboardWorkerPhase::Starting { .. } => self.reserve_next_generation().map(Some)\n            WhiteboardWorkerPhase::Running { .. } => Ok(None)", "duplicate launch refusal"),
    ("client", "restart_requested: true", "restart_requested: false", "stop-window demand latch"),
    ("client", "WhiteboardWorkerPhase::Running { generation };", "WhiteboardWorkerPhase::Idle;", "startup publication"),
    ("client", "restart_requested: false,\n        };\n        true", "restart_requested: true,\n        };\n        true", "idle stop without implicit retry"),
    ("client", "fn sender_failed(&mut self, generation: u64)", "fn sender_failed(&mut self, generation: u64, has_demand: bool)", "failure retry surface"),
    ("client", "restart_requested && has_demand", "restart_requested || has_demand", "successor demand conjunction"),
    ("client", "_ => return Ok(None)", "_ => self.reserve_next_generation().map(Some)", "stale finalizer refusal"),
    ("client", "worker: Option<(u64, tokio::task::JoinHandle<()>)>", "worker: Option<tokio::task::JoinHandle<()>>", "generation-bound task handle"),
    ("client", "static ref WHITEBOARD_CLIENT: Mutex<WhiteboardClientState>", "static ref WHITEBOARD_CLIENT: RwLock<WhiteboardClientState>", "single serialized lifecycle"),
    ("client", "(*generation, sender.try_send(command))", "(*generation, sender.blocking_send(command))", "nonblocking command admission"),
    ("client", "Err(TrySendError::Full(WhiteboardIpcCommand::Event { .. }))", "Err(TrySendError::Full(_))", "lossy event-only overflow"),
    ("client", "self.sender.take();\n                self.lifecycle.sender_failed(generation);", "self.sender.take();\n                self.lifecycle.request_worker()?;", "critical failure no retry"),
    ("client", "tokio::runtime::Handle::try_current()", "tokio::runtime::Builder::new_current_thread()", "existing runtime ownership"),
    ("client", "runtime.spawn(run_whiteboard_worker(generation))", "std::thread::spawn(move || start_whiteboard_(generation))", "runtime-owned task"),
    ("client", "state.worker = Some((generation, worker));", "drop(worker);", "retained task handle"),
    ("client", "finish_whiteboard_worker(self.generation);", "finish_whiteboard_worker(0);", "exact terminal generation"),
    ("client", "state.worker.take().map(|(_, worker)| worker)", "None", "exact task-handle retirement"),
    ("client", "state.lifecycle.finish(generation, has_demand)", "state.lifecycle.finish(generation + 1, has_demand)", "exact lifecycle finalization"),
    ("client", "install_reserved_whiteboard_worker(&mut state, restart_generation)", "Ok(())", "demanded successor installation"),
    ("client", "let _terminal = WhiteboardClientWorkerGuard { generation };", "let _terminal_finalizer_was_removed = ();", "first-action task finalizer"),
    ("client", ".catch_unwind()", ".map(Ok)", "visible task panic"),
    ("client", "state.conns.contains_key(&conn_id)", "false", "duplicate registration identity"),
    ("client", "state.conns.len() >= ipc::WHITEBOARD_IPC_MAX_ACTIVE_CONNECTIONS", "false", "registration capacity"),
    ("client", "let launch_generation = match state.lifecycle.request_worker()", "let launch_generation = match WhiteboardWorkerLifecycle::default().request_worker()", "registration lifecycle request"),
    ("client", "if !matches!(admission, WhiteboardCommandAdmission::Accepted)", "if false", "failed-bind successor demand"),
    ("client", "install_reserved_whiteboard_worker(&mut state, generation)", "Ok(())", "registration task installation"),
    ("client", "state.send_command(WhiteboardIpcCommand::Shutdown)", "WhiteboardCommandAdmission::Accepted", "idle shutdown publication"),
    ("client", "let mut commands = [None, None];", "let mut commands = Vec::with_capacity(2);", "fixed cursor command storage"),
    ("client", "state.lifecycle.begin_stop(generation)", "true", "exact idle stop transition"),
    ("client", "state.lifecycle.publish(generation)", "true", "exact sender publication"),
    ("client", "state.sender = Some((generation, tx.clone()));", "state.sender = Some((0, tx.clone()));", "generation-bound sender"),
    ("client", "close_whiteboard_if_idle(generation)", "close_whiteboard_if_idle(0)", "generation-bound idle stop"),
    ("client", "fn r_s11ho_duplicate_whiteboard_demand_owns_one_generation", "fn whiteboard_duplicate_demand_may_launch_again", "duplicate-demand regression"),
    ("client", "fn r_s11ho_demand_during_committed_stop_starts_one_successor", "fn whiteboard_terminal_demand_may_be_lost", "stop-window regression"),
    ("client", "fn r_s11ho_unexpected_worker_failure_does_not_self_retry", "fn whiteboard_failure_may_self_retry", "no-retry regression"),
    ("client", "fn r_s11ho_stale_finalizer_cannot_retire_current_generation", "fn stale_finalizer_may_retire_current_generation", "stale-finalizer regression"),
    ("verify", "python3 scripts/verify-whiteboard-client-lifecycle.py --repo . --self-test", "true # whiteboard client lifecycle gate disabled", "shared focused gate"),
    ("verify", "cargo test --lib --features linux-pkg-config,flutter r_s11ho_ --color never", "true # whiteboard client lifecycle tests disabled", "shared behavior gate"),
    ("apple", "python3 scripts/verify-whiteboard-client-lifecycle.py --repo . --self-test", "true # whiteboard client lifecycle gate disabled", "Apple focused gate"),
    ("requirements", '<div class="req"><span class="id">R-S11ho</span>', '<div class="req"><span class="id">R-S11ho-disabled</span>', "normative lifecycle requirement"),
    ("requirements", "<tr><td>375</td>", "<tr><td>375-disabled</td>", "Appendix C lifecycle disposition"),
    ("hardening", "### R-S11ho/R-S11e-252 — exact-generation whiteboard client worker ownership", "### R-S11ho-disabled/R-S11e-252 — exact-generation whiteboard client worker ownership", "hardening lifecycle ledger"),
    ("workspace", "    validate_whiteboard_client_lifecycle_contract(sources)\n", "    validate_whiteboard_client_lifecycle_contract_disabled(sources)\n", "independent lifecycle dispatch"),
    ("workspace", '            "whiteboard_client_lifecycle_verifier": (\n', '            "whiteboard_client_lifecycle_verifier_disabled": (\n', "focused-verifier source binding"),
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
            "Whiteboard client lifecycle verifier self-test passed "
            f"({len(MUTATIONS)} mutations)"
        )
    else:
        print("Whiteboard client lifecycle verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"Whiteboard client lifecycle verifier failed: {error}")
        raise SystemExit(1)
