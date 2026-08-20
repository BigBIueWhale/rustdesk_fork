#!/usr/bin/env python3
"""Verify bounded, exact-generation native clipboard-listener ownership."""

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
        "clipboard": "src/clipboard.rs",
        "client": "src/client.rs",
        "service": "src/server/clipboard_service.rs",
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
    service = sources["service"]

    for source, needle, label in (
        (clipboard, "HashMap<String, Sender<CallbackResult>>", "unbounded subscriber sender map"),
        (clipboard, "tx.send(CallbackResult::Next).ok();", "unbounded callback-change send"),
        (clipboard, "pub fn subscribe(name: String, tx: Sender<CallbackResult>)", "caller-created callback queue"),
        (clipboard, "pub fn unsubscribe(name: &str)", "name-only callback retirement"),
        (client, "let (tx_cb_result, rx_cb_result) = mpsc::channel();", "viewer callback queue"),
        (service, "let (tx_cb_result, rx_cb_result) = channel();", "controlled callback queue"),
    ):
        forbid(source, needle, label)

    for needle, label in (
        ("change_pending: bool", "one-bit change readiness"),
        ("terminal: Option<CallbackTerminal>", "terminal callback state"),
        ("receiver_alive: bool", "receiver lifetime state"),
        ("generation: u64", "monotonic subscription identity"),
        ("next_generation: u64", "generation allocator state"),
        ("identity: Option<Arc<SubscriptionIdentity>>", "receiver exact cleanup identity"),
        ("pub struct ClipboardSubscription", "retained subscription owner"),
    ):
        require(clipboard, needle, label)

    mailbox = extract_braced_item(clipboard, "struct CallbackMailbox", "callback mailbox")
    require(mailbox, "ready: Condvar,", "non-queue readiness wake")

    notify_change = extract_braced_item(
        clipboard, "fn notify_change(&self) -> bool", "change notification admission"
    )
    require_order(
        notify_change,
        (
            "if !state.receiver_alive",
            "if state.terminal.is_none()",
            "state.change_pending = true;",
            "self.mailbox.ready.notify_one();",
        ),
        "bounded nonblocking coalesced change notification",
    )

    notify_terminal = extract_braced_item(
        clipboard,
        "fn notify_terminal(&self, terminal: CallbackTerminal) -> bool",
        "terminal notification admission",
    )
    require_order(
        notify_terminal,
        (
            "if !state.receiver_alive",
            "if state.terminal.is_none()",
            "state.change_pending = false;",
            "state.terminal = Some(terminal);",
            "self.mailbox.ready.notify_one();",
        ),
        "terminal-over-readiness priority",
    )

    receive = extract_braced_item(
        clipboard,
        "pub fn recv_timeout(&self, timeout: Duration) -> Option<CallbackResult>",
        "bounded callback receive",
    )
    require_order(
        receive,
        (
            "wait_timeout_while(state, timeout",
            "if let Some(terminal) = state.terminal.take()",
            "CallbackTerminal::Error(message)",
            "if state.change_pending",
            "state.change_pending = false;",
            "Some(CallbackResult::Next)",
            "if wait_result.timed_out()",
        ),
        "terminal-first callback receive and readiness drain",
    )

    receiver_drop = extract_braced_item(
        clipboard, "impl Drop for CallbackReceiver", "receiver finalizer"
    )
    require_order(
        receiver_drop,
        (
            "state.receiver_alive = false;",
            "state.change_pending = false;",
            "state.terminal = None;",
            "if let Some(identity) = self.identity.take()",
            "unsubscribe_exact(&identity);",
        ),
        "receiver-close-before-exact-unsubscribe finality",
    )

    subscription_drop = extract_braced_item(
        clipboard, "impl Drop for ClipboardSubscription", "subscription finalizer"
    )
    require(subscription_drop, "self.close();", "subscription RAII close")

    subscribe = extract_braced_item(
        clipboard,
        "pub fn subscribe(name: String) -> ResultType<(ClipboardSubscription, CallbackReceiver)>",
        "exact clipboard subscription",
    )
    require_order(
        subscribe,
        (
            ".contains_key(&name)",
            "subscription already exists",
            "next_generation.checked_add(1)",
            "listener_lock.next_generation = generation;",
            "Subscriber { generation, sender }",
            "start_clipboard_master_thread(",
            "remove_exact_subscriber(",
            "drop(listener_lock);",
            "drop(receiver);",
            "Ok((ClipboardSubscription { identity }, receiver))",
        ),
        "duplicate refusal, checked identity, startup rollback, and exact return",
    )
    if subscribe.count("remove_exact_subscriber(") != 2:
        raise VerificationError("both clipboard-listener startup failures must roll back")
    if subscribe.count("drop(listener_lock);") != 2 or subscribe.count("drop(receiver);") != 2:
        raise VerificationError("both startup failures must release the listener lock before receiver drop")

    remove_exact = extract_braced_item(
        clipboard,
        "fn remove_exact_subscriber(",
        "generation-bound clipboard subscription removal",
    )
    require_order(
        remove_exact,
        (
            ".get(&identity.name)",
            "subscriber.generation == identity.generation",
            "if is_current",
            "subscribers.remove(&identity.name)",
        ),
        "exact-generation removal",
    )

    unsubscribe = extract_braced_item(
        clipboard, "fn unsubscribe_exact(identity: &SubscriptionIdentity)", "exact unsubscribe"
    )
    require_order(
        unsubscribe,
        (
            "remove_exact_subscriber(&mut sub_lock, identity)",
            "notify_terminal(CallbackTerminal::Stop)",
            "sub_lock.is_empty()",
            "listener_lock.handle.take()",
            "shutdown.signal();",
            "h.join().is_err()",
        ),
        "exact removal, stop publication, and last-owner join",
    )

    master = extract_braced_item(
        clipboard,
        "fn start_clipboard_master_thread(",
        "clipboard master thread finality",
    )
    require_order(
        master,
        (
            "if tx_start_res",
            "master.run()",
            "notify_subscribers_terminal(",
            '"Clipboard listener stopped with error: {}"',
            '"Clipboard listener stopped unexpectedly"',
        ),
        "startup observation and post-start master finality",
    )

    for test in (
        "clipboard_change_wakes_are_coalesced",
        "clipboard_terminal_error_supersedes_pending_change",
        "clipboard_receiver_retirement_closes_admission",
        "stale_clipboard_identity_cannot_remove_replacement",
    ):
        require(clipboard, test, f"{test} regression")

    worker = extract_braced_item(
        client, "struct ClientClipboardWorker", "viewer clipboard worker owner"
    )
    require_order(
        worker,
        (
            "stop_requested: Arc<AtomicBool>",
            "subscription: clipboard_listener::ClipboardSubscription",
            "thread: std::thread::JoinHandle<()>",
        ),
        "viewer stop, subscription, and thread ownership",
    )
    viewer_start = extract_braced_item(
        client,
        "fn start_client_clipboard_worker_locked(",
        "desktop viewer clipboard start",
    )
    require_order(
        viewer_start,
        (
            "clipboard_listener::subscribe(Self::CLIENT_CLIPBOARD_NAME.to_owned())",
            "Some(CallbackResult::Next)",
            "Some(CallbackResult::Stop)",
            "Some(CallbackResult::StopWithError(err))",
            "state.worker = Some(ClientClipboardWorker {",
            "subscription,",
            "thread,",
        ),
        "viewer exact subscription handoff",
    )
    retire = extract_braced_item(
        client,
        "fn retire_client_clipboard_worker_locked(",
        "viewer clipboard retirement",
    )
    require_order(
        retire,
        (
            "let worker = state.worker.take()?;",
            "worker.stop_requested.store(true, Ordering::Release);",
            "state.worker_transition = true;",
            "worker.subscription.close();",
            "Some(worker)",
        ),
        "viewer stop-before-exact-subscription close",
    )

    controlled_run = extract_braced_item(service, "fn run(sp: EmptyExtraFieldService)", "controlled clipboard service")
    require_order(
        controlled_run,
        (
            "let (_subscription, rx_cb_result) = clipboard_listener::subscribe(sp.name())?;",
            "while sp.ok()",
            "Some(CallbackResult::Next)",
            "Some(CallbackResult::StopWithError(err))",
            'bail!("Clipboard listener stopped with error: {}", err);',
        ),
        "controlled scope-owned subscription including error exit",
    )
    forbid(controlled_run, "clipboard_listener::unsubscribe", "manual name-only controlled cleanup")

    gate_command = "python3 scripts/verify-clipboard-listener-ownership.py --repo . --self-test"
    for key, needle, label in (
        ("verify", gate_command, "shared focused gate"),
        ("verify", "cargo test --lib --features linux-pkg-config,flutter clipboard_listener::tests:: --color never", "shared behavior gate"),
        ("apple", gate_command, "Apple/shared focused gate"),
        ("requirements", '<div class="req"><span class="id">R-S11hb</span>', "normative requirement"),
        ("requirements", "<tr><td>363</td>", "Appendix C row"),
        ("hardening", "### R-S11hb/R-S11e-240 — exact bounded native clipboard-listener ownership", "hardening ledger"),
        ("workspace", "def validate_clipboard_listener_ownership_contract(sources):", "independent workspace contract"),
        ("workspace", "validate_clipboard_listener_ownership_contract(sources)", "independent workspace dispatch"),
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
        raise VerificationError("independent clipboard-listener dispatch owner is absent")
    dispatches = [
        node
        for node in validate_sources_function.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "validate_clipboard_listener_ownership_contract"
    ]
    if len(dispatches) != 1:
        raise VerificationError("independent clipboard-listener dispatch must occur exactly once")

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
    ("clipboard", "change_pending: bool,", "change_pending: usize,", "one-bit readiness state"),
    ("clipboard", "terminal: Option<CallbackTerminal>,", "terminal: Vec<CallbackTerminal>,", "single terminal state"),
    ("clipboard", "ready: Condvar,", "ready: Mutex<()>,", "condition wake"),
    ("clipboard", "if !state.receiver_alive {", "if false && !state.receiver_alive {", "receiver admission finality"),
    ("clipboard", "state.change_pending = false;\n                state.terminal = Some(terminal);", "state.terminal = Some(terminal);", "terminal clears ordinary readiness"),
    ("clipboard", "if let Some(terminal) = state.terminal.take()", "if false && state.terminal.is_some()", "terminal-first receive"),
    ("clipboard", "next_generation.checked_add(1)", "next_generation.wrapping_add(1).into()", "checked generation"),
    ("clipboard", ".contains_key(&name)", ".contains_key(&format!(\"disabled-{name}\"))", "duplicate refusal"),
    ("clipboard", "subscriber.generation == identity.generation", "true", "exact-generation removal"),
    ("clipboard", "unsubscribe_exact(&identity);", "// exact receiver cleanup disabled", "receiver RAII cleanup"),
    ("clipboard", "impl Drop for ClipboardSubscription", "impl ClipboardSubscription", "subscription RAII cleanup"),
    ("clipboard", '"Clipboard listener stopped unexpectedly",', '"listener stopped without terminal publication",', "master stop terminal publication"),
    ("clipboard", "fn clipboard_change_wakes_are_coalesced", "fn clipboard_changes_may_accumulate", "coalescing regression"),
    ("clipboard", "fn clipboard_terminal_error_supersedes_pending_change", "fn clipboard_error_may_follow_change", "terminal priority regression"),
    ("clipboard", "fn clipboard_receiver_retirement_closes_admission", "fn clipboard_receiver_retirement_is_advisory", "receiver finality regression"),
    ("clipboard", "fn stale_clipboard_identity_cannot_remove_replacement", "fn stale_clipboard_identity_may_remove_replacement", "generation regression"),
    ("client", "subscription: clipboard_listener::ClipboardSubscription,", "subscription: (),", "viewer subscription owner"),
    ("client", "worker.subscription.close();", "// viewer subscription left active", "viewer exact retirement"),
    ("service", "let (_subscription, rx_cb_result) = clipboard_listener::subscribe(sp.name())?;", "let (_, rx_cb_result) = clipboard_listener::subscribe(sp.name())?;", "controlled RAII owner"),
    ("service", "let ctx = Some(ClipboardContext::new()", "let (tx_cb_result, rx_cb_result) = channel();\n    let ctx = Some(ClipboardContext::new()", "unbounded callback queue absence"),
    ("verify", "python3 scripts/verify-clipboard-listener-ownership.py --repo . --self-test", "true # clipboard-listener gate disabled", "shared gate"),
    ("verify", "cargo test --lib --features linux-pkg-config,flutter clipboard_listener::tests:: --color never", "true # clipboard-listener tests disabled", "behavior gate"),
    ("apple", "python3 scripts/verify-clipboard-listener-ownership.py --repo . --self-test", "true # clipboard-listener gate disabled", "Apple gate"),
    ("requirements", '<div class="req"><span class="id">R-S11hb</span>', '<div class="req"><span class="id">R-S11hb-disabled</span>', "normative requirement"),
    ("requirements", "<tr><td>363</td>", "<tr><td>363-disabled</td>", "Appendix disposition"),
    ("hardening", "### R-S11hb/R-S11e-240 — exact bounded native clipboard-listener ownership", "### R-S11hb-disabled/R-S11e-240 — exact bounded native clipboard-listener ownership", "hardening ledger"),
    ("workspace", "    validate_cm_egress_budget_contract(sources)\n    validate_clipboard_listener_ownership_contract(sources)\n    validate_clipboard_route_budget_contract(sources)", "    validate_cm_egress_budget_contract(sources)\n    validate_clipboard_listener_ownership_contract_disabled(sources)\n    validate_clipboard_route_budget_contract(sources)", "independent dispatch"),
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
        print(f"Clipboard-listener ownership verifier self-test passed ({len(MUTATIONS)} mutations)")
    else:
        print("Clipboard-listener ownership verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"Clipboard-listener ownership verifier failed: {error}")
        raise SystemExit(1)
