#!/usr/bin/env python3
"""Verify lossless whiteboard IPC/event-loop lifecycle ownership."""

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
        "lifecycle": "src/whiteboard/event_lifecycle.rs",
        "module": "src/whiteboard/mod.rs",
        "server": "src/whiteboard/server.rs",
        "linux": "src/whiteboard/linux.rs",
        "windows": "src/whiteboard/windows.rs",
        "macos": "src/whiteboard/macos.rs",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "verify": "scripts/verify.sh",
        "apple": "scripts/apple-conform-check.sh",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def validate(sources: Dict[str, str]) -> None:
    lifecycle_source = sources["lifecycle"]
    server = sources["server"]
    platforms = lifecycle_source + server + sources["linux"] + sources["windows"] + sources["macos"]
    for needle, label in (
        ("unbounded_channel", "unbounded whiteboard lifecycle channel"),
        ("UnboundedReceiver", "unbounded whiteboard lifecycle receiver"),
        ("EVENT_PROXY", "direct whiteboard event-proxy global"),
        ("std::thread::spawn(", "detached whiteboard IPC thread"),
    ):
        forbid(platforms, needle, label)

    lifecycle = extract_braced_item(
        lifecycle_source,
        "pub(crate) struct WhiteboardEventLifecycle<Proxy>",
        "whiteboard event lifecycle state",
    )
    require_order(
        lifecycle,
        ("proxy: Option<Proxy>", "ipc_terminated: bool"),
        "closed proxy/terminal lifecycle state",
    )

    install = extract_braced_item(
        lifecycle_source,
        "pub(crate) fn install(&mut self, proxy: Proxy) -> Option<Proxy>",
        "level-triggered proxy installation",
    )
    require_order(
        install,
        (
            "if self.ipc_terminated",
            "Some(proxy)",
            "self.proxy = Some(proxy);",
            "None",
        ),
        "termination-before-proxy latch delivery",
    )

    terminate = extract_braced_item(
        lifecycle_source,
        "pub(crate) fn terminate(&mut self) -> Option<Proxy>",
        "exact-once IPC termination",
    )
    require_order(
        terminate,
        (
            "if self.ipc_terminated",
            "return None;",
            "self.ipc_terminated = true;",
            "self.proxy.take()",
        ),
        "proxy-before-termination exact take",
    )

    clear_proxy = extract_braced_item(
        lifecycle_source,
        "pub(crate) fn clear_proxy(&mut self)",
        "event-loop proxy retirement",
    )
    require(clear_proxy, "self.proxy = None;", "proxy-only event-loop retirement")
    forbid(clear_proxy, "ipc_terminated = false", "terminal-latch reset on proxy retirement")

    install_proxy = extract_braced_item(
        server,
        "pub(super) fn install_whiteboard_event_proxy(",
        "serialized platform proxy installation",
    )
    require_order(
        install_proxy,
        (
            "EVENT_LIFECYCLE.write().unwrap().install(proxy)",
            "if let Some(proxy) = terminal_proxy",
            "proxy.send_event((0, CustomEvent::Exit))",
            "WhiteboardEventProxyGuard",
        ),
        "latched terminal delivery at proxy installation",
    )

    terminate_generation = extract_braced_item(
        server,
        "fn terminate_whiteboard_ipc_generation()",
        "serialized IPC terminal publication",
    )
    require_order(
        terminate_generation,
        (
            "EVENT_LIFECYCLE.write().unwrap().terminate()",
            "if let Some(proxy) = terminal_proxy",
            "proxy.send_event((0, CustomEvent::Exit))",
        ),
        "exact installed-proxy terminal delivery",
    )

    proxy_guard = extract_braced_item(
        server,
        "impl Drop for WhiteboardEventProxyGuard",
        "platform proxy retirement guard",
    )
    require(
        proxy_guard,
        "EVENT_LIFECYCLE.write().unwrap().clear_proxy();",
        "serialized proxy-only retirement",
    )
    terminal_guard = extract_braced_item(
        server,
        "impl Drop for WhiteboardIpcTerminalGuard",
        "IPC terminal finalizer",
    )
    require(
        terminal_guard,
        "terminate_whiteboard_ipc_generation();",
        "single terminal publication owner",
    )

    worker_state = extract_braced_item(
        server,
        "pub(super) struct WhiteboardIpcWorker",
        "retained whiteboard IPC worker",
    )
    require_order(
        worker_state,
        (
            "stop: oneshot::Sender<()>",
            "thread: std::thread::JoinHandle<()>",
        ),
        "one-shot stop and exact thread ownership",
    )
    spawn = extract_braced_item(
        server,
        "pub(super) fn spawn() -> ResultType<Self>",
        "fallible named whiteboard worker spawn",
    )
    require_order(
        spawn,
        (
            "let (stop, stop_requested) = oneshot::channel();",
            "std::thread::Builder::new()",
            '.name("rustdesk-whiteboard-ipc".to_owned())',
            ".spawn(move || run_whiteboard_ipc_worker(stop_requested))",
            "failed to spawn whiteboard IPC worker",
            "Ok(Self { stop, thread })",
        ),
        "fallible named worker construction",
    )
    stop_and_join = extract_braced_item(
        server,
        "pub(super) fn stop_and_join(self) -> ResultType<()>",
        "whiteboard worker terminal join",
    )
    require_order(
        stop_and_join,
        (
            "self.stop.send(()).is_err()",
            "whiteboard IPC worker had already terminated before stop",
            "self.thread",
            ".join()",
            "whiteboard IPC worker panicked",
        ),
        "one-shot stop followed by exact join",
    )

    shared_run = extract_braced_item(server, "pub fn run()", "Windows/macOS helper owner")
    require_order(
        shared_run,
        (
            "WhiteboardIpcWorker::spawn()",
            "super::create_event_loop()",
            "worker.stop_and_join()",
        ),
        "Windows/macOS retained worker lifecycle",
    )

    worker_entry = extract_braced_item(
        server,
        "fn run_whiteboard_ipc_worker(",
        "whiteboard IPC worker entrypoint",
    )
    require(
        worker_entry,
        "fn run_whiteboard_ipc_worker(stop_requested: oneshot::Receiver<()>) {\n"
        "    let _terminal = WhiteboardIpcTerminalGuard;\n"
        "    start_ipc(stop_requested);",
        "first-action terminal finalizer",
    )
    start_ipc = extract_braced_item(server, "async fn start_ipc(", "whiteboard IPC runtime")
    require_order(
        start_ipc,
        (
            "ipc::whiteboard_endpoint_postfix_from_env()",
            "WHITEBOARD_LAUNCH_PARENT_ENV",
            "new_listener(&postfix).await",
            "_ = &mut stop_requested",
            "handle_new_stream(stream, &mut stop_requested).await",
        ),
        "startup-wide finalizer and one-shot cancellation ownership",
    )

    handler = extract_braced_item(
        server,
        "async fn handle_new_stream(",
        "single owned whiteboard stream handler",
    )
    require_order(
        handler,
        (
            "stop_requested.try_recv()",
            "TryRecvError::Closed",
            "TryRecvError::Empty",
            "next_whiteboard_command_timeout(ipc::WHITEBOARD_IPC_IO_TIMEOUT_MS)",
        ),
        "bounded stream cancellation wake",
    )
    forbid(handler, "CustomEvent::Exit", "stream-handler-only terminal publication")

    linux_run = extract_braced_item(sources["linux"], "pub fn run()", "Linux helper owner")
    require_order(
        linux_run,
        (
            "install_whiteboard_event_proxy(event_loop_proxy)",
            "WhiteboardIpcWorker::spawn()",
            "WhiteboardApplication::new(&event_loop)",
            "event_loop.run_app(&mut app)",
            "worker.stop_and_join()",
        ),
        "Linux event-loop and worker ownership",
    )
    if linux_run.count("worker.stop_and_join()") != 2:
        raise VerificationError("Linux must join after both application construction failure and event-loop return")

    for key in ("windows", "macos"):
        event_loop = extract_braced_item(
            sources[key],
            "pub(super) fn create_event_loop()",
            f"{key} whiteboard event loop",
        )
        require(
            event_loop,
            "install_whiteboard_event_proxy(proxy)",
            f"{key} serialized proxy lifecycle",
        )

    for test in (
        "r_s11hn_whiteboard_ipc_termination_before_proxy_is_delivered_once",
        "r_s11hn_whiteboard_ipc_termination_takes_exact_installed_proxy_once",
        "r_s11hn_whiteboard_event_loop_retirement_preserves_terminal_latch",
    ):
        require(lifecycle_source, test, f"{test} regression")

    require(sources["module"], "mod event_lifecycle;", "production lifecycle module wiring")
    require(
        server,
        "event_lifecycle::WhiteboardEventLifecycle",
        "server use of the independently executable lifecycle module",
    )

    focused_gate = "python3 scripts/verify-whiteboard-ipc-lifecycle.py --repo . --self-test"
    fast_behavior_gate = "rustc --edition=2021 --crate-name whiteboard_event_lifecycle --test"
    behavior_gate = "cargo test --lib --features linux-pkg-config,flutter r_s11hn_ --color never"
    for key, needle, label in (
        ("verify", focused_gate, "shared focused gate"),
        ("verify", fast_behavior_gate, "shared fast behavior gate"),
        ("verify", behavior_gate, "shared behavior gate"),
        ("apple", focused_gate, "Apple focused gate"),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11hn</span>',
            "normative lifecycle requirement",
        ),
        ("requirements", "<tr><td>374</td>", "Appendix C lifecycle disposition"),
        (
            "hardening",
            "### R-S11hn/R-S11e-251 — lossless whiteboard IPC/event-loop lifecycle ownership",
            "hardening lifecycle ledger",
        ),
    ):
        require(sources[key], needle, label)

    requirements_digest = hashlib.sha256(
        sources["requirements"].encode("utf-8")
    ).hexdigest()
    require(
        sources["hardening"],
        f"{requirements_digest}  requirements.html",
        "exact hardening requirements digest",
    )


Mutation = Tuple[str, str, str, str]

MUTATIONS: Tuple[Mutation, ...] = (
    ("lifecycle", "ipc_terminated: bool", "ipc_termination_was_advisory: bool", "terminal latch state"),
    ("lifecycle", "if self.ipc_terminated {\n            Some(proxy)", "if false {\n            Some(proxy)", "termination-before-proxy delivery"),
    ("lifecycle", "self.proxy = Some(proxy);", "self.proxy = None;", "proxy installation ownership"),
    ("lifecycle", "self.ipc_terminated = true;", "self.ipc_terminated = false;", "terminal latch publication"),
    ("lifecycle", "self.proxy.take()", "None", "installed proxy exact take"),
    ("lifecycle", "pub(crate) fn clear_proxy(&mut self) {\n        self.proxy = None;", "pub(crate) fn clear_proxy(&mut self) {\n        self.ipc_terminated = false;", "proxy-only retirement"),
    ("server", "EVENT_LIFECYCLE.write().unwrap().install(proxy)", "WhiteboardEventLifecycle::default().install(proxy)", "serialized proxy install"),
    ("server", "EVENT_LIFECYCLE.write().unwrap().terminate()", "WhiteboardEventLifecycle::default().terminate()", "serialized terminal publication"),
    ("server", "proxy.send_event((0, CustomEvent::Exit))", "proxy.send_event((0, CustomEvent::Clear))", "latched exit delivery"),
    ("server", "EVENT_LIFECYCLE.write().unwrap().clear_proxy();", "// proxy retirement removed", "guarded proxy retirement"),
    ("server", "terminate_whiteboard_ipc_generation();", "// terminal finalization removed", "terminal guard"),
    ("server", "let (stop, stop_requested) = oneshot::channel();", "let (stop, stop_requested) = tokio::sync::mpsc::unbounded_channel();", "one-shot stop edge"),
    ("server", "std::thread::Builder::new()", "std::thread::spawn(", "fallible retained thread construction"),
    ("server", '.name("rustdesk-whiteboard-ipc".to_owned())', '.name("anonymous".to_owned())', "named worker"),
    ("server", ".spawn(move || run_whiteboard_ipc_worker(stop_requested))", ".spawn(move || start_ipc(stop_requested))", "terminal-guarded worker entrypoint"),
    ("server", "self.stop.send(()).is_err()", "false", "stop publication outcome"),
    ("server", ".join()\n            .map_err", ".is_finished()\n            .then_some(())\n            .ok_or_else", "exact thread join"),
    ("server", "let _terminal = WhiteboardIpcTerminalGuard;", "let _terminal_finalizer_was_removed = ();", "startup-wide terminal finalizer"),
    ("server", "fn run_whiteboard_ipc_worker(stop_requested: oneshot::Receiver<()>) {\n    let _terminal = WhiteboardIpcTerminalGuard;\n    start_ipc(stop_requested);", "fn run_whiteboard_ipc_worker(stop_requested: oneshot::Receiver<()>) {\n    let _work_before_terminal = ipc::whiteboard_endpoint_postfix_from_env();\n    let _terminal = WhiteboardIpcTerminalGuard;\n    start_ipc(stop_requested);", "first-action terminal finalizer"),
    ("server", "stop_requested.try_recv()", "Ok(())", "stream cancellation observation"),
    ("linux", "install_whiteboard_event_proxy(event_loop_proxy)", "event_loop_proxy", "Linux proxy lifecycle"),
    ("linux", "WhiteboardIpcWorker::spawn()", "Err(anyhow::anyhow!(\"disabled\"))", "Linux worker construction"),
    ("linux", "event_loop.run_app(&mut app)", "Ok(())", "Linux event-loop ownership"),
    ("linux", "worker.stop_and_join()", "Ok(())", "Linux application-failure join"),
    ("linux", "    if let Err(err) = worker.stop_and_join() {\n        log::error!(\"Failed to finish whiteboard IPC worker: {err}\");\n    }\n}", "    if let Err(err) = Ok(()) {\n        log::error!(\"Failed to finish whiteboard IPC worker: {err}\");\n    }\n}", "Linux event-loop-return join"),
    ("windows", "install_whiteboard_event_proxy(proxy)", "proxy", "Windows proxy lifecycle"),
    ("macos", "install_whiteboard_event_proxy(proxy)", "proxy", "macOS proxy lifecycle"),
    ("lifecycle", "fn r_s11hn_whiteboard_ipc_termination_before_proxy_is_delivered_once", "fn whiteboard_ipc_termination_before_proxy_may_be_lost", "termination-before-proxy regression"),
    ("lifecycle", "fn r_s11hn_whiteboard_ipc_termination_takes_exact_installed_proxy_once", "fn whiteboard_ipc_termination_may_repeat", "proxy-before-termination regression"),
    ("lifecycle", "fn r_s11hn_whiteboard_event_loop_retirement_preserves_terminal_latch", "fn whiteboard_event_loop_retirement_resets_terminal_latch", "retirement-latch regression"),
    ("module", "mod event_lifecycle;", "// lifecycle module removed", "production lifecycle module wiring"),
    ("server", "event_lifecycle::WhiteboardEventLifecycle", "WhiteboardEventLifecycle", "server lifecycle module use"),
    ("verify", "python3 scripts/verify-whiteboard-ipc-lifecycle.py --repo . --self-test", "true # whiteboard lifecycle gate disabled", "shared focused gate"),
    ("verify", "rustc --edition=2021 --crate-name whiteboard_event_lifecycle --test", "true # fast lifecycle behavior gate disabled", "shared fast behavior gate"),
    ("verify", "cargo test --lib --features linux-pkg-config,flutter r_s11hn_ --color never", "true # whiteboard lifecycle tests disabled", "shared behavior gate"),
    ("apple", "python3 scripts/verify-whiteboard-ipc-lifecycle.py --repo . --self-test", "true # whiteboard lifecycle gate disabled", "Apple focused gate"),
    ("requirements", '<div class="req"><span class="id">R-S11hn</span>', '<div class="req"><span class="id">R-S11hn-disabled</span>', "normative lifecycle requirement"),
    ("requirements", "<tr><td>374</td>", "<tr><td>374-disabled</td>", "Appendix C lifecycle disposition"),
    ("hardening", "### R-S11hn/R-S11e-251 — lossless whiteboard IPC/event-loop lifecycle ownership", "### R-S11hn-disabled/R-S11e-251 — lossless whiteboard IPC/event-loop lifecycle ownership", "hardening lifecycle ledger"),
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
            "Whiteboard IPC lifecycle verifier self-test passed "
            f"({len(MUTATIONS)} mutations)"
        )
    else:
        print("Whiteboard IPC lifecycle verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"Whiteboard IPC lifecycle verifier failed: {error}")
        raise SystemExit(1)
