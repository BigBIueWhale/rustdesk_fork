#!/usr/bin/env python3
"""R-S11as/R-S11e-59 desktop IPC readiness and retained-owner verifier."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, Iterable, Tuple


class VerificationError(RuntimeError):
    pass


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}")


def absent(source: str, needle: str, label: str) -> None:
    if needle in source:
        raise VerificationError(f"stale/forbidden {label}")


def ordered(source: str, needles: Iterable[str], label: str) -> None:
    position = -1
    for needle in needles:
        next_position = source.find(needle, position + 1)
        if next_position < 0:
            raise VerificationError(f"missing or out-of-order {label}: {needle}")
        position = next_position


def region(source: str, start: str, end: str, label: str) -> str:
    begin = source.find(start)
    if begin < 0:
        raise VerificationError(f"missing {label} start")
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise VerificationError(f"missing {label} end")
    return source[begin:finish]


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "server": "src/server.rs",
        "direct": "src/direct_service.rs",
        "ipc": "src/ipc.rs",
        "common": "src/common.rs",
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
    server = sources["server"]
    direct = sources["direct"]
    ipc = sources["ipc"]

    desktop_entry = region(
        server,
        '#[cfg(not(any(target_os = "android", target_os = "ios")))]\n'
        "#[tokio::main]\npub async fn start_server(is_server: bool)",
        '\n#[cfg(any(target_os = "windows", target_os = "macos"))]\n'
        '#[tokio::main(flavor = "current_thread")]',
        "desktop server entry",
    )
    controlled_entry = region(
        desktop_entry,
        "    if is_server {",
        "\n    } else {",
        "controlled desktop server branch",
    )
    ordered(
        controlled_entry,
        (
            "crate::direct_service::assert_startup_invariants()",
            "std::process::exit(1);",
            "install_controlled_server_shutdown_signals()",
            "std::process::exit(1);",
            "crate::direct_service::start_direct_only(shutdown_signals).await;",
        ),
        "invariants/signals before controlled service entry",
    )
    for needle, label in (
        ("std::thread::spawn", "detached desktop IPC spawn"),
        ('crate::ipc::start("")', "ordinary detached IPC runtime"),
        ("start_windows_service_main_ipc", "independent Windows IPC runtime"),
        ("set_server_running", "optimistic server-running marker"),
    ):
        absent(controlled_entry, needle, label)

    for needle, label in (
        ("SERVER_RUNNING", "unused server-running state"),
        ("set_server_running", "unused server-running writer"),
        ("is_server_running", "unused server-running reader"),
    ):
        absent(sources["common"], needle, label)

    worker = region(
        ipc,
        "pub(crate) struct DesktopIpcWorker",
        '\n#[cfg(target_os = "windows")]\nconst WINDOWS_SERVICE_CREDENTIAL_TRANSACTION_BUDGET',
        "desktop IPC worker owner",
    )
    for needle, label in (
        ("readiness: oneshot::Receiver<Result<(), String>>", "readiness receiver"),
        ("completion: oneshot::Receiver<Result<(), String>>", "completion receiver"),
        ("thread: Option<std::thread::JoinHandle<()>>", "native thread handle"),
        ("std::thread::Builder::new()", "fallible native worker creation"),
        ('.name("rustdesk-desktop-ipc".to_owned())', "named native worker"),
        ("run_desktop_ipc(readiness_tx)", "single desktop IPC runtime entry"),
        ("completion_tx.send(outcome)", "worker completion report"),
        ("tokio::task::spawn_blocking(move || thread.join())", "runtime-safe exact join"),
    ):
        require(worker, needle, label)
    absent(worker, "std::thread::spawn", "infallible worker creation")
    absent(worker, "thread.detach", "native thread detachment")

    runtime = region(
        ipc,
        "async fn run_desktop_ipc(",
        '\n#[cfg(target_os = "linux")]\n#[tokio::main(flavor = "current_thread")]',
        "desktop IPC runtime",
    )
    require(
        ipc[ipc.rfind("#[tokio::main", 0, ipc.find("async fn run_desktop_ipc(")) :],
        '#[tokio::main(flavor = "current_thread")]\nasync fn run_desktop_ipc(',
        "desktop current-thread runtime annotation",
    )
    ordered(
        runtime,
        (
            "Config::ensure_loaded();",
            "prepare_main_ipc().await",
            "prepare_windows_service_main_ipc().await",
            "readiness.send(Ok(()))",
            "tokio::join!(",
            "run_main_ipc(main)",
            "run_windows_service_main_ipc(service_main)",
        ),
        "all desktop IPC prepared before one readiness report",
    )
    if runtime.count("readiness.send(Err(err.to_string()))") != 2:
        raise VerificationError("both desktop IPC preparation failures are not reported")
    for needle, label in (
        ("std::thread", "nested/detached runtime thread"),
        ("Runtime::", "manual nested Tokio runtime"),
        ("process::exit", "worker-owned process exit"),
        ("finish_graceful_shutdown", "worker-owned process finalizer"),
    ):
        absent(runtime, needle, label)

    main_prepare = region(
        ipc,
        "async fn prepare_main_ipc()",
        '\n#[cfg(not(any(target_os = "android", target_os = "ios")))]\nasync fn run_main_ipc',
        "ordinary main IPC preparation",
    )
    ordered(
        main_prepare,
        (
            'new_listener("").await?;',
            "new_listener(password::USER_PASSWORD_IPC_POSTFIX).await?;",
            "start_windows_user_owned_password_listener(",
            "LocalIpcListenerGuard::activate(&MAIN_IPC_LISTENER_STATE",
            "Ok(PreparedMainIpc {",
        ),
        "main/password listeners and guard before prepared state",
    )
    main_run = region(
        ipc,
        "async fn run_main_ipc(",
        '\n#[cfg(any(target_os = "linux", target_os = "macos"))]\nfn sensitive_main_ipc_authority',
        "ordinary main IPC run/drain",
    )
    ordered(
        main_run,
        (
            "while let Some(result) = transactions.join_next().await",
            "password_mutations().drain().await;",
            "password_mutations().clear_after_transactions_drain();",
            "drop(listener_guard);",
            "match listener_error",
            "Some(err) => Err(hbb_common::anyhow::anyhow!(err))",
            "None => Ok(())",
        ),
        "main IPC drain/guard release before returned outcome",
    )

    windows_prepare = region(
        ipc,
        "async fn prepare_windows_service_main_ipc()",
        '\n#[cfg(target_os = "windows")]\nasync fn run_windows_service_main_ipc',
        "Windows service-main IPC preparation",
    )
    ordered(
        windows_prepare,
        (
            "is_service_owned_server_process()",
            "crate::platform::is_root()",
            "new_listener(WINDOWS_SERVICE_CREDENTIAL_IPC_POSTFIX).await?;",
            "new_listener(WINDOWS_SERVICE_MAIN_CONTROL_IPC_POSTFIX).await?;",
            "LocalIpcListenerGuard::activate(",
            "Ok(PreparedWindowsServiceMainIpc {",
        ),
        "Windows service-main proof/listeners/guard before prepared state",
    )
    windows_run = region(
        ipc,
        "async fn run_windows_service_main_ipc(",
        '\n#[cfg(target_os = "windows")]\nasync fn handle_windows_service_credential_transaction',
        "Windows service-main IPC run/drain",
    )
    ordered(
        windows_run,
        (
            "while let Some(result) = transactions.join_next().await",
            "drop(listener_guard);",
            "match listener_error",
            "Some(err) => Err(hbb_common::anyhow::anyhow!(err))",
            "None => Ok(())",
        ),
        "Windows service-main drain/guard release before returned outcome",
    )
    for run_source, label in ((main_run, "main IPC"), (windows_run, "Windows service-main IPC")):
        for needle in ("finish_graceful_shutdown", "process::exit", "#[tokio::main", "std::thread::spawn"):
            absent(run_source, needle, f"{label} terminal/detached authority")
    absent(ipc, "pub async fn start_windows_service_main_ipc", "independent Windows IPC runtime entry")

    owner = region(
        direct,
        "async fn own_controlled_server_lifecycle(",
        "\n/// Android/iOS receive the exact mobile listener-generation input.",
        "desktop lifecycle owner",
    )
    ordered(
        owner,
        (
            "ipc_worker.startup_receivers();",
            "_ = shutdown.cancelled() => ControlledServerStartupEvent::ShutdownRequested",
            "signal = signals.recv() => ControlledServerStartupEvent::Signal(signal)",
            "readiness = ipc_readiness",
            "outcome = ipc_completion",
            "ControlledServerStartupEvent::DesktopIpcReady(Ok(()))",
            "let mut direct_listener = server.map(|server|",
            "tokio::spawn(async move",
            "direct_server(server, None).await;",
            "_ = shutdown.cancelled() => ControlledServerLifecycleEvent::ShutdownRequested",
            "signal = signals.recv() => ControlledServerLifecycleEvent::Signal(signal)",
            "outcome = wait_for_direct_listener_task(&mut direct_listener)",
            "outcome = ipc_worker.wait_for_completion()",
            "finish_owned_controlled_server_lifecycle(",
        ),
        "signal-aware readiness then public/IPC lifecycle selection",
    )
    for needle, label in (
        ("Controlled-server IPC readiness failed", "readiness failure classification"),
        ("Controlled-server IPC worker returned before readiness", "pre-ready completion classification"),
        ("Controlled-server direct listener completed without a shutdown request", "public completion classification"),
        ("Controlled-server IPC worker completed without a shutdown request", "IPC completion classification"),
    ):
        require(owner, needle, label)

    finish = region(
        direct,
        "async fn finish_owned_controlled_server_lifecycle(",
        "\n/// Own the complete desktop controlled-side lifetime.",
        "desktop lifecycle completion helper",
    )
    ordered(
        finish,
        (
            "Some(task) => Some(task.await)",
            "worker.wait_for_completion().await",
            "worker.join().await",
            "crate::server::finish_graceful_shutdown().await",
        ),
        "exact public/IPC join before sole finalizer",
    )
    if direct.count("crate::server::finish_graceful_shutdown().await") != 1:
        raise VerificationError("desktop finalizer does not have exactly one source caller")
    absent(ipc, "finish_graceful_shutdown().await", "IPC finalizer caller")

    finalizer = region(
        server,
        "pub(crate) async fn finish_graceful_shutdown() -> ! {",
        "\n#[cfg(test)]",
        "sole process finalizer",
    )
    ordered(
        finalizer,
        (
            "AUTHED_CONNS.lock().unwrap().len()",
            "crate::server::input_service::fix_key_down_timeout_at_exit();",
            "SHUTDOWN_FAILURE_LATCHED.load(Ordering::Acquire)",
            "std::process::exit(exit_code);",
        ),
        "authenticated drain and fatal status before exit",
    )
    for source, needle, label in (
        (server, "SHUTDOWN_FINALIZER_STARTED", "multi-finalizer election"),
        (server, "pending::<std::convert::Infallible>", "finalizer follower wait"),
        (server, "wait_for_local_ipc_shutdown", "polling local-IPC barrier call"),
        (ipc, "wait_for_local_ipc_shutdown", "polling local-IPC barrier"),
        (ipc, "LOCAL_IPC_DRAIN_CHANGED", "polling local-IPC notification"),
        (server, "begin_graceful_shutdown", "returning compatibility finalizer"),
    ):
        absent(source, needle, label)

    failure_helper = "crate::server::request_graceful_shutdown_after_listener_failure();"
    messages = (
        "main password IPC listener ended unexpectedly",
        "main IPC listener ended unexpectedly",
        "protected service credential IPC listener ended unexpectedly",
        "protected macOS service credential IPC listener ended unexpectedly",
        "protected service password IPC listener ended unexpectedly",
        "protected _service IPC listener ended unexpectedly",
        "Windows service-main control IPC listener ended unexpectedly",
        "Windows service credential IPC listener ended unexpectedly",
    )
    if ipc.count(failure_helper) != len(messages):
        raise VerificationError("exact eight IPC listener fatal producers are absent")
    for message in messages:
        anchor = f'listener_error = Some("{message}".to_owned());'
        require(ipc, anchor, f"listener failure producer: {message}")
        branch = ipc[ipc.index(anchor) : ipc.index("break;", ipc.index(anchor))]
        require(branch, failure_helper, f"failure-before-cancellation: {message}")

    protected = region(
        ipc,
        "async fn run_service_ipc(postfix: &str, listeners: PreparedServiceIpc)",
        '\n#[cfg(target_os = "linux")]\nasync fn handle_sensitive_linux_service_ipc_transaction',
        "protected Unix IPC worker",
    )
    absent(protected, "finish_graceful_shutdown", "protected service finalizer authority")

    start = region(
        direct,
        "pub async fn start_direct_only(",
        '\n#[cfg_attr(not(target_os = "android"), allow(unused_variables))]',
        "shared direct-only entry",
    )
    ordered(
        start,
        (
            "crate::ipc::spawn_desktop_ipc_worker()",
            "own_controlled_server_lifecycle(server, ipc_worker, shutdown_signals).await;",
        ),
        "desktop worker transfer to lifecycle owner",
    )
    require(server, "start_direct_only(Some(generation)).await;", "Android generation transfer")
    if start.count(
        "if android_listener_lifecycle_snapshot(my_generation.get()).is_none() {"
    ) != 2:
        raise VerificationError("both Android exact active-generation teardown checks are absent")
    absent(
        start,
        "android_generation_current(my_generation)",
        "obsolete Android generation teardown",
    )
    require(start, "assert_startup_invariants()", "mobile shared-process invariant refusal")

    for source, needle, label in (
        (sources["requirements"], '<span class="id">R-S11as</span>', "R-S11as requirement"),
        (sources["requirements"], "Desktop local IPC readiness, completion, and native-thread lifetime have one retained owner", "R-S11as title"),
        (sources["requirements"], "<tr><td>167</td>", "Appendix C #167"),
        (sources["requirements"], "Desktop authority-bearing IPC started before mandatory invariants", "Appendix C #167 disposition"),
        (sources["hardening"], "R-S11e-59 — desktop local-IPC readiness and retained native-worker ownership", "R-S11e-59 ledger"),
        (sources["verify"], "desktop local-IPC readiness and retained native-worker ownership (R-S11as/R-S11e-59)", "shared source gate"),
        (sources["apple"], "desktop local-IPC readiness and retained native-worker ownership (R-S11as/R-S11e-59)", "Apple source gate"),
    ):
        require(source, needle, label)


Mutation = Tuple[str, str, str, str]


MUTATIONS: Tuple[Mutation, ...] = (
    ("server", "crate::direct_service::assert_startup_invariants()", "crate::direct_service::assert_startup_invariants_after_admission()", "pre-admission invariants"),
    ("server", "crate::direct_service::start_direct_only(shutdown_signals).await;", "std::thread::spawn(|| crate::ipc::start(\"\"));\n        crate::direct_service::start_direct_only(shutdown_signals).await;", "detached IPC spawn absence"),
    ("ipc", "let thread = std::thread::Builder::new()", "let thread = std::thread::spawn(move || {});\n    //", "fallible worker creation"),
    ("ipc", '.name("rustdesk-desktop-ipc".to_owned())', '.name("ipc".to_owned())', "named worker"),
    ("ipc", '#[tokio::main(flavor = "current_thread")]\nasync fn run_desktop_ipc(', "#[tokio::main]\nasync fn run_desktop_ipc(", "single current-thread runtime"),
    ("ipc", "readiness.send(Ok(()))", "readiness.send(Err(\"not ready\".to_owned()))", "successful all-listener readiness"),
    ("ipc", "completion_tx.send(outcome)", "drop(outcome)", "worker completion report"),
    ("ipc", "tokio::task::spawn_blocking(move || thread.join())", "thread.join()", "runtime-safe native join"),
    ("ipc", "run_windows_service_main_ipc(service_main)", "std::future::pending::<ResultType<()>>()", "Windows service-main co-ownership"),
    ("ipc", "    password_mutations().clear_after_transactions_drain();\n    drop(listener_guard);\n    match listener_error", "    password_mutations().clear_after_transactions_drain();\n    match listener_error", "main guard before return"),
    ("ipc", "async fn run_main_ipc(listeners: PreparedMainIpc) -> ResultType<()> {", "async fn run_main_ipc(listeners: PreparedMainIpc) -> ResultType<()> {\n    crate::server::finish_graceful_shutdown().await;", "main IPC finalizer absence"),
    ("direct", "readiness = ipc_readiness", "readiness = std::future::pending()", "readiness observation"),
    ("direct", "outcome = ipc_worker.wait_for_completion()", "outcome = std::future::pending()", "IPC completion observation"),
    ("direct", "worker.join().await", "Ok(())", "exact native join"),
    ("direct", "crate::server::finish_graceful_shutdown().await", "crate::server::begin_graceful_shutdown().await", "sole finalizer call"),
    ("server", "static SHUTDOWN_FAILURE_LATCHED", "static SHUTDOWN_FINALIZER_STARTED: AtomicBool = AtomicBool::new(false);\nstatic SHUTDOWN_FAILURE_LATCHED", "multi-finalizer election absence"),
    ("server", "crate::server::input_service::fix_key_down_timeout_at_exit();", "crate::ipc::wait_for_local_ipc_shutdown().await;\n    crate::server::input_service::fix_key_down_timeout_at_exit();", "polling IPC barrier absence"),
    ("common", "static ref IS_SERVER:", "static ref SERVER_RUNNING: bool = false;\n    static ref IS_SERVER:", "server-running state absence"),
    ("ipc", 'listener_error = Some("protected service credential IPC listener ended unexpectedly".to_owned());\n                        crate::server::request_graceful_shutdown_after_listener_failure();', 'listener_error = Some("protected service credential IPC listener ended unexpectedly".to_owned());', "Linux service credential listener fatal latch"),
    ("ipc", 'listener_error = Some("protected macOS service credential IPC listener ended unexpectedly".to_owned());\n                        crate::server::request_graceful_shutdown_after_listener_failure();', 'listener_error = Some("protected macOS service credential IPC listener ended unexpectedly".to_owned());', "macOS service credential listener fatal latch"),
    ("requirements", '<span class="id">R-S11as</span>', '<span class="id">R-S11az</span>', "R-S11as requirement"),
    ("requirements", "<tr><td>167</td>", "<tr><td>9167</td>", "Appendix C #167"),
    ("hardening", "R-S11e-59 — desktop local-IPC readiness and retained native-worker ownership", "R-S11e-59 — detached desktop IPC", "R-S11e-59 ledger"),
    ("server", "start_direct_only(Some(generation)).await;", "start_direct_only(None).await;", "Android generation boundary"),
    ("direct", "_ = sleep(1.) => {\n                        if android_listener_lifecycle_snapshot(my_generation.get()).is_none() {", "_ = sleep(1.) => {\n                        if android_listener_lifecycle_snapshot(0).is_none() {", "Android exact active-generation teardown"),
    ("ipc", "    protected_service_ipc_result(listener_error)\n}", "    crate::server::finish_graceful_shutdown().await;\n    protected_service_ipc_result(listener_error)\n}", "protected service finalizer absence"),
)


def run_mutations(sources: Dict[str, str]) -> None:
    for key, old, new, label in MUTATIONS:
        if sources[key].count(old) != 1:
            raise VerificationError(f"mutation anchor is not unique for {label}")
        mutated = dict(sources)
        mutated[key] = sources[key].replace(old, new, 1)
        try:
            validate(mutated)
        except VerificationError:
            continue
        raise VerificationError(f"mutation was not rejected: {label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    sources = load_sources(args.repo.resolve())
    validate(sources)
    if args.self_test:
        run_mutations(sources)
    print(
        "desktop IPC lifecycle semantic validation: OK"
        + (f" ({len(MUTATIONS)} mutations)" if args.self_test else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
