#!/usr/bin/env python3
"""Verify serialized, drainable controlled-side Dart status refresh ownership."""

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


def forbid_bare_call(source: str, call: str, label: str) -> None:
    if any(line.strip() == f"{call};" for line in source.splitlines()):
        raise VerificationError(f"forbidden detached {label} remains: {call!r}")


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
        "loop": "flutter/lib/models/server_status_refresh_loop.dart",
        "model": "flutter/lib/models/server_model.dart",
        "server_page": "flutter/lib/desktop/pages/server_page.dart",
        "test": "flutter/test/server_status_refresh_loop_test.dart",
        "dart_verify": "scripts/dart-verify.sh",
        "verify": "scripts/verify.sh",
        "apple": "scripts/apple-conform-check.sh",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "native_watch": "docs/NATIVE-CODEC-WATCH.md",
        "workspace": "scripts/verify-verifier-workspace.py",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def validate(sources: Dict[str, str]) -> None:
    loop = sources["loop"]
    model = sources["model"]
    constructor = extract_braced_item(
        model, "ServerModel(this.parent)", "process-owned ServerModel constructor"
    )

    for source, needle, label in (
        (loop, "Timer.periodic", "periodic refresh timer"),
        (loop, "StreamController", "refresh event stream"),
        (loop, "List<Future", "retained refresh backlog"),
        (model, "Timer.periodic", "ServerModel periodic async callback"),
        (constructor, "Future.delayed", "detached initial status refresh"),
    ):
        forbid(source, needle, label)

    owner = extract_braced_item(
        loop, "class ServerStatusRefreshLoop", "status refresh owner"
    )
    require_order(
        owner,
        (
            "final Duration _interval;",
            "final Future<void> Function() _refresh;",
            "final void Function(Object error, StackTrace stackTrace) _onError;",
            "Timer? _timer;",
            "Future<void>? _activeTurn;",
            "bool _started = false;",
            "bool _closed = false;",
        ),
        "single timer, one active turn, and terminal owner state",
    )

    start = extract_braced_item(
        loop,
        "void start({Future<bool> Function()? initialReady})",
        "single-start admission",
    )
    require_order(
        start,
        (
            "if (_started)",
            "throw StateError('server status refresh loop is already started')",
            "if (_closed)",
            "throw StateError('server status refresh loop is closed')",
            "_started = true;",
            "_arm(Duration.zero, initialReady);",
        ),
        "single process-owner start",
    )

    close = extract_braced_item(loop, "Future<void> close()", "refresh finality")
    require_order(
        close,
        (
            "_closed = true;",
            "_timer?.cancel();",
            "_timer = null;",
            "final activeTurn = _activeTurn;",
            "if (activeTurn != null)",
            "await activeTurn;",
        ),
        "cancel pending work and drain the active turn",
    )

    arm = extract_braced_item(loop, "void _arm(", "one-shot scheduling")
    require_order(
        arm,
        (
            "if (_closed) return;",
            "if (_timer != null || _activeTurn != null)",
            "throw StateError('server status refresh loop already owns scheduled work')",
            "_timer = Timer(delay, ()",
            "_timer = null;",
            "_beginTurn(initialReady);",
        ),
        "one exact one-shot timer",
    )

    begin = extract_braced_item(loop, "void _beginTurn(", "turn ownership")
    require_order(
        begin,
        (
            "final turn = _runTurn(initialReady);",
            "_activeTurn = turn;",
            "unawaited(turn.whenComplete(() ",
            "if (identical(_activeTurn, turn))",
            "_activeTurn = null;",
            "if (!_closed)",
            "_arm(_interval, null);",
        ),
        "completion-before-next-interval ordering",
    )

    run = extract_braced_item(loop, "Future<void> _runTurn(", "complete refresh turn")
    require_order(
        run,
        (
            "if (initialReady == null || await initialReady())",
            "await _refresh();",
            "catch (error, stackTrace)",
            "_onError(error, stackTrace);",
        ),
        "one-shot readiness and visible refresh failure",
    )

    for needle, label in (
        ("import 'server_status_refresh_loop.dart';", "refresh owner import"),
        (
            "late final ServerStatusRefreshLoop _statusRefreshLoop;",
            "process-owned refresh field",
        ),
        ("interval: const Duration(milliseconds: 500)", "preserved refresh interval"),
        ("refresh: _refreshStatus", "complete-turn callback"),
        ("Server status refresh failed: $error", "visible refresh failure"),
        (
            "_statusRefreshLoop.start(initialReady: () => bind.optionSynced());",
            "single initial-readiness start",
        ),
    ):
        require(model, needle, label)

    refresh = extract_braced_item(
        model, "Future<void> _refreshStatus()", "ServerModel complete refresh turn"
    )
    require_order(
        refresh,
        (
            "await bind.cmCheckClientsLength(length: _clients.length)",
            "await updateClientState(res);",
            "await hideCmWindow();",
            "await showCmWindow();",
            "await updatePasswordModel();",
        ),
        "CM reconciliation before password reconciliation",
    )
    for call, label in (
        ("updateClientState(res)", "client-state refresh"),
        ("hideCmWindow()", "CM hide reconciliation"),
        ("showCmWindow()", "CM show reconciliation"),
        ("updatePasswordModel()", "password status refresh"),
    ):
        forbid_bare_call(refresh, call, label)

    update_clients = extract_braced_item(
        model,
        "Future<void> updateClientState([String? json])",
        "client-state reconciliation",
    )
    require_order(
        update_clients,
        (
            "final res = json ?? await bind.cmGetClientsState();",
            "clientsJson = jsonDecode(res);",
            "await hideCmWindow();",
            "await showCmWindow();",
        ),
        "supplied snapshot reuse and complete window reconciliation",
    )
    require(
        model,
        "Future<void> updatePasswordModel() async",
        "typed password refresh completion",
    )
    require(
        sources["server_page"],
        "unawaited(gFFI.serverModel.updateClientState());",
        "explicit UI-event asynchronous refresh",
    )
    start_service = extract_braced_item(
        model, "Future<void> startService()", "controlled service start"
    )
    require_order(
        start_service,
        (
            'await parent.target?.invokeMethod("init_service");',
            "} catch (e)",
            "_isStart = false;",
            "return;",
            "await updateClientState();",
            "} catch (error, stackTrace)",
            "Initial client-state refresh failed: $error",
            "if (isAndroid)",
        ),
        "service success and client observation remain distinct",
    )

    for name in (
        "never overlaps a slow refresh and waits a full interval",
        "initial readiness is checked once before periodic refresh",
        "a failed turn is visible and does not wedge later turns",
        "close drains the active turn and prevents rearming",
        "refuses duplicate start and restart after close",
    ):
        require(sources["test"], name, f"{name} regression")

    gate = "python3 scripts/verify-server-status-refresh-loop.py --repo . --self-test"
    for key, needle, label in (
        (
            "dart_verify",
            "flutter test --no-pub test/server_status_refresh_loop_test.dart",
            "Dart behavior gate",
        ),
        ("verify", gate, "shared focused gate"),
        ("apple", gate, "Apple/shared focused gate"),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11he</span>',
            "normative requirement",
        ),
        ("requirements", "<tr><td>366</td>", "Appendix C row"),
        (
            "hardening",
            "### R-S11he/R-S11e-243 — serialized controlled-side status refresh ownership",
            "hardening ledger",
        ),
        (
            "workspace",
            "def validate_server_status_refresh_loop_contract(sources):",
            "independent workspace contract",
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
        raise VerificationError("independent status-refresh source map is absent")
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
        raise VerificationError("independent status-refresh source map is not singular")
    source_map_keys = [
        key.value
        for key in source_maps[0].keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    ]
    for key in (
        "server_status_refresh_loop_dart",
        "server_status_refresh_loop_test",
        "server_status_refresh_loop_verifier",
    ):
        if source_map_keys.count(key) != 1:
            raise VerificationError(f"independent status-refresh binding is absent: {key}")

    validate_sources = next(
        (
            node
            for node in workspace_module.body
            if isinstance(node, ast.FunctionDef) and node.name == "validate_sources"
        ),
        None,
    )
    if validate_sources is None:
        raise VerificationError("independent status-refresh dispatch owner is absent")
    dispatches = [
        node
        for node in validate_sources.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "validate_server_status_refresh_loop_contract"
    ]
    if len(dispatches) != 1:
        raise VerificationError(
            "independent status-refresh dispatch must occur exactly once"
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
    ("loop", "Timer? _timer;", "List<Timer> _timer = [];", "single timer, one active turn, and terminal owner state"),
    ("loop", "Future<void>? _activeTurn;", "List<Future<void>> _activeTurn = [];", "retained refresh backlog"),
    ("loop", "if (_started) {", "if (false) {", "single process-owner start"),
    ("loop", "if (_closed) {", "if (false) {", "single process-owner start"),
    ("loop", "_arm(Duration.zero, initialReady);", "_beginTurn(initialReady);", "single process-owner start"),
    ("loop", "_timer?.cancel();", "// timer cancellation disabled", "cancel pending work and drain the active turn"),
    ("loop", "await activeTurn;", "unawaited(activeTurn);", "cancel pending work and drain the active turn"),
    ("loop", "if (_timer != null || _activeTurn != null) {", "if (false) {", "one exact one-shot timer"),
    ("loop", "_timer = Timer(delay, () {", "_timer = Timer.periodic(delay, (_) {", "periodic refresh timer"),
    ("loop", "_activeTurn = turn;", "// active turn ownership disabled", "completion-before-next-interval ordering"),
    ("loop", "if (identical(_activeTurn, turn)) {", "if (false) {", "completion-before-next-interval ordering"),
    ("loop", "if (!_closed) {", "if (true) {", "completion-before-next-interval ordering"),
    ("loop", "_arm(_interval, null);", "_arm(Duration.zero, null);", "completion-before-next-interval ordering"),
    ("loop", "if (initialReady == null || await initialReady()) {", "if (true) {", "one-shot readiness and visible refresh failure"),
    ("loop", "await _refresh();", "unawaited(_refresh());", "one-shot readiness and visible refresh failure"),
    ("loop", "_onError(error, stackTrace);", "// refresh failure hidden", "one-shot readiness and visible refresh failure"),
    ("model", "late final ServerStatusRefreshLoop _statusRefreshLoop;", "late final Timer _statusRefreshLoop;", "process-owned refresh field"),
    ("model", "interval: const Duration(milliseconds: 500),", "interval: Duration.zero,", "preserved refresh interval"),
    ("model", "refresh: _refreshStatus,", "refresh: updatePasswordModel,", "complete-turn callback"),
    ("model", "_statusRefreshLoop.start(initialReady: () => bind.optionSynced());", "_statusRefreshLoop.start();", "single initial-readiness start"),
    ("model", "await updateClientState(res);", "updateClientState(res);", "CM reconciliation before password reconciliation"),
    ("model", "} else if (_clients.isEmpty) {\n        // R-S11gic: the server owns this CM generation across sessions. Keep its UI hidden while\n        // idle; closing the window here exits the process and defeats exact reuse.\n        await hideCmWindow();", "} else if (_clients.isEmpty) {\n        // R-S11gic: the server owns this CM generation across sessions. Keep its UI hidden while\n        // idle; closing the window here exits the process and defeats exact reuse.\n        hideCmWindow();", "CM reconciliation before password reconciliation"),
    ("model", "        await showCmWindow();\n      }\n    }\n\n    await updatePasswordModel();", "        showCmWindow();\n      }\n    }\n\n    await updatePasswordModel();", "CM reconciliation before password reconciliation"),
    ("model", "await updatePasswordModel();", "updatePasswordModel();", "CM reconciliation before password reconciliation"),
    ("model", "final res = json ?? await bind.cmGetClientsState();", "final res = await bind.cmGetClientsState();", "supplied snapshot reuse and complete window reconciliation"),
    ("server_page", "unawaited(gFFI.serverModel.updateClientState());", "gFFI.serverModel.updateClientState();", "explicit UI-event asynchronous refresh"),
    ("model", "    try {\n      await updateClientState();\n    } catch (error, stackTrace) {", "    unawaited(updateClientState());\n    try {\n    } catch (error, stackTrace) {", "service success and client observation remain distinct"),
    ("model", "Initial client-state refresh failed: $error", "Initial client-state refresh ignored: $error", "service success and client observation remain distinct"),
    ("test", "never overlaps a slow refresh and waits a full interval", "allows overlapping slow refreshes", "never overlaps a slow refresh and waits a full interval regression"),
    ("test", "initial readiness is checked once before periodic refresh", "initial readiness is never checked", "initial readiness is checked once before periodic refresh regression"),
    ("test", "a failed turn is visible and does not wedge later turns", "a failed turn wedges later turns", "a failed turn is visible and does not wedge later turns regression"),
    ("test", "close drains the active turn and prevents rearming", "close abandons the active turn", "close drains the active turn and prevents rearming regression"),
    ("test", "refuses duplicate start and restart after close", "allows duplicate start and restart", "refuses duplicate start and restart after close regression"),
    ("dart_verify", "flutter test --no-pub test/server_status_refresh_loop_test.dart", "true # server status refresh test disabled", "Dart behavior gate"),
    ("verify", "python3 scripts/verify-server-status-refresh-loop.py --repo . --self-test", "true # status refresh gate disabled", "shared focused gate"),
    ("apple", "python3 scripts/verify-server-status-refresh-loop.py --repo . --self-test", "true # status refresh gate disabled", "Apple/shared focused gate"),
    ("requirements", '<div class="req"><span class="id">R-S11he</span>', '<div class="req"><span class="id">R-S11he-disabled</span>', "normative requirement"),
    ("requirements", "<tr><td>366</td>", "<tr><td>366-disabled</td>", "Appendix C row"),
    ("hardening", "### R-S11he/R-S11e-243 — serialized controlled-side status refresh ownership", "### R-S11he-disabled/R-S11e-243 — serialized controlled-side status refresh ownership", "hardening ledger"),
    ("workspace", "    validate_server_status_refresh_loop_contract(sources)\n", "    validate_server_status_refresh_loop_contract_disabled(sources)\n", "independent status-refresh dispatch must occur exactly once"),
)


def run_self_test(sources: Dict[str, str]) -> None:
    for key, old, new, expected in MUTATIONS:
        if sources[key].count(old) != 1:
            raise VerificationError(
                f"mutation fixture is not singular for {key}: {old!r}"
            )
        mutated = dict(sources)
        mutated[key] = sources[key].replace(old, new, 1)
        try:
            validate(mutated)
        except VerificationError as error:
            if expected not in str(error):
                raise VerificationError(
                    f"mutation {key}:{old!r} failed for the wrong reason: {error}"
                ) from error
        else:
            raise VerificationError(f"mutation unexpectedly passed: {key}:{old!r}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    sources = load_sources(args.repo.resolve())
    validate(sources)
    if args.self_test:
        run_self_test(sources)
        print(f"server status refresh loop: {len(MUTATIONS)} mutations rejected")
    else:
        print("server status refresh loop: verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
