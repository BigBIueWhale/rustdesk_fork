#!/usr/bin/env python3
"""Verify bounded exact-generation process-global Dart event dispatch."""

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
    if signature.startswith("class "):
        open_brace = source.find("{", start + len(signature))
    else:
        body_marker = source.find(") {", start)
        open_brace = body_marker + 2 if body_marker >= 0 else -1
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
        "dispatcher": "flutter/lib/models/global_event_dispatcher.dart",
        "common": "flutter/lib/common.dart",
        "frame_queue": "flutter/lib/models/latest_frame_queue.dart",
        "native": "flutter/lib/models/native_model.dart",
        "web": "flutter/lib/models/web_model.dart",
        "model": "flutter/lib/models/model.dart",
        "test": "flutter/test/global_event_dispatcher_test.dart",
        "frame_test": "flutter/test/latest_frame_queue_test.dart",
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
    dispatcher = sources["dispatcher"]
    owner = extract_braced_item(
        dispatcher, "class GlobalEventDispatcher", "global event owner"
    )
    for needle, label in (
        ("Timer", "event-dispatch timer"),
        ("StreamController", "secondary event queue"),
        ("Future.sync", "per-event future chain"),
        ("List<Future", "retained future backlog"),
    ):
        forbid(owner, needle, label)

    require_order(
        owner,
        (
            "this.maxPending = 64,",
            "this.maxMessageCodeUnits = 16 * 1024 * 1024,",
            "this.maxRetainedBytes = 64 * 1024 * 1024,",
            "this.maxRegisteredHandlers = 256,",
            "static const int _entryOverheadBytes = 256;",
            "static const int _handlerReferenceBytes = 16;",
            "final Set<String> _synchronousFallbackEvents;",
            "final Queue<_GlobalEventEntry> _pending",
            "_GlobalEventEntry? _running;",
            "_FallbackBinding? _fallback;",
            "Future<void>? _drainFuture;",
            "int _fallbackGeneration = 0;",
            "int _registeredHandlerCount = 0;",
            "int _retainedBytes = 0;",
        ),
        "one bounded serial process owner",
    )
    require(
        dispatcher,
        "typedef GlobalEventHandler = Future<void>? Function(",
        "unambiguous nullable-future global event result",
    )
    require(
        sources["common"],
        "typedef StreamEventHandler = Future<void>? Function(Map<String, dynamic>);",
        "unambiguous nullable-future session event result",
    )

    register = extract_braced_item(
        dispatcher, "bool registerHandler(", "registered handler admission"
    )
    require_order(
        register,
        (
            "if (existing != null)",
            "if (!replace)",
            "existing.retired = true;",
            "_retirePendingRegisteredHandler(existing);",
            "if (_registeredHandlerCount >= maxRegisteredHandlers)",
            "_registeredHandlerCount += 1;",
        ),
        "bounded exact registered-handler generations",
    )
    unregister = extract_braced_item(
        dispatcher, "void unregisterHandler(", "registered handler retirement"
    )
    require_order(
        unregister,
        (
            "final binding = eventHandlers?.remove(handlerName);",
            "binding.retired = true;",
            "_registeredHandlerCount -= 1;",
            "_retirePendingRegisteredHandler(binding);",
            "if (eventHandlers!.isEmpty)",
            "_handlers.remove(eventName);",
        ),
        "exact registered-handler retirement",
    )

    replace = extract_braced_item(
        dispatcher, "int replaceFallback(", "fallback replacement"
    )
    require_order(
        replace,
        (
            "final previous = _fallback;",
            "if (previous != null)",
            "_retireFallback(previous);",
            "++_fallbackGeneration",
            "_fallback = binding;",
            "return binding.generation;",
        ),
        "retire-before-publish fallback replacement",
    )
    retire = extract_braced_item(
        dispatcher, "bool retireFallback(", "exact fallback retirement"
    )
    require_order(
        retire,
        (
            "binding.generation != generation",
            "return false;",
            "_fallback = null;",
            "_retireFallback(binding);",
            "return true;",
        ),
        "generation-capability fallback retirement",
    )

    dispatch = extract_braced_item(dispatcher, "bool dispatch(", "event admission")
    require_order(
        dispatch,
        (
            "final fallback = allowFallback ? _currentFallback() : null;",
            "if (message.length > maxMessageCodeUnits)",
            "final decoded = jsonDecode(message);",
            "if (decoded is! Map<String, dynamic>)",
            "if (allowRegistered)",
            "eventHandlers.values",
            ".toList(growable: true);",
            "final owner = ownsRegisteredRoute ? null : fallback;",
            "_synchronousFallbackEvents.contains(eventName)",
            "final completion = owner.handler(event);",
            "if (completion != null)",
            "StateError('synchronous global event handoff returned a future')",
            "return true;",
            "message.length * 2",
            "handlerCount * _handlerReferenceBytes;",
            "_pending.length >= maxPending",
            "weight > maxRetainedBytes",
            "_retainedBytes > maxRetainedBytes - weight",
            "_retainedBytes += weight;",
            "if (_running == null)",
            "_running = entry;",
            "_startDrain();",
            "_pending.addLast(entry);",
        ),
        "synchronous exact-owner count-and-byte admission",
    )

    frame_queue = sources["frame_queue"]
    observed = extract_braced_item(
        frame_queue, "bool submitObserved(", "future-free latest-state handoff"
    )
    require_order(
        observed,
        (
            "final entry = _LatestFrameEntry.observed(frame, present, onError);",
            "final admission = _admit(expectedOwner, key, entry);",
            "if (admission == _LatestFrameAdmission.retired)",
            "if (admission == _LatestFrameAdmission.exhausted)",
            "return true;",
        ),
        "future-free exact-owner latest-state handoff",
    )
    frame_admit = extract_braced_item(
        frame_queue, "_LatestFrameAdmission _admit(", "shared latest-state admission"
    )
    require_order(
        frame_admit,
        (
            "if (_retired || expectedOwner != owner)",
            "if (_lanes.length >= maxKeys)",
            "_retireAll();",
            "if (lane.running == null)",
            "unawaited(_drain(key, lane));",
            "lane.pending?.complete(LatestFrameDisposition.superseded);",
            "lane.pending = entry;",
            "return _LatestFrameAdmission.accepted;",
        ),
        "one shared running-plus-latest admission owner",
    )
    require(
        frame_queue,
        "_LatestFrameEntry.observed(this.frame, this.present, this._onError)\n"
        "      : done = null;",
        "future-free latest-state entry completion",
    )

    start = extract_braced_item(dispatcher, "void _startDrain()", "sole drain start")
    require_order(
        start,
        (
            "if (_drainFuture != null)",
            "final drain = Future<void>.microtask(_drain);",
            "_drainFuture = drain;",
            "if (identical(_drainFuture, drain))",
            "_drainFuture = null;",
        ),
        "one retained drain future",
    )
    drain = extract_braced_item(dispatcher, "Future<void> _drain()", "serial drain")
    require_order(
        drain,
        (
            "final entry = _running;",
            "if (!_entryRetired(entry))",
            "final decoded = jsonDecode(entry.message);",
            "if (!binding.retired)",
            "await binding.handler(decoded);",
            "if (fallback != null && !fallback.retired)",
            "await fallback.handler(decoded);",
            "catch (error, stackTrace)",
            "_failFallback(fallback, error, stackTrace);",
            "finally",
            "_release(entry);",
            "_running = _pending.isEmpty ? null : _pending.removeFirst();",
        ),
        "FIFO nonoverlap and visible failure",
    )
    release = extract_braced_item(
        dispatcher, "void _release(", "exact retained-byte release"
    )
    require_order(
        release,
        (
            "if (entry.released)",
            "entry.released = true;",
            "_retainedBytes -= entry.weight;",
        ),
        "release-once retained accounting",
    )
    fail = extract_braced_item(
        dispatcher, "void _failFallback(", "fallback failure finality"
    )
    require_order(
        fail,
        (
            "if (binding.retired)",
            "if (identical(_fallback, binding))",
            "_fallback = null;",
            "_retireFallback(binding);",
            "binding.onFailure(error, stackTrace);",
        ),
        "exact fallback failure finality",
    )

    native = sources["native"]
    for needle, label in (
        ("final _eventHandlers", "native mutable handler map"),
        ("StreamEventHandler? _eventCallback", "late-selected native callback"),
        ("Future<bool> tryHandle", "async native route probe"),
    ):
        forbid(native, needle, label)
    native_listen = extract_braced_item(
        native, "void _startListenEvent(", "native global stream listener"
    )
    forbid(
        native_listen,
        "() async {",
        "per-message detached native closure",
    )
    require_order(
        native_listen,
        (
            "sink.listen(",
            "_eventDispatcher.dispatch,",
            "onError:",
            "_eventDispatcher.failCurrent(error, stackTrace)",
            "onDone:",
            "StateError('global event stream ended')",
        ),
        "native serial routing and terminal visibility",
    )
    for needle, label in (
        ("_eventDispatcher.registerHandler", "native registered route"),
        ("_eventDispatcher.unregisterHandler", "native registered retirement"),
        ("_eventDispatcher.replaceFallback", "native fallback replacement"),
        ("_eventDispatcher.retireFallback", "native fallback retirement"),
    ):
        require(native, needle, label)

    web = sources["web"]
    for needle, label in (
        ("final _eventHandlers", "web mutable handler map"),
        ("Future<bool> tryHandle", "async web route probe"),
        ("fun(event);", "discarded web handler completion"),
    ):
        forbid(web, needle, label)
    require(
        web,
        "_eventDispatcher.dispatch(message, allowFallback: false);",
        "web registered-only route",
    )
    require(
        web,
        "_eventDispatcher.dispatch(message, allowRegistered: false);",
        "web fallback-only route",
    )
    require_order(
        web,
        (
            "synchronousFallbackEvents: const {",
            "'cursor_position',",
            "'cursor_data',",
            "'cursor_id',",
        ),
        "web high-rate synchronous handoff classification",
    )
    for needle, label in (
        ("_eventDispatcher.registerHandler", "web registered route"),
        ("_eventDispatcher.unregisterHandler", "web registered retirement"),
        ("_eventDispatcher.replaceFallback", "web fallback replacement"),
        ("_eventDispatcher.retireFallback", "web fallback retirement"),
    ):
        require(web, needle, label)

    model = sources["model"]
    listener = extract_braced_item(
        model, "StreamEventHandler startEventListener(", "session event listener"
    )
    forbid(
        listener,
        "return (evt) async {",
        "always-async high-rate session event callback",
    )
    require_order(
        listener,
        (
            "return (evt) {",
            "if (name == 'cursor_position' && isWeb)",
            "ffi.submitWebCursorPosition(",
            "return null;",
            "ffi.submitWebCursorShape(",
            "return null;",
            "return _submitOrderedSessionTopologyEvent(",
            "return operation();",
        ),
        "synchronous web latest-state handoff before awaited control work",
    )
    cursor_position = extract_braced_item(
        model,
        "bool submitWebCursorPosition(",
        "future-free web cursor-position admission",
    )
    require_order(
        cursor_position,
        (
            "expectedOwner != _sessionOwner",
            "_webCursorPositions.submitObserved(",
            "expectedOwner, 0, _WebCursorPosition(x, y)",
            "onError: (error, stackTrace)",
            "_reportSessionStreamFailure(expectedSessionId, peerId,",
        ),
        "bounded observed web cursor-position handoff",
    )
    cursor_shape = extract_braced_item(
        model,
        "bool submitWebCursorShape(",
        "future-free web cursor-shape admission",
    )
    require_order(
        cursor_shape,
        (
            "expectedOwner != _sessionOwner",
            "_webCursorShapes.submitObserved(",
            "onError: (error, stackTrace)",
            "_reportSessionStreamFailure(expectedSessionId, peerId,",
        ),
        "bounded observed web cursor-shape handoff",
    )
    update = extract_braced_item(
        model, "updateEventListener(SessionID", "session fallback installation"
    )
    require_order(
        update,
        (
            "final ffi = parent.target;",
            "final generation = platformFFI.setEventCallback(",
            "startEventListener(sessionId, peerId),",
            "onFailure: (error, stackTrace)",
            "ffi._reportSessionStreamFailure(sessionId, peerId,",
            "_eventListenerGeneration = generation;",
            "_eventListenerSessionId = sessionId;",
        ),
        "exact session fallback generation and visible failure",
    )
    retirement = extract_braced_item(
        model, "void retireEventListener(", "session fallback retirement"
    )
    require_order(
        retirement,
        (
            "if (_eventListenerSessionId != expectedSessionId)",
            "final generation = _eventListenerGeneration;",
            "platformFFI.clearEventCallback(generation);",
            "_eventListenerGeneration = null;",
            "_eventListenerSessionId = null;",
        ),
        "exact session teardown capability",
    )
    retire_owner = extract_braced_item(
        model, "void _retireSessionOwner(", "complete session owner retirement"
    )
    require(
        retire_owner,
        "ffiModel.retireEventListener(retiringSessionId);",
        "fallback retirement on every exact session terminal edge",
    )

    for name in (
        "runs admitted events in FIFO order without handler overlap",
        "replacement retires old pending work without migrating its event",
        "active old work settles before replacement work and never overlaps",
        "fallback overflow fails once, retires pending work, and recovers",
        "byte and message bounds fail the exact fallback visibly",
        "registered handler inventory is finite and reusable after retirement",
        "registered handlers are captured and retired by exact registration",
        "registered-only routing never falls through to session fallback",
        "configured latest-state events hand off synchronously outside FIFO",
        "configured synchronous handoff fails closed on an async callback",
        "handler and malformed-input failures remain visible and drainable",
    ):
        require(sources["test"], name, f"{name} regression")
    for name in (
        "observed submissions retain only running and latest without futures",
        "observed failure is visible and retires its exact queue",
    ):
        require(sources["frame_test"], name, f"{name} regression")
    require(
        sources["requirements"],
        'it <span class="kw">MUST NOT</span> retain the raw JSON in a generic control FIFO or allocate one completion future per cursor event',
        "R-S11gu future-free web cursor handoff",
    )
    require(
        sources["requirements"],
        "Their raw strings may not enter the 64-entry FIFO",
        "R-S11hf web cursor FIFO exclusion",
    )

    gate = "python3 scripts/verify-global-event-dispatcher.py --repo . --self-test"
    for key, needle, label in (
        (
            "dart_verify",
            "flutter test --no-pub test/global_event_dispatcher_test.dart",
            "Dart behavior gate",
        ),
        ("verify", gate, "shared focused gate"),
        ("apple", gate, "Apple/shared focused gate"),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11hf</span>',
            "normative requirement",
        ),
        ("requirements", "<tr><td>367</td>", "Appendix C row"),
        (
            "hardening",
            "### R-S11hf/R-S11e-244 — bounded exact-generation global event dispatch",
            "hardening ledger",
        ),
        (
            "workspace",
            "def validate_global_event_dispatcher_contract(sources):",
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
        raise VerificationError("independent global-event source map is absent")
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
        raise VerificationError("independent global-event source map is not singular")
    source_map_keys = [
        key.value
        for key in source_maps[0].keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    ]
    for key in (
        "common_dart",
        "latest_frame_queue_dart",
        "latest_frame_queue_test",
        "global_event_dispatcher_dart",
        "native_model_dart",
        "web_model_dart",
        "global_event_dispatcher_test",
        "global_event_dispatcher_verifier",
    ):
        if source_map_keys.count(key) != 1:
            raise VerificationError(f"independent global-event binding is absent: {key}")

    validate_sources = next(
        (
            node
            for node in workspace_module.body
            if isinstance(node, ast.FunctionDef) and node.name == "validate_sources"
        ),
        None,
    )
    if validate_sources is None:
        raise VerificationError("independent global-event dispatch owner is absent")
    dispatches = [
        node
        for node in validate_sources.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "validate_global_event_dispatcher_contract"
    ]
    if len(dispatches) != 1:
        raise VerificationError(
            "independent global-event dispatch must occur exactly once"
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
    ("dispatcher", "this.maxPending = 64,", "this.maxPending = 6400,", "one bounded serial process owner"),
    ("dispatcher", "this.maxMessageCodeUnits = 16 * 1024 * 1024,", "this.maxMessageCodeUnits = 160 * 1024 * 1024,", "one bounded serial process owner"),
    ("dispatcher", "this.maxRetainedBytes = 64 * 1024 * 1024,", "this.maxRetainedBytes = 640 * 1024 * 1024,", "one bounded serial process owner"),
    ("dispatcher", "this.maxRegisteredHandlers = 256,", "this.maxRegisteredHandlers = 2560,", "one bounded serial process owner"),
    ("dispatcher", "typedef GlobalEventHandler = Future<void>? Function(", "typedef GlobalEventHandler = FutureOr<void> Function(", "unambiguous nullable-future global event result"),
    ("common", "typedef StreamEventHandler = Future<void>? Function(Map<String, dynamic>);", "typedef StreamEventHandler = FutureOr<void> Function(Map<String, dynamic>);", "unambiguous nullable-future session event result"),
    ("dispatcher", "existing.retired = true;", "// old registered owner retained", "bounded exact registered-handler generations"),
    ("dispatcher", "_retirePendingRegisteredHandler(existing);", "// pending old registered work retained", "bounded exact registered-handler generations"),
    ("dispatcher", "binding.retired = true;\n    _registeredHandlerCount -= 1;", "// registered binding remains live\n    _registeredHandlerCount -= 1;", "exact registered-handler retirement"),
    ("dispatcher", "_retirePendingRegisteredHandler(binding);", "// pending registered work retained", "exact registered-handler retirement"),
    ("dispatcher", "_retireFallback(previous);", "// previous fallback retained", "retire-before-publish fallback replacement"),
    ("dispatcher", "binding.generation != generation", "false", "generation-capability fallback retirement"),
    ("dispatcher", "final fallback = allowFallback ? _currentFallback() : null;", "final fallback = _currentFallback();", "synchronous exact-owner count-and-byte admission"),
    ("dispatcher", "if (message.length > maxMessageCodeUnits)", "if (false)", "synchronous exact-owner count-and-byte admission"),
    ("dispatcher", "_synchronousFallbackEvents.contains(eventName)", "false", "synchronous exact-owner count-and-byte admission"),
    ("dispatcher", "if (completion != null)", "if (false)", "synchronous exact-owner count-and-byte admission"),
    ("dispatcher", "message.length * 2", "message.length", "synchronous exact-owner count-and-byte admission"),
    ("dispatcher", "_pending.length >= maxPending", "false", "synchronous exact-owner count-and-byte admission"),
    ("dispatcher", "_retainedBytes > maxRetainedBytes - weight", "false", "synchronous exact-owner count-and-byte admission"),
    ("dispatcher", "_retainedBytes += weight;", "// retained bytes not acquired", "synchronous exact-owner count-and-byte admission"),
    ("dispatcher", "final drain = Future<void>.microtask(_drain);", "final drain = _drain();", "one retained drain future"),
    ("dispatcher", "_drainFuture = drain;", "// drain future not retained", "one retained drain future"),
    ("dispatcher", "await binding.handler(decoded);", "binding.handler(decoded);", "FIFO nonoverlap and visible failure"),
    ("dispatcher", "await fallback.handler(decoded);", "fallback.handler(decoded);", "FIFO nonoverlap and visible failure"),
    ("dispatcher", "      } finally {\n        _release(entry);", "      } finally {\n        // running entry bytes retained", "FIFO nonoverlap and visible failure"),
    ("dispatcher", "entry.released = true;", "entry.released = false;", "release-once retained accounting"),
    ("dispatcher", "_retainedBytes -= entry.weight;", "_retainedBytes += entry.weight;", "release-once retained accounting"),
    ("dispatcher", "binding.onFailure(error, stackTrace);", "// fallback failure hidden", "exact fallback failure finality"),
    ("frame_queue", "bool submitObserved(", "bool submitObservedDisabled(", "future-free latest-state handoff"),
    ("frame_queue", "_LatestFrameEntry.observed(this.frame, this.present, this._onError)\n      : done = null;", "_LatestFrameEntry.observed(this.frame, this.present, this._onError)\n      : done = Completer<LatestFrameDisposition>();", "future-free latest-state entry completion"),
    ("native", "_eventDispatcher.dispatch,", "(message) { _eventDispatcher.dispatch(message); },", "native serial routing and terminal visibility"),
    ("native", "_eventDispatcher.failCurrent(error, stackTrace)", "debugPrint('$error')", "native serial routing and terminal visibility"),
    ("web", "_eventDispatcher.dispatch(message, allowFallback: false);", "_eventDispatcher.dispatch(message);", "web registered-only route"),
    ("web", "_eventDispatcher.dispatch(message, allowRegistered: false);", "_eventDispatcher.dispatch(message);", "web fallback-only route"),
    ("web", "      'cursor_position',", "      'cursor_position_disabled',", "web high-rate synchronous handoff classification"),
    ("model", "    return (evt) {", "    return (evt) async {", "always-async high-rate session event callback"),
    ("model", "_webCursorPositions.submitObserved(", "_webCursorPositions.submit(", "bounded observed web cursor-position handoff"),
    ("model", "_webCursorShapes.submitObserved(", "_webCursorShapes.submit(", "bounded observed web cursor-shape handoff"),
    ("model", "_eventListenerGeneration = generation;", "_eventListenerGeneration = null;", "exact session fallback generation and visible failure"),
    ("model", "platformFFI.clearEventCallback(generation);", "// exact callback not cleared", "exact session teardown capability"),
    ("model", "ffiModel.retireEventListener(retiringSessionId);", "// fallback owner not retired", "fallback retirement on every exact session terminal edge"),
    ("test", "replacement retires old pending work without migrating its event", "replacement migrates old pending work", "replacement retires old pending work without migrating its event regression"),
    ("test", "registered handler inventory is finite and reusable after retirement", "registered handler inventory is unbounded", "registered handler inventory is finite and reusable after retirement regression"),
    ("test", "configured latest-state events hand off synchronously outside FIFO", "configured latest-state events enter the FIFO", "configured latest-state events hand off synchronously outside FIFO regression"),
    ("test", "configured synchronous handoff fails closed on an async callback", "configured synchronous handoff accepts an async callback", "configured synchronous handoff fails closed on an async callback regression"),
    ("frame_test", "observed submissions retain only running and latest without futures", "observed submissions retain detached futures", "observed submissions retain only running and latest without futures regression"),
    ("frame_test", "observed failure is visible and retires its exact queue", "observed failure is hidden", "observed failure is visible and retires its exact queue regression"),
    ("requirements", 'it <span class="kw">MUST NOT</span> retain the raw JSON in a generic control FIFO or allocate one completion future per cursor event', "it may retain raw JSON or one completion future per cursor event", "R-S11gu future-free web cursor handoff"),
    ("requirements", "Their raw strings may not enter the 64-entry FIFO", "Their raw strings may enter the 64-entry FIFO", "R-S11hf web cursor FIFO exclusion"),
    ("dart_verify", "flutter test --no-pub test/global_event_dispatcher_test.dart", "true # global event dispatcher test disabled", "Dart behavior gate"),
    ("verify", "python3 scripts/verify-global-event-dispatcher.py --repo . --self-test", "true # global event gate disabled", "shared focused gate"),
    ("apple", "python3 scripts/verify-global-event-dispatcher.py --repo . --self-test", "true # global event gate disabled", "Apple/shared focused gate"),
    ("requirements", '<div class="req"><span class="id">R-S11hf</span>', '<div class="req"><span class="id">R-S11hf-disabled</span>', "normative requirement"),
    ("requirements", "<tr><td>367</td>", "<tr><td>367-disabled</td>", "Appendix C row"),
    ("hardening", "### R-S11hf/R-S11e-244 — bounded exact-generation global event dispatch", "### R-S11hf-disabled/R-S11e-244 — bounded exact-generation global event dispatch", "hardening ledger"),
    ("workspace", "    validate_global_event_dispatcher_contract(sources)\n", "    validate_global_event_dispatcher_contract_disabled(sources)\n", "independent global-event dispatch must occur exactly once"),
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
        print(f"global event dispatcher: {len(MUTATIONS)} mutations rejected")
    else:
        print("global event dispatcher: verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
