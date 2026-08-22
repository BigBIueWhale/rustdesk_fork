#!/usr/bin/env python3
"""Verify bounded exact-session Flutter file-confirm event ownership."""

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


def require_count(source: str, needle: str, count: int, label: str) -> None:
    actual = source.count(needle)
    if actual != count:
        raise VerificationError(
            f"{label}: expected {count} occurrence(s) of {needle!r}, found {actual}"
        )


def extract_braced_item(source: str, signature: str, label: str) -> str:
    start = source.find(signature)
    if start < 0:
        raise VerificationError(f"missing {label}")
    search_from = start + len(signature)
    if signature.rstrip().endswith("("):
        parameter_depth = 1
        for offset in range(search_from, len(source)):
            character = source[offset]
            if character == "(":
                parameter_depth += 1
            elif character == ")":
                parameter_depth -= 1
                if parameter_depth == 0:
                    search_from = offset + 1
                    break
        else:
            raise VerificationError(f"unterminated parameters for {label}")
    open_brace = source.find("{", search_from)
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
        "event_loop": "flutter/lib/utils/event_loop.dart",
        "file_model": "flutter/lib/models/file_model.dart",
        "model": "flutter/lib/models/model.dart",
        "test": "flutter/test/file_dialog_event_loop_test.dart",
        "native_handler": "src/flutter.rs",
        "native_io": "src/client/io_loop.rs",
        "dart_verify": "scripts/dart-verify.sh",
        "android_verify": "scripts/verify-android-voice-call-ownership.py",
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
    event_loop = sources["event_loop"]
    owner = extract_braced_item(
        event_loop, "abstract class BaseEventLoop", "bounded event-loop owner"
    )
    for needle, label in (
        ("Timer", "idle or retry timer"),
        ("Timer.periodic", "idle polling"),
        ("List<BaseEvent", "head-shifting event list"),
        ("removeAt(0)", "linear-time head removal"),
        ("StreamController", "secondary event stream"),
    ):
        forbid(owner, needle, label)
    require(event_loop, "import 'dart:collection';", "FIFO collection import")
    require(
        event_loop,
        "typedef EventCallback<Data> = Future<void> Function(Data data);",
        "void-only callback contract",
    )
    base_event = extract_braced_item(event_loop, "abstract class BaseEvent", "event")
    require_order(
        base_event,
        (
            "final EventType type;",
            "final Data data;",
            "final callback = findCallback(type);",
            "if (callback == null)",
            "throw StateError('No callback owns the admitted event');",
            "await callback(data);",
        ),
        "immutable callback-owned event",
    )
    require_order(
        owner,
        (
            "BaseEventLoop({required this.maxOwnedEvents})",
            "if (maxOwnedEvents <= 0)",
            "final int maxOwnedEvents;",
            "final Queue<BaseEvent<EventType, Data>> _events = Queue();",
            "var _generation = 0;",
            "var _closed = true;",
            "var _draining = false;",
            "var _eventRunning = false;",
            "int? _scheduledGeneration;",
            "int get ownedEventCount => _events.length + (_eventRunning ? 1 : 0);",
        ),
        "one bounded running-plus-pending owner",
    )

    ready = extract_braced_item(owner, "Future<void> onReady()", "event-loop start")
    require_order(
        ready,
        ("_generation += 1;", "_closed = false;", "_scheduleDrain(_generation);"),
        "generation-owned event-loop start",
    )
    scheduler = extract_braced_item(owner, "void _scheduleDrain(", "drain scheduler")
    require_order(
        scheduler,
        (
            "if (!_isCurrent(generation)",
            "_draining ||",
            "_events.isEmpty ||",
            "_scheduledGeneration == generation",
            "_scheduledGeneration = generation;",
            "scheduleMicrotask(()",
            "if (_scheduledGeneration == generation)",
            "_scheduledGeneration = null;",
            "if (!_isCurrent(generation))",
            "if (!_closed && _events.isNotEmpty)",
            "_scheduleDrain(_generation);",
            "unawaited(_drain(generation));",
        ),
        "single exact-generation event-driven scheduler",
    )
    drain = extract_braced_item(owner, "Future<void> _drain(", "serial drain")
    require_order(
        drain,
        (
            "if (_draining || !_isCurrent(generation)) return;",
            "_draining = true;",
            "while (_events.isNotEmpty)",
            "currentEvent = _events.removeFirst();",
            "_eventRunning = true;",
            "await onPreConsume(currentEvent);",
            "if (!_isCurrent(generation)) return;",
            "await currentEvent.consume();",
            "if (!_isCurrent(generation)) return;",
            "await onPostConsume(currentEvent);",
            "if (!_isCurrent(generation)) return;",
            "_eventRunning = false;",
            "currentEvent = null;",
            "await onEventsClear();",
            "catch (error, stackTrace)",
            "if (_isCurrent(generation))",
            "_closed = true;",
            "_generation += 1;",
            "_scheduledGeneration = null;",
            "_events.clear();",
            "onEventsRetired();",
            "onTerminalError(currentEvent, error, stackTrace);",
            "finally",
            "_eventRunning = false;",
            "_draining = false;",
            "if (!_closed && _events.isNotEmpty)",
            "_scheduleDrain(_generation);",
        ),
        "FIFO nonoverlap, exact retirement, and terminal failure",
    )
    require(
        owner,
        "!_closed && generation == _generation;",
        "exact generation comparison",
    )
    close = extract_braced_item(owner, "Future<void> close()", "event-loop close")
    require_order(
        close,
        (
            "_closed = true;",
            "_generation += 1;",
            "_scheduledGeneration = null;",
            "_events.clear();",
            "onEventsRetired();",
        ),
        "synchronous close-before-retire",
    )
    admission = extract_braced_item(owner, "bool pushEvent(", "event admission")
    require_order(
        admission,
        (
            "if (_closed || ownedEventCount >= maxOwnedEvents)",
            "return false;",
            "_events.addLast(event);",
            "_scheduleDrain(_generation);",
            "return true;",
        ),
        "bounded closed-state FIFO admission",
    )

    file_model = sources["file_model"]
    payload = extract_braced_item(
        file_model, "class FileOverrideConfirmation", "typed confirmation payload"
    )
    require_order(
        payload,
        (
            "static const int maxReadPathCodeUnits = 32768;",
            "static const int _maxNativeInt = 0x7fffffff;",
            "final int jobId;",
            "final int fileNum;",
            "final String readPath;",
            "final bool isUpload;",
            "final bool isIdentical;",
            "static FileOverrideConfirmation? tryParse(",
            "event['name'] != 'override_file_confirm'",
            "rawJobId is! String",
            "rawFileNum is! String",
            "readPath is! String",
            "rawIsUpload is! String",
            "rawIsIdentical is! String",
            "final jobId = int.tryParse(rawJobId);",
            "final fileNum = int.tryParse(rawFileNum);",
            "jobId <= 0",
            "jobId > _maxNativeInt",
            "rawJobId != jobId.toString()",
            "fileNum < 0",
            "fileNum > _maxNativeInt",
            "rawFileNum != fileNum.toString()",
            "readPath.isEmpty",
            "readPath.length > maxReadPathCodeUnits",
            "readPath.contains('\\u0000')",
            "isUpload == null",
            "isIdentical == null",
            "return FileOverrideConfirmation(",
        ),
        "canonical bounded typed confirmation parse",
    )
    require_order(
        payload,
        (
            "if (value == 'true') return true;",
            "if (value == 'false') return false;",
            "return null;",
        ),
        "closed boolean vocabulary",
    )
    begin = extract_braced_item(file_model, "void beginSession(", "file session start")
    require_order(
        begin,
        (
            "if (!_isCurrentSession(expectedSessionId)) return;",
            "unawaited(evtLoop.close());",
            "dialogManager.dismissAll();",
            "fileFetcher.cancelPending();",
            "jobController.clear();",
        ),
        "one close-owned prior-session retirement",
    )
    forbid(begin, "evtLoop.clear()", "second pending-event retirement owner")
    post = extract_braced_item(
        file_model, "bool postOverrideFileConfirm(", "confirmation admission"
    )
    require_order(
        post,
        (
            "if (!_isCurrentSession(expectedSessionId)) return false;",
            "final confirmation = FileOverrideConfirmation.tryParse(event);",
            "if (confirmation == null) return false;",
            "return evtLoop.pushEvent(_FileDialogEvent(WeakReference(this),",
            "expectedSessionId, FileDialogType.overwrite, confirmation));",
        ),
        "typed exact-session checked admission result",
    )
    consume = extract_braced_item(
        file_model, "Future<void> overrideFileConfirm(", "confirmation consumer"
    )
    require_order(
        consume,
        (
            "FileOverrideConfirmation confirmation",
            "if (!_isCurrentSession(expectedSessionId)) return;",
            "final id = confirmation.jobId;",
            "final jobIndex = jobController.getJob(id);",
            "if (jobIndex == -1)",
            "throw StateError('File confirmation has no matching job');",
            "confirmation.readPath",
            "confirmation.isIdentical",
            "if (!_isCurrentSession(expectedSessionId)) return;",
            "await jobController.cancelJob(id);",
            "if (!_isCurrentSession(expectedSessionId)) return;",
            "sessionId: expectedSessionId,",
            "fileNum: confirmation.fileNum,",
            "isUpload: confirmation.isUpload",
            "if (!_isCurrentSession(expectedSessionId)) return;",
        ),
        "typed exact-session file-confirm consumption",
    )
    forbid(consume, "int.parse(", "late integer parsing")
    forbid(consume, "evt['", "retained raw event map")
    require(
        file_model,
        "enum FileDialogType { overwrite }",
        "closed file-dialog operation vocabulary",
    )
    file_loop = extract_braced_item(
        file_model, "class FileDialogEventLoop", "file-confirm loop"
    )
    require_order(
        file_loop,
        (
            "extends BaseEventLoop<FileDialogType, FileOverrideConfirmation>",
            "static const int maxOwnedConfirmations = 64;",
            "FileDialogEventLoop() : super(maxOwnedEvents: maxOwnedConfirmations);",
            "void onEventsRetired()",
            "_overrideConfirm = null;",
            "_skip = false;",
            "Future<void> onPreConsume(",
            "final event = evt as _FileDialogEvent;",
            "event.setOverrideConfirm(_overrideConfirm);",
            "event.setSkip(_skip);",
            "Future<void> onEventsClear()",
            "_overrideConfirm = null;",
            "_skip = false;",
            "void onTerminalError(",
            "if (fileEvent is _FileDialogEvent)",
            "ffi.reportFileDialogFailure(fileEvent.expectedSessionId);",
            "super.onTerminalError(event, error, stackTrace);",
        ),
        "bounded policy-scoped terminal-visible file-confirm owner",
    )

    model = sources["model"]
    session_handler = extract_braced_item(
        model, "Future<void> _handleSessionEvent(", "session event handler"
    )
    require_order(
        session_handler,
        (
            "else if (name == 'override_file_confirm')",
            "final ffi = parent.target;",
            "!ffi.fileModel.postOverrideFileConfirm(evt, sessionId)",
            "ffi.reportFileDialogFailure(sessionId);",
        ),
        "visible exact-session refusal",
    )
    report = extract_braced_item(
        model, "void reportFileDialogFailure(", "narrow file-dialog failure facade"
    )
    require_order(
        report,
        (
            "SessionID expectedSessionId",
            "_reportSessionStreamFailure(expectedSessionId, id,",
            "'The remote file transfer became inconsistent'",
        ),
        "existing exact-session terminal failure reuse",
    )

    native_handler = sources["native_handler"]
    native_override = extract_braced_item(
        native_handler, "fn override_file_confirm(", "native confirmation producer"
    )
    require_order(
        native_override,
        (
            '"override_file_confirm"',
            '("id", &id.to_string())',
            '("file_num", &file_num.to_string())',
            '("read_path", &to)',
            '("is_upload", &is_upload.to_string())',
            '("is_identical", &is_identical.to_string())',
        ),
        "native producer and typed parser vocabulary",
    )
    require_count(
        sources["native_io"],
        "self.handler.override_file_confirm(",
        2,
        "two viewer upload/download confirmation producers",
    )

    test = sources["test"]
    for needle, label in (
        ("bounded event loop consumes admitted work in FIFO order", "FIFO test"),
        ("capacity counts running and pending events", "capacity test"),
        ("close retires pending work and rejects admission while closed", "close test"),
        ("retired callback cannot consume replacement-generation work", "replacement test"),
        ("callback failure is terminal and clears successors", "failure test"),
        ("file confirmation parser owns one exact bounded typed payload", "typed parse test"),
        ("file confirmation parser rejects malformed scalar authority", "scalar negative test"),
        ("file confirmation parser rejects unowned path storage", "path negative test"),
        ("expect(loop.ownedEventCount, 2);", "running-plus-pending assertion"),
        ("expect(loop.pushEvent(_TestEvent(3, (_) async {})), isFalse);", "refusal assertion"),
        ("FileOverrideConfirmation.maxReadPathCodeUnits + 1", "overlong path fixture"),
    ):
        require(test, needle, label)
    for needle, label in (
        ("lib/utils/event_loop.dart", "Dart format source wiring"),
        ("test/file_dialog_event_loop_test.dart", "Dart test/format wiring"),
        (
            "flutter test --no-pub test/file_dialog_event_loop_test.dart",
            "Dart behavior gate",
        ),
    ):
        require(sources["dart_verify"], needle, label)

    require(
        sources["android_verify"],
        "void onEventsRetired()",
        "prior mobile exact-generation verifier update",
    )
    require(
        sources["android_verify"],
        "void _scheduleDrain(int generation)",
        "prior mobile event-driven generation verifier update",
    )
    for key, needle, label in (
        (
            "requirements",
            '<div class="req"><span class="id">R-S11hk</span>',
            "R-S11hk normative requirement",
        ),
        ("requirements", "<tr><td>371</td>", "Appendix C #371"),
        (
            "hardening",
            "### R-S11hk/R-S11e-248 — bounded exact-session file-confirm ownership",
            "R-S11hk hardening ledger",
        ),
        (
            "verify",
            "python3 scripts/verify-file-dialog-event-ownership.py --repo . --self-test",
            "shared focused-verifier wiring",
        ),
        (
            "apple",
            "python3 scripts/verify-file-dialog-event-ownership.py --repo . --self-test",
            "Apple focused-verifier wiring",
        ),
        (
            "workspace",
            '            "file_dialog_event_ownership_verifier": (\n'
            '                repo / "scripts/verify-file-dialog-event-ownership.py"\n'
            '            ).read_text(encoding="utf-8"),',
            "independent focused-verifier source binding",
        ),
        (
            "workspace",
            "    validate_file_dialog_event_ownership_contract(sources)\n",
            "independent validator dispatch",
        ),
    ):
        require(sources[key], needle, label)

    requirements_digest = hashlib.sha256(
        sources["requirements"].encode("utf-8")
    ).hexdigest()
    require(
        sources["hardening"],
        f"{requirements_digest}  requirements.html",
        "hardening requirements digest",
    )
    require(
        sources["native_watch"],
        f"Requirements hash: {requirements_digest}",
        "native-watch requirements digest",
    )


Mutation = Tuple[str, str, str, str]

MUTATIONS: Tuple[Mutation, ...] = (
    ("event_loop", "import 'dart:collection';", "", "FIFO collection"),
    ("event_loop", "final Queue<BaseEvent<EventType, Data>> _events = Queue();", "final List<BaseEvent<EventType, Data>> _events = [];", "bounded FIFO type"),
    ("event_loop", "if (maxOwnedEvents <= 0)", "if (maxOwnedEvents < 0)", "positive capacity"),
    ("event_loop", "_events.length + (_eventRunning ? 1 : 0)", "_events.length", "running event accounting"),
    ("event_loop", "generation == _generation", "generation <= _generation", "exact generation"),
    ("event_loop", "scheduleMicrotask(()", "Timer.run(()", "event-driven microtask"),
    ("event_loop", "_events.removeFirst()", "_events.removeLast()", "FIFO consumption"),
    ("event_loop", "_eventRunning = true;", "_eventRunning = false;", "running ownership"),
    ("event_loop", "_events.clear();\n        onEventsRetired();\n        onTerminalError", "onEventsRetired();\n        onTerminalError", "terminal pending retirement"),
    ("event_loop", "onTerminalError(currentEvent, error, stackTrace);", "FlutterError.reportError(FlutterErrorDetails(exception: error));", "terminal owner callback"),
    ("event_loop", "_events.clear();\n    onEventsRetired();\n  }\n\n  bool pushEvent", "onEventsRetired();\n  }\n\n  bool pushEvent", "close pending retirement"),
    ("event_loop", "if (_closed || ownedEventCount >= maxOwnedEvents)", "if (ownedEventCount > maxOwnedEvents)", "closed and saturated refusal"),
    ("event_loop", "_events.addLast(event);", "_events.addFirst(event);", "FIFO admission"),
    ("event_loop", "_scheduleDrain(_generation);\n    return true;", "return true;", "admission drain trigger"),
    ("event_loop", "throw StateError('No callback owns the admitted event');", "return;", "missing callback failure"),
    ("file_model", "static const int maxReadPathCodeUnits = 32768;", "static const int maxReadPathCodeUnits = 32769;", "path bound"),
    ("file_model", "event['name'] != 'override_file_confirm' ||", "false ||", "event type identity"),
    ("file_model", "rawJobId is! String ||", "rawJobId == null ||", "job scalar type"),
    ("file_model", "rawJobId != jobId.toString() ||", "false ||", "canonical job identity"),
    ("file_model", "rawFileNum != fileNum.toString() ||", "false ||", "canonical file number"),
    ("file_model", "readPath.contains('\\u0000') ||", "false ||", "NUL path refusal"),
    ("file_model", "if (value == 'false') return false;", "if (value != 'true') return false;", "closed boolean vocabulary"),
    (
        "file_model",
        "bool postOverrideFileConfirm(\n"
        "      Map<String, dynamic> event, SessionID expectedSessionId) {\n"
        "    if (!_isCurrentSession(expectedSessionId)) return false;",
        "bool postOverrideFileConfirm(\n"
        "      Map<String, dynamic> event, SessionID expectedSessionId) {\n"
        "    if (parent.target == null) return false;",
        "exact-session admission",
    ),
    ("file_model", "if (confirmation == null) return false;", "if (confirmation == null) return true;", "malformed refusal"),
    ("file_model", "return evtLoop.pushEvent(_FileDialogEvent(WeakReference(this),", "evtLoop.pushEvent(_FileDialogEvent(WeakReference(this),\n    return true;", "checked queue admission"),
    ("file_model", "Future<void> overrideFileConfirm(FileOverrideConfirmation confirmation,", "Future<void> overrideFileConfirm(Map<String, dynamic> confirmation,", "typed consumer"),
    ("file_model", "throw StateError('File confirmation has no matching job');", "return;", "missing-job terminal failure"),
    ("file_model", "static const int maxOwnedConfirmations = 64;", "static const int maxOwnedConfirmations = 65;", "file-confirm count bound"),
    ("file_model", "ffi.reportFileDialogFailure(fileEvent.expectedSessionId);", "return;", "callback failure visibility"),
    ("model", "!ffi.fileModel.postOverrideFileConfirm(evt, sessionId)", "ffi.fileModel.postOverrideFileConfirm(evt, sessionId)", "admission refusal handling"),
    ("model", "ffi.reportFileDialogFailure(sessionId);", "ffi.reportFileDialogFailure(ffi.sessionId);", "exact failing session"),
    ("test", "capacity counts running and pending events", "capacity ignores running events", "capacity behavior proof"),
    ("dart_verify", "flutter test --no-pub test/file_dialog_event_loop_test.dart", "true # file-dialog test disabled", "Dart behavior gate"),
    ("requirements", '<span class="id">R-S11hk</span>', '<span class="id">R-S11hk-disabled</span>', "normative requirement"),
    ("requirements", "<tr><td>371</td>", "<tr><td>371-disabled</td>", "Appendix C row"),
    ("hardening", "R-S11hk/R-S11e-248 — bounded exact-session file-confirm ownership", "R-S11hk-disabled/R-S11e-248 — bounded exact-session file-confirm ownership", "hardening ledger"),
    ("verify", "python3 scripts/verify-file-dialog-event-ownership.py --repo . --self-test", "true # file-confirm verifier disabled", "shared gate"),
    ("apple", "python3 scripts/verify-file-dialog-event-ownership.py --repo . --self-test", "true # file-confirm verifier disabled", "Apple gate"),
    (
        "workspace",
        '            "file_dialog_event_ownership_verifier": (\n'
        '                repo / "scripts/verify-file-dialog-event-ownership.py"\n'
        '            ).read_text(encoding="utf-8"),',
        '            "file_dialog_event_ownership_verifier_disabled": (\n'
        '                repo / "scripts/verify-file-dialog-event-ownership.py"\n'
        '            ).read_text(encoding="utf-8"),',
        "independent source binding",
    ),
    (
        "workspace",
        "    validate_file_dialog_event_ownership_contract(sources)\n",
        "    validate_file_dialog_event_ownership_contract_disabled(sources)\n",
        "independent dispatch",
    ),
)


def run_self_test(sources: Dict[str, str]) -> None:
    for key, old, new, label in MUTATIONS:
        count = sources[key].count(old)
        if count != 1:
            raise VerificationError(
                f"self-test fixture for {label} occurs {count} time(s): {old!r}"
            )
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
            "file-dialog event ownership verifier self-test passed "
            f"({len(MUTATIONS)} mutations)"
        )
    else:
        print("file-dialog event ownership verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"file-dialog event ownership verifier failed: {error}")
        raise SystemExit(1)
