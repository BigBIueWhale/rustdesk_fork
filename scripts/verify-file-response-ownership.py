#!/usr/bin/env python3
"""Verify reserve-before-dispatch exact-session Flutter file responses."""

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
    if signature.rstrip().endswith("{"):
        open_brace = start + signature.rfind("{")
    else:
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
        "file_model": "flutter/lib/models/file_model.dart",
        "model": "flutter/lib/models/model.dart",
        "test": "flutter/test/mobile_file_session_lifecycle_test.dart",
        "flutter_source": "src/flutter.rs",
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
    file_model = sources["file_model"]
    requests = extract_braced_item(
        file_model, "class FileFetcherRequests", "typed request dependency"
    )
    require_order(
        requests,
        (
            "required this.readDirectory,",
            "required this.readEmptyDirectories,",
            "required this.readDirectoryTree,",
            "final ReadRemoteDirectory readDirectory;",
            "final ReadRemoteDirectory readEmptyDirectories;",
            "final ReadRemoteDirectoryTree readDirectoryTree;",
            "static final native = FileFetcherRequests(",
            "bind.sessionReadRemoteDir(",
            "bind.sessionReadRemoteEmptyDirsRecursiveSync(",
            "bind.sessionReadDirToRemoveRecursive(",
        ),
        "three-operation production request surface",
    )
    for needle, label in (
        ("Timer", "request dependency timer"),
        ("retry", "request dependency retry"),
        ("StreamController", "alternate event transport"),
        ("Isolate", "request isolate"),
    ):
        forbid(requests, needle, label)

    fetcher = extract_braced_item(file_model, "class FileFetcher {", "file fetcher")
    require_order(
        fetcher,
        (
            "final Map<String, _PendingFileRequest<FileDirectory>> _remoteTasks = {};",
            "_remoteEmptyDirsTasks = {};",
            "final Map<int, _PendingFileRequest<FileDirectory>> _readRecursiveTasks = {};",
            "final FileFetcherRequests _requests;",
            "this.maxPending = 64,",
            "this.requestTimeout = const Duration(seconds: 2)",
            "if (maxPending < 1)",
            "if (requestTimeout.inMicroseconds < 1)",
            "int get _pendingCount =>",
            "_remoteTasks.length +",
            "_remoteEmptyDirsTasks.length +",
            "_readRecursiveTasks.length;",
        ),
        "one bounded owner across all response maps",
    )
    for legacy in (
        "registerReadTask",
        "registerReadEmptyDirsTask",
        "registerReadRecursiveTask",
        "Map<String, Completer<FileDirectory>> remoteTasks",
    ):
        forbid(fetcher, legacy, "send-before-register API")

    cancel = extract_braced_item(fetcher, "void cancelPending()", "request retirement")
    require_order(
        cancel,
        (
            "_remoteTasks.values.toList(growable: false)",
            "_remoteEmptyDirsTasks.values.toList(growable: false)",
            "_readRecursiveTasks.values.toList(growable: false)",
            "_remoteTasks.clear();",
            "_remoteEmptyDirsTasks.clear();",
            "_readRecursiveTasks.clear();",
            "StateError('Superseded file-transfer session')",
            "task.completeError(error);",
            "task.completeError(error);",
            "task.completeError(error);",
        ),
        "clear-before-complete exact retirement",
    )

    reserve = extract_braced_item(fetcher, "_PendingFileRequest<T> _reserve<", "reservation")
    require_order(
        reserve,
        (
            "if (tasks.containsKey(key))",
            "throw StateError('$operation is already pending');",
            "if (_pendingCount >= maxPending)",
            "throw StateError('File request capacity exhausted');",
            "final pending = _PendingFileRequest<T>(expectedSessionId, isLocal);",
            "tasks[key] = pending;",
            "pending.startTimeout(requestTimeout, ()",
            "if (!identical(tasks[key], pending)) return;",
            "wire response has no per-request nonce",
            "pending.completeError(TimeoutException(",
            "return pending;",
        ),
        "duplicate/capacity refusal and bounded timeout tombstone",
    )
    forbid(reserve, "tasks.remove(key);", "timeout tombstone removal")
    dispatch = extract_braced_item(
        fetcher, "Future<T> _dispatchAndWait<", "dispatch finality"
    )
    forbid(dispatch, "await dispatch", "blocking bridge dispatch")
    forbid(dispatch, ") async {", "async dispatch wrapper")
    require_order(
        dispatch,
        (
            "dispatchResult = dispatch();",
            "catch (error, stackTrace)",
            "if (identical(tasks[key], pending))",
            "tasks.remove(key);",
            "pending.completeError(error, stackTrace);",
            "return pending.future;",
            "unawaited(dispatchResult.then<void>",
            "pending.markDispatchSettled();",
            "if (pending.responseReceived && identical(tasks[key], pending))",
            "onError: (Object error, StackTrace stackTrace)",
            "if (identical(tasks[key], pending))",
            "tasks.remove(key);",
            "pending.completeError(error, stackTrace);",
            "return pending.future;",
        ),
        "nonblocking deadline and exact dispatch finality",
    )
    complete = extract_braced_item(fetcher, "bool _complete<", "response completion")
    require_order(
        complete,
        (
            "final pending = tasks[key];",
            "pending == null ||",
            "pending.expectedSessionId != expectedSessionId ||",
            "pending.isLocal != isLocal",
            "return false;",
            "if (pending.responseReceived) return false;",
            "if (pending.isCompleted)",
            "tasks.remove(key);",
            "return false;",
            "pending.complete(value);",
            "if (pending.dispatchSettled)",
            "tasks.remove(key);",
            "return true;",
        ),
        "exact response completion and late-response consumption",
    )
    require_order(
        fetcher,
        (
            "if (value == 'true') return true;",
            "if (value == 'false') return false;",
            "return null;",
        ),
        "closed response-side vocabulary",
    )

    empty = extract_braced_item(
        fetcher, "Future<List<FileDirectory>> readEmptyDirs(", "empty-directory request"
    )
    require_order(
        empty,
        (
            "final selectedSessionId = expectedSessionId ?? sessionId;",
            "if (isLocal)",
            "bind.sessionReadLocalEmptyDirsRecursiveSync(",
            "final pending = _reserve(_remoteEmptyDirsTasks, path, selectedSessionId,",
            "return _dispatchAndWait(_remoteEmptyDirsTasks, path, pending,",
            "_requests.readEmptyDirectories(",
        ),
        "empty-directory reserve before remote dispatch",
    )
    directory = extract_braced_item(
        fetcher, "Future<FileDirectory> fetchDirectory(", "directory request"
    )
    require_order(
        directory,
        (
            "final selectedSessionId = expectedSessionId ?? sessionId;",
            "if (isLocal)",
            "bind.sessionReadLocalDirSync(",
            "final pending = _reserve(_remoteTasks, path, selectedSessionId, false,",
            "return _dispatchAndWait(_remoteTasks, path, pending,",
            "_requests.readDirectory(selectedSessionId, path, showHidden)",
        ),
        "directory reserve before remote dispatch",
    )
    recursive = extract_braced_item(
        fetcher,
        "Future<FileDirectory> fetchDirectoryRecursiveToRemove(",
        "recursive directory request",
    )
    require_order(
        recursive,
        (
            "final selectedSessionId = expectedSessionId ?? sessionId;",
            "final pending = _reserve(_readRecursiveTasks, actID, selectedSessionId,",
            "return _dispatchAndWait(",
            "_readRecursiveTasks,",
            "actID,",
            "pending,",
            "_requests.readDirectoryTree(",
        ),
        "recursive reserve before remote dispatch",
    )

    response = extract_braced_item(
        fetcher, "bool tryCompleteTask(", "typed directory response"
    )
    require_order(
        response,
        (
            "final isLocal = _parseIsLocal(isLocalValue);",
            "if (msg is! String || isLocal == null) return false;",
            "if (fd.id > 0)",
            "_complete(_readRecursiveTasks, fd.id, expectedSessionId,",
            "else if (fd.id == 0 && fd.path.isNotEmpty)",
            "_complete(",
            "_remoteTasks, fd.path, expectedSessionId, isLocal, fd)",
            "return false;",
        ),
        "closed response routing",
    )
    empty_response = extract_braced_item(
        fetcher, "bool tryCompleteEmptyDirsTask(", "typed empty-directory response"
    )
    require_order(
        empty_response,
        (
            "final isLocal = _parseIsLocal(isLocalValue);",
            "if (msg is! String || isLocal == null) return false;",
            "return _complete(_remoteEmptyDirsTasks, path, expectedSessionId,",
        ),
        "closed empty-directory response routing",
    )
    response_error = extract_braced_item(
        fetcher,
        "bool tryCompleteRecursiveTaskWithError(",
        "recursive error response",
    )
    require_order(
        response_error,
        (
            "pending.expectedSessionId != expectedSessionId",
            "return false;",
            "if (pending.responseReceived) return false;",
            "if (pending.isCompleted)",
            "_readRecursiveTasks.remove(id);",
            "return false;",
            "pending.completeResponseError(StateError(error));",
            "if (pending.dispatchSettled)",
            "_readRecursiveTasks.remove(id);",
            "return true;",
        ),
        "exact-session recursive error and tombstone consumption",
    )

    pending = extract_braced_item(
        file_model, "class _PendingFileRequest", "pending request owner"
    )
    require_order(
        pending,
        (
            "final SessionID expectedSessionId;",
            "final bool isLocal;",
            "final Completer<T> _done = Completer<T>();",
            "Timer? _timer;",
            "bool _dispatchSettled = false;",
            "bool _responseReceived = false;",
            "_timer = Timer(timeout, onTimeout);",
            "void complete(T value)",
            "_responseReceived = true;",
            "_timer?.cancel();",
            "_done.complete(value);",
            "void completeError(Object error, [StackTrace? stackTrace])",
            "_timer?.cancel();",
            "_done.completeError(error, stackTrace);",
            "void completeResponseError(Object error)",
            "_responseReceived = true;",
            "_timer?.cancel();",
            "_done.completeError(error);",
            "void markDispatchSettled()",
            "_dispatchSettled = true;",
        ),
        "exact owner, dispatch state, and timer finality",
    )

    begin = extract_braced_item(file_model, "void beginSession(", "file session start")
    require_order(
        begin,
        (
            "if (parent.target?.isCurrentSession(expectedSessionId) != true) return;",
            "_ownedSessionId = null;",
            "fileFetcher.cancelPending();",
            "_ownedSessionId = expectedSessionId;",
        ),
        "replacement retirement",
    )
    close = extract_braced_item(file_model, "Future<void> close(", "file model close")
    require_order(
        close,
        (
            "if (_ownedSessionId != expectedSessionId ||",
            "_ownedSessionId = null;",
            "final eventLoopClose = evtLoop.close();",
            "fileFetcher.cancelPending();",
            "await eventLoopClose;",
        ),
        "exact-session close retirement",
    )
    receive = extract_braced_item(file_model, "void receiveFileDir(", "directory event")
    require_order(
        receive,
        (
            "if (!_isCurrentSession(expectedSessionId)) return;",
            "fileFetcher.tryCompleteTask(",
            "expectedSessionId, evt['value'], evt['is_local']",
        ),
        "exact-session directory event",
    )
    receive_empty = extract_braced_item(
        file_model, "void receiveEmptyDirs(", "empty-directory event"
    )
    require_order(
        receive_empty,
        (
            "if (!_isCurrentSession(expectedSessionId)) return;",
            "fileFetcher.tryCompleteEmptyDirsTask(",
            "expectedSessionId, evt['value'], evt['is_local']",
        ),
        "exact-session empty-directory event",
    )

    model = sources["model"]
    handler = extract_braced_item(
        model, "Future<void> _handleSessionEvent(", "session event handler"
    )
    require_order(
        handler,
        (
            "else if (name == 'file_dir')",
            "receiveFileDir(evt, sessionId);",
            "else if (name == 'empty_dirs')",
            "receiveEmptyDirs(evt, sessionId);",
            "else if (name == 'job_error')",
            "handleJobError(evt, sessionId);",
        ),
        "stream session identity propagation",
    )

    producer = extract_braced_item(
        sources["flutter_source"],
        "fn update_folder_files(",
        "native directory response producer",
    )
    require_order(
        producer,
        (
            "is_local: bool,",
            "if only_count",
            "let is_local = is_local.to_string();",
            '"file_dir",',
            '("is_local", &is_local),',
            '("value", &crate::common::make_fd_to_json(id, path, entries)),',
        ),
        "actual recursive-directory response side",
    )
    forbid(producer, '("is_local", "false")', "hardcoded response side")

    test = sources["test"]
    for needle, label in (
        (
            "directory response owner exists before bridge dispatch settles",
            "fast-response regression",
        ),
        (
            "response must match session, locality, operation, and key",
            "correlation regression",
        ),
        (
            "retirement cancels an in-flight dispatch and permits replacement",
            "retirement regression",
        ),
        ("dispatch failure removes its exact reservation", "dispatch regression"),
        ("one total capacity bounds all response maps", "capacity regression"),
        (
            "timeout quarantines its key until the late response is consumed",
            "timeout tombstone regression",
        ),
        ("await dispatchEntered.future;", "blocked-dispatch fixture"),
        ("fetcher.tryCompleteTask(session,", "synchronous response completion"),
        ("maxPending: 1,", "blocked-dispatch retained-capacity fixture"),
        ("'/different-path'", "blocked-dispatch cross-key capacity proof"),
        ("maxPending: 2,", "cross-map capacity fixture"),
        ("throwsA(isA<TimeoutException>())", "timeout assertion"),
        ("directoryResponse('/owned', id: -1)", "negative-ID refusal"),
        ("fetcher.tryCompleteTask(session, 7, 'false')", "non-string refusal"),
        ("session, 0, 'anonymous error'", "anonymous-error refusal"),
        ("path now would let the stale answer complete", "timeout retry refusal"),
    ):
        require(test, needle, label)

    for key, needle, label in (
        (
            "dart_verify",
            "flutter test --no-pub test/mobile_file_session_lifecycle_test.dart",
            "Dart behavior gate",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11hl</span>',
            "R-S11hl normative requirement",
        ),
        ("requirements", "<tr><td>372</td>", "Appendix C #372"),
        (
            "hardening",
            "### R-S11hl/R-S11e-249 — reserve-before-dispatch file-response ownership",
            "R-S11hl hardening ledger",
        ),
        (
            "verify",
            "python3 scripts/verify-file-response-ownership.py --repo . --self-test",
            "shared focused-verifier wiring",
        ),
        (
            "apple",
            "python3 scripts/verify-file-response-ownership.py --repo . --self-test",
            "Apple focused-verifier wiring",
        ),
        (
            "workspace",
            '            "file_response_ownership_verifier": (\n'
            '                repo / "scripts/verify-file-response-ownership.py"\n'
            '            ).read_text(encoding="utf-8"),',
            "independent focused-verifier source binding",
        ),
        (
            "workspace",
            "    validate_file_response_ownership_contract(sources)\n",
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
    (
        "file_model",
        "FileFetcher(this.getSessionID,\n"
        "      {FileFetcherRequests? requests,\n"
        "      this.maxPending = 64,",
        "FileFetcher(this.getSessionID,\n"
        "      {FileFetcherRequests? requests,\n"
        "      this.maxPending = 6400,",
        "total capacity",
    ),
    (
        "file_model",
        "_remoteTasks.length +\n      _remoteEmptyDirsTasks.length +",
        "_remoteTasks.length +\n      0 +",
        "cross-map capacity",
    ),
    (
        "file_model",
        "if (_pendingCount >= maxPending)",
        "if (_pendingCount > maxPending)",
        "capacity refusal",
    ),
    (
        "file_model",
        "tasks[key] = pending;\n    pending.startTimeout",
        "pending.startTimeout",
        "reservation publication",
    ),
    (
        "file_model",
        "if (!identical(tasks[key], pending)) return;",
        "if (!tasks.containsKey(key)) return;",
        "exact timeout owner",
    ),
    (
        "file_model",
        "pending.expectedSessionId != expectedSessionId ||",
        "false ||",
        "response session identity",
    ),
    (
        "file_model",
        "pending.isLocal != isLocal",
        "false",
        "response side identity",
    ),
    (
        "file_model",
        "if (pending.dispatchSettled) {\n      tasks.remove(key);\n    }\n    return true;",
        "return true;",
        "post-dispatch response removal",
    ),
    (
        "file_model",
        "void complete(T value) {\n"
        "    if (_done.isCompleted) return;\n"
        "    _responseReceived = true;\n"
        "    _timer?.cancel();\n"
        "    _timer = null;\n"
        "    _done.complete(value);",
        "void complete(T value) {\n"
        "    if (_done.isCompleted) return;\n"
        "    _responseReceived = true;\n"
        "    _timer = null;\n"
        "    _done.complete(value);",
        "success timer cancellation",
    ),
    (
        "file_model",
        "// The wire response has no per-request nonce. Keep this exact owner as a",
        "tasks.remove(key);\n      // The wire response has no per-request nonce. Keep this exact owner as a",
        "timeout tombstone retention",
    ),
    (
        "file_model",
        "if (identical(tasks[key], pending)) {\n"
        "        tasks.remove(key);\n"
        "      }\n"
        "      pending.completeError(error, stackTrace);\n"
        "      return pending.future;\n"
        "    }\n\n"
        "    unawaited(dispatchResult.then<void>",
        "if (identical(tasks[key], pending)) {\n"
        "        tasks.remove(key);\n"
        "      }\n"
        "      pending.completeError(error, stackTrace);\n"
        "      return pending.future;\n"
        "    }\n\n"
        "    Future<void>.value().then<void>",
        "nonblocking dispatch observation",
    ),
    (
        "file_model",
        "if (pending.responseReceived) return false;\n"
        "    if (pending.isCompleted) {\n"
        "      // Consume the late response owned by a timed-out tombstone.",
        "if (pending.isCompleted) {\n"
        "      // Consume the late response owned by a timed-out tombstone.",
        "completed-response tombstone retention",
    ),
    (
        "file_model",
        "} else if (fd.id == 0 && fd.path.isNotEmpty) {",
        "} else if (fd.path.isNotEmpty) {",
        "negative response ID refusal",
    ),
    (
        "file_model",
        "bool tryCompleteTask(SessionID expectedSessionId, Object? msg,\n"
        "      Object? isLocalValue) {\n"
        "    final isLocal = _parseIsLocal(isLocalValue);\n"
        "    if (msg is! String || isLocal == null) return false;",
        "bool tryCompleteTask(SessionID expectedSessionId, Object? msg,\n"
        "      Object? isLocalValue) {\n"
        "    final isLocal = _parseIsLocal(isLocalValue);\n"
        "    if (msg == null || isLocal == null) return false;",
        "malformed response type refusal",
    ),
    (
        "file_model",
        "final pending = _reserve(_remoteTasks, path, selectedSessionId, false,",
        "final pending = _PendingFileRequest<FileDirectory>(selectedSessionId, false);",
        "directory reserve",
    ),
    (
        "file_model",
        "final pending = _reserve(_remoteEmptyDirsTasks, path, selectedSessionId,",
        "final pending = _PendingFileRequest<List<FileDirectory>>(selectedSessionId, false);",
        "empty-directory reserve",
    ),
    (
        "file_model",
        "final pending = _reserve(_readRecursiveTasks, actID, selectedSessionId,",
        "final pending = _PendingFileRequest<FileDirectory>(selectedSessionId, isLocal);",
        "recursive reserve",
    ),
    (
        "file_model",
        "final eventLoopClose = evtLoop.close();\n    fileFetcher.cancelPending();",
        "final eventLoopClose = evtLoop.close();",
        "close retirement",
    ),
    (
        "file_model",
        "void receiveFileDir(\n      Map<String, dynamic> evt, SessionID expectedSessionId) {\n    if (!_isCurrentSession(expectedSessionId)) return;",
        "void receiveFileDir(\n      Map<String, dynamic> evt, SessionID expectedSessionId) {",
        "event current-session proof",
    ),
    (
        "model",
        "receiveFileDir(evt, sessionId);",
        "receiveFileDir(evt, parent.target!.sessionId);",
        "stream session propagation",
    ),
    (
        "flutter_source",
        '("is_local", &is_local),',
        '("is_local", "false"),',
        "native response side",
    ),
    (
        "test",
        "directory response owner exists before bridge dispatch settles",
        "directory response runs after bridge dispatch settles",
        "fast-response behavior proof",
    ),
    (
        "test",
        "one total capacity bounds all response maps",
        "each response map has its own capacity",
        "capacity behavior proof",
    ),
    (
        "test",
        "maxPending: 1,",
        "maxPending: 64,",
        "blocked-dispatch retained capacity proof",
    ),
    (
        "test",
        "timeout quarantines its key until the late response is consumed",
        "timeout permits immediate same-key replacement",
        "timeout tombstone behavior proof",
    ),
    (
        "test",
        "directoryResponse('/owned', id: -1)",
        "directoryResponse('/owned', id: 0)",
        "negative-ID behavior proof",
    ),
    (
        "test",
        "fetcher.tryCompleteTask(session, 7, 'false')",
        "fetcher.tryCompleteTask(session, directoryResponse('/owned'), 'false')",
        "malformed-type behavior proof",
    ),
    (
        "test",
        "session, 0, 'anonymous error'",
        "session, 7, 'anonymous error'",
        "anonymous-error behavior proof",
    ),
    (
        "dart_verify",
        "flutter test --no-pub test/mobile_file_session_lifecycle_test.dart",
        "true # file-response test disabled",
        "Dart behavior gate",
    ),
    (
        "requirements",
        '<span class="id">R-S11hl</span>',
        '<span class="id">R-S11hl-disabled</span>',
        "normative requirement",
    ),
    (
        "requirements",
        "<tr><td>372</td>",
        "<tr><td>372-disabled</td>",
        "Appendix C row",
    ),
    (
        "hardening",
        "R-S11hl/R-S11e-249 — reserve-before-dispatch file-response ownership",
        "R-S11hl-disabled/R-S11e-249 — reserve-before-dispatch file-response ownership",
        "hardening ledger",
    ),
    (
        "verify",
        "python3 scripts/verify-file-response-ownership.py --repo . --self-test",
        "true # file-response verifier disabled",
        "shared gate",
    ),
    (
        "apple",
        "python3 scripts/verify-file-response-ownership.py --repo . --self-test",
        "true # file-response verifier disabled",
        "Apple gate",
    ),
    (
        "workspace",
        '            "file_response_ownership_verifier": (\n'
        '                repo / "scripts/verify-file-response-ownership.py"\n'
        '            ).read_text(encoding="utf-8"),',
        '            "file_response_ownership_verifier_disabled": (\n'
        '                repo / "scripts/verify-file-response-ownership.py"\n'
        '            ).read_text(encoding="utf-8"),',
        "independent source binding",
    ),
    (
        "workspace",
        "    validate_file_response_ownership_contract(sources)\n",
        "    validate_file_response_ownership_contract_disabled(sources)\n",
        "independent validator dispatch",
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
            "file-response ownership verifier self-test passed "
            f"({len(MUTATIONS)} mutations)"
        )
    else:
        print("file-response ownership verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"file-response ownership verifier failed: {error}")
        raise SystemExit(1)
