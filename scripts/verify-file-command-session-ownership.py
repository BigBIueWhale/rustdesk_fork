#!/usr/bin/env python3
"""Verify exact-session Flutter file commands and job-result ownership."""

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
        "desktop": "flutter/lib/desktop/pages/file_manager_page.dart",
        "mobile": "flutter/lib/mobile/pages/file_manager_page.dart",
        "web": "flutter/lib/web/web_unique.dart",
        "test": "flutter/test/file_command_session_ownership_test.dart",
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
    controller_requests = extract_braced_item(
        file_model, "class FileControllerRequests", "file command surface"
    )
    require_order(
        controller_requests,
        (
            "final SendFilesRequest sendFiles;",
            "final RemoveFileRequest removeFile;",
            "final RemoveEmptyDirectoriesRequest removeEmptyDirectories;",
            "final CreateDirectoryRequest createDirectory;",
            "final RenameFileRequest renameFile;",
            "static final native = FileControllerRequests(",
            "bind.sessionSendFiles(",
            "bind.sessionRemoveFile(",
            "bind.sessionRemoveAllEmptyDirs(",
            "bind.sessionCreateDir(",
            "bind.sessionRenameFile(",
        ),
        "closed production file command surface",
    )
    for needle, label in (
        ("Timer", "command timer"),
        ("retry", "command retry"),
        ("StreamController", "alternate command transport"),
        ("Isolate", "command isolate"),
    ):
        forbid(controller_requests, needle, label)

    controller = extract_braced_item(
        file_model, "class FileController {", "file controller"
    )
    for needle, label in (
        ("rootState", "broad FFI authority"),
        ("bind.sessionSendFiles", "direct send binding"),
        ("bind.sessionRemoveFile", "direct remove binding"),
        ("bind.sessionRemoveAllEmptyDirs", "direct remove-dir binding"),
        ("bind.sessionCreateDir", "direct create binding"),
        ("bind.sessionRenameFile", "direct rename binding"),
    ):
        forbid(controller, needle, label)
    require(
        controller,
        "final IsCurrentSession isCurrentSession;",
        "file-controller session authority",
    )
    require_order(
        controller,
        (
            "final selectedSessionId = expectedSessionId ?? sessionId;",
            "if (!_isCurrentSession(selectedSessionId)) return;",
            ".map(_FileOperationEntry.fromEntry)",
            "final toPath = otherSideData.directory.path;",
            "final sourceRootPath = directory.value.path;",
            "await _requests.sendFiles(selectedSessionId,",
            "if (!_isCurrentSession(selectedSessionId)) return;",
            "expectedSessionId: selectedSessionId",
        ),
        "send operation exact-owner snapshots",
    )
    for needle, label in (
        (
            "jobController.dispatchAndWaitForResult(",
            "reserve-before-dispatch delete result",
        ),
        (
            "dispatch: () => _requests.removeFile(\n"
            "            expectedSessionId, actionId, path, !isLocal, fileNum)",
            "explicit remove command session",
        ),
        (
            "final confirmationState = _RemoveConfirmationState();",
            "operation-local confirmation state",
        ),
        (
            "final actionId = jobController.allocateJobId(selectedSessionId);",
            "rename exact-session action allocation",
        ),
        ("textEditingController.dispose();", "rename controller disposal"),
        (
            "Future<List<Entry>?> listWindowsDrives(\n"
            "      {SessionID? expectedSessionId}) async {",
            "explicitly owned drive lookup",
        ),
    ):
        require(controller, needle, label)

    job_controller = extract_braced_item(
        file_model, "class JobController {", "job controller"
    )
    for needle, label in (
        ("await bind.sessionCancelJob", "direct dynamic cancel binding"),
        ("await bind.sessionAddJob", "direct dynamic add binding"),
        ("await bind.sessionResumeJob", "direct dynamic resume binding"),
    ):
        forbid(job_controller, needle, label)
    for needle, label in (
        ("required this.isCurrentSession", "job current-session authority"),
        (
            "await _requests.addJob(expectedSessionId,",
            "load-job exact-session dispatch",
        ),
        (
            "if (!isCurrentSession(expectedSessionId)) return;\n\n"
            "    if (isAutoStart)",
            "load-job post-dispatch retirement check",
        ),
        (
            "await _requests.resumeJob(selectedSessionId, actionId, isRemote);",
            "resume exact-session dispatch",
        ),
    ):
        require(job_controller, needle, label)
    job_done = extract_braced_item(
        job_controller, "Future<bool> jobDone(", "job-done completion route"
    )
    require_order(
        job_done,
        (
            "if (!isCurrentSession(expectedSessionId)) return false;",
            "final id = _eventInt(evt['id'], positive: true);",
            "final eventFileNum = _eventInt(evt['file_num']);",
            "if (id == null || eventFileNum == null) return false;",
            "jobResultListener.tryComplete(expectedSessionId, evt);",
        ),
        "exact-session job completion",
    )
    job_error_route = extract_braced_item(
        job_controller, "void jobError(", "job-error completion route"
    )
    require_order(
        job_error_route,
        (
            "if (!isCurrentSession(expectedSessionId)) return;",
            "final id = _eventInt(evt['id'], positive: true);",
            "final errValue = evt['err'];",
            "if (id == null || errValue is! String) return;",
            "jobResultListener.tryCompleteError(expectedSessionId, evt);",
        ),
        "exact-session job error",
    )

    listener = extract_braced_item(
        file_model, "class JobResultListener {", "job result listener"
    )
    require_order(
        listener,
        (
            "this.maxPending = 64,",
            "this.requestTimeout = const Duration(seconds: 5)",
            "final Map<_JobResultKey, _PendingJobResult> _pending = {};",
            "if (_pending.containsKey(key))",
            "if (_pending.length >= maxPending)",
            "_pending[key] = pending;",
            "pending.startTimeout(requestTimeout,",
            "dispatchResult = dispatch();",
            "unawaited(dispatchResult.then<void>",
            "bool tryComplete(",
            "bool tryCompleteError(",
        ),
        "bounded exact job-result owner",
    )
    job_success = extract_braced_item(
        listener, "bool tryComplete(", "job result success completion"
    )
    require_order(
        job_success,
        (
            "final actionId = JobController._eventInt(event['id'], positive: true);",
            "final fileNum = JobController._eventInt(event['file_num']);",
            "if (actionId == null || fileNum == null) return false;",
        ),
        "job-result file identity",
    )
    require(
        job_success,
        "final key = _JobResultKey(expectedSessionId, actionId, fileNum);",
        "job-result session identity",
    )
    require_order(
        job_success,
        (
            "final key = _JobResultKey(expectedSessionId, actionId, fileNum);",
            "final pending = _pending[key];",
            "if (pending == null) return false;",
            "_retainLateResponseUntilDispatchSettles(key, pending);",
            "pending.complete(Map<String, dynamic>.unmodifiable(event));",
        ),
        "exact job-result success owner",
    )
    job_error = extract_braced_item(
        listener, "bool tryCompleteError(", "job result error completion"
    )
    require_order(
        job_error,
        (
            "final actionId = JobController._eventInt(event['id'], positive: true);",
            "final fileNum = JobController._eventInt(event['file_num']);",
            "final error = event['err'];",
            "if (actionId == null || fileNum == null || error is! String) return false;",
        ),
        "job-result error file identity",
    )
    require_order(
        job_error,
        (
            "final key = _JobResultKey(expectedSessionId, actionId, fileNum);",
            "final pending = _pending[key];",
            "if (pending == null) return false;",
            "_retainLateResponseUntilDispatchSettles(key, pending);",
            "pending.completeResponseError(StateError(error));",
        ),
        "exact job-result error owner",
    )
    pending_result = extract_braced_item(
        file_model, "class _PendingJobResult {", "pending job result"
    )
    require_order(
        pending_result,
        (
            "bool _dispatchSettled = false;",
            "bool _responseReceived = false;",
            "Map<String, dynamic>? _responseValue;",
            "Object? _responseError;",
            "_responseValue = value;",
            "_completeResponseIfDispatchSettled();",
            "_responseError = error;",
            "void markDispatchSettled()",
            "_dispatchSettled = true;",
            "void _completeResponseIfDispatchSettled()",
            "if (!_dispatchSettled || !_responseReceived || _done.isCompleted) return;",
            "_timer?.cancel();",
            "_done.completeError(error);",
            "_done.complete(value);",
        ),
        "response-and-dispatch terminal join",
    )
    complete_result = extract_braced_item(
        pending_result,
        "void complete(Map<String, dynamic> value)",
        "pending success response",
    )
    forbid(
        complete_result,
        "_done.complete(value);",
        "success before dispatch settlement",
    )
    terminal_error = extract_braced_item(
        pending_result,
        "void completeError(Object error, [StackTrace? stackTrace])",
        "pending terminal error",
    )
    require(
        terminal_error,
        "_timer?.cancel();",
        "terminal-error timer finality",
    )
    late_response = extract_braced_item(
        pending_result,
        "bool markLateResponseReceived()",
        "timed-out late response ownership",
    )
    require_order(
        late_response,
        (
            "if (!_done.isCompleted || _responseReceived) return false;",
            "_responseReceived = true;",
            "return true;",
        ),
        "late response retained through dispatch settlement",
    )
    retention = extract_braced_item(
        listener,
        "void _retainLateResponseUntilDispatchSettles(",
        "timed-out owner dispatch-drain retention",
    )
    require_order(
        retention,
        (
            "if (!pending.markLateResponseReceived()) return;",
            "if (pending.dispatchSettled && identical(_pending[key], pending))",
            "_pending.remove(key);",
        ),
        "timed-out owner dispatch-drain retention",
    )
    if listener.count("_retainLateResponseUntilDispatchSettles(key, pending);") != 2:
        raise VerificationError(
            "success and error late-result paths must share dispatch retention"
        )
    forbid(listener, "Completer<T>? _completer", "anonymous result completer")

    file_model_owner = extract_braced_item(
        file_model, "class FileModel {", "file model owner"
    )
    require_order(
        file_model_owner,
        (
            "SessionID? _ownedSessionId;",
            "_ownedSessionId = getSessionID();",
            "_ownedSessionId == expectedSessionId &&",
            "void beginSession(SessionID expectedSessionId)",
            "_ownedSessionId = null;",
            "fileFetcher.cancelPending();",
            "jobController.clear();",
            "_ownedSessionId = expectedSessionId;",
            "Future<void> close(SessionID expectedSessionId)",
            "_ownedSessionId = null;",
            "final eventLoopClose = evtLoop.close();",
            "fileFetcher.cancelPending();",
            "jobController.clear();",
        ),
        "synchronous file owner retirement",
    )

    for source_key, needle, label in (
        (
            "model",
            ".jobDone(evt, sessionId)",
            "job-done stream session propagation",
        ),
        (
            "model",
            ".loadLastJob(evt, sessionId)",
            "awaited load-job session propagation",
        ),
        (
            "model",
            "await parent.target?.fileModel.onSelectedFiles(evt, sessionId);",
            "awaited web-file command",
        ),
        (
            "model",
            "await fileModel.close(closingSessionId);",
            "central file-model close",
        ),
        (
            "desktop",
            "final drives = await controller.listWindowsDrives(\n"
            "                            expectedSessionId: expectedSessionId);",
            "desktop owned drive lookup",
        ),
        (
            "desktop",
            "jobController.removeJob(\n                                      expectedSessionId, item.id);",
            "desktop exact job removal",
        ),
        (
            "mobile",
            "model.jobController.clearForSession(expectedSessionId);",
            "mobile exact job cleanup",
        ),
        (
            "mobile",
            "final SessionID expectedSessionId;",
            "mobile file-view owner",
        ),
        (
            "mobile",
            "expectedSessionId: expectedSessionId);",
            "mobile explicit command owner",
        ),
        (
            "desktop",
            "if (!mounted ||\n"
            "                                !_ffi.isCurrentSession(expectedSessionId)) {\n"
            "                              return;\n"
            "                            }\n"
            "                            selectedItems.clear();",
            "desktop send post-await owner check",
        ),
    ):
        require(sources[source_key], needle, label)

    for source_key, label in (
        ("mobile", "mobile file-page wakelock finality"),
        ("desktop", "desktop file-page wakelock finality"),
    ):
        page_state = extract_braced_item(
            sources[source_key],
            "class _FileManagerPageState",
            f"{label} state",
        )
        page_dispose = extract_braced_item(
            page_state,
            "void dispose()",
            f"{label} dispose",
        )
        require_order(
            page_dispose,
            (
                "WakelockManager.disable(_uniqueKey);",
                "unawaited(() async {",
            ),
            label,
        )
    for needle, label in (
        (
            "key: const ValueKey('local-file-manager'),",
            "mobile local-controller view owner",
        ),
        (
            "key: const ValueKey('remote-file-manager'),",
            "mobile remote-controller view owner",
        ),
        ("{super.key,", "mobile keyed file-view constructor"),
    ):
        require(sources["mobile"], needle, label)

    web_send = extract_braced_item(
        sources["web"], "Future<void> webSendLocalFiles(", "web file dispatch"
    )
    require(web_send, "required bool isRemote}) async {", "immediate web dispatch")
    require(web_send, "js.context.callMethod('setByName'", "web bridge command")
    forbid(web_send, "return Future(", "detached web command")
    web_picker = extract_braced_item(
        sources["web"], "Future<void> webselectFiles(", "web file picker"
    )
    require(web_picker, "required bool is_folder}) async {", "immediate web picker")
    require(web_picker, "js.context.callMethod('setByName'", "web picker bridge command")
    forbid(web_picker, "return Future(", "detached web picker")
    require(
        sources["desktop"],
        "if (!isCurrentSession) return;\n"
        "                        await webselectFiles(\n"
        "                            is_folder: isUploadFolder.value);\n"
        "                        if (!isCurrentSession) return;",
        "desktop awaited exact-session web picker",
    )

    test = sources["test"]
    for needle, label in (
        (
            "retired send continuation cannot target replacement session",
            "retired-send regression",
        ),
        (
            "send operation snapshots entries and directory arguments at admission",
            "immutable command regression",
        ),
        (
            "job result requires exact session action and file before completion",
            "job-result correlation regression",
        ),
        (
            "retirement completes an exact pending job result with an error",
            "job-result retirement regression",
        ),
        (
            "exact job error is caller-visible instead of successful completion",
            "job-error terminal regression",
        ),
        (
            "dispatch failure wins over an early matching success response",
            "dispatch-versus-response regression",
        ),
        (
            "timed-out late result remains owned until dispatch settles",
            "timed-out dispatch-drain regression",
        ),
        (
            "load-last-job cannot resume after its session is replaced",
            "load-job retirement regression",
        ),
        ("expect(calls, hasLength(1));", "no-retarget assertion"),
        ("'path': '/source/two'", "immutable source assertion"),
        ("'to': '/destination/two'", "immutable destination assertion"),
        ("expect(resumeCalls, 0);", "no-stale-resume assertion"),
        ("expect(resultCompleted, isFalse);", "dispatch-drain assertion"),
    ):
        require(test, needle, label)

    for source_key, needle, label in (
        (
            "dart_verify",
            "flutter test --no-pub test/file_command_session_ownership_test.dart",
            "Dart behavior gate",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11hm</span>',
            "R-S11hm requirement",
        ),
        (
            "requirements",
            "complete its owner with a caller-visible error, never as successful deletion",
            "job-error requirement",
        ),
        (
            "requirements",
            "transaction deadline remains live until both bridge dispatch and the exact response settle",
            "dispatch-and-response terminal requirement",
        ),
        ("requirements", "<tr><td>373</td>", "Appendix C #373"),
        (
            "hardening",
            "### R-S11hm/R-S11e-250 — exact-session file-command and job-result ownership",
            "hardening ledger",
        ),
        (
            "verify",
            "python3 scripts/verify-file-command-session-ownership.py --repo . --self-test",
            "shared focused gate",
        ),
        (
            "apple",
            "python3 scripts/verify-file-command-session-ownership.py --repo . --self-test",
            "Apple focused gate",
        ),
        (
            "workspace",
            '            "file_command_session_ownership_verifier": (\n'
            '                repo / "scripts/verify-file-command-session-ownership.py"\n'
            '            ).read_text(encoding="utf-8"),',
            "independent verifier source binding",
        ),
        (
            "workspace",
            "    validate_file_command_session_ownership_contract(sources)\n",
            "independent validator dispatch",
        ),
    ):
        require(sources[source_key], needle, label)

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
        "final GetDialogManager getDialogManager;\n"
        "  final IsCurrentSession isCurrentSession;\n"
        "  final GetPeerPlatform getPeerPlatform;",
        "final GetDialogManager getDialogManager;\n"
        "  final GetPeerPlatform getPeerPlatform;",
        "session authority",
    ),
    (
        "file_model",
        "final entries = items.items\n"
        "        .map(_FileOperationEntry.fromEntry)\n"
        "        .toList(growable: false);",
        "final entries = items.items.toList();",
        "entry snapshot",
    ),
    ("file_model", "await _requests.sendFiles(selectedSessionId,", "await _requests.sendFiles(sessionId,", "send owner"),
    ("file_model", "jobController.dispatchAndWaitForResult(", "_requests.removeFile(", "reserve-before-dispatch result"),
    (
        "file_model",
        "class JobResultListener {\n"
        "  JobResultListener(\n"
        "      {this.maxPending = 64,",
        "class JobResultListener {\n"
        "  JobResultListener(\n"
        "      {this.maxPending = 6400,",
        "result capacity",
    ),
    ("file_model", "if (_pending.length >= maxPending)", "if (_pending.length > maxPending)", "capacity refusal"),
    ("file_model", "_pending[key] = pending;\n    pending.startTimeout", "pending.startTimeout", "reservation publication"),
    (
        "file_model",
        "final fileNum = JobController._eventInt(event['file_num']);\n"
        "    if (actionId == null || fileNum == null) return false;\n"
        "    final key = _JobResultKey(expectedSessionId, actionId, fileNum);",
        "final fileNum = JobController._eventInt(event['file_num']);\n"
        "    if (actionId == null || fileNum == null) return false;\n"
        "    final key = _JobResultKey(getSessionID(), actionId, fileNum);",
        "result session identity",
    ),
    (
        "file_model",
        "bool tryComplete(\n"
        "      SessionID expectedSessionId, Map<String, dynamic> event) {\n"
        "    final actionId = JobController._eventInt(event['id'], positive: true);\n"
        "    final fileNum = JobController._eventInt(event['file_num']);",
        "bool tryComplete(\n"
        "      SessionID expectedSessionId, Map<String, dynamic> event) {\n"
        "    final actionId = JobController._eventInt(event['id'], positive: true);\n"
        "    final fileNum = 0;",
        "result file identity",
    ),
    ("file_model", "jobResultListener.tryCompleteError(expectedSessionId, evt);", "jobResultListener.tryComplete(expectedSessionId, evt);", "job-error finality"),
    ("file_model", "_responseValue = value;", "_done.complete(value);", "response waits for dispatch"),
    (
        "file_model",
        "bool markLateResponseReceived() {\n"
        "    if (!_done.isCompleted || _responseReceived) return false;\n"
        "    _responseReceived = true;\n"
        "    return true;\n"
        "  }",
        "bool markLateResponseReceived() {\n"
        "    if (!_done.isCompleted || _responseReceived) return false;\n"
        "    return true;\n"
        "  }",
        "late response dispatch-drain retention",
    ),
    (
        "file_model",
        "final error = event['err'];\n"
        "    if (actionId == null || fileNum == null || error is! String) return false;\n"
        "    final key = _JobResultKey(expectedSessionId, actionId, fileNum);\n"
        "    final pending = _pending[key];\n"
        "    if (pending == null) return false;\n"
        "    if (pending.isCompleted) {\n"
        "      _retainLateResponseUntilDispatchSettles(key, pending);",
        "final error = event['err'];\n"
        "    if (actionId == null || fileNum == null || error is! String) return false;\n"
        "    final key = _JobResultKey(expectedSessionId, actionId, fileNum);\n"
        "    final pending = _pending[key];\n"
        "    if (pending == null) return false;\n"
        "    if (pending.isCompleted) {\n"
        "      pending.markLateResponseReceived();",
        "late error dispatch-drain path",
    ),
    (
        "file_model",
        "void complete(Map<String, dynamic> value) {\n"
        "    if (_done.isCompleted) return;\n"
        "    _responseReceived = true;\n"
        "    _responseValue = value;\n"
        "    _completeResponseIfDispatchSettled();\n"
        "  }\n\n"
        "  void completeError(Object error, [StackTrace? stackTrace]) {\n"
        "    if (_done.isCompleted) return;\n"
        "    _timer?.cancel();",
        "void complete(Map<String, dynamic> value) {\n"
        "    if (_done.isCompleted) return;\n"
        "    _responseReceived = true;\n"
        "    _responseValue = value;\n"
        "    _completeResponseIfDispatchSettled();\n"
        "  }\n\n"
        "  void completeError(Object error, [StackTrace? stackTrace]) {\n"
        "    if (_done.isCompleted) return;\n"
        "    // timer retained",
        "terminal-error timer finality",
    ),
    ("file_model", "_ownedSessionId = null;\n    final eventLoopClose = evtLoop.close();", "final eventLoopClose = evtLoop.close();", "synchronous retirement"),
    ("model", "await fileModel.close(closingSessionId);", "unawaited(fileModel.close(closingSessionId));", "central close ordering"),
    ("model", "await parent.target?.fileModel.onSelectedFiles(evt, sessionId);", "parent.target?.fileModel.onSelectedFiles(evt, sessionId);", "awaited web command"),
    ("web", "required bool isRemote}) async {", "required bool isRemote}) {", "immediate web dispatch"),
    (
        "web",
        "Future<void> webselectFiles({required bool is_folder}) async {\n"
        "  js.context.callMethod('setByName', ['select_files', is_folder]);\n"
        "}",
        "Future<void> webselectFiles({required bool is_folder}) {\n"
        "  return Future(() =>\n"
        "      js.context.callMethod('setByName', ['select_files', is_folder]));\n"
        "}",
        "immediate web picker",
    ),
    (
        "desktop",
        "final drives = await controller.listWindowsDrives(\n"
        "                            expectedSessionId: expectedSessionId);",
        "final drives = controller.directory.value.entries;",
        "drive ownership",
    ),
    (
        "desktop",
        "if (!isCurrentSession) return;\n"
        "                        await webselectFiles(\n"
        "                            is_folder: isUploadFolder.value);\n"
        "                        if (!isCurrentSession) return;",
        "if (!isCurrentSession) return;\n"
        "                        webselectFiles(\n"
        "                            is_folder: isUploadFolder.value);",
        "web picker session finality",
    ),
    (
        "mobile",
        "void dispose() {\n"
        "    WakelockManager.disable(_uniqueKey);\n"
        "    unawaited(() async {",
        "void dispose() {\n"
        "    unawaited(() async {",
        "mobile file-page wakelock finality",
    ),
    (
        "mobile",
        "key: const ValueKey('local-file-manager'),",
        "key: const ValueKey('shared-file-manager'),",
        "mobile controller-specific view owner",
    ),
    (
        "desktop",
        "void dispose() {\n"
        "    WakelockManager.disable(_uniqueKey);\n"
        "    unawaited(() async {",
        "void dispose() {\n"
        "    unawaited(() async {",
        "desktop file-page wakelock finality",
    ),
    ("mobile", "final SessionID expectedSessionId;", "", "mobile file-view owner"),
    (
        "desktop",
        "if (!mounted ||\n"
        "                                !_ffi.isCurrentSession(expectedSessionId)) {\n"
        "                              return;\n"
        "                            }\n"
        "                            selectedItems.clear();",
        "selectedItems.clear();",
        "desktop post-await owner check",
    ),
    ("test", "retired send continuation cannot target replacement session", "retired send continuation targets replacement session", "retired-send regression"),
    ("test", "job result requires exact session action and file before completion", "job result accepts anonymous completion", "correlation regression"),
    ("test", "exact job error is caller-visible instead of successful completion", "job error is successful completion", "job-error regression"),
    ("test", "dispatch failure wins over an early matching success response", "early response hides dispatch failure", "dispatch-failure regression"),
    ("test", "timed-out late result remains owned until dispatch settles", "timed-out late result releases dispatch owner", "timed-out dispatch-drain regression"),
    ("test", "expect(resumeCalls, 0);", "expect(resumeCalls, 1);", "stale-resume assertion"),
    ("dart_verify", "flutter test --no-pub test/file_command_session_ownership_test.dart", "true # file-command test disabled", "Dart gate"),
    ("requirements", '<span class="id">R-S11hm</span>', '<span class="id">R-S11hm-disabled</span>', "requirement"),
    ("requirements", "complete its owner with a caller-visible error, never as successful deletion", "may complete as success", "job-error requirement"),
    ("requirements", "transaction deadline remains live until both bridge dispatch and the exact response settle", "response may finish before dispatch", "dispatch-and-response requirement"),
    ("requirements", "<tr><td>373</td>", "<tr><td>373-disabled</td>", "Appendix row"),
    ("hardening", "R-S11hm/R-S11e-250 — exact-session file-command and job-result ownership", "R-S11hm-disabled/R-S11e-250 — exact-session file-command and job-result ownership", "hardening ledger"),
    ("verify", "python3 scripts/verify-file-command-session-ownership.py --repo . --self-test", "true # file-command verifier disabled", "shared gate"),
    ("apple", "python3 scripts/verify-file-command-session-ownership.py --repo . --self-test", "true # file-command verifier disabled", "Apple gate"),
    ("workspace", "    validate_file_command_session_ownership_contract(sources)\n", "    validate_file_command_session_ownership_contract_disabled(sources)\n", "independent dispatch"),
)


def run_self_test(sources: Dict[str, str]) -> None:
    for key, old, new, label in MUTATIONS:
        count = sources[key].count(old)
        if count != 1:
            raise VerificationError(
                f"self-test fixture for {label} occurs {count} time(s): {old!r}"
            )
        mutated = dict(sources)
        mutated[key] = mutated[key].replace(old, new, 1)
        try:
            validate(mutated)
        except VerificationError:
            continue
        raise VerificationError(f"self-test failed to detect {label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    repo = args.repo.resolve()
    sources = load_sources(repo)
    ast.parse(sources["workspace"], filename="verify-verifier-workspace.py")
    validate(sources)
    if args.self_test:
        run_self_test(sources)
    print("file-command exact-session ownership: OK")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, VerificationError, SyntaxError) as error:
        print(f"file-command exact-session ownership: FAIL: {error}")
        raise SystemExit(1)
