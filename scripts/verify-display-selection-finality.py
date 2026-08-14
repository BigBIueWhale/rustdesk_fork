#!/usr/bin/env python3
"""Verify exact-owner, ordered, bounded Flutter display-selection finality."""

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
    cursor = 0
    for needle in needles:
        position = source.find(needle, cursor)
        if position < 0:
            raise VerificationError(f"{label}: missing or misordered {needle!r}")
        cursor = position + len(needle)


def extract_braced_item(source: str, signature: str, label: str) -> str:
    start = source.find(signature)
    if start < 0:
        raise VerificationError(f"missing {label}")
    open_brace = -1
    parentheses = signature.count("(") - signature.count(")")
    brackets = signature.count("[") - signature.count("]")
    for offset in range(start + len(signature), len(source)):
        character = source[offset]
        if character == "(":
            parentheses += 1
        elif character == ")":
            parentheses -= 1
        elif character == "[":
            brackets += 1
        elif character == "]":
            brackets -= 1
        elif character == "{" and parentheses == 0 and brackets == 0:
            open_brace = offset
            break
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
    raise VerificationError(f"unterminated {label}")


def extract_between(source: str, start: str, end: str, label: str) -> str:
    start_at = source.find(start)
    if start_at < 0:
        raise VerificationError(f"missing start of {label}: {start!r}")
    end_at = source.find(end, start_at + len(start))
    if end_at < 0:
        raise VerificationError(f"missing end of {label}: {end!r}")
    return source[start_at:end_at]


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "client": "src/client.rs",
        "io_loop": "src/client/io_loop.rs",
        "ui_session": "src/ui_session_interface.rs",
        "flutter": "src/flutter.rs",
        "ffi": "src/flutter_ffi.rs",
        "server": "src/server/connection.rs",
        "common_dart": "flutter/lib/common.dart",
        "model_dart": "flutter/lib/models/model.dart",
        "selection_queue_dart": "flutter/lib/models/display_selection_queue.dart",
        "selection_queue_test": "flutter/test/display_selection_queue_test.dart",
        "toolbar_dart": "flutter/lib/desktop/widgets/remote_toolbar.dart",
        "remote_dart": "flutter/lib/mobile/pages/remote_page.dart",
        "camera_dart": "flutter/lib/mobile/pages/view_camera_page.dart",
        "web_dart": "flutter/lib/web/bridge.dart",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "native_watch": "docs/NATIVE-CODEC-WATCH.md",
        "verify": "scripts/verify.sh",
        "dart_verify": "scripts/dart-verify.sh",
        "apple": "scripts/apple-conform-check.sh",
        "workspace": "scripts/verify-verifier-workspace.py",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def validate(sources: Dict[str, str]) -> None:
    client = sources["client"]
    io_loop = sources["io_loop"]
    ui_session = sources["ui_session"]
    flutter = sources["flutter"]
    ffi = sources["ffi"]
    server = sources["server"]

    refresh = extract_braced_item(
        client,
        "pub(crate) enum DisplaySelectionRefresh",
        "typed display-selection refresh plan",
    )
    require_order(
        refresh,
        ("All,", "Displays(Box<[usize]>)"),
        "legacy/exact refresh plan with exact retained storage",
    )

    switch = extract_braced_item(
        client,
        "pub(crate) struct DisplaySelectionSwitch",
        "typed display-selection switch",
    )
    require_order(
        switch,
        ("display: i32", "width: i32", "height: i32"),
        "minimal switch fields",
    )

    command = extract_braced_item(
        client, "pub struct DisplaySelectionCommand", "typed display-selection command"
    )
    require_order(
        command,
        (
            "switch_display: Option<DisplaySelectionSwitch>",
            "capture_set: Box<[i32]>",
            "refresh: Option<DisplaySelectionRefresh>",
        ),
        "fixed typed command fields",
    )
    for forbidden in (
        "Option<SwitchDisplay>",
        "Message",
        "Vec<Message>",
        "VecDeque",
        "Sender",
        "Receiver",
    ):
        forbid(command, forbidden, "ambient/generic command field")

    constructor = extract_braced_item(
        client, "fn validated(", "display-selection command validation"
    )
    require_order(
        constructor,
        (
            "if capture_set.is_empty()",
            "capture_set.len() > MAX_PEER_VIDEO_DISPLAYS",
            "usize::try_from(*display)",
            "display_index >= MAX_PEER_VIDEO_DISPLAYS",
            "!capture_seen.insert(display_index)",
            "if let Some(switch)",
            "!capture_seen.contains(&display_index)",
            "switch.width > DISPLAY_SELECTION_MAX_DIMENSION",
            "Some(DisplaySelectionRefresh::All)",
            "Some(DisplaySelectionRefresh::Displays(displays))",
            "if displays.is_empty()",
            "displays.len() > DISPLAY_SELECTION_MAX_REFRESH_TARGETS",
            "!capture_seen.contains(display)",
            "!refresh_seen.insert(*display)",
            "Some(DisplaySelectionRefresh::Displays(displays))",
            "capture_set: capture_set.into_boxed_slice()",
        ),
        "bounded protocol-representable command construction",
    )

    payload = extract_braced_item(client, "fn payload_bytes(&self)", "command byte accounting")
    require_order(
        payload,
        (
            ".checked_mul(std::mem::size_of::<i32>())",
            ".checked_mul(std::mem::size_of::<usize>())",
            "capture_storage.checked_add(refresh_storage)?",
            "switch_message(*switch).compute_size()",
            "capture_message(&self.capture_set).compute_size()",
            "LoginConfigHandler::refresh().compute_size()",
            "LoginConfigHandler::refresh_display(*display).compute_size()",
        ),
        "retained-heap and wire-work checked accounting",
    )
    require(
        client,
        "fn r_s11go_display_selection_command_is_shape_and_byte_bounded()",
        "command shape/accounting regression",
    )
    reservation = extract_braced_item(
        client,
        "fn send_with_commit<F>(",
        "viewer-command reservation transaction",
    )
    require_order(
        reservation,
        (
            "let command_permit = match self.commands.try_reserve()",
            "try_acquire_many_owned(permit_count)",
            "commit();",
            "command_permit.send(QueuedViewerCommand",
        ),
        "reserve bytes, commit local ownership, then publish",
    )
    require(
        client,
        "fn r_s11go_display_selection_commit_precedes_network_visibility()",
        "commit-before-publication regression",
    )
    require(
        client,
        "fn r_s11go_display_selection_refusal_does_not_commit_local_ownership()",
        "admission-refusal preserves local ownership regression",
    )

    generic_branch = extract_between(
        io_loop,
        "Data::Message(msg) => {",
        "Data::DisplaySelection(command) => {",
        "generic viewer command branch",
    )
    require_order(
        generic_branch,
        (
            "is_video_refresh_message(&msg)",
            "return false;",
            "is_display_control_message(&msg)",
            "return false;",
        ),
        "generic refresh/display-control refusal",
    )
    selection_branch = extract_braced_item(
        io_loop,
        "Data::DisplaySelection(command) =>",
        "sole network-loop display-selection branch",
    )
    require_order(
        selection_branch,
        (
            "let (switch_display, capture_set, refresh) = command.into_parts();",
            "if let Some(switch_display)",
            "switch_message(switch_display)",
            "peer.send(&message).await",
            "capture_message(&capture_set)",
            "peer.send(&message).await",
            "DisplaySelectionRefresh::All",
            "ViewerVideoRefreshRequest::All",
            "DisplaySelectionRefresh::Displays(displays)",
            "ViewerVideoRefreshRequest::Display(display)",
        ),
        "switch-capture-refresh transport order",
    )
    for forbidden in (
        "tokio::spawn",
        "Runtime::",
        "thread::sleep",
        "time::sleep",
        "retry",
        "reconnect",
        "Data::Message",
        "Vec<Message>",
    ):
        forbid(selection_branch, forbidden, "display-selection bypass/background work")

    typed_capture = extract_braced_item(
        ui_session, "pub fn try_capture_displays", "typed capture maintenance sender"
    )
    require_order(
        typed_capture,
        (
            "DisplaySelectionCommand::capture_set(set)?",
            "self.try_send(Data::DisplaySelection(command))",
        ),
        "typed capture maintenance admission",
    )
    typed_selection = extract_braced_item(
        ui_session, "pub fn try_select_displays", "typed selection sender"
    )
    require_order(
        typed_selection,
        (
            "switch_display: Option<i32>",
            "capture_set: Vec<i32>",
            "refresh: DisplaySelectionRefresh",
            "commit: F",
            "get_custom_resolution(display)",
            "Some(DisplaySelectionSwitch::new(display, width, height))",
            "DisplaySelectionCommand::selection(switch_display, capture_set, refresh)?",
            "send_display_selection_with_commit(command, commit)",
        ),
        "typed selection construction and exact-round admission",
    )
    forbid(ui_session, "pub fn switch_display(&self", "generic switch-display sender")
    forbid(ui_session, "pub fn capture_displays(&self", "generic capture-display sender")

    validation = extract_braced_item(
        flutter, "fn validate_display_selection", "live peer-inventory validation"
    )
    require_order(
        validation,
        (
            "if value.is_empty()",
            "let peer_info = session.ui_handler.peer_info.read().unwrap();",
            "let display_count = peer_info.displays.len();",
            "if value.len() > display_count",
            "usize::try_from(*display)",
            "if display >= display_count",
            "if !seen.insert(display)",
        ),
        "nonempty distinct current-inventory validation",
    )
    refresh_region = extract_between(
        flutter,
        "fn ordered_display_selection_refresh(",
        "pub fn session_switch_display(",
        "cross-platform ordered refresh selection",
    )
    require_order(
        refresh_region,
        (
            "is_support_multi_ui_session_num",
            "DisplaySelectionRefresh::Displays(displays.to_vec().into_boxed_slice())",
            "DisplaySelectionRefresh::All",
        ),
        "exact-capable and legacy refresh policy",
    )
    forbid(refresh_region, "#[cfg", "platform-specific refresh omission")

    selection = extract_braced_item(
        flutter, "pub fn session_switch_display(", "exact-owner display selection"
    )
    require_order(
        selection,
        (
            "session_handlers.write().unwrap()",
            "handler.client_owner_id.as_ref() != Some(&client_owner_id)",
            "let displays = validate_display_selection(s, &value)?;",
            "remaining_displays(Some(&session_id), &write_lock)?",
            "capture_set.extend(value.iter().copied())",
            "let refresh = ordered_display_selection_refresh(s, &displays);",
            "s.try_select_displays(switch_display, capture_set, refresh, || {",
            "handler.displays = displays;",
            ".retire_rgba_displays_except(&session_id, &value);",
        ),
        "exact owner/union/reservation/local-commit/publication ordering",
    )
    forbid(selection, "is_desktop", "caller-selected platform/union policy")
    startup = extract_braced_item(
        flutter, "pub fn session_add_existed(", "existing-window startup admission"
    )
    require_order(
        startup,
        (
            "let result = sessions::replace_peer_session_display_owner(",
            "drop(owner_admission);",
            "result",
        ),
        "startup exact-owner replacement admission",
    )
    replacement = extract_braced_item(
        flutter,
        "pub fn replace_peer_session_display_owner(",
        "existing-window atomic owner replacement",
    )
    require_order(
        replacement,
        (
            "let validated_displays = validate_display_selection(s, &displays)?;",
            "let mut handlers = s.ui_handler.session_handlers.write().unwrap();",
            "remaining_displays(Some(&session_id), &handlers)?",
            "h.displays = validated_displays;",
            "s.try_select_displays(None, capture_set, refresh, || {",
            "handlers.insert(session_id, h);",
            ".retire_rgba_displays_except(&session_id, &displays);",
        ),
        "reserve before replacing the old UI owner and publishing startup capture",
    )
    for retired in (
        "pub fn insert_peer_session_id(",
        "pub fn session_capture_displays(",
        "pub fn ensure_display_selection_committed(",
        "sessions::remove_session_by_session_id(&session_id)",
    ):
        forbid(flutter, retired, "staged/rollback startup surface")
    require(
        flutter,
        "fn r_s11go_display_selection_is_exact_owned_ordered_and_commit_after_admission()",
        "exact-owner selection regression",
    )
    require(
        flutter,
        "assert_eq!(handler.client_owner_id, Some(current_owner));",
        "failed owner replacement preserves its predecessor regression",
    )

    ffi_switch = extract_braced_item(
        ffi, "pub fn session_switch_display(", "fallible display-selection FFI"
    )
    require_order(
        ffi_switch,
        (
            "session_id: SessionID",
            "client_owner_id: SessionID",
            "value: Vec<i32>",
            ") -> ResultType<()>",
            "sessions::session_switch_display(session_id, client_owner_id, value)",
        ),
        "connection and UI-owner FFI capability",
    )
    forbid(ffi_switch, "is_desktop", "caller-selected platform/union FFI flag")
    forbid(ffi, "pub fn session_start_with_displays(", "second startup capture FFI")

    owner_helper = extract_braced_item(
        sources["model_dart"],
        "bool isCurrentSessionOwner(",
        "immutable Dart session/owner predicate",
    )
    require_order(
        owner_helper,
        (
            "SessionID expectedSessionId",
            "SessionID expectedClientOwnerId",
            "isCurrentSession(expectedSessionId)",
            "clientOwnerId == expectedClientOwnerId",
        ),
        "Dart session/owner conjunction",
    )
    dart_selection = extract_braced_item(
        sources["common_dart"],
        "Future<bool> selectRemoteDisplays(",
        "awaited Dart display selection",
    )
    require_order(
        dart_selection,
        (
            "final expectedClientOwnerId = ffi.clientOwnerId;",
            "display < -0x80000000 || display > 0x7fffffff",
            "final requestedDisplays = Int32List.fromList(displays);",
            "return ffi.submitDisplaySelection(",
            "expectedSessionId, expectedClientOwnerId",
            "() async {",
            "ffi.isCurrentSessionOwner(",
            "await bind.sessionSwitchDisplay(",
            "clientOwnerId: expectedClientOwnerId",
            "value: requestedDisplays",
            "ffi.isCurrentSessionOwner(",
            "return false;",
            "return ffi.isCurrentSessionOwner(",
        ),
        "Dart pre/post-await exact owner proof",
    )
    forbid(dart_selection, "isDesktop:", "Dart-selected native platform/union policy")
    queue = extract_braced_item(
        sources["selection_queue_dart"],
        "class DisplaySelectionQueue",
        "bounded Dart display-selection sequencer",
    )
    require_order(
        queue,
        (
            "DisplaySelectionQueue(this.owner);",
            "final Owner owner;",
            "_DisplaySelectionEntry? _running;",
            "_DisplaySelectionEntry? _pending;",
            "bool _retired = false;",
            "Owner expectedOwner",
            "if (_retired || expectedOwner != owner)",
            "if (_running == null)",
            "unawaited(_drain());",
            "_pending?.complete(false);",
            "_pending = entry;",
            "bool retire(Owner expectedOwner)",
            "if (expectedOwner != owner)",
            "_retired = true;",
            "_running?.complete(false);",
            "_pending?.complete(false);",
            "final admitted = await entry.operation();",
            "entry.complete(_retired ? false : admitted);",
            "if (_retired)",
            "_running = null;",
            "_running = _pending;",
            "_pending = null;",
        ),
        "exact-owner one-running/one-latest-pending Dart admission order",
    )
    owner = extract_braced_item(
        sources["model_dart"],
        "class _DisplaySelectionOwner",
        "immutable Dart display-selection owner",
    )
    require_order(
        owner,
        (
            "final SessionID sessionId;",
            "final SessionID clientOwnerId;",
            "other is _DisplaySelectionOwner",
            "sessionId == other.sessionId",
            "clientOwnerId == other.clientOwnerId",
            "Object.hash(sessionId, clientOwnerId)",
        ),
        "display-selection owner value identity",
    )
    submit_selection = extract_braced_item(
        sources["model_dart"],
        "Future<bool> submitDisplaySelection(",
        "owner-bound Dart display-selection submission",
    )
    require_order(
        submit_selection,
        (
            "SessionID expectedSessionId",
            "SessionID expectedClientOwnerId",
            "_DisplaySelectionOwner(expectedSessionId, expectedClientOwnerId)",
            "if (expectedOwner != _displaySelectionOwner)",
            "return Future.value(false);",
            "_displaySelections.submit(expectedOwner, operation)",
        ),
        "exact-pair display-selection submission",
    )
    install_owner = extract_braced_item(
        sources["model_dart"],
        "void _installDisplaySelectionOwner(",
        "fresh Dart display-selection owner installation",
    )
    require_order(
        install_owner,
        (
            "_DisplaySelectionOwner(nextSessionId, clientOwnerId)",
            "_displaySelectionOwner = nextOwner;",
            "_displaySelections = DisplaySelectionQueue(nextOwner);",
        ),
        "fresh exact-pair queue installation",
    )
    retire_owner = extract_braced_item(
        sources["model_dart"],
        "void _retireDisplaySelectionOwner(",
        "exact Dart display-selection owner retirement",
    )
    require_order(
        retire_owner,
        (
            "_DisplaySelectionOwner(retiringSessionId, clientOwnerId)",
            "if (!_displaySelections.retire(retiringOwner))",
            "throw StateError(",
        ),
        "fail-closed exact-pair queue retirement",
    )
    mobile_start = extract_between(
        sources["model_dart"],
        "if (isMobile) {\n      final previousSessionId = sessionId;",
        "final activeSessionId = sessionId;",
        "mobile display-selection owner rotation",
    )
    require_order(
        mobile_start,
        (
            "final previousSessionId = sessionId;",
            "_retireDisplaySelectionOwner(previousSessionId);",
            "mobileReset(previousSessionId);",
            "sessionId = Uuid().v4obj();",
            "_installDisplaySelectionOwner(sessionId);",
        ),
        "retire-old/reset/rotate/install before mobile connection start",
    )
    close = extract_braced_item(
        sources["model_dart"],
        "Future<void> close(",
        "Dart exact-session close",
    )
    require_order(
        close,
        (
            "final closingSessionId = expectedSessionId ?? sessionId;",
            "if (closingSessionId == sessionId)",
            "closed = true;",
            "_retireDisplaySelectionOwner(closingSessionId);",
            "if (sessionId != closingSessionId)",
        ),
        "current exact-session queue retirement before asynchronous close",
    )
    stream_failure = extract_braced_item(
        sources["model_dart"],
        "void _reportSessionStreamFailure(",
        "Dart stream-failure finality",
    )
    require_order(
        stream_failure,
        (
            "if (!isCurrentSession(expectedSessionId))",
            "closed = true;",
            "_retireDisplaySelectionOwner(expectedSessionId);",
            "dialogManager.dismissAll();",
            "unawaited(_closeNativeSession(expectedSessionId));",
        ),
        "stream failure retires exact display-selection owner before UI/native cleanup",
    )
    expected_close = extract_between(
        sources["model_dart"],
        'if (message.field0 == "close") {',
        "debugPrint('Exit session event loop');",
        "Dart expected stream-close finality",
    )
    require_order(
        expected_close,
        (
            "streamFinality.acceptExpectedClose();",
            "if (sessionId == activeSessionId)",
            "closed = true;",
            "_retireDisplaySelectionOwner(activeSessionId);",
        ),
        "expected stream close retires exact display-selection owner",
    )
    require(
        sources["selection_queue_test"],
        "keeps one running display selection and only the latest successor",
        "bounded latest-wins display-selection regression",
    )
    require(
        sources["selection_queue_test"],
        "a stale owner cannot enter the display selection sequencer",
        "stale owner refusal regression",
    )
    require(
        sources["selection_queue_test"],
        "a retired session cannot block its replacement session",
        "retired/replacement session independence regression",
    )
    require(
        sources["requirements"],
        '<div class="req"><span class="id">R-S11gp</span>',
        "R-S11gp normative owner-lifetime requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>351</td>",
        "Appendix C #351 disposition",
    )
    require(
        sources["hardening"],
        "### R-S11gp/R-S11e-228 — exact-session display-selection queue lifetime",
        "R-S11gp hardening ledger",
    )
    same_tab = extract_braced_item(
        sources["common_dart"],
        "Future<bool> openMonitorInTheSameTab(",
        "same-tab local display commit",
    )
    require_order(
        same_tab,
        (
            "final expectedSessionId = ffi.sessionId;",
            "if (!await selectRemoteDisplays(ffi, expectedSessionId, displays))",
            "ffi.imageModel.clearImage();",
            "ffi.ffiModel.switchToNewDisplay(",
            "return true;",
        ),
        "native admission before image/display mutation",
    )
    startup_dart = extract_between(
        sources["model_dart"],
        "if (!displays.contains(display)",
        "_listenToSessionStream(stream, activeSessionId, id, tabWindowId, display);",
        "existing-window Dart startup",
    )
    require_order(
        startup_dart,
        (
            "!displays.contains(display)",
            "candidate < -0x80000000 || candidate > 0x7fffffff",
            "final requestedDisplays = Int32List.fromList(displays);",
            "final addRes = bind.sessionAddExistedSync(",
            "displays: requestedDisplays",
            "if (addRes != '')",
            "return activeSessionId;",
            "ffiModel.pi.currentDisplay = display;",
            "stream = bind.sessionStart(",
        ),
        "startup admission before local display commit and stream attach",
    )
    forbid(startup_dart, "sessionStartWithDisplays", "second Dart startup capture")
    forbid(sources["model_dart"], "bind.sessionSwitchDisplay(", "unawaited model display switch")
    require(
        sources["model_dart"],
        "await handleSyncPeerInfo(evt, sessionId, peerId);",
        "awaited live-topology selection event",
    )
    require(
        sources["model_dart"],
        "await handleFollowCurrentDisplay(evt, sessionId, peerId);",
        "awaited follow-display selection event",
    )
    for key in ("toolbar_dart", "remote_dart", "camera_dart"):
        require(sources[key], "await openMonitorInTheSameTab", f"{key} awaited selection")
    web_selection = extract_braced_item(
        sources["web_dart"],
        "Future<void> sessionSwitchDisplay(",
        "web compatibility display-selection signature",
    )
    require_order(
        web_selection,
        (
            "required UuidValue sessionId",
            "required UuidValue clientOwnerId",
            "required Int32List value",
        ),
        "web compatibility owner-shaped signature",
    )
    forbid(
        web_selection,
        "required bool isDesktop",
        "web caller-selected platform/union policy",
    )
    forbid(
        sources["web_dart"],
        "sessionStartWithDisplays",
        "web second startup-capture surface",
    )

    capture_policy = extract_braced_item(
        server,
        "fn capture_display_has_exactly_one_operation",
        "controlled capture operation policy",
    )
    require_order(
        capture_policy,
        (
            "!displays.add.is_empty()",
            "!displays.sub.is_empty()",
            "!displays.set.is_empty()",
            "== 1",
        ),
        "exactly one capture operation",
    )
    controlled = extract_between(
        server,
        "Some(misc::Union::SwitchDisplay(s)) => {",
        "Some(misc::Union::RestartRemoteDevice(_)) => {",
        "controlled display-control receive branches",
    )
    require_order(
        controlled,
        (
            "if !self.handle_switch_display(s).await",
            "return false;",
            "if !capture_display_has_exactly_one_operation(&displays)",
            "return false;",
            "validate_peer_display_indexes_syntax",
            "return false;",
            "validate_peer_display_indexes(",
            "return false;",
            "if !self.capture_displays(&add, &sub, &set).await",
            "return false;",
            "Some(misc::Union::RefreshVideoDisplay(display))",
            "validate_peer_display_index(display, \"refresh video display\")",
            "return false;",
            "if !self.refresh_video_display(Some(display))",
            "return false;",
        ),
        "invalid controlled display request terminates its round",
    )
    switch_handler = extract_braced_item(
        server, "async fn handle_switch_display", "controlled switch validation"
    )
    require_order(
        switch_handler,
        (
            "if !switch_display_resolution_is_well_formed(s.width, s.height)",
            "return false;",
            "validate_peer_display_index(s.display, \"switch display\")",
            "return false;",
            "switch display server owner is no longer active",
            "return false;",
            "true",
        ),
        "controlled switch fail-stop validation",
    )
    require(
        server,
        "fn r_s11go_controlled_display_requests_are_exact_or_terminal()",
        "controlled display validation regression",
    )
    refresh_handler = extract_braced_item(
        server, "fn refresh_video_display", "controlled refresh execution"
    )
    require_order(
        refresh_handler,
        (
            "-> bool",
            "let Some(server) = self.server.upgrade() else",
            "return false;",
            "set_video_service_opt(",
            "true",
        ),
        "controlled refresh requires its live server owner",
    )
    capture_handler = extract_braced_item(
        server, "async fn capture_displays", "controlled capture execution"
    )
    require_order(
        capture_handler,
        (
            "-> bool",
            "capture display server owner is no longer active",
            "return false;",
            "lock.capture_displays(",
            "true",
        ),
        "controlled capture requires its live server owner",
    )

    for key, needle, label in (
        (
            "requirements",
            '<div class="req"><span class="id">R-S11go</span>',
            "R-S11go requirement",
        ),
        (
            "requirements",
            "one sequencer per live connection/UI-owner pair retaining exactly one running request and at most the latest pending request",
            "normative bounded multi-worker bridge sequencing",
        ),
        ("requirements", "<tr><td>350</td>", "Appendix C #350"),
        (
            "hardening",
            "### R-S11go/R-S11e-227 — ordered exact-owner display-selection finality",
            "R-S11go hardening ledger",
        ),
        (
            "verify",
            "python3 scripts/verify-display-selection-finality.py --repo . --self-test",
            "shared focused gate",
        ),
        (
            "dart_verify",
            "python3 scripts/verify-display-selection-finality.py --repo . --self-test",
            "generated-bridge focused gate",
        ),
        (
            "dart_verify",
            "flutter test --no-pub test/display_selection_queue_test.dart",
            "generated-bridge bounded display-selection test gate",
        ),
        (
            "dart_verify",
            'display_selection_line="$(grep -nF "  Future<void> sessionSwitchDisplay("',
            "generated display-selection shape check",
        ),
        (
            "dart_verify",
            "display selection is not a normal worker-pool bridge call",
            "generated display-selection worker-mode check",
        ),
        (
            "apple",
            "python3 scripts/verify-display-selection-finality.py --repo . --self-test",
            "Apple/shared focused gate",
        ),
        (
            "workspace",
            '"display_selection_finality_verifier": (',
            "independent verifier source binding",
        ),
        (
            "workspace",
            "validate_display_selection_finality_contract(sources)",
            "independent verifier dispatch",
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
        raise VerificationError("independent workspace validate_sources function is absent")
    dispatches = [
        node
        for node in validate_sources_function.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "validate_display_selection_finality_contract"
    ]
    if len(dispatches) != 1:
        raise VerificationError(
            "independent display-selection validator must have one direct runtime dispatch"
        )

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
    ("client", "Displays(Box<[usize]>)", "Displays(Vec<usize>)", "exact refresh storage"),
    ("client", "pub(crate) struct DisplaySelectionSwitch", "pub(crate) struct SwitchDisplay", "minimal typed switch"),
    ("client", "capture_set: Box<[i32]>", "capture_set: Vec<Message>", "typed capture field"),
    ("client", "if capture_set.is_empty()", "if false", "nonempty capture set"),
    ("client", "!capture_seen.insert(display_index)", "false", "duplicate capture refusal"),
    ("client", "!capture_seen.contains(&display_index)", "false", "switch/capture coherence"),
    ("client", "    All,\n    Displays(Box<[usize]>)", "    AllDisabled,\n    Displays(Box<[usize]>)", "legacy refresh plan"),
    ("client", "!refresh_seen.insert(*display)", "false", "duplicate refresh refusal"),
    ("client", "capture_set: capture_set.into_boxed_slice()", "capture_set: capture_set.into()", "exact retained capture storage"),
    ("client", "capture_storage.checked_add(refresh_storage)?", "capture_storage", "checked byte addition"),
    ("client", "fn r_s11go_display_selection_command_is_shape_and_byte_bounded()", "fn display_selection_command_is_shape_and_byte_bounded()", "command regression"),
    ("client", "let command_permit = match self.commands.try_reserve()", "let command_permit = match self.commands.try_send(())", "queue-slot reservation"),
    ("client", "commit();\n        command_permit.send(QueuedViewerCommand", "command_permit.send(QueuedViewerCommand", "local commit before publication"),
    ("client", "fn r_s11go_display_selection_commit_precedes_network_visibility()", "fn display_selection_commit_precedes_network_visibility()", "commit-before-publication regression"),
    ("client", "fn r_s11go_display_selection_refusal_does_not_commit_local_ownership()", "fn display_selection_refusal_does_not_commit_local_ownership()", "admission refusal preserves local ownership"),
    ("io_loop", "if is_display_control_message(&msg)", "if false", "generic display refusal"),
    ("io_loop", "switch_message(switch_display)", "capture_message(&capture_set)", "switch order"),
    ("io_loop", "DisplaySelectionRefresh::All", "DisplaySelectionRefresh::Displays", "legacy execution"),
    ("ui_session", "DisplaySelectionCommand::capture_set(set)?", "DisplaySelectionCommand::selection(None, set, refresh)?", "typed maintenance capture"),
    ("ui_session", "send_display_selection_with_commit(command, commit)", "send(Data::DisplaySelection(command))", "reserved selection commit"),
    ("flutter", "if value.is_empty()", "if false", "nonempty live selection"),
    ("flutter", "let peer_info = session.ui_handler.peer_info.read().unwrap();", "let peer_info = session.lc.read().unwrap();", "current native display inventory"),
    ("flutter", "if !seen.insert(display)", "if false", "duplicate live selection"),
    ("flutter", "DisplaySelectionRefresh::All", "DisplaySelectionRefresh::Displays(Vec::new().into_boxed_slice())", "cross-version refresh"),
    ("flutter", "handler.client_owner_id.as_ref() != Some(&client_owner_id)", "false", "exact UI owner"),
    ("flutter", "remaining_displays(Some(&session_id), &write_lock)?", "value.clone()", "native cross-owner display union"),
    ("flutter", "s.try_select_displays(switch_display, capture_set, refresh, || {", "if true {", "reserved admission before local commit"),
    ("flutter", "pub fn replace_peer_session_display_owner(", "pub fn insert_peer_session_id(", "atomic startup owner replacement"),
    ("flutter", "s.try_select_displays(None, capture_set, refresh, || {", "if true {", "startup reservation before replacement"),
    ("flutter", "assert_eq!(handler.client_owner_id, Some(current_owner));", "assert_eq!(handler.client_owner_id, Some(replacement_owner));", "failed replacement preserves predecessor"),
    ("flutter", "fn r_s11go_display_selection_is_exact_owned_ordered_and_commit_after_admission()", "fn display_selection_is_exact_owned_ordered_and_commit_after_admission()", "selection regression"),
    ("ffi", "pub fn session_switch_display(\n    session_id: SessionID,\n    client_owner_id: SessionID,", "pub fn session_switch_display(\n    is_desktop: bool,\n    session_id: SessionID,\n    client_owner_id: SessionID,", "FFI native union ownership"),
    ("ffi", "sessions::session_switch_display(session_id, client_owner_id, value)", "sessions::session_switch_display(session_id, SessionID::default(), value)", "FFI owner capability"),
    ("ffi", "pub fn session_get_remember", "pub fn session_start_with_displays() {}\n\npub fn session_get_remember", "retired second startup capture"),
    ("common_dart", "final expectedClientOwnerId = ffi.clientOwnerId;", "final expectedClientOwnerId = Uuid().v4obj();", "Dart captured owner"),
    ("common_dart", "display < -0x80000000 || display > 0x7fffffff", "display < 0", "Dart exact i32 representation"),
    ("common_dart", "final requestedDisplays = Int32List.fromList(displays);", "final requestedDisplays = displays;", "Dart invocation-time selection snapshot"),
    ("common_dart", "return ffi.submitDisplaySelection(\n      expectedSessionId, expectedClientOwnerId, () async {", "return Future<bool>(() async {", "bounded Dart admission sequencing"),
    ("model_dart", "!displays.contains(display)", "false", "startup selected-display coherence"),
    ("model_dart", "candidate < -0x80000000 || candidate > 0x7fffffff", "candidate < 0", "startup exact i32 representation"),
    ("model_dart", "final requestedDisplays = Int32List.fromList(displays);", "final requestedDisplays = displays;", "startup invocation-time selection snapshot"),
    ("common_dart", "if (!await selectRemoteDisplays(ffi, expectedSessionId, displays))", "if (false)", "Dart await before commit"),
    ("common_dart", "await bind.sessionSwitchDisplay(", "await bind.sessionSwitchDisplay(isDesktop: isDesktop,", "Dart native-union authority"),
    ("model_dart", "clientOwnerId == expectedClientOwnerId", "true", "Dart owner recheck"),
    ("selection_queue_dart", "if (_retired || expectedOwner != owner)", "if (_retired)", "exact queue owner admission"),
    ("selection_queue_dart", "_pending?.complete(false);", "_pending = null;", "latest pending supersession"),
    ("selection_queue_dart", "_running?.complete(false);", "// retired running caller retained", "running caller retirement"),
    ("selection_queue_dart", "entry.complete(_retired ? false : admitted);", "entry.complete(admitted);", "post-operation retirement decision"),
    ("model_dart", "if (expectedOwner != _displaySelectionOwner)", "if (false)", "FFI exact queue owner admission"),
    ("model_dart", "_retireDisplaySelectionOwner(previousSessionId);\n      mobileReset(previousSessionId);", "mobileReset(previousSessionId);", "mobile predecessor queue retirement"),
    ("model_dart", "sessionId = Uuid().v4obj();\n      _installDisplaySelectionOwner(sessionId);", "sessionId = Uuid().v4obj();", "mobile replacement queue installation"),
    ("model_dart", "closed = true;\n      _retireDisplaySelectionOwner(closingSessionId);", "closed = true;", "current-session close queue retirement"),
    ("model_dart", "closed = true;\n    _retireDisplaySelectionOwner(expectedSessionId);", "closed = true;", "stream-failure queue retirement"),
    ("model_dart", "closed = true;\n              _retireDisplaySelectionOwner(activeSessionId);", "closed = true;", "expected stream-close queue retirement"),
    ("selection_queue_test", "keeps one running display selection and only the latest successor", "runs all pending display selections", "bounded display-selection regression"),
    ("selection_queue_test", "a stale owner cannot enter the display selection sequencer", "a stale owner enters the display selection sequencer", "stale owner regression"),
    ("selection_queue_test", "a retired session cannot block its replacement session", "a retired session blocks its replacement session", "replacement independence regression"),
    ("model_dart", "await handleSyncPeerInfo(evt, sessionId, peerId);", "handleSyncPeerInfo(evt, sessionId, peerId);", "awaited topology selection"),
    ("model_dart", "await handleFollowCurrentDisplay(evt, sessionId, peerId);", "handleFollowCurrentDisplay(evt, sessionId, peerId);", "awaited follow-display selection"),
    ("model_dart", "    stream = bind.sessionStart(\n        sessionId: activeSessionId", "    stream = bind.sessionStartWithDisplays(\n        sessionId: activeSessionId", "single startup admission"),
    ("web_dart", "Future<void> sessionSwitchDisplay(\n      {required UuidValue sessionId,\n      required UuidValue clientOwnerId,", "Future<void> sessionSwitchDisplay(\n      {required UuidValue sessionId,\n      required bool isDesktop,", "web owner capability"),
    ("web_dart", "Future<bool?> sessionGetRemember", "Stream<EventToUI> sessionStartWithDisplays() => Stream.empty();\n\n  Future<bool?> sessionGetRemember", "web retired startup surface"),
    ("server", "== 1", ">= 1", "exact controlled capture operation"),
    ("server", "if !self.handle_switch_display(s).await", "if false", "terminal invalid switch"),
    ("server", "switch display server owner is no longer active", "switch display server owner absence is ignored", "terminal missing switch owner"),
    ("server", "if !self.capture_displays(&add, &sub, &set).await", "if false", "terminal capture execution failure"),
    ("server", "capture display server owner is no longer active", "capture display server owner absence is ignored", "terminal missing capture owner"),
    ("server", "fn refresh_video_display(&self, display: Option<usize>) -> bool", "fn refresh_video_display(&self, display: Option<usize>)", "terminal refresh execution failure"),
    ("server", "validate_peer_display_index(display, \"refresh video display\")", "Some(display as usize)", "terminal invalid exact refresh"),
    ("server", "fn r_s11go_controlled_display_requests_are_exact_or_terminal()", "fn controlled_display_requests_are_exact_or_terminal()", "controlled regression"),
    ("requirements", '<div class="req"><span class="id">R-S11go</span>', '<div class="req"><span class="id">R-S11go-disabled</span>', "normative requirement"),
    ("requirements", "one sequencer per live connection/UI-owner pair retaining exactly one running request and at most the latest pending request", "an unbounded per-UI-owner sequencer", "normative bounded multi-worker bridge sequencing"),
    ("requirements", "<tr><td>350</td>", "<tr><td>350-disabled</td>", "Appendix disposition"),
    ("requirements", '<div class="req"><span class="id">R-S11gp</span>', '<div class="req"><span class="id">R-S11gp-disabled</span>', "exact queue lifetime requirement"),
    ("requirements", "<tr><td>351</td>", "<tr><td>351-disabled</td>", "exact queue lifetime Appendix disposition"),
    ("hardening", "### R-S11go/R-S11e-227 — ordered exact-owner display-selection finality", "### R-S11go-disabled/R-S11e-227 — ordered exact-owner display-selection finality", "hardening ledger"),
    ("hardening", "### R-S11gp/R-S11e-228 — exact-session display-selection queue lifetime", "### R-S11gp-disabled/R-S11e-228 — exact-session display-selection queue lifetime", "exact queue lifetime ledger"),
    ("verify", "python3 scripts/verify-display-selection-finality.py --repo . --self-test", "python3 scripts/verify-display-selection-finality.py --repo .", "shared gate"),
    ("dart_verify", "python3 scripts/verify-display-selection-finality.py --repo . --self-test", "python3 scripts/verify-display-selection-finality.py --repo .", "generated gate"),
    ("dart_verify", "flutter test --no-pub test/display_selection_queue_test.dart", "true # display selection queue test disabled", "generated bounded display-selection test gate"),
    ("dart_verify", "display selection is not a normal worker-pool bridge call", "display selection worker mode is unchecked", "generated display-selection worker-mode gate"),
    ("apple", "python3 scripts/verify-display-selection-finality.py --repo . --self-test", "python3 scripts/verify-display-selection-finality.py --repo .", "Apple gate"),
    ("workspace", '"display_selection_finality_verifier": (', '"display_selection_finality_verifier_disabled": (', "independent source binding"),
    ("workspace", "    validate_viewer_rgba_mailbox_contract(sources)\n    validate_display_selection_finality_contract(sources)\n    validate_desktop_texture_lifecycle_contract(sources)", "    validate_viewer_rgba_mailbox_contract(sources)\n    validate_display_selection_finality_contract_disabled(sources)\n    validate_desktop_texture_lifecycle_contract(sources)", "independent verifier dispatch"),
)


def run_self_test(sources: Dict[str, str]) -> None:
    for key, old, new, label in MUTATIONS:
        if old not in sources[key]:
            raise VerificationError(f"self-test fixture missing for {label}")
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
            "display selection finality verifier self-test passed "
            f"({len(MUTATIONS)} mutations)"
        )
    else:
        print("display selection finality verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"display selection finality verifier failed: {error}")
        raise SystemExit(1)
