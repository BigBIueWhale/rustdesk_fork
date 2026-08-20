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
        "session_queue_dart": "flutter/lib/models/session_event_queue.dart",
        "session_queue_test": "flutter/test/session_event_queue_test.dart",
        "frame_queue_dart": "flutter/lib/models/latest_frame_queue.dart",
        "frame_queue_test": "flutter/test/latest_frame_queue_test.dart",
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
    remaining = extract_braced_item(
        flutter, "fn remaining_displays(", "cross-owner capture authority"
    )
    require_order(
        remaining,
        (
            "let mut remains_displays = HashSet::new();",
            "for (k, h) in handlers.iter()",
            "if excluded == Some(k)",
            "remains_displays.extend(h.displays.iter().copied());",
            "i32::try_from(display)",
            "remains_displays.sort_unstable();",
        ),
        "capture union derives only committed native handler displays",
    )
    forbid(
        remaining,
        "map_display_sessions",
        "renderer resource keys as capture authority",
    )
    initial_owner = extract_braced_item(
        flutter, "fn bind_initial_display_owner(", "initial display-owner binding"
    )
    require_order(
        initial_owner,
        (
            "usize::try_from(current_display)",
            "if display >= display_count",
            ".flat_map(|handler| handler.displays.iter())",
            ".any(|owned_display| *owned_display >= display_count)",
            "handler.awaiting_initial_display.then_some(*session_id)",
            "if pending.len() > 1",
            "if handlers.is_empty() || handlers.values().any(|handler| handler.displays.is_empty())",
            "return Ok(());",
            "other_session_id != session_id && handler.displays.is_empty()",
            "let handler = handlers",
            ".get_mut(session_id)",
            "if !handler.displays.is_empty()",
            "handler.displays.push(display);",
            "handler.awaiting_initial_display = false;",
        ),
        "bounded fresh binding or reconnect preservation of explicit display ownership",
    )
    forbid(
        initial_owner,
        "handlers.values_mut()",
        "reconnect mutation of already-explicit display owners",
    )
    login_peer_info = sources["io_loop"].find(
        "Some(login_response::Union::PeerInfo(pi)) =>"
    )
    sync_peer_info = sources["io_loop"].find(
        "Some(message::Union::PeerInfo(pi)) =>", login_peer_info + 1
    )
    if login_peer_info < 0 or sync_peer_info < 0:
        raise VerificationError("missing initial/synchronized peer-information dispatch")
    require_order(
        sources["io_loop"][login_peer_info:sync_peer_info],
        (
            "let initial_display = pi.current_display;",
            "let pi = bound_peer_info(pi);",
            ".bind_initial_display_owner(initial_display, pi.displays.len())",
            "self.handler.on_error(&message);",
            "return false;",
            "self.set_peer_info(&pi);",
        ),
        "raw initial display authority before bounded peer-state consumption",
    )
    renderer_size = extract_braced_item(
        flutter, "fn set_owned_display_size(", "owned-display renderer sizing"
    )
    require_order(
        renderer_size,
        (
            "if !self.displays.contains(&display)",
            "return false;",
            "self.renderer.set_size(display, width, height);",
            "true",
        ),
        "renderer sizing requires committed display ownership",
    )
    session_size = extract_braced_item(
        flutter, "pub fn session_set_size(", "session renderer sizing"
    )
    require_order(
        session_size,
        (
            "client_owner_id: SessionID",
            "display: usize",
            "width: usize",
            "height: usize",
            "-> ResultType<()>",
            "s.ui_handler.set_exact_owned_display_size(",
            "&session_id",
            "&client_owner_id",
            "display",
            "width",
            "height",
            "if admitted",
            "return Ok(());",
            "bail!(",
        ),
        "result-bearing exact-owner renderer-size admission",
    )
    forbid(session_size, "h.displays.push(display)", "renderer-size-created capture authority")
    exact_owned_size = extract_braced_item(
        flutter,
        "fn set_exact_owned_display_size(",
        "exact-owner renderer sizing",
    )
    require_order(
        exact_owned_size,
        (
            "let handler = handlers.get_mut(session_id)?;",
            "if handler.client_owner_id.as_ref() != Some(client_owner_id)",
            "return Some(false);",
            "Some(handler.set_owned_display_size(display, width, height))",
        ),
        "renderer sizing requires the exact current UI owner",
    )
    ffi_size = extract_braced_item(ffi, "pub fn session_set_size(", "renderer-size FFI")
    require_order(
        ffi_size,
        (
            "client_owner_id: SessionID",
            "-> Result<()>",
            "super::flutter::session_set_size(session_id, client_owner_id, display, width, height)",
        ),
        "renderer-size FFI exact-owner forwarding",
    )
    dart_size_region = extract_between(
        sources["model_dart"],
        "Future<bool> updateCurDisplay(",
        "/// Handle the peer info event",
        "Dart exact-owner renderer sizing",
    )
    require_order(
        dart_size_region,
        (
            "final expectedClientOwnerId = ffi.clientOwnerId;",
            "ffi.isCurrentSessionOwner(sessionId, expectedClientOwnerId)",
            "await _updateSessionWidthHeight(sessionId, expectedClientOwnerId);",
            "SessionID sessionId",
            "SessionID expectedClientOwnerId",
            "async {",
        ),
        "Dart renderer sizing retains and rechecks the exact UI owner",
    )
    if dart_size_region.count("clientOwnerId: expectedClientOwnerId") != 2:
        raise VerificationError(
            "Dart renderer sizing must pass the exact UI owner in both display shapes"
        )
    if dart_size_region.count("await bind.sessionSetSize(") != 2:
        raise VerificationError(
            "Dart renderer sizing must await both bounded bridge-call shapes"
        )
    dart_peer_info = extract_between(
        sources["model_dart"],
        "Future<void> handlePeerInfo(",
        "Future<void> tryUseAllMyDisplaysForTheRemoteSession(",
        "Dart peer information",
    )
    require_order(
        dart_peer_info,
        (
            "final previousCurrentDisplay = _pi.currentDisplay;",
            "final restoreDisplaySelection = !isCache && _pi.isSet.value;",
            "final preserveDisplaySelection = isCache || restoreDisplaySelection;",
            "if (!preserveDisplaySelection &&",
            "_pi.currentDisplay = currentDisplay;",
            "_pi.displays.value = newDisplays;",
            "if (restoreDisplaySelection)",
            "previousCurrentDisplay == kAllDisplayValue",
            "List.generate(_pi.displays.length, (index) => index)",
            "!await selectRemoteDisplays(",
            "'The previous display selection could not be restored'",
            "if (_pi.currentDisplay < _pi.displays.length)",
            "await updateCurDisplay(",
        ),
        "established reconnect restores exact display selection before geometry",
    )
    web_size = extract_between(
        sources["web_dart"],
        "Future<void> sessionSetSize(",
        "\n  Future<void> sessionSendSelectedSessionId(",
        "web renderer sizing",
    )
    require_order(
        web_size,
        (
            "required UuidValue sessionId",
            "required UuidValue clientOwnerId",
        ),
        "web renderer-size exact-owner parity",
    )
    session_start = extract_between(
        flutter,
        "pub fn session_start_(",
        "\nfn rollback_failed_session_start",
        "exact-owner UI stream start",
    )
    require_order(
        session_start,
        (
            "let mut thread_lock = s.thread.lock().unwrap();",
            "let mut handlers = s.session_handlers.write().unwrap();",
            "if let Some(h) = handlers.get_mut(session_id)",
        ),
        "worker-slot before handler-owner session-start lock order",
    )
    start_admission = extract_braced_item(
        flutter,
        "fn admit_session_start(",
        "display-owned session-start admission",
    )
    require_order(
        start_admission,
        (
            "let starts_peer_connection =",
            "!has_ui_stream",
            "&& is_first_ui_session",
            "&& is_unselected_ui_session",
            "&& !is_awaiting_initial_display",
            "if is_video_session",
            "&& is_unselected_ui_session",
            "&& !starts_peer_connection",
            "&& !is_awaiting_initial_display",
            'bail!("Outgoing video UI session has no explicit display owner")',
            "Ok(starts_peer_connection)",
        ),
        "fresh, pending-marker, or explicit-owner session-start admission",
    )
    start_guard = extract_braced_item(
        session_start,
        "if let Some(h) = handlers.get_mut(session_id)",
        "exact-owner session-start critical section",
    )
    require_order(
        start_guard,
        (
            "h.client_owner_id.as_ref() != Some(client_owner_id)",
            'bail!("Outgoing session is not owned by the active mobile/desktop client owner")',
            "let starts_peer_connection = match admit_session_start(",
            "is_video_session",
            "h.event_stream.is_some()",
            "is_first_ui_session",
            "h.displays.is_empty()",
            "h.awaiting_initial_display",
            "Err(error)",
            "start_failure = Some(error);",
            "try_send_close_event(&h.event_stream);",
            "h.event_stream = Some(event_stream);",
            "if start_failure.is_none() && starts_peer_connection && is_video_session",
            "h.awaiting_initial_display = true;",
            "match s.start_io_thread_with_lock(&mut thread_lock)",
            "Ok(false)",
            "Err(error) => start_failure = Some(error.into())",
        ),
        "under-guard exact-owner and display-owned stream admission through peer-I/O start",
    )
    require_order(
        session_start,
        (
            "if let Some(error) = start_failure",
            "rollback_failed_session_start(session_id, client_owner_id);",
            "return Err(error);",
            ".replay_ready_rgba(session_id, client_owner_id)",
            "rollback_failed_session_start(session_id, client_owner_id);",
        ),
        "exact-owner failed-start and replay rollback",
    )
    require(
        flutter,
        "r_s11gt_capture_authority_excludes_renderer_resource_keys",
        "renderer-resource capture-authority exclusion regression",
    )
    require(
        flutter,
        "r_s11gt_reconnect_preserves_explicit_display_owners_without_rebinding",
        "reconnect display-owner preservation regression",
    )
    require(
        flutter,
        "r_s11gt_session_start_requires_fresh_or_explicit_display_authority",
        "display-owned session-start admission regression",
    )
    require(
        flutter,
        "r_s11gt_renderer_size_requires_exact_current_ui_owner",
        "renderer-size exact-owner regression",
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
        "class _SessionOwner",
        "immutable Dart session owner",
    )
    require_order(
        owner,
        (
            "final SessionID sessionId;",
            "final SessionID clientOwnerId;",
            "other is _SessionOwner",
            "sessionId == other.sessionId",
            "clientOwnerId == other.clientOwnerId",
            "Object.hash(sessionId, clientOwnerId)",
        ),
        "session owner value identity",
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
            "_SessionOwner(expectedSessionId, expectedClientOwnerId)",
            "if (expectedOwner != _sessionOwner)",
            "return Future.value(false);",
            "_displaySelections.submit(expectedOwner, operation)",
        ),
        "exact-pair display-selection submission",
    )
    install_owner = extract_braced_item(
        sources["model_dart"],
        "void _installSessionOwner(",
        "fresh Dart session owner installation",
    )
    require_order(
        install_owner,
        (
            "_SessionOwner(nextSessionId, clientOwnerId)",
            "_sessionOwner = nextOwner;",
            "_displaySelections = DisplaySelectionQueue(nextOwner);",
            "_sessionEvents = SessionEventQueue(nextOwner);",
            "_webRgbaFrames = LatestFrameQueue(nextOwner);",
        ),
        "fresh exact-pair queue installation",
    )
    retire_owner = extract_braced_item(
        sources["model_dart"],
        "void _retireSessionOwner(",
        "exact Dart session owner retirement",
    )
    require_order(
        retire_owner,
        (
            "_SessionOwner(retiringSessionId, clientOwnerId)",
            "_sessionEvents.retire(retiringOwner)",
            "_displaySelections.retire(retiringOwner)",
            "_webRgbaFrames.retire(retiringOwner)",
            "!sessionEventsRetired ||",
            "!displaySelectionsRetired ||",
            "!webRgbaFramesRetired",
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
            "_retireSessionOwner(previousSessionId);",
            "mobileReset(previousSessionId);",
            "sessionId = Uuid().v4obj();",
            "_installSessionOwner(sessionId);",
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
            "_retireSessionOwner(closingSessionId);",
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
            "_retireSessionOwner(expectedSessionId);",
            "dialogManager.dismissAll();",
            "unawaited(_closeNativeSession(expectedSessionId));",
        ),
        "stream failure retires exact display-selection owner before UI/native cleanup",
    )
    expected_close = extract_between(
        sources["model_dart"],
        "if (message.field0 == 'close') {",
        "debugPrint('Exit session event loop');",
        "Dart expected stream-close finality",
    )
    require_order(
        expected_close,
        (
            "streamFinality.acceptExpectedClose();",
            "sessionEvents.retire(streamOwner);",
            "if (isCurrentSessionOwner(",
            "closed = true;",
            "_retireSessionOwner(activeSessionId);",
        ),
        "expected stream close retires exact display-selection owner",
    )
    session_queue = extract_braced_item(
        sources["session_queue_dart"],
        "class SessionEventQueue",
        "bounded exact-owner session topology queue",
    )
    require_order(
        session_queue,
        (
            "SessionEventQueue(this.owner, {this.maxPending = 32})",
            "final Owner owner;",
            "final int maxPending;",
            "final Queue<_SessionEventEntry> _pending",
            "bool _retired = false;",
            "int _acceptedGeneration = 0;",
            "int _completedGeneration = 0;",
            "if (_retired || expectedOwner != owner)",
            "if (_pending.length >= maxPending)",
            "_retireCurrentAndPending();",
            "_SessionEventEntry(++_acceptedGeneration, operation)",
            "_pending.addLast(entry);",
            "SessionEventCheckpoint<Owner> checkpoint(",
            "final tail = _pending.isEmpty ? _running : _pending.last;",
            "tail?.done.future ?? Future.value(SessionEventDisposition.completed)",
            "bool isCurrent(SessionEventCheckpoint<Owner> checkpoint)",
            "checkpoint.generation == _acceptedGeneration",
            "_completedGeneration >= checkpoint.generation",
            "bool retire(Owner expectedOwner)",
            "await entry.operation();",
            "_completedGeneration = entry.generation;",
            "entry.complete(SessionEventDisposition.completed);",
            "entry.completeError(error, stackTrace);",
            "_retireCurrentAndPending();",
            "_running = _pending.isEmpty ? null : _pending.removeFirst();",
        ),
        "bounded FIFO/checkpoint/retirement session topology order",
    )
    queue_submit = extract_braced_item(
        sources["session_queue_dart"],
        "Future<SessionEventDisposition> submit(",
        "exact-owner session topology queue submission",
    )
    require_order(
        queue_submit,
        (
            "if (_retired || expectedOwner != owner)",
            "Future.value(SessionEventDisposition.retired)",
            "if (_pending.length >= maxPending)",
        ),
        "exact-owner session topology queue submission",
    )
    queue_checkpoint = extract_braced_item(
        sources["session_queue_dart"],
        "SessionEventCheckpoint<Owner> checkpoint(",
        "exact-owner media topology checkpoint",
    )
    require_order(
        queue_checkpoint,
        (
            "if (_retired || expectedOwner != owner)",
            "Future.value(SessionEventDisposition.retired)",
            "final tail = _pending.isEmpty ? _running : _pending.last;",
        ),
        "exact-owner media topology checkpoint",
    )
    for forbidden in ("Timer(", "Future.delayed(", "Isolate", "compute("):
        forbid(
            session_queue,
            forbidden,
            "timer/worker recovery in the session topology queue",
        )
    frame_queue = extract_braced_item(
        sources["frame_queue_dart"],
        "class LatestFrameQueue",
        "bounded exact-owner per-display frame queue",
    )
    require_order(
        frame_queue,
        (
            "LatestFrameQueue(this.owner, {this.maxKeys = 32})",
            "final Owner owner;",
            "final int maxKeys;",
            "final Map<Key, _LatestFrameLane<Frame>> _lanes = {};",
            "bool _retired = false;",
            "if (_retired || expectedOwner != owner)",
            "if (_lanes.length >= maxKeys)",
            "_retireAll();",
            "Future.error(StateError('frame display capacity exhausted'))",
            "_lanes[key] = lane;",
            "if (lane.running == null)",
            "unawaited(_drain(key, lane));",
            "lane.pending?.complete(LatestFrameDisposition.superseded);",
            "lane.pending = entry;",
            "bool retire(Owner expectedOwner)",
            "await entry.present(entry.frame);",
            "entry.completeError(error, stackTrace);",
            "_retireAll();",
            "lane.running = lane.pending;",
            "lane.pending = null;",
            "if (identical(_lanes[key], lane))",
            "_lanes.remove(key);",
        ),
        "exact-owner one-running/one-latest per-display frame order",
    )
    for forbidden in (
        "List<",
        "Timer(",
        "Future.delayed(",
        "Isolate",
        "compute(",
    ):
        forbid(
            frame_queue,
            forbidden,
            "unbounded/timed/worker web-frame recovery",
        )
    submit_session_event = extract_braced_item(
        sources["model_dart"],
        "Future<SessionEventDisposition> submitSessionEvent(",
        "exact-owner session topology submission",
    )
    require_order(
        submit_session_event,
        (
            "SessionID expectedSessionId",
            "SessionID expectedClientOwnerId",
            "_SessionOwner(expectedSessionId, expectedClientOwnerId)",
            "if (expectedOwner != _sessionOwner)",
            "Future.value(SessionEventDisposition.retired)",
            "_sessionEvents.submit(expectedOwner, operation)",
        ),
        "exact-owner session topology admission",
    )
    ordered_events = extract_braced_item(
        sources["model_dart"],
        "const _orderedSessionTopologyEvents",
        "closed ordered session topology event set",
    )
    require_order(
        ordered_events,
        (
            "'peer_info'",
            "'sync_peer_info'",
            "'sync_platform_additions'",
            "'switch_display'",
            "'follow_current_display'",
            "'use_texture_render'",
        ),
        "closed low-rate session topology event set",
    )
    event_listener = extract_braced_item(
        sources["model_dart"],
        "StreamEventHandler startEventListener(",
        "ordered session event callback",
    )
    require_order(
        event_listener,
        (
            "final expectedClientOwnerId = parent.target!.clientOwnerId;",
            "final operation = () => _handleSessionEvent(evt, sessionId, peerId);",
            "_orderedSessionTopologyEvents.contains(name)",
            "await ffi.submitSessionEvent(",
            "sessionId, expectedClientOwnerId, operation",
            "ffi._reportSessionStreamFailure(",
            "await operation();",
        ),
        "topology-only exact-owner event serialization",
    )
    platform_additions = extract_braced_item(
        sources["model_dart"],
        "Future<void> handlePlatformAdditions(",
        "platform-additions topology mutation",
    )
    require_order(
        platform_additions,
        (
            "_beginDisplayTopologyMutation(sessionId)",
            "if (topologyRevision == null) return;",
            "final updateData = evt['platform_additions'] as String?;",
            "cachedPeerData.peerInfo['platform_additions']",
        ),
        "platform additions invalidate in-flight media",
    )
    require(
        platform_additions,
        "final updateJson = json.decode(updateData) as Map<String, dynamic>;",
        "fallible platform-additions decode",
    )
    forbid(
        platform_additions,
        "catch (",
        "log-and-continue malformed platform additions",
    )
    local_switch = extract_braced_item(
        sources["model_dart"],
        "Future<bool> switchToNewDisplay(",
        "local display topology commit",
    )
    require_order(
        local_switch,
        (
            "if (expectedTopologyRevision == null)",
            "final expectedClientOwnerId = ffi.clientOwnerId;",
            "await ffi.submitSessionEvent(",
            "applied = await _applyDisplaySwitch(",
            "disposition == SessionEventDisposition.completed",
            "ffi.isCurrentSessionOwner(sessionId, expectedClientOwnerId)",
            "return _applyDisplaySwitch(",
        ),
        "local post-native display commit shares the topology lane",
    )
    stream_listener = extract_braced_item(
        sources["model_dart"],
        "void _listenToSessionStream(",
        "exact-owner session stream listener",
    )
    require_order(
        stream_listener,
        (
            "final streamOwner = _SessionOwner(activeSessionId, clientOwnerId);",
            "if (streamOwner != _sessionOwner)",
            "final sessionEvents = _sessionEvents;",
            "final cachedState = sessionEvents.submit(streamOwner, () async {",
            "await ffiModel.handleCachedPeerData(",
            "_observeQueuedSessionState(cachedState, activeSessionId, peerId);",
            "streamFinality.acceptExpectedClose();",
            "sessionEvents.retire(streamOwner);",
            "final decoded = json.decode(message.field0);",
            "decoded is! Map<String, dynamic>",
            "_reportSessionStreamFailure(activeSessionId, peerId,",
            "_handleSoftwareRgba(sessionEvents, streamOwner, activeSessionId,",
            "_handleTextureRgba(sessionEvents, streamOwner, activeSessionId,",
        ),
        "cached-state/event/media/terminal stream ordering",
    )
    forbid(
        stream_listener,
        "Future.delayed(Duration.zero",
        "detached cached-state continuation",
    )
    forbid(
        stream_listener,
        "      () async {",
        "detached per-message async session callback",
    )
    web_callback = extract_between(
        stream_listener,
        "if (isWeb) {",
        "final cb = ffiModel.startEventListener(activeSessionId, peerId);",
        "bounded live web RGBA callback",
    )
    require_order(
        web_callback,
        (
            "final webRgbaFrames = _webRgbaFrames;",
            "platformFFI.setRgbaCallback((int display, Uint8List data) {",
            "final ownedData = Uint8List.fromList(data);",
            "final frame = webRgbaFrames.submit(",
            "streamOwner,",
            "display,",
            "ownedData,",
            "(rgba) => _handleWebRgba(sessionEvents, streamOwner,",
            "unawaited(frame.then<void>",
            "_reportSessionStreamFailure(activeSessionId, peerId,",
        ),
        "synchronous buffer ownership before bounded asynchronous presentation",
    )
    for forbidden in (
        "_WebRgbaFrame",
        "_webRgbaList",
        "_webDecodingRgba",
        "webOnRgba(",
    ):
        forbid(
            sources["model_dart"],
            forbidden,
            "obsolete alternate web RGBA backlog",
        )
    topology_checkpoint = extract_braced_item(
        sources["model_dart"],
        "Future<int?> _displayTopologyAfterCheckpoint(",
        "media topology checkpoint",
    )
    require_order(
        topology_checkpoint,
        (
            "final checkpoint = sessionEvents.checkpoint(streamOwner);",
            "final disposition = await checkpoint.done;",
            "disposition != SessionEventDisposition.completed",
            "!sessionEvents.isCurrent(checkpoint)",
            "!isCurrentSessionOwner(activeSessionId, streamOwner.clientOwnerId)",
            "ffiModel.currentDisplayTopologyRevision(activeSessionId)",
        ),
        "capacity-free exact media topology checkpoint",
    )
    software_rgba = extract_braced_item(
        sources["model_dart"],
        "Future<void> _handleSoftwareRgba(",
        "checkpointed software RGBA presentation",
    )
    require_order(
        software_rgba,
        (
            "await _displayTopologyAfterCheckpoint(",
            "platformFFI.nextRgba(activeSessionId, display, publication);",
            "platformFFI.copyRgba(activeSessionId, display, publication)",
            "imageOwnsAcknowledgement = true;",
            "await imageModel.onRgba(",
            "publication: publication",
            "expectedDisplayTopologyRevision: topologyRevision",
            "await onEvent2UIRgba(",
            "imageGeometryInitialized: true",
        ),
        "checkpointed exact-publication RGBA presentation",
    )
    image_decode = extract_braced_item(
        sources["model_dart"],
        "Future<bool> decodeAndUpdate(",
        "topology-bound image decode",
    )
    require_order(
        image_decode,
        (
            "required int expectedDisplayTopologyRevision",
            "isCurrentDisplayTopology(",
            "final rect = parent.target?.ffiModel.pi.getDisplayRect(display);",
            "final image = await img.decodeImageFromPixels(",
            "isCurrentDisplayTopology(",
            "image.dispose();",
            "expectedDisplayTopologyRevision: expectedDisplayTopologyRevision",
        ),
        "pre/post-decode topology revision admission",
    )
    first_image = extract_braced_item(
        sources["model_dart"],
        "Future<bool> onEvent2UIRgba(",
        "single exact first-image initialization",
    )
    require_order(
        first_image,
        (
            "isCurrentDisplayTopology(",
            "final inProgress = _firstImageInitialization;",
            "if (inProgress != null)",
            "final initialization = _initializeFirstImage(",
            "_firstImageInitialization = initialization;",
            "if (identical(_firstImageInitialization, initialization))",
            "_firstImageInitialization = null;",
        ),
        "one exact in-flight first-image transaction",
    )
    require_order(
        first_image,
        (
            "final completed = await inProgress;",
            "if (completed) return true;",
            "continue;",
            "final initialization = _initializeFirstImage(",
        ),
        "stale first-image retry",
    )
    forbid(
        sources["model_dart"],
        "updateCurDisplay(sessionId);",
        "discarded current-display geometry future",
    )
    for needle, label in (
        (
            "runs bounded session-state work in native stream order",
            "FIFO/checkpoint behavior regression",
        ),
        (
            "media checkpoints neither consume capacity nor survive later state",
            "capacity-free stale-checkpoint regression",
        ),
        (
            "capacity failure retires running and queued session-state work",
            "bounded overflow finality regression",
        ),
        (
            "task failure is terminal and does not run retained successors",
            "task-failure finality regression",
        ),
        (
            "mismatched owners are refused before invocation",
            "exact-owner refusal regression",
        ),
        (
            "exact retirement cannot block a replacement session",
            "replacement-session independence regression",
        ),
    ):
        require(sources["session_queue_test"], needle, label)
    for needle, label in (
        (
            "retains one running frame and only the latest successor per display",
            "bounded latest-frame regression",
        ),
        ("different displays drain independently", "cross-display independence regression"),
        ("a failed frame retires its retained successor", "frame-failure finality regression"),
        (
            "owner mismatch and display overflow refuse frames before invocation",
            "frame owner/capacity regression",
        ),
        (
            "exact retirement releases retained frames and cannot block replacement",
            "frame retirement/replacement regression",
        ),
    ):
        require(sources["frame_queue_test"], needle, label)
    require(
        sources["requirements"],
        '<div class="req"><span class="id">R-S11gq</span>',
        "R-S11gq normative session topology ordering requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>352</td>",
        "Appendix C #352 disposition",
    )
    require(
        sources["hardening"],
        "### R-S11gq/R-S11e-229 — exact-session topology and presentation ordering",
        "R-S11gq hardening ledger",
    )
    require(
        sources["dart_verify"],
        "flutter test --no-pub test/session_event_queue_test.dart",
        "generated-bridge session topology queue behavior gate",
    )
    require(
        sources["requirements"],
        '<div class="req"><span class="id">R-S11gr</span>',
        "R-S11gr normative bounded web-frame requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>353</td>",
        "Appendix C #353 disposition",
    )
    require(
        sources["hardening"],
        "### R-S11gr/R-S11e-230 — bounded exact-session web frame ownership",
        "R-S11gr hardening ledger",
    )
    require(
        sources["dart_verify"],
        "flutter test --no-pub test/latest_frame_queue_test.dart",
        "generated-bridge bounded web-frame behavior gate",
    )
    require(
        sources["requirements"],
        '<div class="req"><span class="id">R-S11gs</span>',
        "R-S11gs normative native refresh-display authority requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>354</td>",
        "Appendix C #354 disposition",
    )
    require(
        sources["hardening"],
        "### R-S11gs/R-S11e-231 — exact-owner presentation-refresh display authority",
        "R-S11gs hardening ledger",
    )
    require(
        sources["requirements"],
        '<div class="req"><span class="id">R-S11gt</span>',
        "R-S11gt explicit native display-owner requirement",
    )
    require(
        sources["requirements"],
        "<tr><td>355</td>",
        "Appendix C #355 disposition",
    )
    require(
        sources["hardening"],
        "### R-S11gt/R-S11e-232 — explicit initial and ongoing native display ownership",
        "R-S11gt hardening ledger",
    )
    require(
        sources["verify"],
        "cargo test --lib --features linux-pkg-config,flutter r_s11gt_ --color never",
        "R-S11gt behavior-test wiring",
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
            "return ffi.ffiModel.switchToNewDisplay(",
            "i, expectedSessionId, ffi.id",
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
            "ffiModel._beginDisplayTopologyMutation(activeSessionId)",
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
        "await handlePlatformAdditions(evt, sessionId, peerId);",
        "awaited platform-additions topology event",
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
    ("flutter", "remains_displays.extend(h.displays.iter().copied());", "remains_displays.extend(h.displays.iter().copied());\n            remains_displays.extend(h.renderer.map_display_sessions.read().unwrap().keys().copied());", "renderer resources excluded from capture authority"),
    ("flutter", "fn bind_initial_display_owner(\n    handlers: &mut HashMap<SessionID, SessionHandler>,", "fn bind_initial_display_owner_disabled(\n    handlers: &mut HashMap<SessionID, SessionHandler>,", "initial display-owner binding"),
    ("flutter", "if handlers.is_empty() || handlers.values().any(|handler| handler.displays.is_empty())", "if false", "missing explicit initial display-owner refusal"),
    ("flutter", "if pending.len() > 1", "if false", "ambiguous initial display-owner refusal"),
    ("flutter", "other_session_id != session_id && handler.displays.is_empty()", "false", "unmarked empty initial display-owner refusal"),
    ("flutter", "if display >= display_count {\n        bail!(\n            \"initial peer display", "if display > display_count {\n        bail!(\n            \"initial peer display", "initial display inventory bound"),
    ("flutter", "handler.awaiting_initial_display = false;", "handler.awaiting_initial_display = true;", "one-time initial display-owner finality"),
    ("io_loop", "let initial_display = pi.current_display;", "let initial_display = 0;", "raw claimed initial display preservation"),
    ("io_loop", ".bind_initial_display_owner(initial_display, pi.displays.len())", ".bind_initial_display_owner(pi.current_display, pi.displays.len())", "initial display admission before normalized use"),
    ("flutter", "if !self.displays.contains(&display)", "if false", "renderer-size exact display ownership"),
    ("flutter", "let handler = handlers.get_mut(session_id)?;\n        if handler.client_owner_id.as_ref() != Some(client_owner_id)", "let handler = handlers.get_mut(session_id)?;\n        if false", "renderer size exact UI owner"),
    ("flutter", "s.ui_handler.set_exact_owned_display_size(\n            &session_id,\n            &client_owner_id,", "s.ui_handler.set_exact_owned_display_size(\n            &session_id,\n            &session_id,", "renderer size exact owner forwarding"),
    ("flutter", ") -> ResultType<()> {\n    for s in sessions::get_sessions() {\n        if let Some(admitted) = s.ui_handler.set_exact_owned_display_size(", ") {\n    for s in sessions::get_sessions() {\n        if let Some(admitted) = s.ui_handler.set_exact_owned_display_size(", "result-bearing renderer size admission"),
    ("ffi", "super::flutter::session_set_size(session_id, client_owner_id, display, width, height)", "super::flutter::session_set_size(session_id, session_id, display, width, height)", "renderer size FFI owner forwarding"),
    ("ffi", ") -> Result<()> {\n    super::flutter::session_set_size(session_id, client_owner_id, display, width, height)", ") {\n    super::flutter::session_set_size(session_id, client_owner_id, display, width, height)", "result-bearing renderer size FFI"),
    ("model_dart", "await _updateSessionWidthHeight(sessionId, expectedClientOwnerId);", "await _updateSessionWidthHeight(sessionId, sessionId);", "Dart renderer size owner propagation"),
    ("model_dart", "await bind.sessionSetSize(", "bind.sessionSetSize(", "awaited Dart renderer size finality"),
    ("model_dart", "clientOwnerId: expectedClientOwnerId", "clientOwnerId: sessionId", "Dart renderer size owner bridge argument"),
    ("model_dart", "final restoreDisplaySelection = !isCache && _pi.isSet.value;", "final restoreDisplaySelection = false;", "established reconnect display restoration"),
    ("model_dart", "if (!preserveDisplaySelection &&", "if (true &&", "reconnect display-state preservation"),
    ("model_dart", "!await selectRemoteDisplays(\n                ffi, expectedSessionId, reconnectDisplays)", "false", "awaited reconnect display restoration"),
    ("model_dart", "'The previous display selection could not be restored'", "'Reconnect display failure ignored'", "terminal reconnect display restoration failure"),
    ("web_dart", "Future<void> sessionSetSize(\n      {required UuidValue sessionId,\n      required UuidValue clientOwnerId", "Future<void> sessionSetSize(\n      {required UuidValue sessionId,\n      required UuidValue retiredClientOwnerId", "web renderer size owner parity"),
    ("flutter", "fn admit_session_start(\n    is_video_session: bool,", "fn admit_session_start_disabled(\n    is_video_session: bool,", "display-owned session-start admission"),
    ("flutter", "let starts_peer_connection = !has_ui_stream\n        && is_first_ui_session\n        && is_unselected_ui_session\n        && !is_awaiting_initial_display;", "let starts_peer_connection = !has_ui_stream\n        && is_first_ui_session\n        && !is_awaiting_initial_display;", "first unselected peer-connection start"),
    ("flutter", "&& is_unselected_ui_session\n        && !is_awaiting_initial_display;\n    if is_video_session", "&& is_unselected_ui_session;\n    if is_video_session", "pending initial owner cannot restart peer connection"),
    ("flutter", "&& !starts_peer_connection\n        && !is_awaiting_initial_display", "&& !starts_peer_connection\n        && false", "unselected video-route refusal"),
    ("flutter", "if let Some(h) = handlers.get_mut(session_id) {\n            if h.client_owner_id.as_ref() != Some(client_owner_id)", "if let Some(h) = handlers.get_mut(session_id) {\n            if false", "under-guard exact-owner stream admission"),
    ("flutter", "let mut thread_lock = s.thread.lock().unwrap();\n        let mut handlers = s.session_handlers.write().unwrap();", "let mut handlers = s.session_handlers.write().unwrap();\n        let mut thread_lock = s.thread.lock().unwrap();", "worker-slot before handler-owner lock order"),
    ("flutter", "match s.start_io_thread_with_lock(&mut thread_lock)", "match s.start_io_thread()", "peer-I/O start inside exact-owner guard"),
    ("flutter", ".any(|owned_display| *owned_display >= display_count)", ".any(|_| false)", "preserved display-owner inventory bound"),
    ("flutter", ".replay_ready_rgba(session_id, client_owner_id)", ".replay_ready_rgba(session_id, session_id)", "exact-owner stream replay"),
    ("flutter", "rollback_failed_session_start(session_id, client_owner_id);", "rollback_failed_session_start(session_id, session_id);", "exact-owner failed-start rollback"),
    ("flutter", "r_s11gt_capture_authority_excludes_renderer_resource_keys", "capture_authority_includes_renderer_resource_keys", "renderer-resource exclusion regression"),
    ("flutter", "r_s11gt_reconnect_preserves_explicit_display_owners_without_rebinding", "reconnect_implicitly_rebinds_display_owners", "reconnect display-owner preservation regression"),
    ("flutter", "r_s11gt_session_start_requires_fresh_or_explicit_display_authority", "session_start_accepts_unselected_existing_video_routes", "display-owned session-start regression"),
    ("flutter", "r_s11gt_renderer_size_requires_exact_current_ui_owner", "renderer_size_accepts_a_reused_session_id", "renderer-size exact-owner regression"),
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
    ("model_dart", "Future<bool> submitDisplaySelection(\n      SessionID expectedSessionId,\n      SessionID expectedClientOwnerId,\n      Future<bool> Function() operation) {\n    final expectedOwner =\n        _SessionOwner(expectedSessionId, expectedClientOwnerId);\n    if (expectedOwner != _sessionOwner)", "Future<bool> submitDisplaySelection(\n      SessionID expectedSessionId,\n      SessionID expectedClientOwnerId,\n      Future<bool> Function() operation) {\n    final expectedOwner =\n        _SessionOwner(expectedSessionId, expectedClientOwnerId);\n    if (false)", "exact-pair display-selection submission"),
    ("model_dart", "Future<SessionEventDisposition> submitSessionEvent(\n      SessionID expectedSessionId,\n      SessionID expectedClientOwnerId,\n      Future<void> Function() operation) {\n    final expectedOwner =\n        _SessionOwner(expectedSessionId, expectedClientOwnerId);\n    if (expectedOwner != _sessionOwner)", "Future<SessionEventDisposition> submitSessionEvent(\n      SessionID expectedSessionId,\n      SessionID expectedClientOwnerId,\n      Future<void> Function() operation) {\n    final expectedOwner =\n        _SessionOwner(expectedSessionId, expectedClientOwnerId);\n    if (false)", "exact-owner session topology submission"),
    ("session_queue_dart", "Future<SessionEventDisposition> submit(\n      Owner expectedOwner, Future<void> Function() operation) {\n    if (_retired || expectedOwner != owner)", "Future<SessionEventDisposition> submit(\n      Owner expectedOwner, Future<void> Function() operation) {\n    if (_retired)", "bounded FIFO/checkpoint/retirement session topology order"),
    ("session_queue_dart", "SessionEventCheckpoint<Owner> checkpoint(Owner expectedOwner) {\n    if (_retired || expectedOwner != owner)", "SessionEventCheckpoint<Owner> checkpoint(Owner expectedOwner) {\n    if (_retired)", "exact-owner media topology checkpoint"),
    ("session_queue_dart", "if (_pending.length >= maxPending)", "if (false)", "session topology capacity bound"),
    ("session_queue_dart", "_SessionEventEntry(++_acceptedGeneration, operation)", "_SessionEventEntry(_acceptedGeneration, operation)", "session topology accepted generation"),
    ("session_queue_dart", "_pending.addLast(entry);", "_pending.addFirst(entry);", "session topology FIFO retention"),
    ("session_queue_dart", "final tail = _pending.isEmpty ? _running : _pending.last;", "final tail = _running;", "media checkpoint observed tail"),
    ("session_queue_dart", "checkpoint.generation == _acceptedGeneration", "checkpoint.generation <= _acceptedGeneration", "stale media checkpoint rejection"),
    ("session_queue_dart", "_completedGeneration = entry.generation;", "_completedGeneration = _acceptedGeneration;", "exact completed topology generation"),
    ("session_queue_dart", "entry.completeError(error, stackTrace);\n          _retireCurrentAndPending();", "entry.completeError(error, stackTrace);", "session topology task-failure retirement"),
    ("frame_queue_dart", "if (_retired || expectedOwner != owner)", "if (_retired)", "exact-owner web-frame admission"),
    ("frame_queue_dart", "if (_lanes.length >= maxKeys) {\n        _retireAll();", "if (_lanes.length >= maxKeys) {", "terminal web-frame display bound"),
    ("frame_queue_dart", "final Map<Key, _LatestFrameLane<Frame>> _lanes = {};", "final List<_LatestFrameLane<Frame>> _lanes = [];", "per-display bounded web-frame lanes"),
    ("frame_queue_dart", "lane.pending?.complete(LatestFrameDisposition.superseded);", "lane.pending?.complete(LatestFrameDisposition.presented);", "superseded web-frame disposition"),
    ("frame_queue_dart", "lane.pending = entry;", "lane.running = entry;", "one-latest-pending web-frame bound"),
    ("frame_queue_dart", "entry.completeError(error, stackTrace);\n          _retireAll();", "entry.completeError(error, stackTrace);", "terminal web-frame operation failure"),
    ("frame_queue_dart", "if (identical(_lanes[key], lane))", "if (false)", "exact per-display lane retirement"),
    ("model_dart", "_sessionEvents = SessionEventQueue(nextOwner);", "_sessionEvents = SessionEventQueue(_SessionOwner(Uuid().v4obj(), clientOwnerId));", "fresh session topology owner"),
    ("model_dart", "final sessionEventsRetired = _sessionEvents.retire(retiringOwner);", "final sessionEventsRetired = true;", "session topology owner retirement"),
    ("model_dart", "_webRgbaFrames = LatestFrameQueue(nextOwner);", "_webRgbaFrames = LatestFrameQueue(_SessionOwner(Uuid().v4obj(), clientOwnerId));", "fresh exact-owner web-frame queue"),
    ("model_dart", "final webRgbaFramesRetired = _webRgbaFrames.retire(retiringOwner);", "final webRgbaFramesRetired = true;", "exact web-frame queue retirement"),
    ("model_dart", "_orderedSessionTopologyEvents.contains(name)", "false", "ordered topology event admission"),
    ("model_dart", "await ffi.submitSessionEvent(\n              sessionId, expectedClientOwnerId, operation);", "await operation();", "session topology callback serialization"),
    ("model_dart", "final disposition = await ffi.submitSessionEvent(\n            sessionId, expectedClientOwnerId, () async {", "final disposition = SessionEventDisposition.completed;\n        if (true) {", "local display commit serialization"),
    ("model_dart", "final cachedState = sessionEvents.submit(streamOwner, () async {", "final cachedState = Future.value(SessionEventDisposition.completed);\n        Future.delayed(Duration.zero, () async {", "cached-state stream ordering"),
    ("model_dart", "if (decoded is! Map<String, dynamic>)", "if (false)", "malformed session event finality"),
    ("model_dart", "final checkpoint = sessionEvents.checkpoint(streamOwner);", "final checkpoint = SessionEventCheckpoint.fake();", "media topology checkpoint"),
    ("model_dart", "!sessionEvents.isCurrent(checkpoint)", "false", "later topology invalidates media checkpoint"),
    ("model_dart", "return ffiModel.currentDisplayTopologyRevision(activeSessionId);", "return 0;", "media display-topology revision capture"),
    ("model_dart", "final ownedData = Uint8List.fromList(data);", "final ownedData = data;", "synchronous web callback buffer ownership"),
    ("model_dart", "final frame = webRgbaFrames.submit(", "final frame = Future.value(LatestFrameDisposition.presented);\n        _handleWebRgba(", "bounded live web-frame submission"),
    ("model_dart", "_reportSessionStreamFailure(activeSessionId, peerId,\n              'The remote session presentation became inconsistent');", "debugPrint('web frame failure ignored');", "visible web-frame failure finality"),
    ("model_dart", "Future<bool> decodeAndUpdate(\n      SessionID expectedSessionId, int display, Uint8List rgba,\n      {RgbaPublicationAdmission<SessionID>? expectedRgbaPublication,\n      required int expectedDisplayTopologyRevision}", "Future<bool> decodeAndUpdate(\n      SessionID expectedSessionId, int display, Uint8List rgba,\n      {RgbaPublicationAdmission<SessionID>? expectedRgbaPublication,\n      int expectedDisplayTopologyRevision = 0}", "required frame topology revision"),
    ("model_dart", "parent.target?.ffiModel.isCurrentDisplayTopology(\n            expectedSessionId, expectedDisplayTopologyRevision) !=", "false &&", "pre-decode topology admission"),
    ("model_dart", "final inProgress = _firstImageInitialization;", "final inProgress = null;", "single first-image initialization"),
    ("model_dart", "if (completed) return true;\n        continue;", "return completed;", "stale first-image retry"),
    ("session_queue_test", "runs bounded session-state work in native stream order", "runs session-state work out of order", "session topology FIFO regression"),
    ("session_queue_test", "media checkpoints neither consume capacity nor survive later state", "media checkpoints consume capacity", "media checkpoint regression"),
    ("session_queue_test", "capacity failure retires running and queued session-state work", "capacity failure retains queued session-state work", "session topology capacity regression"),
    ("session_queue_test", "task failure is terminal and does not run retained successors", "task failure runs retained successors", "session topology failure regression"),
    ("session_queue_test", "mismatched owners are refused before invocation", "mismatched owners may invoke work", "session topology exact-owner regression"),
    ("session_queue_test", "exact retirement cannot block a replacement session", "exact retirement blocks a replacement session", "session topology replacement regression"),
    ("frame_queue_test", "retains one running frame and only the latest successor per display", "retains an unbounded frame backlog", "bounded latest-frame regression"),
    ("frame_queue_test", "different displays drain independently", "different displays block each other", "cross-display frame regression"),
    ("frame_queue_test", "a failed frame retires its retained successor", "a failed frame runs its retained successor", "frame-failure finality regression"),
    ("frame_queue_test", "owner mismatch and display overflow refuse frames before invocation", "owner mismatch invokes frames", "frame owner/capacity regression"),
    ("frame_queue_test", "exact retirement releases retained frames and cannot block replacement", "exact retirement retains frames", "frame retirement/replacement regression"),
    ("model_dart", "_retireSessionOwner(previousSessionId);\n      mobileReset(previousSessionId);", "mobileReset(previousSessionId);", "mobile predecessor queue retirement"),
    ("model_dart", "sessionId = Uuid().v4obj();\n      _installSessionOwner(sessionId);", "sessionId = Uuid().v4obj();", "mobile replacement queue installation"),
    ("model_dart", "closed = true;\n      _retireSessionOwner(closingSessionId);", "closed = true;", "current-session close queue retirement"),
    ("model_dart", "closed = true;\n    _retireSessionOwner(expectedSessionId);", "closed = true;", "stream-failure queue retirement"),
    ("model_dart", "closed = true;\n            _retireSessionOwner(activeSessionId);", "closed = true;", "expected stream-close queue retirement"),
    ("selection_queue_test", "keeps one running display selection and only the latest successor", "runs all pending display selections", "bounded display-selection regression"),
    ("selection_queue_test", "a stale owner cannot enter the display selection sequencer", "a stale owner enters the display selection sequencer", "stale owner regression"),
    ("selection_queue_test", "a retired session cannot block its replacement session", "a retired session blocks its replacement session", "replacement independence regression"),
    ("model_dart", "await handleSyncPeerInfo(evt, sessionId, peerId);", "handleSyncPeerInfo(evt, sessionId, peerId);", "awaited topology selection"),
    ("model_dart", "await handlePlatformAdditions(evt, sessionId, peerId);", "handlePlatformAdditions(evt, sessionId, peerId);", "awaited platform-additions topology event"),
    ("model_dart", "final topologyRevision = _beginDisplayTopologyMutation(sessionId);\n    if (topologyRevision == null) return;\n    final updateData = evt['platform_additions'] as String?;", "const topologyRevision = 0;\n    final updateData = evt['platform_additions'] as String?;", "platform additions invalidate in-flight media"),
    ("model_dart", "final updateJson = json.decode(updateData) as Map<String, dynamic>;", "final updateJson = <String, dynamic>{};", "fallible platform-additions decode"),
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
    ("requirements", '<div class="req"><span class="id">R-S11gq</span>', '<div class="req"><span class="id">R-S11gq-disabled</span>', "session topology ordering requirement"),
    ("requirements", "<tr><td>352</td>", "<tr><td>352-disabled</td>", "session topology ordering Appendix disposition"),
    ("requirements", '<div class="req"><span class="id">R-S11gr</span>', '<div class="req"><span class="id">R-S11gr-disabled</span>', "bounded web-frame requirement"),
    ("requirements", "<tr><td>353</td>", "<tr><td>353-disabled</td>", "bounded web-frame Appendix disposition"),
    ("requirements", '<div class="req"><span class="id">R-S11gs</span>', '<div class="req"><span class="id">R-S11gs-disabled</span>', "native refresh-display authority requirement"),
    ("requirements", "<tr><td>354</td>", "<tr><td>354-disabled</td>", "native refresh-display authority Appendix disposition"),
    ("requirements", '<div class="req"><span class="id">R-S11gt</span>', '<div class="req"><span class="id">R-S11gt-disabled</span>', "explicit native display-owner requirement"),
    ("requirements", "<tr><td>355</td>", "<tr><td>355-disabled</td>", "explicit native display-owner Appendix disposition"),
    ("hardening", "### R-S11go/R-S11e-227 — ordered exact-owner display-selection finality", "### R-S11go-disabled/R-S11e-227 — ordered exact-owner display-selection finality", "hardening ledger"),
    ("hardening", "### R-S11gp/R-S11e-228 — exact-session display-selection queue lifetime", "### R-S11gp-disabled/R-S11e-228 — exact-session display-selection queue lifetime", "exact queue lifetime ledger"),
    ("hardening", "### R-S11gq/R-S11e-229 — exact-session topology and presentation ordering", "### R-S11gq-disabled/R-S11e-229 — exact-session topology and presentation ordering", "session topology ordering ledger"),
    ("hardening", "### R-S11gr/R-S11e-230 — bounded exact-session web frame ownership", "### R-S11gr-disabled/R-S11e-230 — bounded exact-session web frame ownership", "bounded web-frame ledger"),
    ("hardening", "### R-S11gs/R-S11e-231 — exact-owner presentation-refresh display authority", "### R-S11gs-disabled/R-S11e-231 — exact-owner presentation-refresh display authority", "native refresh-display authority ledger"),
    ("hardening", "### R-S11gt/R-S11e-232 — explicit initial and ongoing native display ownership", "### R-S11gt-disabled/R-S11e-232 — explicit initial and ongoing native display ownership", "explicit native display-owner ledger"),
    ("verify", "cargo test --lib --features linux-pkg-config,flutter r_s11gt_ --color never", "cargo test --lib --features linux-pkg-config,flutter disabled_ --color never", "explicit native display-owner behavior gate"),
    ("verify", "python3 scripts/verify-display-selection-finality.py --repo . --self-test", "python3 scripts/verify-display-selection-finality.py --repo .", "shared gate"),
    ("dart_verify", "python3 scripts/verify-display-selection-finality.py --repo . --self-test", "python3 scripts/verify-display-selection-finality.py --repo .", "generated gate"),
    ("dart_verify", "flutter test --no-pub test/display_selection_queue_test.dart", "true # display selection queue test disabled", "generated bounded display-selection test gate"),
    ("dart_verify", "flutter test --no-pub test/session_event_queue_test.dart", "true # session event queue test disabled", "generated session topology queue test gate"),
    ("dart_verify", "flutter test --no-pub test/latest_frame_queue_test.dart", "true # latest frame queue test disabled", "generated bounded web-frame test gate"),
    ("dart_verify", "display selection is not a normal worker-pool bridge call", "display selection worker mode is unchecked", "generated display-selection worker-mode gate"),
    ("apple", "python3 scripts/verify-display-selection-finality.py --repo . --self-test", "python3 scripts/verify-display-selection-finality.py --repo .", "Apple gate"),
    ("workspace", '"display_selection_finality_verifier": (', '"display_selection_finality_verifier_disabled": (', "independent source binding"),
    ("workspace", "    validate_viewer_cursor_mailbox_contract(sources)\n    validate_viewer_cursor_resources_contract(sources)\n    validate_controlled_control_egress_contract(sources)\n    validate_cm_egress_budget_contract(sources)\n    validate_clipboard_listener_ownership_contract(sources)\n    validate_clipboard_route_budget_contract(sources)\n    validate_keyed_writer_budget_contract(sources)\n    validate_display_selection_finality_contract(sources)\n    validate_desktop_texture_lifecycle_contract(sources)", "    validate_viewer_cursor_mailbox_contract(sources)\n    validate_viewer_cursor_resources_contract(sources)\n    validate_controlled_control_egress_contract(sources)\n    validate_cm_egress_budget_contract(sources)\n    validate_clipboard_listener_ownership_contract(sources)\n    validate_clipboard_route_budget_contract(sources)\n    validate_keyed_writer_budget_contract(sources)\n    validate_display_selection_finality_contract_disabled(sources)\n    validate_desktop_texture_lifecycle_contract(sources)", "independent verifier dispatch"),
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
