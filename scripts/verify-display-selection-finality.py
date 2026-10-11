#!/usr/bin/env python3
"""Check source guards for Flutter display-selection ownership and ordering."""

import argparse
import ast
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
        "verify": "scripts/verify.sh",
        "dart_verify": "scripts/dart-verify.sh",
        "apple": "scripts/apple-conform-check.sh",
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
        ui_session,
        "pub fn try_capture_displays_with_commit",
        "typed capture maintenance sender",
    )
    require_order(
        typed_capture,
        (
            "commit: F",
            "DisplaySelectionCommand::capture_set(set)?",
            "send_display_selection_with_commit(command, commit)",
        ),
        "typed capture maintenance reserve-before-commit admission",
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
    ffi_size_sync = extract_braced_item(
        ffi, "pub fn session_set_size_sync(", "synchronous renderer-size FFI"
    )
    require_order(
        ffi_size_sync,
        (
            "client_owner_id: SessionID",
            "-> SyncReturn<String>",
            "session_set_size(",
            "client_owner_id,",
            ".err()",
            ".map_or_else(String::new, |error| error.to_string())",
        ),
        "synchronous renderer-size FFI preserves exact-owner errors",
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
            "_updateSessionWidthHeight(sessionId, expectedClientOwnerId);",
            "void _updateSessionWidthHeight(",
            "SessionID sessionId",
            "SessionID expectedClientOwnerId",
            "bind.sessionSetSizeSync(",
            "throw StateError(error);",
        ),
        "Dart renderer sizing retains and rechecks the exact UI owner",
    )
    if dart_size_region.count("clientOwnerId: expectedClientOwnerId") != 2:
        raise VerificationError(
            "Dart renderer sizing must pass the exact UI owner in both display shapes"
        )
    if dart_size_region.count("bind.sessionSetSizeSync(") != 2:
        raise VerificationError(
            "Dart renderer sizing must synchronously commit both bounded bridge-call shapes"
        )
    if dart_size_region.count("throw StateError(error);") != 2:
        raise VerificationError(
            "Dart renderer sizing must fail both bridge-call shapes on native refusal"
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
        "String sessionSetSizeSync(",
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
            ".rearm_rgba_for_stream_replacement(",
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
            "Ok(())",
        ),
        "exact-owner failed-start rollback and successful completion",
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
            "Entry::Vacant(entry)",
            "s.try_select_displays(None, capture_set, refresh, || {",
            "entry.insert(h);",
            ".retire_rgba_displays_except(&session_id, &displays);",
        ),
        "reserve before replacing the old UI owner and publishing startup capture",
    )
    for retired in (
        "pub fn insert_peer_session_id(",
        "pub fn session_capture_displays(",
        "pub fn ensure_display_selection_committed(",
        "pub fn remove_session_by_session_id(",
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
            ") -> Result<()>",
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
            "_softwareRgbaFrames = LatestFrameQueue(nextOwner,",
            "maxConcurrentDrainsPerKey: 3,",
            "maxCurrentDrainsPerKey: 2,",
            "drainPool: _softwareRgbaDrainPool);",
            "_webRgbaFrames = LatestFrameQueue(nextOwner, drainPool: _webRgbaDrainPool);",
        ),
        "fresh exact-pair queue installation",
    )
    require_order(
        sources["model_dart"],
        (
            "final _softwareRgbaDrainPool = LatestFrameDrainPool(",
            "maxConcurrentDrains: 3,",
            "maxWaitingDrains: 64,",
        ),
        "isolate-wide bounded software-frame conversion authority",
    )
    require_order(
        sources["model_dart"],
        (
            "final _webRgbaDrainPool = LatestFrameDrainPool(",
            "maxConcurrentDrains: 64,",
            "maxWaitingDrains: 0,",
        ),
        "isolate-wide nonwaiting web-frame presentation authority",
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
            "_softwareRgbaFrames.retire(retiringOwner)",
            "_webRgbaFrames.retire(retiringOwner)",
            "!sessionEventsRetired ||",
            "!displaySelectionsRetired ||",
            "!softwareRgbaFramesRetired ||",
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
    drain_pool = extract_braced_item(
        sources["frame_queue_dart"],
        "class LatestFrameDrainPool",
        "isolate-wide frame-drain authority",
    )
    frame_admit = extract_braced_item(
        sources["frame_queue_dart"],
        "_LatestFrameAdmission _admit(",
        "shared exact-owner per-display frame admission",
    )
    require_order(
        frame_admit,
        (
            "if (_retired || _suspended || expectedOwner != owner)",
            "return _LatestFrameAdmission.retired;",
        ),
        "exact-owner web-frame admission",
    )
    require_order(
        frame_admit,
        (
            "final activeDrains = _activeDrains[key] ?? 0;",
            "if (activeDrains >= maxConcurrentDrainsPerKey)",
            "_retireAll();",
            "return _LatestFrameAdmission.exhausted;",
            "lane = _LatestFrameLane<Frame>();",
            "_lanes[key] = lane;",
        ),
        "terminal current-plus-detached per-key drain bound",
    )
    require_order(
        frame_admit,
        (
            "if (_hasLocalCapacity(key, lane) && _tryStartDrain(key, lane, entry))",
            "return _LatestFrameAdmission.accepted;",
            "lane.pending?.complete(LatestFrameDisposition.superseded);",
            "lane.pending = entry;",
            "if (_hasLocalCapacity(key, lane) && !_ensurePoolWaiter(key, lane))",
            "lane.pending = null;",
            "_retireAll();",
            "return _LatestFrameAdmission.exhausted;",
        ),
        "bounded latest-only pooled frame admission",
    )
    require_order(
        drain_pool,
        (
            "required this.maxConcurrentDrains,",
            "this.maxWaitingDrains = 64,",
            "final Queue<_LatestFrameDrainWaiter> _waiters",
            "int _activeDrains = 0;",
            "int _waitingDrains = 0;",
            "bool _tryAcquire()",
            "if (_activeDrains >= maxConcurrentDrains)",
            "_activeDrains += 1;",
            "bool _enqueue(_LatestFrameDrainWaiter waiter)",
            "if (_waitingDrains >= maxWaitingDrains)",
            "_waiters.addLast(waiter);",
            "void _cancel(_LatestFrameDrainWaiter waiter)",
            "_waiters.remove(waiter);",
            "void _release()",
            "_activeDrains -= 1;",
            "final waiter = _waiters.removeFirst();",
            "_activeDrains += 1;",
            "started = waiter.start();",
        ),
        "bounded FIFO isolate-wide frame-drain authority",
    )
    require_order(
        frame_queue,
        (
            "class LatestFrameQueue<Owner, Key, Frame>",
            "this.maxKeys = 32,",
            "this.maxConcurrentDrainsPerKey = 2,",
            "this.maxCurrentDrainsPerKey = 1,",
            "this.drainPool,",
            "final Owner owner;",
            "final int maxKeys;",
            "final int maxConcurrentDrainsPerKey;",
            "final int maxCurrentDrainsPerKey;",
            "final LatestFrameDrainPool? drainPool;",
            "final Map<Key, _LatestFrameLane<Frame>> _lanes = {};",
            "final Map<Key, int> _activeDrains = {};",
            "bool _retired = false;",
            "bool _suspended = false;",
            "Future<LatestFrameDisposition> submit(",
            "final admission = _admit(expectedOwner, key, entry);",
            "entry.completeError(",
            "bool submitObserved(",
            "_LatestFrameEntry.observed(frame, present, onError)",
            "_LatestFrameAdmission _admit(",
            "if (_retired || _suspended || expectedOwner != owner)",
            "lane.pending?.complete(LatestFrameDisposition.superseded);",
            "lane.pending = entry;",
            "return _LatestFrameAdmission.accepted;",
            "bool suspend(Owner expectedOwner)",
            "bool recover(Owner expectedOwner)",
            "bool retire(Owner expectedOwner)",
            "bool _hasLocalCapacity(",
            "bool _tryStartDrain(",
            "if (pool != null && !pool._tryAcquire())",
            "bool _ensurePoolWaiter(",
            "if (pool._enqueue(waiter))",
            "bool _startPendingWithPoolPermit(",
            "_startDrain(key, lane, pending, hasPoolPermit: true);",
            "await entry.present(entry.frame);",
            "entry.completeError(error, stackTrace);",
            "_retireAll();",
            "if (!drain.detached && identical(_lanes[key], lane))",
            "if (drain.hasPoolPermit)",
            "drainPool!._release();",
            "_lanes.remove(key);",
            "void _detachLanes()",
            "drainPool?._cancel(waiter);",
        ),
        "exact-owner bounded pooled frame order",
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
        forbid(
            drain_pool,
            forbidden,
            "unbounded/timed/worker isolate frame-drain authority",
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
            "return _submitOrderedSessionTopologyEvent(",
            "return operation();",
        ),
        "topology-only exact-owner event serialization",
    )
    ordered_submit = extract_braced_item(
        sources["model_dart"],
        "Future<void> _submitOrderedSessionTopologyEvent(",
        "ordered session topology submission",
    )
    require_order(
        ordered_submit,
        (
            "await ffi.submitSessionEvent(",
            "sessionId, expectedClientOwnerId, operation",
            "ffi._reportSessionStreamFailure(",
        ),
        "session topology callback serialization",
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
            "SessionStreamBinding<_SessionOwner> streamBinding",
            "final streamOwner = streamBinding.owner;",
            "if (!_isCurrentSessionStream(streamBinding))",
            "final sessionEvents = _sessionEvents;",
            "final cachedState = sessionEvents.submit(streamOwner, () async {",
            "await ffiModel.handleCachedPeerData(",
            "_observeQueuedSessionState(cachedState, activeSessionId, peerId);",
            "streamFinality.acceptExpectedClose();",
            "sessionEvents.retire(streamOwner);",
            "final decoded = json.decode(message.field0);",
            "decoded is! Map<String, dynamic>",
            "_reportSessionStreamFailure(activeSessionId, peerId,",
            "softwareRgbaFrames.submitObserved(",
            "(frame) => _handleSoftwareRgba(",
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
            "final publication =",
            "_WebRgbaPublication(ownedData, imageModel.presentationRevision);",
            "final frameTask = webRgbaFrames.submit(",
            "streamOwner,",
            "display,",
            "publication,",
            "(publication) => _handleWebRgba(",
            "sessionEvents, streamOwner,",
            "activeSessionId, display, publication));",
            "unawaited(frameTask.then<void>",
            "_reportSessionStreamFailure(activeSessionId, peerId,",
            "return;",
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
            "platformFFI.takeLatestRgba(",
            "activeSessionId, frame.display, frame.publication",
            "await _displayTopologyAfterCheckpoint(",
            "await imageModel.onRgba(",
            "publication: frame.publication",
            "expectedDisplayTopologyRevision: topologyRevision",
            "await onEvent2UIRgba(",
            "imageGeometryInitialized: true",
        ),
        "atomic newest-frame take before bounded RGBA presentation",
    )
    for obsolete in ("copyRgba(", "nextRgba(", "RgbaPresentationReceipt"):
        forbid(
            sources["model_dart"],
            obsolete,
            "paint-callback-owned native RGBA flow control",
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
            "required int expectedPresentationRevision",
            "isCurrentDisplayTopology(",
            "isCurrentPresentationRevision(",
            "final rect = parent.target?.ffiModel.pi.getDisplayRect(display);",
            "final image = await img.decodeImageFromPixels(",
            "if (image == null)",
            "return update(image,",
            "expectedDisplayTopologyRevision: expectedDisplayTopologyRevision",
            "expectedPresentationRevision: expectedPresentationRevision",
        ),
        "pre-decode admission and exact image-ownership transfer",
    )
    image_update = extract_braced_item(
        sources["model_dart"],
        "Future<bool> update(ui.Image? image,",
        "owned image admission and adoption",
    )
    require_order(
        image_update,
        (
            "bool acceptsExpectedImage() =>",
            "isCurrentSession(expectedSessionId)",
            "_rgbaPublicationOrder.canComplete(expectedRgbaPublication)",
            "isCurrentPresentationRevision(expectedPresentationRevision)",
            "isCurrentDisplayTopology(",
            "var adopted = false;",
            "try {",
            "if (!acceptsExpectedImage())",
            "_rgbaPublicationOrder.commit(expectedRgbaPublication)",
            "_image = image;",
            "adopted = true;",
            "finally {",
            "if (!adopted && !identical(image, _image))",
            "image?.dispose();",
        ),
        "exact image admission, synchronous adoption and unadopted cleanup",
    )
    first_image = extract_braced_item(
        sources["model_dart"],
        "Future<bool> onEvent2UIRgba(",
        "single exact first-image initialization",
    )
    require_order(
        first_image,
        (
            "final owner = canvasModel.captureUpdateOwner(",
            "expectedDisplayTopologyRevision: expectedDisplayTopologyRevision",
            "if (owner == null) return false;",
            "if (!owner.isCurrent) return false;",
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
            "if (!owner.isCurrent) return false;",
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
        (
            "shared drain pool survives queue replacement without minting capacity",
            "cross-session conversion-capacity regression",
        ),
        (
            "shared drain pool retains only the latest waiting frame",
            "latest-only shared-waiter regression",
        ),
        (
            "shared drain pool starts live waiting lanes in FIFO order",
            "shared-waiter FIFO regression",
        ),
        (
            "shared drain pool refuses excess waiting lanes visibly",
            "shared-waiter capacity regression",
        ),
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
        sources["dart_verify"],
        "flutter test --no-pub test/session_event_queue_test.dart",
        "generated-bridge session topology queue behavior gate",
    )
    require(
        sources["dart_verify"],
        "flutter test --no-pub test/latest_frame_queue_test.dart",
        "generated-bridge bounded web-frame behavior gate",
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
        "if ((display != kAllDisplayValue && !displays.contains(display))",
        "moveFromSessionId, moveFromClientOwnerId);",
        "existing-window Dart startup",
    )
    require_order(
        startup_dart,
        (
            "display != kAllDisplayValue && !displays.contains(display)",
            "displays.isEmpty",
            "candidate < -0x80000000 || candidate > 0x7fffffff",
            "final requestedDisplays = Int32List.fromList(displays);",
            "final addRes = isMove",
            "bind.sessionAddExistedForMoveSync(",
            "sourceSessionId: moveFromSessionId!",
            "sourceClientOwnerId: moveFromClientOwnerId!",
            "bind.sessionAddExistedSync(",
            "displays: requestedDisplays",
            "if (addRes != '')",
            "return activeSessionId;",
            "ffiModel._beginDisplayTopologyMutation(activeSessionId)",
            "ffiModel.pi.currentDisplay = display;",
            "textureModel.updateCurrentDisplay(display);",
            "stream = bind.sessionStart(",
        ),
        "startup admission before local display/texture commit and stream attach",
    )
    dart_start = extract_braced_item(
        sources["model_dart"], "SessionID start(", "Dart session startup"
    )
    if dart_start.count("textureModel.updateCurrentDisplay(") != 1:
        raise VerificationError(
            "fresh peers must not publish a desktop texture before initial display ownership"
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
            "verify",
            "python3 scripts/verify-display-selection-finality.py --repo .",
            "shared focused gate",
        ),
        (
            "dart_verify",
            "python3 scripts/verify-display-selection-finality.py --repo .",
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
            "python3 scripts/verify-display-selection-finality.py --repo .",
            "Apple/shared focused gate",
        ),
    ):
        require(sources[key], needle, label)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    args = parser.parse_args()
    sources = load_sources(args.repo.resolve())
    validate(sources)
    print("display selection finality source checks passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"display selection finality source checks failed: {error}")
        raise SystemExit(1)
