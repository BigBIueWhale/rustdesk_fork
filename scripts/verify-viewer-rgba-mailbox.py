#!/usr/bin/env python3
"""Verify exact, bounded Flutter software-RGBA publication semantics."""

from __future__ import annotations

import argparse
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


def extract_async_dart_item(source: str, signature: str, label: str) -> str:
    start = source.find(signature)
    if start < 0:
        raise VerificationError(f"missing {label}")
    async_body = source.find("async {", start + len(signature))
    if async_body < 0:
        raise VerificationError(f"missing async body for {label}")
    open_brace = async_body + len("async ")
    depth = 0
    for offset in range(open_brace, len(source)):
        character = source[offset]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return source[start : offset + 1]
    raise VerificationError(f"unterminated async body for {label}")


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "flutter": "src/flutter.rs",
        "ffi": "src/flutter_ffi.rs",
        "io_loop": "src/client/io_loop.rs",
        "ui_session": "src/ui_session_interface.rs",
        "model": "flutter/lib/models/model.dart",
        "publication_order": "flutter/lib/models/rgba_publication_order.dart",
        "publication_order_test": "flutter/test/rgba_publication_order_test.dart",
        "native_model": "flutter/lib/models/native_model.dart",
        "web_model": "flutter/lib/models/web_model.dart",
        "web_bridge": "flutter/lib/web/bridge.dart",
        "ios_app": "flutter/ios/Runner/AppDelegate.swift",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "verify": "scripts/verify.sh",
        "apple": "scripts/apple-conform-check.sh",
        "dart_verify": "scripts/dart-verify.sh",
        "workspace": "scripts/verify-verifier-workspace.py",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def validate(sources: Dict[str, str]) -> None:
    flutter = sources["flutter"]
    ffi = sources["ffi"]

    require(
        flutter,
        "HashMap<(SessionID, usize), RgbaData>",
        "exact session/display mailbox key",
    )
    require(
        flutter,
        "rgba_publication_counter: Arc<AtomicU64>",
        "handler-wide publication counter",
    )
    session_handler = extract_braced_item(
        flutter, "struct SessionHandler", "UI session handler state"
    )
    require(
        session_handler,
        "awaiting_initial_display: bool",
        "explicit initial display-owner state",
    )

    rgba_data = extract_braced_item(flutter, "struct RgbaData", "RGBA mailbox state")
    require_order(
        rgba_data,
        (
            "data: Vec<u8>",
            "valid: bool",
            "publication: u64",
            "pending: Option<Vec<u8>>",
            "spare: Vec<u8>",
        ),
        "one published, one pending, and reusable-capacity mailbox state",
    )

    offer_swap = extract_braced_item(
        flutter, "fn offer_swap<F>", "single-consumer swap admission"
    )
    require_order(
        offer_swap,
        (
            "if !self.valid",
            "let publication = next_publication()?",
            "std::mem::swap(incoming, &mut self.data);",
            "self.publication = publication;",
            "if let Some(pending) = self.pending.as_mut()",
            "std::mem::swap(incoming, pending);",
            "self.pending = Some(std::mem::take(&mut self.spare));",
        ),
        "zero-copy initial publication and latest-only pending replacement",
    )
    forbid(offer_swap, ".push(", "unbounded swap-path queue")

    offer_copy = extract_braced_item(
        flutter, "fn offer_copy<F>", "independent-consumer copy admission"
    )
    require_order(
        offer_copy,
        (
            "if !self.valid",
            "let publication = next_publication()?",
            "self.data.extend_from_slice(incoming);",
            "if self.pending.is_none()",
            "self.pending = Some(std::mem::take(&mut self.spare));",
            "pending.clear();",
            "pending.extend_from_slice(incoming);",
        ),
        "independent stable storage and latest-only copy replacement",
    )
    forbid(offer_copy, ".push(", "unbounded copy-path queue")

    copy = extract_braced_item(flutter, "fn copy(&self", "exact publication copy")
    require(
        copy,
        "self.valid && self.publication == publication",
        "exact-token copy admission",
    )
    require(copy, "self.data.clone()", "owned bridge result")

    acknowledge = extract_braced_item(
        flutter, "fn acknowledge<F>", "exact publication acknowledgement"
    )
    require_order(
        acknowledge,
        (
            "if !self.valid || self.publication != publication",
            "RgbaAcknowledgement::Ignored",
            "let Some(mut latest) = self.pending.take()",
            "self.valid = false;",
            "RgbaAcknowledgement::Drained",
            "let Some(publication) = next_publication()",
            "RgbaAcknowledgement::Exhausted",
            "std::mem::swap(&mut self.data, &mut latest);",
            "self.spare = latest;",
            "self.publication = publication;",
            "RgbaAcknowledgement::Promoted(publication)",
        ),
        "stale rejection, drain, checked promotion, and exhaustion",
    )

    rearm = extract_braced_item(
        flutter, "fn rearm<F>", "presentation recovery publication re-arm"
    )
    require_order(
        rearm,
        (
            "if !self.valid",
            "RgbaRearm::Idle",
            "let Some(publication) = next_publication()",
            "self.valid = false;",
            "self.pending = None;",
            "RgbaRearm::Exhausted",
            "if let Some(mut latest) = self.pending.take()",
            "std::mem::swap(&mut self.data, &mut latest);",
            "self.spare = latest;",
            "self.publication = publication;",
            "RgbaRearm::Rearmed(publication)",
        ),
        "idle, checked-token, latest-pending, and fail-closed re-arm",
    )

    next_publication = extract_braced_item(
        flutter, "fn next_rgba_publication", "checked publication allocation"
    )
    require_order(
        next_publication,
        (
            ".fetch_update(",
            ".checked_add(1)",
            ".filter(|next| *next <= i64::MAX as u64)",
        ),
        "positive checked Dart-compatible publication sequence",
    )

    offer_sessions = extract_braced_item(
        flutter, "fn offer_rgba_to_sessions(", "exact consumer publication"
    )
    require_order(
        offer_sessions,
        (
            "session_ids.split_last()",
            ".entry((*session_id, display))",
            ".offer_copy(incoming, || self.next_rgba_publication())",
            ".entry((*last, display))",
            ".offer_swap(incoming, || self.next_rgba_publication())",
        ),
        "independent preceding consumers and swap-based common consumer",
    )

    handler_copy = extract_braced_item(
        flutter, "fn copy_rgba(", "handler exact publication copy"
    )
    require_order(
        handler_copy,
        (
            ".get(&(*session_id, display))",
            ".and_then(|rgba| rgba.copy(publication))",
        ),
        "exact session/display/token copy",
    )

    next_rgba = extract_braced_item(
        flutter, "fn next_rgba(&self", "handler exact acknowledgement"
    )
    require_order(
        next_rgba,
        (
            ".get_mut(&(*session_id, display))",
            "mailbox.acknowledge(publication",
            "RgbaAcknowledgement::Exhausted",
            "mailboxes.remove(&(*session_id, display));",
            "RgbaAcknowledgement::Promoted(next_publication)",
            "EventToUI::Rgba(display, next_publication)",
            ".remove(&(*session_id, display));",
        ),
        "exact promotion notification and failed-stream retirement",
    )

    replay = extract_braced_item(
        flutter, "fn replay_ready_rgba", "event-stream publication replay"
    )
    require_order(
        replay,
        (
            "let publications = self.ready_rgba_publications(session_id);",
            ".get(session_id)",
            "EventToUI::Rgba(display, publication)",
        ),
        "exact display/token replay",
    )

    recovery_rearm = extract_braced_item(
        flutter,
        "fn rearm_rgba_for_presentation_recovery(",
        "exact software publication recovery",
    )
    require_order(
        recovery_rearm,
        (
            ".get_mut(&(*session_id, display))",
            "mailbox.rearm(|| self.next_rgba_publication())",
            "RgbaRearm::Exhausted",
            "mailboxes.remove(&(*session_id, display));",
            "RgbaRearm::Rearmed(publication)",
            "stream.add(EventToUI::Rgba(display, publication))",
            ".remove(&(*session_id, display));",
            'bail!("software RGBA presentation re-arm was rejected by its exact UI stream")',
        ),
        "exact re-arm notification and refused-stream retirement",
    )

    exact_refresh_owner = extract_braced_item(
        flutter,
        "pub fn request_video_refresh_for_exact_ui_owner(",
        "exact UI-owner presentation recovery",
    )
    require_order(
        exact_refresh_owner,
        (
            "handler.client_owner_id.as_ref() != Some(client_owner_id)",
            "if handler.displays.is_empty()",
            "for display in &handler.displays",
            "session.ui_handler.rearm_rgba_for_presentation_recovery(",
            "*display",
            "handler.event_stream.as_ref()",
            "handler.renderer.notify_pending_frame(*display)?;",
            "for display in &handler.displays",
            "let display = i32::try_from(*display)",
            "session.refresh_video(display)?;",
            "return Ok(());",
        ),
        "exact-owner display-set software publication before native pending-frame and peer refresh admission",
    )
    forbid(
        exact_refresh_owner,
        "display: i32",
        "caller-selected native presentation-refresh display",
    )

    soft_render = extract_braced_item(
        flutter, "fn on_rgba_soft_render", "software RGBA producer"
    )
    require_order(
        soft_render,
        (
            "let handlers = self.session_handlers.read().unwrap();",
            "if !handler.displays.contains(&display)",
            "handler.event_stream.as_ref().map(|_| *session_id)",
            "self.offer_rgba_to_sessions(&session_ids, display, &mut rgba.raw)",
            "for (session_id, publication) in notifications",
            "EventToUI::Rgba(display, publication)",
            "mailboxes.remove(&(session_id, display));",
        ),
        "eligible exact consumers and exact initial delivery",
    )
    forbid(soft_render, "is_multi_sessions", "handler-count presentation authority")
    forbid(
        soft_render,
        "if rgba_data.valid {\n                return;",
        "oldest-frame early return",
    )

    session_start = extract_braced_item(
        flutter, "pub fn session_start_(", "session stream installation"
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
    peer_start = extract_braced_item(
        flutter,
        "fn admit_session_start(",
        "display-owned session-start admission",
    )
    require_order(
        peer_start,
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
        "fresh, marker-bearing replacement, or explicit display-owned session-start admission",
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
            "if starts_peer_connection && is_video_session",
            "h.awaiting_initial_display = true;",
            "match s.start_io_thread_with_lock(&mut thread_lock)",
            "Ok(false)",
            "start_failure = Some(anyhow!(",
            "Err(error) => start_failure = Some(error.into())",
            "is_found = true;",
        ),
        "under-guard exact-owner stream admission and peer-I/O start",
    )
    require_order(
        session_start,
        (
            "if let Some(error) = start_failure",
            "rollback_failed_session_start(session_id, client_owner_id);",
            "return Err(error);",
            ".replay_ready_rgba(session_id, client_owner_id)",
            "rollback_failed_session_start(session_id, client_owner_id);",
            'bail!("Outgoing session event stream rejected pending video")',
        ),
        "visible exact-owner failed-start and replay rollback",
    )
    if session_start.count(
        "rollback_failed_session_start(session_id, client_owner_id);"
    ) != 2:
        raise VerificationError("session start must have exactly two exact-owner rollback sinks")
    rollback = extract_braced_item(
        flutter,
        "fn rollback_failed_session_start(",
        "exact-owner failed-start rollback",
    )
    require_order(
        rollback,
        (
            "client_owner_id: &SessionID",
            "remove_failed_start_by_exact_ui_owner(session_id, client_owner_id)",
            "session.close_and_join();",
        ),
        "failed-start rollback preserves replacement owners",
    )
    exact_removal = extract_braced_item(
        flutter,
        "pub(super) fn remove_failed_start_by_exact_ui_owner(",
        "exact-owner failed-start removal",
    )
    require_order(
        exact_removal,
        (
            "handlers.get(id)",
            "handler.client_owner_id.as_ref() != Some(client_owner_id)",
            "return None;",
            "if handlers.remove(id).is_none()",
            "retire_rgba_session(id);",
        ),
        "failed-start removal checks the exact current UI owner before mutation",
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
        "bounded fresh binding or reconnect preservation of explicit native display ownership",
    )
    forbid(
        initial_owner,
        "handlers.values_mut()",
        "reconnect mutation of already-explicit display owners",
    )
    flutter_owner_admission = extract_braced_item(
        flutter,
        "fn bind_initial_display_owner(\n        &self,",
        "Flutter initial display-owner admission",
    )
    require_order(
        flutter_owner_admission,
        (
            "-> ResultType<()>",
            "bind_initial_display_owner(",
            "&mut self.session_handlers.write().unwrap()",
            "current_display",
            "display_count",
        ),
        "Flutter initial display-owner delegation",
    )
    require(
        sources["ui_session"],
        "fn bind_initial_display_owner(\n        &self,\n        current_display: i32,\n        display_count: usize,\n    ) -> ResultType<()>;",
        "result-bearing initial display-owner UI trait",
    )
    interface_impl = sources["ui_session"].find("impl<T: InvokeUiSession> Session<T>")
    if interface_impl < 0:
        raise VerificationError("missing Flutter Session implementation")
    interface_owner_admission = extract_braced_item(
        sources["ui_session"][interface_impl:],
        "fn bind_initial_display_owner(\n        &self,\n        current_display: i32,",
        "session initial display-owner admission",
    )
    require_order(
        interface_owner_admission,
        (
            "if self.is_file_transfer() || self.is_port_forward() || self.is_terminal()",
            "return Ok(());",
            ".bind_initial_display_owner(current_display, display_count)",
        ),
        "video-only exact initial display-owner admission",
    )
    login_peer_info = sources["io_loop"].find(
        "Some(login_response::Union::PeerInfo(pi)) =>"
    )
    sync_peer_info = sources["io_loop"].find(
        "Some(message::Union::PeerInfo(pi)) =>", login_peer_info + 1
    )
    sync_peer_info_end = sources["io_loop"].find(
        "Some(message::Union::ScreenshotResponse(response)) =>", sync_peer_info + 1
    )
    if login_peer_info < 0 or sync_peer_info < 0 or sync_peer_info_end < 0:
        raise VerificationError("missing initial/synchronized peer-information dispatch")
    initial_peer_dispatch = sources["io_loop"][login_peer_info:sync_peer_info]
    require_order(
        initial_peer_dispatch,
        (
            "let initial_display = pi.current_display;",
            "let pi = bound_peer_info(pi);",
            ".bind_initial_display_owner(initial_display, pi.displays.len())",
            "self.handler.on_error(&message);",
            "return false;",
            "self.set_peer_info(&pi);",
            "self.handler.handle_peer_info(pi);",
        ),
        "raw claimed initial display admission before bounded peer-state consumption",
    )
    forbid(
        sources["io_loop"][sync_peer_info:sync_peer_info_end],
        "bind_initial_display_owner",
        "later topology re-binding of initial display ownership",
    )

    set_size = extract_braced_item(flutter, "pub fn session_set_size(", "renderer sizing")
    require_order(
        set_size,
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
        "result-bearing exact-UI-owner renderer sizing",
    )
    forbid(set_size, "h.displays.push(display)", "renderer-size-created display ownership")
    exact_owned_size = extract_braced_item(
        flutter,
        "fn set_exact_owned_display_size(",
        "exact-UI-owner renderer-size helper",
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
    owned_size = extract_braced_item(
        flutter, "fn set_owned_display_size(", "owned-display renderer-size helper"
    )
    require_order(
        owned_size,
        (
            "if !self.displays.contains(&display)",
            "return false;",
            "self.renderer.set_size(display, width, height);",
            "true",
        ),
        "renderer sizing requires pre-existing exact display ownership",
    )
    ffi_size = extract_braced_item(ffi, "pub fn session_set_size(", "renderer-size FFI")
    require_order(
        ffi_size,
        (
            "client_owner_id: SessionID",
            "-> Result<()>",
            "super::flutter::session_set_size(session_id, client_owner_id, display, width, height)",
        ),
        "renderer-size FFI preserves exact UI ownership and failure",
    )
    dart_display_update = extract_async_dart_item(
        sources["model"], "Future<bool> updateCurDisplay(", "Dart display update"
    )
    require_order(
        dart_display_update,
        (
            "final expectedClientOwnerId = ffi.clientOwnerId;",
            "ffi.isCurrentSessionOwner(sessionId, expectedClientOwnerId)",
            "await _updateSessionWidthHeight(sessionId, expectedClientOwnerId);",
        ),
        "Dart renderer sizing retains and rechecks the exact UI owner",
    )
    dart_size = extract_braced_item(
        sources["model"],
        "Future<void> _updateSessionWidthHeight(\n      SessionID",
        "Dart renderer sizing",
    )
    require_order(
        dart_size,
        ("SessionID sessionId", "SessionID expectedClientOwnerId", "async {"),
        "Dart exact-owner renderer-size parameters",
    )
    if dart_size.count("await bind.sessionSetSize(") != 2:
        raise VerificationError(
            "Dart renderer sizing must await both bounded bridge-call shapes"
        )
    if dart_size.count("clientOwnerId: expectedClientOwnerId") != 2:
        raise VerificationError(
            "Dart renderer sizing must pass the exact UI owner in both display shapes"
        )
    dart_peer_info = extract_async_dart_item(
        sources["model"], "Future<void> handlePeerInfo(", "Dart peer information"
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
            "isCurrentDisplayTopology(",
            "if (_pi.currentDisplay < _pi.displays.length)",
            "await updateCurDisplay(",
        ),
        "established reconnect restores exact display selection before geometry",
    )
    web_size = extract_braced_item(
        sources["web_bridge"], "Future<void> sessionSetSize(", "web renderer sizing"
    )
    require_order(
        web_size,
        ("required UuidValue sessionId", "required UuidValue clientOwnerId"),
        "web renderer-size exact-owner parity",
    )
    for regression in (
        "r_s11gt_initial_peer_info_binds_one_exact_display_owner_once",
        "r_s11gt_initial_display_binding_refuses_ambiguous_or_invalid_authority",
        "r_s11gt_reconnect_preserves_explicit_display_owners_without_rebinding",
        "r_s11gt_session_start_requires_fresh_or_explicit_display_authority",
        "r_s11gt_capture_authority_excludes_renderer_resource_keys",
        "r_s11gt_renderer_size_requires_exact_current_ui_owner",
    ):
        require(flutter, regression, f"{regression} native regression")

    for needle, label in (
        ("retire_rgba_session(id);", "ordinary session retirement"),
        (
            "retire_rgba_displays_except(&session_id, &value);",
            "display-switch retirement",
        ),
        (
            "retire_rgba_session(&stale_handler_id);",
            "mobile predecessor retirement",
        ),
        (
            "retire_rgba_session(owned_handler_id);",
            "mobile owner retirement",
        ),
    ):
        require(flutter, needle, label)

    exported_copy = extract_braced_item(
        flutter, "pub fn session_copy_rgba(", "exact public bridge copy"
    )
    require(
        exported_copy,
        ".copy_rgba(&session_id, display, publication)",
        "public exact copy delegation",
    )
    exported_ack = extract_braced_item(
        flutter, "pub fn session_next_rgba(", "exact public acknowledgement"
    )
    require(
        exported_ack,
        ".next_rgba(&session_id, display, publication)",
        "public exact acknowledgement delegation",
    )
    for forbidden in (
        "pub extern \"C\" fn session_get_rgba",
        "pub fn session_get_rgba_size",
        "fn char_to_session_id",
    ):
        forbid(flutter, forbidden, "raw size/pointer RGBA protocol")

    trait = sources["ui_session"]
    forbid(trait, "fn get_rgba(", "display-only generic RGBA lookup")
    forbid(trait, "fn next_rgba(", "display-only generic RGBA acknowledgement")

    event = extract_braced_item(ffi, "pub enum EventToUI", "Flutter event enum")
    require(event, "Rgba(usize, u64)", "display/publication event payload")
    ffi_copy = extract_braced_item(
        ffi, "pub fn session_copy_rgba(", "generated-bridge copy wrapper"
    )
    require(
        ffi_copy,
        "SyncReturn<Option<Vec<u8>>>",
        "owned optional byte result",
    )
    require(ffi_copy, "publication: u64", "copy publication argument")
    ffi_ack = extract_braced_item(
        ffi, "pub fn session_next_rgba(", "generated-bridge acknowledgement wrapper"
    )
    require(ffi_ack, "publication: u64", "acknowledgement publication argument")

    native = sources["native_model"]
    require(native, "Uint8List? copyRgba(", "native owned-copy wrapper")
    require(native, "_ffiBind.sessionCopyRgba(", "generated native copy call")
    require(
        native,
        "void nextRgba(SessionID sessionId, int display, int publication)",
        "native exact-token acknowledgement",
    )
    for forbidden in (
        "_session_get_rgba",
        'lookupFunction<F3Dart, F3>("session_get_rgba")',
        "asTypedList(bufSize)",
        "toNativeUtf8()",
    ):
        forbid(native, forbidden, "borrowed native RGBA pointer path")

    model = sources["model"]
    on_rgba = extract_async_dart_item(
        model, "Future<bool> onRgba(", "asynchronous RGBA decode"
    )
    require_order(
        on_rgba,
        (
            "required int expectedDisplayTopologyRevision",
            "isCurrentDisplayTopology(",
            "admission = _rgbaPublicationOrder.admit(",
            "if (admission == null)",
            "platformFFI.nextRgba(expectedSessionId, display, publication);",
            "return false;",
            "return await decodeAndUpdate(expectedSessionId, display, rgba,",
            "expectedRgbaPublication: admission",
            "expectedDisplayTopologyRevision:",
            "} finally {",
            "platformFFI.nextRgba(expectedSessionId, display, publication);",
        ),
        "stale refusal and exact acknowledgement after admitted decode finality",
    )
    decode = extract_async_dart_item(
        model, "Future<bool> decodeAndUpdate(", "ordered RGBA decode"
    )
    require_order(
        decode,
        (
            "required int expectedDisplayTopologyRevision",
            "isCurrentDisplayTopology(",
            "_rgbaPublicationOrder.isCurrent(expectedRgbaPublication)",
            "final image = await img.decodeImageFromPixels(",
            "isCurrentDisplayTopology(",
            "_rgbaPublicationOrder.isCurrent(expectedRgbaPublication)",
            "image.dispose();",
            "expectedRgbaPublication: expectedRgbaPublication",
        ),
        "publication admission before and after asynchronous image decode",
    )
    update = extract_async_dart_item(model, "Future<bool> update(", "image commit")
    require_order(
        update,
        (
            "bool acceptsExpectedImage()",
            "_rgbaPublicationOrder.isCurrent(expectedRgbaPublication)",
            "isCurrentDisplayTopology(",
            "await parent.target?.canvasModel",
            "if (!acceptsExpectedImage())",
            "await initializeCursorAndCanvas(",
            "if (!acceptsExpectedImage())",
            "if (image == null)",
            "_rgbaPublicationOrder.retire();",
            "_image?.dispose();",
            "_image = image;",
        ),
        "exact publication checks across awaits and immediately before commit",
    )
    clear_image = extract_braced_item(model, "void clearImage()", "image retirement")
    require_order(
        clear_image,
        (
            "_rgbaPublicationOrder.retire();",
            "_image?.dispose();",
            "_image = null;",
        ),
        "publication and image retirement",
    )

    publication_order = sources["publication_order"]
    order_owner = extract_braced_item(
        publication_order,
        "class ExactRgbaPublicationOrder<Session extends Object>",
        "exact Dart publication order owner",
    )
    require_order(
        order_owner,
        (
            "publication <= 0",
            "_session == session && publication <= _publication",
            "_session = session;",
            "_publication = publication;",
            "_revision += 1;",
            "return RgbaPublicationAdmission._(",
            "admission.revision == _revision",
            "admission.session == _session",
            "admission.display == _display",
            "admission.publication == _publication",
            "void retire()",
            "_revision += 1;",
            "_session = null;",
        ),
        "same-session monotonic admission, exact commit, and retirement",
    )
    for forbidden in ("Timer", "Future", "Stream", "List<", "Queue"):
        forbid(publication_order, forbidden, "detached or queued publication owner")
    listener = extract_async_dart_item(
        model,
        "Future<void> _handleSoftwareRgba(",
        "checkpointed exact RGBA event handling",
    )
    require_order(
        listener,
        (
            "await _displayTopologyAfterCheckpoint(",
            "platformFFI.nextRgba(activeSessionId, display, publication);",
            "platformFFI.copyRgba(activeSessionId, display, publication)",
            "imageOwnsAcknowledgement = true;",
            "await imageModel.onRgba(",
            "activeSessionId, display, rgba",
            "publication: publication",
            "expectedDisplayTopologyRevision: topologyRevision",
        ),
        "exact checkpoint/copy/decode ownership wiring",
    )
    stream_listener = extract_braced_item(
        model, "void _listenToSessionStream(", "session RGBA event dispatch"
    )
    require_order(
        stream_listener,
        (
            "message is EventToUI_Rgba",
            "_handleSoftwareRgba(sessionEvents, streamOwner, activeSessionId,",
            "message.field0, message.field1)",
        ),
        "exact session RGBA event token dispatch",
    )
    forbid(listener, "getRgbaSize", "size-then-pointer Dart protocol")
    forbid(listener, "getRgba(", "raw-pointer Dart protocol")

    web_model = sources["web_model"]
    require(
        web_model,
        "Uint8List? copyRgba(SessionID sessionId, int display, int publication)",
        "web model signature parity",
    )
    require(
        web_model,
        "void nextRgba(SessionID sessionId, int display, int publication)",
        "web acknowledgement signature parity",
    )
    web_bridge = sources["web_bridge"]
    require_order(
        web_bridge,
        (
            "const factory EventToUI.rgba(",
            "int field0,",
            "int field1,",
            "class EventToUI_Rgba",
            "final int f0;",
            "final int f1;",
            "int get field1 => f1;",
        ),
        "web event display/publication parity",
    )
    require(
        web_bridge,
        "required int publication",
        "web acknowledgement publication stub",
    )

    forbid(
        sources["ios_app"],
        "session_get_rgba(",
        "iOS raw-pointer linker reference",
    )

    for test in (
        "r_s11ew_rgba_mailbox_keeps_published_frame_stable_and_promotes_only_latest",
        "r_s11ew_rgba_mailboxes_are_exact_per_ui_session_and_display",
        "r_s11ew_rgba_without_a_live_consumer_retains_no_frame",
        "r_s11ew_display_switch_retires_only_obsolete_exact_mailboxes",
        "r_s11ew_rgba_publication_exhaustion_fails_closed",
        "r_s11fr_rgba_rearm_replaces_the_token_and_promotes_only_the_latest_frame",
        "r_s11fr_rgba_rearm_is_idle_without_a_publication_and_fails_closed_on_exhaustion",
        "r_s11fr_failed_rgba_rearm_retires_the_exact_mailbox",
        "r_s11ff_r_s11gs_video_refresh_derives_the_current_exact_ui_owner_displays",
    ):
        require(flutter, f"fn {test}()", f"{test} behavior regression")

    for test in (
        "a newer publication invalidates an older asynchronous completion",
        "out-of-order asynchronous completions commit only the latest",
        "a newer cross-display publication supersedes the old display",
        "an exact new session may begin with a lower native publication",
        "retirement invalidates an admitted asynchronous completion",
        "nonpositive native publications are rejected",
    ):
        require(
            sources["publication_order_test"],
            f"test('{test}'",
            f"{test} Dart behavior regression",
        )

    for key, needle, label in (
        (
            "requirements",
            '<div class="req"><span class="id">R-S11ew</span>',
            "R-S11ew requirement",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11fr</span>',
            "R-S11fr requirement",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11gs</span>',
            "R-S11gs requirement",
        ),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11gt</span>',
            "R-S11gt requirement",
        ),
        ("requirements", "<tr><td>305</td>", "Appendix C #305"),
        ("requirements", "<tr><td>326</td>", "Appendix C #326"),
        ("requirements", "<tr><td>354</td>", "Appendix C #354"),
        ("requirements", "<tr><td>355</td>", "Appendix C #355"),
        (
            "hardening",
            "**R-S11ew/R-S11e-184 exact, bounded, latest-wins Flutter software-RGBA publication",
            "RGBA mailbox hardening ledger",
        ),
        (
            "hardening",
            "**R-S11fr/R-S11e-205 exact software-RGBA presentation recovery",
            "software RGBA recovery hardening ledger",
        ),
        (
            "hardening",
            "### R-S11gs/R-S11e-231 — exact-owner presentation-refresh display authority",
            "exact-owner refresh-display authority hardening ledger",
        ),
        (
            "hardening",
            "### R-S11gt/R-S11e-232 — explicit initial and ongoing native display ownership",
            "explicit native display-owner hardening ledger",
        ),
        (
            "verify",
            "cargo test --lib --features linux-pkg-config,flutter r_s11ew_ --color never",
            "shared behavior-test wiring",
        ),
        (
            "verify",
            "cargo test --lib --features linux-pkg-config,flutter r_s11fr_ --color never",
            "shared recovery behavior-test wiring",
        ),
        (
            "verify",
            "cargo test --lib --features linux-pkg-config,flutter r_s11gt_ --color never",
            "initial display-owner behavior-test wiring",
        ),
        (
            "dart_verify",
            "flutter test --no-pub test/rgba_publication_order_test.dart",
            "Dart publication-order behavior-test wiring",
        ),
        (
            "verify",
            "python3 scripts/verify-viewer-rgba-mailbox.py --repo . --self-test",
            "shared focused-verifier wiring",
        ),
        (
            "apple",
            "python3 scripts/verify-viewer-rgba-mailbox.py --repo . --self-test",
            "Apple/shared focused-verifier wiring",
        ),
        (
            "workspace",
            '"viewer_rgba_mailbox_verifier": (',
            "independent verifier source binding",
        ),
        (
            "workspace",
            "validate_viewer_rgba_mailbox_contract(sources)",
            "independent verifier dispatch",
        ),
    ):
        require(sources[key], needle, label)

    requirements_digest = hashlib.sha256(
        sources["requirements"].encode("utf-8")
    ).hexdigest()
    require(
        sources["hardening"],
        f"{requirements_digest}  requirements.html",
        "exact requirements digest binding",
    )


Mutation = Tuple[str, str, str, str]

MUTATIONS: Tuple[Mutation, ...] = (
    ("flutter", "HashMap<(SessionID, usize), RgbaData>", "HashMap<usize, RgbaData>", "exact mailbox key"),
    ("flutter", "rgba_publication_counter: Arc<AtomicU64>", "rgba_publication_counter: Arc<AtomicUsize>", "publication counter"),
    ("flutter", "pending: Option<Vec<u8>>", "pending: Vec<Vec<u8>>", "single pending frame"),
    ("flutter", "std::mem::swap(incoming, &mut self.data);", "self.data.clone_from(incoming);", "initial buffer swap"),
    ("flutter", "std::mem::swap(incoming, pending);", "pending.extend_from_slice(incoming);", "latest pending replacement"),
    ("flutter", "self.valid && self.publication == publication", "self.valid", "copy token check"),
    ("flutter", "self.data.clone()", "Vec::new()", "owned copy bytes"),
    ("flutter", "if !self.valid || self.publication != publication", "if !self.valid", "stale acknowledgement"),
    ("flutter", "let Some(publication) = next_publication()", "let publication = self.publication", "promotion token"),
    ("flutter", "fn rearm<F>", "fn rearm_disabled<F>", "presentation recovery re-arm"),
    ("flutter", "self.pending = None;", "self.pending.take();", "re-arm exhaustion retirement"),
    ("flutter", "std::mem::swap(&mut self.data, &mut latest);", "self.data = latest;", "re-arm latest-frame promotion"),
    ("flutter", "fn rearm_rgba_for_presentation_recovery(", "fn rearm_rgba_for_presentation_recovery_disabled(", "exact recovery notification"),
    ("flutter", "session.ui_handler.rearm_rgba_for_presentation_recovery(", "session.ui_handler.replay_ready_rgba(", "refresh-owned software re-arm"),
    ("flutter", "if let Some(handler) = handlers.get(session_id) {\n                if handler.client_owner_id.as_ref() != Some(client_owner_id)", "if let Some(handler) = handlers.get(session_id) {\n                if false", "refresh exact UI owner"),
    ("flutter", "if handler.displays.is_empty()", "if false", "empty exact-owner refresh display refusal"),
    ("flutter", "for display in &handler.displays {\n                    session.ui_handler.rearm_rgba_for_presentation_recovery(", "for display in &[0usize] {\n                    session.ui_handler.rearm_rgba_for_presentation_recovery(", "native exact-owner refresh display derivation"),
    ("flutter", "handler.renderer.notify_pending_frame(*display)?;", "// pending native texture was not re-notified", "exact-owner pending native texture notification"),
    ("flutter", "    awaiting_initial_display: bool,\n    renderer: VideoRenderer,", "    initial_display_unknown: bool,\n    renderer: VideoRenderer,", "initial display-owner state"),
    ("flutter", "fn admit_session_start(\n    is_video_session: bool,", "fn admit_session_start_disabled(\n    is_video_session: bool,", "display-owned session-start admission"),
    ("flutter", "let starts_peer_connection = !has_ui_stream\n        && is_first_ui_session\n        && is_unselected_ui_session\n        && !is_awaiting_initial_display;", "let starts_peer_connection = !has_ui_stream\n        && is_first_ui_session\n        && !is_awaiting_initial_display;", "first unselected peer connection start"),
    ("flutter", "&& is_unselected_ui_session\n        && !is_awaiting_initial_display;\n    if is_video_session", "&& is_unselected_ui_session;\n    if is_video_session", "pending initial owner cannot restart peer connection"),
    ("flutter", "&& !starts_peer_connection\n        && !is_awaiting_initial_display", "&& !starts_peer_connection\n        && false", "unselected video route refusal"),
    ("flutter", "if let Some(h) = handlers.get_mut(session_id) {\n            if h.client_owner_id.as_ref() != Some(client_owner_id)", "if let Some(h) = handlers.get_mut(session_id) {\n            if false", "under-guard exact-owner stream admission"),
    ("flutter", "let mut thread_lock = s.thread.lock().unwrap();\n        let mut handlers = s.session_handlers.write().unwrap();", "let mut handlers = s.session_handlers.write().unwrap();\n        let mut thread_lock = s.thread.lock().unwrap();", "worker-slot before handler-owner lock order"),
    ("flutter", "if starts_peer_connection && is_video_session", "if is_video_session", "initial owner marker follows exact peer start"),
    ("flutter", "h.awaiting_initial_display = true;", "h.awaiting_initial_display = false;", "initial display-owner marker commit"),
    ("flutter", "fn bind_initial_display_owner(\n    handlers: &mut HashMap<SessionID, SessionHandler>,", "fn bind_initial_display_owner_disabled(\n    handlers: &mut HashMap<SessionID, SessionHandler>,", "initial display-owner binding"),
    ("flutter", "if handlers.is_empty() || handlers.values().any(|handler| handler.displays.is_empty())", "if false", "missing explicit initial owner refusal"),
    ("flutter", "if pending.len() > 1", "if false", "ambiguous initial owner refusal"),
    ("flutter", "// that committed UI selection implicitly.\n        return Ok(());", "// that committed UI selection implicitly.\n        handlers.values_mut().for_each(|handler| handler.displays.clear());\n        return Ok(());", "reconnect explicit display-owner preservation"),
    ("flutter", "other_session_id != session_id && handler.displays.is_empty()", "false", "unmarked empty initial owner refusal"),
    ("flutter", "if !handler.displays.is_empty()", "if false", "conflicting initial owner refusal"),
    ("flutter", "usize::try_from(current_display)", "usize::try_from(0)", "claimed initial display authority"),
    ("flutter", "if display >= display_count {\n        bail!(\n            \"initial peer display", "if display > display_count {\n        bail!(\n            \"initial peer display", "initial display inventory bound"),
    ("flutter", ".any(|owned_display| *owned_display >= display_count)", ".any(|_| false)", "preserved display-owner inventory bound"),
    ("flutter", "handler.awaiting_initial_display = false;", "handler.awaiting_initial_display = true;", "one-time initial owner finality"),
    ("io_loop", "let initial_display = pi.current_display;", "let initial_display = 0;", "raw claimed initial display preservation"),
    ("io_loop", ".bind_initial_display_owner(initial_display, pi.displays.len())", ".bind_initial_display_owner(pi.current_display, pi.displays.len())", "initial admission before normalized display use"),
    ("io_loop", "self.handler.on_error(&message);\n                            return false;", "self.handler.on_error(&message);\n                            continue;", "terminal initial-owner refusal"),
    ("flutter", "if !handler.displays.contains(&display)", "if false", "software exact display membership"),
    ("ui_session", "fn bind_initial_display_owner(\n        &self,\n        current_display: i32,\n        display_count: usize,\n    ) -> ResultType<()>;", "fn bind_initial_display_owner(&self, current_display: i32, display_count: usize);", "result-bearing UI display-owner admission"),
    ("ui_session", "if self.is_file_transfer() || self.is_port_forward() || self.is_terminal()", "if true", "video-only initial display-owner requirement"),
    ("ui_session", ".bind_initial_display_owner(current_display, display_count)", ".bind_initial_display_owner(0, 0)", "exact initial display-owner delegation"),
    ("flutter", "if !self.displays.contains(&display)", "if false", "renderer size exact display membership"),
    ("flutter", "let handler = handlers.get_mut(session_id)?;\n        if handler.client_owner_id.as_ref() != Some(client_owner_id)", "let handler = handlers.get_mut(session_id)?;\n        if false", "renderer size exact UI owner"),
    ("flutter", "s.ui_handler.set_exact_owned_display_size(\n            &session_id,\n            &client_owner_id,", "s.ui_handler.set_exact_owned_display_size(\n            &session_id,\n            &session_id,", "renderer size exact owner forwarding"),
    ("flutter", ") -> ResultType<()> {\n    for s in sessions::get_sessions() {\n        if let Some(admitted) = s.ui_handler.set_exact_owned_display_size(", ") {\n    for s in sessions::get_sessions() {\n        if let Some(admitted) = s.ui_handler.set_exact_owned_display_size(", "result-bearing renderer size admission"),
    ("ffi", "super::flutter::session_set_size(session_id, client_owner_id, display, width, height)", "super::flutter::session_set_size(session_id, session_id, display, width, height)", "renderer size FFI owner forwarding"),
    ("ffi", ") -> Result<()> {\n    super::flutter::session_set_size(session_id, client_owner_id, display, width, height)", ") {\n    super::flutter::session_set_size(session_id, client_owner_id, display, width, height)", "result-bearing renderer size FFI"),
    ("model", "await _updateSessionWidthHeight(sessionId, expectedClientOwnerId);", "await _updateSessionWidthHeight(sessionId, sessionId);", "Dart renderer size owner propagation"),
    ("model", "await bind.sessionSetSize(", "bind.sessionSetSize(", "awaited Dart renderer size finality"),
    ("model", "clientOwnerId: expectedClientOwnerId", "clientOwnerId: sessionId", "Dart renderer size owner bridge argument"),
    ("model", "final restoreDisplaySelection = !isCache && _pi.isSet.value;", "final restoreDisplaySelection = false;", "established reconnect display restoration"),
    ("model", "if (!preserveDisplaySelection &&", "if (true &&", "reconnect display-state preservation"),
    ("model", "!await selectRemoteDisplays(\n                ffi, expectedSessionId, reconnectDisplays)", "false", "awaited reconnect display restoration"),
    ("model", "'The previous display selection could not be restored'", "'Reconnect display failure ignored'", "terminal reconnect display restoration failure"),
    ("web_bridge", "Future<void> sessionSetSize(\n      {required UuidValue sessionId,\n      required UuidValue clientOwnerId", "Future<void> sessionSetSize(\n      {required UuidValue sessionId,\n      required UuidValue retiredClientOwnerId", "web renderer size owner parity"),
    ("flutter", ".filter(|next| *next <= i64::MAX as u64)", ".filter(|_| true)", "Dart token bound"),
    ("flutter", ".entry((*session_id, display))", ".entry((SessionID::nil(), display))", "independent session copy"),
    ("flutter", ".and_then(|rgba| rgba.copy(publication))", ".map(|rgba| rgba.data.clone())", "exact public copy"),
    ("flutter", "mailbox.acknowledge(publication", "mailbox.acknowledge(0", "exact acknowledgement"),
    ("flutter", "EventToUI::Rgba(display, next_publication)", "EventToUI::Rgba(display, publication)", "promoted event token"),
    ("flutter", "EventToUI::Rgba(display, publication)", "EventToUI::Rgba(display, 0)", "initial/replay event token"),
    ("flutter", ".replay_ready_rgba(session_id, client_owner_id)", ".replay_ready_rgba(session_id, session_id)", "exact-owner stream replay"),
    ("flutter", "rollback_failed_session_start(session_id, client_owner_id);", "rollback_failed_session_start(session_id, session_id);", "exact-owner failed-start rollback"),
    ("flutter", "handler.client_owner_id.as_ref() != Some(client_owner_id) {\n                return None;\n            }\n            if handlers.remove(id).is_none()", "false {\n                return None;\n            }\n            if handlers.remove(id).is_none()", "failed-start replacement-owner preservation"),
    ("flutter", "retire_rgba_displays_except(&session_id, &value);", "retire_rgba_session(&session_id);", "exact display retirement"),
    ("flutter", "pub fn session_copy_rgba(", "pub fn session_get_rgba_size(", "owned copy API"),
    ("ffi", "Rgba(usize, u64)", "Rgba(usize)", "event token payload"),
    ("ffi", "SyncReturn<Option<Vec<u8>>>", "SyncReturn<usize>", "owned bridge result"),
    ("ui_session", "fn update_record_status", "fn get_rgba(&self, display: usize) -> *const u8;\n    fn update_record_status", "display-only trait authority"),
    ("native_model", "Uint8List? copyRgba(", "Uint8List? getRgba(", "native owned copy"),
    ("native_model", "_ffiBind.sessionCopyRgba(", "_session_get_rgba!(", "generated bridge copy"),
    ("model", "message.field0, message.field1)", "message.field0, 0)", "Dart event token"),
    ("model", "platformFFI.copyRgba(activeSessionId, display, publication)", "platformFFI.copyRgba(activeSessionId, display, 0)", "Dart exact copy"),
    ("model", "publication: publication", "publication: 0", "Dart exact decode acknowledgement"),
    ("model", "admission = _rgbaPublicationOrder.admit(", "admission = null; // disabled ", "Dart publication admission"),
    ("model", "expectedRgbaPublication: admission", "expectedRgbaPublication: null", "Dart decode publication propagation"),
    ("model", "_rgbaPublicationOrder.retire();", "// publication owner retained", "Dart image retirement"),
    ("publication_order", "publication <= 0", "publication < 0", "positive Dart publication admission"),
    ("publication_order", "_session == session && publication <= _publication", "_session == session && publication < _publication", "strict same-session publication order"),
    ("publication_order", "admission.revision == _revision", "true", "exact asynchronous commit revision"),
    ("publication_order_test", "a newer publication invalidates an older asynchronous completion", "an older completion is allowed", "Dart ordering regression"),
    ("publication_order_test", "out-of-order asynchronous completions commit only the latest", "out-of-order asynchronous completions commit both", "Dart asynchronous ordering regression"),
    ("web_bridge", "final int f1;", "final bool f1;", "web token parity"),
    ("ios_app", "dummy_method_to_enforce_bundling();", "dummy_method_to_enforce_bundling();\n    session_get_rgba(nil, 0);", "iOS raw pointer"),
    ("flutter", "fn r_s11ew_rgba_publication_exhaustion_fails_closed()", "fn rgba_publication_exhaustion_fails_closed()", "exhaustion regression"),
    ("flutter", "fn r_s11fr_rgba_rearm_replaces_the_token_and_promotes_only_the_latest_frame()", "fn rgba_rearm_replaces_the_token_and_promotes_only_the_latest_frame()", "re-arm behavior regression"),
    ("flutter", "fn r_s11ff_r_s11gs_video_refresh_derives_the_current_exact_ui_owner_displays()", "fn video_refresh_accepts_caller_selected_displays()", "exact-owner display authority behavior regression"),
    ("flutter", "fn r_s11gt_initial_peer_info_binds_one_exact_display_owner_once()", "fn initial_peer_info_implicitly_selects_a_display()", "initial display-owner behavior regression"),
    ("flutter", "fn r_s11gt_initial_display_binding_refuses_ambiguous_or_invalid_authority()", "fn initial_display_binding_accepts_ambiguous_authority()", "initial display-owner refusal regression"),
    ("flutter", "fn r_s11gt_reconnect_preserves_explicit_display_owners_without_rebinding()", "fn reconnect_implicitly_rebinds_display_owners()", "reconnect display-owner preservation regression"),
    ("flutter", "fn r_s11gt_session_start_requires_fresh_or_explicit_display_authority()", "fn session_start_accepts_unselected_existing_video_routes()", "display-owned session-start regression"),
    ("flutter", "fn r_s11gt_renderer_size_requires_exact_current_ui_owner()", "fn renderer_size_accepts_a_reused_session_id()", "renderer-size exact-owner regression"),
    ("flutter", "fn r_s11gt_capture_authority_excludes_renderer_resource_keys()", "fn renderer_resources_create_capture_authority()", "renderer resource-authority regression"),
    ("requirements", '<div class="req"><span class="id">R-S11ew</span>', '<div class="req"><span class="id">R-S11ew-disabled</span>', "normative requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11fr</span>', '<div class="req"><span class="id">R-S11fr-disabled</span>', "recovery normative requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11gs</span>', '<div class="req"><span class="id">R-S11gs-disabled</span>', "refresh-display authority normative requirement"),
    ("requirements", '<div class="req"><span class="id">R-S11gt</span>', '<div class="req"><span class="id">R-S11gt-disabled</span>', "initial display-owner normative requirement"),
    ("requirements", "<tr><td>305</td>", "<tr><td>305-disabled</td>", "Appendix disposition"),
    ("requirements", "<tr><td>326</td>", "<tr><td>326-disabled</td>", "recovery Appendix disposition"),
    ("requirements", "<tr><td>354</td>", "<tr><td>354-disabled</td>", "refresh-display authority Appendix disposition"),
    ("requirements", "<tr><td>355</td>", "<tr><td>355-disabled</td>", "initial display-owner Appendix disposition"),
    ("hardening", "**R-S11ew/R-S11e-184 exact, bounded, latest-wins Flutter software-RGBA publication", "**R-S11ew-disabled/R-S11e-184 exact, bounded, latest-wins Flutter software-RGBA publication", "hardening ledger"),
    ("hardening", "**R-S11fr/R-S11e-205 exact software-RGBA presentation recovery", "**R-S11fr-disabled/R-S11e-205 exact software-RGBA presentation recovery", "recovery hardening ledger"),
    ("hardening", "### R-S11gs/R-S11e-231 — exact-owner presentation-refresh display authority", "### R-S11gs-disabled/R-S11e-231 — exact-owner presentation-refresh display authority", "refresh-display authority hardening ledger"),
    ("hardening", "### R-S11gt/R-S11e-232 — explicit initial and ongoing native display ownership", "### R-S11gt-disabled/R-S11e-232 — explicit initial and ongoing native display ownership", "initial display-owner hardening ledger"),
    ("verify", "cargo test --lib --features linux-pkg-config,flutter r_s11ew_ --color never", "cargo test --lib --features linux-pkg-config,flutter disabled_ --color never", "shared behavior gate"),
    ("verify", "cargo test --lib --features linux-pkg-config,flutter r_s11fr_ --color never", "cargo test --lib --features linux-pkg-config,flutter disabled_ --color never", "shared recovery behavior gate"),
    ("verify", "cargo test --lib --features linux-pkg-config,flutter r_s11gt_ --color never", "cargo test --lib --features linux-pkg-config,flutter disabled_ --color never", "initial display-owner behavior gate"),
    ("dart_verify", "flutter test --no-pub test/rgba_publication_order_test.dart", "true # RGBA publication ordering test removed", "Dart behavior gate"),
    ("verify", "python3 scripts/verify-viewer-rgba-mailbox.py --repo . --self-test", "python3 scripts/verify-viewer-rgba-mailbox.py --repo .", "shared mutation gate"),
    ("apple", "python3 scripts/verify-viewer-rgba-mailbox.py --repo . --self-test", "python3 scripts/verify-viewer-rgba-mailbox.py --repo .", "Apple mutation gate"),
    ("workspace", '"viewer_rgba_mailbox_verifier": (', '"viewer_rgba_mailbox_verifier_disabled": (', "independent source binding"),
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
            "viewer RGBA mailbox verifier self-test passed "
            f"({len(MUTATIONS)} mutations)"
        )
    else:
        print("viewer RGBA mailbox verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"viewer RGBA mailbox verifier failed: {error}")
        raise SystemExit(1)
