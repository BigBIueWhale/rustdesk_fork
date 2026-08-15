#!/usr/bin/env python3
"""Verify bounded, exact-owner native-to-Dart cursor-position publication."""

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


def extract_between(source: str, start: str, end: str, label: str) -> str:
    begin = source.find(start)
    if begin < 0:
        raise VerificationError(f"missing start for {label}")
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise VerificationError(f"missing end for {label}")
    return source[begin:finish]


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "input": "src/server/input_service.rs",
        "io_loop": "src/client/io_loop.rs",
        "flutter": "src/flutter.rs",
        "ffi": "src/flutter_ffi.rs",
        "model": "flutter/lib/models/model.dart",
        "native_model": "flutter/lib/models/native_model.dart",
        "web_model": "flutter/lib/models/web_model.dart",
        "web_bridge": "flutter/lib/web/bridge.dart",
        "cargo": "Cargo.toml",
        "lock": "Cargo.lock",
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
    input_source = sources["input"]
    require(
        input_source,
        "GenericService::repeat::<StatePos, _, _>(&svc.clone(), 33, run_pos);",
        "33-millisecond controlled cursor sampling",
    )
    run_pos = extract_braced_item(input_source, "fn run_pos(", "cursor-position producer")
    require_order(
        run_pos,
        (
            "if state.is_moved(x, y)",
            "msg_out.set_cursor_position(CursorPosition {",
            "sp.send_without(msg_out, exclude);",
        ),
        "changed cursor sample publication",
    )
    io_cursor = extract_between(
        sources["io_loop"],
        "Some(message::Union::CursorPosition(cp)) =>",
        "Some(message::Union::Clipboard(cb)) =>",
        "viewer cursor dispatch",
    )
    require(io_cursor, "self.handler.set_cursor_position(cp);", "native viewer cursor dispatch")

    require(
        sources["cargo"],
        'flutter_rust_bridge = { version = "=1.80", features = ["uuid"], optional = true}',
        "exact Flutter Rust Bridge dependency",
    )
    locked_bridge = extract_between(
        sources["lock"],
        '[[package]]\nname = "flutter_rust_bridge"',
        "\n[[package]]",
        "locked Flutter Rust Bridge package",
    )
    require_order(
        locked_bridge,
        (
            'name = "flutter_rust_bridge"',
            'version = "1.80.1"',
            'source = "registry+https://github.com/rust-lang/crates.io-index"',
            'checksum = "fd0305ebc9f097d9826530a55fc2acd63222e912c663f7adce3ab641ecc0f346"',
        ),
        "exact locked Flutter Rust Bridge 1.80.1 identity",
    )

    flutter = sources["flutter"]
    handler = extract_braced_item(flutter, "struct SessionHandler", "exact UI handler")
    require(
        handler,
        "cursor_position: CursorPositionMailbox",
        "per-exact-UI cursor mailbox",
    )
    flutter_handler = extract_braced_item(flutter, "pub struct FlutterHandler", "Flutter handler")
    require(
        flutter_handler,
        "cursor_position_publication_counter: Arc<AtomicU64>",
        "connection-wide nonreused cursor publication counter",
    )

    mailbox = extract_braced_item(
        flutter, "struct CursorPositionMailbox", "cursor-position mailbox"
    )
    require_order(
        mailbox,
        (
            "published: Option<CursorPositionPublication>",
            "pending: Option<CursorPositionValue>",
        ),
        "one published and one latest-pending cursor state",
    )
    mailbox_fields = [
        line.strip() for line in mailbox.splitlines()[1:-1] if line.strip()
    ]
    if mailbox_fields != [
        "published: Option<CursorPositionPublication>,",
        "pending: Option<CursorPositionValue>,",
    ]:
        raise VerificationError(
            f"cursor mailbox must have exactly one published and one pending field: {mailbox_fields!r}"
        )
    for forbidden in ("Vec<", "VecDeque", "HashMap", "Sender", "Receiver"):
        forbid(mailbox, forbidden, "unbounded or detached cursor mailbox state")

    offer = extract_braced_item(
        flutter,
        "fn offer<F>(&mut self, position: CursorPositionValue",
        "cursor admission",
    )
    require_order(
        offer,
        (
            "if self.published.is_some()",
            "self.pending = Some(position);",
            "return CursorPositionOffer::Pending;",
            "let Some(publication) = next_publication()",
            "self.published = Some(published);",
            "CursorPositionOffer::Published(published)",
        ),
        "one-active latest-wins cursor admission",
    )
    acknowledge = extract_braced_item(
        flutter,
        "fn acknowledge<F>(\n        &mut self,\n        expected: CursorPositionPublication",
        "cursor publication take",
    )
    require_order(
        acknowledge,
        (
            "if self.published != Some(expected)",
            "CursorPositionAcknowledgement::Ignored",
            "let Some(position) = self.pending.take()",
            "self.published = None;",
            "CursorPositionAcknowledgement::Drained",
            "let Some(publication) = next_publication()",
            "CursorPositionAcknowledgement::Exhausted",
            "self.published = Some(published);",
            "CursorPositionAcknowledgement::Promoted(published)",
        ),
        "exact take, drain, checked promotion, and exhaustion",
    )
    rearm = extract_braced_item(
        flutter,
        "fn rearm<F>(&mut self, next_publication: F) -> CursorPositionRearm",
        "cursor stream re-arm",
    )
    require_order(
        rearm,
        (
            "let Some(current) = self.published",
            "CursorPositionRearm::Idle",
            "self.pending.take().unwrap_or(current.position)",
            "let Some(publication) = next_publication()",
            "self.published = None;",
            "CursorPositionRearm::Exhausted",
            "self.published = Some(published);",
            "CursorPositionRearm::Rearmed(published)",
        ),
        "replacement stream gets only latest state and a fresh token",
    )

    barrier = extract_braced_item(
        flutter,
        "fn is_cursor_position_topology_barrier(",
        "cursor topology barrier inventory",
    )
    for name in (
        '"peer_info"',
        '"sync_peer_info"',
        '"sync_platform_additions"',
        '"switch_display"',
        '"follow_current_display"',
        '"use_texture_render"',
    ):
        require(barrier, name, f"topology barrier {name}")
    cursor_post = extract_braced_item(
        flutter, "fn post_cursor_position(", "typed cursor publication helper"
    )
    require_order(
        cursor_post,
        (
            "stream.add(EventToUI::CursorPosition(",
            "publication.position.x",
            "publication.position.y",
            "publication.publication",
        ),
        "exact typed cursor coordinates and publication token",
    )
    push_event = extract_braced_item(flutter, "pub fn push_event_<V>", "generic event publication")
    require_order(
        push_event,
        (
            "if is_cursor_position_topology_barrier(name)",
            "let mut sessions = self.session_handlers.write().unwrap();",
            "session.cursor_position.discard_pending();",
            "stream.add(EventToUI::Event(out.clone()));",
        ),
        "pre-topology pending cursor retirement before ordered event publication",
    )

    next_publication = extract_braced_item(
        flutter,
        "fn next_cursor_position_publication",
        "checked cursor publication allocation",
    )
    require_order(
        next_publication,
        (
            ".fetch_update(",
            ".checked_add(1)",
            ".filter(|next| *next <= i64::MAX as u64)",
        ),
        "positive checked Dart-compatible cursor publication sequence",
    )
    setter = extract_braced_item(
        flutter, "fn set_cursor_position(&self", "native cursor-position handoff"
    )
    require_order(
        setter,
        (
            "self.session_handlers.write().unwrap().values_mut()",
            "handler.cursor_position.offer(position",
            "CursorPositionOffer::Pending",
            "CursorPositionOffer::Published(publication)",
            "post_cursor_position(stream, publication)",
            "handler.cursor_position.clear();",
            "CursorPositionOffer::Exhausted",
        ),
        "bounded per-handler cursor handoff and failed-stream retirement",
    )
    forbid(setter, "push_event", "generic JSON cursor event")
    forbid(setter, "to_string", "cursor JSON/string serialization")
    forbid(flutter, '"cursor_position"', "native generic JSON cursor event name")

    event_enum = extract_braced_item(sources["ffi"], "pub enum EventToUI", "typed UI event")
    require(
        event_enum,
        "CursorPosition(i32, i32, u64)",
        "typed cursor coordinates and publication",
    )
    take = extract_braced_item(flutter, "fn take_cursor_position(", "exact cursor take")
    require_order(
        take,
        (
            ".get_mut(session_id)",
            "handler.client_owner_id.as_ref() == Some(client_owner_id)",
            "handler.cursor_position.acknowledge(expected",
            "CursorPositionAcknowledgement::Ignored => false",
            "CursorPositionAcknowledgement::Drained => true",
            "CursorPositionAcknowledgement::Promoted(next)",
            "post_cursor_position(stream, next)",
            "handler.cursor_position.clear();",
            "CursorPositionAcknowledgement::Exhausted",
        ),
        "exact session/owner/publication take and successor delivery",
    )
    session_take = extract_braced_item(
        flutter, "pub fn session_take_cursor_position(", "public cursor take"
    )
    require_order(
        session_take,
        (
            "session_id: SessionID",
            "client_owner_id: SessionID",
            "x: i32",
            "y: i32",
            "publication: u64",
            "session.ui_handler.take_cursor_position(",
            "&session_id",
            "&client_owner_id",
            "position: CursorPositionValue { x, y }",
            "publication,",
        ),
        "exact cursor take bridge inputs",
    )
    ffi_take = extract_braced_item(
        sources["ffi"], "pub fn session_take_cursor_position(", "cursor take FFI"
    )
    require_order(
        ffi_take,
        (
            "client_owner_id: SessionID",
            "publication: u64",
            "-> SyncReturn<bool>",
            "super::flutter::session_take_cursor_position(",
            "session_id,",
            "client_owner_id,",
            "x,",
            "y,",
            "publication,",
        ),
        "result-bearing generated cursor take",
    )

    session_start = extract_braced_item(
        flutter, "pub fn session_start_(", "exact stream installation"
    )
    require_order(
        session_start,
        (
            "try_send_close_event(&h.event_stream);",
            "h.event_stream = Some(event_stream);",
            "h.cursor_position.rearm(",
            "CursorPositionRearm::Rearmed(publication)",
            "post_cursor_position(stream, publication)",
            "h.cursor_position.clear();",
            "start_failure = Some(anyhow!(",
            "CursorPositionRearm::Exhausted",
            "if start_failure.is_none() && starts_peer_connection",
        ),
        "fresh-token latest-state replay before peer-start continuation",
    )

    model = sources["model"]
    generic_handler = extract_braced_item(
        model, "Future<void> _handleSessionEvent(", "generic Dart session event handler"
    )
    forbid(generic_handler, "cursor_position", "generic JSON cursor event branch")
    web_coordinate = extract_braced_item(
        model, "int? _webCursorCoordinate(", "bounded web cursor coordinate parser"
    )
    require_order(
        web_coordinate,
        (
            "value is int",
            "value is String",
            "int.tryParse(value)",
            "parsed < _minSigned32",
            "parsed > _maxSigned32",
            "return parsed;",
        ),
        "integral signed-32-bit web cursor coordinates",
    )
    event_listener = extract_braced_item(
        model, "StreamEventHandler startEventListener(", "generic/web event ingress"
    )
    require_order(
        event_listener,
        (
            "if (name == 'cursor_position' && isWeb)",
            "_webCursorCoordinate(evt['x'])",
            "_webCursorCoordinate(evt['y'])",
            "ffi.submitWebCursorPosition(",
            "return;",
            "_orderedSessionTopologyEvents.contains(name)",
        ),
        "web-only cursor ingress before ordered topology admission",
    )
    web_cursor_submit = extract_braced_item(
        model, "Future<LatestFrameDisposition> submitWebCursorPosition(",
        "bounded exact-owner web cursor publication"
    )
    require_order(
        web_cursor_submit,
        (
            "expectedOwner != _sessionOwner",
            "_webCursorPositions.submit(",
            "expectedOwner, 0, _WebCursorPosition(x, y)",
            "await _displayTopologyAfterCheckpoint(",
            "sessionEvents, expectedOwner, expectedSessionId",
            "cursorModel.updateCursorPosition(",
            "expectedSessionId, topologyRevision",
        ),
        "one-lane latest web cursor checkpoint and topology-bound commit",
    )
    require_order(
        model,
        (
            "_webCursorPositions = LatestFrameQueue(nextOwner, maxKeys: 1);",
            "_webCursorPositions.retire(retiringOwner)",
            "!webCursorPositionsRetired",
        ),
        "exact-owner one-key web cursor lifecycle",
    )
    cursor_handler = extract_braced_item(
        model, "Future<void> _handleCursorPosition(", "typed Dart cursor handler"
    )
    require_order(
        cursor_handler,
        (
            "await _displayTopologyAfterCheckpoint(",
            "platformFFI.takeCursorPosition(",
            "streamOwner.clientOwnerId",
            "if (!accepted || topologyRevision == null) return;",
            "cursorModel.updateCursorPosition(",
            "activeSessionId, topologyRevision",
        ),
        "completed topology checkpoint, exact take, and revision-bound cursor commit",
    )
    stream_listener = extract_braced_item(
        model, "void _listenToSessionStream(", "Dart session stream listener"
    )
    require_order(
        stream_listener,
        (
            "message is EventToUI_CursorPosition",
            "_handleCursorPosition(",
            "message.field0",
            "message.field1",
            "message.field2",
        ),
        "typed cursor stream dispatch",
    )
    require_order(
        stream_listener,
        (
            "if (isWeb)",
            "platformFFI.setRgbaCallback(",
            "return;",
            "final cb = ffiModel.startEventListener(",
            "stream.listen(",
            "message is EventToUI_CursorPosition",
        ),
        "web returns before the native typed cursor stream listener",
    )
    cursor_update = extract_braced_item(
        model, "bool updateCursorPosition(", "cursor model commit"
    )
    require_order(
        cursor_update,
        (
            "expectedDisplayTopologyRevision",
            "ffiModel.isCurrentDisplayTopology(",
            "return false;",
            "_x = x.toDouble();",
            "_y = y.toDouble();",
            "notifyListeners();",
            "return true;",
        ),
        "synchronous topology-revision-bound cursor mutation",
    )
    forbid(cursor_update, "double.parse", "string cursor coordinate parsing")

    for key in ("native_model", "web_model"):
        wrapper = extract_braced_item(
            sources[key], "bool takeCursorPosition(", f"{key} cursor wrapper"
        )
        require_order(
            wrapper,
            (
                "SessionID sessionId",
                "SessionID clientOwnerId",
                "int x",
                "int y",
                "int publication",
                "sessionTakeCursorPosition(",
                "sessionId: sessionId",
                "clientOwnerId: clientOwnerId",
                "x: x",
                "y: y",
                "publication: publication",
            ),
            f"{key} exact cursor take wrapper",
        )
    require(
        sources["web_bridge"],
        "class EventToUI_CursorPosition implements EventToUI",
        "web typed-event source parity",
    )
    require(
        sources["web_bridge"],
        "bool sessionTakeCursorPosition(",
        "web cursor-take source parity",
    )

    for test in (
        "r_s11gu_cursor_position_mailbox_retains_one_publication_and_only_the_latest_successor",
        "r_s11gu_cursor_topology_barrier_discards_only_pre_topology_pending_state",
        "r_s11gu_cursor_stream_rearm_replaces_the_token_and_keeps_only_latest_state",
    ):
        require(flutter, test, f"deterministic {test} regression")
    mailbox_test = extract_braced_item(
        flutter,
        "fn r_s11gu_cursor_position_mailbox_retains_one_publication_and_only_the_latest_successor",
        "exact cursor mailbox regression",
    )
    require(
        mailbox_test,
        "publication: first_publication.publication + 1",
        "isolated wrong-token cursor refusal regression",
    )
    rearm_test = extract_braced_item(
        flutter,
        "fn r_s11gu_cursor_stream_rearm_replaces_the_token_and_keeps_only_latest_state",
        "cursor re-arm and exhaustion regression",
    )
    require_order(
        rearm_test,
        (
            "mailbox.acknowledge(exhausted_publication, || None)",
            "mailbox.offer(first, || None)",
            "CursorPositionOffer::Exhausted",
            "mailbox.offer(first, || Some(4))",
            "mailbox.rearm(|| None)",
            "CursorPositionRearm::Exhausted",
        ),
        "acknowledgement, initial-offer, and stream-rearm exhaustion regressions",
    )

    for key, needle, label in (
        ("verify", "python3 scripts/verify-viewer-cursor-mailbox.py --repo . --self-test", "shared focused gate"),
        ("verify", "cargo test --lib --features linux-pkg-config,flutter r_s11gu_ --color never", "shared Rust behavior gate"),
        ("dart_verify", "python3 scripts/verify-viewer-cursor-mailbox.py --repo . --self-test", "generated-bridge focused gate"),
        ("dart_verify", "flutter::mobile_session_lifecycle_tests::r_s11gu_", "generated-bridge Rust behavior gate"),
        ("apple", "python3 scripts/verify-viewer-cursor-mailbox.py --repo . --self-test", "Apple/shared focused gate"),
        ("requirements", '<div class="req"><span class="id">R-S11gu</span>', "normative cursor mailbox requirement"),
        ("requirements", 'Dart <span class="kw">MUST</span> still attempt the exact take after checkpoint completion', "normative stale-topology cursor acknowledgement liveness"),
        ("requirements", "<tr><td>356</td>", "Appendix C cursor mailbox row"),
        ("requirements", "invalidation suppresses the stale coordinate commit but not the exact acknowledgement", "Appendix C stale-topology cursor acknowledgement liveness"),
        ("hardening", "### R-S11gu/R-S11e-233 — bounded exact-owner native-to-Dart cursor publication", "hardening ledger entry"),
        ("hardening", "but still performs that exact take", "hardening stale-topology cursor acknowledgement liveness"),
        ("workspace", "bounded exact-owner native-to-Dart cursor publication", "independent workspace contract"),
    ):
        require(sources[key], needle, label)

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
    ("input", "&svc.clone(), 33, run_pos", "&svc.clone(), 3, run_pos", "controlled cursor cadence"),
    ("cargo", 'flutter_rust_bridge = { version = "=1.80"', 'flutter_rust_bridge = { version = "1.80"', "exact Flutter Rust Bridge dependency"),
    ("lock", 'name = "flutter_rust_bridge"\nversion = "1.80.1"', 'name = "flutter_rust_bridge"\nversion = "1.80.0"', "exact locked Flutter Rust Bridge identity"),
    ("flutter", "pending: Option<CursorPositionValue>", "pending: Vec<CursorPositionValue>", "latest-only mailbox"),
    ("flutter", "pending: Option<CursorPositionValue>,", "pending: Option<CursorPositionValue>,\n    retained: Option<CursorPositionValue>,", "exact cursor mailbox field inventory"),
    ("flutter", "self.pending = Some(position);", "self.pending.get_or_insert(position);", "latest-wins replacement"),
    ("flutter", "if self.published != Some(expected)", "if self.published.is_none()", "exact publication take"),
    ("flutter", "self.pending.take().unwrap_or(current.position)", "current.position", "latest-state stream rearm"),
    ("flutter", '"switch_display"', '"switch_display_disabled"', "topology barrier inventory"),
    ("flutter", "stream.add(EventToUI::CursorPosition(\n        publication.position.x,\n        publication.position.y,\n        publication.publication,\n    ))", "stream.add(EventToUI::CursorPosition(\n        publication.position.y,\n        publication.position.x,\n        0,\n    ))", "exact typed cursor event payload"),
    ("flutter", "session.cursor_position.discard_pending();", "session.cursor_position.clear();", "topology ordering"),
    ("flutter", "let mut sessions = self.session_handlers.write().unwrap();", "let sessions = self.session_handlers.read().unwrap();", "topology/cursor write-lock linearization"),
    (
        "flutter",
        "self.cursor_position_publication_counter\n"
        "            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {\n"
        "                current\n"
        "                    .checked_add(1)\n"
        "                    .filter(|next| *next <= i64::MAX as u64)",
        "self.cursor_position_publication_counter\n"
        "            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {\n"
        "                current\n"
        "                    .checked_add(1)\n"
        "                    .filter(|_| true)",
        "Dart-compatible cursor token bound",
    ),
    ("flutter", "handler.client_owner_id.as_ref() == Some(client_owner_id)", "true", "exact UI-owner take"),
    ("flutter", "CursorPositionAcknowledgement::Ignored => false", "CursorPositionAcknowledgement::Ignored => true", "stale take refusal"),
    ("flutter", "post_cursor_position(stream, publication)", "true", "initial cursor notification"),
    ("flutter", "post_cursor_position(stream, next)", "true", "promoted cursor notification"),
    ("flutter", "if !post_cursor_position(stream, next) {\n                        handler.cursor_position.clear();\n                    }", "if !post_cursor_position(stream, next) {\n                        // failed promoted cursor notification was ignored\n                    }", "promoted cursor failure cleanup"),
    ("flutter", "let position = CursorPositionValue { x: cp.x, y: cp.y };", "self.push_event(\"cursor_position\", &[(\"x\", &cp.x.to_string()), (\"y\", &cp.y.to_string())], &[]);\n        let position = CursorPositionValue { x: cp.x, y: cp.y };", "native generic JSON cursor event absence"),
    ("flutter", "h.cursor_position.rearm(", "CursorPositionMailbox::default().rearm(", "replacement stream replay"),
    ("flutter", ".is_some_and(|stream| post_cursor_position(stream, publication));", ".is_some_and(|_| true);", "replacement stream cursor notification"),
    ("flutter", "if !delivered {\n                        h.cursor_position.clear();", "if !delivered {\n                        // failed replacement cursor state was retained", "replacement stream cursor failure cleanup"),
    ("flutter", "fn r_s11gu_cursor_position_mailbox_retains_one_publication_and_only_the_latest_successor", "fn cursor_position_mailbox_is_unbounded", "mailbox regression"),
    ("flutter", "fn r_s11gu_cursor_topology_barrier_discards_only_pre_topology_pending_state", "fn cursor_topology_barrier_is_disabled", "topology regression"),
    ("flutter", "fn r_s11gu_cursor_stream_rearm_replaces_the_token_and_keeps_only_latest_state", "fn cursor_stream_rearm_reuses_the_token", "rearm regression"),
    ("flutter", "publication: first_publication.publication + 1", "publication: first_publication.publication", "isolated wrong-token regression"),
    ("flutter", "mailbox.offer(first, || None)", "mailbox.offer(first, || Some(4))", "initial cursor publication exhaustion regression"),
    ("flutter", "mailbox.rearm(|| None)", "mailbox.rearm(|| Some(5))", "stream re-arm exhaustion regression"),
    ("ffi", "CursorPosition(i32, i32, u64)", "CursorPosition(String)", "typed cursor event"),
    ("ffi", "pub fn session_take_cursor_position(", "pub fn session_ignore_cursor_position(", "result-bearing cursor take"),
    ("flutter", "position: CursorPositionValue { x, y },\n                publication,", "position: CursorPositionValue { x: y, y: x },\n                publication,", "exact public cursor take coordinates"),
    ("flutter", "position: CursorPositionValue { x, y },\n                publication,", "position: CursorPositionValue { x, y },\n                publication: 0,", "exact public cursor take token"),
    ("ffi", "super::flutter::session_take_cursor_position(\n        session_id,\n        client_owner_id,\n        x,\n        y,\n        publication,", "super::flutter::session_take_cursor_position(\n        session_id,\n        client_owner_id,\n        y,\n        x,\n        publication,", "exact FFI cursor coordinates"),
    (
        "model",
        "final topologyRevision = await _displayTopologyAfterCheckpoint(\n"
        "        sessionEvents, streamOwner, activeSessionId);\n"
        "    final accepted = platformFFI.takeCursorPosition(",
        "const topologyRevision = 0;\n"
        "    final accepted = platformFFI.takeCursorPosition(",
        "cursor topology checkpoint",
    ),
    (
        "model",
        "    final accepted = platformFFI.takeCursorPosition(\n"
        "        activeSessionId,\n"
        "        streamOwner.clientOwnerId,\n"
        "        x,\n"
        "        y,\n"
        "        publication);\n"
        "    if (!accepted || topologyRevision == null) return;",
        "    if (topologyRevision == null) return;\n"
        "    final accepted = platformFFI.takeCursorPosition(\n"
        "        activeSessionId,\n"
        "        streamOwner.clientOwnerId,\n"
        "        x,\n"
        "        y,\n"
        "        publication);\n"
        "    if (!accepted) return;",
        "stale-topology cursor acknowledgement liveness",
    ),
    (
        "model",
        "    if (!accepted || topologyRevision == null) return;\n"
        "    cursorModel.updateCursorPosition(",
        "    if (topologyRevision == null) return;\n"
        "    cursorModel.updateCursorPosition(",
        "refused native cursor take",
    ),
    ("model", "platformFFI.takeCursorPosition(", "platformFFI.ignoreCursorPosition(", "exact native cursor take"),
    ("model", "message is EventToUI_CursorPosition", "message is EventToUI_Event", "typed cursor dispatch"),
    ("model", "      return;\n    }\n\n    final cb = ffiModel.startEventListener(activeSessionId, peerId);", "    }\n\n    final cb = ffiModel.startEventListener(activeSessionId, peerId);", "web bypasses native typed cursor stream"),
    ("model", "if (name == 'cursor_position' && isWeb)", "if (name == 'cursor_position')", "web-only cursor ingress"),
    ("model", "parsed < _minSigned32 || parsed > _maxSigned32", "false", "bounded web cursor coordinates"),
    ("model", "_webCursorPositions = LatestFrameQueue(nextOwner, maxKeys: 1);", "_webCursorPositions = LatestFrameQueue(nextOwner);", "bounded web cursor lane"),
    ("model", "expectedOwner, 0, _WebCursorPosition(x, y)", "_sessionOwner, 0, _WebCursorPosition(x, y)", "exact-owner web cursor lane"),
    (
        "model",
        "final topologyRevision = await _displayTopologyAfterCheckpoint(\n"
        "          sessionEvents, expectedOwner, expectedSessionId);",
        "const topologyRevision = 0;",
        "web cursor topology checkpoint",
    ),
    ("model", "!webCursorPositionsRetired", "false", "web cursor retirement"),
    (
        "model",
        "bool updateCursorPosition(int x, int y, String id,\n"
        "      SessionID expectedSessionId, int expectedDisplayTopologyRevision) {\n"
        "    if (parent.target?.ffiModel.isCurrentDisplayTopology(\n"
        "            expectedSessionId, expectedDisplayTopologyRevision) !=",
        "bool updateCursorPosition(int x, int y, String id,\n"
        "      SessionID expectedSessionId, int expectedDisplayTopologyRevision) {\n"
        "    if (parent.target?.ffiModel.ignoresCurrentDisplayTopology(\n"
        "            expectedSessionId, expectedDisplayTopologyRevision) !=",
        "cursor topology revision",
    ),
    ("native_model", "bool takeCursorPosition(", "bool ignoreCursorPosition(", "native wrapper"),
    ("native_model", "x: x,\n          y: y,\n          publication: publication", "x: y,\n          y: x,\n          publication: publication", "native wrapper exact cursor coordinates"),
    ("web_model", "x: x,\n          y: y,\n          publication: publication", "x: y,\n          y: x,\n          publication: publication", "web wrapper exact cursor coordinates"),
    ("web_bridge", "class EventToUI_CursorPosition implements EventToUI", "class EventToUI_CursorPositionDisabled implements EventToUI", "web event parity"),
    ("verify", "python3 scripts/verify-viewer-cursor-mailbox.py --repo . --self-test", "true # cursor verifier disabled", "shared focused gate"),
    ("dart_verify", "python3 scripts/verify-viewer-cursor-mailbox.py --repo . --self-test", "true # cursor verifier disabled", "generated-bridge focused gate"),
    ("apple", "python3 scripts/verify-viewer-cursor-mailbox.py --repo . --self-test", "true # cursor verifier disabled", "Apple focused gate"),
    ("requirements", '<div class="req"><span class="id">R-S11gu</span>', '<div class="req"><span class="id">R-S11gu-disabled</span>', "normative requirement"),
    ("requirements", 'Dart <span class="kw">MUST</span> still attempt the exact take after checkpoint completion', 'Dart <span class="kw">MUST NOT</span> attempt the exact take after checkpoint completion', "normative stale-topology cursor acknowledgement liveness"),
    ("requirements", "<tr><td>356</td>", "<tr><td>356-disabled</td>", "Appendix disposition"),
    ("requirements", "invalidation suppresses the stale coordinate commit but not the exact acknowledgement", "invalidation suppresses the stale coordinate commit and skips the exact acknowledgement", "Appendix stale-topology cursor acknowledgement liveness"),
    ("hardening", "### R-S11gu/R-S11e-233 — bounded exact-owner native-to-Dart cursor publication", "### R-S11gu-disabled/R-S11e-233 — bounded exact-owner native-to-Dart cursor publication", "hardening ledger"),
    ("hardening", "but still performs that exact take", "and returns before that exact take", "hardening stale-topology cursor acknowledgement liveness"),
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
            "viewer cursor mailbox verifier self-test passed "
            f"({len(MUTATIONS)} mutations)"
        )
    else:
        print("viewer cursor mailbox verifier passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"viewer cursor mailbox verifier failed: {error}")
        raise SystemExit(1)
