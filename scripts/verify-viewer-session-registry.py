#!/usr/bin/env python3
"""Check the source shape of exact-owner viewer-session registry transactions."""

from __future__ import annotations

import argparse
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


def require_count(source: str, needle: str, count: int, label: str) -> None:
    actual = source.count(needle)
    if actual != count:
        raise VerificationError(f"{label}: expected {count}, found {actual}")


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
        "flutter": "src/flutter.rs",
        "ffi": "src/flutter_ffi.rs",
        "model": "flutter/lib/models/model.dart",
        "web": "flutter/lib/web/bridge.dart",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def validate(sources: Dict[str, str]) -> None:
    flutter = sources["flutter"]
    ffi = sources["ffi"]
    model = sources["model"]
    web = sources["web"]

    require(
        flutter,
        "collections::{hash_map::Entry, HashMap, HashSet}",
        "non-replacing registry entry API",
    )
    for retired, label in (
        ("remove_session_by_session_id", "identity-only normal retirement"),
        ("remove_failed_start_by_exact_ui_owner", "failed-start-only duplicate retirement"),
        ("would_remove_peer_by_session_id", "identity-only close prediction"),
        (
            "would_remove_peer_by_exact_ui_owner",
            "dead separate close prediction",
        ),
        ("close_event_stream", "post-removal event-stream lookup"),
    ):
        forbid(flutter, retired, label)
    forbid(
        ffi,
        "will_session_close_close_session",
        "dead separate close prediction",
    )
    forbid(
        web,
        "willSessionCloseCloseSession",
        "dead separate close prediction",
    )

    session_add = extract_braced_item(flutter, "pub fn session_add(", "viewer admission")
    require_order(
        session_add,
        (
            "let candidate = Arc::new(session.clone());",
            "let session = sessions::insert_session(",
            "candidate,",
            ")?;",
            "LocalConfig::set_remote_id(&id);",
            "Ok(session)",
        ),
        "successful registry admission before ambient last-peer publication",
    )
    forbid(
        session_add,
        "get_session_by_session_id",
        "detached duplicate-identity precheck",
    )

    insertion = extract_braced_item(
        flutter, "pub fn insert_session(", "atomic viewer registry admission"
    )
    require_order(
        insertion,
        (
            ") -> ResultType<FlutterSession>",
            "let mut sessions = SESSIONS.write().unwrap();",
            "sessions.values().any(|peer|",
            ".contains_key(&session_id)",
            'bail!("viewer UI session identity is already active")',
            ".entry((session.get_id(), conn_type))",
            ".or_insert(session)",
            "let mut handlers = peer_session.session_handlers.write().unwrap();",
            "match handlers.entry(session_id)",
            "Entry::Vacant(entry)",
            "entry.insert(handler);",
            "let peer_session = peer_session.clone();",
            "Ok(peer_session)",
        ),
        "one-lock unique admission and actual installed-peer return",
    )
    require_count(
        insertion,
        "SESSIONS.write().unwrap()",
        1,
        "single registry admission transaction",
    )
    forbid(
        insertion,
        ".insert(session_id, handler)",
        "replacing handler admission",
    )

    replacement = extract_braced_item(
        flutter,
        "pub fn replace_peer_session_display_owner(",
        "atomic existing-peer attachment",
    )
    require_order(
        replacement,
        (
            "let sessions = SESSIONS.write().unwrap();",
            "sessions.values().any(|peer|",
            ".contains_key(&session_id)",
            "let entry = match handlers.entry(session_id)",
            "Entry::Vacant(entry)",
            "s.try_select_displays(None, capture_set, refresh, || {",
            "entry.insert(h);",
        ),
        "unique existing-peer attachment before display-command publication",
    )
    require_count(
        replacement,
        "SESSIONS.write().unwrap()",
        1,
        "single existing-peer attachment transaction",
    )
    forbid(
        replacement,
        "handlers.insert(session_id, h)",
        "replacing existing-peer attachment",
    )

    retirement = extract_braced_item(
        flutter,
        "pub fn remove_session_by_exact_ui_owner(",
        "atomic exact-owner viewer retirement",
    )
    require_order(
        retirement,
        (
            "client_owner_id: &SessionID",
            "let mut sessions = SESSIONS.write().unwrap();",
            "for (peer_key, session) in sessions.iter_mut()",
            "let Some(handler) = handlers.get(id)",
            "handler.client_owner_id.as_ref() != Some(client_owner_id)",
            "return None;",
            "if handlers.remove(id).is_none()",
            "retire_rgba_session(id);",
            "if handlers.is_empty()",
            "remove_peer_key = Some(peer_key.clone());",
            "sessions.remove(&remove_peer_key?)",
        ),
        "exact handler retirement and last peer removal under one registry lock",
    )
    require_count(
        retirement,
        "SESSIONS.write().unwrap()",
        1,
        "single registry retirement transaction",
    )

    rollback = extract_braced_item(
        flutter, "fn rollback_failed_session_start(", "failed-start retirement"
    )
    require_order(
        rollback,
        (
            "client_owner_id: &SessionID",
            "remove_session_by_exact_ui_owner(session_id, client_owner_id)",
            "session.close_and_join();",
        ),
        "failed-start and normal close share exact retirement semantics",
    )

    close = extract_braced_item(ffi, "pub fn session_close(", "exact-owner close FFI")
    require_order(
        close,
        (
            "session_id: SessionID",
            "client_owner_id: SessionID",
            "remove_session_by_exact_ui_owner(&session_id, &client_owner_id)",
            "session.close_and_join();",
        ),
        "exact-owner close and complete last-peer finality",
    )
    forbid(close, "get_session_by_session_id", "close lookup outside retirement transaction")

    require_count(model, "bind.sessionClose(", 3, "all authored native close calls")
    require_count(
        model,
        "sessionId: closingSessionId, clientOwnerId: clientOwnerId",
        3,
        "all authored dual-identity close calls",
    )
    web_close = extract_braced_item(web, "Future<void> sessionClose(", "web close signature")
    require_order(
        web_close,
        ("required UuidValue sessionId", "required UuidValue clientOwnerId"),
        "web close signature dual identity",
    )

    for name in (
        "r_s11hu_registry_admission_returns_the_installed_peer_and_refuses_duplicate_identity",
        "r_s11hu_registry_retirement_requires_exact_owner_and_removes_last_peer_atomically",
        "failed_session_start_rolls_back_and_joins_only_the_exact_session",
        "stale_mobile_session_close_cannot_select_replacement_from_same_owner",
    ):
        require(flutter, name, f"{name} regression")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    args = parser.parse_args()
    sources = load_sources(args.repo.resolve())
    validate(sources)
    print("viewer session registry source shape: verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
