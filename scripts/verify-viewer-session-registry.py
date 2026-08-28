#!/usr/bin/env python3
"""Verify atomic, exact-owner outgoing viewer-session registry transactions."""

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
        "verify": "scripts/verify.sh",
        "dart_verify": "scripts/dart-verify.sh",
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
        ("close_event_stream", "post-removal event-stream lookup"),
    ):
        forbid(flutter, retired, label)

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

    prediction = extract_braced_item(
        flutter,
        "pub fn would_remove_peer_by_exact_ui_owner(",
        "exact-owner close prediction",
    )
    require_order(
        prediction,
        (
            "client_owner_id: &SessionID",
            "read_lock.get(id)",
            "handler.client_owner_id.as_ref() == Some(client_owner_id)",
            "&& read_lock.len() == 1",
        ),
        "close prediction uses the same dual identity",
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

    close_prediction = extract_braced_item(
        ffi,
        "pub fn will_session_close_close_session(",
        "exact-owner close-prediction FFI",
    )
    require_order(
        close_prediction,
        (
            "session_id: SessionID",
            "client_owner_id: SessionID",
            "would_remove_peer_by_exact_ui_owner(",
            "&session_id",
            "&client_owner_id",
        ),
        "exact-owner close-prediction bridge",
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
    for signature, label in (
        ("Future<void> sessionClose(", "web close signature"),
        ("bool willSessionCloseCloseSession(", "web close-prediction signature"),
    ):
        item = extract_braced_item(web, signature, label)
        require_order(
            item,
            ("required UuidValue sessionId", "required UuidValue clientOwnerId"),
            f"{label} dual identity",
        )

    for name in (
        "r_s11hu_registry_admission_returns_the_installed_peer_and_refuses_duplicate_identity",
        "r_s11hu_registry_retirement_requires_exact_owner_and_removes_last_peer_atomically",
        "failed_session_start_rolls_back_and_joins_only_the_exact_session",
        "stale_mobile_session_close_cannot_select_replacement_from_same_owner",
    ):
        require(flutter, name, f"{name} regression")

    gate = "python3 scripts/verify-viewer-session-registry.py --repo . --self-test"
    for key, needle, label in (
        ("verify", gate, "shared focused gate"),
        ("dart_verify", gate, "Dart focused gate"),
        ("apple", gate, "Apple/shared focused gate"),
        (
            "requirements",
            '<div class="req"><span class="id">R-S11hu</span>',
            "normative requirement",
        ),
        ("requirements", "<tr><td>380</td>", "Appendix C row"),
        (
            "hardening",
            "### R-S11hu/R-S11e-258 — atomic exact-owner outgoing viewer-session registry",
            "hardening ledger",
        ),
        (
            "workspace",
            "def validate_viewer_session_registry_contract(sources):",
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
        raise VerificationError("independent viewer-registry source map is absent")
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
        raise VerificationError("independent viewer-registry source map is not singular")
    source_map_keys = [
        key.value
        for key in source_maps[0].keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    ]
    if source_map_keys.count("viewer_session_registry_verifier") != 1:
        raise VerificationError("independent viewer-registry verifier binding is absent")

    validate_sources = next(
        (
            node
            for node in workspace_module.body
            if isinstance(node, ast.FunctionDef) and node.name == "validate_sources"
        ),
        None,
    )
    if validate_sources is None:
        raise VerificationError("independent viewer-registry dispatch owner is absent")
    dispatches = [
        node
        for node in validate_sources.body
        if isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "validate_viewer_session_registry_contract"
    ]
    if len(dispatches) != 1:
        raise VerificationError(
            "independent viewer-registry dispatch must occur exactly once"
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
    ("flutter", "let session = sessions::insert_session(", "sessions::insert_session(", "successful registry admission before ambient last-peer publication"),
    ("flutter", "LocalConfig::set_remote_id(&id);", "// last-peer publication omitted", "successful registry admission before ambient last-peer publication"),
    ("flutter", ") -> ResultType<FlutterSession> {\n        let mut sessions = SESSIONS.write().unwrap();", ") -> ResultType<FlutterSession> {\n        let sessions = SESSIONS.read().unwrap();", "one-lock unique admission and actual installed-peer return"),
    ("flutter", "let mut handlers = peer_session.session_handlers.write().unwrap();\n        match handlers.entry(session_id)", "let mut handlers = peer_session.session_handlers.write().unwrap();\n        if let Entry::Vacant(entry) = handlers.entry(session_id)", "one-lock unique admission and actual installed-peer return"),
    ("flutter", "let peer_session = peer_session.clone();", "let peer_session = session.clone();", "one-lock unique admission and actual installed-peer return"),
    ("flutter", "pub fn remove_session_by_exact_ui_owner(", "pub fn remove_session_by_session_id(", "identity-only normal retirement"),
    ("flutter", "let Some(handler) = handlers.get(id) else {\n                continue;\n            };\n            if handler.client_owner_id.as_ref() != Some(client_owner_id)", "let Some(handler) = handlers.get(id) else {\n                continue;\n            };\n            if false", "exact handler retirement and last peer removal under one registry lock"),
    ("flutter", "sessions.remove(&remove_peer_key?)", "SESSIONS.write().unwrap().remove(&remove_peer_key?)", "exact handler retirement and last peer removal under one registry lock"),
    ("flutter", "pub fn would_remove_peer_by_exact_ui_owner(", "pub fn would_remove_peer_by_session_id(", "identity-only close prediction"),
    ("ffi", "would_remove_peer_by_exact_ui_owner(", "would_remove_peer_by_session_id(", "exact-owner close-prediction bridge"),
    ("ffi", "remove_session_by_exact_ui_owner(&session_id, &client_owner_id)", "remove_session_by_exact_ui_owner(&session_id, &session_id)", "exact-owner close and complete last-peer finality"),
    ("model", "Future<void> _closeNativeSession(SessionID closingSessionId) async {\n    try {\n      await bind.sessionClose(\n          sessionId: closingSessionId, clientOwnerId: clientOwnerId);", "Future<void> _closeNativeSession(SessionID closingSessionId) async {\n    try {\n      await bind.sessionClose(\n          sessionId: closingSessionId, clientOwnerId: closingSessionId);", "all authored dual-identity close calls"),
    ("web", "Future<void> sessionClose(\n      {required UuidValue sessionId,\n      required UuidValue clientOwnerId,", "Future<void> sessionClose(\n      {required UuidValue sessionId,\n      UuidValue? clientOwnerId,", "web close signature dual identity"),
    ("flutter", "fn r_s11hu_registry_admission_returns_the_installed_peer_and_refuses_duplicate_identity()", "fn registry_admission_can_replace_duplicate_identity()", "r_s11hu_registry_admission_returns_the_installed_peer_and_refuses_duplicate_identity regression"),
    ("flutter", "fn r_s11hu_registry_retirement_requires_exact_owner_and_removes_last_peer_atomically()", "fn registry_retirement_ignores_owner()", "r_s11hu_registry_retirement_requires_exact_owner_and_removes_last_peer_atomically regression"),
    ("verify", "python3 scripts/verify-viewer-session-registry.py --repo . --self-test", "true # viewer registry gate disabled", "shared focused gate"),
    ("dart_verify", "python3 scripts/verify-viewer-session-registry.py --repo . --self-test", "true # viewer registry gate disabled", "Dart focused gate"),
    ("apple", "python3 scripts/verify-viewer-session-registry.py --repo . --self-test", "true # viewer registry gate disabled", "Apple/shared focused gate"),
    ("requirements", '<div class="req"><span class="id">R-S11hu</span>', '<div class="req"><span class="id">R-S11hu-disabled</span>', "normative requirement"),
    ("requirements", "<tr><td>380</td>", "<tr><td>380-disabled</td>", "Appendix C row"),
    ("hardening", "### R-S11hu/R-S11e-258 — atomic exact-owner outgoing viewer-session registry", "### R-S11hu-disabled/R-S11e-258 — atomic exact-owner outgoing viewer-session registry", "hardening ledger"),
    ("workspace", "\n\ndef validate_viewer_session_registry_contract(sources):\n    focused =", "\n\ndef validate_viewer_session_registry_contract_disabled(sources):\n    focused =", "independent workspace contract"),
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
        print(f"viewer session registry: {len(MUTATIONS)} mutations rejected")
    else:
        print("viewer session registry: verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
