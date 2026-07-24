#!/usr/bin/env python3
"""Verify authenticated Linux/macOS incumbent-listener detection."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, Tuple


class VerificationError(RuntimeError):
    pass


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}")


def require_order(source: str, needles: Tuple[str, ...], label: str) -> None:
    position = -1
    for needle in needles:
        position = source.find(needle, position + 1)
        if position < 0:
            raise VerificationError(f"{label}: missing or misordered {needle!r}")


def extract_rust_function(source: str, signature: str, label: str) -> str:
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
    return {
        "fs": (repo / "src/ipc/fs.rs").read_text(encoding="utf-8"),
        "auth": (repo / "src/ipc/auth.rs").read_text(encoding="utf-8"),
        "ipc": (repo / "src/ipc.rs").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "apple": (repo / "scripts/apple-conform-check.sh").read_text(encoding="utf-8"),
    }


def validate(sources: Dict[str, str]) -> None:
    executable_identity = extract_rust_function(
        sources["auth"],
        "pub(crate) fn peer_executable_is_current_by_pid(",
        "fallible current-executable identity predicate",
    )
    require_order(
        executable_identity,
        (
            "let peer_exe = peer_exe_canonical_path_by_pid(peer_pid)?;",
            "let current_exe = current_exe_canonical_path()?;",
            "Ok(executable_paths_match(&peer_exe, &current_exe))",
        ),
        "fallible peer/current executable comparison",
    )

    policy = extract_rust_function(
        sources["fs"],
        "fn existing_listener_identity_is_acceptable(",
        "incumbent identity policy",
    )
    require(
        policy,
        "peer_uid == current_uid && executable_matches",
        "UID plus executable conjunction",
    )

    probe = extract_rust_function(
        sources["fs"],
        "async fn probe_existing_listener(",
        "fallible incumbent listener probe",
    )
    require(
        probe,
        "async fn probe_existing_listener(postfix: &str) -> ResultType<bool>",
        "fallible incumbent probe result",
    )
    require_order(
        probe,
        (
            "let Ok(mut stream) = connect(1000, postfix).await else",
            "return Ok(false);",
            'if postfix == "_cm"',
            "authenticate_cm_endpoint(",
            'if postfix == "_pa"',
            "let Ok(expected) = current_linux_process_identity()",
            'ensure_linux_process_identity_matches(&stream, &expected, "_pa")',
            "let current_uid = unsafe { hbb_common::libc::geteuid() as u32 };",
            "let peer_uid = stream.peer_uid().ok_or_else(",
            "if peer_uid != current_uid",
            "return Ok(false);",
            "let peer_pid = stream.peer_pid().ok_or_else(",
            "let executable_matches = peer_executable_is_current_by_pid(peer_pid)?;",
            "if !existing_listener_identity_is_acceptable(",
            "return Ok(false);",
            "if postfix != crate::POSTFIX_SERVICE",
            "return Ok(true);",
            "stream.send(&Data::Test).await.map_err(",
            "Ok(Some(Data::Test)) => Ok(true)",
            "Ok(response) => Err(",
            "Err(err) => Err(",
        ),
        "special proof, generic identity, and protected liveness ordering",
    )
    for forbidden in (
        "if postfix != crate::POSTFIX_SERVICE {\n        return true;",
        "if stream.send(&Data::Test).await.is_err() {\n        return Ok(false);",
        "matches!(stream.next_timeout(1000).await, Ok(Some(Data::Test)))",
    ):
        if forbidden in probe:
            raise VerificationError(
                "incumbent probe retains connect-only or ambiguous cleanup authority"
            )

    check_pid = extract_rust_function(
        sources["fs"], "pub(crate) async fn check_pid(", "fallible singleton check"
    )
    require(
        check_pid,
        "pub(crate) async fn check_pid(postfix: &str) -> ResultType<bool>",
        "fallible singleton result",
    )
    require_order(
        check_pid,
        (
            "probe_existing_listener(postfix).await?",
            "probe_existing_listener(postfix).await?",
            "remove_ipc_socket_via_secure_parent_fd(postfix)",
            "Ok(false)",
        ),
        "identity proof before stale cleanup",
    )

    listener = extract_rust_function(
        sources["ipc"], "pub async fn new_listener(", "Unix listener constructor"
    )
    require_order(
        listener,
        (
            "let existing_listener_alive = check_pid(postfix).await?;",
            "should_scrub_parent_entries_after_check_pid(",
            "let mut endpoint = Endpoint::new(path.clone());",
        ),
        "fallible incumbent check before endpoint creation",
    )

    require(
        sources["fs"],
        "fn r_s11e85_existing_listener_requires_current_principal_and_executable()",
        "focused incumbent identity regression",
    )
    for negative in (
        "1001, 1000, true",
        "1000, 1000, false",
    ):
        require(sources["fs"], negative, f"incumbent identity negative {negative}")

    for key, needle, label in (
        ("requirements", '<span class="id">R-S11bs</span>', "R-S11bs requirement"),
        ("requirements", "<tr><td>212</td>", "Appendix C #212"),
        (
            "hardening",
            "R-S11bs/R-S11e-85 — Unix incumbent-listener identity is explicit",
            "incumbent-listener hardening ledger",
        ),
        (
            "verify",
            "python3 scripts/verify-unix-listener-incumbent.py --repo . --self-test",
            "shared focused-verifier wiring",
        ),
        (
            "apple",
            "python3 scripts/verify-unix-listener-incumbent.py --repo . --self-test",
            "Apple focused-verifier wiring",
        ),
    ):
        require(sources[key], needle, label)


Mutation = Tuple[str, str, str, str]

MUTATIONS: Tuple[Mutation, ...] = (
    (
        "auth",
        "Ok(executable_paths_match(&peer_exe, &current_exe))",
        "Ok(true)",
        "peer/current executable equality",
    ),
    (
        "fs",
        "peer_uid == current_uid && executable_matches",
        "peer_uid == current_uid || executable_matches",
        "UID and executable conjunction",
    ),
    (
        "fs",
        "async fn probe_existing_listener(postfix: &str) -> ResultType<bool>",
        "async fn probe_existing_listener(postfix: &str) -> bool",
        "fallible incumbent probe",
    ),
    (
        "fs",
        'ensure_linux_process_identity_matches(&stream, &expected, "_pa")',
        "Ok(())",
        "PA minimal process identity proof",
    ),
    (
        "fs",
        "let peer_uid = stream.peer_uid().ok_or_else(|| {",
        "let peer_uid = stream.peer_uid().unwrap_or(current_uid); if false {",
        "missing peer UID refusal",
    ),
    (
        "fs",
        "if peer_uid != current_uid {",
        "if false {",
        "peer UID mismatch refusal",
    ),
    (
        "fs",
        "let peer_pid = stream.peer_pid().ok_or_else(|| {",
        "let peer_pid = stream.peer_pid().unwrap_or_default(); if false {",
        "missing peer PID refusal",
    ),
    (
        "fs",
        "let executable_matches = peer_executable_is_current_by_pid(peer_pid)?;",
        "let executable_matches = true;",
        "fallible executable identity proof",
    ),
    (
        "fs",
        "if !existing_listener_identity_is_acceptable(peer_uid, current_uid, executable_matches) {",
        "if false {",
        "generic incumbent identity enforcement",
    ),
    (
        "fs",
        "stream.send(&Data::Test).await.map_err(|err| {",
        "if stream.send(&Data::Test).await.is_err() { return Ok(false); } let _ = (|err| {",
        "protected liveness write ambiguity",
    ),
    (
        "fs",
        "Ok(response) => Err(Error::new(",
        "Ok(_response) => Ok(true).and_then(|_| Err(Error::new(",
        "malformed protected liveness refusal",
    ),
    (
        "fs",
        "pub(crate) async fn check_pid(postfix: &str) -> ResultType<bool>",
        "pub(crate) async fn check_pid(postfix: &str) -> bool",
        "fallible singleton check",
    ),
    (
        "ipc",
        "let existing_listener_alive = check_pid(postfix).await?;",
        "let existing_listener_alive = check_pid(postfix).await;",
        "listener error propagation",
    ),
    (
        "fs",
        "fn r_s11e85_existing_listener_requires_current_principal_and_executable()",
        "fn incumbent_listener_accepts_any_connected_peer()",
        "focused identity regression",
    ),
    (
        "requirements",
        '<span class="id">R-S11bs</span>',
        '<span class="id">R-S11bs-disabled</span>',
        "R-S11bs requirement",
    ),
    (
        "requirements",
        "<tr><td>212</td>",
        "<tr><td>212-disabled</td>",
        "Appendix C #212",
    ),
    (
        "hardening",
        "R-S11bs/R-S11e-85 — Unix incumbent-listener identity is explicit",
        "R-S11bs/R-S11e-85 — Unix incumbent-listener identity is ambient",
        "hardening ledger",
    ),
    (
        "verify",
        "python3 scripts/verify-unix-listener-incumbent.py --repo . --self-test",
        "true # Unix incumbent-listener verifier removed",
        "shared gate wiring",
    ),
    (
        "apple",
        "python3 scripts/verify-unix-listener-incumbent.py --repo . --self-test",
        "true # Unix incumbent-listener verifier removed",
        "Apple gate wiring",
    ),
)


def run_mutations(sources: Dict[str, str]) -> None:
    for key, old, new, label in MUTATIONS:
        if sources[key].count(old) != 1:
            raise VerificationError(f"mutation anchor is not unique for {label}")
        mutated = dict(sources)
        mutated[key] = sources[key].replace(old, new, 1)
        try:
            validate(mutated)
        except VerificationError:
            continue
        raise VerificationError(f"mutation was not rejected: {label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    sources = load_sources(args.repo.resolve())
    validate(sources)
    if args.self_test:
        run_mutations(sources)
    print(
        "Unix incumbent-listener semantic validation: OK"
        + (f" ({len(MUTATIONS)} mutations)" if args.self_test else "")
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, VerificationError) as error:
        print(
            f"Unix incumbent-listener verification failed: {error}",
            file=__import__("sys").stderr,
        )
        raise SystemExit(1)
