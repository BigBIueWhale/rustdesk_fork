#!/usr/bin/env python3
"""Verify exact Linux/macOS desktop helper process-role authentication."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, Tuple


class VerificationError(RuntimeError):
    pass


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}")


def require_exact_count(source: str, needle: str, count: int, label: str) -> None:
    actual = source.count(needle)
    if actual != count:
        raise VerificationError(f"{label}: expected {count}, found {actual}")


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
        "auth": (repo / "src/ipc/auth.rs").read_text(encoding="utf-8"),
        "platform": (repo / "src/platform/mod.rs").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "apple": (repo / "scripts/apple-conform-check.sh").read_text(encoding="utf-8"),
    }


def validate(sources: Dict[str, str]) -> None:
    auth = sources["auth"]
    exact = extract_rust_function(
        auth, "fn process_argv_is_exact(", "Unix exact-argv predicate"
    )
    require_order(
        exact,
        (
            "args.len() == expected_args.len() + 1",
            ".all(|(index, expected)| args[index + 1] == *expected)",
        ),
        "complete case-sensitive argv equality",
    )
    for forbidden in (">=", "eq_ignore_ascii_case", "to_lowercase", "starts_with"):
        if forbidden in exact:
            raise VerificationError(
                f"Unix exact-argv predicate retains non-exact operation {forbidden!r}"
            )

    cm_role = extract_rust_function(
        auth, "fn cm_process_argv_is_expected(", "CM exact-role predicate"
    )
    require(
        cm_role,
        "process_argv_is_exact(args, &[expected_arg])",
        "CM exact single-role decision",
    )

    server_role = extract_rust_function(
        auth, "fn helper_server_argv_is_expected(", "server exact-role predicate"
    )
    require_exact_count(
        server_role,
        "process_argv_is_exact(",
        2,
        "closed server-role inventory",
    )
    require(
        server_role,
        'process_argv_is_exact(args, &["--server"])',
        "user-owned exact server role",
    )
    require_order(
        server_role,
        (
            "process_argv_is_exact(",
            '&["--server", crate::common::SERVICE_OWNED_SERVER_ARG]',
        ),
        "service-owned exact server role",
    )
    require(
        server_role,
        '|| process_argv_is_exact(args, &["--server", crate::common::SERVICE_OWNED_SERVER_ARG])',
        "either exact user-owned or exact service-owned server role",
    )

    server_peer = extract_rust_function(
        auth,
        "fn peer_process_is_current_exe_server(",
        "desktop helper server-peer authenticator",
    )
    require_order(
        server_peer,
        (
            "match main_server_cmdline_args(peer_pid)",
            "Ok(args) => helper_server_argv_is_expected(&args)",
            "Err(err) =>",
            "false",
        ),
        "direct fail-closed server-peer argv decision",
    )

    macos_cm = extract_rust_function(
        auth,
        "pub(crate) fn authenticate_macos_cm_endpoint",
        "macOS CM endpoint authenticator",
    )
    require_order(
        macos_cm,
        (
            'ensure_peer_executable_matches_current_by_pid(peer_pid, "_cm")?',
            "let args = macos_process_cmdline_args(peer_pid)?;",
            "if !cm_process_argv_is_expected(&args, expected_arg)",
            'bail!("_cm endpoint mode mismatch: expected {}", expected_arg)',
        ),
        "macOS executable and exact CM role checks",
    )

    for weak in (
        "peer_process_is_current_exe_with_first_arg",
        "get_pids_of_process_with_first_arg",
        "get_pids_of_process_with_args",
    ):
        if weak in auth or weak in sources["platform"]:
            raise VerificationError(f"ambient process-scan helper remains: {weak}")

    require_exact_count(
        auth,
        "fn r_s11e81_unix_helper_process_roles_require_exact_argument_vectors()",
        1,
        "focused Unix process-role regression",
    )
    for rejected in (
        'vec!["rustdesk".to_owned(), "--CM".to_owned()]',
        'vec!["rustdesk".to_owned(), "--SERVER".to_owned()]',
        '"--unexpected".to_owned()',
        'vec!["rustdesk".to_owned(), "--cm".to_owned()]',
    ):
        require(auth, rejected, f"negative process-role regression {rejected}")

    for key, needle, label in (
        (
            "requirements",
            '<span class="id">R-S11bo</span>',
            "R-S11bo requirement",
        ),
        ("requirements", "<tr><td>208</td>", "Appendix C #208"),
        (
            "hardening",
            "R-S11bo/R-S11e-81 — Unix desktop helper IPC accepts only exact process roles",
            "Unix process-role hardening ledger",
        ),
        (
            "verify",
            "python3 scripts/verify-unix-helper-process-role.py --repo . --self-test",
            "shared focused-verifier wiring",
        ),
        (
            "apple",
            "python3 scripts/verify-unix-helper-process-role.py --repo . --self-test",
            "Apple focused-verifier wiring",
        ),
    ):
        require(sources[key], needle, label)


Mutation = Tuple[str, str, str, str]

MUTATIONS: Tuple[Mutation, ...] = (
    (
        "auth",
        "args.len() == expected_args.len() + 1",
        "args.len() >= expected_args.len() + 1",
        "exact argv length",
    ),
    (
        "auth",
        "args[index + 1] == *expected",
        "args[index + 1].eq_ignore_ascii_case(expected)",
        "case-sensitive argv equality",
    ),
    (
        "auth",
        "process_argv_is_exact(args, &[expected_arg])",
        "args.get(1).map(String::as_str) == Some(expected_arg)",
        "CM complete argv decision",
    ),
    (
        "auth",
        'process_argv_is_exact(args, &["--server"])',
        "false",
        "user-owned server role",
    ),
    (
        "auth",
        '|| process_argv_is_exact(args, &["--server", crate::common::SERVICE_OWNED_SERVER_ARG])',
        "|| false",
        "service-owned server role",
    ),
    (
        "auth",
        '|| process_argv_is_exact(args, &["--server", crate::common::SERVICE_OWNED_SERVER_ARG])',
        '&& process_argv_is_exact(args, &["--server", crate::common::SERVICE_OWNED_SERVER_ARG])',
        "alternative server-role composition",
    ),
    (
        "auth",
        "match main_server_cmdline_args(peer_pid)",
        "match Ok(vec![String::new(), \"--server\".to_owned()])",
        "direct peer argv acquisition",
    ),
    (
        "auth",
        "Ok(args) => helper_server_argv_is_expected(&args)",
        "Ok(_args) => true",
        "server role enforcement",
    ),
    (
        "auth",
        "let args = macos_process_cmdline_args(peer_pid)?;",
        'let args = vec![String::new(), expected_arg.to_owned()];',
        "macOS peer argv acquisition",
    ),
    (
        "auth",
        "if !cm_process_argv_is_expected(&args, expected_arg)",
        "if false",
        "macOS CM role enforcement",
    ),
    (
        "auth",
        "fn r_s11e81_unix_helper_process_roles_require_exact_argument_vectors()",
        "fn unix_helper_process_roles_accept_suffix_arguments()",
        "focused process-role regression",
    ),
    (
        "auth",
        'vec!["rustdesk".to_owned(), "--CM".to_owned()]',
        'vec!["rustdesk".to_owned(), "--cm".to_owned()]',
        "CM case-confusion negative",
    ),
    (
        "auth",
        'vec!["rustdesk".to_owned(), "--SERVER".to_owned()]',
        'vec!["rustdesk".to_owned(), "--server".to_owned()]',
        "server case-confusion negative",
    ),
    (
        "requirements",
        '<span class="id">R-S11bo</span>',
        '<span class="id">R-S11bo-disabled</span>',
        "R-S11bo requirement",
    ),
    (
        "requirements",
        "<tr><td>208</td>",
        "<tr><td>208-disabled</td>",
        "Appendix C #208",
    ),
    (
        "hardening",
        "R-S11bo/R-S11e-81 — Unix desktop helper IPC accepts only exact process roles",
        "R-S11bo/R-S11e-81 — Unix desktop helper IPC accepts process-role prefixes",
        "hardening ledger",
    ),
    (
        "verify",
        "python3 scripts/verify-unix-helper-process-role.py --repo . --self-test",
        "true # Unix helper process-role verifier removed",
        "shared gate wiring",
    ),
    (
        "apple",
        "python3 scripts/verify-unix-helper-process-role.py --repo . --self-test",
        "true # Unix helper process-role verifier removed",
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
        "Unix helper process-role semantic validation: OK"
        + (f" ({len(MUTATIONS)} mutations)" if args.self_test else "")
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, VerificationError) as error:
        print(
            f"Unix helper process-role verification failed: {error}",
            file=__import__("sys").stderr,
        )
        raise SystemExit(1)
