#!/usr/bin/env python3
"""R-S11aw/R-S11e-63 Windows production-listener DACL verifier."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, Tuple


class VerificationError(RuntimeError):
    pass


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}")


def absent(source: str, needle: str, label: str) -> None:
    if needle in source:
        raise VerificationError(f"stale/forbidden {label}")


def region(source: str, start: str, end: str, label: str) -> str:
    begin = source.find(start)
    if begin < 0:
        raise VerificationError(f"missing {label} start")
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise VerificationError(f"missing {label} end")
    return source[begin:finish]


def require_all(source: str, needles: Iterable[Tuple[str, str]]) -> None:
    for needle, label in needles:
        require(source, needle, label)


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "ipc": "src/ipc.rs",
        "auth": "src/ipc/auth.rs",
        "cm": "src/ui_cm_interface.rs",
        "whiteboard": "src/whiteboard/server.rs",
        "server": "src/server.rs",
        "windows": "src/platform/windows.rs",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
        "verify": "scripts/verify.sh",
    }
    sources = {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }
    rust_sources = {}
    for path in sorted((repo / "src").rglob("*.rs")):
        relative = path.relative_to(repo).as_posix()
        rust_sources[relative] = path.read_text(encoding="utf-8")
    sources["rust_sources"] = rust_sources  # type: ignore[assignment]
    return sources


def validate_listener_inventory(sources: Dict[str, str]) -> None:
    expected = Counter(
        {
            ("src/ipc.rs", '""'): 1,
            ("src/ipc.rs", "password::USER_PASSWORD_IPC_POSTFIX"): 1,
            ("src/ipc.rs", "postfix"): 1,
            ("src/ipc.rs", "password::SERVICE_PASSWORD_IPC_POSTFIX"): 1,
            ("src/ipc.rs", "WINDOWS_SERVICE_CREDENTIAL_IPC_POSTFIX"): 1,
            ("src/ipc.rs", "WINDOWS_SERVICE_MAIN_CONTROL_IPC_POSTFIX"): 1,
            ("src/ipc.rs", '"_pa"'): 1,
            ("src/platform/windows.rs", "crate::POSTFIX_SERVICE"): 2,
            (
                "src/platform/windows.rs",
                "ipc::WINDOWS_SERVICE_SAS_IPC_POSTFIX",
            ): 2,
            ("src/server.rs", '"_url"'): 1,
            ("src/ui_cm_interface.rs", '"_cm"'): 1,
            ("src/whiteboard/server.rs", "&postfix"): 1,
        }
    )
    observed: Counter[Tuple[str, str]] = Counter()
    token_occurrences = 0
    definition_occurrences = 0
    import_occurrences = 0
    rust_sources = sources["rust_sources"]  # type: ignore[assignment]
    for relative, source in rust_sources.items():
        token_occurrences += len(re.findall(r"\bnew_listener\b", source))
        definition_occurrences += len(
            re.findall(r"\bfn\s+new_listener\s*\(", source, flags=re.DOTALL)
        )
        import_occurrences += len(
            re.findall(r"\buse\b[^;]*\bnew_listener\b", source, flags=re.DOTALL)
        )
        for match in re.finditer(
            r"(?<!fn )\bnew_listener\s*\((.*?)\)", source, flags=re.DOTALL
        ):
            argument = re.sub(r"\s+", " ", match.group(1)).strip()
            observed[(relative, argument)] += 1
    expected_calls = sum(expected.values())
    if (
        definition_occurrences != 1
        or import_occurrences != 1
        or token_occurrences != expected_calls + 2
    ):
        raise VerificationError(
            "Windows IPC listener token inventory drift: "
            f"definitions={definition_occurrences}, imports={import_occurrences}, "
            f"tokens={token_occurrences}, expected_calls={expected_calls}"
        )
    if observed != expected:
        missing = expected - observed
        unexpected = observed - expected
        raise VerificationError(
            "Windows IPC listener call-site inventory drift: "
            f"missing={dict(missing)}, unexpected={dict(unexpected)}"
        )


def validate(sources: Dict[str, str]) -> None:
    validate_listener_inventory(sources)

    whiteboard_name = region(
        sources["ipc"],
        "const WHITEBOARD_ENDPOINT_NAME_CONTEXT:",
        "\n#[cfg(not(any(target_os = \"android\", target_os = \"ios\")))]\nconst WHITEBOARD_ENDPOINT_AUTH_TIMEOUT_MS:",
        "shared whiteboard endpoint-name policy",
    )
    require_all(
        whiteboard_name,
        (
            (
                'const WHITEBOARD_ENDPOINT_POSTFIX_PREFIX: &str = "_whiteboard_";',
                "shared whiteboard postfix prefix",
            ),
        ),
    )
    whiteboard_postfix = region(
        sources["ipc"],
        "pub(crate) fn whiteboard_endpoint_postfix(",
        "\n#[cfg(not(any(target_os = \"android\", target_os = \"ios\")))]\npub(crate) fn whiteboard_endpoint_postfix_from_env(",
        "whiteboard endpoint postfix construction",
    )
    require_all(
        whiteboard_postfix,
        (
            ('"{}{}"', "shared-prefix endpoint rendering"),
            (
                "WHITEBOARD_ENDPOINT_POSTFIX_PREFIX,",
                "shared whiteboard postfix prefix use",
            ),
            (
                "whiteboard_endpoint_name_suffix(launch_token)?",
                "token-derived whiteboard endpoint suffix",
            ),
        ),
    )
    absent(
        whiteboard_postfix,
        '"_whiteboard_{}"',
        "duplicated whiteboard postfix literal",
    )

    classifier = region(
        sources["auth"],
        "fn windows_whiteboard_ipc_postfix_is_valid(",
        "\n#[cfg(windows)]\npub(crate) const WINDOWS_NAMED_PIPE_CLIENT_ACCESS_MASK:",
        "Windows IPC listener-postfix policy",
    )
    require_all(
        classifier,
        (
            (
                ".strip_prefix(super::WHITEBOARD_ENDPOINT_POSTFIX_PREFIX)",
                "shared whiteboard prefix validation",
            ),
            ("suffix.len() == 32", "exact whiteboard suffix length"),
            ("byte.is_ascii_digit()", "whiteboard decimal hex validation"),
            ("(b'a'..=b'f').contains(&byte)", "lowercase whiteboard hex validation"),
            ("postfix.is_empty()", "main endpoint classification"),
            (
                "postfix == super::password::USER_PASSWORD_IPC_POSTFIX",
                "user-password endpoint classification",
            ),
            (
                "hbb_common::config::is_service_ipc_postfix(postfix)",
                "service endpoint classification",
            ),
            (
                "postfix == super::WINDOWS_SERVICE_CREDENTIAL_IPC_POSTFIX",
                "service-credential endpoint classification",
            ),
            (
                "postfix == super::WINDOWS_SERVICE_MAIN_CONTROL_IPC_POSTFIX",
                "service-control endpoint classification",
            ),
            (
                "postfix == super::WINDOWS_SERVICE_SAS_IPC_POSTFIX",
                "service-SAS endpoint classification",
            ),
            ("postfix == WINDOWS_URL_IPC_POSTFIX", "URL endpoint classification"),
            ('postfix == "_cm"', "connection-manager endpoint classification"),
            (
                "|| windows_whiteboard_ipc_postfix_is_valid(postfix)",
                "whiteboard endpoint classification",
            ),
        ),
    )

    attributes = region(
        sources["auth"],
        "pub(crate) fn windows_ipc_listener_security_attributes(",
        "\n#[cfg(windows)]\npub(crate) fn windows_ipc_listener_sddl(",
        "Windows listener security-attribute construction",
    )
    require_all(
        attributes,
        (
            (
                "let sddl = windows_ipc_listener_sddl(postfix)?;",
                "mandatory listener SDDL construction",
            ),
            (
                "parity_tokio_ipc::SecurityAttributes::from_sddl(&sddl)",
                "explicit listener security attributes",
            ),
        ),
    )
    absent(
        attributes,
        "SecurityAttributes::empty()",
        "default/null Windows listener security attributes",
    )

    sddl_policy = region(
        sources["auth"],
        "pub(crate) fn windows_ipc_listener_sddl(",
        "\n#[cfg(windows)]\npub(crate) fn windows_sensitive_pipe_security(",
        "Windows listener SDDL admission",
    )
    require_all(
        sddl_policy,
        (
            (
                "if !windows_ipc_postfix_uses_restricted_dacl(postfix)",
                "exhaustive postfix gate",
            ),
            (
                'bail!("Unsupported Windows IPC endpoint has no explicit DACL policy")',
                "unknown endpoint refusal",
            ),
            (
                "windows_restricted_ipc_sddl(",
                "restricted SDDL construction",
            ),
        ),
    )

    dacl = region(
        sources["auth"],
        "fn windows_restricted_ipc_sddl(",
        "\n#[cfg(windows)]\npub(crate) fn ensure_windows_ipc_server_matches_current(",
        "Windows restricted IPC DACL",
    )
    require_all(
        dacl,
        (
            (
                'String::from("D:P(D;;GA;;;NU)(A;;GA;;;SY)")',
                "protected System-only DACL base",
            ),
            (
                '"(A;;0x{:08x};;;{})"',
                "narrow active-session client ACE",
            ),
            (
                "WINDOWS_NAMED_PIPE_CLIENT_ACCESS_MASK",
                "narrow client access mask use",
            ),
        ),
    )
    for principal in (";;;WD", ";;;AN", ";;;BA"):
        absent(dacl, principal, f"ambient {principal} DACL principal")

    regression = region(
        sources["auth"],
        "fn r_s11e63_windows_ipc_postfix_uses_restricted_dacl_policy()",
        "\n    #[test]\n    #[cfg(windows)]\n    fn r_s11e63_windows_unknown_ipc_listener_has_no_default_dacl_fallback()",
        "Windows listener DACL regression",
    )
    require_all(
        regression,
        (
            (
                'windows_ipc_postfix_uses_restricted_dacl("_cm")',
                "CM DACL regression",
            ),
            (
                '"_whiteboard_0123456789abcdef0123456789abcdef"',
                "valid whiteboard postfix regression",
            ),
            (
                '"_whiteboard_0123456789abcdef0123456789abcde"',
                "short whiteboard postfix rejection",
            ),
            (
                '"_whiteboard_0123456789abcdef0123456789abcdeg"',
                "non-hex whiteboard postfix rejection",
            ),
        ),
    )
    unknown_listener_regression = region(
        sources["auth"],
        "fn r_s11e63_windows_unknown_ipc_listener_has_no_default_dacl_fallback()",
        "\n    #[test]\n    #[cfg(windows)]\n    fn windows_service_control_and_sas_dacls_are_system_only()",
        "unknown Windows listener refusal regression",
    )
    require(
        unknown_listener_regression,
        'windows_ipc_listener_security_attributes("_portable_service").is_err()',
        "unknown listener refusal regression",
    )

    require_all(
        sources["cm"],
        (
            (
                'ipc::new_listener("_cm").await',
                "connection-manager listener call site",
            ),
            (
                "ipc::authorize_cm_ipc_connection(&stream)",
                "connection-manager process-role authorization",
            ),
            (
                "ipc::answer_cm_endpoint_challenge(&mut stream).await",
                "connection-manager launch-proof authorization",
            ),
        ),
    )
    require_all(
        sources["whiteboard"],
        (
            ("new_listener(&postfix).await", "whiteboard listener call site"),
            (
                "ipc::authorize_whiteboard_ipc_connection(&stream, expected_parent_pid)",
                "whiteboard parent authorization",
            ),
            (
                "ipc::answer_whiteboard_endpoint_challenge(&mut stream).await",
                "whiteboard launch-proof authorization",
            ),
        ),
    )

    for source, needle, label in (
        (
            sources["requirements"],
            '<span class="id">R-S11aw</span>',
            "R-S11aw requirement",
        ),
        (
            sources["requirements"],
            "Every production Windows IPC listener is born with an explicit local DACL",
            "R-S11aw title",
        ),
        (sources["requirements"], "<tr><td>171</td>", "Appendix C #171"),
        (
            sources["hardening"],
            "R-S11e-63 — complete Windows production-listener DACL coverage",
            "R-S11e-63 ledger",
        ),
        (
            sources["verify"],
            'echo "== (3b-iii-d9cm) Windows production-listener DACL coverage (R-S11aw/R-S11e-63) =="',
            "shared source gate",
        ),
    ):
        require(source, needle, label)


Mutation = Tuple[str, str, str, str]


MUTATIONS: Tuple[Mutation, ...] = (
    (
        "cm",
        'match ipc::new_listener("_cm").await {',
        'let _unexpected = ipc::new_listener("_future").await;\n    match ipc::new_listener("_cm").await {',
        "production listener inventory",
    ),
    ("auth", '|| postfix == "_cm"', '|| postfix == "_cm_disabled"', "CM DACL policy"),
    (
        "auth",
        "|| windows_whiteboard_ipc_postfix_is_valid(postfix)",
        "|| false && windows_whiteboard_ipc_postfix_is_valid(postfix)",
        "whiteboard DACL policy",
    ),
    ("auth", "suffix.len() == 32", "suffix.len() == 31", "whiteboard suffix length"),
    (
        "auth",
        "(b'a'..=b'f').contains(&byte)",
        "byte.is_ascii_alphabetic()",
        "lowercase whiteboard hex alphabet",
    ),
    (
        "auth",
        "let sddl = windows_ipc_listener_sddl(postfix)?;",
        "if !windows_ipc_postfix_uses_restricted_dacl(postfix) { return Ok(parity_tokio_ipc::SecurityAttributes::empty()); }\n    let sddl = windows_ipc_listener_sddl(postfix)?;",
        "default-security fallback absence",
    ),
    (
        "auth",
        "Unsupported Windows IPC endpoint has no explicit DACL policy",
        "Unknown Windows IPC endpoint uses default policy",
        "unknown endpoint refusal",
    ),
    (
        "auth",
        'String::from("D:P(D;;GA;;;NU)(A;;GA;;;SY)")',
        'String::from("D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GR;;;WD)")',
        "Everyone-free DACL",
    ),
    (
        "auth",
        'windows_ipc_listener_security_attributes("_portable_service").is_err()',
        'windows_ipc_listener_security_attributes("_portable_service").is_ok()',
        "unknown endpoint regression",
    ),
    (
        "ipc",
        'const WHITEBOARD_ENDPOINT_POSTFIX_PREFIX: &str = "_whiteboard_";',
        'const WHITEBOARD_ENDPOINT_POSTFIX_PREFIX: &str = "_whiteboard2_";',
        "shared whiteboard endpoint prefix",
    ),
    (
        "cm",
        'ipc::new_listener("_cm").await',
        'ipc::new_listener("_cm_legacy").await',
        "CM production call site",
    ),
    (
        "whiteboard",
        "ipc::answer_whiteboard_endpoint_challenge(&mut stream).await",
        "ipc::answer_whiteboard_endpoint_challenge_legacy(&mut stream).await",
        "whiteboard application authentication",
    ),
    (
        "requirements",
        '<span class="id">R-S11aw</span>',
        '<span class="id">R-S11az</span>',
        "R-S11aw requirement",
    ),
    ("requirements", "<tr><td>171</td>", "<tr><td>9171</td>", "Appendix C #171"),
    (
        "hardening",
        "R-S11e-63 — complete Windows production-listener DACL coverage",
        "R-S11e-63 — default Windows helper DACLs retained",
        "R-S11e-63 ledger",
    ),
    (
        "verify",
        'echo "== (3b-iii-d9cm) Windows production-listener DACL coverage (R-S11aw/R-S11e-63) =="',
        'echo "== (3b-iii-d9cm) Windows partial-listener DACL coverage (R-S11aw/R-S11e-63) =="',
        "shared source gate",
    ),
)


RUST_SOURCE_KEYS = {
    "ipc": "src/ipc.rs",
    "auth": "src/ipc/auth.rs",
    "cm": "src/ui_cm_interface.rs",
    "whiteboard": "src/whiteboard/server.rs",
    "server": "src/server.rs",
    "windows": "src/platform/windows.rs",
}


def run_mutations(sources: Dict[str, str]) -> None:
    for key, old, new, label in MUTATIONS:
        if sources[key].count(old) != 1:
            raise VerificationError(f"mutation anchor is not unique for {label}")
        mutated = dict(sources)
        mutated[key] = sources[key].replace(old, new, 1)
        if key in RUST_SOURCE_KEYS:
            rust_sources = dict(sources["rust_sources"])  # type: ignore[arg-type]
            rust_sources[RUST_SOURCE_KEYS[key]] = mutated[key]
            mutated["rust_sources"] = rust_sources  # type: ignore[assignment]
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
        "Windows production-listener DACL semantic validation: OK"
        + (f" ({len(MUTATIONS)} mutations)" if args.self_test else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
