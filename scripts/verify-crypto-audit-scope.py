#!/usr/bin/env python3
"""Fail closed when the living R-V3 audit handoff drifts from current source."""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from pathlib import Path
from typing import Dict, Iterable, Mapping, Sequence, Tuple


SCOPE = "docs/CRYPTO-AUDIT-SCOPE.md"
PAKE_README = "libs/pake/README.md"
TRANSPORT = "docs/TRANSPORT-SECURITY.md"
ROOT_README = "README.md"
STATUS = "HARDENING_STATUS.md"
VERIFY = "scripts/verify.sh"

MANDATORY_ROOTS: Tuple[str, ...] = (
    "requirements.html",
    "Cargo.lock",
    "libs/pake/Cargo.toml",
    "libs/pake/src/lib.rs",
    "libs/pake/src/tests.rs",
    "libs/hbb_common/src/config/permanent_password.rs",
    "libs/hbb_common/protos/message.proto",
    "libs/hbb_common/src/cpace.rs",
    "libs/hbb_common/src/stream.rs",
    "libs/hbb_common/src/tcp.rs",
    "src/client.rs",
    "src/server.rs",
    "src/direct_service.rs",
    "src/server/connection.rs",
    "libs/cpace_it/tests/handshake.rs",
    "libs/cpace_it/tests/guess_limiter_cap.rs",
    "libs/config_it/tests/prs_derivation.rs",
    "libs/config_it/tests/lockdown.rs",
    "scripts/verify.sh",
    "scripts/audit.sh",
    "scripts/pins.env",
    "deny.toml",
    "docs/TRANSPORT-SECURITY.md",
    "docs/CRYPTO-AUDIT-2026-07-02.md",
    "HARDENING_STATUS.md",
    "README.md",
)

# (source file, exact source token, exact symbol spelling required in the scope)
SOURCE_ANCHORS: Tuple[Tuple[str, str, str], ...] = (
    (
        "libs/hbb_common/src/config/permanent_password.rs",
        "const CPACE_PRS_SALT_DSI",
        "CPACE_PRS_SALT_DSI",
    ),
    (
        "libs/hbb_common/src/config/permanent_password.rs",
        "const CPACE_PRS_OPSLIMIT",
        "CPACE_PRS_OPSLIMIT",
    ),
    (
        "libs/hbb_common/src/config/permanent_password.rs",
        "const CPACE_PRS_MEMLIMIT",
        "CPACE_PRS_MEMLIMIT",
    ),
    (
        "libs/hbb_common/src/config/permanent_password.rs",
        "fn derive_cpace_prs_raw",
        "derive_cpace_prs_raw",
    ),
    (
        "libs/hbb_common/src/config/permanent_password.rs",
        "pub fn derive_cpace_prs",
        "derive_cpace_prs",
    ),
    ("libs/pake/src/lib.rs", "fn canonical_order", "canonical_order"),
    ("libs/pake/src/lib.rs", "fn canonical_compose", "canonical_compose"),
    ("libs/pake/src/lib.rs", "fn try_nfc_normalize", "try_nfc_normalize"),
    ("libs/pake/src/lib.rs", "pub fn nfc_normalize", "nfc_normalize"),
    ("libs/pake/src/lib.rs", "fn generator_string", "generator_string"),
    ("libs/pake/src/lib.rs", "fn derive_generator", "derive_generator"),
    ("libs/pake/src/lib.rs", "fn compute_isk", "compute_isk"),
    ("libs/pake/src/lib.rs", "fn derive_session_keys", "derive_session_keys"),
    ("libs/pake/src/lib.rs", "fn derive_mac_key", "derive_mac_key"),
    ("libs/pake/src/lib.rs", "fn compute_tag", "compute_tag"),
    ("libs/pake/src/lib.rs", "fn verify_tag", "verify_tag"),
    ("libs/pake/src/lib.rs", "fn sample_scalar", "sample_scalar"),
    ("libs/pake/src/lib.rs", "pub fn recv_step2", "Initiator::recv_step2"),
    (
        "libs/pake/src/lib.rs",
        "pub fn recv_step4",
        "InitiatorAwaitConfirm::recv_step4",
    ),
    ("libs/pake/src/lib.rs", "pub fn recv_step1", "Responder::recv_step1"),
    (
        "libs/pake/src/lib.rs",
        "pub fn recv_step3",
        "ResponderAwaitConfirm::recv_step3",
    ),
    ("libs/hbb_common/src/cpace.rs", "async fn send_cpace", "send_cpace"),
    ("libs/hbb_common/src/cpace.rs", "async fn recv_cpace", "recv_cpace"),
    (
        "libs/hbb_common/src/cpace.rs",
        "pub async fn run_initiator_with_transcript",
        "run_initiator_with_transcript",
    ),
    (
        "libs/hbb_common/src/cpace.rs",
        "pub async fn run_responder_with_transcript",
        "run_responder_with_transcript",
    ),
    (
        "libs/hbb_common/src/cpace.rs",
        "pub fn split_session_keys",
        "split_session_keys",
    ),
    ("libs/hbb_common/src/cpace.rs", "fn cipher_nonce", "cipher_nonce"),
    (
        "libs/hbb_common/src/tcp.rs",
        "impl Decoder for SecretboxCodec",
        "SecretboxCodec::decode",
    ),
    (
        "libs/hbb_common/src/tcp.rs",
        "pub async fn send_bytes",
        "FramedStream::send_bytes",
    ),
    (
        "libs/hbb_common/src/tcp.rs",
        "pub fn set_session_keys",
        "FramedStream::set_session_keys",
    ),
    ("libs/hbb_common/src/tcp.rs", "async fn writer_task", "writer_task"),
    ("src/client.rs", "async fn key_initiator", "key_initiator"),
    (
        "src/server.rs",
        "async fn authenticate_tcp_stream",
        "authenticate_tcp_stream",
    ),
    (
        "src/server.rs",
        "pub async fn create_tcp_connection",
        "create_tcp_connection",
    ),
    (
        "src/server/connection.rs",
        "self.authorized = true",
        "self.authorized = true",
    ),
)

REQUIRED_SCOPE_FACTS: Tuple[str, ...] = (
    "Current status: R-V3 is outstanding.",
    "do not satisfy R-V3",
    "exact, clean public Git commit",
    "The entire repository remains in scope",
    "mandatory minimum, not an exclusion list",
    "draft-irtf-cfrg-cpace-21",
    "https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-cpace-21",
    "65e7a118161f57f29b8ef2ed6cf7eb48da9a6a3e",
    "8fb4056e1b9201927d9f651b9970d9d5660c7892",
    "https://www.rfc-editor.org/rfc/rfc8265",
    "https://doc.libsodium.org/secret-key_cryptography/secretbox",
    "local NFC implementation as handwritten",
    "security-relevant code",
    "not an independent proof",
    "independence/conflict",
    "No such behavioral test",
    "required runtime evidence",
    "It therefore does not satisfy R-V3.",
)

STALE_LINE_REFERENCE = re.compile(
    r"(?:"
    r"\b(?:line|lines|l\.)\s*\d+(?:\s*[\-–]\s*\d+)?"
    r"|\b(?:src/lib|lib|cpace|tcp|client|server|stream|permanent_password)\.rs:"
    r"\d+(?:[\-–]\d+)?"
    r"|`:\d+(?:[\-–]\d+)?`"
    r")"
)

FALSE_SIGNOFF = re.compile(
    r"(?:"
    r"\*\*Independently audited"
    r"|independent(?:ly)?[^\n]{0,80}VERDICT:\s*SOUND"
    r"|R-V3[^\n]{0,40}(?:satisfied|complete|closed)"
    r"|external expert audit[^\n]{0,40}(?:satisfied|complete|closed|passed)"
    r")",
    re.IGNORECASE,
)


class ScopeError(ValueError):
    pass


def required_files() -> Tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            (SCOPE, PAKE_README, TRANSPORT, ROOT_README, STATUS, VERIFY)
            + MANDATORY_ROOTS
            + tuple(source for source, _, _ in SOURCE_ANCHORS)
        )
    )


def load_texts(repo: Path) -> Dict[str, str]:
    texts: Dict[str, str] = {}
    for relative in required_files():
        path = repo / relative
        try:
            metadata = os.lstat(path)
        except OSError as error:
            raise ScopeError(f"missing audit-scope input {relative}: {error}") from error
        if not stat.S_ISREG(metadata.st_mode):
            raise ScopeError(f"audit-scope input is not a regular file: {relative}")
        try:
            texts[relative] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise ScopeError(f"cannot read audit-scope input {relative}: {error}") from error
    return texts


def require_tokens(text: str, tokens: Iterable[str], context: str) -> None:
    for token in tokens:
        if token not in text:
            raise ScopeError(f"{context} is missing {token!r}")


def validate(texts: Mapping[str, str]) -> None:
    scope = texts[SCOPE]

    require_tokens(scope, REQUIRED_SCOPE_FACTS, SCOPE)
    require_tokens(scope, MANDATORY_ROOTS, f"{SCOPE} mandatory roots")

    for source, source_token, scope_token in SOURCE_ANCHORS:
        if source_token not in texts[source]:
            raise ScopeError(f"source anchor missing from {source}: {source_token!r}")
        if scope_token not in scope:
            raise ScopeError(f"{SCOPE} is missing current symbol anchor {scope_token!r}")

    require_tokens(
        texts[PAKE_README],
        ("CRYPTO-AUDIT-SCOPE.md", "R-V3 remains outstanding", "try_nfc_normalize"),
        PAKE_README,
    )
    require_tokens(
        texts[TRANSPORT],
        ("CRYPTO-AUDIT-SCOPE.md", "R-V3 remains outstanding", "split_session_keys"),
        TRANSPORT,
    )
    require_tokens(
        texts[ROOT_README],
        ("CRYPTO-AUDIT-SCOPE.md", "R-V3 remains outstanding"),
        ROOT_README,
    )
    require_tokens(
        texts[STATUS],
        (
            "R-V3 independent CPace audit — ⛔ OUTSTANDING",
            "AUDITOR HANDOFF PREPARED",
            "docs/CRYPTO-AUDIT-SCOPE.md",
            "scripts/verify-crypto-audit-scope.py",
        ),
        STATUS,
    )
    require_tokens(
        texts[VERIFY],
        ("verify-crypto-audit-scope.py --self-test", "R-V3 audit handoff"),
        VERIFY,
    )

    for current_doc in (PAKE_README, TRANSPORT):
        match = STALE_LINE_REFERENCE.search(texts[current_doc])
        if match:
            raise ScopeError(
                f"{current_doc} contains brittle source line citation {match.group(0)!r}; "
                "cite file and symbol"
            )

    for current_doc in (SCOPE, PAKE_README, TRANSPORT, ROOT_README, STATUS):
        match = FALSE_SIGNOFF.search(texts[current_doc])
        if match:
            raise ScopeError(
                f"{current_doc} claims independent sign-off while R-V3 is outstanding: "
                f"{match.group(0)!r}"
            )


def expect_rejected(
    name: str,
    texts: Mapping[str, str],
    expected_fragment: str,
) -> None:
    try:
        validate(texts)
    except ScopeError as error:
        if expected_fragment not in str(error):
            raise ScopeError(
                f"self-test {name!r} failed for the wrong reason: {error}"
            ) from error
        return
    raise ScopeError(f"self-test {name!r} mutation was accepted")


def mutated(texts: Mapping[str, str], path: str, old: str, new: str) -> Dict[str, str]:
    result = dict(texts)
    if old not in result[path]:
        raise ScopeError(f"self-test fixture token absent in {path}: {old!r}")
    result[path] = result[path].replace(old, new, 1)
    return result


def self_test(texts: Mapping[str, str]) -> None:
    validate(texts)

    expect_rejected(
        "missing mandatory root",
        mutated(texts, SCOPE, "libs/hbb_common/src/tcp.rs", "missing/tcp.rs"),
        "mandatory roots",
    )
    expect_rejected(
        "source symbol drift",
        mutated(
            texts,
            "libs/pake/src/lib.rs",
            "fn try_nfc_normalize",
            "fn renamed_nfc",
        ),
        "source anchor missing",
    )
    stale = dict(texts)
    stale[TRANSPORT] += "\nStale pointer: `tcp.rs:999`.\n"
    expect_rejected("stale line citation", stale, "brittle source line citation")
    false_signoff = dict(texts)
    false_signoff[ROOT_README] += "\n**Independently audited — VERDICT: SOUND**\n"
    expect_rejected(
        "false independent signoff",
        false_signoff,
        "claims independent sign-off",
    )
    expect_rejected(
        "missing non-signoff boundary",
        mutated(
            texts,
            SCOPE,
            "It therefore does not satisfy R-V3.",
            "It therefore closes the review.",
        ),
        "It therefore does not satisfy R-V3.",
    )


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    try:
        texts = load_texts(Path(args.repo))
        if args.self_test:
            self_test(texts)
            print("crypto audit scope verifier self-test: OK")
        else:
            validate(texts)
            print("crypto audit scope verifier: OK")
    except ScopeError as error:
        print(f"crypto audit scope verifier: FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
