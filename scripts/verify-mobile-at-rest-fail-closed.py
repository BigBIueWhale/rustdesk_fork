#!/usr/bin/env python3
"""Verify that mobile legacy at-rest migration requires the live OS key."""

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


def require_order(source: str, needles: Tuple[str, ...], label: str) -> None:
    position = -1
    for needle in needles:
        next_position = source.find(needle, position + 1)
        if next_position < 0:
            raise VerificationError(f"{label}: missing or misordered {needle!r}")
        position = next_position


def load_sources(repo: Path) -> Dict[str, str]:
    return {
        "password": (repo / "libs/hbb_common/src/password_security.rs").read_text(
            encoding="utf-8"
        ),
        "config": (repo / "libs/hbb_common/src/config.rs").read_text(encoding="utf-8"),
        "android": (
            repo
            / "flutter/android/app/src/main/kotlin/com/carriez/flutter_hbb/MainApplication.kt"
        ).read_text(encoding="utf-8"),
        "ios": (repo / "flutter/ios/Runner/AppDelegate.swift").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "apple": (repo / "scripts/apple-conform-check.sh").read_text(encoding="utf-8"),
    }


def validate(sources: Dict[str, str]) -> None:
    password = sources["password"]
    policy = extract_rust_function(
        password,
        "fn legacy_key_pair_fallback_authorized(",
        "mobile legacy-fallback policy",
    )
    require(
        policy,
        "storage_key_available || !mobile",
        "OS-key-or-desktop authorization rule",
    )
    require(
        policy,
        "If the OS key is unavailable, encrypted reads must stay fail-closed.",
        "mobile failure-policy rationale",
    )

    fallback = extract_rust_function(
        password,
        "fn open_with_existing_key_pair(",
        "legacy keypair fallback",
    )
    require_order(
        fallback,
        (
            'let mobile = cfg!(any(target_os = "android", target_os = "ios"));',
            "if !legacy_key_pair_fallback_authorized(primary_key.is_some(), mobile)",
            "return Err(());",
            "Config::get_existing_key_pair()",
            "should_rewrap: mobile",
        ),
        "fallback authorization before legacy-key access",
    )
    require_exact_count(
        password,
        "Config::get_existing_key_pair()",
        1,
        "legacy keypair read site inventory",
    )

    open_payload = extract_rust_function(
        password, "fn open_at_rest_payload(", "at-rest open dispatcher"
    )
    require(
        open_payload,
        "open_with_existing_key_pair(data, Some(&storage_key))",
        "legacy migration after current-key attempt",
    )
    require(
        open_payload,
        "open_with_existing_key_pair(data, None)",
        "unavailable-key path routed through authorization policy",
    )

    require_exact_count(
        password,
        "fn test_mobile_legacy_keypair_fallback_requires_os_storage_key()",
        1,
        "focused Rust policy regression",
    )
    for assertion, label in (
        (
            "assert!(!super::legacy_key_pair_fallback_authorized(false, true));",
            "mobile unavailable-key denial assertion",
        ),
        (
            "assert!(super::legacy_key_pair_fallback_authorized(true, true));",
            "mobile migration assertion",
        ),
        (
            "assert!(super::legacy_key_pair_fallback_authorized(false, false));",
            "desktop recovery preservation assertion",
        ),
    ):
        require(password, assertion, label)

    peer_load = extract_rust_function(
        sources["config"], "    fn load_path_with_status(", "peer-config load path"
    )
    require_order(
        peer_load,
        (
            "decrypt_vec_or_original(&config.password, PASSWORD_ENC_VERSION)",
            "decrypt_vec_or_original(&config.password_prs, PASSWORD_ENC_VERSION)",
            "if store {",
            "Self::store_path_(&path, &config);",
        ),
        "credential migration write path",
    )

    require_order(
        sources["android"],
        (
            "MobileAtRestStorageKey.getOrCreate(applicationContext)",
            "FFI.setMobileAtRestStorageKey(storageKey)",
            "FFI.onAppStart(applicationContext)",
        ),
        "Android OS-key bootstrap ordering",
    )
    require(
        sources["android"],
        "encrypted config reads fail closed",
        "Android unavailable-key diagnostic",
    )
    require_order(
        sources["ios"],
        (
            "installMobileAtRestStorageKey()",
            "GeneratedPluginRegistrant.register(with: self)",
        ),
        "iOS OS-key bootstrap ordering",
    )
    require(
        sources["ios"],
        "encrypted config reads fail closed",
        "iOS unavailable-key diagnostic",
    )

    for source_key, needle, label in (
        ("requirements", '<span class="id">R-S11bh</span>', "R-S11bh requirement"),
        (
            "requirements",
            "Mobile legacy at-rest migration requires live OS-key authority",
            "R-S11bh title",
        ),
        ("requirements", "<tr><td>197</td>", "Appendix C #197"),
        (
            "hardening",
            "R-S11bh/R-S11e-74 — mobile legacy at-rest migration requires live OS-key authority",
            "mobile fail-closed hardening ledger",
        ),
        (
            "verify",
            "python3 scripts/verify-mobile-at-rest-fail-closed.py --repo . --self-test",
            "shared focused-verifier wiring",
        ),
        (
            "apple",
            "python3 scripts/verify-mobile-at-rest-fail-closed.py --repo . --self-test",
            "Apple focused-verifier wiring",
        ),
    ):
        require(sources[source_key], needle, label)


Mutation = Tuple[str, str, str, str]

MUTATIONS: Tuple[Mutation, ...] = (
    (
        "password",
        "storage_key_available || !mobile",
        "storage_key_available || mobile",
        "mobile unavailable-key fallback",
    ),
    (
        "password",
        "legacy_key_pair_fallback_authorized(primary_key.is_some(), mobile)",
        "legacy_key_pair_fallback_authorized(true, mobile)",
        "fabricated storage-key availability",
    ),
    (
        "password",
        'let mobile = cfg!(any(target_os = "android", target_os = "ios"));',
        "let mobile = false;",
        "mobile platform classification",
    ),
    (
        "password",
        "open_with_existing_key_pair(data, Some(&storage_key))",
        "open_with_existing_key_pair(data, None)",
        "authorized legacy migration edge",
    ),
    (
        "password",
        "should_rewrap: mobile",
        "should_rewrap: false",
        "mobile migration rewrap marker",
    ),
    (
        "password",
        "Config::get_existing_key_pair()",
        "Config::get_key_pair()",
        "read-only legacy key access",
    ),
    (
        "password",
        "assert!(!super::legacy_key_pair_fallback_authorized(false, true));",
        "assert!(super::legacy_key_pair_fallback_authorized(false, true));",
        "mobile unavailable-key policy regression",
    ),
    (
        "requirements",
        '<span class="id">R-S11bh</span>',
        '<span class="id">R-S11bh-disabled</span>',
        "R-S11bh requirement",
    ),
    (
        "requirements",
        "<tr><td>197</td>",
        "<tr><td>197-disabled</td>",
        "Appendix C #197",
    ),
    (
        "hardening",
        "R-S11bh/R-S11e-74 — mobile legacy at-rest migration requires live OS-key authority",
        "R-S11bh/R-S11e-74 — mobile legacy at-rest migration accepts missing OS-key authority",
        "hardening ledger",
    ),
    (
        "verify",
        "python3 scripts/verify-mobile-at-rest-fail-closed.py --repo . --self-test",
        "true # mobile at-rest fail-closed verifier removed",
        "shared gate wiring",
    ),
    (
        "apple",
        "python3 scripts/verify-mobile-at-rest-fail-closed.py --repo . --self-test",
        "true # mobile at-rest fail-closed verifier removed",
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
        "Mobile at-rest fail-closed semantic validation: OK"
        + (f" ({len(MUTATIONS)} mutations)" if args.self_test else "")
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, VerificationError) as error:
        print(
            f"Mobile at-rest fail-closed verification failed: {error}",
            file=__import__("sys").stderr,
        )
        raise SystemExit(1)
