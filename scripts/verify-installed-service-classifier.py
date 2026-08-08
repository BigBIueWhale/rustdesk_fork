#!/usr/bin/env python3
"""Verify exact Linux/macOS installed-service ownership classification."""

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
        "linux": (repo / "src/platform/linux.rs").read_text(encoding="utf-8"),
        "macos": (repo / "src/platform/macos.rs").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "apple": (repo / "scripts/apple-conform-check.sh").read_text(encoding="utf-8"),
    }


def validate(sources: Dict[str, str]) -> None:
    linux = sources["linux"]
    require_exact_count(
        linux,
        "const LINUX_INSTALLED_EXECUTABLE_PATHS: [&str; 2] =",
        1,
        "closed Linux installed-executable inventory",
    )
    require_exact_count(
        linux,
        '["/usr/share/rustdesk/rustdesk", "/usr/bin/rustdesk"]',
        1,
        "closed Linux installed-executable values",
    )
    linux_match = extract_rust_function(
        linux,
        "fn linux_path_is_supported_installed_executable(",
        "Linux installed-executable matcher",
    )
    require_order(
        linux_match,
        (
            "LINUX_INSTALLED_EXECUTABLE_PATHS",
            ".iter()",
            ".any(|expected| path == Path::new(expected))",
        ),
        "Linux closed exact-path decision",
    )
    linux_installed = extract_rust_function(
        linux, "pub fn is_installed()", "Linux installed-state classifier"
    )
    require_order(
        linux_installed,
        (
            "std::env::current_exe()",
            "Ok(path) => linux_path_is_supported_installed_executable(&path)",
            "Err(err) =>",
            'log::warn!("Failed to identify the current Linux executable: {err}")',
            "false",
        ),
        "Linux fail-closed current-image classification",
    )
    if "starts_with" in linux_match + linux_installed:
        raise VerificationError("Linux installed-state classifier retains prefix authority")
    linux_regression = extract_rust_function(
        linux,
        "fn r_s11e80_linux_installed_classifier_requires_an_exact_supported_executable()",
        "focused Linux exact-path regression",
    )
    for accepted in (
        '"/usr/share/rustdesk/rustdesk"',
        '"/usr/bin/rustdesk"',
    ):
        require_exact_count(
            linux_regression,
            accepted,
            1,
            f"Linux positive path regression {accepted}",
        )
    for rejected in (
        '"/usr/share/rustdesk/rustdesk-helper"',
        '"/usr-malicious/rustdesk"',
        '"/nix/store/attacker-selected/bin/rustdesk"',
    ):
        require(linux_regression, rejected, f"Linux negative path regression {rejected}")

    macos = sources["macos"]
    macos_expected = extract_rust_function(
        macos,
        "fn macos_installed_executable_path()",
        "macOS installed-executable path",
    )
    require_order(
        macos_expected,
        (
            "let app_name = crate::get_app_name();",
            '"/Applications/{app_name}.app/Contents/MacOS/{app_name}"',
        ),
        "macOS exact app executable derivation",
    )
    macos_match = extract_rust_function(
        macos,
        "fn macos_path_is_supported_installed_executable(",
        "macOS installed-executable matcher",
    )
    require(
        macos_match,
        "path == macos_installed_executable_path()",
        "macOS exact path equality",
    )
    macos_installed = extract_rust_function(
        macos, "pub fn is_installed()", "macOS installed-state classifier"
    )
    require_order(
        macos_installed,
        (
            "std::env::current_exe()",
            "Ok(path) => macos_path_is_supported_installed_executable(&path)",
            "Err(err) =>",
            'log::warn!("Failed to identify the current macOS executable: {err}")',
            "false",
        ),
        "macOS fail-closed current-image classification",
    )
    if "starts_with" in macos_expected + macos_match + macos_installed:
        raise VerificationError("macOS installed-state classifier retains prefix authority")
    require_exact_count(
        macos,
        "fn r_s11e80_macos_installed_classifier_requires_the_exact_app_executable()",
        1,
        "focused macOS exact-path regression",
    )
    for rejected in (
        'format!("/Applications/{app_name}.app/Contents/MacOS/service")',
        'format!("/Applications/{app_name}.app-copy/Contents/MacOS/{app_name}")',
        'format!("/Applications/{app_name}.app/Contents/MacOS/{app_name}-helper")',
    ):
        require(macos, rejected, f"macOS negative path regression {rejected}")

    for key, needle, label in (
        (
            "requirements",
            '<span class="id">R-S11bn</span>',
            "R-S11bn requirement",
        ),
        ("requirements", "<tr><td>207</td>", "Appendix C #207"),
        (
            "hardening",
            "R-S11bn/R-S11e-80 — installed-service ownership uses exact executable identities",
            "installed-service classifier hardening ledger",
        ),
        (
            "verify",
            "python3 scripts/verify-installed-service-classifier.py --repo . --self-test",
            "shared focused-verifier wiring",
        ),
        (
            "apple",
            "python3 scripts/verify-installed-service-classifier.py --repo . --self-test",
            "Apple focused-verifier wiring",
        ),
    ):
        require(sources[key], needle, label)


Mutation = Tuple[str, str, str, str]

MUTATIONS: Tuple[Mutation, ...] = (
    (
        "linux",
        ".any(|expected| path == Path::new(expected))",
        ".any(|expected| path.starts_with(Path::new(expected)))",
        "Linux exact equality",
    ),
    (
        "linux",
        '["/usr/share/rustdesk/rustdesk", "/usr/bin/rustdesk"]',
        '["/usr/share/rustdesk", "/usr/bin/rustdesk"]',
        "Linux package executable identity",
    ),
    (
        "linux",
        '["/usr/share/rustdesk/rustdesk", "/usr/bin/rustdesk"]',
        '["/usr/share/rustdesk/rustdesk", "/usr/bin"]',
        "Linux entry executable identity",
    ),
    (
        "linux",
        'log::warn!("Failed to identify the current Linux executable: {err}");\n            false',
        'log::warn!("Failed to identify the current Linux executable: {err}");\n            true',
        "Linux current-executable failure default",
    ),
    (
        "linux",
        "fn r_s11e80_linux_installed_classifier_requires_an_exact_supported_executable()",
        "fn linux_installed_classifier_accepts_prefixes()",
        "Linux focused regression",
    ),
    (
        "linux",
        '"/usr-malicious/rustdesk"',
        '"/opt/rustdesk"',
        "Linux prefix-confusion negative",
    ),
    (
        "macos",
        'PathBuf::from(format!(\n        "/Applications/{app_name}.app/Contents/MacOS/{app_name}"\n    ))',
        'PathBuf::from(format!("/Applications/{app_name}.app"))',
        "macOS exact app executable identity",
    ),
    (
        "macos",
        "path == macos_installed_executable_path()",
        "path.starts_with(macos_installed_executable_path())",
        "macOS exact equality",
    ),
    (
        "macos",
        'log::warn!("Failed to identify the current macOS executable: {err}");\n            false',
        'log::warn!("Failed to identify the current macOS executable: {err}");\n            true',
        "macOS current-executable failure default",
    ),
    (
        "macos",
        "fn r_s11e80_macos_installed_classifier_requires_the_exact_app_executable()",
        "fn macos_installed_classifier_accepts_bundle_prefixes()",
        "macOS focused regression",
    ),
    (
        "macos",
        'format!("/Applications/{app_name}.app-copy/Contents/MacOS/{app_name}")',
        'format!("/Applications/{app_name}.copy/Contents/MacOS/{app_name}")',
        "macOS bundle-prefix negative",
    ),
    (
        "requirements",
        '<span class="id">R-S11bn</span>',
        '<span class="id">R-S11bn-disabled</span>',
        "R-S11bn requirement",
    ),
    (
        "requirements",
        "<tr><td>207</td>",
        "<tr><td>207-disabled</td>",
        "Appendix C #207",
    ),
    (
        "hardening",
        "R-S11bn/R-S11e-80 — installed-service ownership uses exact executable identities",
        "R-S11bn/R-S11e-80 — installed-service ownership uses path prefixes",
        "hardening ledger",
    ),
    (
        "verify",
        "python3 scripts/verify-installed-service-classifier.py --repo . --self-test",
        "true # installed-service classifier verifier removed",
        "shared gate wiring",
    ),
    (
        "apple",
        "python3 scripts/verify-installed-service-classifier.py --repo . --self-test",
        "true # installed-service classifier verifier removed",
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
        "installed-service classifier semantic validation: OK"
        + (f" ({len(MUTATIONS)} mutations)" if args.self_test else "")
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, VerificationError) as error:
        print(
            f"installed-service classifier verification failed: {error}",
            file=__import__("sys").stderr,
        )
        raise SystemExit(1)
