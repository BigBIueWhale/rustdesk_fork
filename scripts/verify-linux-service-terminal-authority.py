#!/usr/bin/env python3
"""Verify Linux service-child terminal authority and the retired ambient parser path."""

from __future__ import annotations

import argparse
import re
import tomllib
from pathlib import Path
from typing import Dict, Iterable, Tuple


class VerificationError(RuntimeError):
    pass


def require(source: str, needle: str, label: str) -> None:
    if needle not in source:
        raise VerificationError(f"missing {label}")


def absent(source: str, needle: str, label: str) -> None:
    if needle in source:
        raise VerificationError(f"forbidden {label}")


def ordered(source: str, needles: Iterable[str], label: str) -> None:
    position = -1
    for needle in needles:
        position = source.find(needle, position + 1)
        if position < 0:
            raise VerificationError(f"missing or out-of-order {label}: {needle!r}")


def rust_block(source: str, marker: str, label: str) -> str:
    start = source.find(marker)
    if start < 0:
        raise VerificationError(f"missing {label}")
    opening = source.find("{", start + len(marker))
    if opening < 0:
        raise VerificationError(f"missing {label} body")
    depth = 0
    for offset in range(opening, len(source)):
        character = source[offset]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return source[start : offset + 1]
    raise VerificationError(f"unterminated {label}")


def region(source: str, start: str, end: str, label: str) -> str:
    begin = source.find(start)
    if begin < 0:
        raise VerificationError(f"missing {label} start")
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise VerificationError(f"missing {label} end")
    return source[begin : finish + len(end)]


def compact(source: str) -> str:
    return "".join(source.split())


def load_sources(repo: Path) -> Dict[str, str]:
    paths = {
        "linux": "src/platform/linux.rs",
        "cargo": "Cargo.toml",
        "lock": "Cargo.lock",
        "verify": "scripts/verify.sh",
        "lifecycle": "scripts/smoke-service-lifecycle.sh",
        "requirements": "requirements.html",
        "hardening": "HARDENING_STATUS.md",
    }
    return {
        key: (repo / relative).read_text(encoding="utf-8")
        for key, relative in paths.items()
    }


def validate(sources: Dict[str, str]) -> None:
    linux = sources["linux"]
    path_inventory = region(
        linux,
        "const SERVICE_XTERM_256COLOR_PATHS: [&str; 6] = [",
        "];",
        "fixed system terminfo path inventory",
    )
    expected_paths = (
        'const SERVICE_XTERM_256COLOR_PATHS: [&str; 6] = ['
        '"/etc/terminfo/x/xterm-256color",'
        '"/etc/terminfo/78/xterm-256color",'
        '"/lib/terminfo/x/xterm-256color",'
        '"/lib/terminfo/78/xterm-256color",'
        '"/usr/share/terminfo/x/xterm-256color",'
        '"/usr/share/terminfo/78/xterm-256color",'
        '];'
    )
    if compact(path_inventory) != compact(expected_paths):
        raise VerificationError("fixed system terminfo path inventory differs")

    selector = rust_block(
        linux,
        "fn select_service_child_terminal_type(",
        "closed service terminal selector",
    )
    if compact(selector) != (
        "fnselect_service_child_terminal_type(has_xterm_256color:bool)->&'staticstr{"
        "ifhas_xterm_256color{TERM_XTERM_256COLOR}else{TERM_XTERM}}"
    ):
        raise VerificationError("service terminal selector is not the exact closed choice")

    owner = rust_block(
        linux,
        "fn service_child_terminal_type()",
        "service-owned terminal selection",
    )
    ordered(
        owner,
        (
            "SERVICE_XTERM_256COLOR_PATHS",
            ".iter()",
            ".any(|path| match fs::metadata(Path::new(path))",
            "Ok(metadata) => metadata.is_file()",
            "ErrorKind::NotFound => false",
            "select_service_child_terminal_type(has_xterm_256color)",
        ),
        "fixed system metadata probe before closed selection",
    )
    for needle, label in (
        ("std::env", "ambient environment read in service terminal owner"),
        ("/proc", "process inspection in service terminal owner"),
        ("Database", "terminfo parser in service terminal owner"),
        ("read_to", "terminal capability file read in service terminal owner"),
        ("File::open", "terminal capability file open in service terminal owner"),
    ):
        absent(owner, needle, label)

    launch = rust_block(linux, "fn try_start_server_(", "service child launcher")
    require(
        launch,
        'command.env("TERM", service_child_terminal_type());',
        "service-owned terminal launch binding",
    )
    if launch.count('command.env("TERM",') != 1:
        raise VerificationError("service child must have one exact terminal binding")

    for needle, label in (
        ("fn get_cur_term(", "desktop-user TERM scanner"),
        ("fn get_all_term_values(", "desktop-user process environment scanner"),
        ("fn suggest_best_term(", "environment-directed terminal fallback"),
        ("fn term_supports_256_colors(", "generic terminal database selector"),
        ("CACHED_TERM", "process-global terminal cache"),
        ("DATABASE_XTERM_256COLOR", "parsed terminal database cache"),
        ("SHELL_PROCESSES", "shell process scanner inventory"),
        ("INVALID_TERM_VALUES", "attacker-selected terminal filtering"),
        ("terminfo::", "terminfo parser dependency use"),
        ("Database::from_name", "environment-directed terminfo parser call"),
    ):
        absent(linux, needle, label)

    test = rust_block(
        linux,
        "fn r_s11e204_linux_service_term_is_service_owned_and_fixed()",
        "service terminal authority regression",
    )
    compact_test = compact(test)
    for needle, label in (
        (
            "assert_eq!(select_service_child_terminal_type(true),TERM_XTERM_256COLOR);",
            "256-color selection assertion",
        ),
        (
            "assert_eq!(select_service_child_terminal_type(false),TERM_XTERM);",
            "fixed fallback assertion",
        ),
    ):
        require(compact_test, needle, label)
    for needle, label in (
        ("SERVICE_XTERM_256COLOR_PATHS.len(), 6", "fixed path count assertion"),
        ("path.is_absolute()", "absolute path assertion"),
        ("path.starts_with(root)", "fixed root assertion"),
    ):
        require(test, needle, label)

    if re.search(r"(?m)^\s*terminfo\s*=", sources["cargo"]):
        raise VerificationError("root manifest retains the terminfo dependency")
    try:
        lock = tomllib.loads(sources["lock"])
    except tomllib.TOMLDecodeError as error:
        raise VerificationError(f"Cargo.lock is invalid TOML: {error}") from error
    retired_lock_packages = {
        ("terminfo", "0.8.0"),
        ("dirs", "4.0.0"),
        ("phf", "0.11.3"),
        ("phf_codegen", "0.11.3"),
        ("phf_generator", "0.11.3"),
        ("phf_shared", "0.11.3"),
        ("siphasher", "1.0.1"),
    }
    present_retired = sorted(
        retired_lock_packages.intersection(
            (package.get("name"), package.get("version"))
            for package in lock.get("package", [])
        )
    )
    if present_retired:
        raise VerificationError(
            f"Cargo.lock retains retired terminfo closure packages: {present_retired}"
        )

    for source_key, needle, label in (
        (
            "verify",
            "python3 scripts/verify-linux-service-terminal-authority.py --repo . --self-test",
            "shared focused-verifier wiring",
        ),
        (
            "verify",
            "cargo test --offline --locked --lib --features linux-pkg-config r_s11e204_",
            "compiled regression wiring",
        ),
        (
            "lifecycle",
            'parsed_environment.get(b"TERM") not in {b"xterm", b"xterm-256color"}',
            "root actual-child terminal allowlist",
        ),
        (
            "lifecycle",
            'parsed_environment[b"TERM"] not in {b"xterm", b"xterm-256color"}',
            "active-user actual-child terminal allowlist",
        ),
        (
            "requirements",
            '<span class="id">R-S11fq</span>',
            "service terminal authority requirement",
        ),
        ("requirements", "<tr><td>325</td>", "Appendix C #325"),
        (
            "hardening",
            "R-S11fq/R-S11e-204 Linux service-child terminal authority",
            "service terminal authority hardening ledger",
        ),
    ):
        require(sources[source_key], needle, label)


Mutation = Tuple[str, str, str, str]

MUTATIONS: Tuple[Mutation, ...] = (
    (
        "linux",
        '"/etc/terminfo/x/xterm-256color",',
        '"/tmp/terminfo/x/xterm-256color",',
        "fixed system terminfo path inventory differs",
    ),
    (
        "linux",
        "fn service_child_terminal_type() -> &'static str {",
        "fn service_child_terminal_type() -> &'static str {\n    let _ = std::env::var(\"TERMINFO\");",
        "ambient environment read",
    ),
    (
        "linux",
        'command.env("TERM", service_child_terminal_type());',
        'command.env("TERM", get_cur_term(&desktop.uid).unwrap_or_default());',
        "service-owned terminal launch binding",
    ),
    (
        "linux",
        "fn select_service_child_terminal_type(has_xterm_256color: bool)",
        "fn get_cur_term(has_xterm_256color: bool)",
        "closed service terminal selector",
    ),
    (
        "linux",
        "Ok(metadata) => metadata.is_file(),",
        "Ok(_) => true,",
        "fixed system metadata probe",
    ),
    (
        "linux",
        "select_service_child_terminal_type(false), TERM_XTERM",
        "select_service_child_terminal_type(false), TERM_XTERM_256COLOR",
        "fixed fallback assertion",
    ),
    (
        "cargo",
        'termios = "0.3"\n',
        'termios = "0.3"\nterminfo = "0.8"\n',
        "root manifest retains the terminfo dependency",
    ),
    (
        "lock",
        "\n[[package]]\nname = \"termios\"\nversion = \"0.2.2\"",
        "\n[[package]]\nname = \"terminfo\"\nversion = \"0.8.0\"\n"
        "\n[[package]]\nname = \"termios\"\nversion = \"0.2.2\"",
        "Cargo.lock retains retired terminfo closure packages",
    ),
    (
        "lock",
        "\n[[package]]\nname = \"termios\"\nversion = \"0.2.2\"",
        "\n[[package]]\nname = \"dirs\"\nversion = \"4.0.0\"\n"
        "\n[[package]]\nname = \"termios\"\nversion = \"0.2.2\"",
        "Cargo.lock retains retired terminfo closure packages",
    ),
    (
        "verify",
        "python3 scripts/verify-linux-service-terminal-authority.py --repo . --self-test",
        "true # Linux service terminal authority verifier removed",
        "shared focused-verifier wiring",
    ),
    (
        "requirements",
        '<span class="id">R-S11fq</span>',
        '<span class="id">R-S11fq-disabled</span>',
        "service terminal authority requirement",
    ),
    (
        "requirements",
        "<tr><td>325</td>",
        "<tr><td>325-disabled</td>",
        "Appendix C #325",
    ),
    (
        "hardening",
        "R-S11fq/R-S11e-204 Linux service-child terminal authority",
        "R-S11fq-disabled/R-S11e-204 Linux service-child terminal authority",
        "service terminal authority hardening ledger",
    ),
)


def run_mutations(sources: Dict[str, str]) -> None:
    for key, old, new, expected in MUTATIONS:
        if sources[key].count(old) != 1:
            raise VerificationError(f"mutation fixture is not unique: {expected}")
        mutated = dict(sources)
        mutated[key] = sources[key].replace(old, new, 1)
        try:
            validate(mutated)
        except VerificationError as error:
            if expected not in str(error):
                raise VerificationError(
                    f"mutation {expected!r} failed for the wrong reason: {error}"
                ) from error
        else:
            raise VerificationError(f"mutation survived: {expected}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument("--self-test", action="store_true", help="run mutation fixtures")
    args = parser.parse_args()
    sources = load_sources(Path(args.repo).resolve())
    validate(sources)
    if args.self_test:
        run_mutations(sources)
    print("verify-linux-service-terminal-authority: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
