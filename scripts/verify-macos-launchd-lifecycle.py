#!/usr/bin/env python3
"""Verify domain-qualified, postcondition-checked macOS launchd lifecycle source."""

from __future__ import annotations

import argparse
import re
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
        "macos": (repo / "src/platform/macos.rs").read_text(encoding="utf-8"),
        "install": (
            repo / "src/platform/privileges_scripts/install.scpt"
        ).read_text(encoding="utf-8"),
        "uninstall": (
            repo / "src/platform/privileges_scripts/uninstall.scpt"
        ).read_text(encoding="utf-8"),
    }


def validate(sources: Dict[str, str]) -> None:
    macos = sources["macos"]
    require(
        macos,
        'const MACOS_LAUNCHCTL: &str = "/bin/launchctl";',
        "fixed launchctl executable",
    )
    query = extract_rust_function(
        macos, "fn launchctl_query_succeeds(", "launchctl query helper"
    )
    require_order(
        query,
        (
            'Command::new(MACOS_LAUNCHCTL)',
            '.arg("print")',
            '.arg(target)',
            '.stdout(Stdio::null())',
            '.stderr(Stdio::null())',
            "configure_command_close_nonstdio_on_exec(&mut command)",
            "command.status()",
        ),
        "launchctl print query and descriptor policy",
    )

    state = extract_rust_function(
        macos, "fn launchctl_service_loaded(", "domain-aware launchd service state"
    )
    require_order(
        state,
        (
            "match launchctl_query_succeeds(domain)",
            "Some(false) =>",
            "return None;",
            "launchctl_query_succeeds(service_target)",
        ),
        "domain proof before service-absence interpretation",
    )

    remove = extract_rust_function(
        macos, "fn ensure_launchctl_service_removed(", "launchd removal helper"
    )
    require_order(
        remove,
        (
            "launchctl_service_loaded(domain, service_target)",
            '["bootout", service_target]',
            "launchctl_service_loaded(domain, service_target)",
            "Some(false) => true",
        ),
        "bootout and final negative-state proof",
    )

    agent_domain = extract_rust_function(
        macos, "fn launch_agent_domain(", "LaunchAgent domain derivation"
    )
    require(agent_domain, 'format!("gui/{effective_uid}")', "effective-UID GUI domain")
    target = extract_rust_function(
        macos, "fn launchctl_service_target(", "launchd service-target derivation"
    )
    require(target, 'format!("{domain}/{label}")', "domain-qualified service target")

    restart = extract_rust_function(
        macos, "fn restart_launch_agent(", "LaunchAgent restart"
    )
    require_order(
        restart,
        (
            "hbb_common::libc::geteuid() as u32",
            "launchctl_service_target(&domain, label)",
            "ensure_launchctl_service_removed(&domain, &service_target)",
            '["enable", &service_target]',
            '["bootstrap", &domain, agent_plist_file]',
            "launchctl_service_loaded(&domain, &service_target)",
            "Some(true) => true",
        ),
        "effective-principal LaunchAgent reconciliation",
    )
    uninstall_rust = extract_rust_function(
        macos, "pub fn uninstall_service(", "macOS service uninstall"
    )
    require_order(
        uninstall_rust,
        (
            "macos_privileged_service_script_command()",
            "launch_agent_domain(unsafe { hbb_common::libc::geteuid() as u32 })",
            "launchctl_service_target(&launch_agent_domain, &server_launch_agent_label())",
            "ensure_launchctl_service_removed(&launch_agent_domain, &launch_agent_target)",
        ),
        "privileged uninstall before current-principal LaunchAgent removal proof",
    )

    for obsolete, label in (
        ('["list",', "implicit-domain list query"),
        ('["load",', "legacy load operation"),
        ('["unload",', "legacy unload operation"),
        ('["remove",', "legacy remove operation"),
    ):
        if obsolete in query + state + remove + restart + uninstall_rust:
            raise VerificationError(f"retained {label}")

    install = sources["install"]
    require(install, 'set service_target to "system/" & service_label', "system daemon target")
    require_order(
        install,
        (
            "set unload_existing_service to",
            "/bin/launchctl print system",
            "/bin/launchctl bootout ",
            "set load_service to",
            "/bin/launchctl enable ",
            "/bin/launchctl bootstrap system ",
            "/bin/launchctl print ",
            "unload_existing_service & load_service",
        ),
        "privileged daemon bootout/enable/bootstrap/final-print order",
    )
    require_exact_count(
        install,
        "/bin/launchctl print system",
        2,
        "install domain reachability checks",
    )

    uninstall = sources["uninstall"]
    require(
        uninstall,
        'set service_target to "system/" & service_label',
        "uninstall system daemon target",
    )
    require_order(
        uninstall,
        (
            "set unload_service to",
            "/bin/launchctl print system",
            "/bin/launchctl bootout ",
            "set verify_unloaded to",
            "/bin/launchctl print system",
            "then exit 1; fi;",
            "remove_daemon_plist & remove_agent_plist & remove_service_exec",
        ),
        "privileged daemon bootout proof before artifact removal",
    )
    require_exact_count(
        uninstall,
        "/bin/launchctl print system",
        2,
        "uninstall domain reachability checks",
    )

    legacy_script_command = re.compile(r"/bin/launchctl (?:list|load|unload|remove)(?: |\")")
    for key in ("install", "uninstall"):
        if legacy_script_command.search(sources[key]):
            raise VerificationError(f"{key} retains a legacy launchctl lifecycle command")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    args = parser.parse_args()
    sources = load_sources(args.repo.resolve())
    validate(sources)
    print("macOS launchd lifecycle source invariant: OK")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, VerificationError) as error:
        print(
            f"macOS launchd lifecycle verification failed: {error}",
            file=__import__("sys").stderr,
        )
        raise SystemExit(1)
