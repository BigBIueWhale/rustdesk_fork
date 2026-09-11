#!/usr/bin/env python3
"""Check the load-bearing source boundary around Cargo-tool acquisition output."""

from __future__ import annotations

import argparse
import ast
from pathlib import Path
import re


class AuthorityError(RuntimeError):
    pass


def require(source: str, token: str, label: str) -> None:
    if token not in source:
        raise AuthorityError(f"missing {label}: {token!r}")


def forbid(source: str, token: str, label: str) -> None:
    if token in source:
        raise AuthorityError(f"forbidden {label} remains: {token!r}")


def require_count(source: str, token: str, expected: int, label: str) -> None:
    actual = source.count(token)
    if actual != expected:
        raise AuthorityError(
            f"{label} count is {actual}, expected {expected}: {token!r}"
        )


def require_order(source: str, tokens: tuple[str, ...], label: str) -> None:
    position = -1
    for token in tokens:
        position = source.find(token, position + 1)
        if position < 0:
            raise AuthorityError(f"{label} is missing ordered token {token!r}")


def extract(source: str, start: str, end: str, label: str) -> str:
    if source.count(start) != 1:
        raise AuthorityError(f"{label} start cardinality differs")
    begin = source.index(start)
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise AuthorityError(f"{label} end is absent")
    return source[begin:finish]


def pin(source: str, name: str) -> str:
    match = re.search(rf'^{re.escape(name)}="([^"]+)"', source, re.MULTILINE)
    if match is None:
        raise AuthorityError(f"{name} is not one canonical quoted pin")
    return match.group(1)


def validate(repo: Path) -> None:
    shell = (repo / "scripts/online-fetch.sh").read_text(encoding="utf-8")
    helper = (repo / "scripts/online-cargo-tool-output.py").read_text(encoding="utf-8")
    pins = (repo / "scripts/pins.env").read_text(encoding="utf-8")
    verify = (repo / "scripts/verify.sh").read_text(encoding="utf-8")
    try:
        ast.parse(helper)
    except SyntaxError as error:
        raise AuthorityError(f"Cargo-tool output helper does not parse: {error}") from error

    expected_pins = {
        "RUST_VERSION": "1.75",
        "FLUTTER_RUST_BRIDGE_VERSION": "1.80.1",
        "CARGO_NDK_VERSION": "3.1.2",
    }
    for name, expected in expected_pins.items():
        if pin(pins, name) != expected:
            raise AuthorityError(f"Cargo-tool output authority has the wrong {name}")
    if re.search(r'^SHA256_RUST_1_75="[0-9a-f]{64}"', pins, re.MULTILINE) is None:
        raise AuthorityError("Rust 1.75 archive lacks one canonical SHA-256 pin")

    lifecycle = extract(
        shell,
        "stage_cargo_installed_tool() {",
        "\n}\n\n# ── The FRB codegen tool",
        "Cargo-tool output lifecycle",
    )
    for token, label in (
        ('"frb:$DEB_BUILDER_IMAGE_ID")', "FRB immutable image"),
        ('"cargo-ndk:$ANDROID_BUILDER_IMAGE_ID")', "cargo-ndk immutable image"),
        ('"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"', "exclusive transaction"),
        ('"$ONLINE_DIR/.rustdesk-cargo-tool-$kind.XXXXXXXXXX"', "private staging"),
        ('source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled', "read-only inputs"),
        ('source=$staging/output,target=/outputs/tool', "sole writable output"),
        ('archive="/online/rust-${RUST_VERSION}.tar.xz"', "exact Rust archive"),
        ('--version "$CARGO_TOOL_VERSION"', "exact package version"),
        ("--locked", "packaged lockfile"),
        ("--root /outputs/tool", "private install root"),
        ('--bin "$CARGO_TOOL_BINARY"', "single binary"),
        ("--target x86_64-unknown-linux-gnu", "host target"),
        ("--profile release", "release profile"),
        ("cargo_tool_output_tool verify", "host output check"),
        ("cargo_tool_output_tool publish", "checked publication"),
        ('[ "$status" -eq 0 ] && [ "$input_status" -eq 0 ] && [ "$output_status" -eq 0 ]', "verdict barrier"),
    ):
        require(lifecycle, token, label)
    require_count(lifecycle, "online_docker_run ", 1, "producer launch")
    require_count(lifecycle, "target=/online", 1, "online input mount")
    require_count(lifecycle, "target=/outputs/tool", 1, "output mount")
    require_count(
        lifecycle,
        '"$ONLINE_DIR/rust-${RUST_VERSION}.tar.xz" "$SHA256_RUST_1_75"',
        2,
        "pre/post Rust archive check",
    )
    for token, label in (
        ('source=$ONLINE_DIR,target=/online"', "writable online mount"),
        ("--root /online/", "direct final install"),
        ("/online/frb-tool", "direct FRB publication"),
        ("/online/cargo-ndk-tool", "direct cargo-ndk publication"),
    ):
        forbid(lifecycle, token, label)
    require_order(
        lifecycle,
        (
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            "recover_cargo_tool_output_staging",
            "check-complete",
            "cargo_tool_output_tool prepare",
            "online_docker_run",
            "cargo_tool_output_tool verify",
            "cargo_tool_output_tool publish",
            "retire_cargo_tool_output_staging",
        ),
        "Cargo-tool checked transaction",
    )

    for token, label in (
        ('STATE_NAME = ".rustdesk-cargo-tool-output-state-v2"', "current state"),
        ('LEGACY_STATE_NAME = ".rustdesk-cargo-tool-output-state-v1"', "legacy refusal input"),
        ('hashlib.sha256(b"rustdesk-cargo-tool-tree-v1\\0")', "domain-separated digest"),
        ('"publication": "unselected"', "unselected initial state"),
        ('updated["publication"] = "selected"', "explicit selection"),
        ('updated["output_digest"] = output_digest', "selected digest"),
        ('fail("unselected Cargo tool transaction moved and was preserved")', "moved-unselected refusal"),
        ('fail("legacy v1 Cargo tool state lacks publication selection and was preserved")', "legacy moved refusal"),
        ('"recovered Cargo tool publication"', "recovery mode transition"),
        ('"selected-tampered"', "selected-byte tamper fixture"),
        ('"unselected-moved"', "unselected move fixture"),
        ('"legacy-moved"', "legacy move fixture"),
        ('"selected-unpublished"', "selected crash fixture"),
        ('"post-publication-rollback"', "post-publication rollback fixture"),
    ):
        require(helper, token, label)
    publication = extract(helper, "def publish(", "\n\ndef optional_identity(", "publication")
    require_order(
        publication,
        (
            "verify_staged(",
            "sync_tree(output)",
            "validate_candidate_output(",
            "record_publication(",
            "validate_candidate_output(",
            'renameat2(staging_fd, "output", online_fd, spec.destination, RENAME_NOREPLACE)',
            "transition_root_mode(",
            "fsync_directory(destination)",
            "validate_candidate_output(",
        ),
        "validate-sync-select-publish-seal-postcheck sequence",
    )
    require(
        verify,
        "/usr/bin/python3 -I -S scripts/online-cargo-tool-output.py self-test",
        "filesystem transaction self-test wiring",
    )
    require(
        verify,
        "/usr/bin/python3 -I -S scripts/verify-online-fetch-cargo-tool-output-authority.py --repo .",
        "focused source gate wiring",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    arguments = parser.parse_args()
    validate(arguments.repo.resolve())
    print("verify-online-fetch-cargo-tool-output-authority: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthorityError, OSError) as error:
        raise SystemExit(f"verify-online-fetch-cargo-tool-output-authority: FAIL: {error}")
