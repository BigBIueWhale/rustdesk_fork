#!/usr/bin/env python3
"""Check the load-bearing vcpkg native-output acquisition boundary."""

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


def validate_lifecycle(
    lifecycle: str,
    *,
    kind: str,
    builder: str,
    libraries: str,
) -> None:
    for token, label in (
        (builder, "immutable builder"),
        (
            "local status=0 source_status=0 output_status=0 publication_status=0",
            "independent verdicts",
        ),
        ('"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"', "exclusive lock"),
        (f'recover_vcpkg_native_output_staging {kind} "$builder"', "recovery"),
        (f'$ONLINE_DIR/.rustdesk-vcpkg-native-{kind}.XXXXXXXXXX', "private staging"),
        ("vcpkg_native_output_tool prepare", "transaction preparation"),
        (
            "source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled",
            "read-only online input",
        ),
        (
            "source=$REPO_ROOT/res/vcpkg,target=/overlay,readonly,bind-recursive=disabled",
            "read-only overlay input",
        ),
        ("source=$staging/output,target=/outputs/native", "sole writable output"),
        ("VCPKG_BINARY_SOURCES=clear", "ambient binary-cache exclusion"),
        (libraries, "exact library projection"),
        (
            f'verify_libvpx_source_authority "after {kind} vcpkg native production"',
            "committed-source postcheck",
        ),
        ("|| source_status=$?", "retained source failure"),
        ("vcpkg_native_output_tool verify", "host validation"),
        (
            '[ "$status" -eq 0 ] && [ "$source_status" -eq 0 ] \\\n'
            '       && [ "$output_status" -eq 0 ]; then',
            "publication verdict barrier",
        ),
        ("vcpkg_native_output_tool publish", "checked publication"),
        ("retire_vcpkg_native_output_staging", "private retirement"),
    ):
        require(lifecycle, token, f"{kind} {label}")
    require_count(lifecycle, "online_docker_run ", 1, f"{kind} producer launch")
    require_count(lifecycle, "target=/online", 1, f"{kind} online mount")
    require_count(lifecycle, "target=/outputs/native", 1, f"{kind} output mount")
    for token, label in (
        ('source=$ONLINE_DIR,target=/online"', "writable online mount"),
        (f"/online/vcpkg/installed/{kind}", "direct final-name write"),
        (f"rm -rf /online/vcpkg/installed/{kind}", "destructive final removal"),
        (f'cp -a "$VR"/installed/{kind} "$staged"', "whole install-tree copy"),
    ):
        forbid(lifecycle, token, f"{kind} {label}")
    require_order(
        lifecycle,
        (
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            "recover_vcpkg_native_output_staging",
            "check-complete",
            "vcpkg_native_output_tool prepare",
            "online_docker_run",
            f'verify_libvpx_source_authority "after {kind} vcpkg native production"',
            "vcpkg_native_output_tool verify",
            '[ "$status" -eq 0 ] && [ "$source_status" -eq 0 ] \\\n'
            '       && [ "$output_status" -eq 0 ]; then',
            "vcpkg_native_output_tool publish",
            "retire_vcpkg_native_output_staging",
        ),
        f"{kind} checked transaction",
    )


def validate(repo: Path) -> None:
    shell = (repo / "scripts/online-fetch.sh").read_text(encoding="utf-8")
    helper = (repo / "scripts/online-vcpkg-native-output.py").read_text(
        encoding="utf-8"
    )
    pins = (repo / "scripts/pins.env").read_text(encoding="utf-8")
    verify = (repo / "scripts/verify.sh").read_text(encoding="utf-8")
    try:
        ast.parse(helper)
    except SyntaxError as error:
        raise AuthorityError(f"vcpkg native-output helper does not parse: {error}") from error

    if re.fullmatch(r"[0-9a-f]{40}", pin(pins, "VCPKG_BASELINE")) is None:
        raise AuthorityError("VCPKG_BASELINE is not one full Git object ID")
    for name in ("SHA256_VCPKG_120DEAC3", "SHA256_ANDROID_NDK_R28C"):
        if re.fullmatch(r"[0-9a-f]{64}", pin(pins, name)) is None:
            raise AuthorityError(f"{name} is not one lowercase SHA-256 pin")
    for name in ("DEB_BUILDER_IMAGE_ID", "ANDROID_BUILDER_IMAGE_ID"):
        if re.fullmatch(r"sha256:[0-9a-f]{64}", pin(pins, name)) is None:
            raise AuthorityError(f"{name} is not one immutable image ID")

    for token, label in (
        ("vcpkg_native_output_key() {", "complete output key"),
        ("FORMAT=rustdesk-vcpkg-native-output-v1", "versioned output key"),
        ("KIND=%s", "kind key binding"),
        ("PORTS=%s", "port key binding"),
        ("BUILDER=%s", "builder key binding"),
        ("SHA256_VCPKG=%s", "vcpkg key binding"),
        ("LIBVPX_NATIVE_KEY=%s", "libvpx key binding"),
        ("LIBYUV_COMMIT=%s", "libyuv commit binding"),
        ("SHA512_LIBYUV=%s", "libyuv archive binding"),
        ("ANDROID_NDK_VERSION=%s", "NDK version binding"),
        ("SHA256_ANDROID_NDK=%s", "NDK archive binding"),
        ("find res/vcpkg -type f -print0 | LC_ALL=C sort -z", "overlay bytes"),
        ("find res/vcpkg -type d -print0 | LC_ALL=C sort -z", "overlay shape"),
        (
            "find res/vcpkg -mindepth 1 ! -type d ! -type f -print -quit",
            "overlay special-entry refusal",
        ),
        ("printf 'OVERLAY_FILE\\0%s\\0' \"$file\"", "overlay path framing"),
        ("vcpkg_native_output_tool() {", "fixed helper routing"),
        ("recover_vcpkg_native_output_staging() {", "reserved-state recovery"),
    ):
        require(shell, token, label)
    x64 = extract(
        shell,
        "stage_vcpkg_natives() {",
        "\n}\n\n# ── The Android NDK",
        "x64-linux lifecycle",
    )
    arm64 = extract(
        shell,
        "stage_vcpkg_natives_arm64() {",
        "\n}\n\n# ── cargo-ndk",
        "arm64-android lifecycle",
    )
    validate_lifecycle(
        x64,
        kind="x64-linux",
        builder='local builder="$DEB_BUILDER_IMAGE_ID"',
        libraries="for archive in libjpeg.a libopus.a libturbojpeg.a libvpx.a libyuv.a; do",
    )
    validate_lifecycle(
        arm64,
        kind="arm64-android",
        builder='local builder="$ANDROID_BUILDER_IMAGE_ID"',
        libraries=(
            "for archive in libjpeg.a liboboe.a libopus.a libturbojpeg.a "
            "libvpx.a libyuv.a; do"
        ),
    )

    for token, label in (
        ('STATE_NAME = ".rustdesk-vcpkg-native-output-state-v2"', "current state"),
        ('LEGACY_STATE_NAME = ".rustdesk-vcpkg-native-output-state-v1"', "legacy state"),
        ('digest.update(b"rustdesk-vcpkg-native-output-tree-v1\\0")', "domain digest"),
        ('"publication": "unselected"', "initial unselected state"),
        ('updated["publication"] = "selected"', "explicit selection"),
        ('updated["output_digest"] = output_digest', "selected digest"),
        ("LEGACY_OUTPUT_BINDINGS: dict[str, tuple[str, str]] = {}", "closed legacy allowlist"),
        ("elf_type != 1 or observed_machine != machine or version != 1", "archive ABI"),
        ("if observed_libraries != set(spec.libraries):", "exact library inventory"),
        ('fail("unselected vcpkg native transaction moved and was preserved")', "moved-unselected refusal"),
        ('fail("legacy v1 vcpkg native state lacks publication selection and was preserved")', "legacy moved refusal"),
        ('"recovered vcpkg native publication"', "recovery mode transition"),
        ('"unselected-moved"', "unselected move fixture"),
        ('"selected-recovery"', "selected crash fixtures"),
        ('"selected-changed"', "selected byte-change fixture"),
        ('"legacy-moved"', "legacy move fixture"),
        ('"interrupted-selection"', "interrupted selection fixture"),
        ('"post-publication-rollback"', "rollback fixture"),
        ("if arguments.uid <= 0 or arguments.gid <= 0:", "root refusal"),
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
            "load_state(",
            "validate_candidate_output(",
            'renameat2(staging_fd, "output", parent_fd, kind, RENAME_NOREPLACE)',
            "transition_root_mode(",
            "fsync_directory(destination)",
            "validate_candidate_output(",
        ),
        "validate-sync-select-recheck-publish-seal-postcheck sequence",
    )
    recovery = extract(helper, "def recover(", "\n\ndef fake_elf_object(", "recovery")
    require_order(
        recovery,
        (
            'if publication == "unselected":',
            'if publication != "selected":',
            "validate_candidate_output(",
            "transition_root_mode(",
            "validate_candidate_output(",
        ),
        "selection-bound recovery sequence",
    )
    require(
        verify,
        "/usr/bin/python3 -I -S scripts/online-vcpkg-native-output.py self-test",
        "filesystem transaction self-test wiring",
    )
    require(
        verify,
        "/usr/bin/python3 -I -S scripts/verify-online-fetch-vcpkg-native-output-authority.py --repo .",
        "focused source gate wiring",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path("."))
    arguments = parser.parse_args()
    validate(arguments.repo.resolve())
    print("verify-online-fetch-vcpkg-native-output-authority: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuthorityError, OSError) as error:
        raise SystemExit(
            f"verify-online-fetch-vcpkg-native-output-authority: FAIL: {error}"
        )
