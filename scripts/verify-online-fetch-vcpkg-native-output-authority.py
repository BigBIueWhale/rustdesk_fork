#!/usr/bin/env python3
"""Validate checked publication of both network-built vcpkg native outputs."""

from __future__ import annotations

import argparse
import ast
import pathlib
import re
from dataclasses import dataclass
from typing import Dict, Tuple


class AuthorityError(RuntimeError):
    pass


@dataclass(frozen=True)
class Mutation:
    source: str
    old: str
    new: str
    label: str


def require(source: str, token: str, label: str) -> None:
    if token not in source:
        raise AuthorityError("missing {}: {!r}".format(label, token))


def require_absent(source: str, token: str, label: str) -> None:
    if token in source:
        raise AuthorityError("forbidden {} remains: {!r}".format(label, token))


def require_count(source: str, token: str, expected: int, label: str) -> None:
    actual = source.count(token)
    if actual != expected:
        raise AuthorityError(
            "{} count is {}, expected {}: {!r}".format(
                label, actual, expected, token
            )
        )


def require_order(source: str, tokens: Tuple[str, ...], label: str) -> None:
    position = -1
    for token in tokens:
        found = source.find(token, position + 1)
        if found < 0:
            raise AuthorityError(
                "{} is missing ordered token {!r}".format(label, token)
            )
        position = found


def extract_between(source: str, start: str, end: str, label: str) -> str:
    if source.count(start) != 1:
        raise AuthorityError("{} start cardinality differs".format(label))
    begin = source.index(start)
    finish = source.find(end, begin + len(start))
    if finish < 0:
        raise AuthorityError("{} end is absent".format(label))
    return source[begin:finish]


def pin_value(source: str, name: str) -> str:
    match = re.search(
        r'^{}="([^"]+)"'.format(re.escape(name)),
        source,
        re.MULTILINE,
    )
    if match is None:
        raise AuthorityError("{} is not one canonical quoted pin".format(name))
    return match.group(1)


def validate_lifecycle(
    lifecycle: str,
    *,
    kind: str,
    builder_token: str,
    libraries: Tuple[str, ...],
) -> None:
    for token, label in (
        (builder_token, "immutable builder"),
        ('"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"', "exclusive transaction"),
        (
            f'recover_vcpkg_native_output_staging {kind} "$builder"',
            "reserved-state recovery",
        ),
        (
            f'$ONLINE_DIR/.rustdesk-vcpkg-native-{kind}.XXXXXXXXXX',
            "unpredictable same-filesystem staging",
        ),
        ("vcpkg_native_output_tool prepare", "transaction preparation"),
        (
            "source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled",
            "read-only nonrecursive online input",
        ),
        (
            "source=$REPO_ROOT/res/vcpkg,target=/overlay,readonly,bind-recursive=disabled",
            "read-only nonrecursive overlay input",
        ),
        ("source=$staging/output,target=/outputs/native", "sole writable output"),
        (
            f'VCPKG_NATIVE_OUTPUT_KEY="$(vcpkg_native_output_key {kind} "$builder")"',
            "kind-bound output receipt",
        ),
        ("VCPKG_BINARY_SOURCES=clear", "ambient binary-cache exclusion"),
        (
            " ".join(libraries),
            "exact static-library consumer projection",
        ),
        ("vcpkg_native_output_tool verify", "independent host postcondition"),
        ("vcpkg_native_output_tool publish", "checked publication"),
        (
            f'"$staging_id" {kind} "$builder"',
            "kind-bound private staging retirement",
        ),
    ):
        require(lifecycle, token, "{} {}".format(kind, label))
    require_count(lifecycle, "online_docker_run ", 1, "{} producer launch".format(kind))
    require_count(
        lifecycle,
        "source=$staging/output,target=/outputs/native",
        1,
        "{} writable output mount".format(kind),
    )
    require_count(
        lifecycle,
        "source=$ONLINE_DIR,target=/online,readonly,bind-recursive=disabled",
        1,
        "{} read-only input mount".format(kind),
    )
    for token, label in (
        ("source=$ONLINE_DIR,target=/online\"", "writable online mount"),
        (f"/online/vcpkg/installed/{kind}", "direct final-name write"),
        (f"rm -rf /online/vcpkg/installed/{kind}", "destructive final removal"),
        ("mv \"$staged\"", "unchecked shell publication"),
        (
            f'cp -a "$VR"/installed/{kind} "$staged"',
            "whole unconsumed install-tree publication",
        ),
    ):
        require_absent(lifecycle, token, "{} {}".format(kind, label))
    require_order(
        lifecycle,
        (
            '"$FLOCK_BIN" --exclusive --nonblock "$lock_fd"',
            "recover_vcpkg_native_output_staging",
            "check-complete",
            "/usr/bin/mktemp -d",
            "vcpkg_native_output_tool prepare",
            "online_docker_run",
            "vcpkg_native_output_tool verify",
            '[ "$status" -eq 0 ] && [ "$output_status" -eq 0 ]',
            "vcpkg_native_output_tool publish",
            "retire_vcpkg_native_output_staging",
            '"$FLOCK_BIN" --unlock "$lock_fd"',
        ),
        "{} validate-seal-publish-retire order".format(kind),
    )


def validate(sources: Dict[str, str]) -> None:
    shell = sources["shell"]
    helper = sources["helper"]
    pins = sources["pins"]
    verify = sources["verify"]
    requirements = sources["requirements"]
    hardening = sources["hardening"]
    workspace = sources["workspace"]
    try:
        ast.parse(helper)
    except SyntaxError as error:
        raise AuthorityError(
            "vcpkg native output helper does not parse: {}".format(error)
        ) from error

    for name in (
        "SHA256_VCPKG_120DEAC3",
        "SHA256_ANDROID_NDK_R28C",
    ):
        if re.fullmatch(r"[0-9a-f]{64}", pin_value(pins, name)) is None:
            raise AuthorityError("{} is not one lowercase SHA-256 pin".format(name))
    for name in ("DEB_BUILDER_IMAGE_ID", "ANDROID_BUILDER_IMAGE_ID"):
        if re.fullmatch(r"sha256:[0-9a-f]{64}", pin_value(pins, name)) is None:
            raise AuthorityError("{} is not one immutable image ID".format(name))
    if re.fullmatch(r"[0-9a-f]{40}", pin_value(pins, "VCPKG_BASELINE")) is None:
        raise AuthorityError("VCPKG_BASELINE is not one full Git object ID")

    for token, label in (
        ("vcpkg_native_output_key() {", "complete native output key"),
        ("FORMAT=rustdesk-vcpkg-native-output-v1", "versioned output key"),
        ("KIND=%s", "kind key binding"),
        ("PORTS=%s", "port-set key binding"),
        ("BUILDER=%s", "builder key binding"),
        ("SHA256_VCPKG=%s", "vcpkg archive key binding"),
        ("LIBVPX_NATIVE_KEY=%s", "libvpx key binding"),
        ("LIBYUV_COMMIT=%s", "libyuv commit key binding"),
        ("SHA512_LIBYUV=%s", "libyuv archive key binding"),
        ("ANDROID_NDK_VERSION=%s", "Android NDK version key binding"),
        ("SHA256_ANDROID_NDK=%s", "Android NDK archive key binding"),
        (
            "find res/vcpkg -type f -print0 | LC_ALL=C sort -z",
            "complete overlay byte binding",
        ),
        (
            "find res/vcpkg -type d -print0 | LC_ALL=C sort -z",
            "complete overlay directory binding",
        ),
        (
            '[ -d "$REPO_ROOT/res/vcpkg" ] && [ ! -L "$REPO_ROOT/res/vcpkg" ]',
            "real overlay-root binding",
        ),
        (
            "printf 'OVERLAY_FILE\\0%s\\0' \"$file\"",
            "unambiguous overlay file framing",
        ),
        (
            "find res/vcpkg -mindepth 1 ! -type d ! -type f -print -quit",
            "overlay special-entry refusal",
        ),
        ("vcpkg_native_output_tool() {", "fixed transaction helper"),
        ("vcpkg_native_output_args() {", "closed transaction argument mapper"),
        ("retire_vcpkg_native_output_staging() {", "private retirement"),
        ("recover_vcpkg_native_output_staging() {", "restart recovery"),
    ):
        require(shell, token, label)

    x64 = extract_between(
        shell,
        "stage_vcpkg_natives() {",
        "\n}\n\n# ── The Android NDK",
        "x64-linux vcpkg native lifecycle",
    )
    arm64 = extract_between(
        shell,
        "stage_vcpkg_natives_arm64() {",
        "\n}\n\n# ── cargo-ndk",
        "arm64-android vcpkg native lifecycle",
    )
    validate_lifecycle(
        x64,
        kind="x64-linux",
        builder_token='local builder="$DEB_BUILDER_IMAGE_ID"',
        libraries=(
            "libjpeg.a",
            "libopus.a",
            "libturbojpeg.a",
            "libvpx.a",
            "libyuv.a",
        ),
    )
    validate_lifecycle(
        arm64,
        kind="arm64-android",
        builder_token='local builder="$ANDROID_BUILDER_IMAGE_ID"',
        libraries=(
            "libjpeg.a",
            "liboboe.a",
            "libopus.a",
            "libturbojpeg.a",
            "libvpx.a",
            "libyuv.a",
        ),
    )
    require(
        x64,
        'verify_sha256 \\\n        "$ONLINE_DIR/vcpkg-${VCPKG_BASELINE}.tar.gz"',
        "x64-linux vcpkg archive precondition",
    )
    require(
        arm64,
        'verify_sha256 \\\n        "$ONLINE_DIR/android-ndk-${ANDROID_NDK_VERSION}.zip"',
        "arm64-android NDK archive precondition",
    )

    for token, label in (
        (
            'STATE_NAME = ".rustdesk-vcpkg-native-output-state-v1"',
            "bounded transaction record",
        ),
        ("MAX_FILES = 256\n", "file-count bound"),
        ("MAX_DIRECTORIES = 32", "directory-count bound"),
        ("MAX_BYTES = 256 * 1024 * 1024\n", "aggregate byte bound"),
        ("reject_mount_at_or_below(staging)", "private mount closure"),
        (
            "if metadata.st_nlink != 1:\n"
            '                    fail(f"vcpkg native output contains an external hardlink: {child_relative}")',
            "external-hardlink rejection",
        ),
        ("if list_xattrs(path):", "extended-attribute rejection"),
        (
            'if relative_regular_files(root / "include") != set(spec.headers):',
            "exact header inventory",
        ),
        (
            "if observed_libraries != set(spec.libraries):",
            "exact library inventory",
        ),
        (
            "if not legacy and set(immediate) != set(spec.libraries):",
            "unconsumed output exclusion",
        ),
        (
            "elf_type != 1 or observed_machine != machine or version != 1",
            "relocatable machine-identity proof",
        ),
        (
            "or header_size != 64\n"
            "        or section_header_size != 64\n"
            "        or section_header_count == 0\n"
            "        or section_header_offset < 64\n"
            "        or section_header_offset\n"
            "        > len(data) - section_header_size * section_header_count",
            "bounded relocatable ELF64 structure proof",
        ),
        (
            'OUTPUT_MARKER = ".rustdesk-vcpkg-native-output-key-v1"',
            "complete output receipt",
        ),
        (
            'AUDITED_STALE_LEGACY_OUTPUTS = {\n'
            '    "x64-linux": (\n'
            '        "2f1a0d9ec38bec3b32c2154a752119c3240c9944ab0ce1c4dfaf91e6a4bfac23",\n'
            '        "4fbb47ef3e8cdd79f96697e9650fc3a31e368dd38a54aa3af372bb5e59b0fa46",',
            "exact x64 stale historical receipt",
        ),
        (
            '"arm64-android": (\n'
            '        "2f1a0d9ec38bec3b32c2154a752119c3240c9944ab0ce1c4dfaf91e6a4bfac23",\n'
            '        "913588e8746761275c3115279789e1590bff9af614072882c09e5fc827e4ad55",',
            "exact arm64 stale historical receipt",
        ),
        (
            "LEGACY_OUTPUT_BINDINGS: dict[str, tuple[str, str]] = {}",
            "empty historical acceptance set",
        ),
        (
            "if expected != (output_key, digest):",
            "historical current-key and full-tree binding",
        ),
        (
            "digest = validate_output(\n"
            "        output,\n"
            "        uid,\n"
            "        gid,\n"
            "        kind,\n"
            "        output_key,\n"
            "        libvpx_key,\n"
            "        legacy=legacy,",
            "historical full-tree digest propagation",
        ),
        (
            "historical vcpkg native output ambiguously carries the new marker",
            "closed historical compatibility",
        ),
        (
            "stat.S_IMODE(metadata.st_mode) not in (0o644, 0o664, 0o755)",
            "closed historical file modes",
        ),
        (
            'for archive in sorted(root.rglob("*.a"), key=lambda path: os.fsencode(path)):',
            "complete historical archive ABI inventory",
        ),
        (
            'os.chmod(\n            directory,\n            0o700 if directory == root else 0o500',
            "private candidate sealing",
        ),
        ("os.chmod(destination, 0o500", "published root sealing"),
        ("sync_tree(output)", "file and directory durability"),
        ("RENAME_NOREPLACE = 1", "no-clobber publication primitive"),
        (
            'renameat2(staging_fd, "output", parent_fd, kind, RENAME_NOREPLACE)',
            "descriptor-relative nested publication",
        ),
        (
            "vcpkg native publication rollback also failed",
            "rollback failure preservation",
        ),
        (
            'return "unpublished-destination-occupied"',
            "destination-race recovery",
        ),
        ('return "unprepared-state-write"', "interrupted state-write recovery"),
        (
            "output transaction state is incoherent and was preserved",
            "ambiguous-state refusal",
        ),
        (
            "vcpkg native publication parent identity changed",
            "parent-identity binding",
        ),
        (
            "self-test accepted a static archive for the wrong ABI",
            "wrong-ABI negative fixture",
        ),
        (
            "self-test accepted malformed ELF64 object structure",
            "malformed-ELF negative fixture",
        ),
        (
            "self-test accepted an unexpected native header",
            "header-inventory negative fixture",
        ),
        (
            "self-test accepted an occupied vcpkg native destination",
            "destination-race fixture",
        ),
        (
            "self-test accepted a symlinked vcpkg native output",
            "symlink negative fixture",
        ),
        (
            "self-test accepted an externally hardlinked vcpkg native output",
            "hardlink negative fixture",
        ),
        (
            "self-test accepted extended attributes in vcpkg native output",
            "extended-attribute negative fixture",
        ),
        (
            "self-test accepted a stale historical full-tree receipt",
            "stale historical-receipt negative fixture",
        ),
        (
            "if arguments.uid <= 0 or arguments.gid <= 0:",
            "root acquisition refusal",
        ),
    ):
        require(helper, token, label)
    require_order(
        helper,
        (
            "def verify_staged(",
            "validate_output(",
            "seal_tree(output)",
            "sync_tree(output)",
            "validate_output(",
            "def publish(",
            "renameat2(staging_fd, \"output\", parent_fd, kind, RENAME_NOREPLACE)",
            "os.chmod(destination, 0o500",
            "validate_output(",
        ),
        "validate-seal-publish-postcheck order",
    )

    require(
        verify,
        "/usr/bin/python3 -I -S scripts/online-vcpkg-native-output.py self-test",
        "transaction self-test wiring",
    )
    require(
        verify,
        "/usr/bin/python3 -I -S scripts/verify-online-fetch-vcpkg-native-output-authority.py --repo . --self-test",
        "focused verifier wiring",
    )
    require(requirements, '<span class="id">R-S11cp</span>', "R-S11cp requirement")
    require(requirements, "<tr><td>243</td>", "Appendix C #243 disposition")
    require(
        hardening,
        "R-S11cp/R-S11e-108 — networked vcpkg native output authority",
        "hardening-ledger disposition",
    )
    require(
        workspace,
        '"online_fetch_vcpkg_native_output_authority_verifier"',
        "workspace-verifier source ownership",
    )
    require(
        workspace,
        "Online-fetch vcpkg native output authority focused verifier",
        "workspace-verifier semantic binding",
    )


MUTATIONS: Tuple[Mutation, ...] = (
    Mutation(
        "shell",
        "FORMAT=rustdesk-vcpkg-native-output-v1",
        "FORMAT=rustdesk-vcpkg-native-output-unversioned",
        "versioned output key",
    ),
    Mutation(
        "shell",
        "find res/vcpkg -type f -print0 | LC_ALL=C sort -z",
        "find res/vcpkg/libvpx -type f -print0 | LC_ALL=C sort -z",
        "complete overlay binding",
    ),
    Mutation(
        "shell",
        "find res/vcpkg -mindepth 1 ! -type d ! -type f -print -quit",
        "find res/vcpkg -mindepth 1 -type l -print -quit",
        "overlay special-entry refusal",
    ),
    Mutation(
        "shell",
        "find res/vcpkg -type d -print0 | LC_ALL=C sort -z",
        "find res/vcpkg/libvpx -type d -print0 | LC_ALL=C sort -z",
        "complete overlay directory binding",
    ),
    Mutation(
        "shell",
        '[ -d "$REPO_ROOT/res/vcpkg" ] && [ ! -L "$REPO_ROOT/res/vcpkg" ]',
        '[ -e "$REPO_ROOT/res/vcpkg" ]',
        "real overlay-root binding",
    ),
    Mutation(
        "shell",
        "printf 'OVERLAY_FILE\\0%s\\0' \"$file\"",
        "printf 'OVERLAY_FILE=%s\\n' \"$file\"",
        "unambiguous overlay file framing",
    ),
    Mutation(
        "shell",
        'stage_vcpkg_natives() {\n    local builder="$DEB_BUILDER_IMAGE_ID"',
        'stage_vcpkg_natives() {\n    local builder="debian:latest"',
        "x64 immutable builder",
    ),
    Mutation(
        "shell",
        'stage_vcpkg_natives_arm64() {\n    local builder="$ANDROID_BUILDER_IMAGE_ID"',
        'stage_vcpkg_natives_arm64() {\n    local builder="ubuntu:latest"',
        "arm64 immutable builder",
    ),
    Mutation(
        "shell",
        "$ONLINE_DIR/.rustdesk-vcpkg-native-x64-linux.XXXXXXXXXX",
        "$ONLINE_DIR/x64-linux.tmp",
        "x64 unpredictable staging",
    ),
    Mutation(
        "shell",
        "$ONLINE_DIR/.rustdesk-vcpkg-native-arm64-android.XXXXXXXXXX",
        "$ONLINE_DIR/arm64-android.tmp",
        "arm64 unpredictable staging",
    ),
    Mutation(
        "shell",
        'VCPKG_NATIVE_OUTPUT_KEY="$(vcpkg_native_output_key x64-linux "$builder")"',
        'VCPKG_NATIVE_OUTPUT_KEY="$(libvpx_native_key)"',
        "x64 complete output receipt",
    ),
    Mutation(
        "shell",
        'VCPKG_NATIVE_OUTPUT_KEY="$(vcpkg_native_output_key arm64-android "$builder")"',
        'VCPKG_NATIVE_OUTPUT_KEY="$(libvpx_native_key)"',
        "arm64 complete output receipt",
    ),
    Mutation(
        "shell",
        "for archive in libjpeg.a libopus.a libturbojpeg.a libvpx.a libyuv.a; do",
        "for archive in libvpx.a libyuv.a; do",
        "x64 exact library projection",
    ),
    Mutation(
        "shell",
        "for archive in libjpeg.a liboboe.a libopus.a libturbojpeg.a libvpx.a libyuv.a; do",
        "for archive in liboboe.a libvpx.a libyuv.a; do",
        "arm64 exact library projection",
    ),
    Mutation(
        "helper",
        "MAX_FILES = 256\n",
        "MAX_FILES = 256000\n",
        "file-count bound",
    ),
    Mutation(
        "helper",
        "MAX_BYTES = 256 * 1024 * 1024\n",
        "MAX_BYTES = 256 * 1024 * 1024 * 1024\n",
        "aggregate byte bound",
    ),
    Mutation(
        "helper",
        "reject_mount_at_or_below(staging)",
        "return # staging mount accepted",
        "staging mount closure",
    ),
    Mutation(
        "helper",
        "if metadata.st_nlink != 1:\n"
        '                    fail(f"vcpkg native output contains an external hardlink: {child_relative}")',
        "if metadata.st_nlink < 1:\n"
        '                    fail(f"vcpkg native output contains an external hardlink: {child_relative}")',
        "external-hardlink rejection",
    ),
    Mutation(
        "helper",
        "if list_xattrs(path):",
        "if False:",
        "extended-attribute rejection",
    ),
    Mutation(
        "helper",
        "elf_type != 1 or observed_machine != machine or version != 1",
        "elf_type != 1 or version != 1",
        "machine-identity proof",
    ),
    Mutation(
        "helper",
        "or header_size != 64\n"
        "        or section_header_size != 64\n"
        "        or section_header_count == 0\n"
        "        or section_header_offset < 64\n"
        "        or section_header_offset\n"
        "        > len(data) - section_header_size * section_header_count",
        "or header_size < 1",
        "bounded relocatable ELF64 structure proof",
    ),
    Mutation(
        "helper",
        "if relative_regular_files(root / \"include\") != set(spec.headers):",
        "if not relative_regular_files(root / \"include\"):",
        "exact header inventory",
    ),
    Mutation(
        "helper",
        "if observed_libraries != set(spec.libraries):",
        "if not observed_libraries:",
        "exact library inventory",
    ),
    Mutation(
        "helper",
        "if not legacy and set(immediate) != set(spec.libraries):",
        "if False:",
        "unconsumed library output exclusion",
    ),
    Mutation(
        "helper",
        "stat.S_IMODE(metadata.st_mode) not in (0o644, 0o664, 0o755)",
        "stat.S_IMODE(metadata.st_mode) not in (0o644, 0o664, 0o666, 0o755)",
        "historical world-write refusal",
    ),
    Mutation(
        "helper",
        'for archive in sorted(root.rglob("*.a"), key=lambda path: os.fsencode(path)):',
        'for archive in sorted((root / "lib").glob("*.a"), key=lambda path: os.fsencode(path)):',
        "complete historical archive ABI inventory",
    ),
    Mutation(
        "helper",
        "if expected != (output_key, digest):",
        "if expected is None:",
        "historical current-key and full-tree binding",
    ),
    Mutation(
        "helper",
        "digest = validate_output(\n"
        "        output,\n"
        "        uid,\n"
        "        gid,\n"
        "        kind,\n"
        "        output_key,\n"
        "        libvpx_key,\n"
        "        legacy=legacy,",
        "validate_output(\n"
        "        output,\n"
        "        uid,\n"
        "        gid,\n"
        "        kind,\n"
        "        output_key,\n"
        "        libvpx_key,\n"
        "        legacy=legacy,",
        "historical full-tree digest propagation",
    ),
    Mutation(
        "helper",
        '"4fbb47ef3e8cdd79f96697e9650fc3a31e368dd38a54aa3af372bb5e59b0fa46"',
        '"0fbb47ef3e8cdd79f96697e9650fc3a31e368dd38a54aa3af372bb5e59b0fa46"',
        "exact x64 stale historical receipt",
    ),
    Mutation(
        "helper",
        '"913588e8746761275c3115279789e1590bff9af614072882c09e5fc827e4ad55"',
        '"013588e8746761275c3115279789e1590bff9af614072882c09e5fc827e4ad55"',
        "exact arm64 stale historical receipt",
    ),
    Mutation(
        "helper",
        "LEGACY_OUTPUT_BINDINGS: dict[str, tuple[str, str]] = {}",
        "LEGACY_OUTPUT_BINDINGS = AUDITED_STALE_LEGACY_OUTPUTS",
        "empty historical acceptance set",
    ),
    Mutation(
        "helper",
        "if arguments.uid <= 0 or arguments.gid <= 0:",
        "if arguments.uid < 0 or arguments.gid < 0:",
        "root acquisition refusal",
    ),
    Mutation(
        "helper",
        "os.chmod(destination, 0o500, follow_symlinks=False)",
        "os.chmod(destination, 0o700, follow_symlinks=False)",
        "published root sealing",
    ),
    Mutation(
        "helper",
        'renameat2(staging_fd, "output", parent_fd, kind, RENAME_NOREPLACE)',
        "os.replace(output, destination)",
        "descriptor-relative no-clobber publication",
    ),
    Mutation(
        "helper",
        "vcpkg native publication rollback also failed",
        "vcpkg native publication rollback omitted",
        "publication rollback",
    ),
    Mutation(
        "helper",
        "vcpkg native publication parent identity changed",
        "vcpkg native parent changed and was ignored",
        "parent-identity binding",
    ),
    Mutation(
        "helper",
        'return "unprepared-state-write"',
        'return "unprepared-output"',
        "interrupted state-write recovery",
    ),
    Mutation(
        "helper",
        "output transaction state is incoherent and was preserved",
        "output transaction state was discarded",
        "ambiguous-state refusal",
    ),
    Mutation(
        "verify",
        "/usr/bin/python3 -I -S scripts/verify-online-fetch-vcpkg-native-output-authority.py --repo . --self-test",
        "true # vcpkg native output authority gate removed",
        "focused verifier wiring",
    ),
    Mutation(
        "requirements",
        '<span class="id">R-S11cp</span>',
        '<span class="id">R-S11cp-disabled</span>',
        "R-S11cp requirement",
    ),
    Mutation(
        "requirements",
        "<tr><td>243</td>",
        "<tr><td>243-disabled</td>",
        "Appendix C #243 disposition",
    ),
    Mutation(
        "hardening",
        "R-S11cp/R-S11e-108 — networked vcpkg native output authority",
        "R-S11cp/R-S11e-108 — ambient vcpkg native output authority",
        "hardening disposition",
    ),
)


def load_sources(repo: pathlib.Path) -> Dict[str, str]:
    return {
        "shell": (repo / "scripts/online-fetch.sh").read_text(encoding="utf-8"),
        "helper": (repo / "scripts/online-vcpkg-native-output.py").read_text(
            encoding="utf-8"
        ),
        "pins": (repo / "scripts/pins.env").read_text(encoding="utf-8"),
        "verify": (repo / "scripts/verify.sh").read_text(encoding="utf-8"),
        "requirements": (repo / "requirements.html").read_text(encoding="utf-8"),
        "hardening": (repo / "HARDENING_STATUS.md").read_text(encoding="utf-8"),
        "workspace": (repo / "scripts/verify-verifier-workspace.py").read_text(
            encoding="utf-8"
        ),
    }


def run_mutations(sources: Dict[str, str]) -> None:
    for mutation in MUTATIONS:
        original = sources[mutation.source]
        count = original.count(mutation.old)
        if count != 1:
            raise AuthorityError(
                "mutation target for {} occurs {} times".format(
                    mutation.label, count
                )
            )
        changed = dict(sources)
        changed[mutation.source] = original.replace(mutation.old, mutation.new, 1)
        try:
            validate(changed)
        except AuthorityError:
            continue
        raise AuthorityError("mutation was accepted: {}".format(mutation.label))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path("."))
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    sources = load_sources(arguments.repo.resolve())
    validate(sources)
    if arguments.self_test:
        run_mutations(sources)
        print(
            "verify-online-fetch-vcpkg-native-output-authority: PASS "
            "({} mutations rejected)".format(len(MUTATIONS))
        )
    else:
        print("verify-online-fetch-vcpkg-native-output-authority: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, AuthorityError) as error:
        raise SystemExit(
            "verify-online-fetch-vcpkg-native-output-authority: {}".format(error)
        )
