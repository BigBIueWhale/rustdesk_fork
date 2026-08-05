#!/usr/bin/env python3
"""Prepare, validate, recover, and publish Gradle warmer output."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path


STATE_NAME = ".rustdesk-gradle-output-state-v3"
LEGACY_STATE_NAME = ".rustdesk-gradle-output-state-v2"
STATE_VERSION = 3
LEGACY_STATE_VERSION = 2
STAGING_PATTERN = re.compile(r"\.rustdesk-gradle-warm\.[A-Za-z0-9_]{8,}\Z")
ARCHIVE_PATTERN = re.compile(
    r"gradle-home-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+\Z"
)
REPLACEMENT_PATTERN = re.compile(
    r"\.rustdesk-retired-gradle-home-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+\Z"
)
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
GRADLE_LIMITS = (100_000, 100_000, 12 * 1024**3, 2 * 1024**3)
SDK_LIMITS = (100_000, 100_000, 4 * 1024**3, 2 * 1024**3)
BLOCK_SIZE = 1024 * 1024
MOUNTINFO_LIMIT = 8 * 1024 * 1024
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2


class OutputError(RuntimeError):
    pass


@dataclass(frozen=True)
class TreeSummary:
    digest: str
    files: int
    directories: int
    bytes: int


def fail(message: str) -> None:
    raise OutputError(message)


def identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def stable_metadata(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def encode_identity(value: tuple[int, int]) -> list[int]:
    return [value[0], value[1]]


def decode_identity(value: object, label: str) -> tuple[int, int]:
    if (
        not isinstance(value, list)
        or len(value) != 2
        or any(type(item) is not int or item < 0 for item in value)
        or value[1] == 0
    ):
        fail(f"{label} identity is malformed")
    return value[0], value[1]


def validate_absolute(path: Path, label: str) -> Path:
    raw = os.fspath(path)
    if not os.path.isabs(raw) or os.path.normpath(raw) != raw:
        fail(f"{label} path is not absolute and normalized")
    try:
        canonical = Path(os.path.realpath(raw, strict=True))
    except OSError as error:
        fail(f"cannot resolve {label}: {error}")
    if canonical != path:
        fail(f"{label} path is not canonical")
    return canonical


def validate_root(
    path: Path,
    label: str,
    owners: set[tuple[int, int]],
    expected_identity: tuple[int, int] | None = None,
) -> os.stat_result:
    canonical = validate_absolute(path, label)
    metadata = os.lstat(canonical)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail(f"{label} is not one real directory")
    if (metadata.st_uid, metadata.st_gid) not in owners:
        fail(f"{label} has an inadmissible owner")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        fail(f"{label} is group/world writable")
    if expected_identity is not None and identity(metadata) != expected_identity:
        fail(f"{label} identity changed")
    reject_descendant_mounts(canonical)
    return metadata


def read_mountinfo() -> list[bytes]:
    descriptor = os.open(
        "/proc/self/mountinfo",
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        data = bytearray()
        while True:
            block = os.read(descriptor, min(BLOCK_SIZE, MOUNTINFO_LIMIT + 1 - len(data)))
            if not block:
                break
            data.extend(block)
            if len(data) > MOUNTINFO_LIMIT:
                fail("/proc/self/mountinfo exceeds its byte bound")
    finally:
        os.close(descriptor)
    mountpoints = []
    for line in bytes(data).splitlines():
        fields = line.split()
        try:
            separator = fields.index(b"-")
        except ValueError:
            fail("malformed /proc/self/mountinfo record")
        if separator < 6:
            fail("truncated /proc/self/mountinfo record")
        mountpoints.append(decode_mount_path(fields[4]))
    if not mountpoints:
        fail("/proc/self/mountinfo has no records")
    return mountpoints


def decode_mount_path(value: bytes) -> bytes:
    decoded = bytearray()
    index = 0
    while index < len(value):
        if value[index] != ord("\\"):
            decoded.append(value[index])
            index += 1
            continue
        if (
            index + 3 >= len(value)
            or any(byte < ord("0") or byte > ord("7") for byte in value[index + 1:index + 4])
        ):
            fail("malformed mountpoint escape")
        decoded.append(int(value[index + 1:index + 4], 8))
        index += 4
    return bytes(decoded)


def reject_descendant_mounts(root: Path) -> None:
    encoded = os.fsencode(root)
    prefix = encoded.rstrip(b"/") + b"/"
    descendants = sorted(
        mountpoint
        for mountpoint in read_mountinfo()
        if mountpoint.startswith(prefix)
    )
    if descendants:
        fail(f"tree contains a descendant mount: {os.fsdecode(descendants[0])}")


def validate_name(name: str, relative: str) -> None:
    raw = os.fsencode(name)
    if (
        not raw
        or raw in (b".", b"..")
        or any(byte < 0x20 or byte > 0x7E for byte in raw)
        or b"\\" in raw
        or b":" in raw
        or raw.startswith(b" ")
        or raw.endswith((b" ", b"."))
    ):
        fail(f"tree contains a nonportable path: {relative!r}")


def digest_file(path: Path, expected: os.stat_result, hash_contents: bool) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if stable_metadata(before) != stable_metadata(expected):
            fail(f"file changed before read: {path}")
        content = hashlib.sha256()
        if hash_contents:
            while True:
                block = os.read(descriptor, BLOCK_SIZE)
                if not block:
                    break
                content.update(block)
        else:
            content.update(str(before.st_size).encode("ascii"))
        after = os.fstat(descriptor)
        if stable_metadata(before) != stable_metadata(after):
            fail(f"file changed while read: {path}")
        return content.digest()
    finally:
        os.close(descriptor)


def inspect_tree(
    root: Path,
    *,
    owners: set[tuple[int, int]],
    limits: tuple[int, int, int, int],
    hash_contents: bool,
    normalize: bool = False,
    seal: bool = False,
    require_sealed: bool = False,
    seal_root: bool = True,
    expected_identity: tuple[int, int] | None = None,
) -> TreeSummary:
    if sum((normalize, seal, require_sealed)) > 1:
        fail("output tree mode policies are mutually exclusive")
    root_metadata = validate_root(root, "output tree", owners, expected_identity)
    root_device = root_metadata.st_dev
    maximum_files, maximum_directories, maximum_bytes, maximum_file = limits
    digest = hashlib.sha256(b"rustdesk-gradle-output-tree-v1\0")
    files = 0
    directories = 1
    content_bytes = 0
    final_metadata: list[tuple[Path, tuple[int, ...]]] = []

    def descend(directory: Path, relative: str, depth: int) -> None:
        nonlocal files, directories, content_bytes
        if depth > 128:
            fail("output tree exceeds its depth bound")
        before = os.lstat(directory)
        if before.st_dev != root_device:
            fail(f"output tree crosses a filesystem: {directory}")
        if (before.st_uid, before.st_gid) not in owners:
            fail(f"output tree has foreign ownership: {directory}")
        if normalize:
            os.chmod(directory, 0o700, follow_symlinks=False)
            before = os.lstat(directory)
        elif seal and (relative or seal_root):
            os.chmod(directory, 0o500, follow_symlinks=False)
            before = os.lstat(directory)
        elif seal and stat.S_IMODE(before.st_mode) != 0o700:
            fail("Gradle publication candidate root is not mode 0700")
        elif require_sealed:
            expected_mode = 0o500 if relative or seal_root else 0o700
            if stat.S_IMODE(before.st_mode) != expected_mode:
                fail(
                    f"sealed output directory has wrong mode: {relative or '.'}"
                )
        elif stat.S_IMODE(before.st_mode) & 0o022:
            fail(f"output directory is group/world writable: {directory}")
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
        for entry in entries:
            child_relative = entry.name if not relative else f"{relative}/{entry.name}"
            validate_name(entry.name, child_relative)
            child = directory / entry.name
            metadata = entry.stat(follow_symlinks=False)
            if metadata.st_dev != root_device:
                fail(f"output tree crosses a filesystem: {child_relative}")
            if (metadata.st_uid, metadata.st_gid) not in owners:
                fail(f"output tree has foreign ownership: {child_relative}")
            if stat.S_ISDIR(metadata.st_mode):
                directories += 1
                if directories > maximum_directories:
                    fail("output tree exceeds its directory bound")
                digest.update(b"D\0" + child_relative.encode("ascii") + b"\0")
                descend(child, child_relative, depth + 1)
            elif stat.S_ISREG(metadata.st_mode):
                files += 1
                content_bytes += metadata.st_size
                if files > maximum_files:
                    fail("output tree exceeds its file bound")
                if content_bytes > maximum_bytes:
                    fail("output tree exceeds its byte bound")
                if metadata.st_size > maximum_file:
                    fail(f"output file exceeds its byte bound: {child_relative}")
                if metadata.st_nlink != 1:
                    fail(f"output file is multiply linked: {child_relative}")
                executable = bool(metadata.st_mode & 0o111)
                if normalize:
                    os.chmod(child, 0o700 if executable else 0o600, follow_symlinks=False)
                    metadata = os.lstat(child)
                elif seal:
                    os.chmod(child, 0o500 if executable else 0o400, follow_symlinks=False)
                    metadata = os.lstat(child)
                elif require_sealed:
                    expected_mode = 0o500 if executable else 0o400
                    if stat.S_IMODE(metadata.st_mode) != expected_mode:
                        fail(
                            f"sealed output file has wrong mode: {child_relative}"
                        )
                elif stat.S_IMODE(metadata.st_mode) & 0o022:
                    fail(f"output file is group/world writable: {child_relative}")
                content = digest_file(child, metadata, hash_contents)
                digest.update(
                    b"F\0"
                    + child_relative.encode("ascii")
                    + b"\0"
                    + (b"X" if executable else b"-")
                    + metadata.st_size.to_bytes(8, "big")
                    + content
                )
                final_metadata.append((child, stable_metadata(metadata)))
            elif stat.S_ISLNK(metadata.st_mode):
                fail(f"output tree contains a symlink: {child_relative}")
            else:
                fail(f"output tree contains a special file: {child_relative}")
        after = os.lstat(directory)
        if (
            identity(before) != identity(after)
            or after.st_dev != root_device
            or not stat.S_ISDIR(after.st_mode)
        ):
            fail(f"output directory changed during traversal: {relative or '.'}")
        final_metadata.append((directory, stable_metadata(after)))

    descend(root, "", 0)
    for path, expected in final_metadata:
        if stable_metadata(os.lstat(path)) != expected:
            fail(f"output tree changed after traversal: {path}")
    return TreeSummary(digest.hexdigest(), files, directories, content_bytes)


def atomic_write_state(staging: Path, value: dict[str, object]) -> None:
    temporary = staging / f"{STATE_NAME}.part"
    state = staging / STATE_NAME
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                fail("short write while recording Gradle output state")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, state)
    fsync_directory(staging)


def validate_semantic_inputs(
    gradle_version: str,
    gradle_sha256: str,
    build_tools: str,
    compile_sdk: str,
) -> None:
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", gradle_version) is None:
        fail("Gradle version is malformed")
    if HEX256.fullmatch(gradle_sha256) is None:
        fail("Gradle distribution checksum is malformed")
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", build_tools) is None:
        fail("Android build-tools version is malformed")
    if re.fullmatch(r"[1-9][0-9]*", compile_sdk) is None:
        fail("Android compile SDK is malformed")


def validate_publication_state(value: dict[str, object]) -> None:
    publication = value.get("publication")
    expected_digest = value.get("expected_gradle_digest")
    replaced_identity = value.get("replaced_gradle_identity")
    replaced_digest = value.get("replaced_gradle_digest")
    retired_root = value.get("retired_root")
    retired_root_identity = value.get("retired_root_identity")
    archive_name = value.get("archive_name")
    replacement_name = value.get("replacement_name")
    if publication == "unselected":
        if any(
            item is not None
            for item in (
                expected_digest,
                replaced_identity,
                replaced_digest,
                retired_root,
                retired_root_identity,
                archive_name,
                replacement_name,
            )
        ):
            fail("unselected Gradle publication carries transaction authority")
        return
    if publication == "new":
        if (
            not isinstance(expected_digest, str)
            or HEX256.fullmatch(expected_digest) is None
            or any(
                item is not None
                for item in (
                    replaced_identity,
                    replaced_digest,
                    retired_root,
                    retired_root_identity,
                    archive_name,
                    replacement_name,
                )
            )
        ):
            fail("new Gradle publication state is malformed")
        return
    if publication != "replacement":
        fail("Gradle publication state has an unknown disposition")
    if (
        not isinstance(expected_digest, str)
        or HEX256.fullmatch(expected_digest) is None
        or not isinstance(replaced_digest, str)
        or HEX256.fullmatch(replaced_digest) is None
        or not isinstance(retired_root, str)
        or not isinstance(archive_name, str)
        or ARCHIVE_PATTERN.fullmatch(archive_name) is None
        or not isinstance(replacement_name, str)
        or REPLACEMENT_PATTERN.fullmatch(replacement_name) is None
    ):
        fail("Gradle replacement state is malformed")
    decode_identity(replaced_identity, "replaced Gradle output")
    decode_identity(retired_root_identity, "retired Gradle root")
    validate_absolute(Path(retired_root), "retired Gradle root")


def load_state(online: Path, staging: Path, uid: int, gid: int) -> dict[str, object]:
    validate_root(online, "online root", {(uid, gid)})
    stage_metadata = validate_root(staging, "Gradle output staging", {(uid, gid)})
    if staging.parent != online or STAGING_PATTERN.fullmatch(staging.name) is None:
        fail("Gradle output staging is outside its reserved online namespace")
    state_paths = [
        path
        for path in (staging / STATE_NAME, staging / LEGACY_STATE_NAME)
        if path.exists() or path.is_symlink()
    ]
    if len(state_paths) != 1:
        fail("Gradle output staging does not contain exactly one state record")
    state_path = state_paths[0]
    metadata = os.lstat(state_path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > 4096
    ):
        fail("Gradle output state metadata is invalid")
    descriptor = os.open(state_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        data = os.read(descriptor, 4097)
        if len(data) > 4096 or os.read(descriptor, 1):
            fail("Gradle output state exceeds its byte bound")
        if stable_metadata(metadata) != stable_metadata(os.fstat(descriptor)):
            fail("Gradle output state changed while opened")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"Gradle output state is malformed: {error}")
    legacy_keys = {
        "version",
        "online",
        "staging",
        "online_identity",
        "staging_identity",
        "original_sdk_identity",
        "staged_gradle_identity",
        "sdk_source_digest",
    }
    current_keys = legacy_keys | {
        "gradle_version",
        "gradle_sha256",
        "build_tools",
        "compile_sdk",
        "publication",
        "expected_gradle_digest",
        "replaced_gradle_identity",
        "replaced_gradle_digest",
        "retired_root",
        "retired_root_identity",
        "archive_name",
        "replacement_name",
    }
    if not isinstance(value, dict):
        fail("Gradle output state is not an object")
    version = value.get("version")
    if version == LEGACY_STATE_VERSION:
        if state_path.name != LEGACY_STATE_NAME or set(value) != legacy_keys:
            fail("legacy Gradle output state has an unexpected schema")
    elif version == STATE_VERSION:
        if state_path.name != STATE_NAME or set(value) != current_keys:
            fail("Gradle output state has an unexpected schema")
        validate_semantic_inputs(
            str(value.get("gradle_version")),
            str(value.get("gradle_sha256")),
            str(value.get("build_tools")),
            str(value.get("compile_sdk")),
        )
        validate_publication_state(value)
    else:
        fail("Gradle output state has the wrong version")
    if value.get("online") != os.fspath(online) or value.get("staging") != os.fspath(staging):
        fail("Gradle output state path binding is invalid")
    if decode_identity(value.get("online_identity"), "online root") != identity(os.lstat(online)):
        fail("online root identity changed")
    if decode_identity(value.get("staging_identity"), "staging root") != identity(stage_metadata):
        fail("Gradle output staging identity changed")
    return value


def prepare(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    *,
    gradle_version: str,
    gradle_sha256: str,
    build_tools: str,
    compile_sdk: str,
) -> None:
    validate_semantic_inputs(
        gradle_version,
        gradle_sha256,
        build_tools,
        compile_sdk,
    )
    online_metadata = validate_root(online, "online root", {(uid, gid)})
    staging_metadata = validate_root(staging, "Gradle output staging", {(uid, gid)})
    if staging.parent != online or STAGING_PATTERN.fullmatch(staging.name) is None:
        fail("Gradle output staging is outside its reserved online namespace")
    if staging_metadata.st_dev != online_metadata.st_dev:
        fail("Gradle output staging is not on the online filesystem")
    if any(staging.iterdir()):
        fail("Gradle output staging is not freshly empty")
    sdk = online / "android-sdk"
    sdk_metadata = validate_root(sdk, "Android SDK source", {(uid, gid)})
    source_summary = inspect_tree(
        sdk,
        owners={(uid, gid)},
        limits=SDK_LIMITS,
        hash_contents=True,
    )
    staged_gradle = staging / "gradle-home"
    staged_gradle.mkdir(mode=0o700)
    after_summary = inspect_tree(
        sdk,
        owners={(uid, gid)},
        limits=SDK_LIMITS,
        hash_contents=True,
        expected_identity=identity(sdk_metadata),
    )
    if source_summary != after_summary:
        fail("Android SDK changed while Gradle output was prepared")
    state = {
        "version": STATE_VERSION,
        "online": os.fspath(online),
        "staging": os.fspath(staging),
        "online_identity": encode_identity(identity(online_metadata)),
        "staging_identity": encode_identity(identity(staging_metadata)),
        "original_sdk_identity": encode_identity(identity(sdk_metadata)),
        "staged_gradle_identity": encode_identity(identity(os.lstat(staged_gradle))),
        "sdk_source_digest": source_summary.digest,
        "gradle_version": gradle_version,
        "gradle_sha256": gradle_sha256,
        "build_tools": build_tools,
        "compile_sdk": compile_sdk,
        "publication": "unselected",
        "expected_gradle_digest": None,
        "replaced_gradle_identity": None,
        "replaced_gradle_digest": None,
        "retired_root": None,
        "retired_root_identity": None,
        "archive_name": None,
        "replacement_name": None,
    }
    atomic_write_state(staging, state)


def require_file(path: Path, *, executable: bool = False, nonempty: bool = False) -> None:
    metadata = os.lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail(f"required output is not a regular file: {path}")
    if executable and not metadata.st_mode & 0o111:
        fail(f"required output is not executable: {path}")
    if nonempty and metadata.st_size == 0:
        fail(f"required output is empty: {path}")


def require_property(path: Path, key: str, expected: str) -> None:
    require_file(path, nonempty=True)
    values = []
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            stripped = line.strip()
            if stripped.startswith("#") or "=" not in stripped:
                continue
            name, value = stripped.split("=", 1)
            if name.strip() == key:
                values.append(value.strip())
    if values != [expected]:
        fail(f"{path} does not bind {key}={expected}")


def validate_semantics(
    sdk: Path,
    gradle: Path,
    *,
    gradle_version: str,
    gradle_sha256: str,
    build_tools: str,
    compile_sdk: str,
) -> None:
    validate_semantic_inputs(
        gradle_version,
        gradle_sha256,
        build_tools,
        compile_sdk,
    )
    modules = gradle / "caches" / "modules-2"
    if not modules.is_dir() or modules.is_symlink():
        fail("Gradle dependency module cache is absent")
    distribution_root = gradle / "wrapper" / "dists" / f"gradle-{gradle_version}-all"
    if not distribution_root.is_dir() or distribution_root.is_symlink():
        fail("pinned Gradle wrapper distribution directory is absent")
    archives = sorted(distribution_root.glob(f"*/gradle-{gradle_version}-all.zip"))
    if len(archives) != 1:
        fail("Gradle wrapper cache does not contain exactly one pinned distribution archive")
    require_file(archives[0], nonempty=True)
    digest = hashlib.sha256()
    with archives[0].open("rb") as stream:
        while block := stream.read(BLOCK_SIZE):
            digest.update(block)
    if digest.hexdigest() != gradle_sha256:
        fail("Gradle wrapper distribution checksum does not match its publisher pin")
    launchers = sorted(distribution_root.glob(f"*/gradle-{gradle_version}/bin/gradle"))
    if len(launchers) != 1:
        fail("Gradle wrapper cache does not contain exactly one extracted pinned launcher")
    require_file(launchers[0], executable=True, nonempty=True)

    tools = sdk / "build-tools" / build_tools
    require_property(tools / "source.properties", "Pkg.Revision", build_tools)
    for name in ("aapt2", "apksigner", "zipalign"):
        require_file(tools / name, executable=True, nonempty=True)
    platform = sdk / "platforms" / f"android-{compile_sdk}"
    require_property(platform / "source.properties", "AndroidVersion.ApiLevel", compile_sdk)
    require_file(platform / "android.jar", nonempty=True)


def require_matching_semantics(
    state: dict[str, object],
    *,
    gradle_version: str,
    gradle_sha256: str,
    build_tools: str,
    compile_sdk: str,
) -> None:
    expected = {
        "gradle_version": gradle_version,
        "gradle_sha256": gradle_sha256,
        "build_tools": build_tools,
        "compile_sdk": compile_sdk,
    }
    for name, value in expected.items():
        if state.get(name) != value:
            fail(f"Gradle output state {name} does not match the requested input")


def verify_staged(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    *,
    gradle_version: str,
    gradle_sha256: str,
    build_tools: str,
    compile_sdk: str,
) -> TreeSummary:
    state = load_state(online, staging, uid, gid)
    if state.get("version") != STATE_VERSION:
        fail("legacy Gradle output state cannot admit a new producer")
    require_matching_semantics(
        state,
        gradle_version=gradle_version,
        gradle_sha256=gradle_sha256,
        build_tools=build_tools,
        compile_sdk=compile_sdk,
    )
    original_sdk = online / "android-sdk"
    original_identity = decode_identity(state.get("original_sdk_identity"), "original SDK")
    source = inspect_tree(
        original_sdk,
        owners={(uid, gid)},
        limits=SDK_LIMITS,
        hash_contents=True,
        expected_identity=original_identity,
    )
    if source.digest != state.get("sdk_source_digest"):
        fail("live Android SDK changed while the networked producer ran")
    staged_gradle = staging / "gradle-home"
    summary = inspect_tree(
        staged_gradle,
        owners={(uid, gid)},
        limits=GRADLE_LIMITS,
        hash_contents=True,
        normalize=True,
        expected_identity=decode_identity(state.get("staged_gradle_identity"), "staged Gradle"),
    )
    validate_semantics(
        original_sdk,
        staged_gradle,
        gradle_version=gradle_version,
        gradle_sha256=gradle_sha256,
        build_tools=build_tools,
        compile_sdk=compile_sdk,
    )
    return summary


def check_complete(
    online: Path,
    uid: int,
    gid: int,
    *,
    gradle_version: str,
    gradle_sha256: str,
    build_tools: str,
    compile_sdk: str,
) -> None:
    validate_root(online, "online root", {(uid, gid)})
    owners = {(uid, gid), (0, 0)}
    sdk = online / "android-sdk"
    gradle = online / "gradle-home"
    inspect_tree(sdk, owners=owners, limits=SDK_LIMITS, hash_contents=False)
    inspect_tree(
        gradle,
        owners=owners,
        limits=GRADLE_LIMITS,
        hash_contents=False,
        require_sealed=True,
    )
    validate_semantics(
        sdk,
        gradle,
        gradle_version=gradle_version,
        gradle_sha256=gradle_sha256,
        build_tools=build_tools,
        compile_sdk=compile_sdk,
    )


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def sync_tree(root: Path) -> None:
    directories = []
    for current, names, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories.append(current_path)
        names.sort()
        files.sort()
        for name in files:
            path = current_path / name
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    fail(f"cannot synchronize non-private output file: {path}")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    for directory in reversed(directories):
        fsync_directory(directory)


def renameat2(
    old_directory: int,
    old_name: str,
    new_directory: int,
    new_name: str,
    flags: int,
) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    function = getattr(library, "renameat2", None)
    if function is None:
        fail("libc does not expose renameat2")
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    result = function(
        old_directory,
        os.fsencode(old_name),
        new_directory,
        os.fsencode(new_name),
        flags,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), f"{old_name} -> {new_name}")


def open_directory(path: Path) -> int:
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)


def transition_root_mode(
    parent_fd: int,
    name: str,
    expected_identity: tuple[int, int],
    uid: int,
    gid: int,
    source_modes: set[int],
    destination_mode: int,
    label: str,
) -> None:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=parent_fd,
    )
    try:
        before = os.fstat(descriptor)
        if (
            identity(before) != expected_identity
            or not stat.S_ISDIR(before.st_mode)
            or before.st_uid != uid
            or before.st_gid != gid
            or stat.S_IMODE(before.st_mode) not in source_modes
        ):
            fail(f"{label} root transition precondition failed")
        os.fchmod(descriptor, destination_mode)
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if (
            identity(after) != expected_identity
            or after.st_uid != uid
            or after.st_gid != gid
            or stat.S_IMODE(after.st_mode) != destination_mode
        ):
            fail(f"{label} root transition postcondition failed")
    finally:
        os.close(descriptor)


def validate_retired_root(
    online: Path,
    retired_root: Path,
    uid: int,
    gid: int,
    expected_identity: tuple[int, int] | None = None,
) -> os.stat_result:
    metadata = validate_root(
        retired_root,
        "retired Gradle root",
        {(uid, gid)},
        expected_identity,
    )
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        fail("retired Gradle root is not mode 0700")
    if metadata.st_dev != os.lstat(online).st_dev:
        fail("retired Gradle root is not on the online filesystem")
    online_text = os.fspath(online).rstrip("/") + "/"
    retired_text = os.fspath(retired_root).rstrip("/") + "/"
    if online_text.startswith(retired_text) or retired_text.startswith(online_text):
        fail("retired Gradle root and online root are not disjoint")
    return metadata


def replacement_archive_name(
    staging_identity: tuple[int, int],
    replaced_identity: tuple[int, int],
) -> str:
    name = "gradle-home-{:x}-{:x}-{:x}-{:x}".format(
        staging_identity[0],
        staging_identity[1],
        replaced_identity[0],
        replaced_identity[1],
    )
    if ARCHIVE_PATTERN.fullmatch(name) is None:
        fail("generated retired Gradle archive name is malformed")
    return name


def replacement_output_name(
    staging_identity: tuple[int, int],
    replaced_identity: tuple[int, int],
) -> str:
    name = ".rustdesk-retired-gradle-home-{:x}-{:x}-{:x}-{:x}".format(
        staging_identity[0],
        staging_identity[1],
        replaced_identity[0],
        replaced_identity[1],
    )
    if REPLACEMENT_PATTERN.fullmatch(name) is None:
        fail("generated replacement Gradle name is malformed")
    return name


def record_new_publication(
    staging: Path,
    state: dict[str, object],
    expected_digest: str,
) -> dict[str, object]:
    if state.get("publication") == "new":
        if state.get("expected_gradle_digest") != expected_digest:
            fail("new Gradle publication digest changed across retry")
        return state
    if state.get("publication") != "unselected":
        fail("Gradle output is already bound to a different publication")
    updated = dict(state)
    updated["publication"] = "new"
    updated["expected_gradle_digest"] = expected_digest
    atomic_write_state(staging, updated)
    return updated


def record_replacement_publication(
    staging: Path,
    state: dict[str, object],
    expected_digest: str,
    replaced: TreeSummary,
    replaced_identity: tuple[int, int],
    retired_root: Path,
    retired_root_identity: tuple[int, int],
) -> dict[str, object]:
    archive_name = replacement_archive_name(
        decode_identity(state.get("staging_identity"), "Gradle output staging"),
        replaced_identity,
    )
    replacement_name = replacement_output_name(
        decode_identity(state.get("staging_identity"), "Gradle output staging"),
        replaced_identity,
    )
    expected = {
        "publication": "replacement",
        "expected_gradle_digest": expected_digest,
        "replaced_gradle_identity": encode_identity(replaced_identity),
        "replaced_gradle_digest": replaced.digest,
        "retired_root": os.fspath(retired_root),
        "retired_root_identity": encode_identity(retired_root_identity),
        "archive_name": archive_name,
        "replacement_name": replacement_name,
    }
    if state.get("publication") == "replacement":
        if any(state.get(name) != value for name, value in expected.items()):
            fail("Gradle replacement authority changed across retry")
        return state
    if state.get("publication") != "unselected":
        fail("Gradle output is already bound to a different publication")
    updated = dict(state)
    updated.update(expected)
    atomic_write_state(staging, updated)
    return updated


def state_semantics(state: dict[str, object]) -> dict[str, str]:
    return {
        "gradle_version": str(state.get("gradle_version")),
        "gradle_sha256": str(state.get("gradle_sha256")),
        "build_tools": str(state.get("build_tools")),
        "compile_sdk": str(state.get("compile_sdk")),
    }


def validate_candidate_output(
    online: Path,
    output: Path,
    state: dict[str, object],
    uid: int,
    gid: int,
    expected_identity: tuple[int, int],
    expected_digest: str,
    *,
    published: bool,
) -> TreeSummary:
    expected_mode = 0o500 if published else 0o700
    if stat.S_IMODE(os.lstat(output).st_mode) != expected_mode:
        fail(f"Gradle candidate root is not mode {expected_mode:04o}")
    summary = inspect_tree(
        output,
        owners={(uid, gid)},
        limits=GRADLE_LIMITS,
        hash_contents=True,
        require_sealed=True,
        seal_root=published,
        expected_identity=expected_identity,
    )
    validate_semantics(online / "android-sdk", output, **state_semantics(state))
    if summary.digest != expected_digest:
        fail("Gradle candidate digest postcondition failed")
    return summary


def validate_displaced_output(
    output: Path,
    uid: int,
    gid: int,
    expected_identity: tuple[int, int] | None = None,
    expected_digest: str | None = None,
) -> TreeSummary:
    metadata = validate_root(
        output,
        "displaced Gradle output",
        {(uid, gid), (0, 0)},
        expected_identity,
    )
    owner = (metadata.st_uid, metadata.st_gid)
    summary = inspect_tree(
        output,
        owners={owner},
        limits=GRADLE_LIMITS,
        hash_contents=True,
        expected_identity=expected_identity,
    )
    if summary.files == 0:
        fail("displaced Gradle output is empty")
    if expected_digest is not None and summary.digest != expected_digest:
        fail("displaced Gradle output digest changed")
    return summary


def rollback_publication(
    online_fd: int,
    staging_fd: int,
    expected_identity: tuple[int, int],
    uid: int,
    gid: int,
) -> None:
    failures = []
    try:
        transition_root_mode(
            online_fd,
            "gradle-home",
            expected_identity,
            uid,
            gid,
            {0o500, 0o700},
            0o700,
            "Gradle rollback",
        )
        renameat2(
            online_fd,
            "gradle-home",
            staging_fd,
            "gradle-home",
            RENAME_NOREPLACE,
        )
    except OSError as error:
        failures.append(f"Gradle rollback failed: {error}")
    try:
        os.fsync(staging_fd)
        os.fsync(online_fd)
    except OSError as error:
        failures.append(f"rollback directory synchronization failed: {error}")
    if failures:
        fail("; ".join(failures))


def publish(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    *,
    gradle_version: str,
    gradle_sha256: str,
    build_tools: str,
    compile_sdk: str,
    expected_digest: str,
) -> None:
    if HEX256.fullmatch(expected_digest) is None:
        fail("verified Gradle digest is malformed")
    candidate = verify_staged(
        online,
        staging,
        uid,
        gid,
        gradle_version=gradle_version,
        gradle_sha256=gradle_sha256,
        build_tools=build_tools,
        compile_sdk=compile_sdk,
    )
    if candidate.digest != expected_digest:
        fail("Gradle output changed after independent verification")
    state = load_state(online, staging, uid, gid)
    if (online / "gradle-home").exists() or (online / "gradle-home").is_symlink():
        fail("Gradle output destination appeared before no-clobber publication")
    sealed_summary = inspect_tree(
        staging / "gradle-home",
        owners={(uid, gid)},
        limits=GRADLE_LIMITS,
        hash_contents=True,
        seal=True,
        seal_root=False,
        expected_identity=decode_identity(
            state.get("staged_gradle_identity"), "staged Gradle"
        ),
    )
    if sealed_summary.digest != expected_digest:
        fail("sealed Gradle candidate digest changed")
    validate_semantics(
        online / "android-sdk",
        staging / "gradle-home",
        gradle_version=gradle_version,
        gradle_sha256=gradle_sha256,
        build_tools=build_tools,
        compile_sdk=compile_sdk,
    )
    sync_tree(staging / "gradle-home")
    fsync_directory(staging)
    state = record_new_publication(staging, state, expected_digest)
    online_fd = open_directory(online)
    staging_fd = open_directory(staging)
    gradle_moved = False
    try:
        renameat2(staging_fd, "gradle-home", online_fd, "gradle-home", RENAME_NOREPLACE)
        gradle_moved = True
        os.fsync(staging_fd)
        os.fsync(online_fd)
        staged_gradle_identity = decode_identity(
            state.get("staged_gradle_identity"), "staged Gradle"
        )
        transition_root_mode(
            online_fd,
            "gradle-home",
            staged_gradle_identity,
            uid,
            gid,
            {0o700},
            0o500,
            "published Gradle",
        )
        os.fsync(online_fd)
        if identity(os.lstat(online / "android-sdk")) != decode_identity(
            state.get("original_sdk_identity"), "original SDK"
        ):
            fail("read-only Android SDK identity postcondition failed")
        sdk_summary = inspect_tree(
            online / "android-sdk",
            owners={(uid, gid)},
            limits=SDK_LIMITS,
            hash_contents=True,
            expected_identity=decode_identity(
                state.get("original_sdk_identity"),
                "original SDK",
            ),
        )
        if sdk_summary.digest != state.get("sdk_source_digest"):
            fail("read-only Android SDK content postcondition failed")
        if identity(os.lstat(online / "gradle-home")) != decode_identity(
            state.get("staged_gradle_identity"), "staged Gradle"
        ):
            fail("published Gradle identity postcondition failed")
        published_summary = inspect_tree(
            online / "gradle-home",
            owners={(uid, gid)},
            limits=GRADLE_LIMITS,
            hash_contents=True,
            require_sealed=True,
            expected_identity=decode_identity(
                state.get("staged_gradle_identity"), "staged Gradle"
            ),
        )
        if published_summary != sealed_summary:
            fail("published sealed Gradle tree postcondition failed")
        if published_summary.digest != expected_digest:
            fail("published Gradle digest postcondition failed")
        validate_semantics(
            online / "android-sdk",
            online / "gradle-home",
            gradle_version=gradle_version,
            gradle_sha256=gradle_sha256,
            build_tools=build_tools,
            compile_sdk=compile_sdk,
        )
    except BaseException as primary:
        if gradle_moved:
            try:
                rollback_publication(
                    online_fd,
                    staging_fd,
                    decode_identity(
                        state.get("staged_gradle_identity"), "staged Gradle"
                    ),
                    uid,
                    gid,
                )
            except BaseException as rollback:
                primary.add_note(f"publication rollback also failed: {rollback}")
        raise
    finally:
        os.close(staging_fd)
        os.close(online_fd)


def optional_identity(path: Path) -> tuple[int, int] | None:
    try:
        return identity(os.lstat(path))
    except FileNotFoundError:
        return None


def optional_relative_identity(directory_fd: int, name: str) -> tuple[int, int] | None:
    try:
        return identity(os.stat(name, dir_fd=directory_fd, follow_symlinks=False))
    except FileNotFoundError:
        return None


def rollback_replacement(
    online_fd: int,
    staging_fd: int,
    replacement_name: str,
    candidate_identity: tuple[int, int],
    replaced_identity: tuple[int, int],
    uid: int,
    gid: int,
    *,
    exchanged: bool,
    promoted: bool,
) -> None:
    failures: list[str] = []
    if exchanged:
        try:
            if optional_relative_identity(online_fd, "gradle-home") != candidate_identity:
                fail("live Gradle identity changed before replacement rollback")
            if optional_relative_identity(online_fd, replacement_name) != replaced_identity:
                fail("displaced Gradle identity changed before replacement rollback")
            renameat2(
                online_fd,
                "gradle-home",
                online_fd,
                replacement_name,
                RENAME_EXCHANGE,
            )
            os.fsync(online_fd)
            if optional_relative_identity(online_fd, "gradle-home") != replaced_identity:
                fail("replacement rollback did not restore the displaced Gradle output")
            if optional_relative_identity(online_fd, replacement_name) != candidate_identity:
                fail("replacement rollback lost the candidate Gradle output")
        except (OSError, OutputError) as error:
            failures.append(f"Gradle same-parent replacement rollback failed: {error}")
    if promoted and not failures:
        try:
            if optional_relative_identity(staging_fd, "gradle-home") is not None:
                fail("Gradle staging output reappeared before replacement rollback")
            transition_root_mode(
                online_fd,
                replacement_name,
                candidate_identity,
                uid,
                gid,
                {0o500, 0o700},
                0o700,
                "Gradle replacement rollback",
            )
            renameat2(
                online_fd,
                replacement_name,
                staging_fd,
                "gradle-home",
                RENAME_NOREPLACE,
            )
            os.fsync(staging_fd)
            os.fsync(online_fd)
            if optional_relative_identity(staging_fd, "gradle-home") != candidate_identity:
                fail("replacement rollback did not restore the staged Gradle candidate")
            if optional_relative_identity(online_fd, replacement_name) is not None:
                fail("replacement rollback left the promoted Gradle name occupied")
        except (OSError, OutputError) as error:
            failures.append(f"Gradle candidate demotion failed: {error}")
    try:
        os.fsync(staging_fd)
        os.fsync(online_fd)
    except OSError as error:
        failures.append(f"Gradle rollback directory synchronization failed: {error}")
    if failures:
        fail("; ".join(failures))


def finish_promoted_replacement(
    online: Path,
    staging: Path,
    state: dict[str, object],
    uid: int,
    gid: int,
    *,
    already_exchanged: bool,
) -> None:
    destination = online / "gradle-home"
    replacement_name = str(state.get("replacement_name"))
    if REPLACEMENT_PATTERN.fullmatch(replacement_name) is None:
        fail("replacement Gradle name is malformed")
    replacement = online / replacement_name
    candidate_identity = decode_identity(
        state.get("staged_gradle_identity"), "staged Gradle"
    )
    replaced_identity = decode_identity(
        state.get("replaced_gradle_identity"), "replaced Gradle output"
    )
    expected_digest = str(state.get("expected_gradle_digest"))
    replaced_digest = str(state.get("replaced_gradle_digest"))
    online_fd = open_directory(online)
    staging_fd = open_directory(staging)
    exchanged = already_exchanged
    try:
        if not exchanged:
            validate_candidate_output(
                online,
                replacement,
                state,
                uid,
                gid,
                candidate_identity,
                expected_digest,
                published=False,
            )
            validate_displaced_output(
                destination,
                uid,
                gid,
                replaced_identity,
                replaced_digest,
            )
            if optional_relative_identity(online_fd, replacement_name) != candidate_identity:
                fail("promoted Gradle candidate identity changed before exchange")
            if optional_relative_identity(online_fd, "gradle-home") != replaced_identity:
                fail("existing Gradle identity changed before exchange")
            renameat2(
                online_fd,
                replacement_name,
                online_fd,
                "gradle-home",
                RENAME_EXCHANGE,
            )
            exchanged = True
            os.fsync(online_fd)
        if optional_relative_identity(online_fd, "gradle-home") != candidate_identity:
            fail("replacement Gradle identity postcondition failed")
        if optional_relative_identity(online_fd, replacement_name) != replaced_identity:
            fail("displaced Gradle identity postcondition failed")
        live_mode = stat.S_IMODE(os.lstat(destination).st_mode)
        if live_mode == 0o700:
            transition_root_mode(
                online_fd,
                "gradle-home",
                candidate_identity,
                uid,
                gid,
                {0o700},
                0o500,
                "replacement Gradle",
            )
        elif live_mode != 0o500:
            fail("replacement Gradle root has an unrecoverable mode")
        fsync_directory(destination)
        os.fsync(online_fd)
        validate_candidate_output(
            online,
            destination,
            state,
            uid,
            gid,
            candidate_identity,
            expected_digest,
            published=True,
        )
        validate_displaced_output(
            replacement,
            uid,
            gid,
            replaced_identity,
            replaced_digest,
        )
        validate_sdk_state(online, state, uid, gid)
    except BaseException as primary:
        try:
            rollback_replacement(
                online_fd,
                staging_fd,
                replacement_name,
                candidate_identity,
                replaced_identity,
                uid,
                gid,
                exchanged=exchanged,
                promoted=True,
            )
        except BaseException as rollback:
            primary.add_note(f"Gradle replacement rollback also failed: {rollback}")
        raise
    finally:
        os.close(staging_fd)
        os.close(online_fd)


def replace(
    online: Path,
    staging: Path,
    retired_root: Path,
    uid: int,
    gid: int,
    *,
    gradle_version: str,
    gradle_sha256: str,
    build_tools: str,
    compile_sdk: str,
    expected_digest: str,
) -> None:
    if HEX256.fullmatch(expected_digest) is None:
        fail("verified Gradle digest is malformed")
    candidate = verify_staged(
        online,
        staging,
        uid,
        gid,
        gradle_version=gradle_version,
        gradle_sha256=gradle_sha256,
        build_tools=build_tools,
        compile_sdk=compile_sdk,
    )
    if candidate.digest != expected_digest:
        fail("Gradle output changed after independent verification")
    state = load_state(online, staging, uid, gid)
    destination = online / "gradle-home"
    replaced_metadata = os.lstat(destination)
    replaced = validate_displaced_output(destination, uid, gid)
    retired_metadata = validate_retired_root(online, retired_root, uid, gid)
    candidate_identity = decode_identity(
        state.get("staged_gradle_identity"), "staged Gradle"
    )
    output = staging / "gradle-home"
    sealed_summary = inspect_tree(
        output,
        owners={(uid, gid)},
        limits=GRADLE_LIMITS,
        hash_contents=True,
        seal=True,
        seal_root=False,
        expected_identity=candidate_identity,
    )
    if sealed_summary.digest != expected_digest:
        fail("sealed Gradle candidate digest changed")
    validate_semantics(online / "android-sdk", output, **state_semantics(state))
    sync_tree(output)
    fsync_directory(staging)
    state = record_replacement_publication(
        staging,
        state,
        expected_digest,
        replaced,
        identity(replaced_metadata),
        retired_root,
        identity(retired_metadata),
    )
    replaced_identity = decode_identity(
        state.get("replaced_gradle_identity"), "replaced Gradle output"
    )
    replaced_digest = str(state.get("replaced_gradle_digest"))
    validate_displaced_output(
        destination,
        uid,
        gid,
        replaced_identity,
        replaced_digest,
    )
    replacement_name = str(state.get("replacement_name"))
    if REPLACEMENT_PATTERN.fullmatch(replacement_name) is None:
        fail("replacement Gradle name is malformed")
    replacement = online / replacement_name
    if replacement.exists() or replacement.is_symlink():
        fail("reserved replacement Gradle name is already occupied")
    validate_sdk_state(online, state, uid, gid)
    online_fd = open_directory(online)
    staging_fd = open_directory(staging)
    promoted = False
    try:
        if identity(os.lstat(output)) != candidate_identity:
            fail("Gradle candidate identity changed before replacement")
        if identity(os.lstat(destination)) != replaced_identity:
            fail("existing Gradle identity changed before replacement")
        renameat2(
            staging_fd,
            "gradle-home",
            online_fd,
            replacement_name,
            RENAME_NOREPLACE,
        )
        promoted = True
        os.fsync(staging_fd)
        os.fsync(online_fd)
    except BaseException as primary:
        if promoted:
            try:
                rollback_replacement(
                    online_fd,
                    staging_fd,
                    replacement_name,
                    candidate_identity,
                    replaced_identity,
                    uid,
                    gid,
                    exchanged=False,
                    promoted=True,
                )
            except BaseException as rollback:
                primary.add_note(f"Gradle replacement rollback also failed: {rollback}")
        raise
    finally:
        os.close(staging_fd)
        os.close(online_fd)
    finish_promoted_replacement(
        online,
        staging,
        state,
        uid,
        gid,
        already_exchanged=False,
    )


def validate_sdk_state(
    online: Path,
    state: dict[str, object],
    uid: int,
    gid: int,
) -> None:
    original_sdk = decode_identity(state.get("original_sdk_identity"), "original SDK")
    if optional_identity(online / "android-sdk") != original_sdk:
        fail("Android SDK identity changed during Gradle output recovery")
    summary = inspect_tree(
        online / "android-sdk",
        owners={(uid, gid)},
        limits=SDK_LIMITS,
        hash_contents=True,
        expected_identity=original_sdk,
    )
    if summary.digest != state.get("sdk_source_digest"):
        fail("Android SDK changed during Gradle output recovery")


def recover_legacy_v2(
    online: Path,
    staging: Path,
    state: dict[str, object],
    uid: int,
    gid: int,
) -> str:
    state = load_state(online, staging, uid, gid)
    original_sdk = decode_identity(state.get("original_sdk_identity"), "original SDK")
    staged_gradle = decode_identity(state.get("staged_gradle_identity"), "staged Gradle")
    live_sdk = optional_identity(online / "android-sdk")
    live_gradle = optional_identity(online / "gradle-home")
    private_gradle = optional_identity(staging / "gradle-home")
    if live_sdk == original_sdk:
        summary = inspect_tree(
            online / "android-sdk",
            owners={(uid, gid)},
            limits=SDK_LIMITS,
            hash_contents=True,
            expected_identity=original_sdk,
        )
        if summary.digest != state.get("sdk_source_digest"):
            fail("Android SDK changed during Gradle output recovery")
    if (
        live_sdk == original_sdk
        and live_gradle is None
        and private_gradle == staged_gradle
    ):
        return "unpublished"
    if (
        live_sdk == original_sdk
        and live_gradle == staged_gradle
        and private_gradle is None
    ):
        live_metadata = os.lstat(online / "gradle-home")
        live_mode = stat.S_IMODE(live_metadata.st_mode)
        if live_mode == 0o700:
            inspect_tree(
                online / "gradle-home",
                owners={(uid, gid)},
                limits=GRADLE_LIMITS,
                hash_contents=False,
                require_sealed=True,
                seal_root=False,
                expected_identity=staged_gradle,
            )
            online_fd = open_directory(online)
            try:
                transition_root_mode(
                    online_fd,
                    "gradle-home",
                    staged_gradle,
                    uid,
                    gid,
                    {0o700},
                    0o500,
                    "recovered Gradle publication",
                )
                os.fsync(online_fd)
            finally:
                os.close(online_fd)
        elif live_mode != 0o500:
            fail("published Gradle root has an unrecoverable mode")
        inspect_tree(
            online / "gradle-home",
            owners={(uid, gid)},
            limits=GRADLE_LIMITS,
            hash_contents=False,
            require_sealed=True,
            expected_identity=staged_gradle,
        )
        return "published"
    fail("Gradle output transaction state is incoherent and was preserved")


def recover(online: Path, staging: Path, uid: int, gid: int) -> str:
    state = load_state(online, staging, uid, gid)
    if state.get("version") == LEGACY_STATE_VERSION:
        return recover_legacy_v2(online, staging, state, uid, gid)
    validate_sdk_state(online, state, uid, gid)
    candidate = decode_identity(state.get("staged_gradle_identity"), "staged Gradle")
    private_candidate = optional_identity(staging / "gradle-home")
    live_candidate = optional_identity(online / "gradle-home")
    publication = state.get("publication")
    if publication == "replacement":
        replaced = decode_identity(
            state.get("replaced_gradle_identity"), "replaced Gradle output"
        )
        expected_digest = str(state.get("expected_gradle_digest"))
        replaced_digest = str(state.get("replaced_gradle_digest"))
        replacement_name = str(state.get("replacement_name"))
        if REPLACEMENT_PATTERN.fullmatch(replacement_name) is None:
            fail("replacement Gradle name is malformed")
        replacement = online / replacement_name
        replacement_identity = optional_identity(replacement)
        retired_root = Path(str(state.get("retired_root")))
        retired_identity = decode_identity(
            state.get("retired_root_identity"), "retired Gradle root"
        )
        validate_retired_root(online, retired_root, uid, gid, retired_identity)
        if (
            private_candidate == candidate
            and live_candidate == replaced
            and replacement_identity is None
        ):
            validate_candidate_output(
                online,
                staging / "gradle-home",
                state,
                uid,
                gid,
                candidate,
                expected_digest,
                published=False,
            )
            validate_displaced_output(
                online / "gradle-home",
                uid,
                gid,
                replaced,
                replaced_digest,
            )
            return "replacement-prepared"
        if (
            private_candidate is None
            and live_candidate == replaced
            and replacement_identity == candidate
        ):
            finish_promoted_replacement(
                online,
                staging,
                state,
                uid,
                gid,
                already_exchanged=False,
            )
            return "replaced"
        if (
            private_candidate is None
            and live_candidate == candidate
            and replacement_identity == replaced
        ):
            finish_promoted_replacement(
                online,
                staging,
                state,
                uid,
                gid,
                already_exchanged=True,
            )
            return "replaced"
        fail("Gradle replacement transaction state is incoherent and was preserved")
    if (
        publication == "unselected"
        and private_candidate == candidate
        and live_candidate is not None
    ):
        return "unselected-while-occupied"
    if private_candidate == candidate and live_candidate is None:
        if publication == "new":
            validate_candidate_output(
                online,
                staging / "gradle-home",
                state,
                uid,
                gid,
                candidate,
                str(state.get("expected_gradle_digest")),
                published=False,
            )
        elif publication != "unselected":
            fail("unpublished Gradle transaction has the wrong disposition")
        return "unpublished"
    if private_candidate is None and live_candidate == candidate and publication == "new":
        live_mode = stat.S_IMODE(os.lstat(online / "gradle-home").st_mode)
        if live_mode == 0o700:
            validate_candidate_output(
                online,
                online / "gradle-home",
                state,
                uid,
                gid,
                candidate,
                str(state.get("expected_gradle_digest")),
                published=False,
            )
            online_fd = open_directory(online)
            try:
                transition_root_mode(
                    online_fd,
                    "gradle-home",
                    candidate,
                    uid,
                    gid,
                    {0o700},
                    0o500,
                    "recovered Gradle publication",
                )
                os.fsync(online_fd)
            finally:
                os.close(online_fd)
        elif live_mode != 0o500:
            fail("published Gradle root has an unrecoverable mode")
        validate_candidate_output(
            online,
            online / "gradle-home",
            state,
            uid,
            gid,
            candidate,
            str(state.get("expected_gradle_digest")),
            published=True,
        )
        return "published"
    fail("Gradle output transaction state is incoherent and was preserved")


def archive_replaced(online: Path, staging: Path, uid: int, gid: int) -> Path:
    if recover(online, staging, uid, gid) != "replaced":
        fail("Gradle output is not a completed replacement")
    state = load_state(online, staging, uid, gid)
    retired_root = Path(str(state.get("retired_root")))
    retired_identity = decode_identity(
        state.get("retired_root_identity"), "retired Gradle root"
    )
    validate_retired_root(online, retired_root, uid, gid, retired_identity)
    archive_name = str(state.get("archive_name"))
    if ARCHIVE_PATTERN.fullmatch(archive_name) is None:
        fail("retired Gradle archive name is malformed")
    destination = retired_root / archive_name
    if destination.exists() or destination.is_symlink():
        fail("retired Gradle archive destination is already occupied")
    staging_identity = decode_identity(
        state.get("staging_identity"), "Gradle output staging"
    )
    replacement_name = str(state.get("replacement_name"))
    if REPLACEMENT_PATTERN.fullmatch(replacement_name) is None:
        fail("replacement Gradle name is malformed")
    replaced_identity = decode_identity(
        state.get("replaced_gradle_identity"), "replaced Gradle output"
    )
    replaced_digest = str(state.get("replaced_gradle_digest"))
    replacement = online / replacement_name
    validate_displaced_output(
        replacement,
        uid,
        gid,
        replaced_identity,
        replaced_digest,
    )
    online_fd = open_directory(online)
    retired_fd = open_directory(retired_root)
    try:
        if identity(os.lstat(staging)) != staging_identity:
            fail("Gradle staging identity changed before archival")
        renameat2(
            online_fd,
            staging.name,
            retired_fd,
            archive_name,
            RENAME_NOREPLACE,
        )
        os.fsync(online_fd)
        os.fsync(retired_fd)
        if optional_identity(staging) is not None:
            fail("Gradle staging name survived archival")
        if identity(os.lstat(destination)) != staging_identity:
            fail("retired Gradle archive identity postcondition failed")
        validate_displaced_output(
            replacement,
            uid,
            gid,
            replaced_identity,
            replaced_digest,
        )
    finally:
        os.close(retired_fd)
        os.close(online_fd)
    return destination


def create_fake_sdk(root: Path, build_tools: str, compile_sdk: str) -> None:
    tools = root / "build-tools" / build_tools
    tools.mkdir(parents=True)
    (tools / "source.properties").write_text(f"Pkg.Revision={build_tools}\n", encoding="utf-8")
    for name in ("aapt2", "apksigner", "zipalign"):
        path = tools / name
        path.write_bytes(b"tool\n")
        path.chmod(0o700)
    platform = root / "platforms" / f"android-{compile_sdk}"
    platform.mkdir(parents=True)
    (platform / "source.properties").write_text(
        f"AndroidVersion.ApiLevel={compile_sdk}\n",
        encoding="utf-8",
    )
    (platform / "android.jar").write_bytes(b"jar\n")


def create_fake_gradle(root: Path, version: str, archive: bytes) -> None:
    (root / "caches" / "modules-2").mkdir(parents=True)
    distribution = root / "wrapper" / "dists" / f"gradle-{version}-all" / "token"
    distribution.mkdir(parents=True)
    (distribution / f"gradle-{version}-all.zip").write_bytes(archive)
    launcher = distribution / f"gradle-{version}" / "bin"
    launcher.mkdir(parents=True)
    (launcher / "gradle").write_bytes(b"#!/bin/sh\n")
    (launcher / "gradle").chmod(0o700)


def make_stage(online: Path) -> Path:
    return Path(tempfile.mkdtemp(prefix=".rustdesk-gradle-warm.", dir=online))


def remove_stage(staging: Path) -> None:
    for current, directories, files in os.walk(staging, topdown=False, followlinks=False):
        current_path = Path(current)
        current_path.chmod(0o700)
        for name in files:
            path = current_path / name
            if path.is_symlink():
                path.unlink()
            else:
                path.chmod(0o600)
                path.unlink()
        for name in directories:
            path = current_path / name
            if path.is_symlink():
                path.unlink()
            else:
                path.chmod(0o700)
                path.rmdir()
    staging.rmdir()


def self_test() -> None:
    uid = os.geteuid()
    gid = os.getegid()
    version = "8.7"
    archive = b"publisher-pinned-gradle-distribution\n"
    archive_hash = hashlib.sha256(archive).hexdigest()
    build_tools = "34.0.0"
    compile_sdk = "34"

    def fixture(base: Path) -> tuple[Path, Path]:
        base.mkdir()
        online = base / "online"
        online.mkdir(mode=0o700)
        previous_umask = os.umask(0o077)
        try:
            create_fake_sdk(online / "android-sdk", build_tools, compile_sdk)
        finally:
            os.umask(previous_umask)
        staging = make_stage(online)
        prepare(
            online,
            staging,
            uid,
            gid,
            gradle_version=version,
            gradle_sha256=archive_hash,
            build_tools=build_tools,
            compile_sdk=compile_sdk,
        )
        create_fake_gradle(staging / "gradle-home", version, archive)
        return online, staging

    def move_candidate_before_root_seal(online: Path, staging: Path) -> None:
        summary = verify_staged(
            online,
            staging,
            uid,
            gid,
            gradle_version=version,
            gradle_sha256=archive_hash,
            build_tools=build_tools,
            compile_sdk=compile_sdk,
        )
        state = load_state(online, staging, uid, gid)
        sealed = inspect_tree(
            staging / "gradle-home",
            owners={(uid, gid)},
            limits=GRADLE_LIMITS,
            hash_contents=True,
            seal=True,
            seal_root=False,
            expected_identity=decode_identity(
                state.get("staged_gradle_identity"), "staged Gradle"
            ),
        )
        if sealed.digest != summary.digest:
            fail("self-test publication sealing changed the candidate digest")
        validate_semantics(
            online / "android-sdk",
            staging / "gradle-home",
            **state_semantics(state),
        )
        sync_tree(staging / "gradle-home")
        fsync_directory(staging)
        state = record_new_publication(staging, state, summary.digest)
        online_fd = open_directory(online)
        staging_fd = open_directory(staging)
        try:
            renameat2(
                staging_fd,
                "gradle-home",
                online_fd,
                "gradle-home",
                RENAME_NOREPLACE,
            )
            os.fsync(staging_fd)
            os.fsync(online_fd)
        finally:
            os.close(staging_fd)
            os.close(online_fd)

    def replacement_fixture(
        base: Path,
    ) -> tuple[Path, Path, Path, TreeSummary, TreeSummary, tuple[int, int]]:
        base.mkdir()
        online = base / "online"
        online.mkdir(mode=0o700)
        retired = base / "retired-records"
        retired.mkdir(mode=0o700)
        previous_umask = os.umask(0o077)
        try:
            create_fake_sdk(online / "android-sdk", build_tools, compile_sdk)
            old = online / "gradle-home"
            old.mkdir(mode=0o700)
            create_fake_gradle(old, "7.6.4", b"stale-gradle-distribution\n")
        finally:
            os.umask(previous_umask)
        inspect_tree(
            old,
            owners={(uid, gid)},
            limits=GRADLE_LIMITS,
            hash_contents=True,
            normalize=True,
        )
        inspect_tree(
            old,
            owners={(uid, gid)},
            limits=GRADLE_LIMITS,
            hash_contents=True,
            seal=True,
        )
        old_summary = validate_displaced_output(old, uid, gid)
        old_identity = identity(os.lstat(old))
        staging = make_stage(online)
        prepare(
            online,
            staging,
            uid,
            gid,
            gradle_version=version,
            gradle_sha256=archive_hash,
            build_tools=build_tools,
            compile_sdk=compile_sdk,
        )
        create_fake_gradle(staging / "gradle-home", version, archive)
        candidate = verify_staged(
            online,
            staging,
            uid,
            gid,
            gradle_version=version,
            gradle_sha256=archive_hash,
            build_tools=build_tools,
            compile_sdk=compile_sdk,
        )
        return online, retired, staging, candidate, old_summary, old_identity

    def bind_replacement(
        online: Path,
        retired: Path,
        staging: Path,
        candidate: TreeSummary,
    ) -> dict[str, object]:
        state = load_state(online, staging, uid, gid)
        old_metadata = os.lstat(online / "gradle-home")
        old_summary = validate_displaced_output(online / "gradle-home", uid, gid)
        retired_metadata = validate_retired_root(online, retired, uid, gid)
        candidate_identity = decode_identity(
            state.get("staged_gradle_identity"), "staged Gradle"
        )
        sealed = inspect_tree(
            staging / "gradle-home",
            owners={(uid, gid)},
            limits=GRADLE_LIMITS,
            hash_contents=True,
            seal=True,
            seal_root=False,
            expected_identity=candidate_identity,
        )
        if sealed.digest != candidate.digest:
            fail("self-test replacement sealing changed the candidate digest")
        validate_semantics(
            online / "android-sdk",
            staging / "gradle-home",
            **state_semantics(state),
        )
        sync_tree(staging / "gradle-home")
        fsync_directory(staging)
        state = record_replacement_publication(
            staging,
            state,
            candidate.digest,
            old_summary,
            identity(old_metadata),
            retired,
            identity(retired_metadata),
        )
        return state

    def promote_replacement(
        online: Path,
        staging: Path,
        state: dict[str, object],
        *,
        exchange: bool,
    ) -> None:
        replacement_name = str(state.get("replacement_name"))
        online_fd = open_directory(online)
        staging_fd = open_directory(staging)
        try:
            renameat2(
                staging_fd,
                "gradle-home",
                online_fd,
                replacement_name,
                RENAME_NOREPLACE,
            )
            os.fsync(staging_fd)
            os.fsync(online_fd)
            if exchange:
                renameat2(
                    online_fd,
                    replacement_name,
                    online_fd,
                    "gradle-home",
                    RENAME_EXCHANGE,
                )
                os.fsync(online_fd)
        finally:
            os.close(staging_fd)
            os.close(online_fd)

    def cleanup_replacement(
        online: Path,
        retired: Path,
        staging: Path,
    ) -> None:
        state = load_state(online, staging, uid, gid)
        displaced = online / str(state.get("replacement_name"))
        archived = archive_replaced(online, staging, uid, gid)
        remove_stage(archived)
        remove_stage(displaced)
        remove_stage(online / "gradle-home")
        remove_stage(online / "android-sdk")
        retired.rmdir()
        online.rmdir()

    with tempfile.TemporaryDirectory(prefix="online-gradle-output-test-") as temporary:
        base = Path(temporary)
        online, staging = fixture(base / "normal")
        summary = verify_staged(
            online,
            staging,
            uid,
            gid,
            gradle_version=version,
            gradle_sha256=archive_hash,
            build_tools=build_tools,
            compile_sdk=compile_sdk,
        )
        publish(
            online,
            staging,
            uid,
            gid,
            gradle_version=version,
            gradle_sha256=archive_hash,
            build_tools=build_tools,
            compile_sdk=compile_sdk,
            expected_digest=summary.digest,
        )
        if recover(online, staging, uid, gid) != "published":
            fail("self-test did not classify completed publication")
        check_complete(
            online,
            uid,
            gid,
            gradle_version=version,
            gradle_sha256=archive_hash,
            build_tools=build_tools,
            compile_sdk=compile_sdk,
        )
        gradle = online / "gradle-home"
        archive_path = (
            gradle
            / "wrapper"
            / "dists"
            / f"gradle-{version}-all"
            / "token"
            / f"gradle-{version}-all.zip"
        )
        launcher_path = (
            archive_path.parent / f"gradle-{version}" / "bin" / "gradle"
        )
        if (
            stat.S_IMODE(os.lstat(gradle).st_mode) != 0o500
            or stat.S_IMODE(os.lstat(archive_path).st_mode) != 0o400
            or stat.S_IMODE(os.lstat(launcher_path).st_mode) != 0o500
        ):
            fail("self-test publication did not seal the Gradle seed")
        gradle.chmod(0o700)
        try:
            check_complete(
                online,
                uid,
                gid,
                gradle_version=version,
                gradle_sha256=archive_hash,
                build_tools=build_tools,
                compile_sdk=compile_sdk,
            )
        except OutputError:
            pass
        else:
            fail("self-test accepted a writable Gradle seed directory")
        gradle.chmod(0o500)
        archive_path.chmod(0o600)
        try:
            check_complete(
                online,
                uid,
                gid,
                gradle_version=version,
                gradle_sha256=archive_hash,
                build_tools=build_tools,
                compile_sdk=compile_sdk,
            )
        except OutputError:
            pass
        else:
            fail("self-test accepted a writable Gradle seed file")
        archive_path.chmod(0o400)
        remove_stage(staging)

        online, staging = fixture(base / "post-rename-recovery")
        move_candidate_before_root_seal(online, staging)
        if stat.S_IMODE(os.lstat(online / "gradle-home").st_mode) != 0o700:
            fail("self-test did not create the post-rename/pre-root-seal state")
        if recover(online, staging, uid, gid) != "published":
            fail("self-test did not recover the post-rename/pre-root-seal state")
        if stat.S_IMODE(os.lstat(online / "gradle-home").st_mode) != 0o500:
            fail("self-test recovery did not seal the published Gradle root")
        check_complete(
            online,
            uid,
            gid,
            gradle_version=version,
            gradle_sha256=archive_hash,
            build_tools=build_tools,
            compile_sdk=compile_sdk,
        )
        remove_stage(staging)

        online, staging = fixture(base / "sealed-root-rollback")
        move_candidate_before_root_seal(online, staging)
        state = load_state(online, staging, uid, gid)
        expected_gradle = decode_identity(
            state.get("staged_gradle_identity"), "staged Gradle"
        )
        online_fd = open_directory(online)
        staging_fd = open_directory(staging)
        try:
            transition_root_mode(
                online_fd,
                "gradle-home",
                expected_gradle,
                uid,
                gid,
                {0o700},
                0o500,
                "self-test published Gradle",
            )
            rollback_publication(
                online_fd,
                staging_fd,
                expected_gradle,
                uid,
                gid,
            )
        finally:
            os.close(staging_fd)
            os.close(online_fd)
        if (online / "gradle-home").exists() or (online / "gradle-home").is_symlink():
            fail("self-test rollback left the published Gradle name occupied")
        if recover(online, staging, uid, gid) != "unpublished":
            fail("self-test rollback did not restore unpublished transaction state")
        if stat.S_IMODE(os.lstat(staging / "gradle-home").st_mode) != 0o700:
            fail("self-test rollback did not restore private root traversal")
        remove_stage(staging)

        online, staging = fixture(base / "sdk-mutation")
        (
            online
            / "android-sdk"
            / "platforms"
            / f"android-{compile_sdk}"
            / "android.jar"
        ).write_bytes(b"changed\n")
        try:
            verify_staged(
                online,
                staging,
                uid,
                gid,
                gradle_version=version,
                gradle_sha256=archive_hash,
                build_tools=build_tools,
                compile_sdk=compile_sdk,
            )
        except OutputError:
            pass
        else:
            fail("self-test accepted a changed read-only Android SDK")
        remove_stage(staging)

        online, staging = fixture(base / "destination-race")
        original_sdk = identity(os.lstat(online / "android-sdk"))
        summary = verify_staged(
            online,
            staging,
            uid,
            gid,
            gradle_version=version,
            gradle_sha256=archive_hash,
            build_tools=build_tools,
            compile_sdk=compile_sdk,
        )
        (online / "gradle-home").mkdir()
        try:
            publish(
                online,
                staging,
                uid,
                gid,
                gradle_version=version,
                gradle_sha256=archive_hash,
                build_tools=build_tools,
                compile_sdk=compile_sdk,
                expected_digest=summary.digest,
            )
        except OutputError:
            pass
        else:
            fail("self-test accepted an occupied Gradle publication destination")
        if identity(os.lstat(online / "android-sdk")) != original_sdk:
            fail("destination-race self-test changed the live SDK")
        (online / "gradle-home").rmdir()
        remove_stage(staging)

        online, staging = fixture(base / "bad-checksum")
        try:
            verify_staged(
                online,
                staging,
                uid,
                gid,
                gradle_version=version,
                gradle_sha256="0" * 64,
                build_tools=build_tools,
                compile_sdk=compile_sdk,
            )
        except OutputError:
            pass
        else:
            fail("self-test accepted a wrong Gradle distribution checksum")
        remove_stage(staging)

        (
            replacement_online,
            replacement_retired,
            replacement_staging,
            replacement_candidate,
            replacement_old,
            replacement_old_identity,
        ) = replacement_fixture(base / "replacement")
        replace(
            replacement_online,
            replacement_staging,
            replacement_retired,
            uid,
            gid,
            gradle_version=version,
            gradle_sha256=archive_hash,
            build_tools=build_tools,
            compile_sdk=compile_sdk,
            expected_digest=replacement_candidate.digest,
        )
        if recover(replacement_online, replacement_staging, uid, gid) != "replaced":
            fail("self-test did not classify a completed Gradle replacement")
        replacement_state = load_state(
            replacement_online, replacement_staging, uid, gid
        )
        replacement_old_path = replacement_online / str(
            replacement_state.get("replacement_name")
        )
        if identity(os.lstat(replacement_old_path)) != replacement_old_identity:
            fail("self-test replacement lost the displaced Gradle identity")
        if (
            validate_displaced_output(replacement_old_path, uid, gid).digest
            != replacement_old.digest
        ):
            fail("self-test replacement changed the displaced Gradle output")
        cleanup_replacement(
            replacement_online,
            replacement_retired,
            replacement_staging,
        )

        (
            prepared_online,
            prepared_retired,
            prepared_staging,
            prepared_candidate,
            prepared_old,
            prepared_old_identity,
        ) = replacement_fixture(base / "prepared-recovery")
        prepared_state = bind_replacement(
            prepared_online,
            prepared_retired,
            prepared_staging,
            prepared_candidate,
        )
        if recover(prepared_online, prepared_staging, uid, gid) != "replacement-prepared":
            fail("self-test did not recover a prepared Gradle replacement")
        if identity(os.lstat(prepared_online / "gradle-home")) != prepared_old_identity:
            fail("prepared recovery lost the old live Gradle identity")
        if (
            validate_displaced_output(prepared_online / "gradle-home", uid, gid).digest
            != prepared_old.digest
        ):
            fail("prepared recovery changed the old live Gradle output")
        prepared_residue = prepared_online / str(prepared_state.get("replacement_name"))
        if prepared_residue.exists() or prepared_residue.is_symlink():
            fail("prepared recovery created a replacement sibling")
        remove_stage(prepared_staging)
        remove_stage(prepared_online / "gradle-home")
        remove_stage(prepared_online / "android-sdk")
        prepared_retired.rmdir()
        prepared_online.rmdir()

        (
            promoted_online,
            promoted_retired,
            promoted_staging,
            promoted_candidate,
            promoted_old,
            promoted_old_identity,
        ) = replacement_fixture(base / "promoted-recovery")
        promoted_state = bind_replacement(
            promoted_online,
            promoted_retired,
            promoted_staging,
            promoted_candidate,
        )
        promote_replacement(
            promoted_online,
            promoted_staging,
            promoted_state,
            exchange=False,
        )
        if recover(promoted_online, promoted_staging, uid, gid) != "replaced":
            fail("self-test did not recover a promoted Gradle replacement")
        promoted_old_path = promoted_online / str(promoted_state.get("replacement_name"))
        if identity(os.lstat(promoted_old_path)) != promoted_old_identity:
            fail("promoted recovery lost the displaced Gradle identity")
        if (
            validate_displaced_output(promoted_old_path, uid, gid).digest
            != promoted_old.digest
        ):
            fail("promoted recovery changed the displaced Gradle output")
        cleanup_replacement(promoted_online, promoted_retired, promoted_staging)

        (
            exchanged_online,
            exchanged_retired,
            exchanged_staging,
            exchanged_candidate,
            exchanged_old,
            exchanged_old_identity,
        ) = replacement_fixture(base / "exchanged-recovery")
        exchanged_state = bind_replacement(
            exchanged_online,
            exchanged_retired,
            exchanged_staging,
            exchanged_candidate,
        )
        promote_replacement(
            exchanged_online,
            exchanged_staging,
            exchanged_state,
            exchange=True,
        )
        if stat.S_IMODE(os.lstat(exchanged_online / "gradle-home").st_mode) != 0o700:
            fail("self-test exchanged Gradle candidate was unexpectedly sealed")
        if recover(exchanged_online, exchanged_staging, uid, gid) != "replaced":
            fail("self-test did not recover an exchanged Gradle replacement")
        if stat.S_IMODE(os.lstat(exchanged_online / "gradle-home").st_mode) != 0o500:
            fail("self-test recovery did not seal the exchanged Gradle candidate")
        exchanged_old_path = exchanged_online / str(
            exchanged_state.get("replacement_name")
        )
        if identity(os.lstat(exchanged_old_path)) != exchanged_old_identity:
            fail("exchanged recovery lost the displaced Gradle identity")
        if (
            validate_displaced_output(exchanged_old_path, uid, gid).digest
            != exchanged_old.digest
        ):
            fail("exchanged recovery changed the displaced Gradle output")
        cleanup_replacement(exchanged_online, exchanged_retired, exchanged_staging)

        (
            rollback_online,
            rollback_retired,
            rollback_staging,
            rollback_candidate,
            rollback_old,
            rollback_old_identity,
        ) = replacement_fixture(base / "replacement-rollback")
        rollback_state = bind_replacement(
            rollback_online,
            rollback_retired,
            rollback_staging,
            rollback_candidate,
        )
        promote_replacement(
            rollback_online,
            rollback_staging,
            rollback_state,
            exchange=True,
        )
        rollback_online_fd = open_directory(rollback_online)
        rollback_staging_fd = open_directory(rollback_staging)
        try:
            rollback_candidate_identity = decode_identity(
                rollback_state.get("staged_gradle_identity"),
                "rollback Gradle candidate",
            )
            transition_root_mode(
                rollback_online_fd,
                "gradle-home",
                rollback_candidate_identity,
                uid,
                gid,
                {0o700},
                0o500,
                "self-test replacement rollback",
            )
            rollback_replacement(
                rollback_online_fd,
                rollback_staging_fd,
                str(rollback_state.get("replacement_name")),
                rollback_candidate_identity,
                rollback_old_identity,
                uid,
                gid,
                exchanged=True,
                promoted=True,
            )
        finally:
            os.close(rollback_staging_fd)
            os.close(rollback_online_fd)
        if recover(rollback_online, rollback_staging, uid, gid) != "replacement-prepared":
            fail("self-test Gradle replacement rollback did not restore prepared state")
        if identity(os.lstat(rollback_online / "gradle-home")) != rollback_old_identity:
            fail("self-test Gradle replacement rollback lost the old live output")
        if (
            validate_displaced_output(rollback_online / "gradle-home", uid, gid).digest
            != rollback_old.digest
        ):
            fail("self-test Gradle replacement rollback changed the old output")
        if identity(os.lstat(rollback_staging / "gradle-home")) != rollback_candidate_identity:
            fail("self-test Gradle replacement rollback lost the candidate")
        if stat.S_IMODE(os.lstat(rollback_staging / "gradle-home").st_mode) != 0o700:
            fail("self-test Gradle replacement rollback did not restore candidate traversal")
        rollback_residue = rollback_online / str(rollback_state.get("replacement_name"))
        if rollback_residue.exists() or rollback_residue.is_symlink():
            fail("self-test Gradle replacement rollback left a reserved sibling")
        remove_stage(rollback_staging)
        remove_stage(rollback_online / "gradle-home")
        remove_stage(rollback_online / "android-sdk")
        rollback_retired.rmdir()
        rollback_online.rmdir()

        hostile = base / "hostile"
        hostile.mkdir()
        (hostile / "target").write_bytes(b"x")
        os.symlink("target", hostile / "link")
        try:
            inspect_tree(
                hostile,
                owners={(uid, gid)},
                limits=SDK_LIMITS,
                hash_contents=False,
            )
        except OutputError:
            pass
        else:
            fail("self-test accepted a symlinked output")


def common_arguments(parser: argparse.ArgumentParser, staging: bool = True) -> None:
    parser.add_argument("--online", type=Path, required=True)
    if staging:
        parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)


def semantic_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--gradle-version", required=True)
    parser.add_argument("--gradle-sha256", required=True)
    parser.add_argument("--build-tools", required=True)
    parser.add_argument("--compile-sdk", required=True)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    subparsers = value.add_subparsers(dest="command", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    common_arguments(prepare_parser)
    semantic_arguments(prepare_parser)
    verify_parser = subparsers.add_parser("verify")
    common_arguments(verify_parser)
    semantic_arguments(verify_parser)
    publish_parser = subparsers.add_parser("publish")
    common_arguments(publish_parser)
    semantic_arguments(publish_parser)
    publish_parser.add_argument("--expected-digest", required=True)
    replace_parser = subparsers.add_parser("replace")
    common_arguments(replace_parser)
    semantic_arguments(replace_parser)
    replace_parser.add_argument("--retired-root", type=Path, required=True)
    replace_parser.add_argument("--expected-digest", required=True)
    recover_parser = subparsers.add_parser("recover")
    common_arguments(recover_parser)
    archive_parser = subparsers.add_parser("archive-replaced")
    common_arguments(archive_parser)
    check_parser = subparsers.add_parser("check-complete")
    common_arguments(check_parser, staging=False)
    semantic_arguments(check_parser)
    subparsers.add_parser("self-test")
    return value


def main() -> int:
    arguments = parser().parse_args()
    if arguments.command == "self-test":
        self_test()
        print("online-gradle-output: self-test OK")
        return 0
    if arguments.uid < 0 or arguments.gid < 0:
        fail("UID/GID must be nonnegative")
    online = arguments.online
    staging = getattr(arguments, "staging", None)
    if arguments.command == "prepare":
        prepare(
            online,
            staging,
            arguments.uid,
            arguments.gid,
            gradle_version=arguments.gradle_version,
            gradle_sha256=arguments.gradle_sha256,
            build_tools=arguments.build_tools,
            compile_sdk=arguments.compile_sdk,
        )
    elif arguments.command == "verify":
        summary = verify_staged(
            online,
            staging,
            arguments.uid,
            arguments.gid,
            gradle_version=arguments.gradle_version,
            gradle_sha256=arguments.gradle_sha256,
            build_tools=arguments.build_tools,
            compile_sdk=arguments.compile_sdk,
        )
        print(f"sha256={summary.digest}")
        return 0
    elif arguments.command == "publish":
        publish(
            online,
            staging,
            arguments.uid,
            arguments.gid,
            gradle_version=arguments.gradle_version,
            gradle_sha256=arguments.gradle_sha256,
            build_tools=arguments.build_tools,
            compile_sdk=arguments.compile_sdk,
            expected_digest=arguments.expected_digest,
        )
    elif arguments.command == "replace":
        replace(
            online,
            staging,
            arguments.retired_root,
            arguments.uid,
            arguments.gid,
            gradle_version=arguments.gradle_version,
            gradle_sha256=arguments.gradle_sha256,
            build_tools=arguments.build_tools,
            compile_sdk=arguments.compile_sdk,
            expected_digest=arguments.expected_digest,
        )
    elif arguments.command == "recover":
        print(recover(online, staging, arguments.uid, arguments.gid))
        return 0
    elif arguments.command == "archive-replaced":
        print(archive_replaced(online, staging, arguments.uid, arguments.gid))
        return 0
    elif arguments.command == "check-complete":
        check_complete(
            online,
            arguments.uid,
            arguments.gid,
            gradle_version=arguments.gradle_version,
            gradle_sha256=arguments.gradle_sha256,
            build_tools=arguments.build_tools,
            compile_sdk=arguments.compile_sdk,
        )
    else:
        fail("unknown command")
    print(f"online-gradle-output: {arguments.command} OK")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, OutputError) as error:
        raise SystemExit(f"online-gradle-output: {error}")
