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


STATE_NAME = ".rustdesk-gradle-output-state-v2"
STATE_VERSION = 2
STAGING_PATTERN = re.compile(r"\.rustdesk-gradle-warm\.[A-Za-z0-9_]{8,}\Z")
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
GRADLE_LIMITS = (100_000, 100_000, 12 * 1024**3, 2 * 1024**3)
SDK_LIMITS = (100_000, 100_000, 4 * 1024**3, 2 * 1024**3)
BLOCK_SIZE = 1024 * 1024
MOUNTINFO_LIMIT = 8 * 1024 * 1024
RENAME_NOREPLACE = 1


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
    expected_identity: tuple[int, int] | None = None,
) -> TreeSummary:
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


def load_state(online: Path, staging: Path, uid: int, gid: int) -> dict[str, object]:
    validate_root(online, "online root", {(uid, gid)})
    stage_metadata = validate_root(staging, "Gradle output staging", {(uid, gid)})
    if staging.parent != online or STAGING_PATTERN.fullmatch(staging.name) is None:
        fail("Gradle output staging is outside its reserved online namespace")
    state_path = staging / STATE_NAME
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
    expected_keys = {
        "version",
        "online",
        "staging",
        "online_identity",
        "staging_identity",
        "original_sdk_identity",
        "staged_gradle_identity",
        "sdk_source_digest",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or value.get("version") != STATE_VERSION
    ):
        fail("Gradle output state has the wrong version")
    if value.get("online") != os.fspath(online) or value.get("staging") != os.fspath(staging):
        fail("Gradle output state path binding is invalid")
    if decode_identity(value.get("online_identity"), "online root") != identity(os.lstat(online)):
        fail("online root identity changed")
    if decode_identity(value.get("staging_identity"), "staging root") != identity(stage_metadata):
        fail("Gradle output staging identity changed")
    return value


def prepare(online: Path, staging: Path, uid: int, gid: int) -> None:
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
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", gradle_version) is None:
        fail("Gradle version is malformed")
    if HEX256.fullmatch(gradle_sha256) is None:
        fail("Gradle distribution checksum is malformed")
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", build_tools) is None:
        fail("Android build-tools version is malformed")
    if re.fullmatch(r"[1-9][0-9]*", compile_sdk) is None:
        fail("Android compile SDK is malformed")
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
) -> None:
    state = load_state(online, staging, uid, gid)
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
    inspect_tree(
        staged_gradle,
        owners={(uid, gid)},
        limits=GRADLE_LIMITS,
        hash_contents=False,
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
    inspect_tree(gradle, owners=owners, limits=GRADLE_LIMITS, hash_contents=False)
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


def rollback_publication(online_fd: int, staging_fd: int) -> None:
    failures = []
    try:
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
) -> None:
    verify_staged(
        online,
        staging,
        uid,
        gid,
        gradle_version=gradle_version,
        gradle_sha256=gradle_sha256,
        build_tools=build_tools,
        compile_sdk=compile_sdk,
    )
    state = load_state(online, staging, uid, gid)
    if (online / "gradle-home").exists() or (online / "gradle-home").is_symlink():
        fail("Gradle output destination appeared before no-clobber publication")
    sync_tree(staging / "gradle-home")
    fsync_directory(staging)
    online_fd = open_directory(online)
    staging_fd = open_directory(staging)
    gradle_moved = False
    try:
        renameat2(staging_fd, "gradle-home", online_fd, "gradle-home", RENAME_NOREPLACE)
        gradle_moved = True
        os.fsync(staging_fd)
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
                rollback_publication(online_fd, staging_fd)
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


def recover(online: Path, staging: Path, uid: int, gid: int) -> str:
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
        return "published"
    fail("Gradle output transaction state is incoherent and was preserved")


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
        current_path.chmod(0o700)
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
        prepare(online, staging, uid, gid)
        create_fake_gradle(staging / "gradle-home", version, archive)
        return online, staging

    with tempfile.TemporaryDirectory(prefix="online-gradle-output-test-") as temporary:
        base = Path(temporary)
        online, staging = fixture(base / "normal")
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
        publish(
            online,
            staging,
            uid,
            gid,
            gradle_version=version,
            gradle_sha256=archive_hash,
            build_tools=build_tools,
            compile_sdk=compile_sdk,
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
    verify_parser = subparsers.add_parser("verify")
    common_arguments(verify_parser)
    semantic_arguments(verify_parser)
    publish_parser = subparsers.add_parser("publish")
    common_arguments(publish_parser)
    semantic_arguments(publish_parser)
    recover_parser = subparsers.add_parser("recover")
    common_arguments(recover_parser)
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
        prepare(online, staging, arguments.uid, arguments.gid)
    elif arguments.command == "verify":
        verify_staged(
            online,
            staging,
            arguments.uid,
            arguments.gid,
            gradle_version=arguments.gradle_version,
            gradle_sha256=arguments.gradle_sha256,
            build_tools=arguments.build_tools,
            compile_sdk=arguments.compile_sdk,
        )
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
        )
    elif arguments.command == "recover":
        print(recover(online, staging, arguments.uid, arguments.gid))
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
