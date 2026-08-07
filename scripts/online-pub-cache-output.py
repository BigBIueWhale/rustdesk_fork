#!/usr/bin/env python3
"""Validate and durably publish the networked Flutter/Dart Pub cache."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile


STATE_NAME = ".rustdesk-pub-cache-output-state-v2"
STATE_VERSION = 2
STAGING_PATTERN = re.compile(r"\.rustdesk-pub-cache\.[A-Za-z0-9_]{8,64}")
ARCHIVE_PATTERN = re.compile(
    r"pub-cache-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+"
)
REPLACEMENT_PATTERN = re.compile(
    r"\.rustdesk-retired-pub-cache-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+-[0-9a-f]+"
)
HEX_OBJECT_PATTERN = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
HEX_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
VERSION_PATTERN = re.compile(r"[0-9]+(?:\.[0-9]+){2,3}")
CHECKOUT_PATTERN = re.compile(r".+-([0-9a-f]{40}|[0-9a-f]{64})")
BARE_CACHE_PATTERN = re.compile(r".+-[0-9a-f]{40}")
EXPECTED_GIT_DEPENDENCIES = 3
ALLOWED_LEGACY_TOP_LEVEL = {"_temp", "log", "README.md"}
TREE_LIMITS = (100_000, 30_000, 4 * 1024**3, 256 * 1024**2, 32)
FORBIDDEN_MODE_BITS = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2
BLOCK_SIZE = 1024 * 1024


class PubCacheError(RuntimeError):
    """A fail-closed Pub-cache validation or publication error."""


class TreeSummary:
    def __init__(self, files: int, directories: int, symlinks: int, size: int, digest: str):
        self.files = files
        self.directories = directories
        self.symlinks = symlinks
        self.size = size
        self.digest = digest


def fail(message: str) -> None:
    raise PubCacheError(message)


def identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def stable_metadata(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
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
        or any(not isinstance(item, int) or item < 0 for item in value)
    ):
        fail(f"recorded {label} identity is malformed")
    return value[0], value[1]


def validate_absolute(path: Path, label: str) -> Path:
    raw = os.fspath(path)
    if (
        not path.is_absolute()
        or "\0" in raw
        or Path(os.path.normpath(raw)) != path
        or ".." in path.parts
    ):
        fail(f"{label} is not one canonical absolute path")
    return path


def validate_pin(value: str, label: str, pattern: re.Pattern[str]) -> str:
    if pattern.fullmatch(value) is None:
        fail(f"{label} is malformed")
    return value


def decode_mount_path(value: bytes) -> bytes:
    result = bytearray()
    index = 0
    while index < len(value):
        if value[index] != ord("\\"):
            result.append(value[index])
            index += 1
            continue
        if index + 3 >= len(value):
            fail("malformed mountpoint escape")
        escaped = value[index + 1 : index + 4]
        if any(byte < ord("0") or byte > ord("7") for byte in escaped):
            fail("malformed mountpoint escape")
        result.append(int(escaped, 8))
        index += 4
    return bytes(result)


def read_mountinfo() -> list[bytes]:
    descriptor = os.open(
        "/proc/self/mountinfo",
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        data = bytearray()
        while True:
            block = os.read(descriptor, BLOCK_SIZE)
            if not block:
                break
            data.extend(block)
            if len(data) > 16 * 1024**2:
                fail("/proc/self/mountinfo exceeds its byte bound")
    finally:
        os.close(descriptor)
    mountpoints = []
    for record in bytes(data).splitlines():
        fields = record.split()
        if len(fields) < 7 or b"-" not in fields:
            fail("malformed /proc/self/mountinfo record")
        mountpoints.append(decode_mount_path(fields[4]))
    if not mountpoints:
        fail("/proc/self/mountinfo has no records")
    return mountpoints


def reject_descendant_mounts(root: Path) -> None:
    encoded = os.fsencode(root)
    prefix = encoded.rstrip(b"/") + b"/"
    descendants = sorted(
        mountpoint
        for mountpoint in read_mountinfo()
        if mountpoint.startswith(prefix)
    )
    if descendants:
        fail(f"Pub cache contains a descendant mount: {os.fsdecode(descendants[0])}")


def reject_extended_metadata(path: Path, metadata: os.stat_result, label: str) -> None:
    if metadata.st_mode & FORBIDDEN_MODE_BITS:
        fail(f"{label} carries set-id/sticky mode bits")
    try:
        attributes = os.listxattr(path, follow_symlinks=False)
    except OSError as error:
        fail(f"cannot inspect {label} extended attributes: {error}")
    if attributes:
        fail(f"{label} carries extended attributes")


def validate_root(
    path: Path,
    label: str,
    owners: set[tuple[int, int]],
    expected_identity: tuple[int, int] | None = None,
    *,
    published: bool = False,
) -> os.stat_result:
    canonical = validate_absolute(path, label)
    metadata = os.lstat(canonical)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail(f"{label} is not one real directory")
    owner = (metadata.st_uid, metadata.st_gid)
    if owner not in owners:
        fail(f"{label} has an inadmissible owner")
    reject_extended_metadata(canonical, metadata, label)
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        fail(f"{label} is group/world writable")
    if published and owner != (0, 0) and stat.S_IMODE(metadata.st_mode) & 0o200:
        fail(f"{label} remains writable by the acquisition identity")
    if expected_identity is not None and identity(metadata) != expected_identity:
        fail(f"{label} identity changed")
    reject_descendant_mounts(canonical)
    return metadata


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
        fail(f"Pub cache contains a nonportable path: {relative!r}")


def validate_symlink_target(relative: str, target: str) -> None:
    raw = os.fsencode(target)
    if (
        not raw
        or raw.startswith(b"/")
        or b"\\" in raw
        or any(byte < 0x20 or byte > 0x7E for byte in raw)
        or len(raw) > 4096
    ):
        fail(f"Pub cache symlink has an inadmissible target: {relative}")
    parts = relative.split("/")[:-1]
    for component in target.split("/"):
        if component in ("", "."):
            continue
        if component == "..":
            if not parts:
                fail(f"Pub cache symlink escapes the cache root: {relative}")
            parts.pop()
        else:
            parts.append(component)
    if not relative.startswith("git/") or relative.startswith("git/cache/"):
        fail(f"Pub cache symlink exists outside a Git checkout: {relative}")


def update_digest(
    digest: "hashlib._Hash",
    kind: bytes,
    relative: str,
    mode: int,
    payload: bytes,
) -> None:
    digest.update(kind)
    digest.update(b"\0")
    digest.update(os.fsencode(relative))
    digest.update(b"\0")
    digest.update(f"{mode:o}".encode("ascii"))
    digest.update(b"\0")
    digest.update(payload)
    digest.update(b"\0")


def inspect_tree(
    root: Path,
    *,
    owners: set[tuple[int, int]],
    normalize: bool = False,
    published: bool = False,
    expected_identity: tuple[int, int] | None = None,
) -> TreeSummary:
    root_metadata = validate_root(
        root,
        "Pub cache output",
        owners,
        expected_identity,
        published=published,
    )
    root_owner = (root_metadata.st_uid, root_metadata.st_gid)
    root_device = root_metadata.st_dev
    maximum_files, maximum_directories, maximum_bytes, maximum_file, maximum_depth = TREE_LIMITS
    files = 0
    directories = 1
    symlinks = 0
    content_bytes = 0
    final_metadata: list[tuple[Path, tuple[int, ...]]] = []
    hardlinks: dict[tuple[int, int], tuple[int, list[str]]] = {}
    normalized_inodes: set[tuple[int, int]] = set()
    tree_digest = hashlib.sha256()

    def descend(directory: Path, relative: str, depth: int) -> None:
        nonlocal files, directories, symlinks, content_bytes
        if depth > maximum_depth:
            fail("Pub cache exceeds its depth bound")
        before = os.lstat(directory)
        if before.st_dev != root_device:
            fail(f"Pub cache crosses a filesystem: {relative or '.'}")
        if (before.st_uid, before.st_gid) != root_owner:
            fail(f"Pub cache has mixed or foreign ownership: {relative or '.'}")
        reject_extended_metadata(directory, before, f"Pub cache directory {relative or '.'}")
        if normalize:
            os.chmod(directory, 0o700 if not relative else 0o500, follow_symlinks=False)
            before = os.lstat(directory)
        else:
            mode = stat.S_IMODE(before.st_mode)
            if mode & 0o022:
                fail(f"Pub cache directory is group/world writable: {relative or '.'}")
            if published and root_owner != (0, 0) and mode & 0o200:
                fail(f"Pub cache directory remains owner-writable: {relative or '.'}")
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
        for entry in entries:
            child_relative = entry.name if not relative else f"{relative}/{entry.name}"
            validate_name(entry.name, child_relative)
            child = directory / entry.name
            metadata = entry.stat(follow_symlinks=False)
            if metadata.st_dev != root_device:
                fail(f"Pub cache crosses a filesystem: {child_relative}")
            if (metadata.st_uid, metadata.st_gid) != root_owner:
                fail(f"Pub cache has mixed or foreign ownership: {child_relative}")
            reject_extended_metadata(child, metadata, f"Pub cache entry {child_relative}")
            if stat.S_ISDIR(metadata.st_mode):
                directories += 1
                if directories > maximum_directories:
                    fail("Pub cache exceeds its directory bound")
                descend(child, child_relative, depth + 1)
            elif stat.S_ISREG(metadata.st_mode):
                files += 1
                content_bytes += metadata.st_size
                if files > maximum_files:
                    fail("Pub cache exceeds its file-count bound")
                if content_bytes > maximum_bytes:
                    fail("Pub cache exceeds its total-byte bound")
                if metadata.st_size > maximum_file:
                    fail(f"Pub cache file exceeds its byte bound: {child_relative}")
                inode = identity(metadata)
                if inode not in hardlinks:
                    hardlinks[inode] = (metadata.st_nlink, [])
                expected_links, paths = hardlinks[inode]
                if expected_links != metadata.st_nlink:
                    fail(f"Pub cache hardlink count changed: {child_relative}")
                paths.append(child_relative)
                executable = bool(metadata.st_mode & 0o111)
                if normalize and inode not in normalized_inodes:
                    os.chmod(child, 0o500 if executable else 0o400, follow_symlinks=False)
                    normalized_inodes.add(inode)
                    metadata = os.lstat(child)
                elif normalize:
                    metadata = os.lstat(child)
                else:
                    mode = stat.S_IMODE(metadata.st_mode)
                    if mode & 0o022:
                        fail(f"Pub cache file is group/world writable: {child_relative}")
                    if published and root_owner != (0, 0) and mode & 0o200:
                        fail(f"Pub cache file remains owner-writable: {child_relative}")
                descriptor = os.open(
                    child,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                try:
                    before_file = os.fstat(descriptor)
                    if stable_metadata(before_file) != stable_metadata(metadata):
                        fail(f"Pub cache file changed before read: {child_relative}")
                    file_digest = hashlib.sha256()
                    while True:
                        block = os.read(descriptor, BLOCK_SIZE)
                        if not block:
                            break
                        file_digest.update(block)
                    after_file = os.fstat(descriptor)
                    if stable_metadata(before_file) != stable_metadata(after_file):
                        fail(f"Pub cache file changed while read: {child_relative}")
                finally:
                    os.close(descriptor)
                update_digest(
                    tree_digest,
                    b"F",
                    child_relative,
                    stat.S_IMODE(metadata.st_mode),
                    file_digest.digest(),
                )
                final_metadata.append((child, stable_metadata(metadata)))
            elif stat.S_ISLNK(metadata.st_mode):
                symlinks += 1
                if symlinks > 1024:
                    fail("Pub cache exceeds its symlink-count bound")
                target = os.readlink(child)
                validate_symlink_target(child_relative, target)
                after_link = os.lstat(child)
                if stable_metadata(metadata) != stable_metadata(after_link):
                    fail(f"Pub cache symlink changed while read: {child_relative}")
                update_digest(
                    tree_digest,
                    b"L",
                    child_relative,
                    stat.S_IMODE(metadata.st_mode),
                    os.fsencode(target),
                )
                final_metadata.append((child, stable_metadata(after_link)))
            else:
                fail(f"Pub cache contains a special file: {child_relative}")
        after = os.lstat(directory)
        if (
            identity(before) != identity(after)
            or after.st_dev != root_device
            or not stat.S_ISDIR(after.st_mode)
        ):
            fail(f"Pub cache directory changed during traversal: {relative or '.'}")
        update_digest(
            tree_digest,
            b"D",
            relative or ".",
            stat.S_IMODE(after.st_mode) & (~0o200 if not relative else 0o777),
            b"",
        )
        final_metadata.append((directory, stable_metadata(after)))

    descend(root, "", 0)
    for inode, (expected_links, paths) in hardlinks.items():
        if expected_links != len(paths):
            fail(
                "Pub cache has a hardlink outside its closed output tree: "
                f"{paths[0]} ({len(paths)} of {expected_links} links)"
            )
        if expected_links > 1:
            update_digest(
                tree_digest,
                b"H",
                "\0".join(sorted(paths)),
                expected_links,
                b"",
            )
    for path, expected in final_metadata:
        if stable_metadata(os.lstat(path)) != expected:
            fail(f"Pub cache changed after traversal: {path}")
    return TreeSummary(
        files,
        directories,
        symlinks,
        content_bytes,
        tree_digest.hexdigest(),
    )


def read_small_regular(path: Path, maximum: int, label: str) -> bytes:
    metadata = os.lstat(path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > maximum
    ):
        fail(f"{label} is not one bounded single-link regular file")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        data = bytearray()
        while True:
            block = os.read(descriptor, min(BLOCK_SIZE, maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
            if len(data) > maximum:
                fail(f"{label} exceeds its byte bound")
        after = os.fstat(descriptor)
        if stable_metadata(before) != stable_metadata(after):
            fail(f"{label} changed while read")
        return bytes(data)
    finally:
        os.close(descriptor)


def validate_shape(
    root: Path,
    *,
    strict_output: bool,
    expected_git_dependencies: int | None = EXPECTED_GIT_DEPENDENCIES,
) -> None:
    with os.scandir(root) as iterator:
        top = {entry.name: entry for entry in iterator}
    required = {"hosted", "hosted-hashes", "git"}
    if not required.issubset(top):
        fail("Pub cache lacks one or more required top-level trees")
    extras = set(top) - required
    if strict_output and extras:
        fail(f"new Pub cache has unexpected top-level state: {sorted(extras)!r}")
    if not strict_output and not extras.issubset(ALLOWED_LEGACY_TOP_LEVEL):
        fail(f"existing Pub cache has unexpected top-level state: {sorted(extras)!r}")
    for name in required:
        if not top[name].is_dir(follow_symlinks=False):
            fail(f"Pub cache top-level {name!r} is not one real directory")

    hosted = root / "hosted" / "pub.dev"
    hashes = root / "hosted-hashes" / "pub.dev"
    git = root / "git"
    bare = git / "cache"
    for path, label in (
        (hosted, "hosted package root"),
        (hashes, "hosted hash root"),
        (bare, "Git bare-cache root"),
    ):
        metadata = os.lstat(path)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            fail(f"Pub cache {label} is missing or not one real directory")

    metadata_cache = hosted / ".cache"
    if not metadata_cache.is_dir() or metadata_cache.is_symlink():
        fail("Pub cache lacks the pinned-host metadata cache needed by Windows staging")
    for advisory in ("archive-advisories.json", "http-advisories.json"):
        if not (metadata_cache / advisory).is_file() or (metadata_cache / advisory).is_symlink():
            fail(f"Pub cache lacks required advisory metadata: {advisory}")

    package_names = set()
    with os.scandir(hosted) as iterator:
        for entry in iterator:
            if entry.name == ".cache":
                continue
            if not entry.is_dir(follow_symlinks=False):
                fail(f"Pub hosted root contains a non-directory package: {entry.name}")
            package_names.add(entry.name)
    hash_names = set()
    with os.scandir(hashes) as iterator:
        for entry in iterator:
            if not entry.is_file(follow_symlinks=False) or not entry.name.endswith(".sha256"):
                fail(f"Pub hosted-hash root contains an unexpected entry: {entry.name}")
            package_name = entry.name[: -len(".sha256")]
            value = read_small_regular(Path(entry.path), 64, "Pub hosted package hash")
            try:
                decoded = value.decode("ascii")
            except UnicodeDecodeError as error:
                fail(f"Pub hosted package hash is not ASCII: {error}")
            validate_pin(decoded, "Pub hosted package hash", HEX_SHA256_PATTERN)
            hash_names.add(package_name)
    if not package_names or package_names != hash_names:
        fail("Pub hosted package directories and content-hash records are not one exact set")

    with os.scandir(git) as iterator:
        checkout_entries = [
            entry for entry in iterator if entry.name != "cache"
        ]
    with os.scandir(bare) as iterator:
        bare_entries = list(iterator)
    if expected_git_dependencies is None:
        if (
            not checkout_entries
            or len(checkout_entries) != len(bare_entries)
            or len(checkout_entries) > 32
        ):
            fail("displaced Pub cache has an incoherent Git dependency inventory")
    elif (
        len(checkout_entries) != expected_git_dependencies
        or len(bare_entries) != expected_git_dependencies
    ):
        fail("Pub cache does not contain the exact three locked Git dependencies")
    for entry in checkout_entries:
        if (
            not entry.is_dir(follow_symlinks=False)
            or CHECKOUT_PATTERN.fullmatch(entry.name) is None
        ):
            fail(f"Pub cache has a malformed Git checkout: {entry.name}")
        dot_git = Path(entry.path) / ".git"
        packages = dot_git / "pub-packages"
        if not dot_git.is_dir() or dot_git.is_symlink():
            fail(f"Pub Git checkout lacks a real .git directory: {entry.name}")
        if not packages.is_file() or packages.is_symlink():
            fail(f"Pub Git checkout lacks its package-path record: {entry.name}")
    for entry in bare_entries:
        if (
            not entry.is_dir(follow_symlinks=False)
            or BARE_CACHE_PATTERN.fullmatch(entry.name) is None
        ):
            fail(f"Pub cache has a malformed bare Git cache: {entry.name}")


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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
                fail("short write while recording Pub-cache output state")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, state)
    fsync_directory(staging)


def provenance_values(
    source_commit: str,
    source_tree: str,
    source_archive_sha256: str,
    flutter_version: str,
    flutter_archive_sha256: str,
) -> dict[str, str]:
    return {
        "source_commit": validate_pin(source_commit, "source commit", HEX_OBJECT_PATTERN),
        "source_tree": validate_pin(source_tree, "source tree", HEX_OBJECT_PATTERN),
        "source_archive_sha256": validate_pin(
            source_archive_sha256,
            "source archive SHA-256",
            HEX_SHA256_PATTERN,
        ),
        "flutter_version": validate_pin(
            flutter_version,
            "Flutter version",
            VERSION_PATTERN,
        ),
        "flutter_archive_sha256": validate_pin(
            flutter_archive_sha256,
            "Flutter archive SHA-256",
            HEX_SHA256_PATTERN,
        ),
    }


def validate_publication_state(value: dict[str, object]) -> None:
    publication = value.get("publication")
    expected_digest = value.get("expected_digest")
    replaced_identity = value.get("replaced_output_identity")
    replaced_digest = value.get("replaced_output_digest")
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
            fail("unselected Pub-cache publication carries transaction authority")
        return
    if publication == "new":
        if (
            not isinstance(expected_digest, str)
            or HEX_SHA256_PATTERN.fullmatch(expected_digest) is None
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
            fail("new Pub-cache publication state is malformed")
        return
    if publication != "replacement":
        fail("Pub-cache publication state has an unknown disposition")
    if (
        not isinstance(expected_digest, str)
        or HEX_SHA256_PATTERN.fullmatch(expected_digest) is None
        or not isinstance(replaced_digest, str)
        or HEX_SHA256_PATTERN.fullmatch(replaced_digest) is None
        or not isinstance(retired_root, str)
        or not isinstance(archive_name, str)
        or ARCHIVE_PATTERN.fullmatch(archive_name) is None
        or not isinstance(replacement_name, str)
        or REPLACEMENT_PATTERN.fullmatch(replacement_name) is None
    ):
        fail("Pub-cache replacement state is malformed")
    decode_identity(replaced_identity, "replaced Pub-cache output")
    decode_identity(retired_root_identity, "retired Pub-cache root")
    validate_absolute(Path(retired_root), "retired Pub-cache root")


def load_state(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
) -> dict[str, object]:
    online_metadata = validate_root(online, "online root", {(uid, gid)})
    staging_metadata = validate_root(staging, "Pub-cache staging", {(uid, gid)})
    if staging.parent != online or STAGING_PATTERN.fullmatch(staging.name) is None:
        fail("Pub-cache staging is outside its reserved online namespace")
    data = read_small_regular(staging / STATE_NAME, 4096, "Pub-cache output state")
    metadata = os.lstat(staging / STATE_NAME)
    if (
        metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        fail("Pub-cache output state metadata is invalid")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"Pub-cache output state is malformed: {error}")
    required_keys = {
        "version",
        "online",
        "staging",
        "online_identity",
        "staging_identity",
        "output_identity",
        "source_commit",
        "source_tree",
        "source_archive_sha256",
        "flutter_version",
        "flutter_archive_sha256",
        "publication",
        "expected_digest",
        "replaced_output_identity",
        "replaced_output_digest",
        "retired_root",
        "retired_root_identity",
        "archive_name",
        "replacement_name",
    }
    if not isinstance(value, dict) or set(value) != required_keys:
        fail("Pub-cache output state has an unexpected schema")
    if value.get("version") != STATE_VERSION:
        fail("Pub-cache output state has the wrong version")
    if value.get("online") != os.fspath(online) or value.get("staging") != os.fspath(staging):
        fail("Pub-cache output state path binding is invalid")
    if decode_identity(value.get("online_identity"), "online root") != identity(online_metadata):
        fail("online root identity changed")
    if decode_identity(value.get("staging_identity"), "Pub-cache staging") != identity(
        staging_metadata
    ):
        fail("Pub-cache staging identity changed")
    provenance_values(
        str(value.get("source_commit")),
        str(value.get("source_tree")),
        str(value.get("source_archive_sha256")),
        str(value.get("flutter_version")),
        str(value.get("flutter_archive_sha256")),
    )
    validate_publication_state(value)
    return value


def prepare(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    provenance: dict[str, str],
) -> None:
    online_metadata = validate_root(online, "online root", {(uid, gid)})
    staging_metadata = validate_root(staging, "Pub-cache staging", {(uid, gid)})
    if staging.parent != online or STAGING_PATTERN.fullmatch(staging.name) is None:
        fail("Pub-cache staging is outside its reserved online namespace")
    if staging_metadata.st_dev != online_metadata.st_dev:
        fail("Pub-cache staging is not on the online filesystem")
    if any(staging.iterdir()):
        fail("Pub-cache staging is not freshly empty")
    output = staging / "output"
    output.mkdir(mode=0o700)
    state: dict[str, object] = {
        "version": STATE_VERSION,
        "online": os.fspath(online),
        "staging": os.fspath(staging),
        "online_identity": encode_identity(identity(online_metadata)),
        "staging_identity": encode_identity(identity(staging_metadata)),
        "output_identity": encode_identity(identity(os.lstat(output))),
        "publication": "unselected",
        "expected_digest": None,
        "replaced_output_identity": None,
        "replaced_output_digest": None,
        "retired_root": None,
        "retired_root_identity": None,
        "archive_name": None,
        "replacement_name": None,
    }
    state.update(provenance)
    atomic_write_state(staging, state)


def require_matching_provenance(
    state: dict[str, object],
    provenance: dict[str, str],
) -> None:
    for name, expected in provenance.items():
        if state.get(name) != expected:
            fail(f"Pub-cache output state {name} does not match the requested input")


def verify_staged(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    provenance: dict[str, str],
    *,
    normalize: bool,
) -> TreeSummary:
    state = load_state(online, staging, uid, gid)
    require_matching_provenance(state, provenance)
    output = staging / "output"
    summary = inspect_tree(
        output,
        owners={(uid, gid)},
        normalize=normalize,
        published=False,
        expected_identity=decode_identity(state.get("output_identity"), "Pub-cache output"),
    )
    if stat.S_IMODE(os.lstat(output).st_mode) != 0o700:
        fail("staged Pub-cache candidate root is not mode 0700")
    validate_shape(output, strict_output=True)
    return summary


def check_complete(online: Path, uid: int, gid: int) -> TreeSummary:
    validate_root(online, "online root", {(uid, gid)})
    output = online / "pub-cache"
    summary = inspect_tree(
        output,
        owners={(uid, gid), (0, 0)},
        published=True,
    )
    validate_shape(output, strict_output=False)
    return summary


def sync_tree(root: Path) -> None:
    directories = []
    for current, names, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories.append(current_path)
        names.sort()
        files.sort()
        for name in files:
            path = current_path / name
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode):
                continue
            if not stat.S_ISREG(metadata.st_mode):
                fail(f"cannot synchronize special Pub-cache entry: {path}")
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
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
        "retired Pub-cache root",
        {(uid, gid)},
        expected_identity,
    )
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        fail("retired Pub-cache root is not mode 0700")
    if metadata.st_dev != os.lstat(online).st_dev:
        fail("retired Pub-cache root is not on the online filesystem")
    online_text = os.fspath(online).rstrip("/") + "/"
    retired_text = os.fspath(retired_root).rstrip("/") + "/"
    if online_text.startswith(retired_text) or retired_text.startswith(online_text):
        fail("retired Pub-cache root and online root are not disjoint")
    return metadata


def replacement_archive_name(
    staging_identity: tuple[int, int],
    replaced_identity: tuple[int, int],
) -> str:
    name = "pub-cache-{:x}-{:x}-{:x}-{:x}".format(
        staging_identity[0],
        staging_identity[1],
        replaced_identity[0],
        replaced_identity[1],
    )
    if ARCHIVE_PATTERN.fullmatch(name) is None:
        fail("generated retired Pub-cache archive name is malformed")
    return name


def replacement_output_name(
    staging_identity: tuple[int, int],
    replaced_identity: tuple[int, int],
) -> str:
    name = ".rustdesk-retired-pub-cache-{:x}-{:x}-{:x}-{:x}".format(
        staging_identity[0],
        staging_identity[1],
        replaced_identity[0],
        replaced_identity[1],
    )
    if REPLACEMENT_PATTERN.fullmatch(name) is None:
        fail("generated replacement Pub-cache name is malformed")
    return name


def record_new_publication(
    staging: Path,
    state: dict[str, object],
    expected_digest: str,
) -> dict[str, object]:
    if state.get("publication") == "new":
        if state.get("expected_digest") != expected_digest:
            fail("new Pub-cache publication digest changed across retry")
        return state
    if state.get("publication") != "unselected":
        fail("Pub-cache output is already bound to a different publication")
    updated = dict(state)
    updated["publication"] = "new"
    updated["expected_digest"] = expected_digest
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
        decode_identity(state.get("staging_identity"), "Pub-cache staging"),
        replaced_identity,
    )
    replacement_name = replacement_output_name(
        decode_identity(state.get("staging_identity"), "Pub-cache staging"),
        replaced_identity,
    )
    expected = {
        "publication": "replacement",
        "expected_digest": expected_digest,
        "replaced_output_identity": encode_identity(replaced_identity),
        "replaced_output_digest": replaced.digest,
        "retired_root": os.fspath(retired_root),
        "retired_root_identity": encode_identity(retired_root_identity),
        "archive_name": archive_name,
        "replacement_name": replacement_name,
    }
    if state.get("publication") == "replacement":
        if any(state.get(name) != value for name, value in expected.items()):
            fail("Pub-cache replacement authority changed across retry")
        return state
    if state.get("publication") != "unselected":
        fail("Pub-cache output is already bound to a different publication")
    updated = dict(state)
    updated.update(expected)
    atomic_write_state(staging, updated)
    return updated


def validate_candidate_output(
    output: Path,
    uid: int,
    gid: int,
    expected_identity: tuple[int, int],
    expected_digest: str,
    *,
    published: bool,
) -> None:
    expected_mode = 0o500 if published else 0o700
    if stat.S_IMODE(os.lstat(output).st_mode) != expected_mode:
        fail(f"Pub-cache candidate root is not mode {expected_mode:04o}")
    summary = inspect_tree(
        output,
        owners={(uid, gid)},
        published=published,
        expected_identity=expected_identity,
    )
    validate_shape(output, strict_output=True)
    if summary.digest != expected_digest:
        fail("Pub-cache candidate digest postcondition failed")


def validate_published_candidate(
    destination: Path,
    uid: int,
    gid: int,
    expected_identity: tuple[int, int],
    expected_digest: str,
) -> None:
    validate_candidate_output(
        destination,
        uid,
        gid,
        expected_identity,
        expected_digest,
        published=True,
    )


def validate_displaced_output(
    output: Path,
    uid: int,
    gid: int,
    expected_identity: tuple[int, int] | None = None,
    expected_digest: str | None = None,
) -> TreeSummary:
    summary = inspect_tree(
        output,
        owners={(uid, gid), (0, 0)},
        published=True,
        expected_identity=expected_identity,
    )
    validate_shape(
        output,
        strict_output=False,
        expected_git_dependencies=None,
    )
    if expected_digest is not None and summary.digest != expected_digest:
        fail("displaced Pub-cache digest changed")
    return summary


def publish(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    provenance: dict[str, str],
    expected_digest: str,
) -> None:
    validate_pin(expected_digest, "verified Pub-cache digest", HEX_SHA256_PATTERN)
    summary = verify_staged(
        online,
        staging,
        uid,
        gid,
        provenance,
        normalize=False,
    )
    if summary.digest != expected_digest:
        fail("Pub cache changed after networkless semantic verification")
    state = load_state(online, staging, uid, gid)
    state = record_new_publication(staging, state, expected_digest)
    destination = online / "pub-cache"
    if destination.exists() or destination.is_symlink():
        fail("Pub-cache destination appeared before no-clobber publication")
    output = staging / "output"
    sync_tree(output)
    fsync_directory(staging)
    online_fd = open_directory(online)
    staging_fd = open_directory(staging)
    moved = False
    try:
        renameat2(staging_fd, "output", online_fd, "pub-cache", RENAME_NOREPLACE)
        moved = True
        transition_root_mode(
            online_fd,
            "pub-cache",
            decode_identity(state.get("output_identity"), "Pub-cache output"),
            uid,
            gid,
            {0o700},
            0o500,
            "published Pub-cache",
        )
        fsync_directory(destination)
        os.fsync(staging_fd)
        os.fsync(online_fd)
        expected_identity = decode_identity(state.get("output_identity"), "Pub-cache output")
        if identity(os.lstat(destination)) != expected_identity:
            fail("published Pub-cache identity postcondition failed")
        validate_published_candidate(
            destination,
            uid,
            gid,
            expected_identity,
            expected_digest,
        )
    except BaseException as primary:
        if moved:
            try:
                transition_root_mode(
                    online_fd,
                    "pub-cache",
                    decode_identity(state.get("output_identity"), "Pub-cache output"),
                    uid,
                    gid,
                    {0o500, 0o700},
                    0o700,
                    "Pub-cache rollback",
                )
                renameat2(
                    online_fd,
                    "pub-cache",
                    staging_fd,
                    "output",
                    RENAME_NOREPLACE,
                )
                os.fsync(staging_fd)
                os.fsync(online_fd)
            except BaseException as rollback:
                primary.add_note(f"Pub-cache publication rollback also failed: {rollback}")
        raise
    finally:
        os.close(staging_fd)
        os.close(online_fd)


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
            if optional_relative_identity(online_fd, "pub-cache") != candidate_identity:
                fail("live Pub-cache identity changed before replacement rollback")
            if optional_relative_identity(online_fd, replacement_name) != replaced_identity:
                fail("displaced Pub-cache identity changed before replacement rollback")
            renameat2(
                online_fd,
                "pub-cache",
                online_fd,
                replacement_name,
                RENAME_EXCHANGE,
            )
            os.fsync(online_fd)
            if optional_relative_identity(online_fd, "pub-cache") != replaced_identity:
                fail("replacement rollback did not restore the displaced Pub-cache")
            if optional_relative_identity(online_fd, replacement_name) != candidate_identity:
                fail("replacement rollback lost the candidate Pub-cache")
        except (OSError, PubCacheError) as error:
            failures.append(f"Pub-cache same-parent replacement rollback failed: {error}")
    if promoted and not failures:
        try:
            if optional_relative_identity(staging_fd, "output") is not None:
                fail("Pub-cache staging output reappeared before replacement rollback")
            transition_root_mode(
                online_fd,
                replacement_name,
                candidate_identity,
                uid,
                gid,
                {0o500, 0o700},
                0o700,
                "Pub-cache replacement rollback",
            )
            renameat2(
                online_fd,
                replacement_name,
                staging_fd,
                "output",
                RENAME_NOREPLACE,
            )
            os.fsync(staging_fd)
            os.fsync(online_fd)
            if optional_relative_identity(staging_fd, "output") != candidate_identity:
                fail("replacement rollback did not restore the staged candidate")
            if optional_relative_identity(online_fd, replacement_name) is not None:
                fail("replacement rollback left the promoted candidate name occupied")
        except (OSError, PubCacheError) as error:
            failures.append(f"Pub-cache candidate demotion failed: {error}")
    try:
        os.fsync(staging_fd)
        os.fsync(online_fd)
    except OSError as error:
        failures.append(f"Pub-cache rollback directory synchronization failed: {error}")
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
    destination = online / "pub-cache"
    replacement_name = str(state.get("replacement_name"))
    if REPLACEMENT_PATTERN.fullmatch(replacement_name) is None:
        fail("replacement Pub-cache name is malformed")
    replacement = online / replacement_name
    candidate_identity = decode_identity(state.get("output_identity"), "Pub-cache output")
    replaced_identity = decode_identity(
        state.get("replaced_output_identity"), "replaced Pub-cache output"
    )
    expected_digest = str(state.get("expected_digest"))
    replaced_digest = str(state.get("replaced_output_digest"))
    online_fd = open_directory(online)
    staging_fd = open_directory(staging)
    exchanged = already_exchanged
    try:
        if not exchanged:
            validate_candidate_output(
                replacement,
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
                fail("promoted Pub-cache candidate identity changed before exchange")
            if optional_relative_identity(online_fd, "pub-cache") != replaced_identity:
                fail("existing Pub-cache identity changed before exchange")
            renameat2(
                online_fd,
                replacement_name,
                online_fd,
                "pub-cache",
                RENAME_EXCHANGE,
            )
            exchanged = True
            os.fsync(online_fd)
        if optional_relative_identity(online_fd, "pub-cache") != candidate_identity:
            fail("replacement Pub-cache identity postcondition failed")
        if optional_relative_identity(online_fd, replacement_name) != replaced_identity:
            fail("displaced Pub-cache identity postcondition failed")
        live_mode = stat.S_IMODE(os.lstat(destination).st_mode)
        if live_mode == 0o700:
            transition_root_mode(
                online_fd,
                "pub-cache",
                candidate_identity,
                uid,
                gid,
                {0o700},
                0o500,
                "replacement Pub-cache",
            )
        elif live_mode != 0o500:
            fail("replacement Pub-cache root has an unrecoverable mode")
        fsync_directory(destination)
        os.fsync(online_fd)
        validate_published_candidate(
            destination,
            uid,
            gid,
            candidate_identity,
            expected_digest,
        )
        validate_displaced_output(
            replacement,
            uid,
            gid,
            replaced_identity,
            replaced_digest,
        )
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
            primary.add_note(f"Pub-cache replacement rollback also failed: {rollback}")
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
    provenance: dict[str, str],
    expected_digest: str,
) -> None:
    validate_pin(expected_digest, "verified Pub-cache digest", HEX_SHA256_PATTERN)
    candidate = verify_staged(
        online,
        staging,
        uid,
        gid,
        provenance,
        normalize=False,
    )
    if candidate.digest != expected_digest:
        fail("Pub cache changed after networkless semantic verification")
    state = load_state(online, staging, uid, gid)
    destination = online / "pub-cache"
    replaced_metadata = os.lstat(destination)
    replaced = validate_displaced_output(destination, uid, gid)
    retired_metadata = validate_retired_root(online, retired_root, uid, gid)
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
        state.get("replaced_output_identity"), "replaced Pub-cache output"
    )
    replaced_digest = str(state.get("replaced_output_digest"))
    validate_displaced_output(
        destination,
        uid,
        gid,
        replaced_identity,
        replaced_digest,
    )
    output = staging / "output"
    replacement_name = str(state.get("replacement_name"))
    if REPLACEMENT_PATTERN.fullmatch(replacement_name) is None:
        fail("replacement Pub-cache name is malformed")
    replacement = online / replacement_name
    if replacement.exists() or replacement.is_symlink():
        fail("reserved replacement Pub-cache name is already occupied")
    sync_tree(output)
    fsync_directory(staging)
    online_fd = open_directory(online)
    staging_fd = open_directory(staging)
    promoted = False
    candidate_identity = decode_identity(state.get("output_identity"), "Pub-cache output")
    try:
        if identity(os.lstat(output)) != candidate_identity:
            fail("Pub-cache candidate identity changed before replacement")
        if identity(os.lstat(destination)) != replaced_identity:
            fail("existing Pub-cache identity changed before replacement")
        renameat2(
            staging_fd,
            "output",
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
                primary.add_note(f"Pub-cache replacement rollback also failed: {rollback}")
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


def optional_identity(path: Path) -> tuple[int, int] | None:
    try:
        return identity(os.lstat(path))
    except FileNotFoundError:
        return None


def recover(online: Path, staging: Path, uid: int, gid: int) -> str:
    state = load_state(online, staging, uid, gid)
    output = decode_identity(state.get("output_identity"), "Pub-cache output")
    private_output = optional_identity(staging / "output")
    live_output = optional_identity(online / "pub-cache")
    publication = state.get("publication")
    if publication == "replacement":
        replaced_output = decode_identity(
            state.get("replaced_output_identity"), "replaced Pub-cache output"
        )
        expected_digest = str(state.get("expected_digest"))
        replaced_digest = str(state.get("replaced_output_digest"))
        replacement_name = str(state.get("replacement_name"))
        if REPLACEMENT_PATTERN.fullmatch(replacement_name) is None:
            fail("replacement Pub-cache name is malformed")
        replacement = online / replacement_name
        replacement_output = optional_identity(replacement)
        retired_root = Path(str(state.get("retired_root")))
        retired_identity = decode_identity(
            state.get("retired_root_identity"), "retired Pub-cache root"
        )
        validate_retired_root(online, retired_root, uid, gid, retired_identity)
        if (
            private_output == output
            and live_output == replaced_output
            and replacement_output is None
        ):
            validate_candidate_output(
                staging / "output",
                uid,
                gid,
                output,
                expected_digest,
                published=False,
            )
            validate_displaced_output(
                online / "pub-cache",
                uid,
                gid,
                replaced_output,
                replaced_digest,
            )
            return "replacement-prepared"
        if (
            private_output is None
            and live_output == replaced_output
            and replacement_output == output
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
            private_output is None
            and live_output == output
            and replacement_output == replaced_output
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
        fail("Pub-cache replacement transaction state is incoherent and was preserved")
    if (
        publication == "unselected"
        and private_output == output
        and live_output is not None
    ):
        return "unselected-while-occupied"
    if private_output == output and live_output is None:
        return "unpublished"
    if private_output is None and live_output == output:
        return "published"
    fail("Pub-cache output transaction state is incoherent and was preserved")


def archive_replaced(online: Path, staging: Path, uid: int, gid: int) -> Path:
    if recover(online, staging, uid, gid) != "replaced":
        fail("Pub-cache output is not a completed replacement")
    state = load_state(online, staging, uid, gid)
    retired_root = Path(str(state.get("retired_root")))
    retired_identity = decode_identity(
        state.get("retired_root_identity"), "retired Pub-cache root"
    )
    validate_retired_root(
        online,
        retired_root,
        uid,
        gid,
        retired_identity,
    )
    archive_name = str(state.get("archive_name"))
    if ARCHIVE_PATTERN.fullmatch(archive_name) is None:
        fail("retired Pub-cache archive name is malformed")
    destination = retired_root / archive_name
    if destination.exists() or destination.is_symlink():
        fail("retired Pub-cache archive destination is already occupied")
    staging_identity = decode_identity(state.get("staging_identity"), "Pub-cache staging")
    replacement_name = str(state.get("replacement_name"))
    if REPLACEMENT_PATTERN.fullmatch(replacement_name) is None:
        fail("replacement Pub-cache name is malformed")
    replaced_identity = decode_identity(
        state.get("replaced_output_identity"), "replaced Pub-cache output"
    )
    replaced_digest = str(state.get("replaced_output_digest"))
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
            fail("Pub-cache staging identity changed before archival")
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
            fail("Pub-cache staging name survived archival")
        if identity(os.lstat(destination)) != staging_identity:
            fail("retired Pub-cache archive identity postcondition failed")
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


def make_stage(online: Path) -> Path:
    return Path(tempfile.mkdtemp(prefix=".rustdesk-pub-cache.", dir=online))


def make_fake_cache(
    root: Path,
    git_dependencies: int = EXPECTED_GIT_DEPENDENCIES,
) -> None:
    hosted = root / "hosted" / "pub.dev"
    hashes = root / "hosted-hashes" / "pub.dev"
    git = root / "git"
    cache = git / "cache"
    (hosted / ".cache").mkdir(parents=True)
    hashes.mkdir(parents=True)
    cache.mkdir(parents=True)
    (hosted / ".cache" / "archive-advisories.json").write_text("{}\n", encoding="ascii")
    (hosted / ".cache" / "http-advisories.json").write_text("{}\n", encoding="ascii")
    package = hosted / "example-1.0.0"
    package.mkdir()
    (package / "pubspec.yaml").write_text(
        'name: example\nversion: "1.0.0"\n',
        encoding="ascii",
    )
    (hashes / "example-1.0.0.sha256").write_text("a" * 64, encoding="ascii")
    for index in range(git_dependencies):
        resolved = f"{index + 1:040x}"
        bare = cache / f"repo{index}-{index + 17:040x}"
        checkout = git / f"repo{index}-{resolved}"
        pack_dir = bare / "objects" / "pack"
        checkout_objects = checkout / ".git" / "objects" / "pack"
        pack_dir.mkdir(parents=True)
        checkout_objects.mkdir(parents=True)
        pack = pack_dir / f"pack-{index:040x}.pack"
        pack.write_bytes(f"pack-{index}".encode("ascii"))
        os.link(pack, checkout_objects / pack.name)
        (checkout / ".git" / "pub-packages").write_text(".\n", encoding="ascii")
        (checkout / "pubspec.yaml").write_text(
            f'name: repo{index}\nversion: "1.0.{index}"\n',
            encoding="ascii",
        )
    os.symlink("../pubspec.yaml", git / f"repo0-{1:040x}" / "lib-link")


def remove_stage(staging: Path) -> None:
    for current, directories, files in os.walk(staging, topdown=True, followlinks=False):
        os.chmod(current, 0o700)
        for name in directories:
            path = Path(current) / name
            if not path.is_symlink():
                os.chmod(path, 0o700)
    shutil.rmtree(staging)


def test_provenance() -> dict[str, str]:
    return provenance_values(
        "1" * 40,
        "2" * 40,
        "3" * 64,
        "3.24.5",
        "4" * 64,
    )


def self_test() -> None:
    uid = os.getuid()
    gid = os.getgid()
    provenance = test_provenance()
    with tempfile.TemporaryDirectory(prefix="pub-cache-output-selftest.") as temporary:
        online = Path(temporary) / "online"
        online.mkdir(mode=0o700)

        def prepare_replacement_case(label: str):
            case_online = Path(temporary) / f"{label}-online"
            case_online.mkdir(mode=0o700)
            case_retired = Path(temporary) / f"{label}-records"
            case_retired.mkdir(mode=0o700)
            old = case_online / "pub-cache"
            old.mkdir(mode=0o700)
            make_fake_cache(old, EXPECTED_GIT_DEPENDENCIES + 1)
            inspect_tree(old, owners={(uid, gid)}, normalize=True)
            old.chmod(0o500)
            old_summary = validate_displaced_output(old, uid, gid)
            old_identity = identity(os.lstat(old))
            case_staging = make_stage(case_online)
            prepare(case_online, case_staging, uid, gid, provenance)
            make_fake_cache(case_staging / "output")
            candidate = verify_staged(
                case_online,
                case_staging,
                uid,
                gid,
                provenance,
                normalize=True,
            )
            return (
                case_online,
                case_retired,
                case_staging,
                candidate,
                old_summary,
                old_identity,
            )

        def bind_replacement_case(
            case_online: Path,
            case_retired: Path,
            case_staging: Path,
            candidate: TreeSummary,
        ) -> dict[str, object]:
            state = load_state(case_online, case_staging, uid, gid)
            old_metadata = os.lstat(case_online / "pub-cache")
            old_summary = validate_displaced_output(
                case_online / "pub-cache",
                uid,
                gid,
            )
            retired_metadata = validate_retired_root(
                case_online,
                case_retired,
                uid,
                gid,
            )
            return record_replacement_publication(
                case_staging,
                state,
                candidate.digest,
                old_summary,
                identity(old_metadata),
                case_retired,
                identity(retired_metadata),
            )

        def promote_replacement_case(
            case_online: Path,
            case_staging: Path,
            state: dict[str, object],
            *,
            exchange: bool,
        ) -> None:
            replacement_name = str(state.get("replacement_name"))
            online_fd = open_directory(case_online)
            staging_fd = open_directory(case_staging)
            try:
                renameat2(
                    staging_fd,
                    "output",
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
                        "pub-cache",
                        RENAME_EXCHANGE,
                    )
                    os.fsync(online_fd)
            finally:
                os.close(staging_fd)
                os.close(online_fd)

        def cleanup_completed_replacement(
            case_online: Path,
            case_retired: Path,
            case_staging: Path,
        ) -> None:
            state = load_state(case_online, case_staging, uid, gid)
            displaced_path = case_online / str(state.get("replacement_name"))
            archived = archive_replaced(case_online, case_staging, uid, gid)
            remove_stage(archived)
            remove_stage(displaced_path)
            remove_stage(case_online / "pub-cache")
            case_retired.rmdir()
            case_online.rmdir()

        staging = make_stage(online)
        prepare(online, staging, uid, gid, provenance)
        make_fake_cache(staging / "output")
        summary = verify_staged(
            online,
            staging,
            uid,
            gid,
            provenance,
            normalize=True,
        )
        publish(online, staging, uid, gid, provenance, summary.digest)
        if recover(online, staging, uid, gid) != "published":
            fail("self-test did not classify a published Pub-cache transaction")
        complete = check_complete(online, uid, gid)
        if complete.digest != summary.digest:
            fail("self-test complete Pub cache changed its verified digest")
        remove_stage(staging)

        published = online / "pub-cache"
        os.rename(published, online / "saved")
        staging = make_stage(online)
        prepare(online, staging, uid, gid, provenance)
        make_fake_cache(staging / "output")
        summary = verify_staged(
            online,
            staging,
            uid,
            gid,
            provenance,
            normalize=True,
        )
        (online / "pub-cache").mkdir()
        try:
            publish(online, staging, uid, gid, provenance, summary.digest)
        except PubCacheError:
            pass
        else:
            fail("self-test accepted an occupied Pub-cache destination")
        os.rmdir(online / "pub-cache")
        remove_stage(staging)

        staging = make_stage(online)
        prepare(online, staging, uid, gid, provenance)
        make_fake_cache(staging / "output")
        os.symlink("../../../../outside", staging / "output" / "git" / f"repo1-{2:040x}" / "escape")
        try:
            verify_staged(online, staging, uid, gid, provenance, normalize=True)
        except PubCacheError:
            pass
        else:
            fail("self-test accepted an escaping Pub-cache symlink")
        remove_stage(staging)

        staging = make_stage(online)
        prepare(online, staging, uid, gid, provenance)
        make_fake_cache(staging / "output")
        outside = Path(temporary) / "outside-link"
        target = staging / "output" / "hosted" / "pub.dev" / "example-1.0.0" / "pubspec.yaml"
        os.link(target, outside)
        try:
            verify_staged(online, staging, uid, gid, provenance, normalize=True)
        except PubCacheError:
            pass
        else:
            fail("self-test accepted a Pub-cache hardlink outside the output")
        outside.unlink()
        remove_stage(staging)

        staging = make_stage(online)
        prepare(online, staging, uid, gid, provenance)
        make_fake_cache(staging / "output")
        os.mkfifo(staging / "output" / "fifo")
        try:
            verify_staged(online, staging, uid, gid, provenance, normalize=True)
        except PubCacheError:
            pass
        else:
            fail("self-test accepted a special file in Pub-cache output")
        remove_stage(staging)

        if hasattr(os, "setxattr"):
            staging = make_stage(online)
            prepare(online, staging, uid, gid, provenance)
            make_fake_cache(staging / "output")
            extended = staging / "output" / "hosted" / "pub.dev" / "example-1.0.0" / "pubspec.yaml"
            try:
                os.setxattr(extended, "user.rustdesk-test", b"x")
            except OSError as error:
                if error.errno not in (errno.ENOTSUP, errno.EOPNOTSUPP, errno.EPERM):
                    raise
            else:
                try:
                    verify_staged(online, staging, uid, gid, provenance, normalize=True)
                except PubCacheError:
                    pass
                else:
                    fail("self-test accepted extended attributes in Pub-cache output")
            remove_stage(staging)

        replacement_online = Path(temporary) / "replacement-online"
        replacement_online.mkdir(mode=0o700)
        retired_root = Path(temporary) / "retired"
        retired_root.mkdir(mode=0o700)
        displaced = replacement_online / "pub-cache"
        displaced.mkdir(mode=0o700)
        make_fake_cache(displaced, EXPECTED_GIT_DEPENDENCIES + 1)
        inspect_tree(
            displaced,
            owners={(uid, gid)},
            normalize=True,
        )
        displaced.chmod(0o500)
        displaced_summary = validate_displaced_output(displaced, uid, gid)
        displaced_identity = identity(os.lstat(displaced))
        staging = make_stage(replacement_online)
        prepare(replacement_online, staging, uid, gid, provenance)
        make_fake_cache(staging / "output")
        candidate = verify_staged(
            replacement_online,
            staging,
            uid,
            gid,
            provenance,
            normalize=True,
        )
        replace(
            replacement_online,
            staging,
            retired_root,
            uid,
            gid,
            provenance,
            candidate.digest,
        )
        if recover(replacement_online, staging, uid, gid) != "replaced":
            fail("self-test did not classify a completed Pub-cache replacement")
        replacement_state = load_state(replacement_online, staging, uid, gid)
        replacement_name = str(replacement_state.get("replacement_name"))
        retired_output = replacement_online / replacement_name
        if identity(os.lstat(retired_output)) != displaced_identity:
            fail("self-test replacement did not preserve the displaced Pub-cache identity")
        if (
            validate_displaced_output(retired_output, uid, gid).digest
            != displaced_summary.digest
        ):
            fail("self-test replacement changed the displaced Pub-cache")
        archived = archive_replaced(replacement_online, staging, uid, gid)
        if staging.exists() or staging.is_symlink():
            fail("self-test replacement archival left the online staging name present")
        if identity(os.lstat(retired_output)) != displaced_identity:
            fail("self-test record archival changed the displaced Pub-cache identity")
        if not (archived / STATE_NAME).is_file():
            fail("self-test replacement archival lost its transaction state")
        complete = check_complete(replacement_online, uid, gid)
        if complete.digest != candidate.digest:
            fail("self-test replacement changed the current Pub-cache candidate")
        remove_stage(archived)
        retired_root.rmdir()
        remove_stage(retired_output)
        remove_stage(replacement_online / "pub-cache")
        replacement_online.rmdir()

        (
            promoted_online,
            promoted_records,
            promoted_staging,
            promoted_candidate,
            promoted_old,
            promoted_old_identity,
        ) = prepare_replacement_case("promoted-crash")
        promoted_state = bind_replacement_case(
            promoted_online,
            promoted_records,
            promoted_staging,
            promoted_candidate,
        )
        promote_replacement_case(
            promoted_online,
            promoted_staging,
            promoted_state,
            exchange=False,
        )
        if recover(promoted_online, promoted_staging, uid, gid) != "replaced":
            fail("self-test did not recover a promoted replacement candidate")
        promoted_displaced = promoted_online / str(promoted_state.get("replacement_name"))
        if identity(os.lstat(promoted_displaced)) != promoted_old_identity:
            fail("promoted-candidate recovery lost the displaced Pub-cache identity")
        if (
            validate_displaced_output(promoted_displaced, uid, gid).digest
            != promoted_old.digest
        ):
            fail("promoted-candidate recovery changed the displaced Pub-cache")
        cleanup_completed_replacement(
            promoted_online,
            promoted_records,
            promoted_staging,
        )

        (
            exchanged_online,
            exchanged_records,
            exchanged_staging,
            exchanged_candidate,
            exchanged_old,
            exchanged_old_identity,
        ) = prepare_replacement_case("exchanged-crash")
        exchanged_state = bind_replacement_case(
            exchanged_online,
            exchanged_records,
            exchanged_staging,
            exchanged_candidate,
        )
        promote_replacement_case(
            exchanged_online,
            exchanged_staging,
            exchanged_state,
            exchange=True,
        )
        if stat.S_IMODE(os.lstat(exchanged_online / "pub-cache").st_mode) != 0o700:
            fail("self-test exchanged candidate was unexpectedly sealed before recovery")
        if recover(exchanged_online, exchanged_staging, uid, gid) != "replaced":
            fail("self-test did not recover an exchanged unsealed candidate")
        if stat.S_IMODE(os.lstat(exchanged_online / "pub-cache").st_mode) != 0o500:
            fail("self-test recovery did not seal the exchanged candidate root")
        exchanged_displaced = exchanged_online / str(exchanged_state.get("replacement_name"))
        if identity(os.lstat(exchanged_displaced)) != exchanged_old_identity:
            fail("exchanged-candidate recovery lost the displaced Pub-cache identity")
        if (
            validate_displaced_output(exchanged_displaced, uid, gid).digest
            != exchanged_old.digest
        ):
            fail("exchanged-candidate recovery changed the displaced Pub-cache")
        cleanup_completed_replacement(
            exchanged_online,
            exchanged_records,
            exchanged_staging,
        )

        (
            rollback_online,
            rollback_records,
            rollback_staging,
            rollback_candidate,
            rollback_old,
            rollback_old_identity,
        ) = prepare_replacement_case("rollback")
        rollback_state = bind_replacement_case(
            rollback_online,
            rollback_records,
            rollback_staging,
            rollback_candidate,
        )
        promote_replacement_case(
            rollback_online,
            rollback_staging,
            rollback_state,
            exchange=True,
        )
        rollback_online_fd = open_directory(rollback_online)
        rollback_staging_fd = open_directory(rollback_staging)
        try:
            candidate_identity = decode_identity(
                rollback_state.get("output_identity"),
                "rollback candidate",
            )
            transition_root_mode(
                rollback_online_fd,
                "pub-cache",
                candidate_identity,
                uid,
                gid,
                {0o700},
                0o500,
                "self-test rollback candidate",
            )
            rollback_replacement(
                rollback_online_fd,
                rollback_staging_fd,
                str(rollback_state.get("replacement_name")),
                candidate_identity,
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
            fail("self-test replacement rollback did not restore prepared state")
        if identity(os.lstat(rollback_online / "pub-cache")) != rollback_old_identity:
            fail("self-test replacement rollback lost the old live Pub-cache")
        if (
            validate_displaced_output(rollback_online / "pub-cache", uid, gid).digest
            != rollback_old.digest
        ):
            fail("self-test replacement rollback changed the old live Pub-cache")
        if identity(os.lstat(rollback_staging / "output")) != candidate_identity:
            fail("self-test replacement rollback lost the candidate Pub-cache")
        if stat.S_IMODE(os.lstat(rollback_staging / "output").st_mode) != 0o700:
            fail("self-test replacement rollback did not restore candidate traversal")
        replacement_residue = rollback_online / str(rollback_state.get("replacement_name"))
        if replacement_residue.exists() or replacement_residue.is_symlink():
            fail("self-test replacement rollback left a reserved sibling occupied")
        remove_stage(rollback_staging)
        remove_stage(rollback_online / "pub-cache")
        rollback_records.rmdir()
        rollback_online.rmdir()

    print("ONLINE PUB CACHE OUTPUT SELF-TEST: PASS")


def common_arguments(parser: argparse.ArgumentParser, *, staging: bool = True) -> None:
    parser.add_argument("--online", type=Path, required=True)
    if staging:
        parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)


def provenance_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--source-archive-sha256", required=True)
    parser.add_argument("--flutter-version", required=True)
    parser.add_argument("--flutter-archive-sha256", required=True)


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare")
    common_arguments(prepare_parser)
    provenance_arguments(prepare_parser)
    verify_parser = commands.add_parser("verify")
    common_arguments(verify_parser)
    provenance_arguments(verify_parser)
    publish_parser = commands.add_parser("publish")
    common_arguments(publish_parser)
    provenance_arguments(publish_parser)
    publish_parser.add_argument("--expected-digest", required=True)
    replace_parser = commands.add_parser("replace")
    common_arguments(replace_parser)
    provenance_arguments(replace_parser)
    replace_parser.add_argument("--retired-root", type=Path, required=True)
    replace_parser.add_argument("--expected-digest", required=True)
    recover_parser = commands.add_parser("recover")
    common_arguments(recover_parser)
    archive_parser = commands.add_parser("archive-replaced")
    common_arguments(archive_parser)
    complete_parser = commands.add_parser("check-complete")
    common_arguments(complete_parser, staging=False)
    commands.add_parser("self-test")
    return parser


def command_provenance(arguments: argparse.Namespace) -> dict[str, str]:
    return provenance_values(
        arguments.source_commit,
        arguments.source_tree,
        arguments.source_archive_sha256,
        arguments.flutter_version,
        arguments.flutter_archive_sha256,
    )


def main() -> int:
    arguments = argument_parser().parse_args()
    try:
        if arguments.command == "self-test":
            self_test()
        elif arguments.command == "prepare":
            prepare(
                arguments.online,
                arguments.staging,
                arguments.uid,
                arguments.gid,
                command_provenance(arguments),
            )
        elif arguments.command == "verify":
            summary = verify_staged(
                arguments.online,
                arguments.staging,
                arguments.uid,
                arguments.gid,
                command_provenance(arguments),
                normalize=True,
            )
            print(f"sha256={summary.digest}")
        elif arguments.command == "publish":
            publish(
                arguments.online,
                arguments.staging,
                arguments.uid,
                arguments.gid,
                command_provenance(arguments),
                arguments.expected_digest,
            )
        elif arguments.command == "replace":
            replace(
                arguments.online,
                arguments.staging,
                arguments.retired_root,
                arguments.uid,
                arguments.gid,
                command_provenance(arguments),
                arguments.expected_digest,
            )
        elif arguments.command == "recover":
            print(
                recover(
                    arguments.online,
                    arguments.staging,
                    arguments.uid,
                    arguments.gid,
                )
            )
        elif arguments.command == "archive-replaced":
            print(
                archive_replaced(
                    arguments.online,
                    arguments.staging,
                    arguments.uid,
                    arguments.gid,
                )
            )
        elif arguments.command == "check-complete":
            summary = check_complete(arguments.online, arguments.uid, arguments.gid)
            print(f"sha256={summary.digest}")
        else:
            fail("unknown command")
    except (OSError, PubCacheError) as error:
        print(f"ONLINE PUB CACHE OUTPUT: FAILED — {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
