#!/usr/bin/env python3
"""Extract, validate, recover, and publish the pinned Android NDK tree."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import hashlib
import json
import os
import re
import stat
import tempfile
import warnings
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


STATE_NAME = ".rustdesk-android-ndk-output-state-v1"
STATE_VERSION = 1
STAGING_PATTERN = re.compile(
    r"\.rustdesk-android-ndk\.[A-Za-z0-9_]{8,}\Z"
)
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
TREE_DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
BLOCK_SIZE = 1024 * 1024
MOUNTINFO_LIMIT = 8 * 1024 * 1024
MAX_STATE_BYTES = 8192
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_ENTRIES = 10000
MAX_DIRECTORIES = 1000
MAX_FILES = 9000
MAX_SYMLINKS = 128
MAX_DEPTH = 20
MAX_TOTAL_BYTES = 3 * 1024 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_NAME_BYTES = 4096
MAX_COMPONENT_BYTES = 255
MAX_SYMLINK_BYTES = 4096
RENAME_NOREPLACE = 1
FORBIDDEN_MODE_BITS = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX


class NdkOutputError(RuntimeError):
    pass


@dataclass(frozen=True)
class NdkSpec:
    version: str
    revision: str
    root: str

    @property
    def source_properties(self) -> bytes:
        return (
            "Pkg.Desc = Android NDK\n"
            f"Pkg.Revision = {self.revision}\n"
            f"Pkg.BaseRevision = {self.revision}\n"
            f"Pkg.ReleaseName = {self.version}\n"
        ).encode("ascii")


@dataclass(frozen=True)
class ArchiveEntry:
    archive_name: str
    relative: str
    kind: str
    mode: int
    size: int
    target: str | None


SPECS = {
    "r28c": NdkSpec("r28c", "28.2.13676358", "android-ndk-r28c"),
}

REQUIRED_ENTRIES = {
    "source.properties": ("file", 0o644),
    "ndk-build": ("file", 0o755),
    "build/cmake/android.toolchain.cmake": ("file", 0o644),
    "toolchains/llvm/prebuilt/linux-x86_64/bin/clang": ("symlink", 0o777),
    "toolchains/llvm/prebuilt/linux-x86_64/bin/clang-19": ("file", 0o755),
    "toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang": (
        "file",
        0o755,
    ),
    (
        "toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/"
        "aarch64-linux-android/libc++_shared.so"
    ): ("file", 0o755),
}


def fail(message: str) -> None:
    raise NdkOutputError(message)


def spec_for(version: str) -> NdkSpec:
    spec = SPECS.get(version)
    if spec is None:
        fail("Android NDK version is outside the closed supported set")
    return spec


def validate_sha256(value: str, label: str) -> str:
    if SHA256_PATTERN.fullmatch(value) is None:
        fail(f"{label} is not one lowercase SHA-256 value")
    return value


def validate_builder(value: str) -> str:
    if IMAGE_PATTERN.fullmatch(value) is None:
        fail("Android NDK extractor is not one immutable image ID")
    return value


def identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


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


def list_xattrs(path: Path) -> list[str]:
    try:
        return os.listxattr(path, follow_symlinks=False)
    except OSError as error:
        fail(f"cannot inspect extended attributes on {path}: {error}")


def reject_extended_metadata(
    path: Path,
    metadata: os.stat_result,
    label: str,
) -> None:
    if metadata.st_mode & FORBIDDEN_MODE_BITS:
        fail(f"{label} carries set-id or sticky mode bits")
    if list_xattrs(path):
        fail(f"{label} carries extended attributes")


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
            or any(
                byte < ord("0") or byte > ord("7")
                for byte in value[index + 1:index + 4]
            )
        ):
            fail("malformed mountpoint escape")
        decoded.append(int(value[index + 1:index + 4], 8))
        index += 4
    return bytes(decoded)


def read_mountpoints() -> list[bytes]:
    descriptor = os.open(
        "/proc/self/mountinfo",
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        data = bytearray()
        while True:
            block = os.read(
                descriptor,
                min(BLOCK_SIZE, MOUNTINFO_LIMIT + 1 - len(data)),
            )
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
            fail("short /proc/self/mountinfo record")
        mountpoints.append(decode_mount_path(fields[4]))
    if not mountpoints:
        fail("/proc/self/mountinfo has no records")
    return mountpoints


def reject_mount_at_or_below(path: Path, *, allow_root: bool = False) -> None:
    encoded = os.fsencode(path)
    prefix = encoded.rstrip(b"/") + b"/"
    for mountpoint in read_mountpoints():
        if (
            (mountpoint == encoded and not allow_root)
            or mountpoint.startswith(prefix)
        ):
            fail(
                "Android NDK private tree contains a mount: "
                f"{os.fsdecode(mountpoint)}"
            )


def validate_online(online: Path, uid: int, gid: int) -> os.stat_result:
    validate_absolute(online, "online root")
    metadata = os.lstat(online)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("online root is not one real directory")
    if (metadata.st_uid, metadata.st_gid) != (uid, gid):
        fail("online root is not owned by the acquisition identity")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        fail("online root is not mode 0700")
    reject_extended_metadata(online, metadata, "online root")
    return metadata


def validate_staging(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
) -> os.stat_result:
    online_metadata = validate_online(online, uid, gid)
    validate_absolute(staging, "Android NDK staging")
    if (
        staging.parent != online
        or STAGING_PATTERN.fullmatch(staging.name) is None
    ):
        fail("Android NDK staging is not one reserved online-root child")
    metadata = os.lstat(staging)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("Android NDK staging is not one real directory")
    if metadata.st_dev != online_metadata.st_dev:
        fail("Android NDK staging is not on the online filesystem")
    if (metadata.st_uid, metadata.st_gid) != (uid, gid):
        fail("Android NDK staging is not owned by the acquisition identity")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        fail("Android NDK staging is not mode 0700")
    reject_extended_metadata(staging, metadata, "Android NDK staging")
    reject_mount_at_or_below(staging)
    return metadata


def validate_archive_host(
    online: Path,
    archive_path: Path,
    uid: int,
    gid: int,
) -> os.stat_result:
    online_metadata = validate_online(online, uid, gid)
    validate_absolute(archive_path, "Android NDK archive")
    if archive_path.parent != online:
        fail("Android NDK archive is not one direct online-root input")
    metadata = os.lstat(archive_path)
    if not stat.S_ISREG(metadata.st_mode):
        fail("Android NDK archive is not one regular file")
    if metadata.st_dev != online_metadata.st_dev:
        fail("Android NDK archive is not on the online filesystem")
    if (metadata.st_uid, metadata.st_gid) not in ((uid, gid), (0, 0)):
        fail("Android NDK archive has foreign ownership")
    if stat.S_IMODE(metadata.st_mode) != 0o644:
        fail("Android NDK archive is not exact mode 0644")
    if metadata.st_nlink != 1:
        fail("Android NDK archive has an external hardlink")
    reject_extended_metadata(archive_path, metadata, "Android NDK archive")
    return metadata


def hash_descriptor(descriptor: int, maximum: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        block = os.pread(
            descriptor,
            min(BLOCK_SIZE, maximum + 1 - offset),
            offset,
        )
        if not block:
            break
        digest.update(block)
        offset += len(block)
        if offset > maximum:
            fail("Android NDK archive exceeds its byte bound while hashing")
    return digest.hexdigest()


def safe_archive_name(raw: str, spec: NdkSpec) -> tuple[str, list[str]]:
    encoded = raw.encode("utf-8")
    if (
        not raw
        or len(encoded) > MAX_NAME_BYTES
        or not raw.isascii()
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in raw)
        or "\\" in raw
        or raw.startswith("/")
        or "//" in raw
    ):
        fail(f"Android NDK archive has an unsafe member name: {raw!r}")
    stripped = raw[:-1] if raw.endswith("/") else raw
    parts = stripped.split("/")
    if (
        not parts
        or parts[0] != spec.root
        or len(parts) > MAX_DEPTH
        or any(
            component in ("", ".", "..")
            or len(component.encode("utf-8")) > MAX_COMPONENT_BYTES
            for component in parts
        )
    ):
        fail(f"Android NDK archive member escapes its exact root: {raw!r}")
    relative = "/".join(parts[1:])
    return relative, parts


def resolve_symlink(
    entry: ArchiveEntry,
    entries: dict[str, ArchiveEntry],
) -> str:
    if entry.target is None:
        fail("internal error: non-symlink entered symlink resolution")
    target = entry.target
    encoded = target.encode("utf-8")
    if (
        not target
        or len(encoded) > MAX_SYMLINK_BYTES
        or not target.isascii()
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in target)
        or "\\" in target
        or target.startswith("/")
    ):
        fail(f"Android NDK archive has an unsafe symlink target: {entry.relative}")
    parent = entry.relative.split("/")[:-1]
    resolved = list(parent)
    for component in target.split("/"):
        if component in ("", "."):
            continue
        if component == "..":
            if not resolved:
                fail(
                    "Android NDK archive symlink escapes its exact root: "
                    f"{entry.relative}"
                )
            resolved.pop()
            continue
        if len(component.encode("utf-8")) > MAX_COMPONENT_BYTES:
            fail(f"Android NDK archive symlink component is too long: {entry.relative}")
        resolved.append(component)
    result = "/".join(resolved)
    if result not in entries:
        fail(
            "Android NDK archive symlink has no exact member target: "
            f"{entry.relative}"
        )
    return result


def validate_symlink_graph(entries: dict[str, ArchiveEntry]) -> None:
    direct = {
        relative: resolve_symlink(entry, entries)
        for relative, entry in entries.items()
        if entry.kind == "symlink"
    }
    for start in direct:
        seen = set()
        current = start
        while current in direct:
            if current in seen or len(seen) > MAX_SYMLINKS:
                fail(f"Android NDK archive contains a symlink loop: {start}")
            seen.add(current)
            current = direct[current]


def validate_required_entries(
    archive: zipfile.ZipFile,
    entries: dict[str, ArchiveEntry],
    spec: NdkSpec,
) -> None:
    for relative, expected in REQUIRED_ENTRIES.items():
        entry = entries.get(relative)
        if entry is None or (entry.kind, entry.mode) != expected:
            fail(f"Android NDK archive is missing required exact entry: {relative}")
    source = entries["source.properties"]
    if archive.read(source.archive_name) != spec.source_properties:
        fail("Android NDK source.properties does not match the pinned revision")
    clang = entries["toolchains/llvm/prebuilt/linux-x86_64/bin/clang"]
    if clang.target != "clang-19":
        fail("Android NDK clang symlink does not select the pinned compiler")


def validate_manifest(
    archive: zipfile.ZipFile,
    spec: NdkSpec,
) -> dict[str, ArchiveEntry]:
    if archive.comment:
        fail("Android NDK archive carries an unexpected archive comment")
    infos = archive.infolist()
    if not infos or len(infos) > MAX_ENTRIES:
        fail("Android NDK archive entry count is outside its bound")
    entries: dict[str, ArchiveEntry] = {}
    directories = files = symlinks = total_bytes = 0
    for info in infos:
        if info.orig_filename != info.filename:
            fail("Android NDK archive member name was NUL-truncated")
        relative, _parts = safe_archive_name(info.filename, spec)
        if relative in entries:
            fail(f"Android NDK archive repeats one output path: {relative}")
        if info.create_system != 3:
            fail("Android NDK archive member lacks Unix type authority")
        if info.flag_bits & ~0x2:
            fail("Android NDK archive member has unsupported or encrypted flags")
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            fail("Android NDK archive member uses an unsupported compression method")
        if info.comment:
            fail("Android NDK archive member carries an unexpected comment")
        raw_mode = (info.external_attr >> 16) & 0xFFFF
        mode = stat.S_IMODE(raw_mode)
        kind_bits = stat.S_IFMT(raw_mode)
        target = None
        if info.is_dir():
            if kind_bits != stat.S_IFDIR or mode != 0o755 or info.file_size != 0:
                fail(f"Android NDK archive directory metadata is invalid: {relative}")
            kind = "directory"
            directories += 1
        elif kind_bits == stat.S_IFREG:
            if mode not in (0o644, 0o755):
                fail(f"Android NDK archive file mode is invalid: {relative}")
            if info.file_size < 0 or info.file_size > MAX_FILE_BYTES:
                fail(f"Android NDK archive file exceeds its byte bound: {relative}")
            kind = "file"
            files += 1
            total_bytes += info.file_size
        elif kind_bits == stat.S_IFLNK:
            if mode != 0o777 or info.file_size > MAX_SYMLINK_BYTES:
                fail(f"Android NDK archive symlink metadata is invalid: {relative}")
            try:
                target = archive.read(info).decode("utf-8")
            except UnicodeDecodeError as error:
                fail(f"Android NDK symlink target is not UTF-8: {relative}: {error}")
            kind = "symlink"
            symlinks += 1
            total_bytes += info.file_size
        else:
            fail(f"Android NDK archive contains a special member: {relative}")
        if total_bytes > MAX_TOTAL_BYTES:
            fail("Android NDK archive expands beyond its total byte bound")
        entries[relative] = ArchiveEntry(
            info.filename,
            relative,
            kind,
            mode,
            info.file_size,
            target,
        )
    if (
        directories > MAX_DIRECTORIES
        or files > MAX_FILES
        or symlinks > MAX_SYMLINKS
    ):
        fail("Android NDK archive type inventory exceeds its bound")
    root = entries.get("")
    if root is None or root.kind != "directory":
        fail("Android NDK archive does not contain its exact root directory")
    for relative, entry in entries.items():
        if not relative:
            continue
        parts = relative.split("/")
        for length in range(1, len(parts)):
            parent = entries.get("/".join(parts[:length]))
            if parent is None or parent.kind != "directory":
                fail(
                    "Android NDK archive member lacks an explicit real parent: "
                    f"{relative}"
                )
        if entry.kind == "directory" and not entry.archive_name.endswith("/"):
            fail(f"Android NDK directory name lacks its slash marker: {relative}")
        if entry.kind != "directory" and entry.archive_name.endswith("/"):
            fail(f"Android NDK non-directory has a slash marker: {relative}")
    validate_symlink_graph(entries)
    validate_required_entries(archive, entries, spec)
    return entries


@contextlib.contextmanager
def open_validated_archive(
    archive_path: Path,
    version: str,
    expected_sha256: str,
) -> Iterator[tuple[zipfile.ZipFile, dict[str, ArchiveEntry], os.stat_result]]:
    spec = spec_for(version)
    validate_sha256(expected_sha256, "Android NDK archive digest")
    validate_absolute(archive_path, "Android NDK archive")
    descriptor = os.open(
        archive_path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > MAX_ARCHIVE_BYTES
        ):
            fail("Android NDK archive file metadata is unsafe")
        if hash_descriptor(descriptor, MAX_ARCHIVE_BYTES) != expected_sha256:
            fail("Android NDK archive SHA-256 does not match its pin")
        duplicate = os.dup(descriptor)
        try:
            with os.fdopen(duplicate, "rb") as stream:
                duplicate = -1
                with zipfile.ZipFile(stream, "r") as archive:
                    entries = validate_manifest(archive, spec)
                    yield archive, entries, before
        finally:
            if duplicate >= 0:
                os.close(duplicate)
        after = os.fstat(descriptor)
        if stable_metadata(before) != stable_metadata(after):
            fail("Android NDK archive changed while it was read")
    except zipfile.BadZipFile as error:
        fail(f"Android NDK archive is malformed: {error}")
    finally:
        os.close(descriptor)


def validate_output_container(
    output: Path,
    uid: int,
    gid: int,
    *,
    empty: bool,
    allow_root_mount: bool = False,
) -> os.stat_result:
    validate_absolute(output, "Android NDK output container")
    metadata = os.lstat(output)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("Android NDK output container is not one real directory")
    if (metadata.st_uid, metadata.st_gid) != (uid, gid):
        fail("Android NDK output container has the wrong owner")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        fail("Android NDK output container is not mode 0700")
    reject_extended_metadata(output, metadata, "Android NDK output container")
    reject_mount_at_or_below(output, allow_root=allow_root_mount)
    if empty:
        with os.scandir(output) as iterator:
            if next(iterator, None) is not None:
                fail("Android NDK output container is not empty")
    return metadata


def extract_archive(
    archive_path: Path,
    output: Path,
    version: str,
    expected_sha256: str,
) -> None:
    uid = os.getuid()
    gid = os.getgid()
    if uid <= 0 or gid <= 0:
        fail("Android NDK extraction refuses root UID or GID")
    validate_output_container(
        output,
        uid,
        gid,
        empty=True,
        allow_root_mount=True,
    )
    spec = spec_for(version)
    with open_validated_archive(
        archive_path,
        version,
        expected_sha256,
    ) as (archive, entries, _archive_metadata):
        root = output / spec.root
        directories = sorted(
            (
                entry
                for entry in entries.values()
                if entry.kind == "directory"
            ),
            key=lambda entry: (
                entry.relative.count("/"),
                os.fsencode(entry.relative),
            ),
        )
        for entry in directories:
            path = root if not entry.relative else root / entry.relative
            path.mkdir(mode=0o755)
            os.chmod(path, 0o755, follow_symlinks=False)
        for entry in sorted(
            (
                entry
                for entry in entries.values()
                if entry.kind == "file"
            ),
            key=lambda entry: os.fsencode(entry.relative),
        ):
            path = root / entry.relative
            descriptor = os.open(
                path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
                entry.mode,
            )
            try:
                written = 0
                with archive.open(entry.archive_name, "r") as source:
                    while True:
                        block = source.read(BLOCK_SIZE)
                        if not block:
                            break
                        view = memoryview(block)
                        while view:
                            count = os.write(descriptor, view)
                            if count <= 0:
                                fail(
                                    "short write while extracting Android NDK member: "
                                    f"{entry.relative}"
                                )
                            written += count
                            view = view[count:]
                if written != entry.size:
                    fail(
                        "Android NDK member size changed during extraction: "
                        f"{entry.relative}"
                    )
                os.fchmod(descriptor, entry.mode)
            finally:
                os.close(descriptor)
        for entry in sorted(
            (
                entry
                for entry in entries.values()
                if entry.kind == "symlink"
            ),
            key=lambda entry: os.fsencode(entry.relative),
        ):
            if entry.target is None:
                fail("internal error: missing Android NDK symlink target")
            os.symlink(entry.target, root / entry.relative)
    validate_output_container(
        output,
        uid,
        gid,
        empty=False,
        allow_root_mount=True,
    )


def collect_output(
    root: Path,
    online_metadata: os.stat_result,
) -> dict[str, os.stat_result]:
    observed = {"": os.lstat(root)}
    pending = [("", root)]
    while pending:
        parent_relative, parent = pending.pop()
        with os.scandir(parent) as iterator:
            children = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
        for child in children:
            relative = (
                child.name
                if not parent_relative
                else f"{parent_relative}/{child.name}"
            )
            if (
                len(relative.encode("utf-8")) > MAX_NAME_BYTES
                or len(relative.split("/")) + 1 > MAX_DEPTH
            ):
                fail(f"Android NDK output path exceeds its bound: {relative}")
            metadata = child.stat(follow_symlinks=False)
            if metadata.st_dev != online_metadata.st_dev:
                fail(f"Android NDK output crosses a filesystem: {relative}")
            observed[relative] = metadata
            if stat.S_ISDIR(metadata.st_mode):
                pending.append((relative, Path(child.path)))
    if len(observed) > MAX_ENTRIES:
        fail("Android NDK output entry count exceeds its bound")
    return observed


def expected_mode(
    entry: ArchiveEntry,
    profile: str,
) -> int:
    if profile == "archive":
        return entry.mode
    if entry.kind == "symlink":
        return 0o777
    if entry.kind == "directory":
        return 0o555
    return 0o555 if entry.mode & 0o111 else 0o444


def compare_regular(
    archive: zipfile.ZipFile,
    entry: ArchiveEntry,
    path: Path,
    digest,
) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail(f"Android NDK output file is not private and regular: {entry.relative}")
        content_digest = hashlib.sha256()
        total = 0
        with archive.open(entry.archive_name, "r") as source:
            while True:
                expected = source.read(BLOCK_SIZE)
                actual = os.read(descriptor, BLOCK_SIZE)
                if expected != actual:
                    fail(f"Android NDK output bytes differ from the archive: {entry.relative}")
                if not expected:
                    break
                total += len(expected)
                content_digest.update(expected)
        if total != entry.size:
            fail(f"Android NDK output size differs from the archive: {entry.relative}")
        after = os.fstat(descriptor)
        if stable_metadata(before) != stable_metadata(after):
            fail(f"Android NDK output file changed while read: {entry.relative}")
        digest.update(content_digest.digest())
    finally:
        os.close(descriptor)


def compare_output(
    archive: zipfile.ZipFile,
    entries: dict[str, ArchiveEntry],
    root: Path,
    online_metadata: os.stat_result,
    uid: int,
    gid: int,
    *,
    profile: str,
    expected_identity: tuple[int, int] | None = None,
) -> str:
    validate_absolute(root, "Android NDK output")
    reject_mount_at_or_below(root)
    observed = collect_output(root, online_metadata)
    if set(observed) != set(entries):
        fail("Android NDK output inventory differs from the pinned archive")
    root_metadata = observed[""]
    if expected_identity is not None and identity(root_metadata) != expected_identity:
        fail("Android NDK output identity changed")
    if profile == "legacy-root":
        owner = (0, 0)
        mode_profile = "archive"
    elif profile == "legacy-user":
        owner = (uid, gid)
        mode_profile = "archive"
    elif profile in ("private-sealed", "sealed"):
        owner = (uid, gid)
        mode_profile = "sealed"
    elif profile == "raw":
        owner = (uid, gid)
        mode_profile = "archive"
    else:
        fail("Android NDK output mode profile is invalid")
    digest = hashlib.sha256()
    directories = files = symlinks = total_bytes = 0
    for relative in sorted(entries, key=os.fsencode):
        entry = entries[relative]
        metadata = observed[relative]
        path = root if not relative else root / relative
        if (metadata.st_uid, metadata.st_gid) != owner:
            fail(f"Android NDK output has mixed or foreign ownership: {relative}")
        reject_extended_metadata(path, metadata, f"Android NDK output {relative or '.'}")
        mode = stat.S_IMODE(metadata.st_mode)
        wanted_mode = expected_mode(entry, mode_profile)
        if profile == "private-sealed" and not relative:
            wanted_mode = 0o700
        if mode != wanted_mode:
            fail(f"Android NDK output mode differs from its profile: {relative or '.'}")
        if entry.kind == "directory":
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                fail(f"Android NDK output directory changed type: {relative}")
            directories += 1
        elif entry.kind == "file":
            if not stat.S_ISREG(metadata.st_mode):
                fail(f"Android NDK output file changed type: {relative}")
            compare_regular(archive, entry, path, digest)
            files += 1
            total_bytes += metadata.st_size
        else:
            if not stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink != 1:
                fail(f"Android NDK output symlink changed type or links: {relative}")
            target = os.readlink(path)
            if target != entry.target:
                fail(f"Android NDK output symlink target changed: {relative}")
            digest.update(target.encode("utf-8"))
            symlinks += 1
            total_bytes += len(target.encode("utf-8"))
        digest.update(entry.kind.encode("ascii"))
        digest.update(b"\0")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(f"{entry.mode:o}".encode("ascii"))
        digest.update(b"\0")
    if (
        directories > MAX_DIRECTORIES
        or files > MAX_FILES
        or symlinks > MAX_SYMLINKS
        or total_bytes > MAX_TOTAL_BYTES
    ):
        fail("Android NDK output exceeds its closed type or byte bound")
    return digest.hexdigest()


def fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def seal_and_sync_tree(
    root: Path,
    entries: dict[str, ArchiveEntry],
) -> None:
    for relative in sorted(entries, key=os.fsencode):
        entry = entries[relative]
        if entry.kind != "file":
            continue
        path = root / relative
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                fail(f"cannot seal nonprivate Android NDK file: {relative}")
            os.fchmod(descriptor, 0o555 if entry.mode & 0o111 else 0o444)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    directories = sorted(
        (
            entry.relative
            for entry in entries.values()
            if entry.kind == "directory"
        ),
        key=lambda relative: (relative.count("/"), os.fsencode(relative)),
        reverse=True,
    )
    for relative in directories:
        path = root if not relative else root / relative
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            os.fchmod(descriptor, 0o700 if not relative else 0o555)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def validate_inventory(path: Path, expected: set[str], label: str) -> None:
    if set(os.listdir(path)) != expected:
        fail(f"{label} inventory is incoherent and was preserved")


def write_state(staging: Path, payload: dict[str, object]) -> None:
    state = staging / STATE_NAME
    temporary = staging / f"{STATE_NAME}.tmp"
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    if len(encoded) > MAX_STATE_BYTES:
        fail("Android NDK transaction state exceeds its byte bound")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                fail("short write while recording Android NDK transaction state")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, state)
    fsync_directory(staging)


def state_payload(
    online: Path,
    staging: Path,
    output: Path,
    archive: Path,
    uid: int,
    gid: int,
    version: str,
    archive_sha256: str,
    builder: str,
) -> dict[str, object]:
    return {
        "state_version": STATE_VERSION,
        "online": os.fspath(online),
        "online_identity": encode_identity(identity(os.lstat(online))),
        "staging": os.fspath(staging),
        "staging_identity": encode_identity(identity(os.lstat(staging))),
        "output_identity": encode_identity(identity(os.lstat(output))),
        "archive": os.fspath(archive),
        "archive_identity": encode_identity(identity(os.lstat(archive))),
        "uid": uid,
        "gid": gid,
        "ndk_version": version,
        "archive_sha256": archive_sha256,
        "builder": builder,
        "destination": "android-ndk",
        "verified": False,
        "candidate_identity": None,
        "tree_digest": None,
    }


def read_regular(path: Path, maximum: int) -> tuple[bytes, os.stat_result]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            fail(f"bounded regular-file read refused: {path}")
        data = bytearray()
        while True:
            block = os.read(
                descriptor,
                min(BLOCK_SIZE, maximum + 1 - len(data)),
            )
            if not block:
                break
            data.extend(block)
            if len(data) > maximum:
                fail(f"bounded regular-file read overflowed: {path}")
        after = os.fstat(descriptor)
        if stable_metadata(before) != stable_metadata(after):
            fail(f"file changed while read: {path}")
        return bytes(data), after
    finally:
        os.close(descriptor)


def load_state(
    online: Path,
    staging: Path,
    archive: Path,
    uid: int,
    gid: int,
    version: str,
    archive_sha256: str,
    builder: str,
) -> dict[str, object]:
    spec_for(version)
    validate_sha256(archive_sha256, "Android NDK archive digest")
    validate_builder(builder)
    staging_metadata = validate_staging(online, staging, uid, gid)
    archive_metadata = validate_archive_host(online, archive, uid, gid)
    data, metadata = read_regular(staging / STATE_NAME, MAX_STATE_BYTES)
    if (
        (metadata.st_uid, metadata.st_gid) != (uid, gid)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        fail("Android NDK transaction state metadata is invalid")
    try:
        payload = json.loads(data.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"Android NDK transaction state is malformed: {error}")
    expected_keys = {
        "state_version",
        "online",
        "online_identity",
        "staging",
        "staging_identity",
        "output_identity",
        "archive",
        "archive_identity",
        "uid",
        "gid",
        "ndk_version",
        "archive_sha256",
        "builder",
        "destination",
        "verified",
        "candidate_identity",
        "tree_digest",
    }
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        fail("Android NDK transaction state has an unexpected schema")
    expected_values = {
        "state_version": STATE_VERSION,
        "online": os.fspath(online),
        "staging": os.fspath(staging),
        "archive": os.fspath(archive),
        "uid": uid,
        "gid": gid,
        "ndk_version": version,
        "archive_sha256": archive_sha256,
        "builder": builder,
        "destination": "android-ndk",
    }
    for key, expected in expected_values.items():
        if payload[key] != expected:
            fail(f"Android NDK transaction state changed its {key} binding")
    if type(payload["verified"]) is not bool:
        fail("Android NDK transaction verification state is malformed")
    if payload["verified"]:
        decode_identity(payload["candidate_identity"], "Android NDK candidate")
        if (
            not isinstance(payload["tree_digest"], str)
            or TREE_DIGEST_PATTERN.fullmatch(payload["tree_digest"]) is None
        ):
            fail("Android NDK transaction tree digest is malformed")
    elif payload["candidate_identity"] is not None or payload["tree_digest"] is not None:
        fail("unverified Android NDK transaction carries output authority")
    if decode_identity(payload["online_identity"], "online root") != identity(
        os.lstat(online)
    ):
        fail("online root identity changed during the Android NDK transaction")
    if decode_identity(payload["staging_identity"], "Android NDK staging") != identity(
        staging_metadata
    ):
        fail("Android NDK staging identity changed")
    output_metadata = os.lstat(staging / "output")
    if decode_identity(payload["output_identity"], "Android NDK output container") != identity(
        output_metadata
    ):
        fail("Android NDK output container identity changed")
    if decode_identity(payload["archive_identity"], "Android NDK archive") != identity(
        archive_metadata
    ):
        fail("Android NDK archive identity changed")
    return payload


def prepare(
    online: Path,
    staging: Path,
    archive: Path,
    uid: int,
    gid: int,
    version: str,
    archive_sha256: str,
    builder: str,
) -> None:
    validate_staging(online, staging, uid, gid)
    validate_inventory(staging, set(), "Android NDK staging")
    validate_archive_host(online, archive, uid, gid)
    with open_validated_archive(archive, version, archive_sha256):
        pass
    validate_builder(builder)
    output = staging / "output"
    output.mkdir(mode=0o700)
    write_state(
        staging,
        state_payload(
            online,
            staging,
            output,
            archive,
            uid,
            gid,
            version,
            archive_sha256,
            builder,
        ),
    )
    validate_inventory(staging, {STATE_NAME, "output"}, "Android NDK staging")
    fsync_directory(online)


def verify_staged(
    online: Path,
    staging: Path,
    archive: Path,
    uid: int,
    gid: int,
    version: str,
    archive_sha256: str,
    builder: str,
) -> None:
    payload = load_state(
        online,
        staging,
        archive,
        uid,
        gid,
        version,
        archive_sha256,
        builder,
    )
    validate_inventory(staging, {STATE_NAME, "output"}, "Android NDK staging")
    output = staging / "output"
    validate_output_container(output, uid, gid, empty=False)
    spec = spec_for(version)
    candidate = output / spec.root
    with open_validated_archive(
        archive,
        version,
        archive_sha256,
    ) as (zip_archive, entries, _archive_metadata):
        if payload["verified"]:
            expected = decode_identity(
                payload["candidate_identity"],
                "Android NDK candidate",
            )
            digest = compare_output(
                zip_archive,
                entries,
                candidate,
                os.lstat(online),
                uid,
                gid,
                profile="private-sealed",
                expected_identity=expected,
            )
            if digest != payload["tree_digest"]:
                fail("Android NDK sealed tree digest changed")
            return
        digest = compare_output(
            zip_archive,
            entries,
            candidate,
            os.lstat(online),
            uid,
            gid,
            profile="raw",
        )
        candidate_identity = identity(os.lstat(candidate))
        seal_and_sync_tree(candidate, entries)
        sealed_digest = compare_output(
            zip_archive,
            entries,
            candidate,
            os.lstat(online),
            uid,
            gid,
            profile="private-sealed",
            expected_identity=candidate_identity,
        )
        if digest != sealed_digest:
            fail("Android NDK tree digest changed while sealing")
    payload["verified"] = True
    payload["candidate_identity"] = encode_identity(candidate_identity)
    payload["tree_digest"] = digest
    write_state(staging, payload)


def existing_profile(
    metadata: os.stat_result,
    uid: int,
    gid: int,
) -> str:
    owner = (metadata.st_uid, metadata.st_gid)
    mode = stat.S_IMODE(metadata.st_mode)
    if owner == (uid, gid) and mode == 0o555:
        return "sealed"
    if owner == (uid, gid) and mode == 0o755:
        return "legacy-user"
    if owner == (0, 0) and mode == 0o755:
        return "legacy-root"
    fail("existing Android NDK output has inadmissible ownership or root mode")


def check_complete(
    online: Path,
    archive: Path,
    uid: int,
    gid: int,
    version: str,
    archive_sha256: str,
    builder: str,
) -> None:
    validate_builder(builder)
    online_metadata = validate_online(online, uid, gid)
    validate_archive_host(online, archive, uid, gid)
    output = online / "android-ndk"
    metadata = os.lstat(output)
    profile = existing_profile(metadata, uid, gid)
    with open_validated_archive(
        archive,
        version,
        archive_sha256,
    ) as (zip_archive, entries, _archive_metadata):
        compare_output(
            zip_archive,
            entries,
            output,
            online_metadata,
            uid,
            gid,
            profile=profile,
            expected_identity=identity(metadata),
        )


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
    return os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )


def publish(
    online: Path,
    staging: Path,
    archive: Path,
    uid: int,
    gid: int,
    version: str,
    archive_sha256: str,
    builder: str,
) -> None:
    verify_staged(
        online,
        staging,
        archive,
        uid,
        gid,
        version,
        archive_sha256,
        builder,
    )
    payload = load_state(
        online,
        staging,
        archive,
        uid,
        gid,
        version,
        archive_sha256,
        builder,
    )
    expected = decode_identity(
        payload["candidate_identity"],
        "Android NDK candidate",
    )
    spec = spec_for(version)
    output = staging / "output"
    candidate = output / spec.root
    destination = online / "android-ndk"
    if destination.exists() or destination.is_symlink():
        fail("Android NDK destination appeared before no-clobber publication")
    fsync_directory(output)
    fsync_directory(staging)
    output_fd = open_directory(output)
    online_fd = open_directory(online)
    moved = False
    try:
        renameat2(
            output_fd,
            spec.root,
            online_fd,
            "android-ndk",
            RENAME_NOREPLACE,
        )
        moved = True
        os.fsync(output_fd)
        os.fsync(online_fd)
        os.chmod(destination, 0o555, follow_symlinks=False)
        fsync_directory(destination)
        os.fsync(online_fd)
        with open_validated_archive(
            archive,
            version,
            archive_sha256,
        ) as (zip_archive, entries, _archive_metadata):
            digest = compare_output(
                zip_archive,
                entries,
                destination,
                os.lstat(online),
                uid,
                gid,
                profile="sealed",
                expected_identity=expected,
            )
        if digest != payload["tree_digest"]:
            fail("published Android NDK tree digest changed")
    except BaseException as primary:
        if moved:
            try:
                os.chmod(destination, 0o700, follow_symlinks=False)
                renameat2(
                    online_fd,
                    "android-ndk",
                    output_fd,
                    spec.root,
                    RENAME_NOREPLACE,
                )
                os.fsync(output_fd)
                os.fsync(online_fd)
            except BaseException as rollback:
                primary.add_note(
                    "Android NDK publication rollback also failed: "
                    f"{rollback}"
                )
        raise
    finally:
        os.close(online_fd)
        os.close(output_fd)


def optional_identity(path: Path) -> tuple[int, int] | None:
    try:
        return identity(os.lstat(path))
    except FileNotFoundError:
        return None


def recover_unprepared(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
) -> str:
    validate_staging(online, staging, uid, gid)
    names = set(os.listdir(staging))
    if not names:
        return "unprepared-empty"
    temporary_state = f"{STATE_NAME}.tmp"
    expected = {"output"}
    if names == {"output", temporary_state}:
        _data, metadata = read_regular(
            staging / temporary_state,
            MAX_STATE_BYTES,
        )
        if (
            (metadata.st_uid, metadata.st_gid) != (uid, gid)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            fail("unprepared Android NDK state write is unsafe and was preserved")
        expected.add(temporary_state)
    if names != expected:
        fail("unprepared Android NDK staging is incoherent and was preserved")
    validate_output_container(staging / "output", uid, gid, empty=True)
    if temporary_state in names:
        return "unprepared-state-write"
    return "unprepared-output"


def recover(
    online: Path,
    staging: Path,
    archive: Path,
    uid: int,
    gid: int,
    version: str,
    archive_sha256: str,
    builder: str,
) -> str:
    state = staging / STATE_NAME
    if not state.exists() and not state.is_symlink():
        return recover_unprepared(online, staging, uid, gid)
    payload = load_state(
        online,
        staging,
        archive,
        uid,
        gid,
        version,
        archive_sha256,
        builder,
    )
    validate_inventory(staging, {STATE_NAME, "output"}, "Android NDK staging")
    output = staging / "output"
    spec = spec_for(version)
    private_candidate = optional_identity(output / spec.root)
    destination = online / "android-ndk"
    live_candidate = optional_identity(destination)
    if not payload["verified"]:
        if live_candidate is not None:
            fail("unverified Android NDK transaction reached a final name")
        return (
            "unverified-unpublished"
            if private_candidate is not None
            else "prepared-empty"
        )
    expected = decode_identity(
        payload["candidate_identity"],
        "Android NDK candidate",
    )
    if private_candidate == expected:
        if live_candidate is None:
            return "verified-unpublished"
        return "verified-unpublished-destination-occupied"
    if private_candidate is None and live_candidate == expected:
        with open_validated_archive(
            archive,
            version,
            archive_sha256,
        ) as (zip_archive, entries, _archive_metadata):
            digest = compare_output(
                zip_archive,
                entries,
                destination,
                os.lstat(online),
                uid,
                gid,
                profile="sealed",
                expected_identity=expected,
            )
        if digest != payload["tree_digest"]:
            fail("recovered Android NDK tree digest changed")
        return "published"
    fail("Android NDK output transaction state is incoherent and was preserved")


def make_zip_info(name: str, kind: str, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    type_bits = {
        "directory": stat.S_IFDIR,
        "file": stat.S_IFREG,
        "symlink": stat.S_IFLNK,
    }[kind]
    info.external_attr = (type_bits | mode) << 16
    info.compress_type = zipfile.ZIP_DEFLATED if kind == "file" else zipfile.ZIP_STORED
    return info


def fixture_members(
    spec: NdkSpec,
) -> list[tuple[str, str, int, bytes]]:
    root = spec.root
    files = {
        "source.properties": (0o644, spec.source_properties),
        "ndk-build": (0o755, b"#!/bin/sh\n"),
        "build/cmake/android.toolchain.cmake": (0o644, b"# toolchain\n"),
        "toolchains/llvm/prebuilt/linux-x86_64/bin/clang-19": (
            0o755,
            b"clang\n",
        ),
        "toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang": (
            0o755,
            b"clang wrapper\n",
        ),
        (
            "toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/"
            "aarch64-linux-android/libc++_shared.so"
        ): (0o755, b"\x7fELFfixture\n"),
    }
    directories = {""}
    for relative in files:
        parts = relative.split("/")
        directories.update("/".join(parts[:length]) for length in range(1, len(parts)))
    directories.update(
        {
            "toolchains/llvm/prebuilt/linux-x86_64/bin",
        }
    )
    members: list[tuple[str, str, int, bytes]] = []
    for relative in sorted(
        directories,
        key=lambda value: (value.count("/"), value),
    ):
        name = f"{root}/" if not relative else f"{root}/{relative}/"
        members.append((name, "directory", 0o755, b""))
    for relative, (mode, data) in sorted(files.items()):
        members.append((f"{root}/{relative}", "file", mode, data))
    members.append(
        (
            f"{root}/toolchains/llvm/prebuilt/linux-x86_64/bin/clang",
            "symlink",
            0o777,
            b"clang-19",
        )
    )
    return members


def write_fixture_archive(
    path: Path,
    spec: NdkSpec,
    *,
    extra: tuple[str, str, int, bytes] | None = None,
    duplicate: bool = False,
) -> str:
    members = fixture_members(spec)
    if extra is not None:
        members.append(extra)
    if duplicate:
        members.append(members[-1])
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message=r"Duplicate name: .*",
            category=UserWarning,
        )
        with zipfile.ZipFile(path, "w") as archive:
            for name, kind, mode, data in members:
                archive.writestr(make_zip_info(name, kind, mode), data)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_staging(online: Path) -> Path:
    return Path(
        tempfile.mkdtemp(
            prefix=".rustdesk-android-ndk.",
            dir=online,
        )
    )


def make_writable(root: Path) -> None:
    if not root.exists():
        return
    for current, directories, files in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        current_path = Path(current)
        try:
            current_path.chmod(0o700)
        except OSError:
            pass
        for name in files:
            path = current_path / name
            if path.is_symlink():
                continue
            try:
                path.chmod(0o600)
            except OSError:
                pass
        for name in directories:
            path = current_path / name
            if path.is_symlink():
                continue
            try:
                path.chmod(0o700)
            except OSError:
                pass


def expect_failure(action, message: str) -> None:
    try:
        action()
    except (OSError, NdkOutputError, UnicodeError, zipfile.BadZipFile):
        return
    fail(message)


def run_self_test() -> None:
    uid = os.getuid()
    gid = os.getgid()
    if uid <= 0 or gid <= 0:
        fail("Android NDK transaction self-test refuses root UID or GID")
    version = "r28c"
    spec = spec_for(version)
    builder = "sha256:" + "3" * 64

    def fixture(base: Path) -> tuple[Path, Path, Path, str]:
        base.mkdir()
        online = base / "online"
        online.mkdir(mode=0o700)
        archive = online / f"android-ndk-{version}.zip"
        archive_sha256 = write_fixture_archive(archive, spec)
        archive.chmod(0o644)
        staging = make_staging(online)
        prepare(
            online,
            staging,
            archive,
            uid,
            gid,
            version,
            archive_sha256,
            builder,
        )
        extract_archive(
            archive,
            staging / "output",
            version,
            archive_sha256,
        )
        return online, staging, archive, archive_sha256

    with tempfile.TemporaryDirectory(prefix="android-ndk-output-self-test.") as temporary:
        root = Path(temporary)
        try:
            online, staging, archive, archive_sha256 = fixture(root / "normal")
            verify_staged(
                online,
                staging,
                archive,
                uid,
                gid,
                version,
                archive_sha256,
                builder,
            )
            publish(
                online,
                staging,
                archive,
                uid,
                gid,
                version,
                archive_sha256,
                builder,
            )
            if (
                recover(
                    online,
                    staging,
                    archive,
                    uid,
                    gid,
                    version,
                    archive_sha256,
                    builder,
                )
                != "published"
            ):
                fail("self-test did not classify completed Android NDK publication")
            check_complete(
                online,
                archive,
                uid,
                gid,
                version,
                archive_sha256,
                builder,
            )

            online, staging, archive, archive_sha256 = fixture(root / "occupied")
            verify_staged(
                online,
                staging,
                archive,
                uid,
                gid,
                version,
                archive_sha256,
                builder,
            )
            (online / "android-ndk").mkdir()
            expect_failure(
                lambda: publish(
                    online,
                    staging,
                    archive,
                    uid,
                    gid,
                    version,
                    archive_sha256,
                    builder,
                ),
                "self-test accepted an occupied Android NDK destination",
            )
            if (
                recover(
                    online,
                    staging,
                    archive,
                    uid,
                    gid,
                    version,
                    archive_sha256,
                    builder,
                )
                != "verified-unpublished-destination-occupied"
            ):
                fail("self-test did not preserve an occupied Android NDK destination")

            online, staging, archive, archive_sha256 = fixture(root / "tamper")
            (
                staging
                / "output"
                / spec.root
                / "build"
                / "cmake"
                / "android.toolchain.cmake"
            ).write_bytes(b"tampered\n")
            expect_failure(
                lambda: verify_staged(
                    online,
                    staging,
                    archive,
                    uid,
                    gid,
                    version,
                    archive_sha256,
                    builder,
                ),
                "self-test accepted changed Android NDK output bytes",
            )

            online, staging, archive, archive_sha256 = fixture(root / "extra")
            (staging / "output" / spec.root / "unexpected").write_bytes(b"x")
            expect_failure(
                lambda: verify_staged(
                    online,
                    staging,
                    archive,
                    uid,
                    gid,
                    version,
                    archive_sha256,
                    builder,
                ),
                "self-test accepted an extra Android NDK output",
            )

            online, staging, archive, archive_sha256 = fixture(root / "hardlink")
            target = (
                staging
                / "output"
                / spec.root
                / "build"
                / "cmake"
                / "android.toolchain.cmake"
            )
            os.link(target, online / "external-link")
            expect_failure(
                lambda: verify_staged(
                    online,
                    staging,
                    archive,
                    uid,
                    gid,
                    version,
                    archive_sha256,
                    builder,
                ),
                "self-test accepted an externally hardlinked Android NDK output",
            )

            malformed_base = root / "path-traversal"
            malformed_base.mkdir()
            malformed = malformed_base / "bad.zip"
            malformed_sha = write_fixture_archive(
                malformed,
                spec,
                extra=(f"{spec.root}/../escape", "file", 0o644, b"x"),
            )
            expect_failure(
                lambda: extract_archive(
                    malformed,
                    _fresh_output(malformed_base),
                    version,
                    malformed_sha,
                ),
                "self-test accepted Android NDK archive path traversal",
            )

            symlink_base = root / "symlink-escape"
            symlink_base.mkdir()
            escaping = symlink_base / "bad.zip"
            escaping_sha = write_fixture_archive(
                escaping,
                spec,
                extra=(
                    f"{spec.root}/escape-link",
                    "symlink",
                    0o777,
                    b"../outside",
                ),
            )
            expect_failure(
                lambda: extract_archive(
                    escaping,
                    _fresh_output(symlink_base),
                    version,
                    escaping_sha,
                ),
                "self-test accepted an escaping Android NDK symlink",
            )

            duplicate_base = root / "duplicate"
            duplicate_base.mkdir()
            duplicate = duplicate_base / "bad.zip"
            duplicate_sha = write_fixture_archive(
                duplicate,
                spec,
                duplicate=True,
            )
            expect_failure(
                lambda: extract_archive(
                    duplicate,
                    _fresh_output(duplicate_base),
                    version,
                    duplicate_sha,
                ),
                "self-test accepted a duplicate Android NDK output path",
            )

            special_base = root / "special"
            special_base.mkdir()
            special = special_base / "bad.zip"
            special_sha = write_fixture_archive(
                special,
                spec,
                extra=(
                    f"{spec.root}/fifo",
                    "file",
                    0o644 | stat.S_IFIFO,
                    b"",
                ),
            )
            expect_failure(
                lambda: extract_archive(
                    special,
                    _fresh_output(special_base),
                    version,
                    special_sha,
                ),
                "self-test accepted a special Android NDK archive member",
            )

            wrong_base = root / "wrong-digest"
            wrong_base.mkdir()
            wrong = wrong_base / "bad.zip"
            write_fixture_archive(wrong, spec)
            expect_failure(
                lambda: extract_archive(
                    wrong,
                    _fresh_output(wrong_base),
                    version,
                    "0" * 64,
                ),
                "self-test accepted a wrong Android NDK archive digest",
            )

            unprepared_base = root / "unprepared"
            unprepared_base.mkdir()
            online = unprepared_base / "online"
            online.mkdir(mode=0o700)
            staging = make_staging(online)
            if recover_unprepared(online, staging, uid, gid) != "unprepared-empty":
                fail("self-test did not classify empty Android NDK staging")

            interrupted_base = root / "interrupted-state-write"
            interrupted_base.mkdir()
            online = interrupted_base / "online"
            online.mkdir(mode=0o700)
            staging = make_staging(online)
            (staging / "output").mkdir(mode=0o700)
            state_write = staging / f"{STATE_NAME}.tmp"
            descriptor = os.open(
                state_write,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
                0o600,
            )
            try:
                if os.write(descriptor, b'{"state_version":') != 17:
                    fail("short Android NDK interrupted-state fixture write")
            finally:
                os.close(descriptor)
            if (
                recover_unprepared(online, staging, uid, gid)
                != "unprepared-state-write"
            ):
                fail("self-test did not classify an interrupted Android NDK state write")

            if hasattr(os, "setxattr"):
                online, staging, archive, archive_sha256 = fixture(root / "xattr")
                target = (
                    staging
                    / "output"
                    / spec.root
                    / "build"
                    / "cmake"
                    / "android.toolchain.cmake"
                )
                try:
                    os.setxattr(target, "user.rustdesk-test", b"1")
                except OSError:
                    pass
                else:
                    expect_failure(
                        lambda: verify_staged(
                            online,
                            staging,
                            archive,
                            uid,
                            gid,
                            version,
                            archive_sha256,
                            builder,
                        ),
                        "self-test accepted extended attributes in Android NDK output",
                    )
        finally:
            make_writable(root)


def _fresh_output(base: Path) -> Path:
    output = base / "output"
    output.mkdir(mode=0o700)
    return output


def add_transaction_arguments(
    parser: argparse.ArgumentParser,
    *,
    staging: bool,
) -> None:
    parser.add_argument("--online", type=Path, required=True)
    if staging:
        parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    parser.add_argument("--version", choices=tuple(SPECS), required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--builder", required=True)


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    extract = subparsers.add_parser("extract")
    extract.add_argument("--archive", type=Path, required=True)
    extract.add_argument("--output", type=Path, required=True)
    extract.add_argument("--version", choices=tuple(SPECS), required=True)
    extract.add_argument("--sha256", required=True)
    for command in ("prepare", "verify", "publish", "recover"):
        add_transaction_arguments(
            subparsers.add_parser(command),
            staging=True,
        )
    add_transaction_arguments(
        subparsers.add_parser("check-complete"),
        staging=False,
    )
    subparsers.add_parser("self-test")
    return parser


def main() -> int:
    arguments = argument_parser().parse_args()
    if arguments.command == "self-test":
        run_self_test()
        print("online-android-ndk-output: self-test OK")
        return 0
    if arguments.command == "extract":
        extract_archive(
            arguments.archive,
            arguments.output,
            arguments.version,
            arguments.sha256,
        )
        return 0
    if arguments.uid <= 0 or arguments.gid <= 0:
        fail("Android NDK transaction owner must be a nonzero UID and GID")
    values = (
        arguments.online,
        arguments.archive,
        arguments.uid,
        arguments.gid,
        arguments.version,
        arguments.sha256,
        arguments.builder,
    )
    if arguments.command == "prepare":
        prepare(values[0], arguments.staging, *values[1:])
    elif arguments.command == "verify":
        verify_staged(values[0], arguments.staging, *values[1:])
    elif arguments.command == "publish":
        publish(values[0], arguments.staging, *values[1:])
    elif arguments.command == "recover":
        print(recover(values[0], arguments.staging, *values[1:]))
    elif arguments.command == "check-complete":
        check_complete(*values)
    else:
        fail("unsupported Android NDK transaction command")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        OSError,
        NdkOutputError,
        UnicodeError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ) as error:
        raise SystemExit(f"online-android-ndk-output: {error}")
