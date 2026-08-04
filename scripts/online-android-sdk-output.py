#!/usr/bin/env python3
"""Acquire, validate, recover, and publish the exact Android SDK tree."""

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
import urllib.request
import warnings
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


STATE_NAME = ".rustdesk-android-sdk-output-state-v1"
STATE_VERSION = 1
STAGING_PATTERN = re.compile(
    r"\.rustdesk-android-sdk\.[A-Za-z0-9_]{8,}\Z"
)
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
TREE_DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
BLOCK_SIZE = 1024 * 1024
MOUNTINFO_LIMIT = 8 * 1024 * 1024
MAX_STATE_BYTES = 16384
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 700 * 1024 * 1024
MAX_ENTRIES = 60000
MAX_DIRECTORIES = 12000
MAX_FILES = 50000
MAX_DEPTH = 32
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_NAME_BYTES = 4096
MAX_COMPONENT_BYTES = 255
RENAME_NOREPLACE = 1
FORBIDDEN_MODE_BITS = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX
DOWNLOAD_BASE = "https://dl.google.com/android/repository/"
EXPECTED_TREE_DIGEST = (
    "f7fa90b41ea168fc385f46e9c5f48f3cee28bddddd44abd5036d97d17a72fd2b"
)
EXPECTED_TREE_FILES = 43480
EXPECTED_TREE_DIRECTORIES = 11295
EXPECTED_TREE_BYTES = 898205722


class SdkOutputError(RuntimeError):
    pass


@dataclass(frozen=True)
class PackageSpec:
    key: str
    filename: str
    size: int
    archive_root: str
    destination: str
    entries: int
    allowed_modes: frozenset[int]
    allowed_flags: frozenset[int]
    local_input: bool = False


@dataclass(frozen=True)
class ArchiveEntry:
    package: str
    archive_name: str
    output_relative: str
    kind: str
    executable: bool
    size: int


@dataclass(frozen=True)
class TreeSummary:
    digest: str
    files: int
    directories: int
    bytes: int


SPECS = (
    PackageSpec(
        "cmdline-tools",
        "android-cmdline-tools.zip",
        174244366,
        "cmdline-tools",
        "cmdline-tools/latest",
        140,
        frozenset({0o755}),
        frozenset({0}),
        True,
    ),
    PackageSpec(
        "platform-tools",
        "platform-tools_r37.0.1-linux.zip",
        9054187,
        "platform-tools",
        "platform-tools",
        12,
        frozenset({0o644, 0o755}),
        frozenset({0, 8}),
    ),
    PackageSpec(
        "build-tools-30.0.3",
        "build-tools_r30.0.3-linux.zip",
        53134793,
        "android-11",
        "build-tools/30.0.3",
        203,
        frozenset({0o660, 0o664, 0o770, 0o775}),
        frozenset({0, 2}),
    ),
    PackageSpec(
        "build-tools-34.0.0",
        "build-tools_r34-linux.zip",
        61224257,
        "android-14",
        "build-tools/34.0.0",
        169,
        frozenset({0o644, 0o755}),
        frozenset({0, 8}),
    ),
    PackageSpec(
        "platform-31",
        "platform-31_r01.zip",
        56475526,
        "android-12",
        "platforms/android-31",
        13222,
        frozenset({0o660, 0o664, 0o770}),
        frozenset({0, 2}),
    ),
    PackageSpec(
        "platform-32",
        "platform-32_r01.zip",
        66108299,
        "android-12",
        "platforms/android-32",
        13386,
        frozenset({0o660, 0o664, 0o770}),
        frozenset({0, 2}),
    ),
    PackageSpec(
        "platform-33",
        "platform-33-ext3_r03.zip",
        67334237,
        "android-13",
        "platforms/android-33",
        13630,
        frozenset({0o660, 0o664, 0o770}),
        frozenset({0, 2}),
    ),
    PackageSpec(
        "platform-34",
        "platform-34-ext7_r03.zip",
        63180081,
        "android-34",
        "platforms/android-34",
        13790,
        frozenset({0o660, 0o664, 0o770}),
        frozenset({0, 2}),
    ),
)
SPEC_BY_KEY = {spec.key: spec for spec in SPECS}
PIN_KEYS = frozenset(SPEC_BY_KEY)


def fail(message: str) -> None:
    raise SdkOutputError(message)


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


def validate_sha256(value: str, label: str) -> str:
    if SHA256_PATTERN.fullmatch(value) is None:
        fail(f"{label} is not one lowercase SHA-256 value")
    return value


def validate_builder(value: str) -> str:
    if IMAGE_PATTERN.fullmatch(value) is None:
        fail("Android SDK producer is not one immutable image ID")
    return value


def parse_pins(values: list[str]) -> dict[str, str]:
    pins: dict[str, str] = {}
    for value in values:
        key, separator, digest = value.partition("=")
        if not separator or key not in PIN_KEYS or key in pins:
            fail("Android SDK package-pin set is malformed")
        pins[key] = validate_sha256(digest, f"Android SDK {key} digest")
    if set(pins) != PIN_KEYS:
        fail("Android SDK package-pin set is incomplete")
    return pins


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
                "Android SDK private tree contains a mount: "
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
    validate_absolute(staging, "Android SDK staging")
    if (
        staging.parent != online
        or STAGING_PATTERN.fullmatch(staging.name) is None
    ):
        fail("Android SDK staging is not one reserved online-root child")
    metadata = os.lstat(staging)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("Android SDK staging is not one real directory")
    if metadata.st_dev != online_metadata.st_dev:
        fail("Android SDK staging is not on the online filesystem")
    if (metadata.st_uid, metadata.st_gid) != (uid, gid):
        fail("Android SDK staging is not owned by the acquisition identity")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        fail("Android SDK staging is not mode 0700")
    reject_extended_metadata(staging, metadata, "Android SDK staging")
    reject_mount_at_or_below(staging)
    return metadata


def validate_cmdline_archive(
    online: Path,
    archive: Path,
    uid: int,
    gid: int,
) -> os.stat_result:
    online_metadata = validate_online(online, uid, gid)
    validate_absolute(archive, "Android command-line-tools archive")
    if archive.parent != online:
        fail("Android command-line-tools archive is not a direct online input")
    metadata = os.lstat(archive)
    if not stat.S_ISREG(metadata.st_mode):
        fail("Android command-line-tools archive is not one regular file")
    if metadata.st_dev != online_metadata.st_dev:
        fail("Android command-line-tools archive is not on the online filesystem")
    if (metadata.st_uid, metadata.st_gid) not in ((uid, gid), (0, 0)):
        fail("Android command-line-tools archive has foreign ownership")
    if stat.S_IMODE(metadata.st_mode) != 0o644 or metadata.st_nlink != 1:
        fail("Android command-line-tools archive metadata is unsafe")
    reject_extended_metadata(
        archive,
        metadata,
        "Android command-line-tools archive",
    )
    return metadata


def validate_container(
    path: Path,
    uid: int,
    gid: int,
    *,
    empty: bool,
    allow_root_mount: bool = False,
) -> os.stat_result:
    validate_absolute(path, "Android SDK private container")
    metadata = os.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("Android SDK private container is not one real directory")
    if (metadata.st_uid, metadata.st_gid) != (uid, gid):
        fail("Android SDK private container has the wrong owner")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        fail("Android SDK private container is not mode 0700")
    reject_extended_metadata(path, metadata, "Android SDK private container")
    reject_mount_at_or_below(path, allow_root=allow_root_mount)
    if empty:
        with os.scandir(path) as iterator:
            if next(iterator, None) is not None:
                fail("Android SDK private container is not empty")
    return metadata


def hash_descriptor(descriptor: int, maximum: int) -> tuple[str, int]:
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
            fail("Android SDK archive exceeds its byte bound while hashing")
    return digest.hexdigest(), offset


@contextlib.contextmanager
def stable_archive(
    path: Path,
    spec: PackageSpec,
    expected_sha256: str,
) -> Iterator[zipfile.ZipFile]:
    validate_absolute(path, f"Android SDK {spec.key} archive")
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != spec.size
            or before.st_size > MAX_ARCHIVE_BYTES
        ):
            fail(f"Android SDK {spec.key} archive metadata is unsafe")
        digest, size = hash_descriptor(descriptor, MAX_ARCHIVE_BYTES)
        if digest != expected_sha256 or size != spec.size:
            fail(f"Android SDK {spec.key} archive does not match its pin")
        duplicate = os.dup(descriptor)
        try:
            with os.fdopen(duplicate, "rb") as stream:
                duplicate = -1
                with zipfile.ZipFile(stream, "r") as archive:
                    yield archive
        finally:
            if duplicate >= 0:
                os.close(duplicate)
        after = os.fstat(descriptor)
        if stable_metadata(before) != stable_metadata(after):
            fail(f"Android SDK {spec.key} archive changed while read")
    except zipfile.BadZipFile as error:
        fail(f"Android SDK {spec.key} archive is malformed: {error}")
    finally:
        os.close(descriptor)


def safe_member_name(raw: str, spec: PackageSpec) -> str:
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
        fail(f"Android SDK archive has an unsafe member name: {raw!r}")
    stripped = raw[:-1] if raw.endswith("/") else raw
    parts = stripped.split("/")
    if (
        not parts
        or parts[0] != spec.archive_root
        or len(parts) > MAX_DEPTH
        or any(
            component in ("", ".", "..")
            or len(component.encode("utf-8")) > MAX_COMPONENT_BYTES
            for component in parts
        )
    ):
        fail(f"Android SDK archive member escapes its exact root: {raw!r}")
    relative = "/".join(parts[1:])
    return relative


def executable_member(spec: PackageSpec, relative: str, mode: int) -> bool:
    if spec.key == "cmdline-tools":
        return relative.startswith("bin/") and "/" not in relative[4:]
    return bool(mode & 0o111)


def validate_archive_manifest(
    archive: zipfile.ZipFile,
    spec: PackageSpec,
) -> dict[str, ArchiveEntry]:
    if archive.comment:
        fail(f"Android SDK {spec.key} archive has an unexpected comment")
    infos = archive.infolist()
    if len(infos) != spec.entries:
        fail(f"Android SDK {spec.key} archive entry count changed")
    entries: dict[str, ArchiveEntry] = {}
    files: set[str] = set()
    total_bytes = 0
    for info in infos:
        if info.orig_filename != info.filename:
            fail(f"Android SDK {spec.key} member name was NUL-truncated")
        relative = safe_member_name(info.filename, spec)
        if relative in entries:
            fail(f"Android SDK {spec.key} repeats one member path: {relative}")
        if info.create_system != 3:
            fail(f"Android SDK {spec.key} member lacks Unix type authority")
        if info.flag_bits not in spec.allowed_flags:
            fail(f"Android SDK {spec.key} member has unsupported flags")
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            fail(f"Android SDK {spec.key} member has unsupported compression")
        if info.comment:
            fail(f"Android SDK {spec.key} member has an unexpected comment")
        raw_mode = (info.external_attr >> 16) & 0xFFFF
        mode = stat.S_IMODE(raw_mode)
        if mode not in spec.allowed_modes or raw_mode & FORBIDDEN_MODE_BITS:
            fail(f"Android SDK {spec.key} member mode is outside its pin")
        if info.is_dir():
            if not stat.S_ISDIR(raw_mode) or info.file_size != 0:
                fail(f"Android SDK {spec.key} directory metadata is invalid")
            kind = "directory"
            executable = True
        elif stat.S_ISREG(raw_mode):
            if info.file_size < 0 or info.file_size > MAX_FILE_BYTES:
                fail(f"Android SDK {spec.key} member exceeds its byte bound")
            kind = "file"
            executable = executable_member(spec, relative, mode)
            files.add(relative)
            total_bytes += info.file_size
        else:
            fail(f"Android SDK {spec.key} archive contains a special member")
        if total_bytes > MAX_TOTAL_BYTES:
            fail(f"Android SDK {spec.key} archive exceeds its expanded bound")
        output_relative = (
            spec.destination
            if not relative
            else f"{spec.destination}/{relative}"
        )
        entries[relative] = ArchiveEntry(
            spec.key,
            info.filename,
            output_relative,
            kind,
            executable,
            info.file_size,
        )
    for relative in files:
        parts = relative.split("/")
        for length in range(1, len(parts)):
            if "/".join(parts[:length]) in files:
                fail(
                    f"Android SDK {spec.key} has a file used as a parent: "
                    f"{relative}"
                )
    return entries


def archive_paths(
    cmdline_archive: Path,
    downloads: Path,
) -> dict[str, Path]:
    return {
        spec.key: (
            cmdline_archive
            if spec.local_input
            else downloads / spec.filename
        )
        for spec in SPECS
    }


@contextlib.contextmanager
def validated_archives(
    cmdline_archive: Path,
    downloads: Path,
    pins: dict[str, str],
) -> Iterator[
    tuple[
        dict[str, zipfile.ZipFile],
        dict[str, dict[str, ArchiveEntry]],
    ]
]:
    paths = archive_paths(cmdline_archive, downloads)
    with contextlib.ExitStack() as stack:
        archives: dict[str, zipfile.ZipFile] = {}
        manifests: dict[str, dict[str, ArchiveEntry]] = {}
        for spec in SPECS:
            archive = stack.enter_context(
                stable_archive(paths[spec.key], spec, pins[spec.key])
            )
            archives[spec.key] = archive
            manifests[spec.key] = validate_archive_manifest(archive, spec)
        yield archives, manifests


def compose_manifest(
    manifests: dict[str, dict[str, ArchiveEntry]],
) -> tuple[dict[str, ArchiveEntry], set[str]]:
    files: dict[str, ArchiveEntry] = {}
    directories = {"", "cmdline-tools", "build-tools", "platforms"}
    for spec in SPECS:
        for entry in manifests[spec.key].values():
            relative = entry.output_relative
            if entry.kind == "file":
                if relative in files or relative in directories:
                    fail(f"Android SDK packages collide at {relative}")
                files[relative] = entry
            else:
                if relative in files:
                    fail(f"Android SDK packages collide at {relative}")
                directories.add(relative)
            parts = relative.split("/")
            directories.update(
                "/".join(parts[:length])
                for length in range(1, len(parts))
            )
    if files.keys() & directories:
        fail("Android SDK package file/directory inventory collides")
    if len(files) > MAX_FILES or len(directories) > MAX_DIRECTORIES:
        fail("Android SDK package inventory exceeds its bound")
    return files, directories


def download_packages(
    downloads: Path,
    uid: int,
    gid: int,
    pins: dict[str, str],
) -> None:
    validate_container(
        downloads,
        uid,
        gid,
        empty=True,
        allow_root_mount=True,
    )
    total = 0
    for spec in SPECS:
        if spec.local_input:
            continue
        url = DOWNLOAD_BASE + spec.filename
        destination = downloads / spec.filename
        descriptor = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o600,
        )
        digest = hashlib.sha256()
        written = 0
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                if (
                    response.status != 200
                    or response.geturl() != url
                    or response.headers.get("Content-Encoding") not in (None, "identity")
                ):
                    fail(f"Android SDK {spec.key} download response is unsafe")
                length = response.headers.get("Content-Length")
                if length is None or int(length) != spec.size:
                    fail(f"Android SDK {spec.key} download length changed")
                while True:
                    block = response.read(BLOCK_SIZE)
                    if not block:
                        break
                    written += len(block)
                    total += len(block)
                    if written > spec.size or total > MAX_DOWNLOAD_BYTES:
                        fail("Android SDK downloads exceed their byte bound")
                    digest.update(block)
                    view = memoryview(block)
                    while view:
                        count = os.write(descriptor, view)
                        if count <= 0:
                            fail("short write while acquiring Android SDK package")
                        view = view[count:]
            if written != spec.size or digest.hexdigest() != pins[spec.key]:
                fail(f"Android SDK {spec.key} download does not match its pin")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    fsync_directory(downloads)


def extract_packages(
    cmdline_archive: Path,
    downloads: Path,
    output: Path,
    uid: int,
    gid: int,
    pins: dict[str, str],
) -> None:
    validate_container(
        output,
        uid,
        gid,
        empty=True,
        allow_root_mount=True,
    )
    with validated_archives(
        cmdline_archive,
        downloads,
        pins,
    ) as (archives, manifests):
        files, directories = compose_manifest(manifests)
        root = output / "android-sdk"
        root.mkdir(mode=0o755)
        os.chmod(root, 0o755, follow_symlinks=False)
        for relative in sorted(
            (item for item in directories if item),
            key=lambda item: (item.count("/"), os.fsencode(item)),
        ):
            path = root / relative
            path.mkdir(mode=0o755)
            os.chmod(path, 0o755, follow_symlinks=False)
        for relative, entry in sorted(
            files.items(),
            key=lambda item: os.fsencode(item[0]),
        ):
            path = root / relative
            descriptor = os.open(
                path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
                0o755 if entry.executable else 0o644,
            )
            try:
                written = 0
                with archives[entry.package].open(
                    entry.archive_name,
                    "r",
                ) as source:
                    while True:
                        block = source.read(BLOCK_SIZE)
                        if not block:
                            break
                        written += len(block)
                        view = memoryview(block)
                        while view:
                            count = os.write(descriptor, view)
                            if count <= 0:
                                fail(
                                    "short write while extracting Android SDK "
                                    f"member: {relative}"
                                )
                            view = view[count:]
                if written != entry.size:
                    fail(f"Android SDK member size changed: {relative}")
                os.fchmod(
                    descriptor,
                    0o755 if entry.executable else 0o644,
                )
            finally:
                os.close(descriptor)
    validate_container(
        output,
        uid,
        gid,
        empty=False,
        allow_root_mount=True,
    )


def acquire(
    cmdline_archive: Path,
    downloads: Path,
    output: Path,
    pins: dict[str, str],
) -> None:
    uid = os.getuid()
    gid = os.getgid()
    if uid <= 0 or gid <= 0:
        fail("Android SDK acquisition refuses root UID or GID")
    download_packages(downloads, uid, gid, pins)
    extract_packages(
        cmdline_archive,
        downloads,
        output,
        uid,
        gid,
        pins,
    )


def validate_downloads(
    downloads: Path,
    uid: int,
    gid: int,
) -> None:
    validate_container(downloads, uid, gid, empty=False)
    expected = {
        spec.filename
        for spec in SPECS
        if not spec.local_input
    }
    if set(os.listdir(downloads)) != expected:
        fail("Android SDK download inventory differs from its closed package set")
    for spec in SPECS:
        if spec.local_input:
            continue
        path = downloads / spec.filename
        metadata = os.lstat(path)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != (uid, gid)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != spec.size
        ):
            fail(f"Android SDK {spec.key} download metadata is unsafe")
        reject_extended_metadata(
            path,
            metadata,
            f"Android SDK {spec.key} download",
        )


def validate_observed_name(name: str, relative: str) -> None:
    raw = os.fsencode(name)
    if (
        not raw
        or len(raw) > MAX_COMPONENT_BYTES
        or any(byte < 0x20 or byte > 0x7E for byte in raw)
        or b"\\" in raw
        or raw in (b".", b"..")
    ):
        fail(f"Android SDK output has a nonportable path: {relative!r}")


def collect_output(
    root: Path,
    filesystem: int,
) -> dict[str, os.stat_result]:
    observed = {"": os.lstat(root)}
    pending = [("", root, 0)]
    while pending:
        parent_relative, parent, depth = pending.pop()
        if depth > MAX_DEPTH:
            fail("Android SDK output exceeds its depth bound")
        with os.scandir(parent) as iterator:
            children = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
        for child in children:
            relative = (
                child.name
                if not parent_relative
                else f"{parent_relative}/{child.name}"
            )
            validate_observed_name(child.name, relative)
            if len(relative.encode("utf-8")) > MAX_NAME_BYTES:
                fail(f"Android SDK output path exceeds its bound: {relative}")
            metadata = child.stat(follow_symlinks=False)
            if metadata.st_dev != filesystem:
                fail(f"Android SDK output crosses a filesystem: {relative}")
            observed[relative] = metadata
            if stat.S_ISDIR(metadata.st_mode):
                pending.append((relative, Path(child.path), depth + 1))
    if len(observed) > MAX_ENTRIES:
        fail("Android SDK output entry count exceeds its bound")
    return observed


def update_tree_digest(
    digest,
    relative: str,
    kind: str,
    executable: bool,
    size: int,
    content_digest: bytes | None = None,
) -> None:
    digest.update(kind.encode("ascii"))
    digest.update(b"\0")
    digest.update(relative.encode("ascii"))
    digest.update(b"\0")
    digest.update(b"X" if executable else b"-")
    digest.update(size.to_bytes(8, "big"))
    if content_digest is not None:
        digest.update(content_digest)


def compare_regular(
    archive: zipfile.ZipFile,
    entry: ArchiveEntry,
    path: Path,
) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != entry.size
        ):
            fail(
                "Android SDK output file is not exact, private, and regular: "
                f"{entry.output_relative}"
            )
        digest = hashlib.sha256()
        total = 0
        with archive.open(entry.archive_name, "r") as source:
            while True:
                expected = source.read(BLOCK_SIZE)
                actual = os.read(descriptor, BLOCK_SIZE)
                if expected != actual:
                    fail(
                        "Android SDK output bytes differ from the pinned archive: "
                        f"{entry.output_relative}"
                    )
                if not expected:
                    break
                digest.update(expected)
                total += len(expected)
        if total != entry.size:
            fail(
                "Android SDK output size differs from the pinned archive: "
                f"{entry.output_relative}"
            )
        after = os.fstat(descriptor)
        if stable_metadata(before) != stable_metadata(after):
            fail(
                "Android SDK output file changed while read: "
                f"{entry.output_relative}"
            )
        return digest.digest()
    finally:
        os.close(descriptor)


def expected_mode(
    *,
    kind: str,
    executable: bool,
    profile: str,
    relative: str,
) -> int:
    if profile == "raw":
        return 0o755 if kind == "directory" or executable else 0o644
    if profile == "private-sealed":
        if not relative:
            return 0o700
        return 0o555 if kind == "directory" or executable else 0o444
    if profile == "sealed":
        return 0o555 if kind == "directory" or executable else 0o444
    fail("Android SDK output mode profile is invalid")


def compare_output(
    archives: dict[str, zipfile.ZipFile],
    manifests: dict[str, dict[str, ArchiveEntry]],
    root: Path,
    online_metadata: os.stat_result,
    uid: int,
    gid: int,
    *,
    profile: str,
    expected_identity: tuple[int, int] | None = None,
) -> TreeSummary:
    validate_absolute(root, "Android SDK output")
    reject_mount_at_or_below(root)
    files, directories = compose_manifest(manifests)
    observed = collect_output(root, online_metadata.st_dev)
    expected_inventory = set(files) | directories
    if set(observed) != expected_inventory:
        fail("Android SDK output inventory differs from the pinned archives")
    if expected_identity is not None and identity(observed[""]) != expected_identity:
        fail("Android SDK output identity changed")
    digest = hashlib.sha256(b"rustdesk-android-sdk-tree-v1\0")
    file_count = 0
    directory_count = 0
    total_bytes = 0
    for relative in sorted(expected_inventory, key=os.fsencode):
        metadata = observed[relative]
        path = root if not relative else root / relative
        if (metadata.st_uid, metadata.st_gid) != (uid, gid):
            fail(f"Android SDK output has foreign ownership: {relative or '.'}")
        reject_extended_metadata(
            path,
            metadata,
            f"Android SDK output {relative or '.'}",
        )
        if relative in directories:
            kind = "directory"
            executable = True
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                fail(f"Android SDK output directory changed type: {relative or '.'}")
            directory_count += 1
            size = 0
            content_digest = None
        else:
            entry = files[relative]
            kind = "file"
            executable = entry.executable
            if not stat.S_ISREG(metadata.st_mode):
                fail(f"Android SDK output file changed type: {relative}")
            content_digest = compare_regular(
                archives[entry.package],
                entry,
                path,
            )
            file_count += 1
            size = metadata.st_size
            total_bytes += size
        wanted = expected_mode(
            kind=kind,
            executable=executable,
            profile=profile,
            relative=relative,
        )
        if stat.S_IMODE(metadata.st_mode) != wanted:
            fail(f"Android SDK output mode differs from its profile: {relative or '.'}")
        update_tree_digest(
            digest,
            relative,
            kind,
            executable,
            size,
            content_digest,
        )
    if (
        file_count > MAX_FILES
        or directory_count > MAX_DIRECTORIES
        or total_bytes > MAX_TOTAL_BYTES
    ):
        fail("Android SDK output exceeds its closed type or byte bound")
    return TreeSummary(
        digest.hexdigest(),
        file_count,
        directory_count,
        total_bytes,
    )


def digest_regular(path: Path, metadata: os.stat_result) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        before = os.fstat(descriptor)
        if stable_metadata(before) != stable_metadata(metadata):
            fail(f"Android SDK file changed before read: {path}")
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(descriptor, BLOCK_SIZE)
            if not block:
                break
            total += len(block)
            if total > MAX_FILE_BYTES:
                fail(f"Android SDK file exceeds its byte bound: {path}")
            digest.update(block)
        after = os.fstat(descriptor)
        if stable_metadata(before) != stable_metadata(after):
            fail(f"Android SDK file changed while read: {path}")
        return digest.digest()
    finally:
        os.close(descriptor)


def inspect_sealed_tree(
    root: Path,
    online_metadata: os.stat_result,
    uid: int,
    gid: int,
    *,
    expected_identity: tuple[int, int] | None = None,
) -> TreeSummary:
    validate_absolute(root, "published Android SDK")
    reject_mount_at_or_below(root)
    observed = collect_output(root, online_metadata.st_dev)
    if expected_identity is not None and identity(observed[""]) != expected_identity:
        fail("published Android SDK identity changed")
    digest = hashlib.sha256(b"rustdesk-android-sdk-tree-v1\0")
    file_count = 0
    directory_count = 0
    total_bytes = 0
    for relative in sorted(observed, key=os.fsencode):
        metadata = observed[relative]
        path = root if not relative else root / relative
        if (metadata.st_uid, metadata.st_gid) != (uid, gid):
            fail(f"published Android SDK has foreign ownership: {relative or '.'}")
        reject_extended_metadata(
            path,
            metadata,
            f"published Android SDK {relative or '.'}",
        )
        mode = stat.S_IMODE(metadata.st_mode)
        if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
            if mode != 0o555:
                fail(f"published Android SDK directory is not sealed: {relative or '.'}")
            kind = "directory"
            executable = True
            size = 0
            content_digest = None
            directory_count += 1
        elif stat.S_ISREG(metadata.st_mode):
            if metadata.st_nlink != 1:
                fail(f"published Android SDK file is multiply linked: {relative}")
            if mode not in (0o444, 0o555):
                fail(f"published Android SDK file is not sealed: {relative}")
            if metadata.st_size > MAX_FILE_BYTES:
                fail(f"published Android SDK file exceeds its bound: {relative}")
            kind = "file"
            executable = mode == 0o555
            size = metadata.st_size
            content_digest = digest_regular(path, metadata)
            file_count += 1
            total_bytes += size
        elif stat.S_ISLNK(metadata.st_mode):
            fail(f"published Android SDK contains a symlink: {relative}")
        else:
            fail(f"published Android SDK contains a special file: {relative}")
        update_tree_digest(
            digest,
            relative,
            kind,
            executable,
            size,
            content_digest,
        )
    if (
        file_count > MAX_FILES
        or directory_count > MAX_DIRECTORIES
        or total_bytes > MAX_TOTAL_BYTES
    ):
        fail("published Android SDK exceeds its closed type or byte bound")
    return TreeSummary(
        digest.hexdigest(),
        file_count,
        directory_count,
        total_bytes,
    )


def required_summary() -> TreeSummary:
    if (
        TREE_DIGEST_PATTERN.fullmatch(EXPECTED_TREE_DIGEST) is None
        or EXPECTED_TREE_FILES <= 0
        or EXPECTED_TREE_DIRECTORIES <= 0
        or EXPECTED_TREE_BYTES <= 0
    ):
        fail("Android SDK expected tree authority is not configured")
    return TreeSummary(
        EXPECTED_TREE_DIGEST,
        EXPECTED_TREE_FILES,
        EXPECTED_TREE_DIRECTORIES,
        EXPECTED_TREE_BYTES,
    )


def validate_required_summary(summary: TreeSummary) -> None:
    if summary != required_summary():
        fail("Android SDK tree does not match its independently recorded closure")


def require_file(
    path: Path,
    *,
    executable: bool = False,
    nonempty: bool = False,
) -> None:
    metadata = os.lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail(f"required Android SDK entry is not one regular file: {path}")
    if executable and not metadata.st_mode & 0o111:
        fail(f"required Android SDK entry is not executable: {path}")
    if nonempty and metadata.st_size == 0:
        fail(f"required Android SDK entry is empty: {path}")


def require_property(path: Path, key: str, expected: str) -> None:
    require_file(path, nonempty=True)
    metadata = os.lstat(path)
    if metadata.st_size > 1024 * 1024:
        fail(f"Android SDK property file exceeds its byte bound: {path}")
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


def validate_semantics(root: Path) -> None:
    require_property(
        root / "cmdline-tools" / "latest" / "source.properties",
        "Pkg.Revision",
        "21.0",
    )
    require_file(
        root / "cmdline-tools" / "latest" / "bin" / "sdkmanager",
        executable=True,
        nonempty=True,
    )
    require_property(
        root / "platform-tools" / "source.properties",
        "Pkg.Revision",
        "37.0.1",
    )
    require_file(
        root / "platform-tools" / "adb",
        executable=True,
        nonempty=True,
    )
    for version in ("30.0.3", "34.0.0"):
        tools = root / "build-tools" / version
        require_property(tools / "source.properties", "Pkg.Revision", version)
        for name in ("aapt2", "apksigner", "zipalign"):
            require_file(tools / name, executable=True, nonempty=True)
    for api in ("31", "32", "33", "34"):
        platform = root / "platforms" / f"android-{api}"
        require_property(
            platform / "source.properties",
            "AndroidVersion.ApiLevel",
            api,
        )
        require_file(platform / "android.jar", nonempty=True)


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
    files: dict[str, ArchiveEntry],
    directories: set[str],
) -> None:
    for relative, entry in sorted(files.items(), key=lambda item: os.fsencode(item[0])):
        path = root / relative
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                fail(f"cannot seal nonprivate Android SDK file: {relative}")
            os.fchmod(descriptor, 0o555 if entry.executable else 0o444)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    for relative in sorted(
        directories,
        key=lambda item: (item.count("/"), os.fsencode(item)),
        reverse=True,
    ):
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
        fail("Android SDK transaction state exceeds its byte bound")
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
                fail("short write while recording Android SDK transaction state")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, state)
    fsync_directory(staging)


def state_payload(
    online: Path,
    staging: Path,
    downloads: Path,
    output: Path,
    cmdline_archive: Path,
    uid: int,
    gid: int,
    pins: dict[str, str],
    builder: str,
) -> dict[str, object]:
    return {
        "state_version": STATE_VERSION,
        "online": os.fspath(online),
        "online_identity": encode_identity(identity(os.lstat(online))),
        "staging": os.fspath(staging),
        "staging_identity": encode_identity(identity(os.lstat(staging))),
        "downloads_identity": encode_identity(identity(os.lstat(downloads))),
        "output_identity": encode_identity(identity(os.lstat(output))),
        "cmdline_archive": os.fspath(cmdline_archive),
        "cmdline_archive_identity": encode_identity(
            identity(os.lstat(cmdline_archive))
        ),
        "uid": uid,
        "gid": gid,
        "pins": dict(sorted(pins.items())),
        "builder": builder,
        "destination": "android-sdk",
        "verified": False,
        "candidate_identity": None,
        "tree_digest": None,
    }


def read_regular(path: Path, maximum: int) -> tuple[bytes, os.stat_result]:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
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
    cmdline_archive: Path,
    uid: int,
    gid: int,
    pins: dict[str, str],
    builder: str,
) -> dict[str, object]:
    validate_builder(builder)
    if set(pins) != PIN_KEYS:
        fail("Android SDK package-pin set changed")
    staging_metadata = validate_staging(online, staging, uid, gid)
    cmdline_metadata = validate_cmdline_archive(
        online,
        cmdline_archive,
        uid,
        gid,
    )
    data, metadata = read_regular(staging / STATE_NAME, MAX_STATE_BYTES)
    if (
        (metadata.st_uid, metadata.st_gid) != (uid, gid)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        fail("Android SDK transaction state metadata is invalid")
    try:
        payload = json.loads(data.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"Android SDK transaction state is malformed: {error}")
    expected_keys = {
        "state_version",
        "online",
        "online_identity",
        "staging",
        "staging_identity",
        "downloads_identity",
        "output_identity",
        "cmdline_archive",
        "cmdline_archive_identity",
        "uid",
        "gid",
        "pins",
        "builder",
        "destination",
        "verified",
        "candidate_identity",
        "tree_digest",
    }
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        fail("Android SDK transaction state has an unexpected schema")
    expected_values = {
        "state_version": STATE_VERSION,
        "online": os.fspath(online),
        "staging": os.fspath(staging),
        "cmdline_archive": os.fspath(cmdline_archive),
        "uid": uid,
        "gid": gid,
        "pins": dict(sorted(pins.items())),
        "builder": builder,
        "destination": "android-sdk",
    }
    for key, expected in expected_values.items():
        if payload[key] != expected:
            fail(f"Android SDK transaction state changed its {key} binding")
    if type(payload["verified"]) is not bool:
        fail("Android SDK transaction verification state is malformed")
    if payload["verified"]:
        decode_identity(payload["candidate_identity"], "Android SDK candidate")
        if (
            not isinstance(payload["tree_digest"], str)
            or TREE_DIGEST_PATTERN.fullmatch(payload["tree_digest"]) is None
        ):
            fail("Android SDK transaction tree digest is malformed")
    elif payload["candidate_identity"] is not None or payload["tree_digest"] is not None:
        fail("unverified Android SDK transaction carries output authority")
    if decode_identity(payload["online_identity"], "online root") != identity(
        os.lstat(online)
    ):
        fail("online root identity changed during the Android SDK transaction")
    if decode_identity(payload["staging_identity"], "Android SDK staging") != identity(
        staging_metadata
    ):
        fail("Android SDK staging identity changed")
    downloads_metadata = validate_container(
        staging / "downloads",
        uid,
        gid,
        empty=False,
    )
    if decode_identity(
        payload["downloads_identity"],
        "Android SDK downloads",
    ) != identity(downloads_metadata):
        fail("Android SDK downloads container identity changed")
    output_metadata = validate_container(
        staging / "output",
        uid,
        gid,
        empty=False,
    )
    if decode_identity(
        payload["output_identity"],
        "Android SDK output",
    ) != identity(output_metadata):
        fail("Android SDK output container identity changed")
    if decode_identity(
        payload["cmdline_archive_identity"],
        "Android command-line-tools archive",
    ) != identity(cmdline_metadata):
        fail("Android command-line-tools archive identity changed")
    return payload


def validate_cmdline_package(
    cmdline_archive: Path,
    pins: dict[str, str],
) -> None:
    spec = SPEC_BY_KEY["cmdline-tools"]
    with stable_archive(
        cmdline_archive,
        spec,
        pins[spec.key],
    ) as archive:
        validate_archive_manifest(archive, spec)


def prepare(
    online: Path,
    staging: Path,
    cmdline_archive: Path,
    uid: int,
    gid: int,
    pins: dict[str, str],
    builder: str,
) -> None:
    validate_staging(online, staging, uid, gid)
    validate_inventory(staging, set(), "Android SDK staging")
    validate_cmdline_archive(online, cmdline_archive, uid, gid)
    validate_cmdline_package(cmdline_archive, pins)
    validate_builder(builder)
    destination = online / "android-sdk"
    if destination.exists() or destination.is_symlink():
        fail("Android SDK destination exists before a new transaction")
    downloads = staging / "downloads"
    output = staging / "output"
    downloads.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    write_state(
        staging,
        state_payload(
            online,
            staging,
            downloads,
            output,
            cmdline_archive,
            uid,
            gid,
            pins,
            builder,
        ),
    )
    validate_inventory(
        staging,
        {STATE_NAME, "downloads", "output"},
        "Android SDK staging",
    )
    fsync_directory(online)


def verify_staged(
    online: Path,
    staging: Path,
    cmdline_archive: Path,
    uid: int,
    gid: int,
    pins: dict[str, str],
    builder: str,
) -> None:
    payload = load_state(
        online,
        staging,
        cmdline_archive,
        uid,
        gid,
        pins,
        builder,
    )
    validate_inventory(
        staging,
        {STATE_NAME, "downloads", "output"},
        "Android SDK staging",
    )
    downloads = staging / "downloads"
    output = staging / "output"
    validate_downloads(downloads, uid, gid)
    candidate = output / "android-sdk"
    with validated_archives(
        cmdline_archive,
        downloads,
        pins,
    ) as (archives, manifests):
        files, directories = compose_manifest(manifests)
        if payload["verified"]:
            expected = decode_identity(
                payload["candidate_identity"],
                "Android SDK candidate",
            )
            summary = compare_output(
                archives,
                manifests,
                candidate,
                os.lstat(online),
                uid,
                gid,
                profile="private-sealed",
                expected_identity=expected,
            )
            validate_required_summary(summary)
            if summary.digest != payload["tree_digest"]:
                fail("Android SDK sealed tree digest changed")
            validate_semantics(candidate)
            return
        summary = compare_output(
            archives,
            manifests,
            candidate,
            os.lstat(online),
            uid,
            gid,
            profile="raw",
        )
        validate_required_summary(summary)
        validate_semantics(candidate)
        candidate_identity = identity(os.lstat(candidate))
        seal_and_sync_tree(candidate, files, directories)
        sealed = compare_output(
            archives,
            manifests,
            candidate,
            os.lstat(online),
            uid,
            gid,
            profile="private-sealed",
            expected_identity=candidate_identity,
        )
        if sealed != summary:
            fail("Android SDK tree changed while sealing")
    payload["verified"] = True
    payload["candidate_identity"] = encode_identity(candidate_identity)
    payload["tree_digest"] = summary.digest
    write_state(staging, payload)


def check_complete(
    online: Path,
    cmdline_archive: Path,
    uid: int,
    gid: int,
    pins: dict[str, str],
    builder: str,
) -> None:
    validate_builder(builder)
    online_metadata = validate_online(online, uid, gid)
    validate_cmdline_archive(online, cmdline_archive, uid, gid)
    validate_cmdline_package(cmdline_archive, pins)
    output = online / "android-sdk"
    metadata = os.lstat(output)
    summary = inspect_sealed_tree(
        output,
        online_metadata,
        uid,
        gid,
        expected_identity=identity(metadata),
    )
    validate_required_summary(summary)
    validate_semantics(output)


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


def transition_directory_mode(
    path: Path,
    expected_identity: tuple[int, int],
    old_mode: int,
    new_mode: int,
    label: str,
) -> None:
    descriptor = open_directory(path)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(before.st_mode)
            or identity(before) != expected_identity
            or stat.S_IMODE(before.st_mode) != old_mode
        ):
            fail(f"{label} identity or mode changed")
        os.fchmod(descriptor, new_mode)
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if (
            identity(after) != expected_identity
            or stat.S_IMODE(after.st_mode) != new_mode
        ):
            fail(f"{label} mode transition did not persist")
    finally:
        os.close(descriptor)


def restore_published_root_for_rollback(
    destination: Path,
    expected_identity: tuple[int, int],
) -> None:
    metadata = os.lstat(destination)
    if identity(metadata) != expected_identity:
        fail("published Android SDK identity changed before rollback")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode == 0o555:
        transition_directory_mode(
            destination,
            expected_identity,
            0o555,
            0o700,
            "published Android SDK rollback root",
        )
    elif mode != 0o700:
        fail("published Android SDK root mode is unsafe for rollback")


def publish(
    online: Path,
    staging: Path,
    cmdline_archive: Path,
    uid: int,
    gid: int,
    pins: dict[str, str],
    builder: str,
) -> None:
    verify_staged(
        online,
        staging,
        cmdline_archive,
        uid,
        gid,
        pins,
        builder,
    )
    payload = load_state(
        online,
        staging,
        cmdline_archive,
        uid,
        gid,
        pins,
        builder,
    )
    expected = decode_identity(
        payload["candidate_identity"],
        "Android SDK candidate",
    )
    output = staging / "output"
    candidate = output / "android-sdk"
    destination = online / "android-sdk"
    if destination.exists() or destination.is_symlink():
        fail("Android SDK destination appeared before no-clobber publication")
    fsync_directory(output)
    fsync_directory(staging)
    output_fd = open_directory(output)
    online_fd = open_directory(online)
    moved = False
    try:
        renameat2(
            output_fd,
            "android-sdk",
            online_fd,
            "android-sdk",
            RENAME_NOREPLACE,
        )
        moved = True
        os.fsync(output_fd)
        os.fsync(online_fd)
        transition_directory_mode(
            destination,
            expected,
            0o700,
            0o555,
            "published Android SDK root",
        )
        os.fsync(online_fd)
        summary = inspect_sealed_tree(
            destination,
            os.lstat(online),
            uid,
            gid,
            expected_identity=expected,
        )
        validate_required_summary(summary)
        if summary.digest != payload["tree_digest"]:
            fail("published Android SDK tree digest changed")
        validate_semantics(destination)
    except BaseException as primary:
        if moved:
            try:
                restore_published_root_for_rollback(destination, expected)
                renameat2(
                    online_fd,
                    "android-sdk",
                    output_fd,
                    "android-sdk",
                    RENAME_NOREPLACE,
                )
                os.fsync(output_fd)
                os.fsync(online_fd)
            except BaseException as rollback:
                primary.add_note(
                    "Android SDK publication rollback also failed: "
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
    allowed = {"downloads", "output"}
    if names == allowed | {temporary_state}:
        _data, metadata = read_regular(
            staging / temporary_state,
            MAX_STATE_BYTES,
        )
        if (
            (metadata.st_uid, metadata.st_gid) != (uid, gid)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            fail("unprepared Android SDK state write is unsafe and was preserved")
        disposition = "unprepared-state-write"
    elif names == allowed:
        disposition = "unprepared-containers"
    else:
        fail("unprepared Android SDK staging is incoherent and was preserved")
    validate_container(staging / "downloads", uid, gid, empty=True)
    validate_container(staging / "output", uid, gid, empty=True)
    return disposition


def complete_published_recovery(
    online: Path,
    staging: Path,
    destination: Path,
    cmdline_archive: Path,
    uid: int,
    gid: int,
    pins: dict[str, str],
    payload: dict[str, object],
    expected: tuple[int, int],
) -> None:
    online_metadata = os.lstat(online)
    metadata = os.lstat(destination)
    if identity(metadata) != expected:
        fail("published Android SDK identity changed during recovery")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode == 0o700:
        downloads = staging / "downloads"
        validate_downloads(downloads, uid, gid)
        with validated_archives(
            cmdline_archive,
            downloads,
            pins,
        ) as (archives, manifests):
            summary = compare_output(
                archives,
                manifests,
                destination,
                online_metadata,
                uid,
                gid,
                profile="private-sealed",
                expected_identity=expected,
            )
        validate_required_summary(summary)
        if summary.digest != payload["tree_digest"]:
            fail("unsealed published Android SDK tree digest changed")
        validate_semantics(destination)
        transition_directory_mode(
            destination,
            expected,
            0o700,
            0o555,
            "recovered Android SDK publication root",
        )
        fsync_directory(online)
    elif mode != 0o555:
        fail("published Android SDK root has an incoherent recovery mode")
    summary = inspect_sealed_tree(
        destination,
        os.lstat(online),
        uid,
        gid,
        expected_identity=expected,
    )
    validate_required_summary(summary)
    if summary.digest != payload["tree_digest"]:
        fail("recovered Android SDK tree digest changed")
    validate_semantics(destination)


def recover(
    online: Path,
    staging: Path,
    cmdline_archive: Path,
    uid: int,
    gid: int,
    pins: dict[str, str],
    builder: str,
) -> str:
    state = staging / STATE_NAME
    if not state.exists() and not state.is_symlink():
        return recover_unprepared(online, staging, uid, gid)
    payload = load_state(
        online,
        staging,
        cmdline_archive,
        uid,
        gid,
        pins,
        builder,
    )
    validate_inventory(
        staging,
        {STATE_NAME, "downloads", "output"},
        "Android SDK staging",
    )
    output = staging / "output"
    private_candidate = optional_identity(output / "android-sdk")
    destination = online / "android-sdk"
    live_candidate = optional_identity(destination)
    if not payload["verified"]:
        if live_candidate is not None:
            fail("unverified Android SDK transaction reached a final name")
        return (
            "unverified-unpublished"
            if private_candidate is not None
            else "prepared-empty"
        )
    expected = decode_identity(
        payload["candidate_identity"],
        "Android SDK candidate",
    )
    if private_candidate == expected:
        if live_candidate is None:
            return "verified-unpublished"
        return "verified-unpublished-destination-occupied"
    if private_candidate is None and live_candidate == expected:
        complete_published_recovery(
            online,
            staging,
            destination,
            cmdline_archive,
            uid,
            gid,
            pins,
            payload,
            expected,
        )
        return "published"
    fail("Android SDK output transaction state is incoherent and was preserved")


def make_zip_info(name: str, kind: str, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = (
        (stat.S_IFDIR if kind == "directory" else stat.S_IFREG) | mode
    ) << 16
    info.compress_type = (
        zipfile.ZIP_STORED
        if kind == "directory"
        else zipfile.ZIP_DEFLATED
    )
    return info


def fixture_members(
    root: str,
    files: dict[str, tuple[int, bytes]],
) -> list[tuple[str, str, int, bytes]]:
    directories = {""}
    for relative in files:
        parts = relative.split("/")
        directories.update(
            "/".join(parts[:length])
            for length in range(1, len(parts))
        )
    members = [
        (
            f"{root}/{relative}/" if relative else f"{root}/",
            "directory",
            0o755,
            b"",
        )
        for relative in sorted(
            directories,
            key=lambda item: (item.count("/"), os.fsencode(item)),
        )
    ]
    members.extend(
        (
            f"{root}/{relative}",
            "file",
            mode,
            data,
        )
        for relative, (mode, data) in sorted(files.items())
    )
    return members


def write_fixture_archive(
    path: Path,
    root: str,
    files: dict[str, tuple[int, bytes]],
    *,
    extra: tuple[str, str, int, bytes] | None = None,
) -> tuple[str, int]:
    members = fixture_members(root, files)
    if extra is not None:
        members.append(extra)
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message=r"Duplicate name: .*",
            category=UserWarning,
        )
        with zipfile.ZipFile(path, "w") as archive:
            for name, kind, mode, data in members:
                archive.writestr(make_zip_info(name, kind, mode), data)
    return hashlib.sha256(path.read_bytes()).hexdigest(), len(members)


def make_staging(online: Path) -> Path:
    return Path(
        tempfile.mkdtemp(
            prefix=".rustdesk-android-sdk.",
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
    except (
        OSError,
        SdkOutputError,
        UnicodeError,
        ValueError,
        zipfile.BadZipFile,
    ):
        return
    fail(message)


def fake_package_definitions() -> list[
    tuple[str, str, str, str, bool, dict[str, tuple[int, bytes]]]
]:
    packages = [
        (
            "cmdline-tools",
            "android-cmdline-tools.zip",
            "cmdline",
            "cmdline-tools/latest",
            True,
            {
                "source.properties": (0o644, b"Pkg.Revision=21.0\n"),
                "bin/sdkmanager": (0o755, b"#!/bin/sh\n"),
            },
        )
    ]
    packages.append(
        (
            "platform-tools",
            "platform-tools.zip",
            "platform-tools",
            "platform-tools",
            False,
            {
                "source.properties": (0o644, b"Pkg.Revision=37.0.1\n"),
                "adb": (0o755, b"adb\n"),
            },
        )
    )
    for version in ("30.0.3", "34.0.0"):
        packages.append(
            (
                f"build-tools-{version}",
                f"build-tools-{version}.zip",
                f"build-tools-{version}",
                f"build-tools/{version}",
                False,
                {
                    "source.properties": (
                        0o644,
                        f"Pkg.Revision={version}\n".encode("ascii"),
                    ),
                    "aapt2": (0o755, b"aapt2\n"),
                    "apksigner": (0o755, b"apksigner\n"),
                    "zipalign": (0o755, b"zipalign\n"),
                },
            )
        )
    for api in ("31", "32", "33", "34"):
        packages.append(
            (
                f"platform-{api}",
                f"platform-{api}.zip",
                f"platform-{api}",
                f"platforms/android-{api}",
                False,
                {
                    "source.properties": (
                        0o644,
                        f"AndroidVersion.ApiLevel={api}\n".encode("ascii"),
                    ),
                    "android.jar": (0o644, f"android-{api}\n".encode("ascii")),
                },
            )
        )
    return packages


def build_fake_archives(
    source: Path,
) -> tuple[tuple[PackageSpec, ...], dict[str, str]]:
    source.mkdir()
    specs = []
    pins = {}
    for key, filename, root, destination, local, files in fake_package_definitions():
        path = source / filename
        digest, entries = write_fixture_archive(path, root, files)
        specs.append(
            PackageSpec(
                key,
                filename,
                path.stat().st_size,
                root,
                destination,
                entries,
                frozenset({0o644, 0o755}),
                frozenset({0}),
                local,
            )
        )
        pins[key] = digest
    return tuple(specs), pins


def run_self_test() -> None:
    uid = os.getuid()
    gid = os.getgid()
    if uid <= 0 or gid <= 0:
        fail("Android SDK transaction self-test refuses root UID or GID")
    builder = "sha256:" + "3" * 64
    global SPECS, SPEC_BY_KEY, PIN_KEYS
    global EXPECTED_TREE_DIGEST, EXPECTED_TREE_FILES
    global EXPECTED_TREE_DIRECTORIES, EXPECTED_TREE_BYTES
    saved = (
        SPECS,
        SPEC_BY_KEY,
        PIN_KEYS,
        EXPECTED_TREE_DIGEST,
        EXPECTED_TREE_FILES,
        EXPECTED_TREE_DIRECTORIES,
        EXPECTED_TREE_BYTES,
    )
    with tempfile.TemporaryDirectory(
        prefix="android-sdk-output-self-test."
    ) as temporary:
        root = Path(temporary)
        try:
            specs, pins = build_fake_archives(root / "authority")
            SPECS = specs
            SPEC_BY_KEY = {spec.key: spec for spec in SPECS}
            PIN_KEYS = frozenset(SPEC_BY_KEY)

            def fixture(base: Path) -> tuple[Path, Path, Path]:
                base.mkdir()
                online = base / "online"
                online.mkdir(mode=0o700)
                cmdline = online / "android-cmdline-tools.zip"
                cmdline.write_bytes(
                    (root / "authority" / "android-cmdline-tools.zip").read_bytes()
                )
                cmdline.chmod(0o644)
                staging = make_staging(online)
                prepare(
                    online,
                    staging,
                    cmdline,
                    uid,
                    gid,
                    pins,
                    builder,
                )
                for spec in SPECS:
                    if spec.local_input:
                        continue
                    destination = staging / "downloads" / spec.filename
                    destination.write_bytes(
                        (root / "authority" / spec.filename).read_bytes()
                    )
                    destination.chmod(0o600)
                previous_umask = os.umask(0o077)
                try:
                    extract_packages(
                        cmdline,
                        staging / "downloads",
                        staging / "output",
                        uid,
                        gid,
                        pins,
                    )
                finally:
                    os.umask(previous_umask)
                return online, staging, cmdline

            online, staging, cmdline = fixture(root / "normal")
            with validated_archives(
                cmdline,
                staging / "downloads",
                pins,
            ) as (archives, manifests):
                summary = compare_output(
                    archives,
                    manifests,
                    staging / "output" / "android-sdk",
                    os.lstat(online),
                    uid,
                    gid,
                    profile="raw",
                )
            EXPECTED_TREE_DIGEST = summary.digest
            EXPECTED_TREE_FILES = summary.files
            EXPECTED_TREE_DIRECTORIES = summary.directories
            EXPECTED_TREE_BYTES = summary.bytes
            verify_staged(
                online,
                staging,
                cmdline,
                uid,
                gid,
                pins,
                builder,
            )
            publish(
                online,
                staging,
                cmdline,
                uid,
                gid,
                pins,
                builder,
            )
            if recover(
                online,
                staging,
                cmdline,
                uid,
                gid,
                pins,
                builder,
            ) != "published":
                fail("self-test did not classify completed Android SDK publication")
            check_complete(
                online,
                cmdline,
                uid,
                gid,
                pins,
                builder,
            )

            online, staging, cmdline = fixture(root / "post-rename-recovery")
            verify_staged(
                online,
                staging,
                cmdline,
                uid,
                gid,
                pins,
                builder,
            )
            payload = load_state(
                online,
                staging,
                cmdline,
                uid,
                gid,
                pins,
                builder,
            )
            expected = decode_identity(
                payload["candidate_identity"],
                "Android SDK candidate",
            )
            output_fd = open_directory(staging / "output")
            online_fd = open_directory(online)
            try:
                renameat2(
                    output_fd,
                    "android-sdk",
                    online_fd,
                    "android-sdk",
                    RENAME_NOREPLACE,
                )
                os.fsync(output_fd)
                os.fsync(online_fd)
            finally:
                os.close(online_fd)
                os.close(output_fd)
            if (
                identity(os.lstat(online / "android-sdk")) != expected
                or stat.S_IMODE(os.lstat(online / "android-sdk").st_mode)
                != 0o700
            ):
                fail("self-test did not create the post-rename recovery state")
            if recover(
                online,
                staging,
                cmdline,
                uid,
                gid,
                pins,
                builder,
            ) != "published":
                fail("self-test did not complete post-rename SDK publication")
            if stat.S_IMODE(os.lstat(online / "android-sdk").st_mode) != 0o555:
                fail("self-test did not seal the recovered SDK root")
            check_complete(
                online,
                cmdline,
                uid,
                gid,
                pins,
                builder,
            )

            online, staging, cmdline = fixture(root / "tamper")
            (
                staging
                / "output"
                / "android-sdk"
                / "platforms"
                / "android-34"
                / "android.jar"
            ).write_bytes(b"tampered\n")
            expect_failure(
                lambda: verify_staged(
                    online,
                    staging,
                    cmdline,
                    uid,
                    gid,
                    pins,
                    builder,
                ),
                "self-test accepted changed Android SDK output bytes",
            )

            online, staging, cmdline = fixture(root / "extra")
            (staging / "output" / "android-sdk" / "unexpected").write_bytes(b"x")
            expect_failure(
                lambda: verify_staged(
                    online,
                    staging,
                    cmdline,
                    uid,
                    gid,
                    pins,
                    builder,
                ),
                "self-test accepted an extra Android SDK output",
            )

            online, staging, cmdline = fixture(root / "hardlink")
            target = (
                staging
                / "output"
                / "android-sdk"
                / "platforms"
                / "android-34"
                / "android.jar"
            )
            os.link(target, online / "external-link")
            expect_failure(
                lambda: verify_staged(
                    online,
                    staging,
                    cmdline,
                    uid,
                    gid,
                    pins,
                    builder,
                ),
                "self-test accepted externally hardlinked Android SDK output",
            )

            online, staging, cmdline = fixture(root / "occupied")
            verify_staged(
                online,
                staging,
                cmdline,
                uid,
                gid,
                pins,
                builder,
            )
            (online / "android-sdk").mkdir()
            expect_failure(
                lambda: publish(
                    online,
                    staging,
                    cmdline,
                    uid,
                    gid,
                    pins,
                    builder,
                ),
                "self-test accepted an occupied Android SDK destination",
            )
            if recover(
                online,
                staging,
                cmdline,
                uid,
                gid,
                pins,
                builder,
            ) != "verified-unpublished-destination-occupied":
                fail("self-test did not preserve occupied Android SDK destination")

            expect_failure(
                lambda: stable_archive(
                    cmdline,
                    SPEC_BY_KEY["cmdline-tools"],
                    "0" * 64,
                ).__enter__(),
                "self-test accepted a wrong Android SDK archive digest",
            )

            malformed = root / "malformed.zip"
            spec = SPEC_BY_KEY["cmdline-tools"]
            digest, entries = write_fixture_archive(
                malformed,
                spec.archive_root,
                {
                    "source.properties": (0o644, b"Pkg.Revision=21.0\n"),
                    "bin/sdkmanager": (0o755, b"#!/bin/sh\n"),
                },
                extra=(
                    f"{spec.archive_root}/../escape",
                    "file",
                    0o644,
                    b"x",
                ),
            )
            malformed_spec = PackageSpec(
                spec.key,
                malformed.name,
                malformed.stat().st_size,
                spec.archive_root,
                spec.destination,
                entries,
                frozenset({0o644, 0o755}),
                frozenset({0}),
                True,
            )
            expect_failure(
                lambda: _validate_fixture_archive(
                    malformed,
                    malformed_spec,
                    digest,
                ),
                "self-test accepted Android SDK archive path traversal",
            )
        finally:
            make_writable(root)
            (
                SPECS,
                SPEC_BY_KEY,
                PIN_KEYS,
                EXPECTED_TREE_DIGEST,
                EXPECTED_TREE_FILES,
                EXPECTED_TREE_DIRECTORIES,
                EXPECTED_TREE_BYTES,
            ) = saved


def _validate_fixture_archive(
    path: Path,
    spec: PackageSpec,
    digest: str,
) -> None:
    with stable_archive(path, spec, digest) as archive:
        validate_archive_manifest(archive, spec)


def add_transaction_arguments(
    parser: argparse.ArgumentParser,
    *,
    staging: bool,
) -> None:
    parser.add_argument("--online", type=Path, required=True)
    if staging:
        parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--cmdline-archive", type=Path, required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    parser.add_argument("--builder", required=True)
    parser.add_argument(
        "--package-pin",
        action="append",
        default=[],
        required=True,
    )


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    acquire_parser = subparsers.add_parser("acquire")
    acquire_parser.add_argument("--cmdline-archive", type=Path, required=True)
    acquire_parser.add_argument("--downloads", type=Path, required=True)
    acquire_parser.add_argument("--output", type=Path, required=True)
    acquire_parser.add_argument(
        "--package-pin",
        action="append",
        default=[],
        required=True,
    )
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
        print("online-android-sdk-output: self-test OK")
        return 0
    pins = parse_pins(arguments.package_pin)
    if arguments.command == "acquire":
        acquire(
            arguments.cmdline_archive,
            arguments.downloads,
            arguments.output,
            pins,
        )
        return 0
    if arguments.uid <= 0 or arguments.gid <= 0:
        fail("Android SDK transaction owner must be a nonzero UID and GID")
    values = (
        arguments.online,
        arguments.cmdline_archive,
        arguments.uid,
        arguments.gid,
        pins,
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
        fail("unsupported Android SDK transaction command")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        OSError,
        SdkOutputError,
        UnicodeError,
        ValueError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ) as error:
        raise SystemExit(f"online-android-sdk-output: {error}")
