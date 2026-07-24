#!/usr/bin/env python3
"""Validate and publish the exact Windows flutter_tools Pub-cache archive."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import io
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO


STATE_NAME = ".rustdesk-flutter-pub-cache-state-v1"
STATE_VERSION = 1
DESTINATION = "flutter-pub-cache.tar.gz"
STAGING_PATTERN = re.compile(
    r"\.rustdesk-flutter-pub-cache\.[A-Za-z0-9_]{8,64}\Z"
)
VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
BLOCK_SIZE = 1024 * 1024
TAR_BLOCK_SIZE = 512
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_STATE_BYTES = 8192
MOUNTINFO_LIMIT = 8 * 1024 * 1024
RENAME_NOREPLACE = 1
ARCHIVE_MTIME = 1_700_000_000
MAX_MEMBER_PATH_BYTES = 181
MAX_MEMBER_DEPTH = 16

SPECIAL_MODES = frozenset(
    {
        "hosted/pub.dev/built_collection-5.1.1/tool/presubmit",
        "hosted/pub.dev/vm_snapshot_analysis-0.7.6/bin/analyse.dart",
    }
)
EMPTY_FILES = frozenset(
    {
        "hosted/pub.dev/archive-3.6.1/test/tests/res/emptyfile.txt",
        "hosted/pub.dev/build_runner_core-7.3.2/test/fixtures/"
        "no_packages_file/no_pubspec",
        "hosted/pub.dev/icons_launcher-2.1.7/coverage/lcov.info",
        "hosted/pub.dev/puppeteer-3.16.0/example/html/empty.html",
    }
)


class FlutterPubCacheOutputError(RuntimeError):
    pass


@dataclass(frozen=True)
class ArchiveContract:
    member_count: int
    directory_count: int
    file_count: int
    total_bytes: int
    metadata_sha256: str
    payload_sha256: str
    named_file_sha256: str
    mode_counts: tuple[tuple[int, int], ...]
    empty_files: frozenset[str]
    special_modes: frozenset[str]
    hosted_members: int | None = None
    hosted_hash_members: int | None = None
    package_directories: int | None = None
    hash_records: int | None = None
    cache_records: int | None = None


PRODUCTION_CONTRACT = ArchiveContract(
    member_count=24_807,
    directory_count=5_348,
    file_count=19_459,
    total_bytes=409_644_171,
    metadata_sha256=(
        "1c46903c18501ccf33c84f8f469082a9747b6f3787a48c54cb820db98bcb4353"
    ),
    payload_sha256=(
        "6d7f2bf0178ef22678492a6f174921601a1f2828f3df05078f4c4720fe9e404a"
    ),
    named_file_sha256=(
        "61afffd626dc838bf66abc3e49c0188da48b29cc9cd5a86e3eb1c9a08b0dd7fb"
    ),
    mode_counts=((0o644, 18_991), (0o754, 2), (0o755, 5_814)),
    empty_files=EMPTY_FILES,
    special_modes=SPECIAL_MODES,
    hosted_members=24_543,
    hosted_hash_members=264,
    package_directories=262,
    hash_records=262,
    cache_records=257,
)


def fail(message: str) -> None:
    raise FlutterPubCacheOutputError(message)


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


def stable_file_metadata(metadata: os.stat_result) -> tuple[int, ...]:
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


def validate_contract_values(
    version: str,
    builder: str,
    source_digest: str,
    flutter_source_sha256: str,
    flutter_tools_lock_sha256: str,
    archive_sha256: str,
    archive_size: int,
) -> None:
    if VERSION_PATTERN.fullmatch(version) is None:
        fail("Flutter version is not one canonical three-component version")
    if IMAGE_PATTERN.fullmatch(builder) is None:
        fail("builder is not one immutable Docker image content ID")
    for value, label in (
        (source_digest, "Pub-cache source digest"),
        (flutter_source_sha256, "Flutter source archive digest"),
        (flutter_tools_lock_sha256, "flutter_tools lockfile digest"),
        (archive_sha256, "Flutter Pub-cache archive digest"),
    ):
        if SHA256_PATTERN.fullmatch(value) is None:
            fail(f"{label} is not one lowercase SHA-256 value")
    if archive_size <= 0 or archive_size > MAX_ARCHIVE_BYTES:
        fail("Flutter Pub-cache archive size is outside its closed byte bound")


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
    return mountpoints


def reject_mount_at_or_below(path: Path) -> None:
    encoded = os.fsencode(path)
    prefix = encoded.rstrip(b"/") + b"/"
    for mountpoint in read_mountpoints():
        if mountpoint == encoded or mountpoint.startswith(prefix):
            fail(
                "private Flutter Pub-cache staging contains a mount: "
                f"{os.fsdecode(mountpoint)}"
            )


def validate_online(online: Path, uid: int, gid: int) -> os.stat_result:
    validate_absolute(online, "online root")
    metadata = os.lstat(online)
    if not stat.S_ISDIR(metadata.st_mode):
        fail("online root is not a directory")
    if (metadata.st_uid, metadata.st_gid) != (uid, gid):
        fail("online root is not owned by the acquisition identity")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        fail("online root is not mode 0700")
    if list_xattrs(online):
        fail("online root carries extended attributes")
    return metadata


def validate_staging(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
) -> os.stat_result:
    online_metadata = validate_online(online, uid, gid)
    validate_absolute(staging, "Flutter Pub-cache staging")
    if staging.parent != online or STAGING_PATTERN.fullmatch(staging.name) is None:
        fail("Flutter Pub-cache staging is not one reserved direct child")
    metadata = os.lstat(staging)
    if not stat.S_ISDIR(metadata.st_mode):
        fail("Flutter Pub-cache staging is not a directory")
    if identity(metadata)[0] != identity(online_metadata)[0]:
        fail("Flutter Pub-cache staging is not on the online filesystem")
    if (metadata.st_uid, metadata.st_gid) != (uid, gid):
        fail("Flutter Pub-cache staging has foreign ownership")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        fail("Flutter Pub-cache staging is not mode 0700")
    if list_xattrs(staging):
        fail("Flutter Pub-cache staging carries extended attributes")
    reject_mount_at_or_below(staging)
    return metadata


def fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def hash_regular_file(
    path: Path,
    expected_identity: tuple[int, int],
    expected_size: int,
) -> tuple[str, os.stat_result]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            fail("Flutter Pub-cache output is not a regular file")
        if identity(before) != expected_identity:
            fail("Flutter Pub-cache output identity changed before hashing")
        if before.st_size != expected_size:
            fail(
                "Flutter Pub-cache archive length is "
                f"{before.st_size}, expected {expected_size}"
            )
        digest = hashlib.sha256()
        read_bytes = 0
        while True:
            block = os.read(descriptor, BLOCK_SIZE)
            if not block:
                break
            read_bytes += len(block)
            if read_bytes > MAX_ARCHIVE_BYTES:
                fail("Flutter Pub-cache archive exceeded its byte bound")
            digest.update(block)
        after = os.fstat(descriptor)
        if stable_file_metadata(before) != stable_file_metadata(after):
            fail("Flutter Pub-cache archive changed while it was hashed")
        return digest.hexdigest(), after
    finally:
        os.close(descriptor)


def validate_member_name(name: str) -> None:
    try:
        encoded = name.encode("ascii")
    except UnicodeEncodeError:
        fail("Flutter Pub-cache archive contains a non-ASCII member name")
    pure = PurePosixPath(name)
    if (
        not name
        or len(encoded) > MAX_MEMBER_PATH_BYTES
        or name.startswith("/")
        or "\\" in name
        or str(pure) != name
        or len(pure.parts) > MAX_MEMBER_DEPTH
        or any(part in ("", ".", "..") for part in pure.parts)
        or pure.parts[0] not in ("hosted", "hosted-hashes")
    ):
        fail(f"Flutter Pub-cache archive contains a noncanonical path: {name!r}")


def update_metadata_digest(
    digest: "hashlib._Hash",
    kind: str,
    name: str,
    mode: int,
    size: int,
) -> None:
    for value in (kind, name, format(mode, "o"), str(size)):
        digest.update(value.encode("ascii"))
        digest.update(b"\0")


def validate_archive_semantics(
    path: Path,
    expected_identity: tuple[int, int],
    expected_metadata: os.stat_result,
    contract: ArchiveContract,
) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if identity(before) != expected_identity:
            fail("Flutter Pub-cache archive identity changed before inspection")
        if stable_file_metadata(before) != stable_file_metadata(expected_metadata):
            fail("Flutter Pub-cache archive metadata changed before inspection")
        with os.fdopen(os.dup(descriptor), "rb", closefd=True) as reader:
            try:
                with tarfile.open(fileobj=reader, mode="r:gz") as archive:
                    if archive.pax_headers:
                        fail("Flutter Pub-cache archive carries global PAX headers")
                    members = archive.getmembers()
                    metadata_digest = hashlib.sha256()
                    payload_digest = hashlib.sha256()
                    named_file_digest = hashlib.sha256()
                    names: set[str] = set()
                    empty_files: set[str] = set()
                    special_modes: set[str] = set()
                    mode_counts: dict[int, int] = {}
                    directory_count = 0
                    file_count = 0
                    total_bytes = 0
                    hosted_members = 0
                    hosted_hash_members = 0
                    package_directories = 0
                    hash_records = 0
                    cache_records = 0
                    for member in members:
                        name = member.name
                        validate_member_name(name)
                        if name in names:
                            fail(
                                "Flutter Pub-cache archive repeats a member: "
                                f"{name}"
                            )
                        names.add(name)
                        if member.pax_headers:
                            fail(
                                "Flutter Pub-cache member carries PAX metadata: "
                                f"{name}"
                            )
                        if member.linkname:
                            fail(
                                "Flutter Pub-cache member carries a link target: "
                                f"{name}"
                            )
                        if (
                            member.uid != 0
                            or member.gid != 0
                            or member.uname != ""
                            or member.gname != ""
                            or member.devmajor != 0
                            or member.devminor != 0
                        ):
                            fail(
                                "Flutter Pub-cache member ownership is not "
                                f"canonical: {name}"
                            )
                        if member.mtime != ARCHIVE_MTIME:
                            fail(
                                "Flutter Pub-cache member mtime is not canonical: "
                                f"{name}"
                            )
                        if member.isdir():
                            kind = "dir"
                            directory_count += 1
                            if member.size != 0 or member.mode != 0o755:
                                fail(
                                    "Flutter Pub-cache directory metadata is not "
                                    f"canonical: {name}"
                                )
                            if (
                                name.startswith("hosted/pub.dev/")
                                and name.count("/") == 2
                                and name != "hosted/pub.dev/.cache"
                            ):
                                package_directories += 1
                        elif member.isfile():
                            kind = "file"
                            file_count += 1
                            expected_mode = (
                                0o754 if name in contract.special_modes
                                else (0o755 if member.mode & 0o111 else 0o644)
                            )
                            if member.mode != expected_mode:
                                fail(
                                    "Flutter Pub-cache member mode is "
                                    f"{member.mode:04o}, expected "
                                    f"{expected_mode:04o}: {name}"
                                )
                            if name in contract.special_modes:
                                special_modes.add(name)
                            if member.size == 0:
                                empty_files.add(name)
                            if (
                                name.startswith("hosted-hashes/pub.dev/")
                                and name.count("/") == 2
                                and name.endswith(".sha256")
                            ):
                                hash_records += 1
                            if (
                                name.startswith("hosted/pub.dev/.cache/")
                                and name.count("/") == 3
                            ):
                                cache_records += 1
                            extracted = archive.extractfile(member)
                            if extracted is None:
                                fail(
                                    "cannot read regular Flutter Pub-cache "
                                    f"member: {name}"
                                )
                            member_digest = hashlib.sha256()
                            member_bytes = 0
                            while True:
                                block = extracted.read(BLOCK_SIZE)
                                if not block:
                                    break
                                member_bytes += len(block)
                                if member_bytes > member.size:
                                    fail(
                                        "Flutter Pub-cache member exceeds its "
                                        f"declared size: {name}"
                                    )
                                member_digest.update(block)
                                payload_digest.update(block)
                            if member_bytes != member.size:
                                fail(
                                    "Flutter Pub-cache member is shorter than its "
                                    f"declared size: {name}"
                                )
                            named_file_digest.update(name.encode("ascii"))
                            named_file_digest.update(b"\0")
                            named_file_digest.update(member_digest.digest())
                            total_bytes += member.size
                            if total_bytes > contract.total_bytes:
                                fail(
                                    "Flutter Pub-cache uncompressed bytes exceed "
                                    "the contract"
                                )
                        else:
                            fail(
                                "Flutter Pub-cache member is neither a directory "
                                f"nor a regular file: {name}"
                            )
                        mode_counts[member.mode] = mode_counts.get(member.mode, 0) + 1
                        update_metadata_digest(
                            metadata_digest,
                            kind,
                            name,
                            member.mode,
                            member.size,
                        )
                        if name == "hosted" or name.startswith("hosted/"):
                            hosted_members += 1
                        elif (
                            name == "hosted-hashes"
                            or name.startswith("hosted-hashes/")
                        ):
                            hosted_hash_members += 1
            except (OSError, tarfile.TarError, EOFError) as error:
                fail(f"Flutter Pub-cache archive is not a valid gzip tar: {error}")
        after = os.fstat(descriptor)
        if stable_file_metadata(before) != stable_file_metadata(after):
            fail("Flutter Pub-cache archive changed during semantic inspection")
    finally:
        os.close(descriptor)

    actual = (
        len(members),
        directory_count,
        file_count,
        total_bytes,
        metadata_digest.hexdigest(),
        payload_digest.hexdigest(),
        named_file_digest.hexdigest(),
        tuple(sorted(mode_counts.items())),
        frozenset(empty_files),
        frozenset(special_modes),
    )
    expected = (
        contract.member_count,
        contract.directory_count,
        contract.file_count,
        contract.total_bytes,
        contract.metadata_sha256,
        contract.payload_sha256,
        contract.named_file_sha256,
        contract.mode_counts,
        contract.empty_files,
        contract.special_modes,
    )
    if actual != expected:
        fail("Flutter Pub-cache logical archive contract differs")
    for actual_value, expected_value, label in (
        (hosted_members, contract.hosted_members, "hosted member count"),
        (
            hosted_hash_members,
            contract.hosted_hash_members,
            "hosted-hashes member count",
        ),
        (
            package_directories,
            contract.package_directories,
            "direct package-directory count",
        ),
        (hash_records, contract.hash_records, "host record count"),
        (cache_records, contract.cache_records, "host metadata-cache count"),
    ):
        if expected_value is not None and actual_value != expected_value:
            fail(
                f"Flutter Pub-cache {label} is {actual_value}, "
                f"expected {expected_value}"
            )
    if contract is PRODUCTION_CONTRACT:
        for required in (
            "hosted/pub.dev/test-1.25.7/pubspec.yaml",
            "hosted/pub.dev/.cache/archive-advisories.json",
            "hosted/pub.dev/.cache/http-advisories.json",
        ):
            if required not in names:
                fail(
                    "Flutter Pub-cache archive lacks required offline state: "
                    f"{required}"
                )


def validate_archive(
    online: Path | None,
    archive: Path,
    uid: int,
    gid: int,
    expected_sha256: str,
    expected_size: int,
    *,
    expected_identity: tuple[int, int] | None,
    staged_mode: int,
    allow_legacy_root: bool,
    contract: ArchiveContract = PRODUCTION_CONTRACT,
) -> os.stat_result:
    validate_absolute(archive, "Flutter Pub-cache archive")
    metadata = os.lstat(archive)
    if not stat.S_ISREG(metadata.st_mode):
        fail("Flutter Pub-cache archive is not a regular file")
    if online is not None:
        online_metadata = os.lstat(online)
        if identity(metadata)[0] != identity(online_metadata)[0]:
            fail("Flutter Pub-cache archive is not on the online filesystem")
    if expected_identity is not None and identity(metadata) != expected_identity:
        fail("Flutter Pub-cache archive identity changed")
    if metadata.st_nlink != 1:
        fail("Flutter Pub-cache archive has a hardlink outside the transaction")
    mode = stat.S_IMODE(metadata.st_mode)
    owner = (metadata.st_uid, metadata.st_gid)
    if allow_legacy_root and owner == (0, 0):
        if mode != 0o644:
            fail("historical root-owned Flutter Pub-cache archive is not mode 0644")
    else:
        if owner != (uid, gid):
            fail("Flutter Pub-cache archive has foreign ownership")
        if mode != staged_mode:
            fail(
                f"Flutter Pub-cache archive mode is {mode:04o}, "
                f"expected {staged_mode:04o}"
            )
    if list_xattrs(archive):
        fail("Flutter Pub-cache archive carries extended attributes")
    archive_identity = identity(metadata)
    digest, after = hash_regular_file(
        archive,
        archive_identity,
        expected_size,
    )
    if digest != expected_sha256:
        fail("Flutter Pub-cache archive SHA-256 does not match its pin")
    validate_archive_semantics(
        archive,
        archive_identity,
        after,
        contract,
    )
    final_metadata = os.lstat(archive)
    if stable_file_metadata(final_metadata) != stable_file_metadata(after):
        fail("Flutter Pub-cache archive changed after semantic validation")
    return final_metadata


def validate_inventory(staging: Path, expected: set[str]) -> None:
    names = set(os.listdir(staging))
    if names != expected:
        fail("Flutter Pub-cache staging inventory is incoherent and was preserved")


def state_payload(
    online: Path,
    staging: Path,
    output: Path,
    uid: int,
    gid: int,
    version: str,
    builder: str,
    source_digest: str,
    flutter_source_sha256: str,
    flutter_tools_lock_sha256: str,
    archive_sha256: str,
    archive_size: int,
) -> dict[str, object]:
    return {
        "version": STATE_VERSION,
        "online": os.fspath(online),
        "online_identity": encode_identity(identity(os.lstat(online))),
        "staging": os.fspath(staging),
        "staging_identity": encode_identity(identity(os.lstat(staging))),
        "output_identity": encode_identity(identity(os.lstat(output))),
        "uid": uid,
        "gid": gid,
        "flutter_version": version,
        "builder": builder,
        "source_digest": source_digest,
        "flutter_source_sha256": flutter_source_sha256,
        "flutter_tools_lock_sha256": flutter_tools_lock_sha256,
        "archive_sha256": archive_sha256,
        "archive_size": archive_size,
        "destination": DESTINATION,
    }


def write_state(staging: Path, payload: dict[str, object]) -> None:
    state = staging / STATE_NAME
    temporary = staging / f"{STATE_NAME}.tmp"
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_STATE_BYTES:
        fail("Flutter Pub-cache transaction state exceeds its byte bound")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        written = 0
        while written < len(encoded):
            count = os.write(descriptor, encoded[written:])
            if count <= 0:
                fail("short write while recording Flutter Pub-cache state")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, state)
    fsync_directory(staging)


def read_bounded_regular_file(path: Path, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            fail("Flutter Pub-cache state is not one bounded regular file")
        data = bytearray()
        while True:
            block = os.read(descriptor, min(BLOCK_SIZE, maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
            if len(data) > maximum:
                fail("Flutter Pub-cache state exceeded its byte bound")
        after = os.fstat(descriptor)
        if stable_file_metadata(before) != stable_file_metadata(after):
            fail("Flutter Pub-cache state changed while it was read")
        return bytes(data)
    finally:
        os.close(descriptor)


def common_state_values(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    version: str,
    builder: str,
    source_digest: str,
    flutter_source_sha256: str,
    flutter_tools_lock_sha256: str,
    archive_sha256: str,
    archive_size: int,
) -> dict[str, object]:
    return {
        "version": STATE_VERSION,
        "online": os.fspath(online),
        "staging": os.fspath(staging),
        "uid": uid,
        "gid": gid,
        "flutter_version": version,
        "builder": builder,
        "source_digest": source_digest,
        "flutter_source_sha256": flutter_source_sha256,
        "flutter_tools_lock_sha256": flutter_tools_lock_sha256,
        "archive_sha256": archive_sha256,
        "archive_size": archive_size,
        "destination": DESTINATION,
    }


def load_state(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    version: str,
    builder: str,
    source_digest: str,
    flutter_source_sha256: str,
    flutter_tools_lock_sha256: str,
    archive_sha256: str,
    archive_size: int,
) -> dict[str, object]:
    validate_contract_values(
        version,
        builder,
        source_digest,
        flutter_source_sha256,
        flutter_tools_lock_sha256,
        archive_sha256,
        archive_size,
    )
    staging_metadata = validate_staging(online, staging, uid, gid)
    state = staging / STATE_NAME
    metadata = os.lstat(state)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid) != (uid, gid)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or list_xattrs(state)
    ):
        fail("Flutter Pub-cache transaction state metadata is unsafe")
    try:
        payload = json.loads(read_bounded_regular_file(state, MAX_STATE_BYTES))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"Flutter Pub-cache transaction state is malformed: {error}")
    expected_keys = {
        "version",
        "online",
        "online_identity",
        "staging",
        "staging_identity",
        "output_identity",
        "uid",
        "gid",
        "flutter_version",
        "builder",
        "source_digest",
        "flutter_source_sha256",
        "flutter_tools_lock_sha256",
        "archive_sha256",
        "archive_size",
        "destination",
    }
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        fail("Flutter Pub-cache transaction state schema changed")
    expected_values = common_state_values(
        online,
        staging,
        uid,
        gid,
        version,
        builder,
        source_digest,
        flutter_source_sha256,
        flutter_tools_lock_sha256,
        archive_sha256,
        archive_size,
    )
    for key, value in expected_values.items():
        if payload[key] != value:
            fail(f"Flutter Pub-cache transaction state changed field {key}")
    decode_identity(payload["output_identity"], "Flutter Pub-cache output")
    if decode_identity(payload["online_identity"], "online root") != identity(
        os.lstat(online)
    ):
        fail("online root identity changed during the Flutter Pub-cache transaction")
    if decode_identity(
        payload["staging_identity"],
        "Flutter Pub-cache staging",
    ) != identity(staging_metadata):
        fail("Flutter Pub-cache staging identity changed")
    return payload


def prepare(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    version: str,
    builder: str,
    source_digest: str,
    flutter_source_sha256: str,
    flutter_tools_lock_sha256: str,
    archive_sha256: str,
    archive_size: int,
) -> None:
    validate_contract_values(
        version,
        builder,
        source_digest,
        flutter_source_sha256,
        flutter_tools_lock_sha256,
        archive_sha256,
        archive_size,
    )
    validate_staging(online, staging, uid, gid)
    validate_inventory(staging, set())
    output = staging / "output"
    descriptor = os.open(
        output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    write_state(
        staging,
        state_payload(
            online,
            staging,
            output,
            uid,
            gid,
            version,
            builder,
            source_digest,
            flutter_source_sha256,
            flutter_tools_lock_sha256,
            archive_sha256,
            archive_size,
        ),
    )
    validate_inventory(staging, {STATE_NAME, "output"})
    fsync_directory(online)


def verify_staged(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    version: str,
    builder: str,
    source_digest: str,
    flutter_source_sha256: str,
    flutter_tools_lock_sha256: str,
    archive_sha256: str,
    archive_size: int,
    *,
    contract: ArchiveContract = PRODUCTION_CONTRACT,
) -> None:
    payload = load_state(
        online,
        staging,
        uid,
        gid,
        version,
        builder,
        source_digest,
        flutter_source_sha256,
        flutter_tools_lock_sha256,
        archive_sha256,
        archive_size,
    )
    validate_inventory(staging, {STATE_NAME, "output"})
    output = staging / "output"
    expected = decode_identity(payload["output_identity"], "Flutter Pub-cache output")
    validate_archive(
        online,
        output,
        uid,
        gid,
        archive_sha256,
        archive_size,
        expected_identity=expected,
        staged_mode=0o600,
        allow_legacy_root=False,
        contract=contract,
    )
    descriptor = os.open(output, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        if identity(os.fstat(descriptor)) != expected:
            fail("Flutter Pub-cache archive identity changed before mode sealing")
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    validate_archive(
        online,
        output,
        uid,
        gid,
        archive_sha256,
        archive_size,
        expected_identity=expected,
        staged_mode=0o400,
        allow_legacy_root=False,
        contract=contract,
    )
    fsync_directory(staging)


def check_complete(
    online: Path,
    uid: int,
    gid: int,
    version: str,
    builder: str,
    source_digest: str,
    flutter_source_sha256: str,
    flutter_tools_lock_sha256: str,
    archive_sha256: str,
    archive_size: int,
) -> None:
    validate_contract_values(
        version,
        builder,
        source_digest,
        flutter_source_sha256,
        flutter_tools_lock_sha256,
        archive_sha256,
        archive_size,
    )
    validate_online(online, uid, gid)
    validate_archive(
        online,
        online / DESTINATION,
        uid,
        gid,
        archive_sha256,
        archive_size,
        expected_identity=None,
        staged_mode=0o400,
        allow_legacy_root=True,
    )


def verify_archive_only(
    archive: Path,
    uid: int,
    gid: int,
    archive_sha256: str,
    archive_size: int,
) -> None:
    if uid <= 0 or gid <= 0:
        fail("Flutter Pub-cache verifier refuses UID or primary GID zero")
    if SHA256_PATTERN.fullmatch(archive_sha256) is None:
        fail("Flutter Pub-cache digest is not one lowercase SHA-256 value")
    validate_archive(
        None,
        archive,
        uid,
        gid,
        archive_sha256,
        archive_size,
        expected_identity=None,
        staged_mode=0o400,
        allow_legacy_root=False,
    )


def renameat2(
    old_directory: int,
    old_name: str,
    new_directory: int,
    new_name: str,
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
        RENAME_NOREPLACE,
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
    uid: int,
    gid: int,
    version: str,
    builder: str,
    source_digest: str,
    flutter_source_sha256: str,
    flutter_tools_lock_sha256: str,
    archive_sha256: str,
    archive_size: int,
    *,
    contract: ArchiveContract = PRODUCTION_CONTRACT,
) -> None:
    payload = load_state(
        online,
        staging,
        uid,
        gid,
        version,
        builder,
        source_digest,
        flutter_source_sha256,
        flutter_tools_lock_sha256,
        archive_sha256,
        archive_size,
    )
    validate_inventory(staging, {STATE_NAME, "output"})
    expected = decode_identity(payload["output_identity"], "Flutter Pub-cache output")
    output = staging / "output"
    validate_archive(
        online,
        output,
        uid,
        gid,
        archive_sha256,
        archive_size,
        expected_identity=expected,
        staged_mode=0o400,
        allow_legacy_root=False,
        contract=contract,
    )
    destination = online / DESTINATION
    if destination.exists() or destination.is_symlink():
        fail("Flutter Pub-cache destination appeared before publication")
    descriptor = os.open(output, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    fsync_directory(staging)
    online_fd = open_directory(online)
    staging_fd = open_directory(staging)
    moved = False
    try:
        renameat2(staging_fd, "output", online_fd, DESTINATION)
        moved = True
        os.fsync(staging_fd)
        os.fsync(online_fd)
        validate_archive(
            online,
            destination,
            uid,
            gid,
            archive_sha256,
            archive_size,
            expected_identity=expected,
            staged_mode=0o400,
            allow_legacy_root=False,
            contract=contract,
        )
    except BaseException as primary:
        if moved:
            try:
                renameat2(online_fd, DESTINATION, staging_fd, "output")
                os.fsync(staging_fd)
                os.fsync(online_fd)
            except BaseException as rollback:
                primary.add_note(
                    "Flutter Pub-cache publication rollback also failed: "
                    f"{rollback}"
                )
        raise
    finally:
        os.close(staging_fd)
        os.close(online_fd)


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
    temporary_state = staging / f"{STATE_NAME}.tmp"
    allowed = {"output"}
    if names == {"output", temporary_state.name}:
        metadata = os.lstat(temporary_state)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != (uid, gid)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > MAX_STATE_BYTES
            or list_xattrs(temporary_state)
        ):
            fail("unprepared Flutter Pub-cache temporary state is unsafe")
        allowed.add(temporary_state.name)
    if names != allowed:
        fail("unprepared Flutter Pub-cache staging is incoherent and was preserved")
    output = staging / "output"
    metadata = os.lstat(output)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid) != (uid, gid)
        or identity(metadata)[0] != identity(os.lstat(online))[0]
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > MAX_ARCHIVE_BYTES
        or list_xattrs(output)
    ):
        fail("unprepared Flutter Pub-cache output is unsafe and was preserved")
    if temporary_state.name in names:
        return "unprepared-state-write"
    return "unprepared-output"


def recover(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    version: str,
    builder: str,
    source_digest: str,
    flutter_source_sha256: str,
    flutter_tools_lock_sha256: str,
    archive_sha256: str,
    archive_size: int,
    *,
    contract: ArchiveContract = PRODUCTION_CONTRACT,
) -> str:
    state = staging / STATE_NAME
    if not state.exists() and not state.is_symlink():
        return recover_unprepared(online, staging, uid, gid)
    payload = load_state(
        online,
        staging,
        uid,
        gid,
        version,
        builder,
        source_digest,
        flutter_source_sha256,
        flutter_tools_lock_sha256,
        archive_sha256,
        archive_size,
    )
    output_identity = decode_identity(
        payload["output_identity"],
        "Flutter Pub-cache output",
    )
    private_output = optional_identity(staging / "output")
    destination = online / DESTINATION
    live_output = optional_identity(destination)
    if private_output == output_identity:
        validate_inventory(staging, {STATE_NAME, "output"})
        if live_output is None:
            return "unpublished"
        return "unpublished-destination-occupied"
    if private_output is None and live_output == output_identity:
        validate_inventory(staging, {STATE_NAME})
        validate_archive(
            online,
            destination,
            uid,
            gid,
            archive_sha256,
            archive_size,
            expected_identity=output_identity,
            staged_mode=0o400,
            allow_legacy_root=False,
            contract=contract,
        )
        return "published"
    fail("Flutter Pub-cache transaction state is incoherent and was preserved")


def parse_tar_octal(field: bytes, label: str) -> int:
    stripped = field.rstrip(b"\0 ").lstrip(b" ")
    if not stripped or any(byte < ord("0") or byte > ord("7") for byte in stripped):
        fail(f"raw tar {label} field is not canonical octal")
    return int(stripped, 8)


def raw_tar_name(header: bytes) -> str:
    name = header[0:100].split(b"\0", 1)[0]
    prefix = header[345:500].split(b"\0", 1)[0]
    combined = prefix + (b"/" if prefix and name else b"") + name
    try:
        return combined.decode("ascii")
    except UnicodeDecodeError:
        fail("raw tar header contains a non-ASCII name")


def validate_raw_tar_checksum(header: bytes) -> None:
    stored = parse_tar_octal(header[148:156], "checksum")
    computed = sum(header[:148]) + (8 * ord(" ")) + sum(header[156:])
    if stored != computed:
        fail("raw tar header checksum is invalid")


def read_exact(reader: BinaryIO, length: int, label: str) -> bytes:
    data = bytearray()
    while len(data) < length:
        block = reader.read(length - len(data))
        if not block:
            fail(f"raw tar ended during {label}")
        data.extend(block)
    return bytes(data)


def write_all(writer: BinaryIO, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = writer.write(data[offset:])
        if written is None:
            written = len(data) - offset
        if written <= 0:
            fail("short write while normalizing raw tar")
        offset += written


def normalize_tar_stream(reader: BinaryIO, writer: BinaryIO) -> None:
    patched: set[str] = set()
    zero_blocks = 0
    while True:
        header = reader.read(TAR_BLOCK_SIZE)
        if not header:
            break
        if len(header) != TAR_BLOCK_SIZE:
            fail("raw tar ends with a partial header block")
        if header == bytes(TAR_BLOCK_SIZE):
            zero_blocks += 1
            write_all(writer, header)
            continue
        if zero_blocks:
            fail("raw tar contains data after its terminal zero blocks")
        validate_raw_tar_checksum(header)
        name = raw_tar_name(header)
        size = parse_tar_octal(header[124:136], "size")
        output_header = header
        if name in SPECIAL_MODES:
            if name in patched:
                fail(f"raw tar repeats special-mode member: {name}")
            if header[156:157] not in (b"0", b"\0"):
                fail(f"special-mode member is not regular: {name}")
            if parse_tar_octal(header[100:108], "mode") != 0o755:
                fail(f"special-mode member input is not normalized 0755: {name}")
            mutable = bytearray(header)
            mutable[100:108] = b"0000754\0"
            mutable[148:156] = b"        "
            checksum = sum(mutable)
            encoded = f"{checksum:06o}\0 ".encode("ascii")
            if len(encoded) != 8:
                fail("normalized tar checksum exceeds its field")
            mutable[148:156] = encoded
            output_header = bytes(mutable)
            validate_raw_tar_checksum(output_header)
            patched.add(name)
        write_all(writer, output_header)
        padded = ((size + TAR_BLOCK_SIZE - 1) // TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE
        remaining = padded
        while remaining:
            block = read_exact(
                reader,
                min(BLOCK_SIZE, remaining),
                f"payload for {name}",
            )
            write_all(writer, block)
            remaining -= len(block)
    if zero_blocks < 2:
        fail("raw tar lacks its terminal zero blocks")
    if patched != SPECIAL_MODES:
        missing = sorted(SPECIAL_MODES - patched)
        fail(f"raw tar lacks exact special-mode members: {missing}")


def write_bounded_output(
    output: Path,
    uid: int,
    gid: int,
    expected_sha256: str,
    expected_size: int,
    reader: BinaryIO,
) -> None:
    if uid <= 0 or gid <= 0 or (os.getuid(), os.getgid()) != (uid, gid):
        fail("bounded writer identity differs from the non-root contract")
    if SHA256_PATTERN.fullmatch(expected_sha256) is None:
        fail("bounded writer digest is not one lowercase SHA-256 value")
    if expected_size <= 0 or expected_size > MAX_ARCHIVE_BYTES:
        fail("bounded writer size is outside the archive limit")
    validate_absolute(output, "bounded Flutter Pub-cache output")
    descriptor = os.open(output, os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or (before.st_uid, before.st_gid) != (uid, gid)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size != 0
            or list_xattrs(output)
        ):
            fail("bounded Flutter Pub-cache output inode is unsafe")
        output_identity = identity(before)
        digest = hashlib.sha256()
        total = 0
        while True:
            block = reader.read(BLOCK_SIZE)
            if not block:
                break
            if total + len(block) > expected_size:
                fail("Flutter Pub-cache output exceeded its exact byte bound")
            offset = 0
            while offset < len(block):
                written = os.write(descriptor, block[offset:])
                if written <= 0:
                    fail("short write to bounded Flutter Pub-cache output")
                offset += written
            digest.update(block)
            total += len(block)
        if total != expected_size:
            fail(
                f"Flutter Pub-cache output length is {total}, "
                f"expected {expected_size}"
            )
        if digest.hexdigest() != expected_sha256:
            fail("Flutter Pub-cache output digest differs from its pin")
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if identity(after) != output_identity or after.st_size != expected_size:
            fail("Flutter Pub-cache output inode changed during bounded write")
    finally:
        os.close(descriptor)


def expect_failure(action, message: str) -> None:
    try:
        action()
    except (OSError, FlutterPubCacheOutputError):
        return
    fail(message)


def fixture_contract(entries: list[tuple[str, bytes | None, int]]) -> ArchiveContract:
    metadata_digest = hashlib.sha256()
    payload_digest = hashlib.sha256()
    named_digest = hashlib.sha256()
    mode_counts: dict[int, int] = {}
    empty_files: set[str] = set()
    special_modes: set[str] = set()
    directories = 0
    files = 0
    total = 0
    for name, payload, mode in entries:
        kind = "dir" if payload is None else "file"
        size = 0 if payload is None else len(payload)
        update_metadata_digest(metadata_digest, kind, name, mode, size)
        mode_counts[mode] = mode_counts.get(mode, 0) + 1
        if payload is None:
            directories += 1
        else:
            files += 1
            total += len(payload)
            if not payload:
                empty_files.add(name)
            payload_digest.update(payload)
            member_digest = hashlib.sha256(payload).digest()
            named_digest.update(name.encode("ascii") + b"\0" + member_digest)
            if name in SPECIAL_MODES:
                special_modes.add(name)
    return ArchiveContract(
        member_count=len(entries),
        directory_count=directories,
        file_count=files,
        total_bytes=total,
        metadata_sha256=metadata_digest.hexdigest(),
        payload_sha256=payload_digest.hexdigest(),
        named_file_sha256=named_digest.hexdigest(),
        mode_counts=tuple(sorted(mode_counts.items())),
        empty_files=frozenset(empty_files),
        special_modes=frozenset(special_modes),
    )


def make_fixture(entries: list[tuple[str, bytes | None, int]]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(
        fileobj=raw,
        mode="w:gz",
        format=tarfile.USTAR_FORMAT,
    ) as archive:
        for name, payload, mode in entries:
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE if payload is None else tarfile.REGTYPE
            member.size = 0 if payload is None else len(payload)
            member.mode = mode
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.mtime = ARCHIVE_MTIME
            archive.addfile(
                member,
                None if payload is None else io.BytesIO(payload),
            )
    return raw.getvalue()


def make_staging(online: Path) -> Path:
    return Path(
        tempfile.mkdtemp(prefix=".rustdesk-flutter-pub-cache.", dir=online)
    )


def run_self_test() -> None:
    uid = os.getuid()
    gid = os.getgid()
    if uid <= 0 or gid <= 0:
        fail("self-test refuses UID or primary GID zero")
    version = "3.24.5"
    builder = "sha256:" + "1" * 64
    source_digest = "2" * 64
    flutter_source_sha256 = "3" * 64
    flutter_tools_lock_sha256 = "4" * 64
    entries = [
        ("hosted", None, 0o755),
        ("hosted/pub.dev", None, 0o755),
        ("hosted/pub.dev/test-1.25.7", None, 0o755),
        (
            "hosted/pub.dev/test-1.25.7/pubspec.yaml",
            b"name: test\nversion: 1.25.7\n",
            0o644,
        ),
        ("hosted-hashes", None, 0o755),
        ("hosted-hashes/pub.dev", None, 0o755),
        (
            "hosted-hashes/pub.dev/test-1.25.7.sha256",
            b"f" * 64,
            0o644,
        ),
    ]
    contract = fixture_contract(entries)
    fixture = make_fixture(entries)
    archive_sha256 = hashlib.sha256(fixture).hexdigest()
    archive_size = len(fixture)
    arguments = (
        uid,
        gid,
        version,
        builder,
        source_digest,
        flutter_source_sha256,
        flutter_tools_lock_sha256,
        archive_sha256,
        archive_size,
    )
    with tempfile.TemporaryDirectory(
        prefix="flutter-pub-cache-output-self-test."
    ) as temporary:
        root = Path(temporary)

        normal = root / "normal"
        normal.mkdir(mode=0o700)
        normal_staging = make_staging(normal)
        prepare(normal, normal_staging, *arguments)
        (normal_staging / "output").write_bytes(fixture)
        verify_staged(normal, normal_staging, *arguments, contract=contract)
        publish(normal, normal_staging, *arguments, contract=contract)
        if (
            recover(normal, normal_staging, *arguments, contract=contract)
            != "published"
        ):
            fail("self-test did not classify completed Flutter Pub-cache publication")
        shutil.rmtree(normal_staging)

        wrong_digest = root / "wrong-digest"
        wrong_digest.mkdir(mode=0o700)
        wrong_staging = make_staging(wrong_digest)
        prepare(wrong_digest, wrong_staging, *arguments)
        (wrong_staging / "output").write_bytes(b"x" * archive_size)
        expect_failure(
            lambda: verify_staged(
                wrong_digest,
                wrong_staging,
                *arguments,
                contract=contract,
            ),
            "self-test accepted a wrong Flutter Pub-cache digest",
        )

        wrong_semantics = root / "wrong-semantics"
        wrong_semantics.mkdir(mode=0o700)
        changed_entries = list(entries)
        changed_entries[3] = (
            changed_entries[3][0],
            b"name: wrong\nversion: 1.25.7\n",
            0o644,
        )
        bad_fixture = make_fixture(changed_entries)
        bad_arguments = (
            uid,
            gid,
            version,
            builder,
            source_digest,
            flutter_source_sha256,
            flutter_tools_lock_sha256,
            hashlib.sha256(bad_fixture).hexdigest(),
            len(bad_fixture),
        )
        bad_staging = make_staging(wrong_semantics)
        prepare(wrong_semantics, bad_staging, *bad_arguments)
        (bad_staging / "output").write_bytes(bad_fixture)
        expect_failure(
            lambda: verify_staged(
                wrong_semantics,
                bad_staging,
                *bad_arguments,
                contract=contract,
            ),
            "self-test accepted a semantically wrong Flutter Pub-cache archive",
        )

        occupied = root / "occupied"
        occupied.mkdir(mode=0o700)
        occupied_staging = make_staging(occupied)
        prepare(occupied, occupied_staging, *arguments)
        (occupied_staging / "output").write_bytes(fixture)
        verify_staged(occupied, occupied_staging, *arguments, contract=contract)
        (occupied / DESTINATION).write_bytes(b"race")
        (occupied / DESTINATION).chmod(0o400)
        expect_failure(
            lambda: publish(
                occupied,
                occupied_staging,
                *arguments,
                contract=contract,
            ),
            "self-test accepted an occupied Flutter Pub-cache destination",
        )
        if (
            recover(
                occupied,
                occupied_staging,
                *arguments,
                contract=contract,
            )
            != "unpublished-destination-occupied"
        ):
            fail("self-test did not preserve an occupied Pub-cache destination")

        symlinked = root / "symlink"
        symlinked.mkdir(mode=0o700)
        symlink_staging = make_staging(symlinked)
        prepare(symlinked, symlink_staging, *arguments)
        (symlinked / "external").write_bytes(fixture)
        (symlink_staging / "output").unlink()
        (symlink_staging / "output").symlink_to("../external")
        expect_failure(
            lambda: verify_staged(
                symlinked,
                symlink_staging,
                *arguments,
                contract=contract,
            ),
            "self-test accepted a symlinked Flutter Pub-cache output",
        )

        hardlinked = root / "hardlink"
        hardlinked.mkdir(mode=0o700)
        hardlink_staging = make_staging(hardlinked)
        prepare(hardlinked, hardlink_staging, *arguments)
        (hardlink_staging / "output").write_bytes(fixture)
        os.link(hardlink_staging / "output", hardlinked / "external")
        expect_failure(
            lambda: verify_staged(
                hardlinked,
                hardlink_staging,
                *arguments,
                contract=contract,
            ),
            "self-test accepted a hardlinked Flutter Pub-cache output",
        )

        interrupted = root / "interrupted"
        interrupted.mkdir(mode=0o700)
        interrupted_staging = make_staging(interrupted)
        (interrupted_staging / "output").write_bytes(b"")
        (interrupted_staging / "output").chmod(0o600)
        (interrupted_staging / f"{STATE_NAME}.tmp").write_bytes(b'{"partial":')
        (interrupted_staging / f"{STATE_NAME}.tmp").chmod(0o600)
        if (
            recover(interrupted, interrupted_staging, *arguments)
            != "unprepared-state-write"
        ):
            fail("self-test did not classify interrupted state publication")

        if hasattr(os, "setxattr"):
            xattrs = root / "xattrs"
            xattrs.mkdir(mode=0o700)
            xattr_staging = make_staging(xattrs)
            prepare(xattrs, xattr_staging, *arguments)
            (xattr_staging / "output").write_bytes(fixture)
            try:
                os.setxattr(
                    xattr_staging / "output",
                    "user.rustdesk-test",
                    b"1",
                )
            except OSError:
                pass
            else:
                expect_failure(
                    lambda: verify_staged(
                        xattrs,
                        xattr_staging,
                        *arguments,
                        contract=contract,
                    ),
                    "self-test accepted xattrs on Flutter Pub-cache output",
                )

        normalization_entries = [
            ("hosted", None, 0o755),
            ("hosted/pub.dev", None, 0o755),
            (
                "hosted/pub.dev/built_collection-5.1.1",
                None,
                0o755,
            ),
            (
                "hosted/pub.dev/built_collection-5.1.1/tool",
                None,
                0o755,
            ),
            (
                "hosted/pub.dev/built_collection-5.1.1/tool/presubmit",
                b"one",
                0o755,
            ),
            (
                "hosted/pub.dev/vm_snapshot_analysis-0.7.6",
                None,
                0o755,
            ),
            (
                "hosted/pub.dev/vm_snapshot_analysis-0.7.6/bin",
                None,
                0o755,
            ),
            (
                "hosted/pub.dev/vm_snapshot_analysis-0.7.6/bin/analyse.dart",
                b"two",
                0o755,
            ),
        ]
        raw_fixture = make_fixture(normalization_entries)
        with tarfile.open(fileobj=io.BytesIO(raw_fixture), mode="r:gz") as archive:
            uncompressed = io.BytesIO()
            with tarfile.open(
                fileobj=uncompressed,
                mode="w",
                format=tarfile.USTAR_FORMAT,
            ) as raw_archive:
                for member in archive.getmembers():
                    extracted = archive.extractfile(member) if member.isfile() else None
                    raw_archive.addfile(member, extracted)
        normalized = io.BytesIO()
        normalize_tar_stream(io.BytesIO(uncompressed.getvalue()), normalized)
        with tarfile.open(fileobj=io.BytesIO(normalized.getvalue()), mode="r:") as archive:
            modes = {member.name: member.mode for member in archive}
        if any(modes.get(name) != 0o754 for name in SPECIAL_MODES):
            fail("self-test did not normalize both exact 0754 members")
        missing_special = make_fixture(normalization_entries[:-1])
        with tarfile.open(
            fileobj=io.BytesIO(missing_special),
            mode="r:gz",
        ) as archive:
            missing_raw = io.BytesIO()
            with tarfile.open(
                fileobj=missing_raw,
                mode="w",
                format=tarfile.USTAR_FORMAT,
            ) as raw_archive:
                for member in archive.getmembers():
                    extracted = archive.extractfile(member) if member.isfile() else None
                    raw_archive.addfile(member, extracted)
        expect_failure(
            lambda: normalize_tar_stream(
                io.BytesIO(missing_raw.getvalue()),
                io.BytesIO(),
            ),
            "self-test accepted a raw tar missing one special-mode member",
        )


def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--online", required=True, type=Path)
    parser.add_argument("--uid", required=True, type=int)
    parser.add_argument("--gid", required=True, type=int)
    parser.add_argument("--flutter-version", required=True)
    parser.add_argument("--builder", required=True)
    parser.add_argument("--source-digest", required=True)
    parser.add_argument("--flutter-source-sha256", required=True)
    parser.add_argument("--flutter-tools-lock-sha256", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--size", required=True, type=int)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("prepare", "verify", "publish", "recover"):
        child = subparsers.add_parser(command)
        add_common_arguments(child)
        child.add_argument("--staging", required=True, type=Path)
    complete = subparsers.add_parser("check-complete")
    add_common_arguments(complete)
    archive = subparsers.add_parser("verify-archive")
    archive.add_argument("--archive", required=True, type=Path)
    archive.add_argument("--uid", required=True, type=int)
    archive.add_argument("--gid", required=True, type=int)
    archive.add_argument("--sha256", required=True)
    archive.add_argument("--size", required=True, type=int)
    bounded = subparsers.add_parser("write-bounded")
    bounded.add_argument("--output", required=True, type=Path)
    bounded.add_argument("--uid", required=True, type=int)
    bounded.add_argument("--gid", required=True, type=int)
    bounded.add_argument("--sha256", required=True)
    bounded.add_argument("--size", required=True, type=int)
    subparsers.add_parser("normalize-tar")
    subparsers.add_parser("self-test")
    arguments = parser.parse_args()

    if arguments.command == "self-test":
        run_self_test()
        print("online-flutter-pub-cache-output: PASS")
        return 0
    if arguments.command == "normalize-tar":
        normalize_tar_stream(sys.stdin.buffer, sys.stdout.buffer)
        return 0
    if arguments.command == "write-bounded":
        write_bounded_output(
            arguments.output,
            arguments.uid,
            arguments.gid,
            arguments.sha256,
            arguments.size,
            sys.stdin.buffer,
        )
        return 0
    if arguments.command == "verify-archive":
        verify_archive_only(
            arguments.archive,
            arguments.uid,
            arguments.gid,
            arguments.sha256,
            arguments.size,
        )
        return 0

    uid = arguments.uid
    gid = arguments.gid
    if uid <= 0 or gid <= 0:
        fail("Flutter Pub-cache transaction refuses UID or primary GID zero")
    common = (
        arguments.online,
        uid,
        gid,
        arguments.flutter_version,
        arguments.builder,
        arguments.source_digest,
        arguments.flutter_source_sha256,
        arguments.flutter_tools_lock_sha256,
        arguments.sha256,
        arguments.size,
    )
    if arguments.command == "check-complete":
        check_complete(*common)
    elif arguments.command == "prepare":
        prepare(arguments.online, arguments.staging, *common[1:])
    elif arguments.command == "verify":
        verify_staged(arguments.online, arguments.staging, *common[1:])
    elif arguments.command == "publish":
        publish(arguments.online, arguments.staging, *common[1:])
    elif arguments.command == "recover":
        print(recover(arguments.online, arguments.staging, *common[1:]))
    else:
        fail("unsupported Flutter Pub-cache transaction command")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, FlutterPubCacheOutputError) as error:
        raise SystemExit(f"online-flutter-pub-cache-output: {error}")
