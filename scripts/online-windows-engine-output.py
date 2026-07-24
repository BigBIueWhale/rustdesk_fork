#!/usr/bin/env python3
"""Validate and publish the exact Flutter Windows-engine cache archive."""

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
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


STATE_NAME = ".rustdesk-windows-engine-state-v1"
STATE_VERSION = 1
DESTINATION = "flutter-windows-engine.tar.gz"
STAGING_PATTERN = re.compile(r"\.rustdesk-windows-engine\.[A-Za-z0-9_]{8,}\Z")
VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
BLOCK_SIZE = 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_STATE_BYTES = 8192
MOUNTINFO_LIMIT = 8 * 1024 * 1024
RENAME_NOREPLACE = 1
ARCHIVE_MTIME = 1_700_000_000

PROFILE_FILES = frozenset(
    {
        "LICENSE.windows_flutter.md",
        "flutter_export.h",
        "flutter_messenger.h",
        "flutter_plugin_registrar.h",
        "flutter_texture_registrar.h",
        "flutter_windows.dll",
        "flutter_windows.dll.exp",
        "flutter_windows.dll.lib",
        "flutter_windows.dll.pdb",
        "flutter_windows.h",
        "gen_snapshot.exe",
    }
)
MAIN_FILES = frozenset(
    {
        "LICENSE.client_wrapper_archive.md",
        "LICENSE.windows_flutter.md",
        "flutter_export.h",
        "flutter_messenger.h",
        "flutter_plugin_registrar.h",
        "flutter_texture_registrar.h",
        "flutter_windows.dll",
        "flutter_windows.dll.exp",
        "flutter_windows.dll.lib",
        "flutter_windows.dll.pdb",
        "flutter_windows.h",
        "gen_snapshot.exe",
    }
)
CPP_WRAPPER_FILES = frozenset(
    {
        "README",
        "binary_messenger_impl.h",
        "byte_buffer_streams.h",
        "core_implementations.cc",
        "engine_method_result.cc",
        "flutter_engine.cc",
        "flutter_view_controller.cc",
        "include/flutter/basic_message_channel.h",
        "include/flutter/binary_messenger.h",
        "include/flutter/byte_streams.h",
        "include/flutter/dart_project.h",
        "include/flutter/encodable_value.h",
        "include/flutter/engine_method_result.h",
        "include/flutter/event_channel.h",
        "include/flutter/event_sink.h",
        "include/flutter/event_stream_handler.h",
        "include/flutter/event_stream_handler_functions.h",
        "include/flutter/flutter_engine.h",
        "include/flutter/flutter_view.h",
        "include/flutter/flutter_view_controller.h",
        "include/flutter/message_codec.h",
        "include/flutter/method_call.h",
        "include/flutter/method_channel.h",
        "include/flutter/method_codec.h",
        "include/flutter/method_result.h",
        "include/flutter/method_result_functions.h",
        "include/flutter/plugin_registrar.h",
        "include/flutter/plugin_registrar_windows.h",
        "include/flutter/plugin_registry.h",
        "include/flutter/standard_codec_serializer.h",
        "include/flutter/standard_message_codec.h",
        "include/flutter/standard_method_codec.h",
        "include/flutter/texture_registrar.h",
        "plugin_registrar.cc",
        "standard_codec.cc",
        "texture_registrar_impl.h",
    }
)
STAMP_FILES = frozenset(
    {
        "bin/cache/libimobiledevice.stamp",
        "bin/cache/usbmuxd.stamp",
        "bin/cache/windows-sdk.stamp",
    }
)


class WindowsEngineOutputError(RuntimeError):
    pass


@dataclass(frozen=True)
class ArchiveContract:
    names: frozenset[str]
    total_bytes: int


def production_names() -> frozenset[str]:
    engine = "bin/cache/artifacts/engine"
    names = set(STAMP_FILES)
    names.update(f"{engine}/windows-x64-profile/{name}" for name in PROFILE_FILES)
    names.update(f"{engine}/windows-x64-release/{name}" for name in PROFILE_FILES)
    names.update(f"{engine}/windows-x64/{name}" for name in MAIN_FILES)
    names.update(
        f"{engine}/windows-x64/cpp_client_wrapper/{name}"
        for name in CPP_WRAPPER_FILES
    )
    return frozenset(names)


PRODUCTION_CONTRACT = ArchiveContract(
    names=production_names(),
    total_bytes=817_399_293,
)


def fail(message: str) -> None:
    raise WindowsEngineOutputError(message)


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
    source_sha256: str,
    archive_sha256: str,
    archive_size: int,
) -> None:
    if VERSION_PATTERN.fullmatch(version) is None:
        fail("Flutter version is not one canonical three-component version")
    if IMAGE_PATTERN.fullmatch(builder) is None:
        fail("builder is not one immutable Docker image content ID")
    if SHA256_PATTERN.fullmatch(source_sha256) is None:
        fail("Flutter source archive digest is not one lowercase SHA-256 value")
    if SHA256_PATTERN.fullmatch(archive_sha256) is None:
        fail("Windows engine digest is not one lowercase SHA-256 value")
    if archive_size <= 0 or archive_size > MAX_ARCHIVE_BYTES:
        fail("Windows engine archive size is outside its closed byte bound")


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
                "private Windows-engine staging contains a mount: "
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
    validate_absolute(staging, "Windows-engine staging")
    if staging.parent != online or STAGING_PATTERN.fullmatch(staging.name) is None:
        fail("Windows-engine staging is not one reserved direct child")
    metadata = os.lstat(staging)
    if not stat.S_ISDIR(metadata.st_mode):
        fail("Windows-engine staging is not a directory")
    if identity(metadata)[0] != identity(online_metadata)[0]:
        fail("Windows-engine staging is not on the online filesystem")
    if (metadata.st_uid, metadata.st_gid) != (uid, gid):
        fail("Windows-engine staging has foreign ownership")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        fail("Windows-engine staging is not mode 0700")
    if list_xattrs(staging):
        fail("Windows-engine staging carries extended attributes")
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
            fail("Windows engine output is not a regular file")
        if identity(before) != expected_identity:
            fail("Windows engine output identity changed before hashing")
        if before.st_size != expected_size:
            fail(
                "Windows engine archive length is "
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
                fail("Windows engine archive exceeded its byte bound while hashing")
            digest.update(block)
        after = os.fstat(descriptor)
        if stable_file_metadata(before) != stable_file_metadata(after):
            fail("Windows engine archive changed while it was hashed")
        return digest.hexdigest(), after
    finally:
        os.close(descriptor)


def expected_member_mode(name: str) -> int:
    if name in STAMP_FILES or name.endswith("/gen_snapshot.exe"):
        return 0o644
    return 0o666


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
            fail("Windows engine archive identity changed before semantic validation")
        if stable_file_metadata(before) != stable_file_metadata(expected_metadata):
            fail("Windows engine archive metadata changed before semantic validation")
        with os.fdopen(os.dup(descriptor), "rb", closefd=True) as reader:
            try:
                with tarfile.open(fileobj=reader, mode="r:gz") as archive:
                    members = archive.getmembers()
                    if archive.pax_headers:
                        fail("Windows engine archive carries global PAX headers")
            except (OSError, tarfile.TarError, EOFError) as error:
                fail(f"Windows engine archive is not a valid gzip tar: {error}")
        after = os.fstat(descriptor)
        if stable_file_metadata(before) != stable_file_metadata(after):
            fail("Windows engine archive changed during semantic validation")
    finally:
        os.close(descriptor)

    names: set[str] = set()
    total_bytes = 0
    for member in members:
        name = member.name
        try:
            name.encode("ascii")
        except UnicodeEncodeError:
            fail("Windows engine archive contains a non-ASCII member name")
        pure = PurePosixPath(name)
        if (
            not name
            or len(name) > 240
            or name.startswith("/")
            or "\\" in name
            or str(pure) != name
            or any(part in ("", ".", "..") for part in pure.parts)
        ):
            fail(f"Windows engine archive contains a noncanonical path: {name!r}")
        if name in names:
            fail(f"Windows engine archive repeats a member: {name}")
        names.add(name)
        if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
            fail(f"Windows engine archive member is not a regular file: {name}")
        if member.linkname:
            fail(f"Windows engine archive member carries a link target: {name}")
        if member.pax_headers:
            fail(f"Windows engine archive member carries PAX metadata: {name}")
        if (
            member.uid != 0
            or member.gid != 0
            or member.uname != ""
            or member.gname != ""
            or member.devmajor != 0
            or member.devminor != 0
        ):
            fail(f"Windows engine archive member ownership is not canonical: {name}")
        if member.mtime != ARCHIVE_MTIME:
            fail(f"Windows engine archive member mtime is not canonical: {name}")
        expected_mode = expected_member_mode(name)
        if member.mode != expected_mode:
            fail(
                f"Windows engine archive member mode is {member.mode:04o}, "
                f"expected {expected_mode:04o}: {name}"
            )
        if member.size <= 0:
            fail(f"Windows engine archive contains an empty member: {name}")
        total_bytes += member.size
        if total_bytes > contract.total_bytes:
            fail("Windows engine archive uncompressed bytes exceed the contract")
    if names != contract.names:
        missing = sorted(contract.names - names)
        unexpected = sorted(names - contract.names)
        fail(
            "Windows engine archive inventory differs"
            f" (missing={missing[:3]}, unexpected={unexpected[:3]})"
        )
    if total_bytes != contract.total_bytes:
        fail(
            "Windows engine archive contains "
            f"{total_bytes} bytes, expected {contract.total_bytes}"
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
    validate_absolute(archive, "Windows engine archive")
    metadata = os.lstat(archive)
    if not stat.S_ISREG(metadata.st_mode):
        fail("Windows engine archive is not a regular file")
    if online is not None:
        online_metadata = os.lstat(online)
        if identity(metadata)[0] != identity(online_metadata)[0]:
            fail("Windows engine archive is not on the online filesystem")
    if expected_identity is not None and identity(metadata) != expected_identity:
        fail("Windows engine archive identity changed")
    if metadata.st_nlink != 1:
        fail("Windows engine archive has a hardlink outside the transaction")
    mode = stat.S_IMODE(metadata.st_mode)
    owner = (metadata.st_uid, metadata.st_gid)
    if allow_legacy_root and owner == (0, 0):
        if mode != 0o644:
            fail("historical root-owned Windows engine archive is not mode 0644")
    else:
        if owner != (uid, gid):
            fail("Windows engine archive has foreign ownership")
        if mode != staged_mode:
            fail(
                f"Windows engine archive mode is {mode:04o}, "
                f"expected {staged_mode:04o}"
            )
    if list_xattrs(archive):
        fail("Windows engine archive carries extended attributes")
    archive_identity = identity(metadata)
    digest, after = hash_regular_file(archive, archive_identity, expected_size)
    if digest != expected_sha256:
        fail("Windows engine archive SHA-256 does not match its pin")
    validate_archive_semantics(
        archive,
        archive_identity,
        after,
        contract,
    )
    final_metadata = os.lstat(archive)
    if stable_file_metadata(final_metadata) != stable_file_metadata(after):
        fail("Windows engine archive changed after semantic validation")
    return final_metadata


def validate_inventory(staging: Path, expected: set[str]) -> None:
    names = set(os.listdir(staging))
    if names != expected:
        fail("Windows-engine staging inventory is incoherent and was preserved")


def state_payload(
    online: Path,
    staging: Path,
    output: Path,
    uid: int,
    gid: int,
    version: str,
    builder: str,
    source_sha256: str,
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
        "source_sha256": source_sha256,
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
        fail("Windows-engine transaction state exceeds its byte bound")
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
                fail("short write while recording Windows-engine state")
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
            fail("Windows-engine state is not one bounded regular file")
        data = bytearray()
        while True:
            block = os.read(descriptor, min(BLOCK_SIZE, maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
            if len(data) > maximum:
                fail("Windows-engine state exceeded its byte bound")
        after = os.fstat(descriptor)
        if stable_file_metadata(before) != stable_file_metadata(after):
            fail("Windows-engine state changed while it was read")
        return bytes(data)
    finally:
        os.close(descriptor)


def load_state(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    version: str,
    builder: str,
    source_sha256: str,
    archive_sha256: str,
    archive_size: int,
) -> dict[str, object]:
    validate_contract_values(
        version,
        builder,
        source_sha256,
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
        fail("Windows-engine transaction state metadata is unsafe")
    try:
        payload = json.loads(read_bounded_regular_file(state, MAX_STATE_BYTES))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"Windows-engine transaction state is malformed: {error}")
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
        "source_sha256",
        "archive_sha256",
        "archive_size",
        "destination",
    }
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        fail("Windows-engine transaction state schema changed")
    expected_values: dict[str, object] = {
        "version": STATE_VERSION,
        "online": os.fspath(online),
        "uid": uid,
        "gid": gid,
        "staging": os.fspath(staging),
        "flutter_version": version,
        "builder": builder,
        "source_sha256": source_sha256,
        "archive_sha256": archive_sha256,
        "archive_size": archive_size,
        "destination": DESTINATION,
    }
    for key, value in expected_values.items():
        if payload[key] != value:
            fail(f"Windows-engine transaction state changed field {key}")
    decode_identity(payload["output_identity"], "Windows engine output")
    if decode_identity(payload["online_identity"], "online root") != identity(
        os.lstat(online)
    ):
        fail("online root identity changed during the Windows-engine transaction")
    if decode_identity(
        payload["staging_identity"],
        "Windows-engine staging",
    ) != identity(staging_metadata):
        fail("Windows-engine staging identity changed")
    return payload


def prepare(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    version: str,
    builder: str,
    source_sha256: str,
    archive_sha256: str,
    archive_size: int,
) -> None:
    validate_contract_values(
        version,
        builder,
        source_sha256,
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
            source_sha256,
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
    source_sha256: str,
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
        source_sha256,
        archive_sha256,
        archive_size,
    )
    validate_inventory(staging, {STATE_NAME, "output"})
    output = staging / "output"
    expected = decode_identity(payload["output_identity"], "Windows engine output")
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
            fail("Windows engine archive identity changed before mode sealing")
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
    source_sha256: str,
    archive_sha256: str,
    archive_size: int,
) -> None:
    validate_contract_values(
        version,
        builder,
        source_sha256,
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
    if uid == 0 or gid == 0:
        fail("Windows-engine verifier refuses UID or primary GID zero")
    if SHA256_PATTERN.fullmatch(archive_sha256) is None:
        fail("Windows engine digest is not one lowercase SHA-256 value")
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
    source_sha256: str,
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
        source_sha256,
        archive_sha256,
        archive_size,
    )
    validate_inventory(staging, {STATE_NAME, "output"})
    expected = decode_identity(payload["output_identity"], "Windows engine output")
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
        fail("Windows engine destination appeared before no-clobber publication")
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
                    "Windows engine archive publication rollback also failed: "
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
            fail("unprepared Windows-engine temporary state is unsafe")
        allowed.add(temporary_state.name)
    if names != allowed:
        fail("unprepared Windows-engine staging is incoherent and was preserved")
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
        fail("unprepared Windows-engine output is unsafe and was preserved")
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
    source_sha256: str,
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
        source_sha256,
        archive_sha256,
        archive_size,
    )
    output_identity = decode_identity(
        payload["output_identity"],
        "Windows engine output",
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
    fail("Windows-engine transaction state is incoherent and was preserved")


def expect_failure(action, message: str) -> None:
    try:
        action()
    except (OSError, WindowsEngineOutputError):
        return
    fail(message)


def make_fixture(
    entries: dict[str, bytes],
) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(entries):
            payload = entries[name]
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            member.mode = expected_member_mode(name)
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.mtime = ARCHIVE_MTIME
            archive.addfile(member, io.BytesIO(payload))
    return raw.getvalue()


def make_staging(online: Path) -> Path:
    return Path(tempfile.mkdtemp(prefix=".rustdesk-windows-engine.", dir=online))


def run_self_test() -> None:
    uid = os.getuid()
    gid = os.getgid()
    if uid == 0 or gid == 0:
        fail("self-test refuses UID or primary GID zero")
    version = "3.24.5"
    builder = "sha256:" + "1" * 64
    source_sha256 = "2" * 64
    entries = {
        "bin/cache/artifacts/engine/windows-x64/flutter_windows.dll": b"dll",
        "bin/cache/windows-sdk.stamp": b"stamp",
    }
    contract = ArchiveContract(
        names=frozenset(entries),
        total_bytes=sum(len(value) for value in entries.values()),
    )
    fixture = make_fixture(entries)
    archive_sha256 = hashlib.sha256(fixture).hexdigest()
    archive_size = len(fixture)
    arguments = (
        uid,
        gid,
        version,
        builder,
        source_sha256,
        archive_sha256,
        archive_size,
    )
    with tempfile.TemporaryDirectory(
        prefix="windows-engine-output-self-test."
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
            fail("self-test did not classify completed Windows-engine publication")
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
            "self-test accepted a wrong Windows-engine digest",
        )

        wrong_semantics = root / "wrong-semantics"
        wrong_semantics.mkdir(mode=0o700)
        bad_fixture = make_fixture(
            {
                "bin/cache/artifacts/engine/windows-x64/flutter_windows.dll": b"dll",
                "bin/cache/unexpected.stamp": b"stamp",
            }
        )
        bad_arguments = (
            uid,
            gid,
            version,
            builder,
            source_sha256,
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
            "self-test accepted a semantically wrong Windows-engine archive",
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
            "self-test accepted an occupied Windows-engine destination",
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
            fail("self-test did not preserve an occupied engine destination")

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
            "self-test accepted a symlinked Windows-engine output",
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
            "self-test accepted a hardlinked Windows-engine output",
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
                    "self-test accepted xattrs on Windows-engine output",
                )


def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--online", required=True, type=Path)
    parser.add_argument("--uid", required=True, type=int)
    parser.add_argument("--gid", required=True, type=int)
    parser.add_argument("--flutter-version", required=True)
    parser.add_argument("--builder", required=True)
    parser.add_argument("--source-sha256", required=True)
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
    subparsers.add_parser("self-test")
    arguments = parser.parse_args()

    if arguments.command == "self-test":
        run_self_test()
        print("online-windows-engine-output: PASS")
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
        fail("Windows-engine transaction refuses UID or primary GID zero")
    common = (
        arguments.online,
        uid,
        gid,
        arguments.flutter_version,
        arguments.builder,
        arguments.source_sha256,
        arguments.sha256,
        arguments.size,
    )
    if arguments.command == "check-complete":
        check_complete(*common)
    elif arguments.command == "prepare":
        prepare(
            arguments.online,
            arguments.staging,
            *common[1:],
        )
    elif arguments.command == "verify":
        verify_staged(
            arguments.online,
            arguments.staging,
            *common[1:],
        )
    elif arguments.command == "publish":
        publish(
            arguments.online,
            arguments.staging,
            *common[1:],
        )
    elif arguments.command == "recover":
        print(
            recover(
                arguments.online,
                arguments.staging,
                *common[1:],
            )
        )
    else:
        fail("unsupported Windows-engine transaction command")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, WindowsEngineOutputError) as error:
        raise SystemExit(f"online-windows-engine-output: {error}")
