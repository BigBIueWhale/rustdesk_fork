#!/usr/bin/env python3
"""Publish the committed libvpx patch and its native-input receipt safely."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Sequence


FORMAT = "rustdesk-libvpx-local-output-v1"
STATE_NAME = "state.json"
STATE_TEMPORARY_NAME = "state.json.tmp"
STAGING_PATTERN = re.compile(r"\.rustdesk-libvpx-local\.[A-Za-z0-9_]{8,}\Z")
FIX_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
OBJECT_ID_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
SHA512_PATTERN = re.compile(r"[0-9a-f]{128}\Z")
PATCH_SOURCE_RELATIVE = Path("res/vcpkg/libvpx/0005-cve-2026-1861.patch")
KEY_NAME = "libvpx-native-key.txt"
STAGING_LIMIT = 32
MAX_PATCH_BYTES = 2 * 1024 * 1024
MAX_STATE_BYTES = 16 * 1024
CHUNK_SIZE = 1024 * 1024
MOUNTINFO_LIMIT = 8 * 1024 * 1024
RENAME_NOREPLACE = 1


class LocalOutputError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise LocalOutputError(message)


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


def validate_hex(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        fail(f"{label} is malformed")
    return value


def patch_name(fix_commit: str) -> str:
    validate_hex(fix_commit, FIX_COMMIT_PATTERN, "libvpx fix commit")
    return f"libvpx-{fix_commit}.patch"


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


def descriptor_mount_id(descriptor: int) -> int:
    information = os.open(
        f"/proc/self/fdinfo/{descriptor}",
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        content = bytearray()
        while True:
            block = os.read(
                information,
                min(8192, 65537 - len(content)),
            )
            if not block:
                break
            content.extend(block)
            if len(content) > 65536:
                fail("descriptor mount information exceeds its byte bound")
    finally:
        os.close(information)
    values = [
        line[len(b"mnt_id:\t") :]
        for line in bytes(content).splitlines()
        if line.startswith(b"mnt_id:\t")
    ]
    if len(values) != 1 or re.fullmatch(rb"[1-9][0-9]*", values[0]) is None:
        fail("descriptor mount identity is unavailable")
    return int(values[0])


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
                for byte in value[index + 1 : index + 4]
            )
        ):
            fail("malformed mountpoint escape")
        decoded.append(int(value[index + 1 : index + 4], 8))
        index += 4
    return bytes(decoded)


def read_mountpoints() -> tuple[bytes, ...]:
    descriptor = os.open(
        "/proc/self/mountinfo",
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        content = bytearray()
        while True:
            block = os.read(
                descriptor,
                min(CHUNK_SIZE, MOUNTINFO_LIMIT + 1 - len(content)),
            )
            if not block:
                break
            content.extend(block)
            if len(content) > MOUNTINFO_LIMIT:
                fail("/proc/self/mountinfo exceeds its byte bound")
    finally:
        os.close(descriptor)
    mountpoints = []
    for line in bytes(content).splitlines():
        fields = line.split()
        try:
            separator = fields.index(b"-")
        except ValueError:
            fail("malformed /proc/self/mountinfo record")
        if separator < 6:
            fail("short /proc/self/mountinfo record")
        mountpoints.append(decode_mount_path(fields[4]))
    return tuple(mountpoints)


def reject_mount_at_or_below(path: Path) -> None:
    encoded = os.fsencode(path)
    prefix = encoded.rstrip(b"/") + b"/"
    for mountpoint in read_mountpoints():
        if mountpoint == encoded or mountpoint.startswith(prefix):
            fail(
                "private libvpx local-output staging contains a mount: "
                f"{os.fsdecode(mountpoint)}"
            )


def open_directory(path: Path) -> int:
    return os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )


def open_child_directory(parent: int, name: str) -> int:
    try:
        return os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
    except OSError as error:
        fail(f"cannot open directory without following links: {name}: {error}")


def validate_directory(
    descriptor: int,
    uid: int,
    gid: int,
    label: str,
    *,
    modes: set[int],
    expected_device: int | None = None,
    expected_mount: int | None = None,
    expected_identity: tuple[int, int] | None = None,
) -> os.stat_result:
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        fail(f"{label} is not a directory")
    if (metadata.st_uid, metadata.st_gid) != (uid, gid):
        fail(f"{label} is not owned by the acquisition identity")
    if stat.S_IMODE(metadata.st_mode) not in modes:
        fail(f"{label} has an unsafe mode")
    if expected_device is not None and metadata.st_dev != expected_device:
        fail(f"{label} crosses a filesystem boundary")
    if expected_mount is not None and descriptor_mount_id(descriptor) != expected_mount:
        fail(f"{label} crosses a mount boundary")
    if expected_identity is not None and identity(metadata) != expected_identity:
        fail(f"{label} identity changed")
    if os.listxattr(descriptor):
        fail(f"{label} carries extended attributes")
    return metadata


def validate_roots(
    online: Path,
    source_root: Path,
    source_patch: Path,
    uid: int,
    gid: int,
) -> tuple[int, int, os.stat_result, os.stat_result]:
    validate_absolute(online, "online root")
    validate_absolute(source_root, "source root")
    validate_absolute(source_patch, "committed libvpx patch")
    if source_patch != source_root / PATCH_SOURCE_RELATIVE:
        fail("committed libvpx patch is outside its exact source location")
    online_fd = open_directory(online)
    source_fd = open_directory(source_root)
    try:
        online_metadata = validate_directory(
            online_fd,
            uid,
            gid,
            "online root",
            modes={0o700},
        )
        source_metadata = os.fstat(source_fd)
        if not stat.S_ISDIR(source_metadata.st_mode):
            fail("source root is not a directory")
        if source_metadata.st_uid != uid:
            fail("source root is not owned by the acquisition identity")
        if stat.S_IMODE(source_metadata.st_mode) & 0o022:
            fail("source root is group- or world-writable")
        if os.listxattr(source_fd):
            fail("source root carries extended attributes")
        return online_fd, source_fd, online_metadata, source_metadata
    except BaseException:
        os.close(source_fd)
        os.close(online_fd)
        raise


def read_stable_file(
    descriptor: int,
    maximum: int,
    label: str,
) -> tuple[bytes, os.stat_result]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        fail(f"{label} is not a regular file")
    if before.st_size < 0 or before.st_size > maximum:
        fail(f"{label} exceeds its byte bound")
    content = bytearray()
    offset = 0
    while True:
        block = os.pread(
            descriptor,
            min(CHUNK_SIZE, maximum + 1 - len(content)),
            offset,
        )
        if not block:
            break
        content.extend(block)
        offset += len(block)
        if len(content) > maximum:
            fail(f"{label} exceeds its byte bound while reading")
    after = os.fstat(descriptor)
    if stable_file_metadata(before) != stable_file_metadata(after):
        fail(f"{label} changed during its stable read")
    return bytes(content), after


def read_source_patch(
    source_patch: Path,
    uid: int,
    patch_sha512: str,
) -> bytes:
    descriptor = os.open(
        source_patch,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            metadata.st_uid != uid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or os.listxattr(descriptor)
        ):
            fail("committed libvpx patch metadata is not a stable private source")
        content, after = read_stable_file(
            descriptor,
            MAX_PATCH_BYTES,
            "committed libvpx patch",
        )
        if identity(after) != identity(metadata):
            fail("committed libvpx patch identity changed")
        if not content:
            fail("committed libvpx patch is empty")
        if hashlib.sha512(content).hexdigest() != patch_sha512:
            fail("committed libvpx patch does not match its SHA-512 pin")
        return content
    finally:
        os.close(descriptor)


def open_distfiles(
    online_fd: int,
    online_metadata: os.stat_result,
    uid: int,
    gid: int,
) -> tuple[int, os.stat_result]:
    distfiles_fd = open_child_directory(online_fd, "vcpkg-distfiles")
    try:
        metadata = validate_directory(
            distfiles_fd,
            uid,
            gid,
            "vcpkg distfile publication root",
            modes={0o700, 0o755, 0o775},
            expected_device=online_metadata.st_dev,
            expected_mount=descriptor_mount_id(online_fd),
        )
        return distfiles_fd, metadata
    except BaseException:
        os.close(distfiles_fd)
        raise


def optional_open_file(parent: int, name: str) -> int | None:
    try:
        return os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent,
        )
    except FileNotFoundError:
        return None
    except OSError as error:
        fail(f"cannot open local-output file without following links: {name}: {error}")


def expected_bytes_for_record(record: dict[str, object]) -> bytes | None:
    kind = record.get("kind")
    if kind == "key":
        native_key = record.get("native_key")
        if not isinstance(native_key, str) or SHA256_PATTERN.fullmatch(native_key) is None:
            fail("libvpx local-output key state is malformed")
        return (native_key + "\n").encode("ascii")
    if kind == "patch":
        return None
    fail("libvpx local-output record kind is malformed")


def validate_output_file(
    descriptor: int,
    root_fd: int,
    uid: int,
    gid: int,
    record: dict[str, object],
    *,
    candidate: bool,
    expected_identity: tuple[int, int] | None = None,
) -> os.stat_result:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        fail("libvpx local output is not one single-link regular file")
    if expected_identity is not None and identity(metadata) != expected_identity:
        fail("libvpx local-output candidate identity changed")
    if (
        metadata.st_dev != os.fstat(root_fd).st_dev
        or descriptor_mount_id(descriptor) != descriptor_mount_id(root_fd)
    ):
        fail("libvpx local output crosses a filesystem or mount boundary")
    mode = stat.S_IMODE(metadata.st_mode)
    if candidate:
        if (metadata.st_uid, metadata.st_gid, mode) != (uid, gid, 0o400):
            fail("libvpx local-output candidate is not current-owner mode 0400")
    else:
        profiles = {
            (uid, gid, 0o400),
            (uid, gid, 0o444),
            (uid, gid, 0o644),
            (uid, gid, 0o664),
            (0, 0, 0o444),
            (0, 0, 0o644),
        }
        if (metadata.st_uid, metadata.st_gid, mode) not in profiles:
            fail("published libvpx local output is outside its closed metadata profiles")
    if os.listxattr(descriptor):
        fail("libvpx local output carries extended attributes")
    size = record.get("size")
    sha256 = record.get("sha256")
    if (
        type(size) is not int
        or size < 1
        or size > MAX_PATCH_BYTES
        or not isinstance(sha256, str)
        or SHA256_PATTERN.fullmatch(sha256) is None
    ):
        fail("libvpx local-output byte contract is malformed")
    content, after = read_stable_file(
        descriptor,
        size,
        "libvpx local output",
    )
    if len(content) != size or hashlib.sha256(content).hexdigest() != sha256:
        fail("libvpx local output differs from its exact byte contract")
    expected = expected_bytes_for_record(record)
    if expected is not None and content != expected:
        fail("libvpx native-key receipt bytes are malformed")
    if record.get("kind") == "patch":
        patch_sha512 = record.get("sha512")
        if (
            not isinstance(patch_sha512, str)
            or SHA512_PATTERN.fullmatch(patch_sha512) is None
            or hashlib.sha512(content).hexdigest() != patch_sha512
        ):
            fail("libvpx security patch differs from its SHA-512 pin")
    if identity(after) != identity(metadata):
        fail("libvpx local output identity changed during validation")
    return after


def output_records(
    fix_commit: str,
    patch: bytes,
    patch_sha512: str,
    native_key: str,
) -> tuple[dict[str, object], dict[str, object]]:
    return (
        {
            "kind": "patch",
            "name": patch_name(fix_commit),
            "size": len(patch),
            "sha256": hashlib.sha256(patch).hexdigest(),
            "sha512": patch_sha512,
        },
        {
            "kind": "key",
            "name": KEY_NAME,
            "size": len(native_key) + 1,
            "sha256": hashlib.sha256((native_key + "\n").encode("ascii")).hexdigest(),
            "native_key": native_key,
        },
    )


def validate_record(record: object) -> dict[str, object]:
    if not isinstance(record, dict):
        fail("libvpx local-output record is not an object")
    kind = record.get("kind")
    expected_keys = {
        "patch": {"kind", "name", "size", "sha256", "sha512", "identity"},
        "key": {"kind", "name", "size", "sha256", "native_key", "identity"},
    }
    if kind not in expected_keys or set(record) != expected_keys[kind]:
        fail("libvpx local-output record schema is malformed")
    name = record["name"]
    if not isinstance(name, str):
        fail("libvpx local-output destination name is malformed")
    if kind == "patch":
        if re.fullmatch(r"libvpx-[0-9a-f]{40}\.patch", name) is None:
            fail("libvpx patch destination name is malformed")
        validate_hex(record["sha512"], SHA512_PATTERN, "libvpx patch SHA-512")
    elif name != KEY_NAME:
        fail("libvpx native-key destination name changed")
    validate_hex(record["sha256"], SHA256_PATTERN, "local-output SHA-256")
    expected_bytes_for_record(record)
    decode_identity(record["identity"], f"{kind} candidate")
    return record


def read_state(
    staging_fd: int,
) -> tuple[dict[str, object], tuple[int, int]]:
    descriptor = optional_open_file(staging_fd, STATE_NAME)
    if descriptor is None:
        fail("libvpx local-output transaction state is absent")
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or os.listxattr(descriptor)
        ):
            fail("libvpx local-output transaction state metadata is unsafe")
        encoded, after = read_stable_file(
            descriptor,
            MAX_STATE_BYTES,
            "libvpx local-output transaction state",
        )
    finally:
        os.close(descriptor)
    try:
        state = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"libvpx local-output transaction state is malformed: {error}")
    expected_keys = {
        "format",
        "online_identity",
        "distfiles_identity",
        "staging_identity",
        "uid",
        "gid",
        "source_commit",
        "source_tree",
        "source_blob",
        "outputs",
    }
    if not isinstance(state, dict) or set(state) != expected_keys:
        fail("libvpx local-output transaction state has an unexpected schema")
    if state["format"] != FORMAT:
        fail("libvpx local-output transaction format changed")
    if state["uid"] != os.geteuid() or state["gid"] != os.getegid():
        fail("libvpx local-output transaction owner changed")
    for key in ("source_commit", "source_tree", "source_blob"):
        value = state[key]
        if not isinstance(value, str) or OBJECT_ID_PATTERN.fullmatch(value) is None:
            fail(f"libvpx local-output {key} is malformed")
    outputs = state["outputs"]
    if not isinstance(outputs, list) or len(outputs) != 2:
        fail("libvpx local-output transaction must name exactly two outputs")
    records = [validate_record(record) for record in outputs]
    if [record["kind"] for record in records] != ["patch", "key"]:
        fail("libvpx local-output publication order changed")
    return state, identity(after)


def validate_state_authority(
    state: dict[str, object],
    expected_records: Sequence[dict[str, object]],
    source_commit: str,
    source_tree: str,
    source_blob: str,
) -> None:
    if (
        state["source_commit"] != source_commit
        or state["source_tree"] != source_tree
        or state["source_blob"] != source_blob
    ):
        fail("recorded libvpx local-output source authority changed")
    records = [validate_record(record) for record in state["outputs"]]
    if len(records) != len(expected_records):
        fail("recorded libvpx local-output byte authority changed")
    for record, expected in zip(records, expected_records):
        without_identity = {
            key: value for key, value in record.items() if key != "identity"
        }
        expected_without_identity = {
            key: value for key, value in expected.items() if key != "identity"
        }
        if without_identity != expected_without_identity:
            fail("recorded libvpx local-output byte authority changed")


def write_full(descriptor: int, content: bytes, label: str) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:
            fail(f"short write while creating {label}")
        offset += written


def create_candidate(
    staging_fd: int,
    name: str,
    content: bytes,
) -> tuple[int, int]:
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=staging_fd,
        )
    except OSError as error:
        fail(f"cannot exclusively create local-output candidate {name}: {error}")
    try:
        write_full(descriptor, content, name)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        return identity(os.fstat(descriptor))
    finally:
        os.close(descriptor)


def write_state(staging_fd: int, state: dict[str, object]) -> None:
    encoded = (
        json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_STATE_BYTES:
        fail("libvpx local-output transaction state exceeds its byte bound")
    descriptor = os.open(
        STATE_TEMPORARY_NAME,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
        dir_fd=staging_fd,
    )
    try:
        write_full(descriptor, encoded, "libvpx local-output state")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    renameat2(
        staging_fd,
        STATE_TEMPORARY_NAME,
        staging_fd,
        STATE_NAME,
    )
    os.fsync(staging_fd)


def renameat2(
    source_directory: int,
    source_name: str,
    destination_directory: int,
    destination_name: str,
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
    if (
        function(
            source_directory,
            os.fsencode(source_name),
            destination_directory,
            os.fsencode(destination_name),
            RENAME_NOREPLACE,
        )
        != 0
    ):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), source_name, destination_name)


def validate_final(
    distfiles_fd: int,
    online_fd: int,
    uid: int,
    gid: int,
    record: dict[str, object],
) -> os.stat_result | None:
    descriptor = optional_open_file(distfiles_fd, str(record["name"]))
    if descriptor is None:
        return None
    try:
        return validate_output_file(
            descriptor,
            online_fd,
            uid,
            gid,
            record,
            candidate=False,
        )
    finally:
        os.close(descriptor)


def unlink_exact(
    parent_fd: int,
    name: str,
    expected_identity: tuple[int, int],
) -> None:
    edge = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (
        not stat.S_ISREG(edge.st_mode)
        or edge.st_nlink != 1
        or identity(edge) != expected_identity
    ):
        fail(f"local-output staging edge changed before retirement: {name}")
    os.unlink(name, dir_fd=parent_fd)
    os.fsync(parent_fd)


def publish_record(
    staging_fd: int,
    distfiles_fd: int,
    online_fd: int,
    uid: int,
    gid: int,
    record: dict[str, object],
) -> None:
    name = str(record["name"])
    expected = decode_identity(record["identity"], f"{record['kind']} candidate")
    candidate_fd = optional_open_file(staging_fd, name)
    if candidate_fd is None:
        fail(f"libvpx local-output candidate disappeared before publication: {name}")
    try:
        validate_output_file(
            candidate_fd,
            online_fd,
            uid,
            gid,
            record,
            candidate=True,
            expected_identity=expected,
        )
    finally:
        os.close(candidate_fd)
    final = validate_final(distfiles_fd, online_fd, uid, gid, record)
    if final is not None:
        unlink_exact(staging_fd, name, expected)
        return
    try:
        renameat2(staging_fd, name, distfiles_fd, name)
    except OSError as error:
        if error.errno != errno.EEXIST:
            raise
        final = validate_final(distfiles_fd, online_fd, uid, gid, record)
        if final is None:
            fail("no-clobber publication reported an absent libvpx destination")
        unlink_exact(staging_fd, name, expected)
        return
    os.fsync(staging_fd)
    os.fsync(distfiles_fd)
    descriptor = optional_open_file(distfiles_fd, name)
    if descriptor is None:
        fail("published libvpx local output disappeared")
    try:
        validate_output_file(
            descriptor,
            online_fd,
            uid,
            gid,
            record,
            candidate=True,
            expected_identity=expected,
        )
    finally:
        os.close(descriptor)


def staging_names(staging_fd: int) -> list[str]:
    with os.scandir(staging_fd) as iterator:
        names = sorted((entry.name for entry in iterator), key=os.fsencode)
    if len(names) > 4:
        fail("libvpx local-output staging exceeds its inventory bound")
    return names


def validate_unprepared_entry(
    staging_fd: int,
    online_fd: int,
    name: str,
    uid: int,
    gid: int,
) -> tuple[int, int]:
    if name in (STATE_NAME,):
        fail("libvpx local-output staging state cannot be parsed")
    if (
        name not in (KEY_NAME, STATE_TEMPORARY_NAME)
        and re.fullmatch(r"libvpx-[0-9a-f]{40}\.patch", name) is None
    ):
        fail("unprepared libvpx local-output staging has an unexpected entry")
    descriptor = optional_open_file(staging_fd, name)
    if descriptor is None:
        fail("unprepared libvpx local-output entry disappeared")
    try:
        metadata = os.fstat(descriptor)
        maximum = MAX_STATE_BYTES if name == STATE_TEMPORARY_NAME else MAX_PATCH_BYTES
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != (uid, gid)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) not in (0o400, 0o600)
            or metadata.st_size < 0
            or metadata.st_size > maximum
            or metadata.st_dev != os.fstat(online_fd).st_dev
            or descriptor_mount_id(descriptor) != descriptor_mount_id(online_fd)
            or os.listxattr(descriptor)
        ):
            fail("unprepared libvpx local-output staging metadata is unsafe")
        return identity(metadata)
    finally:
        os.close(descriptor)


def retire_unprepared(
    online_fd: int,
    staging_fd: int,
    uid: int,
    gid: int,
) -> None:
    entries = [
        (name, validate_unprepared_entry(staging_fd, online_fd, name, uid, gid))
        for name in staging_names(staging_fd)
    ]
    for name, expected in entries:
        unlink_exact(staging_fd, name, expected)


def retire_recorded(
    online_fd: int,
    distfiles_fd: int,
    staging_fd: int,
    state: dict[str, object],
    state_identity: tuple[int, int],
    uid: int,
    gid: int,
) -> None:
    records = [validate_record(record) for record in state["outputs"]]
    allowed = {STATE_NAME, *(str(record["name"]) for record in records)}
    names = set(staging_names(staging_fd))
    if not names.issubset(allowed) or STATE_NAME not in names:
        fail("recorded libvpx local-output staging inventory is incoherent")
    for record in records:
        name = str(record["name"])
        expected = decode_identity(record["identity"], f"{record['kind']} candidate")
        candidate = optional_open_file(staging_fd, name)
        final_metadata = validate_final(distfiles_fd, online_fd, uid, gid, record)
        if candidate is not None:
            try:
                validate_output_file(
                    candidate,
                    online_fd,
                    uid,
                    gid,
                    record,
                    candidate=True,
                    expected_identity=expected,
                )
            finally:
                os.close(candidate)
            unlink_exact(staging_fd, name, expected)
        elif final_metadata is None:
            fail("recorded libvpx local-output candidate has no exact final")
    current_state, current_identity = read_state(staging_fd)
    if current_state != state or current_identity != state_identity:
        fail("libvpx local-output state changed before retirement")
    unlink_exact(staging_fd, STATE_NAME, state_identity)


def retire_staging(
    online: Path,
    online_fd: int,
    distfiles_fd: int,
    staging: Path,
    uid: int,
    gid: int,
    expected_records: Sequence[dict[str, object]],
    source_commit: str,
    source_tree: str,
    source_blob: str,
) -> None:
    if staging.parent != online or STAGING_PATTERN.fullmatch(staging.name) is None:
        fail("libvpx local-output staging name is outside its reserved namespace")
    staging_fd = open_child_directory(online_fd, staging.name)
    try:
        metadata = validate_directory(
            staging_fd,
            uid,
            gid,
            "libvpx local-output staging",
            modes={0o700},
            expected_device=os.fstat(online_fd).st_dev,
            expected_mount=descriptor_mount_id(online_fd),
        )
        reject_mount_at_or_below(staging)
        names = staging_names(staging_fd)
        if STATE_NAME in names:
            state, state_identity = read_state(staging_fd)
            validate_state_authority(
                state,
                expected_records,
                source_commit,
                source_tree,
                source_blob,
            )
            if decode_identity(state["online_identity"], "recorded online root") != identity(
                os.fstat(online_fd)
            ):
                fail("online root identity changed during local-output transaction")
            if decode_identity(
                state["distfiles_identity"], "recorded distfile root"
            ) != identity(os.fstat(distfiles_fd)):
                fail("vcpkg distfile root identity changed during local-output transaction")
            if decode_identity(
                state["staging_identity"], "recorded staging root"
            ) != identity(metadata):
                fail("libvpx local-output staging identity changed")
            retire_recorded(
                online_fd,
                distfiles_fd,
                staging_fd,
                state,
                state_identity,
                uid,
                gid,
            )
        else:
            retire_unprepared(online_fd, staging_fd, uid, gid)
        if staging_names(staging_fd):
            fail("libvpx local-output staging remains nonempty after retirement")
        os.fsync(staging_fd)
        expected_staging = identity(metadata)
    finally:
        os.close(staging_fd)
    edge = os.stat(staging.name, dir_fd=online_fd, follow_symlinks=False)
    if identity(edge) != expected_staging:
        fail("libvpx local-output staging edge changed before directory retirement")
    os.rmdir(staging.name, dir_fd=online_fd)
    os.fsync(online_fd)


def recover_staging(
    online: Path,
    online_fd: int,
    distfiles_fd: int,
    uid: int,
    gid: int,
    expected_records: Sequence[dict[str, object]],
    source_commit: str,
    source_tree: str,
    source_blob: str,
) -> None:
    with os.scandir(online_fd) as iterator:
        names = sorted(
            (
                entry.name
                for entry in iterator
                if entry.name.startswith(".rustdesk-libvpx-local.")
            ),
            key=os.fsencode,
        )
    if len(names) > STAGING_LIMIT:
        fail("reserved libvpx local-output staging exceeds its count bound")
    for name in names:
        if STAGING_PATTERN.fullmatch(name) is None:
            fail(f"malformed reserved libvpx local-output entry: {name}")
        retire_staging(
            online,
            online_fd,
            distfiles_fd,
            online / name,
            uid,
            gid,
            expected_records,
            source_commit,
            source_tree,
            source_blob,
        )


def create_staging(
    online: Path,
    online_fd: int,
    uid: int,
    gid: int,
) -> tuple[Path, int, os.stat_result]:
    staging = Path(
        tempfile.mkdtemp(prefix=".rustdesk-libvpx-local.", dir=online)
    )
    staging_fd = open_child_directory(online_fd, staging.name)
    try:
        metadata = validate_directory(
            staging_fd,
            uid,
            gid,
            "libvpx local-output staging",
            modes={0o700},
            expected_device=os.fstat(online_fd).st_dev,
            expected_mount=descriptor_mount_id(online_fd),
        )
        reject_mount_at_or_below(staging)
        os.fsync(online_fd)
        return staging, staging_fd, metadata
    except BaseException:
        os.close(staging_fd)
        raise


def publish_local_outputs(
    online: Path,
    source_root: Path,
    source_patch: Path,
    uid: int,
    gid: int,
    fix_commit: str,
    patch_sha512: str,
    native_key: str,
    source_commit: str,
    source_tree: str,
    source_blob: str,
) -> str:
    if uid == 0 or gid == 0 or (os.geteuid(), os.getegid()) != (uid, gid):
        fail("libvpx local-output publication requires the invoking non-root identity")
    validate_hex(fix_commit, FIX_COMMIT_PATTERN, "libvpx fix commit")
    validate_hex(patch_sha512, SHA512_PATTERN, "libvpx patch SHA-512")
    validate_hex(native_key, SHA256_PATTERN, "libvpx native key")
    for value, label in (
        (source_commit, "source commit"),
        (source_tree, "source tree"),
        (source_blob, "source blob"),
    ):
        validate_hex(value, OBJECT_ID_PATTERN, label)
    online_fd, source_fd, online_metadata, _ = validate_roots(
        online,
        source_root,
        source_patch,
        uid,
        gid,
    )
    try:
        patch = read_source_patch(source_patch, uid, patch_sha512)
        records = [
            dict(record)
            for record in output_records(
                fix_commit,
                patch,
                patch_sha512,
                native_key,
            )
        ]
        distfiles_fd, distfiles_metadata = open_distfiles(
            online_fd,
            online_metadata,
            uid,
            gid,
        )
        try:
            recover_staging(
                online,
                online_fd,
                distfiles_fd,
                uid,
                gid,
                records,
                source_commit,
                source_tree,
                source_blob,
            )
            finals = [
                validate_final(distfiles_fd, online_fd, uid, gid, record)
                for record in records
            ]
            if all(metadata is not None for metadata in finals):
                return "complete"
            staging, staging_fd, staging_metadata = create_staging(
                online,
                online_fd,
                uid,
                gid,
            )
            try:
                contents = (patch, (native_key + "\n").encode("ascii"))
                for record, content in zip(records, contents):
                    record["identity"] = encode_identity(
                        create_candidate(
                            staging_fd,
                            str(record["name"]),
                            content,
                        )
                    )
                state = {
                    "format": FORMAT,
                    "online_identity": encode_identity(identity(online_metadata)),
                    "distfiles_identity": encode_identity(identity(distfiles_metadata)),
                    "staging_identity": encode_identity(identity(staging_metadata)),
                    "uid": uid,
                    "gid": gid,
                    "source_commit": source_commit,
                    "source_tree": source_tree,
                    "source_blob": source_blob,
                    "outputs": records,
                }
                write_state(staging_fd, state)
                for record in records:
                    descriptor = optional_open_file(staging_fd, str(record["name"]))
                    if descriptor is None:
                        fail("libvpx local-output candidate disappeared after prepare")
                    try:
                        validate_output_file(
                            descriptor,
                            online_fd,
                            uid,
                            gid,
                            record,
                            candidate=True,
                            expected_identity=decode_identity(
                                record["identity"],
                                f"{record['kind']} candidate",
                            ),
                        )
                    finally:
                        os.close(descriptor)
                os.fsync(staging_fd)
                for record in records:
                    publish_record(
                        staging_fd,
                        distfiles_fd,
                        online_fd,
                        uid,
                        gid,
                        record,
                    )
                for record in records:
                    if validate_final(
                        distfiles_fd,
                        online_fd,
                        uid,
                        gid,
                        record,
                    ) is None:
                        fail("libvpx local-output publication is incomplete")
            finally:
                os.close(staging_fd)
            retire_staging(
                online,
                online_fd,
                distfiles_fd,
                staging,
                uid,
                gid,
                records,
                source_commit,
                source_tree,
                source_blob,
            )
            for record in records:
                if validate_final(
                    distfiles_fd,
                    online_fd,
                    uid,
                    gid,
                    record,
                ) is None:
                    fail("libvpx local output disappeared after staging retirement")
            return "published"
        finally:
            os.close(distfiles_fd)
    finally:
        os.close(source_fd)
        os.close(online_fd)


def check_local_outputs(
    online: Path,
    source_root: Path,
    source_patch: Path,
    uid: int,
    gid: int,
    fix_commit: str,
    patch_sha512: str,
    native_key: str,
    source_commit: str,
    source_tree: str,
    source_blob: str,
) -> None:
    if uid == 0 or gid == 0 or (os.geteuid(), os.getegid()) != (uid, gid):
        fail("libvpx local-output validation requires the invoking non-root identity")
    validate_hex(fix_commit, FIX_COMMIT_PATTERN, "libvpx fix commit")
    validate_hex(patch_sha512, SHA512_PATTERN, "libvpx patch SHA-512")
    validate_hex(native_key, SHA256_PATTERN, "libvpx native key")
    for value, label in (
        (source_commit, "source commit"),
        (source_tree, "source tree"),
        (source_blob, "source blob"),
    ):
        validate_hex(value, OBJECT_ID_PATTERN, label)
    online_fd, source_fd, online_metadata, _ = validate_roots(
        online,
        source_root,
        source_patch,
        uid,
        gid,
    )
    try:
        patch = read_source_patch(source_patch, uid, patch_sha512)
        records = output_records(
            fix_commit,
            patch,
            patch_sha512,
            native_key,
        )
        distfiles_fd, _ = open_distfiles(
            online_fd,
            online_metadata,
            uid,
            gid,
        )
        try:
            with os.scandir(online_fd) as iterator:
                reserved = [
                    entry.name
                    for entry in iterator
                    if entry.name.startswith(".rustdesk-libvpx-local.")
                ]
            if reserved:
                fail("reserved libvpx local-output staging remains unreconciled")
            for record in records:
                if validate_final(
                    distfiles_fd,
                    online_fd,
                    uid,
                    gid,
                    record,
                ) is None:
                    fail(f"libvpx local output is missing: {record['name']}")
        finally:
            os.close(distfiles_fd)
    finally:
        os.close(source_fd)
        os.close(online_fd)


def expect_failure(action, message: str) -> None:
    try:
        action()
    except (OSError, LocalOutputError):
        return
    fail(message)


def fixture_source(root: Path, patch: bytes) -> tuple[Path, Path]:
    source = root / "source"
    source.mkdir(mode=0o700)
    source.chmod(0o700)
    patch_path = source / PATCH_SOURCE_RELATIVE
    patch_path.parent.mkdir(parents=True)
    patch_path.write_bytes(patch)
    patch_path.chmod(0o644)
    return source, patch_path


def fixture_online(root: Path, name: str) -> Path:
    online = root / name
    online.mkdir(mode=0o700)
    (online / "vcpkg-distfiles").mkdir(mode=0o700)
    return online


def self_test() -> None:
    uid = os.geteuid()
    gid = os.getegid()
    if uid == 0 or gid == 0:
        fail("libvpx local-output self-test refuses root")
    patch = b"committed libvpx security patch fixture\n"
    patch_sha512 = hashlib.sha512(patch).hexdigest()
    native_key = hashlib.sha256(b"native input fixture").hexdigest()
    fix_commit = "1" * 40
    source_commit = "2" * 40
    source_tree = "3" * 40
    source_blob = "4" * 40
    with tempfile.TemporaryDirectory(prefix="libvpx-local-output-self-test.") as temporary:
        root = Path(temporary)
        source, source_patch = fixture_source(root, patch)

        online = fixture_online(root, "normal")
        result = publish_local_outputs(
            online,
            source,
            source_patch,
            uid,
            gid,
            fix_commit,
            patch_sha512,
            native_key,
            source_commit,
            source_tree,
            source_blob,
        )
        if result != "published":
            fail("self-test did not publish the libvpx local outputs")
        patch_final = online / "vcpkg-distfiles" / patch_name(fix_commit)
        key_final = online / "vcpkg-distfiles" / KEY_NAME
        identities = (identity(os.lstat(patch_final)), identity(os.lstat(key_final)))
        if (
            patch_final.read_bytes() != patch
            or key_final.read_bytes() != (native_key + "\n").encode("ascii")
            or stat.S_IMODE(os.lstat(patch_final).st_mode) != 0o400
            or stat.S_IMODE(os.lstat(key_final).st_mode) != 0o400
        ):
            fail("self-test published wrong libvpx local-output bytes or modes")
        if (
            publish_local_outputs(
                online,
                source,
                source_patch,
                uid,
                gid,
                fix_commit,
                patch_sha512,
                native_key,
                source_commit,
                source_tree,
                source_blob,
            )
            != "complete"
            or identities
            != (identity(os.lstat(patch_final)), identity(os.lstat(key_final)))
        ):
            fail("self-test replaced an exact occupied libvpx local output")
        patch_final.chmod(0o664)
        key_final.chmod(0o664)
        if (
            publish_local_outputs(
                online,
                source,
                source_patch,
                uid,
                gid,
                fix_commit,
                patch_sha512,
                native_key,
                source_commit,
                source_tree,
                source_blob,
            )
            != "complete"
        ):
            fail("self-test rejected exact historical libvpx local-output metadata")

        mixed = fixture_online(root, "exact-patch-missing-key")
        mixed_patch = mixed / "vcpkg-distfiles" / patch_name(fix_commit)
        mixed_key = mixed / "vcpkg-distfiles" / KEY_NAME
        mixed_patch.write_bytes(patch)
        mixed_patch.chmod(0o664)
        mixed_patch_identity = identity(os.lstat(mixed_patch))
        if (
            publish_local_outputs(
                mixed,
                source,
                source_patch,
                uid,
                gid,
                fix_commit,
                patch_sha512,
                native_key,
                source_commit,
                source_tree,
                source_blob,
            )
            != "published"
            or identity(os.lstat(mixed_patch)) != mixed_patch_identity
            or mixed_key.read_bytes() != (native_key + "\n").encode("ascii")
        ):
            fail("self-test did not consume an exact occupied patch duplicate")
        check_local_outputs(
            online,
            source,
            source_patch,
            uid,
            gid,
            fix_commit,
            patch_sha512,
            native_key,
            source_commit,
            source_tree,
            source_blob,
        )
        unresolved = Path(
            tempfile.mkdtemp(prefix=".rustdesk-libvpx-local.", dir=online)
        )
        expect_failure(
            lambda: check_local_outputs(
                online,
                source,
                source_patch,
                uid,
                gid,
                fix_commit,
                patch_sha512,
                native_key,
                source_commit,
                source_tree,
                source_blob,
            ),
            "self-test accepted unreconciled state in the read-only consumer",
        )
        if not unresolved.is_dir():
            fail("self-test read-only consumer mutated unreconciled state")
        unresolved.rmdir()

        wrong = fixture_online(root, "wrong")
        wrong_patch = wrong / "vcpkg-distfiles" / patch_name(fix_commit)
        wrong_patch.write_bytes(b"wrong")
        wrong_patch.chmod(0o664)
        expect_failure(
            lambda: publish_local_outputs(
                wrong,
                source,
                source_patch,
                uid,
                gid,
                fix_commit,
                patch_sha512,
                native_key,
                source_commit,
                source_tree,
                source_blob,
            ),
            "self-test overwrote an occupied wrong libvpx destination",
        )
        if wrong_patch.read_bytes() != b"wrong":
            fail("self-test changed an occupied wrong libvpx destination")

        partial = fixture_online(root, "partial")
        partial_staging = Path(
            tempfile.mkdtemp(prefix=".rustdesk-libvpx-local.", dir=partial)
        )
        partial_file = partial_staging / patch_name(fix_commit)
        partial_file.write_bytes(b"partial")
        partial_file.chmod(0o600)
        if (
            publish_local_outputs(
                partial,
                source,
                source_patch,
                uid,
                gid,
                fix_commit,
                patch_sha512,
                native_key,
                source_commit,
                source_tree,
                source_blob,
            )
            != "published"
            or partial_staging.exists()
        ):
            fail("self-test did not reconcile interrupted unprepared local output")

        stale = fixture_online(root, "stale-recorded")
        stale_records = [
            dict(record)
            for record in output_records(
                fix_commit,
                patch,
                patch_sha512,
                native_key,
            )
        ]
        stale_online_fd = open_directory(stale)
        stale_staging_fd = -1
        stale_distfiles_fd = -1
        try:
            stale_online_metadata = validate_directory(
                stale_online_fd,
                uid,
                gid,
                "self-test stale online root",
                modes={0o700},
            )
            stale_distfiles_fd, stale_distfiles_metadata = open_distfiles(
                stale_online_fd,
                stale_online_metadata,
                uid,
                gid,
            )
            stale_staging, stale_staging_fd, stale_staging_metadata = create_staging(
                stale,
                stale_online_fd,
                uid,
                gid,
            )
            for record, content in zip(
                stale_records,
                (patch, (native_key + "\n").encode("ascii")),
            ):
                record["identity"] = encode_identity(
                    create_candidate(
                        stale_staging_fd,
                        str(record["name"]),
                        content,
                    )
                )
            write_state(
                stale_staging_fd,
                {
                    "format": FORMAT,
                    "online_identity": encode_identity(identity(stale_online_metadata)),
                    "distfiles_identity": encode_identity(
                        identity(stale_distfiles_metadata)
                    ),
                    "staging_identity": encode_identity(identity(stale_staging_metadata)),
                    "uid": uid,
                    "gid": gid,
                    "source_commit": "5" * 40,
                    "source_tree": source_tree,
                    "source_blob": source_blob,
                    "outputs": stale_records,
                },
            )
        finally:
            if stale_staging_fd >= 0:
                os.close(stale_staging_fd)
            if stale_distfiles_fd >= 0:
                os.close(stale_distfiles_fd)
            os.close(stale_online_fd)
        expect_failure(
            lambda: publish_local_outputs(
                stale,
                source,
                source_patch,
                uid,
                gid,
                fix_commit,
                patch_sha512,
                native_key,
                source_commit,
                source_tree,
                source_blob,
            ),
            "self-test accepted recorded staging from a different source authority",
        )
        if not stale_staging.is_dir() or not (stale_staging / STATE_NAME).is_file():
            fail("self-test removed mismatched recorded source authority")

        symlinked = fixture_online(root, "symlinked")
        symlink_staging = Path(
            tempfile.mkdtemp(prefix=".rustdesk-libvpx-local.", dir=symlinked)
        )
        (symlink_staging / KEY_NAME).symlink_to("/dev/null")
        expect_failure(
            lambda: publish_local_outputs(
                symlinked,
                source,
                source_patch,
                uid,
                gid,
                fix_commit,
                patch_sha512,
                native_key,
                source_commit,
                source_tree,
                source_blob,
            ),
            "self-test accepted a symlinked stale local-output entry",
        )
        if not (symlink_staging / KEY_NAME).is_symlink():
            fail("self-test removed incoherent symlinked staging")

        hardlinked = fixture_online(root, "hardlinked")
        hardlink_staging = Path(
            tempfile.mkdtemp(prefix=".rustdesk-libvpx-local.", dir=hardlinked)
        )
        hardlink_candidate = hardlink_staging / KEY_NAME
        hardlink_candidate.write_bytes(b"partial")
        hardlink_candidate.chmod(0o600)
        os.link(hardlink_candidate, hardlinked / "external-link")
        expect_failure(
            lambda: publish_local_outputs(
                hardlinked,
                source,
                source_patch,
                uid,
                gid,
                fix_commit,
                patch_sha512,
                native_key,
                source_commit,
                source_tree,
                source_blob,
            ),
            "self-test accepted externally hardlinked stale local-output state",
        )
        if not hardlink_candidate.exists():
            fail("self-test removed incoherent externally linked staging")

        source_symlink_root = root / "source-symlink"
        source_symlink_path = source_symlink_root / PATCH_SOURCE_RELATIVE
        source_symlink_path.parent.mkdir(parents=True)
        source_symlink_path.symlink_to(source_patch)
        source_target = fixture_online(root, "source-symlink-target")
        expect_failure(
            lambda: publish_local_outputs(
                source_target,
                source_symlink_root,
                source_symlink_path,
                uid,
                gid,
                fix_commit,
                patch_sha512,
                native_key,
                source_commit,
                source_tree,
                source_blob,
            ),
            "self-test accepted a symlinked committed patch source",
        )

        if hasattr(os, "setxattr"):
            xattr = fixture_online(root, "xattr")
            xattr_key = xattr / "vcpkg-distfiles" / KEY_NAME
            xattr_key.write_bytes((native_key + "\n").encode("ascii"))
            xattr_key.chmod(0o664)
            try:
                os.setxattr(xattr_key, "user.rustdesk-test", b"1")
            except OSError:
                pass
            else:
                expect_failure(
                    lambda: publish_local_outputs(
                        xattr,
                        source,
                        source_patch,
                        uid,
                        gid,
                        fix_commit,
                        patch_sha512,
                        native_key,
                        source_commit,
                        source_tree,
                        source_blob,
                    ),
                    "self-test accepted extended attributes on a published local output",
                )
    print("online-libvpx-local-output: PASS")


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("publish", "check"):
        child = subparsers.add_parser(command)
        child.add_argument("--online", required=True, type=Path)
        child.add_argument("--source-root", required=True, type=Path)
        child.add_argument("--source-patch", required=True, type=Path)
        child.add_argument("--uid", required=True, type=int)
        child.add_argument("--gid", required=True, type=int)
        child.add_argument("--fix-commit", required=True)
        child.add_argument("--patch-sha512", required=True)
        child.add_argument("--native-key", required=True)
        child.add_argument("--source-commit", required=True)
        child.add_argument("--source-tree", required=True)
        child.add_argument("--source-blob", required=True)
    subparsers.add_parser("self-test")
    arguments = parser.parse_args(argv)
    if arguments.command == "self-test":
        self_test()
        return 0
    if arguments.command == "check":
        check_local_outputs(
            arguments.online,
            arguments.source_root,
            arguments.source_patch,
            arguments.uid,
            arguments.gid,
            arguments.fix_commit,
            arguments.patch_sha512,
            arguments.native_key,
            arguments.source_commit,
            arguments.source_tree,
            arguments.source_blob,
        )
        return 0
    result = publish_local_outputs(
        arguments.online,
        arguments.source_root,
        arguments.source_patch,
        arguments.uid,
        arguments.gid,
        arguments.fix_commit,
        arguments.patch_sha512,
        arguments.native_key,
        arguments.source_commit,
        arguments.source_tree,
        arguments.source_blob,
    )
    print(result)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except LocalOutputError as error:
        print(f"[FATAL] {error}", file=sys.stderr)
        raise SystemExit(1)
