#!/usr/bin/env python3
"""Validate and durably publish the pinned Cargo vendor closure and source map."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


FORMAT = "rustdesk-cargo-vendor-output-v1"
STATE_NAME = "state.jsonl"
VENDOR_NAME = "cargo-vendor"
CONFIG_NAME = "cargo-vendor-config.toml"
RAW_CONFIG_NAME = "raw-config.toml"
TREE_SUFFIX = ".tree"
STAGING_PATTERN = re.compile(r"\.rustdesk-cargo-vendor\.[A-Za-z0-9_]{8,64}\Z")
OBJECT_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
PHASES = (
    "prepared",
    "verified",
    "authorized",
    "publishing",
    "vendor-published",
    "complete",
)
MAX_STATE_BYTES = 64 * 1024
MAX_CONFIG_BYTES = 64 * 1024
MAX_FILES = 60_000
MAX_DIRECTORIES = 15_000
MAX_CONTENT_BYTES = 3 * 1024**3
MAX_FILE_BYTES = 768 * 1024**2
BLOCK_SIZE = 1024 * 1024
MOUNTINFO_LIMIT = 16 * 1024**2
RENAME_NOREPLACE = 1
FORBIDDEN_MODE_BITS = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX


class VendorOutputError(RuntimeError):
    pass


@dataclass(frozen=True)
class Contract:
    source_commit: str
    source_tree: str
    source_archive_sha256: str
    builder: str
    rust_sha256: str
    vendor_sha256: str
    config_sha256: str
    config_vendor_path: str
    config_size: int
    files: int
    directories: int
    content_bytes: int

    def record(self) -> dict[str, object]:
        return {
            "source_commit": self.source_commit,
            "source_tree": self.source_tree,
            "source_archive_sha256": self.source_archive_sha256,
            "builder": self.builder,
            "rust_sha256": self.rust_sha256,
            "vendor_sha256": self.vendor_sha256,
            "config_sha256": self.config_sha256,
            "config_vendor_path": self.config_vendor_path,
            "config_size": self.config_size,
            "files": self.files,
            "directories": self.directories,
            "content_bytes": self.content_bytes,
        }


def fail(message: str) -> None:
    raise VendorOutputError(message)


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


def validate_hex(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        fail(f"{label} is malformed")
    return value


def validate_count(value: int, maximum: int, label: str) -> int:
    if type(value) is not int or value < 1 or value > maximum:
        fail(f"{label} is outside its bound")
    return value


def make_contract(arguments: argparse.Namespace) -> Contract:
    return Contract(
        source_commit=validate_hex(
            arguments.source_commit, OBJECT_PATTERN, "source commit"
        ),
        source_tree=validate_hex(arguments.source_tree, OBJECT_PATTERN, "source tree"),
        source_archive_sha256=validate_hex(
            arguments.source_archive_sha256,
            SHA256_PATTERN,
            "source archive SHA-256",
        ),
        builder=validate_hex(arguments.builder, IMAGE_PATTERN, "builder image"),
        rust_sha256=validate_hex(
            arguments.rust_sha256, SHA256_PATTERN, "Rust archive SHA-256"
        ),
        vendor_sha256=validate_hex(
            arguments.vendor_sha256, SHA256_PATTERN, "Cargo vendor SHA-256"
        ),
        config_sha256=validate_hex(
            arguments.config_sha256, SHA256_PATTERN, "Cargo config SHA-256"
        ),
        config_vendor_path=os.fspath(
            validate_absolute(
                Path(arguments.config_vendor_path),
                "Cargo config vendor",
                must_exist=False,
            )
        ),
        config_size=validate_count(
            arguments.config_size, MAX_CONFIG_BYTES, "Cargo config size"
        ),
        files=validate_count(arguments.files, MAX_FILES, "Cargo vendor file count"),
        directories=validate_count(
            arguments.directories,
            MAX_DIRECTORIES,
            "Cargo vendor directory count",
        ),
        content_bytes=validate_count(
            arguments.content_bytes,
            MAX_CONTENT_BYTES,
            "Cargo vendor content size",
        ),
    )


def validate_absolute(path: Path, label: str, *, must_exist: bool = True) -> Path:
    raw = os.fspath(path)
    if not os.path.isabs(raw) or os.path.normpath(raw) != raw:
        fail(f"{label} path is not absolute and normalized")
    if must_exist:
        try:
            canonical = Path(os.path.realpath(raw, strict=True))
        except OSError as error:
            fail(f"cannot resolve {label}: {error}")
        if canonical != path:
            fail(f"{label} path is not canonical")
    return path


def candidate_vendor_path(staging: Path) -> Path:
    return staging.with_name(staging.name + TREE_SUFFIX)


def descriptor_mount_id(descriptor: int) -> int:
    information = os.open(
        f"/proc/self/fdinfo/{descriptor}",
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        content = bytearray()
        while True:
            block = os.read(information, min(8192, 65537 - len(content)))
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
    result = bytearray()
    index = 0
    while index < len(value):
        if value[index] != ord("\\"):
            result.append(value[index])
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
        result.append(int(value[index + 1 : index + 4], 8))
        index += 4
    return bytes(result)


def mountpoints() -> tuple[bytes, ...]:
    descriptor = os.open(
        "/proc/self/mountinfo",
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        content = bytearray()
        while True:
            block = os.read(
                descriptor,
                min(BLOCK_SIZE, MOUNTINFO_LIMIT + 1 - len(content)),
            )
            if not block:
                break
            content.extend(block)
            if len(content) > MOUNTINFO_LIMIT:
                fail("/proc/self/mountinfo exceeds its byte bound")
    finally:
        os.close(descriptor)
    values = []
    for line in bytes(content).splitlines():
        fields = line.split()
        try:
            separator = fields.index(b"-")
        except ValueError:
            fail("malformed /proc/self/mountinfo record")
        if separator < 6:
            fail("short /proc/self/mountinfo record")
        values.append(decode_mount_path(fields[4]))
    if not values:
        fail("/proc/self/mountinfo has no records")
    return tuple(values)


def reject_mount_at_or_below(path: Path) -> None:
    encoded = os.fsencode(path)
    prefix = encoded.rstrip(b"/") + b"/"
    for mountpoint in mountpoints():
        if mountpoint == encoded or mountpoint.startswith(prefix):
            fail(f"Cargo vendor staging contains a mount: {os.fsdecode(mountpoint)}")


def open_directory(path: Path) -> int:
    return os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )


def open_child_directory(parent: int, name: str) -> int:
    return os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=parent,
    )


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
    staging: Path | None,
    uid: int,
    gid: int,
) -> tuple[int, os.stat_result, int | None, os.stat_result | None]:
    validate_absolute(online, "online root")
    online_fd = open_directory(online)
    staging_fd = None
    try:
        online_metadata = validate_directory(
            online_fd,
            uid,
            gid,
            "online root",
            modes={0o700},
        )
        if staging is None:
            return online_fd, online_metadata, None, None
        validate_absolute(staging, "Cargo vendor staging")
        if staging.parent != online or STAGING_PATTERN.fullmatch(staging.name) is None:
            fail("Cargo vendor staging is outside its reserved namespace")
        staging_fd = open_child_directory(online_fd, staging.name)
        staging_metadata = validate_directory(
            staging_fd,
            uid,
            gid,
            "Cargo vendor staging",
            modes={0o700},
            expected_device=online_metadata.st_dev,
            expected_mount=descriptor_mount_id(online_fd),
        )
        reject_mount_at_or_below(staging)
        return online_fd, online_metadata, staging_fd, staging_metadata
    except BaseException:
        if staging_fd is not None:
            os.close(staging_fd)
        os.close(online_fd)
        raise


def read_stable_file(
    descriptor: int,
    maximum: int,
    label: str,
) -> tuple[bytes, os.stat_result]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > maximum:
        fail(f"{label} is not one bounded regular file")
    content = bytearray()
    offset = 0
    while True:
        block = os.pread(
            descriptor,
            min(BLOCK_SIZE, maximum + 1 - len(content)),
            offset,
        )
        if not block:
            break
        content.extend(block)
        offset += len(block)
        if len(content) > maximum:
            fail(f"{label} exceeds its byte bound")
    after = os.fstat(descriptor)
    if stable_metadata(before) != stable_metadata(after):
        fail(f"{label} changed during its stable read")
    return bytes(content), after


def open_regular(
    parent: int,
    name: str,
    flags: int = os.O_RDONLY,
) -> int:
    return os.open(
        name,
        flags | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=parent,
    )


def optional_lstat(parent: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None


def validate_candidate_file(
    parent: int,
    name: str,
    uid: int,
    gid: int,
    expected_identity: tuple[int, int],
    label: str,
    *,
    modes: set[int],
    maximum: int,
) -> tuple[bytes, os.stat_result]:
    descriptor = open_regular(parent, name)
    try:
        metadata = os.fstat(descriptor)
        if (
            (metadata.st_uid, metadata.st_gid) != (uid, gid)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) not in modes
            or identity(metadata) != expected_identity
            or os.listxattr(descriptor)
        ):
            fail(f"{label} metadata is unsafe or changed")
        return read_stable_file(descriptor, maximum, label)
    finally:
        os.close(descriptor)


def write_full(descriptor: int, content: bytes, label: str) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:
            fail(f"short write while creating {label}")
        offset += written


def fsync_directory(path: Path) -> None:
    descriptor = open_directory(path)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def create_file(parent: int, name: str) -> tuple[int, int]:
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
        dir_fd=parent,
    )
    try:
        os.fsync(descriptor)
        return identity(os.fstat(descriptor))
    finally:
        os.close(descriptor)


def base_state(
    online: Path,
    staging: Path,
    online_metadata: os.stat_result,
    staging_metadata: os.stat_result,
    uid: int,
    gid: int,
    vendor_identity: tuple[int, int],
    raw_identity: tuple[int, int],
    config_identity: tuple[int, int],
    state_identity: tuple[int, int],
    contract: Contract,
) -> dict[str, object]:
    value: dict[str, object] = {
        "format": FORMAT,
        "online": os.fspath(online),
        "staging": os.fspath(staging),
        "uid": uid,
        "gid": gid,
        "online_identity": encode_identity(identity(online_metadata)),
        "staging_identity": encode_identity(identity(staging_metadata)),
        "vendor_identity": encode_identity(vendor_identity),
        "raw_config_identity": encode_identity(raw_identity),
        "config_identity": encode_identity(config_identity),
        "state_identity": encode_identity(state_identity),
    }
    value.update(contract.record())
    return value


def state_record(
    base: dict[str, object],
    sequence: int,
    phase: str,
    vendor_disposition: str,
    config_disposition: str,
) -> dict[str, object]:
    value = dict(base)
    value.update(
        {
            "sequence": sequence,
            "phase": phase,
            "vendor_disposition": vendor_disposition,
            "config_disposition": config_disposition,
        }
    )
    return value


def encoded_record(record: dict[str, object]) -> bytes:
    value = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )
    if len(value) > 8192:
        fail("Cargo vendor state record exceeds its byte bound")
    return value


def append_record(
    staging_fd: int,
    state_identity: tuple[int, int],
    record: dict[str, object],
    *,
    initial: bool = False,
) -> None:
    descriptor = open_regular(staging_fd, STATE_NAME, os.O_WRONLY | os.O_APPEND)
    try:
        before = os.fstat(descriptor)
        if (
            identity(before) != state_identity
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or before.st_gid != os.getegid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size < 0
            or before.st_size > MAX_STATE_BYTES
            or os.listxattr(descriptor)
        ):
            fail("Cargo vendor state journal metadata is unsafe")
        if initial and before.st_size != 0:
            fail("Cargo vendor state journal is not freshly empty")
        value = encoded_record(record)
        if before.st_size + len(value) > MAX_STATE_BYTES:
            fail("Cargo vendor state journal exceeds its byte bound")
        write_full(descriptor, value, "Cargo vendor state journal")
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if identity(after) != state_identity or after.st_size != before.st_size + len(value):
            fail("Cargo vendor state journal changed during append")
    finally:
        os.close(descriptor)
    os.fsync(staging_fd)


def expected_state_keys() -> set[str]:
    return {
        "format",
        "online",
        "staging",
        "uid",
        "gid",
        "online_identity",
        "staging_identity",
        "vendor_identity",
        "raw_config_identity",
        "config_identity",
        "state_identity",
        *Contract.__dataclass_fields__.keys(),
        "sequence",
        "phase",
        "vendor_disposition",
        "config_disposition",
    }


def validate_state_record(
    value: object,
    base: dict[str, object] | None,
    index: int,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected_state_keys():
        fail("Cargo vendor state record has an unexpected schema")
    if (
        value["format"] != FORMAT
        or type(value["sequence"]) is not int
        or value["sequence"] != index
        or type(value["uid"]) is not int
        or type(value["gid"]) is not int
        or value["uid"] < 1
        or value["gid"] < 1
        or not isinstance(value["online"], str)
        or not isinstance(value["staging"], str)
    ):
        fail("Cargo vendor state record version or sequence changed")
    phase = value["phase"]
    if phase not in PHASES:
        fail("Cargo vendor state record has an unknown phase")
    if index == 0 and phase != "prepared":
        fail("Cargo vendor state journal does not begin at prepared")
    if value["vendor_disposition"] not in ("staged", "published", "duplicate"):
        fail("Cargo vendor disposition is malformed")
    if value["config_disposition"] not in ("staged", "published", "duplicate"):
        fail("Cargo vendor config disposition is malformed")
    phase_dispositions = {
        "prepared": ({"staged"}, {"staged"}),
        "verified": ({"staged"}, {"staged"}),
        "authorized": ({"staged"}, {"staged"}),
        "publishing": ({"staged"}, {"staged"}),
        "vendor-published": ({"published", "duplicate"}, {"staged"}),
        "complete": ({"published", "duplicate"}, {"published", "duplicate"}),
    }
    vendor_allowed, config_allowed = phase_dispositions[str(phase)]
    if (
        value["vendor_disposition"] not in vendor_allowed
        or value["config_disposition"] not in config_allowed
    ):
        fail("Cargo vendor state disposition contradicts its phase")
    if base is not None:
        for key, expected in base.items():
            if key in ("sequence", "phase", "vendor_disposition", "config_disposition"):
                continue
            if value[key] != expected:
                fail(f"Cargo vendor state authority changed at {key}")
        previous_phase = base["phase"]
        if PHASES.index(phase) != PHASES.index(str(previous_phase)) + 1:
            fail("Cargo vendor state did not make one exact forward transition")
    return value


def read_journal(
    staging_fd: int,
    expected_state_identity: tuple[int, int] | None = None,
) -> tuple[list[dict[str, object]], tuple[int, int]]:
    descriptor = open_regular(staging_fd, STATE_NAME)
    try:
        metadata = os.fstat(descriptor)
        observed_identity = identity(metadata)
        if (
            (metadata.st_uid, metadata.st_gid) != (os.geteuid(), os.getegid())
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size < 1
            or metadata.st_size > MAX_STATE_BYTES
            or os.listxattr(descriptor)
            or (
                expected_state_identity is not None
                and observed_identity != expected_state_identity
            )
        ):
            fail("Cargo vendor state journal metadata is unsafe")
        data, after = read_stable_file(
            descriptor,
            MAX_STATE_BYTES,
            "Cargo vendor state journal",
        )
        if identity(after) != observed_identity:
            fail("Cargo vendor state journal identity changed")
    finally:
        os.close(descriptor)
    if not data.endswith(b"\n"):
        fail("Cargo vendor state journal has a partial record")
    records = []
    previous = None
    for index, line in enumerate(data.splitlines()):
        try:
            decoded = json.loads(line.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            fail(f"Cargo vendor state journal is malformed: {error}")
        current = validate_state_record(decoded, previous, index)
        records.append(current)
        previous = current
    if not records:
        fail("Cargo vendor state journal is empty")
    return records, observed_identity


def contract_from_record(record: dict[str, object]) -> Contract:
    namespace = argparse.Namespace(**{key: record[key] for key in Contract.__dataclass_fields__})
    return make_contract(namespace)


def load_state(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    contract: Contract,
) -> tuple[int, os.stat_result, int, os.stat_result, dict[str, object], tuple[int, int]]:
    online_fd, online_metadata, staging_fd, staging_metadata = validate_roots(
        online, staging, uid, gid
    )
    assert staging_fd is not None and staging_metadata is not None
    try:
        records, state_identity = read_journal(staging_fd)
        latest = records[-1]
        if (
            latest["online"] != os.fspath(online)
            or latest["staging"] != os.fspath(staging)
            or latest["uid"] != uid
            or latest["gid"] != gid
            or decode_identity(latest["online_identity"], "online root")
            != identity(online_metadata)
            or decode_identity(latest["staging_identity"], "staging root")
            != identity(staging_metadata)
            or decode_identity(latest["state_identity"], "state journal")
            != state_identity
            or contract_from_record(latest) != contract
        ):
            fail("Cargo vendor state does not match the requested authority")
        return (
            online_fd,
            online_metadata,
            staging_fd,
            staging_metadata,
            latest,
            state_identity,
        )
    except BaseException:
        os.close(staging_fd)
        os.close(online_fd)
        raise


def run_provenance(tree: Path, expected: str) -> None:
    helper = Path(__file__).resolve().with_name("online-input-provenance.py")
    metadata = os.lstat(helper)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o022
    ):
        fail("Cargo vendor provenance helper metadata is unsafe")
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            os.fspath(helper),
            "verify-subtree",
            "--tree",
            os.fspath(tree),
            "--expected",
            expected,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env={
            "PATH": "/usr/bin:/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        timeout=300,
    )
    expected_stdout = f"verified subtree {expected}\n".encode("ascii")
    if result.returncode != 0 or result.stdout != expected_stdout or result.stderr:
        detail = result.stderr[:1024].decode("utf-8", "replace")
        fail(f"Cargo vendor canonical provenance failed: {detail}")


def validate_entry_metadata(
    metadata: os.stat_result,
    owner: tuple[int, int],
    root_device: int,
    label: str,
) -> None:
    if (metadata.st_uid, metadata.st_gid) != owner:
        fail(f"Cargo vendor entry has foreign ownership: {label}")
    if metadata.st_dev != root_device:
        fail(f"Cargo vendor entry crosses a filesystem boundary: {label}")
    if metadata.st_mode & FORBIDDEN_MODE_BITS:
        fail(f"Cargo vendor entry has set-id/sticky authority: {label}")
    mode = stat.S_IMODE(metadata.st_mode)
    if stat.S_ISDIR(metadata.st_mode):
        allowed = {0o500}
    elif stat.S_ISREG(metadata.st_mode):
        allowed = {0o400, 0o500}
        if metadata.st_nlink != 1:
            fail(f"Cargo vendor entry has an external hardlink: {label}")
        if metadata.st_size < 0 or metadata.st_size > MAX_FILE_BYTES:
            fail(f"Cargo vendor file exceeds its size bound: {label}")
    else:
        fail(f"Cargo vendor contains a symlink or special entry: {label}")
    if mode not in allowed:
        fail(f"Cargo vendor entry has an inadmissible mode: {label}")


def inspect_tree(
    root: Path,
    uid: int,
    gid: int,
    contract: Contract,
    *,
    candidate: bool,
    expected_identity: tuple[int, int] | None = None,
    normalize: bool = False,
) -> None:
    validate_absolute(root, "Cargo vendor tree")
    reject_mount_at_or_below(root)
    root_metadata = os.lstat(root)
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        fail("Cargo vendor output is not one real directory")
    if expected_identity is not None and identity(root_metadata) != expected_identity:
        fail("Cargo vendor output identity changed")
    owner = (uid, gid)
    if (root_metadata.st_uid, root_metadata.st_gid) != owner:
        fail("Cargo vendor output has an inadmissible owner")
    files = 0
    directories = 1
    content_bytes = 0
    directories_to_seal = [root]
    root_device = root_metadata.st_dev
    before_modes = {0o700, 0o750, 0o755, 0o775} if normalize else set()
    file_modes = (
        {0o400, 0o500, 0o600, 0o640, 0o644, 0o664, 0o700, 0o750, 0o755}
        if normalize
        else {0o400, 0o500}
    )
    if normalize:
        if (
            (root_metadata.st_uid, root_metadata.st_gid) != (uid, gid)
            or stat.S_IMODE(root_metadata.st_mode) not in before_modes
            or os.listxattr(root, follow_symlinks=False)
        ):
            fail("new Cargo vendor root metadata is unsafe")
    else:
        validate_entry_metadata(
            root_metadata,
            owner,
            root_device,
            ".",
        )
        if os.listxattr(root, follow_symlinks=False):
            fail("Cargo vendor root carries extended attributes")
    for current, directory_names, file_names in os.walk(
        root, topdown=True, followlinks=False
    ):
        directory_names.sort(key=os.fsencode)
        file_names.sort(key=os.fsencode)
        current_path = Path(current)
        for name in directory_names:
            path = current_path / name
            metadata = os.lstat(path)
            if normalize:
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or stat.S_ISLNK(metadata.st_mode)
                    or (metadata.st_uid, metadata.st_gid) != (uid, gid)
                    or metadata.st_dev != root_device
                    or metadata.st_mode & FORBIDDEN_MODE_BITS
                    or stat.S_IMODE(metadata.st_mode)
                    not in {0o700, 0o750, 0o755, 0o775}
                    or os.listxattr(path, follow_symlinks=False)
                ):
                    fail(f"new Cargo vendor directory metadata is unsafe: {path}")
            else:
                validate_entry_metadata(
                    metadata,
                    owner,
                    root_device,
                    os.fspath(path.relative_to(root)),
                )
                if os.listxattr(path, follow_symlinks=False):
                    fail(f"Cargo vendor directory carries extended attributes: {path}")
            directories += 1
            if directories > MAX_DIRECTORIES:
                fail("Cargo vendor directory count exceeds its bound")
            directories_to_seal.append(path)
        for name in file_names:
            path = current_path / name
            metadata = os.lstat(path)
            label = os.fspath(path.relative_to(root))
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or (metadata.st_uid, metadata.st_gid) != owner
                or metadata.st_dev != root_device
                or metadata.st_nlink != 1
                or metadata.st_mode & FORBIDDEN_MODE_BITS
                or stat.S_IMODE(metadata.st_mode) not in file_modes
                or metadata.st_size < 0
                or metadata.st_size > MAX_FILE_BYTES
                or os.listxattr(path, follow_symlinks=False)
            ):
                fail(f"Cargo vendor file metadata is unsafe: {label}")
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                after = os.fstat(descriptor)
                if stable_metadata(metadata) != stable_metadata(after):
                    fail(f"Cargo vendor file changed while opened: {label}")
                if normalize:
                    executable = bool(stat.S_IMODE(metadata.st_mode) & 0o111)
                    os.fchmod(descriptor, 0o500 if executable else 0o400)
                    os.fsync(descriptor)
                    sealed = os.fstat(descriptor)
                    expected_mode = 0o500 if executable else 0o400
                    if (
                        identity(sealed) != identity(metadata)
                        or (sealed.st_uid, sealed.st_gid) != owner
                        or sealed.st_nlink != 1
                        or stat.S_IMODE(sealed.st_mode) != expected_mode
                        or os.listxattr(descriptor)
                    ):
                        fail(f"Cargo vendor file changed while sealing: {label}")
            finally:
                os.close(descriptor)
            files += 1
            content_bytes += metadata.st_size
            if files > MAX_FILES or content_bytes > MAX_CONTENT_BYTES:
                fail("Cargo vendor file or byte count exceeds its bound")
    if (
        files != contract.files
        or directories != contract.directories
        or content_bytes != contract.content_bytes
    ):
        fail(
            "Cargo vendor inventory differs from the exact "
            f"{contract.files}/{contract.directories}/{contract.content_bytes} contract"
        )
    run_provenance(root, contract.vendor_sha256)
    if normalize:
        for path in reversed(directories_to_seal):
            os.chmod(path, 0o500, follow_symlinks=False)
            fsync_directory(path)
        inspect_tree(
            root,
            uid,
            gid,
            contract,
            candidate=True,
            expected_identity=expected_identity,
        )


def canonical_config_bytes(raw: bytes, contract: Contract) -> bytes:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"Cargo vendor config is not UTF-8: {error}")
    if "\0" in text or "\r" in text or text.count("directory = ") != 1:
        fail("Cargo vendor raw config has ambiguous directory authority")
    raw_tail = '[source.vendored-sources]\ndirectory = "/outputs/vendor"\n'
    if not text.endswith(raw_tail):
        fail("Cargo vendor raw config has an unexpected terminal source map")
    destination = contract.config_vendor_path
    if any(character in destination for character in ('"', "\\", "\n", "\r")):
        fail("Cargo vendor final path cannot be represented canonically")
    canonical = (
        text[: -len('directory = "/outputs/vendor"\n')]
        + f'directory = "{destination}"\n'
    ).encode("utf-8")
    if (
        len(canonical) != contract.config_size
        or hashlib.sha256(canonical).hexdigest() != contract.config_sha256
    ):
        fail("Cargo vendor config differs from its exact canonical pin")
    return canonical


def validate_final_config(
    online_fd: int,
    online: Path,
    uid: int,
    gid: int,
    contract: Contract,
) -> os.stat_result:
    descriptor = open_regular(online_fd, CONFIG_NAME)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (metadata.st_uid, metadata.st_gid) != (uid, gid)
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_dev != os.fstat(online_fd).st_dev
            or descriptor_mount_id(descriptor) != descriptor_mount_id(online_fd)
            or os.listxattr(descriptor)
        ):
            fail("published Cargo vendor config metadata is unsafe")
        content, after = read_stable_file(
            descriptor, MAX_CONFIG_BYTES, "published Cargo vendor config"
        )
        if (
            len(content) != contract.config_size
            or hashlib.sha256(content).hexdigest() != contract.config_sha256
        ):
            fail("published Cargo vendor config differs from its exact pin")
        return after
    finally:
        os.close(descriptor)


def validate_final_vendor(
    online: Path,
    uid: int,
    gid: int,
    contract: Contract,
    expected_identity: tuple[int, int] | None = None,
) -> os.stat_result:
    destination = online / VENDOR_NAME
    metadata = os.lstat(destination)
    inspect_tree(
        destination,
        uid,
        gid,
        contract,
        candidate=False,
        expected_identity=expected_identity,
    )
    return metadata


def prepare(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    contract: Contract,
) -> None:
    if uid == 0 or gid == 0 or (os.geteuid(), os.getegid()) != (uid, gid):
        fail("Cargo vendor preparation requires the invoking non-root identity")
    online_fd, online_metadata, staging_fd, staging_metadata = validate_roots(
        online, staging, uid, gid
    )
    assert staging_fd is not None and staging_metadata is not None
    try:
        if os.listdir(staging_fd):
            fail("Cargo vendor staging is not freshly empty")
        candidate_name = candidate_vendor_path(staging).name
        if (
            optional_lstat(online_fd, VENDOR_NAME) is not None
            or optional_lstat(online_fd, CONFIG_NAME) is not None
            or optional_lstat(online_fd, candidate_name) is not None
        ):
            fail("Cargo vendor final state appeared before preparation")
        os.mkdir(candidate_name, mode=0o700, dir_fd=online_fd)
        vendor_fd = open_child_directory(online_fd, candidate_name)
        try:
            vendor_identity = identity(os.fstat(vendor_fd))
            os.fsync(vendor_fd)
        finally:
            os.close(vendor_fd)
        raw_identity = create_file(staging_fd, RAW_CONFIG_NAME)
        config_identity = create_file(staging_fd, CONFIG_NAME)
        state_identity = create_file(staging_fd, STATE_NAME)
        base = base_state(
            online,
            staging,
            online_metadata,
            staging_metadata,
            uid,
            gid,
            vendor_identity,
            raw_identity,
            config_identity,
            state_identity,
            contract,
        )
        append_record(
            staging_fd,
            state_identity,
            state_record(base, 0, "prepared", "staged", "staged"),
            initial=True,
        )
        os.fsync(staging_fd)
        os.fsync(online_fd)
    finally:
        os.close(staging_fd)
        os.close(online_fd)


def verify_staged(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    contract: Contract,
) -> None:
    (
        online_fd,
        _,
        staging_fd,
        _,
        latest,
        state_identity,
    ) = load_state(online, staging, uid, gid, contract)
    try:
        if latest["phase"] != "prepared":
            fail("Cargo vendor verification requires prepared state")
        vendor_identity = decode_identity(latest["vendor_identity"], "vendor candidate")
        candidate = candidate_vendor_path(staging)
        vendor_fd = open_child_directory(online_fd, candidate.name)
        try:
            if identity(os.fstat(vendor_fd)) != vendor_identity:
                fail("Cargo vendor candidate identity changed")
        finally:
            os.close(vendor_fd)
        raw, _ = validate_candidate_file(
            staging_fd,
            RAW_CONFIG_NAME,
            uid,
            gid,
            decode_identity(latest["raw_config_identity"], "raw config"),
            "raw Cargo vendor config",
            modes={0o600},
            maximum=MAX_CONFIG_BYTES,
        )
        if not raw:
            fail("Cargo vendor producer emitted an empty config")
        canonical = canonical_config_bytes(raw, contract)
        config_identity = decode_identity(latest["config_identity"], "config candidate")
        descriptor = open_regular(staging_fd, CONFIG_NAME, os.O_WRONLY)
        try:
            metadata = os.fstat(descriptor)
            if (
                identity(metadata) != config_identity
                or (metadata.st_uid, metadata.st_gid) != (uid, gid)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size != 0
                or os.listxattr(descriptor)
            ):
                fail("Cargo vendor config candidate changed before canonicalization")
            write_full(descriptor, canonical, "canonical Cargo vendor config")
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        inspect_tree(
            candidate,
            uid,
            gid,
            contract,
            candidate=True,
            expected_identity=vendor_identity,
            normalize=True,
        )
        content, _ = validate_candidate_file(
            staging_fd,
            CONFIG_NAME,
            uid,
            gid,
            config_identity,
            "canonical Cargo vendor config",
            modes={0o400},
            maximum=MAX_CONFIG_BYTES,
        )
        if (
            len(content) != contract.config_size
            or hashlib.sha256(content).hexdigest() != contract.config_sha256
        ):
            fail("canonical Cargo vendor config changed during verification")
        next_record = state_record(
            latest,
            int(latest["sequence"]) + 1,
            "verified",
            "staged",
            "staged",
        )
        append_record(staging_fd, state_identity, next_record)
    finally:
        os.close(staging_fd)
        os.close(online_fd)


def authorize(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    contract: Contract,
) -> None:
    (
        online_fd,
        _,
        staging_fd,
        _,
        latest,
        state_identity,
    ) = load_state(online, staging, uid, gid, contract)
    try:
        if latest["phase"] != "verified":
            fail("Cargo vendor authorization requires verified state")
        inspect_tree(
            candidate_vendor_path(staging),
            uid,
            gid,
            contract,
            candidate=True,
            expected_identity=decode_identity(
                latest["vendor_identity"], "vendor candidate"
            ),
        )
        content, _ = validate_candidate_file(
            staging_fd,
            CONFIG_NAME,
            uid,
            gid,
            decode_identity(latest["config_identity"], "config candidate"),
            "canonical Cargo vendor config",
            modes={0o400},
            maximum=MAX_CONFIG_BYTES,
        )
        if (
            len(content) != contract.config_size
            or hashlib.sha256(content).hexdigest() != contract.config_sha256
        ):
            fail("Cargo vendor config changed before authorization")
        append_record(
            staging_fd,
            state_identity,
            state_record(
                latest,
                int(latest["sequence"]) + 1,
                "authorized",
                "staged",
                "staged",
            ),
        )
    finally:
        os.close(staging_fd)
        os.close(online_fd)


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
        value = ctypes.get_errno()
        raise OSError(value, os.strerror(value), source_name, destination_name)


def unlink_exact(
    parent: int,
    name: str,
    expected_identity: tuple[int, int],
) -> None:
    metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or identity(metadata) != expected_identity
    ):
        fail(f"Cargo vendor staging entry changed before retirement: {name}")
    os.unlink(name, dir_fd=parent)
    os.fsync(parent)


def ensure_raw_retired(
    staging_fd: int,
    uid: int,
    gid: int,
    latest: dict[str, object],
) -> None:
    expected = decode_identity(latest["raw_config_identity"], "raw config")
    metadata = optional_lstat(staging_fd, RAW_CONFIG_NAME)
    if metadata is None:
        return
    validate_candidate_file(
        staging_fd,
        RAW_CONFIG_NAME,
        uid,
        gid,
        expected,
        "raw Cargo vendor config",
        modes={0o600},
        maximum=MAX_CONFIG_BYTES,
    )
    unlink_exact(staging_fd, RAW_CONFIG_NAME, expected)


def append_phase(
    staging_fd: int,
    state_identity: tuple[int, int],
    latest: dict[str, object],
    phase: str,
    vendor_disposition: str,
    config_disposition: str,
) -> dict[str, object]:
    record = state_record(
        latest,
        int(latest["sequence"]) + 1,
        phase,
        vendor_disposition,
        config_disposition,
    )
    append_record(staging_fd, state_identity, record)
    return record


def publish(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    contract: Contract,
) -> None:
    (
        online_fd,
        _,
        staging_fd,
        _,
        latest,
        state_identity,
    ) = load_state(online, staging, uid, gid, contract)
    try:
        if latest["phase"] not in (
            "authorized",
            "publishing",
            "vendor-published",
            "complete",
        ):
            fail("Cargo vendor publication lacks semantic authorization")
        if latest["phase"] == "complete":
            validate_final_vendor(online, uid, gid, contract)
            validate_final_config(online_fd, online, uid, gid, contract)
            return
        if latest["phase"] == "authorized":
            latest = append_phase(
                staging_fd,
                state_identity,
                latest,
                "publishing",
                str(latest["vendor_disposition"]),
                str(latest["config_disposition"]),
            )
        ensure_raw_retired(staging_fd, uid, gid, latest)
        vendor_expected = decode_identity(latest["vendor_identity"], "vendor candidate")
        candidate = candidate_vendor_path(staging)
        staged_vendor = optional_lstat(online_fd, candidate.name)
        final_vendor = optional_lstat(online_fd, VENDOR_NAME)
        vendor_disposition = str(latest["vendor_disposition"])
        if staged_vendor is not None and identity(staged_vendor) == vendor_expected:
            inspect_tree(
                candidate,
                uid,
                gid,
                contract,
                candidate=True,
                expected_identity=vendor_expected,
            )
            if final_vendor is None:
                try:
                    renameat2(online_fd, candidate.name, online_fd, VENDOR_NAME)
                    os.fsync(online_fd)
                    vendor_disposition = "published"
                except OSError as error:
                    if error.errno != errno.EEXIST:
                        raise
                    validate_final_vendor(online, uid, gid, contract)
                    vendor_disposition = "duplicate"
            else:
                validate_final_vendor(online, uid, gid, contract)
                vendor_disposition = "duplicate"
        elif staged_vendor is None:
            validate_final_vendor(
                online,
                uid,
                gid,
                contract,
                expected_identity=vendor_expected,
            )
            vendor_disposition = "published"
        else:
            fail("Cargo vendor candidate identity changed during publication")
        if latest["phase"] != "vendor-published":
            latest = append_phase(
                staging_fd,
                state_identity,
                latest,
                "vendor-published",
                vendor_disposition,
                str(latest["config_disposition"]),
            )
        validate_final_vendor(online, uid, gid, contract)
        config_expected = decode_identity(latest["config_identity"], "config candidate")
        staged_config = optional_lstat(staging_fd, CONFIG_NAME)
        final_config = optional_lstat(online_fd, CONFIG_NAME)
        config_disposition = str(latest["config_disposition"])
        if staged_config is not None and identity(staged_config) == config_expected:
            content, _ = validate_candidate_file(
                staging_fd,
                CONFIG_NAME,
                uid,
                gid,
                config_expected,
                "canonical Cargo vendor config",
                modes={0o400},
                maximum=MAX_CONFIG_BYTES,
            )
            if (
                len(content) != contract.config_size
                or hashlib.sha256(content).hexdigest() != contract.config_sha256
            ):
                fail("Cargo vendor config changed during publication")
            if final_config is None:
                try:
                    renameat2(staging_fd, CONFIG_NAME, online_fd, CONFIG_NAME)
                    os.fsync(staging_fd)
                    os.fsync(online_fd)
                    config_disposition = "published"
                except OSError as error:
                    if error.errno != errno.EEXIST:
                        raise
                    validate_final_config(online_fd, online, uid, gid, contract)
                    config_disposition = "duplicate"
            else:
                validate_final_config(online_fd, online, uid, gid, contract)
                config_disposition = "duplicate"
        elif staged_config is None:
            metadata = validate_final_config(online_fd, online, uid, gid, contract)
            if identity(metadata) != config_expected:
                fail("published Cargo vendor config identity changed")
            config_disposition = "published"
        else:
            fail("Cargo vendor config candidate identity changed during publication")
        validate_final_vendor(online, uid, gid, contract)
        validate_final_config(online_fd, online, uid, gid, contract)
        if latest["phase"] != "complete":
            append_phase(
                staging_fd,
                state_identity,
                latest,
                "complete",
                vendor_disposition,
                config_disposition,
            )
    finally:
        os.close(staging_fd)
        os.close(online_fd)


def validate_unprepared_staging(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
) -> None:
    online_fd, _, staging_fd, _ = validate_roots(online, staging, uid, gid)
    assert staging_fd is not None
    try:
        names = set(os.listdir(staging_fd))
        if not names.issubset({RAW_CONFIG_NAME, CONFIG_NAME, STATE_NAME}):
            fail("unprepared Cargo vendor staging has unexpected entries")
        candidate = candidate_vendor_path(staging)
        candidate_metadata = optional_lstat(online_fd, candidate.name)
        if candidate_metadata is not None:
            reject_mount_at_or_below(candidate)
            vendor_fd = open_child_directory(online_fd, candidate.name)
            try:
                validate_directory(
                    vendor_fd,
                    uid,
                    gid,
                    "unprepared Cargo vendor directory",
                    modes={0o700},
                    expected_device=os.fstat(online_fd).st_dev,
                    expected_mount=descriptor_mount_id(online_fd),
                )
                if os.listdir(vendor_fd):
                    fail("unprepared Cargo vendor directory is not empty")
            finally:
                os.close(vendor_fd)
        for name in names:
            descriptor = open_regular(staging_fd, name)
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or (metadata.st_uid, metadata.st_gid) != (uid, gid)
                    or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_size != 0
                    or descriptor_mount_id(descriptor)
                    != descriptor_mount_id(staging_fd)
                    or os.listxattr(descriptor)
                ):
                    fail("unprepared Cargo vendor file is unsafe or nonempty")
            finally:
                os.close(descriptor)
    finally:
        os.close(staging_fd)
        os.close(online_fd)


def recover(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    contract: Contract,
) -> str:
    if uid == 0 or gid == 0 or (os.geteuid(), os.getegid()) != (uid, gid):
        fail("Cargo vendor recovery requires the invoking non-root identity")
    online_fd, _, staging_fd, _ = validate_roots(online, staging, uid, gid)
    assert staging_fd is not None
    try:
        state_metadata = optional_lstat(staging_fd, STATE_NAME)
        unprepared = state_metadata is None or (
            stat.S_ISREG(state_metadata.st_mode) and state_metadata.st_size == 0
        )
    finally:
        os.close(staging_fd)
        os.close(online_fd)
    if unprepared:
        validate_unprepared_staging(online, staging, uid, gid)
        return "discardable"
    try:
        (
            online_fd,
            _,
            staging_fd,
            _,
            latest,
            _,
        ) = load_state(online, staging, uid, gid, contract)
    except FileNotFoundError:
        validate_unprepared_staging(online, staging, uid, gid)
        return "discardable"
    else:
        os.close(staging_fd)
        os.close(online_fd)
    if latest["phase"] in ("prepared", "verified"):
        return "discardable"
    publish(online, staging, uid, gid, contract)
    return "published"


def check_complete(
    online: Path,
    uid: int,
    gid: int,
    contract: Contract,
) -> None:
    if uid == 0 or gid == 0 or (os.geteuid(), os.getegid()) != (uid, gid):
        fail("Cargo vendor validation requires the invoking non-root identity")
    online_fd, _, _, _ = validate_roots(online, None, uid, gid)
    try:
        with os.scandir(online_fd) as iterator:
            reserved = [
                entry.name
                for entry in iterator
                if entry.name.startswith(".rustdesk-cargo-vendor.")
            ]
        if reserved:
            fail("reserved Cargo vendor staging remains unreconciled")
        validate_final_vendor(online, uid, gid, contract)
        validate_final_config(online_fd, online, uid, gid, contract)
    finally:
        os.close(online_fd)


def fixture_contract(
    online: Path,
    vendor: Path,
    canonical_config: bytes,
) -> Contract:
    helper = Path(__file__).resolve().with_name("online-input-provenance.py")
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            os.fspath(helper),
            "maintenance-print-root",
            "--tree",
            os.fspath(vendor),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    values = {}
    for line in result.stdout.decode("ascii").splitlines()[1:]:
        key, value = line.split("=", 1)
        values[key] = value
    return Contract(
        source_commit="1" * 40,
        source_tree="2" * 40,
        source_archive_sha256="3" * 64,
        builder="sha256:" + "4" * 64,
        rust_sha256="5" * 64,
        vendor_sha256=values["sha256"],
        config_sha256=hashlib.sha256(canonical_config).hexdigest(),
        config_vendor_path=os.fspath(online / VENDOR_NAME),
        config_size=len(canonical_config),
        files=int(values["files"]),
        directories=int(values["directories"]),
        content_bytes=int(values["content_bytes"]),
    )


def write_fixture_output(staging: Path, online: Path) -> Contract:
    vendor = candidate_vendor_path(staging)
    package = vendor / "example-1.0.0"
    package.mkdir()
    (package / "Cargo.toml").write_text(
        '[package]\nname = "example"\nversion = "1.0.0"\n',
        encoding="ascii",
    )
    executable = package / "configure"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    executable.chmod(0o755)
    raw = (
        "[source.crates-io]\n"
        'replace-with = "vendored-sources"\n\n'
        "[source.vendored-sources]\n"
        'directory = "/outputs/vendor"\n'
    ).encode("ascii")
    canonical = raw.replace(
        b'directory = "/outputs/vendor"',
        f'directory = "{online / VENDOR_NAME}"'.encode("ascii"),
    )
    (staging / RAW_CONFIG_NAME).write_bytes(raw)
    return fixture_contract(online, vendor, canonical)


def remove_fixture(path: Path) -> None:
    for current, directories, _ in os.walk(path, topdown=True):
        os.chmod(current, 0o700)
        for name in directories:
            child = Path(current) / name
            if not child.is_symlink():
                os.chmod(child, 0o700)
    shutil.rmtree(path)


def remove_transaction(staging: Path) -> None:
    candidate = candidate_vendor_path(staging)
    if candidate.exists():
        remove_fixture(candidate)
    remove_fixture(staging)


def self_test() -> None:
    uid = os.geteuid()
    gid = os.getegid()
    if uid == 0 or gid == 0:
        fail("Cargo vendor output self-test refuses root")
    with tempfile.TemporaryDirectory(prefix="cargo-vendor-output-self-test.") as temporary:
        root = Path(temporary)
        online = root / "online"
        online.mkdir(mode=0o700)
        staging = Path(tempfile.mkdtemp(prefix=".rustdesk-cargo-vendor.", dir=online))

        placeholder = Contract(
            source_commit="1" * 40,
            source_tree="2" * 40,
            source_archive_sha256="3" * 64,
            builder="sha256:" + "4" * 64,
            rust_sha256="5" * 64,
            vendor_sha256="6" * 64,
            config_sha256="7" * 64,
            config_vendor_path=os.fspath(online / VENDOR_NAME),
            config_size=1,
            files=1,
            directories=1,
            content_bytes=1,
        )
        prepare(online, staging, uid, gid, placeholder)
        contract = write_fixture_output(staging, online)
        # The real shell knows the contract before preparation. Rewrite this fixture's
        # freshly prepared journal only by restarting with a clean transaction.
        remove_transaction(staging)
        staging = Path(tempfile.mkdtemp(prefix=".rustdesk-cargo-vendor.", dir=online))
        prepare(online, staging, uid, gid, contract)
        write_fixture_output(staging, online)
        verify_staged(online, staging, uid, gid, contract)
        if recover(online, staging, uid, gid, contract) != "discardable":
            fail("self-test treated structural verification as publication authority")
        authorize(online, staging, uid, gid, contract)
        publish(online, staging, uid, gid, contract)
        if recover(online, staging, uid, gid, contract) != "published":
            fail("self-test did not recover an authorized Cargo vendor transaction")
        remove_fixture(staging)
        check_complete(online, uid, gid, contract)
        sealed_vendor = online / VENDOR_NAME
        sealed_file = sealed_vendor / "example-1.0.0" / "Cargo.toml"
        sealed_config = online / CONFIG_NAME
        for path, unsafe_mode, sealed_mode, label in (
            (sealed_vendor, 0o700, 0o500, "writable vendor root"),
            (sealed_file, 0o600, 0o400, "writable vendor file"),
            (sealed_config, 0o600, 0o400, "writable vendor config"),
        ):
            path.chmod(unsafe_mode)
            try:
                check_complete(online, uid, gid, contract)
            except VendorOutputError:
                pass
            else:
                fail(f"self-test accepted {label}")
            path.chmod(sealed_mode)
        check_complete(online, uid, gid, contract)

        saved_vendor = online / "saved-vendor"
        saved_config = online / "saved-config"
        os.rename(online / VENDOR_NAME, saved_vendor)
        os.rename(online / CONFIG_NAME, saved_config)
        staging = Path(tempfile.mkdtemp(prefix=".rustdesk-cargo-vendor.", dir=online))
        prepare(online, staging, uid, gid, contract)
        write_fixture_output(staging, online)
        verify_staged(online, staging, uid, gid, contract)
        authorize(online, staging, uid, gid, contract)
        # Simulate interruption after the vendor directory entered its final name.
        os.rename(candidate_vendor_path(staging), online / VENDOR_NAME)
        if recover(online, staging, uid, gid, contract) != "published":
            fail("self-test did not resume vendor-before-config publication")
        if not (online / CONFIG_NAME).is_file():
            fail("self-test recovery did not publish the Cargo vendor config")
        remove_fixture(staging)

        remove_fixture(online / VENDOR_NAME)
        (online / CONFIG_NAME).unlink()
        os.rename(saved_vendor, online / VENDOR_NAME)
        os.rename(saved_config, online / CONFIG_NAME)

        wrong = root / "wrong"
        wrong.mkdir(mode=0o700)
        (wrong / VENDOR_NAME).mkdir()
        (wrong / VENDOR_NAME / "wrong").write_text("wrong\n", encoding="ascii")
        (wrong / CONFIG_NAME).write_text("wrong\n", encoding="ascii")
        try:
            check_complete(wrong, uid, gid, contract)
        except VendorOutputError:
            pass
        else:
            fail("self-test accepted wrong occupied Cargo vendor outputs")
        if (wrong / VENDOR_NAME / "wrong").read_text(encoding="ascii") != "wrong\n":
            fail("self-test changed wrong occupied Cargo vendor output")

        unsafe = root / "unsafe"
        unsafe.mkdir(mode=0o700)
        unsafe_stage = Path(
            tempfile.mkdtemp(prefix=".rustdesk-cargo-vendor.", dir=unsafe)
        )
        prepare(unsafe, unsafe_stage, uid, gid, contract)
        write_fixture_output(unsafe_stage, unsafe)
        outside = root / "outside"
        os.link(
            candidate_vendor_path(unsafe_stage) / "example-1.0.0" / "Cargo.toml",
            outside,
        )
        try:
            verify_staged(unsafe, unsafe_stage, uid, gid, contract)
        except VendorOutputError:
            pass
        else:
            fail("self-test accepted an externally hardlinked Cargo vendor file")
        if not outside.is_file():
            fail("self-test removed external state after hardlink refusal")
        remove_transaction(unsafe_stage)
        outside.unlink()
        remove_fixture(unsafe)
        remove_fixture(wrong)
        remove_fixture(online / VENDOR_NAME)
        (online / CONFIG_NAME).unlink()
    print("online-cargo-vendor-output: PASS")


def add_contract_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--source-archive-sha256", required=True)
    parser.add_argument("--builder", required=True)
    parser.add_argument("--rust-sha256", required=True)
    parser.add_argument("--vendor-sha256", required=True)
    parser.add_argument("--config-sha256", required=True)
    parser.add_argument("--config-vendor-path", required=True)
    parser.add_argument("--config-size", required=True, type=int)
    parser.add_argument("--files", required=True, type=int)
    parser.add_argument("--directories", required=True, type=int)
    parser.add_argument("--content-bytes", required=True, type=int)


def add_common_arguments(parser: argparse.ArgumentParser, *, staging: bool = True) -> None:
    parser.add_argument("--online", required=True, type=Path)
    if staging:
        parser.add_argument("--staging", required=True, type=Path)
    parser.add_argument("--uid", required=True, type=int)
    parser.add_argument("--gid", required=True, type=int)
    add_contract_arguments(parser)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    for command in ("prepare", "verify", "authorize", "publish", "recover"):
        add_common_arguments(commands.add_parser(command))
    add_common_arguments(commands.add_parser("check-complete"), staging=False)
    commands.add_parser("self-test")
    return result


def main(argv: Sequence[str]) -> int:
    arguments = parser().parse_args(argv)
    if arguments.command == "self-test":
        self_test()
        return 0
    contract = make_contract(arguments)
    if arguments.command == "prepare":
        prepare(
            arguments.online,
            arguments.staging,
            arguments.uid,
            arguments.gid,
            contract,
        )
    elif arguments.command == "verify":
        verify_staged(
            arguments.online,
            arguments.staging,
            arguments.uid,
            arguments.gid,
            contract,
        )
    elif arguments.command == "authorize":
        authorize(
            arguments.online,
            arguments.staging,
            arguments.uid,
            arguments.gid,
            contract,
        )
    elif arguments.command == "publish":
        publish(
            arguments.online,
            arguments.staging,
            arguments.uid,
            arguments.gid,
            contract,
        )
    elif arguments.command == "recover":
        print(
            recover(
                arguments.online,
                arguments.staging,
                arguments.uid,
                arguments.gid,
                contract,
            )
        )
    elif arguments.command == "check-complete":
        check_complete(arguments.online, arguments.uid, arguments.gid, contract)
    else:
        fail("unknown Cargo vendor output command")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, subprocess.SubprocessError, VendorOutputError) as error:
        print(f"[FATAL] {error}", file=sys.stderr)
        raise SystemExit(1)
