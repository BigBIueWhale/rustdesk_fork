#!/usr/bin/env python3
"""Prepare, validate, recover, and publish network-acquired Cargo tools."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import stat
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path


STATE_NAME = ".rustdesk-cargo-tool-output-state-v1"
STATE_VERSION = 1
STAGING_PATTERN = re.compile(
    r"\.rustdesk-cargo-tool-(frb|cargo-ndk)\.[A-Za-z0-9_]{8,}\Z"
)
VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
BLOCK_SIZE = 1024 * 1024
MOUNTINFO_LIMIT = 8 * 1024 * 1024
TREE_LIMITS = (16, 4, 512 * 1024**2, 512 * 1024**2)
RENAME_NOREPLACE = 1
FORBIDDEN_MODE_BITS = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX
REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
RUSTC_1_75_DETAILS = (
    "rustc 1.75.0 (82e1608df 2023-12-21)\n"
    "binary: rustc\n"
    "commit-hash: 82e1608dfa6e0b5569232559e3d385fea5a93112\n"
    "commit-date: 2023-12-21\n"
    "host: x86_64-unknown-linux-gnu\n"
    "release: 1.75.0\n"
    "LLVM version: 17.0.6\n"
)


class ToolOutputError(RuntimeError):
    pass


@dataclass(frozen=True)
class ToolSpec:
    kind: str
    destination: str
    package: str
    binary: str
    features: tuple[str, ...]


@dataclass(frozen=True)
class TreeSummary:
    files: int
    directories: int
    bytes: int


SPECS = {
    "frb": ToolSpec(
        kind="frb",
        destination="frb-tool",
        package="flutter_rust_bridge_codegen",
        binary="flutter_rust_bridge_codegen",
        features=("uuid",),
    ),
    "cargo-ndk": ToolSpec(
        kind="cargo-ndk",
        destination="cargo-ndk-tool",
        package="cargo-ndk",
        binary="cargo-ndk",
        features=(),
    ),
}


def fail(message: str) -> None:
    raise ToolOutputError(message)


def spec_for(kind: str) -> ToolSpec:
    spec = SPECS.get(kind)
    if spec is None:
        fail("Cargo tool kind is not one of the closed supported set")
    return spec


def validate_version(value: str, label: str) -> str:
    if VERSION_PATTERN.fullmatch(value) is None:
        fail(f"{label} is not one exact semantic version")
    return value


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


def read_mountinfo() -> list[bytes]:
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
            fail("truncated /proc/self/mountinfo record")
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
        fail(f"Cargo tool tree contains a descendant mount: {os.fsdecode(descendants[0])}")


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
    reject_extended_metadata(canonical, metadata, label)
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        fail(f"{label} is group/world writable")
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
        fail(f"Cargo tool tree contains a nonportable path: {relative!r}")


def reject_extended_metadata(
    path: Path,
    metadata: os.stat_result,
    label: str,
) -> None:
    if metadata.st_mode & FORBIDDEN_MODE_BITS:
        fail(f"{label} carries set-id/sticky mode bits")
    try:
        attributes = os.listxattr(path, follow_symlinks=False)
    except OSError as error:
        fail(f"cannot inspect {label} extended attributes: {error}")
    if attributes:
        fail(f"{label} carries extended attributes")


def read_regular(path: Path, maximum: int) -> tuple[bytes, os.stat_result]:
    metadata = os.lstat(path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > maximum
    ):
        fail(f"Cargo tool metadata is not one bounded regular file: {path}")
    reject_extended_metadata(path, metadata, "Cargo tool metadata")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if stable_metadata(before) != stable_metadata(metadata):
            fail(f"Cargo tool metadata changed before read: {path}")
        data = bytearray()
        while True:
            block = os.read(descriptor, min(BLOCK_SIZE, maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
            if len(data) > maximum:
                fail(f"Cargo tool metadata exceeds its byte bound: {path}")
        after = os.fstat(descriptor)
        if stable_metadata(before) != stable_metadata(after):
            fail(f"Cargo tool metadata changed while read: {path}")
        return bytes(data), after
    finally:
        os.close(descriptor)


def read_regular_prefix(
    path: Path,
    length: int,
    maximum: int,
) -> tuple[bytes, os.stat_result]:
    metadata = os.lstat(path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > maximum
    ):
        fail(f"Cargo tool binary is not one bounded regular file: {path}")
    reject_extended_metadata(path, metadata, "Cargo tool binary")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if stable_metadata(before) != stable_metadata(metadata):
            fail(f"Cargo tool binary changed before header read: {path}")
        data = bytearray()
        while len(data) < length:
            block = os.read(descriptor, length - len(data))
            if not block:
                break
            data.extend(block)
        after = os.fstat(descriptor)
        if stable_metadata(before) != stable_metadata(after):
            fail(f"Cargo tool binary changed while reading its header: {path}")
        return bytes(data), after
    finally:
        os.close(descriptor)


def inspect_tree(
    root: Path,
    *,
    owners: set[tuple[int, int]],
    normalize: bool = False,
    expected_identity: tuple[int, int] | None = None,
) -> TreeSummary:
    root_metadata = validate_root(root, "Cargo tool output", owners, expected_identity)
    root_device = root_metadata.st_dev
    maximum_files, maximum_directories, maximum_bytes, maximum_file = TREE_LIMITS
    files = 0
    directories = 1
    content_bytes = 0
    final_metadata: list[tuple[Path, tuple[int, ...]]] = []

    def descend(directory: Path, relative: str, depth: int) -> None:
        nonlocal files, directories, content_bytes
        if depth > 8:
            fail("Cargo tool output exceeds its depth bound")
        before = os.lstat(directory)
        if before.st_dev != root_device:
            fail(f"Cargo tool output crosses a filesystem: {directory}")
        if (before.st_uid, before.st_gid) not in owners:
            fail(f"Cargo tool output has foreign ownership: {directory}")
        if normalize:
            os.chmod(directory, 0o700, follow_symlinks=False)
            before = os.lstat(directory)
        elif stat.S_IMODE(before.st_mode) & 0o022:
            fail(f"Cargo tool directory is group/world writable: {directory}")
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
        for entry in entries:
            child_relative = entry.name if not relative else f"{relative}/{entry.name}"
            validate_name(entry.name, child_relative)
            child = directory / entry.name
            metadata = entry.stat(follow_symlinks=False)
            if metadata.st_dev != root_device:
                fail(f"Cargo tool output crosses a filesystem: {child_relative}")
            if (metadata.st_uid, metadata.st_gid) not in owners:
                fail(f"Cargo tool output has foreign ownership: {child_relative}")
            reject_extended_metadata(child, metadata, f"Cargo tool entry {child_relative}")
            if stat.S_ISDIR(metadata.st_mode):
                directories += 1
                if directories > maximum_directories:
                    fail("Cargo tool output exceeds its directory bound")
                descend(child, child_relative, depth + 1)
            elif stat.S_ISREG(metadata.st_mode):
                files += 1
                content_bytes += metadata.st_size
                if files > maximum_files:
                    fail("Cargo tool output exceeds its file bound")
                if content_bytes > maximum_bytes:
                    fail("Cargo tool output exceeds its byte bound")
                if metadata.st_size > maximum_file:
                    fail(f"Cargo tool file exceeds its byte bound: {child_relative}")
                if metadata.st_nlink != 1:
                    fail(f"Cargo tool file is multiply linked: {child_relative}")
                executable = bool(metadata.st_mode & 0o111)
                if normalize:
                    os.chmod(child, 0o700 if executable else 0o600, follow_symlinks=False)
                    metadata = os.lstat(child)
                elif stat.S_IMODE(metadata.st_mode) & 0o022:
                    fail(f"Cargo tool file is group/world writable: {child_relative}")
                descriptor = os.open(
                    child,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                try:
                    before_file = os.fstat(descriptor)
                    if stable_metadata(before_file) != stable_metadata(metadata):
                        fail(f"Cargo tool file changed before read: {child_relative}")
                    digest = hashlib.sha256()
                    while True:
                        block = os.read(descriptor, BLOCK_SIZE)
                        if not block:
                            break
                        digest.update(block)
                    after_file = os.fstat(descriptor)
                    if stable_metadata(before_file) != stable_metadata(after_file):
                        fail(f"Cargo tool file changed while read: {child_relative}")
                finally:
                    os.close(descriptor)
                final_metadata.append((child, stable_metadata(metadata)))
            elif stat.S_ISLNK(metadata.st_mode):
                fail(f"Cargo tool output contains a symlink: {child_relative}")
            else:
                fail(f"Cargo tool output contains a special file: {child_relative}")
        after = os.lstat(directory)
        if (
            identity(before) != identity(after)
            or after.st_dev != root_device
            or not stat.S_ISDIR(after.st_mode)
        ):
            fail(f"Cargo tool directory changed during traversal: {relative or '.'}")
        final_metadata.append((directory, stable_metadata(after)))

    descend(root, "", 0)
    for path, expected in final_metadata:
        if stable_metadata(os.lstat(path)) != expected:
            fail(f"Cargo tool output changed after traversal: {path}")
    return TreeSummary(files, directories, content_bytes)


def expected_package_key(spec: ToolSpec, version: str) -> str:
    return f"{spec.package} {version} ({REGISTRY_SOURCE})"


def validate_elf(binary: Path) -> None:
    data, metadata = read_regular_prefix(binary, 64, TREE_LIMITS[3])
    if metadata.st_size == 0 or not metadata.st_mode & 0o111:
        fail("Cargo tool binary is empty or nonexecutable")
    if len(data) < 64:
        fail("Cargo tool binary has a truncated ELF header")
    fields = struct.unpack("<16sHHIQQQIHHHHHH", data[:64])
    ident = fields[0]
    if (
        ident[:7] != b"\x7fELF\x02\x01\x01"
        or ident[7] != 0
        or any(ident[8:])
    ):
        fail("Cargo tool binary is not canonical 64-bit little-endian System V ELF")
    (
        _,
        elf_type,
        machine,
        version,
        _entry,
        program_offset,
        _section_offset,
        _flags,
        header_size,
        program_entry_size,
        program_count,
        _section_entry_size,
        _section_count,
        _section_names,
    ) = fields
    if elf_type not in (2, 3) or machine != 62 or version != 1 or header_size != 64:
        fail("Cargo tool binary has the wrong ELF identity")
    if (
        program_entry_size != 56
        or program_count == 0
        or program_count > 128
        or program_offset < 64
        or program_offset + program_entry_size * program_count > metadata.st_size
    ):
        fail("Cargo tool binary has an invalid program-header table")


def validate_semantics(
    root: Path,
    *,
    kind: str,
    tool_version: str,
    rust_version: str,
) -> None:
    spec = spec_for(kind)
    validate_version(tool_version, "Cargo tool version")
    validate_version(f"{rust_version}.0", "Rust toolchain version")
    if rust_version != "1.75":
        fail("Cargo tool validator admits only the pinned Rust 1.75 toolchain")
    with os.scandir(root) as iterator:
        top_level = {entry.name: entry for entry in iterator}
    if set(top_level) != {".crates.toml", ".crates2.json", "bin"}:
        fail("Cargo tool installation root has an unexpected inventory")
    if not top_level["bin"].is_dir(follow_symlinks=False):
        fail("Cargo tool bin entry is not one real directory")
    bin_root = root / "bin"
    with os.scandir(bin_root) as iterator:
        binaries = {entry.name: entry for entry in iterator}
    if set(binaries) != {spec.binary}:
        fail("Cargo tool installation has an unexpected binary inventory")
    if not binaries[spec.binary].is_file(follow_symlinks=False):
        fail("Cargo tool binary is not one regular file")

    key = expected_package_key(spec, tool_version)
    crates_toml, _ = read_regular(root / ".crates.toml", 64 * 1024)
    expected_toml = f'[v1]\n"{key}" = ["{spec.binary}"]\n'.encode("ascii")
    if crates_toml != expected_toml:
        fail("Cargo tool legacy installation metadata is not canonical")

    crates_json, _ = read_regular(root / ".crates2.json", 64 * 1024)
    if not crates_json or crates_json[:1] != b"{" or b"\r" in crates_json or b"\0" in crates_json:
        fail("Cargo tool installation metadata is not canonical JSON")
    try:
        metadata = json.loads(crates_json)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"Cargo tool installation metadata is malformed: {error}")
    if (
        not isinstance(metadata, dict)
        or set(metadata) != {"installs"}
        or not isinstance(metadata["installs"], dict)
        or set(metadata["installs"]) != {key}
    ):
        fail("Cargo tool installation metadata does not identify exactly the pinned package")
    install = metadata["installs"][key]
    required = {
        "version_req": f"={tool_version}",
        "bins": [spec.binary],
        "features": list(spec.features),
        "all_features": False,
        "no_default_features": False,
        "profile": "release",
        "target": "x86_64-unknown-linux-gnu",
        "rustc": RUSTC_1_75_DETAILS,
    }
    if not isinstance(install, dict) or install != required:
        fail("Cargo tool installation metadata does not match the pinned build contract")
    canonical_json = json.dumps(
        metadata,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    if crates_json != canonical_json:
        fail("Cargo tool installation metadata bytes are not canonical")
    validate_elf(bin_root / spec.binary)


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
                fail("short write while recording Cargo tool output state")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, state)
    fsync_directory(staging)


def load_state(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    expected_kind: str | None = None,
) -> dict[str, object]:
    online_metadata = validate_root(online, "online root", {(uid, gid)})
    staging_metadata = validate_root(staging, "Cargo tool staging", {(uid, gid)})
    match = STAGING_PATTERN.fullmatch(staging.name)
    if staging.parent != online or match is None:
        fail("Cargo tool staging is outside its reserved online namespace")
    state_path = staging / STATE_NAME
    data, metadata = read_regular(state_path, 4096)
    if (
        metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        fail("Cargo tool output state metadata is invalid")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"Cargo tool output state is malformed: {error}")
    required_keys = {
        "version",
        "kind",
        "tool_version",
        "rust_version",
        "online",
        "staging",
        "online_identity",
        "staging_identity",
        "output_identity",
    }
    if not isinstance(value, dict) or set(value) != required_keys:
        fail("Cargo tool output state has an unexpected schema")
    if value.get("version") != STATE_VERSION:
        fail("Cargo tool output state has the wrong version")
    kind = value.get("kind")
    if not isinstance(kind, str) or spec_for(kind).kind != kind or match.group(1) != kind:
        fail("Cargo tool output state kind binding is invalid")
    if expected_kind is not None and kind != expected_kind:
        fail("Cargo tool output state belongs to another tool kind")
    tool_version = value.get("tool_version")
    rust_version = value.get("rust_version")
    if not isinstance(tool_version, str) or not isinstance(rust_version, str):
        fail("Cargo tool output state version fields are malformed")
    validate_version(tool_version, "recorded Cargo tool version")
    if rust_version != "1.75":
        fail("Cargo tool output state has the wrong Rust version")
    if value.get("online") != os.fspath(online) or value.get("staging") != os.fspath(staging):
        fail("Cargo tool output state path binding is invalid")
    if decode_identity(value.get("online_identity"), "online root") != identity(online_metadata):
        fail("online root identity changed")
    if decode_identity(value.get("staging_identity"), "Cargo tool staging") != identity(
        staging_metadata
    ):
        fail("Cargo tool staging identity changed")
    return value


def prepare(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    *,
    kind: str,
    tool_version: str,
    rust_version: str,
) -> None:
    spec_for(kind)
    validate_version(tool_version, "Cargo tool version")
    if rust_version != "1.75":
        fail("Cargo tool preparation admits only the pinned Rust 1.75 toolchain")
    online_metadata = validate_root(online, "online root", {(uid, gid)})
    staging_metadata = validate_root(staging, "Cargo tool staging", {(uid, gid)})
    match = STAGING_PATTERN.fullmatch(staging.name)
    if staging.parent != online or match is None or match.group(1) != kind:
        fail("Cargo tool staging is outside its reserved online namespace")
    if staging_metadata.st_dev != online_metadata.st_dev:
        fail("Cargo tool staging is not on the online filesystem")
    if any(staging.iterdir()):
        fail("Cargo tool staging is not freshly empty")
    output = staging / "output"
    output.mkdir(mode=0o700)
    state = {
        "version": STATE_VERSION,
        "kind": kind,
        "tool_version": tool_version,
        "rust_version": rust_version,
        "online": os.fspath(online),
        "staging": os.fspath(staging),
        "online_identity": encode_identity(identity(online_metadata)),
        "staging_identity": encode_identity(identity(staging_metadata)),
        "output_identity": encode_identity(identity(os.lstat(output))),
    }
    atomic_write_state(staging, state)


def verify_staged(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    *,
    kind: str,
    tool_version: str,
    rust_version: str,
) -> None:
    state = load_state(online, staging, uid, gid, kind)
    if state["tool_version"] != tool_version or state["rust_version"] != rust_version:
        fail("Cargo tool output state version does not match the requested validator")
    output = staging / "output"
    inspect_tree(
        output,
        owners={(uid, gid)},
        normalize=True,
        expected_identity=decode_identity(state.get("output_identity"), "Cargo tool output"),
    )
    validate_semantics(
        output,
        kind=kind,
        tool_version=tool_version,
        rust_version=rust_version,
    )


def check_complete(
    online: Path,
    uid: int,
    gid: int,
    *,
    kind: str,
    tool_version: str,
    rust_version: str,
) -> None:
    spec = spec_for(kind)
    validate_root(online, "online root", {(uid, gid)})
    output = online / spec.destination
    inspect_tree(
        output,
        owners={(uid, gid), (0, 0)},
    )
    validate_semantics(
        output,
        kind=kind,
        tool_version=tool_version,
        rust_version=rust_version,
    )


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
                    fail(f"cannot synchronize nonprivate Cargo tool file: {path}")
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


def publish(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    *,
    kind: str,
    tool_version: str,
    rust_version: str,
) -> None:
    verify_staged(
        online,
        staging,
        uid,
        gid,
        kind=kind,
        tool_version=tool_version,
        rust_version=rust_version,
    )
    state = load_state(online, staging, uid, gid, kind)
    spec = spec_for(kind)
    destination = online / spec.destination
    if destination.exists() or destination.is_symlink():
        fail("Cargo tool destination appeared before no-clobber publication")
    output = staging / "output"
    sync_tree(output)
    fsync_directory(staging)
    online_fd = open_directory(online)
    staging_fd = open_directory(staging)
    moved = False
    try:
        renameat2(staging_fd, "output", online_fd, spec.destination, RENAME_NOREPLACE)
        moved = True
        os.fsync(staging_fd)
        os.fsync(online_fd)
        expected = decode_identity(state.get("output_identity"), "Cargo tool output")
        if identity(os.lstat(destination)) != expected:
            fail("published Cargo tool identity postcondition failed")
        validate_semantics(
            destination,
            kind=kind,
            tool_version=tool_version,
            rust_version=rust_version,
        )
    except BaseException as primary:
        if moved:
            try:
                renameat2(
                    online_fd,
                    spec.destination,
                    staging_fd,
                    "output",
                    RENAME_NOREPLACE,
                )
                os.fsync(staging_fd)
                os.fsync(online_fd)
            except BaseException as rollback:
                primary.add_note(f"Cargo tool publication rollback also failed: {rollback}")
        raise
    finally:
        os.close(staging_fd)
        os.close(online_fd)


def optional_identity(path: Path) -> tuple[int, int] | None:
    try:
        return identity(os.lstat(path))
    except FileNotFoundError:
        return None


def recover(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    *,
    kind: str,
) -> str:
    state = load_state(online, staging, uid, gid, kind)
    spec = spec_for(kind)
    output = decode_identity(state.get("output_identity"), "Cargo tool output")
    private_output = optional_identity(staging / "output")
    live_output = optional_identity(online / spec.destination)
    if private_output == output and live_output is None:
        return "unpublished"
    if private_output is None and live_output == output:
        return "published"
    fail("Cargo tool output transaction state is incoherent and was preserved")


def fake_elf() -> bytes:
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        3,
        62,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        1,
        64,
        0,
        0,
    )
    return header + b"\0" * 56


def create_fake_install(root: Path, spec: ToolSpec, version: str) -> None:
    key = expected_package_key(spec, version)
    (root / "bin").mkdir()
    binary = root / "bin" / spec.binary
    binary.write_bytes(fake_elf())
    binary.chmod(0o700)
    (root / ".crates.toml").write_text(
        f'[v1]\n"{key}" = ["{spec.binary}"]\n',
        encoding="ascii",
    )
    metadata = {
        "installs": {
            key: {
                "version_req": f"={version}",
                "bins": [spec.binary],
                "features": list(spec.features),
                "all_features": False,
                "no_default_features": False,
                "profile": "release",
                "target": "x86_64-unknown-linux-gnu",
                "rustc": RUSTC_1_75_DETAILS,
            }
        }
    }
    (root / ".crates2.json").write_text(
        json.dumps(metadata, separators=(",", ":")),
        encoding="ascii",
    )


def make_stage(online: Path, kind: str) -> Path:
    return Path(
        tempfile.mkdtemp(
            prefix=f".rustdesk-cargo-tool-{kind}.",
            dir=online,
        )
    )


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
    versions = {"frb": "1.80.1", "cargo-ndk": "3.1.2"}

    def fixture(base: Path, kind: str) -> tuple[Path, Path]:
        base.mkdir()
        online = base / "online"
        online.mkdir(mode=0o700)
        staging = make_stage(online, kind)
        prepare(
            online,
            staging,
            uid,
            gid,
            kind=kind,
            tool_version=versions[kind],
            rust_version="1.75",
        )
        create_fake_install(staging / "output", spec_for(kind), versions[kind])
        return online, staging

    with tempfile.TemporaryDirectory(prefix="online-cargo-tool-output-test-") as temporary:
        base = Path(temporary)
        for kind in SPECS:
            online, staging = fixture(base / f"normal-{kind}", kind)
            verify_staged(
                online,
                staging,
                uid,
                gid,
                kind=kind,
                tool_version=versions[kind],
                rust_version="1.75",
            )
            publish(
                online,
                staging,
                uid,
                gid,
                kind=kind,
                tool_version=versions[kind],
                rust_version="1.75",
            )
            if recover(online, staging, uid, gid, kind=kind) != "published":
                fail("self-test did not classify completed Cargo tool publication")
            check_complete(
                online,
                uid,
                gid,
                kind=kind,
                tool_version=versions[kind],
                rust_version="1.75",
            )
            remove_stage(staging)

        online, staging = fixture(base / "unpublished", "frb")
        if recover(online, staging, uid, gid, kind="frb") != "unpublished":
            fail("self-test did not classify unpublished Cargo tool output")
        remove_stage(staging)

        online, staging = fixture(base / "destination-race", "cargo-ndk")
        (online / "cargo-ndk-tool").mkdir()
        try:
            publish(
                online,
                staging,
                uid,
                gid,
                kind="cargo-ndk",
                tool_version=versions["cargo-ndk"],
                rust_version="1.75",
            )
        except ToolOutputError:
            pass
        else:
            fail("self-test accepted an occupied Cargo tool destination")
        (online / "cargo-ndk-tool").rmdir()
        remove_stage(staging)

        online, staging = fixture(base / "wrong-metadata", "frb")
        (staging / "output" / ".crates2.json").write_text("{}\n", encoding="ascii")
        try:
            verify_staged(
                online,
                staging,
                uid,
                gid,
                kind="frb",
                tool_version=versions["frb"],
                rust_version="1.75",
            )
        except ToolOutputError:
            pass
        else:
            fail("self-test accepted wrong Cargo installation metadata")
        remove_stage(staging)

        hostile = base / "hostile"
        hostile.mkdir()
        (hostile / "target").write_bytes(b"x")
        os.symlink("target", hostile / "link")
        try:
            inspect_tree(hostile, owners={(uid, gid)})
        except ToolOutputError:
            pass
        else:
            fail("self-test accepted a symlinked Cargo tool output")

        linked = base / "linked"
        linked.mkdir()
        (linked / "source").write_bytes(b"x")
        os.link(linked / "source", linked / "alias")
        try:
            inspect_tree(linked, owners={(uid, gid)})
        except ToolOutputError:
            pass
        else:
            fail("self-test accepted a hardlinked Cargo tool output")

        extended = base / "extended"
        extended.mkdir()
        (extended / "payload").write_bytes(b"x")
        os.setxattr(extended / "payload", "user.rustdesk-test", b"x")
        try:
            inspect_tree(extended, owners={(uid, gid)})
        except ToolOutputError:
            pass
        else:
            fail("self-test accepted extended attributes in Cargo tool output")

        set_id = base / "set-id"
        set_id.mkdir()
        payload = set_id / "payload"
        payload.write_bytes(b"x")
        payload.chmod(0o4700)
        try:
            inspect_tree(set_id, owners={(uid, gid)})
        except ToolOutputError:
            pass
        else:
            fail("self-test accepted set-id mode bits in Cargo tool output")


def common_arguments(parser: argparse.ArgumentParser, staging: bool = True) -> None:
    parser.add_argument("--online", type=Path, required=True)
    if staging:
        parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    parser.add_argument("--kind", choices=tuple(SPECS), required=True)


def semantic_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--tool-version", required=True)
    parser.add_argument("--rust-version", required=True)


def argument_parser() -> argparse.ArgumentParser:
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
    recover_parser = subparsers.add_parser("recover")
    common_arguments(recover_parser)
    check_parser = subparsers.add_parser("check-complete")
    common_arguments(check_parser, staging=False)
    semantic_arguments(check_parser)
    subparsers.add_parser("self-test")
    return value


def main() -> int:
    arguments = argument_parser().parse_args()
    if arguments.command == "self-test":
        self_test()
        print("online-cargo-tool-output: self-test OK")
        return 0
    if arguments.uid < 0 or arguments.gid < 0:
        fail("UID/GID must be nonnegative")
    staging = getattr(arguments, "staging", None)
    if arguments.command == "prepare":
        prepare(
            arguments.online,
            staging,
            arguments.uid,
            arguments.gid,
            kind=arguments.kind,
            tool_version=arguments.tool_version,
            rust_version=arguments.rust_version,
        )
    elif arguments.command == "verify":
        verify_staged(
            arguments.online,
            staging,
            arguments.uid,
            arguments.gid,
            kind=arguments.kind,
            tool_version=arguments.tool_version,
            rust_version=arguments.rust_version,
        )
    elif arguments.command == "publish":
        publish(
            arguments.online,
            staging,
            arguments.uid,
            arguments.gid,
            kind=arguments.kind,
            tool_version=arguments.tool_version,
            rust_version=arguments.rust_version,
        )
    elif arguments.command == "recover":
        print(
            recover(
                arguments.online,
                staging,
                arguments.uid,
                arguments.gid,
                kind=arguments.kind,
            )
        )
    elif arguments.command == "check-complete":
        check_complete(
            arguments.online,
            arguments.uid,
            arguments.gid,
            kind=arguments.kind,
            tool_version=arguments.tool_version,
            rust_version=arguments.rust_version,
        )
    else:
        fail("unknown command")
    print(f"online-cargo-tool-output: {arguments.command} OK")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ToolOutputError) as error:
        raise SystemExit(f"online-cargo-tool-output: {error}")
