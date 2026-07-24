#!/usr/bin/env python3
"""Prepare, validate, recover, and publish vcpkg native-codec outputs."""

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


STATE_NAME = ".rustdesk-vcpkg-native-output-state-v1"
STATE_VERSION = 1
OUTPUT_MARKER = ".rustdesk-vcpkg-native-output-key-v1"
LIBVPX_MARKER = ".rustdesk-libvpx-native-key"
STAGING_PATTERN = re.compile(
    r"\.rustdesk-vcpkg-native-(x64-linux|arm64-android)\.[A-Za-z0-9_]{8,}\Z"
)
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
BLOCK_SIZE = 1024 * 1024
MOUNTINFO_LIMIT = 8 * 1024 * 1024
MAX_STATE_BYTES = 8192
MAX_FILES = 256
MAX_DIRECTORIES = 32
MAX_DEPTH = 4
MAX_BYTES = 256 * 1024 * 1024
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 131072
RENAME_NOREPLACE = 1
FORBIDDEN_MODE_BITS = stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX


class NativeOutputError(RuntimeError):
    pass


@dataclass(frozen=True)
class NativeSpec:
    kind: str
    machine: int
    headers: frozenset[str]
    libraries: frozenset[str]


COMMON_HEADERS = frozenset(
    {
        "jconfig.h",
        "jerror.h",
        "jmorecfg.h",
        "jpeglib.h",
        "libyuv.h",
        "libyuv/basic_types.h",
        "libyuv/compare.h",
        "libyuv/compare_row.h",
        "libyuv/convert.h",
        "libyuv/convert_argb.h",
        "libyuv/convert_from.h",
        "libyuv/convert_from_argb.h",
        "libyuv/cpu_id.h",
        "libyuv/loongson_intrinsics.h",
        "libyuv/macros_msa.h",
        "libyuv/mjpeg_decoder.h",
        "libyuv/planar_functions.h",
        "libyuv/rotate.h",
        "libyuv/rotate_argb.h",
        "libyuv/rotate_row.h",
        "libyuv/row.h",
        "libyuv/scale.h",
        "libyuv/scale_argb.h",
        "libyuv/scale_rgb.h",
        "libyuv/scale_row.h",
        "libyuv/scale_uv.h",
        "libyuv/version.h",
        "libyuv/video_common.h",
        "opus/opus.h",
        "opus/opus_defines.h",
        "opus/opus_multistream.h",
        "opus/opus_projection.h",
        "opus/opus_types.h",
        "turbojpeg.h",
        "vpx/vp8.h",
        "vpx/vp8cx.h",
        "vpx/vp8dx.h",
        "vpx/vpx_codec.h",
        "vpx/vpx_decoder.h",
        "vpx/vpx_encoder.h",
        "vpx/vpx_ext_ratectrl.h",
        "vpx/vpx_frame_buffer.h",
        "vpx/vpx_image.h",
        "vpx/vpx_integer.h",
        "vpx/vpx_tpl.h",
    }
)
OBOE_HEADERS = frozenset(
    {
        "oboe/AudioStream.h",
        "oboe/AudioStreamBase.h",
        "oboe/AudioStreamBuilder.h",
        "oboe/AudioStreamCallback.h",
        "oboe/Definitions.h",
        "oboe/FifoBuffer.h",
        "oboe/FifoControllerBase.h",
        "oboe/FullDuplexStream.h",
        "oboe/LatencyTuner.h",
        "oboe/Oboe.h",
        "oboe/OboeExtensions.h",
        "oboe/ResultWithValue.h",
        "oboe/StabilizedCallback.h",
        "oboe/Utilities.h",
        "oboe/Version.h",
    }
)
COMMON_LIBRARIES = frozenset(
    {"libjpeg.a", "libopus.a", "libturbojpeg.a", "libvpx.a", "libyuv.a"}
)
SPECS = {
    "x64-linux": NativeSpec(
        "x64-linux",
        62,
        COMMON_HEADERS,
        COMMON_LIBRARIES,
    ),
    "arm64-android": NativeSpec(
        "arm64-android",
        183,
        COMMON_HEADERS | OBOE_HEADERS,
        COMMON_LIBRARIES | {"liboboe.a"},
    ),
}
AUDITED_STALE_LEGACY_OUTPUTS = {
    "x64-linux": (
        "2f1a0d9ec38bec3b32c2154a752119c3240c9944ab0ce1c4dfaf91e6a4bfac23",
        "4fbb47ef3e8cdd79f96697e9650fc3a31e368dd38a54aa3af372bb5e59b0fa46",
    ),
    "arm64-android": (
        "2f1a0d9ec38bec3b32c2154a752119c3240c9944ab0ce1c4dfaf91e6a4bfac23",
        "913588e8746761275c3115279789e1590bff9af614072882c09e5fc827e4ad55",
    ),
}
LEGACY_OUTPUT_BINDINGS: dict[str, tuple[str, str]] = {}


def fail(message: str) -> None:
    raise NativeOutputError(message)


def spec_for(kind: str) -> NativeSpec:
    spec = SPECS.get(kind)
    if spec is None:
        fail("vcpkg native output kind is outside the closed supported set")
    return spec


def validate_sha256(value: str, label: str) -> str:
    if SHA256_PATTERN.fullmatch(value) is None:
        fail(f"{label} is not one lowercase SHA-256 value")
    return value


def validate_builder(value: str) -> str:
    if IMAGE_PATTERN.fullmatch(value) is None:
        fail("vcpkg native builder is not one immutable image ID")
    return value


def validate_legacy_binding(kind: str, output_key: str, digest: str) -> None:
    expected = LEGACY_OUTPUT_BINDINGS.get(kind)
    if expected != (output_key, digest):
        fail(
            "historical vcpkg native output does not match its exact "
            "current-key and full-tree receipt"
        )


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


def reject_mount_at_or_below(path: Path) -> None:
    encoded = os.fsencode(path)
    prefix = encoded.rstrip(b"/") + b"/"
    for mountpoint in read_mountpoints():
        if mountpoint == encoded or mountpoint.startswith(prefix):
            fail(f"vcpkg native private tree contains a mount: {os.fsdecode(mountpoint)}")


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


def validate_directory(
    path: Path,
    label: str,
    online_metadata: os.stat_result,
    owners_and_modes: set[tuple[int, int, int]],
) -> os.stat_result:
    validate_absolute(path, label)
    metadata = os.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail(f"{label} is not one real directory")
    if metadata.st_dev != online_metadata.st_dev:
        fail(f"{label} is not on the online filesystem")
    observed = (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode))
    if observed not in owners_and_modes:
        fail(f"{label} ownership or mode is inadmissible")
    reject_extended_metadata(path, metadata, label)
    return metadata


def parent_paths(online: Path) -> tuple[Path, Path]:
    vcpkg = online / "vcpkg"
    return vcpkg, vcpkg / "installed"


def ensure_private_parents(
    online: Path,
    uid: int,
    gid: int,
) -> tuple[os.stat_result, os.stat_result]:
    online_metadata = validate_online(online, uid, gid)
    vcpkg, installed = parent_paths(online)
    for path, parent, label in (
        (vcpkg, online, "vcpkg cache root"),
        (installed, vcpkg, "vcpkg installed root"),
    ):
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        metadata = validate_directory(
            path,
            label,
            online_metadata,
            {(uid, gid, 0o700)},
        )
        if metadata.st_dev != online_metadata.st_dev:
            fail(f"{label} crossed the online filesystem")
        fsync_directory(parent)
    return (
        validate_directory(
            vcpkg,
            "vcpkg cache root",
            online_metadata,
            {(uid, gid, 0o700)},
        ),
        validate_directory(
            installed,
            "vcpkg installed root",
            online_metadata,
            {(uid, gid, 0o700)},
        ),
    )


def validate_existing_parents(
    online: Path,
    uid: int,
    gid: int,
) -> tuple[os.stat_result, os.stat_result]:
    online_metadata = validate_online(online, uid, gid)
    vcpkg, installed = parent_paths(online)
    admitted = {(uid, gid, 0o700), (0, 0, 0o755)}
    return (
        validate_directory(vcpkg, "vcpkg cache root", online_metadata, admitted),
        validate_directory(installed, "vcpkg installed root", online_metadata, admitted),
    )


def validate_staging(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    kind: str,
) -> os.stat_result:
    online_metadata = validate_online(online, uid, gid)
    validate_absolute(staging, "vcpkg native staging")
    match = STAGING_PATTERN.fullmatch(staging.name)
    if staging.parent != online or match is None or match.group(1) != kind:
        fail("vcpkg native staging is outside its reserved online namespace")
    metadata = os.lstat(staging)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("vcpkg native staging is not one real directory")
    if metadata.st_dev != online_metadata.st_dev:
        fail("vcpkg native staging is not on the online filesystem")
    if (metadata.st_uid, metadata.st_gid) != (uid, gid):
        fail("vcpkg native staging is not owned by the acquisition identity")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        fail("vcpkg native staging is not mode 0700")
    reject_extended_metadata(staging, metadata, "vcpkg native staging")
    reject_mount_at_or_below(staging)
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
        fail(f"vcpkg native output contains a nonportable path: {relative!r}")


def read_regular(path: Path, maximum: int) -> tuple[bytes, os.stat_result]:
    metadata = os.lstat(path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size < 0
        or metadata.st_size > maximum
    ):
        fail(f"vcpkg native entry is not one bounded single-link file: {path}")
    reject_extended_metadata(path, metadata, "vcpkg native regular file")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if stable_metadata(before) != stable_metadata(metadata):
            fail(f"vcpkg native file changed before read: {path}")
        data = bytearray()
        while True:
            block = os.read(descriptor, min(BLOCK_SIZE, maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
            if len(data) > maximum:
                fail(f"vcpkg native file exceeds its byte bound: {path}")
        after = os.fstat(descriptor)
        if stable_metadata(before) != stable_metadata(after):
            fail(f"vcpkg native file changed while read: {path}")
        return bytes(data), after
    finally:
        os.close(descriptor)


def inspect_tree(
    root: Path,
    uid: int,
    gid: int,
    *,
    legacy: bool,
    normalize: bool = False,
    sealed: bool = False,
    private_sealed_root: bool = False,
    expected_identity: tuple[int, int] | None = None,
) -> str:
    validate_absolute(root, "vcpkg native output")
    root_metadata = os.lstat(root)
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        fail("vcpkg native output is not one real directory")
    if expected_identity is not None and identity(root_metadata) != expected_identity:
        fail("vcpkg native output identity changed")
    root_owner = (0, 0) if legacy else (uid, gid)
    if (root_metadata.st_uid, root_metadata.st_gid) != root_owner:
        fail("vcpkg native output owner is inadmissible")
    reject_mount_at_or_below(root)
    root_device = root_metadata.st_dev
    files = 0
    directories = 1
    content_bytes = 0
    digest = hashlib.sha256()
    final_metadata: list[tuple[Path, tuple[int, ...]]] = []

    def descend(directory: Path, relative: str, depth: int) -> None:
        nonlocal files, directories, content_bytes
        if depth > MAX_DEPTH:
            fail("vcpkg native output exceeds its depth bound")
        before = os.lstat(directory)
        if (
            not stat.S_ISDIR(before.st_mode)
            or before.st_dev != root_device
            or (before.st_uid, before.st_gid) != root_owner
        ):
            fail(f"vcpkg native directory authority is invalid: {relative or '.'}")
        reject_extended_metadata(
            directory,
            before,
            f"vcpkg native directory {relative or '.'}",
        )
        if normalize:
            os.chmod(directory, 0o700, follow_symlinks=False)
            before = os.lstat(directory)
        elif sealed:
            expected_mode = 0o700 if private_sealed_root and depth == 0 else 0o500
            if stat.S_IMODE(before.st_mode) != expected_mode:
                fail(
                    "sealed vcpkg native directory has the wrong mode: "
                    f"{relative or '.'}"
                )
        elif legacy and stat.S_IMODE(before.st_mode) != 0o755:
            fail(f"historical vcpkg native directory has an unexpected mode: {relative or '.'}")
        elif not sealed and not legacy and stat.S_IMODE(before.st_mode) & 0o022:
            fail(f"staged vcpkg native directory is group/world writable: {relative or '.'}")
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
        digest.update(b"D\0" + os.fsencode(relative) + b"\0")
        for entry in entries:
            child_relative = entry.name if not relative else f"{relative}/{entry.name}"
            validate_name(entry.name, child_relative)
            child = directory / entry.name
            metadata = entry.stat(follow_symlinks=False)
            if (
                metadata.st_dev != root_device
                or (metadata.st_uid, metadata.st_gid) != root_owner
            ):
                fail(f"vcpkg native entry has foreign authority: {child_relative}")
            reject_extended_metadata(
                child,
                metadata,
                f"vcpkg native entry {child_relative}",
            )
            if stat.S_ISDIR(metadata.st_mode):
                directories += 1
                if directories > MAX_DIRECTORIES:
                    fail("vcpkg native output exceeds its directory bound")
                descend(child, child_relative, depth + 1)
            elif stat.S_ISREG(metadata.st_mode):
                files += 1
                content_bytes += metadata.st_size
                if files > MAX_FILES:
                    fail("vcpkg native output exceeds its file bound")
                if content_bytes > MAX_BYTES or metadata.st_size > MAX_FILE_BYTES:
                    fail(f"vcpkg native output exceeds its byte bound: {child_relative}")
                if metadata.st_nlink != 1:
                    fail(f"vcpkg native output contains an external hardlink: {child_relative}")
                if normalize:
                    os.chmod(child, 0o600, follow_symlinks=False)
                    metadata = os.lstat(child)
                elif sealed and stat.S_IMODE(metadata.st_mode) != 0o400:
                    fail(f"published vcpkg native file is not mode 0400: {child_relative}")
                elif legacy and stat.S_IMODE(metadata.st_mode) not in (0o644, 0o664, 0o755):
                    fail(f"historical vcpkg native file has an unexpected mode: {child_relative}")
                elif not sealed and not legacy and stat.S_IMODE(metadata.st_mode) & 0o022:
                    fail(f"staged vcpkg native file is group/world writable: {child_relative}")
                data, after = read_regular(child, MAX_FILE_BYTES)
                if identity(after) != identity(metadata):
                    fail(f"vcpkg native file identity changed: {child_relative}")
                digest.update(
                    b"F\0"
                    + os.fsencode(child_relative)
                    + b"\0"
                    + len(data).to_bytes(8, "big")
                    + hashlib.sha256(data).digest()
                )
                final_metadata.append((child, stable_metadata(after)))
            elif stat.S_ISLNK(metadata.st_mode):
                fail(f"vcpkg native output contains a symlink: {child_relative}")
            else:
                fail(f"vcpkg native output contains a special file: {child_relative}")
        after = os.lstat(directory)
        if (
            identity(before) != identity(after)
            or not stat.S_ISDIR(after.st_mode)
            or after.st_dev != root_device
        ):
            fail(f"vcpkg native directory changed during traversal: {relative or '.'}")
        final_metadata.append((directory, stable_metadata(after)))

    descend(root, "", 0)
    if files == 0:
        fail("vcpkg native output is empty")
    for path, expected in final_metadata:
        if stable_metadata(os.lstat(path)) != expected:
            fail(f"vcpkg native output changed after traversal: {path}")
    return digest.hexdigest()


def relative_regular_files(root: Path) -> set[str]:
    values = set()
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        directories.sort()
        files.sort()
        current_path = Path(current)
        for name in files:
            values.add(os.fspath((current_path / name).relative_to(root)))
    return values


def expected_header_directories(headers: frozenset[str]) -> set[str]:
    directories = set()
    for header in headers:
        parent = Path(header).parent
        while os.fspath(parent) != ".":
            directories.add(os.fspath(parent))
            parent = parent.parent
    return directories


def relative_directories(root: Path) -> set[str]:
    values = set()
    for current, directories, _files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories.sort()
        for name in directories:
            values.add(os.fspath((current_path / name).relative_to(root)))
    return values


def parse_decimal(field: bytes, label: str) -> int:
    value = field.strip()
    if not value or any(byte < ord("0") or byte > ord("9") for byte in value):
        fail(f"static archive has a malformed {label}")
    return int(value)


def validate_elf_object(data: bytes, machine: int, archive: Path) -> None:
    if len(data) < 64:
        fail(f"static archive contains a truncated object: {archive}")
    if (
        data[:7] != b"\x7fELF\x02\x01\x01"
        or data[7] not in (0, 3)
        or data[8] != 0
        or any(data[9:16])
    ):
        fail(f"static archive contains a noncanonical ELF64 object: {archive}")
    (
        elf_type,
        observed_machine,
        version,
        entry,
        program_header_offset,
        section_header_offset,
        _flags,
        header_size,
        program_header_size,
        program_header_count,
        section_header_size,
        section_header_count,
        section_name_index,
    ) = struct.unpack("<HHIQQQIHHHHHH", data[16:64])
    if elf_type != 1 or observed_machine != machine or version != 1:
        fail(f"static archive contains an object for the wrong ABI: {archive}")
    if (
        entry != 0
        or program_header_offset != 0
        or program_header_size != 0
        or program_header_count != 0
        or header_size != 64
        or section_header_size != 64
        or section_header_count == 0
        or section_header_offset < 64
        or section_header_offset
        > len(data) - section_header_size * section_header_count
        or section_name_index >= section_header_count
    ):
        fail(f"static archive contains a malformed relocatable ELF64 object: {archive}")


def validate_static_archive(path: Path, machine: int) -> None:
    data, _metadata = read_regular(path, MAX_FILE_BYTES)
    if not data.startswith(b"!<arch>\n"):
        fail(f"native library is not a regular static archive: {path}")
    offset = 8
    members = 0
    objects = 0
    string_table = b""
    while offset < len(data):
        if len(data) - offset < 60:
            fail(f"static archive has a truncated member header: {path}")
        header = data[offset:offset + 60]
        if header[58:60] != b"`\n":
            fail(f"static archive has an invalid member trailer: {path}")
        size = parse_decimal(header[48:58], "member size")
        start = offset + 60
        end = start + size
        if end > len(data):
            fail(f"static archive member exceeds the file: {path}")
        name = header[:16].decode("ascii", "strict").rstrip()
        payload = data[start:end]
        members += 1
        if members > MAX_ARCHIVE_MEMBERS:
            fail(f"static archive exceeds its member bound: {path}")
        special = False
        if name == "//":
            string_table = payload
            special = True
        elif name in ("/", "/SYM64/") or name.startswith("__.SYMDEF"):
            special = True
        elif name.startswith("#1/"):
            name_length = parse_decimal(name[3:].encode("ascii"), "BSD name length")
            if name_length > len(payload):
                fail(f"static archive has a truncated BSD member name: {path}")
            payload = payload[name_length:]
        elif name.startswith("/") and name[1:].isdigit():
            table_offset = int(name[1:])
            if table_offset >= len(string_table):
                fail(f"static archive has an invalid GNU member name: {path}")
        if not special:
            validate_elf_object(payload, machine, path)
            objects += 1
        offset = end + (size & 1)
    if offset != len(data) or members == 0 or objects == 0:
        fail(f"static archive has no closed ELF object inventory: {path}")


def read_marker(path: Path, expected: str, label: str) -> None:
    data, _metadata = read_regular(path, 256)
    if data != f"{expected}\n".encode("ascii"):
        fail(f"{label} does not match the transaction key")


def validate_semantics(
    root: Path,
    kind: str,
    output_key: str,
    libvpx_key: str,
    *,
    legacy: bool,
) -> None:
    spec = spec_for(kind)
    validate_sha256(output_key, "vcpkg native output key")
    validate_sha256(libvpx_key, "libvpx native key")
    with os.scandir(root) as iterator:
        top = {entry.name: entry for entry in iterator}
    required = {"include", "lib", LIBVPX_MARKER}
    if legacy:
        if not required.issubset(top):
            fail("historical vcpkg native output is missing a required top-level entry")
        if OUTPUT_MARKER in top:
            fail("historical vcpkg native output ambiguously carries the new marker")
    else:
        required.add(OUTPUT_MARKER)
        if set(top) != required:
            fail("new vcpkg native output has an unexpected top-level inventory")
    if not top["include"].is_dir(follow_symlinks=False):
        fail("vcpkg native include entry is not one real directory")
    if not top["lib"].is_dir(follow_symlinks=False):
        fail("vcpkg native lib entry is not one real directory")
    if relative_regular_files(root / "include") != set(spec.headers):
        fail("vcpkg native output has the wrong exact header inventory")
    if relative_directories(root / "include") != expected_header_directories(spec.headers):
        fail("vcpkg native output has the wrong exact header-directory inventory")
    with os.scandir(root / "lib") as iterator:
        immediate = {entry.name: entry for entry in iterator}
    observed_libraries = {
        name
        for name, entry in immediate.items()
        if entry.is_file(follow_symlinks=False) and name.endswith(".a")
    }
    if observed_libraries != set(spec.libraries):
        fail("vcpkg native output has the wrong exact static-library inventory")
    if not legacy and set(immediate) != set(spec.libraries):
        fail("new vcpkg native lib directory contains unconsumed output")
    for library in sorted(spec.libraries):
        validate_static_archive(root / "lib" / library, spec.machine)
    if legacy:
        for archive in sorted(root.rglob("*.a"), key=lambda path: os.fsencode(path)):
            if archive.parent == root / "lib" and archive.name in spec.libraries:
                continue
            validate_static_archive(archive, spec.machine)
    read_marker(root / LIBVPX_MARKER, libvpx_key, "libvpx native marker")
    if not legacy:
        read_marker(root / OUTPUT_MARKER, output_key, "vcpkg native output marker")


def validate_output(
    root: Path,
    uid: int,
    gid: int,
    kind: str,
    output_key: str,
    libvpx_key: str,
    *,
    legacy: bool,
    normalize: bool = False,
    sealed: bool = False,
    private_sealed_root: bool = False,
    expected_identity: tuple[int, int] | None = None,
) -> str:
    digest = inspect_tree(
        root,
        uid,
        gid,
        legacy=legacy,
        normalize=normalize,
        sealed=sealed,
        private_sealed_root=private_sealed_root,
        expected_identity=expected_identity,
    )
    validate_semantics(root, kind, output_key, libvpx_key, legacy=legacy)
    return digest


def fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
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
                    fail(f"cannot synchronize nonprivate vcpkg native file: {path}")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    for directory in reversed(directories):
        fsync_directory(directory)


def seal_tree(root: Path) -> None:
    directories = []
    for current, names, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories.append(current_path)
        names.sort()
        files.sort()
        for name in files:
            os.chmod(current_path / name, 0o400, follow_symlinks=False)
    for directory in reversed(directories):
        os.chmod(
            directory,
            0o700 if directory == root else 0o500,
            follow_symlinks=False,
        )


def write_state(staging: Path, payload: dict[str, object]) -> None:
    state = staging / STATE_NAME
    temporary = staging / f"{STATE_NAME}.tmp"
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    if len(encoded) > MAX_STATE_BYTES:
        fail("vcpkg native transaction state exceeds its byte bound")
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
                fail("short write while recording vcpkg native transaction state")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, state)
    fsync_directory(staging)


def validate_inventory(staging: Path, expected: set[str]) -> None:
    if set(os.listdir(staging)) != expected:
        fail("vcpkg native staging inventory is incoherent and was preserved")


def state_payload(
    online: Path,
    staging: Path,
    output: Path,
    parent: Path,
    uid: int,
    gid: int,
    kind: str,
    output_key: str,
    libvpx_key: str,
    builder: str,
) -> dict[str, object]:
    return {
        "version": STATE_VERSION,
        "online": os.fspath(online),
        "online_identity": encode_identity(identity(os.lstat(online))),
        "staging": os.fspath(staging),
        "staging_identity": encode_identity(identity(os.lstat(staging))),
        "output_identity": encode_identity(identity(os.lstat(output))),
        "parent": os.fspath(parent),
        "parent_identity": encode_identity(identity(os.lstat(parent))),
        "uid": uid,
        "gid": gid,
        "kind": kind,
        "output_key": output_key,
        "libvpx_key": libvpx_key,
        "builder": builder,
        "destination": kind,
    }


def load_state(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    kind: str,
    output_key: str,
    libvpx_key: str,
    builder: str,
) -> dict[str, object]:
    spec_for(kind)
    validate_sha256(output_key, "vcpkg native output key")
    validate_sha256(libvpx_key, "libvpx native key")
    validate_builder(builder)
    staging_metadata = validate_staging(online, staging, uid, gid, kind)
    _vcpkg_metadata, parent_metadata = ensure_private_parents(online, uid, gid)
    data, metadata = read_regular(staging / STATE_NAME, MAX_STATE_BYTES)
    if (
        (metadata.st_uid, metadata.st_gid) != (uid, gid)
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        fail("vcpkg native transaction state metadata is invalid")
    try:
        payload = json.loads(data.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"vcpkg native transaction state is malformed: {error}")
    expected_keys = {
        "version",
        "online",
        "online_identity",
        "staging",
        "staging_identity",
        "output_identity",
        "parent",
        "parent_identity",
        "uid",
        "gid",
        "kind",
        "output_key",
        "libvpx_key",
        "builder",
        "destination",
    }
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        fail("vcpkg native transaction state has an unexpected schema")
    if payload["version"] != STATE_VERSION:
        fail("vcpkg native transaction state version changed")
    if payload["online"] != os.fspath(online) or payload["staging"] != os.fspath(staging):
        fail("vcpkg native transaction state has the wrong path binding")
    parent = parent_paths(online)[1]
    if payload["parent"] != os.fspath(parent):
        fail("vcpkg native transaction state has the wrong publication parent")
    expected_values = {
        "uid": uid,
        "gid": gid,
        "kind": kind,
        "output_key": output_key,
        "libvpx_key": libvpx_key,
        "builder": builder,
        "destination": kind,
    }
    for key, expected in expected_values.items():
        if payload[key] != expected:
            fail(f"vcpkg native transaction state changed its {key} binding")
    if decode_identity(payload["online_identity"], "online root") != identity(
        os.lstat(online)
    ):
        fail("online root identity changed during the vcpkg native transaction")
    if decode_identity(payload["staging_identity"], "vcpkg native staging") != identity(
        staging_metadata
    ):
        fail("vcpkg native staging identity changed")
    if decode_identity(payload["parent_identity"], "vcpkg installed parent") != identity(
        parent_metadata
    ):
        fail("vcpkg native publication parent identity changed")
    return payload


def prepare(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    kind: str,
    output_key: str,
    libvpx_key: str,
    builder: str,
) -> None:
    spec_for(kind)
    validate_sha256(output_key, "vcpkg native output key")
    validate_sha256(libvpx_key, "libvpx native key")
    validate_builder(builder)
    validate_staging(online, staging, uid, gid, kind)
    validate_inventory(staging, set())
    _vcpkg_metadata, parent_metadata = ensure_private_parents(online, uid, gid)
    output = staging / "output"
    output.mkdir(mode=0o700)
    write_state(
        staging,
        state_payload(
            online,
            staging,
            output,
            parent_paths(online)[1],
            uid,
            gid,
            kind,
            output_key,
            libvpx_key,
            builder,
        ),
    )
    if identity(os.lstat(parent_paths(online)[1])) != identity(parent_metadata):
        fail("vcpkg native publication parent changed during preparation")
    validate_inventory(staging, {STATE_NAME, "output"})
    fsync_directory(online)


def verify_staged(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    kind: str,
    output_key: str,
    libvpx_key: str,
    builder: str,
) -> None:
    payload = load_state(
        online,
        staging,
        uid,
        gid,
        kind,
        output_key,
        libvpx_key,
        builder,
    )
    validate_inventory(staging, {STATE_NAME, "output"})
    output = staging / "output"
    expected = decode_identity(payload["output_identity"], "vcpkg native output")
    validate_output(
        output,
        uid,
        gid,
        kind,
        output_key,
        libvpx_key,
        legacy=False,
        normalize=True,
        expected_identity=expected,
    )
    seal_tree(output)
    sync_tree(output)
    validate_output(
        output,
        uid,
        gid,
        kind,
        output_key,
        libvpx_key,
        legacy=False,
        sealed=True,
        private_sealed_root=True,
        expected_identity=expected,
    )
    fsync_directory(staging)


def check_complete(
    online: Path,
    uid: int,
    gid: int,
    kind: str,
    output_key: str,
    libvpx_key: str,
    builder: str,
) -> None:
    spec_for(kind)
    validate_sha256(output_key, "vcpkg native output key")
    validate_sha256(libvpx_key, "libvpx native key")
    validate_builder(builder)
    validate_existing_parents(online, uid, gid)
    output = parent_paths(online)[1] / kind
    metadata = os.lstat(output)
    legacy = (metadata.st_uid, metadata.st_gid) == (0, 0)
    if not legacy and (metadata.st_uid, metadata.st_gid) != (uid, gid):
        fail("existing vcpkg native output has foreign ownership")
    digest = validate_output(
        output,
        uid,
        gid,
        kind,
        output_key,
        libvpx_key,
        legacy=legacy,
        sealed=not legacy,
    )
    if legacy:
        validate_legacy_binding(kind, output_key, digest)


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
    uid: int,
    gid: int,
    kind: str,
    output_key: str,
    libvpx_key: str,
    builder: str,
) -> None:
    verify_staged(
        online,
        staging,
        uid,
        gid,
        kind,
        output_key,
        libvpx_key,
        builder,
    )
    payload = load_state(
        online,
        staging,
        uid,
        gid,
        kind,
        output_key,
        libvpx_key,
        builder,
    )
    output = staging / "output"
    expected = decode_identity(payload["output_identity"], "vcpkg native output")
    parent = parent_paths(online)[1]
    destination = parent / kind
    if destination.exists() or destination.is_symlink():
        fail("vcpkg native destination appeared before no-clobber publication")
    sync_tree(output)
    fsync_directory(staging)
    parent_fd = open_directory(parent)
    staging_fd = open_directory(staging)
    moved = False
    try:
        renameat2(staging_fd, "output", parent_fd, kind, RENAME_NOREPLACE)
        moved = True
        os.fsync(staging_fd)
        os.fsync(parent_fd)
        os.chmod(destination, 0o500, follow_symlinks=False)
        fsync_directory(destination)
        os.fsync(parent_fd)
        validate_output(
            destination,
            uid,
            gid,
            kind,
            output_key,
            libvpx_key,
            legacy=False,
            sealed=True,
            expected_identity=expected,
        )
    except BaseException as primary:
        if moved:
            try:
                os.chmod(destination, 0o700, follow_symlinks=False)
                renameat2(parent_fd, kind, staging_fd, "output", RENAME_NOREPLACE)
                os.fsync(staging_fd)
                os.fsync(parent_fd)
            except BaseException as rollback:
                primary.add_note(
                    f"vcpkg native publication rollback also failed: {rollback}"
                )
        raise
    finally:
        os.close(staging_fd)
        os.close(parent_fd)


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
    kind: str,
) -> str:
    validate_staging(online, staging, uid, gid, kind)
    names = set(os.listdir(staging))
    if not names:
        return "unprepared-empty"
    expected = {"output"}
    temporary_state = staging / f"{STATE_NAME}.tmp"
    if names == {"output", temporary_state.name}:
        data, metadata = read_regular(temporary_state, MAX_STATE_BYTES)
        del data
        if (
            (metadata.st_uid, metadata.st_gid) != (uid, gid)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            fail("unprepared vcpkg native state write is unsafe and was preserved")
        expected.add(temporary_state.name)
    if names != expected:
        fail("unprepared vcpkg native staging is incoherent and was preserved")
    output = staging / "output"
    metadata = os.lstat(output)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid) != (uid, gid)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or list_xattrs(output)
    ):
        fail("unprepared vcpkg native output is unsafe and was preserved")
    with os.scandir(output) as entries:
        if next(entries, None) is not None:
            fail("unprepared vcpkg native output is not empty and was preserved")
    if temporary_state.name in names:
        return "unprepared-state-write"
    return "unprepared-output"


def recover(
    online: Path,
    staging: Path,
    uid: int,
    gid: int,
    kind: str,
    output_key: str,
    libvpx_key: str,
    builder: str,
) -> str:
    state = staging / STATE_NAME
    if not state.exists() and not state.is_symlink():
        return recover_unprepared(online, staging, uid, gid, kind)
    payload = load_state(
        online,
        staging,
        uid,
        gid,
        kind,
        output_key,
        libvpx_key,
        builder,
    )
    expected = decode_identity(payload["output_identity"], "vcpkg native output")
    private_output = optional_identity(staging / "output")
    destination = parent_paths(online)[1] / kind
    live_output = optional_identity(destination)
    if private_output == expected:
        validate_inventory(staging, {STATE_NAME, "output"})
        if live_output is None:
            return "unpublished"
        return "unpublished-destination-occupied"
    if private_output is None and live_output == expected:
        validate_inventory(staging, {STATE_NAME})
        validate_output(
            destination,
            uid,
            gid,
            kind,
            output_key,
            libvpx_key,
            legacy=False,
            sealed=True,
            expected_identity=expected,
        )
        return "published"
    fail("vcpkg native output transaction state is incoherent and was preserved")


def fake_elf_object(machine: int) -> bytes:
    ident = b"\x7fELF\x02\x01\x01\0\0" + b"\0" * 7
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        1,
        machine,
        1,
        0,
        0,
        64,
        0,
        64,
        0,
        0,
        64,
        1,
        0,
    )
    return ident + header + b"\0" * 64


def fake_archive(machine: int) -> bytes:
    payload = fake_elf_object(machine)
    name = b"fixture.o/".ljust(16)
    header = (
        name
        + b"0".ljust(12)
        + b"0".ljust(6)
        + b"0".ljust(6)
        + b"644".ljust(8)
        + str(len(payload)).encode("ascii").ljust(10)
        + b"`\n"
    )
    return b"!<arch>\n" + header + payload + (b"\n" if len(payload) & 1 else b"")


def populate_fake_output(
    output: Path,
    spec: NativeSpec,
    output_key: str,
    libvpx_key: str,
) -> None:
    include = output / "include"
    library = output / "lib"
    include.mkdir()
    library.mkdir()
    for relative in sorted(spec.headers):
        path = include / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"/* {relative} */\n".encode("ascii"))
    for name in sorted(spec.libraries):
        (library / name).write_bytes(fake_archive(spec.machine))
    (output / OUTPUT_MARKER).write_text(output_key + "\n", encoding="ascii")
    (output / LIBVPX_MARKER).write_text(libvpx_key + "\n", encoding="ascii")


def make_staging(online: Path, kind: str) -> Path:
    return Path(
        tempfile.mkdtemp(
            prefix=f".rustdesk-vcpkg-native-{kind}.",
            dir=online,
        )
    )


def make_writable(root: Path) -> None:
    if not root.exists():
        return
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        try:
            current_path.chmod(0o700)
        except OSError:
            pass
        for name in files:
            try:
                (current_path / name).chmod(0o600)
            except OSError:
                pass
        for name in directories:
            try:
                (current_path / name).chmod(0o700)
            except OSError:
                pass


def expect_failure(action, message: str) -> None:
    try:
        action()
    except (OSError, NativeOutputError):
        return
    fail(message)


def run_self_test() -> None:
    uid = os.getuid()
    gid = os.getgid()
    output_key = "1" * 64
    libvpx_key = "2" * 64
    builder = "sha256:" + "3" * 64

    for kind, stale in AUDITED_STALE_LEGACY_OUTPUTS.items():
        expect_failure(
            lambda kind=kind, stale=stale: validate_legacy_binding(
                kind,
                output_key,
                stale[1],
            ),
            "self-test accepted a stale historical full-tree receipt",
        )

    def fixture(base: Path, kind: str) -> tuple[Path, Path]:
        base.mkdir()
        online = base / "online"
        online.mkdir(mode=0o700)
        staging = make_staging(online, kind)
        prepare(
            online,
            staging,
            uid,
            gid,
            kind,
            output_key,
            libvpx_key,
            builder,
        )
        populate_fake_output(
            staging / "output",
            spec_for(kind),
            output_key,
            libvpx_key,
        )
        return online, staging

    with tempfile.TemporaryDirectory(prefix="vcpkg-native-output-self-test.") as temporary:
        root = Path(temporary)
        try:
            for kind in SPECS:
                online, staging = fixture(root / f"normal-{kind}", kind)
                verify_staged(
                    online,
                    staging,
                    uid,
                    gid,
                    kind,
                    output_key,
                    libvpx_key,
                    builder,
                )
                publish(
                    online,
                    staging,
                    uid,
                    gid,
                    kind,
                    output_key,
                    libvpx_key,
                    builder,
                )
                if (
                    recover(
                        online,
                        staging,
                        uid,
                        gid,
                        kind,
                        output_key,
                        libvpx_key,
                        builder,
                    )
                    != "published"
                ):
                    fail("self-test did not classify completed vcpkg native publication")
                check_complete(
                    online,
                    uid,
                    gid,
                    kind,
                    output_key,
                    libvpx_key,
                    builder,
                )

            online, staging = fixture(root / "wrong-abi", "x64-linux")
            (
                staging / "output" / "lib" / "libvpx.a"
            ).write_bytes(
                fake_archive(spec_for("arm64-android").machine)
            )
            expect_failure(
                lambda: verify_staged(
                    online,
                    staging,
                    uid,
                    gid,
                    "x64-linux",
                    output_key,
                    libvpx_key,
                    builder,
                ),
                "self-test accepted a static archive for the wrong ABI",
            )

            online, staging = fixture(root / "malformed-elf", "x64-linux")
            archive = staging / "output" / "lib" / "libvpx.a"
            malformed = bytearray(archive.read_bytes())
            struct.pack_into("<H", malformed, 8 + 60 + 52, 0)
            archive.write_bytes(malformed)
            expect_failure(
                lambda: verify_staged(
                    online,
                    staging,
                    uid,
                    gid,
                    "x64-linux",
                    output_key,
                    libvpx_key,
                    builder,
                ),
                "self-test accepted malformed ELF64 object structure",
            )

            online, staging = fixture(root / "extra-header", "x64-linux")
            (staging / "output" / "include" / "unexpected.h").write_bytes(b"x")
            expect_failure(
                lambda: verify_staged(
                    online,
                    staging,
                    uid,
                    gid,
                    "x64-linux",
                    output_key,
                    libvpx_key,
                    builder,
                ),
                "self-test accepted an unexpected native header",
            )

            online, staging = fixture(root / "occupied", "arm64-android")
            verify_staged(
                online,
                staging,
                uid,
                gid,
                "arm64-android",
                output_key,
                libvpx_key,
                builder,
            )
            destination = parent_paths(online)[1] / "arm64-android"
            destination.mkdir()
            expect_failure(
                lambda: publish(
                    online,
                    staging,
                    uid,
                    gid,
                    "arm64-android",
                    output_key,
                    libvpx_key,
                    builder,
                ),
                "self-test accepted an occupied vcpkg native destination",
            )
            if (
                recover(
                    online,
                    staging,
                    uid,
                    gid,
                    "arm64-android",
                    output_key,
                    libvpx_key,
                    builder,
                )
                != "unpublished-destination-occupied"
            ):
                fail("self-test did not preserve an occupied vcpkg native destination")

            online, staging = fixture(root / "symlink", "x64-linux")
            header = staging / "output" / "include" / "jconfig.h"
            header.unlink()
            header.symlink_to("jerror.h")
            expect_failure(
                lambda: verify_staged(
                    online,
                    staging,
                    uid,
                    gid,
                    "x64-linux",
                    output_key,
                    libvpx_key,
                    builder,
                ),
                "self-test accepted a symlinked vcpkg native output",
            )

            online, staging = fixture(root / "hardlink", "x64-linux")
            archive = staging / "output" / "lib" / "libvpx.a"
            os.link(archive, online / "external-link")
            expect_failure(
                lambda: verify_staged(
                    online,
                    staging,
                    uid,
                    gid,
                    "x64-linux",
                    output_key,
                    libvpx_key,
                    builder,
                ),
                "self-test accepted an externally hardlinked vcpkg native output",
            )

            unprepared = root / "unprepared"
            unprepared.mkdir()
            online = unprepared / "online"
            online.mkdir(mode=0o700)
            staging = make_staging(online, "x64-linux")
            if (
                recover(
                    online,
                    staging,
                    uid,
                    gid,
                    "x64-linux",
                    output_key,
                    libvpx_key,
                    builder,
                )
                != "unprepared-empty"
            ):
                fail("self-test did not classify empty unprepared vcpkg native staging")

            if hasattr(os, "setxattr"):
                online, staging = fixture(root / "xattr", "x64-linux")
                target = staging / "output" / "include" / "jconfig.h"
                try:
                    os.setxattr(target, "user.rustdesk-test", b"1")
                except OSError:
                    pass
                else:
                    expect_failure(
                        lambda: verify_staged(
                            online,
                            staging,
                            uid,
                            gid,
                            "x64-linux",
                            output_key,
                            libvpx_key,
                            builder,
                        ),
                        "self-test accepted extended attributes in vcpkg native output",
                    )
        finally:
            make_writable(root)


def add_common_arguments(parser: argparse.ArgumentParser, staging: bool = True) -> None:
    parser.add_argument("--online", type=Path, required=True)
    if staging:
        parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    parser.add_argument("--kind", choices=tuple(SPECS), required=True)
    parser.add_argument("--output-key", required=True)
    parser.add_argument("--libvpx-key", required=True)
    parser.add_argument("--builder", required=True)


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("prepare", "verify", "publish", "recover"):
        add_common_arguments(subparsers.add_parser(command))
    add_common_arguments(subparsers.add_parser("check-complete"), staging=False)
    subparsers.add_parser("self-test")
    return parser


def main() -> int:
    arguments = argument_parser().parse_args()
    if arguments.command == "self-test":
        run_self_test()
        print("online-vcpkg-native-output: self-test OK")
        return 0
    if arguments.uid <= 0 or arguments.gid <= 0:
        fail("vcpkg native transaction owner must be a nonzero UID and GID")
    values = (
        arguments.online,
        arguments.uid,
        arguments.gid,
        arguments.kind,
        arguments.output_key,
        arguments.libvpx_key,
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
        fail("unsupported vcpkg native transaction command")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, NativeOutputError, UnicodeError) as error:
        raise SystemExit(f"online-vcpkg-native-output: {error}")
