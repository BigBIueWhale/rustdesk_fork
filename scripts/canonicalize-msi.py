#!/usr/bin/env python3
"""Canonicalize bounded MSI package-code and timestamp metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import struct
import sys
import tempfile
import uuid

import olefile


PID_REVNUMBER = 9
PID_CREATE_DTM = 12
PID_LASTSAVE_DTM = 13
VT_LPSTR = 0x1E
VT_FILETIME = 0x40
SUMINFO = "\x05SummaryInformation"
FMTID_SUMMARY_INFORMATION = bytes.fromhex("e0859ff2f94f6810ab9108002b27b3d9")
CFB_SIGNATURE = bytes.fromhex("d0cf11e0a1b11ae1")
FORK_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+-hardened\.[0-9]+$")
GIT_ID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
BRACED_GUID_RE = re.compile(rb"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}\0$")
CROSS_HANDLE_STABLE_FIELDS = ("st_dev", "st_ino", "st_nlink", "st_size", "st_mtime_ns")
STABLE_FIELDS = CROSS_HANDLE_STABLE_FIELDS + (
    () if os.name == "nt" else ("st_mode", "st_ctime_ns")
)


class MSIFormatError(ValueError):
    pass


def _same_file_state(left: os.stat_result, right: os.stat_result) -> bool:
    return all(getattr(left, field) == getattr(right, field) for field in STABLE_FIELDS)


def _require_real_directory_path(path: str) -> None:
    absolute = os.path.abspath(path)
    drive, tail = os.path.splitdrive(absolute)
    current = drive + os.sep if drive else os.sep
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    for component in (part for part in tail.split(os.sep) if part):
        current = os.path.join(current, component)
        metadata = os.lstat(current)
        if not stat.S_ISDIR(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & reparse:
            raise MSIFormatError("canonical output path traverses a non-directory or reparse point")


def _make_deletable(path: str) -> None:
    if os.name == "nt":
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)


def _open_regular(path: str) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    state = os.fstat(descriptor)
    if not stat.S_ISREG(state.st_mode) or state.st_nlink != 1:
        os.close(descriptor)
        raise MSIFormatError("input must be one non-hardlinked regular file")
    if not _same_file_state(state, os.lstat(path)):
        os.close(descriptor)
        raise MSIFormatError("input path changed while being opened")
    return descriptor, state


def _open_sync_regular(path: str, expected_identity: tuple[int, int]) -> int:
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    state = os.fstat(descriptor)
    current = os.lstat(path)
    if (
        not stat.S_ISREG(state.st_mode)
        or state.st_nlink != 1
        or (state.st_dev, state.st_ino) != expected_identity
        or not _same_file_state(state, current)
    ):
        os.close(descriptor)
        raise MSIFormatError("published MSI sync path identity is invalid")
    return descriptor


def _read_file(path: str) -> bytes:
    descriptor, before = _open_regular(path)
    try:
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        if not _same_file_state(before, os.fstat(descriptor)):
            raise MSIFormatError("input changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _require_zero_padding(data: bytes | bytearray, content_end: int, property_end: int, what: str) -> None:
    padding = property_end - content_end
    if padding < 0 or padding > 3 or any(data[content_end:property_end]):
        raise MSIFormatError(f"{what} has non-canonical trailing bytes")


def _require(data: bytes | bytearray, offset: int, size: int, what: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) - size:
        raise MSIFormatError(f"{what} is outside its containing structure")


def _u16(data: bytes | bytearray, offset: int, what: str) -> int:
    _require(data, offset, 2, what)
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes | bytearray, offset: int, what: str) -> int:
    _require(data, offset, 4, what)
    return struct.unpack_from("<I", data, offset)[0]


def _identity(fork_version: str, source_commit: str, source_tree: str, target: str) -> tuple[str, uuid.UUID]:
    if not FORK_VERSION_RE.fullmatch(fork_version):
        raise MSIFormatError("FORK_VERSION is not canonical")
    if not GIT_ID_RE.fullmatch(source_commit):
        raise MSIFormatError("source commit is not a canonical Git object ID")
    if not GIT_ID_RE.fullmatch(source_tree):
        raise MSIFormatError("source tree is not a canonical Git object ID")
    if target != "windows-x86_64":
        raise MSIFormatError("MSI target must be windows-x86_64")
    canonical = json.dumps(
        {
            "fork_version": fork_version,
            "source_commit": source_commit,
            "source_tree": source_tree,
            "target": target,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return canonical, uuid.uuid5(uuid.NAMESPACE_URL, "rustdesk-hardened-msi-package-code-v1\n" + canonical)


def _summary_properties(data: bytes | bytearray) -> tuple[int, dict[int, tuple[int, int]]]:
    _require(data, 0, 48, "SummaryInformation header")
    if _u16(data, 0, "property-set byte order") != 0xFFFE:
        raise MSIFormatError("SummaryInformation byte order is not little-endian")
    if _u16(data, 2, "property-set version") not in (0, 1):
        raise MSIFormatError("SummaryInformation property-set version is unsupported")
    if _u32(data, 24, "property-set section count") != 1:
        raise MSIFormatError("SummaryInformation must contain exactly one section")
    if bytes(data[28:44]) != FMTID_SUMMARY_INFORMATION:
        raise MSIFormatError("SummaryInformation FMTID is incorrect")
    section = _u32(data, 44, "SummaryInformation section offset")
    if section % 4 != 0:
        raise MSIFormatError("SummaryInformation section offset is unaligned")
    _require(data, section, 8, "SummaryInformation section")
    section_size = _u32(data, section, "SummaryInformation section size")
    if section_size < 8 or section > len(data) - section_size:
        raise MSIFormatError("SummaryInformation section size is invalid")
    section_end = section + section_size
    if any(data[section_end:]):
        raise MSIFormatError("SummaryInformation has nonzero bytes after its section")
    property_count = _u32(data, section + 4, "SummaryInformation property count")
    if property_count == 0 or property_count > 4096:
        raise MSIFormatError("SummaryInformation property count is invalid")
    table_end = section + 8 + property_count * 8
    if table_end > section_end:
        raise MSIFormatError("SummaryInformation property table is truncated")

    offsets: list[tuple[int, int]] = []
    seen: set[int] = set()
    for index in range(property_count):
        prop_id, relative = struct.unpack_from("<II", data, section + 8 + index * 8)
        if prop_id in seen:
            raise MSIFormatError(f"SummaryInformation property {prop_id} is duplicated")
        seen.add(prop_id)
        if relative % 4 != 0 or relative < table_end - section or relative >= section_size:
            raise MSIFormatError(f"SummaryInformation property {prop_id} has an invalid offset")
        offsets.append((relative, prop_id))
    offsets.sort()
    properties: dict[int, tuple[int, int]] = {}
    for index, (relative, prop_id) in enumerate(offsets):
        end_relative = offsets[index + 1][0] if index + 1 < len(offsets) else section_size
        if end_relative <= relative:
            raise MSIFormatError("SummaryInformation properties overlap")
        properties[prop_id] = (section + relative, section + end_relative)
    return section_end, properties


def _canonicalize_summary(data: bytes, package_code: uuid.UUID) -> bytes:
    mutable = bytearray(data)
    _, properties = _summary_properties(mutable)
    required = {PID_REVNUMBER, PID_CREATE_DTM, PID_LASTSAVE_DTM}
    missing = required.difference(properties)
    if missing:
        raise MSIFormatError(f"SummaryInformation lacks required properties: {sorted(missing)}")

    revision, revision_end = properties[PID_REVNUMBER]
    if _u32(mutable, revision, "PID_REVNUMBER type") != VT_LPSTR:
        raise MSIFormatError("PID_REVNUMBER is not VT_LPSTR")
    string_length = _u32(mutable, revision + 4, "PID_REVNUMBER length")
    if string_length != 39 or revision + 8 + string_length > revision_end:
        raise MSIFormatError("PID_REVNUMBER is not an exact braced GUID string")
    original = bytes(mutable[revision + 8 : revision + 8 + string_length])
    if not BRACED_GUID_RE.fullmatch(original):
        raise MSIFormatError("PID_REVNUMBER is not an exact braced GUID")
    _require_zero_padding(mutable, revision + 8 + string_length, revision_end, "PID_REVNUMBER")
    replacement = ("{%s}" % str(package_code).upper()).encode("ascii") + b"\0"
    if len(replacement) != string_length:
        raise AssertionError("canonical package code has the wrong length")
    mutable[revision + 8 : revision + 8 + string_length] = replacement

    for prop_id, name in ((PID_CREATE_DTM, "PID_CREATE_DTM"), (PID_LASTSAVE_DTM, "PID_LASTSAVE_DTM")):
        offset, end = properties[prop_id]
        if _u32(mutable, offset, f"{name} type") != VT_FILETIME or offset + 12 > end:
            raise MSIFormatError(f"{name} is not an exact VT_FILETIME")
        _require_zero_padding(mutable, offset + 12, end, name)
        struct.pack_into("<Q", mutable, offset + 4, 0)
    _validate_summary(bytes(mutable), package_code)
    return bytes(mutable)


def _validate_summary(data: bytes, package_code: uuid.UUID) -> None:
    _, properties = _summary_properties(data)
    expected = ("{%s}" % str(package_code).upper()).encode("ascii") + b"\0"
    revision, revision_end = properties.get(PID_REVNUMBER, (-1, -1))
    if revision < 0 or _u32(data, revision, "PID_REVNUMBER type") != VT_LPSTR:
        raise MSIFormatError("canonical PID_REVNUMBER is missing or mistyped")
    length = _u32(data, revision + 4, "PID_REVNUMBER length")
    if length != len(expected) or revision + 8 + length > revision_end:
        raise MSIFormatError("canonical PID_REVNUMBER length is invalid")
    if bytes(data[revision + 8 : revision + 8 + length]) != expected:
        raise MSIFormatError("canonical PID_REVNUMBER value is incorrect")
    for prop_id, name in ((PID_CREATE_DTM, "PID_CREATE_DTM"), (PID_LASTSAVE_DTM, "PID_LASTSAVE_DTM")):
        offset, end = properties.get(prop_id, (-1, -1))
        if offset < 0 or _u32(data, offset, f"{name} type") != VT_FILETIME or offset + 12 > end:
            raise MSIFormatError(f"canonical {name} is missing or mistyped")
        if struct.unpack_from("<Q", data, offset + 4)[0] != 0:
            raise MSIFormatError(f"canonical {name} is nonzero")
        _require_zero_padding(data, offset + 12, end, name)


def _cabinet_layout(
    data: bytes | bytearray,
) -> tuple[list[tuple[str, int, int, int]], list[tuple[int, int]]]:
    _require(data, 0, 36, "cabinet header")
    if bytes(data[:4]) != b"MSCF":
        raise MSIFormatError("embedded stream is not a cabinet")
    if any(data[4:8]) or any(data[12:16]) or any(data[20:24]):
        raise MSIFormatError("cabinet reserved header fields are nonzero")
    cabinet_size = _u32(data, 8, "cabinet size")
    if cabinet_size != len(data):
        raise MSIFormatError("cabinet size does not equal the embedded stream size")
    files_offset = _u32(data, 16, "cabinet file-table offset")
    if data[24] != 3 or data[25] != 1:
        raise MSIFormatError("cabinet version is not 1.3")
    folder_count = _u16(data, 26, "cabinet folder count")
    file_count = _u16(data, 28, "cabinet file count")
    flags = _u16(data, 30, "cabinet flags")
    if flags & ~0x0007:
        raise MSIFormatError("cabinet has unknown flags")
    if flags & 0x0003:
        raise MSIFormatError("embedded cabinet must not reference a previous or next cabinet")
    if folder_count != 1 or file_count == 0:
        raise MSIFormatError("embedded cabinet must contain exactly one folder and at least one file")

    cursor = 36
    folder_reserve = 0
    data_reserve = 0
    if flags & 0x0004:
        _require(data, cursor, 4, "cabinet reserve sizes")
        header_reserve = _u16(data, cursor, "cabinet header reserve size")
        folder_reserve = data[cursor + 2]
        data_reserve = data[cursor + 3]
        cursor += 4
        _require(data, cursor, header_reserve, "cabinet header reserve")
        cursor += header_reserve

    first_data = cabinet_size
    folder_entry_size = 8 + folder_reserve
    _require(data, cursor, folder_count * folder_entry_size, "cabinet folder table")
    folders = []
    for index in range(folder_count):
        folder = cursor + index * folder_entry_size
        data_offset = _u32(data, folder, "cabinet folder data offset")
        block_count = _u16(data, folder + 4, "cabinet folder data-block count")
        compression = _u16(data, folder + 6, "cabinet folder compression")
        if data_offset < cursor + folder_count * folder_entry_size or data_offset >= cabinet_size:
            raise MSIFormatError("cabinet folder data offset is invalid")
        if block_count == 0 or compression & 0x000F not in (0, 1, 2, 3):
            raise MSIFormatError("cabinet folder block count or compression type is invalid")
        first_data = min(first_data, data_offset)
        folders.append((data_offset, block_count))
    folder_table_end = cursor + folder_count * folder_entry_size
    if files_offset < folder_table_end or files_offset >= first_data:
        raise MSIFormatError("cabinet file table is outside the header/data gap")

    file_times: list[tuple[int, int]] = []
    file_ranges: list[tuple[int, int, int]] = []
    file_entries: list[tuple[str, int, int, int]] = []
    file_names: set[bytes] = set()
    previous_order: tuple[int, int, bytes] | None = None
    cursor = files_offset
    for index in range(file_count):
        _require(data, cursor, 16, f"cabinet file {index} header")
        file_size = _u32(data, cursor, f"cabinet file {index} size")
        folder_offset = _u32(data, cursor + 4, f"cabinet file {index} folder offset")
        folder_index = _u16(data, cursor + 8, f"cabinet file {index} folder")
        attributes = _u16(data, cursor + 14, f"cabinet file {index} attributes")
        if folder_index >= folder_count:
            raise MSIFormatError("cabinet file references an invalid folder")
        if attributes & ~0x0067 or attributes & 0x0080:
            raise MSIFormatError("cabinet file has unknown attributes or a non-ASCII name flag")
        name_start = cursor + 16
        name_end = bytes(data).find(b"\0", name_start, first_data)
        if name_end < 0 or name_end == name_start:
            raise MSIFormatError(f"cabinet file {index} name is missing")
        name = bytes(data[name_start:name_end])
        if (any(byte < 0x20 or byte > 0x7E for byte in name)
                or any(byte in name for byte in (ord("/"), ord("\\"), ord(":")))
                or name in (b".", b"..")):
            raise MSIFormatError(f"cabinet file {index} name is not canonical ASCII")
        folded = name.lower()
        if folded in file_names:
            raise MSIFormatError("cabinet contains duplicate or case-colliding file names")
        order = (folder_index, folder_offset, folded)
        if previous_order is not None and order <= previous_order:
            raise MSIFormatError("cabinet files are not in canonical folder/offset/name order")
        previous_order = order
        file_names.add(folded)
        file_times.append((cursor + 10, cursor + 12))
        file_ranges.append((folder_index, folder_offset, file_size))
        file_entries.append((name.decode("ascii"), file_size, folder_index, folder_offset))
        cursor = name_end + 1
    if cursor > first_data:
        raise MSIFormatError("cabinet file table overlaps compressed data")

    folder_ranges = []
    folder_uncompressed = []
    for folder_index, (data_offset, block_count) in enumerate(folders):
        block_cursor = data_offset
        uncompressed = 0
        for block_index in range(block_count):
            _require(data, block_cursor, 8 + data_reserve, f"cabinet folder {folder_index} data block {block_index}")
            compressed_size = _u16(data, block_cursor + 4, "cabinet compressed block size")
            uncompressed_size = _u16(data, block_cursor + 6, "cabinet uncompressed block size")
            if compressed_size == 0 or uncompressed_size == 0:
                raise MSIFormatError("cabinet contains an empty data block")
            block_cursor += 8 + data_reserve
            _require(data, block_cursor, compressed_size, "cabinet compressed block payload")
            block_cursor += compressed_size
            uncompressed += uncompressed_size
        folder_ranges.append((data_offset, block_cursor))
        folder_uncompressed.append(uncompressed)
    ordered_ranges = sorted(folder_ranges)
    if ordered_ranges[0][0] != first_data or ordered_ranges[-1][1] != cabinet_size:
        raise MSIFormatError("cabinet folder data does not span the compressed-data region")
    for previous, current in zip(ordered_ranges, ordered_ranges[1:]):
        if previous[1] != current[0]:
            raise MSIFormatError("cabinet folder data is overlapping or non-contiguous")
    if any(data[cursor:first_data]):
        raise MSIFormatError("cabinet has nonzero bytes between file table and compressed data")
    previous_end_by_folder: dict[int, int] = {}
    for folder_index, folder_offset, file_size in file_ranges:
        if folder_offset > folder_uncompressed[folder_index] or file_size > folder_uncompressed[folder_index] - folder_offset:
            raise MSIFormatError("cabinet file exceeds its folder's uncompressed data")
        previous_end = previous_end_by_folder.get(folder_index, 0)
        if folder_offset != previous_end:
            raise MSIFormatError("cabinet files do not span their folder contiguously")
        previous_end_by_folder[folder_index] = folder_offset + file_size
    if previous_end_by_folder.get(0) != folder_uncompressed[0]:
        raise MSIFormatError("cabinet files do not cover the full uncompressed folder")
    return file_entries, file_times


def _canonicalize_cabinet(data: bytes) -> bytes:
    mutable = bytearray(data)
    file_entries, file_times = _cabinet_layout(mutable)
    if len(file_times) != len(file_entries):
        raise AssertionError("cabinet parser did not process exactly cFiles")
    for date_offset, time_offset in file_times:
        struct.pack_into("<H", mutable, date_offset, 0x0021)
        struct.pack_into("<H", mutable, time_offset, 0)
    checked_entries, checked_times = _cabinet_layout(mutable)
    if checked_entries != file_entries or len(checked_times) != len(file_entries):
        raise MSIFormatError("canonical cabinet file count changed")
    for date_offset, time_offset in checked_times:
        if _u16(mutable, date_offset, "canonical cabinet date") != 0x0021:
            raise MSIFormatError("canonical cabinet date is incorrect")
        if _u16(mutable, time_offset, "canonical cabinet time") != 0:
            raise MSIFormatError("canonical cabinet time is incorrect")
    return bytes(mutable)


def _cabinet_stream(ole: olefile.OleFileIO) -> tuple[list[str], bytes]:
    candidates: list[tuple[list[str], bytes]] = []
    for path in ole.listdir(streams=True, storages=False):
        stream = ole.openstream(path)
        prefix = stream.read(4)
        if prefix != b"MSCF":
            continue
        data = prefix + stream.read()
        _cabinet_layout(data)
        candidates.append((path, data))
    if len(candidates) != 1:
        raise MSIFormatError(f"MSI must contain exactly one valid embedded cabinet, found {len(candidates)}")
    return candidates[0]


def _root_directory_times(path: str, zero: bool) -> tuple[int, int]:
    mode = "r+b" if zero else "rb"
    with open(path, mode) as handle:
        header = handle.read(512)
        _require(header, 0, 512, "compound-file header")
        if header[:8] != CFB_SIGNATURE:
            raise MSIFormatError("MSI is not an OLE compound file")
        if _u16(header, 28, "compound-file byte order") != 0xFFFE:
            raise MSIFormatError("compound-file byte order is invalid")
        sector_shift = _u16(header, 30, "compound-file sector shift")
        if sector_shift not in (9, 12):
            raise MSIFormatError("compound-file sector size is unsupported")
        sector_size = 1 << sector_shift
        first_directory_sector = _u32(header, 48, "first directory sector")
        if first_directory_sector >= 0xFFFFFFFA:
            raise MSIFormatError("compound file has no concrete first directory sector")
        root_offset = (first_directory_sector + 1) * sector_size
        handle.seek(0, os.SEEK_END)
        file_size = handle.tell()
        if root_offset > file_size - 128:
            raise MSIFormatError("root directory entry is outside the compound file")
        handle.seek(root_offset)
        root = bytearray(handle.read(128))
        _require(root, 0, 128, "root directory entry")
        if root[66] != 5:
            raise MSIFormatError("directory entry zero is not the OLE root storage")
        create_time = struct.unpack_from("<Q", root, 100)[0]
        modify_time = struct.unpack_from("<Q", root, 108)[0]
        if zero:
            struct.pack_into("<Q", root, 100, 0)
            struct.pack_into("<Q", root, 108, 0)
            handle.seek(root_offset)
            handle.write(root)
            handle.flush()
            os.fsync(handle.fileno())
        return create_time, modify_time


def _canonicalize_in_place(path: str, package_code: uuid.UUID) -> None:
    ole = olefile.OleFileIO(path, write_mode=True)
    try:
        if not ole.exists(SUMINFO):
            raise MSIFormatError("MSI lacks the SummaryInformation stream")
        summary = ole.openstream(SUMINFO).read()
        canonical_summary = _canonicalize_summary(summary, package_code)
        cabinet_path, cabinet = _cabinet_stream(ole)
        canonical_cabinet = _canonicalize_cabinet(cabinet)
        ole.write_stream(SUMINFO, canonical_summary)
        ole.write_stream(cabinet_path, canonical_cabinet)
    finally:
        ole.close()
    _root_directory_times(path, zero=True)


def _verify_file(path: str, package_code: uuid.UUID) -> dict[str, object]:
    ole = olefile.OleFileIO(path, write_mode=False)
    try:
        if not ole.exists(SUMINFO):
            raise MSIFormatError("canonical MSI lacks SummaryInformation")
        summary = ole.openstream(SUMINFO).read()
        _validate_summary(summary, package_code)
        _, cabinet = _cabinet_stream(ole)
        if _canonicalize_cabinet(cabinet) != cabinet:
            raise MSIFormatError("canonical cabinet still contains variable file times")
        entries, _ = _cabinet_layout(cabinet)
    finally:
        ole.close()
    create_time, modify_time = _root_directory_times(path, zero=False)
    if create_time != 0 or modify_time != 0:
        raise MSIFormatError("canonical OLE root timestamps are nonzero")
    return {
        "cabinet_sha256": hashlib.sha256(cabinet).hexdigest(),
        "cabinet_size": len(cabinet),
        "files": [
            {
                "folder": folder,
                "id": name,
                "offset": offset,
                "sequence": index,
                "size": size,
            }
            for index, (name, size, folder, offset) in enumerate(entries, 1)
        ],
        "format": "rustdesk-msi-cabinet-contract-v1",
    }


def canonicalize(
    path: str,
    output: str,
    contract_output: str,
    fork_version: str,
    source_commit: str,
    source_tree: str,
    target: str,
) -> uuid.UUID:
    _, package_code = _identity(fork_version, source_commit, source_tree, target)
    path = os.path.abspath(path)
    output = os.path.abspath(output)
    contract_output = os.path.abspath(contract_output)
    if len({os.path.normcase(path), os.path.normcase(output), os.path.normcase(contract_output)}) != 3:
        raise MSIFormatError("input, canonical output, and contract output must be distinct")
    if os.path.lexists(output) or os.path.lexists(contract_output):
        raise MSIFormatError("canonical MSI output or contract path already exists")
    _require_real_directory_path(os.path.dirname(path))
    source_descriptor, source_state = _open_regular(path)
    source_mode = source_state.st_mode & 0o777
    directory = os.path.dirname(output)
    contract_directory = os.path.dirname(contract_output)
    for parent in (directory, contract_directory):
        _require_real_directory_path(parent)
    descriptor, temporary = tempfile.mkstemp(prefix=".canonicalize-msi.", dir=directory)
    contract_descriptor = -1
    contract_temporary = ""
    output_published = False
    contract_published = False
    output_identity: tuple[int, int] | None = None
    contract_identity: tuple[int, int] | None = None
    try:
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if not _same_file_state(source_state, os.fstat(source_descriptor)):
            raise MSIFormatError("input changed while being copied")
        os.close(source_descriptor)
        source_descriptor = -1
        _canonicalize_in_place(temporary, package_code)
        contract = _verify_file(temporary, package_code)
        first = _read_file(temporary)
        _canonicalize_in_place(temporary, package_code)
        if _verify_file(temporary, package_code) != contract:
            raise MSIFormatError("canonical MSI contract changed on the idempotence pass")
        if _read_file(temporary) != first:
            raise MSIFormatError("canonicalization is not byte-for-byte idempotent")
        if not _same_file_state(source_state, os.lstat(path)):
            raise MSIFormatError("input path changed before canonical output publication")

        contract_bytes = (
            json.dumps(contract, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
        ).encode("ascii")
        contract_descriptor, contract_temporary = tempfile.mkstemp(
            prefix=".canonicalize-msi-contract.", dir=contract_directory
        )
        view = memoryview(contract_bytes)
        while view:
            written = os.write(contract_descriptor, view)
            if written <= 0:
                raise OSError("short write while creating MSI cabinet contract")
            view = view[written:]
        os.fsync(contract_descriptor)
        os.close(contract_descriptor)
        contract_descriptor = -1
        os.link(temporary, output, follow_symlinks=False)
        output_published = True
        output_state = os.lstat(output)
        output_identity = (output_state.st_dev, output_state.st_ino)
        os.link(contract_temporary, contract_output, follow_symlinks=False)
        contract_published = True
        contract_state = os.lstat(contract_output)
        contract_identity = (contract_state.st_dev, contract_state.st_ino)
        os.unlink(temporary)
        temporary = ""
        os.unlink(contract_temporary)
        contract_temporary = ""
        if _verify_file(output, package_code) != contract:
            raise MSIFormatError("published canonical MSI does not match its cabinet contract")
        if _read_file(contract_output) != contract_bytes:
            raise MSIFormatError("published MSI cabinet contract bytes are incorrect")
        if os.name != "nt":
            for sync_directory in {directory, contract_directory}:
                directory_fd = os.open(sync_directory, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        output_sync = -1
        contract_sync = -1
        try:
            output_sync = _open_sync_regular(output, output_identity)
            contract_sync = _open_sync_regular(contract_output, contract_identity)
            os.chmod(output, source_mode)
            os.chmod(contract_output, 0o400)
            os.fsync(output_sync)
            os.fsync(contract_sync)
        finally:
            if output_sync >= 0:
                os.close(output_sync)
            if contract_sync >= 0:
                os.close(contract_sync)
    except BaseException as original:
        cleanup_errors = []
        if contract_published and contract_identity is not None:
            try:
                state = os.lstat(contract_output)
                if (state.st_dev, state.st_ino) == contract_identity:
                    _make_deletable(contract_output)
                    os.unlink(contract_output)
            except FileNotFoundError:
                pass
            except OSError as error:
                cleanup_errors.append(f"contract output cleanup failed: {error}")
        if output_published and output_identity is not None:
            try:
                state = os.lstat(output)
                if (state.st_dev, state.st_ino) == output_identity:
                    _make_deletable(output)
                    os.unlink(output)
            except FileNotFoundError:
                pass
            except OSError as error:
                cleanup_errors.append(f"MSI output cleanup failed: {error}")
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as error:
                cleanup_errors.append(f"MSI temporary descriptor cleanup failed: {error}")
        if contract_descriptor >= 0:
            try:
                os.close(contract_descriptor)
            except OSError as error:
                cleanup_errors.append(f"contract temporary descriptor cleanup failed: {error}")
        for temporary_path in (temporary, contract_temporary):
            if not temporary_path:
                continue
            try:
                _make_deletable(temporary_path)
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
            except OSError as error:
                cleanup_errors.append(f"temporary cleanup failed for {temporary_path}: {error}")
        if cleanup_errors and hasattr(original, "add_note"):
            original.add_note("; ".join(cleanup_errors))
        raise
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)
    print(f"canonicalize-msi: {output}: package-code={{{str(package_code).upper()}}}")
    return package_code


def _synthetic_summary() -> bytes:
    values = {
        2: struct.pack("<II", VT_LPSTR, 5) + b"Test\0" + b"\0" * 3,
        PID_REVNUMBER: struct.pack("<II", VT_LPSTR, 39) + b"{11111111-2222-3333-4444-555555555555}\0" + b"\0",
        PID_CREATE_DTM: struct.pack("<IQ", VT_FILETIME, 0x1111222233334444),
        PID_LASTSAVE_DTM: struct.pack("<IQ", VT_FILETIME, 0xAAAABBBBCCCCDDDD),
    }
    property_count = len(values)
    table_size = 8 + property_count * 8
    section = bytearray(b"\0" * table_size)
    cursor = table_size
    entries: list[tuple[int, int]] = []
    for prop_id in sorted(values):
        cursor = (cursor + 3) & ~3
        if len(section) < cursor:
            section.extend(b"\0" * (cursor - len(section)))
        entries.append((prop_id, cursor))
        section.extend(values[prop_id])
        cursor += len(values[prop_id])
    section.extend(b"\0" * (((len(section) + 3) & ~3) - len(section)))
    struct.pack_into("<II", section, 0, len(section), property_count)
    for index, entry in enumerate(entries):
        struct.pack_into("<II", section, 8 + index * 8, *entry)
    header = bytearray(b"\0" * 48)
    struct.pack_into("<HHI", header, 0, 0xFFFE, 0, 0)
    struct.pack_into("<I", header, 24, 1)
    header[28:44] = FMTID_SUMMARY_INFORMATION
    struct.pack_into("<I", header, 44, 48)
    return bytes(header + section)


def _synthetic_cabinet() -> bytes:
    file_names = [b"rustdesk.exe", b"rustdesk.msi"]
    files = bytearray()
    for index, name in enumerate(file_names):
        files.extend(struct.pack("<IIHHHH", 10 + index, index * 10, 0, 0x5A21, 0x7BDE, 0x20))
        files.extend(name + b"\0")
    files_offset = 44
    data_offset = files_offset + len(files)
    payload = b"CAB-DATA"
    cfdata = struct.pack("<IHH", 0, len(payload), 21) + payload
    cabinet_size = data_offset + len(cfdata)
    header = bytearray(b"\0" * 36)
    header[:4] = b"MSCF"
    struct.pack_into("<I", header, 8, cabinet_size)
    struct.pack_into("<I", header, 16, files_offset)
    header[24:26] = bytes((3, 1))
    struct.pack_into("<HHHHH", header, 26, 1, len(file_names), 0, 7, 0)
    folder = struct.pack("<IHH", data_offset, 1, 0)
    return bytes(header + folder + files + cfdata)


def _synthetic_cfb_root() -> bytearray:
    data = bytearray(1024)
    data[:8] = CFB_SIGNATURE
    struct.pack_into("<H", data, 28, 0xFFFE)
    struct.pack_into("<H", data, 30, 9)
    struct.pack_into("<I", data, 48, 0)
    data[512 + 66] = 5
    struct.pack_into("<Q", data, 512 + 100, 1)
    struct.pack_into("<Q", data, 512 + 108, 2)
    return data


def self_test() -> None:
    _, code = _identity(
        "1.4.7-hardened.6",
        "1" * 40,
        "2" * 40,
        "windows-x86_64",
    )
    other = _identity("1.4.7-hardened.7", "1" * 40, "2" * 40, "windows-x86_64")[1]
    assert code != other
    assert code != _identity("1.4.7-hardened.6", "3" * 40, "2" * 40, "windows-x86_64")[1]
    assert code != _identity("1.4.7-hardened.6", "1" * 40, "4" * 40, "windows-x86_64")[1]

    summary = _synthetic_summary()
    canonical_summary = _canonicalize_summary(summary, code)
    _validate_summary(canonical_summary, code)
    assert _canonicalize_summary(canonical_summary, code) == canonical_summary
    for mutation in ("missing", "duplicate", "wrong-type", "revision-padding"):
        broken = bytearray(summary)
        if mutation == "missing":
            struct.pack_into("<I", broken, 48 + 4, 3)
        elif mutation == "duplicate":
            struct.pack_into("<I", broken, 48 + 8 + 8, 2)
        elif mutation == "wrong-type":
            _, props = _summary_properties(broken)
            struct.pack_into("<I", broken, props[PID_CREATE_DTM][0], VT_LPSTR)
        else:
            _, props = _summary_properties(broken)
            broken[props[PID_REVNUMBER][1] - 1] = 1
        try:
            _canonicalize_summary(bytes(broken), code)
        except MSIFormatError:
            pass
        else:
            raise AssertionError(f"malformed SummaryInformation accepted: {mutation}")

    cabinet = _synthetic_cabinet()
    canonical_cabinet = _canonicalize_cabinet(cabinet)
    _, times = _cabinet_layout(canonical_cabinet)
    assert len(times) == 2
    assert all(_u16(canonical_cabinet, date, "date") == 0x21 for date, _ in times)
    assert all(_u16(canonical_cabinet, time, "time") == 0 for _, time in times)
    assert _canonicalize_cabinet(canonical_cabinet) == canonical_cabinet
    for mutation in (
        "count",
        "size",
        "name",
        "blocks",
        "file-range",
        "duplicate-name",
        "cabinet-chain",
        "file-order",
        "file-overlap",
    ):
        broken = bytearray(cabinet)
        if mutation == "count":
            struct.pack_into("<H", broken, 28, 3)
        elif mutation == "size":
            struct.pack_into("<I", broken, 8, len(broken) - 1)
        elif mutation == "name":
            broken[44 + 16 : broken.find(b"\0", 44 + 16)] = b"X" * (broken.find(b"\0", 44 + 16) - (44 + 16))
            broken[broken.find(b"\0", 44 + 16)] = 0x58
        elif mutation == "blocks":
            struct.pack_into("<H", broken, 36 + 4, 2)
        elif mutation == "file-range":
            struct.pack_into("<I", broken, 44, 22)
        elif mutation == "duplicate-name":
            first_name_start = 44 + 16
            first_name_end = broken.find(b"\0", first_name_start)
            second_header = first_name_end + 1
            second_name_start = second_header + 16
            second_name_end = broken.find(b"\0", second_name_start)
            broken[second_name_start:second_name_end] = broken[first_name_start:first_name_end]
        elif mutation == "cabinet-chain":
            struct.pack_into("<H", broken, 30, 1)
        else:
            first_name_end = broken.find(b"\0", 44 + 16)
            second_header = first_name_end + 1
            if mutation == "file-order":
                struct.pack_into("<I", broken, 44 + 4, 10)
                struct.pack_into("<I", broken, second_header + 4, 0)
            else:
                struct.pack_into("<I", broken, second_header + 4, 5)
        try:
            _canonicalize_cabinet(bytes(broken))
        except MSIFormatError:
            pass
        else:
            raise AssertionError(f"malformed cabinet accepted: {mutation}")

    with tempfile.TemporaryDirectory(prefix="canonicalize-msi-test-") as directory:
        path = os.path.join(directory, "root.cfb")
        with open(path, "wb") as handle:
            handle.write(_synthetic_cfb_root())
        assert _root_directory_times(path, zero=True) == (1, 2)
        assert _root_directory_times(path, zero=False) == (0, 0)
        alias = os.path.join(directory, "alias.cfb")
        os.link(path, alias)
        try:
            _open_regular(path)
        except MSIFormatError:
            pass
        else:
            raise AssertionError("hardlinked MSI input was accepted")
        os.unlink(alias)
        os.symlink(path, alias)
        try:
            _open_regular(alias)
        except (OSError, MSIFormatError):
            pass
        else:
            raise AssertionError("symlink MSI input was accepted")
    print("canonicalize-msi self-test: ok")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("msi", nargs="?")
    parser.add_argument("--output")
    parser.add_argument("--contract-out")
    parser.add_argument("--fork-version")
    parser.add_argument("--source-commit")
    parser.add_argument("--source-tree")
    parser.add_argument("--target")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        if any(
            (
                args.msi,
                args.output,
                args.contract_out,
                args.fork_version,
                args.source_commit,
                args.source_tree,
                args.target,
            )
        ):
            parser.error("--self-test does not accept build arguments")
        return args
    if not all(
        (
            args.msi,
            args.output,
            args.contract_out,
            args.fork_version,
            args.source_commit,
            args.source_tree,
            args.target,
        )
    ):
        parser.error("MSI input, absent outputs, and all identity options are required")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        self_test()
    else:
        canonicalize(
            args.msi,
            args.output,
            args.contract_out,
            args.fork_version,
            args.source_commit,
            args.source_tree,
            args.target,
        )
    return 0


if __name__ == "__main__":
    try:
        exit_code = main(sys.argv[1:])
    except (MSIFormatError, OSError) as exc:
        print(f"canonicalize-msi: fatal: {exc}", file=sys.stderr)
        raise SystemExit(1)
    raise SystemExit(exit_code)
