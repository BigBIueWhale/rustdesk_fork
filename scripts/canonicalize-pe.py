#!/usr/bin/env python3
"""Canonicalize bounded, reproducibility-only PE metadata."""

from __future__ import annotations

import os
import stat
import struct
import sys
import tempfile


IMAGE_DEBUG_TYPE_REPRO = 16


class PEFormatError(ValueError):
    pass


STABLE_FIELDS = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")


def _same_file_state(left: os.stat_result, right: os.stat_result) -> bool:
    return all(getattr(left, field) == getattr(right, field) for field in STABLE_FIELDS)


def _read_regular_file(path: str) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise PEFormatError("input must be one non-hardlinked regular file")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if not _same_file_state(before, after):
            raise PEFormatError("input changed while being read")
    finally:
        os.close(descriptor)
    current = os.lstat(path)
    if not _same_file_state(after, current):
        raise PEFormatError("input path changed while being read")
    return b"".join(chunks), after


def _require(data: bytes | bytearray, offset: int, size: int, what: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) - size:
        raise PEFormatError(f"{what} is outside the file")


def _u16(data: bytes | bytearray, offset: int, what: str = "u16") -> int:
    _require(data, offset, 2, what)
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes | bytearray, offset: int, what: str = "u32") -> int:
    _require(data, offset, 4, what)
    return struct.unpack_from("<I", data, offset)[0]


ByteRange = tuple[int, int, str]


def _overlaps(left: ByteRange, right: ByteRange) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def _validate_disjoint(ranges: list[ByteRange], what: str) -> None:
    ordered = sorted(ranges)
    for left, right in zip(ordered, ordered[1:]):
        if _overlaps(left, right):
            raise PEFormatError(f"{what} overlap: {left[2]} and {right[2]}")


def _prove_only_authorized_changes(source: bytes, result: bytes, authorized: list[ByteRange]) -> None:
    if len(result) != len(source):
        raise PEFormatError("canonicalization changed the PE file length")
    _validate_disjoint(authorized, "authorized mutation ranges")
    cursor = 0
    for start, end, description in sorted(authorized):
        _require(source, start, end - start, description)
        if source[cursor:start] != result[cursor:start]:
            raise PEFormatError("canonicalization changed bytes outside authorized ranges")
        if any(result[start:end]):
            raise PEFormatError(f"canonicalization did not clear {description}")
        cursor = end
    if source[cursor:] != result[cursor:]:
        raise PEFormatError("canonicalization changed bytes outside authorized ranges")


class PEImage:
    def __init__(self, data: bytes | bytearray):
        self.data = bytearray(data)
        _require(self.data, 0, 0x40, "DOS header")
        if self.data[:2] != b"MZ":
            raise PEFormatError("missing DOS MZ signature")
        self.pe = _u32(self.data, 0x3C, "e_lfanew")
        _require(self.data, self.pe, 24, "PE header")
        if self.data[self.pe : self.pe + 4] != b"PE\0\0":
            raise PEFormatError("missing PE signature")

        self.section_count = _u16(self.data, self.pe + 6, "NumberOfSections")
        if self.section_count == 0 or self.section_count > 96:
            raise PEFormatError("invalid NumberOfSections")
        self.optional_size = _u16(self.data, self.pe + 20, "SizeOfOptionalHeader")
        self.optional = self.pe + 24
        _require(self.data, self.optional, self.optional_size, "optional header")
        self.magic = _u16(self.data, self.optional, "optional-header magic")
        if self.magic == 0x20B:
            minimum_optional = 112
            self.directory_base = self.optional + 112
            count_offset = self.optional + 108
        elif self.magic == 0x10B:
            minimum_optional = 96
            self.directory_base = self.optional + 96
            count_offset = self.optional + 92
        else:
            raise PEFormatError(f"unsupported optional-header magic {self.magic:#x}")
        if self.optional_size < minimum_optional:
            raise PEFormatError("optional header is too short")
        self.directory_count = _u32(self.data, count_offset, "NumberOfRvaAndSizes")
        available_directories = (self.optional + self.optional_size - self.directory_base) // 8
        if self.directory_count > available_directories:
            raise PEFormatError("data-directory count exceeds optional header")

        self.section_table = self.optional + self.optional_size
        _require(self.data, self.section_table, self.section_count * 40, "section table")
        self.sections: list[tuple[int, int, int, int]] = []
        for index in range(self.section_count):
            entry = self.section_table + index * 40
            virtual_size = _u32(self.data, entry + 8, "section VirtualSize")
            virtual_address = _u32(self.data, entry + 12, "section VirtualAddress")
            raw_size = _u32(self.data, entry + 16, "section SizeOfRawData")
            raw_offset = _u32(self.data, entry + 20, "section PointerToRawData")
            if raw_size:
                _require(self.data, raw_offset, raw_size, "section raw data")
            self.sections.append((virtual_address, virtual_size, raw_offset, raw_size))

    def data_directory(self, index: int) -> tuple[int, int]:
        if index >= self.directory_count:
            return 0, 0
        entry = self.directory_base + index * 8
        return (
            _u32(self.data, entry, "data-directory RVA"),
            _u32(self.data, entry + 4, "data-directory size"),
        )

    def rva_mapping(self, rva: int, size: int, what: str) -> tuple[int, int]:
        if rva == 0 or size <= 0:
            raise PEFormatError(f"{what} has an empty RVA range")
        matches: list[tuple[int, int]] = []
        for index, (virtual_address, virtual_size, raw_offset, raw_size) in enumerate(self.sections):
            span = max(virtual_size, raw_size)
            if rva < virtual_address or rva - virtual_address > span:
                continue
            delta = rva - virtual_address
            if delta > raw_size or size > raw_size - delta:
                continue
            offset = raw_offset + delta
            _require(self.data, offset, size, what)
            matches.append((offset, index))
        if len(matches) != 1:
            raise PEFormatError(f"{what} does not map to exactly one section")
        return matches[0]

    def rva_to_offset(self, rva: int, size: int, what: str) -> int:
        return self.rva_mapping(rva, size, what)[0]

    def raw_mapping(self, offset: int, size: int, what: str) -> tuple[int, int]:
        if offset == 0 or size <= 0:
            raise PEFormatError(f"{what} has an empty raw-data range")
        _require(self.data, offset, size, what)
        matches: list[tuple[int, int]] = []
        for index, (virtual_address, _, raw_offset, raw_size) in enumerate(self.sections):
            if offset < raw_offset:
                continue
            delta = offset - raw_offset
            if delta > raw_size or size > raw_size - delta:
                continue
            matches.append((virtual_address + delta, index))
        if len(matches) != 1:
            raise PEFormatError(f"{what} does not map to exactly one section")
        return matches[0]

    def debug_plan(
        self, pe_fields: list[ByteRange], pe_structures: list[ByteRange]
    ) -> tuple[int, int, list[ByteRange]]:
        debug_rva, debug_size = self.data_directory(6)
        if debug_rva == 0 and debug_size == 0:
            return 0, 0, []
        if debug_rva == 0 or debug_size == 0 or debug_size % 28 != 0:
            raise PEFormatError("debug directory is incomplete or misaligned")
        directory = self.rva_to_offset(debug_rva, debug_size, "debug directory")
        directory_range = (directory, directory + debug_size, "debug directory")
        for structure in pe_structures:
            if _overlaps(directory_range, structure):
                raise PEFormatError(f"debug directory overlaps {structure[2]}")

        entries = debug_size // 28
        timestamps: list[ByteRange] = []
        payloads: list[tuple[ByteRange, int, int]] = []
        for index in range(entries):
            entry = directory + index * 28
            timestamps.append((entry + 4, entry + 8, f"debug entry {index} timestamp"))
            debug_type = _u32(self.data, entry + 12, "debug type")
            data_size = _u32(self.data, entry + 16, "debug data size")
            data_rva = _u32(self.data, entry + 20, "debug data RVA")
            data_offset = _u32(self.data, entry + 24, "debug raw-data pointer")
            if data_size == 0:
                if data_rva != 0 or data_offset != 0:
                    raise PEFormatError(f"debug entry {index} has an inconsistent empty payload")
                if debug_type == IMAGE_DEBUG_TYPE_REPRO:
                    raise PEFormatError("IMAGE_DEBUG_TYPE_REPRO has no payload")
                continue
            if data_rva == 0 or data_offset == 0:
                raise PEFormatError(f"debug entry {index} has a nonempty payload without both mappings")
            mapped_offset, rva_section = self.rva_mapping(data_rva, data_size, f"debug entry {index} data RVA")
            mapped_rva, raw_section = self.raw_mapping(
                data_offset, data_size, f"debug entry {index} raw-data pointer"
            )
            if mapped_offset != data_offset or mapped_rva != data_rva or rva_section != raw_section:
                raise PEFormatError(f"debug entry {index} RVA and raw-data pointer disagree")
            payloads.append(
                ((data_offset, data_offset + data_size, f"debug entry {index} payload"), debug_type, index)
            )

        payload_ranges = [payload for payload, _, _ in payloads]
        _validate_disjoint(payload_ranges, "debug payload ranges")
        mutable_fields = pe_fields + timestamps
        for payload, _, _ in payloads:
            if _overlaps(payload, directory_range):
                raise PEFormatError(f"{payload[2]} overlaps the debug directory")
            for field in mutable_fields:
                if _overlaps(payload, field):
                    raise PEFormatError(f"{payload[2]} overlaps {field[2]}")
            for structure in pe_structures:
                if _overlaps(payload, structure):
                    raise PEFormatError(f"{payload[2]} overlaps {structure[2]}")

        repro_ranges = [
            (payload[0], payload[1], f"debug entry {index} REPRO payload")
            for payload, debug_type, index in payloads
            if debug_type == IMAGE_DEBUG_TYPE_REPRO
        ]
        return entries, len(repro_ranges), timestamps + repro_ranges


def canonicalize_bytes(source: bytes) -> tuple[bytes, tuple[int, int]]:
    image = PEImage(source)
    pe_fields = [
        (image.pe + 8, image.pe + 12, "COFF timestamp"),
        (image.optional + 64, image.optional + 68, "optional-header checksum"),
    ]
    pe_structures = [
        (0, 0x40, "DOS header"),
        (image.pe, image.pe + 24, "PE signature and COFF header"),
        (image.optional, image.optional + image.optional_size, "optional header"),
        (
            image.section_table,
            image.section_table + image.section_count * 40,
            "section table",
        ),
    ]
    debug_entries, repro_entries, debug_ranges = image.debug_plan(pe_fields, pe_structures)
    authorized = pe_fields + debug_ranges
    _validate_disjoint(authorized, "authorized mutation ranges")
    for start, end, _ in authorized:
        image.data[start:end] = b"\0" * (end - start)
    result = bytes(image.data)
    _prove_only_authorized_changes(source, result, authorized)
    return result, (debug_entries, repro_entries)


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _require_real_directory_path(path: str) -> None:
    absolute = os.path.abspath(path)
    drive, tail = os.path.splitdrive(absolute)
    current = drive + os.sep if drive else os.sep
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    for component in (part for part in tail.split(os.sep) if part):
        current = os.path.join(current, component)
        metadata = os.lstat(current)
        if not stat.S_ISDIR(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & reparse:
            raise PEFormatError("output path traverses a non-directory or reparse point")


def _make_deletable(path: str) -> None:
    if os.name == "nt":
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)


def _read_descriptor(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _publish_absent(output_path: str, content: bytes, mode: int) -> None:
    output_path = os.path.abspath(output_path)
    directory = os.path.dirname(output_path)
    _require_real_directory_path(directory)
    parent_before = os.lstat(directory)
    if os.path.lexists(output_path):
        raise PEFormatError("output path must not exist")

    descriptor, temporary = tempfile.mkstemp(prefix=".canonicalize-pe.", dir=directory)
    temporary_identity = os.fstat(descriptor)
    output_published = False
    output_identity: tuple[int, int] | None = None
    try:
        with os.fdopen(descriptor, "w+b", closefd=False) as handle:
            handle.write(content)
            handle.flush()
        os.fsync(descriptor)
        temporary_state = os.fstat(descriptor)
        if not _same_file_identity(temporary_state, os.lstat(temporary)):
            raise PEFormatError("canonical PE temporary path changed before publication")
        if not _same_file_identity(parent_before, os.lstat(directory)):
            raise PEFormatError("output parent changed before publication")
        try:
            os.link(temporary, output_path, follow_symlinks=False)
        except FileExistsError as exc:
            raise PEFormatError("output path appeared before publication") from exc
        output_published = True
        linked_state = os.lstat(output_path)
        output_identity = (linked_state.st_dev, linked_state.st_ino)
        if not _same_file_identity(temporary_state, linked_state):
            raise PEFormatError("published PE does not identify the prepared file")
        if not _same_file_identity(temporary_state, os.lstat(temporary)):
            raise PEFormatError("canonical PE temporary path changed during publication")
        os.unlink(temporary)
        temporary = ""

        final_state = os.lstat(output_path)
        descriptor_state = os.fstat(descriptor)
        if not _same_file_identity(final_state, descriptor_state) or final_state.st_nlink != 1:
            raise PEFormatError("published PE identity postcondition failed")
        if _read_descriptor(descriptor) != content:
            raise PEFormatError("published PE content postcondition failed")
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, mode)
        else:
            os.chmod(output_path, mode)
        os.fsync(descriptor)
        if not _same_file_identity(parent_before, os.lstat(directory)):
            raise PEFormatError("output parent changed during publication")
        if os.name != "nt":
            directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        os.close(descriptor)
        descriptor = -1
    except BaseException as original:
        cleanup_errors = []
        if output_published and output_identity is not None:
            try:
                current = os.lstat(output_path)
                if (current.st_dev, current.st_ino) == output_identity:
                    _make_deletable(output_path)
                    os.unlink(output_path)
            except FileNotFoundError:
                pass
            except OSError as error:
                cleanup_errors.append(f"PE output cleanup failed: {error}")
        if temporary:
            try:
                current = os.lstat(temporary)
            except FileNotFoundError:
                pass
            else:
                if _same_file_identity(temporary_identity, current):
                    try:
                        _make_deletable(temporary)
                        os.unlink(temporary)
                    except OSError as error:
                        cleanup_errors.append(f"PE temporary cleanup failed: {error}")
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError as error:
                cleanup_errors.append(f"PE descriptor cleanup failed: {error}")
        if cleanup_errors and hasattr(original, "add_note"):
            original.add_note("; ".join(cleanup_errors))
        raise


def canonicalize(input_path: str, output_path: str) -> None:
    if os.path.abspath(input_path) == os.path.abspath(output_path):
        raise PEFormatError("in-place canonicalization is not supported")
    _require_real_directory_path(os.path.dirname(os.path.abspath(input_path)))
    source, source_state = _read_regular_file(input_path)
    canonical, counts = canonicalize_bytes(source)
    second, _ = canonicalize_bytes(canonical)
    if second != canonical:
        raise PEFormatError("canonicalization is not idempotent")
    if not _same_file_state(source_state, os.lstat(input_path)):
        raise PEFormatError("input path changed before output publication")
    _publish_absent(output_path, canonical, source_state.st_mode & 0o777)
    debug_entries, repro_entries = counts
    print(f"canonicalize-pe: {output_path}: debug={debug_entries}, repro={repro_entries}")


def _synthetic_pe() -> tuple[bytes, int, int]:
    data = bytearray(0x600)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    pe = 0x80
    data[pe : pe + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, pe + 4, 0x8664, 2, 0xAABBCCDD, 0, 0, 240, 0x22)
    optional = pe + 24
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 64, 0x11223344)
    struct.pack_into("<I", data, optional + 108, 16)
    directory = optional + 112
    struct.pack_into("<II", data, directory + 6 * 8, 0x1000, 56)
    sections = optional + 240
    data[sections : sections + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", data, sections + 8, 0x200, 0x1000, 0x200, 0x400)
    data[sections + 40 : sections + 48] = b".header\0"
    struct.pack_into("<IIII", data, sections + 48, 0x100, 0x3000, 0x100, 0x80)

    repro_offset = 0x480
    codeview_offset = 0x490
    struct.pack_into("<IIHHIIII", data, 0x400, 0, 0x12345678, 0, 0, IMAGE_DEBUG_TYPE_REPRO, 8, 0x1080, repro_offset)
    struct.pack_into("<IIHHIIII", data, 0x41C, 0, 0x87654321, 0, 0, 2, 8, 0x1090, codeview_offset)
    data[repro_offset : repro_offset + 8] = b"REPRO123"
    data[codeview_offset : codeview_offset + 8] = b"CODEVIEW"
    return bytes(data), repro_offset, codeview_offset


def _set_debug_payload(
    data: bytearray, index: int, debug_type: int, size: int, rva: int, offset: int
) -> None:
    struct.pack_into("<IIII", data, 0x400 + index * 28 + 12, debug_type, size, rva, offset)


def _must_reject(source: bytes | bytearray, description: str, expected: str) -> None:
    try:
        canonicalize_bytes(bytes(source))
    except PEFormatError as exc:
        if expected not in str(exc):
            raise AssertionError(f"{description} failed for the wrong reason: {exc}") from exc
        return
    raise AssertionError(f"{description} was accepted")


def self_test() -> None:
    source, repro_offset, codeview_offset = _synthetic_pe()
    canonical, counts = canonicalize_bytes(source)
    assert counts == (2, 1), counts
    assert canonical[repro_offset : repro_offset + 8] == b"\0" * 8
    assert canonical[codeview_offset : codeview_offset + 8] == b"CODEVIEW"
    assert _u32(canonical, 0x88) == 0
    assert _u32(canonical, 0x80 + 24 + 64) == 0
    assert _u32(canonical, 0x400 + 4) == 0
    assert _u32(canonical, 0x41C + 4) == 0
    assert canonical[0x400 : 0x404] == source[0x400 : 0x404]
    assert canonical[0x408 : 0x41C] == source[0x408 : 0x41C]
    assert canonical[0x41C : 0x420] == source[0x41C : 0x420]
    assert canonical[0x424 : 0x438] == source[0x424 : 0x438]
    assert canonicalize_bytes(canonical)[0] == canonical
    unauthorized = bytearray(canonical)
    unauthorized[0x500] = 1
    try:
        _prove_only_authorized_changes(
            source,
            bytes(unauthorized),
            [
                (0x88, 0x8C, "COFF timestamp"),
                (0x80 + 24 + 64, 0x80 + 24 + 68, "optional-header checksum"),
                (0x404, 0x408, "debug entry 0 timestamp"),
                (0x420, 0x424, "debug entry 1 timestamp"),
                (repro_offset, repro_offset + 8, "debug entry 0 REPRO payload"),
            ],
        )
    except PEFormatError as exc:
        assert "outside authorized ranges" in str(exc), exc
    else:
        raise AssertionError("mutation outside the authorization union was accepted")

    malformed = bytearray(source)
    optional = 0x80 + 24
    struct.pack_into("<I", malformed, optional + 112 + 6 * 8 + 4, 55)
    _must_reject(malformed, "misaligned debug directory", "incomplete or misaligned")

    exact_alias = bytearray(source)
    _set_debug_payload(exact_alias, 0, IMAGE_DEBUG_TYPE_REPRO, 8, 0x1090, codeview_offset)
    _must_reject(exact_alias, "exact REPRO/CodeView payload alias", "debug payload ranges overlap")

    repro_overlaps_codeview = bytearray(source)
    _set_debug_payload(repro_overlaps_codeview, 0, IMAGE_DEBUG_TYPE_REPRO, 8, 0x108C, 0x48C)
    _must_reject(
        repro_overlaps_codeview,
        "REPRO payload overlapping the start of CodeView",
        "debug payload ranges overlap",
    )

    codeview_overlaps_repro = bytearray(source)
    _set_debug_payload(codeview_overlaps_repro, 1, 2, 8, 0x1084, 0x484)
    _must_reject(
        codeview_overlaps_repro,
        "CodeView payload overlapping the end of REPRO",
        "debug payload ranges overlap",
    )

    directory_overlap = bytearray(source)
    _set_debug_payload(directory_overlap, 0, IMAGE_DEBUG_TYPE_REPRO, 4, 0x1020, 0x420)
    _must_reject(
        directory_overlap,
        "REPRO payload overlapping a debug-directory entry",
        "overlaps the debug directory",
    )

    checksum_overlap = bytearray(source)
    _set_debug_payload(checksum_overlap, 0, IMAGE_DEBUG_TYPE_REPRO, 4, 0x3058, optional + 64)
    _must_reject(
        checksum_overlap,
        "REPRO payload overlapping the optional-header checksum",
        "overlaps optional-header checksum",
    )

    coff_overlap = bytearray(source)
    _set_debug_payload(coff_overlap, 0, IMAGE_DEBUG_TYPE_REPRO, 4, 0x3008, 0x88)
    _must_reject(coff_overlap, "REPRO payload overlapping the COFF timestamp", "overlaps COFF timestamp")

    missing_rva = bytearray(source)
    _set_debug_payload(missing_rva, 0, IMAGE_DEBUG_TYPE_REPRO, 8, 0, repro_offset)
    _must_reject(missing_rva, "nonempty debug payload with a zero RVA", "without both mappings")

    missing_pointer = bytearray(source)
    _set_debug_payload(missing_pointer, 0, IMAGE_DEBUG_TYPE_REPRO, 8, 0x1080, 0)
    _must_reject(
        missing_pointer,
        "nonempty debug payload with a zero raw-data pointer",
        "without both mappings",
    )

    inconsistent_empty = bytearray(source)
    _set_debug_payload(inconsistent_empty, 0, 2, 0, 0x1080, repro_offset)
    _must_reject(inconsistent_empty, "empty debug payload with nonzero mappings", "inconsistent empty payload")

    empty_repro = bytearray(source)
    _set_debug_payload(empty_repro, 0, IMAGE_DEBUG_TYPE_REPRO, 0, 0, 0)
    _must_reject(empty_repro, "empty REPRO payload", "IMAGE_DEBUG_TYPE_REPRO has no payload")

    empty_codeview = bytearray(source)
    _set_debug_payload(empty_codeview, 1, 2, 0, 0, 0)
    empty_canonical, empty_counts = canonicalize_bytes(bytes(empty_codeview))
    assert empty_counts == (2, 1), empty_counts
    assert empty_canonical[codeview_offset : codeview_offset + 8] == b"CODEVIEW"

    inconsistent_mapping = bytearray(source)
    _set_debug_payload(inconsistent_mapping, 0, IMAGE_DEBUG_TYPE_REPRO, 8, 0x1081, repro_offset)
    _must_reject(inconsistent_mapping, "inconsistent debug RVA/raw-data mapping", "disagree")

    duplicate_repro = bytearray(source)
    _set_debug_payload(duplicate_repro, 1, IMAGE_DEBUG_TYPE_REPRO, 8, 0x1080, repro_offset)
    _must_reject(duplicate_repro, "duplicate REPRO payload range", "debug payload ranges overlap")

    ambiguous_pointer = bytearray(source)
    sections = optional + 240
    struct.pack_into("<IIII", ambiguous_pointer, sections + 48, 0x200, 0x3000, 0x200, 0x400)
    _must_reject(
        ambiguous_pointer,
        "debug payload pointer with ambiguous section ownership",
        "does not map to exactly one section",
    )

    malformed = bytearray(source)
    struct.pack_into("<I", malformed, 0x400 + 24, repro_offset + 1)
    _must_reject(malformed, "disagreeing debug RVA/raw pointer", "disagree")

    with tempfile.TemporaryDirectory(prefix="canonicalize-pe-test-") as directory:
        regular = os.path.join(directory, "input.exe")
        output = os.path.join(directory, "output.exe")
        alias = os.path.join(directory, "alias.exe")
        with open(regular, "wb") as handle:
            handle.write(source)
        canonicalize(regular, output)
        with open(regular, "rb") as handle:
            assert handle.read() == source
        with open(output, "rb") as handle:
            assert handle.read() == canonical

        occupied = os.path.join(directory, "occupied.exe")
        with open(occupied, "wb") as handle:
            handle.write(b"sentinel")
        try:
            canonicalize(regular, occupied)
        except PEFormatError:
            pass
        else:
            raise AssertionError("pre-existing output path was overwritten")
        with open(occupied, "rb") as handle:
            assert handle.read() == b"sentinel"

        try:
            canonicalize(regular, regular)
        except PEFormatError:
            pass
        else:
            raise AssertionError("in-place output path was accepted")

        os.link(regular, alias)
        try:
            _read_regular_file(regular)
        except PEFormatError:
            pass
        else:
            raise AssertionError("hardlinked PE input was accepted")
        os.unlink(alias)
        os.symlink(regular, alias)
        try:
            _read_regular_file(alias)
        except (OSError, PEFormatError):
            pass
        else:
            raise AssertionError("symlink PE input was accepted")
    print("canonicalize-pe self-test: ok")


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        self_test()
        return 0
    if len(argv) != 3 or argv[0] != "--output":
        print("usage: canonicalize-pe.py --output ABSENT_OUTPUT INPUT.exe", file=sys.stderr)
        return 2
    canonicalize(argv[2], argv[1])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except PEFormatError as exc:
        print(f"canonicalize-pe: fatal: {exc}", file=sys.stderr)
        raise SystemExit(1)
