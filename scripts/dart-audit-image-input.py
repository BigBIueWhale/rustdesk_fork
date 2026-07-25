#!/usr/bin/env python3
"""Validate the exact standalone inputs for the offline Dart advisory image."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tempfile
import zipfile


HEX256 = re.compile(r"[0-9a-f]{64}\Z")
ADVISORY_FILE = re.compile(r"([A-Za-z0-9_.:-]+)[.]json\Z")
MAX_SCANNER_BYTES = 64 * 1024 * 1024
MAX_DATABASE_BYTES = 16 * 1024 * 1024
MAX_RECORD_BYTES = 4 * 1024 * 1024


class InputError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InputError(message)


def parse_positive_decimal(value: str, label: str) -> int:
    require(
        re.fullmatch(r"[1-9][0-9]*", value) is not None,
        f"{label} is not one canonical positive decimal integer",
    )
    return int(value)


def parse_sha256(value: str, label: str) -> str:
    require(HEX256.fullmatch(value) is not None, f"{label} is not canonical SHA-256")
    return value


def metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def stable_read(
    path: Path,
    maximum_bytes: int,
    *,
    expected_size: int,
    expected_sha256: str,
) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise InputError(f"cannot inspect {path}: {exc}") from exc
    require(stat.S_ISREG(before.st_mode), f"input is not one regular file: {path}")
    require(not stat.S_ISLNK(before.st_mode), f"input is a symlink: {path}")
    require(before.st_nlink == 1, f"input is hardlinked: {path}")
    require(before.st_size == expected_size, f"input size differs from its pin: {path}")
    require(before.st_size <= maximum_bytes, f"input exceeds its fixed parser bound: {path}")
    require(
        (before.st_uid, before.st_gid) == (os.geteuid(), os.getegid())
        and stat.S_IMODE(before.st_mode) == 0o400,
        f"input is not current-identity-owned mode 0400: {path}",
    )
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise InputError(f"cannot open {path} without following links: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        require(
            metadata_identity(before) == metadata_identity(opened),
            f"input changed while being opened: {path}",
        )
        chunks: list[bytes] = []
        remaining = expected_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            require(bool(chunk), f"input ended before its pinned size: {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        require(not os.read(descriptor, 1), f"input grew beyond its pinned size: {path}")
        closed = os.fstat(descriptor)
        require(
            metadata_identity(opened) == metadata_identity(closed),
            f"input changed while being read: {path}",
        )
        try:
            after = os.lstat(path)
        except OSError as exc:
            raise InputError(f"cannot reinspect {path}: {exc}") from exc
        require(
            metadata_identity(closed) == metadata_identity(after),
            f"input path changed while being read: {path}",
        )
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    actual = hashlib.sha256(data).hexdigest()
    require(actual == expected_sha256, f"input SHA-256 differs from its pin: {path}")
    return data


def crc32c(data: bytes) -> int:
    value = 0xFFFFFFFF
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
    return value ^ 0xFFFFFFFF


def validate_database(
    data: bytes,
    *,
    expected_md5: str,
    expected_crc32c: str,
    expected_records: int,
    expected_uncompressed_bytes: int,
) -> None:
    actual_md5 = base64.b64encode(
        hashlib.md5(data, usedforsecurity=False).digest()
    ).decode("ascii")
    actual_crc32c = base64.b64encode(struct.pack(">I", crc32c(data))).decode("ascii")
    require(actual_md5 == expected_md5, "Pub database MD5 differs from GCS metadata")
    require(actual_crc32c == expected_crc32c, "Pub database CRC32C differs from GCS metadata")
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            require(not archive.comment, "Pub database ZIP has an archive comment")
            members = archive.infolist()
            require(
                len(members) == expected_records,
                "Pub database record count differs from its pin",
            )
            names: set[str] = set()
            folded: set[str] = set()
            total = 0
            for member in members:
                name = member.filename
                match = ADVISORY_FILE.fullmatch(name)
                require(match is not None, f"Pub database has a noncanonical member: {name!r}")
                require(name not in names, f"Pub database repeats a member: {name}")
                require(name.lower() not in folded, f"Pub database has a case collision: {name}")
                require(member.flag_bits & 1 == 0, f"Pub database member is encrypted: {name}")
                require(
                    member.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                    f"Pub database member uses an unsupported compression method: {name}",
                )
                require(
                    0 < member.file_size <= MAX_RECORD_BYTES,
                    f"Pub database member is empty or oversized: {name}",
                )
                total += member.file_size
                require(
                    total <= expected_uncompressed_bytes,
                    "Pub database exceeds its pinned uncompressed size",
                )
                payload = archive.read(member)
                require(len(payload) == member.file_size, f"short Pub database member: {name}")
                try:
                    record = json.loads(payload)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise InputError(f"Pub database member is not valid JSON: {name}: {exc}") from exc
                require(isinstance(record, dict), f"Pub database record is not an object: {name}")
                require(record.get("id") == match.group(1), f"Pub database ID/name mismatch: {name}")
                names.add(name)
                folded.add(name.lower())
            require(
                total == expected_uncompressed_bytes,
                "Pub database uncompressed size differs from its pin",
            )
            require(archive.testzip() is None, "Pub database ZIP CRC validation failed")
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise InputError(f"Pub database ZIP is malformed: {exc}") from exc


def validate_scanner(data: bytes) -> None:
    require(data.startswith(b"\x7fELF"), "scanner input is not an ELF binary")


def validate(args: argparse.Namespace) -> None:
    scanner_size = parse_positive_decimal(args.scanner_size, "scanner size")
    database_size = parse_positive_decimal(args.database_size, "database size")
    scanner_sha = parse_sha256(args.scanner_sha256, "scanner SHA-256")
    database_sha = parse_sha256(args.database_sha256, "database SHA-256")
    records = parse_positive_decimal(args.database_records, "database record count")
    uncompressed = parse_positive_decimal(
        args.database_uncompressed_bytes,
        "database uncompressed byte count",
    )
    scanner = stable_read(
        args.scanner,
        MAX_SCANNER_BYTES,
        expected_size=scanner_size,
        expected_sha256=scanner_sha,
    )
    validate_scanner(scanner)
    database = stable_read(
        args.database,
        MAX_DATABASE_BYTES,
        expected_size=database_size,
        expected_sha256=database_sha,
    )
    validate_database(
        database,
        expected_md5=args.database_md5,
        expected_crc32c=args.database_crc32c,
        expected_records=records,
        expected_uncompressed_bytes=uncompressed,
    )
    print("dart audit image inputs: verified")


def expect_failure(operation, label: str) -> None:
    try:
        operation()
    except InputError:
        return
    raise InputError(f"self-test accepted {label}")


def run_self_test() -> None:
    require(crc32c(b"123456789") == 0xE3069283, "CRC32C known-answer mismatch")
    checks = 1
    with tempfile.TemporaryDirectory(prefix="dart-audit-image-input.") as raw:
        root = Path(raw)
        record = json.dumps({"id": "GHSA-test-0000-0000"}).encode("utf-8")

        def make_database(name: str, payload: bytes) -> bytes:
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(name, payload)
            return stream.getvalue()

        def validate_fixture_database(candidate: bytes, expanded_size: int) -> None:
            validate_database(
                candidate,
                expected_md5=base64.b64encode(
                    hashlib.md5(
                        candidate,
                        usedforsecurity=False,
                    ).digest()
                ).decode("ascii"),
                expected_crc32c=base64.b64encode(
                    struct.pack(">I", crc32c(candidate))
                ).decode("ascii"),
                expected_records=1,
                expected_uncompressed_bytes=expanded_size,
            )

        database = make_database("GHSA-test-0000-0000.json", record)
        validate_database(
            database,
            expected_md5=base64.b64encode(
                hashlib.md5(database, usedforsecurity=False).digest()
            ).decode("ascii"),
            expected_crc32c=base64.b64encode(
                struct.pack(">I", crc32c(database))
            ).decode("ascii"),
            expected_records=1,
            expected_uncompressed_bytes=len(record),
        )
        checks += 1
        expect_failure(
            lambda: validate_database(
                database,
                expected_md5="AAAAAAAAAAAAAAAAAAAAAA==",
                expected_crc32c=base64.b64encode(
                    struct.pack(">I", crc32c(database))
                ).decode("ascii"),
                expected_records=1,
                expected_uncompressed_bytes=len(record),
            ),
            "wrong publisher MD5",
        )
        checks += 1
        expect_failure(
            lambda: validate_database(
                database,
                expected_md5=base64.b64encode(
                    hashlib.md5(database, usedforsecurity=False).digest()
                ).decode("ascii"),
                expected_crc32c="AAAAAA==",
                expected_records=1,
                expected_uncompressed_bytes=len(record),
            ),
            "wrong publisher CRC32C",
        )
        checks += 1
        noncanonical_database = make_database(
            "nested/GHSA-test-0000-0000.json",
            record,
        )
        expect_failure(
            lambda: validate_fixture_database(
                noncanonical_database,
                len(record),
            ),
            "noncanonical database member",
        )
        checks += 1
        wrong_id_record = json.dumps({"id": "GHSA-other-0000-0000"}).encode(
            "utf-8"
        )
        wrong_id_database = make_database(
            "GHSA-test-0000-0000.json",
            wrong_id_record,
        )
        expect_failure(
            lambda: validate_fixture_database(
                wrong_id_database,
                len(wrong_id_record),
            ),
            "database record ID mismatch",
        )
        checks += 1
        scanner = root / "scanner"
        scanner.write_bytes(b"\x7fELFfixture")
        scanner.chmod(0o400)
        scanner_size = scanner.stat().st_size
        scanner_sha = hashlib.sha256(b"\x7fELFfixture").hexdigest()
        scanner_bytes = stable_read(
            scanner,
            MAX_SCANNER_BYTES,
            expected_size=scanner_size,
            expected_sha256=scanner_sha,
        )
        require(scanner_bytes == b"\x7fELFfixture", "stable scanner read mismatch")
        checks += 1
        scanner.chmod(0o600)
        expect_failure(
            lambda: stable_read(
                scanner,
                MAX_SCANNER_BYTES,
                expected_size=scanner_size,
                expected_sha256=scanner_sha,
            ),
            "writable input",
        )
        checks += 1
        scanner.chmod(0o400)
        scanner_link = root / "scanner-hardlink"
        os.link(scanner, scanner_link)
        expect_failure(
            lambda: stable_read(
                scanner,
                MAX_SCANNER_BYTES,
                expected_size=scanner_size,
                expected_sha256=scanner_sha,
            ),
            "hardlinked input",
        )
        scanner_link.unlink()
        checks += 1
        expect_failure(
            lambda: stable_read(
                scanner,
                MAX_SCANNER_BYTES,
                expected_size=scanner_size,
                expected_sha256="0" * 64,
            ),
            "input checksum mismatch",
        )
        checks += 1
        expect_failure(
            lambda: validate_scanner(b"not an ELF"),
            "scanner format mismatch",
        )
        checks += 1
    require(checks == 11, f"self-test count drifted: {checks}")
    print("dart audit image input self-test: PASS (11 decisions)")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--self-test", action="store_true")
    result.add_argument("--scanner", type=Path)
    result.add_argument("--scanner-size")
    result.add_argument("--scanner-sha256")
    result.add_argument("--database", type=Path)
    result.add_argument("--database-size")
    result.add_argument("--database-sha256")
    result.add_argument("--database-md5")
    result.add_argument("--database-crc32c")
    result.add_argument("--database-records")
    result.add_argument("--database-uncompressed-bytes")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.self_test:
            supplied = tuple(
                value
                for name, value in vars(args).items()
                if name != "self_test" and value is not None
            )
            require(not supplied, "--self-test takes no input arguments")
            run_self_test()
            return 0
        required = (
            "scanner",
            "scanner_size",
            "scanner_sha256",
            "database",
            "database_size",
            "database_sha256",
            "database_md5",
            "database_crc32c",
            "database_records",
            "database_uncompressed_bytes",
        )
        require(
            all(getattr(args, name) is not None for name in required),
            "all scanner/database arguments are required",
        )
        validate(args)
        return 0
    except (InputError, OSError) as exc:
        print(f"dart-audit-image-input: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
