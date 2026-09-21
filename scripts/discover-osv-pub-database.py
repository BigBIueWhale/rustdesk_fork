#!/usr/bin/env python3
"""Discover one reviewable, generation-bound OSV Pub database pin candidate."""

from __future__ import annotations

import argparse
import base64
import binascii
import calendar
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request


BUCKET = "osv-vulnerabilities"
OBJECT = "Pub/all.zip"
OBJECT_ESCAPED = "Pub%2Fall.zip"
ORIGIN = "storage.googleapis.com"
METADATA_URL = (
    f"https://{ORIGIN}/storage/v1/b/{BUCKET}/o/{OBJECT_ESCAPED}"
    "?projection=noAcl"
)
MAX_METADATA_BYTES = 128 * 1024
MAX_DATABASE_BYTES = 16 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024
TIMEOUT_SECONDS = 120
VALIDATOR_TIMEOUT_SECONDS = 120
USER_AGENT = "rustdesk-osv-pub-pin-discovery/1"
DECIMAL = re.compile(r"[1-9][0-9]*\Z")
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
UPDATED = re.compile(
    r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:[.]([0-9]{1,9}))?Z\Z"
)


class DiscoveryError(RuntimeError):
    """A fail-closed discovery transaction error."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DiscoveryError(message)


def parse_decimal(value: object, label: str, maximum: int | None = None) -> int:
    require(isinstance(value, str), f"{label} is not a JSON string")
    require(DECIMAL.fullmatch(value) is not None, f"{label} is not canonical decimal")
    parsed = int(value)
    if maximum is not None:
        require(parsed <= maximum, f"{label} exceeds its fixed bound")
    return parsed


def parse_base64(value: object, decoded_size: int, label: str) -> str:
    require(isinstance(value, str), f"{label} is not a JSON string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DiscoveryError(f"{label} is not canonical base64") from exc
    require(len(decoded) == decoded_size, f"{label} has the wrong decoded size")
    require(
        base64.b64encode(decoded).decode("ascii") == value,
        f"{label} is not canonical base64",
    )
    return value


def updated_epoch(value: object) -> tuple[str, int]:
    require(isinstance(value, str), "object updated time is not a JSON string")
    match = UPDATED.fullmatch(value)
    require(match is not None, "object updated time is not canonical UTC RFC 3339")
    try:
        parsed = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S")
    except ValueError as exc:
        raise DiscoveryError("object updated time is not a valid UTC time") from exc
    return value, calendar.timegm(parsed.timetuple())


@dataclass(frozen=True)
class ObjectCandidate:
    generation: str
    metageneration: str
    size: int
    md5_base64: str
    crc32c_base64: str
    updated: str
    capture_epoch: int


def parse_metadata(data: bytes) -> ObjectCandidate:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DiscoveryError(f"object metadata is not valid JSON: {exc}") from exc
    require(isinstance(value, dict), "object metadata is not a JSON object")
    require(value.get("kind") == "storage#object", "object metadata kind differs")
    require(value.get("bucket") == BUCKET, "object metadata bucket differs")
    require(value.get("name") == OBJECT, "object metadata name differs")
    generation_value = value.get("generation")
    metageneration_value = value.get("metageneration")
    parse_decimal(generation_value, "object generation")
    parse_decimal(metageneration_value, "object metageneration")
    size = parse_decimal(value.get("size"), "object size", MAX_DATABASE_BYTES)
    md5_base64 = parse_base64(value.get("md5Hash"), 16, "object MD5")
    crc32c_base64 = parse_base64(value.get("crc32c"), 4, "object CRC32C")
    require(
        value.get("contentEncoding") in (None, "identity"),
        "object metadata requests transformed content",
    )
    updated, capture_epoch = updated_epoch(value.get("updated"))
    return ObjectCandidate(
        generation=str(generation_value),
        metageneration=str(metageneration_value),
        size=size,
        md5_base64=md5_base64,
        crc32c_base64=crc32c_base64,
        updated=updated,
        capture_epoch=capture_epoch,
    )


class RefuseRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        raise urllib.error.HTTPError(
            req.full_url,
            code,
            "OSV discovery refuses redirects",
            headers,
            fp,
        )


def build_opener():
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        RefuseRedirects(),
    )


def validate_response(response, expected_url: str, label: str) -> None:
    require(getattr(response, "status", None) == 200, f"{label} status is not 200")
    require(response.geturl() == expected_url, f"{label} final URL differs")
    encoding = response.headers.get("Content-Encoding")
    require(encoding in (None, "", "identity"), f"{label} used transformed content")
    transfer = response.headers.get("Transfer-Encoding")
    length = response.headers.get("Content-Length")
    if length is None:
        require(
            transfer is not None and transfer.strip().lower() == "chunked",
            f"{label} has no admitted length framing",
        )
    else:
        require(transfer is None and length.isdigit(), f"{label} framing is ambiguous")


def request_bytes(opener, url: str, maximum: int, label: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "Accept-Encoding": "identity",
            "User-Agent": USER_AGENT,
        },
        method="GET",
    )
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            validate_response(response, url, label)
            length = response.headers.get("Content-Length")
            if length is not None:
                require(int(length) <= maximum, f"{label} exceeds its fixed byte bound")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = response.read(min(CHUNK_SIZE, maximum + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                require(total <= maximum, f"{label} exceeds its fixed byte bound")
                chunks.append(chunk)
            if length is not None:
                require(total == int(length), f"{label} length differs from its framing")
            return b"".join(chunks)
    except DiscoveryError:
        raise
    except (OSError, urllib.error.URLError) as exc:
        raise DiscoveryError(f"{label} request failed: {exc}") from exc


def exact_query(candidate: ObjectCandidate, *, media: bool) -> str:
    parameters = []
    if media:
        parameters.append(("alt", "media"))
    parameters.extend(
        (
            ("generation", candidate.generation),
            ("ifGenerationMatch", candidate.generation),
            ("ifMetagenerationMatch", candidate.metageneration),
        )
    )
    if not media:
        parameters.append(("projection", "noAcl"))
    return (
        f"https://{ORIGIN}/storage/v1/b/{BUCKET}/o/{OBJECT_ESCAPED}?"
        + urllib.parse.urlencode(parameters)
    )


def crc32c(data: bytes) -> int:
    value = 0xFFFFFFFF
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
    return value ^ 0xFFFFFFFF


def database_digests(data: bytes) -> dict[str, object]:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "md5_base64": base64.b64encode(
            hashlib.md5(data, usedforsecurity=False).digest()
        ).decode("ascii"),
        "crc32c_base64": base64.b64encode(
            struct.pack(">I", crc32c(data))
        ).decode("ascii"),
    }


def validate_validator(path: Path, expected_sha256: str) -> tuple[int, ...]:
    require(HEX256.fullmatch(expected_sha256) is not None, "validator SHA-256 is malformed")
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise DiscoveryError(f"cannot inspect structural validator: {exc}") from exc
    require(stat.S_ISREG(metadata.st_mode), "structural validator is not a regular file")
    require(not stat.S_ISLNK(metadata.st_mode), "structural validator is a symlink")
    require(metadata.st_size > 0, "structural validator is empty")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise DiscoveryError(f"cannot read structural validator: {exc}") from exc
    require(
        hashlib.sha256(data).hexdigest() == expected_sha256,
        "structural validator SHA-256 differs",
    )
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


def inspect_database_with_validator(
    database: Path,
    validator: Path,
    validator_sha256: str,
) -> dict[str, object]:
    before = validate_validator(validator, validator_sha256)
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                os.fspath(validator),
                "--inspect-database",
                os.fspath(database),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=VALIDATOR_TIMEOUT_SECONDS,
            cwd="/tmp",
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise DiscoveryError(f"structural validator execution failed: {exc}") from exc
    require(result.returncode == 0, "Pub database structural validation failed")
    require(not result.stderr, "Pub database structural validator wrote stderr")
    require(result.stdout.endswith("\n") and result.stdout.count("\n") == 1,
            "Pub database structural result is not one line")
    try:
        inspection = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise DiscoveryError("Pub database structural result is not JSON") from exc
    require(isinstance(inspection, dict), "Pub database structural result is not an object")
    require(
        set(inspection) == {
            "crc32c_base64",
            "md5_base64",
            "records",
            "sha256",
            "size",
            "uncompressed_bytes",
        },
        "Pub database structural result fields differ",
    )
    require(
        validate_validator(validator, validator_sha256) == before,
        "structural validator changed while executing",
    )
    return inspection


def write_database(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise DiscoveryError(f"cannot create private database candidate: {exc}") from exc
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            require(written > 0, "database candidate write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def metadata_candidate(opener, url: str, label: str) -> ObjectCandidate:
    return parse_metadata(request_bytes(opener, url, MAX_METADATA_BYTES, label))


def print_candidate(candidate: ObjectCandidate, inspection: dict[str, object]) -> None:
    values = (
        ("OSV_DB_PUB_SHA256", inspection["sha256"]),
        ("OSV_DB_PUB_SIZE", candidate.size),
        ("OSV_DB_PUB_CAPTURE_EPOCH", candidate.capture_epoch),
        ("OSV_DB_PUB_GENERATION", candidate.generation),
        ("OSV_DB_PUB_METAGENERATION", candidate.metageneration),
        ("OSV_DB_PUB_UPDATED", candidate.updated),
        ("OSV_DB_PUB_MD5_BASE64", candidate.md5_base64),
        ("OSV_DB_PUB_CRC32C_BASE64", candidate.crc32c_base64),
        ("OSV_DB_PUB_RECORDS", inspection["records"]),
        ("OSV_DB_PUB_UNCOMPRESSED_BYTES", inspection["uncompressed_bytes"]),
    )
    for name, value in values:
        print(f'{name}="{value}"')
    print(
        "OSV_PUB_DISCOVERY=pass source=gcs-json-api object=Pub/all.zip "
        f"generation={candidate.generation} metageneration={candidate.metageneration} "
        "latest-stable=yes publication=none"
    )


def discover(validator: Path, validator_sha256: str) -> None:
    validate_validator(validator, validator_sha256)
    opener = build_opener()
    latest_before = metadata_candidate(opener, METADATA_URL, "latest metadata")
    exact_metadata = metadata_candidate(
        opener,
        exact_query(latest_before, media=False),
        "exact-generation metadata",
    )
    require(exact_metadata == latest_before, "exact-generation metadata differs from latest")
    database = request_bytes(
        opener,
        exact_query(latest_before, media=True),
        latest_before.size,
        "exact-generation database",
    )
    digests = database_digests(database)
    require(digests["size"] == latest_before.size, "database size differs from metadata")
    require(digests["md5_base64"] == latest_before.md5_base64,
            "database MD5 differs from metadata")
    require(digests["crc32c_base64"] == latest_before.crc32c_base64,
            "database CRC32C differs from metadata")
    with tempfile.TemporaryDirectory(prefix="osv-pub-discovery.") as raw:
        database_path = Path(raw) / "Pub-all.zip"
        write_database(database_path, database)
        inspection = inspect_database_with_validator(
            database_path,
            validator,
            validator_sha256,
        )
    require(
        all(inspection[name] == value for name, value in digests.items()),
        "structural inspection digests differ from discovery digests",
    )
    latest_after = metadata_candidate(opener, METADATA_URL, "final latest metadata")
    require(latest_after == latest_before, "publisher replaced or changed latest during discovery")
    print_candidate(latest_before, inspection)


def expect_failure(operation, label: str) -> None:
    try:
        operation()
    except DiscoveryError:
        return
    raise DiscoveryError(f"self-test accepted {label}")


def run_self_test() -> None:
    require(crc32c(b"123456789") == 0xE3069283, "CRC32C known-answer mismatch")
    checks = 1
    metadata = {
        "kind": "storage#object",
        "bucket": BUCKET,
        "name": OBJECT,
        "generation": "123456789",
        "metageneration": "1",
        "size": "4",
        "md5Hash": base64.b64encode(hashlib.md5(b"data", usedforsecurity=False).digest()).decode("ascii"),
        "crc32c": base64.b64encode(struct.pack(">I", crc32c(b"data"))).decode("ascii"),
        "updated": "2026-09-22T12:34:56.789Z",
    }
    candidate = parse_metadata(json.dumps(metadata).encode("utf-8"))
    require(candidate.size == 4 and candidate.capture_epoch == 1790080496,
            "metadata fixture result differs")
    checks += 1
    require("alt=media" in exact_query(candidate, media=True)
            and "generation=123456789" in exact_query(candidate, media=True)
            and "ifMetagenerationMatch=1" in exact_query(candidate, media=True),
            "exact media URL is not generation/metageneration bound")
    checks += 1
    for field, replacement, label in (
        ("name", "npm/all.zip", "wrong object"),
        ("generation", "0", "zero generation"),
        ("size", str(MAX_DATABASE_BYTES + 1), "oversized database"),
        ("md5Hash", "AAAA", "malformed MD5"),
        ("updated", "2026-09-22T12:34:56+00:00", "noncanonical update time"),
        ("contentEncoding", "gzip", "transformed object"),
    ):
        hostile = dict(metadata)
        hostile[field] = replacement
        expect_failure(
            lambda hostile=hostile: parse_metadata(json.dumps(hostile).encode("utf-8")),
            label,
        )
        checks += 1
    require(checks == 9, f"self-test count drifted: {checks}")
    print("OSV Pub discovery self-test: PASS (9 decisions)")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--self-test", action="store_true")
    result.add_argument("--validator", type=Path)
    result.add_argument("--validator-sha256")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.self_test:
            require(
                args.validator is None and args.validator_sha256 is None,
                "--self-test takes no discovery arguments",
            )
            run_self_test()
            return 0
        require(args.validator is not None, "--validator is required")
        require(args.validator_sha256 is not None, "--validator-sha256 is required")
        discover(args.validator, args.validator_sha256)
        return 0
    except DiscoveryError as exc:
        print(f"discover-osv-pub-database: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
