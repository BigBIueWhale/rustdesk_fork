#!/usr/bin/env python3
"""Discover the exact Rust 1.75 x86_64 Android std archive without publishing it.

The immutable Rust release public key authenticates the versioned channel
manifest.  The signed manifest, in turn, selects and authenticates the one
x86_64-linux-android rust-std archive.  This maintenance helper writes only to
its private temporary directory and emits a bounded receipt for later review.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import lzma
import os
import pathlib
import re
import ssl
import stat
import subprocess
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.request
from typing import NoReturn


RUST_VERSION = "1.75.0"
RUST_DATE = "2023-12-28"
TARGET = "x86_64-linux-android"
PACKAGE = "rust-std"
KEY_URL = "https://static.rust-lang.org/rust-key.gpg.ascii"
MANIFEST_URL = f"https://static.rust-lang.org/dist/channel-rust-{RUST_VERSION}.toml"
SIGNATURE_URL = MANIFEST_URL + ".asc"
ARCHIVE_URL = (
    f"https://static.rust-lang.org/dist/{RUST_DATE}/"
    f"{PACKAGE}-{RUST_VERSION}-{TARGET}.tar.xz"
)
PUBLIC_KEY_SHA256 = "e54b09a439647e006b4831eec9785cbaaf3e07ab371c3a6ee6a68e1bdb9fbc6b"
SIGNING_FINGERPRINT = "108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE"
ALLOWED_URLS = frozenset((KEY_URL, MANIFEST_URL, SIGNATURE_URL, ARCHIVE_URL))
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
ARMOR_BEGIN = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
ARMOR_END = "-----END PGP PUBLIC KEY BLOCK-----"
DOWNLOAD_CHUNK = 1024 * 1024
LIMITS = {
    KEY_URL: 1024 * 1024,
    MANIFEST_URL: 16 * 1024 * 1024,
    SIGNATURE_URL: 1024 * 1024,
    ARCHIVE_URL: 1024 * 1024 * 1024,
}
MAX_ARCHIVE_ENTRIES = 50_000
MAX_ARCHIVE_EXPANDED = 4 * 1024 * 1024 * 1024


class DiscoveryError(RuntimeError):
    """A publisher input or archive failed its closed discovery contract."""


def fail(message: str) -> NoReturn:
    raise DiscoveryError(message)


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def downloader() -> urllib.request.OpenerDirector:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        RejectRedirects(),
    )


def download(
    url: str,
    output: pathlib.Path,
    *,
    expected_sha256: str | None = None,
    opener: urllib.request.OpenerDirector | None = None,
) -> tuple[int, str]:
    if url not in ALLOWED_URLS:
        fail("download URL is outside the exact Rust Android discovery allowlist")
    if expected_sha256 is not None and LOWER_SHA256.fullmatch(expected_sha256) is None:
        fail("expected download SHA-256 is malformed")
    if not output.is_absolute() or output.name in ("", ".", ".."):
        fail("download output is not one absolute ordinary path")
    parent = os.lstat(output.parent)
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or (parent.st_uid, parent.st_gid, stat.S_IMODE(parent.st_mode))
        != (os.getuid(), os.getgid(), 0o700)
    ):
        fail("download output parent is not current-user-private mode 0700")
    if output.exists() or output.is_symlink():
        fail("download output is already occupied")
    request = urllib.request.Request(
        url,
        headers={
            "Accept-Encoding": "identity",
            "User-Agent": "rustdesk-rust-android-x86-input-discovery/1",
        },
        method="GET",
    )
    try:
        response = (opener or downloader()).open(request, timeout=120)
    except (OSError, urllib.error.URLError) as error:
        fail(f"cannot open Rust release input: {error}")
    descriptor = -1
    identity: tuple[int, int] | None = None
    try:
        with response:
            if response.getcode() != 200 or response.geturl() != url:
                fail("Rust release input response changed URL or status")
            if response.headers.get("Content-Encoding", "").strip().lower() not in ("", "identity"):
                fail("Rust release input uses unexpected content encoding")
            declared_text = response.headers.get("Content-Length")
            declared = None
            if declared_text is not None:
                if re.fullmatch(r"[1-9][0-9]*", declared_text) is None:
                    fail("Rust release input Content-Length is malformed")
                declared = int(declared_text)
                if declared > LIMITS[url]:
                    fail("Rust release input Content-Length exceeds its bound")
            descriptor = os.open(
                output,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            created = os.fstat(descriptor)
            identity = (created.st_dev, created.st_ino)
            digest = hashlib.sha256()
            received = 0
            while True:
                block = response.read(DOWNLOAD_CHUNK)
                if not block:
                    break
                received += len(block)
                if received > LIMITS[url]:
                    fail("Rust release input exceeds its byte bound")
                digest.update(block)
                view = memoryview(block)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        fail("short write while saving Rust release input")
                    view = view[written:]
            observed = digest.hexdigest()
            if received == 0 or (declared is not None and received != declared):
                fail("Rust release input byte count differs")
            if expected_sha256 is not None and observed != expected_sha256:
                fail("Rust release input differs from its SHA-256 pin")
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
            final = os.fstat(descriptor)
            edge = os.lstat(output)
            if (
                identity != (final.st_dev, final.st_ino)
                or identity != (edge.st_dev, edge.st_ino)
                or not stat.S_ISREG(final.st_mode)
                or final.st_nlink != 1
                or edge.st_nlink != 1
                or (final.st_uid, final.st_gid, stat.S_IMODE(final.st_mode), final.st_size)
                != (os.getuid(), os.getgid(), 0o400, received)
            ):
                fail("Rust release input identity or metadata changed")
            os.close(descriptor)
            descriptor = -1
            return received, observed
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        if identity is not None:
            try:
                current = os.lstat(output)
            except FileNotFoundError:
                current = None
            if current is not None:
                if (current.st_dev, current.st_ino) != identity or not stat.S_ISREG(current.st_mode):
                    fail("failed download output identity changed")
                os.unlink(output)
        raise


def crc24(payload: bytes) -> int:
    value = 0xB704CE
    for octet in payload:
        value ^= octet << 16
        for _ in range(8):
            value <<= 1
            if value & 0x1000000:
                value ^= 0x1864CFB
    return value & 0xFFFFFF


def decode_public_key(source: bytes) -> bytes:
    try:
        lines = source.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        fail(f"Rust public key armor is not ASCII: {error}")
    if len(lines) < 5 or lines[0] != ARMOR_BEGIN or lines[-1] != ARMOR_END:
        fail("Rust public key armor boundary differs")
    separator = None
    for index, line in enumerate(lines[1:-1], start=1):
        if line == "":
            separator = index
            break
        if re.fullmatch(r"[A-Za-z0-9-]+: [ -~]*", line) is None:
            fail("Rust public key armor header is malformed")
    if separator is None:
        fail("Rust public key armor header terminator is absent")
    body = lines[separator + 1 : -1]
    if len(body) < 2 or re.fullmatch(r"=[A-Za-z0-9+/]{4}", body[-1]) is None:
        fail("Rust public key armor checksum is malformed")
    if any(re.fullmatch(r"[A-Za-z0-9+/]{1,76}={0,2}", line) is None for line in body[:-1]):
        fail("Rust public key armor payload is malformed")
    encoded = "".join(body[:-1])
    try:
        decoded = base64.b64decode(encoded, validate=True)
        checksum = base64.b64decode(body[-1][1:], validate=True)
    except ValueError as error:
        fail(f"Rust public key armor base64 is malformed: {error}")
    if (
        not decoded
        or len(decoded) > LIMITS[KEY_URL]
        or base64.b64encode(decoded).decode("ascii") != encoded
        or len(checksum) != 3
        or int.from_bytes(checksum, "big") != crc24(decoded)
    ):
        fail("Rust public key armor payload or CRC-24 differs")
    return decoded


def write_private(path: pathlib.Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o400,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                fail("short write while creating private discovery input")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def signature_fingerprint(status: str) -> str:
    fingerprints = []
    for line in status.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[:2] == ["[GNUPG:]", "VALIDSIG"]:
            candidates = (fields[2], fields[-1])
            matching = [value for value in candidates if value == SIGNING_FINGERPRINT]
            if matching:
                fingerprints.append(SIGNING_FINGERPRINT)
            else:
                fingerprints.append(fields[2])
    if fingerprints != [SIGNING_FINGERPRINT]:
        fail("Rust manifest does not have one exact release-key VALIDSIG")
    return fingerprints[0]


def verify_signature(key: pathlib.Path, signature: pathlib.Path, manifest: pathlib.Path, home: pathlib.Path) -> str:
    home.mkdir(mode=0o700)
    try:
        result = subprocess.run(
            [
                "/usr/bin/gpgv",
                "--status-fd=1",
                "--homedir",
                os.fspath(home),
                "--keyring",
                os.fspath(key),
                os.fspath(signature),
                os.fspath(manifest),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
            env={"HOME": "/nonexistent", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        fail(f"cannot execute bounded Rust manifest signature verification: {error}")
    if result.returncode != 0 or len(result.stdout) > 65536 or len(result.stderr) > 65536:
        fail("Rust manifest signature verification failed or exceeded its output bound")
    try:
        return signature_fingerprint(result.stdout.decode("utf-8", errors="strict"))
    except UnicodeError as error:
        fail(f"Rust signature status is not UTF-8: {error}")


def archive_identity(manifest_bytes: bytes) -> tuple[str, str]:
    try:
        manifest = tomllib.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        fail(f"signed Rust manifest is malformed: {error}")
    if manifest.get("manifest-version") != "2" or manifest.get("date") != RUST_DATE:
        fail("signed Rust manifest identity differs")
    package = manifest.get("pkg", {}).get(PACKAGE, {})
    version = package.get("version")
    if not isinstance(version, str) or re.fullmatch(r"1[.]75[.]0 \([0-9a-f]{9,40} 2023-12-[0-9]{2}\)", version) is None:
        fail("signed Rust standard-library package version differs")
    target = package.get("target", {}).get(TARGET)
    if not isinstance(target, dict) or target.get("available") is not True:
        fail("signed Rust x86_64 Android standard library is unavailable")
    digest = target.get("xz_hash")
    url = target.get("xz_url")
    if LOWER_SHA256.fullmatch(digest or "") is None or url != ARCHIVE_URL:
        fail("signed Rust x86_64 Android archive identity differs")
    return digest, version


def inspect_archive(path: pathlib.Path) -> tuple[int, int, str]:
    expected_root = f"{PACKAGE}-{RUST_VERSION}-{TARGET}"
    entries = 0
    expanded = 0
    names: set[str] = set()
    required = {
        f"{expected_root}/install.sh",
        f"{expected_root}/components",
        f"{expected_root}/rust-std-{TARGET}/lib/rustlib/{TARGET}/lib",
    }
    seen_required: set[str] = set()
    try:
        with tarfile.open(path, mode="r:xz") as archive:
            for member in archive:
                entries += 1
                if entries > MAX_ARCHIVE_ENTRIES:
                    fail("Rust standard-library archive entry count exceeds its bound")
                name = pathlib.PurePosixPath(member.name)
                if (
                    name.is_absolute()
                    or not name.parts
                    or name.parts[0] != expected_root
                    or any(part in ("", ".", "..") for part in name.parts)
                    or "\\" in member.name
                    or "\x00" in member.name
                ):
                    fail("Rust standard-library archive contains a noncanonical path")
                canonical = name.as_posix().rstrip("/")
                if canonical in names:
                    fail("Rust standard-library archive contains a duplicate path")
                names.add(canonical)
                if not (member.isfile() or member.isdir()):
                    fail("Rust standard-library archive contains a nonordinary entry")
                if member.size < 0:
                    fail("Rust standard-library archive contains a negative size")
                expanded += member.size
                if expanded > MAX_ARCHIVE_EXPANDED:
                    fail("Rust standard-library archive expanded size exceeds its bound")
                for item in required:
                    if canonical == item or canonical.startswith(item + "/"):
                        seen_required.add(item)
    except (OSError, lzma.LZMAError, tarfile.TarError) as error:
        fail(f"cannot fully inspect Rust standard-library archive: {error}")
    if entries == 0 or seen_required != required:
        fail("Rust standard-library archive layout is incomplete")
    if not any(
        name.startswith(f"{expected_root}/rust-std-{TARGET}/lib/rustlib/{TARGET}/lib/libstd-")
        and name.endswith(".rlib")
        for name in names
    ):
        fail("Rust standard-library archive contains no target libstd")
    return entries, expanded, expected_root


def self_test() -> None:
    digest = "a" * 64
    manifest = f'''manifest-version = "2"
date = "{RUST_DATE}"
[pkg.rust-std]
version = "1.75.0 (82e1608df 2023-12-21)"
[pkg.rust-std.target.{TARGET}]
available = true
xz_hash = "{digest}"
xz_url = "{ARCHIVE_URL}"
'''.encode("utf-8")
    if archive_identity(manifest) != (digest, "1.75.0 (82e1608df 2023-12-21)"):
        fail("self-test manifest result differs")
    if signature_fingerprint(f"[GNUPG:] VALIDSIG {SIGNING_FINGERPRINT}") != SIGNING_FINGERPRINT:
        fail("self-test signature result differs")
    payload = b"fixture-openpgp-key"
    encoded = base64.b64encode(payload).decode("ascii")
    checksum = base64.b64encode(crc24(payload).to_bytes(3, "big")).decode("ascii")
    armor = f"{ARMOR_BEGIN}\n\n{encoded}\n={checksum}\n{ARMOR_END}\n".encode("ascii")
    if decode_public_key(armor) != payload:
        fail("self-test public-key decoding differs")
    with tempfile.TemporaryDirectory(prefix="rust-android-x86-discovery-self-test-") as temporary:
        root = pathlib.Path(temporary)
        root.chmod(0o700)
        archive_path = root / "std.tar.xz"
        archive_root = f"{PACKAGE}-{RUST_VERSION}-{TARGET}"
        with tarfile.open(archive_path, mode="w:xz") as archive:
            for name, data in (
                (f"{archive_root}/install.sh", b"#!/bin/sh\n"),
                (f"{archive_root}/components", b"rust-std-x86_64-linux-android\n"),
                (
                    f"{archive_root}/rust-std-{TARGET}/lib/rustlib/{TARGET}/lib/libstd-fixture.rlib",
                    b"fixture",
                ),
            ):
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        entries, _, observed_root = inspect_archive(archive_path)
        if entries != 3 or observed_root != archive_root:
            fail("self-test archive inspection differs")
    print("RUST_ANDROID_X86_DISCOVERY_SELF_TEST=pass cases=4")


def discover() -> None:
    self_test()
    with tempfile.TemporaryDirectory(prefix="rust-android-x86-discovery-") as temporary:
        root = pathlib.Path(temporary)
        root.chmod(0o700)
        key_armor = root / "rust-key.asc"
        key_binary = root / "rust-key.gpg"
        manifest = root / "channel.toml"
        signature = root / "channel.toml.asc"
        archive = root / f"{PACKAGE}-{RUST_VERSION}-{TARGET}.tar.xz"
        _, key_hash = download(KEY_URL, key_armor, expected_sha256=PUBLIC_KEY_SHA256)
        manifest_size, manifest_hash = download(MANIFEST_URL, manifest)
        signature_size, signature_hash = download(SIGNATURE_URL, signature)
        write_private(key_binary, decode_public_key(key_armor.read_bytes()))
        fingerprint = verify_signature(key_binary, signature, manifest, root / "gpg-home")
        archive_hash, package_version = archive_identity(manifest.read_bytes())
        archive_size, observed_archive_hash = download(
            ARCHIVE_URL,
            archive,
            expected_sha256=archive_hash,
        )
        entries, expanded, archive_root = inspect_archive(archive)
    result = {
        "schema": 1,
        "rust_version": RUST_VERSION,
        "release_date": RUST_DATE,
        "package_version": package_version,
        "target": TARGET,
        "public_key": {
            "url": KEY_URL,
            "sha256": key_hash,
            "fingerprint": fingerprint,
        },
        "manifest": {
            "url": MANIFEST_URL,
            "size": manifest_size,
            "sha256": manifest_hash,
        },
        "signature": {
            "url": SIGNATURE_URL,
            "size": signature_size,
            "sha256": signature_hash,
        },
        "archive": {
            "url": ARCHIVE_URL,
            "size": archive_size,
            "sha256": observed_archive_hash,
            "entries": entries,
            "expanded_bytes": expanded,
            "root": archive_root,
        },
    }
    print(
        "RUST_ANDROID_X86_DISCOVERY_JSON="
        + json.dumps(result, sort_keys=True, separators=(",", ":"))
    )
    print(
        "RUST_ANDROID_X86_DISCOVERY=pass "
        f"version={RUST_VERSION} target={TARGET} size={archive_size} "
        f"sha256={observed_archive_hash} signature=valid fingerprint={fingerprint} "
        "archive=fully-inspected publication=none"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-test", action="store_true")
    mode.add_argument("--discover", action="store_true")
    arguments = parser.parse_args()
    if arguments.self_test:
        self_test()
    else:
        discover()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DiscoveryError as error:
        raise SystemExit(f"Rust Android x86 discovery: {error}") from error
