#!/usr/bin/env python3
"""Validate the exact signed Rust release inputs used by the Apple-check image."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import os
import pathlib
import re
import ssl
import stat
import tarfile
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import NoReturn


RUST_VERSION = "1.81.0"
RUST_DATE = "2024-09-05"
MINIMAL_PROFILE = ["rustc", "cargo", "rust-std", "rust-mingw"]
PACKAGE_VERSIONS = {
    "rustc": "1.81.0 (eeb90cda1 2024-09-04)",
    "cargo": "0.82.0 (2dbb1af80 2024-08-20)",
    "rust-std": "1.81.0 (eeb90cda1 2024-09-04)",
}
COMPONENT_SHAPES = (
    ("rustc-host", "rustc", "x86_64-unknown-linux-gnu"),
    ("cargo-host", "cargo", "x86_64-unknown-linux-gnu"),
    ("std-host", "rust-std", "x86_64-unknown-linux-gnu"),
    ("std-aarch64-darwin", "rust-std", "aarch64-apple-darwin"),
    ("std-x86_64-darwin", "rust-std", "x86_64-apple-darwin"),
    ("std-aarch64-ios", "rust-std", "aarch64-apple-ios"),
)
LOWER_HEX_256 = re.compile(r"[0-9a-f]{64}")
DOWNLOAD_CHUNK_BYTES = 1024 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 20
DOWNLOAD_DEADLINE_SECONDS = 600
ASCII_ARMOR_BYTE_LIMIT = 1024 * 1024
ARMOR_BEGIN = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
ARMOR_END = "-----END PGP PUBLIC KEY BLOCK-----"
ALLOWED_DOWNLOAD_URLS = frozenset(
    {
        "https://static.rust-lang.org/rust-key.gpg.ascii",
        f"https://static.rust-lang.org/dist/channel-rust-{RUST_VERSION}.toml",
        f"https://static.rust-lang.org/dist/channel-rust-{RUST_VERSION}.toml.asc",
        *(
            "https://static.rust-lang.org/dist/"
            f"{RUST_DATE}/{package}-{RUST_VERSION}-{target}.tar.xz"
            for _, package, target in COMPONENT_SHAPES
        ),
    }
)


class VerificationError(RuntimeError):
    """The release input does not meet the exact Apple toolchain contract."""


def fail(message: str) -> NoReturn:
    raise VerificationError(message)


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: object,
        code: int,
        message: str,
        headers: object,
        new_url: str,
    ) -> None:
        return None


def validate_download_parent(output: pathlib.Path) -> None:
    if not output.is_absolute() or output.name in {"", ".", ".."}:
        fail("download output must be one absolute ordinary filename")
    try:
        parent = os.lstat(output.parent)
    except OSError as exc:
        fail(f"cannot inspect download output directory: {exc}")
    if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
        fail("download output parent is not one real directory")
    if parent.st_uid != os.getuid() or parent.st_gid != os.getgid() \
       or stat.S_IMODE(parent.st_mode) != 0o700:
        fail("download output parent is not current-user-private mode 0700")


def fetch_release_input(
    url: str,
    output: pathlib.Path,
    expected_sha256: str,
    max_bytes: int,
    opener: object | None = None,
) -> None:
    if url not in ALLOWED_DOWNLOAD_URLS:
        fail("download URL is outside the exact Rust 1.81 release allowlist")
    if LOWER_HEX_256.fullmatch(expected_sha256) is None:
        fail("download SHA-256 is malformed")
    if max_bytes <= 0 or max_bytes > 1024 * 1024 * 1024:
        fail("download byte bound is invalid")
    validate_download_parent(output)
    if output.exists() or output.is_symlink():
        fail("refusing to replace an existing download output")

    if opener is None:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
            RejectRedirects(),
        )
    request = urllib.request.Request(
        url,
        headers={
            "Accept-Encoding": "identity",
            "User-Agent": "rustdesk-apple-toolchain-acquisition/1",
        },
        method="GET",
    )
    try:
        response = opener.open(request, timeout=DOWNLOAD_TIMEOUT_SECONDS)
    except (OSError, urllib.error.URLError) as exc:
        fail(f"cannot open authenticated Rust release input: {exc}")

    output_fd = -1
    output_identity: tuple[int, int] | None = None
    try:
        with response:
            if response.getcode() != 200 or response.geturl() != url:
                fail("Rust release input response identity differs")
            content_encoding = response.headers.get("Content-Encoding", "")
            if content_encoding.strip().lower() not in {"", "identity"}:
                fail("Rust release input response uses content encoding")
            content_length_header = response.headers.get("Content-Length")
            content_length: int | None = None
            if content_length_header is not None:
                if re.fullmatch(r"[1-9][0-9]*", content_length_header) is None:
                    fail("Rust release input Content-Length is malformed")
                content_length = int(content_length_header)
                if content_length > max_bytes:
                    fail("Rust release input exceeds its byte bound")

            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                output_fd = os.open(output, flags, 0o600)
            except OSError as exc:
                fail(f"cannot create download output: {exc}")
            created = os.fstat(output_fd)
            output_identity = (created.st_dev, created.st_ino)
            if not stat.S_ISREG(created.st_mode) or created.st_nlink != 1 \
               or created.st_uid != os.getuid() \
               or created.st_gid != os.getgid():
                fail("new download output authority differs")
            digest = hashlib.sha256()
            byte_count = 0
            deadline = time.monotonic() + DOWNLOAD_DEADLINE_SECONDS
            while True:
                if time.monotonic() > deadline:
                    fail("Rust release input exceeded its download deadline")
                try:
                    block = response.read(DOWNLOAD_CHUNK_BYTES)
                except OSError as exc:
                    fail(f"cannot read authenticated Rust release input: {exc}")
                if not block:
                    break
                byte_count += len(block)
                if byte_count > max_bytes:
                    fail("Rust release input exceeds its byte bound")
                digest.update(block)
                view = memoryview(block)
                while view:
                    written = os.write(output_fd, view)
                    if written <= 0:
                        fail("short write while saving Rust release input")
                    view = view[written:]
            if byte_count == 0:
                fail("Rust release input is empty")
            if content_length is not None and byte_count != content_length:
                fail("Rust release input length differs from its response")
            if digest.hexdigest() != expected_sha256:
                fail("Rust release input differs from its SHA-256 pin")
            os.fchmod(output_fd, 0o400)
            os.fsync(output_fd)
            final = os.fstat(output_fd)
            if (final.st_dev, final.st_ino) != output_identity \
               or stat.S_IMODE(final.st_mode) != 0o400 \
               or final.st_nlink != 1 \
               or final.st_size != byte_count:
                fail("download output identity or metadata changed")
            path_final = os.lstat(output)
            if (path_final.st_dev, path_final.st_ino) != output_identity \
               or not stat.S_ISREG(path_final.st_mode) \
               or path_final.st_nlink != 1 \
               or path_final.st_uid != os.getuid() \
               or path_final.st_gid != os.getgid() \
               or stat.S_IMODE(path_final.st_mode) != 0o400 \
               or path_final.st_size != byte_count:
                fail("download output edge or authority changed")
            os.close(output_fd)
            output_fd = -1
    except BaseException:
        if output_fd >= 0:
            os.close(output_fd)
            output_fd = -1
        if output_identity is not None:
            try:
                current = os.lstat(output)
            except FileNotFoundError:
                current = None
            except OSError as exc:
                fail(f"cannot inspect failed download output: {exc}")
            if current is not None:
                if (current.st_dev, current.st_ino) != output_identity \
                   or not stat.S_ISREG(current.st_mode):
                    fail("failed download output identity changed")
                try:
                    os.unlink(output)
                except OSError as exc:
                    fail(f"cannot remove failed download output: {exc}")
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


def read_private_regular(path: pathlib.Path, max_bytes: int, label: str) -> bytes:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        fail(f"{label} must be one absolute ordinary filename")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot open {label}: {exc}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 \
           or before.st_uid != os.getuid() or before.st_gid != os.getgid() \
           or stat.S_IMODE(before.st_mode) != 0o400 \
           or before.st_size <= 0 or before.st_size > max_bytes:
            fail(f"{label} authority or size differs")
        chunks: list[bytes] = []
        count = 0
        while True:
            try:
                block = os.read(descriptor, min(65536, max_bytes - count + 1))
            except OSError as exc:
                fail(f"cannot read {label}: {exc}")
            if not block:
                break
            count += len(block)
            if count > max_bytes:
                fail(f"{label} exceeds its byte bound")
            chunks.append(block)
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(
            getattr(before, field) != getattr(after, field)
            for field in stable_fields
        ) or count != before.st_size:
            fail(f"{label} changed while it was read")
        path_after = os.lstat(path)
        if (path_after.st_dev, path_after.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            fail(f"{label} edge changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def decode_public_key_armor(source: bytes) -> bytes:
    try:
        lines = source.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        fail(f"OpenPGP public-key armor is not ASCII: {exc}")
    if len(lines) < 5 or lines[0] != ARMOR_BEGIN or lines[-1] != ARMOR_END:
        fail("OpenPGP public-key armor boundary differs")
    position = 1
    seen_headers: set[str] = set()
    while position < len(lines) and lines[position] != "":
        header = lines[position]
        match = re.fullmatch(r"([A-Za-z0-9-]+): ([ -~]*)", header)
        if match is None or match.group(1).lower() in seen_headers \
           or len(seen_headers) >= 16:
            fail("OpenPGP public-key armor header is malformed")
        seen_headers.add(match.group(1).lower())
        position += 1
    if position >= len(lines) or lines[position] != "":
        fail("OpenPGP public-key armor header terminator is absent")
    position += 1
    armored_body = lines[position:-1]
    if len(armored_body) < 2:
        fail("OpenPGP public-key armor body is absent")
    checksum_line = armored_body[-1]
    encoded_lines = armored_body[:-1]
    if re.fullmatch(r"=[A-Za-z0-9+/]{4}", checksum_line) is None \
       or any(
           re.fullmatch(r"[A-Za-z0-9+/]{1,76}={0,2}", line) is None
           for line in encoded_lines
       ):
        fail("OpenPGP public-key armor payload is malformed")
    encoded = "".join(encoded_lines)
    try:
        decoded = base64.b64decode(encoded, validate=True)
        checksum = base64.b64decode(checksum_line[1:], validate=True)
    except ValueError as exc:
        fail(f"OpenPGP public-key armor base64 is malformed: {exc}")
    if not decoded or len(decoded) > ASCII_ARMOR_BYTE_LIMIT \
       or base64.b64encode(decoded).decode("ascii") != encoded \
       or len(checksum) != 3 \
       or int.from_bytes(checksum, "big") != crc24(decoded):
        fail("OpenPGP public-key armor payload or CRC-24 differs")
    return decoded


def dearmor_public_key(source: pathlib.Path, output: pathlib.Path) -> None:
    decoded = decode_public_key_armor(
        read_private_regular(
            source,
            ASCII_ARMOR_BYTE_LIMIT,
            "OpenPGP public-key armor",
        )
    )
    validate_download_parent(output)
    if output.exists() or output.is_symlink():
        fail("refusing to replace an existing dearmored public key")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    identity: tuple[int, int] | None = None
    try:
        try:
            descriptor = os.open(output, flags, 0o600)
        except OSError as exc:
            fail(f"cannot create dearmored public key: {exc}")
        created = os.fstat(descriptor)
        identity = (created.st_dev, created.st_ino)
        if not stat.S_ISREG(created.st_mode) or created.st_nlink != 1 \
           or created.st_uid != os.getuid() or created.st_gid != os.getgid():
            fail("new dearmored public-key authority differs")
        view = memoryview(decoded)
        while view:
            try:
                written = os.write(descriptor, view)
            except OSError as exc:
                fail(f"cannot write dearmored public key: {exc}")
            if written <= 0:
                fail("short write while saving dearmored public key")
            view = view[written:]
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        path_final = os.lstat(output)
        if (final.st_dev, final.st_ino) != identity \
           or (path_final.st_dev, path_final.st_ino) != identity \
           or not stat.S_ISREG(path_final.st_mode) \
           or final.st_nlink != 1 or path_final.st_nlink != 1 \
           or final.st_uid != os.getuid() or final.st_gid != os.getgid() \
           or stat.S_IMODE(final.st_mode) != 0o400 \
           or stat.S_IMODE(path_final.st_mode) != 0o400 \
           or final.st_size != len(decoded) \
           or path_final.st_size != len(decoded):
            fail("dearmored public-key output identity or metadata changed")
        os.close(descriptor)
        descriptor = -1
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
        if identity is not None:
            try:
                current = os.lstat(output)
            except FileNotFoundError:
                current = None
            except OSError as exc:
                fail(f"cannot inspect failed dearmored public key: {exc}")
            if current is not None:
                if (current.st_dev, current.st_ino) != identity \
                   or not stat.S_ISREG(current.st_mode):
                    fail("failed dearmored public-key output identity changed")
                try:
                    os.unlink(output)
                except OSError as exc:
                    fail(f"cannot remove failed dearmored public key: {exc}")
        raise


@dataclass(frozen=True)
class Component:
    output: str
    package: str
    target: str
    sha256: str

    @property
    def filename(self) -> str:
        return f"{self.package}-{RUST_VERSION}-{self.target}.tar.xz"

    @property
    def url(self) -> str:
        return f"https://static.rust-lang.org/dist/{RUST_DATE}/{self.filename}"

    def as_tsv(self) -> str:
        return f"{self.output}\t{self.sha256}\t{self.url}"


def components_from_args(args: argparse.Namespace) -> tuple[Component, ...]:
    hashes = (
        args.rustc_host_sha256,
        args.cargo_host_sha256,
        args.rust_std_host_sha256,
        args.rust_std_aarch64_darwin_sha256,
        args.rust_std_x86_64_darwin_sha256,
        args.rust_std_aarch64_ios_sha256,
    )
    for value in hashes:
        if LOWER_HEX_256.fullmatch(value) is None:
            fail("Rust component SHA-256 is malformed")
    return tuple(
        Component(output, package, target, sha256)
        for (output, package, target), sha256 in zip(
            COMPONENT_SHAPES,
            hashes,
            strict=True,
        )
    )


def verify_manifest(path: pathlib.Path, components: tuple[Component, ...]) -> list[str]:
    try:
        manifest = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        fail(f"cannot parse Rust release manifest: {exc}")
    if manifest.get("manifest-version") != "2" or manifest.get("date") != RUST_DATE:
        fail("Rust release manifest identity differs")
    if manifest.get("profiles", {}).get("minimal") != MINIMAL_PROFILE:
        fail("Rust minimal profile differs")
    for package, expected_version in PACKAGE_VERSIONS.items():
        if manifest.get("pkg", {}).get(package, {}).get("version") != expected_version:
            fail(f"Rust release package version differs: {package}")
    lines = []
    for component in components:
        item = (
            manifest.get("pkg", {})
            .get(component.package, {})
            .get("target", {})
            .get(component.target)
        )
        if not isinstance(item, dict) or item.get("available") is not True:
            fail(
                "Rust release component is unavailable: "
                f"{component.package}/{component.target}"
            )
        if item.get("xz_hash") != component.sha256 or item.get("xz_url") != component.url:
            fail(
                "Rust release component identity differs: "
                f"{component.package}/{component.target}"
            )
        lines.append(component.as_tsv())
    return lines


def verify_component_archive(path: pathlib.Path) -> None:
    try:
        package = tarfile.open(path, mode="r:xz")
    except (OSError, tarfile.TarError) as exc:
        fail(f"cannot parse Rust component archive: {exc}")
    roots: set[str] = set()
    count = 0
    try:
        for member in package:
            name = pathlib.PurePosixPath(member.name)
            if (
                name.is_absolute()
                or not name.parts
                or any(part in {"", ".", ".."} for part in name.parts)
            ):
                fail(f"unsafe Rust component member: {member.name!r}")
            if "\\" in member.name or "\0" in member.name:
                fail(f"noncanonical Rust component member: {member.name!r}")
            if not (member.isfile() or member.isdir()):
                fail(f"non-ordinary Rust component member: {member.name!r}")
            roots.add(name.parts[0])
            count += 1
    except (OSError, tarfile.TarError) as exc:
        fail(f"cannot enumerate Rust component archive: {exc}")
    finally:
        package.close()
    if count == 0 or len(roots) != 1:
        fail("Rust component archive does not contain one nonempty root")


def synthetic_manifest(components: tuple[Component, ...]) -> str:
    lines = [
        'manifest-version = "2"',
        f'date = "{RUST_DATE}"',
        "[profiles]",
        'minimal = ["rustc", "cargo", "rust-std", "rust-mingw"]',
    ]
    for package, version in PACKAGE_VERSIONS.items():
        lines.extend((f"[pkg.{package}]", f'version = "{version}"'))
        for component in components:
            if component.package != package:
                continue
            lines.extend(
                (
                    f"[pkg.{package}.target.{component.target}]",
                    "available = true",
                    f'xz_url = "{component.url}"',
                    f'xz_hash = "{component.sha256}"',
                )
            )
    return "\n".join(lines) + "\n"


def self_test() -> None:
    hashes = tuple(f"{index:064x}" for index in range(1, 7))
    components = tuple(
        Component(output, package, target, sha256)
        for (output, package, target), sha256 in zip(
            COMPONENT_SHAPES,
            hashes,
            strict=True,
        )
    )
    with tempfile.TemporaryDirectory(prefix="apple-toolchain-release.") as temporary:
        root = pathlib.Path(temporary)
        root.chmod(0o700)
        download_payload = b"authenticated fixture\n"
        download_sha256 = hashlib.sha256(download_payload).hexdigest()

        public_key_fixture = b"\x99\x01\x02\x03fixture-openpgp-key"
        encoded_public_key = base64.b64encode(public_key_fixture).decode("ascii")
        encoded_checksum = base64.b64encode(
            crc24(public_key_fixture).to_bytes(3, "big")
        ).decode("ascii")
        armored_public_key = root / "public-key.asc"
        armored_public_key.write_text(
            f"{ARMOR_BEGIN}\n\n{encoded_public_key}\n"
            f"={encoded_checksum}\n{ARMOR_END}\n",
            encoding="ascii",
        )
        armored_public_key.chmod(0o400)
        binary_public_key = root / "public-key.gpg"
        dearmor_public_key(armored_public_key, binary_public_key)
        binary_metadata = os.lstat(binary_public_key)
        if binary_public_key.read_bytes() != public_key_fixture \
           or stat.S_IMODE(binary_metadata.st_mode) != 0o400 \
           or binary_metadata.st_nlink != 1:
            fail("self-test dearmored public key differs")
        bad_armored_public_key = root / "bad-public-key.asc"
        bad_armored_public_key.write_text(
            f"{ARMOR_BEGIN}\n\n{encoded_public_key}\n"
            f"=AAAA\n{ARMOR_END}\n",
            encoding="ascii",
        )
        bad_armored_public_key.chmod(0o400)
        rejected_binary_public_key = root / "bad-public-key.gpg"
        try:
            dearmor_public_key(
                bad_armored_public_key,
                rejected_binary_public_key,
            )
        except VerificationError:
            if rejected_binary_public_key.exists() \
               or rejected_binary_public_key.is_symlink():
                fail("self-test failed dearmor retained output")
        else:
            fail("self-test accepted wrong OpenPGP armor CRC-24")

        class FixtureResponse:
            def __init__(self, url: str, payload: bytes) -> None:
                self.url = url
                self.payload = payload
                self.position = 0
                self.headers = {"Content-Length": str(len(payload))}

            def __enter__(self) -> FixtureResponse:
                return self

            def __exit__(self, *arguments: object) -> None:
                return None

            def getcode(self) -> int:
                return 200

            def geturl(self) -> str:
                return self.url

            def read(self, size: int) -> bytes:
                block = self.payload[self.position : self.position + size]
                self.position += len(block)
                return block

        class FixtureOpener:
            def __init__(self, payload: bytes) -> None:
                self.payload = payload

            def open(
                self,
                request: urllib.request.Request,
                timeout: int,
            ) -> FixtureResponse:
                if timeout != DOWNLOAD_TIMEOUT_SECONDS:
                    fail("self-test download timeout differs")
                return FixtureResponse(request.full_url, self.payload)

        key_url = "https://static.rust-lang.org/rust-key.gpg.ascii"
        download = root / "download"
        fetch_release_input(
            key_url,
            download,
            download_sha256,
            len(download_payload),
            FixtureOpener(download_payload),
        )
        metadata = os.lstat(download)
        if download.read_bytes() != download_payload \
           or stat.S_IMODE(metadata.st_mode) != 0o400 \
           or metadata.st_nlink != 1:
            fail("self-test authenticated download output differs")
        for label, url, digest, bound, candidate_payload in (
            (
                "URL allowlist",
                key_url + "?mutable=1",
                download_sha256,
                len(download_payload),
                download_payload,
            ),
            (
                "digest",
                key_url,
                "f" * 64,
                len(download_payload),
                download_payload,
            ),
            (
                "byte bound",
                key_url,
                download_sha256,
                len(download_payload) - 1,
                download_payload,
            ),
        ):
            rejected = root / ("rejected-" + label.replace(" ", "-"))
            try:
                fetch_release_input(
                    url,
                    rejected,
                    digest,
                    bound,
                    FixtureOpener(candidate_payload),
                )
            except VerificationError:
                if rejected.exists() or rejected.is_symlink():
                    fail(f"self-test failed {label} download retained output")
            else:
                fail(f"self-test accepted wrong download {label}")

        manifest = root / "channel.toml"
        manifest.write_text(synthetic_manifest(components), encoding="utf-8")
        if verify_manifest(manifest, components) != [
            component.as_tsv() for component in components
        ]:
            fail("self-test component list differs")
        manifest.write_text(
            synthetic_manifest(components).replace(
                RUST_DATE,
                "2024-09-06",
                1,
            ),
            encoding="utf-8",
        )
        try:
            verify_manifest(manifest, components)
        except VerificationError:
            pass
        else:
            fail("self-test manifest identity mutation was accepted")

        archive = root / "component.tar.xz"
        with tarfile.open(archive, mode="w:xz") as package:
            directory = tarfile.TarInfo("component")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            package.addfile(directory)
            payload = b"installer"
            installer = tarfile.TarInfo("component/install.sh")
            installer.size = len(payload)
            installer.mode = 0o755
            package.addfile(installer, io.BytesIO(payload))
        verify_component_archive(archive)

        unsafe = root / "unsafe.tar.xz"
        with tarfile.open(unsafe, mode="w:xz") as package:
            payload = b"escape"
            member = tarfile.TarInfo("../escape")
            member.size = len(payload)
            package.addfile(member, io.BytesIO(payload))
        try:
            verify_component_archive(unsafe)
        except VerificationError:
            pass
        else:
            fail("self-test traversal archive was accepted")

        linked = root / "linked.tar.xz"
        with tarfile.open(linked, mode="w:xz") as package:
            member = tarfile.TarInfo("component/link")
            member.type = tarfile.SYMTYPE
            member.linkname = "target"
            package.addfile(member)
        try:
            verify_component_archive(linked)
        except VerificationError:
            pass
        else:
            fail("self-test linked archive was accepted")
    print("apple-toolchain-release: self-test ok")


def add_component_hash_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--rustc-host-sha256", required=True)
    parser.add_argument("--cargo-host-sha256", required=True)
    parser.add_argument("--rust-std-host-sha256", required=True)
    parser.add_argument("--rust-std-aarch64-darwin-sha256", required=True)
    parser.add_argument("--rust-std-x86-64-darwin-sha256", required=True)
    parser.add_argument("--rust-std-aarch64-ios-sha256", required=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    manifest = subparsers.add_parser("manifest")
    manifest.add_argument("--path", type=pathlib.Path, required=True)
    add_component_hash_arguments(manifest)
    archive = subparsers.add_parser("archive")
    archive.add_argument("--path", type=pathlib.Path, required=True)
    fetch = subparsers.add_parser("fetch")
    fetch.add_argument("--url", required=True)
    fetch.add_argument("--output", type=pathlib.Path, required=True)
    fetch.add_argument("--sha256", required=True)
    fetch.add_argument("--max-bytes", type=int, required=True)
    dearmor = subparsers.add_parser("dearmor")
    dearmor.add_argument("--input", type=pathlib.Path, required=True)
    dearmor.add_argument("--output", type=pathlib.Path, required=True)
    subparsers.add_parser("self-test")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "manifest":
            for line in verify_manifest(args.path, components_from_args(args)):
                print(line)
        elif args.command == "archive":
            verify_component_archive(args.path)
            print("apple-toolchain-release: archive ok")
        elif args.command == "fetch":
            fetch_release_input(
                args.url,
                args.output,
                args.sha256,
                args.max_bytes,
            )
            print("apple-toolchain-release: fetch ok")
        elif args.command == "dearmor":
            dearmor_public_key(args.input, args.output)
            print("apple-toolchain-release: dearmor ok")
        else:
            self_test()
        return 0
    except VerificationError as exc:
        print(f"apple-toolchain-release: {exc}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
