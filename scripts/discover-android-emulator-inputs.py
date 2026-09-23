#!/usr/bin/env python3
"""Discover exact official Android Emulator inputs without publishing them.

This maintenance helper is intentionally not an input fetcher.  It reads the
official Google repository metadata, selects one closed package tuple, verifies
the publisher's size/SHA-1 against the actual HTTPS bytes, computes SHA-256
pins, and inspects the ZIP structure.  The caller may review its bounded JSON
receipt and add pins in a later commit; nothing here writes canonical inputs.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import stat
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from typing import Iterable
from xml.etree import ElementTree


EMULATOR_METADATA_URL = "https://dl.google.com/android/repository/repository2-3.xml"
SYSTEM_IMAGE_METADATA_URL = (
    "https://dl.google.com/android/repository/sys-img/android/sys-img2-3.xml"
)
EMULATOR_PACKAGE = "emulator"
SYSTEM_IMAGE_PACKAGE = "system-images;android-34;default;arm64-v8a"
USER_AGENT = "rustdesk-fork-android-emulator-input-discovery/1"
METADATA_LIMIT = 32 * 1024 * 1024
ARCHIVE_LIMIT = 5 * 1024 * 1024 * 1024
ZIP_ENTRY_LIMIT = 20_000
ZIP_UNCOMPRESSED_LIMIT = 32 * 1024 * 1024 * 1024


class DiscoveryError(RuntimeError):
    """A discovery input was ambiguous, unsafe, or inconsistent."""


@dataclass(frozen=True)
class PackageArchive:
    package: str
    revision: str
    url: str
    size: int
    publisher_checksum_type: str
    publisher_checksum: str


@dataclass(frozen=True)
class ArchiveReceipt:
    package: str
    revision: str
    url: str
    size: int
    publisher_sha1: str
    sha256: str
    zip_entries: int
    zip_uncompressed_bytes: int
    zip_symlinks: int


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def fail(message: str) -> DiscoveryError:
    return DiscoveryError(message)


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def children(element: ElementTree.Element, name: str) -> list[ElementTree.Element]:
    return [child for child in element if local_name(child.tag) == name]


def one_child(element: ElementTree.Element, name: str) -> ElementTree.Element:
    matches = children(element, name)
    if len(matches) != 1:
        raise fail(f"expected exactly one {name}, found {len(matches)}")
    return matches[0]


def one_text(element: ElementTree.Element, name: str) -> str:
    text = (one_child(element, name).text or "").strip()
    if not text:
        raise fail(f"{name} is empty")
    return text


def optional_text(element: ElementTree.Element, name: str) -> str | None:
    matches = children(element, name)
    if len(matches) > 1:
        raise fail(f"multiple {name} values are ambiguous")
    if not matches:
        return None
    text = (matches[0].text or "").strip()
    return text or None


def parse_positive_decimal(value: str, label: str, upper: int) -> int:
    if not re.fullmatch(r"[1-9][0-9]*", value):
        raise fail(f"{label} is not one canonical positive decimal")
    parsed = int(value)
    if parsed > upper:
        raise fail(f"{label} exceeds its bound")
    return parsed


def parse_revision(package: ElementTree.Element) -> str:
    revision = one_child(package, "revision")
    parts: list[int] = []
    for name in ("major", "minor", "micro"):
        matches = children(revision, name)
        if len(matches) > 1:
            raise fail(f"revision has multiple {name} fields")
        if not matches:
            parts.append(0)
            continue
        value = (matches[0].text or "").strip()
        if not re.fullmatch(r"0|[1-9][0-9]*", value):
            raise fail(f"revision {name} is malformed")
        parts.append(int(value))
    if children(revision, "preview"):
        raise fail("preview Android packages are outside the stable discovery operation")
    return ".".join(str(part) for part in parts)


def is_stable(package: ElementTree.Element) -> bool:
    references = children(package, "channelRef")
    if len(references) > 1:
        raise fail("package has multiple channel references")
    return not references or references[0].get("ref") == "channel-0"


def is_current(package: ElementTree.Element) -> bool:
    obsolete = package.get("obsolete")
    if obsolete is None:
        return True
    if obsolete == "true":
        return False
    raise fail("package has a malformed obsolete attribute")


def package_url(metadata_url: str, relative: str) -> str:
    if not relative or "\\" in relative or "\x00" in relative:
        raise fail("archive URL is empty or malformed")
    relative_parts = urllib.parse.urlsplit(relative)
    if relative_parts.scheme or relative_parts.netloc or relative_parts.query or relative_parts.fragment:
        raise fail("archive URL is not one relative repository filename")
    decoded = urllib.parse.unquote(relative)
    path = PurePosixPath(decoded)
    if path.is_absolute() or len(path.parts) != 1 or path.name in ("", ".", ".."):
        raise fail("archive URL escapes its repository directory")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+()-]*[.]zip", path.name):
        raise fail("archive URL filename is outside the closed ZIP grammar")
    resolved = urllib.parse.urljoin(metadata_url, relative)
    parsed = urllib.parse.urlsplit(resolved)
    if parsed.scheme != "https" or parsed.hostname != "dl.google.com":
        raise fail("archive URL does not remain on official Google HTTPS")
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        raise fail("archive URL carries unexpected authority state")
    if parsed.query or parsed.fragment:
        raise fail("archive URL carries a query or fragment")
    return resolved


def archive_matches(archive: ElementTree.Element, role: str) -> bool:
    host_os = optional_text(archive, "host-os")
    host_arch = optional_text(archive, "host-arch")
    host_bits = optional_text(archive, "host-bits")
    if role == "emulator":
        if host_os != "linux":
            return False
        if host_arch not in (None, "x86", "x64", "x86_64"):
            return False
        if host_bits not in (None, "64"):
            return False
        return host_arch != "x86" or host_bits == "64"
    if role == "system-image":
        return host_os in (None, "linux") and host_arch in (None, "x86_64")
    raise fail(f"unknown archive role: {role}")


def parse_package(
    document: bytes, metadata_url: str, package_path: str, role: str
) -> PackageArchive:
    try:
        root = ElementTree.fromstring(document)
    except ElementTree.ParseError as error:
        raise fail(f"Android repository metadata is not well-formed XML: {error}") from error
    path_matches = [
        element
        for element in root.iter()
        if local_name(element.tag) == "remotePackage"
        and element.get("path") == package_path
    ]
    matches = [
        package
        for package in path_matches
        if is_current(package) and is_stable(package)
    ]
    if len(matches) != 1:
        raise fail(
            f"package {package_path!r} has {len(path_matches)} path matches "
            f"but {len(matches)} current stable matches"
        )
    package = matches[0]
    revision = parse_revision(package)
    archives_parent = one_child(package, "archives")
    candidates = [
        archive
        for archive in children(archives_parent, "archive")
        if archive_matches(archive, role)
    ]
    if len(candidates) != 1:
        filters = [
            {
                "host_os": optional_text(archive, "host-os"),
                "host_arch": optional_text(archive, "host-arch"),
                "host_bits": optional_text(archive, "host-bits"),
            }
            for archive in children(archives_parent, "archive")
        ]
        raise fail(
            f"package {package_path!r} has {len(candidates)} matching archives; "
            f"available filters={json.dumps(filters, sort_keys=True, separators=(',', ':'))}"
        )
    complete = one_child(candidates[0], "complete")
    size = parse_positive_decimal(one_text(complete, "size"), "archive size", ARCHIVE_LIMIT)
    checksums = children(complete, "checksum")
    if len(checksums) != 1:
        raise fail("archive does not have exactly one publisher checksum")
    checksum_type = (checksums[0].get("type") or "").lower()
    checksum = (checksums[0].text or "").strip().lower()
    if checksum_type not in ("sha1", "sha-1") or not re.fullmatch(r"[0-9a-f]{40}", checksum):
        raise fail("archive does not carry one canonical publisher SHA-1")
    url = package_url(metadata_url, one_text(complete, "url"))
    return PackageArchive(
        package=package_path,
        revision=revision,
        url=url,
        size=size,
        publisher_checksum_type="sha1",
        publisher_checksum=checksum,
    )


def opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(NoRedirect())


def request(url: str) -> urllib.request.Request:
    return urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"},
        method="GET",
    )


def fetch_metadata(url: str) -> bytes:
    try:
        with opener().open(request(url), timeout=120) as response:
            if response.geturl() != url or getattr(response, "status", None) != 200:
                raise fail("metadata response changed URL or status")
            declared = response.headers.get("Content-Length")
            if declared is not None:
                parse_positive_decimal(declared, "metadata Content-Length", METADATA_LIMIT)
            output = bytearray()
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > METADATA_LIMIT:
                    raise fail("metadata exceeds its byte bound")
    except (OSError, urllib.error.URLError) as error:
        raise fail(f"metadata HTTPS request failed: {error}") from error
    if not output:
        raise fail("metadata response is empty")
    if declared is not None and len(output) != int(declared):
        raise fail("metadata response length differs from Content-Length")
    return bytes(output)


def safe_zip_name(name: str) -> PurePosixPath:
    if not name or "\x00" in name or "\\" in name:
        raise fail("ZIP entry has an empty or malformed name")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise fail(f"ZIP entry escapes its root: {name!r}")
    if len(name.encode("utf-8")) > 1024:
        raise fail("ZIP entry name exceeds its bound")
    return path


def normalized_symlink_target(name: PurePosixPath, target: str) -> None:
    if not target or "\x00" in target or "\\" in target:
        raise fail("ZIP symlink target is empty or malformed")
    target_path = PurePosixPath(target)
    if target_path.is_absolute() or len(target.encode("utf-8")) > 1024:
        raise fail("ZIP symlink target is absolute or oversized")
    depth = len(name.parent.parts)
    for part in target_path.parts:
        if part in ("", "."):
            continue
        if part == "..":
            depth -= 1
            if depth < 0:
                raise fail("ZIP symlink target escapes its root")
        else:
            depth += 1


def inspect_zip(path: str, role: str) -> tuple[int, int, int]:
    try:
        with zipfile.ZipFile(path, "r") as archive:
            entries = archive.infolist()
            if not entries or len(entries) > ZIP_ENTRY_LIMIT:
                raise fail("ZIP entry count is empty or exceeds its bound")
            names: set[str] = set()
            regular: set[str] = set()
            total = 0
            symlinks = 0
            for entry in entries:
                name = safe_zip_name(entry.filename)
                canonical = name.as_posix().rstrip("/")
                if canonical in names:
                    raise fail(f"ZIP contains a duplicate normalized entry: {canonical}")
                names.add(canonical)
                if entry.flag_bits & 0x1:
                    raise fail("ZIP contains an encrypted entry")
                if entry.file_size < 0 or entry.compress_size < 0:
                    raise fail("ZIP contains a negative entry size")
                total += entry.file_size
                if total > ZIP_UNCOMPRESSED_LIMIT:
                    raise fail("ZIP uncompressed size exceeds its bound")
                mode = (entry.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(mode)
                is_directory = entry.is_dir()
                if file_type == stat.S_IFLNK:
                    if entry.file_size > 1024:
                        raise fail("ZIP symlink target exceeds its bound")
                    target = archive.read(entry).decode("utf-8", errors="strict")
                    normalized_symlink_target(name, target)
                    symlinks += 1
                elif file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise fail("ZIP contains a device, socket, or other special entry")
                elif not is_directory:
                    regular.add(canonical)
            required = {
                "emulator": {
                    "emulator/emulator",
                    "emulator/qemu/linux-x86_64/qemu-system-aarch64-headless",
                },
                "system-image": {
                    "system.img",
                    "ramdisk.img",
                    "kernel-ranchu",
                    "source.properties",
                },
            }[role]
            missing = sorted(required - regular)
            if missing:
                raise fail(f"ZIP is missing required {role} files: {missing}")
            bad = archive.testzip()
            if bad is not None:
                raise fail(f"ZIP CRC validation failed at {bad!r}")
            return len(entries), total, symlinks
    except (OSError, UnicodeError, zipfile.BadZipFile) as error:
        raise fail(f"ZIP validation failed: {error}") from error


def download_and_verify(spec: PackageArchive, role: str, directory: str) -> ArchiveReceipt:
    destination = os.path.join(directory, f"{role}.zip")
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    received = 0
    try:
        with opener().open(request(spec.url), timeout=1800) as response:
            if response.geturl() != spec.url or getattr(response, "status", None) != 200:
                raise fail("archive response changed URL or status")
            declared = response.headers.get("Content-Length")
            if declared is not None and parse_positive_decimal(
                declared, "archive Content-Length", ARCHIVE_LIMIT
            ) != spec.size:
                raise fail("archive Content-Length differs from publisher metadata")
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    received += len(chunk)
                    if received > spec.size:
                        raise fail("archive exceeds its publisher-declared size")
                    sha1.update(chunk)
                    sha256.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
    except (OSError, urllib.error.URLError) as error:
        raise fail(f"archive HTTPS request failed: {error}") from error
    if received != spec.size or os.stat(destination).st_size != spec.size:
        raise fail("archive byte count differs from publisher metadata")
    observed_sha1 = sha1.hexdigest()
    if observed_sha1 != spec.publisher_checksum:
        raise fail("archive bytes differ from the publisher SHA-1")
    entries, uncompressed, symlinks = inspect_zip(destination, role)
    receipt = ArchiveReceipt(
        package=spec.package,
        revision=spec.revision,
        url=spec.url,
        size=spec.size,
        publisher_sha1=observed_sha1,
        sha256=sha256.hexdigest(),
        zip_entries=entries,
        zip_uncompressed_bytes=uncompressed,
        zip_symlinks=symlinks,
    )
    os.unlink(destination)
    return receipt


def make_zip(path: str, names: Iterable[str]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in names:
            archive.writestr(name, name.encode("utf-8"))


def metadata_fixture(package: str, size: int, digest: str, url: str) -> bytes:
    return f"""<?xml version='1.0' encoding='UTF-8'?>
<repository>
  <channel id='channel-0'>stable</channel>
  <remotePackage path='{package}'>
    <channelRef ref='channel-0'/>
    <revision><major>35</major><minor>2</minor><micro>1</micro></revision>
    <archives><archive><host-os>linux</host-os><host-arch>x86_64</host-arch>
      <complete><size>{size}</size><checksum type='sha1'>{digest}</checksum><url>{url}</url></complete>
    </archive></archives>
  </remotePackage>
</repository>""".encode("utf-8")


def expect_failure(callable_, phrase: str) -> None:  # type: ignore[no-untyped-def]
    try:
        callable_()
    except DiscoveryError as error:
        if phrase not in str(error):
            raise fail(f"self-test refusal differed: {error}") from error
        return
    raise fail("self-test expected a refusal")


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="android-emulator-discovery-self-test-") as root:
        valid = os.path.join(root, "valid.zip")
        make_zip(
            valid,
            (
                "emulator/emulator",
                "emulator/qemu/linux-x86_64/qemu-system-aarch64-headless",
                "emulator/NOTICE.txt",
            ),
        )
        with open(valid, "rb") as source:
            payload = source.read()
        document = metadata_fixture(
            EMULATOR_PACKAGE,
            len(payload),
            hashlib.sha1(payload).hexdigest(),
            "emulator-linux_test.zip",
        )
        spec = parse_package(document, EMULATOR_METADATA_URL, EMULATOR_PACKAGE, "emulator")
        if spec.revision != "35.2.1" or spec.size != len(payload):
            raise fail("self-test valid metadata result differs")
        document_root = ElementTree.fromstring(document)
        stable_package = next(
            element
            for element in document_root
            if local_name(element.tag) == "remotePackage"
        )
        beta_package = copy.deepcopy(stable_package)
        one_child(beta_package, "channelRef").set("ref", "channel-1")
        obsolete_package = copy.deepcopy(stable_package)
        obsolete_package.set("obsolete", "true")
        document_root.extend((beta_package, obsolete_package))
        alternatives = ElementTree.tostring(document_root)
        alternative_spec = parse_package(
            alternatives, EMULATOR_METADATA_URL, EMULATOR_PACKAGE, "emulator"
        )
        if alternative_spec != spec:
            raise fail("self-test stable package selection differs")
        x86_root = ElementTree.fromstring(document)
        x86_package = next(
            element for element in x86_root if local_name(element.tag) == "remotePackage"
        )
        x86_archive = one_child(one_child(x86_package, "archives"), "archive")
        one_child(x86_archive, "host-arch").text = "x86"
        ElementTree.SubElement(x86_archive, "host-bits").text = "64"
        x86_spec = parse_package(
            ElementTree.tostring(x86_root),
            EMULATOR_METADATA_URL,
            EMULATOR_PACKAGE,
            "emulator",
        )
        if x86_spec != spec:
            raise fail("self-test 64-bit x86 archive selection differs")
        one_child(x86_archive, "host-arch").text = "x64"
        x86_archive.remove(one_child(x86_archive, "host-bits"))
        x64_spec = parse_package(
            ElementTree.tostring(x86_root),
            EMULATOR_METADATA_URL,
            EMULATOR_PACKAGE,
            "emulator",
        )
        if x64_spec != spec:
            raise fail("self-test x64 archive selection differs")
        entries, _, symlinks = inspect_zip(valid, "emulator")
        if entries != 3 or symlinks != 0:
            raise fail("self-test valid ZIP result differs")

        traversal = os.path.join(root, "traversal.zip")
        make_zip(
            traversal,
            (
                "../escape",
                "emulator/emulator",
                "emulator/qemu/linux-x86_64/qemu-system-aarch64-headless",
            ),
        )
        expect_failure(lambda: inspect_zip(traversal, "emulator"), "escapes")
        expect_failure(
            lambda: parse_package(
                document.replace(b"channel-0", b"channel-1"),
                EMULATOR_METADATA_URL,
                EMULATOR_PACKAGE,
                "emulator",
            ),
            "current stable",
        )
        expect_failure(
            lambda: package_url(EMULATOR_METADATA_URL, "../escape.zip"),
            "escapes",
        )
    print("ANDROID_EMULATOR_DISCOVERY_SELF_TEST=pass cases=7")


def discover() -> None:
    self_test()
    emulator_document = fetch_metadata(EMULATOR_METADATA_URL)
    system_document = fetch_metadata(SYSTEM_IMAGE_METADATA_URL)
    emulator = parse_package(
        emulator_document, EMULATOR_METADATA_URL, EMULATOR_PACKAGE, "emulator"
    )
    system_image = parse_package(
        system_document,
        SYSTEM_IMAGE_METADATA_URL,
        SYSTEM_IMAGE_PACKAGE,
        "system-image",
    )
    with tempfile.TemporaryDirectory(prefix="android-emulator-discovery-") as root:
        emulator_receipt = download_and_verify(emulator, "emulator", root)
        system_receipt = download_and_verify(system_image, "system-image", root)
    result = {
        "schema": 1,
        "metadata": {
            "emulator": {
                "url": EMULATOR_METADATA_URL,
                "size": len(emulator_document),
                "sha256": hashlib.sha256(emulator_document).hexdigest(),
            },
            "system_image": {
                "url": SYSTEM_IMAGE_METADATA_URL,
                "size": len(system_document),
                "sha256": hashlib.sha256(system_document).hexdigest(),
            },
        },
        "emulator": asdict(emulator_receipt),
        "system_image": asdict(system_receipt),
    }
    print(
        "ANDROID_EMULATOR_DISCOVERY_JSON="
        + json.dumps(result, sort_keys=True, separators=(",", ":"))
    )
    print(
        "ANDROID_EMULATOR_DISCOVERY=pass "
        f"emulator_revision={emulator_receipt.revision} "
        f"emulator_size={emulator_receipt.size} "
        f"emulator_sha256={emulator_receipt.sha256} "
        f"system_package={SYSTEM_IMAGE_PACKAGE} "
        f"system_revision={system_receipt.revision} "
        f"system_size={system_receipt.size} "
        f"system_sha256={system_receipt.sha256} "
        "publisher_sha1=verified zip=crc-verified publication=none"
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
        print(f"android-emulator discovery: {error}", file=os.sys.stderr)
        raise SystemExit(1) from error
