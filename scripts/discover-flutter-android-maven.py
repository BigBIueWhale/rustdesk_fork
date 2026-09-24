#!/usr/bin/env python3
"""Discover the exact Flutter 3.24.5 Android runtime Maven inputs.

This maintenance helper never publishes build inputs.  It downloads each
closed Google Storage object twice into private temporary storage, requires the
two observations to agree, validates the Maven coordinates and archive
structure, and prints a bounded receipt whose pins can be reviewed separately.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import stat
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import NoReturn
from xml.etree import ElementTree


ENGINE_REVISION = "a18df97ca57a249df5d8d68cd0820600223ce262"
MAVEN_VERSION = f"1.0.0-{ENGINE_REVISION}"
MAVEN_ROOT = "https://storage.googleapis.com/download.flutter.io/io/flutter"
USER_AGENT = "rustdesk-fork-flutter-android-maven-discovery/1"
DOWNLOAD_LIMIT = 64 * 1024 * 1024
POM_LIMIT = 1024 * 1024
ZIP_ENTRY_LIMIT = 10_000
ZIP_EXPANDED_LIMIT = 256 * 1024 * 1024
ARTIFACTS = ("flutter_embedding_release", "x86_64_release")
EXTENSIONS = ("jar", "pom")
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class DiscoveryError(RuntimeError):
    """An upstream response or artifact violated the closed contract."""


@dataclass(frozen=True)
class ArtifactReceipt:
    artifact: str
    extension: str
    url: str
    size: int
    sha1: str
    sha256: str
    zip_entries: int | None
    zip_uncompressed_bytes: int | None


def fail(message: str) -> NoReturn:
    raise DiscoveryError(message)


def artifact_url(artifact: str, extension: str) -> str:
    if artifact not in ARTIFACTS or extension not in EXTENSIONS:
        fail("Flutter Maven coordinate is outside the closed artifact set")
    filename = f"{artifact}-{MAVEN_VERSION}.{extension}"
    return f"{MAVEN_ROOT}/{artifact}/{MAVEN_VERSION}/{filename}"


ALLOWED_URLS = frozenset(
    artifact_url(artifact, extension)
    for artifact in ARTIFACTS
    for extension in EXTENSIONS
)


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


def validate_private_directory(path: Path) -> tuple[int, int]:
    metadata = os.lstat(path)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode))
        != (os.getuid(), os.getgid(), 0o700)
    ):
        fail("discovery output directory is not current-user-private mode 0700")
    return metadata.st_dev, metadata.st_ino


def download(
    opener: urllib.request.OpenerDirector, url: str, output: Path
) -> tuple[int, str, str]:
    if url not in ALLOWED_URLS:
        fail("download URL is outside the exact Flutter Maven allowlist")
    parent_identity = validate_private_directory(output.parent)
    if output.exists() or output.is_symlink():
        fail("download output is already occupied")
    request = urllib.request.Request(
        url,
        headers={"Accept-Encoding": "identity", "User-Agent": USER_AGENT},
        method="GET",
    )
    try:
        response = opener.open(request, timeout=120)
    except (OSError, urllib.error.URLError) as error:
        fail(f"cannot open Flutter Maven input: {error}")
    descriptor = -1
    identity: tuple[int, int] | None = None
    try:
        with response:
            if response.getcode() != 200 or response.geturl() != url:
                fail("Flutter Maven response changed URL or status")
            if response.headers.get("Content-Encoding", "").strip().lower() not in (
                "",
                "identity",
            ):
                fail("Flutter Maven response uses unexpected content encoding")
            declared_text = response.headers.get("Content-Length")
            declared = None
            if declared_text is not None:
                if re.fullmatch(r"[1-9][0-9]*", declared_text) is None:
                    fail("Flutter Maven Content-Length is malformed")
                declared = int(declared_text)
                if declared > DOWNLOAD_LIMIT:
                    fail("Flutter Maven Content-Length exceeds its bound")
            descriptor = os.open(
                output,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            created = os.fstat(descriptor)
            identity = created.st_dev, created.st_ino
            sha1 = hashlib.sha1(usedforsecurity=False)
            sha256 = hashlib.sha256()
            received = 0
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                received += len(block)
                if received > DOWNLOAD_LIMIT:
                    fail("Flutter Maven input exceeds its byte bound")
                sha1.update(block)
                sha256.update(block)
                view = memoryview(block)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        fail("short write while saving Flutter Maven input")
                    view = view[written:]
            if received == 0 or (declared is not None and declared != received):
                fail("Flutter Maven response byte count differs")
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
            final = os.fstat(descriptor)
            edge = os.lstat(output)
            if (
                (final.st_dev, final.st_ino) != identity
                or (edge.st_dev, edge.st_ino) != identity
                or not stat.S_ISREG(final.st_mode)
                or final.st_nlink != 1
                or edge.st_nlink != 1
                or (final.st_uid, final.st_gid, stat.S_IMODE(final.st_mode), final.st_size)
                != (os.getuid(), os.getgid(), 0o400, received)
                or validate_private_directory(output.parent) != parent_identity
            ):
                fail("Flutter Maven output identity or metadata changed")
            os.close(descriptor)
            descriptor = -1
            return received, sha1.hexdigest(), sha256.hexdigest()
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        if identity is not None:
            try:
                current = os.lstat(output)
            except FileNotFoundError:
                current = None
            if current is not None:
                if (current.st_dev, current.st_ino) != identity:
                    fail("failed Flutter Maven output identity changed")
                os.unlink(output)
        raise


def direct_text(root: ElementTree.Element, name: str) -> str:
    matches = [child for child in root if child.tag.rsplit("}", 1)[-1] == name]
    if len(matches) != 1:
        fail(f"Flutter Maven POM must contain exactly one direct {name}")
    value = (matches[0].text or "").strip()
    if not value:
        fail(f"Flutter Maven POM direct {name} is empty")
    return value


def validate_pom(path: Path, artifact: str) -> None:
    metadata = os.lstat(path)
    if metadata.st_size > POM_LIMIT:
        fail("Flutter Maven POM exceeds its byte bound")
    try:
        root = ElementTree.parse(path).getroot()
    except (ElementTree.ParseError, OSError) as error:
        fail(f"Flutter Maven POM is not well-formed XML: {error}")
    if root.tag.rsplit("}", 1)[-1] != "project":
        fail("Flutter Maven POM root is not project")
    expected = {
        "modelVersion": "4.0.0",
        "groupId": "io.flutter",
        "artifactId": artifact,
        "version": MAVEN_VERSION,
        "packaging": "jar",
    }
    for name, value in expected.items():
        if direct_text(root, name) != value:
            fail(f"Flutter Maven POM {name} differs")
    dependencies = [
        child for child in root if child.tag.rsplit("}", 1)[-1] == "dependencies"
    ]
    if len(dependencies) != 1:
        fail("Flutter Maven POM dependencies element is absent or duplicated")
    dependency_count = sum(
        child.tag.rsplit("}", 1)[-1] == "dependency" for child in dependencies[0]
    )
    if artifact == "x86_64_release" and dependency_count != 0:
        fail("Flutter x86_64 engine POM unexpectedly has dependencies")
    if artifact == "flutter_embedding_release" and not 1 <= dependency_count <= 64:
        fail("Flutter embedding POM dependency count is outside its bound")


def validate_zip_name(name: str) -> None:
    if not name or "\\" in name or "\x00" in name:
        fail("Flutter Maven JAR has an empty or malformed member name")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        fail("Flutter Maven JAR member escapes its archive root")


def validate_jar(path: Path, artifact: str) -> tuple[int, int]:
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as error:
        fail(f"Flutter Maven JAR is not one valid ZIP: {error}")
    with archive:
        entries = archive.infolist()
        if not entries or len(entries) > ZIP_ENTRY_LIMIT:
            fail("Flutter Maven JAR entry count is outside its bound")
        names: set[str] = set()
        expanded = 0
        regular_names: list[str] = []
        for entry in entries:
            validate_zip_name(entry.filename)
            if entry.filename in names:
                fail("Flutter Maven JAR contains duplicate member names")
            names.add(entry.filename)
            if entry.flag_bits & 0x1:
                fail("Flutter Maven JAR contains an encrypted member")
            mode = (entry.external_attr >> 16) & 0xFFFF
            if mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                fail("Flutter Maven JAR contains a non-file member")
            expanded += entry.file_size
            if expanded > ZIP_EXPANDED_LIMIT:
                fail("Flutter Maven JAR expanded bytes exceed their bound")
            if not entry.is_dir():
                regular_names.append(entry.filename)
        bad = archive.testzip()
        if bad is not None:
            fail(f"Flutter Maven JAR member fails CRC validation: {bad}")
        if artifact == "x86_64_release":
            expected_name = "lib/x86_64/libflutter.so"
            if regular_names != [expected_name]:
                fail("Flutter x86_64 engine JAR inventory differs")
            with archive.open(expected_name) as stream:
                header = stream.read(20)
            if (
                len(header) != 20
                or header[:4] != b"\x7fELF"
                or header[4] != 2
                or header[5] != 1
                or int.from_bytes(header[18:20], "little") != 62
            ):
                fail("Flutter x86_64 engine is not one little-endian ELF64 EM_X86_64")
        else:
            required = {
                "META-INF/MANIFEST.MF",
                "io/flutter/embedding/engine/FlutterEngine.class",
            }
            if not required.issubset(names):
                fail("Flutter embedding JAR omits required classes or manifest")
            if any(name.startswith("lib/") for name in regular_names):
                fail("Flutter embedding JAR unexpectedly contains a native library")
            classes = sum(name.endswith(".class") for name in regular_names)
            if not 100 <= classes <= 10_000:
                fail("Flutter embedding JAR class count is outside its bound")
        return len(entries), expanded


def inspect_download(
    artifact: str,
    extension: str,
    url: str,
    path: Path,
    observation: tuple[int, str, str],
) -> ArtifactReceipt:
    size, sha1, sha256 = observation
    if extension == "pom":
        validate_pom(path, artifact)
        entries = None
        expanded = None
    else:
        entries, expanded = validate_jar(path, artifact)
    return ArtifactReceipt(
        artifact=artifact,
        extension=extension,
        url=url,
        size=size,
        sha1=sha1,
        sha256=sha256,
        zip_entries=entries,
        zip_uncompressed_bytes=expanded,
    )


def discover() -> list[ArtifactReceipt]:
    opener = downloader()
    with tempfile.TemporaryDirectory(prefix="rustdesk-flutter-maven-a.") as first_name:
        with tempfile.TemporaryDirectory(prefix="rustdesk-flutter-maven-b.") as second_name:
            first_root = Path(first_name)
            second_root = Path(second_name)
            validate_private_directory(first_root)
            validate_private_directory(second_root)
            receipts: list[ArtifactReceipt] = []
            for artifact in ARTIFACTS:
                for extension in EXTENSIONS:
                    url = artifact_url(artifact, extension)
                    filename = f"{artifact}-{MAVEN_VERSION}.{extension}"
                    first_path = first_root / filename
                    second_path = second_root / filename
                    first = download(opener, url, first_path)
                    second = download(opener, url, second_path)
                    if first != second:
                        fail("independent Flutter Maven downloads disagree")
                    first_receipt = inspect_download(
                        artifact, extension, url, first_path, first
                    )
                    second_receipt = inspect_download(
                        artifact, extension, url, second_path, second
                    )
                    if first_receipt != second_receipt:
                        fail("independent Flutter Maven validations disagree")
                    receipts.append(first_receipt)
            return receipts


def write_test_file(path: Path, payload: bytes) -> None:
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
                fail("self-test fixture write failed")
            view = view[written:]
    finally:
        os.close(descriptor)


def self_test() -> None:
    expected = (
        "https://storage.googleapis.com/download.flutter.io/io/flutter/"
        f"x86_64_release/{MAVEN_VERSION}/x86_64_release-{MAVEN_VERSION}.jar"
    )
    if artifact_url("x86_64_release", "jar") != expected:
        fail("self-test exact URL construction failed")
    try:
        artifact_url("../escape", "jar")
    except DiscoveryError:
        pass
    else:
        fail("self-test accepted an escaping coordinate")
    with tempfile.TemporaryDirectory(prefix="rustdesk-flutter-maven-test.") as name:
        root = Path(name)
        validate_private_directory(root)
        pom = root / "engine.pom"
        write_test_file(
            pom,
            (
                '<?xml version="1.0"?><project xmlns="http://maven.apache.org/POM/4.0.0">'
                "<modelVersion>4.0.0</modelVersion><groupId>io.flutter</groupId>"
                "<artifactId>x86_64_release</artifactId>"
                f"<version>{MAVEN_VERSION}</version><packaging>jar</packaging>"
                "<dependencies></dependencies></project>"
            ).encode("ascii"),
        )
        validate_pom(pom, "x86_64_release")
        jar = root / "engine.jar"
        elf = bytearray(20)
        elf[:6] = b"\x7fELF\x02\x01"
        elf[18:20] = (62).to_bytes(2, "little")
        with zipfile.ZipFile(jar, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("lib/x86_64/libflutter.so", bytes(elf))
        os.chmod(jar, 0o400)
        if validate_jar(jar, "x86_64_release") != (1, 20):
            fail("self-test engine JAR validation receipt differs")
    print("FLUTTER_ANDROID_MAVEN_DISCOVERY_SELF_TEST=pass")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--self-test", action="store_true")
    operation.add_argument("--discover", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        if arguments.self_test:
            self_test()
        else:
            receipts = discover()
            if len(receipts) != len(ARTIFACTS) * len(EXTENSIONS):
                fail("Flutter Maven discovery receipt cardinality differs")
            value = {
                "engine_revision": ENGINE_REVISION,
                "maven_version": MAVEN_VERSION,
                "observations": 2,
                "artifacts": [asdict(receipt) for receipt in receipts],
            }
            print(
                "FLUTTER_ANDROID_MAVEN_DISCOVERY="
                + json.dumps(value, sort_keys=True, separators=(",", ":"))
            )
    except DiscoveryError as error:
        print(f"[FATAL] {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
