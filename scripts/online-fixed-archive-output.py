#!/usr/bin/env python3
"""Acquire and transactionally publish exact fixed SHA-256 archive bundles."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import io
import json
import os
import secrets
import stat
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterable, Sequence


FORMAT = "rustdesk-fixed-archive-output-v1"
STATE_NAME = "state.json"
OUTPUT_NAME = "output"
RENAME_NOREPLACE = 1
MAX_STATE_BYTES = 128 * 1024
MAX_REDIRECTS = 5
CHUNK_SIZE = 1024 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 120
SYSTEMD_IMAGE_DOWNLOAD_TIMEOUT_SECONDS = 300
USER_AGENT = "rustdesk-fixed-archive-acquisition/1"


class ContractError(RuntimeError):
    """A fail-closed archive transaction error."""


class MissingPathError(ContractError):
    """A path component is absent, rather than present with unsafe metadata."""


def fail(message: str) -> None:
    raise ContractError(message)


@dataclass(frozen=True)
class ArchiveSpec:
    name: str
    url: str
    size: int
    sha256: str
    redirect_hosts: tuple[str, ...]

    def as_record(self) -> dict[str, object]:
        return {
            "name": self.name,
            "url": self.url,
            "size": self.size,
            "sha256": self.sha256,
            "redirect_hosts": list(self.redirect_hosts),
        }


def checked_identity(value: str, label: str) -> tuple[int, int]:
    parts = value.split(":")
    if len(parts) != 2 or any(not part.isdigit() for part in parts):
        fail(f"{label} is not a canonical device:inode identity")
    identity = (int(parts[0]), int(parts[1]))
    if identity[0] <= 0 or identity[1] <= 0:
        fail(f"{label} contains a zero device or inode")
    return identity


def identity_for_stat(metadata: os.stat_result) -> str:
    return f"{metadata.st_dev}:{metadata.st_ino}"


def descriptor_mount_id(descriptor: int) -> int:
    try:
        with open(
            f"/proc/self/fdinfo/{descriptor}",
            "r",
            encoding="ascii",
            errors="strict",
        ) as handle:
            for line in handle:
                if line.startswith("mnt_id:"):
                    value = line.split(":", 1)[1].strip()
                    if value.isdigit() and int(value) > 0:
                        return int(value)
                    break
    except OSError as exc:
        fail(f"cannot inspect descriptor mount identity: {exc}")
    fail("descriptor mount identity is unavailable")


def open_directory(path: Path) -> int:
    try:
        return os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as exc:
        fail(f"cannot open directory without following links: {path}: {exc}")


def open_child_directory(parent_fd: int, name: str) -> int:
    try:
        return os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
    except FileNotFoundError as exc:
        raise MissingPathError(f"child directory is absent: {name}") from exc
    except OSError as exc:
        fail(f"cannot open child directory without following links: {name}: {exc}")


def ensure_private_directory(
    descriptor: int,
    uid: int,
    gid: int,
    label: str,
    *,
    expected_identity: str | None = None,
    expected_device: int | None = None,
    expected_mount: int | None = None,
) -> os.stat_result:
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        fail(f"{label} is not a directory")
    if (metadata.st_uid, metadata.st_gid) != (uid, gid):
        fail(f"{label} is not owned by the acquisition identity")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        fail(f"{label} is not mode 0700")
    if expected_identity is not None:
        checked_identity(expected_identity, f"{label} recorded identity")
        if identity_for_stat(metadata) != expected_identity:
            fail(f"{label} identity changed")
    if expected_device is not None and metadata.st_dev != expected_device:
        fail(f"{label} is not on the transaction filesystem")
    mount_id = descriptor_mount_id(descriptor)
    if expected_mount is not None and mount_id != expected_mount:
        fail(f"{label} crosses a mount boundary")
    if os.listxattr(descriptor):
        fail(f"{label} has extended attributes")
    return metadata


def validate_name(name: str) -> tuple[str, ...]:
    if not name or len(name) > 180 or name != name.strip():
        fail("archive destination name is empty, padded, or too long")
    try:
        name.encode("ascii")
    except UnicodeEncodeError:
        fail("archive destination name is not ASCII")
    path = Path(name)
    parts = path.parts
    if path.is_absolute() or len(parts) not in (1, 2, 3):
        fail(f"archive destination is not a bounded relative path: {name}")
    for component in parts:
        if (
            component in ("", ".", "..")
            or "/" in component
            or "\x00" in component
            or len(component) > 160
        ):
            fail(f"archive destination has an unsafe component: {name}")
        if not all(char.isalnum() or char in "._+~-" for char in component):
            fail(f"archive destination has a noncanonical component: {name}")
    return parts


def is_debian_systemd_image_name(name: str) -> bool:
    parts = validate_name(name)
    prefix = "debian-12-genericcloud-amd64-"
    suffix = ".qcow2"
    if len(parts) != 1 or not name.startswith(prefix) or not name.endswith(suffix):
        return False
    build = name[len(prefix) : -len(suffix)]
    return (
        len(build) == 13
        and build[8] == "-"
        and build[:8].isdigit()
        and build[9:].isdigit()
    )


def download_timeout_seconds(spec: ArchiveSpec) -> int:
    if is_debian_systemd_image_name(spec.name):
        return SYSTEMD_IMAGE_DOWNLOAD_TIMEOUT_SECONDS
    return DOWNLOAD_TIMEOUT_SECONDS


def validate_manifest_shape(specs: Sequence[ArchiveSpec]) -> None:
    names = tuple(spec.name for spec in specs)
    if len(specs) == 1:
        if not is_debian_systemd_image_name(names[0]):
            fail("the one-entry systemd image manifest has a noncanonical destination")
        return
    if len(specs) == 2:
        if names != (
            "dart-audit-inputs/Pub-all.zip",
            "dart-audit-inputs/osv-scanner",
        ):
            fail("the Dart audit manifest is not the exact two-input rebuild source")
        return
    if len(specs) == 14:
        if any(
            len(validate_name(name)) > 1 and validate_name(name)[0] != "win"
            for name in names
        ):
            fail("the fourteen-entry toolchain manifest has a non-win/ nested path")
        return
    if len(specs) == 6:
        expected = tuple(
            f"wix-nuget-packages/{package}.4.0.5.nupkg"
            for package in (
                "wixtoolset.firewall.wixext",
                "wixtoolset.heat",
                "wixtoolset.netfx.wixext",
                "wixtoolset.sdk",
                "wixtoolset.ui.wixext",
                "wixtoolset.util.wixext",
            )
        )
        if names != expected:
            fail("the WiX manifest is not the exact sorted six-package 4.0.5 source")
        return
    if len(specs) == 33:
        source_names = tuple(
            name
            for name in names
            if len(validate_name(name)) == 2
            and validate_name(name)[0] == "vcpkg-distfiles"
            and validate_name(name)[1].startswith("libvpx-")
            and validate_name(name)[1].endswith(".tar.gz")
        )
        tool_names = tuple(
            name
            for name in names
            if len(validate_name(name)) == 3
            and validate_name(name)[:2] == ("vcpkg-distfiles", "windows-tools")
        )
        if len(source_names) != 1 or len(tool_names) != 32:
            fail(
                "the vcpkg distfile manifest must contain one libvpx archive "
                "and exactly 32 windows-tools/ archives"
            )
        return
    fail(
        "the archive manifest must contain exactly one Debian systemd image, "
        "two Dart audit inputs, six WiX packages, 14 toolchain entries, "
        "or 33 vcpkg distfile entries, "
        f"got {len(specs)}"
    )


def validate_url(url: str, redirect_hosts: tuple[str, ...]) -> None:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        fail(f"archive URL is not a canonical credential-free HTTPS URL: {url}")
    if parsed.hostname.lower() not in redirect_hosts:
        fail(f"archive origin is absent from its redirect-host allowlist: {url}")


def parse_specs(raw_entries: Sequence[Sequence[str]]) -> tuple[ArchiveSpec, ...]:
    specs: list[ArchiveSpec] = []
    names: set[str] = set()
    for raw in raw_entries:
        if len(raw) != 5:
            fail("each archive entry requires NAME URL SIZE SHA256 REDIRECT_HOSTS")
        name, url, size_raw, digest, hosts_raw = raw
        validate_name(name)
        if name in names:
            fail(f"duplicate archive destination: {name}")
        names.add(name)
        if not size_raw.isdigit() or int(size_raw) <= 0 or int(size_raw) > 2_000_000_000:
            fail(f"archive size is invalid or unbounded: {name}")
        if (
            len(digest) != 64
            or digest != digest.lower()
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            fail(f"archive SHA-256 is not canonical: {name}")
        hosts = tuple(host.strip().lower() for host in hosts_raw.split(","))
        if (
            not hosts
            or len(hosts) > 4
            or any(
                not host
                or host != host.strip(".")
                or "/" in host
                or ":" in host
                for host in hosts
            )
            or len(set(hosts)) != len(hosts)
        ):
            fail(f"archive redirect-host allowlist is invalid: {name}")
        validate_url(url, hosts)
        specs.append(ArchiveSpec(name, url, int(size_raw), digest, hosts))
    validate_manifest_shape(specs)
    if tuple(sorted(spec.name for spec in specs)) != tuple(spec.name for spec in specs):
        fail("the fixed archive manifest is not sorted by destination name")
    return tuple(specs)


def specs_from_records(records: object) -> tuple[ArchiveSpec, ...]:
    if not isinstance(records, list):
        fail("transaction archive manifest is not a list")
    entries: list[list[str]] = []
    for record in records:
        if not isinstance(record, dict):
            fail("transaction archive manifest entry is not an object")
        expected = {"name", "url", "size", "sha256", "redirect_hosts"}
        if set(record) != expected:
            fail("transaction archive manifest entry has unexpected fields")
        hosts = record["redirect_hosts"]
        if not isinstance(hosts, list) or any(not isinstance(host, str) for host in hosts):
            fail("transaction redirect-host record is invalid")
        entries.append(
            [
                str(record["name"]),
                str(record["url"]),
                str(record["size"]),
                str(record["sha256"]),
                ",".join(hosts),
            ]
        )
    return parse_specs(entries)


def manifest_digest(specs: Sequence[ArchiveSpec]) -> str:
    payload = json.dumps(
        [spec.as_record() for spec in specs],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def regular_file_sha256(path: Path) -> str:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        fail(f"cannot open exact helper without following links: {path}: {exc}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail(f"exact helper is not one single-link regular file: {path}")
        digest = hashlib.sha256()
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(descriptor, min(CHUNK_SIZE, before.st_size - offset), offset)
            if not chunk:
                fail(f"exact helper ended during hashing: {path}")
            digest.update(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size")
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            fail(f"exact helper changed during hashing: {path}")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def validate_builder_identity(builder_id: str) -> None:
    if (
        not builder_id.startswith("sha256:")
        or len(builder_id) != 71
        or any(char not in "0123456789abcdef" for char in builder_id[7:])
    ):
        fail("archive acquisition builder is not an immutable SHA-256 image ID")


def validate_helper_digest(helper_sha256: str) -> None:
    if (
        len(helper_sha256) != 64
        or helper_sha256 != helper_sha256.lower()
        or any(char not in "0123456789abcdef" for char in helper_sha256)
    ):
        fail("archive acquisition helper digest is not canonical SHA-256")


def stable_file_digest(descriptor: int, expected_size: int) -> str:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
        fail("archive candidate is not an exact-size regular file")
    digest = hashlib.sha256()
    offset = 0
    while offset < expected_size:
        chunk = os.pread(descriptor, min(CHUNK_SIZE, expected_size - offset), offset)
        if not chunk:
            fail("archive candidate ended before its recorded length")
        digest.update(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, expected_size):
        fail("archive candidate grew beyond its recorded length")
    after = os.fstat(descriptor)
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_uid",
        "st_gid",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
        fail("archive candidate changed during validation")
    return digest.hexdigest()


def open_parent(
    root_fd: int,
    parts: Sequence[str],
    uid: int,
    gid: int,
    *,
    create: bool,
    candidate: bool,
) -> int:
    descriptor = os.dup(root_fd)
    root_metadata = os.fstat(root_fd)
    root_mount = descriptor_mount_id(root_fd)
    try:
        for component in parts:
            try:
                child = open_child_directory(descriptor, component)
            except MissingPathError:
                if not create:
                    raise
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                    os.fsync(descriptor)
                except OSError as exc:
                    fail(f"cannot create archive destination directory {component}: {exc}")
                child = open_child_directory(descriptor, component)
            metadata = os.fstat(child)
            if (metadata.st_uid, metadata.st_gid) != (uid, gid):
                os.close(child)
                fail(f"archive destination directory has foreign ownership: {component}")
            mode = stat.S_IMODE(metadata.st_mode)
            admitted_modes = {0o700} if candidate else {0o700, 0o755, 0o775}
            if mode not in admitted_modes:
                os.close(child)
                fail(f"archive destination directory has an unsafe mode: {component}")
            if metadata.st_dev != root_metadata.st_dev or descriptor_mount_id(child) != root_mount:
                os.close(child)
                fail(f"archive destination directory crosses a filesystem or mount: {component}")
            if os.listxattr(child):
                os.close(child)
                fail(f"archive destination directory has extended attributes: {component}")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def validate_archive_at(
    root_fd: int,
    spec: ArchiveSpec,
    uid: int,
    gid: int,
    *,
    candidate: bool,
) -> bool:
    parts = validate_name(spec.name)
    try:
        parent_fd = open_parent(
            root_fd,
            parts[:-1],
            uid,
            gid,
            create=False,
            candidate=candidate,
        )
    except MissingPathError:
        return False
    try:
        try:
            descriptor = os.open(
                parts[-1],
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            return False
        except OSError as exc:
            fail(f"cannot open archive without following links: {spec.name}: {exc}")
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                fail(f"archive is not one single-link regular file: {spec.name}")
            root_metadata = os.fstat(root_fd)
            if (
                metadata.st_dev != root_metadata.st_dev
                or descriptor_mount_id(descriptor) != descriptor_mount_id(root_fd)
            ):
                fail(f"archive crosses a filesystem or mount boundary: {spec.name}")
            mode = stat.S_IMODE(metadata.st_mode)
            if candidate:
                if (metadata.st_uid, metadata.st_gid, mode) != (uid, gid, 0o400):
                    fail(f"archive candidate metadata is not current-owner mode 0400: {spec.name}")
            else:
                if is_debian_systemd_image_name(spec.name):
                    current_profiles = {
                        (uid, gid, 0o400),
                        (uid, gid, 0o444),
                    }
                    root_profiles: set[tuple[int, int, int]] = set()
                else:
                    current_profiles = {
                        (uid, gid, 0o400),
                        (uid, gid, 0o444),
                        (uid, gid, 0o644),
                        (uid, gid, 0o664),
                    }
                    root_profiles = {(0, 0, 0o444), (0, 0, 0o644)}
                if (metadata.st_uid, metadata.st_gid, mode) not in current_profiles | root_profiles:
                    fail(f"published archive metadata is outside the closed profiles: {spec.name}")
            if os.listxattr(descriptor):
                fail(f"archive has extended attributes: {spec.name}")
            digest = stable_file_digest(descriptor, spec.size)
            if digest != spec.sha256:
                fail(f"archive SHA-256 mismatch: {spec.name}")
        finally:
            os.close(descriptor)
        return True
    finally:
        os.close(parent_fd)


def scan_candidate_tree(
    root_fd: int,
    uid: int,
    gid: int,
    prefix: tuple[str, ...] = (),
) -> tuple[set[str], set[str]]:
    directories: set[str] = set()
    files: set[str] = set()
    root_metadata = os.fstat(root_fd)
    root_mount = descriptor_mount_id(root_fd)
    with os.scandir(root_fd) as iterator:
        entries = sorted(iterator, key=lambda entry: entry.name)
    for entry in entries:
        parts = prefix + (entry.name,)
        name = "/".join(parts)
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as exc:
            fail(f"cannot inspect archive candidate entry {name}: {exc}")
        if stat.S_ISDIR(metadata.st_mode):
            child = open_child_directory(root_fd, entry.name)
            try:
                child_metadata = os.fstat(child)
                if (
                    (child_metadata.st_uid, child_metadata.st_gid) != (uid, gid)
                    or stat.S_IMODE(child_metadata.st_mode) != 0o700
                    or child_metadata.st_dev != root_metadata.st_dev
                    or descriptor_mount_id(child) != root_mount
                    or os.listxattr(child)
                ):
                    fail(f"archive candidate directory metadata is invalid: {name}")
                directories.add(name)
                child_dirs, child_files = scan_candidate_tree(child, uid, gid, parts)
                directories.update(child_dirs)
                files.update(child_files)
            finally:
                os.close(child)
        elif stat.S_ISREG(metadata.st_mode):
            files.add(name)
        else:
            fail(f"archive candidate contains a non-file/non-directory entry: {name}")
    return directories, files


def validate_candidate_tree(
    output: Path,
    specs: Sequence[ArchiveSpec],
    uid: int,
    gid: int,
    expected_identity: str,
) -> None:
    output_fd = open_directory(output)
    try:
        metadata = ensure_private_directory(
            output_fd,
            uid,
            gid,
            "archive output",
            expected_identity=expected_identity,
        )
        directories, files = scan_candidate_tree(output_fd, uid, gid)
        expected_files = {spec.name for spec in specs}
        expected_directories = {
            "/".join(parts[:depth])
            for spec in specs
            for parts in (validate_name(spec.name),)
            for depth in range(1, len(parts))
        }
        if files != expected_files or directories != expected_directories:
            fail("archive candidate inventory differs from the transaction manifest")
        for spec in specs:
            if not validate_archive_at(output_fd, spec, uid, gid, candidate=True):
                fail(f"archive candidate is missing: {spec.name}")
        if os.fstat(output_fd).st_dev != metadata.st_dev:
            fail("archive output filesystem changed during validation")
    finally:
        os.close(output_fd)


def validate_publication_layout(
    online: Path,
    output: Path,
    missing: Sequence[ArchiveSpec],
    published_names: set[str],
    uid: int,
    gid: int,
    output_identity: str,
) -> None:
    output_fd = open_directory(output)
    online_fd = open_directory(online)
    try:
        ensure_private_directory(
            output_fd,
            uid,
            gid,
            "archive output",
            expected_identity=output_identity,
        )
        directories, files = scan_candidate_tree(output_fd, uid, gid)
        expected_names = {spec.name for spec in missing}
        expected_directories = {
            "/".join(parts[:depth])
            for spec in missing
            for parts in (validate_name(spec.name),)
            for depth in range(1, len(parts))
        }
        if (
            not files.issubset(expected_names)
            or not directories.issubset(expected_directories)
        ):
            fail("archive publication staging contains an unowned entry")
        for spec in missing:
            source_present = validate_archive_at(
                output_fd, spec, uid, gid, candidate=True
            )
            destination_present = validate_archive_at(
                online_fd, spec, uid, gid, candidate=False
            )
            if spec.name in published_names:
                if source_present or not destination_present:
                    fail(f"recorded archive publication is incoherent: {spec.name}")
            elif not source_present and not destination_present:
                fail(f"archive is absent from both publication namespaces: {spec.name}")
    finally:
        os.close(online_fd)
        os.close(output_fd)


class BoundedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: Iterable[str]) -> None:
        super().__init__()
        self.allowed_hosts = frozenset(host.lower() for host in allowed_hosts)
        self.redirects = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        self.redirects += 1
        if self.redirects > MAX_REDIRECTS:
            raise urllib.error.HTTPError(
                req.full_url, code, "too many redirects", headers, fp
            )
        parsed = urllib.parse.urlsplit(newurl)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.hostname.lower() not in self.allowed_hosts
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise urllib.error.HTTPError(
                req.full_url, code, "redirect left the HTTPS host allowlist", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_opener(spec: ArchiveSpec):
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        BoundedRedirectHandler(spec.redirect_hosts),
    )


def download_archive(
    output_fd: int,
    spec: ArchiveSpec,
    opener,
) -> None:
    parts = validate_name(spec.name)
    parent_fd = open_parent(
        output_fd,
        parts[:-1],
        os.geteuid(),
        os.getegid(),
        create=True,
        candidate=True,
    )
    descriptor = -1
    try:
        try:
            descriptor = os.open(
                parts[-1],
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
        except OSError as exc:
            fail(f"cannot exclusively create archive candidate {spec.name}: {exc}")
        request = urllib.request.Request(
            spec.url,
            headers={
                "Accept-Encoding": "identity",
                "User-Agent": USER_AGENT,
            },
            method="GET",
        )
        digest = hashlib.sha256()
        total = 0
        try:
            with opener.open(
                request,
                timeout=download_timeout_seconds(spec),
            ) as response:
                if getattr(response, "status", None) != 200:
                    fail(f"archive response status is not 200: {spec.name}")
                final_url = urllib.parse.urlsplit(response.geturl())
                if (
                    final_url.scheme != "https"
                    or not final_url.hostname
                    or final_url.hostname.lower() not in spec.redirect_hosts
                ):
                    fail(f"archive final URL left the HTTPS host allowlist: {spec.name}")
                encoding = response.headers.get("Content-Encoding")
                if encoding not in (None, "", "identity"):
                    fail(f"archive response used transformed content: {spec.name}")
                length = response.headers.get("Content-Length")
                transfer_encoding = response.headers.get("Transfer-Encoding")
                if length is None:
                    if (
                        transfer_encoding is None
                        or transfer_encoding.strip().lower() != "chunked"
                    ):
                        fail(f"archive response has no admitted length framing: {spec.name}")
                elif (
                    transfer_encoding is not None
                    or not length.isdigit()
                    or int(length) != spec.size
                ):
                    fail(f"archive response length differs from the pin: {spec.name}")
                while True:
                    chunk = response.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > spec.size:
                        fail(f"archive response exceeded its pinned length: {spec.name}")
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            fail(f"archive output write made no progress: {spec.name}")
                        view = view[written:]
        except ContractError:
            raise
        except (OSError, urllib.error.URLError) as exc:
            fail(f"archive download failed: {spec.name}: {exc}")
        if total != spec.size or digest.hexdigest() != spec.sha256:
            fail(f"archive response bytes differ from the exact pin: {spec.name}")
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        os.fsync(parent_fd)
    except Exception as primary_error:
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
        try:
            os.unlink(parts[-1], dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileNotFoundError:
            pass
        except OSError as cleanup_error:
            raise ContractError(
                f"cannot remove failed archive candidate {spec.name}: {cleanup_error}"
            ) from primary_error
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


def read_state(staging: Path) -> dict[str, object]:
    staging_fd = open_directory(staging)
    try:
        try:
            descriptor = os.open(
                STATE_NAME,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=staging_fd,
            )
        except OSError as exc:
            fail(f"cannot open archive transaction state: {exc}")
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size <= 0
                or metadata.st_size > MAX_STATE_BYTES
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                fail("archive transaction state metadata is invalid")
            payload = b""
            while len(payload) <= MAX_STATE_BYTES:
                chunk = os.read(descriptor, min(8192, MAX_STATE_BYTES + 1 - len(payload)))
                if not chunk:
                    break
                payload += chunk
            if len(payload) > MAX_STATE_BYTES:
                fail("archive transaction state is oversized")
        finally:
            os.close(descriptor)
    finally:
        os.close(staging_fd)
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"archive transaction state is malformed: {exc}")
    if not isinstance(value, dict):
        fail("archive transaction state is not an object")
    return value


def write_state(staging: Path, state: dict[str, object]) -> None:
    payload = (
        json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if len(payload) > MAX_STATE_BYTES:
        fail("archive transaction state exceeds its fixed bound")
    staging_fd = open_directory(staging)
    temporary = f".state.{secrets.token_hex(8)}"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=staging_fd,
        )
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                fail("archive transaction state write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.rename(temporary, STATE_NAME, src_dir_fd=staging_fd, dst_dir_fd=staging_fd)
        os.fsync(staging_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=staging_fd)
        except FileNotFoundError:
            pass
        os.close(staging_fd)


def validate_state(
    state: dict[str, object],
    online: Path,
    staging: Path,
    specs: Sequence[ArchiveSpec],
    uid: int,
    gid: int,
    builder_id: str,
    helper_sha256: str,
) -> tuple[tuple[ArchiveSpec, ...], str]:
    expected_fields = {
        "format",
        "online",
        "staging",
        "output",
        "uid",
        "gid",
        "manifest_sha256",
        "builder_id",
        "helper_sha256",
        "archives",
        "missing",
        "phase",
        "published",
    }
    if set(state) != expected_fields or state.get("format") != FORMAT:
        fail("archive transaction state fields or format are invalid")
    if state.get("uid") != uid or state.get("gid") != gid or uid == 0 or gid == 0:
        fail("archive transaction identity is invalid")
    validate_builder_identity(builder_id)
    validate_helper_digest(helper_sha256)
    if (
        state.get("builder_id") != builder_id
        or state.get("helper_sha256") != helper_sha256
    ):
        fail("archive transaction executable inputs differ from current source")
    recorded_specs = specs_from_records(state.get("archives"))
    if recorded_specs != tuple(specs) or state.get("manifest_sha256") != manifest_digest(specs):
        fail("archive transaction manifest differs from current source pins")
    online_fd = open_directory(online)
    staging_fd = open_directory(staging)
    output_fd = open_child_directory(staging_fd, OUTPUT_NAME)
    try:
        online_metadata = ensure_private_directory(
            online_fd,
            uid,
            gid,
            "online root",
            expected_identity=str(state.get("online")),
        )
        ensure_private_directory(
            staging_fd,
            uid,
            gid,
            "archive staging",
            expected_identity=str(state.get("staging")),
            expected_device=online_metadata.st_dev,
            expected_mount=descriptor_mount_id(online_fd),
        )
        ensure_private_directory(
            output_fd,
            uid,
            gid,
            "archive output",
            expected_identity=str(state.get("output")),
            expected_device=online_metadata.st_dev,
            expected_mount=descriptor_mount_id(online_fd),
        )
    finally:
        os.close(output_fd)
        os.close(staging_fd)
        os.close(online_fd)
    missing_raw = state.get("missing")
    if (
        not isinstance(missing_raw, list)
        or any(not isinstance(name, str) for name in missing_raw)
        or len(set(missing_raw)) != len(missing_raw)
    ):
        fail("archive transaction missing-list is invalid")
    by_name = {spec.name: spec for spec in specs}
    if any(name not in by_name for name in missing_raw):
        fail("archive transaction missing-list names an unknown archive")
    missing = tuple(by_name[name] for name in missing_raw)
    published = state.get("published")
    if (
        not isinstance(published, list)
        or any(not isinstance(name, str) for name in published)
        or len(set(published)) != len(published)
        or any(name not in missing_raw for name in published)
    ):
        fail("archive transaction published-list is invalid")
    phase = state.get("phase")
    if phase not in {"prepared", "verified", "publishing", "complete"}:
        fail("archive transaction phase is invalid")
    return missing, str(phase)


def prepare_transaction(
    online: Path,
    staging: Path,
    specs: Sequence[ArchiveSpec],
    uid: int,
    gid: int,
    builder_id: str,
    helper_sha256: str,
) -> str:
    if uid == 0 or gid == 0 or (os.geteuid(), os.getegid()) != (uid, gid):
        fail("archive transaction refuses root or a mismatched host identity")
    validate_builder_identity(builder_id)
    validate_helper_digest(helper_sha256)
    online_fd = open_directory(online)
    staging_fd = open_directory(staging)
    try:
        online_metadata = ensure_private_directory(online_fd, uid, gid, "online root")
        ensure_private_directory(
            staging_fd,
            uid,
            gid,
            "archive staging",
            expected_device=online_metadata.st_dev,
            expected_mount=descriptor_mount_id(online_fd),
        )
        missing: list[str] = []
        for spec in specs:
            if not validate_archive_at(online_fd, spec, uid, gid, candidate=False):
                missing.append(spec.name)
        try:
            os.mkdir(OUTPUT_NAME, 0o700, dir_fd=staging_fd)
            os.fsync(staging_fd)
        except OSError as exc:
            fail(f"cannot create archive transaction output: {exc}")
        output_fd = open_child_directory(staging_fd, OUTPUT_NAME)
        try:
            output_metadata = ensure_private_directory(
                output_fd,
                uid,
                gid,
                "archive output",
                expected_device=online_metadata.st_dev,
                expected_mount=descriptor_mount_id(online_fd),
            )
        finally:
            os.close(output_fd)
        state: dict[str, object] = {
            "format": FORMAT,
            "online": identity_for_stat(online_metadata),
            "staging": identity_for_stat(os.fstat(staging_fd)),
            "output": identity_for_stat(output_metadata),
            "uid": uid,
            "gid": gid,
            "manifest_sha256": manifest_digest(specs),
            "builder_id": builder_id,
            "helper_sha256": helper_sha256,
            "archives": [spec.as_record() for spec in specs],
            "missing": missing,
            "phase": "prepared" if missing else "complete",
            "published": [],
        }
    finally:
        os.close(staging_fd)
        os.close(online_fd)
    write_state(staging, state)
    return "acquire" if missing else "complete"


def acquire_transaction(
    state_path: Path,
    output: Path,
    builder_id: str,
    helper_sha256: str,
) -> None:
    if os.geteuid() == 0 or os.getegid() == 0:
        fail("archive acquisition refuses root UID or GID")
    state = read_state(state_path.parent)
    validate_builder_identity(builder_id)
    validate_helper_digest(helper_sha256)
    if (
        state.get("builder_id") != builder_id
        or state.get("helper_sha256") != helper_sha256
        or regular_file_sha256(Path(__file__)) != helper_sha256
    ):
        fail("archive acquisition executable inputs differ from the transaction")
    specs = specs_from_records(state.get("archives"))
    missing_names = state.get("missing")
    if not isinstance(missing_names, list):
        fail("archive acquisition plan has no canonical missing-list")
    by_name = {spec.name: spec for spec in specs}
    missing = tuple(by_name[str(name)] for name in missing_names)
    if state.get("phase") != "prepared" or not missing:
        fail("archive acquisition requires one nonempty prepared transaction")
    if state.get("uid") != os.geteuid() or state.get("gid") != os.getegid():
        fail("archive acquisition identity differs from the transaction")
    output_fd = open_directory(output)
    try:
        ensure_private_directory(
            output_fd,
            os.geteuid(),
            os.getegid(),
            "archive output",
            expected_identity=str(state.get("output")),
        )
        directories, files = scan_candidate_tree(output_fd, os.geteuid(), os.getegid())
        if directories or files:
            fail("archive acquisition output is not initially empty")
        for spec in missing:
            download_archive(output_fd, spec, build_opener(spec))
        os.fsync(output_fd)
    finally:
        os.close(output_fd)
    validate_candidate_tree(
        output,
        missing,
        os.geteuid(),
        os.getegid(),
        str(state.get("output")),
    )


def verify_transaction(
    online: Path,
    staging: Path,
    specs: Sequence[ArchiveSpec],
    uid: int,
    gid: int,
    builder_id: str,
    helper_sha256: str,
) -> None:
    state = read_state(staging)
    missing, phase = validate_state(
        state, online, staging, specs, uid, gid, builder_id, helper_sha256
    )
    if phase != "prepared" or not missing:
        fail("archive output verification requires a nonempty prepared transaction")
    validate_candidate_tree(
        staging / OUTPUT_NAME,
        missing,
        uid,
        gid,
        str(state.get("output")),
    )
    state["phase"] = "verified"
    write_state(staging, state)


def renameat2(
    source_fd: int,
    source_name: str,
    destination_fd: int,
    destination_name: str,
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
        source_fd,
        os.fsencode(source_name),
        destination_fd,
        os.fsencode(destination_name),
        flags,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def publish_transaction(
    online: Path,
    staging: Path,
    specs: Sequence[ArchiveSpec],
    uid: int,
    gid: int,
    builder_id: str,
    helper_sha256: str,
) -> None:
    state = read_state(staging)
    missing, phase = validate_state(
        state, online, staging, specs, uid, gid, builder_id, helper_sha256
    )
    if phase not in {"verified", "publishing", "complete"}:
        fail("archive publication requires a verified transaction")
    if phase == "complete":
        online_fd = open_directory(online)
        try:
            for spec in specs:
                if not validate_archive_at(online_fd, spec, uid, gid, candidate=False):
                    fail(f"completed archive transaction lost {spec.name}")
        finally:
            os.close(online_fd)
        return
    validate_publication_layout(
        online,
        staging / OUTPUT_NAME,
        missing,
        set(state["published"]),
        uid,
        gid,
        str(state.get("output")),
    )
    state["phase"] = "publishing"
    write_state(staging, state)
    online_fd = open_directory(online)
    output_fd = open_directory(staging / OUTPUT_NAME)
    try:
        for spec in missing:
            published = set(state["published"])
            parts = validate_name(spec.name)
            if spec.name in published:
                if not validate_archive_at(online_fd, spec, uid, gid, candidate=False):
                    fail(f"published archive changed during transaction: {spec.name}")
                continue
            source_parent = open_parent(
                output_fd,
                parts[:-1],
                uid,
                gid,
                create=False,
                candidate=True,
            )
            destination_parent = open_parent(
                online_fd,
                parts[:-1],
                uid,
                gid,
                create=True,
                candidate=False,
            )
            try:
                source_present = validate_archive_at(
                    output_fd, spec, uid, gid, candidate=True
                )
                destination_present = validate_archive_at(
                    online_fd, spec, uid, gid, candidate=False
                )
                if not source_present and not destination_present:
                    fail(f"archive exists in neither transaction namespace: {spec.name}")
                if source_present and not destination_present:
                    try:
                        renameat2(
                            source_parent,
                            parts[-1],
                            destination_parent,
                            parts[-1],
                            RENAME_NOREPLACE,
                        )
                    except OSError as exc:
                        if exc.errno != errno.EEXIST:
                            fail(f"archive no-clobber publication failed: {spec.name}: {exc}")
                    os.fsync(source_parent)
                    os.fsync(destination_parent)
                if validate_archive_at(output_fd, spec, uid, gid, candidate=True):
                    if not validate_archive_at(online_fd, spec, uid, gid, candidate=False):
                        fail(f"archive destination race was not byte-identical: {spec.name}")
                    os.unlink(parts[-1], dir_fd=source_parent)
                    os.fsync(source_parent)
                if not validate_archive_at(online_fd, spec, uid, gid, candidate=False):
                    fail(f"archive post-publication check failed: {spec.name}")
            finally:
                os.close(destination_parent)
                os.close(source_parent)
            state["published"] = list(state["published"]) + [spec.name]
            write_state(staging, state)
        os.fsync(output_fd)
        os.fsync(online_fd)
        for spec in specs:
            if not validate_archive_at(online_fd, spec, uid, gid, candidate=False):
                fail(f"archive bundle is incomplete after publication: {spec.name}")
    finally:
        os.close(output_fd)
        os.close(online_fd)
    state["phase"] = "complete"
    write_state(staging, state)


def reconcile_transaction(
    online: Path,
    staging: Path,
    specs: Sequence[ArchiveSpec],
    uid: int,
    gid: int,
    builder_id: str,
    helper_sha256: str,
) -> None:
    state = read_state(staging)
    missing, phase = validate_state(
        state, online, staging, specs, uid, gid, builder_id, helper_sha256
    )
    if phase == "prepared":
        if state["published"]:
            fail("an unverified archive transaction claims published output")
        online_fd = open_directory(online)
        try:
            for spec in specs:
                present = validate_archive_at(online_fd, spec, uid, gid, candidate=False)
                if spec.name not in {item.name for item in missing} and not present:
                    fail(f"archive existing at prepare time disappeared: {spec.name}")
        finally:
            os.close(online_fd)
        return
    publish_transaction(
        online, staging, specs, uid, gid, builder_id, helper_sha256
    )


class FakeResponse(io.BytesIO):
    def __init__(
        self,
        payload: bytes,
        url: str,
        *,
        length: str | None = None,
        chunked: bool = False,
        unframed: bool = False,
    ) -> None:
        super().__init__(payload)
        self.status = 200
        self._url = url
        self.headers = {"Content-Encoding": "identity"}
        if chunked and unframed:
            fail("fake response cannot be both chunked and unframed")
        if chunked:
            self.headers["Transfer-Encoding"] = "chunked"
        elif not unframed:
            self.headers["Content-Length"] = (
                str(len(payload)) if length is None else length
            )

    def geturl(self) -> str:
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


class FakeOpener:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response

    def open(self, request, timeout=0):  # noqa: ARG002
        return self.response


def test_specs() -> tuple[ArchiveSpec, ...]:
    records: list[list[str]] = []
    for index in range(14):
        name = f"archive-{index:02d}.bin" if index < 13 else "win/archive-13.bin"
        payload = f"payload-{index}".encode("ascii")
        records.append(
            [
                name,
                f"https://example.invalid/{name}",
                str(len(payload)),
                hashlib.sha256(payload).hexdigest(),
                "example.invalid",
            ]
        )
    return parse_specs(records)


def test_vcpkg_specs() -> tuple[ArchiveSpec, ...]:
    records: list[list[str]] = []
    for index in range(33):
        if index == 0:
            name = "vcpkg-distfiles/libvpx-v1.2.3.tar.gz"
        elif index == 1:
            name = (
                "vcpkg-distfiles/windows-tools/"
                "mingw-w64-x86_64-pkgconf-1~2.4.3-1-any.pkg.tar.zst"
            )
        else:
            name = f"vcpkg-distfiles/windows-tools/tool-{index:02d}.bin"
        payload = f"vcpkg-payload-{index}".encode("ascii")
        records.append(
            [
                name,
                f"https://example.invalid/{name}",
                str(len(payload)),
                hashlib.sha256(payload).hexdigest(),
                "example.invalid",
            ]
        )
    return parse_specs(records)


def test_wix_specs() -> tuple[ArchiveSpec, ...]:
    records: list[list[str]] = []
    for package in (
        "wixtoolset.firewall.wixext",
        "wixtoolset.heat",
        "wixtoolset.netfx.wixext",
        "wixtoolset.sdk",
        "wixtoolset.ui.wixext",
        "wixtoolset.util.wixext",
    ):
        name = f"wix-nuget-packages/{package}.4.0.5.nupkg"
        payload = f"wix-payload-{package}".encode("ascii")
        records.append(
            [
                name,
                f"https://example.invalid/{name}",
                str(len(payload)),
                hashlib.sha256(payload).hexdigest(),
                "example.invalid",
            ]
        )
    return parse_specs(records)


def test_systemd_image_specs() -> tuple[ArchiveSpec, ...]:
    name = "debian-12-genericcloud-amd64-20260712-2537.qcow2"
    payload = b"systemd-image-fixture"
    return parse_specs(
        [
            [
                name,
                f"https://example.invalid/{name}",
                str(len(payload)),
                hashlib.sha256(payload).hexdigest(),
                "example.invalid",
            ]
        ]
    )


def test_dart_audit_specs() -> tuple[ArchiveSpec, ...]:
    records: list[list[str]] = []
    for name, payload in (
        ("dart-audit-inputs/Pub-all.zip", b"dart-database-fixture"),
        ("dart-audit-inputs/osv-scanner", b"dart-scanner-fixture"),
    ):
        records.append(
            [
                name,
                f"https://example.invalid/{name}",
                str(len(payload)),
                hashlib.sha256(payload).hexdigest(),
                "example.invalid",
            ]
        )
    return parse_specs(records)


def self_test() -> None:
    uid = os.geteuid()
    gid = os.getegid()
    if uid == 0 or gid == 0:
        fail("self-test refuses root UID or GID")
    specs = test_specs()
    builder_id = "sha256:" + ("a" * 64)
    helper_sha256 = regular_file_sha256(Path(__file__))
    with tempfile.TemporaryDirectory(prefix="fixed-archive-self-test.") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        online = root / "online"
        staging = root / "staging"
        online.mkdir(mode=0o700)
        staging.mkdir(mode=0o700)
        if (
            prepare_transaction(
                online,
                staging,
                specs,
                uid,
                gid,
                builder_id,
                helper_sha256,
            )
            != "acquire"
        ):
            fail("self-test transaction unexpectedly reused output")
        state = read_state(staging)
        output = staging / OUTPUT_NAME
        output_fd = open_directory(output)
        try:
            for index, spec in enumerate(specs):
                payload = f"payload-{index}".encode("ascii")
                download_archive(
                    output_fd,
                    spec,
                    FakeOpener(FakeResponse(payload, spec.url)),
                )
        finally:
            os.close(output_fd)
        validate_candidate_tree(output, specs, uid, gid, str(state["output"]))
        verify_transaction(
            online, staging, specs, uid, gid, builder_id, helper_sha256
        )
        first = specs[0]
        output_fd = open_directory(output)
        online_fd = open_directory(online)
        source_parent = open_parent(
            output_fd, (), uid, gid, create=False, candidate=True
        )
        destination_parent = open_parent(
            online_fd, (), uid, gid, create=False, candidate=False
        )
        try:
            renameat2(
                source_parent,
                first.name,
                destination_parent,
                first.name,
                RENAME_NOREPLACE,
            )
            os.fsync(source_parent)
            os.fsync(destination_parent)
        finally:
            os.close(destination_parent)
            os.close(source_parent)
            os.close(online_fd)
            os.close(output_fd)
        publish_transaction(
            online, staging, specs, uid, gid, builder_id, helper_sha256
        )
        publish_transaction(
            online, staging, specs, uid, gid, builder_id, helper_sha256
        )
        online_fd = open_directory(online)
        try:
            for spec in specs:
                if not validate_archive_at(online_fd, spec, uid, gid, candidate=False):
                    fail("self-test publication omitted an archive")
        finally:
            os.close(online_fd)

        vcpkg_specs = test_vcpkg_specs()
        vcpkg_online = root / "vcpkg-online"
        vcpkg_staging = root / "vcpkg-staging"
        vcpkg_online.mkdir(mode=0o700)
        vcpkg_staging.mkdir(mode=0o700)
        if (
            prepare_transaction(
                vcpkg_online,
                vcpkg_staging,
                vcpkg_specs,
                uid,
                gid,
                builder_id,
                helper_sha256,
            )
            != "acquire"
        ):
            fail("vcpkg self-test transaction unexpectedly reused output")
        vcpkg_state = read_state(vcpkg_staging)
        vcpkg_output = vcpkg_staging / OUTPUT_NAME
        vcpkg_output_fd = open_directory(vcpkg_output)
        try:
            for index, spec in enumerate(vcpkg_specs):
                payload = f"vcpkg-payload-{index}".encode("ascii")
                download_archive(
                    vcpkg_output_fd,
                    spec,
                    FakeOpener(FakeResponse(payload, spec.url)),
                )
        finally:
            os.close(vcpkg_output_fd)
        validate_candidate_tree(
            vcpkg_output,
            vcpkg_specs,
            uid,
            gid,
            str(vcpkg_state["output"]),
        )
        verify_transaction(
            vcpkg_online,
            vcpkg_staging,
            vcpkg_specs,
            uid,
            gid,
            builder_id,
            helper_sha256,
        )
        publish_transaction(
            vcpkg_online,
            vcpkg_staging,
            vcpkg_specs,
            uid,
            gid,
            builder_id,
            helper_sha256,
        )
        vcpkg_online_fd = open_directory(vcpkg_online)
        try:
            for spec in vcpkg_specs:
                if not validate_archive_at(
                    vcpkg_online_fd, spec, uid, gid, candidate=False
                ):
                    fail("vcpkg self-test publication omitted an archive")
        finally:
            os.close(vcpkg_online_fd)

        wix_specs = test_wix_specs()
        wix_online = root / "wix-online"
        wix_staging = root / "wix-staging"
        wix_online.mkdir(mode=0o700)
        wix_staging.mkdir(mode=0o700)
        if (
            prepare_transaction(
                wix_online,
                wix_staging,
                wix_specs,
                uid,
                gid,
                builder_id,
                helper_sha256,
            )
            != "acquire"
        ):
            fail("WiX self-test transaction unexpectedly reused output")
        wix_state = read_state(wix_staging)
        wix_output = wix_staging / OUTPUT_NAME
        wix_output_fd = open_directory(wix_output)
        try:
            for package, spec in zip(
                (
                    "wixtoolset.firewall.wixext",
                    "wixtoolset.heat",
                    "wixtoolset.netfx.wixext",
                    "wixtoolset.sdk",
                    "wixtoolset.ui.wixext",
                    "wixtoolset.util.wixext",
                ),
                wix_specs,
                strict=True,
            ):
                payload = f"wix-payload-{package}".encode("ascii")
                download_archive(
                    wix_output_fd,
                    spec,
                    FakeOpener(FakeResponse(payload, spec.url)),
                )
        finally:
            os.close(wix_output_fd)
        validate_candidate_tree(
            wix_output,
            wix_specs,
            uid,
            gid,
            str(wix_state["output"]),
        )
        verify_transaction(
            wix_online,
            wix_staging,
            wix_specs,
            uid,
            gid,
            builder_id,
            helper_sha256,
        )
        publish_transaction(
            wix_online,
            wix_staging,
            wix_specs,
            uid,
            gid,
            builder_id,
            helper_sha256,
        )
        wix_online_fd = open_directory(wix_online)
        try:
            for spec in wix_specs:
                if not validate_archive_at(
                    wix_online_fd, spec, uid, gid, candidate=False
                ):
                    fail("WiX self-test publication omitted a package")
        finally:
            os.close(wix_online_fd)

        systemd_specs = test_systemd_image_specs()
        if download_timeout_seconds(systemd_specs[0]) != 300:
            fail("systemd-image self-test lost its bounded large-image timeout")
        if download_timeout_seconds(specs[0]) != 120:
            fail("archive self-test widened the ordinary download timeout")
        systemd_online = root / "systemd-online"
        systemd_staging = root / "systemd-staging"
        systemd_online.mkdir(mode=0o700)
        systemd_staging.mkdir(mode=0o700)
        if (
            prepare_transaction(
                systemd_online,
                systemd_staging,
                systemd_specs,
                uid,
                gid,
                builder_id,
                helper_sha256,
            )
            != "acquire"
        ):
            fail("systemd-image self-test transaction unexpectedly reused output")
        systemd_state = read_state(systemd_staging)
        systemd_output = systemd_staging / OUTPUT_NAME
        systemd_output_fd = open_directory(systemd_output)
        try:
            spec = systemd_specs[0]
            download_archive(
                systemd_output_fd,
                spec,
                FakeOpener(FakeResponse(b"systemd-image-fixture", spec.url)),
            )
        finally:
            os.close(systemd_output_fd)
        validate_candidate_tree(
            systemd_output,
            systemd_specs,
            uid,
            gid,
            str(systemd_state["output"]),
        )
        verify_transaction(
            systemd_online,
            systemd_staging,
            systemd_specs,
            uid,
            gid,
            builder_id,
            helper_sha256,
        )
        publish_transaction(
            systemd_online,
            systemd_staging,
            systemd_specs,
            uid,
            gid,
            builder_id,
            helper_sha256,
        )
        systemd_online_fd = open_directory(systemd_online)
        try:
            if not validate_archive_at(
                systemd_online_fd,
                systemd_specs[0],
                uid,
                gid,
                candidate=False,
            ):
                fail("systemd-image self-test publication omitted its image")
        finally:
            os.close(systemd_online_fd)
        systemd_final = systemd_online / systemd_specs[0].name
        os.chmod(systemd_final, 0o444)
        systemd_reuse_staging = root / "systemd-reuse-staging"
        systemd_reuse_staging.mkdir(mode=0o700)
        if (
            prepare_transaction(
                systemd_online,
                systemd_reuse_staging,
                systemd_specs,
                uid,
                gid,
                builder_id,
                helper_sha256,
            )
            != "complete"
        ):
            fail("systemd-image self-test rejected historical mode-0444 output")
        os.chmod(systemd_final, 0o644)
        systemd_unsafe_staging = root / "systemd-unsafe-staging"
        systemd_unsafe_staging.mkdir(mode=0o700)
        try:
            prepare_transaction(
                systemd_online,
                systemd_unsafe_staging,
                systemd_specs,
                uid,
                gid,
                builder_id,
                helper_sha256,
            )
        except ContractError:
            pass
        else:
            fail("systemd-image self-test accepted writable published output")
        os.chmod(systemd_final, 0o400)

        dart_specs = test_dart_audit_specs()
        dart_online = root / "dart-online"
        dart_staging = root / "dart-staging"
        dart_online.mkdir(mode=0o700)
        dart_staging.mkdir(mode=0o700)
        if (
            prepare_transaction(
                dart_online,
                dart_staging,
                dart_specs,
                uid,
                gid,
                builder_id,
                helper_sha256,
            )
            != "acquire"
        ):
            fail("Dart-audit self-test transaction unexpectedly reused output")
        dart_state = read_state(dart_staging)
        dart_output = dart_staging / OUTPUT_NAME
        dart_output_fd = open_directory(dart_output)
        try:
            for spec, payload in zip(
                dart_specs,
                (b"dart-database-fixture", b"dart-scanner-fixture"),
                strict=True,
            ):
                download_archive(
                    dart_output_fd,
                    spec,
                    FakeOpener(FakeResponse(payload, spec.url)),
                )
        finally:
            os.close(dart_output_fd)
        validate_candidate_tree(
            dart_output,
            dart_specs,
            uid,
            gid,
            str(dart_state["output"]),
        )
        verify_transaction(
            dart_online,
            dart_staging,
            dart_specs,
            uid,
            gid,
            builder_id,
            helper_sha256,
        )
        publish_transaction(
            dart_online,
            dart_staging,
            dart_specs,
            uid,
            gid,
            builder_id,
            helper_sha256,
        )
        dart_online_fd = open_directory(dart_online)
        try:
            for spec in dart_specs:
                if not validate_archive_at(
                    dart_online_fd, spec, uid, gid, candidate=False
                ):
                    fail("Dart-audit self-test publication omitted an input")
        finally:
            os.close(dart_online_fd)

        bad_output = root / "bad-output"
        bad_output.mkdir(mode=0o700)
        bad_fd = open_directory(bad_output)
        try:
            first = specs[0]
            try:
                download_archive(
                    bad_fd,
                    first,
                    FakeOpener(FakeResponse(b"wrong", first.url)),
                )
            except ContractError:
                pass
            else:
                fail("self-test accepted a wrong-length/wrong-digest response")
            if list(bad_output.iterdir()):
                fail("failed acquisition left a candidate file")
        finally:
            os.close(bad_fd)

        chunked_output = root / "chunked-output"
        chunked_output.mkdir(mode=0o700)
        chunked_fd = open_directory(chunked_output)
        try:
            first = specs[0]
            download_archive(
                chunked_fd,
                first,
                FakeOpener(FakeResponse(b"payload-0", first.url, chunked=True)),
            )
            if not validate_archive_at(chunked_fd, first, uid, gid, candidate=True):
                fail("self-test rejected an exact bounded chunked response")
        finally:
            os.close(chunked_fd)

        unframed_output = root / "unframed-output"
        unframed_output.mkdir(mode=0o700)
        unframed_fd = open_directory(unframed_output)
        try:
            first = specs[0]
            try:
                download_archive(
                    unframed_fd,
                    first,
                    FakeOpener(
                        FakeResponse(b"payload-0", first.url, unframed=True)
                    ),
                )
            except ContractError:
                pass
            else:
                fail("self-test accepted a response without admitted length framing")
            if list(unframed_output.iterdir()):
                fail("failed unframed acquisition left a candidate file")
        finally:
            os.close(unframed_fd)

        redirect = BoundedRedirectHandler(("example.invalid",))
        request = urllib.request.Request("https://example.invalid/input")
        try:
            redirect.redirect_request(
                request,
                None,
                302,
                "redirect",
                {},
                "https://outside.invalid/output",
            )
        except urllib.error.HTTPError:
            pass
        else:
            fail("self-test accepted a redirect outside the host allowlist")

        symlink_root = root / "symlink-output"
        symlink_root.mkdir(mode=0o700)
        os.symlink("/dev/null", symlink_root / specs[0].name)
        try:
            validate_candidate_tree(
                symlink_root,
                (specs[0],),
                uid,
                gid,
                identity_for_stat(os.stat(symlink_root)),
            )
        except ContractError:
            pass
        else:
            fail("self-test accepted a symlink candidate")

        occupied_online = root / "occupied-online"
        occupied_staging = root / "occupied-staging"
        occupied_online.mkdir(mode=0o700)
        occupied_staging.mkdir(mode=0o700)
        (occupied_online / specs[0].name).write_bytes(b"wrong")
        os.chmod(occupied_online / specs[0].name, 0o400)
        try:
            prepare_transaction(
                occupied_online,
                occupied_staging,
                specs,
                uid,
                gid,
                builder_id,
                helper_sha256,
            )
        except ContractError:
            pass
        else:
            fail("self-test accepted an occupied wrong archive destination")

        unsafe_parent_online = root / "unsafe-parent-online"
        unsafe_parent_staging = root / "unsafe-parent-staging"
        unsafe_parent_online.mkdir(mode=0o700)
        unsafe_parent_staging.mkdir(mode=0o700)
        (unsafe_parent_online / "win").mkdir(mode=0o700)
        os.chmod(unsafe_parent_online / "win", 0o777)
        try:
            prepare_transaction(
                unsafe_parent_online,
                unsafe_parent_staging,
                specs,
                uid,
                gid,
                builder_id,
                helper_sha256,
            )
        except ContractError:
            pass
        else:
            fail("self-test accepted an unsafe nested archive parent as missing")

        unsafe_vcpkg_online = root / "unsafe-vcpkg-online"
        unsafe_vcpkg_staging = root / "unsafe-vcpkg-staging"
        unsafe_vcpkg_online.mkdir(mode=0o700)
        unsafe_vcpkg_staging.mkdir(mode=0o700)
        (unsafe_vcpkg_online / "vcpkg-distfiles").mkdir(mode=0o700)
        (unsafe_vcpkg_online / "vcpkg-distfiles" / "windows-tools").mkdir(
            mode=0o700
        )
        os.chmod(
            unsafe_vcpkg_online / "vcpkg-distfiles" / "windows-tools",
            0o777,
        )
        try:
            prepare_transaction(
                unsafe_vcpkg_online,
                unsafe_vcpkg_staging,
                vcpkg_specs,
                uid,
                gid,
                builder_id,
                helper_sha256,
            )
        except ContractError:
            pass
        else:
            fail("self-test accepted an unsafe vcpkg archive parent")
    print("fixed archive transaction self-test: PASS")


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--online", type=Path, required=True)
    parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    parser.add_argument("--builder-id", required=True)
    parser.add_argument("--helper-sha256", required=True)
    parser.add_argument(
        "--entry",
        action="append",
        nargs=5,
        metavar=("NAME", "URL", "SIZE", "SHA256", "REDIRECT_HOSTS"),
        required=True,
    )


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("prepare", "verify", "publish", "reconcile"):
        add_common(subparsers.add_parser(command))
    acquire = subparsers.add_parser("acquire")
    acquire.add_argument("--state", type=Path, required=True)
    acquire.add_argument("--output", type=Path, required=True)
    acquire.add_argument("--builder-id", required=True)
    acquire.add_argument("--helper-sha256", required=True)
    subparsers.add_parser("self-test")
    args = parser.parse_args(argv)
    if args.command == "self-test":
        self_test()
        return 0
    if args.command == "acquire":
        acquire_transaction(
            args.state,
            args.output,
            args.builder_id,
            args.helper_sha256,
        )
        return 0
    specs = parse_specs(args.entry)
    if args.command == "prepare":
        print(
            prepare_transaction(
                args.online,
                args.staging,
                specs,
                args.uid,
                args.gid,
                args.builder_id,
                args.helper_sha256,
            )
        )
    elif args.command == "verify":
        verify_transaction(
            args.online,
            args.staging,
            specs,
            args.uid,
            args.gid,
            args.builder_id,
            args.helper_sha256,
        )
    elif args.command == "publish":
        publish_transaction(
            args.online,
            args.staging,
            specs,
            args.uid,
            args.gid,
            args.builder_id,
            args.helper_sha256,
        )
    elif args.command == "reconcile":
        reconcile_transaction(
            args.online,
            args.staging,
            specs,
            args.uid,
            args.gid,
            args.builder_id,
            args.helper_sha256,
        )
    else:
        fail("unknown archive transaction command")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except ContractError as exc:
        print(f"[FATAL] {exc}", file=sys.stderr)
        raise SystemExit(1)
