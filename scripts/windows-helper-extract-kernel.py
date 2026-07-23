#!/usr/bin/env python3
"""Extract the one pinned libguestfs kernel from a captured Docker image archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tarfile
from pathlib import Path
from typing import NoReturn


ARCHIVE_MEMBER = re.compile(r"blobs/sha256/[0-9a-f]{64}")
KERNEL_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)+(?:-[0-9]+)?-[A-Za-z0-9._+-]+")
SHA256 = re.compile(r"[0-9a-f]{64}")


def fail(message: str) -> NoReturn:
    raise SystemExit(f"windows-helper-extract-kernel: {message}")


def load_json_member(archive: tarfile.TarFile, name: str) -> object:
    member = archive.getmember(name)
    if not member.isfile():
        fail(f"{name} is not a regular archive member")
    stream = archive.extractfile(member)
    if stream is None:
        fail(f"cannot read {name}")
    try:
        return json.load(stream)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{name} is not canonical JSON: {error}")


def copy_kernel(
    source: tarfile.ExFileObject,
    member: tarfile.TarInfo,
    candidate: Path,
    expected_sha256: str,
) -> None:
    if member.size < 1024 * 1024 or member.size > 128 * 1024 * 1024:
        fail("kernel archive member has an implausible size")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    digest = hashlib.sha256()
    copied = 0
    descriptor = os.open(candidate, flags, 0o400)
    try:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            digest.update(chunk)
            copied += len(chunk)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    fail("short write while extracting the kernel")
                view = view[written:]
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_nlink != 1
            or metadata.st_size != copied
        ):
            fail("extracted kernel metadata is invalid")
    finally:
        os.close(descriptor)
    if copied != member.size:
        fail("kernel archive member ended before its declared size")
    if digest.hexdigest() != expected_sha256:
        fail("extracted kernel SHA-256 does not equal its independent pin")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--kernel-version", required=True)
    parser.add_argument("--kernel-sha256", required=True)
    args = parser.parse_args()

    if not KERNEL_VERSION.fullmatch(args.kernel_version):
        fail("kernel version is malformed")
    if not SHA256.fullmatch(args.kernel_sha256):
        fail("kernel SHA-256 is malformed")
    if args.output.name != "vmlinuz":
        fail("output basename must be vmlinuz")
    if args.output.exists() or args.output.is_symlink():
        fail("kernel output must be freshly absent")
    output_parent = args.output.parent
    parent_metadata = output_parent.lstat()
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        or parent_metadata.st_uid != os.getuid()
    ):
        fail("kernel output parent must be a current-UID mode-0700 directory")

    candidate = output_parent / ".vmlinuz.candidate"
    if candidate.exists() or candidate.is_symlink():
        fail("private kernel candidate path is occupied")
    target = f"boot/vmlinuz-{args.kernel_version}"
    whiteout = f"boot/.wh.vmlinuz-{args.kernel_version}"
    opaque_whiteout = "boot/.wh..wh..opq"
    boot_whiteout = ".wh.boot"
    found = 0
    try:
        with tarfile.open(args.archive, "r:gz") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            if len(names) != len(set(names)):
                fail("outer image archive contains duplicate member names")
            if names.count("manifest.json") != 1:
                fail("outer image archive must contain exactly one manifest.json")
            manifest = load_json_member(archive, "manifest.json")
            if not isinstance(manifest, list) or len(manifest) != 1:
                fail("Docker image manifest must describe exactly one image")
            image = manifest[0]
            if not isinstance(image, dict):
                fail("Docker image manifest entry is malformed")
            config = image.get("Config")
            layers = image.get("Layers")
            if not isinstance(config, str) or not ARCHIVE_MEMBER.fullmatch(config):
                fail("Docker image config member is malformed")
            if (
                not isinstance(layers, list)
                or not layers
                or not all(isinstance(layer, str) and ARCHIVE_MEMBER.fullmatch(layer) for layer in layers)
                or len(layers) != len(set(layers))
            ):
                fail("Docker image layer list is malformed")
            if config not in names or any(layer not in names for layer in layers):
                fail("Docker image manifest references an absent blob")

            for layer_name in layers:
                outer_member = archive.getmember(layer_name)
                if not outer_member.isfile():
                    fail("Docker image layer blob is not regular")
                layer_stream = archive.extractfile(outer_member)
                if layer_stream is None:
                    fail("cannot read Docker image layer blob")
                with tarfile.open(fileobj=layer_stream, mode="r|gz") as layer:
                    for member in layer:
                        normalized = member.name
                        while normalized.startswith("./"):
                            normalized = normalized[2:]
                        if normalized in (whiteout, opaque_whiteout, boot_whiteout):
                            fail("a later image layer removes the pinned kernel")
                        if normalized != target:
                            continue
                        found += 1
                        if found != 1 or not member.isfile():
                            fail("image archive does not contain one unambiguous regular kernel")
                        source = layer.extractfile(member)
                        if source is None:
                            fail("cannot read the kernel archive member")
                        copy_kernel(source, member, candidate, args.kernel_sha256)
        if found != 1:
            fail("image archive does not contain exactly one pinned kernel")
        os.replace(candidate, args.output)
        parent_descriptor = os.open(output_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        try:
            candidate.unlink()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    main()
