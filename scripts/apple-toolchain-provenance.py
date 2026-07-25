#!/usr/bin/env python3
"""Describe and verify the exact installed Rust toolchain used by the Apple gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn


CONTRACT = b"rustdesk-apple-toolchain-tree-v1\0"
ALLOWED_FILE_MODES = {0o644, 0o755}
DIRECTORY_MODE = 0o755


class VerificationError(RuntimeError):
    """The candidate tree does not meet the toolchain authority contract."""


def fail(message: str) -> NoReturn:
    raise VerificationError(message)


def stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def add_bytes(digest: "hashlib._Hash", value: bytes) -> None:
    digest.update(struct.pack(">Q", len(value)))
    digest.update(value)


@dataclass(frozen=True)
class TreeDescription:
    sha256: str
    files: int
    directories: int
    content_bytes: int

    def as_json(self) -> str:
        return json.dumps(
            {
                "contract": CONTRACT[:-1].decode("ascii"),
                "sha256": self.sha256,
                "files": self.files,
                "directories": self.directories,
                "content_bytes": self.content_bytes,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


class TreeWalker:
    def __init__(self, root: bytes, owner: int, group: int) -> None:
        self.root = root
        self.owner = owner
        self.group = group
        self.digest = hashlib.sha256()
        self.digest.update(CONTRACT)
        self.files = 0
        self.directories = 0
        self.content_bytes = 0
        self.root_device = 0

    def check_common(
        self,
        metadata: os.stat_result,
        relative: bytes,
        expected_type: int,
    ) -> int:
        if stat.S_IFMT(metadata.st_mode) != expected_type:
            fail(f"toolchain entry changed type: {relative!r}")
        if metadata.st_dev != self.root_device:
            fail(f"toolchain entry crosses a filesystem boundary: {relative!r}")
        if (metadata.st_uid, metadata.st_gid) != (self.owner, self.group):
            fail(f"toolchain entry has foreign ownership: {relative!r}")
        if metadata.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
            fail(f"toolchain entry has a special mode bit: {relative!r}")
        try:
            xattrs = os.listxattr(
                os.path.join(self.root, relative) if relative else self.root,
                follow_symlinks=False,
            )
        except OSError as exc:
            fail(f"cannot inspect toolchain entry xattrs {relative!r}: {exc}")
        if xattrs:
            fail(f"toolchain entry has extended attributes: {relative!r}")
        return stat.S_IMODE(metadata.st_mode)

    def record_directory(self, relative: bytes, metadata: os.stat_result) -> None:
        mode = self.check_common(metadata, relative, stat.S_IFDIR)
        if mode != DIRECTORY_MODE:
            fail(f"toolchain directory mode is not 0755: {relative!r}")
        self.digest.update(b"D")
        add_bytes(self.digest, relative)
        self.digest.update(struct.pack(">I", mode))
        self.directories += 1

    def record_file(self, relative: bytes, metadata: os.stat_result) -> None:
        mode = self.check_common(metadata, relative, stat.S_IFREG)
        if mode not in ALLOWED_FILE_MODES:
            fail(f"toolchain file mode is not 0644 or 0755: {relative!r}")
        if metadata.st_nlink != 1:
            fail(f"toolchain file is hardlinked: {relative!r}")
        absolute = os.path.join(self.root, relative)
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            descriptor = os.open(absolute, flags)
        except OSError as exc:
            fail(f"cannot no-follow open toolchain file {relative!r}: {exc}")
        content_digest = hashlib.sha256()
        content_size = 0
        try:
            opened = os.fstat(descriptor)
            if stat_identity(opened) != stat_identity(metadata):
                fail(f"toolchain file changed before open: {relative!r}")
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                content_digest.update(chunk)
                content_size += len(chunk)
            after_read = os.fstat(descriptor)
            if stat_identity(after_read) != stat_identity(opened):
                fail(f"toolchain file changed while read: {relative!r}")
        finally:
            os.close(descriptor)
        try:
            after_close = os.lstat(absolute)
        except OSError as exc:
            fail(f"cannot restat toolchain file {relative!r}: {exc}")
        if stat_identity(after_close) != stat_identity(metadata):
            fail(f"toolchain file changed after read: {relative!r}")
        if content_size != metadata.st_size:
            fail(f"toolchain file size changed while read: {relative!r}")
        self.digest.update(b"F")
        add_bytes(self.digest, relative)
        self.digest.update(struct.pack(">I", mode))
        self.digest.update(struct.pack(">Q", content_size))
        self.digest.update(content_digest.digest())
        self.files += 1
        self.content_bytes += content_size

    def walk_directory(self, relative: bytes) -> None:
        absolute = os.path.join(self.root, relative) if relative else self.root
        try:
            before = os.lstat(absolute)
        except OSError as exc:
            fail(f"cannot stat toolchain directory {relative!r}: {exc}")
        self.record_directory(relative, before)
        try:
            with os.scandir(absolute) as iterator:
                entries = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
        except OSError as exc:
            fail(f"cannot enumerate toolchain directory {relative!r}: {exc}")
        for entry in entries:
            name = os.fsencode(entry.name)
            if not name or name in {b".", b".."} or b"/" in name or b"\0" in name:
                fail(f"toolchain entry has an invalid name: {name!r}")
            child = name if not relative else relative + b"/" + name
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                fail(f"cannot stat toolchain entry {child!r}: {exc}")
            entry_type = stat.S_IFMT(metadata.st_mode)
            if entry_type == stat.S_IFDIR:
                self.walk_directory(child)
            elif entry_type == stat.S_IFREG:
                self.record_file(child, metadata)
            else:
                fail(f"toolchain entry is a link or special file: {child!r}")
        try:
            after = os.lstat(absolute)
        except OSError as exc:
            fail(f"cannot restat toolchain directory {relative!r}: {exc}")
        if stat_identity(after) != stat_identity(before):
            fail(f"toolchain directory changed while traversed: {relative!r}")

    def describe(self) -> TreeDescription:
        try:
            root_metadata = os.lstat(self.root)
        except OSError as exc:
            fail(f"cannot stat toolchain root: {exc}")
        if not stat.S_ISDIR(root_metadata.st_mode):
            fail("toolchain root is not one real directory")
        self.root_device = root_metadata.st_dev
        self.walk_directory(b"")
        return TreeDescription(
            sha256=self.digest.hexdigest(),
            files=self.files,
            directories=self.directories,
            content_bytes=self.content_bytes,
        )


def describe_tree(root: Path, owner: int, group: int) -> TreeDescription:
    if not root.is_absolute():
        fail("toolchain root must be absolute")
    return TreeWalker(os.fsencode(root), owner, group).describe()


def verify_description(actual: TreeDescription, args: argparse.Namespace) -> None:
    expected = TreeDescription(
        sha256=args.sha256,
        files=args.files,
        directories=args.directories,
        content_bytes=args.content_bytes,
    )
    if actual != expected:
        fail(
            "toolchain tree differs: "
            f"expected={expected.as_json()} actual={actual.as_json()}"
        )


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="apple-toolchain-provenance.") as temporary:
        root = Path(temporary) / "toolchain"
        root.mkdir(mode=0o755)
        library = root / "lib"
        library.mkdir(mode=0o755)
        binary = root / "cargo"
        binary.write_bytes(b"cargo")
        binary.chmod(0o755)
        archive = library / "libstd.rlib"
        archive.write_bytes(b"std")
        archive.chmod(0o644)
        first = describe_tree(root, os.geteuid(), os.getegid())
        second = describe_tree(root, os.geteuid(), os.getegid())
        if first != second or (first.files, first.directories, first.content_bytes) != (
            2,
            2,
            8,
        ):
            fail("self-test stable tree description differs")
        archive.write_bytes(b"std!")
        changed = describe_tree(root, os.geteuid(), os.getegid())
        if changed.sha256 == first.sha256:
            fail("self-test content mutation was not detected")
        archive.write_bytes(b"std")
        linked = root / "linked"
        os.link(binary, linked)
        try:
            describe_tree(root, os.geteuid(), os.getegid())
        except VerificationError:
            pass
        else:
            fail("self-test hardlink was accepted")
        linked.unlink()
        link = root / "symlink"
        link.symlink_to("cargo")
        try:
            describe_tree(root, os.geteuid(), os.getegid())
        except VerificationError:
            pass
        else:
            fail("self-test symlink was accepted")
        link.unlink()
        binary.chmod(0o775)
        try:
            describe_tree(root, os.geteuid(), os.getegid())
        except VerificationError:
            pass
        else:
            fail("self-test writable file mode was accepted")
    print("apple-toolchain-provenance: self-test ok")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--owner", type=int, default=os.geteuid())
    parser.add_argument("--group", type=int, default=os.getegid())
    parser.add_argument("--sha256")
    parser.add_argument("--files", type=int)
    parser.add_argument("--directories", type=int)
    parser.add_argument("--content-bytes", type=int)
    args = parser.parse_args()
    if args.self_test:
        return args
    if args.root is None:
        parser.error("--root is required")
    expected = (args.sha256, args.files, args.directories, args.content_bytes)
    if any(item is None for item in expected) and any(item is not None for item in expected):
        parser.error("all expected tree fields must be provided together")
    if args.sha256 is not None and (
        len(args.sha256) != 64
        or any(character not in "0123456789abcdef" for character in args.sha256)
    ):
        parser.error("--sha256 must be 64 lowercase hexadecimal characters")
    if any(
        item is not None and item < 0
        for item in (args.files, args.directories, args.content_bytes)
    ):
        parser.error("expected tree counts must be non-negative")
    if args.owner < 0 or args.group < 0:
        parser.error("owner and group must be non-negative")
    return args


def main() -> int:
    args = parse_args()
    try:
        if args.self_test:
            self_test()
            return 0
        actual = describe_tree(args.root, args.owner, args.group)
        if args.sha256 is not None:
            verify_description(actual, args)
        print(actual.as_json())
        return 0
    except VerificationError as exc:
        print(f"apple-toolchain-provenance: {exc}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
