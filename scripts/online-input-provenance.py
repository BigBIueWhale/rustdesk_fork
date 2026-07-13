#!/usr/bin/env python3
"""Canonical provenance and private snapshots for the offline input tree."""

from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import os
import re
import shutil
import stat
import struct
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


DOMAIN = b"rustdesk-online-closure-v1\0"
RECORD_NAME = b".rustdesk-online-closure-v1"
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
FICLONE = 0x40049409


class ProvenanceError(RuntimeError):
    pass


@dataclass(frozen=True)
class Result:
    root: str
    files: int
    directories: int
    symlinks: int
    content_bytes: int
    hardlink_groups: int
    case_collisions: int

    def record(self) -> bytes:
        return (
            "rustdesk-online-closure-v1\n"
            f"sha256={self.root}\n"
            f"files={self.files}\n"
            f"directories={self.directories}\n"
            f"symlinks={self.symlinks}\n"
            f"content_bytes={self.content_bytes}\n"
            f"hardlink_groups={self.hardlink_groups}\n"
            f"case_collisions={self.case_collisions}\n"
        ).encode("ascii")


@dataclass
class Counters:
    files: int = 0
    directories: int = 0
    symlinks: int = 0
    content_bytes: int = 0


def fail(message: str) -> None:
    raise ProvenanceError(message)


def framed(*parts: bytes) -> bytes:
    out = bytearray(DOMAIN)
    for part in parts:
        out += struct.pack(">Q", len(part))
        out += part
    return bytes(out)


def digest(*parts: bytes) -> bytes:
    return hashlib.sha256(framed(*parts)).digest()


def validate_name(name: bytes, relative: bytes) -> None:
    shown = os.fsdecode(relative or name)
    if name in (b"", b".", b".."):
        fail(f"invalid path segment: {shown!r}")
    if any(byte < 0x20 or byte > 0x7E for byte in name):
        fail(f"unsupported non-printable or non-ASCII path bytes: {shown!r}")
    if b"/" in name or b"\\" in name or b":" in name:
        fail(f"non-portable path segment: {shown!r}")
    if name.startswith((b" ", b".")) and name not in (RECORD_NAME,):
        if name.startswith(b" ") or name in (b".", b".."):
            fail(f"ambiguous leading path byte: {shown!r}")
    if name.endswith((b" ", b".")):
        fail(f"ambiguous trailing path byte: {shown!r}")


def stable_stat(before: os.stat_result, after: os.stat_result, path: bytes) -> None:
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        fail(f"input mutated while hashing: {os.fsdecode(path)}")


def executable_marker(mode: int) -> bytes:
    return b"1" if mode & 0o111 else b"0"


class Walker:
    def __init__(self, root: bytes):
        self.root = root
        self.counts = Counters()
        self.inodes: dict[tuple[int, int], list[tuple[bytes, int]]] = {}
        self.case_paths: dict[bytes, bytes] = {}
        self.case_collisions: set[tuple[bytes, bytes]] = set()
        self.final_stats: dict[bytes, tuple[bytes, os.stat_result]] = {}

    def register_path(self, relative: bytes) -> None:
        folded = relative.lower()
        previous = self.case_paths.get(folded)
        if previous is not None and previous != relative:
            self.case_collisions.add(tuple(sorted((previous, relative))))
        else:
            self.case_paths[folded] = relative

    def regular(self, path: bytes, relative: bytes, entry_stat: os.stat_result) -> bytes:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            fail(f"cannot open regular input {os.fsdecode(relative)}: {exc}")
        content = hashlib.sha256()
        try:
            before = os.fstat(fd)
            stable_stat(entry_stat, before, path)
            while True:
                block = os.read(fd, 1024 * 1024)
                if not block:
                    break
                content.update(block)
            after = os.fstat(fd)
            stable_stat(before, after, path)
        finally:
            os.close(fd)
        self.counts.files += 1
        self.counts.content_bytes += entry_stat.st_size
        self.inodes.setdefault((entry_stat.st_dev, entry_stat.st_ino), []).append(
            (relative, entry_stat.st_nlink)
        )
        self.final_stats[relative] = (path, after)
        return digest(b"file", relative, executable_marker(entry_stat.st_mode), content.digest())

    def symlink(self, path: bytes, relative: bytes, entry_stat: os.stat_result) -> bytes:
        target = os.readlink(path)
        target_bytes = os.fsencode(target)
        validate_link_target(relative, target_bytes)
        try:
            resolved = Path(os.fsdecode(path)).resolve(strict=True)
            resolved.relative_to(Path(os.fsdecode(self.root)).resolve(strict=True))
        except (OSError, RuntimeError, ValueError) as exc:
            fail(f"symlink escapes, is broken, or cycles at {os.fsdecode(relative)}: {exc}")
        after = os.lstat(path)
        stable_stat(entry_stat, after, path)
        self.final_stats[relative] = (path, after)
        self.counts.symlinks += 1
        return digest(b"symlink", relative, target_bytes)

    def directory(self, path: bytes, relative: bytes, is_root: bool = False) -> bytes:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            fail(f"cannot open input directory {os.fsdecode(relative) or '.'}: {exc}")
        try:
            before = os.fstat(fd)
            if not stat.S_ISDIR(before.st_mode):
                fail(f"not a directory: {os.fsdecode(relative) or '.'}")
            try:
                entries = list(os.scandir(path))
            except OSError as exc:
                fail(f"cannot enumerate input directory {os.fsdecode(relative) or '.'}: {exc}")
            entries.sort(key=lambda entry: os.fsencode(entry.name))
            children: list[bytes] = []
            names: set[bytes] = set()
            for entry in entries:
                name = os.fsencode(entry.name)
                child_relative = name if not relative else relative + b"/" + name
                validate_name(name, child_relative)
                if name in names:
                    fail(f"duplicate directory entry: {os.fsdecode(child_relative)}")
                names.add(name)
                if is_root and name == RECORD_NAME:
                    record_stat = entry.stat(follow_symlinks=False)
                    if not stat.S_ISREG(record_stat.st_mode) or record_stat.st_nlink != 1:
                        fail("the closure record must be one non-hardlinked regular file")
                    continue
                self.register_path(child_relative)
                entry_stat = entry.stat(follow_symlinks=False)
                child_path = path + b"/" + name
                if stat.S_ISREG(entry_stat.st_mode):
                    node = self.regular(child_path, child_relative, entry_stat)
                elif stat.S_ISDIR(entry_stat.st_mode):
                    node = self.directory(child_path, child_relative)
                elif stat.S_ISLNK(entry_stat.st_mode):
                    node = self.symlink(child_path, child_relative, entry_stat)
                else:
                    fail(f"unsupported special file: {os.fsdecode(child_relative)}")
                children.append(digest(b"entry", name, node))
            after = os.fstat(fd)
            stable_stat(before, after, path)
        finally:
            os.close(fd)
        self.final_stats[relative] = (path, after)
        self.counts.directories += 1
        return digest(
            b"directory",
            relative,
            executable_marker(before.st_mode),
            *children,
        )

    def finish(self, node: bytes) -> Result:
        for relative, (path, expected) in sorted(self.final_stats.items()):
            try:
                current = os.lstat(path)
            except OSError as exc:
                fail(f"input path changed after hashing {os.fsdecode(relative) or '.'}: {exc}")
            stable_stat(expected, current, path)
        hardlink_groups = 0
        for paths in self.inodes.values():
            observed = len(paths)
            declared = {links for _, links in paths}
            if len(declared) != 1 or observed != next(iter(declared)):
                names = ", ".join(os.fsdecode(path) for path, _ in paths[:4])
                fail(f"regular file has hardlinks outside the closure or changed links: {names}")
            if observed > 1:
                hardlink_groups += 1
        topology = hashlib.sha256(DOMAIN + b"hardlinks\0")
        for paths in sorted(
            (sorted(path for path, _ in group) for group in self.inodes.values() if len(group) > 1),
            key=lambda group: group[0],
        ):
            topology.update(framed(*paths))
        root = digest(b"root", node, topology.digest()).hex()
        return Result(
            root=root,
            files=self.counts.files,
            directories=self.counts.directories,
            symlinks=self.counts.symlinks,
            content_bytes=self.counts.content_bytes,
            hardlink_groups=hardlink_groups,
            case_collisions=len(self.case_collisions),
        )

    def result(self) -> Result:
        node = self.directory(self.root, b"", is_root=True)
        return self.finish(node)


def validate_link_target(relative: bytes, target: bytes) -> None:
    if not target or target.startswith((b"/", b"\\")):
        fail(f"absolute or empty symlink target at {os.fsdecode(relative)}")
    if any(byte < 0x20 or byte > 0x7E for byte in target) or b"\\" in target or b":" in target:
        fail(f"unsupported symlink target bytes at {os.fsdecode(relative)}")
    components = relative.split(b"/")[:-1]
    for component in target.split(b"/"):
        if component in (b"", b"."):
            continue
        if component == b"..":
            if not components:
                fail(f"symlink target traverses outside closure at {os.fsdecode(relative)}")
            components.pop()
        else:
            validate_name(component, relative + b" -> " + target)
            components.append(component)


def calculate(tree: Path) -> Result:
    raw = os.fsencode(os.path.abspath(tree))
    try:
        root_stat = os.lstat(raw)
    except OSError as exc:
        fail(f"cannot stat online tree {tree}: {exc}")
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        fail(f"online tree is not a real directory: {tree}")
    return Walker(raw).result()


def parse_expected(value: str) -> str:
    if not HEX256.fullmatch(value):
        fail("expected closure pin must be exactly 64 lowercase hexadecimal characters")
    return value


def verify(tree: Path, expected: str) -> Result:
    expected = parse_expected(expected)
    result = calculate(tree)
    if result.root != expected:
        fail(f"online closure mismatch: expected {expected}, got {result.root}")
    record = tree / os.fsdecode(RECORD_NAME)
    try:
        actual_record = record.read_bytes()
    except OSError as exc:
        fail(f"cannot read closure record {record}: {exc}")
    if actual_record != result.record():
        fail("online closure record is absent, malformed, stale, or non-canonical")
    return result


def write_record(tree: Path) -> Result:
    result = calculate(tree)
    record = tree / os.fsdecode(RECORD_NAME)
    temporary = tree / (os.fsdecode(RECORD_NAME) + ".part")
    try:
        with temporary.open("xb") as stream:
            stream.write(result.record())
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, record)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return result


def copy_regular(source: Path, destination: Path) -> None:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    source_fd = os.open(source, flags)
    try:
        before = os.fstat(source_fd)
        destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        try:
            try:
                fcntl.ioctl(destination_fd, FICLONE, source_fd)
            except OSError as exc:
                if exc.errno not in (errno.EXDEV, errno.EOPNOTSUPP, errno.ENOTTY, errno.EINVAL):
                    raise
                while True:
                    block = os.read(source_fd, 1024 * 1024)
                    if not block:
                        break
                    view = memoryview(block)
                    while view:
                        written = os.write(destination_fd, view)
                        view = view[written:]
            os.fchmod(destination_fd, 0o700 if before.st_mode & 0o111 else 0o600)
            os.fsync(destination_fd)
        finally:
            os.close(destination_fd)
        stable_stat(before, os.fstat(source_fd), os.fsencode(source))
    finally:
        os.close(source_fd)


def make_read_only(tree: Path) -> None:
    for root, directories, files in os.walk(tree, topdown=False, followlinks=False):
        root_path = Path(root)
        for name in files:
            path = root_path / name
            if path.is_symlink():
                continue
            mode = path.stat(follow_symlinks=False).st_mode
            os.chmod(path, 0o500 if mode & 0o111 else 0o400, follow_symlinks=False)
        for name in directories:
            path = root_path / name
            if not path.is_symlink():
                os.chmod(path, 0o500, follow_symlinks=False)
    os.chmod(tree, 0o500)


def copy_tree(source: Path, destination: Path) -> None:
    inode_destinations: dict[tuple[int, int], Path] = {}
    destination.mkdir(mode=0o700)

    def descend(src: Path, dst: Path) -> None:
        with os.scandir(src) as iterator:
            entries = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
        for entry in entries:
            source_path = src / entry.name
            destination_path = dst / entry.name
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                destination_path.mkdir(mode=0o700)
                descend(source_path, destination_path)
            elif stat.S_ISLNK(info.st_mode):
                os.symlink(os.readlink(source_path), destination_path)
            elif stat.S_ISREG(info.st_mode):
                key = (info.st_dev, info.st_ino)
                previous = inode_destinations.get(key)
                if previous is None:
                    copy_regular(source_path, destination_path)
                    inode_destinations[key] = destination_path
                else:
                    os.link(previous, destination_path, follow_symlinks=False)
            else:
                fail(f"unsupported special file while snapshotting: {source_path}")

    try:
        descend(source, destination)
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def create_snapshot(
    source: Path,
    destination: Path,
    expected: str,
    after_preflight: Callable[[], None] | None = None,
) -> Result:
    if destination.exists() or destination.is_symlink():
        fail(f"snapshot destination already exists: {destination}")
    before = verify(source, expected)
    if after_preflight is not None:
        after_preflight()
    destination.mkdir(mode=0o700)
    snapshot_tree = destination / "online"
    copy_tree(source, snapshot_tree)
    try:
        source_after = verify(source, expected)
        snapshot = verify(snapshot_tree, expected)
        if before != source_after or before != snapshot:
            fail("online input changed while the private snapshot was created")
        make_read_only(snapshot_tree)
        final = verify(snapshot_tree, expected)
        if final != before:
            fail("read-only snapshot conversion changed the closure")
        return final
    except BaseException:
        os.chmod(destination, 0o700)
        for root, directories, files in os.walk(destination):
            for name in directories:
                path = Path(root) / name
                if not path.is_symlink():
                    os.chmod(path, 0o700, follow_symlinks=False)
            for name in files:
                path = Path(root) / name
                if not path.is_symlink():
                    os.chmod(path, 0o600, follow_symlinks=False)
        shutil.rmtree(destination, ignore_errors=True)
        raise


def expect_failure(operation: Callable[[], object], label: str) -> None:
    try:
        operation()
    except ProvenanceError:
        return
    fail(f"self-test mutation was accepted: {label}")


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="online-provenance-test-") as temporary:
        base = Path(temporary)
        tree = base / "online"
        tree.mkdir()
        (tree / "dir").mkdir()
        (tree / "dir" / "content").write_bytes(b"alpha")
        executable = tree / "tool"
        executable.write_bytes(b"#!/bin/sh\n")
        executable.chmod(0o755)
        os.link(tree / "dir" / "content", tree / "hardlink")
        os.symlink("dir/content", tree / "link")
        original = write_record(tree)
        verify(tree, original.root)

        record = tree / os.fsdecode(RECORD_NAME)
        record.write_bytes(b"changed record\n")
        if calculate(tree).root != original.root:
            fail("closure record was not self-excluded")
        expect_failure(lambda: verify(tree, original.root), "malformed self-excluded record")
        record.write_bytes(original.record())

        def mutation(label: str, change: Callable[[], None], restore: Callable[[], None]) -> None:
            change()
            expect_failure(lambda: verify(tree, original.root), label)
            restore()
            verify(tree, original.root)

        content = tree / "dir" / "content"
        mutation("content", lambda: content.write_bytes(b"beta"), lambda: content.write_bytes(b"alpha"))
        mutation("executable mode", lambda: executable.chmod(0o644), lambda: executable.chmod(0o755))
        mutation("extra", lambda: (tree / "extra").write_bytes(b"x"), lambda: (tree / "extra").unlink())
        mutation("deletion", content.unlink, lambda: os.link(tree / "hardlink", content))
        mutation("path", lambda: executable.rename(tree / "Tool"), lambda: (tree / "Tool").rename(executable))
        mutation("case collision", lambda: (tree / "TOOL").write_bytes(b"x"), lambda: (tree / "TOOL").unlink())
        os.unlink(tree / "link")
        os.symlink("hardlink", tree / "link")
        expect_failure(lambda: verify(tree, original.root), "symlink target")
        os.unlink(tree / "link")
        os.symlink("dir/content", tree / "link")
        verify(tree, original.root)

        outside_link = base / "outside-hardlink"
        os.link(content, outside_link)
        expect_failure(lambda: calculate(tree), "hardlink outside closure")
        outside_link.unlink()

        late_walker = Walker(os.fsencode(tree))
        late_node = late_walker.directory(os.fsencode(tree), b"", is_root=True)
        content.write_bytes(b"late mutation")
        expect_failure(lambda: late_walker.finish(late_node), "late same-pass mutation")
        content.write_bytes(b"alpha")

        outside_file = base / "outside-file"
        outside_file.write_bytes(b"outside")
        os.unlink(tree / "link")
        os.symlink("../outside-file", tree / "link")
        expect_failure(lambda: calculate(tree), "traversing symlink")
        os.unlink(tree / "link")
        os.symlink("dir/content", tree / "link")

        invalid_path = os.fsencode(tree) + b"/bad-\xff"
        invalid_fd = os.open(invalid_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(invalid_fd)
        expect_failure(lambda: calculate(tree), "unsupported path bytes")
        os.unlink(invalid_path)

        fifo = tree / "fifo"
        os.mkfifo(fifo)
        expect_failure(lambda: calculate(tree), "special file")
        fifo.unlink()

        raced = base / "raced"
        expect_failure(
            lambda: create_snapshot(
                tree,
                raced,
                original.root,
                after_preflight=lambda: content.write_bytes(b"raced"),
            ),
            "source TOCTOU",
        )
        content.write_bytes(b"alpha")
        record.write_bytes(original.record())
        snapshot = base / "snapshot"
        create_snapshot(tree, snapshot, original.root)
        snapshot_content = snapshot / "online" / "dir" / "content"
        snapshot_content.chmod(0o600)
        snapshot_content.write_bytes(b"after-use mutation")
        expect_failure(lambda: verify(snapshot / "online", original.root), "post-use snapshot mutation")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    subparsers = value.add_subparsers(dest="command", required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--tree", type=Path, required=True)
    verify_parser.add_argument("--expected", required=True)
    print_parser = subparsers.add_parser("maintenance-print-root")
    print_parser.add_argument("--tree", type=Path, required=True)
    record_parser = subparsers.add_parser("maintenance-write-record")
    record_parser.add_argument("--tree", type=Path, required=True)
    snapshot_parser = subparsers.add_parser("snapshot-create")
    snapshot_parser.add_argument("--source", type=Path, required=True)
    snapshot_parser.add_argument("--destination", type=Path, required=True)
    snapshot_parser.add_argument("--expected", required=True)
    snapshot_verify = subparsers.add_parser("snapshot-verify")
    snapshot_verify.add_argument("--tree", type=Path, required=True)
    snapshot_verify.add_argument("--expected", required=True)
    return value


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        print("online input provenance self-test: PASS")
        return 0
    args = parser().parse_args()
    if args.command == "verify" or args.command == "snapshot-verify":
        result = verify(args.tree, args.expected)
        print(f"verified {result.root}")
    elif args.command == "maintenance-print-root":
        result = calculate(args.tree)
        sys.stdout.write(result.record().decode("ascii"))
    elif args.command == "maintenance-write-record":
        result = write_record(args.tree)
        sys.stdout.write(result.record().decode("ascii"))
    elif args.command == "snapshot-create":
        result = create_snapshot(args.source, args.destination, args.expected)
        print(f"snapshot {args.destination / 'online'} verified {result.root}")
    else:
        fail(f"unsupported command: {args.command}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProvenanceError as exc:
        print(f"online-input-provenance: {exc}", file=sys.stderr)
        raise SystemExit(1)
