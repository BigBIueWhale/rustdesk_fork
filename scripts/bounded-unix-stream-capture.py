#!/usr/bin/env python3
"""Drain one private Unix stream into a size-bounded evidence file."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import socket
import stat
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise RuntimeError(message)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-bytes", type=int, required=True)
    parser.add_argument("--archive-output", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.max_bytes <= 0 or args.max_bytes > 64 * 1024 * 1024:
        fail("capture bound must be within 1..67108864 bytes")
    if not args.socket.is_absolute() or not args.output.is_absolute():
        fail("capture paths must be absolute")
    if args.socket.parent != args.output.parent:
        fail("capture socket and output must share one private parent")
    if args.archive_output is not None:
        if (not args.archive_output.is_absolute()
                or args.archive_output.parent != args.output.parent.parent
                or re.fullmatch(r"[a-z][a-z0-9-]*-run\.[A-Za-z0-9]{10}\.serial\.log",
                                args.archive_output.name) is None):
            fail("archive output must be one named file in the private run parent")

    parent = os.lstat(args.output.parent)
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or parent.st_gid != os.getgid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        fail("capture parent is not current-user/current-group mode 0700")
    if args.archive_output is not None:
        archive_parent = os.lstat(args.archive_output.parent)
        if (
            not stat.S_ISDIR(archive_parent.st_mode)
            or archive_parent.st_uid != os.getuid()
            or archive_parent.st_gid != os.getgid()
            or stat.S_IMODE(archive_parent.st_mode) != 0o700
        ):
            fail("archive parent is not current-user/current-group mode 0700")
    endpoint = os.lstat(args.socket)
    if (
        not stat.S_ISSOCK(endpoint.st_mode)
        or endpoint.st_uid != os.getuid()
        or endpoint.st_gid != os.getgid()
        or stat.S_IMODE(endpoint.st_mode) & 0o077 != 0
    ):
        fail("capture endpoint is not a current-user-private Unix socket")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    output_fd = os.open(args.output, flags, 0o600)
    archive_fd = None
    total = 0
    stored = 0
    overflow = False
    digest = hashlib.sha256()
    stream = None
    try:
        if args.archive_output is not None:
            archive_fd = os.open(args.archive_output, flags, 0o600)
        stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stream.settimeout(10)
        stream.connect(os.fspath(args.socket))
        stream.settimeout(None)
        while True:
            data = stream.recv(65536)
            if not data:
                break
            total += len(data)
            if stored < args.max_bytes:
                admitted = data[: args.max_bytes - stored]
                view = memoryview(admitted)
                while view:
                    written = os.write(output_fd, view)
                    if written <= 0:
                        fail("capture output made no write progress")
                    view = view[written:]
                if archive_fd is not None:
                    view = memoryview(admitted)
                    while view:
                        written = os.write(archive_fd, view)
                        if written <= 0:
                            fail("capture archive made no write progress")
                        view = view[written:]
                digest.update(admitted)
                stored += len(admitted)
            if total > args.max_bytes:
                overflow = True
        os.fsync(output_fd)
        if archive_fd is not None:
            os.fsync(archive_fd)
    finally:
        if stream is not None:
            stream.close()
        if archive_fd is not None:
            os.close(archive_fd)
        os.close(output_fd)

    output = os.lstat(args.output)
    if (
        not stat.S_ISREG(output.st_mode)
        or output.st_nlink != 1
        or output.st_uid != os.getuid()
        or output.st_gid != os.getgid()
        or stat.S_IMODE(output.st_mode) != 0o600
        or output.st_size != stored
    ):
        fail("capture output metadata differs")
    if overflow:
        fail(
            f"Unix-stream evidence exceeded {args.max_bytes} bytes "
            f"({total} bytes drained)"
        )
    if args.archive_output is not None:
        archive_fd = os.open(args.archive_output, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            archived = os.fstat(archive_fd)
            if (
                not stat.S_ISREG(archived.st_mode)
                or archived.st_nlink != 1
                or archived.st_uid != os.getuid()
                or archived.st_gid != os.getgid()
                or stat.S_IMODE(archived.st_mode) != 0o600
                or archived.st_size != stored
            ):
                fail("capture archive metadata differs")
            archived_digest = hashlib.sha256()
            while data := os.read(archive_fd, 65536):
                archived_digest.update(data)
            if archived_digest.digest() != digest.digest():
                fail("capture archive bytes differ")
        finally:
            os.close(archive_fd)
        archive_parent_fd = os.open(
            args.archive_output.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            current_parent = os.fstat(archive_parent_fd)
            if (current_parent.st_dev, current_parent.st_ino) != (
                archive_parent.st_dev, archive_parent.st_ino
            ):
                fail("capture archive parent identity changed")
            os.fsync(archive_parent_fd)
        finally:
            os.close(archive_parent_fd)
        print(f"bounded-unix-stream-capture: PASS bytes={total} "
              f"archive_sha256={digest.hexdigest()}")
    else:
        print(f"bounded-unix-stream-capture: PASS bytes={total}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError) as error:
        print(f"bounded-unix-stream-capture: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
