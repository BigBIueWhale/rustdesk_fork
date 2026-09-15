#!/usr/bin/env python3
"""Exercise the exact flagged-rename contract required by online publishers."""

from __future__ import annotations

import argparse
import ctypes
import errno
import os
import pathlib
import shutil
import stat
import tempfile


AT_FDCWD = -100
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"virtiofs rename contract: {message}")


def renameat2(source: pathlib.Path, destination: pathlib.Path, flags: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.renameat2(
        AT_FDCWD,
        os.fsencode(source),
        AT_FDCWD,
        os.fsencode(destination),
        flags,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(source), str(destination))


def write_exact(path: pathlib.Path, content: bytes) -> tuple[int, int]:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        if os.write(descriptor, content) != len(content):
            fail("fixture write was short")
        os.fsync(descriptor)
        identity = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    return identity.st_dev, identity.st_ino


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    args = parser.parse_args()

    if os.geteuid() == 0 or os.getegid() == 0:
        fail("the behavioral probe refuses root")
    root = pathlib.Path(args.root).resolve(strict=True)
    active = root / "inputs"
    retired = root / "retired"
    for directory in (root, active, retired):
        metadata = directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or directory.is_symlink():
            fail(f"cache authority is not one real directory: {directory}")
        if (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) != (
            os.geteuid(),
            os.getegid(),
            0o700,
        ):
            fail(f"cache authority metadata differs: {directory}")
    if len({root.stat().st_dev, active.stat().st_dev, retired.stat().st_dev}) != 1:
        fail("active and retired roots do not share one filesystem")

    active_probe = pathlib.Path(tempfile.mkdtemp(prefix=".virtiofs-rename.", dir=active))
    retired_probe = pathlib.Path(tempfile.mkdtemp(prefix=".virtiofs-rename.", dir=retired))
    try:
        os.chmod(active_probe, 0o700)
        os.chmod(retired_probe, 0o700)

        source = active_probe / "noreplace-source"
        destination = retired_probe / "noreplace-destination"
        source_identity = write_exact(source, b"cross-parent-noreplace\n")
        renameat2(source, destination, RENAME_NOREPLACE)
        if source.exists() or not destination.is_file():
            fail("RENAME_NOREPLACE did not move the cross-parent source exactly once")
        destination_stat = destination.stat()
        if (destination_stat.st_dev, destination_stat.st_ino) != source_identity:
            fail("RENAME_NOREPLACE changed the published inode identity")
        if destination.read_bytes() != b"cross-parent-noreplace\n":
            fail("RENAME_NOREPLACE changed the published bytes")

        collision_source = active_probe / "collision-source"
        collision_destination = retired_probe / "collision-destination"
        collision_source_identity = write_exact(collision_source, b"source-must-survive\n")
        collision_destination_identity = write_exact(
            collision_destination, b"destination-must-survive\n"
        )
        try:
            renameat2(collision_source, collision_destination, RENAME_NOREPLACE)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                fail(f"RENAME_NOREPLACE collision returned errno {exc.errno}")
        else:
            fail("RENAME_NOREPLACE overwrote an occupied destination")
        if (
            collision_source.read_bytes() != b"source-must-survive\n"
            or collision_destination.read_bytes() != b"destination-must-survive\n"
        ):
            fail("RENAME_NOREPLACE collision changed fixture content")
        if (
            (collision_source.stat().st_dev, collision_source.stat().st_ino)
            != collision_source_identity
            or (
                collision_destination.stat().st_dev,
                collision_destination.stat().st_ino,
            )
            != collision_destination_identity
        ):
            fail("RENAME_NOREPLACE collision changed fixture identity")

        exchange_left = active_probe / "exchange-left"
        exchange_right = active_probe / "exchange-right"
        exchange_left.mkdir(mode=0o700)
        exchange_right.mkdir(mode=0o700)
        left_identity = (exchange_left.stat().st_dev, exchange_left.stat().st_ino)
        right_identity = (exchange_right.stat().st_dev, exchange_right.stat().st_ino)
        write_exact(exchange_left / "left", b"left\n")
        write_exact(exchange_right / "right", b"right\n")
        renameat2(exchange_left, exchange_right, RENAME_EXCHANGE)
        if (exchange_left.stat().st_dev, exchange_left.stat().st_ino) != right_identity:
            fail("RENAME_EXCHANGE did not install the right directory at the left name")
        if (exchange_right.stat().st_dev, exchange_right.stat().st_ino) != left_identity:
            fail("RENAME_EXCHANGE did not install the left directory at the right name")
        if (exchange_left / "right").read_bytes() != b"right\n":
            fail("RENAME_EXCHANGE changed right-directory content")
        if (exchange_right / "left").read_bytes() != b"left\n":
            fail("RENAME_EXCHANGE changed left-directory content")

        for directory in (active_probe, retired_probe):
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        for directory in (active_probe, retired_probe):
            if directory.exists() and not directory.is_symlink():
                shutil.rmtree(directory)

    if any(path.name.startswith(".virtiofs-rename.") for path in active.iterdir()):
        fail("active-root probe residue remains")
    if any(path.name.startswith(".virtiofs-rename.") for path in retired.iterdir()):
        fail("retired-root probe residue remains")
    print(
        "VIRTIOFS_RENAME_CONTRACT=pass "
        "noreplace=cross-parent collision=no-clobber exchange=nonempty cleanup=complete"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
