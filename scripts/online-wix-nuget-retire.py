#!/usr/bin/env python3
"""Retire the obsolete expanded WiX cache after exact packages are durable."""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import os
import secrets
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


LEGACY_NAME = "wix-nuget.tar.gz"
STAGING_PREFIX = ".rustdesk-wix-nuget-retire."
RENAME_NOREPLACE = 1
CHUNK_SIZE = 1024 * 1024
PACKAGE_NAMES = (
    "wix-nuget-packages/wixtoolset.firewall.wixext.4.0.5.nupkg",
    "wix-nuget-packages/wixtoolset.heat.4.0.5.nupkg",
    "wix-nuget-packages/wixtoolset.netfx.wixext.4.0.5.nupkg",
    "wix-nuget-packages/wixtoolset.sdk.4.0.5.nupkg",
    "wix-nuget-packages/wixtoolset.ui.wixext.4.0.5.nupkg",
    "wix-nuget-packages/wixtoolset.util.wixext.4.0.5.nupkg",
)


class ContractError(RuntimeError):
    """A fail-closed retirement error."""


def fail(message: str) -> None:
    raise ContractError(message)


@dataclass(frozen=True)
class FileSpec:
    name: str
    size: int
    sha256: str


def parse_positive(value: str, label: str) -> int:
    if not value.isdigit() or int(value) <= 0:
        fail(f"{label} is not a positive canonical decimal integer")
    return int(value)


def parse_digest(value: str, label: str) -> str:
    if (
        len(value) != 64
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        fail(f"{label} is not a canonical SHA-256")
    return value


def parse_package_specs(raw: Sequence[Sequence[str]]) -> tuple[FileSpec, ...]:
    if len(raw) != len(PACKAGE_NAMES):
        fail("retirement requires the exact six WiX package records")
    result: list[FileSpec] = []
    for index, record in enumerate(raw):
        if len(record) != 3:
            fail("each WiX package record requires NAME SIZE SHA256")
        name, size, digest = record
        if name != PACKAGE_NAMES[index]:
            fail("WiX package records are not the exact sorted 4.0.5 inventory")
        result.append(
            FileSpec(
                name=name,
                size=parse_positive(size, f"{name} size"),
                sha256=parse_digest(digest, f"{name} digest"),
            )
        )
    return tuple(result)


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
    except OSError as exc:
        fail(f"cannot open child directory without following links: {name}: {exc}")


def ensure_directory(
    descriptor: int,
    uid: int,
    gid: int,
    label: str,
    root_device: int,
    root_mount: int,
) -> None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid) != (uid, gid)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_dev != root_device
        or descriptor_mount_id(descriptor) != root_mount
        or os.listxattr(descriptor)
    ):
        fail(f"{label} is not one private same-filesystem directory")


def stable(before: os.stat_result, after: os.stat_result) -> bool:
    fields = (
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
    return all(getattr(before, field) == getattr(after, field) for field in fields)


def validate_file(
    parent_fd: int,
    leaf: str,
    spec: FileSpec,
    uid: int,
    gid: int,
    root_device: int,
    root_mount: int,
    *,
    allowed_modes: set[int],
) -> None:
    try:
        descriptor = os.open(
            leaf,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
    except OSError as exc:
        fail(f"cannot open exact file without following links: {spec.name}: {exc}")
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (before.st_uid, before.st_gid) != (uid, gid)
            or stat.S_IMODE(before.st_mode) not in allowed_modes
            or before.st_dev != root_device
            or descriptor_mount_id(descriptor) != root_mount
            or before.st_size != spec.size
            or os.listxattr(descriptor)
        ):
            fail(f"exact file metadata changed or is unsafe: {spec.name}")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if not stable(before, after):
            fail(f"exact file changed while hashing: {spec.name}")
        if digest.hexdigest() != spec.sha256:
            fail(f"exact file digest changed: {spec.name}")
    finally:
        os.close(descriptor)


def validate_packages(
    root_fd: int,
    specs: Sequence[FileSpec],
    uid: int,
    gid: int,
    root_device: int,
    root_mount: int,
) -> None:
    package_fd = open_child_directory(root_fd, "wix-nuget-packages")
    try:
        ensure_directory(
            package_fd,
            uid,
            gid,
            "WiX package directory",
            root_device,
            root_mount,
        )
        actual = tuple(sorted(os.listdir(package_fd)))
        expected = tuple(spec.name.rsplit("/", 1)[1] for spec in specs)
        if actual != expected:
            fail("WiX package directory is not the exact six-file inventory")
        for spec in specs:
            validate_file(
                package_fd,
                spec.name.rsplit("/", 1)[1],
                spec,
                uid,
                gid,
                root_device,
                root_mount,
                allowed_modes={0o400},
            )
    finally:
        os.close(package_fd)


def legacy_spec(
    parent_fd: int,
    six: FileSpec,
    eight: FileSpec,
    uid: int,
    gid: int,
    root_device: int,
    root_mount: int,
) -> FileSpec:
    try:
        metadata = os.stat(LEGACY_NAME, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        raise
    except OSError as exc:
        fail(f"cannot inspect obsolete WiX cache archive: {exc}")
    match = six if metadata.st_size == six.size else eight if metadata.st_size == eight.size else None
    if match is None:
        fail("obsolete WiX cache archive has an unknown size and was preserved")
    validate_file(
        parent_fd,
        LEGACY_NAME,
        match,
        uid,
        gid,
        root_device,
        root_mount,
        allowed_modes={0o644},
    )
    return match


def rename_noreplace(
    old_parent: int,
    old_name: str,
    new_parent: int,
    new_name: str,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        fail("renameat2(RENAME_NOREPLACE) is unavailable")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if (
        renameat2(
            old_parent,
            os.fsencode(old_name),
            new_parent,
            os.fsencode(new_name),
            RENAME_NOREPLACE,
        )
        != 0
    ):
        error = ctypes.get_errno()
        fail(f"cannot no-clobber retire obsolete WiX cache archive: {os.strerror(error)}")


def retire_staging(
    root_fd: int,
    name: str,
    six: FileSpec,
    eight: FileSpec,
    uid: int,
    gid: int,
    root_device: int,
    root_mount: int,
) -> None:
    staging_fd = open_child_directory(root_fd, name)
    try:
        ensure_directory(
            staging_fd,
            uid,
            gid,
            f"WiX retirement staging {name}",
            root_device,
            root_mount,
        )
        entries = tuple(sorted(os.listdir(staging_fd)))
        if entries == ():
            pass
        elif entries == (LEGACY_NAME,):
            legacy_spec(
                staging_fd,
                six,
                eight,
                uid,
                gid,
                root_device,
                root_mount,
            )
            os.unlink(LEGACY_NAME, dir_fd=staging_fd)
            os.fsync(staging_fd)
        else:
            fail(f"WiX retirement staging has unexpected entries and was preserved: {name}")
    finally:
        os.close(staging_fd)
    try:
        os.rmdir(name, dir_fd=root_fd)
        os.fsync(root_fd)
    except OSError as exc:
        fail(f"cannot retire empty WiX staging directory {name}: {exc}")


def recover_staging(
    root_fd: int,
    six: FileSpec,
    eight: FileSpec,
    uid: int,
    gid: int,
    root_device: int,
    root_mount: int,
) -> None:
    names = tuple(
        sorted(name for name in os.listdir(root_fd) if name.startswith(STAGING_PREFIX))
    )
    for name in names:
        retire_staging(
            root_fd,
            name,
            six,
            eight,
            uid,
            gid,
            root_device,
            root_mount,
        )


def retire(
    online: Path,
    package_specs: Sequence[FileSpec],
    six: FileSpec,
    eight: FileSpec,
    uid: int,
    gid: int,
) -> bool:
    if uid == 0 or gid == 0:
        fail("WiX retirement refuses root UID or GID")
    root_fd = open_directory(online)
    try:
        try:
            fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            fail(f"another online transaction owns the root: {exc}")
        root = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(root.st_mode)
            or (root.st_uid, root.st_gid) != (uid, gid)
            or stat.S_IMODE(root.st_mode) != 0o700
            or root.st_nlink < 2
            or os.listxattr(root_fd)
        ):
            fail("locked online root metadata is unsafe")
        root_device = root.st_dev
        root_mount = descriptor_mount_id(root_fd)
        validate_packages(
            root_fd,
            package_specs,
            uid,
            gid,
            root_device,
            root_mount,
        )
        recover_staging(
            root_fd,
            six,
            eight,
            uid,
            gid,
            root_device,
            root_mount,
        )
        try:
            legacy_spec(
                root_fd,
                six,
                eight,
                uid,
                gid,
                root_device,
                root_mount,
            )
        except FileNotFoundError:
            return False
        for _ in range(16):
            staging_name = STAGING_PREFIX + secrets.token_hex(12)
            try:
                os.mkdir(staging_name, mode=0o700, dir_fd=root_fd)
                break
            except FileExistsError:
                continue
            except OSError as exc:
                fail(f"cannot create private WiX retirement staging: {exc}")
        else:
            fail("cannot allocate a unique WiX retirement staging name")
        staging_fd = open_child_directory(root_fd, staging_name)
        try:
            ensure_directory(
                staging_fd,
                uid,
                gid,
                "new WiX retirement staging",
                root_device,
                root_mount,
            )
            rename_noreplace(root_fd, LEGACY_NAME, staging_fd, LEGACY_NAME)
            os.fsync(root_fd)
            os.fsync(staging_fd)
        finally:
            os.close(staging_fd)
        retire_staging(
            root_fd,
            staging_name,
            six,
            eight,
            uid,
            gid,
            root_device,
            root_mount,
        )
        return True
    finally:
        os.close(root_fd)


def self_test() -> None:
    uid = os.geteuid()
    gid = os.getegid()
    if uid == 0 or gid == 0:
        fail("self-test refuses root UID or GID")
    packages: list[FileSpec] = []
    with tempfile.TemporaryDirectory(prefix="wix-retire-self-test.") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        package_root = root / "wix-nuget-packages"
        package_root.mkdir(mode=0o700)
        for name in PACKAGE_NAMES:
            payload = f"package:{name}\n".encode("ascii")
            path = root / name
            path.write_bytes(payload)
            os.chmod(path, 0o400)
            packages.append(
                FileSpec(name, len(payload), hashlib.sha256(payload).hexdigest())
            )
        six_payload = b"legacy-six\n"
        eight_payload = b"legacy-eight\n"
        six = FileSpec(LEGACY_NAME, len(six_payload), hashlib.sha256(six_payload).hexdigest())
        eight = FileSpec(
            LEGACY_NAME,
            len(eight_payload),
            hashlib.sha256(eight_payload).hexdigest(),
        )
        legacy = root / LEGACY_NAME
        legacy.write_bytes(eight_payload)
        os.chmod(legacy, 0o644)
        if not retire(root, packages, six, eight, uid, gid):
            fail("self-test did not retire the exact legacy archive")
        if legacy.exists():
            fail("self-test left the exact legacy archive")
        if retire(root, packages, six, eight, uid, gid):
            fail("self-test reported an absent archive as retired")
        legacy.write_bytes(b"wrong-size")
        os.chmod(legacy, 0o644)
        try:
            retire(root, packages, six, eight, uid, gid)
        except ContractError:
            pass
        else:
            fail("self-test accepted an unknown legacy archive")
        if legacy.read_bytes() != b"wrong-size":
            fail("self-test changed an unknown legacy archive")
        legacy.unlink()
        legacy.write_bytes(six_payload)
        os.chmod(legacy, 0o600)
        try:
            retire(root, packages, six, eight, uid, gid)
        except ContractError:
            pass
        else:
            fail("self-test accepted an exact legacy archive in a nonhistorical mode")
        if legacy.read_bytes() != six_payload:
            fail("self-test changed an exact legacy archive in a nonhistorical mode")
        legacy.unlink()
        os.chmod(root, 0o750)
        try:
            retire(root, packages, six, eight, uid, gid)
        except ContractError:
            pass
        else:
            fail("self-test accepted a nonprivate online root")
        os.chmod(root, 0o700)
        staging = root / (STAGING_PREFIX + "recovery")
        staging.mkdir(mode=0o700)
        staged = staging / LEGACY_NAME
        staged.write_bytes(six_payload)
        os.chmod(staged, 0o644)
        if retire(root, packages, six, eight, uid, gid):
            fail("self-test reported recovered staging as a live retirement")
        if staging.exists():
            fail("self-test did not recover exact interrupted retirement staging")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subparsers = result.add_subparsers(dest="command", required=True)
    retire_parser = subparsers.add_parser("retire")
    retire_parser.add_argument("--online", type=Path, required=True)
    retire_parser.add_argument("--uid", type=int, required=True)
    retire_parser.add_argument("--gid", type=int, required=True)
    retire_parser.add_argument("--package", nargs=3, action="append", default=[])
    retire_parser.add_argument("--legacy-six-size", required=True)
    retire_parser.add_argument("--legacy-six-sha256", required=True)
    retire_parser.add_argument("--legacy-eight-size", required=True)
    retire_parser.add_argument("--legacy-eight-sha256", required=True)
    subparsers.add_parser("self-test")
    return result


def main() -> int:
    args = parser().parse_args()
    if args.command == "self-test":
        self_test()
        print("online-wix-nuget-retire: self-test PASS")
        return 0
    packages = parse_package_specs(args.package)
    six = FileSpec(
        LEGACY_NAME,
        parse_positive(args.legacy_six_size, "legacy six-package size"),
        parse_digest(args.legacy_six_sha256, "legacy six-package digest"),
    )
    eight = FileSpec(
        LEGACY_NAME,
        parse_positive(args.legacy_eight_size, "legacy eight-package size"),
        parse_digest(args.legacy_eight_sha256, "legacy eight-package digest"),
    )
    changed = retire(args.online, packages, six, eight, args.uid, args.gid)
    print("retired" if changed else "absent")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractError as exc:
        print(f"online-wix-nuget-retire: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
