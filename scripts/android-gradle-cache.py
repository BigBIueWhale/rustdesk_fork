#!/usr/bin/env python3
"""Project an immutable Gradle cache seed into a private writable build cache."""

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile


class ProjectionError(Exception):
    pass


SOURCE_DIRECTORY_MODE = 0o500
SOURCE_FILE_MODES = {0o400, 0o500}
DESTINATION_DIRECTORY_MODE = 0o700
DESTINATION_FILE_MODE = 0o600
DESTINATION_EXECUTABLE_MODE = 0o700
DESTINATION = Path("/tmp/gradle-home")
INIT_DESTINATION_NAME = "init.gradle"
ROOT_INIT_AUTHORITY_NAMES = {INIT_DESTINATION_NAME, "init.gradle.kts", "init.d"}
BLOCK_SIZE = 1024 * 1024
MOUNTINFO_LIMIT = 8 * 1024 * 1024


def fail(message):
    raise ProjectionError(message)


def mode(metadata):
    return stat.S_IMODE(metadata.st_mode)


def stable_identity(metadata):
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


def validate_source(metadata, display, root_device, uid, gid):
    if metadata.st_dev != root_device:
        fail("Gradle cache seed crosses a mount boundary: {}".format(display))
    if metadata.st_uid != uid or metadata.st_gid != gid:
        fail("Gradle cache seed has foreign ownership: {}".format(display))
    if stat.S_ISDIR(metadata.st_mode):
        if mode(metadata) != SOURCE_DIRECTORY_MODE:
            fail("Gradle cache seed directory is not mode 0500: {}".format(display))
        return "directory"
    if stat.S_ISREG(metadata.st_mode):
        if mode(metadata) not in SOURCE_FILE_MODES:
            fail("Gradle cache seed file is not mode 0400 or 0500: {}".format(display))
        if metadata.st_nlink != 1:
            fail("Gradle cache seed file is multiply linked: {}".format(display))
        return "file"
    fail("Gradle cache seed contains a link or special file: {}".format(display))


def decode_mount_path(value):
    decoded = bytearray()
    index = 0
    while index < len(value):
        if value[index] != ord("\\"):
            decoded.append(value[index])
            index += 1
            continue
        if (
            index + 3 >= len(value)
            or any(byte < ord("0") or byte > ord("7") for byte in value[index + 1:index + 4])
        ):
            fail("malformed escaped path in /proc/self/mountinfo")
        decoded.append(int(value[index + 1:index + 4], 8))
        index += 4
    return bytes(decoded)


def parse_mountinfo(data):
    records = []
    for line in data.splitlines():
        fields = line.split()
        try:
            separator = fields.index(b"-")
        except ValueError:
            fail("malformed /proc/self/mountinfo record")
        if separator < 6 or len(fields) < separator + 4:
            fail("truncated /proc/self/mountinfo record")
        try:
            mount_id = int(fields[0])
            parent_id = int(fields[1])
        except ValueError:
            fail("non-numeric mount identity in /proc/self/mountinfo")
        mountpoint = decode_mount_path(fields[4])
        if not mountpoint.startswith(b"/"):
            fail("non-absolute mountpoint in /proc/self/mountinfo")
        records.append((mount_id, parent_id, mountpoint))
    if not records:
        fail("/proc/self/mountinfo contains no mount records")
    return records


def read_mountinfo():
    descriptor = os.open(
        "/proc/self/mountinfo",
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        data = bytearray()
        while True:
            block = os.read(descriptor, min(BLOCK_SIZE, MOUNTINFO_LIMIT + 1 - len(data)))
            if not block:
                break
            data.extend(block)
            if len(data) > MOUNTINFO_LIMIT:
                fail("/proc/self/mountinfo exceeds the bounded input limit")
    finally:
        os.close(descriptor)
    return parse_mountinfo(bytes(data))


def path_at_or_below(path, root):
    if root == b"/":
        return path.startswith(b"/")
    return path == root or path.startswith(root.rstrip(b"/") + b"/")


def source_mount_authority(source):
    absolute = os.path.abspath(os.fsencode(source))
    canonical = os.path.realpath(absolute)
    if absolute != canonical:
        fail("Gradle cache seed path is not canonical: {}".format(source))
    relevant = tuple(
        sorted(
            record
            for record in read_mountinfo()
            if path_at_or_below(absolute, record[2]) or path_at_or_below(record[2], absolute)
        )
    )
    if not relevant:
        fail("Gradle cache seed has no mount authority")
    descendants = sorted(
        mountpoint
        for _, _, mountpoint in relevant
        if mountpoint != absolute and path_at_or_below(mountpoint, absolute)
    )
    if descendants:
        fail(
            "Gradle cache seed contains a descendant mount: {}"
            .format(os.fsdecode(descendants[0]))
        )
    return absolute, relevant


def validate_destination_parent():
    parent = DESTINATION.parent
    metadata = os.lstat(str(parent))
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("Gradle cache destination parent is not a real directory")
    if metadata.st_uid != 0 or metadata.st_gid != 0 or mode(metadata) != 0o1777:
        fail("Gradle cache destination parent is not root-owned mode 01777")
    if DESTINATION.exists() or DESTINATION.is_symlink():
        fail("Gradle cache destination already exists: {}".format(DESTINATION))


def write_all(descriptor, data):
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            fail("short write while projecting Gradle cache")
        view = view[written:]


def digest_descriptor(descriptor):
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        block = os.read(descriptor, BLOCK_SIZE)
        if not block:
            return digest.digest()
        digest.update(block)


def copy_file(source_parent, destination_parent, name, source_metadata, display):
    source_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    destination_flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_CREAT | os.O_EXCL
    destination_mode = (
        DESTINATION_EXECUTABLE_MODE
        if mode(source_metadata) == SOURCE_DIRECTORY_MODE
        else DESTINATION_FILE_MODE
    )
    source_fd = os.open(name, source_flags, dir_fd=source_parent)
    destination_fd = -1
    try:
        before = os.fstat(source_fd)
        if stable_identity(before) != stable_identity(source_metadata):
            fail("Gradle cache seed changed before read: {}".format(display))
        destination_fd = os.open(
            name,
            destination_flags,
            destination_mode,
            dir_fd=destination_parent,
        )
        source_digest = hashlib.sha256()
        copied = 0
        while True:
            block = os.read(source_fd, BLOCK_SIZE)
            if not block:
                break
            source_digest.update(block)
            write_all(destination_fd, block)
            copied += len(block)
        after = os.fstat(source_fd)
        if stable_identity(before) != stable_identity(after):
            fail("Gradle cache seed changed during read: {}".format(display))
        if copied != before.st_size:
            fail("Gradle cache seed produced a short read: {}".format(display))
        os.fchmod(destination_fd, destination_mode)
        os.utime(
            destination_fd,
            ns=(before.st_atime_ns, before.st_mtime_ns),
        )
        destination_metadata = os.fstat(destination_fd)
        if (
            not stat.S_ISREG(destination_metadata.st_mode)
            or destination_metadata.st_uid != os.geteuid()
            or destination_metadata.st_gid != os.getegid()
            or mode(destination_metadata) != destination_mode
            or destination_metadata.st_nlink != 1
            or destination_metadata.st_size != before.st_size
            or destination_metadata.st_mtime_ns != before.st_mtime_ns
        ):
            fail("projected Gradle cache file metadata is invalid: {}".format(display))
        destination_digest = digest_descriptor(destination_fd)
        if destination_digest != source_digest.digest():
            fail("projected Gradle cache file bytes differ: {}".format(display))
        return (destination_mode, before.st_size, before.st_mtime_ns, destination_digest)
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        os.close(source_fd)


def copy_directory(source_fd, destination_fd, relative, root_device, uid, gid, records):
    source_before = os.fstat(source_fd)
    display = relative or "."
    if validate_source(source_before, display, root_device, uid, gid) != "directory":
        fail("Gradle cache seed root is not a directory")
    records[relative] = ("directory", DESTINATION_DIRECTORY_MODE, source_before.st_mtime_ns)
    with os.scandir(source_fd) as iterator:
        entries = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
    for entry in entries:
        child_relative = entry.name if not relative else relative + "/" + entry.name
        if (
            (not relative and entry.name in ROOT_INIT_AUTHORITY_NAMES)
            or (
                relative.split("/")[-1] == "init.d"
                and entry.name.endswith((".gradle", ".gradle.kts"))
            )
        ):
            fail("Gradle cache seed contains ambient init authority: {}".format(child_relative))
        source_metadata = entry.stat(follow_symlinks=False)
        kind = validate_source(source_metadata, child_relative, root_device, uid, gid)
        if kind == "directory":
            os.mkdir(
                entry.name,
                DESTINATION_DIRECTORY_MODE,
                dir_fd=destination_fd,
            )
            source_child = os.open(
                entry.name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=source_fd,
            )
            destination_child = os.open(
                entry.name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=destination_fd,
            )
            try:
                copy_directory(
                    source_child,
                    destination_child,
                    child_relative,
                    root_device,
                    uid,
                    gid,
                    records,
                )
                os.fchmod(destination_child, DESTINATION_DIRECTORY_MODE)
                os.utime(
                    destination_child,
                    ns=(source_metadata.st_atime_ns, source_metadata.st_mtime_ns),
                )
            finally:
                os.close(destination_child)
                os.close(source_child)
        else:
            file_record = copy_file(
                source_fd,
                destination_fd,
                entry.name,
                source_metadata,
                child_relative,
            )
            records[child_relative] = ("file",) + file_record
    source_after = os.fstat(source_fd)
    if stable_identity(source_before) != stable_identity(source_after):
        fail("Gradle cache seed directory changed during traversal: {}".format(display))


def install_init_script(source, destination_fd, uid, gid, records):
    source_metadata = os.lstat(str(source))
    if (
        not stat.S_ISREG(source_metadata.st_mode)
        or stat.S_ISLNK(source_metadata.st_mode)
        or source_metadata.st_uid != uid
        or source_metadata.st_gid != gid
        or mode(source_metadata) not in {0o600, 0o644}
        or source_metadata.st_nlink != 1
        or source_metadata.st_size == 0
        or source_metadata.st_size > 64 * 1024
    ):
        fail("Gradle offline init authority must be a current-owner mode-0600/0644 regular file: {}".format(source))

    source_fd = os.open(
        str(source),
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    projected_fd = -1
    try:
        before = os.fstat(source_fd)
        if stable_identity(before) != stable_identity(source_metadata):
            fail("Gradle offline init authority changed before read")
        projected_fd = os.open(
            INIT_DESTINATION_NAME,
            os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_CREAT | os.O_EXCL,
            DESTINATION_FILE_MODE,
            dir_fd=destination_fd,
        )
        source_digest = hashlib.sha256()
        copied = 0
        while True:
            block = os.read(source_fd, BLOCK_SIZE)
            if not block:
                break
            source_digest.update(block)
            write_all(projected_fd, block)
            copied += len(block)
        after = os.fstat(source_fd)
        if stable_identity(before) != stable_identity(after):
            fail("Gradle offline init authority changed during read")
        if copied != before.st_size:
            fail("Gradle offline init authority produced a short read")
        os.fchmod(projected_fd, DESTINATION_FILE_MODE)
        os.utime(projected_fd, ns=(0, 0))
        projected_metadata = os.fstat(projected_fd)
        projected_digest = digest_descriptor(projected_fd)
        if (
            not stat.S_ISREG(projected_metadata.st_mode)
            or projected_metadata.st_uid != uid
            or projected_metadata.st_gid != gid
            or mode(projected_metadata) != DESTINATION_FILE_MODE
            or projected_metadata.st_nlink != 1
            or projected_metadata.st_size != before.st_size
            or projected_metadata.st_mtime_ns != 0
            or projected_digest != source_digest.digest()
        ):
            fail("projected Gradle offline init authority differs from its source")
        records[INIT_DESTINATION_NAME] = (
            "file",
            DESTINATION_FILE_MODE,
            before.st_size,
            0,
            projected_digest,
        )
    finally:
        if projected_fd >= 0:
            os.close(projected_fd)
        os.close(source_fd)


def destination_records(root):
    uid = os.geteuid()
    gid = os.getegid()
    records = {}

    def descend(directory, relative):
        metadata = os.lstat(str(directory))
        display = relative or "."
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            fail("projected Gradle cache directory is invalid: {}".format(display))
        if (
            metadata.st_uid != uid
            or metadata.st_gid != gid
            or mode(metadata) != DESTINATION_DIRECTORY_MODE
        ):
            fail("projected Gradle cache directory metadata is invalid: {}".format(display))
        records[relative] = ("directory", DESTINATION_DIRECTORY_MODE, metadata.st_mtime_ns)
        with os.scandir(str(directory)) as iterator:
            entries = sorted(iterator, key=lambda entry: os.fsencode(entry.name))
        for entry in entries:
            child_relative = entry.name if not relative else relative + "/" + entry.name
            child = directory / entry.name
            child_metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(child_metadata.st_mode) and not stat.S_ISLNK(child_metadata.st_mode):
                descend(child, child_relative)
                continue
            if not stat.S_ISREG(child_metadata.st_mode):
                fail("projected Gradle cache contains a link or special file: {}".format(child_relative))
            if (
                child_metadata.st_uid != uid
                or child_metadata.st_gid != gid
                or mode(child_metadata) not in {DESTINATION_FILE_MODE, DESTINATION_EXECUTABLE_MODE}
                or child_metadata.st_nlink != 1
            ):
                fail("projected Gradle cache file metadata is invalid: {}".format(child_relative))
            descriptor = os.open(
                str(child),
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                digest = digest_descriptor(descriptor)
            finally:
                os.close(descriptor)
            records[child_relative] = (
                "file",
                mode(child_metadata),
                child_metadata.st_size,
                child_metadata.st_mtime_ns,
                digest,
            )

    descend(root, "")
    return records


def projection_digest(records):
    digest = hashlib.sha256()
    for name in sorted(records, key=os.fsencode):
        record = records[name]
        encoded_name = os.fsencode(name)
        digest.update(len(encoded_name).to_bytes(8, "big"))
        digest.update(encoded_name)
        digest.update(repr(record[:-1] if record[0] == "file" else record).encode("ascii"))
        if record[0] == "file":
            digest.update(record[-1])
    return digest.hexdigest()


def materialize(source, init_script):
    uid = os.geteuid()
    gid = os.getegid()
    source_metadata = os.lstat(str(source))
    if not stat.S_ISDIR(source_metadata.st_mode) or stat.S_ISLNK(source_metadata.st_mode):
        fail("Gradle cache seed is not a real directory: {}".format(source))
    validate_source(source_metadata, ".", source_metadata.st_dev, uid, gid)
    source_absolute, source_mounts = source_mount_authority(source)
    validate_destination_parent()
    created = False
    source_fd = -1
    destination_fd = -1
    try:
        os.mkdir(str(DESTINATION), DESTINATION_DIRECTORY_MODE)
        created = True
        source_fd = os.open(
            str(source),
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        destination_fd = os.open(
            str(DESTINATION),
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        if stable_identity(os.fstat(source_fd)) != stable_identity(source_metadata):
            fail("Gradle cache seed root changed before traversal")
        records = {}
        copy_directory(
            source_fd,
            destination_fd,
            "",
            source_metadata.st_dev,
            uid,
            gid,
            records,
        )
        install_init_script(init_script, destination_fd, uid, gid, records)
        if source_mount_authority(Path(os.fsdecode(source_absolute)))[1] != source_mounts:
            fail("Gradle cache seed mount authority changed during projection")
        os.fchmod(destination_fd, DESTINATION_DIRECTORY_MODE)
        os.utime(
            destination_fd,
            ns=(source_metadata.st_atime_ns, source_metadata.st_mtime_ns),
        )
        observed = destination_records(DESTINATION)
        if observed != records:
            fail("projected Gradle cache inventory differs from its immutable seed")
        return projection_digest(records)
    except BaseException as error:
        if created:
            try:
                shutil.rmtree(str(DESTINATION))
            except BaseException as cleanup_error:
                raise ProjectionError(
                    "failed Gradle cache projection also failed to remove its private destination: {}"
                    .format(cleanup_error)
                ) from error
        raise
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        if source_fd >= 0:
            os.close(source_fd)


def writable_tree(root):
    if not root.exists() or root.is_symlink():
        return
    for directory, directories, files in os.walk(str(root), topdown=False, followlinks=False):
        for name in files:
            path = Path(directory) / name
            if not path.is_symlink():
                path.chmod(0o600)
        for name in directories:
            path = Path(directory) / name
            if not path.is_symlink():
                path.chmod(0o700)
    root.chmod(0o700)


def source_fingerprint(root):
    result = []
    for directory, directories, files in os.walk(str(root), followlinks=False):
        directories.sort(key=os.fsencode)
        files.sort(key=os.fsencode)
        directory_path = Path(directory)
        for name in [None] + files:
            path = directory_path if name is None else directory_path / name
            metadata = os.lstat(str(path))
            relative = str(path.relative_to(root)) if path != root else "."
            digest = None
            if stat.S_ISREG(metadata.st_mode):
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            result.append(
                (
                    relative,
                    metadata.st_mode,
                    metadata.st_uid,
                    metadata.st_gid,
                    metadata.st_nlink,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                    digest,
                )
            )
    return result


def expect_failure(operation, expected):
    try:
        operation()
    except ProjectionError as error:
        if expected not in str(error):
            fail("unexpected self-test failure: {}".format(error))
        return
    fail("self-test accepted invalid Gradle cache seed: {}".format(expected))


def self_test(init_script):
    if os.geteuid() == 0:
        fail("Gradle cache projection self-test must run as a non-root UID")
    validate_destination_parent()
    scratch = Path(tempfile.mkdtemp(prefix="android-gradle-cache-test-", dir="/tmp"))
    source = scratch / "seed"
    owned_destination = None

    def record_owned_destination():
        nonlocal owned_destination
        metadata = os.lstat(str(DESTINATION))
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or mode(metadata) != DESTINATION_DIRECTORY_MODE
        ):
            fail("self-test destination has invalid ownership metadata")
        owned_destination = (metadata.st_dev, metadata.st_ino)

    def remove_owned_destination():
        nonlocal owned_destination
        if owned_destination is None:
            return
        metadata = os.lstat(str(DESTINATION))
        if (metadata.st_dev, metadata.st_ino) != owned_destination:
            fail("self-test destination identity changed before cleanup")
        writable_tree(DESTINATION)
        shutil.rmtree(str(DESTINATION))
        if DESTINATION.exists() or DESTINATION.is_symlink():
            fail("self-test destination remains after cleanup")
        owned_destination = None

    try:
        mount_fixture = (
            b"1 0 8:1 / / rw - ext4 /dev/root rw\n"
            b"2 1 8:1 /cache /tmp/seed\\040name/cache rw - none none rw\n"
        )
        parsed_fixture = parse_mountinfo(mount_fixture)
        if parsed_fixture[1][2] != b"/tmp/seed name/cache":
            fail("mountinfo escaped-path parsing self-test failed")
        if not path_at_or_below(parsed_fixture[1][2], b"/tmp/seed name"):
            fail("mountinfo descendant classification self-test failed")

        source.mkdir(mode=0o700)
        nested = source / "caches" / "modules"
        nested.mkdir(parents=True)
        payload = nested / "payload.bin"
        payload.write_bytes(b"immutable-cache-payload\n")
        executable = source / "wrapper-tool"
        executable.write_bytes(b"#!/bin/sh\nexit 0\n")
        executable.chmod(0o500)
        payload.chmod(0o400)
        nested.chmod(0o500)
        nested.parent.chmod(0o500)
        source.chmod(0o500)
        before = source_fingerprint(source)

        first = materialize(source, init_script)
        record_owned_destination()
        if source_fingerprint(source) != before:
            fail("Gradle cache seed changed during successful projection")
        clone_payload = DESTINATION / "caches" / "modules" / "payload.bin"
        if clone_payload.stat().st_ino == payload.stat().st_ino:
            fail("projected Gradle cache remains hardlinked to its seed")
        with clone_payload.open("ab") as stream:
            stream.write(b"private-mutation\n")
        lock = DESTINATION / "caches" / "modules" / "build.lock"
        renamed = lock.with_name("build.lock.ready")
        lock.write_bytes(b"lock")
        lock.rename(renamed)
        renamed.unlink()
        remove_owned_destination()

        second = materialize(source, init_script)
        record_owned_destination()
        if first != second or source_fingerprint(source) != before:
            fail("successive Gradle cache projections differ or mutate their seed")
        remove_owned_destination()

        symlink_seed = scratch / "symlink-seed"
        shutil.copytree(str(source), str(symlink_seed))
        writable_tree(symlink_seed)
        os.symlink("caches/modules/payload.bin", str(symlink_seed / "link"))
        for directory, directories, files in os.walk(str(symlink_seed), topdown=False):
            for name in files:
                path = Path(directory) / name
                if not path.is_symlink():
                    path.chmod(0o400)
            for name in directories:
                (Path(directory) / name).chmod(0o500)
        symlink_seed.chmod(0o500)
        expect_failure(lambda: materialize(symlink_seed, init_script), "link or special file")
        if DESTINATION.exists() or DESTINATION.is_symlink():
            fail("failed Gradle cache projection retained a destination")

        writable_tree(symlink_seed)
        shutil.rmtree(str(symlink_seed))
        hardlink_seed = scratch / "hardlink-seed"
        hardlink_seed.mkdir()
        original = hardlink_seed / "original"
        original.write_bytes(b"linked")
        os.link(str(original), str(hardlink_seed / "alias"))
        original.chmod(0o400)
        hardlink_seed.chmod(0o500)
        expect_failure(lambda: materialize(hardlink_seed, init_script), "multiply linked")

        writable_tree(hardlink_seed)
        shutil.rmtree(str(hardlink_seed))

        for reserved in sorted(ROOT_INIT_AUTHORITY_NAMES):
            reserved_seed = scratch / ("reserved-" + reserved.replace(".", "-"))
            reserved_seed.mkdir()
            if reserved == INIT_DESTINATION_NAME:
                (reserved_seed / reserved).write_bytes(b"untrusted init\n")
                (reserved_seed / reserved).chmod(0o400)
            else:
                (reserved_seed / reserved).mkdir()
                (reserved_seed / reserved).chmod(0o500)
            reserved_seed.chmod(0o500)
            expect_failure(
                lambda seed=reserved_seed: materialize(seed, init_script),
                "ambient init authority",
            )
            writable_tree(reserved_seed)
            shutil.rmtree(str(reserved_seed))

        distribution_seed = scratch / "distribution-init"
        distribution_init = distribution_seed / "wrapper" / "gradle" / "init.d"
        distribution_init.mkdir(parents=True)
        hostile_init = distribution_init / "hostile.gradle.kts"
        hostile_init.write_bytes(b"throw GradleException(\"ambient\")\n")
        hostile_init.chmod(0o400)
        for directory in (distribution_init, distribution_init.parent, distribution_init.parent.parent):
            directory.chmod(0o500)
        distribution_seed.chmod(0o500)
        expect_failure(
            lambda: materialize(distribution_seed, init_script),
            "ambient init authority",
        )
        writable_tree(distribution_seed)
        shutil.rmtree(str(distribution_seed))

        DESTINATION.mkdir(mode=0o700)
        record_owned_destination()
        marker = DESTINATION / "marker"
        marker.write_bytes(b"do-not-adopt")
        expect_failure(lambda: materialize(source, init_script), "destination already exists")
        if marker.read_bytes() != b"do-not-adopt":
            fail("pre-existing Gradle cache destination was modified")
        remove_owned_destination()
    finally:
        remove_owned_destination()
        writable_tree(scratch)
        shutil.rmtree(str(scratch))
    if DESTINATION.exists() or DESTINATION.is_symlink() or scratch.exists():
        fail("Gradle cache projection self-test cleanup is incomplete")


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    subparsers = value.add_subparsers(dest="command", required=True)
    materialize_parser = subparsers.add_parser("materialize")
    materialize_parser.add_argument("--source", type=Path, required=True)
    materialize_parser.add_argument("--init-script", type=Path, required=True)
    self_test_parser = subparsers.add_parser("self-test")
    self_test_parser.add_argument("--init-script", type=Path, required=True)
    return value


def main():
    arguments = parser().parse_args()
    if arguments.command == "materialize":
        digest = materialize(arguments.source, arguments.init_script)
        print("android Gradle cache projection verified {}".format(digest))
    elif arguments.command == "self-test":
        self_test(arguments.init_script)
        print("android Gradle cache projection self-test: OK")
    else:
        fail("unsupported command")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ProjectionError) as error:
        print("android-gradle-cache: FATAL: {}".format(error), file=sys.stderr)
        raise SystemExit(1)
