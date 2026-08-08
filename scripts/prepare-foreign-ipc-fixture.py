#!/usr/bin/env python3
"""Create exact foreign-owned IPC directory fixtures as an ordinary numeric user."""

import argparse
import errno
import os
from pathlib import Path
import stat
import struct
import sys


ACL_XATTR = b"system.posix_acl_access"
FIXTURE_NAMES = ("nonempty-service", "recreate-service")
KNOWN_ENTRIES = ("ipc_service", "ipc_service.pid")
MAX_NUMERIC_ID = 2_147_483_647


class FixtureError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise FixtureError(message)


def parse_numeric_id(value, label):
    try:
        parsed = int(value, 10)
    except (TypeError, ValueError) as error:
        raise FixtureError("{} must be a decimal numeric ID".format(label)) from error
    require(0 < parsed <= MAX_NUMERIC_ID, "{} must be a non-root Docker numeric ID".format(label))
    return parsed


def acl_entry(tag, permissions, qualifier=0xFFFFFFFF):
    return struct.pack("<HHI", tag, permissions, qualifier)


def foreign_access_acl(foreign_uid, actor_uid):
    # Linux POSIX access ACL xattr version 2, in canonical tag order:
    # owner rwx, sorted named users rwx, group r-x, mask rwx, other r-x. The
    # foreign entry is the grant whose destruction the Rust test proves. The
    # actor entry supplies only the directory-write authority that production
    # root obtains from the kernel, without granting the test container root or
    # a capability; the implementation must still remove only known entries.
    require(actor_uid != foreign_uid, "foreign and actor ACL UIDs must differ")
    entries = [struct.pack("<I", 2), acl_entry(0x01, 0x07)]
    entries.extend(acl_entry(0x02, 0x07, uid) for uid in sorted((foreign_uid, actor_uid)))
    entries.extend(
        (
            acl_entry(0x04, 0x05),
            acl_entry(0x10, 0x07),
            acl_entry(0x20, 0x05),
        )
    )
    return b"".join(entries)


def open_directory(path, *, dir_fd=None, path_only=False):
    if path_only:
        require(hasattr(os, "O_PATH"), "Linux O_PATH directory descriptors are unavailable")
        flags = os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC
    else:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(path, flags, dir_fd=dir_fd)


def stable_root(root, actor_uid, actor_gid):
    require(root == Path("/fixture"), "fixture root must be exactly /fixture")
    root_fd = open_directory(root, path_only=True)
    metadata = os.fstat(root_fd)
    edge = os.lstat(root)
    require(stat.S_ISDIR(metadata.st_mode), "fixture root is not a directory")
    require((metadata.st_dev, metadata.st_ino) == (edge.st_dev, edge.st_ino), "fixture root edge changed")
    require(metadata.st_nlink == 2, "fixture root must begin without child directories")
    require(metadata.st_uid == actor_uid, "fixture root owner differs")
    require(metadata.st_gid == actor_gid, "fixture root group differs")
    require(stat.S_IMODE(metadata.st_mode) == 0o733, "fixture root mode differs")
    return root_fd, metadata


def stable_cleanup_root(root, actor_uid, actor_gid):
    require(root == Path("/fixture"), "fixture root must be exactly /fixture")
    require(os.geteuid() == actor_uid, "fixture cleanup must run as the actor UID")
    require(os.getegid() == actor_gid, "fixture cleanup must run as the actor GID")
    root_fd = open_directory(root)
    metadata = os.fstat(root_fd)
    edge = os.lstat(root)
    require(stat.S_ISDIR(metadata.st_mode), "fixture cleanup root is not a directory")
    require(
        (metadata.st_dev, metadata.st_ino) == (edge.st_dev, edge.st_ino),
        "fixture cleanup root edge changed",
    )
    require(metadata.st_nlink == 4, "fixture cleanup root child cardinality differs")
    require(metadata.st_uid == actor_uid, "fixture cleanup root owner differs")
    require(metadata.st_gid == actor_gid, "fixture cleanup root group differs")
    require(stat.S_IMODE(metadata.st_mode) == 0o733, "fixture cleanup root mode differs")
    return root_fd, metadata


def create_regular_at(parent_fd, name, content, *, mode=0o600):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, mode, dir_fd=parent_fd)
    try:
        written = 0
        while written < len(content):
            count = os.write(descriptor, content[written:])
            require(count > 0, "fixture write made no progress")
            written += count
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode), "fixture entry is not regular")
        require(metadata.st_nlink == 1, "fixture entry is hardlinked")
        require(metadata.st_uid == os.geteuid(), "fixture entry owner differs")
        require(stat.S_IMODE(metadata.st_mode) == mode, "fixture entry mode differs")
    finally:
        os.close(descriptor)


def create_foreign_directory(root_fd, name, foreign_uid, acl, *, attacker_junk):
    os.mkdir(name, 0o733, dir_fd=root_fd)
    child_fd = open_directory(name, dir_fd=root_fd)
    try:
        child = os.fstat(child_fd)
        require(stat.S_ISDIR(child.st_mode), "foreign fixture child is not a directory")
        require(child.st_uid == foreign_uid, "foreign fixture child owner differs")
        require(child.st_gid == os.getegid(), "foreign fixture child group differs")
        require(child.st_nlink == 2, "foreign fixture child is not initially empty")
        for entry_name in KNOWN_ENTRIES:
            create_regular_at(child_fd, entry_name, b"stale")
        if attacker_junk:
            # The actor must be able to prove this unknown byte survives the
            # fail-closed path without receiving root or file-read capability.
            # Directory write authority remains controlled by the access ACL.
            create_regular_at(child_fd, "attacker-junk", b"x", mode=0o644)
        try:
            os.setxattr(child_fd, ACL_XATTR, acl, 0)
        except OSError as error:
            raise FixtureError(
                "required non-root POSIX ACL fixture is unavailable: {}".format(error)
            ) from error
        require(os.getxattr(child_fd, ACL_XATTR) == acl, "foreign POSIX ACL bytes differ")
    finally:
        os.close(child_fd)


def verify_fixture(root_fd, foreign_uid, acl):
    root = os.fstat(root_fd)
    require(root.st_nlink == 4, "fixture root child-directory cardinality differs")
    for name in FIXTURE_NAMES:
        child_fd = open_directory(name, dir_fd=root_fd)
        try:
            metadata = os.fstat(child_fd)
            require(metadata.st_uid == foreign_uid, "foreign fixture owner differs")
            require(os.getxattr(child_fd, ACL_XATTR) == acl, "foreign fixture ACL differs")
            expected = set(KNOWN_ENTRIES)
            if name == "nonempty-service":
                expected.add("attacker-junk")
            require(set(os.listdir(child_fd)) == expected, "foreign fixture entry inventory differs")
        finally:
            os.close(child_fd)


def read_acl_or_none(descriptor):
    try:
        return os.getxattr(descriptor, ACL_XATTR)
    except OSError as error:
        if error.errno in (errno.ENODATA, getattr(errno, "ENOATTR", errno.ENODATA)):
            return None
        raise


def open_entry_authority(parent_fd, name, foreign_uid, foreign_gid, expected_mode):
    metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    require(stat.S_ISREG(metadata.st_mode), "fixture cleanup entry is not regular")
    require(metadata.st_nlink == 1, "fixture cleanup entry is hardlinked")
    require(metadata.st_uid == foreign_uid, "fixture cleanup entry owner differs")
    require(metadata.st_gid == foreign_gid, "fixture cleanup entry group differs")
    require(stat.S_IMODE(metadata.st_mode) == expected_mode, "fixture cleanup entry mode differs")
    expected_size = 1 if name == "attacker-junk" else len(b"stale")
    require(metadata.st_size == expected_size, "fixture cleanup entry size differs")
    descriptor = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    opened = os.fstat(descriptor)
    require(
        (opened.st_dev, opened.st_ino) == (metadata.st_dev, metadata.st_ino),
        "fixture cleanup entry changed during acquisition",
    )
    return descriptor, metadata


def acquire_cleanup_directory(root_fd, name, actor_uid, actor_gid, foreign_uid, foreign_gid, acl):
    child_fd = open_directory(name, dir_fd=root_fd)
    entry_authorities = {}
    try:
        metadata = os.fstat(child_fd)
        edge = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        require(stat.S_ISDIR(metadata.st_mode), "fixture cleanup child is not a directory")
        require(
            (metadata.st_dev, metadata.st_ino) == (edge.st_dev, edge.st_ino),
            "fixture cleanup child edge changed",
        )
        entries = set(os.listdir(child_fd))
        if name == "recreate-service" and metadata.st_uid == actor_uid:
            require(metadata.st_gid == actor_gid, "recreated fixture group differs")
            require(stat.S_IMODE(metadata.st_mode) == 0o711, "recreated fixture mode differs")
            require(metadata.st_nlink == 2, "recreated fixture link count differs")
            require(entries == set(), "recreated fixture is not empty")
            require(read_acl_or_none(child_fd) is None, "recreated fixture retained an access ACL")
        else:
            require(metadata.st_uid == foreign_uid, "foreign cleanup fixture owner differs")
            require(metadata.st_gid == foreign_gid, "foreign cleanup fixture group differs")
            require(stat.S_IMODE(metadata.st_mode) == 0o775, "foreign cleanup fixture mode differs")
            require(metadata.st_nlink == 2, "foreign cleanup fixture link count differs")
            require(read_acl_or_none(child_fd) == acl, "foreign cleanup fixture ACL differs")
            allowed = set(KNOWN_ENTRIES)
            if name == "nonempty-service":
                allowed.add("attacker-junk")
                require("attacker-junk" in entries, "fail-closed marker is absent")
            require(entries.issubset(allowed), "fixture cleanup found an unknown entry")
            require(
                entries in ({"attacker-junk"}, allowed) if name == "nonempty-service" else entries in (set(), allowed),
                "fixture cleanup found a partial known-entry state",
            )
            for entry_name in sorted(entries):
                expected_mode = 0o644 if entry_name == "attacker-junk" else 0o600
                entry_authorities[entry_name] = open_entry_authority(
                    child_fd,
                    entry_name,
                    foreign_uid,
                    foreign_gid,
                    expected_mode,
                )
        return child_fd, metadata, entry_authorities
    except BaseException:
        for descriptor, _metadata in entry_authorities.values():
            os.close(descriptor)
        os.close(child_fd)
        raise


def remove_acquired_directory(root_fd, name, child_fd, metadata, entry_authorities):
    try:
        for entry_name, (descriptor, expected) in entry_authorities.items():
            current = os.stat(entry_name, dir_fd=child_fd, follow_symlinks=False)
            opened = os.fstat(descriptor)
            expected_identity = (expected.st_dev, expected.st_ino)
            require(
                (current.st_dev, current.st_ino) == expected_identity
                and (opened.st_dev, opened.st_ino) == expected_identity,
                "fixture cleanup entry changed before unlink",
            )
            os.unlink(entry_name, dir_fd=child_fd)
            require(os.fstat(descriptor).st_nlink == 0, "fixture cleanup unlink retained an edge")
        require(os.listdir(child_fd) == [], "fixture cleanup child remains nonempty")
        current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        require(
            (current.st_dev, current.st_ino) == (metadata.st_dev, metadata.st_ino),
            "fixture cleanup child changed before removal",
        )
        os.rmdir(name, dir_fd=root_fd)
        require(os.fstat(child_fd).st_nlink == 0, "fixture cleanup directory retained an edge")
    finally:
        for descriptor, _metadata in entry_authorities.values():
            os.close(descriptor)
        os.close(child_fd)


def cleanup(root, actor_uid, actor_gid, foreign_uid, foreign_gid):
    require(foreign_uid != actor_uid, "fixture cleanup principals must differ")
    require(foreign_uid != 0 and foreign_gid != 0, "fixture cleanup foreign principal must be non-root")
    root_fd, before = stable_cleanup_root(root, actor_uid, actor_gid)
    acl = foreign_access_acl(foreign_uid, actor_uid)
    acquired = []
    try:
        for name in FIXTURE_NAMES:
            acquired.append(
                (
                    name,
                    *acquire_cleanup_directory(
                        root_fd,
                        name,
                        actor_uid,
                        actor_gid,
                        foreign_uid,
                        foreign_gid,
                        acl,
                    ),
                )
            )
        while acquired:
            name, child_fd, metadata, entries = acquired.pop(0)
            remove_acquired_directory(root_fd, name, child_fd, metadata, entries)
        require(os.listdir(root_fd) == [], "fixture cleanup root remains nonempty")
        os.fchmod(root_fd, 0o700)
        os.fsync(root_fd)
        after = os.fstat(root_fd)
        require(
            (before.st_dev, before.st_ino, before.st_uid, before.st_gid)
            == (after.st_dev, after.st_ino, after.st_uid, after.st_gid),
            "fixture cleanup root identity changed",
        )
        require(after.st_nlink == 2, "fixture cleanup root link count differs")
        require(stat.S_IMODE(after.st_mode) == 0o700, "fixture cleanup root final mode differs")
    finally:
        for _name, child_fd, _metadata, entries in acquired:
            for descriptor, _entry_metadata in entries.values():
                os.close(descriptor)
            os.close(child_fd)
        os.close(root_fd)
    print(
        "prepare-foreign-ipc-fixture: cleanup ok actor={}:{} foreign={}:{} dirs=2 root=0700".format(
            actor_uid, actor_gid, foreign_uid, foreign_gid
        )
    )


def prepare(root, actor_uid, actor_gid):
    foreign_uid = os.geteuid()
    foreign_gid = os.getegid()
    require(foreign_uid != 0 and foreign_gid != 0, "fixture preparer must be non-root")
    require(foreign_uid != actor_uid, "fixture preparer and actor UIDs must differ")
    root_fd, before = stable_root(root, actor_uid, actor_gid)
    acl = foreign_access_acl(foreign_uid, actor_uid)
    try:
        create_foreign_directory(
            root_fd,
            "recreate-service",
            foreign_uid,
            acl,
            attacker_junk=False,
        )
        create_foreign_directory(
            root_fd,
            "nonempty-service",
            foreign_uid,
            acl,
            attacker_junk=True,
        )
        verify_fixture(root_fd, foreign_uid, acl)
        after = os.fstat(root_fd)
        require(
            (before.st_dev, before.st_ino, before.st_uid, before.st_gid)
            == (after.st_dev, after.st_ino, after.st_uid, after.st_gid),
            "fixture root identity changed",
        )
    finally:
        os.close(root_fd)
    print(
        "prepare-foreign-ipc-fixture: ok actor={}:{} foreign={}:{} dirs=2 acl=required".format(
            actor_uid, actor_gid, foreign_uid, foreign_gid
        )
    )


def self_test():
    checks = 0
    acl = foreign_access_acl(65534, 1000)
    require(len(acl) == 52, "ACL byte length differs")
    checks += 1
    require(acl[:4] == struct.pack("<I", 2), "ACL version differs")
    checks += 1
    require(acl[12:20] == acl_entry(0x02, 0x07, 1000), "actor ACL entry differs")
    require(acl[20:28] == acl_entry(0x02, 0x07, 65534), "foreign ACL entry differs")
    checks += 1
    require(parse_numeric_id("65534", "test UID") == 65534, "numeric ID parse differs")
    checks += 1
    try:
        parse_numeric_id("0", "test UID")
    except FixtureError:
        checks += 1
    else:
        raise FixtureError("root numeric ID self-test mutation was accepted")
    require(read_acl_or_none, "ACL absence reader is unavailable")
    checks += 1
    require(FIXTURE_NAMES == ("nonempty-service", "recreate-service"), "fixture names differ")
    checks += 1
    require(checks == 7, "self-test check count differs")
    print("prepare-foreign-ipc-fixture: self-test ok (7 checks)")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path)
    parser.add_argument("--actor-uid")
    parser.add_argument("--actor-gid")
    parser.add_argument("--foreign-uid")
    parser.add_argument("--foreign-gid")
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        require(
            args.root is None
            and args.actor_uid is None
            and args.actor_gid is None
            and args.foreign_uid is None
            and args.foreign_gid is None
            and not args.cleanup,
            "self-test takes no fixture arguments",
        )
        self_test()
        return 0
    require(args.root is not None, "fixture root is required")
    actor_uid = parse_numeric_id(args.actor_uid, "actor UID")
    actor_gid = parse_numeric_id(args.actor_gid, "actor GID")
    if args.cleanup:
        foreign_uid = parse_numeric_id(args.foreign_uid, "foreign UID")
        foreign_gid = parse_numeric_id(args.foreign_gid, "foreign GID")
        cleanup(args.root, actor_uid, actor_gid, foreign_uid, foreign_gid)
    else:
        require(args.foreign_uid is None and args.foreign_gid is None, "prepare forbids cleanup IDs")
        prepare(args.root, actor_uid, actor_gid)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (FixtureError, OSError, UnicodeError, ValueError) as error:
        print("prepare-foreign-ipc-fixture: {}".format(error), file=sys.stderr)
        sys.exit(1)
