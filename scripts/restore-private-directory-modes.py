#!/usr/bin/env python3
"""Restore owner traversal on a quiescent private tree without touching files."""

import argparse
import os
import re
import shutil
import stat
import tempfile


ENTRY_LIMIT = 524288
DEPTH_LIMIT = 128


class RestoreError(Exception):
    pass


def identity(metadata):
    return metadata.st_dev, metadata.st_ino


def mount_id(descriptor):
    with open(
        "/proc/self/fdinfo/{}".format(descriptor), "rb", buffering=0
    ) as information:
        content = information.read(65537)
    if len(content) > 65536:
        raise RestoreError("directory descriptor mount information exceeds its byte bound")
    values = [
        line[len(b"mnt_id:\t") :]
        for line in content.splitlines()
        if line.startswith(b"mnt_id:\t")
    ]
    if len(values) != 1 or re.fullmatch(br"[1-9][0-9]*", values[0]) is None:
        raise RestoreError("directory descriptor mount identity is unavailable")
    return int(values[0])


def normalized_directory_mode(mode, root=False):
    if root:
        return 0o700
    return (stat.S_IMODE(mode) | 0o700) & 0o755


def open_path_directory(name, descriptor=None):
    return os.open(
        name,
        os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=descriptor,
    )


def open_root_path(path):
    components = path.split(os.sep)[1:]
    descriptor = open_path_directory(os.sep)
    try:
        for index, component in enumerate(components):
            child = open_path_directory(component, descriptor)
            if index == len(components) - 1:
                return descriptor, child
            os.close(descriptor)
            descriptor = child
    except BaseException:
        os.close(descriptor)
        raise
    raise RestoreError("private-tree root has no path component")


def chmod_descriptor(descriptor, mode):
    os.chmod("/proc/self/fd/{}".format(descriptor), mode)


def open_read_directory(path_descriptor):
    return os.open(
        ".",
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=path_descriptor,
    )


def validate_root_path(path):
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise RestoreError("private-tree root is not an absolute normalized path")
    components = path.split(os.sep)[1:]
    if not components or any(component in ("", ".", "..") for component in components):
        raise RestoreError("private-tree root has an invalid path component")


def restore_children(
    descriptor,
    device,
    expected_mount,
    owner,
    group,
    remaining,
    depth,
):
    try:
        names = sorted(os.listdir(descriptor), key=os.fsencode)
    except OSError as error:
        raise RestoreError("cannot inventory a private-tree directory") from error
    for name in names:
        remaining[0] -= 1
        if remaining[0] < 0:
            raise RestoreError("private-tree directory restoration exceeds its entry bound")
        metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if metadata.st_dev != device:
            raise RestoreError("private-tree directory restoration crosses a filesystem")
        if stat.S_ISDIR(metadata.st_mode):
            if depth >= DEPTH_LIMIT:
                raise RestoreError("private-tree directory restoration exceeds its depth bound")
            if metadata.st_uid != owner or metadata.st_gid != group:
                raise RestoreError("private-tree directory has the wrong owner")
            expected_identity = identity(metadata)
            path_descriptor = open_path_directory(name, descriptor)
            try:
                opened_path = os.fstat(path_descriptor)
                if (
                    identity(opened_path) != expected_identity
                    or not stat.S_ISDIR(opened_path.st_mode)
                    or opened_path.st_uid != owner
                    or opened_path.st_gid != group
                    or descriptor_mount_id(path_descriptor) != expected_mount
                ):
                    raise RestoreError(
                        "private-tree directory changed authority during traversal"
                    )
                chmod_descriptor(
                    path_descriptor,
                    normalized_directory_mode(opened_path.st_mode),
                )
                after_mode = os.fstat(path_descriptor)
                if (
                    identity(after_mode) != expected_identity
                    or not stat.S_ISDIR(after_mode.st_mode)
                    or after_mode.st_uid != owner
                    or after_mode.st_gid != group
                ):
                    raise RestoreError(
                        "private-tree directory changed during mode restoration"
                    )
                child = open_read_directory(path_descriptor)
                try:
                    opened = os.fstat(child)
                    if (
                        identity(opened) != expected_identity
                        or descriptor_mount_id(child) != expected_mount
                    ):
                        raise RestoreError(
                            "private-tree directory changed authority during traversal"
                        )
                    restore_children(
                        child,
                        device,
                        expected_mount,
                        owner,
                        group,
                        remaining,
                        depth + 1,
                    )
                finally:
                    os.close(child)
            finally:
                os.close(path_descriptor)
        elif not (
            stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
        ):
            raise RestoreError("private-tree directory restoration found a special file")


def descriptor_mount_id(descriptor):
    return mount_id(descriptor)


def restore(root, expected_identity, owner, group):
    validate_root_path(root)
    metadata = os.stat(root, follow_symlinks=False)
    if (
        identity(metadata) != expected_identity
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != owner
        or metadata.st_gid != group
    ):
        raise RestoreError("private-tree root identity or ownership is invalid")
    parent_descriptor, path_descriptor = open_root_path(root)
    try:
        opened_path = os.fstat(path_descriptor)
        parent = os.fstat(parent_descriptor)
        if (
            identity(opened_path) != expected_identity
            or not stat.S_ISDIR(opened_path.st_mode)
            or opened_path.st_uid != owner
            or opened_path.st_gid != group
            or opened_path.st_dev != parent.st_dev
            or descriptor_mount_id(path_descriptor)
            != descriptor_mount_id(parent_descriptor)
        ):
            raise RestoreError("private-tree root changed during descriptor acquisition")
        expected_mount = descriptor_mount_id(path_descriptor)
        chmod_descriptor(
            path_descriptor,
            normalized_directory_mode(opened_path.st_mode, root=True),
        )
        after_mode = os.fstat(path_descriptor)
        if (
            identity(after_mode) != expected_identity
            or not stat.S_ISDIR(after_mode.st_mode)
            or stat.S_IMODE(after_mode.st_mode) != 0o700
            or after_mode.st_uid != owner
            or after_mode.st_gid != group
        ):
            raise RestoreError("private-tree root changed during mode restoration")
        descriptor = open_read_directory(path_descriptor)
        try:
            opened = os.fstat(descriptor)
            if (
                identity(opened) != expected_identity
                or descriptor_mount_id(descriptor) != expected_mount
            ):
                raise RestoreError(
                    "private-tree root changed during descriptor acquisition"
                )
            restore_children(
                descriptor,
                opened.st_dev,
                expected_mount,
                owner,
                group,
                [ENTRY_LIMIT],
                0,
            )
        finally:
            os.close(descriptor)
    finally:
        os.close(path_descriptor)
        os.close(parent_descriptor)


def expect_failure(action, label):
    try:
        action()
    except (OSError, RestoreError):
        return
    raise RestoreError("self-test accepted {}".format(label))


def self_test():
    outer = tempfile.mkdtemp(prefix="private-directory-modes.")
    try:
        root = os.path.join(outer, "root")
        nested = os.path.join(root, "nested")
        deeper = os.path.join(nested, "deeper")
        regular = os.path.join(deeper, "regular")
        external = os.path.join(outer, "external")
        linked = os.path.join(deeper, "linked")
        symlink = os.path.join(deeper, "symlink")
        os.mkdir(root, 0o700)
        os.mkdir(nested, 0o700)
        os.mkdir(deeper, 0o700)
        with open(regular, "wb") as output:
            output.write(b"regular\n")
        with open(external, "wb") as output:
            output.write(b"external\n")
        os.chmod(external, 0o640)
        os.link(external, linked)
        os.symlink(external, symlink)
        os.chmod(deeper, 0o000)
        os.chmod(nested, 0o000)
        os.chmod(root, 0o000)
        root_metadata = os.stat(root, follow_symlinks=False)
        restore(root, identity(root_metadata), os.geteuid(), os.getegid())
        if stat.S_IMODE(os.stat(root).st_mode) != 0o700:
            raise RestoreError("self-test root mode was not normalized")
        if stat.S_IMODE(os.stat(nested).st_mode) != 0o700:
            raise RestoreError("self-test nested mode was not normalized")
        if stat.S_IMODE(os.stat(deeper).st_mode) != 0o700:
            raise RestoreError("self-test deeper mode was not normalized")
        if stat.S_IMODE(os.stat(external).st_mode) != 0o640:
            raise RestoreError("self-test changed a hardlinked regular file mode")
        if not os.path.islink(symlink):
            raise RestoreError("self-test changed a symlink")

        wrong_mount_root = os.path.join(outer, "wrong-mount-root")
        wrong_mount_nested = os.path.join(wrong_mount_root, "nested")
        os.mkdir(wrong_mount_root, 0o700)
        os.mkdir(wrong_mount_nested, 0o000)
        wrong_mount_descriptor = os.open(
            wrong_mount_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            wrong_mount_metadata = os.fstat(wrong_mount_descriptor)
            expect_failure(
                lambda: restore_children(
                    wrong_mount_descriptor,
                    wrong_mount_metadata.st_dev,
                    descriptor_mount_id(wrong_mount_descriptor) + 1,
                    os.geteuid(),
                    os.getegid(),
                    [ENTRY_LIMIT],
                    0,
                ),
                "mount mismatch",
            )
        finally:
            os.close(wrong_mount_descriptor)
        if stat.S_IMODE(os.stat(wrong_mount_nested).st_mode) != 0o000:
            raise RestoreError("self-test changed a cross-mount directory mode")

        real_parent = os.path.join(outer, "real-parent")
        real_root = os.path.join(real_parent, "root")
        parent_alias = os.path.join(outer, "parent-alias")
        os.mkdir(real_parent, 0o700)
        os.mkdir(real_root, 0o000)
        os.symlink(real_parent, parent_alias)
        real_metadata = os.stat(real_root, follow_symlinks=False)
        expect_failure(
            lambda: restore(
                os.path.join(parent_alias, "root"),
                identity(real_metadata),
                os.geteuid(),
                os.getegid(),
            ),
            "symlinked parent",
        )
        if stat.S_IMODE(os.stat(real_root).st_mode) != 0o000:
            raise RestoreError("self-test changed a symlink-parent directory mode")

        special_root = os.path.join(outer, "special-root")
        os.mkdir(special_root, 0o700)
        os.mkfifo(os.path.join(special_root, "fifo"), 0o600)
        special_metadata = os.stat(special_root, follow_symlinks=False)
        expect_failure(
            lambda: restore(
                special_root,
                identity(special_metadata),
                os.geteuid(),
                os.getegid(),
            ),
            "special file",
        )
        os.unlink(os.path.join(special_root, "fifo"))
    finally:
        for current, directories, _files in os.walk(
            outer, topdown=True, followlinks=False
        ):
            os.chmod(current, 0o700)
            for name in directories:
                path = os.path.join(current, name)
                if not os.path.islink(path):
                    os.chmod(path, 0o700)
        shutil.rmtree(outer)


def parse_identity(value):
    match = re.fullmatch(r"([0-9]+):([1-9][0-9]*)", value)
    if match is None:
        raise RestoreError("expected identity is malformed")
    return int(match.group(1)), int(match.group(2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root")
    parser.add_argument("--expected-identity")
    parser.add_argument("--owner", type=int)
    parser.add_argument("--group", type=int)
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    if arguments.self_test:
        if any(
            value is not None
            for value in (
                arguments.root,
                arguments.expected_identity,
                arguments.owner,
                arguments.group,
            )
        ):
            parser.error("--self-test does not accept tree arguments")
        self_test()
        print("restore-private-directory-modes: self-test OK")
        return
    if (
        arguments.root is None
        or arguments.expected_identity is None
        or arguments.owner is None
        or arguments.owner < 0
        or arguments.group is None
        or arguments.group < 0
    ):
        parser.error("tree mode requires root, identity, owner, and group")
    restore(
        arguments.root,
        parse_identity(arguments.expected_identity),
        arguments.owner,
        arguments.group,
    )
    print("restore-private-directory-modes: OK")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RestoreError) as error:
        raise SystemExit("restore-private-directory-modes: {}".format(error))
