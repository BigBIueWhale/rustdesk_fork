#!/usr/bin/env python3
import argparse
import os
import re
import stat
import sys
import tempfile


class ClosureError(Exception):
    pass


def require_real_directory(path):
    resolved = os.path.realpath(path)
    if resolved != path:
        raise ClosureError("tree path is not canonical")
    metadata = os.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode):
        raise ClosureError("tree root is not a real directory")


def decode_mount_path(value):
    def replace(match):
        return bytes((int(match.group(1), 8),))

    if re.search(br"\\(?![0-7]{3})", value):
        raise ClosureError("mountinfo path contains an invalid escape")
    return re.sub(br"\\([0-7]{3})", replace, value)


def verify_mount_closure(root, mountinfo_path):
    require_real_directory(root)
    encoded_root = os.fsencode(root)
    prefix = encoded_root.rstrip(b"/") + b"/"
    descendants = []
    with open(mountinfo_path, "rb") as mountinfo:
        for number, raw_line in enumerate(mountinfo, 1):
            fields = raw_line.rstrip(b"\n").split(b" ")
            if len(fields) < 10 or b"-" not in fields[6:]:
                raise ClosureError("malformed mountinfo line {}".format(number))
            mount_path = decode_mount_path(fields[4])
            if mount_path == encoded_root or mount_path.startswith(prefix):
                descendants.append(mount_path)
    if descendants:
        raise ClosureError(
            "tree contains a mount boundary: {}".format(
                b", ".join(sorted(set(descendants))).decode("utf-8", "backslashreplace")
            )
        )


def verify_inode_closure(root):
    require_real_directory(root)
    linked = {}

    def walk_error(error):
        raise ClosureError("tree traversal failed: {}".format(error))

    for directory, directory_names, file_names in os.walk(
        root, topdown=True, onerror=walk_error, followlinks=False
    ):
        for name in directory_names + file_names:
            path = os.path.join(directory, name)
            try:
                metadata = os.lstat(path)
            except OSError as error:
                raise ClosureError("tree entry inspection failed: {}".format(error))
            if stat.S_ISDIR(metadata.st_mode):
                continue
            if metadata.st_nlink < 1:
                raise ClosureError("tree entry has an invalid link count")
            if metadata.st_nlink == 1:
                continue
            key = (metadata.st_dev, metadata.st_ino)
            expected, count = linked.get(key, (metadata.st_nlink, 0))
            if expected != metadata.st_nlink:
                raise ClosureError("tree inode link count changed during inspection")
            linked[key] = (expected, count + 1)

    for expected, count in linked.values():
        if count != expected:
            raise ClosureError("tree contains a non-directory inode linked outside its boundary")


def require_rejection(function, *arguments):
    try:
        function(*arguments)
    except ClosureError:
        return
    raise ClosureError("negative closure fixture was accepted")


def run_self_test():
    escape_fixture = br"/space\040tab\011line\012slash\134"
    if decode_mount_path(escape_fixture) != b"/space tab\tline\nslash\\":
        raise ClosureError("mountinfo escape decoding fixture failed")
    require_rejection(decode_mount_path, br"/invalid\09x")
    with tempfile.TemporaryDirectory(prefix="private-tree-closure-") as temporary:
        root = os.path.join(temporary, "tree with space")
        os.mkdir(root, 0o700)
        internal = os.path.join(root, "internal-a")
        with open(internal, "wb") as output:
            output.write(b"internal\n")
        os.link(internal, os.path.join(root, "internal-b"))
        internal_symlink = os.path.join(root, "internal-symlink-a")
        os.symlink("internal-a", internal_symlink)
        os.link(
            internal_symlink,
            os.path.join(root, "internal-symlink-b"),
            follow_symlinks=False,
        )
        verify_inode_closure(root)

        external = os.path.join(temporary, "external")
        with open(external, "wb") as output:
            output.write(b"external\n")
        external_link = os.path.join(root, "external-link")
        os.link(external, external_link)
        require_rejection(verify_inode_closure, root)
        os.unlink(external_link)

        external_symlink = os.path.join(temporary, "external-symlink")
        os.symlink("external", external_symlink)
        external_symlink_link = os.path.join(root, "external-symlink-link")
        os.link(external_symlink, external_symlink_link, follow_symlinks=False)
        require_rejection(verify_inode_closure, root)
        os.unlink(external_symlink_link)

        mountinfo = os.path.join(temporary, "mountinfo")
        encoded_root = os.fsencode(root).replace(b" ", br"\040")
        with open(mountinfo, "wb") as output:
            output.write(b"1 0 0:1 / / rw - ext4 /dev/root rw\n")
        verify_mount_closure(root, mountinfo)
        with open(mountinfo, "ab") as output:
            output.write(
                b"2 1 0:1 /bound " + encoded_root + b"/nested rw - ext4 /dev/root rw\n"
            )
        require_rejection(verify_mount_closure, root, mountinfo)


def main():
    parser = argparse.ArgumentParser(description="Verify a private tree's filesystem closure.")
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--mount-root")
    modes.add_argument("--inode-root")
    modes.add_argument("--self-test", action="store_true")
    parser.add_argument("--mountinfo", default="/proc/self/mountinfo")
    arguments = parser.parse_args()
    try:
        if arguments.self_test:
            run_self_test()
        elif arguments.mount_root is not None:
            verify_mount_closure(arguments.mount_root, arguments.mountinfo)
        else:
            verify_inode_closure(arguments.inode_root)
    except (ClosureError, OSError) as error:
        print("verify-private-tree-closure: FAIL: {}".format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
