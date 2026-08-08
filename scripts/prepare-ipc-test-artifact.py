#!/usr/bin/env python3
"""Select and privately copy the exact Rust lib-test artifact for IPC fixture tests."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


MAX_MESSAGES_BYTES = 64 * 1024 * 1024
MAX_MESSAGE_LINE_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 1024 * 1024 * 1024
ARTIFACT_RE = re.compile(r"^/build/debug/deps/librustdesk-[0-9a-f]{16,64}$")


class PreparationError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise PreparationError(message)


def stable_regular(path, *, executable=False, expected_owner=None, expected_group=None):
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    metadata = os.fstat(descriptor)
    edge = os.lstat(path)
    require(stat.S_ISREG(metadata.st_mode), "input is not a regular file")
    require((metadata.st_dev, metadata.st_ino) == (edge.st_dev, edge.st_ino), "input edge changed")
    require(metadata.st_nlink == 1, "input is hardlinked")
    if expected_owner is not None:
        require(metadata.st_uid == expected_owner, "input owner differs")
    if expected_group is not None:
        require(metadata.st_gid == expected_group, "input group differs")
    require(metadata.st_mode & 0o022 == 0, "input is group/world writable")
    if executable:
        require(metadata.st_mode & stat.S_IXUSR != 0, "artifact is not owner-executable")
        require(0 < metadata.st_size <= MAX_ARTIFACT_BYTES, "artifact size is invalid")
    return descriptor, metadata


def read_messages(path):
    descriptor, before = stable_regular(path, expected_owner=os.geteuid(), expected_group=os.getegid())
    try:
        require(before.st_size <= MAX_MESSAGES_BYTES, "Cargo message stream exceeds its byte bound")
        values = []
        with os.fdopen(os.dup(descriptor), "rb", closefd=True) as stream:
            for number, raw in enumerate(stream, 1):
                require(len(raw) <= MAX_MESSAGE_LINE_BYTES, "Cargo message line exceeds its byte bound")
                try:
                    value = json.loads(raw.decode("utf-8"))
                except (UnicodeError, ValueError) as error:
                    raise PreparationError("Cargo message line {} is invalid JSON".format(number)) from error
                if not isinstance(value, dict):
                    continue
                target = value.get("target")
                profile = value.get("profile")
                executable = value.get("executable")
                if (
                    value.get("reason") == "compiler-artifact"
                    and isinstance(target, dict)
                    and target.get("name") == "librustdesk"
                    and target.get("kind") == ["cdylib", "staticlib", "rlib"]
                    and target.get("crate_types") == ["cdylib", "staticlib", "rlib"]
                    and target.get("src_path") == "/work/src/lib.rs"
                    and isinstance(profile, dict)
                    and profile.get("test") is True
                    and isinstance(executable, str)
                ):
                    values.append(executable)
        after = os.fstat(descriptor)
        require(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            "Cargo message stream changed while read",
        )
    finally:
        os.close(descriptor)
    require(len(values) == 1, "expected exactly one Rust lib-test artifact, found {}".format(len(values)))
    require(ARTIFACT_RE.fullmatch(values[0]) is not None, "Rust lib-test artifact path is not canonical")
    return values[0]


def copy_artifact(messages, target_root, output):
    target_root = target_root.resolve(strict=True)
    require(target_root.is_dir(), "target root is not a directory")
    target_metadata = os.lstat(target_root)
    require(target_metadata.st_uid == os.geteuid(), "target root owner differs")
    require(target_metadata.st_gid == os.getegid(), "target root group differs")
    virtual_path = read_messages(messages)
    relative = Path(virtual_path).relative_to("/build")
    source = target_root / relative
    require(source.parent.resolve(strict=True).is_relative_to(target_root), "artifact escapes the target root")
    source_fd, source_before = stable_regular(
        source,
        executable=True,
        expected_owner=os.geteuid(),
        expected_group=os.getegid(),
    )
    output_parent = output.parent.resolve(strict=True)
    parent_metadata = os.lstat(output_parent)
    require(
        stat.S_ISDIR(parent_metadata.st_mode)
        and parent_metadata.st_uid == os.geteuid()
        and parent_metadata.st_gid == os.getegid()
        and stat.S_IMODE(parent_metadata.st_mode) == 0o700,
        "artifact destination parent is not private",
    )
    digest = hashlib.sha256()
    output_fd = None
    try:
        output_fd = os.open(
            output,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o500,
        )
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(output_fd, view)
                require(written > 0, "artifact copy made no progress")
                view = view[written:]
        # The fixture-test container runs as this exact owner and receives the
        # file as a read-only bind, so no group/other execute authority is needed.
        os.fchmod(output_fd, 0o500)
        os.fsync(output_fd)
        copied = os.fstat(output_fd)
        require(copied.st_size == source_before.st_size, "artifact copy size differs")
        require(copied.st_nlink == 1, "artifact copy is hardlinked")
        require(copied.st_uid == os.geteuid() and copied.st_gid == os.getegid(), "artifact copy owner differs")
        require(stat.S_IMODE(copied.st_mode) == 0o500, "artifact copy mode differs")
        source_after = os.fstat(source_fd)
        require(
            (
                source_before.st_dev,
                source_before.st_ino,
                source_before.st_size,
                source_before.st_mtime_ns,
                source_before.st_ctime_ns,
            )
            == (
                source_after.st_dev,
                source_after.st_ino,
                source_after.st_size,
                source_after.st_mtime_ns,
                source_after.st_ctime_ns,
            ),
            "source artifact changed while copied",
        )
    except BaseException:
        if output_fd is not None:
            os.close(output_fd)
            output_fd = None
        try:
            os.unlink(output)
        except FileNotFoundError:
            pass
        raise
    finally:
        if output_fd is not None:
            os.close(output_fd)
        os.close(source_fd)
    return digest.hexdigest(), source_before.st_size


def fixture_message(
    executable,
    *,
    test=True,
    target_name="librustdesk",
    target_kind=("cdylib", "staticlib", "rlib"),
):
    return {
        "reason": "compiler-artifact",
        "package_id": "path+file:///work#rustdesk@1.4.7",
        "target": {
            "name": target_name,
            "kind": list(target_kind),
            "crate_types": ["cdylib", "staticlib", "rlib"],
            "src_path": "/work/src/lib.rs",
        },
        "profile": {"test": test},
        "executable": executable,
    }


def self_test():
    checks = 0
    with tempfile.TemporaryDirectory(prefix="ipc-test-artifact-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        target = root / "target"
        deps = target / "debug" / "deps"
        deps.mkdir(parents=True)
        artifact = deps / "librustdesk-0123456789abcdef"
        artifact.write_bytes(b"#!/bin/sh\nexit 0\n")
        artifact.chmod(0o500)
        messages = root / "messages.json"
        messages.write_text(json.dumps(fixture_message("/build/debug/deps/" + artifact.name)) + "\n")
        messages.chmod(0o600)
        output = root / "output"
        digest, size = copy_artifact(messages, target, output)
        require(digest == hashlib.sha256(artifact.read_bytes()).hexdigest(), "self-test digest differs")
        require(size == artifact.stat().st_size and output.stat().st_mode & 0o777 == 0o500, "self-test copy differs")
        checks += 1

        def expect_failure(label, operation):
            nonlocal checks
            try:
                operation()
            except (PreparationError, OSError, ValueError):
                checks += 1
                return
            raise PreparationError("self-test mutation was accepted: " + label)

        expect_failure("existing destination", lambda: copy_artifact(messages, target, output))
        bad_messages = root / "bad-messages.json"
        bad_messages.write_text(json.dumps(fixture_message("/build/debug/deps/" + artifact.name, test=False)) + "\n")
        bad_messages.chmod(0o600)
        expect_failure("non-test artifact", lambda: copy_artifact(bad_messages, target, root / "bad-output"))
        wrong_target = root / "wrong-target.json"
        wrong_target.write_text(
            json.dumps(
                fixture_message(
                    "/build/debug/deps/" + artifact.name,
                    target_name="rustdesk",
                )
            )
            + "\n"
        )
        wrong_target.chmod(0o600)
        expect_failure(
            "package name substituted for library target",
            lambda: copy_artifact(wrong_target, target, root / "wrong-target-output"),
        )
        wrong_kind = root / "wrong-kind.json"
        wrong_kind.write_text(
            json.dumps(
                fixture_message(
                    "/build/debug/deps/" + artifact.name,
                    target_kind=("lib",),
                )
            )
            + "\n"
        )
        wrong_kind.chmod(0o600)
        expect_failure(
            "generic library kind substituted for exact crate types",
            lambda: copy_artifact(wrong_kind, target, root / "wrong-kind-output"),
        )
        duplicate = root / "duplicate.json"
        line = json.dumps(fixture_message("/build/debug/deps/" + artifact.name)) + "\n"
        duplicate.write_text(line + line)
        duplicate.chmod(0o600)
        expect_failure("duplicate artifact", lambda: copy_artifact(duplicate, target, root / "duplicate-output"))
        wrong_path = root / "wrong-path.json"
        wrong_path.write_text(json.dumps(fixture_message("/tmp/rustdesk-0123456789abcdef")) + "\n")
        wrong_path.chmod(0o600)
        expect_failure("non-target artifact", lambda: copy_artifact(wrong_path, target, root / "wrong-output"))
        hardlink = root / "artifact-hardlink"
        os.link(artifact, hardlink)
        expect_failure("hardlinked artifact", lambda: copy_artifact(messages, target, root / "hardlink-output"))
        hardlink.unlink()
        symlink = deps / "librustdesk-fedcba9876543210"
        symlink.symlink_to(artifact.name)
        symlink_messages = root / "symlink.json"
        symlink_messages.write_text(json.dumps(fixture_message("/build/debug/deps/" + symlink.name)) + "\n")
        symlink_messages.chmod(0o600)
        expect_failure("symlink artifact", lambda: copy_artifact(symlink_messages, target, root / "symlink-output"))
        invalid = root / "invalid.json"
        invalid.write_bytes(b"not-json\n")
        invalid.chmod(0o600)
        expect_failure("invalid JSON", lambda: copy_artifact(invalid, target, root / "invalid-output"))
    require(checks == 10, "self-test check count differs")
    print("prepare-ipc-test-artifact: self-test ok (10 checks)")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--messages", type=Path)
    parser.add_argument("--target-root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        require(args.messages is None and args.target_root is None and args.output is None, "self-test takes no paths")
        self_test()
        return 0
    require(args.messages is not None and args.target_root is not None and args.output is not None, "all paths are required")
    digest, size = copy_artifact(args.messages, args.target_root, args.output)
    print("sha256={} bytes={}".format(digest, size))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (PreparationError, OSError, UnicodeError, ValueError) as error:
        print("prepare-ipc-test-artifact: {}".format(error), file=sys.stderr)
        sys.exit(1)
