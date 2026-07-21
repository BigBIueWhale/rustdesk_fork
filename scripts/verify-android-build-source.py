#!/usr/bin/env python3
"""Prove that Android's writable build copy retains every exact-commit source input."""

import argparse
import hashlib
import os
import shutil
import stat
import tempfile


class SourceError(Exception):
    pass


REFERENCE_DIRECTORY_MODE = 0o555
REFERENCE_FILE_MODE = 0o444
REFERENCE_EXECUTABLE_MODE = 0o555
CANDIDATE_DIRECTORY_MODE = 0o755
CANDIDATE_FILE_MODE = 0o644
CANDIDATE_EXECUTABLE_MODE = 0o755


def canonical_directory(path, label):
    absolute = os.path.abspath(path)
    if absolute != path or os.path.realpath(path) != path:
        raise SourceError("{} must be an absolute canonical path".format(label))
    metadata = os.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode):
        raise SourceError("{} must be a real directory".format(label))
    if metadata.st_uid != os.getuid():
        raise SourceError("{} must be owned by the invoking user".format(label))
    return path


def stable_file(path, expected_uid, label):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SourceError("{} cannot be opened safely: {}".format(label, error))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SourceError("{} is not a regular file".format(label))
        if before.st_uid != expected_uid:
            raise SourceError("{} has the wrong owner".format(label))
        if before.st_nlink != 1:
            raise SourceError("{} must have exactly one link".format(label))
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after:
            raise SourceError("{} changed while it was read".format(label))
        return digest.hexdigest(), stat.S_IMODE(before.st_mode)
    finally:
        os.close(descriptor)


def reference_entries(root):
    entries = []
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        directories.sort()
        files.sort()
        for name in directories:
            path = os.path.join(current, name)
            metadata = os.lstat(path)
            if not stat.S_ISDIR(metadata.st_mode):
                raise SourceError("reference contains a non-directory edge: {}".format(path))
            if metadata.st_uid != os.getuid():
                raise SourceError("reference directory has the wrong owner: {}".format(path))
            entries.append((os.path.relpath(path, root), "directory"))
        for name in files:
            path = os.path.join(current, name)
            metadata = os.lstat(path)
            if not stat.S_ISREG(metadata.st_mode):
                raise SourceError("reference contains a symlink or special file: {}".format(path))
            entries.append((os.path.relpath(path, root), "file"))
    return entries


def validate(reference, candidate, allow_extras=False):
    reference = canonical_directory(reference, "reference source")
    candidate = canonical_directory(candidate, "candidate source")
    if reference == candidate:
        raise SourceError("reference and candidate source must be distinct")

    reference_root_mode = stat.S_IMODE(os.lstat(reference).st_mode)
    candidate_root_mode = stat.S_IMODE(os.lstat(candidate).st_mode)
    if reference_root_mode != REFERENCE_DIRECTORY_MODE:
        raise SourceError("reference source root has noncanonical mode")
    if candidate_root_mode != CANDIDATE_DIRECTORY_MODE:
        raise SourceError("candidate source root has noncanonical mode")

    uid = os.getuid()
    entries = reference_entries(reference)
    if not entries:
        raise SourceError("reference source is empty")
    reference_names = {relative for relative, _kind in entries}
    if not allow_extras:
        for relative, _kind in reference_entries(candidate):
            if relative not in reference_names:
                raise SourceError("candidate source contains an extra input: {}".format(relative))
    for relative, kind in entries:
        reference_path = os.path.join(reference, relative)
        candidate_path = os.path.join(candidate, relative)
        try:
            candidate_metadata = os.lstat(candidate_path)
        except FileNotFoundError:
            raise SourceError("candidate source is missing {}".format(relative))
        if candidate_metadata.st_uid != uid:
            raise SourceError("candidate source has the wrong owner: {}".format(relative))
        if kind == "directory":
            if not stat.S_ISDIR(candidate_metadata.st_mode):
                raise SourceError("candidate directory changed type: {}".format(relative))
            reference_mode = stat.S_IMODE(os.lstat(reference_path).st_mode)
            candidate_mode = stat.S_IMODE(candidate_metadata.st_mode)
            if reference_mode != REFERENCE_DIRECTORY_MODE:
                raise SourceError("reference directory has noncanonical mode: {}".format(relative))
            if candidate_mode != CANDIDATE_DIRECTORY_MODE:
                raise SourceError("candidate directory has noncanonical mode: {}".format(relative))
            continue
        if not stat.S_ISREG(candidate_metadata.st_mode):
            raise SourceError("candidate file changed type: {}".format(relative))
        reference_digest, reference_mode = stable_file(reference_path, uid, relative)
        candidate_digest, candidate_mode = stable_file(candidate_path, uid, relative)
        if reference_digest != candidate_digest:
            raise SourceError("candidate source bytes changed: {}".format(relative))
        if reference_mode == REFERENCE_FILE_MODE:
            expected_candidate_mode = CANDIDATE_FILE_MODE
        elif reference_mode == REFERENCE_EXECUTABLE_MODE:
            expected_candidate_mode = CANDIDATE_EXECUTABLE_MODE
        else:
            raise SourceError("reference file has noncanonical mode: {}".format(relative))
        if candidate_mode != expected_candidate_mode:
            raise SourceError("candidate source mode changed: {}".format(relative))


def expect_failure(reference, candidate, label):
    try:
        validate(reference, candidate)
    except SourceError:
        return
    raise SourceError("self-test accepted {}".format(label))


def self_test():
    root = tempfile.mkdtemp(prefix="android-build-source-test.")
    try:
        reference = os.path.join(root, "reference")
        candidate = os.path.join(root, "candidate")
        os.mkdir(reference, 0o700)
        os.mkdir(candidate, 0o700)
        os.mkdir(os.path.join(reference, "nested"), 0o700)
        os.mkdir(os.path.join(candidate, "nested"), 0o700)
        os.mkdir(os.path.join(reference, "empty"), 0o700)
        os.mkdir(os.path.join(candidate, "empty"), 0o700)
        reference_file = os.path.join(reference, "nested", "source.rs")
        candidate_file = os.path.join(candidate, "nested", "source.rs")
        with open(reference_file, "wb") as handle:
            handle.write(b"exact source\n")
        with open(candidate_file, "wb") as handle:
            handle.write(b"exact source\n")
        os.chmod(reference_file, 0o444)
        os.chmod(candidate_file, 0o644)
        os.chmod(os.path.join(reference, "nested"), 0o555)
        os.chmod(os.path.join(reference, "empty"), 0o555)
        os.chmod(reference, 0o555)
        os.chmod(os.path.join(candidate, "nested"), 0o755)
        os.chmod(os.path.join(candidate, "empty"), 0o755)
        os.chmod(candidate, 0o755)
        validate(reference, candidate)
        expect_failure(reference, reference, "identical source roots")

        os.chmod(reference, 0o575)
        expect_failure(reference, candidate, "group-writable reference root")
        os.chmod(reference, 0o555)

        os.chmod(candidate, 0o775)
        expect_failure(reference, candidate, "group-writable candidate root")
        os.chmod(candidate, 0o755)

        os.chmod(os.path.join(reference, "nested"), 0o575)
        expect_failure(reference, candidate, "group-writable reference directory")
        os.chmod(os.path.join(reference, "nested"), 0o555)

        os.chmod(os.path.join(candidate, "nested"), 0o775)
        expect_failure(reference, candidate, "group-writable candidate directory")
        os.chmod(os.path.join(candidate, "nested"), 0o755)

        candidate_empty = os.path.join(candidate, "empty")
        os.rmdir(candidate_empty)
        with open(candidate_empty, "wb") as handle:
            handle.write(b"not a directory\n")
        expect_failure(reference, candidate, "changed directory type")
        os.unlink(candidate_empty)
        os.mkdir(candidate_empty, 0o700)
        os.chmod(candidate_empty, 0o755)

        extra_file = os.path.join(candidate, "extra-input")
        with open(extra_file, "wb") as handle:
            handle.write(b"unexpected\n")
        expect_failure(reference, candidate, "extra input")
        validate(reference, candidate, allow_extras=True)
        os.unlink(extra_file)

        with open(candidate_file, "wb") as handle:
            handle.write(b"changed source\n")
        expect_failure(reference, candidate, "changed bytes")

        os.unlink(candidate_file)
        os.symlink(reference_file, candidate_file)
        expect_failure(reference, candidate, "symlink substitution")

        os.unlink(candidate_file)
        os.link(reference_file, candidate_file)
        expect_failure(reference, candidate, "hardlink substitution")

        os.unlink(candidate_file)
        with open(candidate_file, "wb") as handle:
            handle.write(b"exact source\n")

        os.chmod(reference_file, 0o464)
        expect_failure(reference, candidate, "group-writable reference source")
        os.chmod(reference_file, 0o444)

        os.chmod(candidate_file, 0o664)
        expect_failure(reference, candidate, "group-writable candidate source")

        os.chmod(candidate_file, 0o755)
        expect_failure(reference, candidate, "changed executable mode")

        os.unlink(candidate_file)
        expect_failure(reference, candidate, "missing source")
    finally:
        for current, directories, _files in os.walk(root, topdown=True, followlinks=False):
            os.chmod(current, 0o700)
            for name in directories:
                path = os.path.join(current, name)
                if not os.path.islink(path):
                    os.chmod(path, 0o700)
        shutil.rmtree(root)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference")
    parser.add_argument("--candidate")
    parser.add_argument("--allow-extras", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        if args.reference or args.candidate or args.allow_extras:
            parser.error("--self-test does not accept source paths")
        self_test()
        print("ANDROID-BUILD-SOURCE: stable exact-input comparison is GREEN")
        return
    if not args.reference or not args.candidate:
        parser.error("--reference and --candidate are required")
    validate(args.reference, args.candidate, allow_extras=args.allow_extras)
    print("ANDROID-BUILD-SOURCE: writable source retains every exact-commit input")


if __name__ == "__main__":
    try:
        main()
    except (OSError, SourceError) as error:
        raise SystemExit("verify-android-build-source: {}".format(error))
