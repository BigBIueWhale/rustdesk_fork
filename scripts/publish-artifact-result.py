#!/usr/bin/env python3
"""Publish one validated build result without pathname or overwrite authority."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import os
import re
import stat
import sys
import tempfile
from typing import NamedTuple


RENAME_NOREPLACE = 1
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024
MAX_CHECKSUM_BYTES = 256
IDENTITY_RE = re.compile(r"^(0|[1-9][0-9]*):([1-9][0-9]*)$")
DESTINATION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
STABLE_FILE_FIELDS = (
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


class ArtifactContract(NamedTuple):
    kind: str
    artifact: str
    checksum: str
    pending_prefix: str
    pending_pattern: re.Pattern[str]
    checksum_line_pattern: re.Pattern[bytes]

    @property
    def expected_inventory(self) -> tuple[str, str]:
        return tuple(sorted((self.artifact, self.checksum)))


DEBIAN_X86_64 = ArtifactContract(
    kind="debian-x86_64",
    artifact="rustdesk-x86_64.deb",
    checksum="rustdesk-x86_64.deb.sha256",
    pending_prefix=".debian-output-pending-",
    pending_pattern=re.compile(r"^\.debian-output-pending-[0-9a-f]{64}$"),
    checksum_line_pattern=re.compile(
        rb"^([0-9a-f]{64})  rustdesk-x86_64\.deb\n$"
    ),
)
ANDROID_ARM64 = ArtifactContract(
    kind="android-arm64",
    artifact="rustdesk-arm64.apk",
    checksum="rustdesk-arm64.apk.sha256",
    pending_prefix=".android-output-pending-",
    pending_pattern=re.compile(r"^\.android-output-pending-[0-9a-f]{64}$"),
    checksum_line_pattern=re.compile(rb"^([0-9a-f]{64})  rustdesk-arm64\.apk\n$"),
)
CONTRACTS = {
    contract.kind: contract for contract in (DEBIAN_X86_64, ANDROID_ARM64)
}


class PublicationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise PublicationError(message)


def identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def stable_file(info: os.stat_result) -> tuple[int, ...]:
    return tuple(getattr(info, field) for field in STABLE_FILE_FIELDS)


def parse_identity(value: str, label: str) -> tuple[int, int]:
    match = IDENTITY_RE.fullmatch(value)
    if match is None:
        fail(f"{label} identity is malformed")
    return int(match.group(1)), int(match.group(2))


def reject_access_acl(descriptor: int, label: str, *, include_default: bool) -> None:
    try:
        names = os.listxattr(descriptor)
    except OSError as exc:
        fail(f"cannot inspect {label} extended attributes: {exc}")
    forbidden = {"system.posix_acl_access"}
    if include_default:
        forbidden.add("system.posix_acl_default")
    if forbidden.intersection(names):
        fail(f"{label} has a POSIX access ACL")


def open_bound_output_parent(path: str, expected: tuple[int, int]) -> int:
    if not os.path.isabs(path) or os.path.realpath(path) != path or path == "/":
        fail("output parent path is not an absolute canonical non-root path")
    try:
        before = os.lstat(path)
    except OSError as exc:
        fail(f"cannot inspect output parent: {exc}")
    if not stat.S_ISDIR(before.st_mode):
        fail("output parent is not a real directory")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot open output parent: {exc}")
    try:
        opened = os.fstat(descriptor)
        mode = stat.S_IMODE(opened.st_mode)
        if stable_file(before) != stable_file(opened):
            fail("output parent changed while it was opened")
        if identity(opened) != expected:
            fail("output parent device/inode identity changed")
        if opened.st_uid != os.getuid() or opened.st_gid != os.getgid():
            fail("output parent is not owned by the invoking principal")
        if mode & 0o7000 or mode & 0o022 or mode & 0o700 != 0o700:
            fail("output parent grants unsafe publication authority")
        reject_access_acl(descriptor, "output parent", include_default=True)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def reprove_output_parent(path: str, expected: tuple[int, int]) -> None:
    descriptor = open_bound_output_parent(path, expected)
    os.close(descriptor)


def open_source(
    path: str,
    expected_identity: tuple[int, int],
) -> tuple[int, os.stat_result]:
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        fail("build artifact source path is not absolute and canonical")
    try:
        before = os.lstat(path)
    except OSError as exc:
        fail(f"cannot inspect build artifact source: {exc}")
    mode = stat.S_IMODE(before.st_mode)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or before.st_gid != os.getgid()
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > MAX_ARTIFACT_BYTES
        or mode & 0o7133
        or mode & 0o400 != 0o400
    ):
        fail("build artifact source metadata is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot open build artifact source: {exc}")
    try:
        opened = os.fstat(descriptor)
        if stable_file(before) != stable_file(opened):
            fail("build artifact source changed while it was opened")
        if identity(opened) != expected_identity:
            fail("build artifact source device/inode identity changed")
        reject_access_acl(descriptor, "build artifact source", include_default=False)
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def open_pending(
    parent: int,
    name: str,
    expected_identity: tuple[int, int] | None,
    contract: ArtifactContract,
) -> int:
    if contract.pending_pattern.fullmatch(name) is None:
        fail("pending build output name is malformed")
    try:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError as exc:
        fail(f"cannot inspect pending build output: {exc}")
    if not stat.S_ISDIR(before.st_mode):
        fail("pending build output is not a real directory")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
    except OSError as exc:
        fail(f"cannot open pending build output: {exc}")
    try:
        opened = os.fstat(descriptor)
        parent_info = os.fstat(parent)
        if stable_file(before) != stable_file(opened):
            fail("pending build output changed while it was opened")
        if expected_identity is not None and identity(opened) != expected_identity:
            fail("pending build output device/inode identity changed")
        if (
            opened.st_dev != parent_info.st_dev
            or opened.st_uid != os.getuid()
            or opened.st_gid != os.getgid()
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            fail("pending build output metadata is invalid")
        reject_access_acl(descriptor, "pending build output", include_default=True)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def require_absent(parent: int, name: str, label: str) -> None:
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        fail(f"cannot inspect {label}: {exc}")
    fail(f"{label} is occupied")


def list_entries(
    descriptor: int,
    label: str,
    contract: ArtifactContract,
) -> tuple[str, ...]:
    try:
        entries = tuple(sorted(os.listdir(descriptor)))
    except OSError as exc:
        fail(f"cannot enumerate {label}: {exc}")
    if entries != contract.expected_inventory:
        fail(f"{label} inventory is not the exact build output set")
    return entries


def open_result_file(
    parent: int,
    name: str,
    *,
    maximum: int,
    label: str,
) -> tuple[int, os.stat_result]:
    try:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError as exc:
        fail(f"cannot inspect {label}: {exc}")
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or before.st_gid != os.getgid()
        or stat.S_IMODE(before.st_mode) != 0o400
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        fail(f"{label} metadata is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
    except OSError as exc:
        fail(f"cannot open {label}: {exc}")
    try:
        opened = os.fstat(descriptor)
        if stable_file(before) != stable_file(opened):
            fail(f"{label} changed while it was opened")
        reject_access_acl(descriptor, label, include_default=False)
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def read_exact_file(
    parent: int,
    name: str,
    *,
    maximum: int,
    label: str,
) -> bytes:
    descriptor, before = open_result_file(parent, name, maximum=maximum, label=label)
    try:
        data = bytearray()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                fail(f"{label} ended before its recorded size")
            data.extend(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            fail(f"{label} grew beyond its recorded size")
        if stable_file(before) != stable_file(os.fstat(descriptor)):
            fail(f"{label} changed while it was read")
        return bytes(data)
    finally:
        os.close(descriptor)


def hash_result_artifact(
    parent: int,
    label: str,
    contract: ArtifactContract,
) -> str:
    descriptor, before = open_result_file(
        parent,
        contract.artifact,
        maximum=MAX_ARTIFACT_BYTES,
        label=f"{label} artifact",
    )
    digest = hashlib.sha256()
    try:
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                fail(f"{label} artifact ended before its recorded size")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            fail(f"{label} artifact grew beyond its recorded size")
        if stable_file(before) != stable_file(os.fstat(descriptor)):
            fail(f"{label} artifact changed while it was hashed")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def verify_result(
    descriptor: int,
    label: str,
    contract: ArtifactContract,
) -> str:
    list_entries(descriptor, label, contract)
    checksum = read_exact_file(
        descriptor,
        contract.checksum,
        maximum=MAX_CHECKSUM_BYTES,
        label=f"{label} checksum",
    )
    match = contract.checksum_line_pattern.fullmatch(checksum)
    if match is None:
        fail(f"{label} checksum is not canonical")
    expected = match.group(1).decode("ascii")
    actual = hash_result_artifact(descriptor, label, contract)
    if actual != expected:
        fail(f"{label} artifact does not match its checksum")
    return actual


def create_output_file(parent: int, name: str) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        return os.open(name, flags, 0o600, dir_fd=parent)
    except OSError as exc:
        fail(f"cannot create pending build output {name}: {exc}")


def write_all(descriptor: int, data: bytes, label: str) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            fail(f"short write while creating {label}")
        offset += written


def copy_source(
    source: int,
    source_info: os.stat_result,
    destination: int,
    expected_sha256: str,
    contract: ArtifactContract,
) -> None:
    output = create_output_file(destination, contract.artifact)
    digest = hashlib.sha256()
    try:
        remaining = source_info.st_size
        while remaining:
            chunk = os.read(source, min(1024 * 1024, remaining))
            if not chunk:
                fail("build artifact source ended before its recorded size")
            write_all(output, chunk, f"pending {contract.artifact}")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(source, 1):
            fail("build artifact source grew beyond its recorded size")
        if stable_file(source_info) != stable_file(os.fstat(source)):
            fail("build artifact source changed while it was copied")
        if digest.hexdigest() != expected_sha256:
            fail("build artifact source does not match its validated SHA-256")
        os.fchmod(output, 0o400)
        os.fsync(output)
        copied = os.fstat(output)
        if (
            not stat.S_ISREG(copied.st_mode)
            or copied.st_uid != os.getuid()
            or copied.st_gid != os.getgid()
            or stat.S_IMODE(copied.st_mode) != 0o400
            or copied.st_nlink != 1
            or copied.st_size != source_info.st_size
        ):
            fail("pending build artifact metadata is invalid")
        reject_access_acl(output, "pending build artifact", include_default=False)
    finally:
        os.close(output)


def create_checksum(
    destination: int,
    digest: str,
    contract: ArtifactContract,
) -> None:
    data = f"{digest}  {contract.artifact}\n".encode("ascii")
    output = create_output_file(destination, contract.checksum)
    try:
        write_all(output, data, f"pending {contract.checksum}")
        os.fchmod(output, 0o400)
        os.fsync(output)
        created = os.fstat(output)
        if (
            not stat.S_ISREG(created.st_mode)
            or created.st_uid != os.getuid()
            or created.st_gid != os.getgid()
            or stat.S_IMODE(created.st_mode) != 0o400
            or created.st_nlink != 1
            or created.st_size != len(data)
        ):
            fail("pending build checksum metadata is invalid")
        reject_access_acl(output, "pending build checksum", include_default=False)
    finally:
        os.close(output)


def rename_noreplace(parent: int, source: str, destination: str) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    function = getattr(library, "renameat2", None)
    if function is None:
        fail("libc does not expose renameat2")
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    if (
        function(
            parent,
            os.fsencode(source),
            parent,
            os.fsencode(destination),
            RENAME_NOREPLACE,
        )
        != 0
    ):
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            fail("build output destination appeared before no-clobber publication")
        if error == errno.EXDEV:
            fail("build output publication crossed a filesystem")
        fail(f"renameat2(RENAME_NOREPLACE) failed: {os.strerror(error)}")


def validate_destination(destination: str, contract: ArtifactContract) -> None:
    if (
        DESTINATION_RE.fullmatch(destination) is None
        or destination in (".", "..")
        or contract.pending_pattern.fullmatch(destination) is not None
    ):
        fail("build output destination name is malformed")


def prepare(
    contract: ArtifactContract,
    source_path: str,
    source_identity: str,
    source_sha256: str,
    output_parent_path: str,
    output_parent_identity: str,
    destination: str,
) -> tuple[str, tuple[int, int]]:
    validate_destination(destination, contract)
    if SHA256_RE.fullmatch(source_sha256) is None:
        fail("validated build artifact SHA-256 is malformed")
    expected_source = parse_identity(source_identity, "build artifact source")
    expected_parent = parse_identity(output_parent_identity, "output parent")
    source, source_info = open_source(source_path, expected_source)
    output_parent = open_bound_output_parent(output_parent_path, expected_parent)
    pending_descriptor = None
    try:
        require_absent(output_parent, destination, "build output destination")
        pending = f"{contract.pending_prefix}{os.urandom(32).hex()}"
        require_absent(output_parent, pending, "pending build output")
        try:
            os.mkdir(pending, 0o700, dir_fd=output_parent)
        except OSError as exc:
            fail(f"cannot create pending build output: {exc}")
        pending_descriptor = open_pending(output_parent, pending, None, contract)
        pending_info = os.fstat(pending_descriptor)
        copy_source(
            source,
            source_info,
            pending_descriptor,
            source_sha256,
            contract,
        )
        create_checksum(pending_descriptor, source_sha256, contract)
        if (
            verify_result(pending_descriptor, "pending build output", contract)
            != source_sha256
        ):
            fail("pending build output digest changed")
        os.fsync(pending_descriptor)
        os.fsync(output_parent)
        require_absent(output_parent, destination, "build output destination")
        edge = os.stat(pending, dir_fd=output_parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(edge.st_mode)
            or identity(edge) != identity(pending_info)
            or stable_file(source_info) != stable_file(os.fstat(source))
        ):
            fail("pending build output or its validated source changed")
        reprove_output_parent(output_parent_path, expected_parent)
        return pending, identity(pending_info)
    finally:
        if pending_descriptor is not None:
            os.close(pending_descriptor)
        os.close(output_parent)
        os.close(source)


def commit(
    contract: ArtifactContract,
    output_parent_path: str,
    output_parent_identity: str,
    pending: str,
    pending_identity: str,
    destination: str,
) -> None:
    validate_destination(destination, contract)
    if contract.pending_pattern.fullmatch(pending) is None:
        fail("pending build output name is malformed")
    expected_parent = parse_identity(output_parent_identity, "output parent")
    expected_pending = parse_identity(pending_identity, "pending build output")
    output_parent = open_bound_output_parent(output_parent_path, expected_parent)
    pending_descriptor = None
    try:
        require_absent(output_parent, destination, "build output destination")
        pending_descriptor = open_pending(
            output_parent,
            pending,
            expected_pending,
            contract,
        )
        pending_info = os.fstat(pending_descriptor)
        verify_result(pending_descriptor, "pending build output", contract)
        os.fsync(pending_descriptor)
        os.fsync(output_parent)
        reprove_output_parent(output_parent_path, expected_parent)
        rename_noreplace(output_parent, pending, destination)
        os.fsync(output_parent)
        require_absent(output_parent, pending, "retired pending build output")
        published = os.stat(destination, dir_fd=output_parent, follow_symlinks=False)
        if not stat.S_ISDIR(published.st_mode) or identity(published) != identity(pending_info):
            fail("published build output is not the authenticated pending object")
        verify_result(pending_descriptor, "published build output", contract)
        require_absent(output_parent, pending, "retired pending build output")
        published = os.stat(destination, dir_fd=output_parent, follow_symlinks=False)
        if not stat.S_ISDIR(published.st_mode) or identity(published) != identity(pending_info):
            fail("published build output changed during final verification")
        reprove_output_parent(output_parent_path, expected_parent)
    finally:
        if pending_descriptor is not None:
            os.close(pending_descriptor)
        os.close(output_parent)


def make_source(
    directory: str,
    name: str,
    data: bytes,
) -> tuple[str, str, str]:
    path = os.path.join(directory, name)
    with open(path, "xb") as handle:
        handle.write(data)
    os.chmod(path, 0o600)
    info = os.stat(path)
    return (
        path,
        f"{info.st_dev}:{info.st_ino}",
        hashlib.sha256(data).hexdigest(),
    )


def assert_rejected(operation, label: str) -> None:
    try:
        operation()
    except PublicationError:
        return
    fail(f"self-test accepted {label}")


def self_test_contract(contract: ArtifactContract) -> None:
    with tempfile.TemporaryDirectory(
        prefix=f"{contract.kind}-publication-test."
    ) as temporary:
        os.chmod(temporary, 0o700)
        output_parent = os.path.join(temporary, "out")
        os.mkdir(output_parent, 0o700)
        parent_info = os.stat(output_parent)
        parent_identity = f"{parent_info.st_dev}:{parent_info.st_ino}"

        source, source_identity, source_sha256 = make_source(
            temporary,
            f"source-{contract.kind}",
            b"synthetic build artifact\n",
        )
        pending, pending_info = prepare(
            contract,
            source,
            source_identity,
            source_sha256,
            output_parent,
            parent_identity,
            "published",
        )
        commit(
            contract,
            output_parent,
            parent_identity,
            pending,
            f"{pending_info[0]}:{pending_info[1]}",
            "published",
        )
        published = os.path.join(output_parent, "published")
        if sorted(os.listdir(published)) != list(contract.expected_inventory):
            fail("self-test publication inventory is wrong")
        for name in contract.expected_inventory:
            if stat.S_IMODE(os.stat(os.path.join(published, name)).st_mode) != 0o400:
                fail("self-test publication mode is wrong")

        collision_source, collision_id, collision_sha = make_source(
            temporary,
            f"collision-{contract.kind}",
            b"collision source\n",
        )
        collision_pending, collision_pending_info = prepare(
            contract,
            collision_source,
            collision_id,
            collision_sha,
            output_parent,
            parent_identity,
            "collision",
        )
        collision = os.path.join(output_parent, "collision")
        os.mkdir(collision, 0o700)
        marker = os.path.join(collision, "preserve")
        with open(marker, "xb") as handle:
            handle.write(b"preserve\n")
        assert_rejected(
            lambda: commit(
                contract,
                output_parent,
                parent_identity,
                collision_pending,
                f"{collision_pending_info[0]}:{collision_pending_info[1]}",
                "collision",
            ),
            "an occupied destination",
        )
        if (
            not os.path.isfile(marker)
            or not os.path.isdir(os.path.join(output_parent, collision_pending))
        ):
            fail("collision self-test changed existing or pending state")

        hardlink_source, hardlink_id, hardlink_sha = make_source(
            temporary,
            f"hardlink-{contract.kind}",
            b"hardlinked source\n",
        )
        os.link(
            hardlink_source,
            os.path.join(temporary, f"hardlink-alias-{contract.kind}"),
        )
        assert_rejected(
            lambda: prepare(
                contract,
                hardlink_source,
                hardlink_id,
                hardlink_sha,
                output_parent,
                parent_identity,
                "hardlink",
            ),
            "a multiply linked source",
        )

        replaced_source, replaced_id, replaced_sha = make_source(
            temporary,
            f"replaced-source-{contract.kind}",
            b"original source\n",
        )
        os.rename(replaced_source, f"{replaced_source}.retained")
        with open(replaced_source, "xb") as handle:
            handle.write(b"replacement source\n")
        os.chmod(replaced_source, 0o600)
        assert_rejected(
            lambda: prepare(
                contract,
                replaced_source,
                replaced_id,
                replaced_sha,
                output_parent,
                parent_identity,
                "replaced-source",
            ),
            "a substituted source",
        )

        pending_source, pending_source_id, pending_source_sha = make_source(
            temporary,
            f"pending-substitution-{contract.kind}",
            b"pending substitution\n",
        )
        replaced_pending, replaced_pending_info = prepare(
            contract,
            pending_source,
            pending_source_id,
            pending_source_sha,
            output_parent,
            parent_identity,
            "replaced-pending",
        )
        displaced = f"{replaced_pending}.displaced"
        os.rename(
            os.path.join(output_parent, replaced_pending),
            os.path.join(output_parent, displaced),
        )
        os.mkdir(os.path.join(output_parent, replaced_pending), 0o700)
        assert_rejected(
            lambda: commit(
                contract,
                output_parent,
                parent_identity,
                replaced_pending,
                f"{replaced_pending_info[0]}:{replaced_pending_info[1]}",
                "replaced-pending",
            ),
            "a substituted pending output",
        )
        if os.path.exists(os.path.join(output_parent, "replaced-pending")):
            fail("pending-substitution self-test exposed a final result")

        extra_source, extra_id, extra_sha = make_source(
            temporary,
            f"extra-{contract.kind}",
            b"extra inventory\n",
        )
        extra_pending, extra_pending_info = prepare(
            contract,
            extra_source,
            extra_id,
            extra_sha,
            output_parent,
            parent_identity,
            "extra",
        )
        with open(os.path.join(output_parent, extra_pending, "unexpected"), "xb") as handle:
            handle.write(b"unexpected\n")
        os.chmod(os.path.join(output_parent, extra_pending, "unexpected"), 0o400)
        assert_rejected(
            lambda: commit(
                contract,
                output_parent,
                parent_identity,
                extra_pending,
                f"{extra_pending_info[0]}:{extra_pending_info[1]}",
                "extra",
            ),
            "an extra pending entry",
        )
        if os.path.exists(os.path.join(output_parent, "extra")):
            fail("inventory self-test exposed a final result")

        retained_parent = os.path.join(temporary, "retained-out")
        os.rename(output_parent, retained_parent)
        os.mkdir(output_parent, 0o700)
        parent_source, parent_source_id, parent_source_sha = make_source(
            temporary,
            f"parent-substitution-{contract.kind}",
            b"parent substitution\n",
        )
        assert_rejected(
            lambda: prepare(
                contract,
                parent_source,
                parent_source_id,
                parent_source_sha,
                output_parent,
                parent_identity,
                "parent-substitution",
            ),
            "a substituted output parent",
        )


def self_test() -> None:
    for contract in CONTRACTS.values():
        self_test_contract(contract)
    print("publish-artifact-result self-test: ok")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--self-test", action="store_true")
    modes.add_argument("--prepare", action="store_true")
    modes.add_argument("--commit", action="store_true")
    parser.add_argument("--artifact-kind", choices=tuple(CONTRACTS))
    parser.add_argument("--source")
    parser.add_argument("--source-identity")
    parser.add_argument("--source-sha256")
    parser.add_argument("--output-parent")
    parser.add_argument("--output-parent-identity")
    parser.add_argument("--pending")
    parser.add_argument("--pending-identity")
    parser.add_argument("--destination")
    args = parser.parse_args(argv)
    if args.self_test:
        if any(
            value is not None
            for value in (
                args.source,
                args.artifact_kind,
                args.source_identity,
                args.source_sha256,
                args.output_parent,
                args.output_parent_identity,
                args.pending,
                args.pending_identity,
                args.destination,
            )
        ):
            parser.error("--self-test takes no publication arguments")
    elif args.prepare:
        if (
            args.artifact_kind is None
            or any(
                value is None
                for value in (
                    args.source,
                    args.source_identity,
                    args.source_sha256,
                    args.output_parent,
                    args.output_parent_identity,
                    args.destination,
                )
            )
            or args.pending is not None
            or args.pending_identity is not None
        ):
            parser.error("prepare requires one artifact profile and six authority arguments")
    elif (
        args.artifact_kind is None
        or any(
            value is None
            for value in (
                args.output_parent,
                args.output_parent_identity,
                args.pending,
                args.pending_identity,
                args.destination,
            )
        )
        or args.source is not None
        or args.source_identity is not None
        or args.source_sha256 is not None
    ):
        parser.error("commit requires one artifact profile and five authority arguments")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        self_test()
    elif args.prepare:
        contract = CONTRACTS[args.artifact_kind]
        pending, pending_identity = prepare(
            contract,
            args.source,
            args.source_identity,
            args.source_sha256,
            args.output_parent,
            args.output_parent_identity,
            args.destination,
        )
        print(f"{pending} {pending_identity[0]}:{pending_identity[1]}")
    else:
        contract = CONTRACTS[args.artifact_kind]
        commit(
            contract,
            args.output_parent,
            args.output_parent_identity,
            args.pending,
            args.pending_identity,
            args.destination,
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (PublicationError, OSError) as exc:
        print(f"publish-artifact-result: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
