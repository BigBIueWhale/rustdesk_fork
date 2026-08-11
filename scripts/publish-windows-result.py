#!/usr/bin/env python3
"""Publish one validated Windows result directory without pathname authority."""

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


RENAME_NOREPLACE = 1
CANDIDATE_NAME = ".windows-output-candidate"
SOURCE_COMPONENTS = ("pass-A", "result")
ARTIFACTS = ("rustdesk-setup.exe", "rustdesk.msi")
CHECKSUMS = {
    "rustdesk-setup.exe": "rustdesk-setup.exe.sha256",
    "rustdesk.msi": "rustdesk.msi.sha256",
}
DIAGNOSTICS = (
    "build-log.txt",
    "build-windows.stderr.txt",
    "build-windows.stdout.txt",
    "domain.xml",
    "run-build-progress.txt",
    "windows-installed-service-probe.stderr.txt",
    "windows-installed-service-probe.stdout.txt",
    "windows-installed-service-result.json",
)
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 64 * 1024 * 1024
MAX_CHECKSUM_BYTES = 256
IDENTITY_RE = re.compile(r"^(0|[1-9][0-9]*):([1-9][0-9]*)$")
DESTINATION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
PENDING_RE = re.compile(r"^\.windows-output-pending-[0-9a-f]{64}$")
SHA256_LINE_RE = re.compile(rb"^([0-9a-f]{64})  ([A-Za-z0-9._-]+)\n$")
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


class PublicationError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise PublicationError(message)


def identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def parse_identity(value: str, label: str) -> tuple[int, int]:
    match = IDENTITY_RE.fullmatch(value)
    if match is None:
        fail(f"{label} identity is malformed")
    return int(match.group(1)), int(match.group(2))


def stable_file(info: os.stat_result) -> tuple[int, ...]:
    return tuple(getattr(info, field) for field in STABLE_FILE_FIELDS)


def reject_access_acl(descriptor: int, label: str) -> None:
    try:
        names = os.listxattr(descriptor)
    except OSError as exc:
        fail(f"cannot inspect {label} extended attributes: {exc}")
    for name in names:
        if name in ("system.posix_acl_access", "system.posix_acl_default"):
            fail(f"{label} has a POSIX access ACL")


def open_bound_directory(
    path: str,
    expected: tuple[int, int],
    *,
    private: bool,
    label: str,
) -> int:
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        fail(f"{label} path is not absolute and canonical")
    try:
        before = os.lstat(path)
    except OSError as exc:
        fail(f"cannot inspect {label}: {exc}")
    if not stat.S_ISDIR(before.st_mode):
        fail(f"{label} is not a real directory")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot open {label}: {exc}")
    try:
        opened = os.fstat(descriptor)
        if stable_file(before) != stable_file(opened):
            fail(f"{label} changed while it was opened")
        if identity(opened) != expected:
            fail(f"{label} device/inode identity changed")
        if opened.st_uid != os.getuid() or opened.st_gid != os.getgid():
            fail(f"{label} is not owned by the invoking principal")
        mode = stat.S_IMODE(opened.st_mode)
        if private:
            if mode != 0o700:
                fail(f"{label} is not mode 0700")
        elif mode & 0o7000 or mode & 0o022 or mode & 0o700 != 0o700:
            fail(f"{label} grants unsafe publication authority")
        reject_access_acl(descriptor, label)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def reprove_path(
    path: str,
    expected: tuple[int, int],
    *,
    private: bool,
    label: str,
) -> None:
    descriptor = open_bound_directory(path, expected, private=private, label=label)
    os.close(descriptor)


def open_private_child(parent: int, name: str, device: int, label: str) -> int:
    if (
        name != CANDIDATE_NAME
        and not DESTINATION_RE.fullmatch(name)
        and not PENDING_RE.fullmatch(name)
    ):
        fail(f"{label} name is malformed")
    try:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError as exc:
        fail(f"cannot inspect {label}: {exc}")
    if not stat.S_ISDIR(before.st_mode):
        fail(f"{label} is not a real directory")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
    except OSError as exc:
        fail(f"cannot open {label}: {exc}")
    try:
        opened = os.fstat(descriptor)
        if stable_file(before) != stable_file(opened):
            fail(f"{label} changed while it was opened")
        if opened.st_dev != device:
            fail(f"{label} crosses the private run filesystem")
        if opened.st_uid != os.getuid() or opened.st_gid != os.getgid():
            fail(f"{label} is not owned by the invoking principal")
        if stat.S_IMODE(opened.st_mode) != 0o700:
            fail(f"{label} is not mode 0700")
        reject_access_acl(descriptor, label)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def list_entries(descriptor: int, label: str) -> tuple[str, ...]:
    try:
        entries = tuple(sorted(os.listdir(descriptor)))
    except OSError as exc:
        fail(f"cannot enumerate {label}: {exc}")
    if any(not isinstance(entry, str) for entry in entries):
        fail(f"{label} contains a non-text name")
    return entries


def open_regular(
    parent: int,
    name: str,
    *,
    maximum: int,
    allow_empty: bool,
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
        or stat.S_IMODE(before.st_mode) != 0o644
        or before.st_nlink != 1
        or before.st_size > maximum
        or (not allow_empty and before.st_size == 0)
    ):
        fail(f"{label} metadata is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
    except OSError as exc:
        fail(f"cannot open {label}: {exc}")
    opened = os.fstat(descriptor)
    if stable_file(before) != stable_file(opened):
        os.close(descriptor)
        fail(f"{label} changed while it was opened")
    return descriptor, opened


def read_regular(
    parent: int,
    name: str,
    *,
    maximum: int,
    allow_empty: bool,
    label: str,
) -> bytes:
    descriptor, before = open_regular(
        parent,
        name,
        maximum=maximum,
        allow_empty=allow_empty,
        label=label,
    )
    try:
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                fail(f"{label} ended before its recorded size")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            fail(f"{label} grew beyond its recorded size")
        after = os.fstat(descriptor)
        if stable_file(before) != stable_file(after):
            fail(f"{label} changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def create_output_file(parent: int, name: str, label: str) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        return os.open(name, flags, 0o600, dir_fd=parent)
    except OSError as exc:
        fail(f"cannot create {label}: {exc}")


def write_all(descriptor: int, data: bytes, label: str) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            fail(f"short write while creating {label}")
        offset += written


def copy_regular(
    source_parent: int,
    destination_parent: int,
    name: str,
    *,
    maximum: int,
    allow_empty: bool,
    label: str,
) -> str:
    source, before = open_regular(
        source_parent,
        name,
        maximum=maximum,
        allow_empty=allow_empty,
        label=label,
    )
    destination = create_output_file(destination_parent, name, f"candidate {name}")
    digest = hashlib.sha256()
    try:
        remaining = before.st_size
        while remaining:
            chunk = os.read(source, min(1024 * 1024, remaining))
            if not chunk:
                fail(f"{label} ended before its recorded size")
            write_all(destination, chunk, f"candidate {name}")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(source, 1):
            fail(f"{label} grew beyond its recorded size")
        if stable_file(before) != stable_file(os.fstat(source)):
            fail(f"{label} changed while it was copied")
        os.fchmod(destination, 0o644)
        os.fsync(destination)
        copied = os.fstat(destination)
        if (
            not stat.S_ISREG(copied.st_mode)
            or copied.st_uid != os.getuid()
            or copied.st_gid != os.getgid()
            or stat.S_IMODE(copied.st_mode) != 0o644
            or copied.st_nlink != 1
            or copied.st_size != before.st_size
        ):
            fail(f"candidate {name} metadata is invalid")
        return digest.hexdigest()
    finally:
        os.close(destination)
        os.close(source)


def parse_checksums(source: int) -> dict[str, tuple[str, bytes]]:
    parsed = {}
    for artifact, checksum_name in CHECKSUMS.items():
        data = read_regular(
            source,
            checksum_name,
            maximum=MAX_CHECKSUM_BYTES,
            allow_empty=False,
            label=f"source checksum {checksum_name}",
        )
        match = SHA256_LINE_RE.fullmatch(data)
        if match is None or match.group(2).decode("ascii") != artifact:
            fail(f"source checksum {checksum_name} is not canonical")
        parsed[artifact] = (match.group(1).decode("ascii"), data)
    return parsed


def validate_inventory(entries: tuple[str, ...], label: str) -> None:
    allowed = set(ARTIFACTS) | set(CHECKSUMS.values()) | set(DIAGNOSTICS)
    required = set(ARTIFACTS) | set(CHECKSUMS.values())
    if set(entries) - allowed or not required.issubset(entries):
        fail(f"{label} inventory is not the closed Windows output set")


def verify_result(descriptor: int, expected_entries: tuple[str, ...], label: str) -> None:
    if list_entries(descriptor, label) != expected_entries:
        fail(f"{label} inventory changed")
    parsed = parse_checksums(descriptor)
    for artifact in ARTIFACTS:
        source, before = open_regular(
            descriptor,
            artifact,
            maximum=MAX_ARTIFACT_BYTES,
            allow_empty=False,
            label=f"{label} artifact {artifact}",
        )
        digest = hashlib.sha256()
        try:
            remaining = before.st_size
            while remaining:
                chunk = os.read(source, min(1024 * 1024, remaining))
                if not chunk:
                    fail(f"{label} artifact {artifact} ended early")
                digest.update(chunk)
                remaining -= len(chunk)
            if os.read(source, 1):
                fail(f"{label} artifact {artifact} grew")
            if stable_file(before) != stable_file(os.fstat(source)):
                fail(f"{label} artifact {artifact} changed while hashing")
        finally:
            os.close(source)
        if digest.hexdigest() != parsed[artifact][0]:
            fail(f"{label} artifact {artifact} does not match its checksum")
    for diagnostic in DIAGNOSTICS:
        if diagnostic in expected_entries:
            descriptor_value, before = open_regular(
                descriptor,
                diagnostic,
                maximum=MAX_DIAGNOSTIC_BYTES,
                allow_empty=True,
                label=f"{label} diagnostic {diagnostic}",
            )
            try:
                remaining = before.st_size
                while remaining:
                    chunk = os.read(descriptor_value, min(1024 * 1024, remaining))
                    if not chunk:
                        fail(f"{label} diagnostic {diagnostic} ended early")
                    remaining -= len(chunk)
                if os.read(descriptor_value, 1):
                    fail(f"{label} diagnostic {diagnostic} grew")
                if stable_file(before) != stable_file(os.fstat(descriptor_value)):
                    fail(f"{label} diagnostic {diagnostic} changed while reading")
            finally:
                os.close(descriptor_value)


def rename_noreplace(
    source_parent: int,
    source_name: str,
    destination_parent: int,
    destination_name: str,
) -> None:
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
            source_parent,
            os.fsencode(source_name),
            destination_parent,
            os.fsencode(destination_name),
            RENAME_NOREPLACE,
        )
        != 0
    ):
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            fail("Windows output destination appeared before no-clobber publication")
        if error == errno.EXDEV:
            fail("Windows output publication is not on one filesystem")
        fail(f"renameat2(RENAME_NOREPLACE) failed: {os.strerror(error)}")


def require_absent(parent: int, name: str, label: str) -> None:
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        fail(f"cannot inspect {label}: {exc}")
    fail(f"{label} is occupied")


def prepare(
    run_root_path: str,
    run_root_identity: str,
    output_parent_path: str,
    output_parent_identity: str,
    destination: str,
) -> tuple[str, tuple[int, int]]:
    if not DESTINATION_RE.fullmatch(destination) or destination in (".", ".."):
        fail("Windows output destination name is malformed")
    expected_run = parse_identity(run_root_identity, "private run root")
    expected_parent = parse_identity(output_parent_identity, "output parent")
    run_root = open_bound_directory(
        run_root_path,
        expected_run,
        private=True,
        label="private run root",
    )
    output_parent = open_bound_directory(
        output_parent_path,
        expected_parent,
        private=False,
        label="output parent",
    )
    opened = []
    try:
        run_info = os.fstat(run_root)
        parent_info = os.fstat(output_parent)
        if run_info.st_dev != parent_info.st_dev:
            fail("Windows output publication requires one filesystem")
        require_absent(output_parent, destination, "Windows output destination")
        require_absent(run_root, CANDIDATE_NAME, "Windows output candidate")

        source_parent = open_private_child(
            run_root,
            SOURCE_COMPONENTS[0],
            run_info.st_dev,
            "pass-A directory",
        )
        opened.append(source_parent)
        source = open_private_child(
            source_parent,
            SOURCE_COMPONENTS[1],
            run_info.st_dev,
            "pass-A result directory",
        )
        opened.append(source)
        source_entries = list_entries(source, "pass-A result")
        validate_inventory(source_entries, "pass-A result")
        parsed = parse_checksums(source)

        try:
            os.mkdir(CANDIDATE_NAME, 0o700, dir_fd=run_root)
        except OSError as exc:
            fail(f"cannot create private Windows output candidate: {exc}")
        candidate = open_private_child(
            run_root,
            CANDIDATE_NAME,
            run_info.st_dev,
            "Windows output candidate",
        )
        opened.append(candidate)

        for artifact in ARTIFACTS:
            actual = copy_regular(
                source,
                candidate,
                artifact,
                maximum=MAX_ARTIFACT_BYTES,
                allow_empty=False,
                label=f"source artifact {artifact}",
            )
            if actual != parsed[artifact][0]:
                fail(f"source artifact {artifact} does not match its checksum")
            checksum_name = CHECKSUMS[artifact]
            output = create_output_file(candidate, checksum_name, f"candidate {checksum_name}")
            try:
                write_all(output, parsed[artifact][1], f"candidate {checksum_name}")
                os.fchmod(output, 0o644)
                os.fsync(output)
            finally:
                os.close(output)
        for diagnostic in DIAGNOSTICS:
            if diagnostic in source_entries:
                copy_regular(
                    source,
                    candidate,
                    diagnostic,
                    maximum=MAX_DIAGNOSTIC_BYTES,
                    allow_empty=True,
                    label=f"source diagnostic {diagnostic}",
                )

        if list_entries(source, "pass-A result") != source_entries:
            fail("pass-A result inventory changed during candidate creation")
        verify_result(candidate, source_entries, "private Windows output candidate")
        os.fsync(candidate)
        os.fsync(run_root)
        reprove_path(
            run_root_path,
            expected_run,
            private=True,
            label="private run root",
        )
        reprove_path(
            output_parent_path,
            expected_parent,
            private=False,
            label="output parent",
        )
        pending = f".windows-output-pending-{os.urandom(32).hex()}"
        require_absent(output_parent, pending, "Windows pending output")
        rename_noreplace(run_root, CANDIDATE_NAME, output_parent, pending)
        os.fsync(run_root)
        os.fsync(output_parent)

        require_absent(run_root, CANDIDATE_NAME, "retired Windows output candidate")
        pending_info = os.stat(pending, dir_fd=output_parent, follow_symlinks=False)
        candidate_info = os.fstat(candidate)
        if not stat.S_ISDIR(pending_info.st_mode) or identity(pending_info) != identity(candidate_info):
            fail("pending Windows output edge is not the authenticated candidate")
        verify_result(candidate, source_entries, "pending Windows output")
        reprove_path(
            run_root_path,
            expected_run,
            private=True,
            label="private run root",
        )
        reprove_path(
            output_parent_path,
            expected_parent,
            private=False,
            label="output parent",
        )
        return pending, identity(candidate_info)
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)
        os.close(output_parent)
        os.close(run_root)


def commit(
    output_parent_path: str,
    output_parent_identity: str,
    pending: str,
    pending_identity: str,
    destination: str,
) -> None:
    if not DESTINATION_RE.fullmatch(destination) or destination in (".", ".."):
        fail("Windows output destination name is malformed")
    if PENDING_RE.fullmatch(pending) is None:
        fail("Windows pending output name is malformed")
    expected_parent = parse_identity(output_parent_identity, "output parent")
    expected_pending = parse_identity(pending_identity, "pending output")
    output_parent = open_bound_directory(
        output_parent_path,
        expected_parent,
        private=False,
        label="output parent",
    )
    candidate = None
    try:
        parent_info = os.fstat(output_parent)
        require_absent(output_parent, destination, "Windows output destination")
        candidate = open_private_child(
            output_parent,
            pending,
            parent_info.st_dev,
            "pending Windows output",
        )
        candidate_info = os.fstat(candidate)
        if identity(candidate_info) != expected_pending:
            fail("pending Windows output device/inode identity changed")
        entries = list_entries(candidate, "pending Windows output")
        validate_inventory(entries, "pending Windows output")
        verify_result(candidate, entries, "pending Windows output")
        os.fsync(candidate)
        os.fsync(output_parent)
        reprove_path(
            output_parent_path,
            expected_parent,
            private=False,
            label="output parent",
        )
        rename_noreplace(output_parent, pending, output_parent, destination)
        os.fsync(output_parent)
        require_absent(output_parent, pending, "retired pending Windows output")
        published = os.stat(destination, dir_fd=output_parent, follow_symlinks=False)
        if not stat.S_ISDIR(published.st_mode) or identity(published) != identity(candidate_info):
            fail("published Windows output edge is not the authenticated candidate")
        verify_result(candidate, entries, "published Windows output")
        reprove_path(
            output_parent_path,
            expected_parent,
            private=False,
            label="output parent",
        )
    finally:
        if candidate is not None:
            os.close(candidate)
        os.close(output_parent)


def make_result(run_root: str, *, hardlink: bool = False, extra: bool = False) -> None:
    pass_root = os.path.join(run_root, "pass-A")
    result = os.path.join(pass_root, "result")
    os.mkdir(pass_root, 0o700)
    os.mkdir(result, 0o700)
    artifacts = {
        "rustdesk-setup.exe": b"synthetic setup\n",
        "rustdesk.msi": b"synthetic msi\n",
    }
    for name, data in artifacts.items():
        path = os.path.join(result, name)
        with open(path, "xb") as handle:
            handle.write(data)
        os.chmod(path, 0o644)
        checksum = hashlib.sha256(data).hexdigest().encode("ascii") + b"  " + name.encode("ascii") + b"\n"
        checksum_name = CHECKSUMS[name]
        with open(os.path.join(result, checksum_name), "xb") as handle:
            handle.write(checksum)
        os.chmod(os.path.join(result, checksum_name), 0o644)
    with open(os.path.join(result, "build-log.txt"), "xb") as handle:
        handle.write(b"synthetic log\n")
    os.chmod(os.path.join(result, "build-log.txt"), 0o644)
    if hardlink:
        os.link(
            os.path.join(result, "rustdesk.msi"),
            os.path.join(run_root, "external-msi-link"),
        )
    if extra:
        with open(os.path.join(result, "unexpected"), "xb") as handle:
            handle.write(b"unexpected\n")
        os.chmod(os.path.join(result, "unexpected"), 0o644)


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="windows-publication-test.") as temporary:
        os.chmod(temporary, 0o700)

        run_root = os.path.join(temporary, "run")
        output_parent = os.path.join(temporary, "out")
        os.mkdir(run_root, 0o700)
        os.mkdir(output_parent, 0o700)
        make_result(run_root)
        run_id = ":".join(str(value) for value in identity(os.stat(run_root)))
        parent_id = ":".join(str(value) for value in identity(os.stat(output_parent)))
        pending, pending_id = prepare(run_root, run_id, output_parent, parent_id, "windows")
        if os.path.exists(os.path.join(run_root, CANDIDATE_NAME)):
            fail("self-test retained a prepared candidate in the run root")
        pending_identity = ":".join(str(value) for value in pending_id)
        commit(output_parent, parent_id, pending, pending_identity, "windows")
        published = os.path.join(output_parent, "windows")
        if not os.path.isdir(published):
            fail("self-test did not publish the Windows output")

        collision_run = os.path.join(temporary, "collision-run")
        os.mkdir(collision_run, 0o700)
        make_result(collision_run)
        collision_id = ":".join(str(value) for value in identity(os.stat(collision_run)))
        collision_pending, collision_pending_id = prepare(
            collision_run,
            collision_id,
            output_parent,
            parent_id,
            "collision",
        )
        collision = os.path.join(output_parent, "collision")
        os.mkdir(collision, 0o700)
        marker = os.path.join(collision, "preserve")
        with open(marker, "xb") as handle:
            handle.write(b"preserve\n")
        try:
            commit(
                output_parent,
                parent_id,
                collision_pending,
                ":".join(str(value) for value in collision_pending_id),
                "collision",
            )
        except PublicationError:
            pass
        else:
            fail("self-test accepted an occupied destination")
        if (
            not os.path.isfile(marker)
            or not os.path.isdir(os.path.join(output_parent, collision_pending))
        ):
            fail("self-test changed an occupied destination")

        retained_parent = os.path.join(temporary, "out-retained")
        os.rename(output_parent, retained_parent)
        os.mkdir(output_parent, 0o700)
        substitute_run = os.path.join(temporary, "substitute-run")
        os.mkdir(substitute_run, 0o700)
        make_result(substitute_run)
        substitute_id = ":".join(str(value) for value in identity(os.stat(substitute_run)))
        try:
            prepare(substitute_run, substitute_id, output_parent, parent_id, "substituted")
        except PublicationError:
            pass
        else:
            fail("self-test accepted a substituted output parent")
        if os.path.exists(os.path.join(output_parent, "substituted")):
            fail("self-test published through a substituted output parent")

        for suffix, options in (
            ("hardlink", {"hardlink": True}),
            ("extra", {"extra": True}),
        ):
            bad_run = os.path.join(temporary, f"{suffix}-run")
            os.mkdir(bad_run, 0o700)
            make_result(bad_run, **options)
            bad_id = ":".join(str(value) for value in identity(os.stat(bad_run)))
            try:
                prepare(bad_run, bad_id, retained_parent, parent_id, f"bad-{suffix}")
            except PublicationError:
                pass
            else:
                fail(f"self-test accepted a {suffix} source")
            if os.path.exists(os.path.join(retained_parent, f"bad-{suffix}")):
                fail(f"self-test published a {suffix} source")

        replaced_run = os.path.join(temporary, "replaced-pending-run")
        os.mkdir(replaced_run, 0o700)
        make_result(replaced_run)
        replaced_run_id = ":".join(str(value) for value in identity(os.stat(replaced_run)))
        replaced_pending, replaced_pending_id = prepare(
            replaced_run,
            replaced_run_id,
            retained_parent,
            parent_id,
            "replaced-pending",
        )
        displaced_pending = f"{replaced_pending}.displaced"
        os.rename(
            os.path.join(retained_parent, replaced_pending),
            os.path.join(retained_parent, displaced_pending),
        )
        os.mkdir(os.path.join(retained_parent, replaced_pending), 0o700)
        try:
            commit(
                retained_parent,
                parent_id,
                replaced_pending,
                ":".join(str(value) for value in replaced_pending_id),
                "replaced-pending",
            )
        except PublicationError:
            pass
        else:
            fail("self-test accepted a substituted pending output")
        if os.path.exists(os.path.join(retained_parent, "replaced-pending")):
            fail("self-test published through a substituted pending output")

    print("publish-windows-result self-test: ok")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--self-test", action="store_true")
    modes.add_argument("--prepare", action="store_true")
    modes.add_argument("--commit", action="store_true")
    parser.add_argument("--run-root")
    parser.add_argument("--run-root-identity")
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
                args.run_root,
                args.run_root_identity,
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
            any(
                value is None
                for value in (
                    args.run_root,
                    args.run_root_identity,
                    args.output_parent,
                    args.output_parent_identity,
                    args.destination,
                )
            )
            or args.pending is not None
            or args.pending_identity is not None
        ):
            parser.error("prepare requires exactly its five authority arguments")
    elif (
        any(
            value is None
            for value in (
                args.output_parent,
                args.output_parent_identity,
                args.pending,
                args.pending_identity,
                args.destination,
            )
        )
        or args.run_root is not None
        or args.run_root_identity is not None
    ):
        parser.error("commit requires exactly its five authority arguments")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        self_test()
    elif args.prepare:
        pending, pending_id = prepare(
            args.run_root,
            args.run_root_identity,
            args.output_parent,
            args.output_parent_identity,
            args.destination,
        )
        print(f"{pending} {pending_id[0]}:{pending_id[1]}")
    else:
        commit(
            args.output_parent,
            args.output_parent_identity,
            args.pending,
            args.pending_identity,
            args.destination,
        )
        print("publish-windows-result: committed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except PublicationError as exc:
        print(f"publish-windows-result: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
