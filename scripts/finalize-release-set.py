#!/usr/bin/env python3
import argparse
import array
import ctypes
import fcntl
import hashlib
import json
import os
import re
import stat
import struct
import sys
import time


ASSETS = (
    "rustdesk-x86_64.deb",
    "rustdesk-arm64.apk",
    "rustdesk-setup.exe",
    "rustdesk.msi",
)
MANIFEST = "SHA256SUMS"
ENTRY_NAMES = ASSETS + (MANIFEST,)
MANIFEST_LIMIT = 65536
CONTENT_LIMIT = 2 * 1024 * 1024 * 1024
RECORD_LIMIT = 4096
PARENT_ENTRY_LIMIT = 4096
PARENT_NAME_LIMIT = 1024 * 1024
MOUNTINFO_LIMIT = 4 * 1024 * 1024
MOUNTINFO_ENTRY_LIMIT = 4096
DEADLINE_SECONDS = 180
FS_IOC_GETFLAGS = 0x80086601
FS_IOC_FSGETXATTR = 0x801C581F
FS_EXTENT_FL = 0x00080000
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2
AT_EMPTY_PATH = 0x1000
AT_FDCWD = -100
AT_SYMLINK_FOLLOW = 0x400
FILE_HANDLE_LIMIT = 128
FS_IOC_GETFSUUID = 0x80111500
FILESYSTEM_UUID_SIZE = 16
SUPPORTED_FILESYSTEMS = {
    0xEF53: "ext4",
}
RECORD_STATES = frozenset(
    ("initializing", "staging", "prepared", "rollback", "cleanup")
)
RECORD_TRANSITIONS = frozenset(
    (
        ("initializing", "staging"),
        ("staging", "prepared"),
        ("prepared", "rollback"),
        ("prepared", "cleanup"),
    )
)
ACL_XATTRS = {"system.posix_acl_access", "system.posix_acl_default"}


class PublicationError(RuntimeError):
    pass


class InjectedStop(RuntimeError):
    pass


def report_cleanup_failures(primary, label, failures):
    if not failures:
        return
    notes = [
        f"{label} [{index}]: {type(error).__name__}: {error}"
        for index, error in enumerate(failures, 1)
    ]
    if primary is not None:
        for note in notes:
            primary.add_note(note)
        return
    error = PublicationError(f"{label} failed {len(failures)} time(s)")
    for note in notes:
        error.add_note(note)
    raise error from failures[0]


def close_descriptors(descriptors, label, primary=None):
    failures = []
    for descriptor in descriptors:
        if descriptor is None:
            continue
        try:
            os.close(descriptor)
        except BaseException as error:
            failures.append(error)
    report_cleanup_failures(primary, label, failures)


def require_deadline(deadline):
    if time.monotonic() >= deadline:
        raise PublicationError("publication operation exceeded its deadline")


def identity(metadata):
    return metadata.st_dev, metadata.st_ino


def stable_metadata(metadata):
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


def descriptor_mount_id(descriptor):
    information = os.open(
        f"/proc/self/fdinfo/{descriptor}", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        content = bytearray()
        while len(content) <= 65536:
            chunk = os.read(information, 65537 - len(content))
            if not chunk:
                break
            content.extend(chunk)
    finally:
        close_descriptors(
            (information,), "publication mount-information descriptor close", sys.exception()
        )
    if len(content) > 65536:
        raise PublicationError("publication descriptor mount information exceeds its byte bound")
    values = [
        line[len(b"mnt_id:\t") :]
        for line in bytes(content).splitlines()
        if line.startswith(b"mnt_id:\t")
    ]
    if len(values) != 1 or re.fullmatch(br"[1-9][0-9]*", values[0]) is None:
        raise PublicationError("publication descriptor mount identity is unavailable")
    return int(values[0])


class StatFs(ctypes.Structure):
    _fields_ = [
        ("f_type", ctypes.c_long),
        ("f_bsize", ctypes.c_long),
        ("f_blocks", ctypes.c_ulong),
        ("f_bfree", ctypes.c_ulong),
        ("f_bavail", ctypes.c_ulong),
        ("f_files", ctypes.c_ulong),
        ("f_ffree", ctypes.c_ulong),
        ("f_fsid", ctypes.c_int * 2),
        ("f_namelen", ctypes.c_long),
        ("f_frsize", ctypes.c_long),
        ("f_flags", ctypes.c_long),
        ("f_spare", ctypes.c_long * 4),
    ]


class FileHandle(ctypes.Structure):
    _fields_ = [
        ("handle_bytes", ctypes.c_uint),
        ("handle_type", ctypes.c_int),
        ("f_handle", ctypes.c_ubyte * FILE_HANDLE_LIMIT),
    ]


LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.fstatfs.argtypes = [ctypes.c_int, ctypes.POINTER(StatFs)]
LIBC.fstatfs.restype = ctypes.c_int
LIBC.renameat2.argtypes = [
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_uint,
]
LIBC.renameat2.restype = ctypes.c_int
LIBC.linkat.argtypes = [
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_int,
]
LIBC.linkat.restype = ctypes.c_int
LIBC.name_to_handle_at.argtypes = [
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.POINTER(FileHandle),
    ctypes.POINTER(ctypes.c_int),
    ctypes.c_int,
]
LIBC.name_to_handle_at.restype = ctypes.c_int


def mount_filesystem_type(mount_id):
    descriptor = os.open(
        "/proc/self/mountinfo", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        content = bytearray()
        while len(content) <= MOUNTINFO_LIMIT:
            chunk = os.read(descriptor, min(65536, MOUNTINFO_LIMIT + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
    finally:
        close_descriptors(
            (descriptor,), "publication mount table descriptor close", sys.exception()
        )
    if len(content) > MOUNTINFO_LIMIT:
        raise PublicationError("publication mount table exceeds its byte bound")
    lines = bytes(content).splitlines()
    if len(lines) > MOUNTINFO_ENTRY_LIMIT:
        raise PublicationError("publication mount table exceeds its entry bound")
    matches = []
    expected = str(mount_id).encode("ascii")
    for line in lines:
        fields = line.split(b" ")
        if len(fields) < 10 or b"-" not in fields[6:]:
            raise PublicationError("publication mount table contains a malformed record")
        separator = fields.index(b"-", 6)
        if separator + 3 > len(fields):
            raise PublicationError("publication mount table contains an incomplete record")
        if fields[0] == expected:
            matches.append(fields[separator + 1])
    if len(matches) != 1:
        raise PublicationError("publication mount table does not bind the parent exactly")
    try:
        return matches[0].decode("ascii")
    except UnicodeDecodeError as error:
        raise PublicationError("publication filesystem type is not ASCII") from error


def filesystem_authority(descriptor, mount_id):
    result = StatFs()
    if LIBC.fstatfs(descriptor, ctypes.byref(result)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    value = result.f_type & 0xFFFFFFFF
    expected = SUPPORTED_FILESYSTEMS.get(value)
    observed = mount_filesystem_type(mount_id)
    if expected is None or observed != expected:
        raise PublicationError(f"publication filesystem is unsupported: 0x{value:08x}")
    filesystem_uuid = bytearray(FILESYSTEM_UUID_SIZE + 1)
    try:
        fcntl.ioctl(descriptor, FS_IOC_GETFSUUID, filesystem_uuid, True)
    except OSError as error:
        raise PublicationError("publication filesystem UUID is unavailable") from error
    if filesystem_uuid[0] != FILESYSTEM_UUID_SIZE:
        raise PublicationError("publication filesystem UUID has an invalid size")
    value = bytes(filesystem_uuid[1:])
    if value == bytes(FILESYSTEM_UUID_SIZE):
        raise PublicationError("publication filesystem UUID is zero")
    return f"{observed}:{value.hex()}"


def renameat2(parent_fd, source, destination, flags):
    if LIBC.renameat2(
        parent_fd,
        os.fsencode(source),
        parent_fd,
        os.fsencode(destination),
        flags,
    ) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def link_unnamed_file(file_fd, parent_fd, name):
    source = os.fsencode(f"/proc/self/fd/{file_fd}")
    if LIBC.linkat(
        AT_FDCWD,
        source,
        parent_fd,
        os.fsencode(name),
        AT_SYMLINK_FOLLOW,
    ) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def persistent_handle(descriptor):
    handle = FileHandle()
    handle.handle_bytes = FILE_HANDLE_LIMIT
    mount_id = ctypes.c_int()
    if LIBC.name_to_handle_at(
        descriptor,
        b"",
        ctypes.byref(handle),
        ctypes.byref(mount_id),
        AT_EMPTY_PATH,
    ) != 0:
        error = ctypes.get_errno()
        raise PublicationError(
            f"publication filesystem object handle is unavailable: {os.strerror(error)}"
        )
    if handle.handle_bytes < 1 or handle.handle_bytes > FILE_HANDLE_LIMIT:
        raise PublicationError("publication filesystem object handle has an invalid size")
    opaque = bytes(handle.f_handle[: handle.handle_bytes]).hex()
    return f"{handle.handle_type}:{opaque}"


def parse_handle(value):
    if not isinstance(value, str):
        raise PublicationError("publication record contains a non-string object handle")
    match = re.fullmatch(r"(-?(?:0|[1-9][0-9]*)):([0-9a-f]{2,256})", value)
    if (
        match is None
        or len(match.group(2)) % 2 != 0
        or not -(2**31) <= int(match.group(1)) < 2**31
        or str(int(match.group(1))) != match.group(1)
    ):
        raise PublicationError("publication record contains an invalid object handle")
    return value


def require_no_extended_acl(descriptor, label):
    names = set(os.listxattr(descriptor))
    if names & ACL_XATTRS:
        raise PublicationError(f"{label} has an extended POSIX ACL")


def require_canonical_security(descriptor, label):
    names = os.listxattr(descriptor)
    if names:
        raise PublicationError(f"{label} has filesystem extended attributes")
    flags = array.array("I", [0])
    fcntl.ioctl(descriptor, FS_IOC_GETFLAGS, flags, True)
    if flags[0] & ~FS_EXTENT_FL:
        raise PublicationError(f"{label} has unsupported inode flags")
    extended = bytearray(28)
    fcntl.ioctl(descriptor, FS_IOC_FSGETXATTR, extended, True)
    xflags, extsize, _nextents, project, cowextsize, pad0, pad1 = struct.unpack(
        "<7I", extended
    )
    if xflags or extsize or project or cowextsize or pad0 or pad1:
        raise PublicationError(f"{label} has unsupported extended inode state")


def bounded_names(descriptor):
    names = []
    name_bytes = 0
    with os.scandir(descriptor) as entries:
        for entry in entries:
            if len(names) >= PARENT_ENTRY_LIMIT:
                raise PublicationError("publication parent exceeds its entry bound")
            encoded = os.fsencode(entry.name)
            name_bytes += len(encoded) + 1
            if name_bytes > PARENT_NAME_LIMIT:
                raise PublicationError("publication parent exceeds its name-byte bound")
            names.append(entry.name)
    return sorted(names, key=os.fsencode)


def open_regular_at(parent_fd, name, label):
    authority = os.open(
        name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd
    )
    descriptor = None
    try:
        metadata = os.fstat(authority)
        edge = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or stable_metadata(edge) != stable_metadata(
            metadata
        ):
            raise PublicationError(f"{label} is not a stable regular file")
        descriptor = os.open(
            f"/proc/self/fd/{authority}",
            os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC,
        )
        current = os.fstat(descriptor)
        if stable_metadata(current) != stable_metadata(metadata):
            raise PublicationError(f"{label} changed during descriptor acquisition")
        return descriptor
    except BaseException as error:
        close_descriptors((descriptor,), f"{label} readable descriptor close", error)
        raise
    finally:
        primary = sys.exception()
        try:
            close_descriptors((authority,), f"{label} authority descriptor close", primary)
        except BaseException as error:
            close_descriptors((descriptor,), f"{label} readable descriptor close", error)
            raise


def read_exact(descriptor, size, limit, label, deadline):
    if size < 0 or size > limit:
        raise PublicationError(f"{label} exceeds its byte bound")
    content = bytearray()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while len(content) < size:
        require_deadline(deadline)
        chunk = os.read(descriptor, min(1024 * 1024, size - len(content)))
        if not chunk:
            raise PublicationError(f"{label} ended before its recorded size")
        content.extend(chunk)
    require_deadline(deadline)
    if os.read(descriptor, 1):
        raise PublicationError(f"{label} grew during inspection")
    require_deadline(deadline)
    return bytes(content)


def hash_exact(descriptor, size, remaining, label, deadline):
    if size <= 0 or size > remaining:
        raise PublicationError(f"{label} exceeds the publication content bound")
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    while total < size:
        require_deadline(deadline)
        chunk = os.read(descriptor, min(1024 * 1024, size - total))
        if not chunk:
            raise PublicationError(f"{label} ended before its recorded size")
        digest.update(chunk)
        total += len(chunk)
    require_deadline(deadline)
    if os.read(descriptor, 1):
        raise PublicationError(f"{label} grew during inspection")
    require_deadline(deadline)
    return digest.hexdigest(), remaining - total


def parse_manifest(content, commit=None, version=None, epoch=None):
    try:
        text = content.decode("ascii")
    except UnicodeDecodeError as error:
        raise PublicationError("release manifest is not ASCII") from error
    if not text.endswith("\n"):
        raise PublicationError("release manifest is not newline-terminated")
    lines = text.splitlines()
    if len(lines) != 9:
        raise PublicationError("release manifest must have exactly nine lines")
    if lines[0] != "# rustdesk-fork release manifest v1":
        raise PublicationError("release manifest format is invalid")
    fields = {}
    for key, line in zip(
        ("version", "commit", "epoch"),
        lines[1:4],
    ):
        prefix = {
            "version": "# fork-version: ",
            "commit": "# commit: ",
            "epoch": "# source-date-epoch: ",
        }[key]
        if not line.startswith(prefix):
            raise PublicationError("release manifest metadata order is invalid")
        fields[key] = line[len(prefix) :]
    if (
        re.fullmatch(r"[A-Za-z0-9._+-]+", fields["version"]) is None
        or re.fullmatch(r"[0-9a-f]{40}", fields["commit"]) is None
        or re.fullmatch(r"[1-9][0-9]*", fields["epoch"]) is None
        or lines[4] != "# reproducibility: independent-snapshots-a-equals-b"
    ):
        raise PublicationError("release manifest metadata is invalid")
    if commit is not None and fields["commit"] != commit:
        raise PublicationError("release manifest commit differs from the transaction")
    if version is not None and fields["version"] != version:
        raise PublicationError("release manifest version differs from the transaction")
    if epoch is not None and fields["epoch"] != epoch:
        raise PublicationError("release manifest epoch differs from the transaction")
    hashes = {}
    for asset, line in zip(ASSETS, lines[5:]):
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._+-]+)", line)
        if match is None or match.group(2) != asset:
            raise PublicationError(f"release manifest entry is not canonical for {asset}")
        hashes[asset] = match.group(1)
    return fields, hashes


class ParentAuthority:
    def __init__(self, parent, destination):
        if (
            not os.path.isabs(parent)
            or os.path.normpath(parent) != parent
            or os.path.realpath(parent) != parent
            or re.fullmatch(r"[A-Za-z0-9._+-]+", destination) is None
            or destination in (".", "..")
        ):
            raise PublicationError("publication parent or destination is not canonical")
        self.path = parent
        self.destination = destination
        self.fd = None
        self.uid = os.geteuid()
        self.gid = os.getegid()
        descriptor = os.open(
            parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        self.fd = descriptor
        try:
            self.metadata = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(self.metadata.st_mode)
                or self.metadata.st_uid != self.uid
                or self.metadata.st_gid != self.gid
                or self.metadata.st_mode & stat.S_IRWXU != stat.S_IRWXU
            ):
                raise PublicationError("publication parent is not an invoking-user directory")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            require_no_extended_acl(descriptor, "publication parent")
            self.mount_id = descriptor_mount_id(descriptor)
            self.filesystem = filesystem_authority(descriptor, self.mount_id)
            self.handle = persistent_handle(descriptor)
            name_max = os.fpathconf(descriptor, "PC_NAME_MAX")
            longest_name = f".{destination}-release-transaction.{('0' * 64)}"
            if len(os.fsencode(longest_name)) > name_max:
                raise PublicationError("publication destination exceeds the sibling-name bound")
            if self.metadata.st_mode & 0o022:
                raise PublicationError("publication parent is writable by another mode class")
            require_no_extended_acl(descriptor, "publication parent")
            self.identity = identity(self.metadata)
            edge = os.stat(parent, follow_symlinks=False)
            if stable_metadata(edge) != stable_metadata(self.metadata):
                raise PublicationError("publication parent edge changed during acquisition")
        except BaseException as error:
            self.fd = None
            close_descriptors(
                (descriptor,), "publication parent acquisition descriptor close", error
            )
            raise

    def close(self):
        descriptor = self.fd
        self.fd = None
        if descriptor is not None:
            os.close(descriptor)

    def assert_bound(self):
        metadata = os.fstat(self.fd)
        edge = os.stat(self.path, follow_symlinks=False)
        if (
            identity(metadata) != self.identity
            or stable_metadata(edge) != stable_metadata(metadata)
            or metadata.st_mode & 0o022
            or metadata.st_uid != self.uid
            or metadata.st_gid != self.gid
            or descriptor_mount_id(self.fd) != self.mount_id
            or filesystem_authority(self.fd, self.mount_id) != self.filesystem
            or persistent_handle(self.fd) != self.handle
        ):
            raise PublicationError("publication parent authority changed")
        require_no_extended_acl(self.fd, "publication parent")

    def path_authority(self, name):
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=self.fd,
            )
        except FileNotFoundError:
            return None
        try:
            metadata = os.fstat(descriptor)
            edge = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stable_metadata(edge) != stable_metadata(metadata)
                or metadata.st_dev != self.metadata.st_dev
                or descriptor_mount_id(descriptor) != self.mount_id
            ):
                raise PublicationError(f"publication path authority is invalid: {name}")
            return {
                "identity": identity(metadata),
                "handle": persistent_handle(descriptor),
            }
        finally:
            close_descriptors(
                (descriptor,),
                f"publication path authority descriptor close: {name}",
                sys.exception(),
            )

    def path_identity(self, name):
        authority = self.path_authority(name)
        return None if authority is None else authority["identity"]


def open_release_set(parent, name, root_modes=(0o555,)):
    root_fd = os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=parent.fd,
    )
    try:
        root = os.fstat(root_fd)
        edge = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        if (
            stable_metadata(edge) != stable_metadata(root)
            or root.st_uid != parent.uid
            or root.st_gid != parent.gid
            or stat.S_IMODE(root.st_mode) not in root_modes
            or root.st_dev != parent.metadata.st_dev
            or descriptor_mount_id(root_fd) != parent.mount_id
        ):
            raise PublicationError("release set root authority is invalid")
        require_canonical_security(root_fd, "release set root")
        return root_fd, root
    except BaseException as error:
        close_descriptors((root_fd,), "release set root descriptor close", error)
        raise


def prove_release_set(
    parent,
    name,
    root_mode,
    finalize,
    commit=None,
    version=None,
    epoch=None,
    manifest_hash=None,
    deadline=None,
):
    if deadline is None:
        deadline = time.monotonic() + DEADLINE_SECONDS
    require_deadline(deadline)
    parent.assert_bound()
    root_fd, root = open_release_set(parent, name, (root_mode,))
    descriptors = {}
    before = {}
    try:
        names = bounded_names(root_fd)
        if tuple(names) != tuple(sorted(ENTRY_NAMES, key=os.fsencode)):
            raise PublicationError("release set is not the exact canonical inventory")
        for entry in names:
            require_deadline(deadline)
            descriptor = open_regular_at(root_fd, entry, f"release entry {entry}")
            descriptors[entry] = descriptor
            metadata = os.fstat(descriptor)
            edge = os.stat(entry, dir_fd=root_fd, follow_symlinks=False)
            if (
                stable_metadata(edge) != stable_metadata(metadata)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != parent.uid
                or metadata.st_gid != parent.gid
                or stat.S_IMODE(metadata.st_mode) != 0o444
                or metadata.st_nlink != 1
                or metadata.st_size <= 0
                or metadata.st_dev != parent.metadata.st_dev
                or descriptor_mount_id(descriptor) != parent.mount_id
            ):
                raise PublicationError(f"release entry authority is invalid: {entry}")
            require_canonical_security(descriptor, f"release entry {entry}")
            before[entry] = stable_metadata(metadata)
        manifest_metadata = os.fstat(descriptors[MANIFEST])
        manifest = read_exact(
            descriptors[MANIFEST],
            manifest_metadata.st_size,
            MANIFEST_LIMIT,
            "release manifest",
            deadline,
        )
        fields, expected_hashes = parse_manifest(manifest, commit, version, epoch)
        observed_manifest_hash = hashlib.sha256(manifest).hexdigest()
        if manifest_hash is not None and observed_manifest_hash != manifest_hash:
            raise PublicationError("release manifest digest differs from the transaction")
        remaining = CONTENT_LIMIT
        for asset in ASSETS:
            metadata = os.fstat(descriptors[asset])
            observed, remaining = hash_exact(
                descriptors[asset], metadata.st_size, remaining, asset, deadline
            )
            if observed != expected_hashes[asset]:
                raise PublicationError(f"release artifact differs from its manifest: {asset}")
        for entry, descriptor in descriptors.items():
            require_deadline(deadline)
            current = os.fstat(descriptor)
            edge = os.stat(entry, dir_fd=root_fd, follow_symlinks=False)
            if stable_metadata(current) != before[entry] or stable_metadata(edge) != before[entry]:
                raise PublicationError(f"release entry changed during proof: {entry}")
        if finalize:
            os.fchmod(root_fd, 0o555)
            require_deadline(deadline)
        expected_root_mode = 0o555 if finalize else root_mode
        final_root = os.fstat(root_fd)
        if (
            identity(final_root) != identity(root)
            or stat.S_IMODE(final_root.st_mode) != expected_root_mode
            or final_root.st_uid != parent.uid
            or final_root.st_gid != parent.gid
        ):
            raise PublicationError("release set root finalization failed")
        require_canonical_security(root_fd, "release set root")
        for descriptor in descriptors.values():
            require_deadline(deadline)
            os.fsync(descriptor)
            require_deadline(deadline)
        os.fsync(root_fd)
        require_deadline(deadline)
        final_edge = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        if stable_metadata(final_edge) != stable_metadata(final_root):
            raise PublicationError("release set root edge changed during proof")
        for entry, descriptor in descriptors.items():
            current = os.fstat(descriptor)
            edge = os.stat(entry, dir_fd=root_fd, follow_symlinks=False)
            if stable_metadata(current) != before[entry] or stable_metadata(edge) != before[entry]:
                raise PublicationError(f"release entry changed during final sync: {entry}")
        parent.assert_bound()
        return {
            "identity": identity(root),
            "manifest_hash": observed_manifest_hash,
            "commit": fields["commit"],
            "version": fields["version"],
            "epoch": fields["epoch"],
        }
    finally:
        close_descriptors(
            tuple(descriptors.values()) + (root_fd,),
            "release set descriptor close",
            sys.exception(),
        )


def verify_release_set(
    parent, name, commit=None, version=None, epoch=None, manifest_hash=None, deadline=None
):
    return prove_release_set(
        parent,
        name,
        0o555,
        False,
        commit,
        version,
        epoch,
        manifest_hash,
        deadline,
    )


def finalize_staged_release_set(
    parent, name, commit, version, epoch, manifest_hash, deadline
):
    return prove_release_set(
        parent,
        name,
        0o700,
        True,
        commit,
        version,
        epoch,
        manifest_hash,
        deadline,
    )


def source_release(parent, source, commit, version, epoch, deadline):
    if (
        not os.path.isabs(source)
        or os.path.normpath(source) != source
        or os.path.realpath(source) != source
    ):
        raise PublicationError("release source is not canonical")
    source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    descriptors = {}
    try:
        require_deadline(deadline)
        source_root = os.fstat(source_fd)
        source_edge = os.stat(source, follow_symlinks=False)
        if (
            stable_metadata(source_edge) != stable_metadata(source_root)
            or source_root.st_uid != parent.uid
            or source_root.st_gid != parent.gid
        ):
            raise PublicationError("release source ownership is invalid")
        names = bounded_names(source_fd)
        if tuple(names) != tuple(sorted(ENTRY_NAMES, key=os.fsencode)):
            raise PublicationError("release source is not the exact canonical inventory")
        for name in names:
            require_deadline(deadline)
            descriptor = open_regular_at(source_fd, name, f"release source entry {name}")
            descriptors[name] = descriptor
            metadata = os.fstat(descriptor)
            edge = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
            if (
                stable_metadata(edge) != stable_metadata(metadata)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != parent.uid
                or metadata.st_gid != parent.gid
                or metadata.st_nlink != 1
                or metadata.st_size <= 0
            ):
                raise PublicationError(f"release source entry authority is invalid: {name}")
        manifest_metadata = os.fstat(descriptors[MANIFEST])
        manifest = read_exact(
            descriptors[MANIFEST],
            manifest_metadata.st_size,
            MANIFEST_LIMIT,
            "release source manifest",
            deadline,
        )
        _, hashes = parse_manifest(manifest, commit, version, epoch)
        remaining = CONTENT_LIMIT
        for asset in ASSETS:
            metadata = os.fstat(descriptors[asset])
            observed, remaining = hash_exact(
                descriptors[asset], metadata.st_size, remaining, asset, deadline
            )
            if observed != hashes[asset]:
                raise PublicationError(
                    f"release source artifact differs from its manifest: {asset}"
                )
        for descriptor in descriptors.values():
            require_deadline(deadline)
            os.lseek(descriptor, 0, os.SEEK_SET)
        return source_fd, descriptors, hashlib.sha256(manifest).hexdigest()
    except BaseException as error:
        close_descriptors(
            tuple(descriptors.values()) + (source_fd,),
            "release source descriptor close",
            error,
        )
        raise


def canonical_record(record):
    try:
        encoded = json.dumps(
            record,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise PublicationError("publication record cannot be canonically encoded") from error
    return encoded + b"\n"


def validate_record(record, parent, token):
    expected_keys = {
        "format",
        "state",
        "token",
        "destination",
        "filesystem",
        "parent_handle",
        "payload",
        "payload_handle",
        "prior_handle",
        "commit",
        "version",
        "epoch",
        "manifest_sha256",
    }
    if not isinstance(record, dict) or set(record) != expected_keys:
        raise PublicationError("publication record shape is invalid")
    if (
        not all(
            isinstance(record[field], str)
            for field in (
                "format",
                "state",
                "token",
                "destination",
                "filesystem",
                "parent_handle",
                "payload",
                "commit",
                "version",
                "epoch",
            )
        )
        or record["format"] != "rustdesk-release-transaction-v3"
        or record["state"] not in RECORD_STATES
        or record["token"] != token
        or record["destination"] != parent.destination
        or record["filesystem"] != parent.filesystem
        or parse_handle(record["parent_handle"]) != parent.handle
        or record["payload"] != f".{parent.destination}-release-payload.{token}"
        or re.fullmatch(r"[0-9a-f]{64}", record["token"]) is None
        or re.fullmatch(r"[0-9a-f]{40}", record["commit"]) is None
        or re.fullmatch(r"[A-Za-z0-9._+-]+", record["version"]) is None
        or re.fullmatch(r"[1-9][0-9]*", record["epoch"]) is None
    ):
        raise PublicationError("publication record authority is invalid")
    for field in ("payload_handle", "prior_handle"):
        if record[field] is not None and not isinstance(record[field], str):
            raise PublicationError("publication record identity type is invalid")
        if record[field] is not None:
            parse_handle(record[field])
    if record["manifest_sha256"] is not None and not isinstance(
        record["manifest_sha256"], str
    ):
        raise PublicationError("publication record manifest digest type is invalid")
    if record["state"] == "initializing":
        if record["payload_handle"] is not None or record["manifest_sha256"] is not None:
            raise PublicationError("initial publication record contains bound payload state")
    elif record["state"] == "staging":
        if record["payload_handle"] is None or record["manifest_sha256"] is not None:
            raise PublicationError("staging publication record has invalid payload state")
    elif (
        record["payload_handle"] is None
        or re.fullmatch(r"[0-9a-f]{64}", record["manifest_sha256"] or "") is None
    ):
        raise PublicationError("prepared publication record is incomplete")
    if (
        record["payload_handle"] is not None
        and record["prior_handle"] is not None
        and record["payload_handle"] == record["prior_handle"]
    ):
        raise PublicationError("publication record reuses the prior release identity")
    return record


def create_record_file(parent, name, record):
    content = canonical_record(record)
    if len(content) > RECORD_LIMIT:
        raise PublicationError("publication record exceeds its byte bound")
    parent.assert_bound()
    descriptor = os.open(
        ".",
        os.O_RDWR | os.O_TMPFILE | os.O_CLOEXEC,
        0o600,
        dir_fd=parent.fd,
    )
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise PublicationError("publication record write made no progress")
            offset += written
        os.fchmod(descriptor, 0o400)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != parent.uid
            or metadata.st_gid != parent.gid
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_nlink != 0
            or metadata.st_dev != parent.metadata.st_dev
            or descriptor_mount_id(descriptor) != parent.mount_id
        ):
            raise PublicationError("publication record creation authority is invalid")
        require_canonical_security(descriptor, "publication record")
        os.fsync(descriptor)
        link_unnamed_file(descriptor, parent.fd, name)
        linked = os.fstat(descriptor)
        edge = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        if linked.st_nlink != 1 or stable_metadata(edge) != stable_metadata(linked):
            raise PublicationError("publication record link binding is invalid")
        os.fsync(parent.fd)
    finally:
        close_descriptors(
            (descriptor,), "publication record creation descriptor close", sys.exception()
        )


def read_record(parent, name, token):
    descriptor = open_regular_at(parent.fd, name, "publication record")
    try:
        before = os.fstat(descriptor)
        edge = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        if (
            stable_metadata(edge) != stable_metadata(before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != parent.uid
            or before.st_gid != parent.gid
            or stat.S_IMODE(before.st_mode) != 0o400
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_dev != parent.metadata.st_dev
            or descriptor_mount_id(descriptor) != parent.mount_id
        ):
            raise PublicationError("publication record file authority is invalid")
        require_canonical_security(descriptor, "publication record")
        content = read_exact(
            descriptor,
            before.st_size,
            RECORD_LIMIT,
            "publication record",
            time.monotonic() + 5,
        )
        try:
            record = json.loads(content.decode("ascii"), parse_constant=reject_json_constant)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PublicationError("publication record encoding is invalid") from error
        if canonical_record(record) != content:
            raise PublicationError("publication record encoding is not canonical")
        after = os.fstat(descriptor)
        final_edge = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        if (
            stable_metadata(after) != stable_metadata(before)
            or stable_metadata(final_edge) != stable_metadata(before)
        ):
            raise PublicationError("publication record changed during inspection")
        return validate_record(record, parent, token), identity(before)
    finally:
        close_descriptors((descriptor,), "publication record descriptor close", sys.exception())


def reject_json_constant(value):
    raise PublicationError(f"publication record contains {value}")


def require_record_transition(current, following):
    current_base = dict(current)
    following_base = dict(following)
    current_base.pop("state")
    following_base.pop("state")
    if current["state"] == "initializing" and following["state"] == "staging":
        current_base["payload_handle"] = following_base["payload_handle"]
    if current["state"] == "staging" and following["state"] == "prepared":
        current_base["manifest_sha256"] = following_base["manifest_sha256"]
    if (
        (current["state"], following["state"]) not in RECORD_TRANSITIONS
        or current_base != following_base
    ):
        raise PublicationError("publication record is not the exact next state")


def path_metadata(parent_fd, name):
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def replace_record(parent, name, current_identity, next_name, next_identity):
    current_fd = open_regular_at(parent.fd, name, "publication current record")
    next_fd = None
    try:
        next_fd = open_regular_at(parent.fd, next_name, "publication next record")
        current = os.fstat(current_fd)
        following = os.fstat(next_fd)
        current_edge = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        next_edge = os.stat(next_name, dir_fd=parent.fd, follow_symlinks=False)
        if (
            identity(current) != current_identity
            or identity(following) != next_identity
            or stable_metadata(current_edge) != stable_metadata(current)
            or stable_metadata(next_edge) != stable_metadata(following)
            or current.st_nlink != 1
            or following.st_nlink != 1
        ):
            raise PublicationError("publication record binding changed before transition")
        require_canonical_security(current_fd, "publication current record")
        require_canonical_security(next_fd, "publication next record")
        parent.assert_bound()
        os.replace(next_name, name, src_dir_fd=parent.fd, dst_dir_fd=parent.fd)
        installed = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        displaced = os.fstat(current_fd)
        if (
            stable_metadata(installed) != stable_metadata(os.fstat(next_fd))
            or identity(installed) != next_identity
            or identity(displaced) != current_identity
            or displaced.st_nlink != 0
            or path_metadata(parent.fd, next_name) is not None
        ):
            raise PublicationError("publication record transition binding is invalid")
        os.fsync(parent.fd)
        installed = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        if (
            stable_metadata(installed) != stable_metadata(os.fstat(next_fd))
            or path_metadata(parent.fd, next_name) is not None
            or os.fstat(current_fd).st_nlink != 0
        ):
            raise PublicationError("publication record transition changed after commit")
    finally:
        close_descriptors(
            (next_fd, current_fd),
            "publication record transition descriptor close",
            sys.exception(),
        )


def install_initial_record(parent, token, record):
    name = f".{parent.destination}-release-transaction.{token}"
    validate_record(record, parent, token)
    if record["state"] != "initializing":
        raise PublicationError("initial publication record has the wrong state")
    create_record_file(parent, name, record)
    read_record(parent, name, token)
    return name


def update_record(parent, name, token, current_identity, record):
    next_name = f".{parent.destination}-release-next.{token}"
    current, observed_identity = read_record(parent, name, token)
    if observed_identity != current_identity:
        raise PublicationError("publication record identity changed before state transition")
    validate_record(record, parent, token)
    require_record_transition(current, record)
    if path_metadata(parent.fd, next_name) is not None:
        raise PublicationError("publication next-record path already exists")
    create_record_file(parent, next_name, record)
    following, next_identity = read_record(parent, next_name, token)
    if following != record:
        raise PublicationError("publication next record changed after creation")
    replace_record(parent, name, current_identity, next_name, next_identity)
    installed, installed_identity = read_record(parent, name, token)
    if installed != record or installed_identity != next_identity:
        raise PublicationError("publication record transition did not install the next state")
    return installed_identity


def unlink_record(parent, name, expected_identity):
    descriptor = open_regular_at(parent.fd, name, "publication record")
    try:
        metadata = os.fstat(descriptor)
        edge = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        if (
            identity(metadata) != expected_identity
            or stable_metadata(edge) != stable_metadata(metadata)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != parent.uid
            or metadata.st_gid != parent.gid
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_nlink != 1
            or metadata.st_dev != parent.metadata.st_dev
            or descriptor_mount_id(descriptor) != parent.mount_id
        ):
            raise PublicationError("publication record identity changed before removal")
        require_canonical_security(descriptor, "publication record")
        parent.assert_bound()
        os.unlink(name, dir_fd=parent.fd)
        removed = os.fstat(descriptor)
        if (
            identity(removed) != expected_identity
            or removed.st_nlink != 0
            or path_metadata(parent.fd, name) is not None
        ):
            raise PublicationError("publication record removal did not consume its edge")
        os.fsync(parent.fd)
        if path_metadata(parent.fd, name) is not None or os.fstat(descriptor).st_nlink != 0:
            raise PublicationError("publication record removal changed after commit")
    finally:
        close_descriptors(
            (descriptor,), "publication record removal descriptor close", sys.exception()
        )


def cleanup_payload(
    parent,
    name,
    expected_identity,
    allow_partial,
    root_modes=(0o555, 0o700),
    entry_modes=(0o444,),
):
    try:
        root_fd = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent.fd,
        )
    except FileNotFoundError:
        return False
    retained = []
    try:
        root = os.fstat(root_fd)
        edge = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        if (
            identity(root) != expected_identity
            or stable_metadata(edge) != stable_metadata(root)
            or root.st_uid != parent.uid
            or root.st_gid != parent.gid
            or stat.S_IMODE(root.st_mode) not in root_modes
            or root.st_dev != parent.metadata.st_dev
            or descriptor_mount_id(root_fd) != parent.mount_id
        ):
            raise PublicationError("publication payload root authority changed before cleanup")
        require_canonical_security(root_fd, "publication payload root")
        names = bounded_names(root_fd)
        if any(entry not in ENTRY_NAMES for entry in names) or (
            not allow_partial and set(names) != set(ENTRY_NAMES)
        ):
            raise PublicationError("publication payload inventory is invalid for cleanup")
        for entry in names:
            descriptor = open_regular_at(
                root_fd, entry, f"publication payload entry {entry}"
            )
            retained.append((entry, descriptor))
            metadata = os.fstat(descriptor)
            current = os.stat(entry, dir_fd=root_fd, follow_symlinks=False)
            if (
                stable_metadata(current) != stable_metadata(metadata)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != parent.uid
                or metadata.st_gid != parent.gid
                or stat.S_IMODE(metadata.st_mode) not in entry_modes
                or metadata.st_nlink != 1
                or metadata.st_dev != parent.metadata.st_dev
                or descriptor_mount_id(descriptor) != parent.mount_id
            ):
                raise PublicationError(f"publication payload entry is unsafe to remove: {entry}")
            require_canonical_security(descriptor, f"publication payload entry {entry}")
        parent.assert_bound()
        os.fchmod(root_fd, 0o700)
        changed_root = os.fstat(root_fd)
        changed_edge = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        if (
            identity(changed_root) != expected_identity
            or stable_metadata(changed_edge) != stable_metadata(changed_root)
            or stat.S_IMODE(changed_root.st_mode) != 0o700
        ):
            raise PublicationError("publication payload root changed during cleanup authorization")
        require_canonical_security(root_fd, "publication payload root")
        for entry, descriptor in retained:
            current = os.stat(entry, dir_fd=root_fd, follow_symlinks=False)
            before = os.fstat(descriptor)
            if stable_metadata(current) != stable_metadata(before):
                raise PublicationError("publication payload entry changed before removal")
            os.unlink(entry, dir_fd=root_fd)
            removed = os.fstat(descriptor)
            if (
                identity(removed) != identity(before)
                or removed.st_nlink != 0
                or path_metadata(root_fd, entry) is not None
            ):
                raise PublicationError("publication payload unlink did not consume its edge")
        if bounded_names(root_fd):
            raise PublicationError("publication payload was repopulated during cleanup")
        os.fsync(root_fd)
        root_before_removal = os.fstat(root_fd)
        current_root = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        if stable_metadata(current_root) != stable_metadata(root_before_removal):
            raise PublicationError("publication payload root changed before removal")
        os.rmdir(name, dir_fd=parent.fd)
        removed_root = os.fstat(root_fd)
        if (
            identity(removed_root) != expected_identity
            or removed_root.st_nlink != 0
            or path_metadata(parent.fd, name) is not None
        ):
            raise PublicationError("publication payload root removal did not consume its edge")
        os.fsync(parent.fd)
        if path_metadata(parent.fd, name) is not None or os.fstat(root_fd).st_nlink != 0:
            raise PublicationError("publication payload removal changed after commit")
        parent.assert_bound()
        return True
    finally:
        close_descriptors(
            tuple(descriptor for _, descriptor in retained) + (root_fd,),
            "publication payload descriptor close",
            sys.exception(),
        )


def create_payload_root(parent, payload_name):
    deadline = time.monotonic() + DEADLINE_SECONDS
    parent.assert_bound()
    os.mkdir(payload_name, 0o700, dir_fd=parent.fd)
    os.fsync(parent.fd)
    require_deadline(deadline)
    payload_fd = os.open(
        payload_name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=parent.fd,
    )
    try:
        payload = os.fstat(payload_fd)
        payload_edge = os.stat(payload_name, dir_fd=parent.fd, follow_symlinks=False)
        if (
            stable_metadata(payload_edge) != stable_metadata(payload)
            or payload.st_uid != parent.uid
            or payload.st_gid != parent.gid
            or stat.S_IMODE(payload.st_mode) != 0o700
            or payload.st_dev != parent.metadata.st_dev
            or descriptor_mount_id(payload_fd) != parent.mount_id
            or bounded_names(payload_fd)
        ):
            raise PublicationError("publication payload creation authority is invalid")
        require_canonical_security(payload_fd, "publication payload")
        payload_id = identity(payload)
        payload_handle = persistent_handle(payload_fd)
    finally:
        close_descriptors(
            (payload_fd,), "publication payload root descriptor close", sys.exception()
        )
    parent.assert_bound()
    return payload_id, payload_handle


def stage_payload(
    parent, source, payload_name, record, expected_payload_id, expected_payload_handle
):
    if (
        record["state"] != "staging"
        or parse_handle(record["payload_handle"]) != expected_payload_handle
    ):
        raise PublicationError("publication payload staging record is invalid")
    deadline = time.monotonic() + DEADLINE_SECONDS
    source_fd, descriptors, manifest_hash = source_release(
        parent,
        source,
        record["commit"],
        record["version"],
        record["epoch"],
        deadline,
    )
    try:
        require_deadline(deadline)
        parent.assert_bound()
        payload_fd = os.open(
            payload_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent.fd,
        )
        try:
            payload = os.fstat(payload_fd)
            payload_edge = os.stat(payload_name, dir_fd=parent.fd, follow_symlinks=False)
            if (
                stable_metadata(payload_edge) != stable_metadata(payload)
                or identity(payload) != expected_payload_id
                or persistent_handle(payload_fd) != expected_payload_handle
                or payload.st_uid != parent.uid
                or payload.st_gid != parent.gid
                or stat.S_IMODE(payload.st_mode) != 0o700
                or payload.st_dev != parent.metadata.st_dev
                or descriptor_mount_id(payload_fd) != parent.mount_id
            ):
                raise PublicationError("publication payload staging authority is invalid")
            require_canonical_security(payload_fd, "publication payload")
            if bounded_names(payload_fd):
                raise PublicationError("publication payload is not empty before staging")
            for name in ENTRY_NAMES:
                require_deadline(deadline)
                source_descriptor = descriptors[name]
                source_before = os.fstat(source_descriptor)
                destination = os.open(
                    ".",
                    os.O_WRONLY | os.O_TMPFILE | os.O_CLOEXEC,
                    0o600,
                    dir_fd=payload_fd,
                )
                try:
                    os.lseek(source_descriptor, 0, os.SEEK_SET)
                    remaining = source_before.st_size
                    while remaining:
                        require_deadline(deadline)
                        chunk = os.read(source_descriptor, min(1024 * 1024, remaining))
                        if not chunk:
                            raise PublicationError(f"release source ended during copy: {name}")
                        offset = 0
                        while offset < len(chunk):
                            require_deadline(deadline)
                            written = os.write(destination, chunk[offset:])
                            if written <= 0:
                                raise PublicationError(
                                    f"publication payload write made no progress: {name}"
                                )
                            offset += written
                        remaining -= len(chunk)
                    require_deadline(deadline)
                    if os.read(source_descriptor, 1):
                        raise PublicationError(f"release source grew during copy: {name}")
                    if stable_metadata(os.fstat(source_descriptor)) != stable_metadata(
                        source_before
                    ):
                        raise PublicationError(f"release source changed during copy: {name}")
                    os.fchmod(destination, 0o444)
                    require_canonical_security(destination, f"publication payload entry {name}")
                    final = os.fstat(destination)
                    if (
                        not stat.S_ISREG(final.st_mode)
                        or final.st_uid != parent.uid
                        or final.st_gid != parent.gid
                        or stat.S_IMODE(final.st_mode) != 0o444
                        or final.st_nlink != 0
                        or final.st_size != source_before.st_size
                        or final.st_dev != parent.metadata.st_dev
                        or descriptor_mount_id(destination) != parent.mount_id
                    ):
                        raise PublicationError(
                            f"publication payload entry authority is invalid: {name}"
                        )
                    os.fsync(destination)
                    require_deadline(deadline)
                    link_unnamed_file(destination, payload_fd, name)
                    linked = os.fstat(destination)
                    linked_edge = os.stat(name, dir_fd=payload_fd, follow_symlinks=False)
                    if linked.st_nlink != 1 or stable_metadata(linked_edge) != stable_metadata(
                        linked
                    ):
                        raise PublicationError(
                            f"publication payload entry link binding is invalid: {name}"
                        )
                    os.fsync(destination)
                    require_deadline(deadline)
                finally:
                    close_descriptors(
                        (destination,),
                        f"publication payload entry descriptor close: {name}",
                        sys.exception(),
                    )
            if tuple(bounded_names(payload_fd)) != tuple(sorted(ENTRY_NAMES, key=os.fsencode)):
                raise PublicationError("publication payload inventory changed during staging")
            os.fsync(payload_fd)
            require_deadline(deadline)
        finally:
            close_descriptors(
                (payload_fd,), "publication payload root descriptor close", sys.exception()
            )
        os.fsync(parent.fd)
        require_deadline(deadline)
        proof = finalize_staged_release_set(
            parent,
            payload_name,
            record["commit"],
            record["version"],
            record["epoch"],
            manifest_hash,
            deadline,
        )
        if proof["identity"] != expected_payload_id:
            raise PublicationError("publication payload identity changed after staging")
        return manifest_hash
    finally:
        close_descriptors(
            tuple(descriptors.values()) + (source_fd,),
            "release source descriptor close",
            sys.exception(),
        )


def record_names(parent):
    escaped = re.escape(parent.destination)
    patterns = {
        "record": re.compile(rf"\.{escaped}-release-transaction\.([0-9a-f]{{64}})"),
        "next": re.compile(rf"\.{escaped}-release-next\.([0-9a-f]{{64}})"),
        "payload": re.compile(rf"\.{escaped}-release-payload\.([0-9a-f]{{64}})"),
    }
    found = {kind: [] for kind in patterns}
    reserved_prefix = f".{parent.destination}-release-"
    for name in bounded_names(parent.fd):
        for kind, pattern in patterns.items():
            match = pattern.fullmatch(name)
            if match is not None:
                found[kind].append((name, match.group(1)))
                break
        else:
            if name.startswith(reserved_prefix):
                raise PublicationError(
                    "publication namespace contains a noncanonical reserved name"
                )
    return found


def reconcile_next_record(parent, record_name, token, record, record_identity, next_name):
    next_record, next_identity = read_record(parent, next_name, token)
    require_record_transition(record, next_record)
    replace_record(parent, record_name, record_identity, next_name, next_identity)
    installed, installed_identity = read_record(parent, record_name, token)
    if installed != next_record or installed_identity != next_identity:
        raise PublicationError("publication next-state recovery installed the wrong record")
    return installed, installed_identity


def finish_cleanup(parent, record_name, record, record_identity):
    destination = parent.path_authority(parent.destination)
    payload = parent.path_authority(record["payload"])
    expected_new = parse_handle(record["payload_handle"])
    old_handle = None if record["prior_handle"] is None else parse_handle(record["prior_handle"])
    if destination is None or destination["handle"] != expected_new:
        raise PublicationError("published destination identity differs during cleanup")
    verify_release_set(
        parent,
        parent.destination,
        record["commit"],
        record["version"],
        record["epoch"],
        record["manifest_sha256"],
    )
    if old_handle is None:
        if payload is not None:
            raise PublicationError("first publication retained an unexpected payload")
    elif payload is not None:
        if payload["handle"] != old_handle:
            raise PublicationError("displaced prior release identity changed during cleanup")
        if not cleanup_payload(parent, record["payload"], payload["identity"], True):
            raise PublicationError("displaced prior release disappeared during cleanup")
    parent.assert_bound()
    verify_release_set(
        parent,
        parent.destination,
        record["commit"],
        record["version"],
        record["epoch"],
        record["manifest_sha256"],
    )
    unlink_record(parent, record_name, record_identity)


def verify_prior_release(parent, expected_handle):
    authority = parent.path_authority(parent.destination)
    if (authority is None) != (expected_handle is None) or (
        authority is not None and authority["handle"] != expected_handle
    ):
        raise PublicationError("prior release identity changed during rollback")
    if authority is not None:
        proof = verify_release_set(parent, parent.destination)
        if proof["identity"] != authority["identity"]:
            raise PublicationError("prior release proof changed during rollback")
    return authority


def finish_rollback(parent, record_name, record, record_identity):
    old_handle = None if record["prior_handle"] is None else parse_handle(record["prior_handle"])
    new_handle = parse_handle(record["payload_handle"])
    verify_prior_release(parent, old_handle)
    payload = parent.path_authority(record["payload"])
    if payload is not None:
        if payload["handle"] != new_handle:
            raise PublicationError("uncommitted payload identity changed during rollback")
        if not cleanup_payload(
            parent, record["payload"], payload["identity"], True, (0o555, 0o700)
        ):
            raise PublicationError("uncommitted payload disappeared during rollback")
    verify_prior_release(parent, old_handle)
    unlink_record(parent, record_name, record_identity)


def recover(parent):
    parent.assert_bound()
    found = record_names(parent)
    if len(found["record"]) > 1 or len(found["next"]) > 1 or len(found["payload"]) > 1:
        raise PublicationError("publication recovery has multiple active transactions")
    if not found["record"]:
        if found["next"] or found["payload"]:
            raise PublicationError(
                "publication recovery found state without a durable transaction record"
            )
        os.fsync(parent.fd)
        parent.assert_bound()
        confirmed = record_names(parent)
        if any(confirmed.values()):
            raise PublicationError("publication namespace changed during the quiescent barrier")
        return
    record_name, token = found["record"][0]
    record, record_identity = read_record(parent, record_name, token)
    if found["next"]:
        next_name, next_token = found["next"][0]
        if next_token != token:
            raise PublicationError("publication next record belongs to another transaction")
        record, record_identity = reconcile_next_record(
            parent, record_name, token, record, record_identity, next_name
        )
    if found["payload"] and found["payload"][0] != (record["payload"], token):
        raise PublicationError("publication payload belongs to another transaction")
    destination = parent.path_authority(parent.destination)
    payload = parent.path_authority(record["payload"])
    old_handle = None if record["prior_handle"] is None else parse_handle(record["prior_handle"])
    if record["state"] == "initializing":
        verify_prior_release(parent, old_handle)
        if payload is not None:
            raise PublicationError(
                "initial publication record has an unbound payload identity"
            )
        verify_prior_release(parent, old_handle)
        unlink_record(parent, record_name, record_identity)
        return
    if record["state"] == "staging":
        finish_rollback(parent, record_name, record, record_identity)
        return
    new_handle = parse_handle(record["payload_handle"])
    if record["state"] == "prepared":
        destination_handle = None if destination is None else destination["handle"]
        payload_handle = None if payload is None else payload["handle"]
        before_exchange = destination_handle == old_handle and payload_handle == new_handle
        after_exchange = destination_handle == new_handle and (
            (old_handle is None and payload_handle is None)
            or (old_handle is not None and payload_handle == old_handle)
        )
        if before_exchange:
            verify_prior_release(parent, old_handle)
            payload_proof = verify_release_set(
                parent,
                record["payload"],
                record["commit"],
                record["version"],
                record["epoch"],
                record["manifest_sha256"],
            )
            if payload is None or payload_proof["identity"] != payload["identity"]:
                raise PublicationError("prepared publication payload identity changed")
            rollback_record = dict(record)
            rollback_record["state"] = "rollback"
            record_identity = update_record(
                parent, record_name, token, record_identity, rollback_record
            )
            record = rollback_record
        elif not after_exchange:
            if old_handle is not None and destination_handle == new_handle and payload_handle is None:
                raise PublicationError(
                    "displaced prior release is absent before cleanup authorization"
                )
            raise PublicationError("publication exchange outcome is ambiguous")
        else:
            verify_release_set(
                parent,
                parent.destination,
                record["commit"],
                record["version"],
                record["epoch"],
                record["manifest_sha256"],
            )
            cleanup_record = dict(record)
            cleanup_record["state"] = "cleanup"
            record_identity = update_record(
                parent, record_name, token, record_identity, cleanup_record
            )
            record = cleanup_record
    if record["state"] == "rollback":
        finish_rollback(parent, record_name, record, record_identity)
    elif record["state"] == "cleanup":
        finish_cleanup(parent, record_name, record, record_identity)
    else:
        raise PublicationError("publication recovery reached an invalid terminal state")


def initial_record(parent, token, commit, version, epoch, old_handle):
    return {
        "format": "rustdesk-release-transaction-v3",
        "state": "initializing",
        "token": token,
        "destination": parent.destination,
        "filesystem": parent.filesystem,
        "parent_handle": parent.handle,
        "payload": f".{parent.destination}-release-payload.{token}",
        "payload_handle": None,
        "prior_handle": old_handle,
        "commit": commit,
        "version": version,
        "epoch": epoch,
        "manifest_sha256": None,
    }


def publish(parent, source, commit, version, epoch, stop_after=None):
    if (
        re.fullmatch(r"[0-9a-f]{40}", commit) is None
        or re.fullmatch(r"[A-Za-z0-9._+-]+", version) is None
        or re.fullmatch(r"[1-9][0-9]*", epoch) is None
    ):
        raise PublicationError("publication metadata arguments are invalid")
    recover(parent)
    old = parent.path_authority(parent.destination)
    old_id = None if old is None else old["identity"]
    old_handle = None if old is None else old["handle"]
    if old is not None:
        old_proof = verify_release_set(parent, parent.destination)
        if old_proof["identity"] != old_id:
            raise PublicationError("prior release identity changed during initial proof")
    token = os.urandom(32).hex()
    record = initial_record(parent, token, commit, version, epoch, old_handle)
    record_name = install_initial_record(parent, token, record)
    record_identity = read_record(parent, record_name, token)[1]
    payload_id, payload_handle = create_payload_root(parent, record["payload"])
    if stop_after == "payload-created":
        raise InjectedStop("publication stopped before payload identity commit")
    staging = dict(record)
    staging["state"] = "staging"
    staging["payload_handle"] = payload_handle
    record_identity = update_record(parent, record_name, token, record_identity, staging)
    if stop_after == "staging":
        raise InjectedStop("publication stopped after staging record")
    manifest_hash = stage_payload(
        parent,
        source,
        record["payload"],
        staging,
        payload_id,
        payload_handle,
    )
    prepared = dict(staging)
    prepared["state"] = "prepared"
    prepared["manifest_sha256"] = manifest_hash
    record_identity = update_record(parent, record_name, token, record_identity, prepared)
    if stop_after == "prepared":
        raise InjectedStop("publication stopped after prepared record")
    if stop_after == "rollback-record":
        rollback_record = dict(prepared)
        rollback_record["state"] = "rollback"
        update_record(parent, record_name, token, record_identity, rollback_record)
        raise InjectedStop("publication stopped after rollback record")
    parent.assert_bound()
    installed_record, installed_identity = read_record(parent, record_name, token)
    if installed_record != prepared or installed_identity != record_identity:
        raise PublicationError("prepared publication record changed before exchange")
    found = record_names(parent)
    if (
        found["record"] != [(record_name, token)]
        or found["next"]
        or found["payload"] != [(record["payload"], token)]
    ):
        raise PublicationError("publication namespace changed before exchange")
    payload_proof = verify_release_set(
        parent, record["payload"], commit, version, epoch, manifest_hash
    )
    if payload_proof["identity"] != payload_id:
        raise PublicationError("publication payload changed before exchange")
    if old is not None:
        prior_proof = verify_release_set(parent, parent.destination)
        if prior_proof["identity"] != old_id:
            raise PublicationError("prior release changed before exchange")
    installed_record, installed_identity = read_record(parent, record_name, token)
    if installed_record != prepared or installed_identity != record_identity:
        raise PublicationError("prepared publication record changed during exchange proof")
    current_destination = parent.path_authority(parent.destination)
    current_payload = parent.path_authority(record["payload"])
    if (
        (current_destination is None) != (old is None)
        or (
            current_destination is not None
            and (
                current_destination["identity"] != old_id
                or current_destination["handle"] != old_handle
            )
        )
        or current_payload is None
        or current_payload["identity"] != payload_id
        or current_payload["handle"] != payload_handle
    ):
        raise PublicationError("publication namespace changed before exchange")
    if old is None:
        renameat2(parent.fd, record["payload"], parent.destination, RENAME_NOREPLACE)
    else:
        renameat2(parent.fd, record["payload"], parent.destination, RENAME_EXCHANGE)
    post_destination = parent.path_authority(parent.destination)
    post_payload = parent.path_authority(record["payload"])
    if (
        post_destination is None
        or post_destination["identity"] != payload_id
        or post_destination["handle"] != payload_handle
    ):
        raise PublicationError("published destination identity differs after exchange")
    if (old is None and post_payload is not None) or (
        old is not None
        and (
            post_payload is None
            or post_payload["identity"] != old_id
            or post_payload["handle"] != old_handle
        )
    ):
        raise PublicationError("displaced publication identity differs after exchange")
    parent.assert_bound()
    os.fsync(parent.fd)
    if (
        parent.path_authority(parent.destination) != post_destination
        or parent.path_authority(record["payload"]) != post_payload
    ):
        raise PublicationError("publication exchange binding changed after commit")
    parent.assert_bound()
    if stop_after == "exchange":
        raise InjectedStop("publication stopped after exchange")
    verify_release_set(parent, parent.destination, commit, version, epoch, manifest_hash)
    cleanup_record = dict(prepared)
    cleanup_record["state"] = "cleanup"
    record_identity = update_record(
        parent, record_name, token, record_identity, cleanup_record
    )
    if stop_after == "cleanup-record":
        raise InjectedStop("publication stopped after cleanup record")
    if old is not None:
        if not cleanup_payload(parent, record["payload"], post_payload["identity"], True):
            raise PublicationError("displaced prior release disappeared during cleanup")
    if stop_after == "payload-removal":
        raise InjectedStop("publication stopped after payload removal")
    verify_release_set(parent, parent.destination, commit, version, epoch, manifest_hash)
    unlink_record(parent, record_name, record_identity)
    parent.assert_bound()


def run_with_parent(parent_path, destination, operation):
    parent = ParentAuthority(parent_path, destination)
    primary = None
    try:
        return operation(parent)
    except BaseException as error:
        primary = error
        raise
    finally:
        failures = []
        try:
            parent.close()
        except BaseException as error:
            failures.append(error)
        report_cleanup_failures(primary, "publication parent descriptor close", failures)


def verify_quiescent_release(parent, commit=None, version=None, epoch=None):
    parent.assert_bound()
    if any(record_names(parent).values()):
        raise PublicationError("release verification found unresolved publication state")
    proof = verify_release_set(parent, parent.destination, commit, version, epoch)
    parent.assert_bound()
    if any(record_names(parent).values()):
        raise PublicationError("publication state appeared during release verification")
    return proof


def verify_path(path, commit=None, version=None, epoch=None):
    parent_path, destination = os.path.split(path)
    if not parent_path or not destination:
        raise PublicationError("release verification path is invalid")
    return run_with_parent(
        parent_path,
        destination,
        lambda parent: verify_quiescent_release(parent, commit, version, epoch),
    )


def parse_arguments():
    parser = argparse.ArgumentParser(description="Finalize a durable RustDesk release set.")
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--publish", action="store_true")
    modes.add_argument("--recover", action="store_true")
    modes.add_argument("--verify", action="store_true")
    parser.add_argument("--parent")
    parser.add_argument("--destination")
    parser.add_argument("--path")
    parser.add_argument("--source")
    parser.add_argument("--commit")
    parser.add_argument("--version")
    parser.add_argument("--epoch")
    parser.add_argument(
        "--stop-after",
        choices=(
            "payload-created",
            "staging",
            "prepared",
            "rollback-record",
            "exchange",
            "cleanup-record",
            "payload-removal",
        ),
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def main():
    arguments = parse_arguments()
    try:
        if arguments.verify:
            if (
                arguments.path is None
                or arguments.parent is not None
                or arguments.destination is not None
                or arguments.source is not None
                or arguments.stop_after is not None
            ):
                raise PublicationError(
                    "verify mode requires only --path and optional release metadata"
                )
            verify_path(arguments.path, arguments.commit, arguments.version, arguments.epoch)
        else:
            if (
                arguments.parent is None
                or arguments.destination is None
                or arguments.path is not None
            ):
                raise PublicationError("publication mode requires --parent and --destination")
            if arguments.recover:
                if any(
                    value is not None
                    for value in (
                        arguments.source,
                        arguments.commit,
                        arguments.version,
                        arguments.epoch,
                        arguments.stop_after,
                    )
                ):
                    raise PublicationError("recover mode received publication inputs")
                run_with_parent(arguments.parent, arguments.destination, recover)
            else:
                if None in (
                    arguments.source,
                    arguments.commit,
                    arguments.version,
                    arguments.epoch,
                ):
                    raise PublicationError("publish mode has incomplete release metadata")
                run_with_parent(
                    arguments.parent,
                    arguments.destination,
                    lambda parent: publish(
                        parent,
                        arguments.source,
                        arguments.commit,
                        arguments.version,
                        arguments.epoch,
                        arguments.stop_after,
                    ),
                )
    except InjectedStop as error:
        print(f"finalize-release-set: STOP: {error}", file=sys.stderr)
        for note in getattr(error, "__notes__", ()):
            print(f"finalize-release-set: NOTE: {note}", file=sys.stderr)
        return 75
    except (OSError, PublicationError) as error:
        print(f"finalize-release-set: FAIL: {error}", file=sys.stderr)
        for note in getattr(error, "__notes__", ()):
            print(f"finalize-release-set: NOTE: {note}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
