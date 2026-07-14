#!/usr/bin/env python3
import argparse
import ctypes
import errno
import os
import re
import resource
import stat
import sys
import contextlib


class ClosureError(Exception):
    pass


def collect_descriptor_close_failures(descriptors, closer=os.close):
    failures = []
    seen = set()
    for descriptor in descriptors:
        if descriptor is None or descriptor in seen:
            continue
        seen.add(descriptor)
        try:
            closer(descriptor)
        except BaseException as error:
            failures.append(error)
    return failures


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
    error = ClosureError(f"{label} failed {len(failures)} time(s)")
    for note in notes:
        error.add_note(note)
    raise error from failures[0]


def close_descriptors(descriptors, label, primary=None):
    failures = collect_descriptor_close_failures(descriptors)
    report_cleanup_failures(primary, label, failures)


def identity(metadata):
    return metadata.st_dev, metadata.st_ino


def directory_is_empty(descriptor):
    with os.scandir(f"/proc/self/fd/{descriptor}") as entries:
        return next(entries, None) is None


def bounded_directory_names(descriptor, limit):
    names = []
    with os.scandir(f"/proc/self/fd/{descriptor}") as entries:
        for entry in entries:
            if len(names) >= limit:
                raise ClosureError("tree directory inventory exceeds its remaining entry bound")
            names.append(entry.name)
    return sorted(names, key=os.fsencode)


def descriptor_mount_id(descriptor):
    with open(f"/proc/self/fdinfo/{descriptor}", "rb", buffering=0) as information:
        content = information.read(65537)
    if len(content) > 65536:
        raise ClosureError("scratch descriptor mount information exceeds its byte bound")
    prefix = b"mnt_id:\t"
    values = [line[len(prefix):] for line in content.splitlines() if line.startswith(prefix)]
    if len(values) != 1 or re.fullmatch(br"[1-9][0-9]*", values[0]) is None:
        raise ClosureError("scratch descriptor mount identity is unavailable")
    return int(values[0])


def validate_parent_authority(metadata):
    mode = stat.S_IMODE(metadata.st_mode)
    protected = metadata.st_uid in (0, os.geteuid()) and mode & 0o022 == 0
    sticky_root = metadata.st_uid == 0 and mode == 0o1777
    if not stat.S_ISDIR(metadata.st_mode) or not (protected or sticky_root):
        raise ClosureError("private-tree parent permits a foreign namespace writer")


class PrivateTreeRoot:
    def __init__(self, path=None, inherited_fd=None, require_empty=True):
        if inherited_fd is not None:
            descriptor = os.dup(inherited_fd)
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or metadata.st_gid != os.getegid()
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                    or not directory_is_empty(descriptor)
                ):
                    raise ClosureError("inherited self-test scratch descriptor is not exact authority")
                mount_id = descriptor_mount_id(descriptor)
            except BaseException:
                close_descriptors(
                    (descriptor,),
                    "inherited scratch descriptor close",
                    sys.exc_info()[1],
                )
                raise
            self.parent_fd = None
            self.fd = descriptor
            self.basename = None
            self.identity = identity(metadata)
            self.device = metadata.st_dev
            self.mount_id = mount_id
            self.parent_identity = None
            self.parent_mount_id = None
            self.parent_metadata = None
            self.owner = os.geteuid()
            self.group = os.getegid()
            self.require_uniform_owner = True
            self.allow_retained_contents = False
            self.removed = False
            self.cleanup_started = False
            return
        if not os.path.isabs(path) or os.path.normpath(path) != path:
            raise ClosureError("private-tree root is not an absolute normalized path")
        components = path.split("/")[1:]
        if not components or any(not part or part in (".", "..") for part in components):
            raise ClosureError("private-tree root path has an invalid component")
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent = None
        try:
            for index, component in enumerate(components):
                child = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                if index == len(components) - 1:
                    parent = descriptor
                    descriptor = child
                    break
                previous = descriptor
                descriptor = child
                close_descriptors(
                    (previous,),
                    "scratch path traversal descriptor close",
                )
            metadata = os.fstat(descriptor)
            edge = os.stat(components[-1], dir_fd=parent, follow_symlinks=False)
            if identity(edge) != identity(metadata):
                raise ClosureError("private-tree root edge changed during acquisition")
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_gid != os.getegid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise ClosureError("private-tree root is not a current-principal mode-0700 directory")
            if require_empty and not directory_is_empty(descriptor):
                raise ClosureError("private-tree root is not initially empty")
            mount_id = descriptor_mount_id(descriptor)
            parent_metadata = os.fstat(parent)
            validate_parent_authority(parent_metadata)
            parent_mount_id = descriptor_mount_id(parent)
            if mount_id != parent_mount_id or metadata.st_dev != parent_metadata.st_dev:
                raise ClosureError("private-tree root crosses its parent mount")
        except BaseException:
            close_descriptors(
                (parent, descriptor),
                "scratch acquisition descriptor close",
                sys.exc_info()[1],
            )
            raise
        self.parent_fd = parent
        self.fd = descriptor
        self.basename = components[-1]
        self.identity = identity(metadata)
        self.device = metadata.st_dev
        self.mount_id = mount_id
        self.parent_identity = identity(parent_metadata)
        self.parent_mount_id = parent_mount_id
        self.parent_metadata = (
            parent_metadata.st_uid,
            parent_metadata.st_gid,
            stat.S_IMODE(parent_metadata.st_mode),
        )
        self.owner = os.geteuid()
        self.group = os.getegid()
        self.require_uniform_owner = True
        self.allow_retained_contents = False
        self.removed = False
        self.cleanup_started = False

    @classmethod
    def for_tree_contents(cls, path, expected_identity, owner, group):
        require_real_directory(path)
        descriptor = os.open(
            path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        try:
            metadata = os.fstat(descriptor)
            edge = os.stat(path, follow_symlinks=False)
            if (
                identity(metadata) != expected_identity
                or identity(edge) != expected_identity
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != owner
                or metadata.st_gid != group
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise ClosureError("tree-contents root is not the exact private authority")
            mount_id = descriptor_mount_id(descriptor)
        except BaseException:
            close_descriptors(
                (descriptor,),
                "tree-contents root descriptor close",
                sys.exc_info()[1],
            )
            raise
        authority = cls.__new__(cls)
        authority.parent_fd = None
        authority.fd = descriptor
        authority.basename = None
        authority.identity = identity(metadata)
        authority.device = metadata.st_dev
        authority.mount_id = mount_id
        authority.parent_identity = None
        authority.parent_mount_id = None
        authority.parent_metadata = None
        authority.owner = owner
        authority.group = group
        authority.require_uniform_owner = False
        authority.allow_retained_contents = True
        authority.removed = False
        authority.cleanup_started = False
        return authority

    def assert_bound(self):
        metadata = os.fstat(self.fd)
        if identity(metadata) != self.identity:
            raise ClosureError("private-tree root authority changed")
        if (
            metadata.st_uid != self.owner
            or metadata.st_gid != self.group
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ClosureError("private-tree root metadata changed")
        if descriptor_mount_id(self.fd) != self.mount_id:
            raise ClosureError("private-tree root mount authority changed")
        if self.parent_fd is not None:
            parent_metadata = os.fstat(self.parent_fd)
            validate_parent_authority(parent_metadata)
            if (
                identity(parent_metadata) != self.parent_identity
                or descriptor_mount_id(self.parent_fd) != self.parent_mount_id
                or (
                    parent_metadata.st_uid,
                    parent_metadata.st_gid,
                    stat.S_IMODE(parent_metadata.st_mode),
                )
                != self.parent_metadata
            ):
                raise ClosureError("private-tree parent authority changed")
            edge = os.stat(self.basename, dir_fd=self.parent_fd, follow_symlinks=False)
            if identity(edge) != self.identity:
                raise ClosureError("private-tree root edge changed")

    def remove_contents(self, descriptor, remaining, authorities, depth=0):
        for name in bounded_directory_names(descriptor, remaining[0]):
            remaining[0] -= 1
            if remaining[0] < 0:
                raise ClosureError("private-tree cleanup exceeds its entry bound")
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if metadata.st_dev != self.device:
                raise ClosureError("private-tree cleanup crosses a filesystem boundary")
            authority_fd = os.open(
                name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor
            )
            try:
                if (
                    identity(os.fstat(authority_fd)) != identity(metadata)
                    or descriptor_mount_id(authority_fd) != self.mount_id
                ):
                    raise ClosureError("private-tree cleanup crosses a mount boundary")
                if stat.S_ISDIR(metadata.st_mode):
                    if depth >= MAX_DIRECTORY_DEPTH:
                        raise ClosureError("tree exceeds its directory-depth bound")
                    child = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=descriptor,
                    )
                    try:
                        opened = os.fstat(child)
                        if (
                            identity(opened) != identity(metadata)
                            or (
                                self.require_uniform_owner
                                and (
                                    opened.st_uid != self.owner
                                    or opened.st_gid != self.group
                                )
                            )
                        ):
                            raise ClosureError("private-tree directory changed during cleanup")
                        if descriptor_mount_id(child) != self.mount_id:
                            raise ClosureError("private-tree directory changed mount during cleanup")
                        if self.require_uniform_owner:
                            os.fchmod(child, 0o700)
                        self.remove_contents(child, remaining, authorities, depth + 1)
                        current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                        if identity(current) != identity(opened):
                            raise ClosureError("private-tree directory changed before removal")
                        os.rmdir(name, dir_fd=descriptor)
                        if os.fstat(authority_fd).st_nlink != 0:
                            raise ClosureError("private-tree directory removal did not consume its edge")
                    finally:
                        close_descriptors(
                            (child,),
                            "scratch cleanup child descriptor close",
                            sys.exc_info()[1],
                        )
                elif stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                    key = identity(metadata)
                    authority = authorities.get(key)
                    if authority is None:
                        raise ClosureError("private-tree cleanup lacks retained inode authority")
                    retained = os.fstat(authority["fd"])
                    current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    if (
                        identity(current) != key
                        or identity(retained) != key
                        or retained.st_nlink != authority["remaining"]
                        or metadata.st_nlink != authority["remaining"]
                        or descriptor_mount_id(authority["fd"]) != self.mount_id
                    ):
                        raise ClosureError("private-tree entry changed before removal")
                    os.unlink(name, dir_fd=descriptor)
                    authority["remaining"] -= 1
                    if (
                        os.fstat(authority["fd"]).st_nlink != authority["remaining"]
                        or os.fstat(authority_fd).st_nlink != authority["remaining"]
                    ):
                        raise ClosureError("private-tree unlink did not consume the authenticated edge")
                    try:
                        os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        raise ClosureError("private-tree entry was replaced during removal")
                else:
                    raise ClosureError("tree contains a special filesystem object")
            finally:
                close_descriptors(
                    (authority_fd,),
                    "scratch cleanup entry descriptor close",
                    sys.exc_info()[1],
                )

    def collect_inode_links(self, descriptor, remaining, linked, depth=0):
        for name in bounded_directory_names(descriptor, remaining[0]):
            remaining[0] -= 1
            if remaining[0] < 0:
                raise ClosureError("private-tree inode-closure inspection exceeds its entry bound")
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if metadata.st_dev != self.device:
                raise ClosureError("private-tree inode-closure inspection crosses a filesystem boundary")
            authority_fd = os.open(
                name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor
            )
            retain_authority = False
            try:
                if (
                    identity(os.fstat(authority_fd)) != identity(metadata)
                    or descriptor_mount_id(authority_fd) != self.mount_id
                ):
                    raise ClosureError("private-tree inode-closure inspection crosses a mount boundary")
                if stat.S_ISDIR(metadata.st_mode):
                    if depth >= MAX_DIRECTORY_DEPTH:
                        raise ClosureError("tree exceeds its directory-depth bound")
                    child = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=descriptor,
                    )
                    try:
                        opened = os.fstat(child)
                        if identity(opened) != identity(metadata):
                            raise ClosureError(
                                "private-tree directory changed during inode-closure inspection"
                            )
                        if descriptor_mount_id(child) != self.mount_id:
                            raise ClosureError(
                                "private-tree inode-closure inspection crosses a mount boundary"
                            )
                        self.collect_inode_links(child, remaining, linked, depth + 1)
                    finally:
                        close_descriptors(
                            (child,),
                            "inode-closure child descriptor close",
                            sys.exc_info()[1],
                        )
                elif stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                    if metadata.st_nlink < 1:
                        raise ClosureError("private-tree entry has an invalid link count")
                    key = identity(metadata)
                    authority = linked.get(key)
                    if authority is None:
                        linked[key] = {
                            "fd": authority_fd,
                            "expected": metadata.st_nlink,
                            "internal": 1,
                            "remaining": metadata.st_nlink,
                        }
                        retain_authority = True
                    elif authority["expected"] != metadata.st_nlink:
                        raise ClosureError("private-tree inode link count changed during inspection")
                    else:
                        authority["internal"] += 1
                else:
                    raise ClosureError("tree contains a special filesystem object")
            finally:
                if not retain_authority:
                    close_descriptors(
                        (authority_fd,),
                        "inode-closure entry descriptor close",
                        sys.exc_info()[1],
                    )

    def close_inode_authorities(self, linked, primary=None):
        close_descriptors(
            (authority["fd"] for authority in linked.values()),
            "retained inode descriptor close",
            primary,
        )

    def acquire_inode_closure(self, descriptor):
        require_retained_descriptor_budget()
        linked = {}
        try:
            self.collect_inode_links(descriptor, [TREE_ENTRY_LIMIT], linked)
            for key, authority in linked.items():
                current = os.fstat(authority["fd"])
                if (
                    identity(current) != key
                    or current.st_nlink != authority["expected"]
                    or authority["internal"] != authority["expected"]
                    or descriptor_mount_id(authority["fd"]) != self.mount_id
                ):
                    raise ClosureError(
                        "private tree contains a non-directory inode linked outside its boundary"
                    )
            return linked
        except BaseException as error:
            self.close_inode_authorities(linked, error)
            raise

    def assert_inode_closure(self, descriptor):
        linked = self.acquire_inode_closure(descriptor)
        self.close_inode_authorities(linked)

    def require_inode_authorities_consumed(self, linked):
        for authority in linked.values():
            if authority["remaining"] != 0 or os.fstat(authority["fd"]).st_nlink != 0:
                raise ClosureError("private-tree cleanup retained an inode edge")

    @contextlib.contextmanager
    def directory(self, prefix):
        self.assert_bound()
        name = prefix + os.urandom(16).hex()
        os.mkdir(name, 0o700, dir_fd=self.fd)
        child = None
        child_identity = None
        child_owned = False
        try:
            edge = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            if (
                not stat.S_ISDIR(edge.st_mode)
                or edge.st_uid != os.geteuid()
                or edge.st_gid != os.getegid()
                or stat.S_IMODE(edge.st_mode) != 0o700
            ):
                raise ClosureError("self-test fixture edge has invalid creation metadata")
            child_identity = identity(edge)
            child = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fd
            )
            if identity(os.fstat(child)) != child_identity:
                raise ClosureError("self-test fixture edge changed during creation")
            if descriptor_mount_id(child) != self.mount_id:
                raise ClosureError("self-test fixture was created across a mount boundary")
            child_owned = True
            yield f"/proc/self/fd/{child}"
        finally:
            primary_error = sys.exc_info()[1]
            cleanup_complete = False
            cleanup_error = None
            try:
                if child_owned:
                    current = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                    if identity(current) != child_identity:
                        raise ClosureError("self-test fixture edge changed before cleanup")
                    authorities = self.acquire_inode_closure(child)
                    try:
                        self.remove_contents(child, [TREE_ENTRY_LIMIT], authorities)
                        self.require_inode_authorities_consumed(authorities)
                    finally:
                        self.close_inode_authorities(authorities, sys.exc_info()[1])
                    current = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                    if identity(current) != child_identity:
                        raise ClosureError("self-test fixture root changed before removal")
                    os.rmdir(name, dir_fd=self.fd)
                    if os.fstat(child).st_nlink != 0:
                        raise ClosureError("self-test fixture root removal did not consume its edge")
                    cleanup_complete = True
                if cleanup_complete:
                    self.assert_bound()
            except BaseException as error:
                cleanup_error = error
            close_descriptors(
                (child,),
                "self-test fixture child descriptor close",
                cleanup_error if cleanup_error is not None else primary_error,
            )
            if cleanup_error is not None:
                if primary_error is None:
                    raise cleanup_error
                primary_error.add_note(
                    f"self-test fixture cleanup failed: {type(cleanup_error).__name__}: {cleanup_error}"
                )
                for note in getattr(cleanup_error, "__notes__", ()):
                    primary_error.add_note(f"self-test fixture cleanup: {note}")

    def close(self, primary=None):
        failures = []
        try:
            if (
                not self.removed
                and not self.cleanup_started
                and not self.allow_retained_contents
            ):
                self.assert_bound()
                if not directory_is_empty(self.fd):
                    raise ClosureError("self-test scratch retained fixture state")
        except BaseException as error:
            failures.append(error)
        failures.extend(collect_descriptor_close_failures((self.fd, self.parent_fd)))
        self.fd = None
        self.parent_fd = None
        report_cleanup_failures(primary, "private-tree root cleanup", failures)

    def remove_root(self, expected_identity):
        if self.parent_fd is None or self.basename is None:
            raise ClosureError("private-tree root removal requires pathname-edge authority")
        self.assert_bound()
        if self.identity != expected_identity:
            raise ClosureError("private-tree root identity differs from its cleanup authority")
        self.cleanup_started = True
        authorities = self.acquire_inode_closure(self.fd)
        try:
            self.remove_contents(self.fd, [TREE_ENTRY_LIMIT], authorities)
            self.require_inode_authorities_consumed(authorities)
        finally:
            self.close_inode_authorities(authorities, sys.exc_info()[1])
        if not directory_is_empty(self.fd):
            raise ClosureError("private-tree root remains nonempty after cleanup")
        edge = os.stat(self.basename, dir_fd=self.parent_fd, follow_symlinks=False)
        if identity(edge) != self.identity:
            raise ClosureError("private-tree root edge changed before removal")
        os.rmdir(self.basename, dir_fd=self.parent_fd)
        if os.fstat(self.fd).st_nlink != 0:
            raise ClosureError("private-tree root removal did not consume its authenticated edge")
        os.fsync(self.parent_fd)
        self.removed = True

    def remove_empty_root(self, expected_identity):
        if self.parent_fd is None or self.basename is None:
            raise ClosureError("empty private-root removal requires pathname-edge authority")
        self.assert_bound()
        if self.identity != expected_identity:
            raise ClosureError("empty private-root identity differs from its cleanup authority")
        if not directory_is_empty(self.fd):
            raise ClosureError("empty private-root removal found retained contents")
        edge = os.stat(self.basename, dir_fd=self.parent_fd, follow_symlinks=False)
        if identity(edge) != self.identity:
            raise ClosureError("empty private-root edge changed before removal")
        self.cleanup_started = True
        os.rmdir(self.basename, dir_fd=self.parent_fd)
        if os.fstat(self.fd).st_nlink != 0:
            raise ClosureError("empty private-root removal did not consume its authenticated edge")
        os.fsync(self.parent_fd)
        self.removed = True

    def remove_tree_contents(self, expected_identity):
        self.assert_bound()
        if self.identity != expected_identity or self.parent_fd is not None:
            raise ClosureError("tree-contents removal authority is invalid")
        self.cleanup_started = True
        authorities = self.acquire_inode_closure(self.fd)
        try:
            self.remove_contents(self.fd, [TREE_ENTRY_LIMIT], authorities)
            self.require_inode_authorities_consumed(authorities)
        finally:
            self.close_inode_authorities(authorities, sys.exc_info()[1])
        if not directory_is_empty(self.fd):
            raise ClosureError("tree-contents root remains nonempty after cleanup")
        self.assert_bound()


AT_EMPTY_PATH = 0x1000
AT_SYMLINK_NOFOLLOW = 0x100
PROTECTED_HARDLINKS = "/proc/sys/fs/protected_hardlinks"
TREE_ENTRY_LIMIT = 524288
MAX_DIRECTORY_DEPTH = 128
MAX_PREEXISTING_DESCRIPTORS = 64
MAX_TRANSIENT_DESCRIPTORS = 8
RETAINED_DESCRIPTOR_RESERVE = 256
RETAINED_DESCRIPTOR_LIMIT = TREE_ENTRY_LIMIT + RETAINED_DESCRIPTOR_RESERVE
LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.fchownat.argtypes = [
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_uint,
    ctypes.c_uint,
    ctypes.c_int,
]
LIBC.fchownat.restype = ctypes.c_int


def descriptor_chown(descriptor, owner, group, symlink=False):
    flags = AT_EMPTY_PATH | (AT_SYMLINK_NOFOLLOW if symlink else 0)
    if LIBC.fchownat(descriptor, b"", owner, group, flags) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def normalized_mode(mode, directory=False, root=False):
    if root:
        return 0o700
    required = 0o700 if directory else 0o600
    return (stat.S_IMODE(mode) | required) & 0o755


def parse_protected_hardlinks(content):
    if content != b"1\n":
        raise ClosureError("kernel hardlink protection is not enabled")


def require_protected_hardlinks():
    descriptor = os.open(PROTECTED_HARDLINKS, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        content = os.read(descriptor, 3)
        if os.read(descriptor, 1):
            raise ClosureError("kernel hardlink protection value exceeds its byte bound")
    finally:
        close_descriptors(
            (descriptor,),
            "kernel hardlink-protection descriptor close",
            sys.exc_info()[1],
        )
    parse_protected_hardlinks(content)


def require_retained_descriptor_budget(exact_hard_limit=False):
    required_reserve = (
        1
        + MAX_DIRECTORY_DEPTH
        + MAX_PREEXISTING_DESCRIPTORS
        + MAX_TRANSIENT_DESCRIPTORS
    )
    if required_reserve > RETAINED_DESCRIPTOR_RESERVE:
        raise ClosureError("retained-authority descriptor reserve is internally inconsistent")
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard != resource.RLIM_INFINITY and hard < RETAINED_DESCRIPTOR_LIMIT:
        raise ClosureError("retained-authority descriptor hard limit is below the tree bound")
    if soft != RETAINED_DESCRIPTOR_LIMIT:
        try:
            resource.setrlimit(
                resource.RLIMIT_NOFILE,
                (RETAINED_DESCRIPTOR_LIMIT, hard),
            )
        except (OSError, ValueError) as error:
            raise ClosureError("retained-authority descriptor budget cannot be established") from error
    observed_soft, observed_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if observed_soft != RETAINED_DESCRIPTOR_LIMIT:
        raise ClosureError("retained-authority descriptor budget differs after establishment")
    if exact_hard_limit and observed_hard != RETAINED_DESCRIPTOR_LIMIT:
        raise ClosureError("retained-authority descriptor hard limit is not exact")
    if len(live_descriptor_inventory()) > MAX_PREEXISTING_DESCRIPTORS:
        raise ClosureError("process has too many pre-existing descriptors for retained authority")


class TreeNormalizationAuthority:
    def __init__(self, path, expected_identity):
        require_retained_descriptor_budget()
        require_real_directory(path)
        self.path = path
        self.root_fd = os.open(
            path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        self.directories = []
        self.inodes = {}
        self.edges = []
        try:
            root = os.fstat(self.root_fd)
            edge = os.stat(path, follow_symlinks=False)
            if (
                identity(root) != expected_identity
                or identity(edge) != expected_identity
                or not stat.S_ISDIR(root.st_mode)
            ):
                raise ClosureError("normalization root identity is invalid")
            self.device = root.st_dev
            self.mount_id = descriptor_mount_id(self.root_fd)
            self.directories.append(
                {
                    "fd": self.root_fd,
                    "parent": None,
                    "name": None,
                    "identity": identity(root),
                    "mode": root.st_mode,
                    "uid": root.st_uid,
                    "gid": root.st_gid,
                    "nlink": root.st_nlink,
                    "names": None,
                }
            )
            self._collect(
                self.root_fd,
                [TREE_ENTRY_LIMIT],
                self.directories[0],
                0,
            )
            self.assert_bound()
            for authority in self.inodes.values():
                if authority["internal"] != authority["nlink"]:
                    raise ClosureError(
                        "normalization tree contains a non-directory inode linked outside its boundary"
                    )
        except BaseException as error:
            self.close(error)
            raise

    def _collect(self, parent_fd, remaining, directory, depth):
        names = bounded_directory_names(parent_fd, remaining[0])
        directory["names"] = tuple(names)
        for name in names:
            remaining[0] -= 1
            if remaining[0] < 0:
                raise ClosureError("normalization tree exceeds its entry bound")
            metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if metadata.st_dev != self.device:
                raise ClosureError("normalization tree crosses a filesystem boundary")
            authority_fd = os.open(
                name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd
            )
            retained = False
            try:
                current = os.fstat(authority_fd)
                if (
                    identity(current) != identity(metadata)
                    or descriptor_mount_id(authority_fd) != self.mount_id
                ):
                    raise ClosureError("normalization tree crosses a mount boundary")
                if stat.S_ISDIR(metadata.st_mode):
                    if depth >= MAX_DIRECTORY_DEPTH:
                        raise ClosureError("tree exceeds its directory-depth bound")
                    child = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=parent_fd,
                    )
                    child_retained = False
                    try:
                        opened = os.fstat(child)
                        if (
                            identity(opened) != identity(metadata)
                            or descriptor_mount_id(child) != self.mount_id
                        ):
                            raise ClosureError(
                                "normalization directory authority changed during acquisition"
                            )
                        child_directory = {
                            "fd": child,
                            "parent": parent_fd,
                            "name": name,
                            "identity": identity(metadata),
                            "mode": metadata.st_mode,
                            "uid": metadata.st_uid,
                            "gid": metadata.st_gid,
                            "nlink": metadata.st_nlink,
                            "names": None,
                        }
                        self.directories.append(child_directory)
                        child_retained = True
                        self._collect(child, remaining, child_directory, depth + 1)
                    finally:
                        if not child_retained:
                            close_descriptors(
                                (child,),
                                "normalization child descriptor close",
                                sys.exc_info()[1],
                            )
                elif stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                    key = identity(metadata)
                    inode = self.inodes.get(key)
                    if inode is None:
                        self.inodes[key] = {
                            "fd": authority_fd,
                            "identity": key,
                            "mode": metadata.st_mode,
                            "uid": metadata.st_uid,
                            "gid": metadata.st_gid,
                            "nlink": metadata.st_nlink,
                            "internal": 1,
                        }
                        retained = True
                    elif (
                        inode["nlink"] != metadata.st_nlink
                        or inode["mode"] != metadata.st_mode
                        or inode["uid"] != metadata.st_uid
                        or inode["gid"] != metadata.st_gid
                    ):
                        raise ClosureError("normalization inode authority changed during acquisition")
                    else:
                        inode["internal"] += 1
                    self.edges.append((parent_fd, name, key))
                else:
                    raise ClosureError("normalization tree contains a special filesystem object")
            finally:
                if not retained:
                    close_descriptors(
                        (authority_fd,),
                        "normalization entry descriptor close",
                        sys.exc_info()[1],
                    )

    def assert_bound(self, normalized_owner=None, normalized_group=None):
        if (normalized_owner is None) != (normalized_group is None):
            raise ClosureError("normalization metadata authority is incomplete")

        def expected_directory_metadata(directory, index):
            if normalized_owner is None:
                return (
                    directory["mode"],
                    directory["uid"],
                    directory["gid"],
                    directory["nlink"],
                )
            return (
                stat.S_IFDIR
                | normalized_mode(directory["mode"], directory=True, root=index == 0),
                normalized_owner,
                normalized_group,
                directory["nlink"],
            )

        def expected_inode_metadata(authority):
            mode = authority["mode"]
            if normalized_owner is not None and not stat.S_ISLNK(mode):
                mode = stat.S_IFREG | normalized_mode(mode)
            if normalized_owner is None:
                owner, group = authority["uid"], authority["gid"]
            else:
                owner, group = normalized_owner, normalized_group
            return mode, owner, group, authority["nlink"]

        root = os.fstat(self.root_fd)
        edge = os.stat(self.path, follow_symlinks=False)
        root_expected = expected_directory_metadata(self.directories[0], 0)
        if (
            identity(root) != self.directories[0]["identity"]
            or identity(edge) != self.directories[0]["identity"]
            or descriptor_mount_id(self.root_fd) != self.mount_id
            or (root.st_mode, root.st_uid, root.st_gid, root.st_nlink) != root_expected
            or (edge.st_mode, edge.st_uid, edge.st_gid, edge.st_nlink) != root_expected
        ):
            raise ClosureError("normalization root authority changed")
        for directory in self.directories:
            if tuple(
                bounded_directory_names(directory["fd"], len(directory["names"]) + 1)
            ) != directory["names"]:
                raise ClosureError("normalization directory inventory changed")
        for index, directory in enumerate(self.directories[1:], 1):
            current = os.fstat(directory["fd"])
            edge = os.stat(
                directory["name"], dir_fd=directory["parent"], follow_symlinks=False
            )
            expected = expected_directory_metadata(directory, index)
            if (
                identity(current) != directory["identity"]
                or identity(edge) != directory["identity"]
                or descriptor_mount_id(directory["fd"]) != self.mount_id
                or (current.st_mode, current.st_uid, current.st_gid, current.st_nlink)
                != expected
                or (edge.st_mode, edge.st_uid, edge.st_gid, edge.st_nlink) != expected
            ):
                raise ClosureError("normalization directory authority changed")
        observed = {key: 0 for key in self.inodes}
        for parent_fd, name, key in self.edges:
            edge = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            expected = expected_inode_metadata(self.inodes[key])
            if (
                identity(edge) != key
                or (edge.st_mode, edge.st_uid, edge.st_gid, edge.st_nlink) != expected
            ):
                raise ClosureError("normalization inode edge changed")
            observed[key] += 1
        for key, authority in self.inodes.items():
            current = os.fstat(authority["fd"])
            expected = expected_inode_metadata(authority)
            if (
                identity(current) != key
                or (current.st_mode, current.st_uid, current.st_gid, current.st_nlink)
                != expected
                or observed[key] != authority["internal"]
                or descriptor_mount_id(authority["fd"]) != self.mount_id
            ):
                raise ClosureError("normalization inode authority changed")

    def normalize(self, owner, group):
        self.assert_bound()
        for index, directory in enumerate(self.directories):
            os.fchown(directory["fd"], 0, 0)
            os.fchmod(
                directory["fd"],
                normalized_mode(directory["mode"], directory=True, root=index == 0),
            )
            current = os.fstat(directory["fd"])
            if current.st_uid != 0 or current.st_gid != 0:
                raise ClosureError("normalization directory ownership transition failed")
        for key, authority in self.inodes.items():
            symlink = stat.S_ISLNK(authority["mode"])
            descriptor_chown(authority["fd"], 0, 0, symlink=symlink)
            if symlink:
                descriptor_chown(authority["fd"], owner, group, symlink=True)
            else:
                descriptor = os.open(
                    f"/proc/self/fd/{authority['fd']}", os.O_RDONLY | os.O_CLOEXEC
                )
                try:
                    if identity(os.fstat(descriptor)) != key:
                        raise ClosureError("normalization regular-file descriptor changed")
                    os.fchmod(descriptor, normalized_mode(authority["mode"]))
                    os.fchown(descriptor, owner, group)
                finally:
                    close_descriptors(
                        (descriptor,),
                        "normalization readable descriptor close",
                        sys.exc_info()[1],
                    )
        for directory in reversed(self.directories):
            os.fchown(directory["fd"], owner, group)
        self.assert_bound(owner, group)
        for index, directory in enumerate(self.directories):
            current = os.fstat(directory["fd"])
            expected_mode = normalized_mode(
                directory["mode"], directory=True, root=index == 0
            )
            if (
                current.st_uid != owner
                or current.st_gid != group
                or stat.S_IMODE(current.st_mode) != expected_mode
            ):
                raise ClosureError("normalization directory postcondition differs")
        for authority in self.inodes.values():
            current = os.fstat(authority["fd"])
            if current.st_uid != owner or current.st_gid != group:
                raise ClosureError("normalization inode ownership postcondition differs")
            if not stat.S_ISLNK(authority["mode"]) and stat.S_IMODE(
                current.st_mode
            ) != normalized_mode(authority["mode"]):
                raise ClosureError("normalization inode mode postcondition differs")

    def close(self, primary=None):
        descriptors = [authority["fd"] for authority in self.inodes.values()]
        descriptors.extend(directory["fd"] for directory in reversed(self.directories))
        if self.root_fd not in descriptors:
            descriptors.append(self.root_fd)
        self.root_fd = None
        self.directories = []
        self.inodes = {}
        close_descriptors(descriptors, "normalization authority close", primary)


def normalize_tree(path, expected_identity, owner, group):
    require_retained_descriptor_budget()
    require_protected_hardlinks()
    authority = TreeNormalizationAuthority(path, expected_identity)
    try:
        authority.normalize(owner, group)
    finally:
        authority.close(sys.exc_info()[1])


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


def exercise_cleanup_failure_accounting():
    attempts = []

    def failing_close(descriptor):
        attempts.append(descriptor)
        raise OSError(errno.EIO, f"injected descriptor close failure {descriptor}")

    failures = collect_descriptor_close_failures((91, 92), failing_close)
    if attempts != [91, 92] or len(failures) != 2:
        raise ClosureError("descriptor close failure fixture did not exhaust cleanup")
    primary = ClosureError("injected primary failure")
    report_cleanup_failures(primary, "injected cleanup", failures)
    notes = getattr(primary, "__notes__", ())
    if len(notes) != 2 or not all("injected cleanup" in note for note in notes):
        raise ClosureError("descriptor close failure fixture replaced its primary error")
    try:
        report_cleanup_failures(None, "injected cleanup", failures)
    except ClosureError as error:
        if "failed 2 time(s)" not in str(error) or len(getattr(error, "__notes__", ())) != 2:
            raise ClosureError("descriptor close failure fixture lost cleanup errors") from error
    else:
        raise ClosureError("descriptor close failure fixture accepted cleanup errors")


def live_descriptor_inventory():
    descriptors = set()
    for name in os.listdir("/proc/self/fd"):
        if re.fullmatch(r"[0-9]+", name) is None:
            raise ClosureError("process descriptor inventory is malformed")
        descriptor = int(name)
        try:
            os.fstat(descriptor)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
        else:
            descriptors.add(descriptor)
    return descriptors


def exercise_authority_bounds(scratch):
    global MAX_DIRECTORY_DEPTH, MAX_PREEXISTING_DESCRIPTORS, TREE_ENTRY_LIMIT
    global live_descriptor_inventory

    require_retained_descriptor_budget()
    observed_soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    if observed_soft != RETAINED_DESCRIPTOR_LIMIT:
        raise ClosureError("descriptor-budget fixture did not establish the exact soft limit")

    original_inventory = live_descriptor_inventory
    _, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)

    def exact_boundary_inventory():
        current_soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        if current_soft != RETAINED_DESCRIPTOR_LIMIT:
            raise ClosureError("descriptor inventory ran before the exact budget was established")
        return set(range(MAX_PREEXISTING_DESCRIPTORS))

    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (MAX_PREEXISTING_DESCRIPTORS, hard_limit))
        live_descriptor_inventory = exact_boundary_inventory
        require_retained_descriptor_budget()
    finally:
        live_descriptor_inventory = original_inventory
        current_soft, current_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if current_soft != RETAINED_DESCRIPTOR_LIMIT:
            resource.setrlimit(
                resource.RLIMIT_NOFILE,
                (RETAINED_DESCRIPTOR_LIMIT, current_hard),
            )

    original_preexisting = MAX_PREEXISTING_DESCRIPTORS
    existing = len(live_descriptor_inventory())
    try:
        MAX_PREEXISTING_DESCRIPTORS = existing - 1
        require_rejection(require_retained_descriptor_budget)
    finally:
        MAX_PREEXISTING_DESCRIPTORS = original_preexisting
    require_retained_descriptor_budget()

    with scratch.directory("closure-bound-") as directory:
        root = os.path.join(os.path.realpath(directory), "tree")
        os.mkdir(root, 0o700)
        first = os.path.join(root, "first")
        os.mkdir(first, 0o700)
        os.mkdir(os.path.join(first, "second"), 0o700)
        expected = identity(os.stat(root, follow_symlinks=False))

        original_depth = MAX_DIRECTORY_DEPTH
        try:
            MAX_DIRECTORY_DEPTH = 1
            require_rejection(TreeNormalizationAuthority, root, expected)
            authority = PrivateTreeRoot.for_tree_contents(
                root, expected, os.geteuid(), os.getegid()
            )
            try:
                require_rejection(authority.acquire_inode_closure, authority.fd)
            finally:
                authority.close(sys.exc_info()[1])
        finally:
            MAX_DIRECTORY_DEPTH = original_depth

        original_entries = TREE_ENTRY_LIMIT
        try:
            TREE_ENTRY_LIMIT = 1
            require_rejection(TreeNormalizationAuthority, root, expected)
        finally:
            TREE_ENTRY_LIMIT = original_entries


def exercise_scratch_acquisition_failures(scratch):
    global descriptor_mount_id
    with scratch.directory("closure-constructor-failure-") as directory:
        path = os.path.realpath(directory)
        before = live_descriptor_inventory()
        original = descriptor_mount_id

        def reject_constructor_mount(descriptor):
            del descriptor
            raise ClosureError("injected closure constructor mount failure")

        descriptor_mount_id = reject_constructor_mount
        try:
            require_rejection(PrivateTreeRoot, path)
        finally:
            descriptor_mount_id = original
        if live_descriptor_inventory() != before:
            raise ClosureError("closure constructor leaked a descriptor after acquisition failure")

    prefix = "closure-child-failure-"
    before = live_descriptor_inventory()
    original = descriptor_mount_id

    def reject_child_mount(descriptor):
        if descriptor == scratch.fd:
            return original(descriptor)
        raise ClosureError("injected closure child mount failure")

    descriptor_mount_id = reject_child_mount
    try:
        try:
            with scratch.directory(prefix):
                pass
        except ClosureError as error:
            if "injected closure child mount failure" not in str(error):
                raise
        else:
            raise ClosureError("closure child accepted a missing mount authority")
    finally:
        descriptor_mount_id = original
    if live_descriptor_inventory() != before:
        raise ClosureError("closure child leaked a descriptor after acquisition failure")
    retained = [name for name in os.listdir(scratch.fd) if name.startswith(prefix)]
    if len(retained) != 1:
        raise ClosureError("closure child acquisition failure did not preserve one ambiguous edge")
    name = retained[0]
    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=scratch.fd)
    try:
        metadata = os.fstat(child)
        if (
            metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or descriptor_mount_id(child) != scratch.mount_id
            or os.listdir(child)
        ):
            raise ClosureError("preserved closure child acquisition state is not exact")
    finally:
        close_descriptors(
            (child,),
            "preserved child fixture descriptor close",
            sys.exc_info()[1],
        )
    os.rmdir(name, dir_fd=scratch.fd)
    scratch.assert_bound()


def exercise_normalization_authority(scratch):
    require_retained_descriptor_budget()
    parse_protected_hardlinks(b"1\n")
    require_rejection(parse_protected_hardlinks, b"0\n")
    require_rejection(parse_protected_hardlinks, b"2\n")
    with scratch.directory("normalization-authority-") as directory:
        temporary = os.path.realpath(directory)
        root = os.path.join(temporary, "tree")
        os.mkdir(root, 0o700)
        nested = os.path.join(root, "nested")
        os.mkdir(nested, 0o700)
        payload = os.path.join(nested, "payload")
        with open(payload, "wb") as output:
            output.write(b"normalization\n")
        os.chmod(payload, 0o6755)

        before = live_descriptor_inventory()
        original_mount_id = descriptor_mount_id
        calls = [0]

        def reject_child_directory_mount(descriptor):
            calls[0] += 1
            if calls[0] == 3:
                raise ClosureError("injected normalization child acquisition failure")
            return original_mount_id(descriptor)

        globals()["descriptor_mount_id"] = reject_child_directory_mount
        try:
            require_rejection(
                TreeNormalizationAuthority,
                root,
                identity(os.stat(root, follow_symlinks=False)),
            )
        finally:
            globals()["descriptor_mount_id"] = original_mount_id
        if live_descriptor_inventory() != before:
            raise ClosureError("normalization constructor leaked a directory descriptor")

        authority = TreeNormalizationAuthority(
            root, identity(os.stat(root, follow_symlinks=False))
        )
        external_name = "normalization-external-" + os.urandom(16).hex()
        external_present = False
        added = os.path.join(root, "added")
        try:
            with open(added, "wb") as output:
                output.write(b"late\n")
            require_rejection(authority.assert_bound)
            os.unlink(added)
            authority.assert_bound()

            os.chmod(payload, 0o600)
            require_rejection(authority.assert_bound)
            os.chmod(payload, 0o6755)
            authority.assert_bound()

            os.chmod(nested, 0o755)
            require_rejection(authority.assert_bound)
            os.chmod(nested, 0o700)
            authority.assert_bound()

            os.link(payload, external_name, dst_dir_fd=scratch.fd, follow_symlinks=False)
            external_present = True
            require_rejection(authority.assert_bound)
            os.unlink(external_name, dir_fd=scratch.fd)
            external_present = False
            authority.assert_bound()
        finally:
            authority.close(sys.exc_info()[1])
            if external_present:
                os.unlink(external_name, dir_fd=scratch.fd)
        if normalized_mode(0o6755) != 0o755 or normalized_mode(0o3777, True) != 0o755:
            raise ClosureError("normalization mode policy retained a special permission bit")
    scratch.assert_bound()


def exercise_scratch_external_link_rejection(scratch):
    prefix = "closure-external-link-"
    external_name = "closure-external-" + os.urandom(16).hex()
    try:
        try:
            with scratch.directory(prefix) as directory:
                descriptor = os.open(
                    os.path.join(directory, "payload"),
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                    0o600,
                )
                try:
                    os.write(descriptor, b"retained\n")
                finally:
                    close_descriptors(
                        (descriptor,),
                        "external-link fixture descriptor close",
                        sys.exc_info()[1],
                    )
                os.link(
                    os.path.join(directory, "payload"),
                    external_name,
                    dst_dir_fd=scratch.fd,
                    follow_symlinks=False,
                )
        except ClosureError as error:
            if "linked outside its boundary" not in str(error):
                raise
        else:
            raise ClosureError("scratch cleanup accepted an externally linked fixture inode")
        retained = [name for name in os.listdir(scratch.fd) if name.startswith(prefix)]
        if len(retained) != 1:
            raise ClosureError("closure external-link fixture did not preserve its directory")
        child_name = retained[0]
        child = os.open(
            child_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=scratch.fd,
        )
        try:
            payload = os.stat("payload", dir_fd=child, follow_symlinks=False)
            external = os.stat(external_name, dir_fd=scratch.fd, follow_symlinks=False)
            if identity(payload) != identity(external) or payload.st_nlink != 2:
                raise ClosureError("closure external-link fixture did not preserve exact inode state")
            os.unlink(external_name, dir_fd=scratch.fd)
            external_name = None
            authorities = scratch.acquire_inode_closure(child)
            try:
                scratch.remove_contents(child, [TREE_ENTRY_LIMIT], authorities)
                scratch.require_inode_authorities_consumed(authorities)
            finally:
                scratch.close_inode_authorities(authorities, sys.exc_info()[1])
        finally:
            close_descriptors(
                (child,),
                "external-link fixture child descriptor close",
                sys.exc_info()[1],
            )
        os.rmdir(child_name, dir_fd=scratch.fd)
    finally:
        if external_name is not None:
            try:
                os.unlink(external_name, dir_fd=scratch.fd)
            except FileNotFoundError:
                pass
    scratch.assert_bound()


def exercise_retained_inode_authority(scratch):
    external_name = "closure-retained-external-" + os.urandom(16).hex()
    external_present = False
    with scratch.directory("closure-retained-authority-") as directory:
        child = os.dup(int(os.path.basename(directory)))
        try:
            descriptor = os.open(
                "payload",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o600,
                dir_fd=child,
            )
            close_descriptors(
                (descriptor,),
                "retained-authority fixture descriptor close",
            )
            authorities = scratch.acquire_inode_closure(child)
            try:
                os.link(
                    "payload",
                    external_name,
                    src_dir_fd=child,
                    dst_dir_fd=scratch.fd,
                    follow_symlinks=False,
                )
                external_present = True
                try:
                    scratch.remove_contents(child, [TREE_ENTRY_LIMIT], authorities)
                except ClosureError as error:
                    if "changed before removal" not in str(error):
                        raise
                else:
                    raise ClosureError("retained inode authority accepted a late external link")
                inside = os.stat("payload", dir_fd=child, follow_symlinks=False)
                outside = os.stat(external_name, dir_fd=scratch.fd, follow_symlinks=False)
                if identity(inside) != identity(outside) or inside.st_nlink != 2:
                    raise ClosureError("retained inode authority changed a rejected linked inode")
                os.unlink(external_name, dir_fd=scratch.fd)
                external_present = False
                scratch.remove_contents(child, [TREE_ENTRY_LIMIT], authorities)
                scratch.require_inode_authorities_consumed(authorities)
            finally:
                scratch.close_inode_authorities(authorities, sys.exc_info()[1])
        finally:
            close_descriptors(
                (child,),
                "retained-authority fixture child descriptor close",
                sys.exc_info()[1],
            )
            if external_present:
                os.unlink(external_name, dir_fd=scratch.fd)
    scratch.assert_bound()


def exercise_scratch_root_removal(scratch):
    root_name = "closure-root-removal-" + os.urandom(16).hex()
    external_name = "closure-root-external-" + os.urandom(16).hex()
    root_authority = None
    external_present = False
    try:
        os.mkdir(root_name, 0o700, dir_fd=scratch.fd)
        external = os.open(
            external_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
            dir_fd=scratch.fd,
        )
        close_descriptors(
            (external,),
            "scratch-root removal fixture descriptor close",
        )
        external_present = True
        root_path = os.path.realpath(f"/proc/self/fd/{scratch.fd}/{root_name}")
        root_authority = PrivateTreeRoot(path=root_path, require_empty=False)
        os.link(
            external_name,
            "external-link",
            src_dir_fd=scratch.fd,
            dst_dir_fd=root_authority.fd,
            follow_symlinks=False,
        )
        try:
            root_authority.remove_root(root_authority.identity)
        except ClosureError as error:
            if "linked outside its boundary" not in str(error):
                raise
        else:
            raise ClosureError("scratch root cleanup accepted an externally linked inode")
        root_authority.assert_bound()
        linked = os.stat("external-link", dir_fd=root_authority.fd, follow_symlinks=False)
        outside = os.stat(external_name, dir_fd=scratch.fd, follow_symlinks=False)
        if identity(linked) != identity(outside) or linked.st_nlink != 2:
            raise ClosureError("scratch root cleanup changed a rejected external inode")
        os.unlink("external-link", dir_fd=root_authority.fd)
        root_authority.remove_root(root_authority.identity)
        root_authority.close()
        root_authority = None
        os.unlink(external_name, dir_fd=scratch.fd)
        external_present = False
    finally:
        if root_authority is not None:
            root_authority.close(sys.exc_info()[1])
        if external_present:
            try:
                os.unlink(external_name, dir_fd=scratch.fd)
            except FileNotFoundError:
                pass

    empty_name = "closure-empty-root-removal-" + os.urandom(16).hex()
    empty_authority = None
    try:
        os.mkdir(empty_name, 0o700, dir_fd=scratch.fd)
        empty_path = os.path.realpath(f"/proc/self/fd/{scratch.fd}/{empty_name}")
        empty_authority = PrivateTreeRoot(path=empty_path, require_empty=True)
        late = os.open(
            "late-entry",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
            dir_fd=empty_authority.fd,
        )
        close_descriptors((late,), "empty-root late-entry descriptor close")
        require_rejection(empty_authority.remove_empty_root, empty_authority.identity)
        os.unlink("late-entry", dir_fd=empty_authority.fd)
        empty_authority.remove_empty_root(empty_authority.identity)
        empty_authority.close()
        empty_authority = None
    finally:
        if empty_authority is not None:
            empty_authority.close(sys.exc_info()[1])
    scratch.assert_bound()


def run_self_test(scratch):
    escape_fixture = br"/space\040tab\011line\012slash\134"
    if decode_mount_path(escape_fixture) != b"/space tab\tline\nslash\\":
        raise ClosureError("mountinfo escape decoding fixture failed")
    require_rejection(decode_mount_path, br"/invalid\09x")
    with scratch.directory("private-tree-closure-") as authority:
        temporary = os.path.realpath(authority)
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
    modes.add_argument("--normalize-root")
    modes.add_argument("--self-test", action="store_true")
    modes.add_argument("--remove-private-root")
    modes.add_argument("--remove-empty-private-root")
    modes.add_argument("--remove-tree-contents")
    modes.add_argument("--check-descriptor-budget", action="store_true")
    modes.add_argument("--check-exact-descriptor-budget", action="store_true")
    parser.add_argument("--scratch-fd", type=int)
    parser.add_argument("--expected-identity")
    parser.add_argument("--owner", type=int)
    parser.add_argument("--group", type=int)
    parser.add_argument("--mountinfo", default="/proc/self/mountinfo")
    arguments = parser.parse_args()
    try:
        if arguments.self_test:
            if (
                arguments.scratch_fd is None
                or arguments.scratch_fd < 3
                or arguments.expected_identity is not None
            ):
                raise ClosureError("self-test requires an inherited --scratch-fd")
            scratch = PrivateTreeRoot(inherited_fd=arguments.scratch_fd)
            try:
                exercise_cleanup_failure_accounting()
                exercise_authority_bounds(scratch)
                exercise_scratch_acquisition_failures(scratch)
                exercise_normalization_authority(scratch)
                exercise_scratch_external_link_rejection(scratch)
                exercise_retained_inode_authority(scratch)
                exercise_scratch_root_removal(scratch)
                run_self_test(scratch)
            finally:
                scratch.close(sys.exc_info()[1])
        elif arguments.remove_private_root is not None:
            if (
                arguments.scratch_fd is not None
                or arguments.expected_identity is None
                or arguments.owner is not None
                or arguments.group is not None
            ):
                raise ClosureError("private-root removal requires only --expected-identity")
            match = re.fullmatch(r"([0-9]+):([1-9][0-9]*)", arguments.expected_identity)
            if match is None:
                raise ClosureError("private-root removal identity is malformed")
            scratch = PrivateTreeRoot(path=arguments.remove_private_root, require_empty=False)
            try:
                scratch.remove_root((int(match.group(1)), int(match.group(2))))
            finally:
                scratch.close(sys.exc_info()[1])
        elif arguments.remove_empty_private_root is not None:
            if (
                arguments.scratch_fd is not None
                or arguments.expected_identity is None
                or arguments.owner is not None
                or arguments.group is not None
            ):
                raise ClosureError(
                    "empty private-root removal requires only --expected-identity"
                )
            match = re.fullmatch(r"([0-9]+):([1-9][0-9]*)", arguments.expected_identity)
            if match is None:
                raise ClosureError("empty private-root removal identity is malformed")
            scratch = PrivateTreeRoot(
                path=arguments.remove_empty_private_root,
                require_empty=True,
            )
            try:
                scratch.remove_empty_root((int(match.group(1)), int(match.group(2))))
            finally:
                scratch.close(sys.exc_info()[1])
        elif arguments.remove_tree_contents is not None:
            if (
                arguments.scratch_fd is not None
                or arguments.expected_identity is None
                or arguments.owner is None
                or arguments.owner < 0
                or arguments.group is None
                or arguments.group < 0
            ):
                raise ClosureError(
                    "tree-contents removal requires identity, owner, and group authority"
                )
            match = re.fullmatch(r"([0-9]+):([1-9][0-9]*)", arguments.expected_identity)
            if match is None:
                raise ClosureError("tree-contents removal identity is malformed")
            expected = (int(match.group(1)), int(match.group(2)))
            scratch = PrivateTreeRoot.for_tree_contents(
                arguments.remove_tree_contents,
                expected,
                arguments.owner,
                arguments.group,
            )
            try:
                scratch.remove_tree_contents(expected)
            finally:
                scratch.close(sys.exc_info()[1])
        elif arguments.check_descriptor_budget or arguments.check_exact_descriptor_budget:
            if (
                arguments.scratch_fd is not None
                or arguments.expected_identity is not None
                or arguments.owner is not None
                or arguments.group is not None
            ):
                raise ClosureError("descriptor-budget check accepts no tree authority")
            require_retained_descriptor_budget(arguments.check_exact_descriptor_budget)
        elif arguments.normalize_root is not None:
            if (
                arguments.scratch_fd is not None
                or arguments.expected_identity is None
                or arguments.owner is None
                or arguments.owner < 0
                or arguments.group is None
                or arguments.group < 0
            ):
                raise ClosureError(
                    "tree normalization requires identity, owner, and group authority"
                )
            match = re.fullmatch(r"([0-9]+):([1-9][0-9]*)", arguments.expected_identity)
            if match is None:
                raise ClosureError("tree normalization identity is malformed")
            normalize_tree(
                arguments.normalize_root,
                (int(match.group(1)), int(match.group(2))),
                arguments.owner,
                arguments.group,
            )
        elif (
            arguments.scratch_fd is not None
            or arguments.expected_identity is not None
            or arguments.owner is not None
            or arguments.group is not None
        ):
            raise ClosureError("tree authority options are valid only with their tree modes")
        elif arguments.mount_root is not None:
            verify_mount_closure(arguments.mount_root, arguments.mountinfo)
        else:
            verify_inode_closure(arguments.inode_root)
    except (ClosureError, OSError) as error:
        print("verify-private-tree-closure: FAIL: {}".format(error), file=sys.stderr)
        for note in getattr(error, "__notes__", ()):
            print("verify-private-tree-closure: DETAIL: {}".format(note), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
