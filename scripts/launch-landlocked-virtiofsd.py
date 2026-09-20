#!/usr/bin/env python3
"""Launch the pinned virtiofsd with one descriptor-bound Landlock authority."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import os
import socket
import stat
import sys


SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE = 445
SYS_LANDLOCK_RESTRICT_SELF = 446
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1
PR_SET_NO_NEW_PRIVS = 38

FS_EXECUTE = 1 << 0
FS_WRITE_FILE = 1 << 1
FS_READ_FILE = 1 << 2
FS_READ_DIR = 1 << 3
FS_REMOVE_DIR = 1 << 4
FS_REMOVE_FILE = 1 << 5
FS_MAKE_CHAR = 1 << 6
FS_MAKE_DIR = 1 << 7
FS_MAKE_REG = 1 << 8
FS_MAKE_SOCK = 1 << 9
FS_MAKE_FIFO = 1 << 10
FS_MAKE_BLOCK = 1 << 11
FS_MAKE_SYM = 1 << 12
FS_REFER = 1 << 13
FS_TRUNCATE = 1 << 14
FS_IOCTL_DEV = 1 << 15
NET_BIND_TCP = 1 << 0
NET_CONNECT_TCP = 1 << 1

HANDLED_FS = (1 << 16) - 1
HANDLED_NET = NET_BIND_TCP | NET_CONNECT_TCP
SHARED_ACCESS = (
    FS_WRITE_FILE
    | FS_READ_FILE
    | FS_READ_DIR
    | FS_REMOVE_DIR
    | FS_REMOVE_FILE
    | FS_MAKE_DIR
    | FS_MAKE_REG
    | FS_MAKE_SYM
    | FS_REFER
    | FS_TRUNCATE
)
READ_ACCESS = FS_READ_FILE | FS_READ_DIR


class RulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
    ]


class PathBeneathAttr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"landlocked virtiofsd launcher: {message}")


def parse_identity(value: str) -> tuple[int, int]:
    fields = value.split(":")
    if len(fields) != 2 or not all(field.isdigit() for field in fields):
        fail("expected directory identity is malformed")
    return int(fields[0]), int(fields[1])


def sha256_file(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def open_exact_path(path: str, *, directory: bool = False) -> int:
    flags = os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW
    if directory:
        flags |= os.O_DIRECTORY
    try:
        return os.open(path, flags)
    except OSError as exc:
        fail(f"cannot retain required path {path}: {exc}")


def add_path_rule(libc: ctypes.CDLL, ruleset_fd: int, path_fd: int, access: int) -> None:
    rule = PathBeneathAttr(access, path_fd)
    result = libc.syscall(
        SYS_LANDLOCK_ADD_RULE,
        ruleset_fd,
        LANDLOCK_RULE_PATH_BENEATH,
        ctypes.byref(rule),
        0,
    )
    if result != 0:
        error = ctypes.get_errno()
        fail(f"cannot add Landlock path rule: {os.strerror(error)}")


def expect_landlock_denial(operation: str, action: "Callable[[], None]") -> None:
    try:
        action()
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM):
            return
        fail(f"{operation} failed with unexpected errno {exc.errno}: {exc}")
    fail(f"{operation} unexpectedly escaped the Landlock policy")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument(
        "--authority",
        required=True,
        choices=("cache", "systemd-cache", "bounded-result"),
    )
    parser.add_argument("--shared-dir", required=True)
    parser.add_argument("--shared-identity", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--uid", required=True, type=int)
    parser.add_argument("--gid", required=True, type=int)
    args = parser.parse_args()

    if sys.platform != "linux" or os.uname().machine != "x86_64":
        fail("this launcher supports only the pinned Linux x86_64 verifier host")
    if os.getuid() != args.uid or os.geteuid() != args.uid:
        fail("real/effective UID differs from the admitted non-root principal")
    if os.getgid() != args.gid or os.getegid() != args.gid:
        fail("real/effective GID differs from the admitted non-root principal")
    if args.uid == 0 or args.gid == 0:
        fail("root identity is forbidden")
    if len(args.binary_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in args.binary_sha256
    ):
        fail("binary SHA-256 is malformed")

    shared = os.path.abspath(args.shared_dir)
    binary = os.path.abspath(args.binary)
    socket_path = os.path.abspath(args.socket)
    if os.path.realpath(shared) != shared:
        fail("shared directory path is not canonical")
    if os.path.realpath(binary) != binary:
        fail("virtiofsd binary path is not canonical")
    socket_parent = os.path.dirname(socket_path)
    if os.path.realpath(socket_parent) != socket_parent:
        fail("socket parent path is not canonical")
    if len(os.fsencode(socket_path)) > 107:
        fail("vhost-user socket path exceeds Linux AF_UNIX pathname capacity")
    if os.path.lexists(socket_path):
        fail("vhost-user socket path is already occupied")

    shared_fd = open_exact_path(shared, directory=True)
    shared_stat = os.fstat(shared_fd)
    if not stat.S_ISDIR(shared_stat.st_mode):
        fail("shared authority is not a directory")
    if (shared_stat.st_dev, shared_stat.st_ino) != parse_identity(args.shared_identity):
        fail("shared directory identity differs")
    if (shared_stat.st_uid, shared_stat.st_gid, stat.S_IMODE(shared_stat.st_mode)) != (
        args.uid,
        args.gid,
        0o700,
    ):
        fail("shared directory metadata differs")

    binary_fd = os.open(binary, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    binary_stat = os.fstat(binary_fd)
    if not stat.S_ISREG(binary_stat.st_mode) or binary_stat.st_nlink != 1:
        fail("virtiofsd binary is not one regular single-link file")
    if (binary_stat.st_uid, binary_stat.st_gid, stat.S_IMODE(binary_stat.st_mode)) != (
        args.uid,
        args.gid,
        0o500,
    ):
        fail("virtiofsd binary metadata differs")
    if sha256_file(binary_fd) != args.binary_sha256:
        fail("virtiofsd binary digest differs")

    parent_fd = open_exact_path(socket_parent, directory=True)
    parent_stat = os.fstat(parent_fd)
    if (parent_stat.st_uid, parent_stat.st_gid, stat.S_IMODE(parent_stat.st_mode)) != (
        args.uid,
        args.gid,
        0o700,
    ):
        fail("socket parent metadata differs")

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    try:
        listener.bind(socket_path)
    except OSError as exc:
        fail(f"cannot bind the vhost-user socket: {exc}")
    listener.listen(1)
    os.chmod(socket_path, 0o600)
    socket_stat = os.lstat(socket_path)
    if not stat.S_ISSOCK(socket_stat.st_mode) or socket_stat.st_nlink != 1:
        fail("prebound vhost-user channel is not one Unix socket")
    if (socket_stat.st_uid, socket_stat.st_gid, stat.S_IMODE(socket_stat.st_mode)) != (
        args.uid,
        args.gid,
        0o600,
    ):
        fail("prebound vhost-user channel metadata differs")
    listener_fd = listener.detach()

    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    abi = libc.syscall(
        SYS_LANDLOCK_CREATE_RULESET,
        ctypes.c_void_p(),
        0,
        LANDLOCK_CREATE_RULESET_VERSION,
    )
    if abi < 8:
        fail(f"Landlock ABI 8 or newer is required, observed {abi}")
    ruleset = RulesetAttr(HANDLED_FS, HANDLED_NET)
    ruleset_fd = libc.syscall(
        SYS_LANDLOCK_CREATE_RULESET,
        ctypes.byref(ruleset),
        ctypes.sizeof(ruleset),
        0,
    )
    if ruleset_fd < 0:
        error = ctypes.get_errno()
        fail(f"cannot create Landlock ruleset: {os.strerror(error)}")

    allowed_fds: list[int] = [shared_fd, binary_fd]
    add_path_rule(libc, ruleset_fd, shared_fd, SHARED_ACCESS)
    add_path_rule(libc, ruleset_fd, binary_fd, FS_EXECUTE | FS_READ_FILE)
    for path, access, directory in (
        ("/usr/lib", READ_ACCESS, True),
        ("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", FS_EXECUTE | FS_READ_FILE, False),
        ("/etc/ld.so.cache", FS_READ_FILE, False),
        ("/proc/sys/fs/nr_open", FS_READ_FILE, False),
        ("/proc/self/mountinfo", FS_READ_FILE, False),
        ("/proc/self/fd", READ_ACCESS, True),
    ):
        path_fd = open_exact_path(path, directory=directory)
        allowed_fds.append(path_fd)
        add_path_rule(libc, ruleset_fd, path_fd, access)

    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        fail(f"cannot set no_new_privs: {os.strerror(error)}")
    if libc.syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0) != 0:
        error = ctypes.get_errno()
        fail(f"cannot enforce Landlock ruleset: {os.strerror(error)}")
    os.close(ruleset_fd)

    def open_forbidden_file() -> None:
        fd = os.open("/etc/passwd", os.O_RDONLY | os.O_CLOEXEC)
        os.close(fd)

    def bind_forbidden_tcp() -> None:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        try:
            probe.bind(("127.0.0.1", 0))
        finally:
            probe.close()

    def connect_forbidden_tcp() -> None:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        try:
            probe.connect(("127.0.0.1", 9))
        finally:
            probe.close()

    expect_landlock_denial("outside-file read", open_forbidden_file)
    expect_landlock_denial("TCP bind", bind_forbidden_tcp)
    expect_landlock_denial("TCP connect", connect_forbidden_tcp)

    reopened_shared = os.open(
        f"/proc/self/fd/{shared_fd}", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC
    )
    reopened_stat = os.fstat(reopened_shared)
    if (reopened_stat.st_dev, reopened_stat.st_ino) != (
        shared_stat.st_dev,
        shared_stat.st_ino,
    ):
        fail("Landlock-allowed shared directory reopened with a different identity")
    os.close(reopened_shared)

    os.set_inheritable(listener_fd, True)
    os.set_inheritable(shared_fd, True)
    os.set_inheritable(binary_fd, True)
    for fd in allowed_fds[2:]:
        os.close(fd)
    os.close(parent_fd)

    print(
        "VIRTIOFSD_LANDLOCK=pass "
        f"abi={abi} uid={args.uid} gid={args.gid} "
        f"filesystem={args.authority}-only "
        "tcp=denied socket=prebound seccomp=kill",
        flush=True,
    )
    argv = [
        "virtiofsd",
        f"--fd={listener_fd}",
        f"--shared-dir=/proc/self/fd/{shared_fd}",
        "--sandbox=none",
        "--seccomp=kill",
        "--cache=never",
        "--xattr",
        "--inode-file-handles=never",
        "--thread-pool-size=0",
        "--rlimit-nofile=524544",
        "--log-level=info",
    ]
    environment = {
        "HOME": "/nonexistent",
        "LC_ALL": "C",
        "PATH": "/nonexistent",
        "TZ": "UTC",
    }
    os.execve(binary_fd, argv, environment)
    fail("virtiofsd exec unexpectedly returned")


if __name__ == "__main__":
    raise SystemExit(main())
