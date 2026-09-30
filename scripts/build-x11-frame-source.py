#!/usr/bin/env python3
"""Build the independent, source-bound display fixture inside the verifier container."""

import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_file(path, modes, limit, readonly=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and info.st_gid == os.getgid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) in modes and 1 <= info.st_size <= limit
                and (not readonly or os.fstatvfs(handle.fileno()).f_flag & os.ST_RDONLY),
                f"fixture file authority differs: {path}")
        raw = handle.read(limit + 1)
        require(len(raw) == info.st_size and identity(os.fstat(handle.fileno())) == identity(info),
                "fixture input changed during reading")
        return raw, identity(info)


def build(source, output, expected_sha):
    require(os.getuid() != 0 and os.getgid() != 0, "fixture builder refuses root")
    require(sorted(path.name for path in Path("/sys/class/net").iterdir()) == ["lo"],
            "fixture builder requires network-none")
    require(re.fullmatch(r"[0-9a-f]{64}", expected_sha), "fixture source digest is malformed")
    require(str(source.resolve()) == str(source) and str(output.resolve()) == str(output),
            "fixture paths are not canonical")
    source_modes = (0o400, 0o444, 0o600, 0o644, 0o664)
    raw, source_id = read_file(source, source_modes, 65536, readonly=True)
    require(hashlib.sha256(raw).hexdigest() == expected_sha, "fixture source digest differs")
    descriptor = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        require(info.st_uid == os.getuid() and info.st_gid == os.getgid()
                and stat.S_IMODE(info.st_mode) == 0o700 and not os.listdir(descriptor),
                "fixture output must be an empty private directory")
        output_id = (info.st_dev, info.st_ino)
        source_fd = os.open("source.c", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600, dir_fd=descriptor)
        with os.fdopen(source_fd, "wb") as handle:
            handle.write(raw)
        environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/nonexistent",
                       "TMPDIR": "/tmp", "SOURCE_DATE_EPOCH": "0"}
        for name in ("frame-a", "frame-b"):
            subprocess.run([
                "/usr/bin/cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                "-frandom-seed=" + expected_sha, "source.c", "-lX11", "-o", name,
            ], cwd=output, env=environment, check=True, timeout=20)
        a, _ = read_file(output / "frame-a", (0o700,), 1048576)
        b, _ = read_file(output / "frame-b", (0o700,), 1048576)
        require(a == b and a[:7] == b"\x7fELF\x02\x01\x01" and b[18:20] == b"\x3e\x00",
                "fixture copies differ or are not Linux x86_64 ELF")
        require(read_file(source, source_modes, 65536, readonly=True) == (raw, source_id),
                "fixture source changed during compilation")
        current = os.stat(output, follow_symlinks=False)
        require((current.st_dev, current.st_ino) == output_id and not output.is_symlink()
                and stat.S_IMODE(current.st_mode) == 0o700
                and sorted(os.listdir(descriptor)) == ["frame-a", "frame-b", "source.c"],
                "fixture output authority changed")
        binary_fd = os.open("frame-b", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
        try:
            os.fchmod(binary_fd, 0o500)
        finally:
            os.close(binary_fd)
        os.rename("frame-b", "frame-source", src_dir_fd=descriptor, dst_dir_fd=descriptor)
        os.unlink("frame-a", dir_fd=descriptor)
        os.unlink("source.c", dir_fd=descriptor)
        require(read_file(output / "frame-source", (0o500,), 1048576)[0] == b
                and os.listdir(descriptor) == ["frame-source"], "fixture final bytes differ")
        print(f"X11_FRAME_SOURCE_BUILD=pass source_sha256={expected_sha} "
              f"sha256={hashlib.sha256(b).hexdigest()} bytes={len(b)} "
              "copies=2 equality=byte-identical network=none output=private", flush=True)
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 4, "usage: build-x11-frame-source.py SOURCE OUTPUT_DIR SOURCE_SHA256")
        os.umask(0o077)
        build(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(f"X11 frame source build: {error}") from error
