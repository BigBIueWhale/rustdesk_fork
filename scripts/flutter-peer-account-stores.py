#!/usr/bin/env python3
"""Observe retired stores during one isolated full-peer stage."""

import ctypes
import hashlib
import json
import os
from pathlib import Path
import select
import stat
import struct
import sys
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def identity(path):
    value = path.lstat()
    require(stat.S_ISREG(value.st_mode) and value.st_uid == os.getuid()
            and value.st_gid == os.getgid() and value.st_nlink == 1
            and stat.S_IMODE(value.st_mode) == 0o600, "store metadata differs")
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size, value.st_atime_ns,
            value.st_mtime_ns, value.st_ctime_ns)


def run():
    require(os.getuid() != 0 and os.getgid() != 0, "refuses root")
    require(len(sys.argv) == 2 and sys.argv[1] in ("server", "viewer"), "invalid role")
    role = sys.argv[1]
    home = Path("/tmp/" + role + "-home")
    require(os.environ.get("HOME") == str(home) and not os.environ.get("XDG_CONFIG_HOME"),
            "private config environment differs")
    for directory in (home, home / ".config", home / ".config/rustdesk"):
        if directory != home:
            directory.mkdir(mode=0o700, exist_ok=True)
        value = directory.lstat()
        require(stat.S_ISDIR(value.st_mode) and value.st_uid == os.getuid()
                and value.st_gid == os.getgid() and stat.S_IMODE(value.st_mode) == 0o700,
                "private directory differs")
    root = home / ".config/rustdesk"
    parent_identity = (root.stat().st_dev, root.stat().st_ino)
    paths = [root / "RustDesk_ab", root / "RustDesk_group"]
    payloads = {}
    for path in paths:
        payload = ("retired-account-store-fixture:" + path.name + "\n").encode()
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
        payloads[path.name] = payload

    libc = ctypes.CDLL(None, use_errno=True)
    libc.inotify_init1.argtypes = [ctypes.c_int]
    libc.inotify_init1.restype = ctypes.c_int
    libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    libc.inotify_add_watch.restype = ctypes.c_int
    descriptor = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    require(descriptor >= 0, "inotify initialization failed")
    try:
        watches = {}
        for path in [root] + paths:
            watch = libc.inotify_add_watch(descriptor, os.fsencode(path), 0x00000FFF | 0x02000000)
            require(watch >= 0 and watch not in watches, "inotify watch failed")
            watches[watch] = None if path == root else path.name

        def drain():
            observed = {path.name: 0 for path in paths}
            for _ in range(64):
                try:
                    data = os.read(descriptor, 65536)
                except BlockingIOError:
                    return observed
                require(bool(data), "inotify closed")
                offset = 0
                while offset < len(data):
                    require(len(data) - offset >= 16, "truncated inotify header")
                    watch, mask, _, length = struct.unpack_from("=iIII", data, offset)
                    offset += 16
                    require(length <= len(data) - offset and length <= 4096,
                            "invalid inotify name length")
                    name = data[offset:offset + length].split(b"\0", 1)[0]
                    offset += length
                    require(not mask & (0x00002000 | 0x00004000 | 0x00008000),
                            "inotify unmount, overflow or lost watch")
                    require(watch in watches, "unknown inotify watch")
                    label = watches[watch]
                    if label is None:
                        require(not mask & (0x00000400 | 0x00000800), "config parent moved or deleted")
                        for path in paths:
                            if name == os.fsencode(path.name):
                                observed[path.name] |= mask
                    else:
                        observed[label] |= mask
            raise RuntimeError("inotify drain exceeds bound")

        # Exercise the actual watched objects before any product process starts.
        # Event sets, not counts: Linux may coalesce repeated notifications.
        for path in paths:
            require(path.read_bytes() == payloads[path.name], "read control differs")
            with path.open("r+b") as output:
                output.write(payloads[path.name])
            path.chmod(0o600)
            moved = path.with_name(path.name + ".control")
            require(not moved.exists(), "control destination occupied")
            path.rename(moved)
            moved.rename(path)
        controls = drain()
        required = 0x00000001 | 0x00000002 | 0x00000004 | 0x00000800 | 0x00000020
        require(all(mask & required == required for mask in controls.values()),
                "read/write/attribute/rename controls were not observed")
        before = {path.name: identity(path) for path in paths}
        require(not any(drain().values()), "control events remained")
        print("ACCOUNT_STORES_READY role=" + role + " files=2 controls=8", flush=True)

        deadline = time.monotonic() + 900
        command = b""
        while command != b"finish\n":
            remaining = deadline - time.monotonic()
            require(remaining > 0, "observation deadline expired")
            readable, _, _ = select.select([descriptor, 0], [], [], remaining)
            require(not any(drain().values()), "product accessed or changed a retired store")
            if 0 in readable:
                part = os.read(0, 16)
                require(bool(part), "observation control closed before completion")
                command += part
                require(b"finish\n".startswith(command), "invalid completion request")
        require(not any(drain().values()), "retired-store event at completion")
    finally:
        os.close(descriptor)

    require((root.lstat().st_dev, root.lstat().st_ino) == parent_identity,
            "config parent identity changed")
    records = []
    for path in paths:
        require(identity(path) == before[path.name], "retired store metadata changed")
        require(path.read_bytes() == payloads[path.name], "retired store bytes changed")
        records.append({"name": path.name, "bytes": len(payloads[path.name]),
                        "sha256": hashlib.sha256(payloads[path.name]).hexdigest(),
                        "identity": before[path.name], "control_mask": controls[path.name]})
    result = {"role": role, "files": records, "product_events": 0,
              "controls": 8, "metadata_unchanged": True, "bytes_unchanged": True}
    with open("/tmp/account-store-observation.json", "x", encoding="utf-8") as output:
        json.dump(result, output, sort_keys=True)
        output.write("\n")


if __name__ == "__main__":
    try:
        run()
    except (OSError, RuntimeError) as error:
        print("account-store observation failed: " + str(error), file=sys.stderr)
        sys.exit(1)
