#!/usr/bin/env python3
"""Create and retire root-owned namespace fixtures only in the disposable verifier VM."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys

ROOT = Path("/var/tmp/rustdesk-verifier-authority")
FIXTURE = ROOT / "trusted-executable-fixture"
MANIFEST = ROOT / "trusted-executable-fixture.manifest.json"
CONTAINER_ROOT = "/trusted-executable-fixture"
MODULES = ("shared", "system", "authorization", "terminal")


def guard():
    marker = Path("/run/rustdesk-verifier-vm").lstat()
    if (os.geteuid() != 0 or not stat.S_ISDIR(marker.st_mode) or marker.st_uid != 0
            or Path("/proc/1/comm").read_text().strip() != "systemd"
            or sorted(p.name for p in Path("/sys/class/net").iterdir()) != ["lo"]
            or Path(__file__).resolve() != ROOT / "focused-rust-test-source/scripts" / Path(__file__).name):
        raise ValueError("namespace fixture requires the exact disposable verifier VM")


def directory(path, mode=0o755, uid=0, gid=0):
    path.mkdir(mode=0o700)
    os.chown(path, uid, gid)
    path.chmod(mode)


def file(path, data, mode=0o755):
    with path.open("xb") as stream:
        stream.write(data)
        os.fchmod(stream.fileno(), mode)


def inventory():
    result = []
    def visit(path):
        meta = path.lstat()
        item = dict(path=str(path.relative_to(FIXTURE)), dev=meta.st_dev, ino=meta.st_ino,
                    uid=meta.st_uid, gid=meta.st_gid, mode=stat.S_IMODE(meta.st_mode), links=meta.st_nlink)
        if stat.S_ISLNK(meta.st_mode):
            item.update(kind="link", target=os.readlink(path))
        elif stat.S_ISREG(meta.st_mode):
            if meta.st_size > 4096 or meta.st_nlink != 1:
                raise ValueError("fixture file exceeds its authority bound")
            item.update(kind="file", sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        elif stat.S_ISDIR(meta.st_mode):
            item["kind"] = "directory"
        elif stat.S_ISFIFO(meta.st_mode):
            item["kind"] = "fifo"
        else:
            raise ValueError("unexpected namespace fixture object")
        result.append(item)
        if len(result) > 192:
            raise ValueError("namespace fixture exceeds its node bound")
        if item["kind"] == "directory":
            for child in sorted(path.iterdir()):
                visit(child)
    visit(FIXTURE)
    return result


def create():
    directory(FIXTURE)
    directory(FIXTURE / "trusted")
    directory(FIXTURE / "trusted/bin")
    directory(FIXTURE / "trusted/links")
    helper = b"#!/bin/sh\nprintf 'legitimate:'\n/usr/bin/id -u\n"
    file(FIXTURE / "trusted/bin/helper", helper)
    file(FIXTURE / "trusted/bin/noexec", helper, 0o644)
    file(FIXTURE / "trusted/bin/writable", helper, 0o777)
    os.mkfifo(FIXTURE / "trusted/bin/fifo", 0o600)
    links = FIXTURE / "trusted/links"
    for name, target in [("relative", "../bin/helper"), ("parent", "../bin/../bin/helper"),
                         ("absolute", CONTAINER_ROOT + "/trusted/bin/helper"),
                         ("file-slash", "../bin/helper/"), ("file-dot", "../bin/helper/."),
                         ("cycle-a", "cycle-b"), ("cycle-b", "cycle-a")]:
        (links / name).symlink_to(target)
    for index in reversed(range(40)):
        (links / f"hop-{index}").symlink_to("../bin/helper" if index == 39 else f"hop-{index + 1}")
    (links / "hop-41").symlink_to("hop-0")
    for kind in ("owner", "group", "world"):
        directory(FIXTURE / kind)
        for module in MODULES:
            parent = FIXTURE / kind / module
            directory(parent, 0o755 if kind == "owner" else (0o770 if kind == "group" else 0o777),
                      1000 if kind == "owner" else 0, 1000 if kind == "group" else 0)
            directory(parent / "bin")
            file(parent / "bin/helper", helper)
    directory(FIXTURE / "hidden")
    directory(FIXTURE / "user-links")
    for module in MODULES:
        directory(FIXTURE / "hidden" / module)
        user = FIXTURE / "user-links" / module
        directory(user, uid=1000, gid=1000)
        (user / "tool").symlink_to("/usr/bin/false")
        os.lchown(user / "tool", 1000, 1000)
        (FIXTURE / "hidden" / module / "helper").symlink_to(CONTAINER_ROOT + "/user-links/" + module + "/tool")
    records = inventory()
    data = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    file(MANIFEST, data, 0o600)
    print(f"TRUSTED_EXECUTABLE_FIXTURE=created nodes={len(records)} manifest_sha256={hashlib.sha256(data).hexdigest()}", flush=True)


def retire():
    info = MANIFEST.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 65536):
        raise ValueError("namespace fixture manifest authority differs")
    data = MANIFEST.read_bytes()
    records = json.loads(data)
    if inventory() != records:
        raise ValueError("namespace fixture identities, permissions or contents changed")
    shutil.rmtree(FIXTURE)
    if FIXTURE.exists():
        raise ValueError("namespace fixture root remains")
    MANIFEST.unlink()
    print(f"TRUSTED_EXECUTABLE_FIXTURE=retired nodes={len(records)} manifest_sha256={hashlib.sha256(data).hexdigest()} identities=preserved container=removed", flush=True)


if __name__ == "__main__":
    guard()
    if sys.argv[1:] == ["create"]:
        create()
    elif sys.argv[1:] == ["retire"]:
        retire()
    else:
        raise SystemExit("namespace fixture phase differs")
