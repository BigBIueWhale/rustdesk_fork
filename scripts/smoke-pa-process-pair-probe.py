#!/usr/bin/env python3
"""Probe the production CM's _pa listener from an unrelated same-UID process.

The earlier request-first handler waited one second for a silent wrong peer. This
probe requires kernel-identified production CM ownership and an earlier close;
it does not claim that an authorized subscriber can capture audio.
"""

import os
import socket
import stat
import struct
import sys
import time


def fail(message):
    raise SystemExit("PA process-pair probe: " + message)


def process_identity(pid):
    try:
        with open(f"/proc/{pid}/stat", "rb") as stream:
            raw = stream.read(65537)
    except FileNotFoundError:
        return None
    if len(raw) > 65536 or b") " not in raw:
        fail(f"invalid process stat for {pid}")
    fields = raw.rsplit(b") ", 1)[1].split()
    if len(fields) < 20:
        fail(f"short process stat for {pid}")
    try:
        parent, started = int(fields[1]), int(fields[19])
    except ValueError:
        fail(f"invalid process identity for {pid}")
    if started <= 0:
        fail(f"nonpositive process start for {pid}")
    return fields[0], parent, started


def same_image_cm(pid, server_pid, executable_identity, uid):
    identity = process_identity(pid)
    if identity is None or identity[0] in (b"Z", b"X") or identity[1] != server_pid:
        return None
    try:
        image = os.stat(f"/proc/{pid}/exe")
        with open(f"/proc/{pid}/cmdline", "rb") as stream:
            command = stream.read(4097)
        with open(f"/proc/{pid}/status", encoding="ascii") as stream:
            uids = next((line.split()[1:] for line in stream if line.startswith("Uid:")), [])
    except FileNotFoundError:
        return None
    if len(command) > 4096 or not command.endswith(b"\0"):
        fail("CM command line is absent or exceeds its bound")
    if (image.st_dev, image.st_ino) != executable_identity:
        return None
    if command[:-1].split(b"\0")[-1:] != [b"--cm"]:
        return None
    if uids != [str(uid)] * 4:
        fail("the production CM does not have the expected UID")
    return identity[2]


def main():
    if len(sys.argv) != 4:
        fail("expected SERVER_PID SERVER_START EXECUTABLE")
    try:
        server_pid = int(sys.argv[1])
        server_start = int(sys.argv[2])
    except ValueError:
        fail("server identity is malformed")
    executable = sys.argv[3]
    uid = os.getuid()
    if uid == 0 or os.geteuid() != uid or server_pid <= 0 or server_start <= 0:
        fail("probe principal or server identity differs")
    if os.getppid() == server_pid:
        fail("probe is a direct child of the production server")
    image = os.stat(executable)
    if not stat.S_ISREG(image.st_mode) or not image.st_mode & 0o111:
        fail("production executable is not an executable regular file")
    executable_identity = image.st_dev, image.st_ino
    parent = f"/tmp/RustDesk-{uid}"
    endpoint = parent + "/ipc_pa"
    deadline = time.monotonic() + 5
    cm_pid = cm_start = None
    while time.monotonic() < deadline:
        server = process_identity(server_pid)
        if server is None or server[0] in (b"Z", b"X") or server[2] != server_start:
            fail("production server identity retired during probe")
        running_image = os.stat(f"/proc/{server_pid}/exe")
        if (running_image.st_dev, running_image.st_ino) != executable_identity:
            fail("production server image changed during probe")
        candidates = []
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            pid = int(name)
            started = same_image_cm(pid, server_pid, executable_identity, uid)
            if started is not None:
                candidates.append((pid, started))
        if len(candidates) > 1:
            fail("multiple production CM children match the server")
        if candidates and os.path.exists(endpoint):
            cm_pid, cm_start = candidates[0]
            break
        time.sleep(0.02)
    if cm_pid is None:
        fail("the production CM and _pa endpoint did not become ready")
    parent_stat = os.lstat(parent)
    endpoint_stat = os.lstat(endpoint)
    if (not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != uid
            or stat.S_IMODE(parent_stat.st_mode) != 0o700
            or not stat.S_ISSOCK(endpoint_stat.st_mode) or endpoint_stat.st_uid != uid
            or stat.S_IMODE(endpoint_stat.st_mode) != 0o600):
        fail("production _pa endpoint filesystem authority differs")

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(0.75)
        started = time.monotonic()
        stream.connect(endpoint)
        peer_pid, peer_uid, _ = struct.unpack(
            "3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        )
        if (peer_pid, peer_uid) != (cm_pid, uid):
            fail("kernel socket peer is not the exact production CM child")
        try:
            response = stream.recv(1)
        except socket.timeout:
            fail("unrelated same-UID caller held the _pa listener for 750 ms")
        elapsed_ms = int((time.monotonic() - started) * 1000)
        if response != b"":
            fail("unrelated same-UID caller received a _pa response")
        if elapsed_ms >= 750:
            fail("unrelated same-UID caller was not disconnected within 750 ms")
    if same_image_cm(cm_pid, server_pid, executable_identity, uid) != cm_start:
        fail("production CM identity changed during the negative request")
    server = process_identity(server_pid)
    if server is None or server[0] in (b"Z", b"X") or server[2] != server_start:
        fail("production server exited during the negative request")
    print(f"PA_PRODUCTION_CM_IDENTITY server_pid={server_pid} cm_pid={cm_pid} "
          f"cm_start={cm_start} kernel_peer_uid={peer_uid} refusal_ms={elapsed_ms}")
    print("PA_PRODUCTION_CM_REFUSAL=pass principal=same-uid-unrelated-process "
          "action=silent-connect result=eof-before-750ms endpoint=cm-owned-pa "
          "server=production network=container-loopback")


if __name__ == "__main__":
    main()
