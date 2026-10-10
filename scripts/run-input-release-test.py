#!/usr/bin/env python3
"""Observe production physical-lease teardown in a private X11 server."""
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    require(os.getuid() == 1000 and os.getgid() == 1000, "native test principal differs")
    require(len(sys.argv) == 2 and re.fullmatch(
        r"/cargo-target/debug/deps/librustdesk-[0-9a-f]{16}", sys.argv[1]), "test artifact path differs")
    executable = Path(sys.argv[1])
    metadata = executable.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 1000
            and metadata.st_gid == 1000 and metadata.st_nlink == 1
            and os.access(executable, os.X_OK), "test artifact authority differs")
    def artifact_digest():
        digest = hashlib.sha256()
        with executable.open("rb") as artifact:
            for chunk in iter(lambda: artifact.read(65536), b""):
                digest.update(chunk)
        return digest.digest()

    digest = artifact_digest()
    socket = Path("/tmp/.X11-unix/X98")
    lock = Path("/tmp/.X98-lock")
    require(not os.path.lexists(socket) and not os.path.lexists(lock), "X11 endpoint exists")
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/tmp/home",
                   "DISPLAY": ":98", "XDG_SESSION_TYPE": "x11",
                   "XKB_CONFIG_ROOT": "/usr/share/X11/xkb",
                   "LD_LIBRARY_PATH": "/xvfb-root/usr/lib/x86_64-linux-gnu"}
    subprocess.run([str(executable), "server::connection::desktop_input_queue_tests::desktop_key_",
                    "--color", "never", "--test-threads=1"],
                   env=environment, check=True, timeout=25)
    require(artifact_digest() == digest, "artifact changed during ownership model tests")
    receipt_path = Path("/tmp/input-release-native.receipt")
    require(not os.path.lexists(receipt_path), "native receipt already exists")
    with open("/tmp/input-release-xvfb.log", "xb") as log:
        server = subprocess.Popen(
            ["/xvfb-root/usr/bin/Xvfb", ":98", "-screen", "0", "320x240x24",
             "-nolisten", "tcp", "-ac", "-noreset"],
            env=environment, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while not socket.is_socket():
                require(server.poll() is None and time.monotonic() < deadline, "Xvfb readiness failed")
                time.sleep(0.05)
            result = subprocess.run(
                [str(executable),
                 "server::connection::input_release_native_tests::physical_lease_retirement_survives_unavailable_keyboard_state",
                 "--exact", "--ignored", "--color", "never", "--test-threads=1"],
                env=environment, text=True, capture_output=True, timeout=25)
            print(result.stdout, end="", flush=True)
            if result.stderr:
                sys.stderr.write(result.stderr)
            require(result.returncode == 0, f"native physical-lease test failed: status={result.returncode}")
            require("test result: ok. 1 passed; 0 failed; 0 ignored;" in result.stdout,
                    "exact native test did not execute")
            receipt_fd = os.open(receipt_path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(receipt_fd, "r") as receipt:
                metadata = os.fstat(receipt.fileno())
                require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 1000
                        and metadata.st_gid == 1000 and metadata.st_nlink == 1
                        and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_size < 512,
                        "native receipt authority differs")
                observation = receipt.read(513)
            require(observation == "INPUT_RELEASE_NATIVE=pass cases=16 shared_owners=2 "
                    "prior_owner_retirement=no-events final_owner_release=exact-key foreign_key=preserved "
                    "keyboard_state=unavailable ordinary_admission=refused registry=retired "
                    "descriptors=retired whole_app=false\n", "native observation differs")
            print(observation, end="", flush=True)
            require(artifact_digest() == digest, "artifact changed")
            require(server.poll() is None, "Xvfb exited during the test")
        finally:
            if server.poll() is None:
                server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
                raise RuntimeError("Xvfb required forced retirement")
            require(server.returncode == 0 and not socket.exists() and not lock.exists(),
                    "Xvfb retirement differs")
    print("INPUT_RELEASE_X11=pass server=owned network=none endpoint=absent cleanup=joined", flush=True)


if __name__ == "__main__":
    main()
