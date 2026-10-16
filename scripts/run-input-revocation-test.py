#!/usr/bin/env python3
"""Observe keyboard restriction through real production input workers and XTEST."""
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


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            value.update(chunk)
    return value.hexdigest()


def main():
    require(os.getuid() == os.getgid() == 1000 and Path("/.dockerenv").is_file(),
            "input revocation requires the isolated nonroot container")
    require(len(sys.argv) == 2 and re.fullmatch(
        r"/cargo-target/debug/deps/librustdesk-[0-9a-f]{16}", sys.argv[1]),
        "native artifact path differs")
    executable = Path(sys.argv[1])
    metadata = executable.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == metadata.st_gid == 1000
            and metadata.st_nlink == 1 and os.access(executable, os.X_OK),
            "native artifact authority differs")
    provider = Path("/usr/lib/rustdesk-fork/libxdo.so.3")
    for path in (provider.parent, *provider.parent.parents):
        metadata = path.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0
                and not stat.S_IMODE(metadata.st_mode) & 0o022,
                "native provider ancestry differs")
    metadata = provider.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == metadata.st_gid == 0
            and stat.S_IMODE(metadata.st_mode) == 0o644 and metadata.st_nlink == 1,
            "native provider authority differs")
    artifact_hash, provider_hash = digest(executable), digest(provider)
    socket, lock = Path("/tmp/.X11-unix/X96"), Path("/tmp/.X96-lock")
    require(not os.path.lexists(socket) and not os.path.lexists(lock), "X11 endpoint exists")
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/tmp/home",
                   "DISPLAY": ":96", "XDG_SESSION_TYPE": "x11",
                   "XKB_CONFIG_ROOT": "/usr/share/X11/xkb",
                   "LD_LIBRARY_PATH": "/xvfb-root/usr/lib/x86_64-linux-gnu"}
    with open("/tmp/input-revocation-xvfb.log", "xb") as log:
        server = subprocess.Popen(
            ["/xvfb-root/usr/bin/Xvfb", ":96", "-screen", "0", "320x240x24",
             "-nolisten", "tcp", "-ac", "-noreset"],
            env=environment, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while not socket.is_socket():
                require(server.poll() is None and time.monotonic() < deadline,
                        "private X11 readiness failed")
                time.sleep(0.05)
            result = subprocess.run(
                [str(executable),
                 "server::connection::input_release_native_tests::keyboard_disable_retires_native_ownership_before_return",
                 "--exact", "--ignored", "--nocapture", "--color", "never", "--test-threads=1"],
                env=environment, text=True, capture_output=True, timeout=25)
            print(result.stdout, end="", flush=True)
            sys.stderr.write(result.stderr)
            require(result.returncode == 0, f"input revocation failed: status={result.returncode}")
            require("test result: ok. 1 passed; 0 failed; 0 ignored;" in result.stdout,
                    "exact native input case did not execute")
            require(result.stdout.count("INPUT_REVOCATION_NATIVE=pass workers=2 shared_modifier=preserved "
                    "foreign_key=preserved disable=before-return duplicate=inert reenable=same-worker "
                    "cleanup=joined network_auth=false") == 1,
                    "native input revocation observation differs")
            require(server.poll() is None, "private X11 exited during the native case")
        finally:
            if server.poll() is None:
                server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
                raise RuntimeError("private X11 required forced retirement")
            require(server.returncode == 0 and not socket.exists() and not lock.exists(),
                    "private X11 retirement differs")
    require(digest(executable) == artifact_hash and digest(provider) == provider_hash,
            "executed native artifact or provider changed")
    print(f"INPUT_REVOCATION_PROVIDER=observed sha256={provider_hash} "
          "source=checked-in-unmodified unchanged=before-after", flush=True)
    print("INPUT_REVOCATION_X11=pass server=owned network=none endpoint=absent cleanup=joined",
          flush=True)


if __name__ == "__main__":
    main()
