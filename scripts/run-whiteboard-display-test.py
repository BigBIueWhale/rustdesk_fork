#!/usr/bin/env python3
"""Execute the compiled whiteboard display-owner regression in a private X11 server."""
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
        r"/cargo-target/debug/deps/librustdesk-[0-9a-f]{16}", sys.argv[1]),
        "compiled library-test path differs")
    executable = Path(sys.argv[1])
    metadata = executable.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 1000
            and metadata.st_gid == 1000 and metadata.st_nlink == 1
            and os.access(executable, os.X_OK), "compiled test artifact authority differs")
    socket = Path("/tmp/.X11-unix/X98")
    lock = Path("/tmp/.X98-lock")
    require(not socket.exists() and not lock.exists(), "X11 endpoint already exists")
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/tmp/home",
                   "DISPLAY": ":98", "XDG_SESSION_TYPE": "x11",
                   "XKB_CONFIG_ROOT": "/usr/share/X11/xkb",
                   "LD_LIBRARY_PATH": "/xvfb-root/usr/lib/x86_64-linux-gnu"}
    with open("/tmp/whiteboard-xvfb.log", "xb") as log:
        server = subprocess.Popen(
            ["/xvfb-root/usr/bin/Xvfb", ":98", "-screen", "0", "320x240x24",
             "-nolisten", "tcp", "-ac", "-noreset"],
            env=environment, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while not socket.is_socket():
                require(server.poll() is None and time.monotonic() < deadline,
                        "owned Xvfb did not become ready")
                time.sleep(0.05)
            subprocess.run(
                [str(executable),
                 "whiteboard::linux::tests::r_s11hn_linux_whiteboard_retires_windows_before_event_loop_return",
                 "--exact", "--ignored", "--color", "never", "--test-threads=1"],
                env=environment, check=True, timeout=25)
            require(server.poll() is None, "owned Xvfb exited during the native test")
        finally:
            if server.poll() is None:
                server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
                raise RuntimeError("owned Xvfb required forced retirement")
            if server.returncode != 0:
                sys.stderr.write(Path("/tmp/whiteboard-xvfb.log").read_text())
            require(server.returncode == 0, "owned Xvfb terminal status differs")
            require(not socket.exists() and not lock.exists(), "Xvfb endpoint was not retired")
    print("WHITEBOARD_DISPLAY_NATIVE=pass backend=x11 pixels=server-readback owners=2 "
          "clear=exact-owner event_loop=retired window=destroyed-before-return xvfb=joined", flush=True)


if __name__ == "__main__":
    main()
