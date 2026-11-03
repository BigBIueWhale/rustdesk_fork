#!/usr/bin/env python3
"""Native cursor image ownership; only Flutter method values are doubled."""
import hashlib
import os
from pathlib import Path
import subprocess
import time


def require(value, message):
    if not value:
        raise RuntimeError(message)


def main():
    require(os.getuid() == os.getgid() == 4000, "fixture principal differs")
    source = Path("/work/flutter/third_party/flutter_custom_cursor/linux/flutter_custom_cursor_plugin.cc")
    fixture = Path("/work/scripts/test-linux-cursor-image.cc")
    data = source.read_bytes()
    text = data.decode("utf-8")
    functions = []
    for begin, end in (
        ("static string create_custom_cursor(", "\nstatic bool set_custom_cursor("),
        ("static bool delete_custom_cursor(", "\n// Called when a method call"),
    ):
        require(text.count(begin) == text.count(end) == 1, "function boundary differs")
        start, stop = text.index(begin), text.index(end)
        require(start < stop, "function order differs")
        functions.append(text[start:stop])
    fragment = Path("/build/cursor-plugin-functions.inc")
    fragment.write_text("\n".join(functions))
    binary = Path("/build/cursor-image-test")
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/tmp",
                   "DISPLAY": ":98", "GDK_BACKEND": "x11", "G_DEBUG": "fatal-warnings",
                   "XKB_CONFIG_ROOT": "/usr/share/X11/xkb",
                   "LD_LIBRARY_PATH": "/xvfb-root/usr/lib/x86_64-linux-gnu"}
    flags = subprocess.check_output(
        ["pkg-config", "--cflags", "--libs", "gtk+-3.0", "xfixes", "x11"],
        env=environment, text=True, timeout=5).split()
    subprocess.run(["g++", "-std=c++14", "-O0", "-g0", "-Wall", "-Wextra",
                    "-I/build", str(fixture), *flags, "-o", str(binary)],
                   env=environment, check=True, timeout=30)
    print("CURSOR_IMAGE_BUILD " + " ".join(
        f"{name}={hashlib.sha256(path.read_bytes()).hexdigest()}"
        for name, path in (("plugin", source), ("fixture", fixture),
                           ("functions", fragment), ("binary", binary))), flush=True)
    server = None
    with Path("/tmp/cursor-image-xvfb.log").open("xb") as log:
        try:
            server = subprocess.Popen(
                ["/xvfb-root/usr/bin/Xvfb", ":98", "-screen", "0", "640x480x24",
                 "-nolisten", "tcp", "-ac", "-noreset"],
                env=environment, stdout=log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 10
            while not Path("/tmp/.X11-unix/X98").is_socket():
                require(server.poll() is None and time.monotonic() < deadline,
                        "owned Xvfb not ready")
                time.sleep(0.05)
            result = subprocess.run([str(binary)], env=environment,
                                    capture_output=True, text=True, timeout=30)
            require(len(result.stdout) + len(result.stderr) < 16384, "output bound exceeded")
            print(result.stdout, end="", flush=True)
            print(result.stderr, end="", flush=True)
            require(server.poll() is None, "owned Xvfb exited during test")
        finally:
            if server is not None:
                if server.poll() is None:
                    server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()
                    raise RuntimeError("owned Xvfb required forced retirement")
    require(server.returncode == 0, "owned Xvfb terminal status differs")
    require(not Path("/tmp/.X11-unix/X98").exists() and not Path("/tmp/.X98-lock").exists(),
            "owned Xvfb endpoints remain")
    print("CURSOR_IMAGE_SERVER=retired child=joined socket=absent lock=absent", flush=True)
    require(result.returncode == 0 and not result.stderr, "native cursor ownership failed")
    require(result.stdout.splitlines() == [
        "CURSOR_IMAGE_OBSERVER=pass retained=observed finalization=observed",
        "CURSOR_IMAGE_RESULT registrations=128 native_shapes=128 cache_entries=0 copies=128 finalized=128 retained=0",
        "CURSOR_IMAGE_CLEANUP=pass images=finalized window=destroyed",
    ], "native cursor result differs")
    require(source.read_bytes() == data, "plugin source changed")
    print("LINUX_CURSOR_IMAGE_NATIVE=pass registrations=128 shapes=128 images=finalized "
          "gtk=real xfixes=real codec=double scope=component network=none cleanup=joined")


if __name__ == "__main__":
    main()
