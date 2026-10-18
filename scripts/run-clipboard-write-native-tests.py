#!/usr/bin/env python3
"""Exercise the production SET queue and native clipboard on an owned Xvfb."""
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
    require(os.getuid() == 1000 and os.getgid() == 1000, "native clipboard principal differs")
    require(len(sys.argv) == 2 and re.fullmatch(
        r"/cargo-target/debug/deps/librustdesk-[0-9a-f]{16}", sys.argv[1]),
        "clipboard artifact path differs")
    executable = Path(sys.argv[1])
    metadata = executable.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 1000
            and metadata.st_gid == 1000 and metadata.st_nlink == 1
            and os.access(executable, os.X_OK), "clipboard artifact authority differs")

    def digest():
        result = hashlib.sha256()
        with executable.open("rb") as artifact:
            for chunk in iter(lambda: artifact.read(65536), b""):
                result.update(chunk)
        return result.hexdigest()

    artifact_sha = digest()
    socket = Path("/tmp/.X11-unix/X98")
    lock = Path("/tmp/.X98-lock")
    require(not os.path.lexists(socket) and not os.path.lexists(lock), "X11 endpoint already exists")
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/tmp/home",
                   "DISPLAY": ":98", "XDG_SESSION_TYPE": "x11",
                   "RUSTDESK_CLIPBOARD_WRITE_NATIVE": "1",
                   "XKB_CONFIG_ROOT": "/usr/share/X11/xkb",
                   "LD_LIBRARY_PATH": "/xvfb-root/usr/lib/x86_64-linux-gnu"}
    with open("/tmp/clipboard-write-xvfb.log", "xb") as log:
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
                [str(executable), "clipboard::write_", "--ignored",
                 "--skip", "screenshot_copy_reports_native_backend_error",
                 "--color", "never", "--test-threads=1", "--show-output"],
                env=environment, capture_output=True, timeout=20)
            require(len(result.stdout) + len(result.stderr) <= 65536, "native clipboard output too large")
            output = result.stdout.decode("utf-8", errors="strict")
            print(output, end="", flush=True)
            if result.stderr:
                sys.stderr.write(result.stderr.decode("utf-8", errors="replace"))
            require(digest() == artifact_sha, "clipboard artifact changed during execution")
            print(f"CLIPBOARD_WRITE_NATIVE_ARTIFACT=observed sha256={artifact_sha} "
                  f"tests=7 exit_code={result.returncode} unchanged=before-after", flush=True)
            require(not os.path.lexists("/tmp/.X11-unix/X99")
                    and not os.path.lexists("/tmp/.X99-lock"), "negative X11 endpoint exists")
            absent_environment = dict(environment, DISPLAY=":99", RUSTDESK_SCREENSHOT_NO_DISPLAY="1")
            backend = subprocess.run(
                [str(executable), "clipboard::write_screenshot_native_tests::screenshot_copy_reports_native_backend_error",
                 "--exact", "--ignored", "--color", "never", "--test-threads=1", "--show-output"],
                env=absent_environment, capture_output=True, timeout=10)
            require(len(backend.stdout) + len(backend.stderr) <= 16384, "backend error output too large")
            backend_output = backend.stdout.decode("utf-8", errors="strict")
            print(backend_output, end="", flush=True)
            if backend.stderr:
                sys.stderr.write(backend.stderr.decode("utf-8", errors="replace"))
            require(digest() == artifact_sha, "clipboard artifact changed during backend refusal")
            print(f"CLIPBOARD_SCREENSHOT_ERROR_ARTIFACT=observed sha256={artifact_sha} "
                  f"tests=1 exit_code={backend.returncode} unchanged=before-after", flush=True)
            require(result.returncode == 0, f"native clipboard tests failed: {result.returncode}")
            require(backend.returncode == 0 and re.findall(
                r"^test (\S+) \.\.\. ok$", backend_output, re.MULTILINE) == [
                "clipboard::write_screenshot_native_tests::screenshot_copy_reports_native_backend_error"],
                "native screenshot backend refusal differs")
            backend_summaries = re.findall(r"^test result: .*", backend_output, re.MULTILINE)
            require(len(backend_summaries) == 1 and re.fullmatch(
                r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in [0-9.]+s",
                backend_summaries[0]),
                "native screenshot backend result differs")
            expected = {
                "clipboard::write_native_tests::live_owner_publishes_a_queued_peer_write_to_x11",
                "clipboard::write_native_tests::retired_owner_cannot_publish_a_dequeued_write_after_the_native_lock",
                "clipboard::write_permission_native_tests::disabling_viewer_clipboard_retires_a_write_waiting_for_native_admission",
                "clipboard::write_permission_native_tests::reenabling_viewer_clipboard_does_not_resurrect_an_old_queued_write",
                "clipboard::write_screenshot_native_tests::screenshot_copy_waits_for_native_publication",
                "clipboard::write_screenshot_native_tests::screenshot_copy_refuses_a_full_dispatcher",
                "clipboard::write_screenshot_native_tests::screenshot_copy_returns_payload_refusal_without_changing_clipboard",
            }
            observed = re.findall(r"^test (\S+) \.\.\. ok$", output, re.MULTILINE)
            require(len(observed) == 7 and set(observed) == expected,
                    "native clipboard test inventory differs")
            summaries = re.findall(r"^test result: .*", output, re.MULTILINE)
            require(len(summaries) == 1 and re.fullmatch(
                r"test result: ok\. 7 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in [0-9.]+s",
                summaries[0]), "native clipboard result differs")
            require(digest() == artifact_sha and server.poll() is None,
                    "clipboard artifact changed or Xvfb exited")
        finally:
            if server.poll() is None:
                server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
                raise RuntimeError("Xvfb required forced retirement")
            require(server.returncode == 0 and not os.path.lexists(socket)
                    and not os.path.lexists(lock), "Xvfb retirement differs")
    print(f"CLIPBOARD_WRITE_NATIVE=pass tests=8 artifact_sha256={artifact_sha} "
          "queue=production native=x11 retired=unchanged live=published cleanup=joined", flush=True)


if __name__ == "__main__":
    main()
