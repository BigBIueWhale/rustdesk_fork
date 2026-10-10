#!/usr/bin/env python3
"""Run actual application input workers with a protected fault-observed XDO provider."""
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


def build():
    output = Path("/provider-build/libxdo.so.3")
    require(not os.path.lexists(output), "provider output exists")
    metadata = output.parent.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 1000
            and metadata.st_gid == 1000 and stat.S_IMODE(metadata.st_mode) == 0o700,
            "provider output parent authority differs")
    source = Path(__file__).resolve().parent / "test-input-lifetime-provider.c"
    subprocess.run([
        "/usr/bin/cc", "-std=c99", "-O2", "-g0", "-fPIC", "-Wall", "-Wextra",
        "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2", "-Wformat", "-Werror=format-security",
        "-shared", "-Wl,-soname,libxdo.so.3", "-Wl,-z,defs,-z,relro,-z,now",
        "-Wl,-Bsymbolic-functions", str(source), "-lX11", "-lX11-xcb", "-lxcb",
        "-lXtst", "-ldl", "-pthread", "-o", str(output),
    ], check=True, timeout=30)
    require(0 < output.stat().st_size <= 1048576, "provider size differs")
    with output.open("rb") as library:
        require(library.read(4) == b"\x7fELF", "provider is not ELF")
    output.chmod(0o644)
    print(f"INPUT_LIFETIME_PROVIDER_BUILD=pass sha256={digest(output)} "
          "source=checked-in-with-observation-hooks execution=nonroot", flush=True)


def run(executable):
    require(re.fullmatch(r"/cargo-target/debug/deps/librustdesk-[0-9a-f]{16}", str(executable)),
            "artifact path differs")
    metadata = executable.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 1000
            and metadata.st_gid == 1000 and metadata.st_nlink == 1
            and os.access(executable, os.X_OK), "artifact authority differs")
    provider = Path("/usr/lib/rustdesk-fork/libxdo.so.3")
    for path in [provider.parent, *provider.parent.parents]:
        metadata = path.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0
                and not stat.S_IMODE(metadata.st_mode) & 0o022,
                "protected provider ancestry differs")
    metadata = provider.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
            and metadata.st_gid == 0 and metadata.st_nlink == 1
            and stat.S_IMODE(metadata.st_mode) == 0o644,
            "protected provider authority differs")
    artifact_hash, provider_hash = digest(executable), digest(provider)
    socket, lock = Path("/tmp/.X11-unix/X97"), Path("/tmp/.X97-lock")
    require(not os.path.lexists(socket) and not os.path.lexists(lock), "X11 endpoint exists")
    environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/tmp/home",
                   "DISPLAY": ":97", "XDG_SESSION_TYPE": "x11",
                   "XKB_CONFIG_ROOT": "/usr/share/X11/xkb",
                   "LD_LIBRARY_PATH": "/xvfb-root/usr/lib/x86_64-linux-gnu"}
    failures = []
    with open("/tmp/input-lifetime-xvfb.log", "xb") as log:
        server = subprocess.Popen(
            ["/xvfb-root/usr/bin/Xvfb", ":97", "-screen", "0", "320x240x24",
             "-nolisten", "tcp", "-ac", "-noreset"],
            env=environment, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 10
            while not socket.is_socket():
                require(server.poll() is None and time.monotonic() < deadline, "Xvfb readiness failed")
                time.sleep(0.05)
            for fault in ["map", "key", "cursor", "shutdown", "empty-shutdown", "failed-start"]:
                receipt_path = Path(f"/tmp/input-lifetime-{fault}.receipt")
                require(not os.path.lexists(receipt_path), "native receipt exists")
                test = (
                    "server::connection::connection_workers_native_tests::graceful_process_exit_preserves_failed_cleanup_worker_start"
                    if fault == "failed-start" else
                    "server::connection::connection_workers_native_tests::graceful_empty_process_exit_leaves_connection_workers_uninitialized"
                    if fault == "empty-shutdown" else
                    "server::connection::connection_workers_native_tests::graceful_process_exit_retires_connection_workers"
                    if fault == "shutdown" else
                    "server::connection::cursor_lifetime_native_tests::remote_cursor_retirement_waits_for_native_query_and_thread_context"
                    if fault == "cursor" else
                    "server::connection::input_lifetime_native_tests::input_workers_retire_pending_text_before_the_global_display"
                )
                arguments = [
                    str(executable), test,
                    "--exact", "--ignored", "--color", "never", "--test-threads=1",
                ]
                if fault in ("shutdown", "empty-shutdown", "failed-start"):
                    arguments.append("--nocapture")
                result = subprocess.run(arguments, env={**environment, "INPUT_LIFETIME_FAULT": fault},
                    text=True, capture_output=True, timeout=25)
                print(result.stdout, end="", flush=True)
                if result.stderr:
                    sys.stderr.write(result.stderr)
                if result.returncode != 0:
                    failures.append(f"{fault}: status={result.returncode}")
                    continue
                if fault in ("shutdown", "empty-shutdown", "failed-start"):
                    prefix = ("CONNECTION_WORKERS_FAILED_START" if fault == "failed-start" else
                              "CONNECTION_WORKERS_EMPTY" if fault == "empty-shutdown" else "CONNECTION_WORKERS")
                    admission_prefix = ("CONNECTION_FAILED_START_ADMISSION" if fault == "failed-start" else
                                        "CONNECTION_EMPTY_ADMISSION" if fault == "empty-shutdown" else "CONNECTION_ADMISSION")
                    require(result.stdout.count(f"{prefix}_ENTERED boundary=graceful-process-exit network_auth=false") == 1,
                            "production process-exit case did not execute")
                    for kind in ("Remote", "FileTransfer", "ViewCamera", "Terminal", "PortForward"):
                        require(result.stdout.count(f"{admission_prefix}_OBSERVED type={kind} accepted=") == 1,
                                "production session admission case did not execute")
                    if fault == "failed-start":
                        require(result.stdout.count("CONNECTION_START_FAILURE_OBSERVED kernel=EAGAIN admission=refused reservation=retired reuse=reserved retry=refused limit=restored recovery=joined") == 1,
                                "native startup refusal/recovery case did not execute")
                else:
                    require("test result: ok. 1 passed; 0 failed; 0 ignored;" in result.stdout,
                            "exact native test did not execute")
                fd = os.open(receipt_path, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(fd, "r") as receipt:
                    metadata = os.fstat(receipt.fileno())
                    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 1000
                            and metadata.st_gid == 1000 and metadata.st_nlink == 1
                            and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_size < 512,
                            "native receipt authority differs")
                    observation = receipt.read(513)
                expected = (
                    "CONNECTION_WORKERS_FAILED_START_NATIVE=pass boundary=graceful-process-exit cleanup=failed-start "
                    "wakelock=uninitialized named_workers=absent cursor=unstarted late_sessions=refused "
                    "types=all-five producer=resource-factory network_auth=false os_inhibitor=false\n"
                    if fault == "failed-start" else
                    "CONNECTION_WORKERS_EMPTY_NATIVE=pass boundary=graceful-process-exit owners=uninitialized "
                    "named_workers=absent cursor=unstarted late_sessions=refused types=all-five "
                    "producer=resource-factory network_auth=false os_inhibitor=false\n"
                    if fault == "empty-shutdown" else
                    "CONNECTION_WORKERS_NATIVE=pass boundary=graceful-process-exit final_remote=joined "
                    "wakelock=joined cursor=retired late_sessions=refused types=all-five producer=resource-factory "
                    "network_auth=false os_inhibitor=false\n"
                    if fault == "shutdown" else
                    "CURSOR_RECORDER_NATIVE=pass generations=32 producer=authenticated-resource-admission "
                    "query=native-x11 sharing=one-worker retirement=exact-join successor=blocked-until-tls-drop "
                    "position=observed invalidation=before-finality admission=reserved-before-await collision=refused cancel=joined reuse=current cm=unpublished descriptors=retired tasks=retired network_auth=false\n"
                    if fault == "cursor" else
                    f"INPUT_LIFETIME_NATIVE=pass fault={fault} generations=16 "
                    "workers=2 producer=typed-queue worker=production loader=protected keys=exact-owner "
                    "foreign=preserved pending=retired mapping=restored child_before_display=true "
                    "descriptors=retired tasks=retired network_auth=false\n"
                )
                print(observation, end="", flush=True)
                if observation != expected:
                    failures.append(f"{fault}: native retirement observation differs")
                    continue
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
    require(digest(executable) == artifact_hash and digest(provider) == provider_hash,
            "executed artifact/provider changed")
    print(f"INPUT_LIFETIME_PROVIDER=observed sha256={provider_hash} unchanged=before-after "
          "path=/usr/lib/rustdesk-fork/libxdo.so.3", flush=True)
    print("INPUT_LIFETIME_X11=pass server=owned network=none endpoint=absent cleanup=joined", flush=True)
    require(not failures, f"native input-lifetime failures: {', '.join(failures)}")


if __name__ == "__main__":
    require(os.getuid() == 1000 and os.getgid() == 1000 and Path("/.dockerenv").is_file(),
            "native input-lifetime execution requires the isolated nonroot container")
    require(len(sys.argv) == 2, "expected build or exact artifact")
    if sys.argv[1] == "build":
        build()
    else:
        run(Path(sys.argv[1]))
