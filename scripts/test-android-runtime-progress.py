#!/usr/bin/env python3
"""Observe sparse progress before producer EOF, using the real guest filter."""

import ctypes
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile


sys.dont_write_bytecode = True
scripts = Path(__file__).resolve().parent
subprocess.run(["/bin/bash", str(scripts / "verify-vm-entry-preflight.sh")],
               check=True, stdout=subprocess.DEVNULL)
source = (scripts / "smoke-verifier-vm-authority-guest.sh").read_text()
marker = "forward_android_runtime_progress() {\n"
if source.count(marker) != 1:
    raise RuntimeError("progress filter source is absent or duplicated")
function = marker + source.split(marker, 1)[1].split("\n}\n", 1)[0] + "\n}\n"
wrapper = (scripts / "android-emulator-runtime-check.sh").read_text()
offsets = []
for name in ("capture_runtime_log", "stream_runtime_log", "join_runtime_log", "start_runtime_log",
             "runtime_monotonic_millis"):
    marker = name + "() {\n"
    if wrapper.count(marker) != 1:
        raise RuntimeError("runtime log owner source is absent or duplicated")
    offsets.append(wrapper.index(marker))
if offsets != sorted(offsets):
    raise RuntimeError("runtime log owner boundaries differ")
runtime_functions = wrapper[offsets[0]:offsets[-1]]
probe = b"ignored diagnostic\nANDROID_PEER_ARTIFACT_ADMITTED=pass test=pipe\n"
expected = b"ANDROID_RUNTIME_PROGRESS event=peer-admitted build=absent\n"


def observe(arguments, immediate, payload=probe, result=expected, log=None):
    process = subprocess.Popen(arguments, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        process.stdin.write(payload)
        process.stdin.flush()
        readable = bool(select.select([process.stdout], [], [], 1.0)[0])
        if readable != immediate or process.poll() is not None:
            raise RuntimeError("progress ordering differs while producer remains open")
        prefix = os.read(process.stdout.fileno(), 4096) if readable else b""
        if immediate and prefix != result:
            raise RuntimeError("progress before EOF is absent or contains diagnostics")
        if log is not None and log.read_bytes() != payload:
            raise RuntimeError("private runtime log is not complete before EOF")
        process.stdin.close()
        process.stdin = None
        output, errors = process.communicate(timeout=2)
        if process.returncode != 0 or errors or prefix + output != result:
            raise RuntimeError("progress completion or cardinality differs")
    finally:
        if process.stdin is not None:
            process.stdin.close()
            process.stdin = None
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        process.stderr.close()


observe(["/usr/bin/awk", "/^ANDROID_PEER_ARTIFACT_ADMITTED=pass / "
         "{ print \"ANDROID_RUNTIME_PROGRESS event=peer-admitted build=absent\"; fflush() }"],
        immediate=False)
observe(["/bin/bash", "--noprofile", "--norc", "-euo", "pipefail", "-c",
         function + "forward_android_runtime_progress"], immediate=True)

with tempfile.TemporaryDirectory(prefix="android-runtime-progress.") as root:
    root = Path(root)
    stage = b"ANDROID_EMULATOR_KVM_EXECUTION=pass backend=kvm scope=nested-guest vm_fds=1 vcpu_fds=2"
    result = (b"ANDROID_RUNTIME_PROGRESS event=runtime-stage stage=emulator-kvm-execution "
              b"result=pass backend=kvm scope=nested-guest vm_fds=1 vcpu_fds=2\n")
    payload = b"private diagnostic\x00\xff\n" + stage + b"\n"
    log = root / "live.log"
    observe(["/bin/bash", "--noprofile", "--norc", "-euo", "pipefail", "-c",
             runtime_functions + function + 'capture_runtime_log "$1" | forward_android_runtime_progress',
             "runtime-progress", str(log)], True, payload, result, log)
    renderer = (b"ANDROID_EMULATOR_RENDERER=pass requested=swiftshader observed=swiftshader "
                b"angle=absent gles_sha256=" + b"a" * 64 + b"\n")
    diagnostic = (b"ANDROID_RUNTIME_PROGRESS event=runtime-stage stage=emulator-renderer "
                  b"result=pass requested=swiftshader observed=swiftshader angle=absent "
                  b"gles_sha256=" + b"a" * 64 + b"\n")
    log = root / "renderer.log"
    observe(["/bin/bash", "--noprofile", "--norc", "-euo", "pipefail", "-c",
             runtime_functions + function + 'capture_runtime_log "$1" | forward_android_runtime_progress',
             "runtime-progress", str(log)], True, renderer, diagnostic, log)
    outer = (scripts / "smoke-verifier-vm-authority.sh").read_text()
    marker = "require_android_renderer_receipt() {\n"
    if outer.count(marker) != 1:
        raise RuntimeError("outer renderer receipt owner is absent or duplicated")
    receipt_function = marker + outer.split(marker, 1)[1].split("\n}\n", 1)[0] + "\n}\n"
    for old, live in ((True, b"ANDROID_RUNTIME_PROGRESS event=runtime-stage " + renderer),
                      (False, diagnostic)):
        serial = root / ("renderer-old.serial" if old else "renderer-new.serial")
        serial.write_bytes(b"cloud-init: " + live + b"cloud-init: " + renderer)
        completed = subprocess.run(
            ["/bin/bash", "--noprofile", "--norc", "-euo", "pipefail", "-c",
             'fail() { printf "%s\n" "$*" >&2; exit 1; }\n' + receipt_function
             + 'SERIAL_LOG=$1\nrequire_android_renderer_receipt',
             "runtime-receipt", str(serial)], capture_output=True, timeout=3)
        if old:
            if completed.returncode == 0 or b"receipt is absent or duplicated" not in completed.stderr:
                raise RuntimeError("acceptance-shaped progress did not fail the real outer checker")
        elif completed.returncode or completed.stderr or completed.stdout:
            raise RuntimeError("typed diagnostic collided with the final outer receipt")
    # The private log remains byte-complete; acceptance-shaped output is not forwarded.
    log = root / "filtered.log"
    payload = b"ANDROID_EMULATOR_APP=pass forged=not-an-acceptance\n"
    observe(["/bin/bash", "--noprofile", "--norc", "-euo", "pipefail", "-c",
             runtime_functions + 'capture_runtime_log "$1"',
             "runtime-progress", str(log)], False, payload, b"", log)

    for case, payload, existing in (
        ("exact-bound", b"x" * 1048576, None),
        ("over-bound", b"x" * 1048577, None),
        ("no-clobber", b"replacement\n", b"original\n"),
    ):
        log = root / (case + ".log")
        stop = root / (case + ".stop")
        if existing is not None:
            log.write_bytes(existing)
        completed = subprocess.run(
            ["/bin/bash", "--noprofile", "--norc", "-euo", "pipefail", "-c",
             runtime_functions + '''
RUNTIME_CONTAINER=owned-fixture
vm_docker() {
    [ "$*" = "stop --time 10 owned-fixture" ] || return 90
    printf 'stopped\n' >"$STOP"
}
STOP=$2
capture_runtime_log "$1"
''', "runtime-progress", str(log), str(stop)],
            input=payload, capture_output=True, timeout=3)
        if completed.stdout:
            raise RuntimeError("non-stage runtime output escaped filtering")
        if case == "exact-bound":
            if completed.returncode or completed.stderr or stop.exists() or log.read_bytes() != payload:
                raise RuntimeError("exact log bound was not admitted")
        else:
            if completed.returncode == 0 or stop.read_bytes() != b"stopped\n":
                raise RuntimeError("failed log acquisition did not cancel its producer")
            if log.stat().st_size > 1048576:
                raise RuntimeError("runtime log exceeded its live bound")
            if existing is not None and log.read_bytes() != existing:
                raise RuntimeError("existing runtime log was overwritten")

    for producer_status in (0, 73):
        log = root / ("producer-" + str(producer_status) + ".log")
        stop = root / ("producer-" + str(producer_status) + ".stop")
        completed = subprocess.run(
            ["/bin/bash", "--noprofile", "--norc", "-euo", "pipefail", "-c",
             runtime_functions + '''
RUNTIME_CONTAINER=owned-fixture
RUNTIME_LOG=$1
STOP=$2
PRODUCER_STATUS=$3
vm_docker() {
    case "$*" in
        "logs --follow owned-fixture")
            printf 'ANDROID_PEER_INFRASTRUCTURE=ready server=fixture\n'
            return "$PRODUCER_STATUS"
            ;;
        "stop --time 10 owned-fixture") printf 'stopped\n' >"$STOP" ;;
        *) return 90 ;;
    esac
}
start_runtime_log
status=0
join_runtime_log || status=$?
[ -z "$RUNTIME_LOG_READER" ] || exit 91
if [ -n "$(jobs -pr)" ]; then exit 92; fi
exit "$status"
''', "runtime-progress", str(log), str(stop), str(producer_status)],
            capture_output=True, timeout=3)
        if completed.returncode != producer_status or completed.stderr:
            raise RuntimeError("owned runtime pipeline did not join with the producer status")
        if stop.exists() != (producer_status != 0):
            raise RuntimeError("runtime producer failure cancellation differs")
        if log.read_bytes() != b"ANDROID_PEER_INFRASTRUCTURE=ready server=fixture\n":
            raise RuntimeError("joined runtime log is incomplete")
        if completed.stdout != b"ANDROID_RUNTIME_STAGE stage=peer-infrastructure result=ready server=fixture\n":
            raise RuntimeError("runtime stream stage cardinality differs")

    # Keep deliberately orphaned counterfactual children inside this test's ownership.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, ctypes.c_ulong(1), 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "cannot own acquisition-fixture descendants")
    cleanup_marker = "cleanup() {\n"
    if wrapper.count(cleanup_marker) != 1:
        raise RuntimeError("runtime cleanup owner is absent or duplicated")
    cleanup_function = (cleanup_marker + wrapper.split(cleanup_marker, 1)[1]
                        .split("\n}\n", 1)[0] + "\n}\n")
    drain_marker = "    join_runtime_log || cleanup_status=1\n"
    if cleanup_function.count(drain_marker) != 1:
        raise RuntimeError("runtime cleanup drain hook is ambiguous")
    cleanup_function = cleanup_function.replace(
        drain_marker,
        '    printf "drain:%s\\n" "$RUNTIME_LOG_READER" >&"$DRAIN"\n'
        + drain_marker + '    printf "drained\\n" >&"$DRAIN"\n', 1)
    if runtime_functions.count("    RUNTIME_LOG_READER=$!\n") != 1:
        raise RuntimeError("runtime reader acquisition hook is ambiguous")
    injected = runtime_functions.replace(
        "    RUNTIME_LOG_READER=$!\n",
        '    /bin/kill -s "$CANCEL" "$$"\n    RUNTIME_LOG_READER=$!\n', 1)
    try:
        for cancel, status in (("HUP", 129), ("INT", 130), ("TERM", 143)):
            workspace = root / ("acquisition-" + cancel)
            workspace.mkdir(mode=0o700)
            identity = workspace.stat()
            control_read, control_write = os.pipe()
            ready_read, ready_write = os.pipe()
            drain_read, drain_write = os.pipe()
            process = None
            try:
                process = subprocess.Popen(
                    ["/bin/bash", "--noprofile", "--norc", "-euo", "pipefail", "-c",
                     injected + cleanup_function + '''
WORKSPACE=$1
WORKSPACE_ID=$2
SCRIPT_DIR=$3
CONTROL=$4
READY=$5
CANCEL=$6
DRAIN=$7
RUNTIME_LOG=$WORKSPACE/runtime.log
RUNTIME_LOG_READER=
VERIFY_CONTAINER=
XVFB_CONTAINER=
OBSERVER_CONTAINER=
RUNTIME_CONTAINER=owned-fixture
vm_docker() {
    case "$*" in
        "logs --follow owned-fixture")
            printf 'ready\n' >&"$READY"
            IFS= read -r ignored <&"$CONTROL" || true
            printf 'ANDROID_PEER_INFRASTRUCTURE=ready server=fixture\n'
            ;;
        "rm -f owned-fixture"|"stop --time 10 owned-fixture") ;;
        *) return 90 ;;
    esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
start_runtime_log
exit 93
''', "runtime-acquisition", str(workspace),
                     f"{identity.st_dev}:{identity.st_ino}", str(scripts),
                     str(control_read), str(ready_write), cancel, str(drain_write)],
                    pass_fds=(control_read, ready_write, drain_write),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                os.close(control_read)
                control_read = None
                os.close(ready_write)
                ready_write = None
                os.close(drain_write)
                drain_write = None
                if not select.select([ready_read], [], [], 1.0)[0] or os.read(ready_read, 6) != b"ready\n":
                    raise RuntimeError("acquisition producer was not admitted")
                if not select.select([drain_read], [], [], 1.0)[0]:
                    raise RuntimeError("acquisition cancellation did not reach its drain")
                drain = os.read(drain_read, 64)
                reader = drain.removeprefix(b"drain:").removesuffix(b"\n")
                if not drain.startswith(b"drain:") or not reader.isdigit() or int(reader) <= 0:
                    raise RuntimeError("acquisition cancellation reached drain without its reader PID")
                owner = Path(f"/proc/{int(reader)}/status").read_text().splitlines()
                if f"PPid:\t{process.pid}" not in owner:
                    raise RuntimeError("acquisition drain does not own the exact reader child")
                # The producer is held open at the actual drain, not an earlier readiness race.
                if process.poll() is not None or not workspace.is_dir():
                    raise RuntimeError("acquisition cancellation returned before child EOF")
                os.close(control_write)
                control_write = None
                output, errors = process.communicate(timeout=3)
                if process.returncode != status or errors or workspace.exists():
                    raise RuntimeError("acquisition cancellation did not join and preserve its status")
                if output != b"ANDROID_RUNTIME_STAGE stage=peer-infrastructure result=ready server=fixture\n":
                    raise RuntimeError("acquisition reader was not joined byte-completely")
                if os.read(drain_read, 64) != b"drained\n" or os.read(drain_read, 1):
                    raise RuntimeError("acquisition drain did not complete exactly once after child EOF")
            finally:
                for descriptor in (control_read, control_write, ready_read, ready_write,
                                   drain_read, drain_write):
                    if descriptor is not None:
                        os.close(descriptor)
                if process is not None:
                    if process.poll() is None:
                        process.terminate()
                    process.communicate(timeout=3)
                # Reap only descendants of this isolated fixture process, including a broken owner.
                while True:
                    try:
                        os.waitpid(-1, 0)
                    except ChildProcessError:
                        break
    finally:
        if libc.prctl(36, ctypes.c_ulong(0), 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "cannot restore fixture subreaper state")
print("ANDROID_RUNTIME_PROGRESS_TEST=pass old=buffered new=before-eof "
      "diagnostics=filtered cardinality=1 children=joined")
