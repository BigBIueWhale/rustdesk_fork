#!/usr/bin/env python3
"""Observe sparse progress before producer EOF, using the real guest filter."""

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
for name in ("capture_runtime_log", "stream_runtime_log", "join_runtime_log",
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
    result = b"ANDROID_RUNTIME_PROGRESS event=runtime-stage " + stage + b"\n"
    payload = b"private diagnostic\x00\xff\n" + stage + b"\n"
    log = root / "live.log"
    observe(["/bin/bash", "--noprofile", "--norc", "-euo", "pipefail", "-c",
             runtime_functions + function + 'capture_runtime_log "$1" | forward_android_runtime_progress',
             "runtime-progress", str(log)], True, payload, result, log)
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
stream_runtime_log &
RUNTIME_LOG_READER=$!
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
        if completed.stdout != b"ANDROID_RUNTIME_STAGE ANDROID_PEER_INFRASTRUCTURE=ready server=fixture\n":
            raise RuntimeError("runtime stream stage cardinality differs")
print("ANDROID_RUNTIME_PROGRESS_TEST=pass old=buffered new=before-eof "
      "diagnostics=filtered cardinality=1 children=joined")
