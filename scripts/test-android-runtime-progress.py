#!/usr/bin/env python3
"""Observe sparse progress before producer EOF, using the real guest filter."""

import ctypes
import hashlib
import os
from pathlib import Path
import select
import shlex
import signal
import socket
import subprocess
import sys
import tempfile


sys.dont_write_bytecode = True
scripts = Path(__file__).resolve().parent
subprocess.run(["/bin/bash", str(scripts / "verify-vm-entry-preflight.sh")],
               check=True, stdout=subprocess.DEVNULL)

capture_source = scripts / "bounded-unix-stream-capture.py"
for case in ("valid", "occupied", "symlink", "overflow"):
    with tempfile.TemporaryDirectory(prefix="verifier-serial-capture.") as root:
        root = Path(root)
        run = root / "run.abcdefghij"
        run.mkdir(mode=0o700)
        endpoint = run / "serial.sock"
        output = run / "serial.log"
        archive = root / "authority-smoke-run.abcdefghij.serial.log"
        payload = b"exact bounded serial bytes"
        limit = len(payload) - 1 if case == "overflow" else len(payload)
        if case == "occupied":
            archive.write_bytes(b"preexisting")
        elif case == "symlink":
            archive.symlink_to(run / "other")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(endpoint))
            endpoint.chmod(0o600)
            server.listen(1)
            command = [sys.executable, "-I", "-S", str(capture_source),
                       "--socket", str(endpoint), "--output", str(output),
                       "--max-bytes", str(limit), "--archive-output", str(archive)]
            if case in ("occupied", "symlink"):
                completed = subprocess.run(command, capture_output=True, timeout=3)
                if (completed.returncode == 0 or completed.stdout
                        or (case == "occupied" and archive.read_bytes() != b"preexisting")
                        or (case == "symlink" and not archive.is_symlink())):
                    raise RuntimeError(f"serial archive did not refuse {case}")
            else:
                process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
                server.settimeout(3)
                with server.accept()[0] as client:
                    client.sendall(payload)
                stdout, stderr = process.communicate(timeout=3)
                expected = (f"bounded-unix-stream-capture: PASS bytes={len(payload)} "
                            f"archive_sha256={hashlib.sha256(payload).hexdigest()}\n").encode()
                if case == "valid":
                    if (process.returncode or stderr or stdout != expected
                            or output.read_bytes() != payload
                            or archive.read_bytes() != payload
                            or archive.stat().st_nlink != 1
                            or archive.stat().st_mode & 0o777 != 0o600):
                        raise RuntimeError("bounded serial archive bytes or receipt differ")
                elif (process.returncode == 0 or stdout
                      or output.read_bytes() != payload[:limit]
                      or archive.read_bytes() != payload[:limit]):
                    raise RuntimeError("oversized serial did not fail closed at the byte limit")
print("VERIFIER_SERIAL_ARCHIVE_TEST=pass cases=4 exact=retained occupied=preserved "
      "symlink=refused overflow=bounded", file=sys.stderr)

native_image = None
if len(sys.argv) != 1:
    if (len(sys.argv) != 3 or sys.argv[1] != "--native-docker"
            or len(sys.argv[2]) != 71 or not sys.argv[2].startswith("sha256:")
            or any(value not in "0123456789abcdef" for value in sys.argv[2][7:])):
        raise RuntimeError("native Docker tests require one explicit immutable guest fixture image")
    native_image = sys.argv[2]
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
boot = (scripts / "smoke-android-emulator-boot.sh").read_text()
stage_marker = "emit_peer_presentation_stage_receipts() {\n"
if boot.count(stage_marker) != 1:
    raise RuntimeError("presentation stage receipt owner is absent or duplicated")
stage_function = (stage_marker + boot.split(stage_marker, 1)[1]
                  .split("\n}\n", 1)[0] + "\n}\n")


def stage_uuid(value):
    return f"{value:08x}-0000-4000-8000-000000000000"


# Execute the actual receipt emitter: a warm replay must not pass after an
# isolate replacement or a reset pool counter, even if every frame stage exists.
phases = (["initial"] + [f"warm-reconnect-{i}" for i in range(1, 7)]
          + [f"task-relaunch-{i}" for i in range(1, 7)])
server_stages = [
    "RUSTDESK_PRESENTATION_STAGE stage=server-independent-enqueued "
    f"connection={i + 1} display=0 wire_generation={i + 1} wall_ms=1 queue_us=0"
    for i in range(13)
]
native_stages = [
    "RUSTDESK_PRESENTATION_STAGE stage=viewer-independent-decoded "
    f"display=0 wire_generation={i + 1} mailbox_generation=1 wall_ms=1 "
    "receive_to_admit_us=0 admit_to_dequeue_us=0 decode_us=0"
    for i in range(13)
]
dart_stages = [
    "RUSTDESK_PRESENTATION_STAGE stage=dart-image-notified "
    f"session={stage_uuid(100 + i)} display=0 publication=1 wall_ms=1 "
    "event_queue_us=1 take_us=1 checkpoint_us=1 decode_commit_us=1 ui_finalize_us=1 total_us=5 "
    "image_conversions_active=1 image_conversions_waiting=0 "
    f"image_conversions_peak={2 if i <= 6 else 1} client_owner={stage_uuid(1 if i <= 6 else i)}"
    for i in range(13)
]
for case in ("valid", "warm-owner", "warm-peak", "task-initial-owner", "task-repeat-owner",
             "missing-owner", "repeat-session", "wrong-phase", "missing-stage"):
    case_dart = dart_stages.copy()
    case_phases = phases.copy()
    if case == "warm-owner":
        case_dart[3] = case_dart[3].replace("client_owner=" + stage_uuid(1),
                                          "client_owner=" + stage_uuid(50))
    elif case == "warm-peak":
        case_dart[4] = case_dart[4].replace("image_conversions_peak=2", "image_conversions_peak=1")
    elif case in ("task-initial-owner", "task-repeat-owner"):
        case_dart[8] = case_dart[8].replace("client_owner=" + stage_uuid(8),
                                          "client_owner=" + stage_uuid(1 if case == "task-initial-owner" else 7))
    elif case == "missing-owner":
        case_dart[0] = case_dart[0].split(" client_owner=", 1)[0]
    elif case == "repeat-session":
        case_dart[5] = case_dart[5].replace("session=" + stage_uuid(105),
                                          "session=" + stage_uuid(100))
    elif case == "wrong-phase":
        case_phases[2] = "task-relaunch-2"
    elif case == "missing-stage":
        case_dart.pop()
    arrays = "".join(name + "=(" + " ".join(shlex.quote(value) for value in values) + ")\n"
                     for name, values in (("PEER_PRESENTATION_PHASES", case_phases),
                                          ("PEER_SERVER_PRESENTATION_STAGES", server_stages),
                                          ("PEER_NATIVE_PRESENTATION_STAGES", native_stages),
                                          ("PEER_DART_PRESENTATION_STAGES", case_dart)))
    completed = subprocess.run(
        ["/bin/bash", "--noprofile", "--norc", "-euo", "pipefail", "-c",
         "PEER_WARM_RECONNECT_CYCLES=6\nPEER_TASK_REPLACEMENT_CYCLES=6\n" + arrays
         + stage_function + "emit_peer_presentation_stage_receipts"],
        capture_output=True, timeout=3)
    if completed.stderr or completed.returncode != (0 if case == "valid" else 1):
        raise RuntimeError(f"actual presentation-stage emitter result differs for {case}")
    if case == "valid":
        lines = completed.stdout.decode().splitlines()
        if len(lines) != 13 or any(
                not line.startswith(f"ANDROID_PEER_PRESENTATION_STAGE=pass phase={phase} ordinal={i + 1} ")
                or not line.endswith(" client_owner=" + stage_uuid(1 if i <= 6 else i))
                for i, (phase, line) in enumerate(zip(phases, lines))):
            raise RuntimeError("warm/task stage cardinality or owner binding differs")
print("ANDROID_PEER_WARM_STAGE_TEST=pass cases=9 warm_owner=preserved warm_peak=monotone "
      "task_owner=fresh missing=refused cardinality=13", file=sys.stderr)
ui_functions = ""
for name in ("ui_semantic_token_count", "assert_peer_presentation_ui_finality"):
    marker = name + "() {\n"
    if boot.count(marker) != 1:
        raise RuntimeError("presentation UI observer is absent or duplicated")
    ui_functions += marker + boot.split(marker, 1)[1].split("\n}\n", 1)[0] + "\n}\n"
with tempfile.TemporaryDirectory(prefix="android-ui-finality.") as root:
    xml = Path(root) / "window.xml"
    for case, package, enabled, controls, text in (
        ("valid", "com.carriez.flutter_hbb", "true", True, ""),
        ("empty", "com.carriez.flutter_hbb", "true", False, ""),
        ("foreign", "other.package", "true", True, ""),
        ("disabled", "com.carriez.flutter_hbb", "false", True, ""),
        ("connecting", "com.carriez.flutter_hbb", "true", True, "Connecting..."),
    ):
        child = (f'<node package="{package}" enabled="{enabled}" '
                 f'class="android.widget.Button" text="{text}"/>' if controls else "")
        xml.write_text('<hierarchy><node resource-id="android:id/content" '
                       'class="android.widget.FrameLayout">' + child + '</node></hierarchy>')
        completed = subprocess.run(
            ["/bin/bash", "--noprofile", "--norc", "-euo", "pipefail", "-c",
             'capture_unobscured_ui_hierarchy() { return 0; }\n'
             'UI_XML=$1\nAPP_PACKAGE=com.carriez.flutter_hbb\n'
             + ui_functions + 'assert_peer_presentation_ui_finality fixture',
             "ui-finality", str(xml)], capture_output=True, timeout=3)
        expected = (b"ANDROID_PEER_PRESENTATION_UI=pass phase=fixture connecting=retired "
                    b"credential=retired waiting=retired\n" if case == "valid" else
                    b"ANDROID_PEER_PRESENTATION_UI=fail phase=fixture token=Connecting... count=1\n"
                    if case == "connecting" else
                    b"ANDROID_PEER_PRESENTATION_UI=unavailable phase=fixture reason=app-controls-unobserved\n")
        if (completed.returncode != (0 if case == "valid" else 1)
                or completed.stderr or completed.stdout != expected):
            raise RuntimeError(f"actual presentation UI observer result differs for {case}")
print("ANDROID_PEER_UI_FINALITY_TEST=pass cases=5 empty=refused foreign=refused "
      "disabled=refused residual=refused observed=required", file=sys.stderr)
export_marker = "preserve_runtime_failure_log() {\n"
if wrapper.count(export_marker) != 1:
    raise RuntimeError("runtime failure-log publisher is absent or duplicated")
export_function = (export_marker + wrapper.split(export_marker, 1)[1]
                   .split("\n}\n", 1)[0] + "\n}\n")


def failure_log_receipt(payload):
    return (f"ANDROID_RUNTIME_FAILURE_LOG=retained bytes={len(payload)} "
            f"sha256={hashlib.sha256(payload).hexdigest()} verdict_input=false\n").encode()


for case in ("valid", "limit", "oversized", "symlink", "hardlink", "mode", "occupied"):
    with tempfile.TemporaryDirectory(prefix="android-failure-log.") as root:
        root = Path(root)
        output = root / "output"
        output.mkdir(mode=0o700)
        source_log = root / "runtime.log"
        payload = bytes(range(256)) * (4096 if case == "limit" else 1024)
        if case == "oversized":
            payload = b"x" * 1048577
        source_log.write_bytes(payload)
        source_log.chmod(0o600)
        if case == "symlink":
            link = root / "link"
            link.symlink_to(source_log)
            source_log = link
        elif case == "hardlink":
            os.link(source_log, root / "alias")
        elif case == "mode":
            source_log.chmod(0o644)
        elif case == "occupied":
            (output / "android-runtime-failure.log").write_bytes(b"existing evidence")
        completed = subprocess.run(
            ["/bin/bash", "--noprofile", "--norc", "-euo", "pipefail", "-c",
             export_function + 'preserve_runtime_failure_log "$1" "$2"',
             "failure-log", str(source_log), str(output)], capture_output=True, timeout=3)
        if case in ("valid", "limit"):
            retained = output / "android-runtime-failure.log"
            if (completed.returncode or completed.stderr or retained.read_bytes() != payload
                    or retained.stat().st_mode & 0o777 != 0o400 or retained.stat().st_nlink != 1
                    or completed.stdout != failure_log_receipt(payload)):
                raise RuntimeError(f"actual failure-log publisher result differs for {case}")
        elif (completed.returncode == 0 or completed.stdout or len(completed.stderr) > 4096
              or (case == "occupied" and (output / "android-runtime-failure.log").read_bytes()
                  != b"existing evidence")
              or (case != "occupied" and list(output.iterdir()))):
            raise RuntimeError(f"failure-log publisher did not refuse {case} without mutation")
print("ANDROID_RUNTIME_FAILURE_LOG_TEST=pass cases=7 bytes=1048576 equality=exact "
      "oversized=refused symlink=refused hardlink=refused mode=refused occupied=preserved", file=sys.stderr)
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
            retained_root = root / ("acquisition-" + cancel + "-evidence")
            retained_root.mkdir(mode=0o700)
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
RUNTIME_FAILURE_ROOT=$8
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
                     str(control_read), str(ready_write), cancel, str(drain_write), str(retained_root)],
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
                expected_log = b"ANDROID_PEER_INFRASTRUCTURE=ready server=fixture\n"
                if (output != b"ANDROID_RUNTIME_STAGE stage=peer-infrastructure result=ready server=fixture\n"
                        + failure_log_receipt(expected_log)
                        or (retained_root / "android-runtime-failure.log").read_bytes() != expected_log):
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

    if native_image is not None:
        docker_marker = "vm_docker() {\n"
        if wrapper.count(docker_marker) != 1 or wrapper.index(docker_marker) >= offsets[0]:
            raise RuntimeError("real runtime Docker request owner is absent or duplicated")
        docker_prefix = wrapper[wrapper.index(docker_marker):offsets[0]] + '''
ENTRY_PREFLIGHT=$1/verify-vm-entry-preflight.sh
DOCKER_SOCKET=/run/rustdesk-verifier-vm/docker.sock
DOCKER_CONFIG_ROOT=/run/rustdesk-verifier-vm/docker-config
DOCKER_CLIENT=/usr/bin/docker
shift
'''
        cleanup_source = (cleanup_marker + wrapper.split(cleanup_marker, 1)[1]
                          .split("\n}\n", 1)[0] + "\n}\n")
        # Observe actual cleanup status after its join and workspace removal; do not alter them.
        final_marker = '    exit "$status"\n'
        if cleanup_source.count(final_marker) != 1:
            raise RuntimeError("runtime cleanup finality hook is ambiguous")
        cleanup_source = cleanup_source.replace(
            final_marker,
            '    printf "final:%s:%s:%s:%s\\n" "$cleanup_status" "$status" '
            '"$RUNTIME_LOG_READER" "$(jobs -pr)" >&"$READY"\n' + final_marker, 1)
        probe_program = '''
chunk=$1
uid= gid= cap= nnp= seccomp=
while IFS=":" read -r key value; do
    set -- $value
    case "$key" in
        Uid) uid="$1:$2:$3:$4" ;;
        Gid) gid="$1:$2:$3:$4" ;;
        CapEff) cap=$1 ;;
        NoNewPrivs) nnp=$1 ;;
        Seccomp) seccomp=$1 ;;
    esac
done </proc/self/status
[ "$uid:$gid" = 4000:4000:4000:4000:4000:4000:4000:4000 ]
[ "$cap:$nnp:$seccomp" = 0000000000000000:1:2 ]
trap 'exit 0' TERM
trap 'i=0; while [ "$i" -lt 1024 ]; do printf "%s" "$chunk"; i=$((i + 1)); done; printf z' USR1
printf 'ANDROID_PEER_INFRASTRUCTURE=ready server=fixture\n'
while :; do IFS= read -r ignored || :; done
'''
        for case in ("normal", "overflow", "cancel"):
            workspace = root / ("docker-" + case)
            workspace.mkdir(mode=0o700)
            identity = workspace.stat()
            retained_root = root / ("docker-" + case + "-evidence")
            retained_root.mkdir(mode=0o700)
            ready_read, ready_write = os.pipe()
            process = None
            passed = False
            try:
                process = subprocess.Popen(
                    ["/bin/bash", "--noprofile", "--norc", "-euo", "pipefail", "-c",
                     docker_prefix + runtime_functions + cleanup_source + '''
WORKSPACE=$1
WORKSPACE_ID=$2
IMAGE=$3
PROBE_PROGRAM=$4
SCRIPT_DIR=$5
READY=$7
CASE=$8
RUNTIME_FAILURE_ROOT=$9
RUNTIME_LOG=$WORKSPACE/runtime.log
RUNTIME_LOG_READER=
VERIFY_CONTAINER=
XVFB_CONTAINER=
OBSERVER_CONTAINER=
RUNTIME_CONTAINER=
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
RUNTIME_CONTAINER=$(vm_docker create --pull=never --network=none --read-only \
    --interactive --user 4000:4000 --pids-limit=16 --memory=64m --memory-swap=64m \
    --cpus=0.5 --ulimit nofile=64:64 --ulimit core=0:0 --cap-drop=ALL \
    --security-opt=no-new-privileges --security-opt=apparmor=docker-default \
    "$IMAGE" -euc "$PROBE_PROGRAM" runtime-probe "$6")
[[ "$RUNTIME_CONTAINER" =~ ^[0-9a-f]{64}$ ]]
profile=$(vm_docker inspect --format '{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.Config.User}}|{{.Config.OpenStdin}}|{{.HostConfig.Privileged}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{json .HostConfig.Devices}}|{{json .HostConfig.PortBindings}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}|{{.HostConfig.PidMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.UTSMode}}|{{.HostConfig.CgroupnsMode}}|{{json .Mounts}}' "$RUNTIME_CONTAINER")
[ "$profile" = 'none|true|4000:4000|true|false|67108864|67108864|500000000|16|[]|{}|["ALL"]|["no-new-privileges","apparmor=docker-default"]||private||private|[]' ]
vm_docker start "$RUNTIME_CONTAINER" >/dev/null
start_runtime_log
[ "$(vm_docker inspect --format '{{.State.Running}}' "$RUNTIME_CONTAINER")" = true ]
printf 'following:%s\n' "$RUNTIME_LOG_READER" >&"$READY"
IFS= read -r trigger
[ "$trigger" = "$CASE" ]
case "$CASE" in
    normal) vm_docker stop --time 10 "$RUNTIME_CONTAINER" >/dev/null ;;
    overflow) vm_docker exec "$RUNTIME_CONTAINER" /bin/dash -c 'kill -USR1 1' ;;
    *) exit 94 ;;
esac
status=0
join_runtime_log || status=$?
if [ "$CASE" = overflow ]; then [ "$status" -eq 1 ]; else [ "$status" -eq 0 ]; fi
[ -z "$RUNTIME_LOG_READER" ] && [ -z "$(jobs -pr)" ]
[ "$(vm_docker inspect --format '{{.State.Status}}:{{.State.ExitCode}}' "$RUNTIME_CONTAINER")" = exited:0 ]
[ "$(stat -c %s "$RUNTIME_LOG")" -le 1048576 ]
''', "runtime-docker-stream", str(scripts), str(workspace),
                     f"{identity.st_dev}:{identity.st_ino}", native_image, probe_program,
                     str(scripts), "x" * 1024, str(ready_write), case, str(retained_root)],
                    pass_fds=(ready_write,), stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                os.close(ready_write)
                ready_write = None
                expected_stage = b"ANDROID_RUNTIME_STAGE stage=peer-infrastructure result=ready server=fixture\n"
                if (not select.select([process.stdout], [], [], 8.0)[0]
                        or os.read(process.stdout.fileno(), 4096) != expected_stage
                        or process.poll() is not None):
                    raise RuntimeError(f"real Docker {case} stream was not observed before EOF")
                if (workspace / "runtime.log").read_bytes() != b"ANDROID_PEER_INFRASTRUCTURE=ready server=fixture\n":
                    raise RuntimeError("real Docker log is not complete before EOF")
                if not select.select([ready_read], [], [], 8.0)[0]:
                    raise RuntimeError("real Docker producer did not reach its live following state")
                following = os.read(ready_read, 64)
                reader = following.removeprefix(b"following:").removesuffix(b"\n")
                if not following.startswith(b"following:") or not reader.isdigit() or int(reader) <= 0:
                    raise RuntimeError("real Docker following state has no retained reader")
                if f"PPid:\t{process.pid}" not in Path(f"/proc/{int(reader)}/status").read_text().splitlines():
                    raise RuntimeError("real Docker reader is not owned by its wrapper")
                if case == "cancel":
                    process.send_signal(signal.SIGTERM)
                    output, errors = process.communicate(timeout=15)
                else:
                    output, errors = process.communicate(input=(case + "\n").encode(), timeout=15)
                expected_status = 143 if case == "cancel" else 0
                expected_log = b"ANDROID_PEER_INFRASTRUCTURE=ready server=fixture\n"
                expected_output = failure_log_receipt(expected_log) if case == "cancel" else b""
                if (process.returncode != expected_status or output != expected_output or workspace.exists()
                        or os.read(ready_read, 64) != f"final:0:{expected_status}::\n".encode()
                        or os.read(ready_read, 1)):
                    raise RuntimeError(f"real Docker {case} did not join with exact finality")
                if case == "cancel":
                    if (retained_root / "android-runtime-failure.log").read_bytes() != expected_log:
                        raise RuntimeError("real Docker cancellation failure log was not retained exactly")
                elif list(retained_root.iterdir()):
                    raise RuntimeError("successful test transaction exported a failure log")
                if case == "overflow":
                    if (len(errors) > 4096
                            or b"RuntimeError: Android app runtime output exceeds its bound" not in errors):
                        raise RuntimeError("real Docker overflow failure was not preserved")
                elif errors:
                    raise RuntimeError(f"real Docker {case} emitted unexpected errors: {errors[:4096]!r}")
                passed = True
            finally:
                if ready_write is not None:
                    os.close(ready_write)
                if process is not None:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        output, errors = process.communicate(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        output, errors = process.communicate(timeout=3)
                    if not passed:
                        print(f"ANDROID_RUNTIME_DOCKER_DIAGNOSTIC case={case} "
                              f"status={process.returncode} stderr={errors[:4096]!r}", file=sys.stderr)
                os.close(ready_read)
        print("ANDROID_RUNTIME_DOCKER_LOG=pass cases=3 before_eof=observed normal=joined "
              "failure=live-log-bound producer=term-stopped cancel=143 pipeline=joined "
              "workspace=removed image=caller-owned", file=sys.stderr)
print("ANDROID_RUNTIME_PROGRESS_TEST=pass old=buffered new=before-eof "
      "diagnostics=filtered cardinality=1 children=joined")
